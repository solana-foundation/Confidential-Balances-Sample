//! Demo server for the zkproof8 confidential transfers slide deck.
//!
//! Wraps the configure / deposit / apply_pending / transfer modules in a small
//! HTTP API so the frontend deck can drive a live confidential transfer on
//! stage. Designed for a single demo session — all keys live in `.env`.
//!
//! Endpoints:
//!   GET  /demo/health         { ok, validator_reachable, mint, port }
//!   GET  /demo/state          full ledger snapshot for the four-column slide
//!   GET  /demo/events         SSE stream of TransferProgress events
//!   POST /demo/init           ensure mint + accounts + sender funded (idempotent)
//!   POST /demo/transfer       { amount_ui } -> run a live confidential transfer
//!   POST /demo/apply-pending  { account: "sender" | "receiver" }

use anyhow::{anyhow, bail, Context, Result};
use axum::{
    extract::State as AxumState,
    http::StatusCode,
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse, Json,
    },
    routing::{get, post},
    Router,
};
use chrono::{DateTime, Utc};
use conf_balances_examples::{
    apply_pending::apply_pending_balance,
    configure::configure_account_for_confidential_transfers,
    deposit::deposit_to_confidential,
    transfer::transfer_confidential_with_progress,
    types::TransferProgress,
};
use futures_util::stream::StreamExt;
use std::convert::Infallible;
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use serde::{Deserialize, Serialize};
use solana_client::rpc_client::RpcClient;
use solana_commitment_config::CommitmentConfig;
use solana_pubkey::Pubkey;
use solana_keypair::Keypair;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction::Transaction;
use solana_system_interface::instruction as system_instruction;
use spl_associated_token_account::{
    get_associated_token_address_with_program_id,
    instruction::create_associated_token_account_idempotent,
};
use spl_token_2022::{
    extension::{
        confidential_transfer::{
            instruction::initialize_mint as initialize_confidential_transfer_mint,
            ConfidentialTransferAccount, ConfidentialTransferMint,
        },
        BaseStateWithExtensions, ExtensionType, StateWithExtensions,
    },
    instruction::{initialize_mint as initialize_mint_base, mint_to},
    state::{Account as TokenAccount, Mint},
};
use solana_zk_sdk::encryption::{
    auth_encryption::{AeCiphertext, AeKey},
    elgamal::{ElGamalCiphertext, ElGamalKeypair},
};
use solana_zk_sdk_pod::encryption::elgamal::PodElGamalPubkey;
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::RwLock;
use tower_http::cors::CorsLayer;

const RECENT_EVENTS_KEEP: usize = 8;

// ============================================================================
// Config + keys
// ============================================================================

#[derive(Clone)]
struct Config {
    rpc_url: String,
    port: u16,
    mint_decimals: u8,
    initial_deposit_ui: f64,
    transfer_amount_ui: f64,
}

impl Config {
    fn load() -> Result<Self> {
        Ok(Self {
            rpc_url: std::env::var("SOLANA_RPC_URL")
                .unwrap_or_else(|_| "https://api.devnet.solana.com".to_string()),
            port: std::env::var("DEMO_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(8088),
            // 2 decimals so 1M UI = 10^8 base units, well under the u32 ceiling
            // that available-balance decryption (`decrypt_u32`) can brute-force
            // via the BSGS table. Bump only if the demo shrinks below 4k UI.
            mint_decimals: std::env::var("MINT_DECIMALS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(2),
            initial_deposit_ui: parse_env_f64("INITIAL_DEPOSIT_UI", 1_000_000.0)?,
            transfer_amount_ui: parse_env_f64("TRANSFER_AMOUNT_UI", 250_000.0)?,
        })
    }
}

fn parse_env_f64(key: &str, default: f64) -> Result<f64> {
    match std::env::var(key) {
        Ok(s) => s
            .parse()
            .with_context(|| format!("env var {key} is not a valid number")),
        Err(_) => Ok(default),
    }
}

struct Keys {
    payer: Keypair,
    mint: Keypair,
    sender: Keypair,
    receiver: Keypair,
    auditor_authority: Keypair,
}

impl Keys {
    fn load_from_env() -> Result<Self> {
        Ok(Self {
            payer: load_keypair_env("PAYER_KEYPAIR")?,
            mint: load_keypair_env("MINT_KEYPAIR")?,
            sender: load_keypair_env("SENDER_KEYPAIR")?,
            receiver: load_keypair_env("RECEIVER_KEYPAIR")?,
            auditor_authority: load_keypair_env("AUDITOR_KEYPAIR")?,
        })
    }
}

fn load_keypair_env(name: &str) -> Result<Keypair> {
    let raw = std::env::var(name).with_context(|| format!("missing env var {name}"))?;
    let bytes: Vec<u8> = serde_json::from_str(&raw)
        .with_context(|| format!("env var {name} is not a JSON byte array"))?;
    if bytes.len() != 64 {
        bail!("env var {name}: expected 64-byte keypair, got {} bytes", bytes.len());
    }
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&bytes[0..32]);
    Ok(Keypair::new_from_array(secret))
}

// ============================================================================
// Shared app state
// ============================================================================

#[derive(Clone)]
struct AppState {
    cfg: Arc<Config>,
    rpc: Arc<RpcClient>,
    keys: Arc<Keys>,
    auditor_elgamal: Arc<ElGamalKeypair>,
    events: Arc<RwLock<Vec<EventLog>>>,
    /// Broadcast channel for live transfer progress (SSE).
    progress: Arc<broadcast::Sender<TransferProgress>>,
}

#[derive(Clone, Debug, Serialize)]
struct EventLog {
    sig: String,
    kind: String,
    amount_ui: f64,
    ts: DateTime<Utc>,
}

// ============================================================================
// Errors
// ============================================================================

struct AppError(anyhow::Error);

impl<E: Into<anyhow::Error>> From<E> for AppError {
    fn from(err: E) -> Self {
        Self(err.into())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let body = serde_json::json!({ "ok": false, "error": format!("{:#}", self.0) });
        tracing::warn!("handler error: {:#}", self.0);
        (StatusCode::INTERNAL_SERVER_ERROR, Json(body)).into_response()
    }
}

type ApiResult<T> = std::result::Result<Json<T>, AppError>;

// ============================================================================
// Response shapes
// ============================================================================

#[derive(Serialize)]
struct HealthResponse {
    ok: bool,
    validator_reachable: bool,
    mint: String,
    port: u16,
    rpc_url: String,
}

#[derive(Serialize)]
struct StateResponse {
    ok: bool,
    state: LedgerState,
}

#[derive(Serialize)]
struct LedgerState {
    mint: String,
    decimals: u8,
    sender: AccountView,
    receiver: AccountView,
    auditor: AuditorView,
}

#[derive(Serialize)]
struct AccountView {
    owner: String,
    token_account: String,
    public_ui: f64,
    pending_ct: Option<String>,
    pending_ui: f64,
    available_ct: Option<String>,
    available_ui: f64,
}

#[derive(Serialize)]
struct AuditorView {
    authority: String,
    elgamal_pubkey: String,
    recent_events: Vec<EventLog>,
}

#[derive(Serialize)]
struct ActionResponse {
    ok: bool,
    signatures: Vec<String>,
    state: LedgerState,
}

#[derive(Deserialize)]
struct TransferBody {
    amount_ui: Option<f64>,
}

#[derive(Deserialize)]
struct ApplyBody {
    account: String, // "sender" | "receiver"
}

// ============================================================================
// Main
// ============================================================================

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(|s| s.as_str()) == Some("generate-env") {
        generate_env();
        return Ok(());
    }

    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cfg = Config::load()?;
    let port = cfg.port;
    let rpc = Arc::new(RpcClient::new_with_commitment(
        cfg.rpc_url.clone(),
        CommitmentConfig::confirmed(),
    ));
    let keys = Keys::load_from_env()?;

    let auditor_elgamal = ElGamalKeypair::new_from_signer(
        &keys.auditor_authority,
        &keys.mint.pubkey().to_bytes(),
    )
    .map_err(|e| anyhow!("derive auditor ElGamal keypair: {e}"))?;

    tracing::info!("rpc:        {}", cfg.rpc_url);
    tracing::info!("payer:      {}", keys.payer.pubkey());
    tracing::info!("mint:       {}", keys.mint.pubkey());
    tracing::info!("sender:     {}", keys.sender.pubkey());
    tracing::info!("receiver:   {}", keys.receiver.pubkey());
    tracing::info!("auditor:    {}", keys.auditor_authority.pubkey());

    match rpc.get_balance(&keys.payer.pubkey()) {
        Ok(lamports) => {
            let sol = lamports as f64 / 1_000_000_000f64;
            if lamports < 50_000_000 {
                tracing::warn!(
                    "payer balance: {sol:.4} SOL — too low. airdrop with: \
                     solana airdrop 5 {} --url {}",
                    keys.payer.pubkey(),
                    cfg.rpc_url
                );
            } else {
                tracing::info!("payer balance: {sol:.4} SOL");
            }
        }
        Err(e) => tracing::warn!("could not read payer balance: {e}"),
    }

    let (progress_tx, _) = broadcast::channel::<TransferProgress>(64);
    let app_state = AppState {
        cfg: Arc::new(cfg),
        rpc,
        keys: Arc::new(keys),
        auditor_elgamal: Arc::new(auditor_elgamal),
        events: Arc::new(RwLock::new(Vec::new())),
        progress: Arc::new(progress_tx),
    };

    let app = Router::new()
        .route("/demo/health", get(health))
        .route("/demo/state", get(state_handler))
        .route("/demo/events", get(events_handler))
        .route("/demo/init", post(init_handler))
        .route("/demo/transfer", post(transfer_handler))
        .route("/demo/apply-pending", post(apply_pending_handler))
        .with_state(app_state)
        .layer(CorsLayer::permissive());

    let addr: SocketAddr = format!("0.0.0.0:{port}").parse()?;
    tracing::info!("listening on http://{addr}");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

// ============================================================================
// Handlers
// ============================================================================

async fn health(AxumState(s): AxumState<AppState>) -> ApiResult<HealthResponse> {
    let mint_pk = s.keys.mint.pubkey();
    let validator_reachable = s.rpc.get_latest_blockhash().is_ok();
    Ok(Json(HealthResponse {
        ok: true,
        validator_reachable,
        mint: mint_pk.to_string(),
        port: s.cfg.port,
        rpc_url: s.cfg.rpc_url.clone(),
    }))
}

async fn state_handler(AxumState(s): AxumState<AppState>) -> ApiResult<StateResponse> {
    let state = read_ledger_state(&s).await?;
    Ok(Json(StateResponse { ok: true, state }))
}

async fn events_handler(
    AxumState(s): AxumState<AppState>,
) -> Sse<impl futures_util::Stream<Item = std::result::Result<Event, Infallible>>> {
    let rx = s.progress.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|res| async move {
        match res {
            Ok(ev) => match serde_json::to_string(&ev) {
                Ok(payload) => Some(Ok(Event::default().data(payload))),
                Err(_) => None,
            },
            // Lagged behind on the broadcast — drop the event silently.
            Err(_) => None,
        }
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}

async fn init_handler(AxumState(s): AxumState<AppState>) -> ApiResult<ActionResponse> {
    let response = run_blocking(s.clone(), |s| async move {
        let mut sigs: Vec<String> = Vec::new();

        let payer_lamports = s.rpc.get_balance(&s.keys.payer.pubkey())?;
        if payer_lamports < 10_000_000 {
            bail!(
                "payer {} has {:.6} SOL — fund it first: solana airdrop 5 {} --url {}",
                s.keys.payer.pubkey(),
                payer_lamports as f64 / 1_000_000_000f64,
                s.keys.payer.pubkey(),
                s.cfg.rpc_url
            );
        }

        if !mint_exists(&s.rpc, &s.keys.mint.pubkey())? {
            let sig = create_confidential_mint(&s).await?;
            sigs.push(sig.to_string());
        } else {
            verify_mint_matches(&s)?;
        }

        sigs.extend(
            ensure_confidential_account(&s, &s.keys.sender)
                .await?
                .into_iter()
                .map(|sig| sig.to_string()),
        );
        sigs.extend(
            ensure_confidential_account(&s, &s.keys.receiver)
                .await?
                .into_iter()
                .map(|sig| sig.to_string()),
        );

        let target_base = ui_to_base(s.cfg.initial_deposit_ui, s.cfg.mint_decimals);
        let sender_view = read_account_view(&s, &s.keys.sender)?;
        let sender_avail_base = ui_to_base(sender_view.available_ui, s.cfg.mint_decimals);
        if sender_avail_base < target_base {
            let needed = target_base.saturating_sub(sender_avail_base);
            let sender_public_base = ui_to_base(sender_view.public_ui, s.cfg.mint_decimals);
            if sender_public_base < needed {
                let mint_extra = needed - sender_public_base;
                let sig = mint_to_sender(&s, mint_extra)?;
                sigs.push(sig.to_string());
            }
            let dep_sig = deposit_to_confidential(
                &s.rpc,
                &s.keys.payer,
                &s.keys.sender,
                &s.keys.mint.pubkey(),
                needed,
                s.cfg.mint_decimals,
            )
            .await
            .map_err(|e| anyhow!("deposit failed: {e}"))?;
            sigs.push(dep_sig.to_string());
            let apply_sig =
                apply_pending_balance(&s.rpc, &s.keys.payer, &s.keys.sender, &s.keys.mint.pubkey())
                    .await
                    .map_err(|e| anyhow!("apply pending (sender) failed: {e}"))?;
            sigs.push(apply_sig.to_string());
            log_event(
                &s,
                "init-deposit",
                base_to_ui(needed, s.cfg.mint_decimals),
                &dep_sig,
            )
            .await;
        }

        let state = read_ledger_state(&s).await?;
        Ok(ActionResponse {
            ok: true,
            signatures: sigs,
            state,
        })
    })
    .await?;
    Ok(Json(response))
}

async fn transfer_handler(
    AxumState(s): AxumState<AppState>,
    Json(body): Json<TransferBody>,
) -> ApiResult<ActionResponse> {
    let amount_ui = body.amount_ui.unwrap_or(s.cfg.transfer_amount_ui);

    // Immediate feedback so the popup shows activity while preflight RPC runs.
    let _ = s.progress.send(TransferProgress::Phase {
        name: "preflight".to_string(),
        detail: format!("Verifying setup before transferring {amount_ui} USDC"),
    });

    let response = run_blocking(s.clone(), move |s| async move {
        require_initialized(&s)?;

        // spl-token-client uses sender as the fee-payer for proof context
        // state account creation. Surface a clean error if sender is dry.
        let sender_lamports = s.rpc.get_balance(&s.keys.sender.pubkey())?;
        if sender_lamports < 20_000_000 {
            bail!(
                "sender {} has {:.6} SOL — fund it first: solana airdrop 1 {} --url {}",
                s.keys.sender.pubkey(),
                sender_lamports as f64 / 1_000_000_000f64,
                s.keys.sender.pubkey(),
                s.cfg.rpc_url
            );
        }

        let amount_base = ui_to_base(amount_ui, s.cfg.mint_decimals);
        let progress_tx = s.progress.as_ref();
        let result = transfer_confidential_with_progress(
            &s.rpc,
            &s.keys.payer,
            &s.keys.sender,
            &s.keys.mint.pubkey(),
            &s.keys.receiver.pubkey(),
            amount_base,
            Some(progress_tx),
        )
        .await;
        let sigs = match result {
            Ok(sigs) => sigs,
            Err(e) => {
                let _ = progress_tx.send(TransferProgress::Error {
                    message: e.to_string(),
                });
                return Err(anyhow!("transfer failed: {e}"));
            }
        };

        // The 3-tx flow puts the actual `inner_transfer` ix in the last tx
        // (alongside eq_verify + 3 closes), so the transfer signature is the
        // last one we got back from `transfer_confidential_with_progress`.
        if let Some(transfer_sig) = sigs.last() {
            log_event(&s, "transfer", amount_ui, transfer_sig).await;
        }

        let state = read_ledger_state(&s).await?;
        Ok(ActionResponse {
            ok: true,
            signatures: sigs.into_iter().map(|s| s.to_string()).collect(),
            state,
        })
    })
    .await?;
    Ok(Json(response))
}

async fn apply_pending_handler(
    AxumState(s): AxumState<AppState>,
    Json(body): Json<ApplyBody>,
) -> ApiResult<ActionResponse> {
    // Immediate feedback before the preflight RPC roundtrip.
    let _ = s.progress.send(TransferProgress::Phase {
        name: "preflight".to_string(),
        detail: format!("Applying pending balance for {}", body.account),
    });

    let progress_for_err = s.progress.clone();
    let account_label = body.account.clone();
    let response = run_blocking(s.clone(), move |s| async move {
        require_initialized(&s)?;

        let _ = s.progress.send(TransferProgress::Phase {
            name: "submit-apply-pending".to_string(),
            detail: "Decrypting pending balance and submitting apply instruction"
                .to_string(),
        });

        let kp = match body.account.as_str() {
            "sender" => &s.keys.sender,
            "receiver" => &s.keys.receiver,
            other => bail!("unknown account: {other}"),
        };

        // Capture the pending balance *before* applying so the auditor event
        // logs the actual amount that moved from pending → available.
        let applied_amount_ui = read_account_view(&s, kp)
            .map(|v| v.pending_ui)
            .unwrap_or(0.0);

        let sig = apply_pending_balance(&s.rpc, &s.keys.payer, kp, &s.keys.mint.pubkey())
            .await
            .map_err(|e| anyhow!("apply_pending failed: {e}"))?;

        let _ = s.progress.send(TransferProgress::Signature {
            label: format!("apply-pending-{}", body.account),
            sig: sig.to_string(),
        });
        let _ = s.progress.send(TransferProgress::Done {
            sigs: vec![sig.to_string()],
        });

        log_event(
            &s,
            &format!("apply-pending-{}", body.account),
            applied_amount_ui,
            &sig,
        )
        .await;

        let state = read_ledger_state(&s).await?;
        Ok(ActionResponse {
            ok: true,
            signatures: vec![sig.to_string()],
            state,
        })
    })
    .await
    .map_err(|e| {
        let _ = progress_for_err.send(TransferProgress::Error {
            message: format!("apply-pending {account_label}: {e}"),
        });
        e
    })?;
    Ok(Json(response))
}

/// Run a non-Send async closure on the blocking pool with a multi-threaded
/// runtime. Lets us drive the `conf_balances_examples::*` async fns (which
/// hold non-Send `Arc<dyn Signer>` across `.await` points) from an axum
/// handler that itself must produce a Send future. Multi-threaded is required
/// because the Solana RPC client calls `block_in_place` internally, which
/// panics on a current-thread runtime.
async fn run_blocking<F, Fut, T>(s: AppState, f: F) -> Result<T>
where
    F: FnOnce(AppState) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<T>>,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|e| anyhow!("build runtime: {e}"))?;
        rt.block_on(f(s))
    })
    .await
    .map_err(|e| anyhow!("blocking join: {e}"))?
}

// ============================================================================
// Mint creation + account configuration
// ============================================================================

fn mint_exists(rpc: &RpcClient, mint: &Pubkey) -> Result<bool> {
    match rpc.get_account(mint) {
        Ok(_) => Ok(true),
        Err(e) => {
            // Treat AccountNotFound (-32602) as "doesn't exist".
            if e.to_string().contains("AccountNotFound") {
                Ok(false)
            } else {
                Err(anyhow!("rpc get_account failed: {e}"))
            }
        }
    }
}

fn verify_mint_matches(s: &AppState) -> Result<()> {
    let data = s.rpc.get_account(&s.keys.mint.pubkey())?;
    let mint = StateWithExtensions::<Mint>::unpack(&data.data)
        .map_err(|e| anyhow!("mint exists but is not a valid Token-2022 mint: {e}"))?;
    let ct = mint
        .get_extension::<ConfidentialTransferMint>()
        .map_err(|e| anyhow!("mint missing ConfidentialTransferMint extension: {e}"))?;

    let expected: PodElGamalPubkey = (*s.auditor_elgamal.pubkey()).into();
    let actual: Option<PodElGamalPubkey> = Option::from(ct.auditor_elgamal_pubkey);
    match actual {
        Some(actual) if actual == expected => Ok(()),
        Some(_) => Err(anyhow!(
            "mint already exists but auditor pubkey does not match the auditor keypair in .env. \
             rotate MINT_KEYPAIR or AUDITOR_KEYPAIR."
        )),
        None => Err(anyhow!(
            "mint already exists with no auditor configured; rotate MINT_KEYPAIR."
        )),
    }
}

async fn create_confidential_mint(s: &AppState) -> Result<Signature> {
    let space = ExtensionType::try_calculate_account_len::<Mint>(&[
        ExtensionType::ConfidentialTransferMint,
    ])?;
    let rent = s.rpc.get_minimum_balance_for_rent_exemption(space)?;
    let auditor_pod: PodElGamalPubkey = (*s.auditor_elgamal.pubkey()).into();

    let create_ix = system_instruction::create_account(
        &s.keys.payer.pubkey(),
        &s.keys.mint.pubkey(),
        rent,
        space as u64,
        &spl_token_2022::id(),
    );
    let init_ct_ix = initialize_confidential_transfer_mint(
        &spl_token_2022::id(),
        &s.keys.mint.pubkey(),
        Some(s.keys.payer.pubkey()), // authority — whoever can later update auditor
        true,                         // auto-approve new accounts
        Some(auditor_pod),
    )
    .map_err(|e| anyhow!("initialize_confidential_transfer_mint: {e}"))?;
    let init_mint_ix = initialize_mint_base(
        &spl_token_2022::id(),
        &s.keys.mint.pubkey(),
        &s.keys.payer.pubkey(),
        None,
        s.cfg.mint_decimals,
    )?;

    let blockhash = s.rpc.get_latest_blockhash()?;
    let tx = Transaction::new_signed_with_payer(
        &[create_ix, init_ct_ix, init_mint_ix],
        Some(&s.keys.payer.pubkey()),
        &[&s.keys.payer, &s.keys.mint],
        blockhash,
    );
    let sig = s.rpc.send_and_confirm_transaction(&tx)?;
    tracing::info!("created confidential mint: {sig}");
    Ok(sig)
}

async fn ensure_confidential_account(
    s: &AppState,
    authority: &Keypair,
) -> Result<Vec<Signature>> {
    let mut sigs = Vec::new();
    let ata = get_associated_token_address_with_program_id(
        &authority.pubkey(),
        &s.keys.mint.pubkey(),
        &spl_token_2022::id(),
    );

    if !ata_is_configured(&s.rpc, &ata)? {
        // 1. Idempotent ATA create.
        let ata_ix = create_associated_token_account_idempotent(
            &s.keys.payer.pubkey(),
            &authority.pubkey(),
            &s.keys.mint.pubkey(),
            &spl_token_2022::id(),
        );
        let blockhash = s.rpc.get_latest_blockhash()?;
        let tx = Transaction::new_signed_with_payer(
            &[ata_ix],
            Some(&s.keys.payer.pubkey()),
            &[&s.keys.payer],
            blockhash,
        );
        sigs.push(s.rpc.send_and_confirm_transaction(&tx)?);

        // 2. Configure for confidential transfers.
        let cfg_sig = configure_account_for_confidential_transfers(
            &s.rpc,
            &s.keys.payer,
            authority,
            &s.keys.mint.pubkey(),
        )
        .await
        .map_err(|e| anyhow!("configure_account failed: {e}"))?;
        sigs.push(cfg_sig);
    }

    Ok(sigs)
}

fn require_initialized(s: &AppState) -> Result<()> {
    if !mint_exists(&s.rpc, &s.keys.mint.pubkey())? {
        bail!(
            "mint {} does not exist on chain — POST /demo/init first (or press I on slide 12)",
            s.keys.mint.pubkey()
        );
    }
    let sender_ata = get_associated_token_address_with_program_id(
        &s.keys.sender.pubkey(),
        &s.keys.mint.pubkey(),
        &spl_token_2022::id(),
    );
    if !ata_is_configured(&s.rpc, &sender_ata)? {
        bail!(
            "sender token account {sender_ata} not configured for confidential transfers — POST /demo/init first"
        );
    }
    let receiver_ata = get_associated_token_address_with_program_id(
        &s.keys.receiver.pubkey(),
        &s.keys.mint.pubkey(),
        &spl_token_2022::id(),
    );
    if !ata_is_configured(&s.rpc, &receiver_ata)? {
        bail!(
            "receiver token account {receiver_ata} not configured for confidential transfers — POST /demo/init first"
        );
    }
    Ok(())
}

fn ata_is_configured(rpc: &RpcClient, ata: &Pubkey) -> Result<bool> {
    let data = match rpc.get_account(ata) {
        Ok(a) => a,
        Err(e) if e.to_string().contains("AccountNotFound") => return Ok(false),
        Err(e) => return Err(anyhow!("rpc get_account failed: {e}")),
    };
    let acc = StateWithExtensions::<TokenAccount>::unpack(&data.data)
        .map_err(|e| anyhow!("ATA exists but is not Token-2022: {e}"))?;
    Ok(acc.get_extension::<ConfidentialTransferAccount>().is_ok())
}

fn mint_to_sender(s: &AppState, amount_base: u64) -> Result<Signature> {
    let sender_ata = get_associated_token_address_with_program_id(
        &s.keys.sender.pubkey(),
        &s.keys.mint.pubkey(),
        &spl_token_2022::id(),
    );
    let ix = mint_to(
        &spl_token_2022::id(),
        &s.keys.mint.pubkey(),
        &sender_ata,
        &s.keys.payer.pubkey(),
        &[],
        amount_base,
    )?;
    let blockhash = s.rpc.get_latest_blockhash()?;
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&s.keys.payer.pubkey()),
        &[&s.keys.payer],
        blockhash,
    );
    Ok(s.rpc.send_and_confirm_transaction(&tx)?)
}

// ============================================================================
// Reading + decrypting state
// ============================================================================

async fn read_ledger_state(s: &AppState) -> Result<LedgerState> {
    let sender = read_account_view(s, &s.keys.sender)?;
    let receiver = read_account_view(s, &s.keys.receiver)?;
    let events = s.events.read().await.clone();

    Ok(LedgerState {
        mint: s.keys.mint.pubkey().to_string(),
        decimals: s.cfg.mint_decimals,
        sender,
        receiver,
        auditor: AuditorView {
            authority: s.keys.auditor_authority.pubkey().to_string(),
            elgamal_pubkey: bs58::encode(s.auditor_elgamal.pubkey().to_string().as_bytes())
                .into_string(),
            recent_events: events,
        },
    })
}

fn read_account_view(s: &AppState, owner: &Keypair) -> Result<AccountView> {
    let token_account = get_associated_token_address_with_program_id(
        &owner.pubkey(),
        &s.keys.mint.pubkey(),
        &spl_token_2022::id(),
    );

    let data = match s.rpc.get_account(&token_account) {
        Ok(a) => a,
        Err(e) if e.to_string().contains("AccountNotFound") => {
            return Ok(AccountView {
                owner: owner.pubkey().to_string(),
                token_account: token_account.to_string(),
                public_ui: 0.0,
                pending_ct: None,
                pending_ui: 0.0,
                available_ct: None,
                available_ui: 0.0,
            });
        }
        Err(e) => return Err(anyhow!("rpc get_account: {e}")),
    };

    let acc = StateWithExtensions::<TokenAccount>::unpack(&data.data)
        .map_err(|e| anyhow!("unpack token account: {e}"))?;
    let public_base = acc.base.amount;

    let ct_ext = acc
        .get_extension::<ConfidentialTransferAccount>()
        .ok();

    let (pending_ct, pending_ui, available_ct, available_ui) = match ct_ext {
        Some(ext) => {
            let elgamal = ElGamalKeypair::new_from_signer(owner, &token_account.to_bytes())
                .map_err(|e| anyhow!("derive ElGamal keypair: {e}"))?;
            let aes = AeKey::new_from_signer(owner, &token_account.to_bytes())
                .map_err(|e| anyhow!("derive AES key: {e}"))?;

            let pending_lo: ElGamalCiphertext = ext
                .pending_balance_lo
                .try_into()
                .map_err(|e| anyhow!("decode pending_lo: {e:?}"))?;
            let pending_hi: ElGamalCiphertext = ext
                .pending_balance_hi
                .try_into()
                .map_err(|e| anyhow!("decode pending_hi: {e:?}"))?;
            let avail_ct: ElGamalCiphertext = ext
                .available_balance
                .try_into()
                .map_err(|e| anyhow!("decode available_balance: {e:?}"))?;

            let pending_lo_v = pending_lo.decrypt_u32(elgamal.secret()).unwrap_or(0) as u64;
            let pending_hi_v = pending_hi.decrypt_u32(elgamal.secret()).unwrap_or(0) as u64;
            let pending_total = pending_lo_v + (pending_hi_v << 16);

            let avail_aes: AeCiphertext = ext
                .decryptable_available_balance
                .try_into()
                .map_err(|e| anyhow!("decode AeCiphertext: {e:?}"))?;
            let avail_v = aes.decrypt(&avail_aes).unwrap_or(0);

            (
                Some(ciphertext_short(&format!("{:?}", pending_lo))),
                base_to_ui(pending_total, s.cfg.mint_decimals),
                Some(ciphertext_short(&format!("{:?}", avail_ct))),
                base_to_ui(avail_v, s.cfg.mint_decimals),
            )
        }
        None => (None, 0.0, None, 0.0),
    };

    Ok(AccountView {
        owner: owner.pubkey().to_string(),
        token_account: token_account.to_string(),
        public_ui: base_to_ui(public_base, s.cfg.mint_decimals),
        pending_ct,
        pending_ui,
        available_ct,
        available_ui,
    })
}

/// Compress a debug-formatted ciphertext into a short fingerprint suitable
/// for the chain-analyst column on slide 12.
fn ciphertext_short(debug: &str) -> String {
    let trimmed: String = debug.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if trimmed.len() <= 16 {
        format!("0x{trimmed}")
    } else {
        format!("0x{}…{}", &trimmed[..8], &trimmed[trimmed.len() - 6..])
    }
}

// ============================================================================
// Misc helpers
// ============================================================================

fn ui_to_base(ui: f64, decimals: u8) -> u64 {
    (ui * 10f64.powi(decimals as i32)).round() as u64
}

fn base_to_ui(base: u64, decimals: u8) -> f64 {
    base as f64 / 10f64.powi(decimals as i32)
}

async fn log_event(s: &AppState, kind: &str, amount_ui: f64, sig: &Signature) {
    let mut log = s.events.write().await;
    log.insert(
        0,
        EventLog {
            sig: sig.to_string(),
            kind: kind.to_string(),
            amount_ui,
            ts: Utc::now(),
        },
    );
    log.truncate(RECENT_EVENTS_KEEP);
}

// ============================================================================
// generate-env subcommand
// ============================================================================

fn generate_env() {
    let names = ["PAYER", "MINT", "SENDER", "RECEIVER", "AUDITOR"];
    let kps: Vec<(String, Keypair)> = names
        .iter()
        .map(|n| (n.to_string(), Keypair::new()))
        .collect();

    println!("# zkproof8 demo-server config — copy this into .env");
    println!("# generated {}", Utc::now().to_rfc3339());
    println!();
    println!("SOLANA_RPC_URL=https://api.devnet.solana.com");
    println!("DEMO_PORT=8088");
    println!("# 2 decimals keeps base-unit balances under the u32 BSGS ceiling.");
    println!("MINT_DECIMALS=2");
    println!("INITIAL_DEPOSIT_UI=1000000");
    println!("TRANSFER_AMOUNT_UI=250000");
    println!();

    for (name, kp) in &kps {
        let bytes: Vec<u8> = kp.to_bytes().to_vec();
        let json = serde_json::to_string(&bytes).expect("serialize keypair");
        println!("# {name} pubkey: {}", kp.pubkey());
        println!("{name}_KEYPAIR={json}");
        println!();
    }

    let payer_pk = kps
        .iter()
        .find(|(n, _)| n == "PAYER")
        .map(|(_, kp)| kp.pubkey())
        .unwrap();
    eprintln!();
    eprintln!("---");
    eprintln!("Fund the PAYER pubkey before starting the server:");
    eprintln!("  solana airdrop 5 {payer_pk} --url https://api.devnet.solana.com");
    eprintln!();
    eprintln!("Then run:  cargo run --bin demo-server");
}
