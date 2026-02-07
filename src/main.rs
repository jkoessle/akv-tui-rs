// src/main.rs
use std::env;
use std::error::Error;
use std::fs::OpenOptions;
use std::sync::Arc;
use std::time::{Duration, Instant};

use azure_identity::DeveloperToolsCredential;
use azure_security_keyvault_secrets::{SecretClient, models::Secret};
use clipboard::{ClipboardContext, ClipboardProvider};
use crossterm::event::{self, Event as CEvent, KeyCode, KeyEvent};
use crossterm::{
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{Terminal, backend::CrosstermBackend};
use tokio::sync::Semaphore;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};
use tracing_subscriber::{EnvFilter, Registry, fmt, prelude::*};

mod app;
mod azure;
mod model;
mod ui;

use app::{App, apply_search, apply_vault_search, handle_modal_key};
use azure::{
    get_token_then_discover, list_secrets_and_cache, list_secrets_incremental, preload_all_vaults,
    refresh_token,
};
use model::{AddInputMode, AppEvent, AppScreen, Modal, TokenCache, VaultCacheEntry};
use ui::draw_ui;

#[tokio::main]
#[allow(clippy::collapsible_if)]
async fn main() -> Result<(), Box<dyn Error>> {
    // parse flags
    let args: Vec<String> = env::args().collect();
    let debug_mode = args.iter().any(|s| s == "--debug");

    // initialize tracing to file only when --debug is passed
    if debug_mode {
        // open log file in append mode
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open("azure_tui.log")?;
        // default filter: debug (for verbose investigation)
        let filter = EnvFilter::new("debug");
        // build two layers if desired; here we only write to file
        let fmt_layer = fmt::layer()
            .with_writer(move || file.try_clone().expect("log file clone"))
            .with_target(false);
        Registry::default().with(filter).with(fmt_layer).init();
        info!("Tracing initialized to azure_tui.log (debug)");
    }

    info!("Starting Azure Key Vault TUI");

    // Create credential & app
    let credential = DeveloperToolsCredential::new(None)?;
    let mut app = App::new(credential.clone());

    // Terminal setup
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    crossterm::terminal::enable_raw_mode()?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Channel for background tasks -> UI
    let (tx, mut rx) = mpsc::unbounded_channel::<AppEvent>();

    // Semaphore to bound concurrent preload tasks (avoid throttling)
    let preload_concurrency = Arc::new(Semaphore::new(4)); // tune as needed

    // Kick off initial discovery (background). The welcome screen will show while this runs.
    {
        let tx2 = tx.clone();
        let cred = credential.clone();
        app.loading = true;
        app.message = Some("Discovering vaults...".into());
        tokio::spawn(async move {
            debug!("Initial discover task started");
            match get_token_then_discover(cred.clone()).await {
                Ok((token_opt, vaults)) => {
                    if let Some((token, fetched_at, ttl)) = token_opt {
                        let _ = tx2.send(AppEvent::TokenCached(token, fetched_at, ttl));
                    }
                    let _ = tx2.send(AppEvent::VaultsLoaded(vaults));
                }
                Err(e) => {
                    let _ = tx2.send(AppEvent::Message(format!("Vault discovery failed: {}", e)));
                }
            }
        });
    }

    let tick_rate = Duration::from_millis(50);
    let mut last_tick = Instant::now();

    loop {
        // Advance spinner + redraw periodically
        if last_tick.elapsed() >= tick_rate {
            if app.loading {
                app.throbber_state.calc_next();
            }
            terminal.draw(|f| draw_ui(f, &mut app)).ok();
            last_tick = Instant::now();
        }

        // Auto-dismiss welcome screen after 1.5s
        if app.screen == AppScreen::Welcome
            && app.welcome_shown_at.elapsed() >= Duration::from_millis(1500)
        {
            app.screen = AppScreen::VaultSelection;
        }

        // Drain background events
        while let Ok(ev) = rx.try_recv() {
            match ev {
                AppEvent::VaultsLoaded(v) => {
                    debug!("VaultsLoaded: {} vaults", v.len());
                    app.vaults = v;
                    apply_vault_search(&mut app); // Update displayed_vaults
                    app.loading = false;
                    if app.displayed_vaults.is_empty() {
                        // If empty, message depends on if it's because of search or no vaults at all.
                        // But here we just loaded fresh, so search query should be empty effectively (or applied).
                        // If search query was active during load (unlikely logic path but possible), we respect it.
                        if app.vaults.is_empty() {
                            app.message = Some("No vaults found (press 'v' to retry)".into());
                        } else {
                            app.message = Some("No vaults match search".into());
                        }
                    } else {
                        app.message = Some(format!(
                            "Discovered {} vault(s). Use ↑/↓ and Enter to select.",
                            app.displayed_vaults.len()
                        ));
                        // Start silent preload in background (on ALL vaults, not just displayed)
                        let vaults_to_preload = app.vaults.clone();
                        let cred = app.credential.clone();
                        let tx2 = tx.clone();
                        let sem = preload_concurrency.clone();
                        tokio::spawn(async move {
                            info!(
                                "Starting background preload for {} vaults",
                                vaults_to_preload.len()
                            );
                            preload_all_vaults(cred, tx2, vaults_to_preload, sem).await;
                            info!("Background preload finished");
                        });
                    }
                }
                AppEvent::SecretsUpdated(vault_name, secrets) => {
                    debug!(
                        "SecretsUpdated for {} ({} items)",
                        vault_name,
                        secrets.len()
                    );
                    let mut sorted = secrets.clone();
                    sorted.sort();
                    app.vault_secret_cache.insert(
                        vault_name.clone(),
                        VaultCacheEntry {
                            secrets: sorted.clone(),
                            refreshed_at: Instant::now(),
                        },
                    );
                    if let Some((current_name, _)) = &app.current_vault {
                        if *current_name == vault_name {
                            app.secrets = sorted.clone();
                            apply_search(&mut app);
                            app.loading = false;
                            app.message = Some(format!(
                                "Loaded {} secrets (from {})",
                                app.secrets.len(),
                                vault_name
                            ));
                        }
                    }
                }
                AppEvent::CacheVaultSecrets(vault_name, secrets) => {
                    debug!(
                        "CacheVaultSecrets (silent) for {} ({} items)",
                        vault_name,
                        secrets.len()
                    );
                    let mut sorted = secrets.clone();
                    sorted.sort();
                    app.vault_secret_cache.insert(
                        vault_name,
                        VaultCacheEntry {
                            secrets: sorted,
                            refreshed_at: Instant::now(),
                        },
                    );
                }
                AppEvent::OpenEdit(name, value) => {
                    app.modal = Some(Modal::Edit { name, value });
                    app.loading = false;
                }
                AppEvent::Message(msg) => {
                    warn!("Background message: {}", msg);
                    app.loading = false;
                    app.message = Some(msg);
                }
                AppEvent::TokenCached(_token, fetched_at, ttl) => {
                    debug!("TokenCached (ttl={:?})", ttl);
                    // we store token string in cache with underscore-prefixed field
                    app.token_cache = Some(TokenCache {
                        _token: String::new(),
                        fetched_at,
                        ttl,
                    });
                }
                AppEvent::SecretValueLoaded(vault, name, value) => {
                    app.secret_value_cache
                        .insert((vault.clone(), name.clone()), value.clone());
                    app.loading = false;
                    let ctx: Result<ClipboardContext, _> = ClipboardProvider::new();
                    match ctx {
                        Ok(mut ctx) => {
                            if ctx.set_contents(value).is_ok() {
                                app.message =
                                    Some(format!("Secret '{}' copied to clipboard", name));
                            } else {
                                app.message = Some("Clipboard error".into());
                            }
                        }
                        Err(e) => {
                            app.message = Some(format!("Clipboard init error: {}", e));
                        }
                    }
                }
            }
        }

        // Input handling
        if event::poll(Duration::from_millis(20))? {
            if let CEvent::Key(KeyEvent {
                code, modifiers, ..
            }) = event::read()?
            {
                // if user presses any key during welcome, skip it
                if app.screen == AppScreen::Welcome {
                    app.screen = AppScreen::VaultSelection;
                    continue;
                }

                // Modal handling prioritized
                if handle_modal_key(&mut app, code, &tx).await? {
                    continue;
                }

                // Search mode handling
                if app.search_mode {
                    match code {
                        KeyCode::Esc => {
                            app.search_mode = false;
                            app.search_query.clear();
                            apply_search(&mut app);
                        }
                        KeyCode::Enter => {
                            app.search_mode = false;
                        }
                        KeyCode::Backspace => {
                            app.search_query.pop();
                            apply_search(&mut app);
                        }
                        KeyCode::Char(c) => {
                            app.search_query.push(c);
                            apply_search(&mut app);
                        }
                        _ => {}
                    }
                    continue;
                }

                // Global quit
                if (modifiers == event::KeyModifiers::CONTROL && code == KeyCode::Char('c'))
                    || code == KeyCode::Char('q')
                {
                    break;
                }

                // Token near-expiry refresh check
                if app.token_should_refresh() {
                    debug!("Token near expiry or missing -> refreshing in background");
                    let tx2 = tx.clone();
                    let cred = app.credential.clone();
                    tokio::spawn(async move {
                        match refresh_token(cred.clone()).await {
                            Ok((token, fetched_at, ttl)) => {
                                let _ = tx2.send(AppEvent::TokenCached(token, fetched_at, ttl));
                            }
                            Err(e) => {
                                let _ = tx2.send(AppEvent::Message(format!(
                                    "Failed to refresh token: {}",
                                    e
                                )));
                            }
                        }
                    });
                }

                match app.screen {
                    AppScreen::VaultSelection => {
                        if app.vault_search_mode {
                            match code {
                                KeyCode::Esc => {
                                    app.vault_search_mode = false;
                                    app.vault_search_query.clear();
                                    apply_vault_search(&mut app);
                                }
                                KeyCode::Enter => {
                                    app.vault_search_mode = false;
                                }
                                KeyCode::Backspace => {
                                    app.vault_search_query.pop();
                                    apply_vault_search(&mut app);
                                }
                                KeyCode::Char(c) => {
                                    app.vault_search_query.push(c);
                                    apply_vault_search(&mut app);
                                }
                                _ => {}
                            }
                        } else {
                            match code {
                                KeyCode::Char('/') => {
                                    app.vault_search_mode = true;
                                    app.vault_search_query.clear();
                                    apply_vault_search(&mut app);
                                }
                                KeyCode::Down | KeyCode::Char('j') => {
                                    if !app.displayed_vaults.is_empty() {
                                        let current = app.vault_list_state.selected().unwrap_or(0);
                                        let next =
                                            (current + 1).min(app.displayed_vaults.len() - 1);
                                        app.vault_list_state.select(Some(next));
                                    }
                                }
                                KeyCode::Up | KeyCode::Char('k') => {
                                    if !app.displayed_vaults.is_empty() {
                                        let current = app.vault_list_state.selected().unwrap_or(0);
                                        if current > 0 {
                                            app.vault_list_state.select(Some(current - 1));
                                        }
                                    }
                                }
                                KeyCode::Enter => {
                                    if let Some(selected_idx) = app.vault_list_state.selected() {
                                        if let Some((name, uri)) =
                                            app.displayed_vaults.get(selected_idx).cloned()
                                        {
                                            app.current_vault = Some((name.clone(), uri.clone()));
                                            // check cache existence without holding borrow across mutable calls
                                            let cache_has_entry =
                                                app.vault_secret_cache.contains_key(&name);
                                            if cache_has_entry {
                                                if let Some(entry) =
                                                    app.vault_secret_cache.get(&name)
                                                {
                                                    let cached_secrets = entry.secrets.clone();
                                                    let refreshed_at = entry.refreshed_at;
                                                    // use cached secrets
                                                    app.secrets = cached_secrets;
                                                    apply_search(&mut app);
                                                    app.screen = AppScreen::Secrets;
                                                    app.loading = false;
                                                    app.message = Some(format!(
                                                        "Using cached secrets for '{}'",
                                                        name
                                                    ));
                                                    // refresh silently if older than 30 minutes
                                                    let age =
                                                        Instant::now().duration_since(refreshed_at);
                                                    if age > Duration::from_secs(60 * 30) {
                                                        let tx2 = tx.clone();
                                                        let client = SecretClient::new(
                                                            &uri,
                                                            app.credential.clone(),
                                                            None,
                                                        )?;
                                                        let client_arc = Arc::new(client);
                                                        let name_clone = name.clone();
                                                        tokio::spawn(async move {
                                                            let _ = list_secrets_and_cache(
                                                                client_arc,
                                                                tx2.clone(),
                                                                name_clone,
                                                            )
                                                            .await;
                                                        });
                                                    }
                                                }
                                            } else {
                                                // No cache -> incremental load
                                                app.screen = AppScreen::Secrets;
                                                app.loading = true;
                                                app.message = Some("Loading secrets...".into());
                                                let tx2 = tx.clone();
                                                let client = SecretClient::new(
                                                    &uri,
                                                    app.credential.clone(),
                                                    None,
                                                )?;
                                                let client_arc = Arc::new(client);
                                                let name_clone = name.clone();
                                                tokio::spawn(async move {
                                                    if let Err(e) = list_secrets_incremental(
                                                        client_arc,
                                                        tx2.clone(),
                                                        name_clone.clone(),
                                                    )
                                                    .await
                                                    {
                                                        let _ =
                                                            tx2.send(AppEvent::Message(format!(
                                                                "Failed to list secrets: {}",
                                                                e
                                                            )));
                                                    }
                                                });
                                            }
                                        }
                                    }
                                }
                                KeyCode::Char('v') => {
                                    app.loading = true;
                                    app.message = Some("Refreshing vaults...".into());
                                    let tx2 = tx.clone();
                                    let cred = app.credential.clone();
                                    tokio::spawn(async move {
                                        match get_token_then_discover(cred.clone()).await {
                                            Ok((token_opt, vaults)) => {
                                                if let Some((token, fetched_at, ttl)) = token_opt {
                                                    let _ = tx2.send(AppEvent::TokenCached(
                                                        token, fetched_at, ttl,
                                                    ));
                                                }
                                                let _ = tx2.send(AppEvent::VaultsLoaded(vaults));
                                            }
                                            Err(e) => {
                                                let _ = tx2.send(AppEvent::Message(format!(
                                                    "Vault discovery failed: {}",
                                                    e
                                                )));
                                            }
                                        }
                                    });
                                }
                                _ => {}
                            }
                        }
                    }

                    AppScreen::Secrets => match code {
                        KeyCode::Char('j') | KeyCode::Down => {
                            if !app.displayed_secrets.is_empty() {
                                app.selected =
                                    (app.selected + 1).min(app.displayed_secrets.len() - 1);
                                app.list_state.select(Some(app.selected));
                            }
                        }
                        KeyCode::Char('k') | KeyCode::Up => {
                            if !app.displayed_secrets.is_empty() {
                                if app.selected > 0 {
                                    app.selected -= 1;
                                }
                                app.list_state.select(Some(app.selected));
                            }
                        }
                        KeyCode::Char('v') => {
                            app.screen = AppScreen::VaultSelection;
                            app.loading = true;
                            app.message = Some("Refreshing vaults...".into());
                            let tx2 = tx.clone();
                            let cred = app.credential.clone();
                            tokio::spawn(async move {
                                match get_token_then_discover(cred.clone()).await {
                                    Ok((token_opt, vaults)) => {
                                        if let Some((token, fetched_at, ttl)) = token_opt {
                                            let _ = tx2.send(AppEvent::TokenCached(
                                                token, fetched_at, ttl,
                                            ));
                                        }
                                        let _ = tx2.send(AppEvent::VaultsLoaded(vaults));
                                    }
                                    Err(e) => {
                                        let _ = tx2.send(AppEvent::Message(format!(
                                            "Vault discovery failed: {}",
                                            e
                                        )));
                                    }
                                }
                            });
                        }
                        KeyCode::Char('r') => {
                            if app.current_vault.is_none() {
                                app.message = Some("No vault selected".into());
                            } else if let Some((name, uri)) = &app.current_vault {
                                app.loading = true;
                                app.message = Some("Refreshing secrets...".into());
                                let tx2 = tx.clone();
                                let client = SecretClient::new(uri, app.credential.clone(), None)?;
                                let client_arc = Arc::new(client);
                                let name_clone = name.clone();
                                tokio::spawn(async move {
                                    if let Err(e) = list_secrets_incremental(
                                        client_arc,
                                        tx2.clone(),
                                        name_clone.clone(),
                                    )
                                    .await
                                    {
                                        let _ = tx2.send(AppEvent::Message(format!(
                                            "Refresh error: {}",
                                            e
                                        )));
                                    }
                                });
                            }
                        }
                        KeyCode::Char('a') => {
                            app.modal = Some(Modal::Add {
                                name: String::new(),
                                value: String::new(),
                                input_mode: AddInputMode::Name,
                            });
                        }
                        KeyCode::Char('d') => {
                            if let Some(name) = app.selected_name() {
                                app.modal = Some(Modal::ConfirmDelete { name });
                            }
                        }
                        KeyCode::Char('/') => {
                            app.search_mode = true;
                            app.search_query.clear();
                        }
                        KeyCode::Char('e') => {
                            if let Some(name) = app.selected_name() {
                                if let Some((_, uri)) = &app.current_vault {
                                    app.loading = true;
                                    app.message = Some("Fetching secret for edit...".into());
                                    let name_clone = name.clone();
                                    let client =
                                        SecretClient::new(uri, app.credential.clone(), None)?;
                                    let client_arc = Arc::new(client);
                                    let tx2 = tx.clone();
                                    tokio::spawn(async move {
                                        match client_arc.get_secret(&name_clone, None).await {
                                            Ok(resp) => {
                                                let body = resp.into_body();
                                                match serde_json::from_slice::<Secret>(&body) {
                                                    Ok(secret) => {
                                                        let val = secret.value.unwrap_or_default();
                                                        let _ = tx2.send(AppEvent::OpenEdit(
                                                            name_clone, val,
                                                        ));
                                                    }
                                                    Err(e) => {
                                                        let _ =
                                                            tx2.send(AppEvent::Message(format!(
                                                                "Failed to parse secret JSON: {}",
                                                                e
                                                            )));
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                let _ = tx2.send(AppEvent::Message(format!(
                                                    "Failed to get secret for edit: {}",
                                                    e
                                                )));
                                            }
                                        }
                                    });
                                } else {
                                    app.message = Some("No vault selected".into());
                                }
                            }
                        }
                        KeyCode::Enter => {
                            if let Some(name) = app.selected_name() {
                                if let Some((vault_name, vault_uri)) = &app.current_vault {
                                    // Check cache first
                                    if let Some(cached_val) = app
                                        .secret_value_cache
                                        .get(&(vault_name.clone(), name.clone()))
                                    {
                                        let ctx: Result<ClipboardContext, _> =
                                            ClipboardProvider::new();
                                        match ctx {
                                            Ok(mut ctx) => {
                                                if ctx.set_contents(cached_val.clone()).is_ok() {
                                                    app.message = Some(format!(
                                                        "Secret '{}' copied to clipboard (cached)",
                                                        name
                                                    ));
                                                } else {
                                                    app.message = Some("Clipboard error".into());
                                                }
                                            }
                                            Err(e) => {
                                                app.message =
                                                    Some(format!("Clipboard init error: {}", e));
                                            }
                                        }
                                    } else {
                                        // Not in cache, fetch it
                                        app.loading = true;
                                        app.message = Some("Fetching secret value...".into());
                                        let name_clone = name.clone();
                                        let vault_name_clone = vault_name.clone();
                                        let client = SecretClient::new(
                                            vault_uri,
                                            app.credential.clone(),
                                            None,
                                        )?;
                                        let client_arc = Arc::new(client);
                                        let tx2 = tx.clone();
                                        tokio::spawn(async move {
                                            match client_arc.get_secret(&name_clone, None).await {
                                                Ok(resp) => {
                                                    let body = resp.into_body();
                                                    match serde_json::from_slice::<Secret>(&body) {
                                                        Ok(secret) => {
                                                            let value =
                                                                secret.value.unwrap_or_default();
                                                            let _ = tx2.send(
                                                                AppEvent::SecretValueLoaded(
                                                                    vault_name_clone,
                                                                    name_clone,
                                                                    value,
                                                                ),
                                                            );
                                                        }
                                                        Err(e) => {
                                                            let _ = tx2.send(AppEvent::Message(format!("Failed to parse secret JSON: {}", e)));
                                                        }
                                                    }
                                                }
                                                Err(e) => {
                                                    let _ = tx2.send(AppEvent::Message(format!(
                                                        "Failed to get secret: {}",
                                                        e
                                                    )));
                                                }
                                            }
                                        });
                                    }
                                } else {
                                    app.message = Some("No vault selected".into());
                                }
                            }
                        }
                        _ => {}
                    },
                    AppScreen::Welcome => {}
                }
            }
        }
    }

    // Cleanup
    crossterm::terminal::disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    info!("Exiting Azure Key Vault TUI");
    Ok(())
}
