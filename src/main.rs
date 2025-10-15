// src/main.rs
use std::collections::HashMap;
use std::error::Error;
use std::process::Command;
use std::time::{Duration, Instant};
use std::sync::Arc;
use std::convert::TryInto;
use std::fs::OpenOptions;
use std::env;

use azure_core::credentials::TokenCredential;
use crossterm::event::{self, Event as CEvent, KeyCode, KeyEvent};
use crossterm::{execute, terminal::{EnterAlternateScreen, LeaveAlternateScreen}};
use ratatui::{backend::CrosstermBackend, Frame};
use ratatui::Terminal;
use ratatui::layout::{Constraint, Direction, Layout, Rect, Alignment};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, ListState};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Span;

use azure_identity::DeveloperToolsCredential;
use azure_security_keyvault_secrets::{SecretClient, models::SetSecretParameters, ResourceExt};
use futures::{TryStreamExt, future::join_all};

use fuzzy_matcher::skim::SkimMatcherV2;
use fuzzy_matcher::FuzzyMatcher;
use clipboard::{ClipboardContext, ClipboardProvider};
use serde_json::Value;
use reqwest::Client;
use throbber_widgets_tui::{Throbber, ThrobberState, WhichUse, BRAILLE_SIX};
use tokio::sync::mpsc::{self, UnboundedSender};
use tokio::sync::Semaphore;
use tokio::task;
use tracing::{debug, info, warn};
use tracing_subscriber::{fmt, EnvFilter, prelude::*, Registry};

use time::OffsetDateTime; // used to compute token expiry

#[derive(Debug, Clone)]
enum Modal {
    Add { name: String, value: String, input_mode: AddInputMode },
    Edit { name: String, value: String },
    ConfirmDelete { name: String },
}

#[derive(Debug, Clone, PartialEq)]
enum AddInputMode { Name, Value }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AppScreen {
    Welcome,
    VaultSelection,
    Secrets,
}

#[derive(Debug)]
enum AppEvent {
    VaultsLoaded(Vec<(String, String)>),
    SecretsUpdated(String, Vec<String>), // vault_name, secrets
    CacheVaultSecrets(String, Vec<String>), // vault_name -> cached secrets (silent)
    OpenEdit(String, String),
    Message(String),
    TokenCached(String, Instant, Duration), // token, fetched_at, ttl
}

#[derive(Debug, Clone)]
struct VaultCacheEntry {
    secrets: Vec<String>,
    refreshed_at: Instant,
}

#[derive(Debug, Clone)]
struct TokenCache {
    _token: String, // leading underscore to avoid "never read" warning
    fetched_at: Instant,
    ttl: Duration,
}

struct App {
    screen: AppScreen,
    credential: Arc<DeveloperToolsCredential>,
    current_vault: Option<(String, String)>, // (name, uri)
    secrets: Vec<String>,
    displayed_secrets: Vec<String>,
    selected: usize,
    list_state: ListState,
    message: Option<String>,
    modal: Option<Modal>,
    search_mode: bool,
    search_query: String,
    throbber_state: ThrobberState,
    loading: bool,
    vaults: Vec<(String, String)>,
    vault_selected: usize,
    token_cache: Option<TokenCache>,                 // in-memory token cache (token string stored but not used directly)
    vault_secret_cache: HashMap<String, VaultCacheEntry>, // in-memory per-vault cache
    welcome_shown_at: Instant,
}

impl App {
    fn new(credential: Arc<DeveloperToolsCredential>) -> Self {
        let mut list_state = ListState::default();
        list_state.select(Some(0));
        Self {
            screen: AppScreen::Welcome,
            credential,
            current_vault: None,
            secrets: Vec::new(),
            displayed_secrets: Vec::new(),
            selected: 0,
            list_state,
            message: None,
            modal: None,
            search_mode: false,
            search_query: String::new(),
            throbber_state: ThrobberState::default(),
            loading: false,
            vaults: Vec::new(),
            vault_selected: 0,
            token_cache: None,
            vault_secret_cache: HashMap::new(),
            welcome_shown_at: Instant::now(),
        }
    }

    fn selected_name(&self) -> Option<String> {
        self.displayed_secrets.get(self.selected).cloned()
    }

    fn token_should_refresh(&self) -> bool {
        match &self.token_cache {
            None => true,
            Some(tc) => {
                let ttl_secs = tc.ttl.as_secs().max(1);
                // compute 10% of TTL (at least 1s), then cap at 120s
                let ten_percent = ttl_secs / 10;
                let threshold_secs = std::cmp::min(120, std::cmp::max(1, ten_percent as u64));
                let threshold = Duration::from_secs(threshold_secs);
                let expires_at = tc.fetched_at + tc.ttl;
                Instant::now() + threshold >= expires_at
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // parse --debug flag early
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
        let fmt_layer = fmt::layer().with_writer(move || file.try_clone().expect("log file clone")).with_target(false);
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
        if app.screen == AppScreen::Welcome {
            if app.welcome_shown_at.elapsed() >= Duration::from_millis(1500) {
                app.screen = AppScreen::VaultSelection;
            }
        }

        // Drain background events
        while let Ok(ev) = rx.try_recv() {
            match ev {
                AppEvent::VaultsLoaded(v) => {
                    debug!("VaultsLoaded: {} vaults", v.len());
                    app.vaults = v;
                    app.loading = false;
                    if app.vaults.is_empty() {
                        app.message = Some("No vaults found (press 'v' to retry)".into());
                    } else {
                        app.message = Some(format!("Discovered {} vault(s). Use ↑/↓ and Enter to select.", app.vaults.len()));
                        // Start silent preload in background
                        let vaults_to_preload = app.vaults.clone();
                        let cred = app.credential.clone();
                        let tx2 = tx.clone();
                        let sem = preload_concurrency.clone();
                        tokio::spawn(async move {
                            info!("Starting background preload for {} vaults", vaults_to_preload.len());
                            preload_all_vaults(cred, tx2, vaults_to_preload, sem).await;
                            info!("Background preload finished");
                        });
                    }
                }
                AppEvent::SecretsUpdated(vault_name, secrets) => {
                    debug!("SecretsUpdated for {} ({} items)", vault_name, secrets.len());
                    let mut sorted = secrets.clone();
                    sorted.sort();
                    app.vault_secret_cache.insert(vault_name.clone(), VaultCacheEntry { secrets: sorted.clone(), refreshed_at: Instant::now() });
                    if let Some((current_name, _)) = &app.current_vault {
                        if *current_name == vault_name {
                            app.secrets = sorted.clone();
                            apply_search(&mut app);
                            app.loading = false;
                            app.message = Some(format!("Loaded {} secrets (from {})", app.secrets.len(), vault_name));
                        }
                    }
                }
                AppEvent::CacheVaultSecrets(vault_name, secrets) => {
                    debug!("CacheVaultSecrets (silent) for {} ({} items)", vault_name, secrets.len());
                    let mut sorted = secrets.clone();
                    sorted.sort();
                    app.vault_secret_cache.insert(vault_name, VaultCacheEntry { secrets: sorted, refreshed_at: Instant::now() });
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
                    app.token_cache = Some(TokenCache { _token: String::new(), fetched_at, ttl });
                }
            }
        }

        // Input handling
        if event::poll(Duration::from_millis(20))? {
            match event::read()? {
                CEvent::Key(KeyEvent { code, .. }) => {
                    // if user presses any key during welcome, skip it
                    if app.screen == AppScreen::Welcome {
                        app.screen = AppScreen::VaultSelection;
                        continue;
                    }

                    // Modal handling prioritized
                    if let Some(_) = &app.modal {
                        if handle_modal_key(&mut app, code, &tx).await? { continue; }
                    }

                    // Search mode handling
                    if app.search_mode {
                        match code {
                            KeyCode::Esc => { app.search_mode = false; app.search_query.clear(); apply_search(&mut app); }
                            KeyCode::Enter => { app.search_mode = false; }
                            KeyCode::Backspace => { app.search_query.pop(); apply_search(&mut app); }
                            KeyCode::Char(c) => { app.search_query.push(c); apply_search(&mut app); }
                            _ => {}
                        }
                        continue;
                    }

                    // Global quit
                    if code == KeyCode::Char('q') || code == KeyCode::Esc {
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
                                    let _ = tx2.send(AppEvent::Message(format!("Failed to refresh token: {}", e)));
                                }
                            }
                        });
                    }

                    match app.screen {
                        AppScreen::VaultSelection => match code {
                            KeyCode::Down | KeyCode::Char('j') => {
                                if !app.vaults.is_empty() {
                                    app.vault_selected = (app.vault_selected + 1).min(app.vaults.len() - 1);
                                }
                            }
                            KeyCode::Up | KeyCode::Char('k') => {
                                if app.vault_selected > 0 { app.vault_selected -= 1; }
                            }
                            KeyCode::Enter => {
                                if let Some((name, uri)) = app.vaults.get(app.vault_selected).cloned() {
                                    app.current_vault = Some((name.clone(), uri.clone()));
                                    // check cache existence without holding borrow across mutable calls
                                    let cache_has_entry = app.vault_secret_cache.get(&name).map(|e| e.secrets.len()).unwrap_or(0) > 0;
                                    if cache_has_entry {
                                        if let Some(entry) = app.vault_secret_cache.get(&name) {
                                            let cached_secrets = entry.secrets.clone();
                                            let refreshed_at = entry.refreshed_at;
                                            // use cached secrets
                                            app.secrets = cached_secrets;
                                            apply_search(&mut app);
                                            app.screen = AppScreen::Secrets;
                                            app.loading = false;
                                            app.message = Some(format!("Using cached secrets for '{}'", name));
                                            // refresh silently if older than 30 minutes
                                            let age = Instant::now().duration_since(refreshed_at);
                                            if age > Duration::from_secs(60 * 30) {
                                                let tx2 = tx.clone();
                                                let client = SecretClient::new(&uri, app.credential.clone(), None)?;
                                                let client_arc = Arc::new(client);
                                                let name_clone = name.clone();
                                                tokio::spawn(async move {
                                                    let _ = list_secrets_and_cache(client_arc, tx2.clone(), name_clone).await;
                                                });
                                            }
                                        }
                                    } else {
                                        // No cache -> incremental load
                                        app.screen = AppScreen::Secrets;
                                        app.loading = true;
                                        app.message = Some("Loading secrets...".into());
                                        let tx2 = tx.clone();
                                        let client = SecretClient::new(&uri, app.credential.clone(), None)?;
                                        let client_arc = Arc::new(client);
                                        let name_clone = name.clone();
                                        tokio::spawn(async move {
                                            if let Err(e) = list_secrets_incremental(client_arc, tx2.clone(), name_clone.clone()).await {
                                                let _ = tx2.send(AppEvent::Message(format!("Failed to list secrets: {}", e)));
                                            }
                                        });
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
                                                let _ = tx2.send(AppEvent::TokenCached(token, fetched_at, ttl));
                                            }
                                            let _ = tx2.send(AppEvent::VaultsLoaded(vaults));
                                        }
                                        Err(e) => { let _ = tx2.send(AppEvent::Message(format!("Vault discovery failed: {}", e))); }
                                    }
                                });
                            }
                            _ => {}
                        },
                        AppScreen::Secrets => match code {
                            KeyCode::Char('j') | KeyCode::Down => {
                                if !app.displayed_secrets.is_empty() {
                                    app.selected = (app.selected + 1).min(app.displayed_secrets.len() - 1);
                                    app.list_state.select(Some(app.selected));
                                }
                            }
                            KeyCode::Char('k') | KeyCode::Up => {
                                if !app.displayed_secrets.is_empty() {
                                    if app.selected > 0 { app.selected -= 1; }
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
                                                let _ = tx2.send(AppEvent::TokenCached(token, fetched_at, ttl));
                                            }
                                            let _ = tx2.send(AppEvent::VaultsLoaded(vaults));
                                        }
                                        Err(e) => { let _ = tx2.send(AppEvent::Message(format!("Vault discovery failed: {}", e))); }
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
                                        if let Err(e) = list_secrets_incremental(client_arc, tx2.clone(), name_clone.clone()).await {
                                            let _ = tx2.send(AppEvent::Message(format!("Refresh error: {}", e)));
                                        }
                                    });
                                }
                            }
                            KeyCode::Char('a') => {
                                app.modal = Some(Modal::Add { name: String::new(), value: String::new(), input_mode: AddInputMode::Name });
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
                                        let client = SecretClient::new(uri, app.credential.clone(), None)?;
                                        let client_arc = Arc::new(client);
                                        let tx2 = tx.clone();
                                        tokio::spawn(async move {
                                            match client_arc.get_secret(&name_clone, None).await {
                                                Ok(resp) => {
                                                    match resp.into_body() {
                                                        Ok(secret) => {
                                                            let val = secret.value.unwrap_or_default();
                                                            let _ = tx2.send(AppEvent::OpenEdit(name_clone, val));
                                                        }
                                                        Err(e) => { let _ = tx2.send(AppEvent::Message(format!("Failed to parse secret for edit: {}", e))); }
                                                    }
                                                }
                                                Err(e) => { let _ = tx2.send(AppEvent::Message(format!("Failed to get secret for edit: {}", e))); }
                                            }
                                        });
                                    } else {
                                        app.message = Some("No vault selected".into());
                                    }
                                }
                            }
                            KeyCode::Enter => {
                                if let Some(name) = app.selected_name() {
                                    if let Some((_, uri)) = &app.current_vault {
                                        app.loading = true;
                                        app.message = Some("Fetching secret value...".into());
                                        let name_clone = name.clone();
                                        let client = SecretClient::new(uri, app.credential.clone(), None)?;
                                        let client_arc = Arc::new(client);
                                        let tx2 = tx.clone();
                                        tokio::spawn(async move {
                                            match client_arc.get_secret(&name_clone, None).await {
                                                Ok(resp) => {
                                                    match resp.into_body() {
                                                        Ok(secret) => {
                                                            let value = secret.value.unwrap_or_default();
                                                            let ctx: Result<ClipboardContext, _> = ClipboardProvider::new();
                                                            match ctx {
                                                                Ok(mut ctx) => {
                                                                    if ctx.set_contents(value.clone()).is_ok() {
                                                                        let _ = tx2.send(AppEvent::Message(format!("Secret '{}' copied to clipboard", name_clone)));
                                                                    } else {
                                                                        let _ = tx2.send(AppEvent::Message("Clipboard error".into()));
                                                                    }
                                                                }
                                                                Err(e) => {
                                                                    let _ = tx2.send(AppEvent::Message(format!("Clipboard init error: {}", e)));
                                                                }
                                                            }
                                                        }
                                                        Err(e) => { let _ = tx2.send(AppEvent::Message(format!("Failed to read secret value: {}", e))); }
                                                    }
                                                }
                                                Err(e) => { let _ = tx2.send(AppEvent::Message(format!("Failed to get secret: {}", e))); }
                                            }
                                        });
                                    } else {
                                        app.message = Some("No vault selected".into());
                                    }
                                }
                            }
                            _ => {}
                        },
                        AppScreen::Welcome => {},
                    }
                }
                _ => {}
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

/// Draw router
fn draw_ui(f: &mut Frame<'_>, app: &mut App) {
    match app.screen {
        AppScreen::Welcome => draw_welcome_screen(f),
        AppScreen::VaultSelection => draw_vault_selection_screen(f, app),
        AppScreen::Secrets => draw_secrets_screen(f, app),
    }
}

/// Welcome ASCII art screen (centered)
fn draw_welcome_screen(f: &mut Frame<'_>) {
    let area = f.area();
    let art = r#"
     e      888  /   Y88b      / 
    d8b     888 /     Y88b    /  
   /Y88b    888/\      Y88b  /   
  /  Y88b   888  \      Y888/    
 /____Y88b  888   \      Y8/     
/      Y88b 888    \      Y      
                                  "#;

    let block = Block::default()
        .borders(Borders::ALL)
        .title("Azure KeyVault TUI")
        .title_alignment(Alignment::Center);

    let paragraph = Paragraph::new(art)
        .alignment(Alignment::Center)
        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
        .block(block);

    // Draw centered box (use most of the screen)
    f.render_widget(paragraph, area);
}

fn draw_vault_selection_screen(f: &mut Frame<'_>, app: &App) {
    let area = f.area();
    let block = Block::default()
        .title("🔐 Select an Azure Key Vault")
        .borders(Borders::ALL)
        .title_alignment(Alignment::Center);

    let inner = block.inner(area);

    let items: Vec<ListItem> = if app.vaults.is_empty() {
        vec![ListItem::new("No vaults found yet...")]
    } else {
        app.vaults.iter().map(|(n, _)| ListItem::new(n.clone())).collect()
    };

    let mut list_state = ListState::default();
    if !items.is_empty() {
        list_state.select(Some(app.vault_selected));
    }

    let list = List::new(items)
        .block(block)
        .highlight_style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD));
    f.render_stateful_widget(list, inner, &mut list_state);

    if app.loading {
        let throbber = Throbber::default()
            .label(" Discovering vaults...")
            .style(Style::default().fg(Color::Yellow))
            .throbber_set(BRAILLE_SIX)
            .use_type(WhichUse::Spin);
        let spinner_area = Rect {
            x: inner.x + 2,
            y: inner.bottom() - 2,
            width: 28,
            height: 1,
        };
        let mut ts = app.throbber_state.clone();
        f.render_stateful_widget(throbber, spinner_area, &mut ts);
    }

    let footer = Paragraph::new(app.message.clone().unwrap_or_default())
        .block(Block::default().borders(Borders::ALL).title("Message"))
        .style(Style::default().fg(Color::Cyan));
    let footer_area = Rect {
        x: area.x,
        y: area.bottom() - 3,
        width: area.width,
        height: 3,
    };
    f.render_widget(footer, footer_area);
}

fn draw_secrets_screen(f: &mut Frame<'_>, app: &mut App) {
    let area = f.area();
    let outer_block = Block::default()
        .borders(Borders::ALL)
        .title(Span::styled(
            "Azure Key Vault Manager",
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        ));
    f.render_widget(outer_block, area);
    let inner = Rect {
        x: area.x + 1,
        y: area.y + 1,
        width: area.width - 2,
        height: area.height - 2,
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(0)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(4),
            Constraint::Length(3),
            Constraint::Length(3),
        ])
        .split(inner);

    let vault_label = app.current_vault.as_ref().map(|(n, _)| format!(" (Vault: {})", n)).unwrap_or_default();
    let header_text = if app.search_mode {
        format!("🔍 Search: {}_", app.search_query)
    } else {
        format!("🔑 Azure Key Vault TUI{} — [q: quit] [v: vault] [/: search] [a: add] [e: edit] [d: delete] [r: refresh] [Enter: copy]", vault_label)
    };

    let header = Paragraph::new(header_text)
        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
        .block(Block::default().borders(Borders::ALL).title("Header"));
    f.render_widget(header, chunks[0]);

    let items: Vec<ListItem> = app.displayed_secrets.iter().map(|s| ListItem::new(s.clone())).collect();
    let mut list_state = app.list_state.clone();
    if app.displayed_secrets.is_empty() {
        list_state.select(None);
    } else {
        list_state.select(Some(app.selected));
    }
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("Secrets"))
        .highlight_style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD));
    f.render_stateful_widget(list, chunks[1], &mut list_state);
    app.list_state = list_state;

    let footer_style = Style::default().fg(Color::Cyan);
    let footer = Paragraph::new(app.message.clone().unwrap_or_default())
        .style(footer_style)
        .block(Block::default().borders(Borders::ALL).title("Message"));
    f.render_widget(footer, chunks[2]);

    if app.loading {
        let throbber = Throbber::default()
            .label(" Processing...")
            .style(Style::default().fg(Color::Yellow))
            .throbber_set(BRAILLE_SIX)
            .use_type(WhichUse::Spin);
        f.render_stateful_widget(throbber, chunks[3], &mut app.throbber_state);
    }

    if let Some(modal) = &app.modal {
        let area_modal = Rect::new(area.width / 8, area.height / 6, area.width * 3 / 4, area.height * 2 / 3);
        match modal {
            Modal::Add { name, value, input_mode } => {
                let mode = if *input_mode == AddInputMode::Name { "(typing name)" } else { "(typing value)" };
                let text = format!("Add Secret {}\n\nName: {}\nValue: {}\n\nPress Enter to submit, Esc to cancel", mode, name, value);
                let p = Paragraph::new(text)
                    .style(Style::default().fg(Color::Yellow))
                    .block(Block::default().borders(Borders::ALL).title(Span::styled("Add Secret", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))));
                f.render_widget(p, area_modal);
            }
            Modal::Edit { name, value } => {
                let text = format!("Edit Secret\n\nName: {}\nValue: {}\n\nPress Enter to save, Esc to cancel", name, value);
                let p = Paragraph::new(text)
                    .style(Style::default().fg(Color::Yellow))
                    .block(Block::default().borders(Borders::ALL).title(Span::styled("Edit Secret", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))));
                f.render_widget(p, area_modal);
            }
            Modal::ConfirmDelete { name } => {
                let text = format!("Delete secret '{}' ?\n\nPress 'y' to confirm, Esc to cancel", name);
                let p = Paragraph::new(text)
                    .style(Style::default().fg(Color::Yellow))
                    .block(Block::default().borders(Borders::ALL).title(Span::styled("Confirm Delete", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))));
                f.render_widget(p, area_modal);
            }
        }
    }
}

/// Handle modal keys; background tasks clone tx to avoid move errors.
async fn handle_modal_key(app: &mut App, code: KeyCode, tx: &UnboundedSender<AppEvent>) -> Result<bool, Box<dyn Error>> {
    if app.modal.is_none() { return Ok(false); }
    match &mut app.modal {
        Some(Modal::Add { name, value, input_mode }) => {
            match code {
                KeyCode::Esc => { app.modal = None; }
                KeyCode::Tab => { *input_mode = if *input_mode == AddInputMode::Name { AddInputMode::Value } else { AddInputMode::Name }; }
                KeyCode::Backspace => { match input_mode { AddInputMode::Name => { name.pop(); }, AddInputMode::Value => { value.pop(); }, } }
                KeyCode::Enter => {
                    if name.is_empty() {
                        app.message = Some("Name cannot be empty".into());
                    } else if app.current_vault.is_none() {
                        app.message = Some("No vault selected".into());
                    } else {
                        let secret_name = name.clone();
                        let secret_value = value.clone();
                        let (vault_name, vault_uri) = app.current_vault.as_ref().unwrap().clone();
                        app.modal = None;
                        app.loading = true;
                        app.message = Some("Creating secret...".into());
                        let tx2 = tx.clone();
                        let client = SecretClient::new(&vault_uri, app.credential.clone(), None)?;
                        let client_arc = Arc::new(client);
                        tokio::spawn(async move {
                            let params = SetSecretParameters { value: Some(secret_value.into()), ..Default::default() };
                            match params.try_into() {
                                Ok(p) => {
                                    match client_arc.set_secret(&secret_name, p, None).await {
                                        Ok(resp) => {
                                            let _ = resp.into_body();
                                            let _ = tx2.send(AppEvent::Message(format!("Secret '{}' created/updated", secret_name)));
                                        }
                                        Err(e) => {
                                            let _ = tx2.send(AppEvent::Message(format!("Failed to set secret: {}", e)));
                                        }
                                    }
                                }
                                Err(e) => {
                                    let _ = tx2.send(AppEvent::Message(format!("Failed to prepare secret params: {}", e)));
                                }
                            }
                            // refresh and cache
                            let _ = list_secrets_and_cache(client_arc.clone(), tx2.clone(), vault_name.clone()).await;
                        });
                    }
                }
                KeyCode::Char(c) => {
                    match input_mode {
                        AddInputMode::Name => name.push(c),
                        AddInputMode::Value => value.push(c),
                    }
                }
                _ => {}
            }
            Ok(true)
        }
        Some(Modal::Edit { name, value }) => {
            match code {
                KeyCode::Esc => { app.modal = None; }
                KeyCode::Backspace => { value.pop(); }
                KeyCode::Enter => {
                    if app.current_vault.is_none() {
                        app.message = Some("No vault selected".into());
                    } else {
                        let (vault_name, vault_uri) = app.current_vault.as_ref().unwrap().clone();
                        let client = SecretClient::new(&vault_uri, app.credential.clone(), None)?;
                        let client_arc = Arc::new(client);
                        let name_clone = name.clone();
                        let value_clone = value.clone();
                        app.modal = None;
                        app.loading = true;
                        app.message = Some("Updating secret...".into());
                        let tx2 = tx.clone();
                        tokio::spawn(async move {
                            let params = SetSecretParameters { value: Some(value_clone.into()), ..Default::default() };
                            match params.try_into() {
                                Ok(p) => {
                                    match client_arc.set_secret(&name_clone, p, None).await {
                                        Ok(resp) => {
                                            let _ = resp.into_body();
                                            let _ = tx2.send(AppEvent::Message(format!("Secret '{}' updated", name_clone)));
                                        }
                                        Err(e) => { let _ = tx2.send(AppEvent::Message(format!("Failed to update secret: {}", e))); }
                                    }
                                }
                                Err(e) => { let _ = tx2.send(AppEvent::Message(format!("Failed to prepare secret params: {}", e))); }
                            }
                            let _ = list_secrets_and_cache(client_arc.clone(), tx2.clone(), vault_name.clone()).await;
                        });
                    }
                }
                KeyCode::Char(c) => { value.push(c); }
                _ => {}
            }
            Ok(true)
        }
        Some(Modal::ConfirmDelete { name }) => {
            match code {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    if let Some((vault_name, vault_uri)) = &app.current_vault {
                        let client = SecretClient::new(vault_uri, app.credential.clone(), None)?;
                        let client_arc = Arc::new(client);
                        let name_clone = name.clone();
                        let vault_name = vault_name.clone();
                        app.modal = None;
                        app.loading = true;
                        app.message = Some("Deleting secret...".into());
                        let tx2 = tx.clone();
                        tokio::spawn(async move {
                            match client_arc.delete_secret(&name_clone, None).await {
                                Ok(_) => { let _ = tx2.send(AppEvent::Message(format!("Deleted '{}'. (soft-delete)", name_clone))); }
                                Err(e) => { let _ = tx2.send(AppEvent::Message(format!("Failed to delete: {}", e))); }
                            }
                            let _ = list_secrets_and_cache(client_arc.clone(), tx2.clone(), vault_name.clone()).await;
                        });
                    } else {
                        app.message = Some("No vault selected".into());
                        app.modal = None;
                    }
                }
                KeyCode::Esc | KeyCode::Char('n') => { app.modal = None; }
                _ => {}
            }
            Ok(true)
        }
        None => Ok(false),
    }
}

/// Incrementally list secrets and send updates for the given vault back to UI.
/// Also sends CacheVaultSecrets for silent caching.
async fn list_secrets_incremental(client: Arc<SecretClient>, tx: UnboundedSender<AppEvent>, vault_name: String) -> Result<(), Box<dyn Error>> {
    debug!("Starting incremental list for vault '{}'", vault_name);
    let mut pager = client.list_secret_properties(None)?.into_stream();
    let mut names = Vec::new();
    const BATCH: usize = 20;
    while let Some(item) = pager.try_next().await? {
        if let Ok(rid) = item.resource_id() {
            names.push(rid.name);
        }
        if names.len() % BATCH == 0 {
            let mut sorted = names.clone();
            sorted.sort();
            let _ = tx.send(AppEvent::SecretsUpdated(vault_name.clone(), sorted.clone()));
            let _ = tx.send(AppEvent::CacheVaultSecrets(vault_name.clone(), names.clone()));
        }
    }
    names.sort();
    let _ = tx.send(AppEvent::SecretsUpdated(vault_name.clone(), names.clone()));
    let _ = tx.send(AppEvent::CacheVaultSecrets(vault_name.clone(), names));
    debug!("Completed incremental list for vault '{}'", vault_name);
    Ok(())
}

/// List secrets fully and update cache (used after write/delete to ensure cache is fresh).
async fn list_secrets_and_cache(client: Arc<SecretClient>, tx: UnboundedSender<AppEvent>, vault_name: String) -> Result<(), Box<dyn Error>> {
    debug!("Starting full list+cache for vault '{}'", vault_name);
    let mut pager = client.list_secret_properties(None)?.into_stream();
    let mut names = Vec::new();
    while let Some(item) = pager.try_next().await? {
        if let Ok(rid) = item.resource_id() {
            names.push(rid.name);
        }
    }
    names.sort();
    let _ = tx.send(AppEvent::CacheVaultSecrets(vault_name.clone(), names.clone()));
    let _ = tx.send(AppEvent::SecretsUpdated(vault_name.clone(), names));
    debug!("Completed full list+cache for vault '{}'", vault_name);
    Ok(())
}

/// Preload secrets for all vaults using bounded concurrency and populate cache silently.
async fn preload_all_vaults(credential: Arc<DeveloperToolsCredential>, tx: UnboundedSender<AppEvent>, vaults: Vec<(String, String)>, sem: Arc<Semaphore>) {
    debug!("preload_all_vaults: starting, {} vaults", vaults.len());
    let client_cred = credential;
    let mut handles = Vec::new();
    for (name, uri) in vaults.into_iter() {
        let tx2 = tx.clone();
        let permit = sem.clone();
        let name_clone = name.clone();
        let uri_clone = uri.clone();
        let cred = client_cred.clone();
        let handle = tokio::spawn(async move {
            let _p = permit.acquire_owned().await.expect("semaphore");
            debug!("Preloading vault '{}' (uri={})", name_clone, uri_clone);
            match SecretClient::new(&uri_clone, cred.clone(), None) {
                Ok(client) => {
                    let client_arc = Arc::new(client);
                    if let Err(e) = list_secrets_and_cache(client_arc, tx2.clone(), name_clone.clone()).await {
                        debug!("Preload failed for {}: {}", name_clone, e);
                    } else {
                        debug!("Preload succeeded for {}", name_clone);
                    }
                }
                Err(e) => {
                    debug!("Failed to create client for {}: {}", name_clone, e);
                }
            }
        });
        handles.push(handle);
    }
    for h in handles {
        let _ = h.await;
    }
    debug!("preload_all_vaults: done");
}

/// Refresh token and return (token_string, fetched_at, ttl).
/// Uses the SDK get_token and reads expires_on (OffsetDateTime) when available.
async fn refresh_token(credential: Arc<DeveloperToolsCredential>) -> Result<(String, Instant, Duration), Box<dyn Error>> {
    debug!("Refreshing token via SDK");
    let token_response = credential.get_token(&["https://management.azure.com/.default"], None).await?;
    let token_str = token_response.token.secret().to_string();

    // expires_on is an OffsetDateTime in azure-core v0.29.1
    let expires_on: OffsetDateTime = token_response.expires_on;
    let now = OffsetDateTime::now_utc();
    let secs_i128 = (expires_on - now).whole_seconds().max(1); // i128
    // convert i128 -> u64 safely
    let ttl_secs: u64 = secs_i128.try_into().unwrap_or(55 * 60);
    let ttl = Duration::from_secs(ttl_secs);
    let fetched_at = Instant::now();
    debug!("Token refreshed, ttl={:?}", ttl);
    Ok((token_str, fetched_at, ttl))
}

/// Get token then discover vaults in ARM (parallel per-subscription).
/// Returns optional token info (token_str,fetched_at,ttl) and vault list.
async fn get_token_then_discover(credential: Arc<DeveloperToolsCredential>) -> Result<(Option<(String, Instant, Duration)>, Vec<(String, String)>), Box<dyn Error>> {
    // Acquire token
    let (token_str, fetched_at, ttl) = refresh_token(credential.clone()).await?;
    let client = Client::new();
    let subs_url = "https://management.azure.com/subscriptions?api-version=2020-01-01";
    let sub_resp = client.get(subs_url).bearer_auth(&token_str).send().await?;
    let subs: Value = sub_resp.json().await?;
    let mut vaults: Vec<(String, String)> = Vec::new();

    if let Some(arr) = subs["value"].as_array() {
        // Build per-subscription futures
        let mut futures = Vec::new();
        for sub in arr {
            if let Some(sub_id) = sub["subscriptionId"].as_str() {
                let client_clone = client.clone();
                let bearer_clone = token_str.clone();
                let sub_id = sub_id.to_string();
                futures.push(async move {
                    let url = format!("https://management.azure.com/subscriptions/{}/providers/Microsoft.KeyVault/vaults?api-version=2025-05-01", sub_id);
                    let resp = client_clone.get(&url).bearer_auth(bearer_clone).send().await.ok()?;
                    let data: Value = resp.json().await.ok()?;
                    let mut list = Vec::new();
                    if let Some(v) = data["value"].as_array() {
                        for item in v {
                            if let (Some(name), Some(uri)) = (item["name"].as_str(), item["properties"]["vaultUri"].as_str()) {
                                list.push((name.to_string(), uri.to_string()));
                            }
                        }
                    }
                    Some(list)
                });
            }
        }

        let results = join_all(futures).await;
        for opt in results.into_iter().flatten() {
            vaults.extend(opt);
        }
    }

    // Fallback to az CLI executed in blocking thread if no vaults found
    if vaults.is_empty() {
        debug!("No vaults from ARM; attempting az CLI fallback");
        if let Ok(out) = task::spawn_blocking(|| {
            Command::new("az").args(["keyvault", "list", "-o", "json"]).output()
        }).await? {
            if out.status.success() {
                let data: Value = serde_json::from_slice(&out.stdout)?;
                if let Some(arr) = data.as_array() {
                    for item in arr {
                        if let (Some(name), Some(uri)) = (item["name"].as_str(), item["properties"]["vaultUri"].as_str()) {
                            vaults.push((name.to_string(), uri.to_string()));
                        }
                    }
                }
            } else {
                debug!("az CLI returned non-zero status");
            }
        } else {
            debug!("az CLI fallback spawn failed");
        }
    }

    Ok((Some((token_str, fetched_at, ttl)), vaults))
}

/// Apply fuzzy search to produce displayed_secrets
fn apply_search(app: &mut App) {
    if app.search_query.is_empty() {
        app.displayed_secrets = app.secrets.clone();
    } else {
        let matcher = SkimMatcherV2::default();
        let mut results: Vec<(i64, &String)> = app
            .secrets
            .iter()
            .filter_map(|s| matcher.fuzzy_match(s, &app.search_query).map(|score| (score, s)))
            .collect();
        results.sort_by(|a, b| b.0.cmp(&a.0));
        app.displayed_secrets = results.into_iter().map(|(_, s)| s.clone()).collect();
    }
    app.selected = 0;
    app.list_state.select(Some(0));
}
