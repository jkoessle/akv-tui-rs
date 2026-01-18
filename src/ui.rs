use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::Span,
    widgets::{Block, Borders, List, ListItem, Paragraph},
};
use throbber_widgets_tui::{BRAILLE_SIX, Throbber, WhichUse};

use crate::app::App;
use crate::model::{AddInputMode, AppScreen, Modal};

/// Draw router
pub fn draw_ui(f: &mut Frame<'_>, app: &mut App) {
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
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .block(block);

    // Draw centered box (use most of the screen)
    f.render_widget(paragraph, area);
}

fn draw_vault_selection_screen(f: &mut Frame<'_>, app: &mut App) {
    let area = f.area();
    
    let title = if app.vault_search_mode {
        format!("🔐 Select Vault (Search: {}_ )", app.vault_search_query)
    } else {
        if !app.vault_search_query.is_empty() {
             format!("🔐 Select Vault (Filter: {})", app.vault_search_query)
        } else {
            "🔐 Select an Azure Key Vault (Press '/' to filter)".to_string()
        }
    };

    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .title_alignment(Alignment::Center);

    let inner = block.inner(area);

    let items: Vec<ListItem> = if app.displayed_vaults.is_empty() {
        if app.vaults.is_empty() {
            vec![ListItem::new("No vaults found yet...")]
        } else {
             vec![ListItem::new("No matching vaults...")]
        }
    } else {
        app.displayed_vaults
            .iter()
            .map(|(n, _)| ListItem::new(n.clone()))
            .collect()
    };
    
    let list = List::new(items).block(block).highlight_style(
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    );
    f.render_stateful_widget(list, inner, &mut app.vault_list_state);

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
    let outer_block = Block::default().borders(Borders::ALL).title(Span::styled(
        "Azure Key Vault Manager",
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
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

    let vault_label = app
        .current_vault
        .as_ref()
        .map(|(n, _)| format!(" (Vault: {})", n))
        .unwrap_or_default();
    let header_text = if app.search_mode {
        format!("🔍 Search: {}_", app.search_query)
    } else {
        format!(
            "🔑 Azure Key Vault TUI{} — [q: quit] [v: vault] [/: search] [a: add] [e: edit] [d: delete] [r: refresh] [Enter: copy]",
            vault_label
        )
    };

    let header = Paragraph::new(header_text)
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .block(Block::default().borders(Borders::ALL).title("Header"));
    f.render_widget(header, chunks[0]);

    let items: Vec<ListItem> = app
        .displayed_secrets
        .iter()
        .map(|s| ListItem::new(s.clone()))
        .collect();
    let mut list_state = app.list_state.clone();
    if app.displayed_secrets.is_empty() {
        list_state.select(None);
    } else {
        list_state.select(Some(app.selected));
    }
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("Secrets"))
        .highlight_style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        );
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
        let area = f.area();
        let area_modal = centered_rect(60, 40, area);
        f.render_widget(ratatui::widgets::Clear, area_modal);

        let block = Block::default()
            .borders(Borders::ALL)
            .title_alignment(Alignment::Center)
            .style(Style::default().bg(Color::Black));

        match modal {
            Modal::Add {
                name,
                value,
                input_mode,
            } => {
                f.render_widget(block.title("Add Secret"), area_modal);

                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .margin(2)
                    .constraints([
                        Constraint::Length(3), // Name label + input
                        Constraint::Length(3), // Value label + input
                        Constraint::Min(1),    // Help text
                    ])
                    .split(area_modal);

                let name_style = if *input_mode == AddInputMode::Name {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default().fg(Color::White)
                };
                let value_style = if *input_mode == AddInputMode::Value {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default().fg(Color::White)
                };

                let name_block = Block::default().borders(Borders::ALL).title("Name");
                let value_block = Block::default().borders(Borders::ALL).title("Value");

                let p_name = Paragraph::new(name.as_str())
                    .block(name_block)
                    .style(name_style);
                let p_value = Paragraph::new(value.as_str())
                    .block(value_block)
                    .style(value_style);

                f.render_widget(p_name, chunks[0]);
                f.render_widget(p_value, chunks[1]);

                let help_text = "Tab: Switch field | Enter: Submit | Esc: Cancel";
                let p_help = Paragraph::new(help_text)
                    .style(Style::default().fg(Color::Gray))
                    .alignment(Alignment::Center);
                f.render_widget(p_help, chunks[2]);
            }
            Modal::Edit { name, value } => {
                f.render_widget(block.title("Edit Secret"), area_modal);

                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .margin(2)
                    .constraints([
                        Constraint::Length(3), // Name (read-only)
                        Constraint::Length(3), // Value (editable)
                        Constraint::Min(1),    // Help text
                    ])
                    .split(area_modal);

                let name_block = Block::default()
                    .borders(Borders::ALL)
                    .title("Name (Read-only)");
                let value_block = Block::default().borders(Borders::ALL).title("Value");

                let p_name = Paragraph::new(name.as_str())
                    .block(name_block)
                    .style(Style::default().fg(Color::DarkGray));
                let p_value = Paragraph::new(value.as_str())
                    .block(value_block)
                    .style(Style::default().fg(Color::Yellow));

                f.render_widget(p_name, chunks[0]);
                f.render_widget(p_value, chunks[1]);

                let help_text = "Enter: Save | Esc: Cancel";
                let p_help = Paragraph::new(help_text)
                    .style(Style::default().fg(Color::Gray))
                    .alignment(Alignment::Center);
                f.render_widget(p_help, chunks[2]);
            }
            Modal::ConfirmDelete { name } => {
                let area_confirm = centered_rect(40, 20, area);
                f.render_widget(ratatui::widgets::Clear, area_confirm);
                let block = Block::default()
                    .borders(Borders::ALL)
                    .title("Confirm Delete")
                    .style(Style::default().bg(Color::Red));
                let text = format!(
                    "\nAre you sure you want to delete\n'{}'?\n\n(y) Yes / (n) No",
                    name
                );
                let p = Paragraph::new(text)
                    .block(block)
                    .alignment(Alignment::Center)
                    .style(
                        Style::default()
                            .fg(Color::White)
                            .add_modifier(Modifier::BOLD),
                    );
                f.render_widget(p, area_confirm);
            }
        }
    }
}

/// Helper to center a rect
fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
