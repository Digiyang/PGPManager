use crossterm::event::{self, Event, KeyCode};
use tui::{
    backend::Backend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Span, Spans, Text},
    widgets::{Block, BorderType, Borders, Clear, List, ListItem, Paragraph, Wrap},
    Frame, Terminal,
};

use crate::widgets::list::StatefulList;

use super::app::App;

// todo: move the functions to a separate files to make the code more readable widgets folder
pub fn ui<B: Backend>(f: &mut Frame<B>, app: &mut App) {
    if app.help_active {
        draw_help(f, app);
    } else {
        main_window(f, app);
        details_popup(f, app);
    }
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Percentage((100 - percent_y) / 2),
                Constraint::Percentage(percent_y),
                Constraint::Percentage((100 - percent_y) / 2),
            ]
            .as_ref(),
        )
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints(
            [
                Constraint::Percentage((100 - percent_x) / 2),
                Constraint::Percentage(percent_x),
                Constraint::Percentage((100 - percent_x) / 2),
            ]
            .as_ref(),
        )
        .split(popup_layout[1])[1]
}

fn details_popup<B: Backend>(f: &mut Frame<B>, app: &mut App) {
    if let Some(details) = &app.key_details {
        let popup_area = centered_rect(40, 60, f.size());
        let content: Vec<Spans> = details
            .lines()
            .enumerate()
            .map(|(i, line)| {
                if i == app.scroll_state {
                    Spans::from(Span::styled(
                        line,
                        Style::default()
                            .add_modifier(Modifier::BOLD)
                            .fg(Color::White)
                            .bg(Color::Yellow),
                    ))
                } else {
                    Spans::from(Span::styled(line, Style::default().fg(Color::White)))
                }
            })
            .collect();

        f.render_widget(Clear, popup_area);
        f.render_widget(
            Paragraph::new(content)
                .block(
                    Block::default()
                        .title(Span::styled("Details", Style::default().fg(Color::Yellow)))
                        .borders(Borders::ALL),
                )
                .scroll((app.scroll_state.try_into().unwrap(), 0)),
            popup_area,
        );
    }
}

fn main_window<B: Backend>(f: &mut Frame<B>, app: &mut App) {
    let selected_file = app.items.state.selected().unwrap_or(0);
    // Create three chunks
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(2)
        .constraints(
            [
                Constraint::Length(3),
                Constraint::Min(2),
                Constraint::Length(3),
            ]
            .as_ref(),
        )
        .split(f.size());

    let help_text = "Help: Press 'q' to quit, 'Enter' to select a directory, 'Space bar' to go back and 'h' to show the help menu.";
    let help_paragraph = Paragraph::new(Text::styled(help_text, Style::default().fg(Color::White)))
        .block(
            Block::default().title("Help").borders(Borders::ALL).style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
        );
    f.render_widget(help_paragraph, chunks[0]);

    let items: Vec<ListItem> = app
        .items
        .items
        .iter()
        .map(|i| {
            let file_name = i
                .split('/') // Replace with '\\' on Windows
                .last()
                .unwrap_or(i);
            let lines = vec![Spans::from(file_name)];
            ListItem::new(lines).style(Style::default().fg(Color::White))
        })
        .collect();

    // Create a List from all list items and highlight the currently selected one
    let items = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Directories")
                .style(
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
        )
        .highlight_style(
            Style::default()
                .bg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");
    // We can now render the item list
    f.render_stateful_widget(items, chunks[1], &mut app.items.state);
    let selected_file_name = app
        .items
        .items
        .get(selected_file)
        .map(|s| s.as_str())
        .unwrap_or("");

    let current_file_widget = Paragraph::new(Text::styled(
        selected_file_name,
        Style::default().fg(Color::White),
    ))
    .block(
        Block::default()
            .title("Current File")
            .borders(Borders::ALL)
            .style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
    );
    f.render_widget(current_file_widget, chunks[2]);
}

pub fn draw_input_prompt<B: Backend>(
    terminal: &mut Terminal<B>,
    prompt: &[Spans],
    display_input: bool,
) -> Result<String, anyhow::Error> {
    let mut input = String::new();

    loop {
        terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(2)
                .constraints([Constraint::Percentage(0), Constraint::Length(3)].as_ref())
                .split(f.size());

            let input_text = if display_input {
                input.clone()
            } else {
                "*".repeat(input.len())
            };

            let input_span = Span::styled(
                &input_text,
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            );

            let prompt_text = prompt
                .iter()
                .map(|spans| spans.clone())
                .chain(std::iter::once(Spans::from(input_span)))
                .collect::<Vec<Spans>>();

            let input_widget = Paragraph::new(prompt_text)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title("User Input")
                        .style(
                            Style::default()
                                .fg(Color::Yellow)
                                .add_modifier(Modifier::BOLD),
                        ),
                )
                .wrap(Wrap { trim: true });

            f.render_widget(Clear, f.size());
            f.render_widget(input_widget, chunks[1]);
        })?;

        if let Event::Key(key_event) = event::read()? {
            match key_event.code {
                KeyCode::Char(c) => {
                    input.push(c);
                }
                KeyCode::Enter => {
                    break;
                }
                KeyCode::Backspace => {
                    input.pop();
                }
                KeyCode::Esc => {
                    return Err(anyhow::anyhow!("OperationCanceled"));
                }
                _ => {}
            }
        }
    }

    Ok(input)
}

pub fn show_input_popup<B: Backend>(
    terminal: &mut Terminal<B>,
    message: &str,
) -> Result<(), anyhow::Error> {
    let popup = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow));

    let text = Text::from(Spans::from(Span::styled(
        message,
        Style::default().fg(Color::White),
    )));

    terminal.draw(|f| {
        let rect = centered_rect(30, 20, f.size());
        let inner_rect = Rect::new(rect.x + 1, rect.y + 1, rect.width - 2, rect.height - 2);
        f.render_widget(Clear, rect);
        f.render_widget(popup, rect);
        let paragraph = Paragraph::new(text).wrap(Wrap { trim: true });
        f.render_widget(paragraph, inner_rect);
    })?;

    // Wait for any key press to close the popup.
    loop {
        if let Event::Key(_) = event::read()? {
            break;
        }
    }

    Ok(())
}

pub fn show_user_selection_popup<B: Backend>(
    terminal: &mut Terminal<B>,
    users: &mut StatefulList<String>,
    selected_items: &mut Vec<bool>,
) -> Result<Option<bool>, anyhow::Error> {
    loop {
        terminal.draw(|f| {
            let popup_area = centered_rect(60, 60, f.size());
            let block = Block::default()
                .title("User Selection")
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .style(Style::default().add_modifier(Modifier::BOLD));

            let mut lines = Vec::new();
            for (index, user) in users.items.iter().enumerate() {
                let checkbox = if selected_items[index] { "[x]" } else { "[ ]" };
                let user_span = if users.state.selected() == Some(index) {
                    Span::styled(
                        format!("{} {}", checkbox, user),
                        Style::default().fg(Color::Black).bg(Color::Yellow),
                    )
                } else {
                    Span::styled(
                        format!("{} {}", checkbox, user),
                        Style::default().fg(Color::White),
                    )
                };
                lines.push(Spans::from(user_span));
            }

            let paragraph = Paragraph::new(lines)
                .block(block)
                .style(Style::default().fg(Color::Yellow))
                .alignment(Alignment::Left)
                .wrap(Wrap { trim: true });

            f.render_widget(paragraph, popup_area);
        })?;

        if let Event::Key(key_event) = event::read()? {
            match key_event.code {
                KeyCode::Enter => {
                    return Ok(Some(true));
                }
                KeyCode::Up => {
                    users.previous();
                }
                KeyCode::Down => {
                    users.next();
                }
                KeyCode::Char(' ') => {
                    if let Some(index) = users.state.selected() {
                        selected_items[index] = !selected_items[index];
                    }
                }
                KeyCode::Esc => {
                    return Ok(None);
                }
                _ => {}
            }
        }
    }
    //Ok(None)
}

fn draw_help<B: Backend>(f: &mut Frame<B>, app: &mut App) {
    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .margin(1)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)].as_ref())
        .split(f.size());

    let left_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(70), Constraint::Percentage(30)].as_ref())
        .split(main_chunks[0]);

    let help_list_items: Vec<ListItem> = app
        .help_items
        .items
        .iter()
        .map(|i| ListItem::new(Text::from(i.clone())).style(Style::default().fg(Color::White)))
        .collect();

    let help_list = List::new(help_list_items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(Spans::from(vec![Span::styled(
                    "Help",
                    Style::default().fg(Color::Yellow),
                )])),
        )
        .highlight_style(Style::default().bg(Color::Yellow).fg(Color::Black))
        .highlight_symbol("> ");

    f.render_stateful_widget(help_list, left_chunks[0], &mut app.help_items.state);

    let selected_help_text = app
        .help_items
        .selected()
        .map(|s| {
            app.help_descriptions
                .get(s)
                .unwrap_or(&String::new())
                .clone()
        })
        .unwrap_or_else(|| String::new());

    let help_description = Paragraph::new(selected_help_text.as_str())
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(Spans::from(vec![Span::styled(
                    "Command description",
                    Style::default().fg(Color::Yellow),
                )])),
        )
        .style(Style::default().fg(Color::White));

    f.render_widget(help_description, left_chunks[1]);

    let right_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(30), Constraint::Percentage(70)].as_ref())
        .split(main_chunks[1]);

    let banner_text = r#"
     ____   ____ ____
    |  _ \ / ___|  _ \ _ __ ___   __ _ _ __   __ _  __ _  ___ _ __
    | |_) | |  _| |_) | '_ ` _ \ / _` | '_ \ / _` |/ _` |/ _ | '__|
    |  __/| |_| |  __/| | | | | | (_| | | | | (_| | (_| |  __| |
    |_|    \____|_|   |_| |_| |_|\__,_|_| |_|\__,_|\__, |\___|_|
                                                   |___/
    "#;

    let banner_widget = Paragraph::new(Text::styled(
        banner_text,
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    ))
    .block(
        Block::default()
            .title(Span::styled("Banner", Style::default().fg(Color::Yellow)))
            .borders(Borders::ALL),
    );
    f.render_widget(banner_widget, right_chunks[0]);

    let contact_text = "\
Contact Information:
Name: Moez Rjiba
Email: Zeom@proton.me
Website: https://github.com/Digiyang";

    let contact_widget = Paragraph::new(Text::styled(
        contact_text,
        Style::default().fg(Color::White),
    ))
    .block(
        Block::default()
            .title(Span::styled("Contact", Style::default().fg(Color::Yellow)))
            .borders(Borders::ALL),
    );
    f.render_widget(contact_widget, right_chunks[1]);
}
