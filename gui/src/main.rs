use std::{error::Error, io, path::PathBuf};

use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use gui::{
    app::{
        app::App,
        launch::{clear_screen, run_app},
    },
    utils::{create_directory::init_directory, list_directory_content::list_directory_contents},
};
use tui::{backend::CrosstermBackend, Terminal};

fn main() -> Result<(), Box<dyn Error>> {
    init_directory()?;

    let home_dir = home::home_dir();
    let parent_dir = PathBuf::from(format!("{}/.pgpman", home_dir.unwrap().display()));
    let files: Vec<String> = list_directory_contents(&parent_dir)?;

    // setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // create app and run it
    let app = App::new(parent_dir, files);
    let res = run_app(&mut terminal, app);

    // restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;
    clear_screen();

    if let Err(err) = res {
        println!("{:?}", err)
    }

    Ok(())
}
