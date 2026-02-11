use ratatui::widgets::ListState;
#[derive(Debug)]
pub struct StatefulList<T> {
    pub items: Vec<T>,
    pub state: ListState,
    pub selected_items: Vec<bool>,
}

impl<T> StatefulList<T> {
    pub fn new(items: Vec<T>, state: ListState, selected_items: Vec<bool>) -> StatefulList<T> {
        Self {
            items,
            state,
            selected_items,
        }
    }

    /// Construct a new `StatefulList` with given items.
    pub fn with_items(items: Vec<T>) -> StatefulList<T> {
        let selected_items = vec![false; items.len()];
        Self::new(items, ListState::default(), selected_items)
    }

    /// Returns the selected item.
    pub fn selected(&self) -> Option<&T> {
        self.items.get(self.state.selected()?)
    }

    /// Selects the next item.
    pub fn next(&mut self) {
        let i = match self.state.selected() {
            Some(i) => {
                if i >= self.items.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
    }

    /// Selects the previous item.
    pub fn previous(&mut self) {
        let i = match self.state.selected() {
            Some(i) => {
                if i == 0 {
                    self.items.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
    }

    pub fn unselect(&mut self) {
        self.state.select(None);
    }
}
