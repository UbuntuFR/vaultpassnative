//! Struct contexte partag\u00e9 dans tout le vault.
use std::cell::RefCell;
use std::rc::Rc;
use zeroize::Zeroizing;
use libadwaita::{Banner, ToastOverlay};
use libadwaita::prelude::*;
use gtk4::prelude::WidgetExt;
use crate::database::{store::VaultStore, models::VaultEntry};

#[derive(Clone)]
pub struct VaultContext {
    pub store:        Rc<VaultStore>,
    pub key:          Rc<Zeroizing<[u8; 32]>>,
    pub db_entries:   Rc<RefCell<Vec<VaultEntry>>>,
    pub entries_list: gtk4::ListBox,
    pub banner:       Banner,
    pub toast:        ToastOverlay,
    pub empty_page:   libadwaita::StatusPage,
}

impl VaultContext {
    pub fn new(
        store:        Rc<VaultStore>,
        key:          Rc<Zeroizing<[u8; 32]>>,
        db_entries:   Rc<RefCell<Vec<VaultEntry>>>,
        entries_list: gtk4::ListBox,
        banner:       Banner,
        toast:        ToastOverlay,
        empty_page:   libadwaita::StatusPage,
    ) -> Self {
        Self { store, key, db_entries, entries_list, banner, toast, empty_page }
    }

    pub fn refresh_banner(&self) {
        let n = self.db_entries.borrow().len();
        self.banner.set_title(&format!(
            "\u{1F510} {} entr\u00e9e{}", n, if n != 1 { "s" } else { "" }
        ));
    }

    pub fn refresh_empty_state(&self) {
        let n = self.db_entries.borrow().len();
        self.empty_page.set_visible(n == 0);
        self.entries_list.set_visible(n > 0);
    }
}
