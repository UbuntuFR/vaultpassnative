//! Bloc-notes global chiffré — auto-sauvegarde avec debounce 1s.
use gtk4::{glib, prelude::*, ScrolledWindow, TextView, Box as GtkBox, Orientation, Label};
use std::rc::Rc;
use std::cell::RefCell;
use zeroize::Zeroizing;

use crate::crypto::cipher;
use crate::database::store::VaultStore;

pub fn build_notepad(
    store: Rc<VaultStore>,
    key:   Rc<Zeroizing<[u8; 32]>>,
) -> GtkBox {
    let outer = GtkBox::new(Orientation::Vertical, 0);
    outer.set_vexpand(true);
    outer.set_hexpand(true);

    let header = GtkBox::new(Orientation::Horizontal, 8);
    header.set_margin_top(12);
    header.set_margin_bottom(4);
    header.set_margin_start(16);
    header.set_margin_end(16);
    let title = Label::builder()
        .label("Bloc-notes securise")
        .css_classes(["heading"])
        .halign(gtk4::Align::Start)
        .hexpand(true)
        .build();
    let hint = Label::builder()
        .label("Chiffre - sauvegarde automatique")
        .css_classes(["caption", "dim-label"])
        .halign(gtk4::Align::End)
        .build();
    header.append(&title);
    header.append(&hint);
    outer.append(&header);

    let scroll = ScrolledWindow::builder()
        .vexpand(true)
        .hexpand(true)
        .margin_top(4)
        .margin_bottom(16)
        .margin_start(16)
        .margin_end(16)
        .build();

    let textview = TextView::builder()
        .wrap_mode(gtk4::WrapMode::Word)
        .accepts_tab(true)
        .monospace(false)
        .top_margin(12)
        .bottom_margin(12)
        .left_margin(16)
        .right_margin(16)
        .build();
    textview.add_css_class("card");
    textview.set_vexpand(true);

    if let Ok(Some(enc)) = store.load_notepad() {
        if let Ok(plain) = cipher::decrypt(&**key, &enc) {
            if let Ok(text) = std::str::from_utf8(&plain) {
                textview.buffer().set_text(text);
            }
        }
    }

    scroll.set_child(Some(&textview));
    outer.append(&scroll);

    let save_timer_id: Rc<RefCell<Option<glib::SourceId>>> = Rc::new(RefCell::new(None));
    let store_s = store.clone();
    let key_s   = key.clone();

    textview.buffer().connect_changed(move |buf| {
        if let Some(id) = save_timer_id.borrow_mut().take() {
            id.remove();
        }
        let store2   = store_s.clone();
        let key2     = key_s.clone();
        let buf2     = buf.clone();
        let timer_rc = save_timer_id.clone();
        let id = glib::timeout_add_local_once(
            std::time::Duration::from_millis(1000),
            move || {
                let (start, end) = buf2.bounds();
                let text = buf2.text(&start, &end, false).to_string();
                match cipher::encrypt(&**key2, text.as_bytes()) {
                    Ok(enc) => { let _ = store2.save_notepad(&enc); }
                    Err(e)  => glib::g_warning!("vaultpass", "notepad encrypt: {}", e),
                }
                *timer_rc.borrow_mut() = None;
            },
        );
        *save_timer_id.borrow_mut() = Some(id);
    });

    outer
}
