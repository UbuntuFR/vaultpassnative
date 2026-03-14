//! Clipboard auto-clear apres 30 secondes.
use gtk4::glib;
use gdk4::prelude::DisplayExt;
use std::rc::Rc;
use std::cell::Cell;

const CLIPBOARD_CLEAR_DELAY_MS: u32 = 30_000;

/// Copie `text` dans le presse-papier et programme son effacement apres 30s.
/// Chaque nouvel appel annule le timer precedent (via une generation counter).
pub fn copy_with_autoclean(display: &gdk4::Display, text: &str) {
    display.clipboard().set_text(text);

    let clipboard = display.clipboard();
    let text_copy = text.to_string();
    let gen       = Rc::new(Cell::new(0u32));
    let gen_weak  = gen.clone();
    let current   = gen.get().wrapping_add(1);
    gen.set(current);

    glib::timeout_add_local_once(
        std::time::Duration::from_millis(CLIPBOARD_CLEAR_DELAY_MS as u64),
        move || {
            if gen_weak.get() == current {
                // Verifie que le contenu n'a pas change entre-temps
                clipboard.read_text_async(
                    None::<&gio::Cancellable>,
                    glib::clone!(@strong clipboard, @strong text_copy => move |result| {
                        if let Ok(Some(current_text)) = result {
                            if current_text.as_str() == text_copy.as_str() {
                                clipboard.set_text("");
                            }
                        }
                    }),
                );
            }
        },
    );
}
