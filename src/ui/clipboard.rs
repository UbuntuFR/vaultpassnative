//! Clipboard auto-clear après 30 secondes.
use gtk4::glib;
use gdk4::prelude::DisplayExt;

const CLIPBOARD_CLEAR_DELAY_MS: u64 = 30_000;

pub fn copy_with_autoclean(display: &gdk4::Display, text: &str) {
    let clipboard = display.clipboard();
    clipboard.set_text(text);

    let text_owned = text.to_string();
    let clipboard2 = clipboard.clone();

    glib::timeout_add_local_once(
        std::time::Duration::from_millis(CLIPBOARD_CLEAR_DELAY_MS),
        move || {
            let clipboard3 = clipboard2.clone();
            clipboard2.read_text_async(
                gtk4::gio::Cancellable::NONE,
                move |result| {
                    if let Ok(Some(current)) = result {
                        if current.as_str() == text_owned.as_str() {
                            clipboard3.set_text("");
                        }
                    }
                },
            );
        },
    );
}
