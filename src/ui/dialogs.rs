use libadwaita::prelude::*;
use libadwaita::{
    Dialog as AdwDialog, AlertDialog,
    EntryRow, PasswordEntryRow,
};
use gtk4::{
    Box as GtkBox, Orientation, Button, Label,

};
use std::rc::Rc;
use std::cell::RefCell;

use crate::crypto::cipher;
use crate::database::{store::VaultStore, models::VaultEntry as DbEntry};
use crate::ui::generator::GeneratorConfig;
use crate::now_unix;
use uuid::Uuid;

// ─────────────────────────────────────────────────────────────────────
// DIALOGUE NOUVELLE ENTRÉE — AdwDialog moderne
// ─────────────────────────────────────────────────────────────────────
pub fn show_add_dialog(
    parent:     &impl IsA<gtk4::Widget>,
    store:      Rc<VaultStore>,
    key:        Rc<[u8; 32]>,
    list:       gtk4::ListBox,
    db_entries: Rc<RefCell<Vec<DbEntry>>>,
    banner:     libadwaita::Banner,
) {
    // AdwDialog : widget natif GNOME 49, remplace gtk4::Dialog
    // 🦀 CONCEPT — IsA<T> : trait bound GTK.
    // Signifie "tout widget qui EST un GtkWidget ou dérive de lui".
    // Permet d'accepter Window, ApplicationWindow, etc. sans surcharge.
    let dialog = AdwDialog::builder()
        .title("Nouvelle entrée")
        .content_width(420)
        .build();

    let toolbar = libadwaita::ToolbarView::new();
    let header  = libadwaita::HeaderBar::new();
    toolbar.add_top_bar(&header);

    let vbox = GtkBox::new(Orientation::Vertical, 12);
    vbox.set_margin_top(16); vbox.set_margin_bottom(16);
    vbox.set_margin_start(16); vbox.set_margin_end(16);

    // AdwEntryRow : champs intégrés style GNOME natif
    let f_title = EntryRow::builder().title("Titre").build();
    let f_user  = EntryRow::builder().title("Identifiant / Email").build();
    let f_pass  = PasswordEntryRow::builder().title("Mot de passe").build();
    let f_url   = EntryRow::builder().title("URL (optionnel)").build();
    let f_cat   = EntryRow::builder().title("Catégorie : Pro / Perso / Finance").build();

    // Bouton générer mot de passe
    let gen_btn = Button::with_label("🎲 Générer");
    gen_btn.add_css_class("suggested-action");
    gen_btn.set_margin_top(4);
    let fp = f_pass.clone();
    gen_btn.connect_clicked(move |_| {
        fp.set_text(&GeneratorConfig::default().generate());
    });

    // ListBox style "boxed-list" pour les champs — look Préférences GNOME
    let fields_box = gtk4::ListBox::new();
    fields_box.add_css_class("boxed-list");
    fields_box.append(&f_title);
    fields_box.append(&f_user);
    fields_box.append(&f_pass);
    fields_box.append(&f_url);
    fields_box.append(&f_cat);

    vbox.append(&fields_box);
    vbox.append(&gen_btn);

    // Boutons action
    let btn_row = GtkBox::new(Orientation::Horizontal, 8);
    btn_row.set_margin_top(8);
    btn_row.set_homogeneous(true);
    let cancel_btn = Button::with_label("Annuler");
    let add_btn    = Button::with_label("➕ Ajouter");
    add_btn.add_css_class("suggested-action");
    btn_row.append(&cancel_btn);
    btn_row.append(&add_btn);
    vbox.append(&btn_row);

    toolbar.set_content(Some(&vbox));
    dialog.set_child(Some(&toolbar));
    dialog.present(Some(parent));

    let dlg_cancel = dialog.clone();
    cancel_btn.connect_clicked(move |_| { dlg_cancel.close(); });

    let dlg_add = dialog.clone();
    dialog.connect_closed(|_| {}); // hook si besoin

    add_btn.connect_clicked(move |_| {
        let title    = f_title.text().to_string();
        let username = f_user.text().to_string();
        let password = f_pass.text().to_string();
        let url_str  = f_url.text().to_string();
        let category = { let c = f_cat.text().to_string();
            if c.is_empty() { "Général".to_string() } else { c } };

        if title.is_empty() || password.is_empty() {
            eprintln!("⚠️ Titre et mot de passe obligatoires");
            dlg_add.close(); return;
        }

        match cipher::encrypt(&key, password.as_bytes()) {
            Ok(encrypted) => {
                let new_entry = DbEntry {
                    id: Uuid::new_v4().to_string(),
                    title: title.clone(), username: username.clone(),
                    password_encrypted: encrypted,
                    url: if url_str.is_empty() { None } else { Some(url_str) },
                    category: category.clone(),
                    notes_encrypted: None,
                    created_at: now_unix(), updated_at: now_unix(),
                };
                match store.insert_entry(&new_entry) {
                    Ok(_) => {
                        // Ligne UI
                        let row_box = GtkBox::new(Orientation::Horizontal, 12);
                        row_box.set_margin_top(10); row_box.set_margin_bottom(10);
                        row_box.set_margin_start(8); row_box.set_margin_end(8);
                        row_box.append(&Label::new(Some("🔑")));
                        let tc = GtkBox::new(Orientation::Vertical, 2);
                        tc.append(&Label::builder().label(title.as_str())
                            .halign(gtk4::Align::Start).css_classes(["heading"]).build());
                        tc.append(&Label::builder().label(username.as_str())
                            .halign(gtk4::Align::Start)
                            .css_classes(["caption","dim-label"]).build());
                        tc.set_hexpand(true);
                        row_box.append(&tc);
                        let cl = Label::new(Some(&category));
                        cl.add_css_class("tag");
                        row_box.append(&cl);
                        let row = gtk4::ListBoxRow::new();
                        row.set_child(Some(&row_box));
                        list.append(&row);

                        db_entries.borrow_mut().push(new_entry);
                        let count = db_entries.borrow().len();
                        banner.set_title(&format!(
                            "🔐 {} entrées — AES-256-GCM + Argon2id", count
                        ));
                        println!("✅ '{}' ajouté", title);
                        dlg_add.close();
                    }
                    Err(e) => eprintln!("❌ SQLite : {e}"),
                }
            }
            Err(e) => eprintln!("❌ Chiffrement : {e}"),
        }
    });
}

// ─────────────────────────────────────────────────────────────────────
// DIALOGUE CONFIRMATION SUPPRESSION — AdwAlertDialog
// ─────────────────────────────────────────────────────────────────────
pub fn show_delete_confirm(
    parent:    &impl IsA<gtk4::Widget>,
    title:     &str,
    on_confirm: impl Fn() + 'static,
) {
    // AdwAlertDialog : dialogue de confirmation natif GNOME 49
    let alert = AlertDialog::builder()
        .heading(&format!("Supprimer \"{}\" ?", title))
        .body("Cette action est irréversible. L'entrée sera définitivement effacée.")
        .default_response("cancel")
        .close_response("cancel")
        .build();

    alert.add_response("cancel", "Annuler");
    alert.add_response("delete", "Supprimer");
    alert.set_response_appearance("delete", libadwaita::ResponseAppearance::Destructive);

    alert.connect_response(None, move |_, response| {
        if response == "delete" {
            on_confirm();
        }
    });

    alert.present(Some(parent));
}
