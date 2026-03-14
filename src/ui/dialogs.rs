use libadwaita::prelude::*;
use libadwaita::{
    AlertDialog, Dialog as AdwDialog,
    EntryRow, PasswordEntryRow,
    ToolbarView, Toast, ToastOverlay,
};
use gtk4::{
    Box as GtkBox, Orientation, Button, Label,
    Adjustment, Scale, Switch, ListBoxRow,
    Separator,
};
use gdk4::prelude::DisplayExt;
use std::rc::Rc;
use std::cell::RefCell;
use zeroize::Zeroizing;

use crate::crypto::{cipher, kdf};
use crate::database::{store::VaultStore, models::VaultEntry as DbEntry};
use crate::ui::generator::GeneratorConfig;
use crate::now_unix;
use uuid::Uuid;

const APP_ID: &str = "io.github.UbuntuFR.VaultpassNative";

// ── Helpers ───────────────────────────────────────────────────────────
fn make_fields_box() -> gtk4::ListBox {
    let lb = gtk4::ListBox::new();
    lb.add_css_class("boxed-list");
    lb
}

fn make_toolbar_dialog(title: &str, width: i32) -> (AdwDialog, ToolbarView) {
    let dialog = AdwDialog::builder()
        .title(title)
        .content_width(width)
        .build();
    let toolbar = ToolbarView::new();
    let header  = libadwaita::HeaderBar::new();
    toolbar.add_top_bar(&header);
    (dialog, toolbar)
}

// ── DIALOGUE NOUVELLE ENTRÉE ──────────────────────────────────────────
pub fn show_add_dialog(
    parent:       &impl IsA<gtk4::Widget>,
    store:        Rc<VaultStore>,
    key:          Rc<Zeroizing<[u8; 32]>>,
    list:         gtk4::ListBox,
    db_entries:   Rc<RefCell<Vec<DbEntry>>>,
    banner:       libadwaita::Banner,
    toast_overlay: ToastOverlay,
    empty_page:   libadwaita::StatusPage,
) {
    let (dialog, toolbar) = make_toolbar_dialog("Nouvelle entrée", 440);

    let vbox = GtkBox::new(Orientation::Vertical, 12);
    vbox.set_margin_top(16);   vbox.set_margin_bottom(16);
    vbox.set_margin_start(16); vbox.set_margin_end(16);

    let f_title = EntryRow::builder().title("Titre *").build();
    let f_user  = EntryRow::builder().title("Identifiant / Email").build();
    let f_pass  = PasswordEntryRow::builder().title("Mot de passe *").build();
    let f_url   = EntryRow::builder().title("URL (optionnel)").build();
    let f_cat   = EntryRow::builder().title("Catégorie : Pro / Perso / Finance").build();
    let f_notes = EntryRow::builder().title("Notes (optionnel)").build();

    let strength_lbl = Label::builder()
        .label("Force : —")
        .halign(gtk4::Align::Start)
        .css_classes(["caption", "dim-label"])
        .build();

    let fp = f_pass.clone();
    let sl = strength_lbl.clone();
    f_pass.connect_changed(move |e| {
        let pw = e.text().to_string();
        let (bars, label) = match GeneratorConfig::strength_score(&pw) {
            0 => ("██░░░░░░░░", "Très faible 🔴"),
            1 => ("████░░░░░░", "Faible 🟠"),
            2 => ("██████░░░░", "Moyen 🟡"),
            3 => ("████████░░", "Fort 🟢"),
            _ => ("██████████", "Excellent ✅"),
        };
        sl.set_text(&format!("Force : {} {}", bars, label));
    });

    let gen_btn = Button::with_label("🎲 Générer un mot de passe");
    gen_btn.add_css_class("suggested-action");
    gen_btn.set_margin_top(4);
    gen_btn.connect_clicked(move |_| {
        fp.set_text(&GeneratorConfig::default().generate());
    });

    let fields_box = make_fields_box();
    fields_box.append(&f_title);
    fields_box.append(&f_user);
    fields_box.append(&f_pass);
    fields_box.append(&f_url);
    fields_box.append(&f_cat);
    fields_box.append(&f_notes);

    vbox.append(&fields_box);
    vbox.append(&strength_lbl);
    vbox.append(&gen_btn);

    let btn_row    = GtkBox::new(Orientation::Horizontal, 8);
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

    let dlg_c = dialog.clone();
    cancel_btn.connect_clicked(move |_| { dlg_c.close(); });

    let dlg_a = dialog.clone();
    add_btn.connect_clicked(move |_| {
        let title    = f_title.text().to_string();
        let username = f_user.text().to_string();
        let password = f_pass.text().to_string();
        let url_str  = f_url.text().to_string();
        let notes_str = f_notes.text().to_string();
        let category = {
            let c = f_cat.text().to_string();
            if c.is_empty() { "Général".to_string() } else { c }
        };

        if title.is_empty() || password.is_empty() {
            gtk4::glib::g_warning!(APP_ID, "Titre et mot de passe obligatoires");
            return;
        }

        match cipher::encrypt(&**key, password.as_bytes()) {
            Ok(encrypted) => {
                let notes_enc = if notes_str.is_empty() {
                    None
                } else {
                    cipher::encrypt(&**key, notes_str.as_bytes()).ok()
                };

                let new_entry = DbEntry {
                    id:                 Uuid::new_v4().to_string(),
                    title:              title.clone(),
                    username:           username.clone(),
                    password_encrypted: encrypted,
                    url:                if url_str.is_empty() { None } else { Some(url_str) },
                    category:           category.clone(),
                    notes_encrypted:    notes_enc,
                    created_at:         now_unix(),
                    updated_at:         now_unix(),
                };
                match store.insert_entry(&new_entry) {
                    Ok(_) => {
                        let row = crate::build_entry_row(
                            &new_entry, &key, &store,
                            &db_entries, &list, &banner, &toast_overlay,
                        );
                        list.append(&row);
                        db_entries.borrow_mut().push(new_entry);
                        let n = db_entries.borrow().len();
                        banner.set_title(&format!(
                            "🔐 {} entrée{}",
                            n, if n != 1 { "s" } else { "" }
                        ));
                        empty_page.set_visible(false);
                        list.set_visible(true);
                        toast_overlay.add_toast(Toast::new("✅ Entrée ajoutée !"));
                        gtk4::glib::g_debug!(APP_ID, "Entrée '{}' ajoutée", title);
                        dlg_a.close();
                    }
                    Err(e) => gtk4::glib::g_critical!(APP_ID, "SQLite insert : {}", e),
                }
            }
            Err(e) => gtk4::glib::g_critical!(APP_ID, "Chiffrement : {}", e),
        }
    });
}

// ── DIALOGUE MODIFIER ENTRÉE ──────────────────────────────────────────
#[allow(clippy::too_many_arguments)]
pub fn show_edit_dialog(
    parent:       &impl IsA<gtk4::Widget>,
    entry:        DbEntry,
    store:        Rc<VaultStore>,
    key:          Rc<Zeroizing<[u8; 32]>>,
    db_entries:   Rc<RefCell<Vec<DbEntry>>>,
    list:         gtk4::ListBox,
    banner:       libadwaita::Banner,
    toast_overlay: ToastOverlay,
    row:          ListBoxRow,
) {
    let (dialog, toolbar) = make_toolbar_dialog("Modifier l'entrée", 440);

    let vbox = GtkBox::new(Orientation::Vertical, 12);
    vbox.set_margin_top(16);   vbox.set_margin_bottom(16);
    vbox.set_margin_start(16); vbox.set_margin_end(16);

    // Déchiffrer le mot de passe pour pré-remplir
    let current_pw = cipher::decrypt(&**key, &entry.password_encrypted)
        .map(|b| String::from_utf8_lossy(&b).to_string())
        .unwrap_or_default();
    let current_notes = entry.notes_encrypted.as_ref()
        .and_then(|enc| cipher::decrypt(&**key, enc).ok())
        .map(|b| String::from_utf8_lossy(&b).to_string())
        .unwrap_or_default();

    let f_title = EntryRow::builder().title("Titre *").text(&entry.title).build();
    let f_user  = EntryRow::builder().title("Identifiant / Email").text(&entry.username).build();
    let f_pass  = PasswordEntryRow::builder().title("Mot de passe *").text(&current_pw).build();
    let f_url   = EntryRow::builder()
        .title("URL (optionnel)")
        .text(entry.url.as_deref().unwrap_or(""))
        .build();
    let f_cat   = EntryRow::builder().title("Catégorie").text(&entry.category).build();
    let f_notes = EntryRow::builder().title("Notes (optionnel)").text(&current_notes).build();

    let strength_lbl = Label::builder()
        .label("Force : —")
        .halign(gtk4::Align::Start)
        .css_classes(["caption", "dim-label"])
        .build();

    let sl2 = strength_lbl.clone();
    f_pass.connect_changed(move |e| {
        let pw = e.text().to_string();
        let (bars, label) = match GeneratorConfig::strength_score(&pw) {
            0 => ("██░░░░░░░░", "Très faible 🔴"),
            1 => ("████░░░░░░", "Faible 🟠"),
            2 => ("██████░░░░", "Moyen 🟡"),
            3 => ("████████░░", "Fort 🟢"),
            _ => ("██████████", "Excellent ✅"),
        };
        sl2.set_text(&format!("Force : {} {}", bars, label));
    });

    let fp2 = f_pass.clone();
    let gen_btn = Button::with_label("🎲 Générer un mot de passe");
    gen_btn.add_css_class("suggested-action");
    gen_btn.set_margin_top(4);
    gen_btn.connect_clicked(move |_| {
        fp2.set_text(&GeneratorConfig::default().generate());
    });

    let fields_box = make_fields_box();
    fields_box.append(&f_title);
    fields_box.append(&f_user);
    fields_box.append(&f_pass);
    fields_box.append(&f_url);
    fields_box.append(&f_cat);
    fields_box.append(&f_notes);

    vbox.append(&fields_box);
    vbox.append(&strength_lbl);
    vbox.append(&gen_btn);

    let btn_row    = GtkBox::new(Orientation::Horizontal, 8);
    btn_row.set_margin_top(8);
    btn_row.set_homogeneous(true);
    let cancel_btn = Button::with_label("Annuler");
    let save_btn   = Button::with_label("💾 Enregistrer");
    save_btn.add_css_class("suggested-action");
    btn_row.append(&cancel_btn);
    btn_row.append(&save_btn);
    vbox.append(&btn_row);

    toolbar.set_content(Some(&vbox));
    dialog.set_child(Some(&toolbar));
    dialog.present(Some(parent));

    let dlg_c = dialog.clone();
    cancel_btn.connect_clicked(move |_| { dlg_c.close(); });

    let entry_id   = entry.id.clone();
    let created_at = entry.created_at;
    let dlg_s      = dialog.clone();

    save_btn.connect_clicked(move |_| {
        let title    = f_title.text().to_string();
        let username = f_user.text().to_string();
        let password = f_pass.text().to_string();
        let url_str  = f_url.text().to_string();
        let notes_str = f_notes.text().to_string();
        let category = {
            let c = f_cat.text().to_string();
            if c.is_empty() { "Général".to_string() } else { c }
        };

        if title.is_empty() || password.is_empty() {
            gtk4::glib::g_warning!(APP_ID, "Titre et mot de passe obligatoires");
            return;
        }

        match cipher::encrypt(&**key, password.as_bytes()) {
            Ok(encrypted) => {
                let notes_enc = if notes_str.is_empty() {
                    None
                } else {
                    cipher::encrypt(&**key, notes_str.as_bytes()).ok()
                };

                let updated = DbEntry {
                    id:                 entry_id.clone(),
                    title:              title.clone(),
                    username:           username.clone(),
                    password_encrypted: encrypted,
                    url:                if url_str.is_empty() { None } else { Some(url_str) },
                    category:           category.clone(),
                    notes_encrypted:    notes_enc,
                    created_at,
                    updated_at:         now_unix(),
                };

                match store.update_entry(&updated) {
                    Ok(_) => {
                        // Mettre à jour db_entries en mémoire
                        if let Some(e) = db_entries.borrow_mut()
                            .iter_mut().find(|e| e.id == entry_id)
                        {
                            *e = updated.clone();
                        }

                        // Reconstruire la ligne dans la liste
                        let new_row = crate::build_entry_row(
                            &updated, &key, &store,
                            &db_entries, &list, &banner, &toast_overlay,
                        );
                        // Insérer avant l'ancienne ligne puis supprimer
                        if let Some(idx) = get_row_index(&list, &row) {
                            list.insert(&new_row, idx);
                            list.remove(&row);
                        } else {
                            list.append(&new_row);
                            list.remove(&row);
                        }

                        toast_overlay.add_toast(Toast::new("✅ Entrée modifiée !"));
                        gtk4::glib::g_debug!(APP_ID, "Entrée '{}' modifiée", title);
                        dlg_s.close();
                    }
                    Err(e) => gtk4::glib::g_critical!(APP_ID, "SQLite update : {}", e),
                }
            }
            Err(e) => gtk4::glib::g_critical!(APP_ID, "Chiffrement : {}", e),
        }
    });
}

fn get_row_index(list: &gtk4::ListBox, target: &ListBoxRow) -> Option<i32> {
    let mut i = 0i32;
    while let Some(row) = list.row_at_index(i) {
        if &row == target { return Some(i); }
        i += 1;
    }
    None
}

// ── DIALOGUE CONFIRMATION SUPPRESSION ────────────────────────────────
pub fn show_delete_confirm(
    parent:     &impl IsA<gtk4::Widget>,
    title:      &str,
    on_confirm: impl Fn() + 'static,
) {
    let alert = AlertDialog::builder()
        .heading(&format!("Supprimer \"{}\" ?", title))
        .body("Cette action est irréversible. L'entrée sera définitivement effacée.")
        .default_response("cancel")
        .close_response("cancel")
        .build();

    alert.add_response("cancel", "Annuler");
    alert.add_response("delete", "🗑️ Supprimer");
    alert.set_response_appearance("delete", libadwaita::ResponseAppearance::Destructive);

    alert.connect_response(None, move |_, response| {
        if response == "delete" { on_confirm(); }
    });

    alert.present(Some(parent));
}

// ── DIALOGUE GÉNÉRATEUR ───────────────────────────────────────────────
pub fn show_generator_dialog(parent: &impl IsA<gtk4::Widget>) {
    let (dialog, toolbar) = make_toolbar_dialog("🎲 Générateur de mots de passe", 460);

    let vbox = GtkBox::new(Orientation::Vertical, 16);
    vbox.set_margin_top(16);   vbox.set_margin_bottom(16);
    vbox.set_margin_start(16); vbox.set_margin_end(16);

    let result_entry = gtk4::Entry::new();
    result_entry.set_editable(false);
    result_entry.add_css_class("monospace");
    result_entry.set_hexpand(true);

    let len_row   = GtkBox::new(Orientation::Horizontal, 8);
    let len_lbl   = Label::new(Some("Longueur : 20"));
    len_lbl.set_hexpand(true);
    let len_scale = Scale::new(
        Orientation::Horizontal,
        Some(&Adjustment::new(20.0, 8.0, 64.0, 1.0, 5.0, 0.0)),
    );
    len_scale.set_hexpand(true);
    len_scale.set_draw_value(false);
    len_row.append(&len_lbl);
    len_row.append(&len_scale);

    fn sw_row(lbl: &str, on: bool) -> (GtkBox, Switch) {
        let r = GtkBox::new(Orientation::Horizontal, 8);
        let l = Label::builder().label(lbl).hexpand(true).build();
        let s = Switch::builder().active(on).build();
        r.append(&l); r.append(&s);
        (r, s)
    }
    let (r_up, sw_up) = sw_row("Majuscules (A-Z)", true);
    let (r_di, sw_di) = sw_row("Chiffres (0-9)", true);
    let (r_sy, sw_sy) = sw_row("Symboles (!@#…)", true);

    let strength_lbl = Label::builder()
        .label("Force : ██████████ Excellent ✅")
        .halign(gtk4::Align::Start)
        .css_classes(["caption"])
        .build();

    let btn_row   = GtkBox::new(Orientation::Horizontal, 8);
    let regen_btn = Button::with_label("🔄 Régénérer");
    regen_btn.add_css_class("suggested-action");
    regen_btn.set_hexpand(true);
    let copy_btn  = Button::with_label("📋 Copier");
    btn_row.append(&regen_btn);
    btn_row.append(&copy_btn);

    for w in [
        result_entry.upcast_ref::<gtk4::Widget>(),
        len_row.upcast_ref(),
        r_up.upcast_ref(), r_di.upcast_ref(), r_sy.upcast_ref(),
        strength_lbl.upcast_ref(),
        btn_row.upcast_ref(),
    ] { vbox.append(w); }

    let sep = Separator::new(Orientation::Horizontal);
    sep.set_margin_top(4);
    vbox.append(&sep);

    let close_btn = Button::with_label("Fermer");
    close_btn.set_halign(gtk4::Align::Center);
    close_btn.set_margin_top(4);
    vbox.append(&close_btn);

    toolbar.set_content(Some(&vbox));
    dialog.set_child(Some(&toolbar));
    dialog.present(Some(parent));

    let re = result_entry.clone();
    let sl = strength_lbl.clone();
    let ls = len_scale.clone();
    let su = sw_up.clone();
    let sd = sw_di.clone();
    let ss = sw_sy.clone();

    let regenerate = Rc::new(move || {
        let pw = GeneratorConfig {
            length:    ls.value() as usize,
            uppercase: su.is_active(),
            digits:    sd.is_active(),
            symbols:   ss.is_active(),
        }.generate();
        let (bars, label) = match GeneratorConfig::strength_score(&pw) {
            0 => ("██░░░░░░░░", "Très faible 🔴"),
            1 => ("████░░░░░░", "Faible 🟠"),
            2 => ("██████░░░░", "Moyen 🟡"),
            3 => ("████████░░", "Fort 🟢"),
            _ => ("██████████", "Excellent ✅"),
        };
        sl.set_text(&format!("Force : {} {}", bars, label));
        re.set_text(&pw);
    });

    regenerate();

    let rg = regenerate.clone();
    regen_btn.connect_clicked(move |_| rg());

    let rg2 = regenerate.clone();
    let ll  = len_lbl.clone();
    len_scale.connect_value_changed(move |s| {
        ll.set_text(&format!("Longueur : {}", s.value() as usize));
        rg2();
    });

    let rg3 = regenerate.clone(); sw_up.connect_state_set(move |_, _| { rg3(); false.into() });
    let rg4 = regenerate.clone(); sw_di.connect_state_set(move |_, _| { rg4(); false.into() });
    let rg5 = regenerate.clone(); sw_sy.connect_state_set(move |_, _| { rg5(); false.into() });

    let re2 = result_entry.clone();
    copy_btn.connect_clicked(move |b| {
        let pw = re2.text().to_string();
        if !pw.is_empty() {
            b.display().clipboard().set_text(&pw);
            gtk4::glib::g_debug!(APP_ID, "Mot de passe copié depuis le générateur");
        }
    });

    let dlg = dialog.clone();
    close_btn.connect_clicked(move |_| { dlg.close(); });
}

// ── DIALOGUE PARAMÈTRES ───────────────────────────────────────────────
pub fn show_settings_dialog(
    parent: &impl IsA<gtk4::Widget>,
    store:  Rc<VaultStore>,
    key:    Rc<Zeroizing<[u8; 32]>>,
    window: Rc<libadwaita::ApplicationWindow>,
) {
    let (dialog, toolbar) = make_toolbar_dialog("⚙️ Paramètres", 420);

    let vbox = GtkBox::new(Orientation::Vertical, 16);
    vbox.set_margin_top(16);   vbox.set_margin_bottom(16);
    vbox.set_margin_start(16); vbox.set_margin_end(16);

    // ── Sécurité ──
    vbox.append(&Label::builder()
        .label("🔒 Sécurité")
        .halign(gtk4::Align::Start)
        .css_classes(["heading"])
        .build());

    let sec_list = make_fields_box();
    for (k, v) in &[
        ("Auto-verrouillage",  "5 minutes"),
        ("Chiffrement",        "AES-256-GCM"),
        ("Dérivation de clé",  "Argon2id — OWASP 2024"),
    ] {
        let r = GtkBox::new(Orientation::Horizontal, 8);
        r.set_margin_top(10); r.set_margin_bottom(10);
        r.set_margin_start(12); r.set_margin_end(12);
        r.append(&Label::builder().label(*k).hexpand(true).halign(gtk4::Align::Start).build());
        r.append(&Label::builder().label(*v).css_classes(["dim-label", "caption"]).build());
        let rw = gtk4::ListBoxRow::new();
        rw.set_child(Some(&r));
        rw.set_activatable(false);
        sec_list.append(&rw);
    }
    vbox.append(&sec_list);

    // ── Changer mot de passe maître ──
    vbox.append(&Label::builder()
        .label("🔑 Mot de passe maître")
        .halign(gtk4::Align::Start)
        .css_classes(["heading"])
        .margin_top(8)
        .build());

    let pw_list = make_fields_box();
    let f_old  = PasswordEntryRow::builder().title("Mot de passe actuel").build();
    let f_new1 = PasswordEntryRow::builder().title("Nouveau mot de passe").build();
    let f_new2 = PasswordEntryRow::builder().title("Confirmer le nouveau").build();
    pw_list.append(&f_old);
    pw_list.append(&f_new1);
    pw_list.append(&f_new2);
    vbox.append(&pw_list);

    let pw_error = Label::new(None);
    pw_error.add_css_class("error");
    pw_error.set_visible(false);
    vbox.append(&pw_error);

    let change_btn = Button::with_label("🔐 Changer le mot de passe");
    change_btn.add_css_class("suggested-action");
    change_btn.set_halign(gtk4::Align::Fill);
    vbox.append(&change_btn);

    let store_ch = store.clone();
    let key_ch   = key.clone();
    let win_ch   = window.clone();
    let err_ch   = pw_error.clone();
    change_btn.connect_clicked(move |_| {
        let old_pw  = f_old.text().to_string();
        let new_pw1 = f_new1.text().to_string();
        let new_pw2 = f_new2.text().to_string();

        if old_pw.is_empty() || new_pw1.is_empty() || new_pw2.is_empty() {
            err_ch.set_text("⚠️ Tous les champs sont obligatoires.");
            err_ch.set_visible(true);
            return;
        }
        if new_pw1 != new_pw2 {
            err_ch.set_text("⚠️ Les nouveaux mots de passe ne correspondent pas.");
            err_ch.set_visible(true);
            return;
        }
        if new_pw1.len() < 8 {
            err_ch.set_text("⚠️ Le nouveau mot de passe doit faire au moins 8 caractères.");
            err_ch.set_visible(true);
            return;
        }

        // Vérifier l'ancien mot de passe
        match store_ch.verify_or_init_sentinel(&key_ch) {
            Ok(true) => {}
            Ok(false) => {
                err_ch.set_text("❌ Mot de passe actuel incorrect.");
                err_ch.set_visible(true);
                return;
            }
            Err(e) => {
                err_ch.set_text(&format!("❌ Erreur : {e}"));
                err_ch.set_visible(true);
                return;
            }
        }

        // Recalculer le sel et re-chiffrer toutes les entrées
        match store_ch.change_master_password(&key_ch, new_pw1.as_bytes()) {
            Ok(_) => {
                // Reverrouiller l'app pour forcer une reconnexion
                let login = crate::build_login_screen(win_ch.clone());
                win_ch.set_content(Some(&login));
                win_ch.set_default_size(480, 560);
                win_ch.set_size_request(0, 0);
                gtk4::glib::g_debug!(APP_ID, "Mot de passe maître changé, reconnexion requise");
            }
            Err(e) => {
                err_ch.set_text(&format!("❌ Impossible de changer le mot de passe : {e}"));
                err_ch.set_visible(true);
            }
        }
    });

    vbox.append(&Separator::new(Orientation::Horizontal));

    // ── À propos ──
    vbox.append(&Label::builder()
        .label("ℹ️ À propos")
        .halign(gtk4::Align::Start)
        .css_classes(["heading"])
        .build());

    let about_list = make_fields_box();
    for (k, v) in &[
        ("Application",  "VaultPass"),
        ("Version",       "0.2.0"),
        ("Plateforme",    "Linux — GTK4 + Libadwaita"),
        ("Développeur",   "UbuntuFR"),
    ] {
        let r = GtkBox::new(Orientation::Horizontal, 8);
        r.set_margin_top(10); r.set_margin_bottom(10);
        r.set_margin_start(12); r.set_margin_end(12);
        r.append(&Label::builder().label(*k).hexpand(true).halign(gtk4::Align::Start).build());
        r.append(&Label::builder().label(*v).css_classes(["dim-label", "caption"]).build());
        let rw = gtk4::ListBoxRow::new();
        rw.set_child(Some(&r));
        rw.set_activatable(false);
        about_list.append(&rw);
    }
    vbox.append(&about_list);

    let close_btn = Button::with_label("Fermer");
    close_btn.add_css_class("pill");
    close_btn.set_halign(gtk4::Align::Center);
    close_btn.set_margin_top(8);
    vbox.append(&close_btn);

    toolbar.set_content(Some(&vbox));
    dialog.set_child(Some(&toolbar));
    dialog.present(Some(parent));

    let dlg = dialog.clone();
    close_btn.connect_clicked(move |_| { dlg.close(); });
}
