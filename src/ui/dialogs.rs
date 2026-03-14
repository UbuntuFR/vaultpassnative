use libadwaita::prelude::*;
use libadwaita::{
    AlertDialog, Dialog as AdwDialog,
    EntryRow, PasswordEntryRow,
    ToolbarView, Toast,
};
use gtk4::{
    Box as GtkBox, Orientation, Button, Label,
    Adjustment, Scale, Switch, ListBoxRow,
    Separator,
};
use gdk4::prelude::DisplayExt;
use std::rc::Rc;
use zeroize::Zeroizing;

use crate::crypto::cipher;
use crate::database::{store::VaultStore, models::{VaultEntry, EntryId}};
use crate::ui::generator::GeneratorConfig;
use crate::ui::vault_context::VaultContext;
use crate::ui::prefs::Prefs;
use crate::ui::theme::Theme;
use crate::now_unix;

const APP_ID: &str = "io.github.UbuntuFR.VaultpassNative";

// ── Helpers UI ──────────────────────────────────────────────────────────────
fn make_fields_box() -> gtk4::ListBox {
    let lb = gtk4::ListBox::new();
    lb.add_css_class("boxed-list");
    lb
}

fn make_toolbar_dialog(title: &str, width: i32) -> (AdwDialog, ToolbarView) {
    let dialog  = AdwDialog::builder().title(title).content_width(width).build();
    let toolbar = ToolbarView::new();
    toolbar.add_top_bar(&libadwaita::HeaderBar::new());
    (dialog, toolbar)
}

fn strength_text(pw: &str) -> String {
    let (bars, label) = match GeneratorConfig::strength_score(pw) {
        0 => ("██░░░░░░░░", "Très faible 🔴"),
        1 => ("████░░░░░░", "Faible 🟠"),
        2 => ("██████░░░░", "Moyen 🟡"),
        3 => ("████████░░", "Fort 🟢"),
        _ => ("██████████", "Excellent ✅"),
    };
    format!("Force : {} {}", bars, label)
}

// ── Données lues depuis un formulaire ───────────────────────────────────────
struct EntryFormData {
    title:    String,
    username: String,
    password: String,
    url:      Option<String>,
    category: String,
    notes:    Option<String>,
}

impl EntryFormData {
    fn read(
        f_title: &EntryRow,
        f_user:  &EntryRow,
        f_pass:  &PasswordEntryRow,
        f_url:   &EntryRow,
        f_cat:   &EntryRow,
        f_notes: &EntryRow,
    ) -> Option<Self> {
        let title    = f_title.text().to_string();
        let password = f_pass.text().to_string();
        if title.is_empty() || password.is_empty() { return None; }
        let url   = Some(f_url.text().to_string()).filter(|s| !s.is_empty());
        let notes = Some(f_notes.text().to_string()).filter(|s| !s.is_empty());
        let cat   = f_cat.text().to_string();
        Some(Self {
            title,
            username: f_user.text().to_string(),
            password,
            url,
            category: if cat.is_empty() { "Général".to_string() } else { cat },
            notes,
        })
    }

    fn encrypt_into(
        &self,
        key:        &[u8; 32],
        id:         EntryId,
        created_at: i64,
    ) -> Option<VaultEntry> {
        let pw_enc    = cipher::encrypt(key, self.password.as_bytes()).ok()?;
        let notes_enc = self.notes.as_ref()
            .and_then(|n| cipher::encrypt(key, n.as_bytes()).ok());
        Some(VaultEntry {
            id,
            title:              self.title.clone(),
            username:           self.username.clone(),
            password_encrypted: pw_enc,
            url:                self.url.clone(),
            category:           self.category.clone(),
            notes_encrypted:    notes_enc,
            created_at,
            updated_at:         now_unix(),
        })
    }
}

// ── Formulaire partagé add / edit ───────────────────────────────────────────
struct EntryForm {
    f_title: EntryRow,
    f_user:  EntryRow,
    f_pass:  PasswordEntryRow,
    f_url:   EntryRow,
    f_cat:   EntryRow,
    f_notes: EntryRow,
    strength_lbl: Label,
    gen_btn:      Button,
    fields_box:   gtk4::ListBox,
}

impl EntryForm {
    fn new(
        title_val:    &str,
        username_val: &str,
        password_val: &str,
        url_val:      &str,
        cat_val:      &str,
        notes_val:    &str,
    ) -> Self {
        let f_title = EntryRow::builder().title("Titre *").text(title_val).build();
        let f_user  = EntryRow::builder().title("Identifiant / Email").text(username_val).build();
        let f_pass  = PasswordEntryRow::builder().title("Mot de passe *").text(password_val).build();
        let f_url   = EntryRow::builder().title("URL (optionnel)").text(url_val).build();
        let f_cat   = EntryRow::builder().title("Catégorie : Pro / Perso / Finance").text(cat_val).build();
        let f_notes = EntryRow::builder().title("Notes (optionnel)").text(notes_val).build();

        let init_strength = if password_val.is_empty() {
            "Force : —".to_string()
        } else {
            strength_text(password_val)
        };
        let strength_lbl = Label::builder()
            .label(&init_strength)
            .halign(gtk4::Align::Start)
            .css_classes(["caption", "dim-label"])
            .build();

        let sl = strength_lbl.clone();
        f_pass.connect_changed(move |e| { sl.set_text(&strength_text(&e.text())); });

        let fp      = f_pass.clone();
        let gen_btn = Button::with_label("🎲 Générer un mot de passe");
        gen_btn.add_css_class("suggested-action");
        gen_btn.set_margin_top(4);
        gen_btn.connect_clicked(move |_| { fp.set_text(&GeneratorConfig::default().generate()); });

        let fields_box = make_fields_box();
        fields_box.append(&f_title);
        fields_box.append(&f_user);
        fields_box.append(&f_pass);
        fields_box.append(&f_url);
        fields_box.append(&f_cat);
        fields_box.append(&f_notes);

        Self { f_title, f_user, f_pass, f_url, f_cat, f_notes, strength_lbl, gen_btn, fields_box }
    }

    fn append_to(&self, vbox: &GtkBox) {
        vbox.append(&self.fields_box);
        vbox.append(&self.strength_lbl);
        vbox.append(&self.gen_btn);
    }

    fn read(&self) -> Option<EntryFormData> {
        EntryFormData::read(
            &self.f_title, &self.f_user, &self.f_pass,
            &self.f_url, &self.f_cat, &self.f_notes,
        )
    }
}

// ── NOUVELLE ENTRÉE ─────────────────────────────────────────────────────────────
pub fn show_add_dialog(
    parent: &impl IsA<gtk4::Widget>,
    ctx:    VaultContext,
) {
    let (dialog, toolbar) = make_toolbar_dialog("Nouvelle entrée", 440);
    let form = EntryForm::new("", "", "", "", "", "");

    let vbox = GtkBox::new(Orientation::Vertical, 12);
    vbox.set_margin_top(16);   vbox.set_margin_bottom(16);
    vbox.set_margin_start(16); vbox.set_margin_end(16);
    form.append_to(&vbox);

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
        let Some(data) = form.read() else {
            gtk4::glib::g_warning!(APP_ID, "Titre et mot de passe obligatoires");
            return;
        };
        let Some(entry) = data.encrypt_into(&**ctx.key, EntryId::new(), now_unix())
        else {
            gtk4::glib::g_critical!(APP_ID, "Échec chiffrement");
            return;
        };
        match ctx.store.insert_entry(&entry) {
            Ok(_) => {
                let row = crate::build_entry_row(&entry, &ctx);
                ctx.entries_list.append(&row);
                ctx.db_entries.borrow_mut().push(entry);
                ctx.refresh_banner();
                ctx.refresh_empty_state();
                ctx.toast.add_toast(Toast::new("✅ Entrée ajoutée !"));
                dlg_a.close();
            }
            Err(e) => gtk4::glib::g_critical!(APP_ID, "SQLite insert : {}", e),
        }
    });
}

// ── MODIFIER ENTRÉE ────────────────────────────────────────────────────────────────
pub fn show_edit_dialog(
    parent: &impl IsA<gtk4::Widget>,
    entry:  VaultEntry,
    ctx:    VaultContext,
    row:    ListBoxRow,
) {
    let current_pw = cipher::decrypt(&**ctx.key, &entry.password_encrypted)
        .map(|b| String::from_utf8_lossy(&b).to_string())
        .unwrap_or_default();
    let current_notes = entry.notes_encrypted.as_ref()
        .and_then(|enc| cipher::decrypt(&**ctx.key, enc).ok())
        .map(|b| String::from_utf8_lossy(&b).to_string())
        .unwrap_or_default();

    let (dialog, toolbar) = make_toolbar_dialog("Modifier l'entrée", 440);
    let form = EntryForm::new(
        &entry.title, &entry.username, &current_pw,
        entry.url.as_deref().unwrap_or(""),
        &entry.category, &current_notes,
    );

    let vbox = GtkBox::new(Orientation::Vertical, 12);
    vbox.set_margin_top(16);   vbox.set_margin_bottom(16);
    vbox.set_margin_start(16); vbox.set_margin_end(16);
    form.append_to(&vbox);

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
        let Some(data) = form.read() else {
            gtk4::glib::g_warning!(APP_ID, "Titre et mot de passe obligatoires");
            return;
        };
        let Some(updated) = data.encrypt_into(&**ctx.key, entry_id.clone(), created_at)
        else {
            gtk4::glib::g_critical!(APP_ID, "Échec chiffrement");
            return;
        };
        match ctx.store.update_entry(&updated) {
            Ok(_) => {
                if let Some(e) = ctx.db_entries.borrow_mut()
                    .iter_mut().find(|e| e.id == entry_id)
                {
                    *e = updated.clone();
                }
                let new_row = crate::build_entry_row(&updated, &ctx);
                let idx     = get_row_index(&ctx.entries_list, &row);
                ctx.entries_list.insert(&new_row, idx.unwrap_or(-1));
                ctx.entries_list.remove(&row);
                ctx.toast.add_toast(Toast::new("✅ Entrée modifiée !"));
                dlg_s.close();
            }
            Err(e) => gtk4::glib::g_critical!(APP_ID, "SQLite update : {}", e),
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

// ── CONFIRMATION SUPPRESSION ──────────────────────────────────────────────────
pub fn show_delete_confirm(
    parent:     &impl IsA<gtk4::Widget>,
    title:      &str,
    on_confirm: impl Fn() + 'static,
) {
    let alert = AlertDialog::builder()
        .heading(&format!("Supprimer \"{}\" ?", title))
        .body("Cette action est irréversible.")
        .default_response("cancel")
        .close_response("cancel")
        .build();
    alert.add_response("cancel", "Annuler");
    alert.add_response("delete", "🗑️ Supprimer");
    alert.set_response_appearance("delete", libadwaita::ResponseAppearance::Destructive);
    alert.connect_response(None, move |_, r| { if r == "delete" { on_confirm(); } });
    alert.present(Some(parent));
}

// ── GÉNÉRATEUR ──────────────────────────────────────────────────────────────────
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
    let (r_di, sw_di) = sw_row("Chiffres (0-9)",   true);
    let (r_sy, sw_sy) = sw_row("Symboles (!@#…)",  true);

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
        len_row.upcast_ref(), r_up.upcast_ref(),
        r_di.upcast_ref(),    r_sy.upcast_ref(),
        strength_lbl.upcast_ref(), btn_row.upcast_ref(),
    ] { vbox.append(w); }

    vbox.append(&Separator::new(Orientation::Horizontal));
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
        sl.set_text(&strength_text(&pw));
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

    let rg3 = regenerate.clone(); sw_up.connect_state_set(move |_,_| { rg3(); false.into() });
    let rg4 = regenerate.clone(); sw_di.connect_state_set(move |_,_| { rg4(); false.into() });
    let rg5 = regenerate.clone(); sw_sy.connect_state_set(move |_,_| { rg5(); false.into() });

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

// ── PARAMÈTRES ─────────────────────────────────────────────────────────────────
pub fn show_settings_dialog(
    parent: &impl IsA<gtk4::Widget>,
    store:  Rc<VaultStore>,
    key:    Rc<Zeroizing<[u8; 32]>>,
    window: Rc<libadwaita::ApplicationWindow>,
    prefs:  Rc<std::cell::RefCell<Prefs>>,
) {
    let (dialog, toolbar) = make_toolbar_dialog("⚙️ Paramètres", 460);

    let vbox = GtkBox::new(Orientation::Vertical, 16);
    vbox.set_margin_top(16);   vbox.set_margin_bottom(16);
    vbox.set_margin_start(16); vbox.set_margin_end(16);

    vbox.append(&Label::builder()
        .label("🔒 Sécurité")
        .halign(gtk4::Align::Start)
        .css_classes(["heading"])
        .build());

    let sec_list = make_fields_box();
    for (k, v) in &[
        ("Auto-verrouillage", "5 minutes"),
        ("Chiffrement",       "AES-256-GCM"),
        ("Dérivation de clé", "Argon2id — OWASP 2024"),
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

    vbox.append(&Label::builder()
        .label("🔑 Mot de passe maître")
        .halign(gtk4::Align::Start)
        .css_classes(["heading"])
        .margin_top(8)
        .build());

    let pw_list = make_fields_box();
    let f_old   = PasswordEntryRow::builder().title("Mot de passe actuel").build();
    let f_new1  = PasswordEntryRow::builder().title("Nouveau mot de passe").build();
    let f_new2  = PasswordEntryRow::builder().title("Confirmer le nouveau").build();
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
            err_ch.set_text("⚠️ Les mots de passe ne correspondent pas.");
            err_ch.set_visible(true);
            return;
        }
        if new_pw1.len() < 8 {
            err_ch.set_text("⚠️ Minimum 8 caractères.");
            err_ch.set_visible(true);
            return;
        }
        match store_ch.change_master_password(&key_ch, new_pw1.as_bytes()) {
            Ok(_) => {
                let login = crate::build_login_screen(win_ch.clone());
                win_ch.set_content(Some(&login));
                win_ch.set_default_size(480, 560);
                win_ch.set_size_request(0, 0);
            }
            Err(e) => {
                err_ch.set_text(&format!("❌ {e}"));
                err_ch.set_visible(true);
            }
        }
    });

    vbox.append(&Separator::new(Orientation::Horizontal));

    // ── Thème ──
    vbox.append(&Label::builder()
        .label("🎨 Apparence")
        .halign(gtk4::Align::Start)
        .css_classes(["heading"])
        .build());

    let theme_list = make_fields_box();
    let current_theme_id = prefs.borrow().theme.clone();
    for th in Theme::all() {
        let rw  = gtk4::ListBoxRow::new();
        let row = GtkBox::new(Orientation::Horizontal, 8);
        row.set_margin_top(10); row.set_margin_bottom(10);
        row.set_margin_start(12); row.set_margin_end(12);
        row.append(&Label::builder().label(th.label()).hexpand(true).halign(gtk4::Align::Start).build());
        if th.id() == current_theme_id {
            row.append(&Label::builder().label("✓").css_classes(["accent"]).build());
        }
        rw.set_child(Some(&row));
        theme_list.append(&rw);
    }
    let prefs_th = prefs.clone();
    theme_list.connect_row_activated(move |_, row| {
        let themes = Theme::all();
        if let Some(th) = themes.get(row.index() as usize) {
            crate::ui::theme::apply(th);
            prefs_th.borrow_mut().theme = th.id().to_string();
            prefs_th.borrow().save();
        }
    });
    vbox.append(&theme_list);

    vbox.append(&Separator::new(Orientation::Horizontal));

    // ── Auto-verrouillage configurable ──
    vbox.append(&Label::builder()
        .label("⏱️ Auto-verrouillage")
        .halign(gtk4::Align::Start)
        .css_classes(["heading"])
        .build());

    use crate::ui::autolock::LockDelay;
    let lock_list = make_fields_box();
    let current_delay = prefs.borrow().lock_delay_secs;
    for delay in LockDelay::all() {
        let rw  = gtk4::ListBoxRow::new();
        let row = GtkBox::new(Orientation::Horizontal, 8);
        row.set_margin_top(10); row.set_margin_bottom(10);
        row.set_margin_start(12); row.set_margin_end(12);
        row.append(&Label::builder().label(delay.label()).hexpand(true).halign(gtk4::Align::Start).build());
        if *delay as u64 == current_delay {
            row.append(&Label::builder().label("✓").css_classes(["accent"]).build());
        }
        rw.set_child(Some(&row));
        lock_list.append(&rw);
    }
    let prefs_lk = prefs.clone();
    lock_list.connect_row_activated(move |_, row| {
        let delays = LockDelay::all();
        if let Some(d) = delays.get(row.index() as usize) {
            prefs_lk.borrow_mut().lock_delay_secs = *d as u64;
            prefs_lk.borrow().save();
        }
    });
    vbox.append(&lock_list);

    vbox.append(&Separator::new(Orientation::Horizontal));

    vbox.append(&Label::builder()
        .label("ℹ️ À propos")
        .halign(gtk4::Align::Start)
        .css_classes(["heading"])
        .build());

    let about_list = make_fields_box();
    for (k, v) in &[
        ("Application", "VaultPass"),
        ("Version",     "0.2.0"),
        ("Plateforme",  "Linux — GTK4 + Libadwaita"),
        ("Développeur", "UbuntuFR"),
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
