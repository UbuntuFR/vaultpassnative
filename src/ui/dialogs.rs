use libadwaita::prelude::*;
use libadwaita::{
    AlertDialog, Dialog as AdwDialog,
    EntryRow, PasswordEntryRow,
    ToolbarView, Toast,
};
use gtk4::{
    Box as GtkBox, Orientation, Button, Label,
    Adjustment, Scale, Switch, ListBoxRow,
    Separator, ScrolledWindow,
};
use gdk4::prelude::DisplayExt;
use std::rc::Rc;
use zeroize::Zeroizing;

use crate::crypto::cipher;
use crate::database::{store::VaultStore, models::{VaultEntry, EntryId}};
use crate::database::custom_fields::{EntrySecrets, CustomField, FieldKind};
use crate::database::importer;
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
    secrets:  EntrySecrets,
}

impl EntryFormData {
    fn read(
        f_title:  &EntryRow,
        f_user:   &EntryRow,
        f_pass:   &PasswordEntryRow,
        f_url:    &EntryRow,
        f_cat:    &EntryRow,
        f_notes:  &EntryRow,
        cf_store: &Rc<std::cell::RefCell<Vec<CustomField>>>,
    ) -> Option<Self> {
        let title    = f_title.text().to_string();
        let password = f_pass.text().to_string();
        if title.is_empty() || password.is_empty() { return None; }
        let url = Some(f_url.text().to_string()).filter(|s| !s.is_empty());
        let cat = f_cat.text().to_string();
        let secrets = EntrySecrets {
            notes:  f_notes.text().to_string(),
            fields: cf_store.borrow().clone(),
        };
        Some(Self {
            title,
            username: f_user.text().to_string(),
            password,
            url,
            category: if cat.is_empty() { "Général".to_string() } else { cat },
            secrets,
        })
    }

    fn encrypt_into(
        &self,
        key:        &[u8; 32],
        id:         EntryId,
        created_at: i64,
    ) -> Option<VaultEntry> {
        let pw_enc    = cipher::encrypt(key, self.password.as_bytes()).ok()?;
        let notes_enc = {
            let json = self.secrets.to_json().ok()?;
            let empty = EntrySecrets::default().to_json().ok()?;
            if json != empty { Some(cipher::encrypt(key, &json).ok()?) } else { None }
        };
        Some(VaultEntry {
            id,
            title:              self.title.clone(),
            username:           self.username.clone(),
            password_encrypted: pw_enc,
            url:                self.url.clone(),
            category:           self.category.clone(),
            notes_encrypted:    notes_enc,
            is_favorite:        false,
            created_at,
            updated_at:         now_unix(),
        })
    }
}

// ── Widget liste de champs custom ────────────────────────────────────────────
fn build_custom_fields_section(
    vbox:     &GtkBox,
    fields:   Rc<std::cell::RefCell<Vec<CustomField>>>,
    key_hint: &str,
) {
    let _ = key_hint;

    let hdr = GtkBox::new(Orientation::Horizontal, 8);
    hdr.set_margin_top(12);
    hdr.append(&Label::builder()
        .label("Champs personnalisés")
        .hexpand(true)
        .halign(gtk4::Align::Start)
        .css_classes(["heading"])
        .build());

    let add_field_btn = Button::from_icon_name("list-add-symbolic");
    add_field_btn.add_css_class("flat");
    add_field_btn.set_tooltip_text(Some("Ajouter un champ"));
    hdr.append(&add_field_btn);
    vbox.append(&hdr);

    let cf_list = gtk4::ListBox::new();
    cf_list.add_css_class("boxed-list");
    vbox.append(&cf_list);

    let cf_list_rc = Rc::new(cf_list.clone());

    let fields2  = fields.clone();
    let list_rc2 = cf_list_rc.clone();
    let redraw = Rc::new(move || {
        while let Some(child) = list_rc2.first_child() {
            list_rc2.remove(&child);
        }
        for (idx, field) in fields2.borrow().iter().enumerate() {
            let row_box = GtkBox::new(Orientation::Horizontal, 6);
            row_box.set_margin_top(8); row_box.set_margin_bottom(8);
            row_box.set_margin_start(12); row_box.set_margin_end(8);

            let icon = gtk4::Image::from_icon_name(field.kind.icon());
            row_box.append(&icon);

            let text_box = GtkBox::new(Orientation::Vertical, 2);
            text_box.set_hexpand(true);
            text_box.append(&Label::builder()
                .label(&field.label)
                .halign(gtk4::Align::Start)
                .css_classes(["caption", "dim-label"])
                .build());
            let val_lbl = if field.kind.is_secret() {
                Label::builder().label("••••••••").halign(gtk4::Align::Start).build()
            } else {
                Label::builder().label(&field.value).halign(gtk4::Align::Start).build()
            };
            text_box.append(&val_lbl);
            row_box.append(&text_box);

            let val_copy = field.value.clone();
            let copy_btn = Button::from_icon_name("edit-copy-symbolic");
            copy_btn.add_css_class("flat");
            copy_btn.set_tooltip_text(Some("Copier"));
            copy_btn.connect_clicked(move |b| {
                b.display().clipboard().set_text(&val_copy);
            });
            row_box.append(&copy_btn);

            let fields_del = fields2.clone();
            let del_btn    = Button::from_icon_name("user-trash-symbolic");
            del_btn.add_css_class("flat");
            del_btn.add_css_class("destructive-action");
            del_btn.set_tooltip_text(Some("Supprimer ce champ"));
            del_btn.connect_clicked(move |_| {
                fields_del.borrow_mut().remove(idx);
            });
            row_box.append(&del_btn);

            let lbr = gtk4::ListBoxRow::new();
            lbr.set_child(Some(&row_box));
            lbr.set_activatable(false);
            list_rc2.append(&lbr);
        }
        if fields2.borrow().is_empty() {
            let empty = gtk4::ListBoxRow::new();
            empty.set_child(Some(&Label::builder()
                .label("Aucun champ — cliquez + pour en ajouter")
                .css_classes(["dim-label", "caption"])
                .margin_top(12).margin_bottom(12)
                .build()));
            empty.set_activatable(false);
            list_rc2.append(&empty);
        }
    });

    redraw();

    let fields_add = fields.clone();
    let redraw_add = redraw.clone();
    let cf_list_parent = vbox.clone();
    add_field_btn.connect_clicked(move |btn| {
        let parent_widget = btn.root()
            .and_then(|r| r.downcast::<gtk4::Window>().ok());

        let add_dialog  = AdwDialog::builder().title("Nouveau champ").content_width(360).build();
        let add_toolbar = ToolbarView::new();
        add_toolbar.add_top_bar(&libadwaita::HeaderBar::new());

        let inner = GtkBox::new(Orientation::Vertical, 12);
        inner.set_margin_top(16); inner.set_margin_bottom(16);
        inner.set_margin_start(16); inner.set_margin_end(16);

        let kind_list = gtk4::ListBox::new();
        kind_list.add_css_class("boxed-list");
        let selected_kind: Rc<std::cell::Cell<usize>> = Rc::new(std::cell::Cell::new(0));
        for (i, k) in FieldKind::all().iter().enumerate() {
            let rw  = gtk4::ListBoxRow::new();
            let rb  = GtkBox::new(Orientation::Horizontal, 8);
            rb.set_margin_top(8); rb.set_margin_bottom(8);
            rb.set_margin_start(12); rb.set_margin_end(12);
            rb.append(&gtk4::Image::from_icon_name(k.icon()));
            rb.append(&Label::builder().label(k.label()).hexpand(true)
                .halign(gtk4::Align::Start).build());
            if i == 0 {
                rb.append(&Label::builder().label("✓").css_classes(["accent"]).build());
            }
            rw.set_child(Some(&rb));
            kind_list.append(&rw);
        }
        let sk = selected_kind.clone();
        kind_list.connect_row_activated(move |list, row| {
            sk.set(row.index() as usize);
            let mut i = 0i32;
            while let Some(r) = list.row_at_index(i) {
                if let Some(child) = r.child() {
                    if let Some(b) = child.downcast_ref::<GtkBox>() {
                        let mut w = b.last_child();
                        while let Some(widget) = w {
                            let prev = widget.prev_sibling();
                            if widget.downcast_ref::<Label>()
                                .map(|l| l.text() == "✓").unwrap_or(false)
                            {
                                b.remove(&widget);
                            }
                            w = prev;
                        }
                    }
                }
                i += 1;
            }
            if let Some(sel) = list.row_at_index(row.index()) {
                if let Some(child) = sel.child() {
                    if let Some(b) = child.downcast_ref::<GtkBox>() {
                        b.append(&Label::builder().label("✓").css_classes(["accent"]).build());
                    }
                }
            }
        });
        inner.append(&kind_list);

        let f_label = EntryRow::builder().title("Nom du champ (ex: PIN, Numéro)").build();
        let f_value = EntryRow::builder().title("Valeur").build();
        let lbx = gtk4::ListBox::new();
        lbx.add_css_class("boxed-list");
        lbx.append(&f_label);
        lbx.append(&f_value);
        inner.append(&lbx);

        let btn_row2   = GtkBox::new(Orientation::Horizontal, 8);
        btn_row2.set_homogeneous(true);
        btn_row2.set_margin_top(8);
        let cancel2 = Button::with_label("Annuler");
        let ok2     = Button::with_label("Ajouter");
        ok2.add_css_class("suggested-action");
        btn_row2.append(&cancel2);
        btn_row2.append(&ok2);
        inner.append(&btn_row2);

        add_toolbar.set_content(Some(&inner));
        add_dialog.set_child(Some(&add_toolbar));

        if let Some(pw) = &parent_widget {
            add_dialog.present(Some(pw));
        } else {
            add_dialog.present(None::<&gtk4::Widget>);
        }

        let dlg_c2 = add_dialog.clone();
        cancel2.connect_clicked(move |_| { dlg_c2.close(); });

        let dlg_ok    = add_dialog.clone();
        let fa2       = fields_add.clone();
        let rd2       = redraw_add.clone();
        let sk2       = selected_kind.clone();
        ok2.connect_clicked(move |_| {
            let label = f_label.text().to_string();
            let value = f_value.text().to_string();
            if label.is_empty() { return; }
            let kind = FieldKind::all()[sk2.get()].clone();
            fa2.borrow_mut().push(CustomField::new(kind, label, value));
            rd2();
            dlg_ok.close();
        });

        let _ = cf_list_parent.is_visible();
    });
}

// ── Formulaire partagé add / edit ───────────────────────────────────────────
struct EntryForm {
    f_title:      EntryRow,
    f_user:       EntryRow,
    f_pass:       PasswordEntryRow,
    f_url:        EntryRow,
    f_cat:        EntryRow,
    f_notes:      EntryRow,
    strength_lbl: Label,
    gen_btn:      Button,
    fields_box:   gtk4::ListBox,
    cf_store:     Rc<std::cell::RefCell<Vec<CustomField>>>,
}

impl EntryForm {
    fn new(
        title_val:    &str,
        username_val: &str,
        password_val: &str,
        url_val:      &str,
        cat_val:      &str,
        secrets:      &EntrySecrets,
    ) -> Self {
        let f_title = EntryRow::builder().title("Titre *").text(title_val).build();
        let f_user  = EntryRow::builder().title("Identifiant / Email").text(username_val).build();
        let f_pass  = PasswordEntryRow::builder().title("Mot de passe *").text(password_val).build();
        let f_url   = EntryRow::builder().title("URL (optionnel)").text(url_val).build();
        let f_cat   = EntryRow::builder().title("Catégorie : Pro / Perso / Finance").text(cat_val).build();
        let f_notes = EntryRow::builder().title("Notes (optionnel)").text(&secrets.notes).build();

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

        let cf_store = Rc::new(std::cell::RefCell::new(secrets.fields.clone()));

        Self { f_title, f_user, f_pass, f_url, f_cat, f_notes,
               strength_lbl, gen_btn, fields_box, cf_store }
    }

    fn append_to(&self, vbox: &GtkBox) {
        vbox.append(&self.fields_box);
        vbox.append(&self.strength_lbl);
        vbox.append(&self.gen_btn);
        build_custom_fields_section(vbox, self.cf_store.clone(), "");
    }

    fn read(&self) -> Option<EntryFormData> {
        EntryFormData::read(
            &self.f_title, &self.f_user, &self.f_pass,
            &self.f_url, &self.f_cat, &self.f_notes,
            &self.cf_store,
        )
    }
}

// ── NOUVELLE ENTRÉE ─────────────────────────────────────────────────────────────
pub fn show_add_dialog(
    parent: &impl IsA<gtk4::Widget>,
    ctx:    VaultContext,
) {
    let (dialog, toolbar) = make_toolbar_dialog("Nouvelle entrée", 440);
    let form = EntryForm::new("", "", "", "", "", &EntrySecrets::default());

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
        let Some(entry) = data.encrypt_into(&ctx.key, EntryId::new(), now_unix())
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
    let current_pw = cipher::decrypt(&ctx.key, &entry.password_encrypted)
        .map(|b| String::from_utf8_lossy(&b).to_string())
        .unwrap_or_default();
    let current_secrets: EntrySecrets = entry.notes_encrypted.as_ref()
        .and_then(|enc| cipher::decrypt(&ctx.key, enc).ok())
        .and_then(|b| EntrySecrets::from_json(&b).ok())
        .or_else(|| entry.notes_encrypted.as_ref()
            .and_then(|enc| cipher::decrypt(&ctx.key, enc).ok())
            .map(|b| EntrySecrets {
                notes: String::from_utf8_lossy(&b).to_string(),
                fields: Vec::new(),
            }))
        .unwrap_or_default();

    let (dialog, toolbar) = make_toolbar_dialog("Modifier l'entrée", 460);
    let form = EntryForm::new(
        &entry.title, &entry.username, &current_pw,
        entry.url.as_deref().unwrap_or(""),
        &entry.category, &current_secrets,
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
        let Some(updated) = data.encrypt_into(&ctx.key, entry_id.clone(), created_at)
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
        .heading(format!("Supprimer \"{}\" ?", title))
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
    parent:   &impl IsA<gtk4::Widget>,
    store:    Rc<VaultStore>,
    key:      Rc<Zeroizing<[u8; 32]>>,
    window:   Rc<libadwaita::ApplicationWindow>,
    prefs:    Rc<std::cell::RefCell<Prefs>>,
    autolock: Rc<crate::ui::autolock::AutoLock>,
) {
    let (dialog, toolbar) = make_toolbar_dialog("⚙️ Paramètres", 460);

    // ── ScrolledWindow pour tout le contenu ──
    let scroll = ScrolledWindow::new();
    scroll.set_vexpand(true);
    scroll.set_hexpand(true);
    scroll.set_policy(gtk4::PolicyType::Never, gtk4::PolicyType::Automatic);

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
        // FIX #3: Proper comparison using LockDelay::from_secs
        if delay.to_secs() == current_delay {
            row.append(&Label::builder().label("✓").css_classes(["accent"]).build());
        }
        rw.set_child(Some(&row));
        lock_list.append(&rw);
    }
    let prefs_lk    = prefs.clone();
    let autolock_lk = autolock.clone();
    let lock_list_rc = lock_list.clone();
    lock_list.connect_row_activated(move |_, row| {
        let delays = LockDelay::all();
        if let Some(d) = delays.get(row.index() as usize) {
            let secs = d.to_secs();
            prefs_lk.borrow_mut().lock_delay_secs = secs;
            prefs_lk.borrow().save();
            autolock_lk.set_delay(secs);

            // Mettre à jour le ✓ visuellement
            let mut i = 0i32;
            while let Some(r) = lock_list_rc.row_at_index(i) {
                if let Some(child) = r.child() {
                    if let Some(b) = child.downcast_ref::<GtkBox>() {
                        let mut w = b.last_child();
                        while let Some(widget) = w {
                            let prev = widget.prev_sibling();
                            if widget.downcast_ref::<Label>()
                                .map(|l| l.text() == "✓").unwrap_or(false)
                            {
                                b.remove(&widget);
                            }
                            w = prev;
                        }
                    }
                }
                i += 1;
            }
            if let Some(sel) = lock_list_rc.row_at_index(row.index()) {
                if let Some(child) = sel.child() {
                    if let Some(b) = child.downcast_ref::<GtkBox>() {
                        b.append(&Label::builder().label("✓").css_classes(["accent"]).build());
                    }
                }
            }
        }
    });
    vbox.append(&lock_list);

    vbox.append(&Separator::new(Orientation::Horizontal));

    // ── Import ──
    vbox.append(&Label::builder()
        .label("📥 Import")
        .halign(gtk4::Align::Start)
        .css_classes(["heading"])
        .build());

    let import_list = make_fields_box();
    let import_bw_row = gtk4::ListBoxRow::new();
    let import_bw_box = GtkBox::new(Orientation::Horizontal, 8);
    import_bw_box.set_margin_top(10); import_bw_box.set_margin_bottom(10);
    import_bw_box.set_margin_start(12); import_bw_box.set_margin_end(12);
    import_bw_box.append(&Label::builder().label("Bitwarden JSON")
        .hexpand(true).halign(gtk4::Align::Start).build());
    import_bw_box.append(&gtk4::Image::from_icon_name("go-next-symbolic"));
    import_bw_row.set_child(Some(&import_bw_box));
    import_list.append(&import_bw_row);

    let import_csv_row = gtk4::ListBoxRow::new();
    let import_csv_box = GtkBox::new(Orientation::Horizontal, 8);
    import_csv_box.set_margin_top(10); import_csv_box.set_margin_bottom(10);
    import_csv_box.set_margin_start(12); import_csv_box.set_margin_end(12);
    import_csv_box.append(&Label::builder().label("CSV générique")
        .hexpand(true).halign(gtk4::Align::Start).build());
    import_csv_box.append(&gtk4::Image::from_icon_name("go-next-symbolic"));
    import_csv_row.set_child(Some(&import_csv_box));
    import_list.append(&import_csv_row);
    vbox.append(&import_list);

    let store_imp = store.clone();
    let key_imp   = key.clone();
    let win_imp   = window.clone();
    import_list.connect_row_activated(move |_, row| {
        let is_bw  = row.index() == 0;
        let filter = gtk4::FileFilter::new();
        if is_bw {
            filter.set_name(Some("Bitwarden JSON"));
            filter.add_pattern("*.json");
        } else {
            filter.set_name(Some("CSV"));
            filter.add_pattern("*.csv");
        }
        let filters = gtk4::gio::ListStore::new::<gtk4::FileFilter>();
        filters.append(&filter);

        let dialog = gtk4::FileDialog::builder()
            .title(if is_bw { "Importer Bitwarden JSON" } else { "Importer CSV" })
            .filters(&filters)
            .build();

        let store2 = store_imp.clone();
        let key2   = key_imp.clone();
        let win2   = win_imp.clone();
        dialog.open(Some(win2.upcast_ref::<gtk4::Window>()), None::<&gtk4::gio::Cancellable>,
            move |result| {
                let Ok(file) = result else { return; };
                let Some(path) = file.path() else { return; };
                let entries_res = if is_bw {
                    importer::from_bitwarden_json(&path, &key2)
                        .map_err(|e| e.to_string())
                } else {
                    importer::from_csv(&path, &key2)
                        .map_err(|e| e.to_string())
                };
                match entries_res {
                    Ok(entries) => {
                        let count = entries.len();
                        for e in entries {
                            let _ = store2.insert_entry(&e);
                        }
                        gtk4::glib::g_message!(
                            "vaultpass", "{} entrée(s) importée(s)", count
                        );
                    }
                    Err(e) => {
                        gtk4::glib::g_critical!("vaultpass", "Import échoué: {}", e);
                    }
                }
            }
        );
    });

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

    // ── Assembler : vbox dans scroll, scroll dans toolbar ──
    scroll.set_child(Some(&vbox));
    toolbar.set_content(Some(&scroll));
    dialog.set_child(Some(&toolbar));
    dialog.present(Some(parent));

    let dlg = dialog.clone();
    close_btn.connect_clicked(move |_| { dlg.close(); });
}
