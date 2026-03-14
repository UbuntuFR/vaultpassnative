use libadwaita::prelude::*;
use libadwaita::{
    Dialog as AdwDialog, AlertDialog,
    EntryRow, PasswordEntryRow,
    ToolbarView,
};
use gtk4::{
    Box as GtkBox, Orientation, Button, Label,
    Adjustment, Scale, Switch,
};
use gdk4::prelude::DisplayExt;
use std::rc::Rc;
use std::cell::RefCell;
use zeroize::Zeroizing;

use crate::crypto::cipher;
use crate::database::{store::VaultStore, models::VaultEntry as DbEntry};
use crate::ui::generator::GeneratorConfig;
use crate::now_unix;
use uuid::Uuid;

const APP_ID: &str = "io.github.UbuntuFR.VaultpassNative";

pub fn show_add_dialog(
    parent:     &impl IsA<gtk4::Widget>,
    store:      Rc<VaultStore>,
    key:        Rc<Zeroizing<[u8; 32]>>,
    list:       gtk4::ListBox,
    db_entries: Rc<RefCell<Vec<DbEntry>>>,
    banner:     libadwaita::Banner,
) {
    let dialog = AdwDialog::builder()
        .title("Nouvelle entrée")
        .content_width(440)
        .build();

    let toolbar = ToolbarView::new();
    let header  = libadwaita::HeaderBar::new();
    toolbar.add_top_bar(&header);

    let vbox = GtkBox::new(Orientation::Vertical, 12);
    vbox.set_margin_top(16);   vbox.set_margin_bottom(16);
    vbox.set_margin_start(16); vbox.set_margin_end(16);

    let f_title = EntryRow::builder().title("Titre *").build();
    let f_user  = EntryRow::builder().title("Identifiant / Email").build();
    let f_pass  = PasswordEntryRow::builder().title("Mot de passe *").build();
    let f_url   = EntryRow::builder().title("URL (optionnel)").build();
    let f_cat   = EntryRow::builder().title("Catégorie : Pro / Perso / Finance").build();

    let gen_btn = Button::with_label("🎲 Générer un mot de passe");
    gen_btn.add_css_class("suggested-action");
    gen_btn.set_margin_top(4);
    let fp = f_pass.clone();
    gen_btn.connect_clicked(move |_| {
        fp.set_text(&GeneratorConfig::default().generate());
    });

    let fields_box = gtk4::ListBox::new();
    fields_box.add_css_class("boxed-list");
    fields_box.append(&f_title);
    fields_box.append(&f_user);
    fields_box.append(&f_pass);
    fields_box.append(&f_url);
    fields_box.append(&f_cat);

    vbox.append(&fields_box);
    vbox.append(&gen_btn);

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

    let dlg_c = dialog.clone();
    cancel_btn.connect_clicked(move |_| { dlg_c.close(); });

    let dlg_a = dialog.clone();
    add_btn.connect_clicked(move |_| {
        let title    = f_title.text().to_string();
        let username = f_user.text().to_string();
        let password = f_pass.text().to_string();
        let url_str  = f_url.text().to_string();
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
                let new_entry = DbEntry {
                    id:                 Uuid::new_v4().to_string(),
                    title:              title.clone(),
                    username:           username.clone(),
                    password_encrypted: encrypted,
                    url:                if url_str.is_empty() { None } else { Some(url_str) },
                    category:           category.clone(),
                    notes_encrypted:    None,
                    created_at:         now_unix(),
                    updated_at:         now_unix(),
                };
                match store.insert_entry(&new_entry) {
                    Ok(_) => {
                        let row_box = GtkBox::new(Orientation::Horizontal, 12);
                        row_box.set_margin_top(10);  row_box.set_margin_bottom(10);
                        row_box.set_margin_start(8); row_box.set_margin_end(8);
                        row_box.append(&Label::new(Some("🔑")));

                        let tc = GtkBox::new(Orientation::Vertical, 2);
                        tc.append(&Label::builder()
                            .label(title.as_str())
                            .halign(gtk4::Align::Start)
                            .css_classes(["heading"])
                            .build());
                        tc.append(&Label::builder()
                            .label(username.as_str())
                            .halign(gtk4::Align::Start)
                            .css_classes(["caption", "dim-label"])
                            .build());
                        tc.set_hexpand(true);
                        row_box.append(&tc);

                        let cl = Label::new(Some(&category));
                        cl.add_css_class("tag");
                        row_box.append(&cl);

                        let row = gtk4::ListBoxRow::new();
                        row.set_child(Some(&row_box));
                        list.append(&row);

                        db_entries.borrow_mut().push(new_entry);
                        banner.set_title(&format!(
                            "🔐 {} entrées — AES-256-GCM + Argon2id",
                            db_entries.borrow().len()
                        ));
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
        if response == "delete" {
            on_confirm();
        }
    });

    alert.present(Some(parent));
}

pub fn show_generator_dialog(parent: &impl IsA<gtk4::Widget>) {
    let dialog = AdwDialog::builder()
        .title("🎲 Générateur de mots de passe")
        .content_width(460)
        .build();

    let toolbar = ToolbarView::new();
    let header  = libadwaita::HeaderBar::new();
    toolbar.add_top_bar(&header);

    let vbox = GtkBox::new(Orientation::Vertical, 16);
    vbox.set_margin_top(16);   vbox.set_margin_bottom(16);
    vbox.set_margin_start(16); vbox.set_margin_end(16);

    let result_entry = gtk4::Entry::new();
    result_entry.set_editable(false);
    result_entry.add_css_class("monospace");
    result_entry.set_hexpand(true);

    let len_row = GtkBox::new(Orientation::Horizontal, 8);
    let len_lbl = Label::new(Some("Longueur : 20"));
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
        r.append(&l);
        r.append(&s);
        (r, s)
    }
    let (r_up, sw_up) = sw_row("Majuscules (A-Z)", true);
    let (r_di, sw_di) = sw_row("Chiffres (0-9)", true);
    let (r_sy, sw_sy) = sw_row("Symboles (!@#…)", true);

    let strength_lbl = Label::builder()
        .label("Force : ██████████ Excellent")
        .halign(gtk4::Align::Start)
        .css_classes(["caption"])
        .build();

    let btn_row   = GtkBox::new(Orientation::Horizontal, 8);
    let regen_btn = Button::with_label("🔄 Régénérer");
    regen_btn.add_css_class("suggested-action");
    regen_btn.set_hexpand(true);
    let copy_btn = Button::with_label("📋 Copier");
    btn_row.append(&regen_btn);
    btn_row.append(&copy_btn);

    for w in [
        result_entry.upcast_ref::<gtk4::Widget>(),
        len_row.upcast_ref::<gtk4::Widget>(),
        r_up.upcast_ref::<gtk4::Widget>(),
        r_di.upcast_ref::<gtk4::Widget>(),
        r_sy.upcast_ref::<gtk4::Widget>(),
        strength_lbl.upcast_ref::<gtk4::Widget>(),
        btn_row.upcast_ref::<gtk4::Widget>(),
    ] {
        vbox.append(w);
    }

    let close_btn = Button::with_label("Fermer");
    close_btn.set_halign(gtk4::Align::Center);
    close_btn.set_margin_top(4);
    vbox.append(&close_btn);

    toolbar.set_content(Some(&vbox));
    dialog.set_child(Some(&toolbar));
    dialog.present(Some(parent));

    let re  = result_entry.clone();
    let sl  = strength_lbl.clone();
    let ls  = len_scale.clone();
    let su  = sw_up.clone();
    let sd  = sw_di.clone();
    let ss  = sw_sy.clone();

    let regenerate = Rc::new(move || {
        let pw = GeneratorConfig {
            length:    ls.value() as usize,
            uppercase: su.is_active(),
            digits:    sd.is_active(),
            symbols:   ss.is_active(),
        }.generate();
        let (bars, label) = match GeneratorConfig::strength_score(&pw) {
            0 => ("██░░░░░░░░", "Très faible"),
            1 => ("████░░░░░░", "Faible"),
            2 => ("██████░░░░", "Moyen"),
            3 => ("████████░░", "Fort"),
            _ => ("██████████", "Excellent"),
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

    let rg3 = regenerate.clone();
    sw_up.connect_state_set(move |_, _| { rg3(); false.into() });
    let rg4 = regenerate.clone();
    sw_di.connect_state_set(move |_, _| { rg4(); false.into() });
    let rg5 = regenerate.clone();
    sw_sy.connect_state_set(move |_, _| { rg5(); false.into() });

    let re2 = result_entry.clone();
    copy_btn.connect_clicked(move |b| {
        let pw = re2.text().to_string();
        if !pw.is_empty() {
            // .display() disponible via use gdk4::prelude::DisplayExt en tête
            b.display().clipboard().set_text(&pw);
            gtk4::glib::g_debug!(APP_ID, "Mot de passe copié depuis le générateur");
        }
    });

    let dlg = dialog.clone();
    close_btn.connect_clicked(move |_| { dlg.close(); });
}
