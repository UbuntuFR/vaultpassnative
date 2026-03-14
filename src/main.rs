use gtk4::glib;
use gdk4::prelude::DisplayExt;
mod crypto;
mod database;
mod ui;

use libadwaita::prelude::*;
use libadwaita::{
    Application, ApplicationWindow, HeaderBar,
    NavigationSplitView, NavigationPage, Banner,
    StatusPage,
};
use gtk4::{
    Box as GtkBox, Orientation, Label, SearchEntry,
    ListBox, ListBoxRow, SelectionMode, ScrolledWindow,
    Separator, Button, Stack, PasswordEntry,
};

use crypto::{kdf, cipher};
use database::{store::VaultStore, models::VaultEntry as DbEntry};
use zeroize::Zeroizing;
use std::time::{SystemTime, UNIX_EPOCH};
use std::cell::RefCell;
use std::rc::Rc;

const APP_ID: &str = "io.github.UbuntuFR.VaultpassNative";

fn db_path() -> std::path::PathBuf {
    let mut p = glib::user_data_dir();
    p.push("vaultpass");
    std::fs::create_dir_all(&p).ok();
    p.push("vault.db");
    p
}

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn main() {
    let app = Application::builder()
        .application_id(APP_ID)
        .build();
    app.connect_activate(build_ui);
    std::process::exit(app.run().into());
}

fn build_ui(app: &Application) {
    let stack = Rc::new(Stack::new());
    stack.set_transition_type(gtk4::StackTransitionType::SlideLeft);
    stack.set_transition_duration(300);

    let login_box = GtkBox::new(Orientation::Vertical, 24);
    login_box.set_valign(gtk4::Align::Center);
    login_box.set_halign(gtk4::Align::Center);
    login_box.set_margin_top(48);
    login_box.set_margin_bottom(48);
    login_box.set_margin_start(48);
    login_box.set_margin_end(48);

    let status = StatusPage::new();
    status.set_icon_name(Some("dialog-password-symbolic"));
    status.set_title("VaultPass Native");
    status.set_description(Some("Entrez votre mot de passe maître pour déverrouiller votre coffre"));
    login_box.append(&status);

    let pw_entry = PasswordEntry::new();
    pw_entry.set_placeholder_text(Some("Mot de passe maître…"));
    pw_entry.set_show_peek_icon(true);
    pw_entry.set_width_chars(30);
    login_box.append(&pw_entry);

    let error_lbl = Label::new(None);
    error_lbl.add_css_class("error");
    error_lbl.set_visible(false);
    login_box.append(&error_lbl);

    let unlock_btn = Button::with_label("🔓 Déverrouiller");
    unlock_btn.add_css_class("suggested-action");
    unlock_btn.add_css_class("pill");
    unlock_btn.set_halign(gtk4::Align::Center);
    login_box.append(&unlock_btn);

    let hint = Label::new(Some("💡 Premier lancement : tapez votre mot de passe maître pour créer un nouveau coffre."));
    hint.add_css_class("caption");
    hint.add_css_class("dim-label");
    hint.set_wrap(true);
    hint.set_justify(gtk4::Justification::Center);
    login_box.append(&hint);

    stack.add_named(&login_box, Some("login"));

    let toolbar_box = GtkBox::new(Orientation::Vertical, 0);
    let login_header = HeaderBar::new();
    login_header.set_title_widget(Some(
        &Label::builder().label("VaultPass Native").css_classes(["heading"]).build()
    ));
    toolbar_box.append(&login_header);
    toolbar_box.append(stack.as_ref());

    let window = Rc::new(ApplicationWindow::builder()
        .application(app)
        .title("VaultPass Native")
        .default_width(480)
        .default_height(560)
        .content(&toolbar_box)
        .build());

    let _autolock = setup_autolock(
        window.upcast_ref::<gtk4::Window>(),
        stack.clone(),
        ui::autolock::LockDelay::FiveMin,
    );
    window.present();

    let stack_u   = stack.clone();
    let window_u  = window.clone();
    let pw_clone  = pw_entry.clone();
    let err_clone = error_lbl.clone();

    let do_unlock = Rc::new(move || {
        let password = pw_clone.text().to_string();
        if password.is_empty() {
            err_clone.set_text("⚠️ Mot de passe vide.");
            err_clone.set_visible(true);
            return;
        }
        err_clone.set_visible(false);

        let path  = db_path();
        let store = match VaultStore::open(path.to_str().unwrap_or("/tmp/vault.db")) {
            Ok(s)  => Rc::new(s),
            Err(e) => {
                err_clone.set_text(&format!("❌ Base de données : {e}"));
                err_clone.set_visible(true);
                return;
            }
        };

        let salt_vec = match store.load_salt() {
            Ok(Some(s)) => s,
            Ok(None) => {
                let s = kdf::generate_salt();
                if let Err(e) = store.save_salt(&s) {
                    err_clone.set_text(&format!("❌ Sauvegarde sel : {e}"));
                    err_clone.set_visible(true);
                    return;
                }
                s.to_vec()
            }
            Err(e) => {
                err_clone.set_text(&format!("❌ Lecture sel : {e}"));
                err_clone.set_visible(true);
                return;
            }
        };

        let salt_arr: [u8; 32] = match salt_vec.try_into() {
            Ok(a)  => a,
            Err(_) => {
                err_clone.set_text("❌ Sel corrompu (longueur invalide).");
                err_clone.set_visible(true);
                return;
            }
        };

        let master_key = match kdf::derive_master_key(password.as_bytes(), &salt_arr) {
            Ok(k)  => k,
            Err(e) => {
                err_clone.set_text(&format!("❌ KDF : {e}"));
                err_clone.set_visible(true);
                return;
            }
        };
        let key: Rc<Zeroizing<[u8; 32]>> = Rc::new(master_key.0);

        match store.verify_or_init_sentinel(&key) {
            Ok(true)  => {}
            Ok(false) => {
                err_clone.set_text("❌ Mot de passe incorrect.");
                err_clone.set_visible(true);
                return;
            }
            Err(e) => {
                err_clone.set_text(&format!("❌ Vérification : {e}"));
                err_clone.set_visible(true);
                return;
            }
        }

        glib::g_debug!(APP_ID, "Coffre déverrouillé");
        let vault = build_vault(store, key, stack_u.clone(), window_u.clone());
        stack_u.add_named(&vault, Some("vault"));
        stack_u.set_visible_child_name("vault");
        window_u.set_default_size(1024, 680);
        window_u.set_size_request(800, 500);
    });

    let du1 = do_unlock.clone();
    unlock_btn.connect_clicked(move |_| du1());
    let du2 = do_unlock.clone();
    pw_entry.connect_activate(move |_| du2());
}

fn build_vault(
    store:     Rc<VaultStore>,
    key_bytes: Rc<Zeroizing<[u8; 32]>>,
    stack:     Rc<Stack>,
    window:    Rc<ApplicationWindow>,
) -> GtkBox {
    let db_entries: Rc<RefCell<Vec<DbEntry>>> = Rc::new(RefCell::new(
        store.list_entries().unwrap_or_default()
    ));

    let sidebar_box = GtkBox::new(Orientation::Vertical, 0);
    sidebar_box.set_width_request(220);

    let sidebar_header = HeaderBar::new();
    sidebar_header.set_show_end_title_buttons(false);
    sidebar_header.set_title_widget(Some(
        &Label::builder().label("VaultPass").css_classes(["heading"]).build()
    ));

    let add_btn = Button::from_icon_name("list-add-symbolic");
    add_btn.add_css_class("flat");
    add_btn.set_tooltip_text(Some("Nouvelle entrée"));
    sidebar_header.pack_end(&add_btn);

    let lock_btn = Button::from_icon_name("system-lock-screen-symbolic");
    lock_btn.add_css_class("flat");
    lock_btn.set_tooltip_text(Some("Verrouiller"));
    sidebar_header.pack_start(&lock_btn);
    sidebar_box.append(&sidebar_header);

    let category_list = ListBox::new();
    category_list.set_selection_mode(SelectionMode::Single);
    category_list.add_css_class("navigation-sidebar");
    for cat in &["🔐  Tous", "👤  Perso", "💼  Pro", "💰  Finance"] {
        let row = ListBoxRow::new();
        let lbl = Label::builder()
            .label(*cat)
            .halign(gtk4::Align::Start)
            .margin_start(12).margin_top(8).margin_bottom(8)
            .build();
        row.set_child(Some(&lbl));
        category_list.append(&row);
    }
    category_list.select_row(category_list.row_at_index(0).as_ref());
    sidebar_box.append(&category_list);
    sidebar_box.append(&Separator::new(Orientation::Horizontal));

    let settings_list = ListBox::new();
    settings_list.add_css_class("navigation-sidebar");
    let sr = ListBoxRow::new();
    sr.set_child(Some(&Label::builder()
        .label("⚙  Paramètres")
        .halign(gtk4::Align::Start)
        .margin_start(12).margin_top(8).margin_bottom(8)
        .build()));
    settings_list.append(&sr);
    sidebar_box.append(&settings_list);

    let content_box    = GtkBox::new(Orientation::Vertical, 0);
    let content_header = HeaderBar::new();

    let search = SearchEntry::new();
    search.set_placeholder_text(Some("Rechercher…"));
    search.set_hexpand(true);
    search.set_max_width_chars(40);
    content_header.set_title_widget(Some(&search));

    let gen_btn = Button::from_icon_name("preferences-system-symbolic");
    gen_btn.add_css_class("flat");
    gen_btn.set_tooltip_text(Some("Générateur"));
    content_header.pack_end(&gen_btn);
    content_box.append(&content_header);

    let count  = db_entries.borrow().len();
    let banner = Banner::new(&format!("🔐 {} entrées — AES-256-GCM + Argon2id", count));
    banner.set_revealed(true);
    content_box.append(&banner);

    let scroll = ScrolledWindow::new();
    scroll.set_vexpand(true);
    scroll.set_policy(gtk4::PolicyType::Never, gtk4::PolicyType::Automatic);

    let entries_list = ListBox::new();
    entries_list.set_selection_mode(SelectionMode::Single);
    entries_list.add_css_class("boxed-list");
    entries_list.set_margin_top(12);
    entries_list.set_margin_bottom(12);
    entries_list.set_margin_start(16);
    entries_list.set_margin_end(16);

    for entry in db_entries.borrow().iter() {
        let row = build_entry_row(
            entry, &key_bytes, &store, &db_entries, &entries_list, &banner,
        );
        entries_list.append(&row);
    }

    let cat_filter:    Rc<RefCell<Option<String>>> = Rc::new(RefCell::new(None));
    let search_filter: Rc<RefCell<String>>         = Rc::new(RefCell::new(String::new()));

    let el_c   = entries_list.clone();
    let cat_f  = cat_filter.clone();
    let srch_f = search_filter.clone();
    let db_c   = db_entries.clone();

    let apply_filter = Rc::new(move || {
        let cat   = cat_f.borrow().clone();
        let q     = srch_f.borrow().to_lowercase();
        let db    = db_c.borrow();
        let mut i = 0i32;
        while let Some(row) = el_c.row_at_index(i) {
            let visible = if let Some(entry) = db.get(i as usize) {
                let cat_ok  = cat.as_deref().map_or(true, |c| entry.category == c);
                let srch_ok = q.is_empty()
                    || entry.title.to_lowercase().contains(&q)
                    || entry.username.to_lowercase().contains(&q)
                    || entry.category.to_lowercase().contains(&q);
                cat_ok && srch_ok
            } else {
                true
            };
            row.set_visible(visible);
            i += 1;
        }
    });

    let af1 = apply_filter.clone();
    let cf1 = cat_filter.clone();
    category_list.connect_row_selected(move |_, sel| {
        let txt = sel
            .and_then(|r| r.child().and_downcast_ref::<Label>().map(|l| l.text().to_string()))
            .unwrap_or_default();
        *cf1.borrow_mut() = if txt.contains("Perso") {
            Some("Perso".to_string())
        } else if txt.contains("Pro") {
            Some("Pro".to_string())
        } else if txt.contains("Finance") {
            Some("Finance".to_string())
        } else {
            None
        };
        af1();
    });

    let af2 = apply_filter.clone();
    let sf2 = search_filter.clone();
    search.connect_search_changed(move |s| {
        *sf2.borrow_mut() = s.text().to_string();
        af2();
    });

    let st = stack.clone();
    let wl = window.clone();
    lock_btn.connect_clicked(move |_| {
        if let Some(v) = st.child_by_name("vault") { st.remove(&v); }
        st.set_visible_child_name("login");
        wl.set_default_size(480, 560);
        glib::g_debug!(APP_ID, "Coffre verrouillé manuellement");
    });

    let wg = window.clone();
    gen_btn.connect_clicked(move |_| {
        ui::dialogs::show_generator_dialog(wg.upcast_ref::<gtk4::Widget>());
    });

    let st2  = store.clone();
    let ka   = key_bytes.clone();
    let el_a = entries_list.clone();
    let db_a = db_entries.clone();
    let bn_a = banner.clone();
    let wa   = window.clone();
    add_btn.connect_clicked(move |_| {
        ui::dialogs::show_add_dialog(
            wa.upcast_ref::<gtk4::Widget>(),
            st2.clone(), ka.clone(),
            el_a.clone(), db_a.clone(), bn_a.clone(),
        );
    });

    scroll.set_child(Some(&entries_list));
    content_box.append(&scroll);

    let split_view = NavigationSplitView::new();
    split_view.set_sidebar(Some(&NavigationPage::new(&sidebar_box, "Catégories")));
    split_view.set_content(Some(&NavigationPage::new(&content_box, "Entrées")));
    split_view.set_min_sidebar_width(200.0);
    split_view.set_max_sidebar_width(280.0);

    let wrapper = GtkBox::new(Orientation::Vertical, 0);
    wrapper.append(&split_view);
    wrapper
}

pub fn build_entry_row(
    entry:        &DbEntry,
    key:          &Rc<Zeroizing<[u8; 32]>>,
    store:        &Rc<VaultStore>,
    db_entries:   &Rc<RefCell<Vec<DbEntry>>>,
    entries_list: &ListBox,
    banner:       &Banner,
) -> ListBoxRow {
    let row     = ListBoxRow::new();
    let row_box = GtkBox::new(Orientation::Horizontal, 12);
    row_box.set_margin_top(10);  row_box.set_margin_bottom(10);
    row_box.set_margin_start(8); row_box.set_margin_end(8);

    row_box.append(&Label::new(Some("🔑")));

    let tc = GtkBox::new(Orientation::Vertical, 2);
    tc.append(&Label::builder()
        .label(entry.title.as_str())
        .halign(gtk4::Align::Start)
        .css_classes(["heading"])
        .build());
    tc.append(&Label::builder()
        .label(entry.username.as_str())
        .halign(gtk4::Align::Start)
        .css_classes(["caption", "dim-label"])
        .build());
    tc.set_hexpand(true);
    row_box.append(&tc);

    let cat_lbl = Label::new(Some(&entry.category));
    cat_lbl.add_css_class("tag");
    row_box.append(&cat_lbl);

    let copy_btn = Button::from_icon_name("edit-copy-symbolic");
    copy_btn.add_css_class("flat");
    copy_btn.set_tooltip_text(Some("Copier le mot de passe"));
    let enc = entry.password_encrypted.clone();
    let kc  = Rc::clone(key);
    let tc2 = entry.title.clone();
    copy_btn.connect_clicked(move |b| {
        match cipher::decrypt(&**kc, &enc) {
            Ok(plain) => {
                let pw = String::from_utf8_lossy(&plain).to_string();
                // .display() disponible via use gdk4::prelude::DisplayExt en tête
                b.display().clipboard().set_text(&pw);
                glib::g_debug!(APP_ID, "Mot de passe copié : {}", tc2);
            }
            Err(e) => glib::g_warning!(APP_ID, "Déchiffrement échoué : {}", e),
        }
    });
    row_box.append(&copy_btn);

    let del_btn = Button::from_icon_name("user-trash-symbolic");
    del_btn.add_css_class("flat");
    del_btn.add_css_class("destructive-action");
    del_btn.set_tooltip_text(Some("Supprimer"));

    let eid    = entry.id.clone();
    let etitle = entry.title.clone();
    let sd     = Rc::clone(store);
    let dd     = Rc::clone(db_entries);
    let ld     = entries_list.clone();
    let bd     = banner.clone();
    let rw     = row.clone();

    del_btn.connect_clicked(move |btn| {
        let sd2  = sd.clone();
        let dd2  = dd.clone();
        let ld2  = ld.clone();
        let bd2  = bd.clone();
        let rw2  = rw.clone();
        let eid2 = eid.clone();
        ui::dialogs::show_delete_confirm(
            btn.upcast_ref::<gtk4::Widget>(),
            &etitle,
            move || {
                if sd2.delete_entry(&eid2).is_ok() {
                    ld2.remove(&rw2);
                    dd2.borrow_mut().retain(|e| e.id != eid2);
                    bd2.set_title(&format!(
                        "🔐 {} entrées — AES-256-GCM + Argon2id",
                        dd2.borrow().len()
                    ));
                    glib::g_debug!(APP_ID, "Entrée supprimée");
                }
            },
        );
    });
    row_box.append(&del_btn);
    row.set_child(Some(&row_box));
    row
}

fn setup_autolock(
    window: &gtk4::Window,
    stack:  Rc<gtk4::Stack>,
    delay:  ui::autolock::LockDelay,
) -> Rc<ui::autolock::AutoLock> {
    let al = Rc::new(ui::autolock::AutoLock::new(delay));

    let motion = gtk4::EventControllerMotion::new();
    let al_m   = al.clone();
    motion.connect_motion(move |_, _, _| al_m.reset());
    window.add_controller(motion);

    let key_ctrl = gtk4::EventControllerKey::new();
    let al_k     = al.clone();
    key_ctrl.connect_key_pressed(move |_, _, _, _| {
        al_k.reset();
        glib::Propagation::Proceed
    });
    window.add_controller(key_ctrl);

    let st = stack.clone();
    al.start(move || {
        if st.visible_child_name().as_deref() == Some("vault") {
            if let Some(v) = st.child_by_name("vault") { st.remove(&v); }
            st.set_visible_child_name("login");
            glib::g_debug!(APP_ID, "Auto-verrouillage déclenché");
        }
    });

    al
}
