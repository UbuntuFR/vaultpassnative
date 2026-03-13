use gtk4::glib;
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
    Separator, Button, Scale, Switch, Adjustment,
    Dialog, ResponseType, Entry, Stack, PasswordEntry,
};

use crypto::{kdf, cipher};
use database::{store::VaultStore, models::VaultEntry as DbEntry};
use ui::generator::GeneratorConfig;
use uuid::Uuid;
use std::time::{SystemTime, UNIX_EPOCH};
use std::cell::RefCell;
use std::rc::Rc;

const APP_ID: &str  = "io.github.UbuntuFR.VaultpassNative";
const DB_PATH: &str = "/tmp/vaultpass_demo.db";

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

    let hint = Label::new(Some("💡 Tapez n'importe quel mot de passe pour créer un coffre."));
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

    let _autolock = setup_autolock(window.upcast_ref(), stack.clone(), ui::autolock::LockDelay::FiveMin);
    window.present();

    let stack_u = stack.clone();
    let window_u = window.clone();
    let pw_clone = pw_entry.clone();
    let err_clone = error_lbl.clone();

    let do_unlock = Rc::new(move || {
        let password = pw_clone.text().to_string();
        if password.is_empty() {
            err_clone.set_text("⚠️ Mot de passe vide.");
            err_clone.set_visible(true);
            return;
        }
        let store = match VaultStore::open(DB_PATH) {
            Ok(s) => Rc::new(s),
            Err(e) => { err_clone.set_text(&format!("❌ {e}")); err_clone.set_visible(true); return; }
        };
        let salt = store.load_salt().unwrap_or_default().unwrap_or_else(|| {
            let s = kdf::generate_salt(); store.save_salt(&s).ok(); s.to_vec()
        });
        let salt_arr: [u8; 32] = salt.try_into().unwrap_or([0u8; 32]);
        let master_key = match kdf::derive_master_key(password.as_bytes(), &salt_arr) {
            Ok(k) => k,
            Err(e) => { err_clone.set_text(&format!("❌ KDF: {e}")); err_clone.set_visible(true); return; }
        };
        let key: Rc<[u8; 32]> = Rc::new((*master_key.0).clone().try_into().unwrap_or([0u8; 32]));

        if store.list_entries().unwrap_or_default().is_empty() {
            for (t, u, c) in [
                ("GitHub", "dev@example.com", "Pro"),
                ("ProtonMail", "user@pm.me", "Perso"),
                ("Netflix", "famille@home.fr", "Perso"),
                ("Société Générale", "0123456789", "Finance"),
                ("Fedora Account", "coding@fedora", "Pro"),
            ] {
                let pw = cipher::encrypt(&key, b"demo_secret").unwrap_or_default();
                store.insert_entry(&DbEntry {
                    id: Uuid::new_v4().to_string(),
                    title: t.into(), username: u.into(),
                    password_encrypted: pw, url: None, category: c.into(),
                    notes_encrypted: None, created_at: now_unix(), updated_at: now_unix(),
                }).ok();
            }
        }

        let vault = build_vault(store, key, stack_u.clone(), window_u.clone());
        stack_u.add_named(&vault, Some("vault"));
        stack_u.set_visible_child_name("vault");
        window_u.set_default_size(1024, 680);
        window_u.set_size_request(800, 500);
        println!("✅ Coffre déverrouillé !");
    });

    let du1 = do_unlock.clone();
    unlock_btn.connect_clicked(move |_| du1());
    let du2 = do_unlock.clone();
    pw_entry.connect_activate(move |_| du2());
}

fn build_vault(
    store: Rc<VaultStore>,
    key_bytes: Rc<[u8; 32]>,
    stack: Rc<Stack>,
    window: Rc<ApplicationWindow>,
) -> GtkBox {
    let db_entries: Rc<RefCell<Vec<DbEntry>>> = Rc::new(RefCell::new(
        store.list_entries().unwrap_or_default()
    ));

    // ── SIDEBAR ──────────────────────────────────────────────────
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
        let lbl = Label::builder().label(*cat).halign(gtk4::Align::Start)
            .margin_start(12).margin_top(8).margin_bottom(8).build();
        row.set_child(Some(&lbl));
        category_list.append(&row);
    }
    category_list.select_row(category_list.row_at_index(0).as_ref());
    sidebar_box.append(&category_list);
    sidebar_box.append(&Separator::new(Orientation::Horizontal));

    let settings_list = ListBox::new();
    settings_list.add_css_class("navigation-sidebar");
    let sr = ListBoxRow::new();
    sr.set_child(Some(&Label::builder().label("⚙  Paramètres")
        .halign(gtk4::Align::Start).margin_start(12).margin_top(8).margin_bottom(8).build()));
    settings_list.append(&sr);
    sidebar_box.append(&settings_list);

    // ── CONTENU ──────────────────────────────────────────────────
    let content_box = GtkBox::new(Orientation::Vertical, 0);
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

    let count = db_entries.borrow().len();
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
        let row = build_entry_row(entry, &key_bytes, &store, &db_entries, &entries_list, &banner);
        entries_list.append(&row);
    }

    // Filtre catégorie
    let el_c = entries_list.clone(); let db_c = db_entries.clone();
    category_list.connect_row_selected(move |_, sel| {
        let txt = sel.and_then(|r| r.child().and_downcast_ref::<Label>()
            .map(|l| l.text().to_string())).unwrap_or_default();
        let cat: Option<&str> =
            if txt.contains("Perso") { Some("Perso") }
            else if txt.contains("Pro") { Some("Pro") }
            else if txt.contains("Finance") { Some("Finance") }
            else { None };
        let mut i = 0i32;
        while let Some(row) = el_c.row_at_index(i) {
            row.set_visible(cat.map_or(true, |c| db_c.borrow().get(i as usize)
                .map_or(false, |e| e.category == c)));
            i += 1;
        }
    });

    // Recherche
    let el_s = entries_list.clone(); let db_s = db_entries.clone();
    search.connect_search_changed(move |s| {
        let q = s.text().to_lowercase();
        let entries = db_s.borrow();
        let mut i = 0i32;
        while let Some(row) = el_s.row_at_index(i) {
            row.set_visible(q.is_empty() || entries.get(i as usize).map_or(false, |e| {
                e.title.to_lowercase().contains(&q)
                || e.username.to_lowercase().contains(&q)
                || e.category.to_lowercase().contains(&q)
            }));
            i += 1;
        }
    });

    // Verrouiller
    let st = stack.clone(); let wl = window.clone();
    lock_btn.connect_clicked(move |_| {
        if let Some(v) = st.child_by_name("vault") { st.remove(&v); }
        st.set_visible_child_name("login");
        wl.set_default_size(480, 560);
        println!("🔒 Coffre verrouillé");
    });

    // Générateur
    let wg = window.clone();
    gen_btn.connect_clicked(move |_| show_generator_dialog(wg.upcast_ref()));

    // Nouvelle entrée
    let st2 = store.clone(); let ka = key_bytes.clone();
    let el_a = entries_list.clone(); let db_a = db_entries.clone();
    let bn_a = banner.clone(); let wa = window.clone();
    add_btn.connect_clicked(move |_| {
        show_add_dialog(wa.upcast_ref(), st2.clone(), ka.clone(),
            el_a.clone(), db_a.clone(), bn_a.clone());
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

fn build_entry_row(
    entry: &DbEntry, key: &Rc<[u8; 32]>,
    store: &Rc<VaultStore>, db_entries: &Rc<RefCell<Vec<DbEntry>>>,
    entries_list: &ListBox, banner: &Banner,
) -> ListBoxRow {
    let row = ListBoxRow::new();
    let row_box = GtkBox::new(Orientation::Horizontal, 12);
    row_box.set_margin_top(10); row_box.set_margin_bottom(10);
    row_box.set_margin_start(8); row_box.set_margin_end(8);

    row_box.append(&Label::new(Some("🔑")));

    let tc = GtkBox::new(Orientation::Vertical, 2);
    tc.append(&Label::builder().label(entry.title.as_str())
        .halign(gtk4::Align::Start).css_classes(["heading"]).build());
    tc.append(&Label::builder().label(entry.username.as_str())
        .halign(gtk4::Align::Start).css_classes(["caption", "dim-label"]).build());
    tc.set_hexpand(true);
    row_box.append(&tc);

    let cat = Label::new(Some(&entry.category));
    cat.add_css_class("tag");
    row_box.append(&cat);

    let copy_btn = Button::from_icon_name("edit-copy-symbolic");
    copy_btn.add_css_class("flat");
    copy_btn.set_tooltip_text(Some("Copier le mot de passe"));
    let enc = entry.password_encrypted.clone();
    let kc = Rc::clone(key);
    let tc2 = entry.title.clone();
    copy_btn.connect_clicked(move |b| {
        if let Ok(plain) = cipher::decrypt(&kc, &enc) {
            let pw = String::from_utf8_lossy(&plain).to_string();
            if let Some(d) = b.display().downcast_ref::<gdk4::Display>() {
                d.clipboard().set_text(&pw);
                println!("✅ Copié : {tc2}");
            }
        }
    });
    row_box.append(&copy_btn);

    let del_btn = Button::from_icon_name("user-trash-symbolic");
    del_btn.add_css_class("flat");
    del_btn.add_css_class("destructive-action");
    del_btn.set_tooltip_text(Some("Supprimer"));
    let eid = entry.id.clone();
    let sd = Rc::clone(store); let dd = Rc::clone(db_entries);
    let ld = entries_list.clone(); let bd = banner.clone();
    let rw = row.clone();
    del_btn.connect_clicked(move |_| {
        if sd.delete_entry(&eid).is_ok() {
            ld.remove(&rw);
            dd.borrow_mut().retain(|e| e.id != eid);
            bd.set_title(&format!("🔐 {} entrées — AES-256-GCM + Argon2id",
                dd.borrow().len()));
            println!("🗑️  Supprimé");
        }
    });
    row_box.append(&del_btn);
    row.set_child(Some(&row_box));
    row
}

fn show_add_dialog(
    parent: &gtk4::Window, store: Rc<VaultStore>, key: Rc<[u8; 32]>,
    list: ListBox, db_entries: Rc<RefCell<Vec<DbEntry>>>, banner: Banner,
) {
    let dialog = Dialog::with_buttons(
        Some("Nouvelle entrée"), Some(parent),
        gtk4::DialogFlags::MODAL | gtk4::DialogFlags::DESTROY_WITH_PARENT,
        &[("Annuler", ResponseType::Cancel), ("➕ Ajouter", ResponseType::Accept)],
    );
    dialog.set_default_size(420, -1);
    let vbox = GtkBox::new(Orientation::Vertical, 10);
    vbox.set_margin_top(16); vbox.set_margin_bottom(16);
    vbox.set_margin_start(16); vbox.set_margin_end(16);

    let f_title = Entry::builder().placeholder_text("Titre").build();
    let f_user  = Entry::builder().placeholder_text("Identifiant / Email").build();
    let f_pass  = Entry::builder().placeholder_text("Mot de passe").build();
    f_pass.set_visibility(false);
    f_pass.set_input_purpose(gtk4::InputPurpose::Password);
    let f_url   = Entry::builder().placeholder_text("URL (optionnel)").build();
    let f_cat   = Entry::builder().placeholder_text("Catégorie : Pro / Perso / Finance").build();

    let pw_row = GtkBox::new(Orientation::Horizontal, 8);
    f_pass.set_hexpand(true);
    let gen_btn = Button::with_label("🎲 Générer");
    gen_btn.add_css_class("suggested-action");
    let fp2 = f_pass.clone();
    gen_btn.connect_clicked(move |_| {
        fp2.set_text(&GeneratorConfig::default().generate());
        fp2.set_visibility(true);
    });
    pw_row.append(&f_pass); pw_row.append(&gen_btn);

    for (lbl, w) in [
        ("Titre",        f_title.upcast_ref::<gtk4::Widget>()),
        ("Identifiant",  f_user.upcast_ref()),
        ("Mot de passe", pw_row.upcast_ref()),
        ("URL",          f_url.upcast_ref()),
        ("Catégorie",    f_cat.upcast_ref()),
    ] {
        vbox.append(&Label::builder().label(lbl)
            .halign(gtk4::Align::Start).css_classes(["heading"]).build());
        vbox.append(w);
    }
    dialog.content_area().append(&vbox);
    dialog.show();

    let (ft, fu, fp, fl, fc) = (f_title.clone(), f_user.clone(), f_pass.clone(), f_url.clone(), f_cat.clone());
    dialog.connect_response(move |dlg, resp| {
        if resp == ResponseType::Accept {
            let title = ft.text().to_string();
            let username = fu.text().to_string();
            let password = fp.text().to_string();
            let url_str  = fl.text().to_string();
            let category = { let c = fc.text().to_string();
                if c.is_empty() { "Général".to_string() } else { c } };

            if !title.is_empty() && !password.is_empty() {
                if let Ok(encrypted) = cipher::encrypt(&key, password.as_bytes()) {
                    let new_entry = DbEntry {
                        id: Uuid::new_v4().to_string(),
                        title: title.clone(), username: username.clone(),
                        password_encrypted: encrypted, url: if url_str.is_empty() { None } else { Some(url_str) },
                        category: category.clone(), notes_encrypted: None,
                        created_at: now_unix(), updated_at: now_unix(),
                    };
                    if store.insert_entry(&new_entry).is_ok() {
                        let rb = GtkBox::new(Orientation::Horizontal, 12);
                        rb.set_margin_top(10); rb.set_margin_bottom(10);
                        rb.set_margin_start(8); rb.set_margin_end(8);
                        rb.append(&Label::new(Some("🔑")));
                        let tc = GtkBox::new(Orientation::Vertical, 2);
                        tc.append(&Label::builder().label(title.as_str())
                            .halign(gtk4::Align::Start).css_classes(["heading"]).build());
                        tc.append(&Label::builder().label(username.as_str())
                            .halign(gtk4::Align::Start).css_classes(["caption","dim-label"]).build());
                        tc.set_hexpand(true); rb.append(&tc);
                        let cl = Label::new(Some(&category)); cl.add_css_class("tag"); rb.append(&cl);
                        let row = ListBoxRow::new(); row.set_child(Some(&rb));
                        list.append(&row);
                        db_entries.borrow_mut().push(new_entry);
                        banner.set_title(&format!("🔐 {} entrées — AES-256-GCM + Argon2id",
                            db_entries.borrow().len()));
                        println!("✅ '{}' ajouté", title);
                    }
                }
            }
        }
        dlg.close();
    });
}

fn show_generator_dialog(parent: &gtk4::Window) {
    let dialog = Dialog::with_buttons(
        Some("🎲 Générateur de mots de passe"), Some(parent),
        gtk4::DialogFlags::MODAL | gtk4::DialogFlags::DESTROY_WITH_PARENT,
        &[("Fermer", ResponseType::Close)],
    );
    dialog.set_default_size(440, -1);
    let vbox = GtkBox::new(Orientation::Vertical, 16);
    vbox.set_margin_top(16); vbox.set_margin_bottom(16);
    vbox.set_margin_start(16); vbox.set_margin_end(16);

    let result_entry = Entry::new();
    result_entry.set_editable(false);
    result_entry.add_css_class("monospace");
    result_entry.set_hexpand(true);

    let len_row = GtkBox::new(Orientation::Horizontal, 8);
    let len_lbl = Label::new(Some("Longueur : 20"));
    len_lbl.set_hexpand(true);
    let len_scale = Scale::new(Orientation::Horizontal,
        Some(&Adjustment::new(20.0, 8.0, 64.0, 1.0, 5.0, 0.0)));
    len_scale.set_hexpand(true); len_scale.set_draw_value(false);
    len_row.append(&len_lbl); len_row.append(&len_scale);

    fn sw_row(lbl: &str, on: bool) -> (GtkBox, Switch) {
        let r = GtkBox::new(Orientation::Horizontal, 8);
        let l = Label::builder().label(lbl).hexpand(true).build();
        let s = Switch::builder().active(on).build();
        r.append(&l); r.append(&s); (r, s)
    }
    let (r_up, sw_up) = sw_row("Majuscules (A-Z)", true);
    let (r_di, sw_di) = sw_row("Chiffres (0-9)", true);
    let (r_sy, sw_sy) = sw_row("Symboles (!@#…)", true);

    let strength_lbl = Label::builder().label("Force : ██████████ Excellent")
        .halign(gtk4::Align::Start).css_classes(["caption"]).build();

    let btn_row = GtkBox::new(Orientation::Horizontal, 8);
    let regen_btn = Button::with_label("🔄 Régénérer");
    regen_btn.add_css_class("suggested-action"); regen_btn.set_hexpand(true);
    let copy_btn = Button::with_label("📋 Copier");
    btn_row.append(&regen_btn); btn_row.append(&copy_btn);

    for w in [result_entry.upcast_ref::<gtk4::Widget>(), len_row.upcast_ref(),
        r_up.upcast_ref(), r_di.upcast_ref(), r_sy.upcast_ref(),
        strength_lbl.upcast_ref(), btn_row.upcast_ref()] {
        vbox.append(w);
    }
    dialog.content_area().append(&vbox);

    let re = result_entry.clone(); let sl = strength_lbl.clone();
    let ls = len_scale.clone(); let su = sw_up.clone();
    let sd = sw_di.clone(); let ss = sw_sy.clone();

    let regenerate = Rc::new(move || {
        let pw = GeneratorConfig {
            length: ls.value() as usize,
            uppercase: su.is_active(), digits: sd.is_active(), symbols: ss.is_active(),
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
    let rg = regenerate.clone(); regen_btn.connect_clicked(move |_| rg());
    let rg2 = regenerate.clone(); let ll = len_lbl.clone();
    len_scale.connect_value_changed(move |s| {
        ll.set_text(&format!("Longueur : {}", s.value() as usize)); rg2();
    });
    let rg3 = regenerate.clone(); sw_up.connect_state_set(move |_,_| { rg3(); false.into() });
    let rg4 = regenerate.clone(); sw_di.connect_state_set(move |_,_| { rg4(); false.into() });
    let rg5 = regenerate.clone(); sw_sy.connect_state_set(move |_,_| { rg5(); false.into() });

    let re2 = result_entry.clone();
    copy_btn.connect_clicked(move |b| {
        let pw = re2.text().to_string();
        if let Some(d) = b.display().downcast_ref::<gdk4::Display>() {
            d.clipboard().set_text(&pw);
            println!("✅ Copié !");
        }
    });

    dialog.show();
    dialog.connect_response(|dlg, _| dlg.close());
}

// ── Auto-lock ────────────────────────────────────────────────────────────────
fn setup_autolock(
    window: &gtk4::Window,
    stack: Rc<gtk4::Stack>,
    delay: ui::autolock::LockDelay,
) -> Rc<ui::autolock::AutoLock> {
    let al = Rc::new(ui::autolock::AutoLock::new(delay));

    // Surveiller les événements souris et clavier sur la fenêtre
    let motion = gtk4::EventControllerMotion::new();
    let al_m = al.clone();
    motion.connect_motion(move |_, _, _| al_m.reset());
    window.add_controller(motion);

    let key = gtk4::EventControllerKey::new();
    let al_k = al.clone();
    key.connect_key_pressed(move |_, _, _, _| { al_k.reset(); glib::Propagation::Proceed });
    window.add_controller(key);

    // Lancer la surveillance
    let st = stack.clone();
    al.start(move || {
        if st.visible_child_name().as_deref() == Some("vault") {
            if let Some(v) = st.child_by_name("vault") { st.remove(&v); }
            st.set_visible_child_name("login");
            println!("🔒 Auto-verrouillage !");
        }
    });

    al
}
