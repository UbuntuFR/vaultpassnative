use gtk4::glib;
mod crypto;
mod database;
mod ui;

use libadwaita::prelude::*;
use libadwaita::{
    Application, ApplicationWindow,
    NavigationSplitView, NavigationPage, Banner,
    StatusPage, ToolbarView, HeaderBar, Toast, ToastOverlay,
};
use gtk4::{
    Box as GtkBox, Orientation, Label, SearchEntry,
    ListBox, ListBoxRow, SelectionMode, ScrolledWindow,
    Separator, Button, PasswordEntry,
};

use crypto::{kdf, cipher};
use database::{store::{VaultStore, StoreError}, models::VaultEntry};
use ui::vault_context::VaultContext;
use ui::prefs::Prefs;
use ui::theme;
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
    let prefs = Prefs::load();
    theme::apply(&theme::Theme::from_id(&prefs.theme));

    let window = Rc::new(ApplicationWindow::builder()
        .application(app)
        .title("VaultPass")
        .default_width(480)
        .default_height(560)
        .build());
    window.set_content(Some(&build_login_screen(window.clone())));
    let autolock = setup_autolock(window.upcast_ref::<gtk4::Window>(), window.clone());
    // FIX #1: Properly maintain AutoLock for entire app lifetime
    // Using std::mem::forget to ensure the Rc is never dropped
    std::mem::forget(autolock);
    window.present();
}

fn initial_color(title: &str) -> &'static str {
    const COLORS: &[&str] = &[
        "#e74c3c", "#e67e22", "#f1c40f", "#2ecc71",
        "#1abc9c", "#3498db", "#9b59b6", "#e91e63",
        "#00bcd4", "#ff5722", "#607d8b", "#795548",
    ];
    let idx = title.chars().next().map(|c| (c as usize) % COLORS.len()).unwrap_or(0);
    COLORS[idx]
}

pub fn build_entry_row(entry: &VaultEntry, ctx: &VaultContext) -> ListBoxRow {
    let row     = ListBoxRow::new();
    let row_box = GtkBox::new(Orientation::Horizontal, 12);
    row_box.set_margin_top(10);  row_box.set_margin_bottom(10);
    row_box.set_margin_start(8); row_box.set_margin_end(8);

    let initial = entry.title.chars().next()
        .unwrap_or('?').to_uppercase().next().unwrap_or('?');
    let color   = initial_color(&entry.title);
    let avatar  = Label::builder().label(initial.to_string()).width_chars(2).build();
    avatar.set_size_request(32, 32);
    let provider = gtk4::CssProvider::new();
    provider.load_from_string(&format!(
        "label {{ background-color:{color}; border-radius:16px; \
         color:white; padding:4px 8px; font-weight:bold; }}"
    ));
    gtk4::style_context_add_provider_for_display(
        &avatar.display(),
        &provider,
        gtk4::STYLE_PROVIDER_PRIORITY_APPLICATION,
    );
    row_box.append(&avatar);

    let info = GtkBox::new(Orientation::Vertical, 2);
    info.append(&Label::builder().label(entry.title.as_str())
        .halign(gtk4::Align::Start).css_classes(["heading"]).build());
    info.append(&Label::builder().label(entry.username.as_str())
        .halign(gtk4::Align::Start).css_classes(["caption", "dim-label"]).build());
    info.set_hexpand(true);
    row_box.append(&info);

    let cat_lbl = Label::new(Some(&entry.category));
    cat_lbl.add_css_class("tag");
    row_box.append(&cat_lbl);

    // Copier — avec auto-clear 30s
    let copy_btn = Button::from_icon_name("edit-copy-symbolic");
    copy_btn.add_css_class("flat");
    copy_btn.set_tooltip_text(Some("Copier le mot de passe (effacé en 30s)"));
    let enc   = entry.password_encrypted.clone();
    let kc    = Rc::clone(&ctx.key);
    let title = entry.title.clone();
    let to1   = ctx.toast.clone();
    copy_btn.connect_clicked(move |b| {
        match cipher::decrypt(kc.as_ref(), &enc) {
            Ok(plain) => {
                let text = String::from_utf8_lossy(&plain).to_string();
                ui::clipboard::copy_with_autoclean(&b.display(), &text);
                to1.add_toast(
                    Toast::builder()
                        .title("✅ Copié — effacé dans 30s")
                        .timeout(4)
                        .build()
                );
                glib::g_debug!(APP_ID, "Copié : {}", title);
            }
            Err(e) => glib::g_warning!(APP_ID, "Déchiffrement échoué : {}", e),
        }
    });
    row_box.append(&copy_btn);

    // Modifier
    let edit_btn = Button::from_icon_name("document-edit-symbolic");
    edit_btn.add_css_class("flat");
    edit_btn.set_tooltip_text(Some("Modifier"));
    let entry_e = entry.clone();
    let ctx_e   = ctx.clone();
    let row_e   = row.clone();
    edit_btn.connect_clicked(move |btn| {
        ui::dialogs::show_edit_dialog(
            btn.upcast_ref::<gtk4::Widget>(),
            entry_e.clone(), ctx_e.clone(), row_e.clone(),
        );
    });
    row_box.append(&edit_btn);

    // Supprimer
    let del_btn = Button::from_icon_name("user-trash-symbolic");
    del_btn.add_css_class("flat");
    del_btn.add_css_class("destructive-action");
    del_btn.set_tooltip_text(Some("Supprimer"));
    let eid    = entry.id.clone();
    let etitle = entry.title.clone();
    let ctx_d  = ctx.clone();
    let rw     = row.clone();
    del_btn.connect_clicked(move |btn| {
        let ctx2 = ctx_d.clone();
        let eid2 = eid.clone();
        let rw2  = rw.clone();
        ui::dialogs::show_delete_confirm(
            btn.upcast_ref::<gtk4::Widget>(),
            &etitle,
            move || {
                if ctx2.store.delete_entry(&eid2).is_ok() {
                    ctx2.entries_list.remove(&rw2);
                    ctx2.db_entries.borrow_mut().retain(|e| e.id != eid2);
                    ctx2.refresh_banner();
                    ctx2.refresh_empty_state();
                    ctx2.toast.add_toast(Toast::new("\u{1F5D1}\u{FE0F} Entrée supprimée"));
                }
            },
        );
    });
    row_box.append(&del_btn);
    row.set_child(Some(&row_box));
    row
}

fn build_vault(
    store:    Rc<VaultStore>,
    key:      Rc<Zeroizing<[u8; 32]>>,
    window:   Rc<ApplicationWindow>,
    prefs:    Rc<RefCell<Prefs>>,
    autolock: Rc<ui::autolock::AutoLock>,
) -> ToolbarView {
    let db_entries = Rc::new(RefCell::new(store.list_entries().unwrap_or_default()));

    let sidebar_box    = GtkBox::new(Orientation::Vertical, 0);
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
        row.set_child(Some(&Label::builder()
            .label(*cat).halign(gtk4::Align::Start)
            .margin_start(12).margin_top(8).margin_bottom(8).build()));
        category_list.append(&row);
    }
    category_list.select_row(category_list.row_at_index(0).as_ref());
    sidebar_box.append(&category_list);
    sidebar_box.append(&Separator::new(Orientation::Horizontal));

    let notes_list = gtk4::ListBox::new();
    notes_list.add_css_class("navigation-sidebar");
    let notes_row = ListBoxRow::new();
    notes_row.set_child(Some(&Label::builder()
        .label("📝  Notes")
        .halign(gtk4::Align::Start)
        .margin_start(12).margin_top(8).margin_bottom(8).build()));
    notes_list.append(&notes_row);
    sidebar_box.append(&notes_list);
    sidebar_box.append(&Separator::new(Orientation::Horizontal));

    let settings_list = ListBox::new();
    settings_list.add_css_class("navigation-sidebar");
    let sr = ListBoxRow::new();
    sr.set_child(Some(&Label::builder()
        .label("⚙️  Paramètres")
        .halign(gtk4::Align::Start)
        .margin_start(12).margin_top(8).margin_bottom(8).build()));
    settings_list.append(&sr);
    sidebar_box.append(&settings_list);

    let store_s    = store.clone();
    let key_s      = key.clone();
    let ws         = window.clone();
    let prefs_s    = prefs.clone();
    let autolock_s = autolock.clone();
    settings_list.connect_row_activated(move |_, _| {
        ui::dialogs::show_settings_dialog(
            ws.upcast_ref::<gtk4::Widget>(),
            store_s.clone(), key_s.clone(), ws.clone(),
            prefs_s.clone(),
            autolock_s.clone(),
        );
    });

    let content_box    = GtkBox::new(Orientation::Vertical, 0);

    // ── Notes : connecté ici car content_box est maintenant en scope ──
    let store_n = store.clone();
    let key_n   = key.clone();
    notes_list.connect_row_activated({
        let content_box = content_box.clone();
        move |_, _| {
            while let Some(child) = content_box.first_child() {
                content_box.remove(&child);
            }
            let np = ui::notepad::build_notepad(store_n.clone(), key_n.clone());
            content_box.append(&np);
        }
    });
    content_box.set_vexpand(true);
    let content_header = HeaderBar::new();

    let search = SearchEntry::new();
    search.set_placeholder_text(Some("Rechercher…"));
    search.set_hexpand(true);
    search.set_max_width_chars(40);
    content_header.set_title_widget(Some(&search));

    let gen_btn  = Button::from_icon_name("preferences-system-symbolic");
    gen_btn.add_css_class("flat");
    gen_btn.set_tooltip_text(Some("Générateur"));
    content_header.pack_end(&gen_btn);

    let sort_btn = Button::from_icon_name("view-sort-ascending-symbolic");
    sort_btn.add_css_class("flat");
    sort_btn.set_tooltip_text(Some("Trier A→Z / Z→A"));
    content_header.pack_end(&sort_btn);
    content_box.append(&content_header);

    let count  = db_entries.borrow().len();
    let banner = Banner::new(&format!("\u{1F510} {} entrée{}", count, if count != 1 { "s" } else { "" }));
    banner.set_revealed(true);
    content_box.append(&banner);

    let toast_overlay = ToastOverlay::new();
    toast_overlay.set_vexpand(true);
    toast_overlay.set_hexpand(true);

    let scroll = ScrolledWindow::new();
    scroll.set_vexpand(true);
    scroll.set_hexpand(true);
    scroll.set_policy(gtk4::PolicyType::Never, gtk4::PolicyType::Automatic);

    let entries_list = ListBox::new();
    entries_list.set_selection_mode(SelectionMode::None);
    entries_list.add_css_class("boxed-list");
    entries_list.set_margin_top(12);   entries_list.set_margin_bottom(12);
    entries_list.set_margin_start(16); entries_list.set_margin_end(16);

    let empty_page = StatusPage::new();
    empty_page.set_icon_name(Some("dialog-password-symbolic"));
    empty_page.set_title("Aucune entrée");
    empty_page.set_description(Some("Cliquez sur + pour ajouter votre premier mot de passe"));
    empty_page.set_vexpand(true);

    let ctx = VaultContext::new(
        store.clone(), key.clone(), db_entries.clone(),
        entries_list.clone(), banner.clone(),
        toast_overlay.clone(), empty_page.clone(),
    );

    for entry in db_entries.borrow().iter() {
        entries_list.append(&build_entry_row(entry, &ctx));
    }

    let inner_box = GtkBox::new(Orientation::Vertical, 0);
    inner_box.set_vexpand(true);
    ctx.refresh_empty_state();
    inner_box.append(&entries_list);
    inner_box.append(&empty_page);
    scroll.set_child(Some(&inner_box));
    toast_overlay.set_child(Some(&scroll));
    content_box.append(&toast_overlay);

    // Tri A<->Z
    let initial_sort = prefs.borrow().sort_ascending;
    let sort_asc = Rc::new(RefCell::new(initial_sort));
    let ctx_sort = ctx.clone();
    sort_btn.connect_clicked(move |_| {
        let mut asc = sort_asc.borrow_mut();
        *asc = !*asc;
        let ascending = *asc;
        drop(asc);
        ctx_sort.db_entries.borrow_mut().sort_by(|a, b| {
            if ascending { a.title.to_lowercase().cmp(&b.title.to_lowercase()) }
            else         { b.title.to_lowercase().cmp(&a.title.to_lowercase()) }
        });
        prefs.borrow_mut().sort_ascending = ascending;
        prefs.borrow().save();
        while let Some(child) = ctx_sort.entries_list.first_child() {
            ctx_sort.entries_list.remove(&child);
        }
        let snap: Vec<VaultEntry> = ctx_sort.db_entries.borrow().clone();
        for entry in &snap {
            ctx_sort.entries_list.append(&build_entry_row(entry, &ctx_sort));
        }
        ctx_sort.refresh_empty_state();
    });

    // Filtre
    let cat_filter:    Rc<RefCell<Option<String>>> = Rc::new(RefCell::new(None));
    let search_filter: Rc<RefCell<String>>         = Rc::new(RefCell::new(String::new()));

    let ctx_f  = ctx.clone();
    let cat_f  = cat_filter.clone();
    let srch_f = search_filter.clone();
    let apply_filter = Rc::new(move || {
        let cat = cat_f.borrow().clone();
        let q   = srch_f.borrow().to_lowercase();
        let db  = ctx_f.db_entries.borrow();
        let mut visible = 0usize;
        let mut i       = 0i32;
        while let Some(row) = ctx_f.entries_list.row_at_index(i) {
            let show = db.get(i as usize).is_none_or(|e| {
                let cat_ok  = cat.as_deref().is_none_or(|c| e.category == c);
                let srch_ok = q.is_empty()
                    || e.title.to_lowercase().contains(&q)
                    || e.username.to_lowercase().contains(&q)
                    || e.category.to_lowercase().contains(&q);
                cat_ok && srch_ok
            });
            row.set_visible(show);
            if show { visible += 1; }
            i += 1;
        }
        ctx_f.empty_page.set_visible(visible == 0);
        ctx_f.entries_list.set_visible(visible > 0 || db.is_empty());
    });

    let af1 = apply_filter.clone();
    let cf1 = cat_filter.clone();
    category_list.connect_row_selected(move |_, sel| {
        let txt = sel
            .and_then(|r| r.child().and_downcast_ref::<Label>().map(|l| l.text().to_string()))
            .unwrap_or_default();
        *cf1.borrow_mut() = if txt.contains("Perso")   { Some("Perso".to_string()) }
            else if txt.contains("Pro")                 { Some("Pro".to_string()) }
            else if txt.contains("Finance")             { Some("Finance".to_string()) }
            else                                         { None };
        af1();
    });

    let af2 = apply_filter.clone();
    let sf2 = search_filter.clone();
    search.connect_search_changed(move |s| {
        *sf2.borrow_mut() = s.text().to_string();
        af2();
    });

    let wl = window.clone();
    lock_btn.connect_clicked(move |_| {
        wl.set_content(Some(&build_login_screen(wl.clone())));
        wl.set_default_size(480, 560);
        wl.set_size_request(0, 0);
    });

    let wg = window.clone();
    gen_btn.connect_clicked(move |_| {
        ui::dialogs::show_generator_dialog(wg.upcast_ref::<gtk4::Widget>());
    });

    let ctx_add = ctx.clone();
    let wa      = window.clone();
    add_btn.connect_clicked(move |_| {
        ui::dialogs::show_add_dialog(wa.upcast_ref::<gtk4::Widget>(), ctx_add.clone());
    });

    let split_view = NavigationSplitView::new();
    split_view.set_sidebar(Some(&NavigationPage::new(&sidebar_box, "Catégories")));
    split_view.set_content(Some(&NavigationPage::new(&content_box, "Entrées")));
    split_view.set_min_sidebar_width(200.0);
    split_view.set_max_sidebar_width(280.0);
    split_view.set_vexpand(true);
    split_view.set_hexpand(true);

    let tv = ToolbarView::new();
    tv.set_content(Some(&split_view));
    tv.set_vexpand(true);
    tv
}

pub fn build_login_screen(window: Rc<ApplicationWindow>) -> ToolbarView {
    let login_toolbar = ToolbarView::new();
    let login_header  = HeaderBar::new();
    login_header.set_title_widget(Some(
        &Label::builder().label("VaultPass").css_classes(["heading"]).build()
    ));
    login_toolbar.add_top_bar(&login_header);

    let login_box = GtkBox::new(Orientation::Vertical, 24);
    login_box.set_valign(gtk4::Align::Center);
    login_box.set_halign(gtk4::Align::Center);
    login_box.set_margin_top(48);   login_box.set_margin_bottom(48);
    login_box.set_margin_start(48); login_box.set_margin_end(48);

    let status = StatusPage::new();
    status.set_icon_name(Some("dialog-password-symbolic"));
    status.set_title("VaultPass");
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

    let unlock_btn = Button::with_label("\u{1F513} Déverrouiller");
    unlock_btn.add_css_class("suggested-action");
    unlock_btn.add_css_class("pill");
    unlock_btn.set_halign(gtk4::Align::Center);
    login_box.append(&unlock_btn);

    let hint = Label::new(Some(
        "\u{1F4A1} Premier lancement : tapez votre mot de passe maître pour créer un nouveau coffre."
    ));
    hint.add_css_class("caption");
    hint.add_css_class("dim-label");
    hint.set_wrap(true);
    hint.set_justify(gtk4::Justification::Center);
    login_box.append(&hint);
    login_toolbar.set_content(Some(&login_box));

    let err = error_lbl.clone();
    let pw  = pw_entry.clone();
    let win = window.clone();

    let do_unlock = Rc::new(move || {
        let password = pw.text().to_string();
        if password.is_empty() {
            err.set_text("⚠️ Mot de passe vide.");
            err.set_visible(true);
            return;
        }
        err.set_visible(false);

        let path  = db_path();
        let store = match VaultStore::open(path.to_str().unwrap_or("/tmp/vault.db")) {
            Ok(s)  => Rc::new(s),
            Err(StoreError::AlreadyLocked) => {
                err.set_text("❌ VaultPass est déjà ouvert dans une autre fenêtre.");
                err.set_visible(true);
                return;
            }
            Err(e) => {
                err.set_text(&format!("❌ Base : {e}"));
                err.set_visible(true);
                return;
            }
        };

        let salt_vec = match store.load_salt() {
            Ok(Some(s)) => s,
            Ok(None) => {
                let s = kdf::generate_salt();
                if let Err(e) = store.save_salt(&s) {
                    err.set_text(&format!("❌ Sel : {e}")); err.set_visible(true); return;
                }
                s.to_vec()
            }
            Err(e) => { err.set_text(&format!("❌ Sel : {e}")); err.set_visible(true); return; }
        };

        let salt_arr: [u8; 32] = match salt_vec.try_into() {
            Ok(a)  => a,
            Err(_) => { err.set_text("❌ Sel corrompu."); err.set_visible(true); return; }
        };

        let master = match kdf::derive_master_key(password.as_bytes(), &salt_arr) {
            Ok(k)  => k,
            Err(e) => { err.set_text(&format!("❌ KDF : {e}")); err.set_visible(true); return; }
        };
        let key: Rc<Zeroizing<[u8; 32]>> = Rc::new(master.0);

        match store.verify_or_init_sentinel(&key) {
            Ok(true)  => {}
            Ok(false) => { err.set_text("❌ Mot de passe incorrect."); err.set_visible(true); return; }
            Err(e)    => { err.set_text(&format!("❌ Vérif : {e}")); err.set_visible(true); return; }
        }

        let al = setup_autolock(win.upcast_ref::<gtk4::Window>(), win.clone());
        let vault = build_vault(store, key, win.clone(), Rc::new(std::cell::RefCell::new(Prefs::load())), al);
        win.set_content(Some(&vault));
        win.set_default_size(1024, 680);
        win.set_size_request(800, 500);
    });

    let du1 = do_unlock.clone();
    unlock_btn.connect_clicked(move |_| du1());
    let du2 = do_unlock.clone();
    pw_entry.connect_activate(move |_| du2());
    login_toolbar
}

fn setup_autolock(
    win:   &gtk4::Window,
    window: Rc<libadwaita::ApplicationWindow>,
) -> Rc<ui::autolock::AutoLock> {
    let delay_secs = ui::prefs::Prefs::load().lock_delay_secs;
    let al = Rc::new(ui::autolock::AutoLock::new(delay_secs));

    // Réinitialiser sur toute activité clavier/souris
    al.bind_widget(win);

    let al2 = al.clone();
    al2.start(move || {
        let w = window.clone();
        w.set_content(Some(&build_login_screen(w.clone())));
    });

    al
}
