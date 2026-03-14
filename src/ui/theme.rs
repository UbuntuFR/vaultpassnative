//! Gestion des thèmes visuels via libadwaita + CSS injecté.
use gtk4::CssProvider;

#[derive(Debug, Clone, PartialEq)]
pub enum Theme {
    System,
    Light,
    Dark,
    Nord,
    CatppuccinMocha,
    Everforest,
}

impl Theme {
    pub fn id(&self) -> &'static str {
        match self {
            Theme::System          => "system",
            Theme::Light           => "light",
            Theme::Dark            => "dark",
            Theme::Nord            => "nord",
            Theme::CatppuccinMocha => "catppuccin",
            Theme::Everforest      => "everforest",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Theme::System          => "🖥️  Système",
            Theme::Light           => "☀️  Clair",
            Theme::Dark            => "🌙  Sombre",
            Theme::Nord            => "❄️  Nord",
            Theme::CatppuccinMocha => "🌸  Catppuccin Mocha",
            Theme::Everforest      => "🌿  Everforest",
        }
    }

    pub fn all() -> &'static [Theme] {
        &[
            Theme::System,
            Theme::Light,
            Theme::Dark,
            Theme::Nord,
            Theme::CatppuccinMocha,
            Theme::Everforest,
        ]
    }

    pub fn from_id(id: &str) -> Self {
        match id {
            "light"      => Theme::Light,
            "dark"       => Theme::Dark,
            "nord"       => Theme::Nord,
            "catppuccin" => Theme::CatppuccinMocha,
            "everforest" => Theme::Everforest,
            _            => Theme::System,
        }
    }

    /// CSS variables injectées pour les thèmes custom.
    fn custom_css(&self) -> Option<&'static str> {
        match self {
            Theme::Nord => Some("
                @define-color accent_color #88C0D0;
                @define-color accent_bg_color #5E81AC;
                @define-color accent_fg_color #ECEFF4;
                @define-color window_bg_color #2E3440;
                @define-color window_fg_color #ECEFF4;
                @define-color view_bg_color #3B4252;
                @define-color view_fg_color #E5E9F0;
                @define-color headerbar_bg_color #2E3440;
                @define-color headerbar_fg_color #ECEFF4;
                @define-color card_bg_color #3B4252;
                @define-color card_fg_color #E5E9F0;
                @define-color sidebar_bg_color #2E3440;
                @define-color popover_bg_color #3B4252;
                @define-color dialog_bg_color #3B4252;
            "),
            Theme::CatppuccinMocha => Some("
                @define-color accent_color #CBA6F7;
                @define-color accent_bg_color #CBA6F7;
                @define-color accent_fg_color #1E1E2E;
                @define-color window_bg_color #1E1E2E;
                @define-color window_fg_color #CDD6F4;
                @define-color view_bg_color #181825;
                @define-color view_fg_color #CDD6F4;
                @define-color headerbar_bg_color #181825;
                @define-color headerbar_fg_color #CDD6F4;
                @define-color card_bg_color #313244;
                @define-color card_fg_color #CDD6F4;
                @define-color sidebar_bg_color #181825;
                @define-color popover_bg_color #313244;
                @define-color dialog_bg_color #313244;
            "),
            Theme::Everforest => Some("
                @define-color accent_color #A7C080;
                @define-color accent_bg_color #A7C080;
                @define-color accent_fg_color #272E33;
                @define-color window_bg_color #272E33;
                @define-color window_fg_color #D3C6AA;
                @define-color view_bg_color #2D353B;
                @define-color view_fg_color #D3C6AA;
                @define-color headerbar_bg_color #272E33;
                @define-color headerbar_fg_color #D3C6AA;
                @define-color card_bg_color #343F44;
                @define-color card_fg_color #D3C6AA;
                @define-color sidebar_bg_color #272E33;
                @define-color popover_bg_color #343F44;
                @define-color dialog_bg_color #343F44;
            "),
            _ => None,
        }
    }
}

use std::cell::OnceCell;

thread_local! {
    static CUSTOM_CSS_PROVIDER: OnceCell<CssProvider> = const { OnceCell::new() };
}

fn with_provider<F: FnOnce(&CssProvider)>(f: F) {
    CUSTOM_CSS_PROVIDER.with(|cell| {
        // FIX #4: Handle missing display gracefully instead of panicking
        let p = cell.get_or_init(|| {
            let p = CssProvider::new();
            // Only add provider if display is available
            if let Some(display) = gdk4::Display::default() {
                gtk4::style_context_add_provider_for_display(
                    &display,
                    &p,
                    gtk4::STYLE_PROVIDER_PRIORITY_USER,
                );
            }
            p
        });
        f(p);
    });
}

/// Applique un thème à toute l'application.
pub fn apply(theme: &Theme) {
    let manager = libadwaita::StyleManager::default();
    match theme {
        Theme::System => {
            manager.set_color_scheme(libadwaita::ColorScheme::Default);
            with_provider(|p| p.load_from_string(""));
        }
        Theme::Light => {
            manager.set_color_scheme(libadwaita::ColorScheme::ForceLight);
            with_provider(|p| p.load_from_string(""));
        }
        Theme::Dark => {
            manager.set_color_scheme(libadwaita::ColorScheme::ForceDark);
            with_provider(|p| p.load_from_string(""));
        }
        custom => {
            manager.set_color_scheme(libadwaita::ColorScheme::ForceDark);
            if let Some(css) = custom.custom_css() {
                with_provider(|p| p.load_from_string(css));
            }
        }
    }
}
