use std::cell::Cell;
use std::rc::Rc;
use gtk4::glib::source::timeout_add_seconds_local;
use gtk4::glib::ControlFlow;

/// Durées de verrouillage disponibles (en secondes)
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LockDelay {
    TwoMin     = 120,
    FiveMin    = 300,
    FifteenMin = 900,
    ThirtyMin  = 1800,
    OneHour    = 3600,
}

impl LockDelay {
    pub fn label(&self) -> &'static str {
        match self {
            LockDelay::TwoMin     => "2 minutes",
            LockDelay::FiveMin    => "5 minutes",
            LockDelay::FifteenMin => "15 minutes",
            LockDelay::ThirtyMin  => "30 minutes",
            LockDelay::OneHour    => "1 heure",
        }
    }

    pub fn all() -> &'static [LockDelay] {
        &[
            LockDelay::TwoMin,
            LockDelay::FiveMin,
            LockDelay::FifteenMin,
            LockDelay::ThirtyMin,
            LockDelay::OneHour,
        ]
    }
}

/// Gestionnaire d'auto-verrouillage basé sur l'inactivité.
pub struct AutoLock {
    pub last_activity: Rc<Cell<u64>>,
    pub delay:         Rc<Cell<u64>>,
}

impl AutoLock {
    pub fn new(delay: LockDelay) -> Self {
        Self {
            last_activity: Rc::new(Cell::new(Self::now())),
            delay:         Rc::new(Cell::new(delay as u64)),
        }
    }

    pub fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Réinitialise le timer d'inactivité.
    pub fn reset(&self) {
        self.last_activity.set(Self::now());
    }

    /// Retourne true si le délai d'inactivité est dépassé.
    pub fn is_expired(&self) -> bool {
        Self::now().saturating_sub(self.last_activity.get()) >= self.delay.get()
    }

    /// Change le délai (depuis les préférences).
    pub fn set_delay(&self, delay: LockDelay) {
        self.delay.set(delay as u64);
        self.reset();
    }

    /// Lance la boucle de surveillance toutes les 10 secondes.
    /// `on_lock` est appelé quand le délai expire.
    pub fn start<F>(&self, on_lock: F)
    where
        F: Fn() + 'static,
    {
        let last  = self.last_activity.clone();
        let delay = self.delay.clone();

        timeout_add_seconds_local(10, move || {
            let elapsed = Self::now().saturating_sub(last.get());
            if elapsed >= delay.get() {
                on_lock();
                last.set(Self::now());
            }
            ControlFlow::Continue
        });
    }
}
