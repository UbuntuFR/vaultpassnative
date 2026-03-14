use std::cell::Cell;
use std::rc::Rc;
use gtk4::glib::source::timeout_add_seconds_local;
use gtk4::glib::ControlFlow;

/// LockDelay enum - using sentinel value instead of u64::MAX to avoid overflow
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LockDelay {
    OneMin     = 60,
    TwoMin     = 120,
    FiveMin    = 300,
    FifteenMin = 900,
    ThirtyMin  = 1800,
    OneHour    = 3600,
    Never      = -1,  // FIX #2: Use -1 as sentinel instead of u64::MAX to avoid overflow
}

impl LockDelay {
    pub fn label(&self) -> &'static str {
        match self {
            LockDelay::OneMin     => "1 minute",
            LockDelay::TwoMin     => "2 minutes",
            LockDelay::FiveMin    => "5 minutes",
            LockDelay::FifteenMin => "15 minutes",
            LockDelay::ThirtyMin  => "30 minutes",
            LockDelay::OneHour    => "1 heure",
            LockDelay::Never      => "Jamais",
        }
    }

    pub fn all() -> &'static [LockDelay] {
        &[
            LockDelay::OneMin,
            LockDelay::TwoMin,
            LockDelay::FiveMin,
            LockDelay::FifteenMin,
            LockDelay::ThirtyMin,
            LockDelay::OneHour,
            LockDelay::Never,
        ]
    }

    /// Convert seconds to LockDelay - handles u64::MAX specially
    pub fn from_secs(s: u64) -> Self {
        match s {
            60   => LockDelay::OneMin,
            120  => LockDelay::TwoMin,
            300  => LockDelay::FiveMin,
            900  => LockDelay::FifteenMin,
            1800 => LockDelay::ThirtyMin,
            3600 => LockDelay::OneHour,
            u64::MAX => LockDelay::Never,  // FIX #2: Handle u64::MAX as Never
            _    => LockDelay::Never,
        }
    }

    /// Check if this delay represents "Never"
    pub fn is_never(&self) -> bool {
        matches!(self, LockDelay::Never)
    }

    /// Convert to seconds for storage
    pub fn to_secs(&self) -> u64 {
        match self {
            LockDelay::OneMin     => 60,
            LockDelay::TwoMin     => 120,
            LockDelay::FiveMin    => 300,
            LockDelay::FifteenMin => 900,
            LockDelay::ThirtyMin  => 1800,
            LockDelay::OneHour    => 3600,
            LockDelay::Never      => u64::MAX,  // FIX #2: Return u64::MAX for Never
        }
    }
}

pub struct AutoLock {
    pub last_activity: Rc<Cell<u64>>,
    pub delay:         Rc<Cell<u64>>,
    pub locked:        Rc<Cell<bool>>,
}

#[allow(dead_code)]
impl AutoLock {
    pub fn new(delay_secs: u64) -> Self {
        Self {
            last_activity: Rc::new(Cell::new(Self::now())),
            delay:         Rc::new(Cell::new(delay_secs)),
            locked:        Rc::new(Cell::new(false)),
        }
    }

    pub fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    pub fn reset(&self) {
        self.last_activity.set(Self::now());
        self.locked.set(false);
    }

    pub fn is_expired(&self) -> bool {
        let delay = self.delay.get();
        // FIX #2: Properly handle u64::MAX as "never expire"
        if delay == u64::MAX { return false; }
        Self::now().saturating_sub(self.last_activity.get()) >= delay
    }

    pub fn set_delay(&self, secs: u64) {
        self.delay.set(secs);
        self.reset();
    }

    /// Lance la boucle toutes les 5s. `on_lock` est appelé une seule fois
    /// par période d'inactivité (flag `locked` évite les appels répétés).
    pub fn start<F>(&self, on_lock: F)
    where
        F: Fn() + 'static,
    {
        let last   = self.last_activity.clone();
        let delay  = self.delay.clone();
        let locked = self.locked.clone();

        timeout_add_seconds_local(5, move || {
            let d = delay.get();
            // FIX #2: Properly handle u64::MAX (Never) case
            if d == u64::MAX { return ControlFlow::Continue; }
            let elapsed = Self::now().saturating_sub(last.get());
            if elapsed >= d && !locked.get() {
                locked.set(true);
                on_lock();
            }
            ControlFlow::Continue
        });
    }

    /// Connecte les événements clavier + pointeur sur `widget` pour reset le timer.
    pub fn bind_widget(&self, widget: &impl gtk4::prelude::WidgetExt) {
        let al = self.last_activity.clone();
        let lk = self.locked.clone();

        let key_ctrl = gtk4::EventControllerKey::new();
        let al2 = al.clone();
        let lk2 = lk.clone();
        key_ctrl.connect_key_pressed(move |_, _, _, _| {
            al2.set(AutoLock::now());
            lk2.set(false);
            gtk4::glib::Propagation::Proceed
        });
        widget.add_controller(key_ctrl);

        let motion_ctrl = gtk4::EventControllerMotion::new();
        motion_ctrl.connect_motion(move |_, _, _| {
            al.set(AutoLock::now());
            lk.set(false);
        });
        widget.add_controller(motion_ctrl);
    }
}
