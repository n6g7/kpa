//! Time that counts the machine's sleep.
//!
//! The idle timer is what still locks a database when nothing tells kpa of
//! a suspend (`docs/threat-model.md` ASM-7), so the time it measures has to
//! pass while the machine is asleep too. `std::time::Instant` doesn't: on
//! Linux it stops across a suspend, which would leave a database unlocked
//! after a night's sleep with most of its `idle_timeout` still to run. A
//! [`Moment`] keeps counting.
//!
//! Only the idle timer needs this. A prompt's or an approval's deadline is
//! awake time, and stays an `Instant`.

use std::ops::{Add, Sub};
use std::time::Duration;

/// A point on a clock that keeps counting while the machine sleeps. Only
/// differences between two of them mean anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Moment(Duration);

impl Moment {
    /// The clock now.
    pub fn now() -> Moment {
        Moment(since_boot())
    }

    /// How long after `earlier` this is, zero if `earlier` is later.
    pub fn saturating_duration_since(self, earlier: Moment) -> Duration {
        self.0.saturating_sub(earlier.0)
    }
}

impl Add<Duration> for Moment {
    type Output = Moment;

    fn add(self, later: Duration) -> Moment {
        Moment(self.0 + later)
    }
}

impl Sub<Duration> for Moment {
    type Output = Moment;

    fn sub(self, earlier: Duration) -> Moment {
        Moment(self.0.saturating_sub(earlier))
    }
}

/// Linux's `CLOCK_BOOTTIME`: `CLOCK_MONOTONIC` plus the time spent
/// suspended.
fn since_boot() -> Duration {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    Duration::new(
        now.tv_sec.try_into().unwrap_or(0),
        now.tv_nsec.try_into().unwrap_or(0),
    )
}

#[cfg(test)]
mod tests {
    use rustix::time::{ClockId, clock_gettime};

    use super::*;

    fn read(id: ClockId) -> Duration {
        let now = clock_gettime(id);
        Duration::new(now.tv_sec as u64, now.tv_nsec as u32)
    }

    /// A moment is a `CLOCK_BOOTTIME` reading, which includes the time the
    /// machine has spent suspended: it is never behind an earlier reading of
    /// the monotonic clock, and a reading taken between two of the boot
    /// clock's lies between them.
    #[test]
    fn now_is_on_the_clock_that_counts_sleep() {
        let monotonic = read(ClockId::Monotonic);
        let before = read(ClockId::Boottime);
        let now = Moment::now();
        let after = read(ClockId::Boottime);

        assert!(Moment(before) <= now && now <= Moment(after));
        assert!(now.0 >= monotonic);
    }

    #[test]
    fn differences_saturate_at_zero_and_add_and_subtract() {
        let early = Moment(Duration::from_secs(10));
        let late = early + Duration::from_secs(5);

        assert_eq!(
            late.saturating_duration_since(early),
            Duration::from_secs(5)
        );
        assert_eq!(early.saturating_duration_since(late), Duration::ZERO);
        assert_eq!(late - Duration::from_secs(5), early);
        assert_eq!(early - Duration::from_secs(60), Moment(Duration::ZERO));
    }
}
