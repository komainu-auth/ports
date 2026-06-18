use std::time::{Duration, SystemTime};

/// Port that abstracts obtaining the current time and computing expirations.
///
/// During tests, swap in an implementation that returns a fixed time to make
/// time-dependent logic deterministic.
///
/// # Default implementations
///
/// [`calculate_expiration`] and [`is_expired`] have default implementations, so
/// implementing [`now`] alone is sufficient.
///
/// # Example
///
/// ```rust,ignore
/// use komainu_ports::driven::Clock;
/// use std::time::SystemTime;
///
/// struct SystemClock;
///
/// impl Clock for SystemClock {
///     fn now(&self) -> SystemTime {
///         SystemTime::now()
///     }
/// }
/// ```
///
/// [`now`]: Clock::now
/// [`calculate_expiration`]: Clock::calculate_expiration
/// [`is_expired`]: Clock::is_expired
pub trait Clock {
    /// Return the current time.
    fn now(&self) -> SystemTime;

    /// Compute an expiration by adding `duration` to the current time.
    ///
    /// Used to calculate `expires_at` for tokens and authorization codes.
    fn calculate_expiration(&self, duration: Duration) -> SystemTime {
        self.now() + duration
    }

    /// Return `true` if `expire_at` is at or before the current time (expired).
    ///
    /// Treats `now() == expire_at` as expired.
    fn is_expired(&self, expire_at: SystemTime) -> bool {
        self.now() >= expire_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    struct FixedClock(SystemTime);

    impl Clock for FixedClock {
        fn now(&self) -> SystemTime {
            self.0
        }
    }

    #[test]
    fn now_returns_fixed_time() {
        let clock = FixedClock(ts(1000));
        assert_eq!(clock.now(), ts(1000));
    }

    #[test]
    fn calculate_expiration_adds_duration() {
        let clock = FixedClock(ts(1000));
        let expiration = clock.calculate_expiration(Duration::from_secs(3600));
        assert_eq!(expiration, ts(4600));
    }

    #[test]
    fn is_expired_returns_true_when_now_equals_expire_at() {
        let clock = FixedClock(ts(1000));
        assert!(clock.is_expired(ts(1000)));
    }

    #[test]
    fn is_expired_returns_true_when_now_is_after_expire_at() {
        let clock = FixedClock(ts(1001));
        assert!(clock.is_expired(ts(1000)));
    }

    #[test]
    fn is_expired_returns_false_when_now_is_before_expire_at() {
        let clock = FixedClock(ts(999));
        assert!(!clock.is_expired(ts(1000)));
    }

    #[test]
    fn calculate_expiration_zero_duration_returns_now() {
        let clock = FixedClock(ts(500));
        assert_eq!(clock.calculate_expiration(Duration::ZERO), ts(500));
    }
}
