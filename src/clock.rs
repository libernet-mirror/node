use std::fmt::Debug;
use std::time::SystemTime;

pub trait Clock: Debug + Send + Sync {
    fn now(&self) -> SystemTime;
}

#[derive(Default, Debug)]
pub struct RealClock {}

impl Clock for RealClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use std::sync::Mutex;
    use std::time::Duration;

    #[derive(Debug)]
    pub struct MockClock {
        time: Mutex<SystemTime>,
    }

    impl MockClock {
        pub fn new(start_time: SystemTime) -> Self {
            Self {
                time: Mutex::new(start_time),
            }
        }

        pub async fn advance(&self, delta: Duration) {
            let mut lock = self.time.lock().unwrap();
            *lock += delta;
            tokio::time::advance(delta).await;
        }
    }

    impl Default for MockClock {
        fn default() -> Self {
            Self {
                time: Mutex::new(SystemTime::UNIX_EPOCH),
            }
        }
    }

    impl Clock for MockClock {
        fn now(&self) -> SystemTime {
            *self.time.lock().unwrap()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use test::MockClock;
    use tokio::time::Instant;

    #[test]
    fn test_default_mock_clock() {
        let clock = MockClock::default();
        assert_eq!(clock.now(), SystemTime::UNIX_EPOCH);
    }

    #[test]
    fn test_new_mock_clock() {
        let clock = MockClock::new(SystemTime::UNIX_EPOCH + Duration::from_secs(123));
        assert_eq!(
            clock.now(),
            SystemTime::UNIX_EPOCH + Duration::from_secs(123)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_advance_mock_clock() {
        let clock = MockClock::new(SystemTime::UNIX_EPOCH + Duration::from_secs(456));
        let start_instant = Instant::now();
        clock.advance(Duration::from_secs(789)).await;
        assert_eq!(
            clock.now(),
            SystemTime::UNIX_EPOCH + Duration::from_secs(1245)
        );
        assert_eq!(Instant::now(), start_instant + Duration::from_secs(789));
    }
}
