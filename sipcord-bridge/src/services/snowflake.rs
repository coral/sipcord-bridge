//! Discord Snowflake ID — type-safe wrapper around u64.
//!
//! Snowflakes encode a millisecond timestamp (bits 22+) relative to the
//! Discord epoch (2015-01-01T00:00:00.000Z), plus worker/process/sequence
//! metadata in the lower 22 bits.

use std::fmt;
use std::ops::Deref;

/// Discord epoch: 2015-01-01T00:00:00.000Z in Unix millis
const DISCORD_EPOCH_MS: u64 = 1_420_070_400_000;

/// Smallest plausible snowflake (~17 digits).
/// Corresponds to roughly mid-2015, shortly after Discord launched.
/// 21_154_535_154_122_752 = (1433289600000 - DISCORD_EPOCH_MS) << 22  (2015-06-03)
const MIN_SNOWFLAKE: u64 = 21_154_535_154_122_752;

/// Largest plausible snowflake — year 2100 relative to Discord epoch.
/// (2_682_288_000_000 << 22) ≈ 11.2e18, still well within u64.
const MAX_SNOWFLAKE: u64 = 2_682_288_000_000 << 22;

/// A Discord Snowflake ID.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Snowflake(u64);

impl Snowflake {
    /// Wrap a raw u64 as a Snowflake (no validation).
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// The raw u64 value.
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Whether this is a plausible Discord snowflake.
    ///
    /// Checks that the value is at least 17 digits (all real Discord IDs are)
    /// and that the embedded timestamp falls between Discord's launch (~mid 2015)
    /// and the year 2100.
    pub const fn is_valid(self) -> bool {
        self.0 >= MIN_SNOWFLAKE && self.0 <= MAX_SNOWFLAKE
    }

    /// Milliseconds since Unix epoch encoded in this snowflake.
    pub const fn timestamp_ms(self) -> u64 {
        (self.0 >> 22) + DISCORD_EPOCH_MS
    }
}

// Transparent access as u64

impl Deref for Snowflake {
    type Target = u64;
    fn deref(&self) -> &u64 {
        &self.0
    }
}

impl From<u64> for Snowflake {
    fn from(v: u64) -> Self {
        Self(v)
    }
}

impl From<Snowflake> for u64 {
    fn from(s: Snowflake) -> u64 {
        s.0
    }
}

impl std::str::FromStr for Snowflake {
    type Err = std::num::ParseIntError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse::<u64>().map(Self)
    }
}

// Display / Debug

impl fmt::Display for Snowflake {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for Snowflake {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Snowflake({})", self.0)
    }
}

// Serde — deserialise from integer OR string (Discord uses both)

impl serde::Serialize for Snowflake {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for Snowflake {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Snowflake;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a snowflake as integer or string")
            }

            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Snowflake, E> {
                Ok(Snowflake(v))
            }

            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Snowflake, E> {
                u64::try_from(v)
                    .map(Snowflake)
                    .map_err(|_| E::custom("snowflake cannot be negative"))
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Snowflake, E> {
                v.parse::<u64>().map(Snowflake).map_err(E::custom)
            }
        }

        deserializer.deserialize_any(Visitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_is_invalid() {
        assert!(!Snowflake::new(0).is_valid());
    }

    #[test]
    fn too_short_is_invalid() {
        // 9 digits — way too small to be a Discord snowflake
        assert!(!Snowflake::new(123_456_789).is_valid());
        // 16 digits — still too short
        assert!(!Snowflake::new(1_000_000_000_000_000).is_valid());
    }

    #[test]
    fn real_snowflakes_are_valid() {
        // Discord's own system messages channel
        assert!(Snowflake::new(80_351_110_224_678_912).is_valid());
        // A typical modern channel ID
        assert!(Snowflake::new(1_098_765_432_101_234_567).is_valid());
    }

    #[test]
    fn timestamp_decodes() {
        let s = Snowflake::new(80_351_110_224_678_912);
        assert!(s.timestamp_ms() > DISCORD_EPOCH_MS);
        // Should be sometime in 2015
        let year_2016 = 1_451_606_400_000u64; // 2016-01-01 Unix ms
        assert!(s.timestamp_ms() < year_2016);
    }

    #[test]
    fn deref_to_u64() {
        let s = Snowflake::new(80_351_110_224_678_912);
        let v: u64 = *s;
        assert_eq!(v, 80_351_110_224_678_912);
    }

    #[test]
    fn serde_roundtrip_integer() {
        let s = Snowflake::new(80_351_110_224_678_912);
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(json, "80351110224678912");
        let back: Snowflake = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn serde_from_string() {
        let back: Snowflake = serde_json::from_str("\"80351110224678912\"").unwrap();
        assert_eq!(back.get(), 80_351_110_224_678_912);
    }

    #[test]
    fn toml_integer_deserializes() {
        #[derive(serde::Deserialize)]
        struct Wrapper {
            id: Snowflake,
        }

        let parsed: Wrapper = toml::from_str("id = 123456789012345678").unwrap();
        assert_eq!(parsed.id, Snowflake::new(123_456_789_012_345_678));
        assert!(toml::from_str::<Wrapper>("id = -1").is_err());
    }
}
