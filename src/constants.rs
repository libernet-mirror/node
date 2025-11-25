/// Current major protocol version.
///
/// Bump it when the `proto` submodule gets updated with breaking changes.
pub const PROTOCOL_VERSION_MAJOR: u32 = 1;

/// Current minor protocol version.
///
/// Bump it when the `proto` submodule gets updated with compatible changes.
pub const PROTOCOL_VERSION_MINOR: u32 = 0;

/// Current protocol build.
///
/// Bump it when the `proto` submodule gets updated with non-observable changes, e.g. doc snippet
/// improvements.
pub const PROTOCOL_VERSION_BUILD: u32 = 0;

/// The stake of each node is multiplied by this factor at every block. These numbers make for a
/// ~10% APY.
///
/// Since our rewards do not automatically compound, they are minted into an account's regular
/// balance rather than its staking balance.
pub const BLOCK_REWARD_NUMERATOR: u64 = 1073741857;
pub const BLOCK_REWARD_DENOMINATOR_LOG2: u8 = 30;
