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

/// The block time in milliseconds.
///
/// TODO: this must be included in the global blockchain data, not hard-wired as a constant. If the
/// node is joining an existing network, the block time must be read from the latest final block;
/// while if the node is creating a new network it must be specified in the command line.
pub const BLOCK_TIME_MS: u64 = 10_000;

/// The stake of each node is multiplied by this factor at every block. These numbers make for a
/// ~10% APY.
///
/// Since our rewards do not automatically compound, they are minted into an account's regular
/// balance rather than its staking balance.
pub const BLOCK_REWARD_NUMERATOR: u64 = 1073741857;
pub const BLOCK_REWARD_DENOMINATOR_LOG2: u8 = 30;
