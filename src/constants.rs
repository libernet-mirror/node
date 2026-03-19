/// Current major protocol version.
///
/// Bump it when the `proto` submodule gets updated with breaking changes.
pub const PROTOCOL_VERSION_MAJOR: u32 = 0;

/// Current minor protocol version.
///
/// Bump it when the `proto` submodule gets updated with compatible changes.
pub const PROTOCOL_VERSION_MINOR: u32 = 2;

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

/// All data files start with this prefix.
pub const DATA_FILE_SIGNATURE: &'static [u8; 8] = b"libernet";

/// Current data file format version.
pub const DATA_FILE_VERSION: u32 = 1;

/// Basic data file types.
pub const DATA_FILE_TYPE_BLOCK_DESCRIPTORS: u32 = 1;
pub const DATA_FILE_TYPE_ACCOUNT_TREE: u32 = 2;
pub const DATA_FILE_TYPE_ACCOUNT_DATA: u32 = 3;
pub const DATA_FILE_TYPE_PROGRAM_CODE_TREE: u32 = 4;
pub const DATA_FILE_TYPE_PROGRAM_STORAGE_TREE: u32 = 5;
pub const DATA_FILE_TYPE_PROGRAM_STORAGE_FOREST: u32 = 6;

/// Transaction data file types.
pub const DATA_FILE_TYPE_TRANSACTION_FOREST: u32 = 7;
pub const DATA_FILE_TYPE_TRANSACTION_INDICES: u32 = 8;
pub const DATA_FILE_TYPE_TRANSACTION_HEAP: u32 = 9;

/// Test data file type.
pub const DATA_FILE_TYPE_TEST_FILE: u32 = 0x01000000;
