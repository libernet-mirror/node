use blstrs::Scalar;
use crypto::utils;

pub fn parse_scalar(s: &str) -> Scalar {
    utils::parse_scalar(s).unwrap()
}
