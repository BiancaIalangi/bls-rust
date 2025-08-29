use std::fmt;

#[derive(Debug, PartialEq, Clone)]
/// `BlsError` type for error
pub enum BlsError {
    InvalidData,
    BadSize,
    InternalError,
    SerializeError,
}

impl fmt::Display for BlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlsError::InvalidData => write!(f, "invalid data"),
            BlsError::BadSize => write!(f, "bad parameter size"),
            BlsError::InternalError => write!(f, "internal error"),
            BlsError::SerializeError => write!(f, "serialize error"),
        }
    }
}
