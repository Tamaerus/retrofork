use serde::{ser::Serializer, Serialize};
use std::error::Error as StdError;

pub type Result<T> = std::result::Result<T, Error>;
pub type BoxDynError = Box<dyn StdError + Send + Sync>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("Other error: {0}")]
    Other(String),
}

impl Serialize for Error {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.to_string().as_ref())
    }
}
