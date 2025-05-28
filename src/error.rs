use std::fmt;

pub type Result<T> = std::result::Result<T, PeError>;

#[derive(Debug)]
pub enum PeError {
  Io(String),
  InvalidArguments(String),
  CorruptedFile(String),
  InvalidHeader(String),
  NotPeFile,
}

impl fmt::Display for PeError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      | PeError::Io(msg) => write!(f, "I/O error: {}", msg),
      | PeError::InvalidArguments(msg) => write!(f, "Invalid Arguments: {}", msg),
      | PeError::CorruptedFile(msg) => write!(f, "Corrupted File: {}", msg),
      | PeError::InvalidHeader(msg) => write!(f, "Invalid Header: {}", msg),
      | PeError::NotPeFile => write!(f, "Not a PE file"),
    }
  }
}

impl std::error::Error for PeError {}

impl From<std::io::Error> for PeError {
  fn from(error: std::io::Error) -> Self {
    PeError::Io(error.to_string())
  }
}
