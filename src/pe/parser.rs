use crate::error::Result;
use crate::pe::structures::DosHeader;
use std::fmt;

pub struct PeFile {
  pub data: Vec<u8>,
  pub dos_header: DosHeader,
}

impl PeFile {
  pub fn from_bytes(data: Vec<u8>) -> Result<Self> {
    let dos_header = DosHeader::parse(&data)?;

    Ok(PeFile { data, dos_header })
  }

  pub fn from_file(path: &str) -> Result<Self> {
    let data = std::fs::read(path)?;
    Self::from_bytes(data)
  }
}

impl fmt::Display for PeFile {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    writeln!(f, "File size: {} bytes", self.data.len())?;
    write!(f, "{}", self.dos_header)?;
    Ok(())
  }
}
