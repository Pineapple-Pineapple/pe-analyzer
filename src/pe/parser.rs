use crate::error::{PeError, Result};
use super::structures::{ DosHeader, CoffHeader };

pub struct PeFile {
  pub data: Vec<u8>,
  pub dos_header: DosHeader,
  pub coff_header: CoffHeader
}

impl PeFile {
  pub fn from_bytes(data: Vec<u8>) -> Result<Self> {
    let dos_header = DosHeader::parse(&data)?;

    let pe_offset = dos_header.e_lfanew as usize;
    if pe_offset + 4 > data.len() {
      return Err(PeError::CorruptedFile("Invalid PE offset".to_string()));
    }

    if &data[pe_offset..pe_offset + 4] != b"PE\0\0" {
      return Err(PeError::NotPeFile);
    }

    let coff_start = pe_offset + 4;
    let coff_header = CoffHeader::parse(&data[coff_start..])?;

    Ok(PeFile { 
      data,
      dos_header,
      coff_header
    })
  }

  pub fn from_file(path: &str) -> Result<Self> {
    let data = std::fs::read(path)?;
    Self::from_bytes(data)
  }
}