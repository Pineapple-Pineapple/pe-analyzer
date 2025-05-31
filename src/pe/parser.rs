use super::structures::{CoffHeader, DosHeader, OptionalHeader};
use crate::error::{PeError, Result};

pub struct PeFile {
  pub data: Vec<u8>,
  pub dos_header: DosHeader,
  pub coff_header: CoffHeader,
  pub optional_header: OptionalHeader,
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

    let optional_start = coff_start + CoffHeader::SIZE;
    if optional_start + 2 > data.len() {
      return Err(PeError::CorruptedFile("Cannot read Option Header magic".to_string()));
    }

    let optional_magic = u16::from_le_bytes([data[optional_start], data[optional_start + 1]]);
    let is_64_bit = optional_magic == 0x20B;

    let optional_header = OptionalHeader::parse(&data[optional_start..], is_64_bit)?;

    Ok(PeFile { data, dos_header, coff_header, optional_header })
  }

  pub fn from_file(path: &str) -> Result<Self> {
    let data = std::fs::read(path)?;
    Self::from_bytes(data)
  }
}
