// https://0xrick.github.io/win-internals/pe1/

use crate::error::{PeError, Result};
use crate::utils::BinaryReader;

#[derive(Debug)]
pub struct DosHeader {
  pub e_magic: u16,      // Magic number
  pub e_cblp: u16,       // Bytes on last page of file
  pub e_cp: u16,         // Pages in file
  pub e_crlc: u16,       // Relocations
  pub e_cparhdr: u16,    // Size of header in paragraphs
  pub e_minalloc: u16,   // Minimum extra paragraphs needed
  pub e_maxalloc: u16,   // Maximum extra paragraphs needed
  pub e_ss: u16,         // Initial (relative) SS value
  pub e_sp: u16,         // Initial SP value
  pub e_csum: u16,       // Checksum
  pub e_ip: u16,         // Initial IP value
  pub e_cs: u16,         // Initial (relative) CS value
  pub e_lfarlc: u16,     // File address of relocation table
  pub e_ovno: u16,       // Overlay number
  pub e_res: [u16; 4],   // Reserved words
  pub e_oemid: u16,      // OEM identifier (for e_oeminfo)
  pub e_oeminfo: u16,    // OEM information; e_oemid specific
  pub e_res2: [u16; 10], // Reserved words
  pub e_lfanew: i32,     // File address of new exe header
}

// SKIP: DOS STUB

impl DosHeader {
  pub const SIZE: usize = 64;

  pub fn parse(data: &[u8]) -> Result<Self> {
    let mut reader = BinaryReader::new(data);

    let e_magic = reader.read_u16()?;
    if e_magic != 0x5A4D {
      return Err(PeError::NotPeFile);
    }

    if data.len() < Self::SIZE {
      return Err(PeError::InvalidHeader("DOS header too small".to_string()));
    }

    Ok(DosHeader {
      e_magic,
      e_cblp: reader.read_u16()?,
      e_cp: reader.read_u16()?,
      e_crlc: reader.read_u16()?,
      e_cparhdr: reader.read_u16()?,
      e_minalloc: reader.read_u16()?,
      e_maxalloc: reader.read_u16()?,
      e_ss: reader.read_u16()?,
      e_sp: reader.read_u16()?,
      e_csum: reader.read_u16()?,
      e_ip: reader.read_u16()?,
      e_cs: reader.read_u16()?,
      e_lfarlc: reader.read_u16()?,
      e_ovno: reader.read_u16()?,
      e_res: [reader.read_u16()?, reader.read_u16()?, reader.read_u16()?, reader.read_u16()?],
      e_oemid: reader.read_u16()?,
      e_oeminfo: reader.read_u16()?,
      e_res2: [
        reader.read_u16()?,
        reader.read_u16()?,
        reader.read_u16()?,
        reader.read_u16()?,
        reader.read_u16()?,
        reader.read_u16()?,
        reader.read_u16()?,
        reader.read_u16()?,
        reader.read_u16()?,
        reader.read_u16()?,
      ],
      e_lfanew: reader.read_i32()?,
    })
  }
}

// SKIP: IMAGE_NT_HEADER(32)(64) - Signature checked in parser

// IMAGE_FILE_HEADER
#[derive(Debug)]
pub struct CoffHeader {
  pub machine: u16,
  pub number_of_sections: u16,
  pub time_date_stamp: u32,
  pub pointer_to_symbol_table: u32,
  pub number_of_symbols: u32,
  pub size_of_optional_header: u16,
  pub characteristics: u16
}

impl CoffHeader {
  pub fn parse(data: &[u8]) -> Result<Self> {
    let mut reader = BinaryReader::new(data);

    Ok(CoffHeader {
      machine: reader.read_u16()?,
      number_of_sections: reader.read_u16()?,
      time_date_stamp: reader.read_u32()?,
      pointer_to_symbol_table: reader.read_u32()?,
      number_of_symbols: reader.read_u32()?,
      size_of_optional_header: reader.read_u16()?,
      characteristics: reader.read_u16()?
    })
  }
}