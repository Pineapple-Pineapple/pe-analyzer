// https://0xrick.github.io/win-internals/pe1/

use crate::error::{PeError, Result};
use crate::utils::BinaryReader;
use std::fmt;

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

impl fmt::Display for DosHeader {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    writeln!(f, "DOS Header:")?;
    writeln!(f, "  Magic Number (e_magic):          0x{:04X}", self.e_magic)?;
    writeln!(f, "  Bytes on last page (e_cblp):     {}", self.e_cblp)?;
    writeln!(f, "  Pages in file (e_cp):            {}", self.e_cp)?;
    writeln!(f, "  Relocations (e_crlc):            {}", self.e_crlc)?;
    writeln!(f, "  Header size in paragraphs:       {}", self.e_cparhdr)?;
    writeln!(f, "  Min extra paragraphs needed:     {}", self.e_minalloc)?;
    writeln!(f, "  Max extra paragraphs needed:     {}", self.e_maxalloc)?;
    writeln!(f, "  Initial SS value (e_ss):         0x{:04X}", self.e_ss)?;
    writeln!(f, "  Initial SP value (e_sp):         0x{:04X}", self.e_sp)?;
    writeln!(f, "  Checksum (e_csum):               0x{:04X}", self.e_csum)?;
    writeln!(f, "  Initial IP value (e_ip):         0x{:04X}", self.e_ip)?;
    writeln!(f, "  Initial CS value (e_cs):         0x{:04X}", self.e_cs)?;
    writeln!(f, "  Relocation table address:        0x{:04X}", self.e_lfarlc)?;
    writeln!(f, "  Overlay number (e_ovno):         {}", self.e_ovno)?;
    writeln!(f, "  OEM identifier (e_oemid):        0x{:04X}", self.e_oemid)?;
    writeln!(f, "  OEM information (e_oeminfo):     0x{:04X}", self.e_oeminfo)?;
    writeln!(f, "  New EXE header address:          0x{:08X}", self.e_lfanew)?;
    Ok(())
  }
}
