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

    if data.len() < Self::SIZE {
      return Err(PeError::InvalidHeader("DOS header too small".to_string()));
    }

    let e_magic = reader.read_u16()?;
    if e_magic != 0x5A4D {
      return Err(PeError::NotPeFile);
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
  const IMAGE_FILE_RELOCS_STRIPPED: u16 = 0x0001;
  const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
  const IMAGE_FILE_LINE_NUMS_STRIPPED: u16 = 0x0004;
  const IMAGE_FILE_LOCAL_SYMS_STRIPPED: u16 = 0x0008;
  const IMAGE_FILE_AGGRESSIVE_WS_TRIM: u16 = 0x0010;
  const IMAGE_FILE_LARGE_ADDRESS_AWARE: u16 = 0x0020;
  const IMAGE_FILE_BYTES_REVERSED_LO: u16 = 0x0080;
  const IMAGE_FILE_32BIT_MACHINE: u16 = 0x0100;
  const IMAGE_FILE_DEBUG_STRIPPED: u16 = 0x0200;
  const IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP: u16 = 0x0400;
  const IMAGE_FILE_NET_RUN_FROM_SWAP: u16 = 0x0800;
  const IMAGE_FILE_SYSTEM: u16 = 0x1000;
  const IMAGE_FILE_DLL: u16 = 0x2000;
  const IMAGE_FILE_UP_SYSTEM_ONLY: u16 = 0x4000;
  const IMAGE_FILE_BYTES_REVERSED_HI: u16 = 0x8000;

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

  pub fn machine_type(self) -> String {
    // TODO: Add other archs
    match self.machine {
      0x0 => "Unknown".into(),
      0x8664 => "x64".into(),
      0x14c => "i386".into(),
      other => format!("Unimplemented: {:0X}", other)
    }
  }

  // TODO: Add more readable names (as argument?)
  pub fn characteristics(&self) -> Vec<&str> {
    let mut flags = Vec::new();
    
    if self.characteristics & Self::IMAGE_FILE_RELOCS_STRIPPED != 0 {
      flags.push("RELOCS_STRIPPED");
    }
    if self.characteristics & Self::IMAGE_FILE_EXECUTABLE_IMAGE != 0 {
      flags.push("EXECUTABLE_IMAGE");
    }
    if self.characteristics & Self::IMAGE_FILE_LINE_NUMS_STRIPPED != 0 {
      flags.push("LINE_NUMS_STRIPPED");
    }
    if self.characteristics & Self::IMAGE_FILE_LOCAL_SYMS_STRIPPED != 0 {
      flags.push("LOCAL_SYMS_STRIPPED");
    }
    if self.characteristics & Self::IMAGE_FILE_AGGRESSIVE_WS_TRIM != 0 {
      flags.push("AGGRESSIVE_WS_TRIM");
    }
    if self.characteristics & Self::IMAGE_FILE_LARGE_ADDRESS_AWARE != 0 {
      flags.push("LARGE_ADDRESS_AWARE");
    }
    if self.characteristics & Self::IMAGE_FILE_BYTES_REVERSED_LO != 0 {
      flags.push("BYTES_REVERSED_LO");
    }
    if self.characteristics & Self::IMAGE_FILE_32BIT_MACHINE != 0 {
      flags.push("32BIT_MACHINE");
    }
    if self.characteristics & Self::IMAGE_FILE_DEBUG_STRIPPED != 0 {
      flags.push("DEBUG_STRIPPED");
    }
    if self.characteristics & Self::IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP != 0 {
      flags.push("REMOVABLE_RUN_FROM_SWAP");
    }
    if self.characteristics & Self::IMAGE_FILE_NET_RUN_FROM_SWAP != 0 {
      flags.push("NET_RUN_FROM_SWAP");
    }
    if self.characteristics & Self::IMAGE_FILE_SYSTEM != 0 {
      flags.push("SYSTEM");
    }
    if self.characteristics & Self::IMAGE_FILE_DLL != 0 {
      flags.push("DLL");
    }
    if self.characteristics & Self::IMAGE_FILE_UP_SYSTEM_ONLY != 0 {
      flags.push("UP_SYSTEM_ONLY");
    }
    if self.characteristics & Self::IMAGE_FILE_BYTES_REVERSED_HI != 0 {
      flags.push("BYTES_REVERSED_HI");
    }
    
    flags
  }

  pub fn characteristics_string(&self) -> String {
    let flags = self.characteristics();
    if flags.is_empty() {
      "None".to_string()
    } else {
      flags.join(" | ")
    }
  }

  pub fn is_executable(&self) -> bool {
    self.characteristics & Self::IMAGE_FILE_EXECUTABLE_IMAGE != 0
  }

  pub fn is_dll(&self) -> bool {
    self.characteristics & Self::IMAGE_FILE_DLL != 0
  }

  pub fn is_system_file(&self) -> bool {
    self.characteristics & Self::IMAGE_FILE_SYSTEM != 0
  }

  pub fn is_large_address_aware(&self) -> bool {
    self.characteristics & Self::IMAGE_FILE_LARGE_ADDRESS_AWARE != 0
  }

  pub fn is_32bit_machine(&self) -> bool {
    self.characteristics & Self::IMAGE_FILE_32BIT_MACHINE != 0
  }
}