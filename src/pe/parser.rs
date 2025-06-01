use super::structures::{
  CoffHeader, DosHeader, ImageImportDescriptor, ImportParser, ImportedDll, OptionalHeader,
  SectionHeader,
};
use crate::error::{PeError, Result};

pub struct PeFile {
  pub data: Vec<u8>,
  pub dos_header: DosHeader,
  pub coff_header: CoffHeader,
  pub optional_header: OptionalHeader,
  pub section_headers: Vec<SectionHeader>,
  pub imported_dlls: Vec<ImportedDll>,
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

    let sections_start = optional_start + coff_header.size_of_optional_header as usize;
    let mut section_headers = Vec::new();

    for i in 0..coff_header.number_of_sections {
      let section_offset = sections_start + (i as usize * SectionHeader::SIZE);
      if section_offset + SectionHeader::SIZE > data.len() {
        return Err(PeError::CorruptedFile(format!("Section {} header out of bounds", i)));
      }

      let section = SectionHeader::parse(&data, section_offset)?;
      section_headers.push(section);
    }

    let imported_dlls = if let Some(import_table_rva) = optional_header.get_import_table_rva() {
      Self::parse_imports(&data, &section_headers, import_table_rva, is_64_bit)?
    } else {
      Vec::new()
    };

    Ok(PeFile { data, dos_header, coff_header, optional_header, section_headers, imported_dlls })
  }

  pub fn from_file(path: &str) -> Result<Self> {
    let data = std::fs::read(path)?;
    Self::from_bytes(data)
  }

  fn parse_imports(
    data: &[u8],
    sections: &[SectionHeader],
    import_table_rva: u32,
    is_64_bit: bool,
  ) -> Result<Vec<ImportedDll>> {
    let import_parser = ImportParser::new(data, sections, is_64_bit);
    let mut imported_dlls = Vec::new();

    let import_table_offset = import_parser.rva_to_file_offset(import_table_rva)?;
    let mut descriptor_offset = import_table_offset;

    loop {
      if descriptor_offset + 20 > data.len() {
        break;
      }

      let import_descriptor = ImageImportDescriptor::parse(data, descriptor_offset)?;

      if import_descriptor.is_null() {
        break;
      }

      match import_parser.parse_imports(&import_descriptor) {
        | Ok(imported_dll) => imported_dlls.push(imported_dll),
        | Err(e) => {
          // Log but continue
          eprintln!("Warning: Failed to parse imports for DLL: {}", e);
        }
      }

      descriptor_offset += 20;
    }

    Ok(imported_dlls)
  }

  pub fn has_imports(&self) -> bool {
    !self.imported_dlls.is_empty()
  }

  pub fn get_total_imported_functions(&self) -> usize {
    self.imported_dlls.iter().map(|dll| dll.functions.len()).sum()
  }
}
