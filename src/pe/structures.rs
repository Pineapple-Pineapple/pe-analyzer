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

// SKIP: IMAGE_NT_HEADER Signature checked in parser

// IMAGE_FILE_HEADER
#[derive(Debug)]
pub struct CoffHeader {
  pub machine: u16,
  pub number_of_sections: u16,
  pub time_date_stamp: u32,
  pub pointer_to_symbol_table: u32,
  pub number_of_symbols: u32,
  pub size_of_optional_header: u16,
  pub characteristics: u16,
}

impl CoffHeader {
  pub const SIZE: usize = 20;

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
    if data.len() < Self::SIZE {
      return Err(PeError::InvalidHeader("COFF Header too small".to_string()));
    }

    let mut reader = BinaryReader::new(data);

    Ok(CoffHeader {
      machine: reader.read_u16()?,
      number_of_sections: reader.read_u16()?,
      time_date_stamp: reader.read_u32()?,
      pointer_to_symbol_table: reader.read_u32()?,
      number_of_symbols: reader.read_u32()?,
      size_of_optional_header: reader.read_u16()?,
      characteristics: reader.read_u16()?,
    })
  }

  pub fn machine_type(&self) -> &str {
    match self.machine {
      | 0x0 => "Unknown (Any)",
      | 0x184 => "Alpha AXP, 32-bit address space",
      | 0x284 => "Alpha 64, 64-bit address space",
      | 0x1d3 => "Matsushita AM33",
      | 0x8664 => "x64",
      | 0x1c0 => "ARM little endian",
      | 0xaa64 => "ARM64 little endian",
      | 0x1c4 => "ARM Thumb-2 little endian",
      | 0xebc => "EFI byte code",
      | 0x14c => "Intel 386 or later processors and compatible processors",
      | 0x200 => "Intel Itanium processor family",
      | 0x6232 => "LoongArch 32-bit processor family",
      | 0x6264 => "LoongArch 64-bit processor family",
      | 0x9041 => "Mitsubishi M32R little endian",
      | 0x266 => "MIPS16",
      | 0x366 => "MIPS with FPU",
      | 0x466 => "MIPS16 with FPU",
      | 0x1f0 => "Power PC little endian",
      | 0x1f1 => "Power PC with floating point support",
      | 0x160 => "MIPS I compatible 32-bit big endian",
      | 0x162 => "MIPS I compatible 32-bit little endian",
      | 0x166 => "MIPS III compatible 64-bit little endian",
      | 0x168 => "MIPS IV compatible 64-bit little endian",
      | 0x5032 => "RISC-V 32-bit address space",
      | 0x5064 => "RISC-V 64-bit address space",
      | 0x5128 => "RISC-V 128-bit address space",
      | 0x1a2 => "Hitachi SH3",
      | 0x1a3 => "Hitachi SH3 DSP",
      | 0x1a6 => "Hitachi SH4",
      | 0x1a8 => "Hitachi SH5",
      | 0x1c2 => "Thumb",
      | 0x169 => "MIPS little-endian WCE v2",
      | _ => "Undocumented",
    }
  }

  // https://github.com/hasherezade/bearparser/blob/master/parser/pe/FileHdrWrapper.cpp
  pub fn characteristics_vec(&self, human_readable: bool) -> Vec<&str> {
    let flags = [
      (Self::IMAGE_FILE_RELOCS_STRIPPED, "RELOCS_STRIPPED", "Relocation info stripped from file"),
      (
        Self::IMAGE_FILE_EXECUTABLE_IMAGE,
        "EXECUTABLE_IMAGE",
        "File is executable (i.e. no unresolved external references)",
      ),
      (
        Self::IMAGE_FILE_LINE_NUMS_STRIPPED,
        "LINE_NUMS_STRIPPED",
        "Line numbers stripped from file",
      ),
      (
        Self::IMAGE_FILE_LOCAL_SYMS_STRIPPED,
        "LOCAL_SYMS_STRIPPED",
        "Local symbols stripped from file",
      ),
      (Self::IMAGE_FILE_AGGRESSIVE_WS_TRIM, "AGGRESSIVE_WS_TRIM", "Aggressively trim working set"),
      (
        Self::IMAGE_FILE_LARGE_ADDRESS_AWARE,
        "LARGE_ADDRESS_AWARE",
        "App can handle >2GB addresses",
      ),
      (
        Self::IMAGE_FILE_BYTES_REVERSED_LO,
        "BYTES_REVERSED_LO",
        "Bytes of machine word are reversed (low)",
      ),
      (Self::IMAGE_FILE_32BIT_MACHINE, "32BIT_MACHINE", "32-bit word machine"),
      (
        Self::IMAGE_FILE_DEBUG_STRIPPED,
        "DEBUG_STRIPPED",
        "Debugging info stripped from file in .DBG file",
      ),
      (
        Self::IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP,
        "REMOVABLE_RUN_FROM_SWAP",
        "If Image is on removable media, copy and run from the swap file",
      ),
      (
        Self::IMAGE_FILE_NET_RUN_FROM_SWAP,
        "NET_RUN_FROM_SWAP",
        "If Image is on Net, copy and run from the swap file",
      ),
      (Self::IMAGE_FILE_SYSTEM, "SYSTEM", "System File"),
      (Self::IMAGE_FILE_DLL, "DLL", "Dynamic Link Library (DLL)"),
      (
        Self::IMAGE_FILE_UP_SYSTEM_ONLY,
        "UP_SYSTEM_ONLY",
        "File should only be run on a UP machine",
      ),
      (
        Self::IMAGE_FILE_BYTES_REVERSED_HI,
        "BYTES_REVERSED_HI",
        "Bytes of machine word are reversed (high)",
      ),
    ];

    flags
      .iter()
      .filter_map(|(flag, name, desc)| {
        if flag & self.characteristics != 0 {
          Some(if human_readable { *desc } else { *name })
        } else {
          None
        }
      })
      .collect()
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

  pub fn get_file_type(&self) -> &str {
    if self.is_dll() {
      "Dynamic Link Library (DLL)"
    } else if self.is_executable() {
      "Executable (EXE)"
    } else if self.is_system_file() {
      "System File"
    } else {
      "Unknown"
    }
  }

  pub fn is_large_address_aware(&self) -> bool {
    self.characteristics & Self::IMAGE_FILE_LARGE_ADDRESS_AWARE != 0
  }

  pub fn is_32bit_machine(&self) -> bool {
    self.characteristics & Self::IMAGE_FILE_32BIT_MACHINE != 0
  }
}

#[derive(Debug)]
pub struct OptionalHeader {
  pub magic: u16,
  pub major_linker_version: u8,
  pub minor_linker_version: u8,
  pub size_of_code: u32,
  pub size_of_initialized_data: u32,
  pub size_of_uninitialized_data: u32,
  pub address_of_entry_point: u32,
  pub base_of_code: u32,
  pub base_of_data: Option<u32>, // 32-bit exec only

  pub image_base: u64,
  pub section_alignment: u32,
  pub file_alignment: u32,
  pub major_operating_system_version: u16,
  pub minor_operating_system_version: u16,
  pub major_image_version: u16,
  pub minor_image_version: u16,
  pub major_subsystem_version: u16,
  pub minor_subsystem_version: u16,
  pub win_32_version_value: u32,
  pub size_of_image: u32,
  pub size_of_headers: u32,
  pub checksum: u32,
  pub subsystem: u16,
  pub dll_characteristics: u16,
  pub size_of_stack_reserve: u64,
  pub size_of_stack_commit: u64,
  pub size_of_heap_reserve: u64,
  pub size_of_heap_commit: u64,
  pub loader_flags: u32,
  pub number_of_rva_and_sizes: u32,
  pub image_data_directory: Vec<DataDirectory>,
}

#[derive(Debug)]
pub struct DataDirectory {
  pub virtual_address: u32,
  pub size: u32,
}

// For display purposes
#[derive(Debug)]
pub struct NamedDataDirectory {
  pub name: &'static str,
  pub idx: usize,
  pub virtual_address: u32,
  pub size: u32,
}

impl OptionalHeader {
  const IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA: u16 = 0x0020;
  const IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE: u16 = 0x0040;
  const IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY: u16 = 0x0080;
  const IMAGE_DLLCHARACTERISTICS_NX_COMPAT: u16 = 0x0100;
  const IMAGE_DLLCHARACTERISTICS_NO_ISOLATION: u16 = 0x0200;
  const IMAGE_DLLCHARACTERISTICS_NO_SEH: u16 = 0x0400;
  const IMAGE_DLLCHARACTERISTICS_NO_BIND: u16 = 0x0800;
  const IMAGE_DLLCHARACTERISTICS_APPCONTAINER: u16 = 0x1000;
  const IMAGE_DLLCHARACTERISTICS_WDM_DRIVER: u16 = 0x200;
  const IMAGE_DLLCHARACTERISTICS_GUARD_CF: u16 = 0x4000;
  const IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE: u16 = 0x8000;

  pub fn parse(data: &[u8], is_64_bit: bool) -> Result<Self> {
    let mut reader = BinaryReader::new(data);

    let magic = reader.read_u16()?;
    let major_linker_version = reader.read_u8()?;
    let minor_linker_version = reader.read_u8()?;
    let size_of_code = reader.read_u32()?;
    let size_of_initialized_data = reader.read_u32()?;
    let size_of_uninitialized_data = reader.read_u32()?;
    let address_of_entry_point = reader.read_u32()?;
    let base_of_code = reader.read_u32()?;

    let (base_of_data, image_base) = if is_64_bit {
      let image_base = reader.read_u64()?;
      (None, image_base)
    } else {
      let base_of_data = reader.read_u32()?;
      let image_base = reader.read_u32()?;
      (Some(base_of_data), image_base as u64)
    };

    let section_alignment = reader.read_u32()?;
    let file_alignment = reader.read_u32()?;
    let major_operating_system_version = reader.read_u16()?;
    let minor_operating_system_version = reader.read_u16()?;
    let major_image_version = reader.read_u16()?;
    let minor_image_version = reader.read_u16()?;
    let major_subsystem_version = reader.read_u16()?;
    let minor_subsystem_version = reader.read_u16()?;
    let win_32_version_value = reader.read_u32()?;
    let size_of_image = reader.read_u32()?;
    let size_of_headers = reader.read_u32()?;
    let checksum = reader.read_u32()?;
    let subsystem = reader.read_u16()?;
    let dll_characteristics = reader.read_u16()?;

    let (size_of_stack_reserve, size_of_stack_commit, size_of_heap_reserve, size_of_heap_commit) =
      if is_64_bit {
        let size_of_stack_reserve = reader.read_u64()?;
        let size_of_stack_commit = reader.read_u64()?;
        let size_of_heap_reserve = reader.read_u64()?;
        let size_of_heap_commit = reader.read_u64()?;
        (size_of_stack_reserve, size_of_stack_commit, size_of_heap_reserve, size_of_heap_commit)
      } else {
        let size_of_stack_reserve = reader.read_u32()? as u64;
        let size_of_stack_commit = reader.read_u32()? as u64;
        let size_of_heap_reserve = reader.read_u32()? as u64;
        let size_of_heap_commit = reader.read_u32()? as u64;
        (size_of_stack_reserve, size_of_stack_commit, size_of_heap_reserve, size_of_heap_commit)
      };

    let loader_flags = reader.read_u32()?;
    let number_of_rva_and_sizes = reader.read_u32()?;

    let mut image_data_directory: Vec<DataDirectory> = Vec::new();
    for _ in 0..number_of_rva_and_sizes {
      let virtual_address = reader.read_u32()?;
      let size = reader.read_u32()?;
      image_data_directory.push(DataDirectory { virtual_address, size });
    }

    Ok(OptionalHeader {
      magic,
      major_linker_version,
      minor_linker_version,
      size_of_code,
      size_of_initialized_data,
      size_of_uninitialized_data,
      address_of_entry_point,
      base_of_code,
      base_of_data,
      image_base,
      section_alignment,
      file_alignment,
      major_operating_system_version,
      minor_operating_system_version,
      major_image_version,
      minor_image_version,
      major_subsystem_version,
      minor_subsystem_version,
      win_32_version_value,
      size_of_image,
      size_of_headers,
      checksum,
      subsystem,
      dll_characteristics,
      size_of_stack_reserve,
      size_of_stack_commit,
      size_of_heap_reserve,
      size_of_heap_commit,
      loader_flags,
      number_of_rva_and_sizes,
      image_data_directory,
    })
  }

  pub fn is_64_bit(&self) -> bool {
    self.magic == 0x20B
  }

  pub fn subsystem_name(&self) -> &str {
    match self.subsystem {
      | 0 => "An Unknown Subsystem",
      | 1 => "Device drivers and native Windows processes",
      | 2 => "The Windows graphical user interface (GUI) subsystem",
      | 3 => "The Windows character subsystem",
      | 5 => "The OS/2 character subsystem",
      | 7 => "The Posix character subsystem",
      | 8 => "Native Win9x driver",
      | 9 => "Windows CE",
      | 10 => "An Extensible Firmware Interface (EFI) application",
      | 11 => "An EFI driver with boot services",
      | 12 => "An EFI driver with run-time services",
      | 13 => "An EFI ROM image",
      | 14 => "XBOX",
      | 16 => "Windows boot application",
      | _ => "Undocumented",
    }
  }

  pub fn dll_characteristics_vec(&self, human_readable: bool) -> Vec<&str> {
    let flags = [
      (
        Self::IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA,
        "DLLCHARACTERISTICS_HIGH_ENTROPY_VA",
        "High Entropy VA",
      ),
      (
        Self::IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE,
        "DLLCHARACTERISTICS_DYNAMIC_BASE",
        "Dynamic Base",
      ),
      (
        Self::IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY,
        "DLLCHARACTERISTICS_FORCE_INTEGRITY",
        "Force Integrity",
      ),
      (Self::IMAGE_DLLCHARACTERISTICS_NX_COMPAT, "DLLCHARACTERISTICS_NX_COMPAT", "NX Compatible"),
      (
        Self::IMAGE_DLLCHARACTERISTICS_NO_ISOLATION,
        "DLLCHARACTERISTICS_NO_ISOLATION",
        "No Isolation",
      ),
      (Self::IMAGE_DLLCHARACTERISTICS_NO_SEH, "DLLCHARACTERISTICS_NO_SEH", "No SEH"),
      (Self::IMAGE_DLLCHARACTERISTICS_NO_BIND, "DLLCHARACTERISTICS_NO_BIND", "No Bind"),
      (
        Self::IMAGE_DLLCHARACTERISTICS_APPCONTAINER,
        "DLLCHARACTERISTICS_APPCONTAINER",
        "AppContainer",
      ),
      (Self::IMAGE_DLLCHARACTERISTICS_WDM_DRIVER, "DLLCHARACTERISTICS_WDM_DRIVER", "WDM Driver"),
      (Self::IMAGE_DLLCHARACTERISTICS_GUARD_CF, "DLLCHARACTERISTICS_GUARD_CF", "Guard CF"),
      (
        Self::IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE,
        "DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE",
        "Terminal Server Aware",
      ),
    ];

    flags
      .iter()
      .filter_map(|(flag, name, desc)| {
        if self.dll_characteristics & flag != 0 {
          Some(if human_readable { *desc } else { *name })
        } else {
          None
        }
      })
      .collect()
  }

  pub fn format_data_directories(&self) -> Vec<NamedDataDirectory> {
    let flags = [
      (0, "Export Directory"),
      (1, "Import Directory"),
      (2, "Resource Directory"),
      (3, "Exception Directory"),
      (4, "Security Directory"),
      (5, "Base Relocation Table"),
      (6, "Debug Directory"),
      (7, "Architecture Specific Data"),
      (8, "RVA of GP"),
      (9, "TLS Directory"),
      (10, "Load Configuration Directory"),
      (11, "Bound Import Directory in headers"),
      (12, "Import Address Table"),
      (13, "Delay Load Import Descriptors"),
      (14, "COM Runtime descriptor"),
    ];

    flags
      .iter()
      .filter_map(|(idx, name)| {
        if *idx < self.image_data_directory.len() {
          let dir = &self.image_data_directory[*idx];
          if dir.virtual_address != 0 || dir.size != 0 {
            Some(NamedDataDirectory {
              name: *name,
              idx: *idx,
              virtual_address: dir.virtual_address,
              size: dir.size,
            })
          } else {
            None
          }
        } else {
          None
        }
      })
      .collect()
  }

  pub fn get_import_table_rva(&self) -> Option<u32> {
    if self.image_data_directory.len() > 1 {
      let import_dir = &self.image_data_directory[1];
      if import_dir.virtual_address != 0 { Some(import_dir.virtual_address) } else { None }
    } else {
      None
    }
  }

  pub fn get_bound_import_table_rva(&self) -> Option<u32> {
    if self.image_data_directory.len() > 11 {
      let bound_import_dir = &self.image_data_directory[11];
      if bound_import_dir.virtual_address != 0 {
        Some(bound_import_dir.virtual_address)
      } else {
        None
      }
    } else {
      None
    }
  }
}

pub struct ImageImportDescriptor {
  pub original_first_thunk: u32, // RVA of ILT
  pub time_date_stamp: u32,
  pub forwarder_chain: u32,
  pub name: u32,        // RVA of dll name
  pub first_thunk: u32, // RVA of IAT
}

pub struct ImportByName {
  pub hint: u16,
  pub name: String,
}

pub struct ImportedFunction {
  pub name: String,
  pub hint: u16,
  pub ordinal: Option<u16>,
  pub is_ordinal_import: bool,
}

pub struct ImportedDll {
  pub name: String,
  pub functions: Vec<ImportedFunction>,
  pub time_date_stamp: u32,
  pub forwarder_chain: u32,
  pub is_bound_import: bool,
  pub ilt_rva: u32, // RVA of ILT
  pub iat_rva: u32, // RVA of IAT
}

pub struct ImageBoundImportDescriptor {
  pub time_date_stamp: u32,
  pub offset_module_name: u16,
  pub number_of_module_forwarder_refs: u16,
}

impl ImageImportDescriptor {
  pub fn parse(data: &[u8], offset: usize) -> Result<Self> {
    if data.len() < offset + 20 {
      return Err(PeError::InvalidHeader("Image Import Descriptor too small".to_string()));
    }

    let mut reader = BinaryReader::new(&data[offset..]);

    Ok(ImageImportDescriptor {
      original_first_thunk: reader.read_u32()?,
      time_date_stamp: reader.read_u32()?,
      forwarder_chain: reader.read_u32()?,
      name: reader.read_u32()?,
      first_thunk: reader.read_u32()?,
    })
  }

  pub fn is_null(&self) -> bool {
    self.original_first_thunk == 0
      && self.time_date_stamp == 0
      && self.forwarder_chain == 0
      && self.name == 0
      && self.first_thunk == 0
  }

  pub fn is_bound(&self) -> bool {
    self.time_date_stamp == 0xFFFFFFFF
  }
}

impl ImportByName {
  pub fn parse(data: &[u8], offset: usize) -> Result<Self> {
    if data.len() < offset + 2 {
      return Err(PeError::InvalidHeader("Import By Name too small".to_string()));
    }

    let mut reader = BinaryReader::new(&data[offset..]);
    let hint = reader.read_u16()?;
    let name = reader.read_cstring(data.len())?;
    if name.is_empty() {
      return Err(PeError::InvalidHeader("Import By Name has no name".to_string()));
    }

    Ok(ImportByName { hint, name })
  }
}

pub struct ImportParser<'a> {
  data: &'a [u8],
  sections: &'a [SectionHeader],
  is_64_bit: bool,
}

pub struct SectionHeader {
  pub name: String,
  pub virtual_size: u32,
  pub virtual_address: u32,
  pub size_of_raw_data: u32,
  pub pointer_to_raw_data: u32,
  pub pointer_to_relocations: u32,
  pub pointer_to_line_numbers: u32,
  pub number_of_relocations: u16,
  pub number_of_line_numbers: u16,
  pub characteristics: u32,
}

impl SectionHeader {
  pub const SIZE: usize = 40;

  pub fn parse(data: &[u8], offset: usize) -> Result<Self> {
    if data.len() < offset + Self::SIZE {
      return Err(PeError::InvalidHeader("Section header too small".to_string()));
    }

    let mut reader = BinaryReader::new(&data[offset..]);

    let name_bytes = reader.read_bytes(8)?;
    let name = String::from_utf8_lossy(name_bytes).trim_end_matches('\0').to_string();

    Ok(SectionHeader {
      name,
      virtual_size: reader.read_u32()?,
      virtual_address: reader.read_u32()?,
      size_of_raw_data: reader.read_u32()?,
      pointer_to_raw_data: reader.read_u32()?,
      pointer_to_relocations: reader.read_u32()?,
      pointer_to_line_numbers: reader.read_u32()?,
      number_of_relocations: reader.read_u16()?,
      number_of_line_numbers: reader.read_u16()?,
      characteristics: reader.read_u32()?,
    })
  }

  pub fn get_characteristics_list(&self, human_readable: bool) -> Vec<&str> {
    let flags = [
      (
        0x00000008,
        "IMAGE_SCN_TYPE_NO_PAD",
        "The section should not be padded to the next boundary. This flag is obsolete and is replaced by IMAGE_SCN_ALIGN_1BYTES.",
      ),
      (0x00000020, "IMAGE_SCN_CNT_CODE", "The section contains executable code."),
      (0x00000040, "IMAGE_SCN_CNT_INITIALIZED_DATA", "The section contains initialized data."),
      (0x00000080, "IMAGE_SCN_CNT_UNINITIALIZED_DATA", "The section contains uninitialized data."),
      (0x00000100, "IMAGE_SCN_LNK_OTHER", "Reserved."),
      (
        0x00000200,
        "IMAGE_SCN_LNK_INFO",
        "The section contains comments or other information. This is valid only for object files.",
      ),
      (
        0x00000400,
        "IMAGE_SCN_LNK_REMOVE",
        "The section will not become part of the image. This is valid only for object files.",
      ),
      (
        0x00001000,
        "IMAGE_SCN_LNK_COMDAT",
        "The section contains COMDAT data. This is valid only for object files.",
      ),
      (
        0x00004000,
        "IMAGE_SCN_NO_DEFER_SPEC_EXC",
        "Reset speculative exceptions handling bits in the TLB entries for this section.",
      ),
      (
        0x00008000,
        "IMAGE_SCN_GPREL",
        "The section contains data referenced through the global pointer.",
      ),
      (0x00020000, "IMAGE_SCN_MEM_PURGEABLE", "Reserved. (IMAGE_SCN_MEM_PURGEABLE)"),
      (0x00040000, "IMAGE_SCN_MEM_LOCKED", "Reserved. (IMAGE_SCN_MEM_LOCKED)"),
      (0x00080000, "IMAGE_SCN_MEM_PRELOAD", "Reserved. (IMAGE_SCN_MEM_PRELOAD)"),
      (
        0x00100000,
        "IMAGE_SCN_ALIGN_1BYTES",
        "Align data on a 1-byte boundary. This is valid only for object files.",
      ),
      (
        0x00200000,
        "IMAGE_SCN_ALIGN_2BYTES",
        "Align data on a 2-byte boundary. This is valid only for object files.",
      ),
      (
        0x00300000,
        "IMAGE_SCN_ALIGN_4BYTES",
        "Align data on a 4-byte boundary. This is valid only for object files.",
      ),
      (
        0x00400000,
        "IMAGE_SCN_ALIGN_8BYTES",
        "Align data on an 8-byte boundary. This is valid only for object files.",
      ),
      (
        0x00500000,
        "IMAGE_SCN_ALIGN_16BYTES",
        "Align data on a 16-byte boundary. This is valid only for object files.",
      ),
      (
        0x00600000,
        "IMAGE_SCN_ALIGN_32BYTES",
        "Align data on a 32-byte boundary. This is valid only for object files.",
      ),
      (
        0x00700000,
        "IMAGE_SCN_ALIGN_64BYTES",
        "Align data on a 64-byte boundary. This is valid only for object files.",
      ),
      (
        0x00800000,
        "IMAGE_SCN_ALIGN_128BYTES",
        "Align data on a 128-byte boundary. This is valid only for object files.",
      ),
      (
        0x00900000,
        "IMAGE_SCN_ALIGN_256BYTES",
        "Align data on a 256-byte boundary. This is valid only for object files.",
      ),
      (
        0x00A00000,
        "IMAGE_SCN_ALIGN_512BYTES",
        "Align data on a 512-byte boundary. This is valid only for object files.",
      ),
      (
        0x00B00000,
        "IMAGE_SCN_ALIGN_1024BYTES",
        "Align data on a 1024-byte boundary. This is valid only for object files.",
      ),
      (
        0x00C00000,
        "IMAGE_SCN_ALIGN_2048BYTES",
        "Align data on a 2048-byte boundary. This is valid only for object files.",
      ),
      (
        0x00D00000,
        "IMAGE_SCN_ALIGN_4096BYTES",
        "Align data on a 4096-byte boundary. This is valid only for object files.",
      ),
      (
        0x00E00000,
        "IMAGE_SCN_ALIGN_8192BYTES",
        "Align data on an 8192-byte boundary. This is valid only for object files.",
      ),
      (
        0x01000000,
        "IMAGE_SCN_LNK_NRELOC_OVFL",
        "The section contains extended relocations. The count of relocations for the section exceeds the 16 bits that is reserved for it in the section header. If the NumberOfRelocations field in the section header is 0xffff, the actual relocation count is stored in the VirtualAddress field of the first relocation. It is an error if IMAGE_SCN_LNK_NRELOC_OVFL is set and there are fewer than 0xffff relocations in the section.",
      ),
      (0x02000000, "IMAGE_SCN_MEM_DISCARDABLE", "The section can be discarded."),
      (0x04000000, "IMAGE_SCN_MEM_NOT_CACHED", "The section cannot be cached."),
      (0x08000000, "IMAGE_SCN_MEM_NOT_PAGED", "The section cannot be paged."),
      (0x10000000, "IMAGE_SCN_MEM_SHARED", "The section can be shared in memory."),
      (0x20000000, "IMAGE_SCN_MEM_EXECUTE", "The section can be executed as code."),
      (0x40000000, "IMAGE_SCN_MEM_READ", "The section can be read."),
      (0x80000000, "IMAGE_SCN_MEM_WRITE", "The section can be written to."),
    ];

    flags
      .iter()
      .filter_map(|(flag, name, desc)| {
        if self.characteristics & flag != 0 {
          Some(if human_readable { *desc } else { *name })
        } else {
          None
        }
      })
      .collect()
  }
}

impl<'a> ImportParser<'a> {
  pub fn new(data: &'a [u8], sections: &'a [SectionHeader], is_64_bit: bool) -> Self {
    Self { data, sections, is_64_bit }
  }

  pub fn rva_to_file_offset(&self, rva: u32) -> Result<usize> {
    for section in self.sections {
      let section_start = section.virtual_address;
      let section_end = section_start + section.virtual_size;

      if rva >= section_start && rva < section_end {
        let offset_in_section = rva - section_start;
        let file_offset = (section.pointer_to_raw_data + offset_in_section) as usize;

        if offset_in_section >= section.size_of_raw_data {
          return Err(PeError::InvalidHeader(format!(
            "RVA 0x{:08X} exceeds section raw data size",
            rva
          )));
        }

        return Ok(file_offset);
      }
    }
    Err(PeError::InvalidHeader(format!("RVA 0x{:08X} not found in any section", rva)))
  }

  fn parse_ilt_entry(&self, entry_value: u64) -> Result<ImportedFunction> {
    let ordinal_flag = if self.is_64_bit { 0x8000000000000000 } else { 0x80000000 };

    if entry_value & ordinal_flag != 0 {
      // Import by ordinal
      let ordinal = (entry_value & 0xFFFF) as u16;
      Ok(ImportedFunction {
        name: String::new(),
        hint: 0,
        ordinal: Some(ordinal),
        is_ordinal_import: true,
      })
    } else {
      let rva = (entry_value & 0x7FFFFFFF) as u32;
      let offset = self.rva_to_file_offset(rva)?;
      let import_by_name = ImportByName::parse(self.data, offset)?;

      Ok(ImportedFunction {
        name: import_by_name.name,
        hint: import_by_name.hint,
        ordinal: None,
        is_ordinal_import: false,
      })
    }
  }

  fn parse_import_table(&self, table_rva: u32) -> Result<Vec<ImportedFunction>> {
    let mut functions = Vec::new();
    let table_offset = self.rva_to_file_offset(table_rva)?;
    let mut reader = BinaryReader::new(&self.data[table_offset..]);

    loop {
      let entry_value = if self.is_64_bit { reader.read_u64()? } else { reader.read_u32()? as u64 };

      if entry_value == 0 {
        break;
      }

      let function = self.parse_ilt_entry(entry_value)?;
      functions.push(function);
    }

    Ok(functions)
  }

  pub fn parse_imports(&self, import_descriptor: &ImageImportDescriptor) -> Result<ImportedDll> {
    let dll_name_offset = self.rva_to_file_offset(import_descriptor.name)?;
    let dll_name = BinaryReader::new(&self.data[dll_name_offset..])
      .read_cstring(256)?
      .trim_end_matches('\0')
      .to_string();

    if dll_name.is_empty() {
      return Err(PeError::InvalidHeader("DLL name is empty".to_string()));
    }

    let functions = if import_descriptor.original_first_thunk != 0 {
      self.parse_import_table(import_descriptor.original_first_thunk)?
    } else if import_descriptor.first_thunk != 0 {
      self.parse_import_table(import_descriptor.first_thunk)? // fallback
    } else {
      Vec::new()
    };

    Ok(ImportedDll {
      name: dll_name,
      functions,
      time_date_stamp: import_descriptor.time_date_stamp,
      forwarder_chain: import_descriptor.forwarder_chain,
      is_bound_import: import_descriptor.is_bound(),
      ilt_rva: import_descriptor.original_first_thunk,
      iat_rva: import_descriptor.first_thunk,
    })
  }
}
