use crate::error::{PeError, Result};
use crate::pe::PeFile;
use crate::utils;
use std::env;

pub struct Args {
  pub file_path: String,
  pub verbose: bool,
  pub show_help: bool,
  pub show_dos: bool,
  pub show_coff: bool,
  pub show_optional_header: bool,
}

impl Args {
  pub fn parse() -> Result<Self> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
      return Err(PeError::InvalidArguments("No file specified".to_string()));
    }

    let mut file_path = String::new();
    let mut verbose = false;
    let mut show_help = false;
    let mut show_dos = false;
    let mut show_coff = false;
    let mut show_optional_header = false;

    let mut i = 1;
    while i < args.len() {
      match args[i].as_str() {
        | "--help" | "-h" => show_help = true,
        | "--verbose" | "-v" => verbose = true,
        | "--dos" => show_dos = true,
        | "--coff" => show_coff = true,
        | "--optional" => show_optional_header = true,
        | arg if arg.starts_with("-") => {
          return Err(PeError::InvalidArguments(format!("Unknown option: {}", arg)));
        }
        | arg => {
          if file_path.is_empty() {
            file_path = arg.to_string();
          } else {
            return Err(PeError::InvalidArguments("Multiple files not supported".to_string()));
          }
        }
      }
      i += 1;
    }

    if show_help {
      return Ok(Args {
        file_path: String::new(),
        verbose,
        show_help,
        show_dos,
        show_coff,
        show_optional_header,
      });
    }

    if file_path.is_empty() {
      return Err(PeError::InvalidArguments("No file specified".to_string()));
    }

    Ok(Args { file_path, verbose, show_help, show_dos, show_coff, show_optional_header })
  }
}

pub struct Cli;

impl Cli {
  pub fn run(args: Args) -> Result<()> {
    if args.show_help {
      Self::show_help();
      return Ok(());
    }

    let pe_file = PeFile::from_file(args.file_path.as_str())?;
    Self::display(&pe_file, &args)
  }

  fn show_help() {
    println!("PE File Analyzer");
    println!("A memory-safe tool for analyzing Windows PE files");
    println!();
    println!("USAGE:");
    println!("    pe-analyzer [OPTIONS] <FILE>");
    println!();
    println!("ARGS:");
    println!("    <FILE>    Path to the PE file to analyze");
    println!();
    println!("OPTIONS:");
    println!("    -h, --help       Show this help message");
    println!("    -v, --verbose    Enable verbose output");
    println!("    --dos            Show DOS Header");
    println!("    --coff           Show COFF File Header");
    println!("    --optional       Show Optional Header");
    println!();
    println!("EXAMPLES:");
    println!("    pe-analyzer example.exe");
  }

  fn display(pe_file: &PeFile, args: &Args) -> Result<()> {
    Self::display_file_overview(pe_file, args)?;

    if args.show_dos {
      Self::display_dos_header(&pe_file)?;
    }
    if args.show_coff {
      Self::display_coff_header(&pe_file)?;
    }
    if args.show_optional_header {
      Self::display_optional_header(&pe_file)?;
    }

    Ok(())
  }

  fn display_file_overview(pe_file: &PeFile, args: &Args) -> Result<()> {
    println!("PE File Analysis");
    println!("================");
    println!();

    println!("📁 File Information:");
    println!("   File: {}", args.file_path);
    println!("   File Size: {} bytes", pe_file.data.len());
    println!("   File Type: {}", pe_file.coff_header.get_file_type());
    println!("   Architecture: {}", pe_file.coff_header.machine_type());
    println!();

    println!("🔧 PE Structure:");
    println!("   DOS Header Offset: 0x00000000");
    println!("   PE Header Offset: 0x{:08X}", pe_file.dos_header.e_lfanew);
    println!("   Number of Sections: {}", pe_file.coff_header.number_of_sections);
    println!();

    println!("📅 Compilation Info:");
    let timestamp = pe_file.coff_header.time_date_stamp;
    if timestamp > 0 {
      println!(
        "   Timestamp: {} ({})",
        timestamp,
        utils::relative_time(timestamp as u64, true, 4)?
      );
    } else {
      println!("   Timestamp: Not set");
    }
    println!();

    println!("⚙️  File Characteristics:");
    let characteristics = pe_file.coff_header.characteristics_vec(true);
    if characteristics.is_empty() {
      println!("   None");
    } else {
      for characteristic in characteristics {
        println!("   • {}", characteristic);
      }
    }

    if args.verbose {
      println!();
      Self::display_verbose_info(pe_file)?;
    }

    Ok(())
  }

  fn display_verbose_info(pe_file: &PeFile) -> Result<()> {
    println!("🔍 Verbose Information:");
    println!("   Machine Type: 0x{:04X}", pe_file.coff_header.machine);
    println!("   Characteristics: 0x{:04X}", pe_file.coff_header.characteristics);
    println!("   Symbol Table Offset: 0x{:08X}", pe_file.coff_header.pointer_to_symbol_table);
    println!("   Number of Symbols: {}", pe_file.coff_header.number_of_symbols);
    println!("   Optional Header Size: {} bytes", pe_file.coff_header.size_of_optional_header);
    Ok(())
  }

  fn display_dos_header(pe_file: &PeFile) -> Result<()> {
    let dos_header = &pe_file.dos_header;
    println!("\nDOS Header");
    println!("==========");
    println!(
      "Magic Number: 0x{:04X} ({})",
      dos_header.e_magic,
      if dos_header.e_magic == 0x5A4D { "MZ" } else { "Invalid" }
    );
    println!("Bytes on last page: {}", dos_header.e_cblp);
    println!("Pages in file: {}", dos_header.e_cp);
    println!("Relocations: {}", dos_header.e_crlc);
    println!("Size of header (paragraphs): {}", dos_header.e_cparhdr);
    println!("PE Header Offset: 0x{:08X}", dos_header.e_lfanew);
    println!();
    Ok(())
  }

  fn display_coff_header(pe_file: &PeFile) -> Result<()> {
    let coff_header = &pe_file.coff_header;
    println!("\nCOFF File Header");
    println!("================");
    println!("Machine Type: {} (0x{:04X})", coff_header.machine_type(), coff_header.machine);
    println!("Number of Sections: {}", coff_header.number_of_sections);
    println!(
      "Timestamp: {} ({})",
      coff_header.time_date_stamp,
      utils::relative_time(coff_header.time_date_stamp as u64, true, 4)?
    );
    println!("Symbol Table Offset: 0x{:08X}", coff_header.pointer_to_symbol_table);
    println!("Number of Symbols: {}", coff_header.number_of_symbols);
    println!("Optional Header Size: {} bytes", coff_header.size_of_optional_header);
    println!("Characteristics: 0x{:04X}", coff_header.characteristics);

    let characteristics = coff_header.characteristics_vec(true);
    if !characteristics.is_empty() {
      println!("  Flags:");
      for characteristic in characteristics {
        println!("    • {}", characteristic);
      }
    }
    println!();
    Ok(())
  }

  fn display_optional_header(pe_file: &PeFile) -> Result<()> {
    let opt = &pe_file.optional_header;
    println!("\nOptional Header");
    println!("===============");

    println!(
      "Format: {} (Magic: 0x{:04X})",
      if opt.is_64_bit() { "PE32+" } else { "PE32" },
      opt.magic
    );
    println!("Linker Version: {}.{}", opt.major_linker_version, opt.minor_linker_version);
    println!();

    println!("📊 Code & Data:");
    println!("   Code Size: {} bytes (0x{:X})", opt.size_of_code, opt.size_of_code);
    println!(
      "   Initialized Data: {} bytes (0x{:X})",
      opt.size_of_initialized_data, opt.size_of_initialized_data
    );
    println!(
      "   Uninitialized Data: {} bytes (0x{:X})",
      opt.size_of_uninitialized_data, opt.size_of_uninitialized_data
    );
    println!();

    println!("💾 Memory Layout:");
    println!("   Image Base: 0x{:016X}", opt.image_base);
    println!("   Entry Point: 0x{:08X}", opt.address_of_entry_point);
    println!("   Code Base: 0x{:08X}", opt.base_of_code);
    if let Some(data_base) = opt.base_of_data {
      println!("   Data Base: 0x{:08X}", data_base);
    }
    println!("   Image Size: {} bytes (0x{:X})", opt.size_of_image, opt.size_of_image);
    println!("   Headers Size: {} bytes (0x{:X})", opt.size_of_headers, opt.size_of_headers);
    println!();

    println!("📐 Alignment:");
    println!(
      "   Section Alignment: 0x{:X} ({} bytes)",
      opt.section_alignment, opt.section_alignment
    );
    println!("   File Alignment: 0x{:X} ({} bytes)", opt.file_alignment, opt.file_alignment);
    println!();

    println!("🔢 Version Info:");
    println!(
      "   OS Version: {}.{}",
      opt.major_operating_system_version, opt.minor_operating_system_version
    );
    println!("   Image Version: {}.{}", opt.major_image_version, opt.minor_image_version);
    println!(
      "   Subsystem Version: {}.{}",
      opt.major_subsystem_version, opt.minor_subsystem_version
    );
    println!();

    println!("🖥️  Target Environment:");
    println!("   Subsystem: {} ({})", opt.subsystem_name(), opt.subsystem);
    println!("   Checksum: 0x{:08X}", opt.checksum);
    println!();

    println!("🔒 Security Features:");
    let dll_chars = opt.dll_characteristics_vec(true);
    if dll_chars.is_empty() {
      println!("   None");
    } else {
      for characteristic in dll_chars {
        println!("   • {}", characteristic);
      }
    }
    println!();

    println!("🧠 Memory Allocation:");
    println!(
      "   Stack Reserve: {} bytes (0x{:X})",
      opt.size_of_stack_reserve, opt.size_of_stack_reserve
    );
    println!(
      "   Stack Commit: {} bytes (0x{:X})",
      opt.size_of_stack_commit, opt.size_of_stack_commit
    );
    println!(
      "   Heap Reserve: {} bytes (0x{:X})",
      opt.size_of_heap_reserve, opt.size_of_heap_reserve
    );
    println!("   Heap Commit: {} bytes (0x{:X})", opt.size_of_heap_commit, opt.size_of_heap_commit);
    println!();

    if !opt.image_data_directory.is_empty() {
      println!("📁 Data Directories ({}):", opt.number_of_rva_and_sizes);
      for dir in opt.format_data_directories() {
        println!(
          "   {} ({}): RVA=0x{:08X}, Size={}",
          dir.name, dir.idx, dir.virtual_address, dir.size
        );
      }
    }

    Ok(())
  }
}
