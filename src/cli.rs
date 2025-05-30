use crate::error::{PeError, Result};
use crate::pe::PeFile;
use std::env;

pub struct Args {
  pub file_path: String,
  pub verbose: bool,
  pub show_help: bool,
  pub show_dos: bool,
  pub show_coff: bool
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

    let mut i = 1;
    while i < args.len() {
      match args[i].as_str() {
        | "--help" | "-h" => show_help = true,
        | "--verbose" | "-v" => verbose = true,
        | "--dos" => show_dos = true,
        | "--coff" => show_coff = true,
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
      return Ok(Args { file_path: String::new(), verbose, show_help, show_dos, show_coff });
    }

    if file_path.is_empty() {
      return Err(PeError::InvalidArguments("No file specified".to_string()));
    }

    Ok(Args { file_path, verbose, show_help, show_dos, show_coff })
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
    println!();
    println!("EXAMPLES:");
    println!("    pe-analyzer example.exe");
  }

  fn display(pe_file: &PeFile, args: &Args) -> Result<()> {
    if args.show_dos {
      println!("{:#0X?}", pe_file.dos_header);
    } else if args.show_coff {
      println!("{:#0X?}", pe_file.coff_header);
    }
    
    Ok(())
  }
}
