use pe_analyzer::cli::{Args, Cli};
use pe_analyzer::error::PeError;
use std::process;

fn main() {
  std::panic::set_hook(Box::new(|panic_info| {
    eprintln!("Internal error occursed:");
    if let Some(location) = panic_info.location() {
      eprintln!("   Location: {}:{}:{}", location.file(), location.line(), location.column());
    }
    if let Some(message) = panic_info.payload().downcast_ref::<&str>() {
      eprintln!("   Message: {}", message);
    } else if let Some(message) = panic_info.payload().downcast_ref::<String>() {
      eprintln!("   Message: {}", message)
    }
  }));

  let args = match Args::parse() {
    | Ok(args) => args,
    | Err(e) => {
      eprintln!("Error parsing arguments:\n  {}", e);
      eprintln!();
      eprintln!("For help, use pe-analyzer --help");
      process::exit(1);
    }
  };

  if let Err(e) = run(args) {
    eprintln!("Analysis failed: {}", e);
    process::exit(1);
  }
}

fn run(args: Args) -> Result<(), PeError> {
  if args.verbose {
    println!("Verbose mode");
  }

  Cli::run(args)?;
  Ok(())
}
