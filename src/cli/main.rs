// SPDX-License-Identifier: GPL-3.0-or-later
use clap::Parser;
mod unpack;
use crate::unpack::unpack;

#[derive(Parser, Debug)]
#[command(author, arg_required_else_help = true, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand, Debug)]
enum Commands {
    /// unpack boot/vendor_boot img
    Unpack { img: String, out: String },
}

fn main() -> anyhow::Result<()> {
    let cli = Args::parse();
    match cli.command {
        Commands::Unpack { img, out } => {
            unpack(img, out)?;
        }
    }
    Ok(())
}
