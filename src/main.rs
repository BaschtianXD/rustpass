use clap::{Args, Parser, Subcommand};
use rustpass::{Vault, VaultEncrypted, VaultEntry};
use std::env;
use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::path::PathBuf;
use std::process::exit;
use std::str::SplitWhitespace;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct ProgramArgs {
    /// Path to the rustpass vault
    #[clap(short, long)]
    directory: String,

    /// Name for a new vault; Required when creating a new vault
    #[clap(short, long)]
    name: Option<String>,

    /// Password for the vault
    #[clap(short, long)]
    password: String,
}

#[derive(Parser)]
struct ReplArgs {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// <website> <username> <password>
    AddEntry(AddEntryArgs),
    GetAll,
    /// <index>
    GetEntry(IndexArg),
    /// <index>
    RemoveEntry(IndexArg),
    Quit,
    Exit,
}

#[derive(Args)]
struct AddEntryArgs {
    website: String,
    username: String,
    password: String,
    comment: Option<String>,
}

#[derive(Args)]
struct IndexArg {
    index: usize,
}

fn main() {
    let args = ProgramArgs::parse();

    let mut path: PathBuf = env::current_dir().expect("Could not get current working directory");
    path.push(&args.directory);

    println!("Path: {:?}", path.as_path());

    let mut vault = if !path.exists() {
        let vault = match args.name {
            None => {
                println!("Name required when creating a new vault");
                exit(1);
            }
            Some(name) => {
                Vault::new_with_password(name, &args.password).expect("Could not build vault")
            }
        };
        println!("Created new vault");
        vault
    } else {
        //let json = fs::read_to_string(&path).expect("Could not read file");
        //let vault: RpVaultEncrypted = serde_json::from_str(&json).expect("Could not parse file");
        let vault_file = File::open(&path).expect("Could not open file");
        let vault: VaultEncrypted =
            ciborium::de::from_reader(&vault_file).expect("Could not parse file");
        vault
            .decrypt(&args.password)
            .expect("Could not decrypt vault. Maybe wrong password?") // TODO improve error handling
    };

    println!("Openend vault");

    // start repl
    println!("Starting REPL");
    let mut buffer = String::new();
    let mut tokens: SplitWhitespace;

    loop {
        println!("?>");
        buffer.clear();
        match io::stdin().read_line(&mut buffer) {
            Err(_) => todo!(),
            Ok(_) => {
                tokens = buffer.split_whitespace();

                // NEW IMPLEMENTATION
                let mut foo: Vec<OsString> = tokens
                    .map(|token| {
                        let mut ostoken = OsString::new();
                        ostoken.push(token);
                        ostoken
                    })
                    .collect();
                let prefix: OsString = "REPL".into();
                foo.splice(0..0, [prefix]);
                match ReplArgs::try_parse_from(foo) {
                    Ok(args) => match args.command {
                        Command::AddEntry(new_entry) => vault.add_entry(VaultEntry::new_password(
                            new_entry.website,
                            None,
                            new_entry.username,
                            new_entry.password,
                            new_entry.comment.unwrap_or("".into()),
                        )),
                        Command::GetAll => {
                            for (index, entry) in vault.iter().enumerate() {
                                println!("[{}] {}", index, entry);
                            }
                        }
                        Command::GetEntry(args) => {
                            if args.index >= vault.get_entries().len() {
                                match vault.get_entries().get(args.index) {
                                    Some(entry) => println!("{}", entry),
                                    None => {
                                        println!("There is no entry with index {}", args.index)
                                    }
                                }
                            }
                        }
                        Command::RemoveEntry(_) => {
                            println!("Not yet implemented");
                        }
                        Command::Quit | Command::Exit => {
                            break;
                        }
                    },
                    Err(err) => {
                        println!("{}", err)
                    }
                }
            }
        }
    }

    let enc = vault
        .encrypt(&args.password)
        .expect("Could not encrypt vault");
    //let json = serde_json::to_string(&enc).expect("Could not serialize vault");
    //fs::write(&path, json).expect("Could not write to file");
    let vault_file = File::create(&path).expect("Could not open file");
    ciborium::ser::into_writer(&enc, &vault_file).expect("Could not write to file");
    vault_file.sync_all().expect("Could not sync file");
    println!("Encrypted and closed vault");
}
