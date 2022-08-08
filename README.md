# Rustpass

A framework for securely storing credentials written in Rust.

## Documentation

Documentation is available [here](https://baschtianxd.github.io/rustpass/rustpass/index.html#).

## Usage (Library)

1. Clone this repository to your system
2. Link the local repository in your `cargo.toml`

## Usage (CLI - WIP)

### Installation

1. Clone this repository
2. Execute `cargo build --release` to build the application

### Create a new vault

1. Execute `./target/release/rustpass -d <path to new vault> -p <password> -n <name for new vault>` to create a new vault at the given path.
2. Interact with the created vault through the REPL. Press Enter to see available commands:
   - `add-entry <website> <username> <password>`
   - `get-all`
   - `get-entry <index>`
   - `remove-entry <index>`
   - `exit`, `quit`
   - `help`

### Open an exisisting vault

1. Execute `./target/release/rustpass -d <path to vault> -p <password>` to open the vault at the given path.
2. Interact with the vault through the REPL.
