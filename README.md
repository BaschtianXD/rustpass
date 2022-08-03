# Rustpass

A framework for securely storing credentials written in Rust.

## Installation

1. Clone this repository
2. Execute `cargo build --release` to build the application

## Usage

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
