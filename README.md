# passManager

A lightweight command-line password manager written in C++.

`passManager` stores password entries inside encrypted vault files, lets you manage multiple vaults from a terminal menu, and uses modern crypto primitives from `libsodium` and `libargon2`.

## Features

- Multiple named vaults
- Encrypted vault storage using ChaCha20-Poly1305
- Master key derivation with Argon2id
- Add, view, edit, and delete password entries
- Password strength scoring with weak-password warnings
- Optional comments for each entry
- Import and export support for vault files
- Configurable password-derivation cost on first run
- 5-minute in-memory session timeout before re-authentication

## Tech Stack

- C++17
- CMake
- `libsodium`
- `libargon2`
- `nlohmann/json`

## Platform Notes

This project is currently built for Linux style terminals and filesystems.

- Password input uses `termios`/`unistd` to disable terminal echo
- Vaults are stored under `~/.local/share/passManager`
- The code expects a Unix-like environment with a `HOME` directory

## Getting Started

### Prerequisites

You need:

- A C++17 compiler
- CMake 3.10 or newer
- `libsodium`
- `libargon2`
- `pkg-config`
- `nlohmann/json`

Example install commands:

```bash
# Ubuntu / Debian
sudo apt install build-essential cmake libsodium-dev libargon2-dev nlohmann-json3-dev pkg-config

# Arch Linux
sudo pacman -S base-devel cmake libsodium argon2 nlohmann-json pkgconf
```

### Build

```bash
cmake -S . -B build
cmake --build build
```

### Run

```bash
./build/passManager
```

## How It Works

On first run, the app will:

1. Create `~/.local/share/passManager` if it does not exist
2. Ask you to choose a security level for Argon2id key derivation
3. Create `config.json` in the application data directory
4. Prompt you to create your first vault if none exist

After that, the main menu lets you:

- Open an existing vault
- Create a new vault
- Delete a vault
- Import a vault file
- Export a vault file
- Exit the program

Inside a vault, you can:

- Get a password
- Add a password entry
- Edit an entry
- Delete an entry
- Exit back to the main vault selection flow

Each entry currently stores:

- Name
- Password
- Comments
- `createdAt`
- `lastUsed`
- `lastEdited`

## Storage Layout

Application data lives here:

```text
~/.local/share/passManager/
```

Typical contents:

```text
config.json
personal.vault
work.vault
```

Vault files are stored as binary `.vault` files containing:

- Salt
- Nonce
- Additional authenticated data (AAD)
- Ciphertext

## Security Notes

This project uses solid libraries, but it should still be treated as a personal or learning project unless you have reviewed and hardened it for your own needs.

- Vault encryption uses `crypto_aead_chacha20poly1305_*` from `libsodium`
- Master keys are derived from your password using Argon2id
- Some sensitive buffers are explicitly wiped with `sodium_memzero`
- Password input is hidden while typing
- Exporting a vault copies the encrypted vault file as-is

Current caveats:

- Retrieved passwords are printed directly to the terminal
- The project has no included automated test suite
- There is no license file in the repository yet
- The codebase has not been security audited

## Project Structure

```text
.
├── CMakeLists.txt
├── src
│   ├── main.cpp
│   ├── vaultCreation.cpp
│   ├── vaultManagement.cpp
│   ├── keyDeriv.cpp
│   ├── addPass.cpp
│   ├── getPass.cpp
│   ├── editPass.cpp
│   ├── delPass.cpp
│   ├── delVault.cpp
│   ├── importVault.cpp
│   ├── exportVault.cpp
│   ├── config.cpp
│   ├── passwordStrength.cpp
│   └── utils.cpp
└── README.md
```

## Example Flow

```text
1. Start the app
2. Choose or create a vault
3. Enter your master password
4. Open the vault menu
5. Add or retrieve entries as needed
6. Re-enter your password if the 5-minute session expires
```

## Roadmap Ideas

- Clipboard support with automatic clearing
- Search/filter for entries
- Better duplicate-entry handling
- Safer export format and backup tooling
- Automated tests
- Cross-platform terminal support

