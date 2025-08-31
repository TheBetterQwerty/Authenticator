# Rust Auth App

A simple authentication helper tool implemented in Rust.  
This project generates authentication codes from a link provided at runtime.  

## Usage

Run the app with:

```
cargo run -q -- "link"
```

- Replace `"link"` with the input string you want to process.
- The app will calculate and return the authentication code based on your link.

## Features

- CLI interface for generating authentication codes.
- Lightweight and dependency-minimal design.
- Completly offline and local.

## TODO

- Add QR code parsing support (convert QR → code).  
- Remove dependency on link inputs (direct QR scan or raw key input).  
- Potential usability improvements for scripts and automation.

## Development

To build and run locally:

```
cargo build
cargo run -q -- "link"
```
