![](https://gitlab.subcom.tech/subcom/npcap-rs/badges/main/pipeline.svg)

# npcap_rs

__WIP__

Rust binding for npcap library. 

# Prerequisite

- Install Npcap from [here](https://npcap.com/#download)
- Download Npcap SDK and extract the SDK in the source tree under third-party folder
- Set the NPCAP_RS_LIB_DIR to the directory where library is installed.

# Usage

You can enable these optional features for additional functionality.
- http-parse - Parses HTTP headers
- cbeam-chan - Use crossbeam channels instead of `std::sync::mpsc`

To use the safe Rust bindings, Add the following to your Cargo.toml

```toml
[dependencies]
npcap-rs = "0.1"
```

# Examples

```
cargo run --example list
```
