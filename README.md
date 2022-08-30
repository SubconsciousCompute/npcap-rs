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
- dns-parse - Parses DNS packets 

To use the safe Rust bindings, Add the following to your Cargo.toml

```toml
[dependencies]
npcap-rs = { version = "0.1", features = [] }
```

# Examples

```
cargo run --example list
```
