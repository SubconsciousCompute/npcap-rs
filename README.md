![](https://gitlab.subcom.tech/subcom/npcap-rs/badges/main/pipeline.svg)

# npcap_rs

__WIP__

Rust binding for npcap library. 

# Usage

To use the safe Rust bindings, Add the following to your Cargo.toml

```toml
[dependencies]
npcap-rs = "0.1"
```

To use the raw unsafe Rust bindings, Add the following to your Cargo.toml

```toml
[dependencies]
npcap-rs = { version = "0.1", default-features = false, features = ["raw"] }
```

# Examples

```
cargo run --example list.rs
```
