fn main() {
    #[cfg(target_os = "windows")]
    {
        println!("cargo:rustc-link-search=native=.\\third-party\\npcap\\Lib\\x64\\");
        println!("cargo:rustc-link-lib=static=wpcap");
    }

    #[cfg(target_os = "linux")]
    {
        println!("cargo:rustc-link-lib=dylib=pcap");
    }
}
