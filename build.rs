fn main() {
    println!("cargo:rustc-link-search=native=.\\third-party\\npcap\\Lib\\x64\\");
    //println!("cargo:rustc-link-lib=static=Packet");
    println!("cargo:rustc-link-lib=static=wpcap");

    /*
    let bindings = bindgen::Builder::default()
        .clang_arg("-I./third-party/npcap/Include")
        .header("third-party/npcap/Include/pcap.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("unable to generate bindings");

    bindings
        .write_to_file(".bindings.rs")
        .expect("Couldn't write to file");
    */
}
