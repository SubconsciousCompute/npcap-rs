fn main() {
    println!("Libpcap version: {}", npcap_rs::version());
    let devs = npcap_rs::PCap::new().unwrap();

    let dev = devs
        .devices()
        .find(|dev| dev.desc.as_ref().unwrap() == "Realtek(R) PCI(e) Ethernet Controller");

    if let Some(dev) = dev {
        let (listener, rx) = dev.open().unwrap();
        listener.run();
        while let Ok(pack) = rx.recv() {
            println!("{}", pack.e_hdr);
        }
    }
}
