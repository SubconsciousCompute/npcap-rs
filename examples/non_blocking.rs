fn main() {
    println!("Libpcap version: {}", npcap_rs::version());
    let devs = npcap_rs::PCap::new().unwrap();

    let dev = devs
        .devices()
        .find(|dev| dev.desc.as_ref().unwrap() == "Realtek(R) PCI(e) Ethernet Controller");

    if let Some(dev) = dev {
        let (listener, _) = dev.open().unwrap();

        while let Some(pack) = listener.next_packet() {
            println!("{:?}", pack);
        }
    }
}
