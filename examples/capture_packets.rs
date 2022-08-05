//! Capture packet from a given devices.
//!
fn main() {
    println!("Libpcap version: {}", npcap_rs::version());
    let pcap = npcap_rs::PCap::new().unwrap();

    let hint = "8811CU".to_string();
    if let Some(dev) = pcap.find_device(&hint) {
        println!("Capturing from device: {:?}", dev.desc);
        let (listener, rx) = dev.open().unwrap();
        listener.run();
        while let Ok(pack) = rx.recv() {
            println!("{:?}", pack);
        }
    } else {
        println!("No device found that has `{}` in its name.", hint);
    }
}
