//! Shows the use of filter.
//! Author: David <david.j@subcom.tech>
//!

fn main() {

    println!("Libpcap version: {}", npcap_rs::version());
    let pcap = npcap_rs::PCap::new().unwrap();
    let dev = pcap.find_device("Wireless");

    if let Some(dev) = dev {
        let (listener, rx) = dev.open(None).unwrap();
        println!("filter set: {}", listener.set_filter(&dev, "ip and tcp"));

        listener.run();

        while let Ok(pack) = rx.recv() {
            println!("{:?}", pack);
        }
    }
}
