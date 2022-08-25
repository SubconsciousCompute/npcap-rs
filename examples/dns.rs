//! Shows the use of filter.
//! Author: David <david.j@subcom.tech>
//!

fn main() {

    println!("Libpcap version: {}", npcap_rs::version());
    let pcap = npcap_rs::PCap::new().unwrap();
    let dev = pcap.find_device("Wireless");

    if let Some(dev) = dev {
        let (listener, rx) = dev.open().unwrap();
        println!("filter set: {}", listener.set_filter(&dev, "udp"));

        listener.run();

        while let Ok(pack) = rx.recv() {
            if let Some(udp) =  pack.udp {
                if let Ok(dns) = dns_parser::Packet::parse(&udp.data.unwrap()) {
                    if dns.header.query {
                        println!("{:?}", dns);
                    }
                }
            }
        }
    }
}
