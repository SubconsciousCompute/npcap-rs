//! Sniffing Bittorrent connections using npcap
//! Author: David <david.j@subcom.tech>
//!
//! This is a very naive approach that only checks if the connections 
//! are in a given range mostly used by bittorrent.
//!

fn main() {
    println!("Libpcap version: {}", npcap_rs::version());
    let pcap = npcap_rs::PCap::new().unwrap();
    let dev = pcap.find_device("Wireless");

    // common port range for torrent connections
    let bt_ports = 6881..6889;

    if let Some(dev) = dev {
        let (listener, rx) = dev.open(None).unwrap();
        println!("filter set: {}", listener.set_filter(&dev, "ip and tcp"));

        listener.run();

        let bt_ports = 6881..=6889;

        while let Ok(pack) = rx.recv() {
            if let Some(tcp) =  pack.tcp {
                if bt_ports.contains(&tcp.hdr.source_port) || bt_ports.contains(&tcp.hdr.dest_port) {
                    println!("{} -> {}", pack.ip_hdr.source_addr, pack.ip_hdr.dest_addr);
                }
            }
        }
    }
}
