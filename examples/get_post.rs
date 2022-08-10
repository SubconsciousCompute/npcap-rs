//! Capture GET and POST packets only.
//!
//! Author: Dilawar <dilawar@subcom.tech>
//!

fn main() {
    println!("Libpcap version: {}", npcap_rs::version());
    let pcap = npcap_rs::PCap::new().unwrap();
    let dev = pcap.find_device("Wireless");

    if let Some(dev) = dev {
        let (listener, rx) = dev.open().unwrap();

        let getpat = "tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420";
        let postpat = "tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504F5354";

        let pat = format!("({}) or ({})", getpat, postpat);
        println!("filter set: {}", listener.set_filter(&dev, &pat));

        listener.run();

        while let Ok(pack) = rx.recv() {
            match pack.app_prot {
                npcap_rs::ApplicationProtocol::TCP => {
                    let pack = pack.tcp.unwrap();
                    match pack.data {
                        npcap_rs::TCPApps::Generic(_) => println!("Generic TCP packet"),
                        npcap_rs::TCPApps::HTTP(data) => println!("HTTP packet: {:?}", data),
                    }
                }
                _ => unimplemented!(),
            }
        }
    }
}
