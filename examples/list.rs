//! List all devices.
//!

use std::io::{self, Write};

fn main() {
    let pcap = npcap_rs::PCap::new().unwrap();
    let devs: Vec<_> = pcap.active_devices();
    let mut sel = 0;
    for (idx, dev) in devs.iter().enumerate() {
        println!(
            "{}: {:?} '{:?}' {:#04X?}",
            idx, dev.name, dev.desc, dev.flags,
        );
    }

    print!("Select an interface: ");
    io::stdout().flush().unwrap();

    let mut inp = String::new();
    io::stdin().read_line(&mut inp);

    let sel = inp.trim().parse::<u8>().unwrap();
    println!("Selected: {}", sel);
    if let Some((listener, rx)) = devs[sel as usize].open() {
        listener.set_filter(&devs[sel as usize], "ip and tcp");
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
