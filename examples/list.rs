fn main() {
    let pcap = npcap_rs::PCap::new().unwrap();
    let mut sel = 0;
    let devs: Vec<_> = pcap.devices().collect();
    for (idx, dev) in devs.iter().enumerate() {
        println!(
            "{}: {} - {}",
            idx,
            dev.name.as_ref().unwrap(),
            dev.desc.as_ref().unwrap()
        );
    }
    print!("Select an interface: ");
    let mut inp = String::new();

    std::io::stdin().read_line(&mut inp);

    let sel = inp.trim().parse::<u8>().unwrap();
    println!("Selected: {}", sel);
    if let Some((listener, rx)) = devs[sel as usize].open() {
        listener.set_filter(&devs[sel as usize], "ip and tcp");
        listener.run();

        while let Ok(pack) = rx.recv() {
            println!("{} -> {}", pack.ip_hdr.src_addr, pack.ip_hdr.dest_addr);
        }
    }
}
