fn main() {
    #[cfg(target_os = "linux")]
    {
        let pcap = npcap_rs::PCap::new().unwrap();
        let (lx, rx) = pcap.open_all().unwrap();
        lx.run();

        while let Ok(packet) = rx.recv() {
            println!("{} -> {}", packet.ip_hdr.src_addr, packet.ip_hdr.dest_addr);
        }
    }
}
