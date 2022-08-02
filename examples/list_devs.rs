fn main() {
    let devs = npcap_rs::PCap::new().unwrap();
    for dev in devs.devices() {
        println!("{:?}", dev)
    }
}
