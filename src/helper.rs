use pktparse::ethernet::{self, EtherType};

/// Parse the raw packet.
///
/// ## Notes
///
/// 1. Every packet lives in an Ethernet frame.
/// 2. MTU may restrict the size of packet. UDP packet can be as big as 2^16-1 bytes (65535 bytes)
///    but the Ethernet frame can only contain 1500 bytes of data. Larger UDP packets will get
///    defragmented.
///
/// ## References:
/// - https://jvns.ca/blog/2017/02/07/mtu/
pub fn parse_raw(data: &[u8]) -> Option<crate::HeaderType> {
    if let Ok((remaining, eth_frame)) = ethernet::parse_ethernet_frame(data) {
        let etype = eth_frame.ethertype;
        if etype == EtherType::IPv4 {
            if let Ok((remaining, header)) = pktparse::ipv4::parse_ipv4_header(remaining) {
                return Some(crate::HeaderType::IPv4(header));
            }
        } else {
            eprintln!(" - Unsupported Ethernet frame type: {:?}", etype);
        }
        return None;
    }
    None
}