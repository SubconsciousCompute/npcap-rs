#[cfg(feature = "non_raw")]
mod raw;

#[cfg(feature = "raw")]
pub mod raw;

use std::ffi::CStr;
use std::sync::mpsc;

/// container that allows for interfacing with network devices
pub struct PCap {
    _iface: *mut raw::_pcap_if,
}

impl PCap {
    pub fn new() -> Option<Self> {
        let mut err = [0u8; 256];
        let mut devs: *mut raw::_pcap_if = std::ptr::null_mut();

        // we'll get a heap allocated object from npcap
        let ret = unsafe { raw::pcap_findalldevs(&mut devs as _, &mut err as *mut _) };
        if ret == 0 {
            Some(Self { _iface: devs })
        } else {
            // dont really wanna deal with errors yet
            // let's just return None and not deal with errbuf shit
            None
        }
    }

    pub fn devices<'a>(&self) -> DeviceIter<'a> {
        unsafe {
            DeviceIter {
                item: Some(self._iface.as_ref().unwrap()),
            }
        }
    }
}

impl Drop for PCap {
    fn drop(&mut self) {
        // free the object allocated by npcap
        if !self._iface.is_null() {
            unsafe { raw::pcap_freealldevs(self._iface) };
        }
    }
}

#[derive(Debug)]
pub struct Address {
    addr: Option<raw::sockaddr>,
    netmask: Option<raw::sockaddr>,
    broad_addr: Option<raw::sockaddr>,
    dst_addr: Option<raw::sockaddr>,
}

/// Represents a physical network interface i.e ethernet NIC/Wifi Card, etc...
#[derive(Debug)]
pub struct Device {
    /// The name of the device
    pub name: Option<String>,
    /// Description of the device
    pub desc: Option<String>,
    addresses: Option<Address>,
}

impl Device {
    fn from_pcap_if(item: &raw::_pcap_if) -> Self {
        let name = {
            if item.name.is_null() {
                None
            } else {
                Some(unsafe { CStr::from_ptr(item.name).to_str().unwrap().to_string() })
            }
        };

        let desc = {
            if item.desc.is_null() {
                None
            } else {
                Some(unsafe { CStr::from_ptr(item.desc).to_str().unwrap().to_string() })
            }
        };

        let addr = if item.addresses.is_null() {
            None
        } else {
            let (netmask, broad_addr, addr, dst_addr) = unsafe {
                let addr = item.addresses.as_ref().unwrap();
                (
                    addr.netmask.as_ref().clone().map(|addr| addr.clone()),
                    addr.broad_addr.as_ref().clone().map(|addr| addr.clone()),
                    addr.addr.as_ref().clone().map(|addr| addr.clone()),
                    addr.dstaddr.as_ref().clone().map(|addr| addr.clone()),
                )
            };
            Some(Address {
                netmask,
                broad_addr,
                addr,
                dst_addr,
            })
        };

        Self {
            name,
            desc,
            addresses: addr, //address: item.addresses.as_ref().unwrap().clone(),
        }
    }

    /// Open the current device for packet sniffing
    pub fn open(&self) -> Option<(Listener, mpsc::Receiver<Packet>)> {
        let mut err_buf = [0i8; 256];

        let name = self.name.as_ref().unwrap();
        let handle =
            unsafe { raw::pcap_open_live(name.as_ptr(), 65536, 1, 1000, &mut err_buf as _) };
        if !handle.is_null() {
            Some(Listener::new(handle))
        } else {
            eprintln!("{:?}", unsafe { std::ffi::CStr::from_ptr(&err_buf as _) });
            None
        }
    }
}

pub struct DeviceIter<'a> {
    item: Option<&'a raw::_pcap_if>,
}

impl<'a> Iterator for DeviceIter<'a> {
    type Item = Device;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(item) = self.item {
            let dev = Device::from_pcap_if(item);
            if item.next.is_null() {
                self.item = None;
            } else {
                self.item = unsafe { Some(item.next.as_ref().unwrap()) };
            }
            Some(dev)
        } else {
            None
        }
    }
}

#[derive(Debug)]
pub enum PacketType {
    IP,
    Ethernet,
    TCP,
    UDP,
}

#[derive(Debug)]
pub struct Packet {
    pub e_hdr: EthernetHdr,
    pub ip_hdr: IPHeader,
    //which: PacketType,
    len: u32,
}

#[derive(Debug)]
pub struct EthernetHdr {
    pub d_mac: (u8, u8, u8, u8, u8, u8),
    pub s_mac: (u8, u8, u8, u8, u8, u8),
    pub ether_type: u16,
}

impl EthernetHdr {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        // MAC header is atleast 14 bytes
        assert!(bytes.len() > 14);

        let mut cur = 0;

        EthernetHdr {
            d_mac: (
                bytes[cur],
                bytes[cur + 1],
                bytes[cur + 2],
                bytes[cur + 3],
                bytes[cur + 4],
                bytes[cur + 5],
            ),
            s_mac: (
                bytes[cur + 6],
                bytes[cur + 7],
                bytes[cur + 8],
                bytes[cur + 9],
                bytes[cur + 10],
                bytes[cur + 11],
            ),
            ether_type: u16::from_be_bytes(bytes[12..14].try_into().unwrap()),
        }
    }
}

impl std::fmt::Display for EthernetHdr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} -> {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.s_mac.0,
            self.s_mac.1,
            self.s_mac.2,
            self.s_mac.3,
            self.s_mac.4,
            self.s_mac.5,
            self.d_mac.0,
            self.d_mac.1,
            self.d_mac.2,
            self.d_mac.3,
            self.d_mac.4,
            self.d_mac.5
        ))
    }
}

/// Handle that captures packet for a device
/// This is returned when a device is opened for capture
/// ```ignore
/// fn main() {
///     let dev: Device = ... ;
///     let (listener, rx) = dev.open();
/// }
/// ```
#[repr(C)]
pub struct Listener {
    //dev: Device,
    handle: raw::pcap_t,
    tx: mpsc::Sender<Packet>,
}

unsafe impl Sync for Listener {}
unsafe impl Send for Listener {}

// handler that is called every time we recv a packet
extern "C" fn pkt_handle(param: *const (), header: &raw::pcap_pkthdr, pkt_data: *const u8) {
    // very unsafe i feel, idk
    let p_ptr = param as *const Listener;
    let param = unsafe { p_ptr.as_ref().unwrap() };

    let data = unsafe { std::slice::from_raw_parts(pkt_data, header.len as usize) };

    let e_hdr = EthernetHdr::from_bytes(data);
    let ip_hdr = IPHeader::from_bytes(&data[14..]);

    _ = param.tx.send(Packet {
        e_hdr,
        ip_hdr,
        len: header.len,
    });
}

impl Listener {
    /// Create a new packet listener for a device
    pub fn new(handle: raw::pcap_t) -> (Self, mpsc::Receiver<Packet>) {
        let (tx, rx) = mpsc::channel();
        (Self { tx, handle }, rx)
    }

    /// This functions starts a new thread and starts capturing packets
    pub fn run(self) {
        use std::thread;
        // we dont care about the thread handle as this will always run
        _ = thread::Builder::new()
            .name("pcap_listener".to_string())
            .spawn(move || unsafe {
                raw::pcap_loop(self.handle, 0, pkt_handle, &self as *const _ as _);
            });
    }

    /// Set a filter on the device capturing packets
    pub fn set_filter(&self, dev: &Device, filter: &str) -> bool {
        let mut code = raw::bpf_program::default();
        let filter = std::ffi::CString::new(filter).unwrap();

        // assuming we have addresses
        let addrs = dev.addresses.as_ref().unwrap();

        let netmask = if let Some(ref addr) = addrs.netmask {
            // NOTE: 2..6 since the ip addr data starts at index 2
            // 0..2 are port, 7..14 is padding and is filled with 0
            u32::from_le_bytes(addr.sa_data[2..6].try_into().unwrap())
        } else {
            0xffffff
        };

        unsafe {
            if raw::pcap_compile(
                self.handle,
                &mut code as *mut _ as _,
                filter.as_ptr(),
                1,
                netmask,
            ) < 0
            {
                false
            } else {
                // TODO: handle when pcap_setfilter fails
                assert!(raw::pcap_setfilter(self.handle, &mut code as *mut _) == 0);
                true
            }
        }
    }

    /// Get the next packet captured by the device
    pub fn next_packet(&self) -> Option<Packet> {
        let mut hdr = raw::pcap_pkthdr::default();
        let data_ptr = unsafe { raw::pcap_next(self.handle, &mut hdr) };
        if data_ptr.is_null() {
            None
        } else {
            let data = unsafe { std::slice::from_raw_parts(data_ptr, hdr.len as usize) };
            let e_hdr = EthernetHdr::from_bytes(data);

            let ip_hdr = IPHeader::from_bytes(&data[14..]);

            Some(Packet {
                e_hdr,
                ip_hdr,
                len: hdr.len,
            })
        }
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        // close the handle on the capture device
        unsafe { raw::pcap_close(self.handle) }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct IP {
    byte1: libc::c_uchar,
    byte2: libc::c_uchar,
    byte3: libc::c_uchar,
    byte4: libc::c_uchar,
}

#[repr(C)]
#[derive(Debug)]
pub struct IPHeader {
    ver_ihl: libc::c_uchar,
    tos: libc::c_uchar,
    tlen: libc::c_uchar,
    ident: libc::c_ushort,
    flags_fo: libc::c_ushort,
    ttl: libc::c_uchar,
    proto: libc::c_uchar,
    crc: libc::c_ushort,
    pub src_addr: std::net::Ipv4Addr,
    pub dest_addr: std::net::Ipv4Addr,
    op_pad: libc::c_int,
}

impl IPHeader {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        /*
        correct: 35.186.224.25 -> 192.168.0.117
        wrong: 35.186.224.195 -> 192.168.0.25
         */
        // idk how i came up with the indexes but ok
        let s_ip = std::net::Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]);
        let d_ip = std::net::Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]);

        IPHeader {
            ver_ihl: bytes[0],
            tos: bytes[1],
            tlen: bytes[2],
            ident: u16::from_le_bytes(bytes[3..5].try_into().unwrap()),
            flags_fo: u16::from_le_bytes(bytes[5..7].try_into().unwrap()),
            ttl: bytes[7],
            proto: bytes[8],
            crc: u16::from_le_bytes(bytes[9..11].try_into().unwrap()),
            src_addr: s_ip,
            dest_addr: d_ip,
            op_pad: 0,
        }
    }
}

pub fn version() -> String {
    let ptr = unsafe { std::ffi::CStr::from_ptr(raw::pcap_lib_version()) };
    ptr.to_str().unwrap().to_string()
}
