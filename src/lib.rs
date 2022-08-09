//! Bindings to npcap
//!
//! (c) 2021, Subconscious Compute

pub mod helper;
#[allow(dead_code, unused_imports)]
pub mod raw;

use std::ffi::CStr;
use std::sync::mpsc;

use helper::parse_raw;

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
            panic!("Failed to bind.");
        }
    }

    pub fn devices<'a>(&self) -> DeviceIter<'a> {
        unsafe {
            DeviceIter {
                item: Some(self._iface.as_ref().unwrap()),
            }
        }
    }

    /// Open all the interfaces for packet capture. Only works on Linux
    #[cfg(target_os = "linux")]
    pub fn open_all(&self) -> Option<(Listener, mpsc::Receiver<raw::HeaderType>)> {
        open_device("rpcap://any")
    }

    /// Return a single device. If environment variable NPCAP_DEVICE_HINT is set, a
    /// device with same name is returned. Else first device that is not a loopback is returned.
    /// Preference is always given to WiFi connections.
    pub fn default_device(&self) -> Option<Device> {
        if let Ok(devhint) = std::env::var("NPCAP_DEVICE_HINT") {
            self.find_device(&devhint)
        } else {
            let wifis: Vec<_> = self.devices().filter(|dev| dev.is_wifi()).collect();
            if !wifis.is_empty() {
                wifis.into_iter().nth(0)
            } else {
                self.devices().filter(|dev| dev.is_in_use()).nth(0)
            }
        }
    }

    /// Find a device that that the given `needle` in its description.
    pub fn find_device(&self, needle: &str) -> Option<Device> {
        self.devices()
            .find(|dev| dev.desc.as_ref().unwrap().contains(needle))
    }

    /// Return currently active devices.
    pub fn active_devices(&self) -> Vec<Device> {
        self.devices().filter(|dev| dev.is_in_use()).collect()
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
    /// flags.
    pub flags: u32,
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
                    addr.netmask.as_ref().copied(),
                    addr.broad_addr.as_ref().copied(),
                    addr.addr.as_ref().copied(),
                    addr.dstaddr.as_ref().copied(),
                )
            };
            Some(Address {
                netmask,
                broad_addr,
                addr,
                dst_addr,
            })
        };

        let flags = item.flags;

        Self {
            name,
            desc,
            addresses: addr, //address: item.addresses.as_ref().unwrap().clone(),
            flags,           // https://github.com/the-tcpdump-group/libpcap/blob/master/pcap/pcap.h
        }
    }

    /// Open the current device for packet sniffing
    pub fn open(&self) -> Option<(Listener, mpsc::Receiver<Packet>)> {
        open_device(self.name.as_ref().unwrap())
    }

    #[inline(always)]
    fn is_flag_set(&self, flag: u32) -> bool {
        (self.flags & flag) != 0
    }

    /// Interface is up
    pub fn is_up(&self) -> bool {
        self.is_flag_set(0x0000_0002)
    }

    /// Interface is running.
    pub fn is_running(&self) -> bool {
        self.is_flag_set(0x0000_0004)
    }

    /// interface is wireless (*NOT* necessarily Wi-Fi!)
    pub fn is_wifi(&self) -> bool {
        self.is_flag_set(0x0000_0008)
    }

    /// connected
    pub fn is_connected(&self) -> bool {
        self.is_flag_set(0x0000_0010)
    }

    /// up and running.
    pub fn is_in_use(&self) -> bool {
        self.is_connected() & self.is_up() && self.is_running()
    }
}

pub fn open_device(dev: &str) -> Option<(Listener, mpsc::Receiver<Packet>)> {
    let mut err_buf = [0i8; 256];
    let name = std::ffi::CString::new(dev.to_string()).unwrap();

    let ptr = if dev.is_empty() {
        std::ptr::null()
    } else {
        name.as_ptr()
    };

    let handle = unsafe { raw::pcap_open_live(ptr, 65536, 1, 1000, &mut err_buf as _) };
    if !handle.is_null() {
        Some(Listener::new(handle))
    } else {
        eprintln!("{:?}", unsafe { std::ffi::CStr::from_ptr(&err_buf as _) });
        None
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

use pktparse::{ethernet, ipv4, ipv6, tcp, udp};

#[derive(Debug)]
pub enum HeaderType {
    Tcp(tcp::TcpHeader),
    Udp(udp::UdpHeader),
    IPv4(ipv4::IPv4Header),
    IPv6(ipv6::IPv6Header),
}

#[derive(Debug)]
pub enum ApplicationProtocol {
    TCP,
    UDP,
}

#[derive(Debug)]
pub enum TCPApps {
    HTTP,
}

#[derive(Debug)]
pub struct TCPPacket {
    pub hdr: tcp::TcpHeader,
    pub data: TCPApps,
}

#[derive(Debug)]
pub struct Packet {
    pub ether_hdr: ethernet::EthernetFrame,
    pub ip_hdr: ipv4::IPv4Header,
    pub app_prot: ApplicationProtocol,
    pub tcp: Option<TCPPacket>,
    // udp_hdr: Option<tcp::TcpHeader>
}

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
    if let Some(pkt) = parse_raw(data) {
        _ = param.tx.send(pkt);
    }
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
            parse_raw(data)
        }
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        // close the handle on the capture device
        unsafe { raw::pcap_close(self.handle) }
    }
}

/// npcap version.
pub fn version() -> String {
    let ptr = unsafe { std::ffi::CStr::from_ptr(raw::pcap_lib_version()) };
    ptr.to_str().unwrap().to_string()
}
