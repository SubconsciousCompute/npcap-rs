
use std::{ffi::CStr, ptr::null};

struct pcap_t {}

extern "C" {
    pub fn pcap_findalldevs(all_dev_sp: *mut *mut _pcap_if, err_buf: *mut u8) -> i32;
    pub fn pcap_freealldevs(all_dev_sp: *mut _pcap_if);

    pub fn pcap_open_live(
        device: *mut u8,
        snaplen: i32,
        promisc: i32,
        to_ms: i32,
        ebuf: *mut u8,
    ) -> *const pcap_t;
}

#[repr(C)]
#[derive(Debug)]
pub struct _pcap_if {
    pub next: *const _pcap_if,
    pub name: *const i8,
    pub desc: *const i8,
    pub addresses: *const _pcap_addr,
    pub flags: u32,
}

impl _pcap_if {
    pub fn new() -> Self {
        Self {
            next: null(),
            name: null(),
            desc: null(),
            addresses: null(),
            flags: 0,
        }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct _pcap_addr {
    pub next: *const _pcap_addr,
    pub addr: *const sockaddr,
    pub netmask: *const sockaddr,
    pub broad_addr: *const sockaddr,
    pub dstaddr: *const sockaddr,
}

impl _pcap_addr {
    fn new() -> Self {
        Self {
            next: null(),
            addr: null(),
            netmask: null(),
            broad_addr: null(),
            dstaddr: null(),
        }
    }
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct sockaddr {
    pub sa_family: u16,
    pub sa_data: [u8; 14],
}
