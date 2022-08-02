mod raw {
    use super::_pcap_if;

    extern "C" {
        pub fn pcap_findalldevs(all_dev_sp: *mut *mut _pcap_if, err_buf: *mut u8) -> i32;
        pub fn pcap_freealldevs(all_dev_sp: *mut _pcap_if);
    }
}

use std::{ffi::CStr, ptr::null};

#[repr(C)]
#[derive(Debug)]
struct _pcap_if {
    next: *const _pcap_if,
    name: *const i8,
    desc: *const i8,
    addresses: *const _pcap_addr,
    flags: u32,
}

macro_rules! null {
    () => {
        std::ptr::null()
    };
}

impl _pcap_if {
    fn new() -> Self {
        Self {
            next: null!(),
            name: null!(),
            desc: null!(),
            addresses: null!(),
            flags: 0,
        }
    }
}

#[derive(Debug)]
pub struct Device {
    pub name: String,
    pub desc: String,
    //address: sockaddr,
}

impl Device {
    fn from_pcap_if(item: &_pcap_if) -> Self {
        unsafe {
            Self {
                name: CStr::from_ptr(item.name).to_str().unwrap().to_string(),
                desc: CStr::from_ptr(item.desc).to_str().unwrap().to_string(),
                //address: item.addresses.as_ref().unwrap().clone(),
            }
        }
    }
}

#[repr(C)]
#[derive(Debug)]
struct _pcap_addr {
    next: *const _pcap_addr,
    addr: *const sockaddr,
    netmask: *const sockaddr,
    broad_addr: *const sockaddr,
    dstaddr: *const sockaddr,
}

impl _pcap_addr {
    fn new() -> Self {
        Self {
            next: null!(),
            addr: null!(),
            netmask: null(),
            broad_addr: null!(),
            dstaddr: null!(),
        }
    }
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
struct sockaddr {
    sa_family: u16,
    sa_data: [u8; 14],
}

pub struct PCap {
    _iface: *mut _pcap_if,
}

pub struct DeviceIter<'a> {
    item: Option<&'a _pcap_if>,
}

impl PCap {
    pub fn new() -> Option<Self> {
        let mut err = [0u8; 1024];
        let mut devs: *mut _pcap_if = std::ptr::null_mut();

        // we'll get a heap allocated object from npcap
        let ret = unsafe { raw::pcap_findalldevs(&mut devs as _, &mut err as *mut _) };
        if ret == 0 {
            Some(Self { _iface: devs })
        } else {
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
