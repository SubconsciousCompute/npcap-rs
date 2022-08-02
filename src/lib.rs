mod raw;

use std::ffi::CStr;
use std::sync::mpsc;

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

/// Represents a physical network interface i.e ethernet NIC/Wifi Card, etc...
#[derive(Debug)]
pub struct Device {
    /// The name of the device
    pub name: Option<String>,
    /// Description of the device
    pub desc: Option<String>,
    //address: sockaddr,
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

        unsafe {
            Self {
                name,
                desc, //address: item.addresses.as_ref().unwrap().clone(),
            }
        }
    }

    /*
    /// Open the current device for packet sniffing
    pub fn open(&self) -> (Listener, mpsc::Receiver<Packet>) {
        // open the conn
        //pcap_open_live()

        //Listener::new(self.clone())
    }
     */
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

pub struct Packet;

pub struct Listener {
    dev: Device,
    tx: mpsc::Sender<Packet>,
}

impl Listener {
    pub fn new(dev: Device) -> (Self, mpsc::Receiver<Packet>) {
        let (tx, rx) = mpsc::channel();
        (Self { dev: dev, tx }, rx)
    }
}