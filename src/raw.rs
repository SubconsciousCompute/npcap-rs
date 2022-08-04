#![allow(non_camel_case_types)]

pub type pcap_t = *const ();

#[derive(Debug, Default)]
#[repr(C)]
pub struct timeval {
    pub tv_sec: i32,
    pub tv_usec: i32,
}

#[derive(Debug, Default)]
#[repr(C)]
pub struct pcap_pkthdr {
    pub ts: timeval,
    pub caplen: u32,
    pub len: u32,
}

pub type pcap_handler = extern "C" fn(u: *const (), h: &pcap_pkthdr, bytes: *const u8);

extern "C" {
    pub fn pcap_findalldevs(all_dev_sp: *mut *mut _pcap_if, err_buf: *mut u8) -> libc::c_int;
    pub fn pcap_freealldevs(all_dev_sp: *mut _pcap_if);

    pub fn pcap_open_live(
        device: *const u8,
        snaplen: i32,
        promisc: i32,
        to_ms: i32,
        ebuf: *mut i8,
    ) -> pcap_t;

    pub fn pcap_lib_version() -> *const i8;

    pub fn pcap_loop(p: pcap_t, cnt: libc::c_int, h: pcap_handler, u: *const ()) -> libc::c_int;
    pub fn pcap_close(p: pcap_t);

    pub fn pcap_compile(
        p: pcap_t,
        fp: *mut (), /*ptr to struct bpf_program*/
        s: *const libc::c_char,
        optimize: i32,
        netmask: u32,
    ) -> libc::c_int;

    pub fn pcap_setfilter(p: pcap_t, fp: *mut bpf_program) -> libc::c_int;

    pub fn pcap_dispatch(
        p: pcap_t,
        cnt: libc::c_int,
        callback: pcap_handler,
        user: *const (),
    ) -> libc::c_int;

    pub fn pcap_next(p: pcap_t, h: &mut pcap_pkthdr) -> *const libc::c_uchar;

    pub fn pcap_lookupdev(err_buf: *mut libc::c_char) -> *mut libc::c_char;
}

#[repr(C)]
#[derive(Debug)]
pub struct bpf_program {
    len: libc::c_ushort,
    // this is a pointer to ops in C but we dont care in Rust
    // TODO: prolly port the ops struct or use a crate for bpf bindings
    filter: *mut (),
}

impl Default for bpf_program {
    fn default() -> Self {
        Self {
            len: 0,
            filter: std::ptr::null_mut(),
        }
    }
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

#[repr(C)]
#[derive(Debug)]
pub struct _pcap_addr {
    pub next: *const _pcap_addr,
    pub addr: *const sockaddr,
    pub netmask: *const sockaddr,
    pub broad_addr: *const sockaddr,
    pub dstaddr: *const sockaddr,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct sockaddr {
    pub sa_family: u16,
    pub sa_data: [u8; 14],
}
