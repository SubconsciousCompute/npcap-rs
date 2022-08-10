//! This module contains unsafe Rust bindings as per
//! [WinPCap Docs](https://www.winpcap.org/docs/docs_412/html/group__wpcapfunc.html)

#![allow(non_camel_case_types)]

use pktparse::{
    ethernet::{self, EtherType},
    tcp::TcpOption,
};
pub type pcap_t = *const ();

#[derive(Debug, Default)]
#[repr(C)]
pub struct timeval {
    pub tv_sec: libc::c_long,
    pub tv_usec: libc::c_long,
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
    /// Construct a list of network devices that can be opened with pcap_open_live().
    pub fn pcap_findalldevs(all_dev_sp: *mut *mut _pcap_if, err_buf: *mut u8) -> libc::c_int;

    /// Free an interface list returned by pcap_findalldevs().
    pub fn pcap_freealldevs(all_dev_sp: *mut _pcap_if);

    /// Open a live capture from the network.
    pub fn pcap_open_live(
        device: *const i8,
        snaplen: i32,
        promisc: i32,
        to_ms: i32,
        ebuf: *mut i8,
    ) -> pcap_t;

    /// Returns a pointer to a string giving information about the version of the libpcap library being used.
    /// note that it contains more information than just a version number.
    pub fn pcap_lib_version() -> *const libc::c_char;

    /// Collect a group of packets.
    pub fn pcap_loop(p: pcap_t, cnt: libc::c_int, h: pcap_handler, u: *const ()) -> libc::c_int;

    ///close the files associated with p and deallocates resources.
    pub fn pcap_close(p: pcap_t);

    /// Compile a packet filter, converting an high level filtering expression
    /// in a program that can be interpreted by the kernel-level filtering engine.
    pub fn pcap_compile(
        p: pcap_t,
        fp: *mut (), /*ptr to struct bpf_program*/
        s: *const libc::c_char,
        optimize: i32,
        netmask: u32,
    ) -> libc::c_int;

    /// Associate a filter to a capture.
    pub fn pcap_setfilter(p: pcap_t, fp: *mut bpf_program) -> libc::c_int;

    /// Collect a group of packets.
    pub fn pcap_dispatch(
        p: pcap_t,
        cnt: libc::c_int,
        callback: pcap_handler,
        user: *const (),
    ) -> libc::c_int;

    /// Return the next available packet.
    pub fn pcap_next(p: pcap_t, h: &mut pcap_pkthdr) -> *const libc::c_uchar;

    /// Return the first valid device in the system.
    #[deprecated(note = "Use pcap_findalldevs and use the first device in the list")]
    pub fn pcap_lookupdev(err_buf: *mut libc::c_char) -> *mut libc::c_char;

    /// Switch between blocking and nonblocking mode.
    pub fn pcap_setnonblock(
        p: pcap_t,
        non_block: libc::c_int,
        err_buf: *mut libc::c_char,
    ) -> libc::c_int;

    /// Get the "non-blocking" state of an interface.
    pub fn pcap_getnonblock(p: pcap_t, err_buf: *mut libc::c_char) -> libc::c_int;

    /// Return the subnet and netmask of an interface.
    pub fn pcap_lookupnet(
        dev: *const libc::c_char,
        netp: u32,
        maskp: u32,
        err_buf: *mut libc::c_char,
    ) -> libc::c_int;

    ///Read a packet from an interface or from an offline capture.
    pub fn pcap_next_ex(
        p: pcap_t,
        pkt_header: *mut *mut pcap_pkthdr,
        pkt_data: *const *const libc::c_char,
    ) -> libc::c_int;

    /// set a flag that will force pcap_dispatch() or pcap_loop() to return rather than looping
    pub fn pcap_breakloop(p: pcap_t);

    /// Send a raw packet.
    pub fn pcap_sendpacket(p: pcap_t, buf: *mut libc::c_uchar, size: libc::c_int) -> libc::c_int;

    ///Save a packet to disk.
    pub fn pcap_dump(user: *mut libc::c_uchar, h: *const pcap_pkthdr, sp: *const libc::c_uchar);

    /// Return the file position for a "savefile".
    /// TODO: *mut T where T: pcap_dumper_t instead of *mut ()
    pub fn pcap_dump_ftell(t: *mut ()) -> libc::c_long;

    /// Free a filter.
    pub fn pcap_freecode(fp: *mut bpf_program);

    /// Return the link layer of an adapter.
    pub fn pcap_datalink(p: pcap_t);

    ///list datalinks
    pub fn pcap_list_datalinks(p: pcap_t, dlt_buf: *mut *mut libc::c_int) -> libc::c_int;

    ///Set the current data link type of the pcap descriptor to the type specified by dlt. -1 is returned on failure.
    pub fn pcap_set_datalink(p: pcap_t, dlt: libc::c_int) -> libc::c_int;

    ///Translates a data link type name, which is a DLT_ name with the DLT_ removed,
    /// to the corresponding data link type value.
    /// The translation is case-insensitive. -1 is returned on failure.
    pub fn pcap_datalink_name_to_val(name: *const libc::c_char) -> libc::c_int;

    ///Translates a data link type value to the corresponding data link type name.
    /// NULL is returned on failure.
    pub fn pcap_datalink_val_to_name(dlt: libc::c_int) -> *const libc::c_char;

    ///Translates a data link type value to a short description of that data link type.
    /// NULL is returned on failure.
    pub fn pcap_datalink_val_to_description(dlt: libc::c_int) -> *const libc::c_char;

    ///Return the dimension of the packet portion (in bytes) that is delivered to the application.
    pub fn pcap_snapshot(p: pcap_t) -> libc::c_int;

    ///returns true if the current savefile uses a different byte order than the current system.
    pub fn pcap_is_swapped(p: pcap_t) -> libc::c_int;

    /// return the major version number of the pcap library used to write the savefile.
    pub fn pcap_major_version(p: pcap_t) -> libc::c_int;

    ///return the minor version number of the pcap library used to write the savefile.
    pub fn pcap_minor_version(p: pcap_t) -> libc::c_int;

    /// Return the standard stream of an offline capture.
    pub fn pcap_file(p: pcap_t) -> *mut libc::FILE;

    /// Return statistics on current capture.
    /// TODO: Add definition of struct pcap_stat.
    pub fn pcap_stats(p: pcap_t, ps: *mut ()) -> libc::c_int;

    ///print the text of the last pcap library error on stderr, prefixed by prefix.
    pub fn pcap_perror(p: pcap_t, prefix: *mut libc::c_char);

    /// return the error text pertaining to the last pcap library error.
    pub fn pcap_geterr(p: pcap_t) -> *mut libc::c_char;

    /// Provided in case strerror() isn't available.
    pub fn pcap_strerror(error: libc::c_int) -> *mut libc::c_char;

    /// return the standard I/O stream of the 'savefile' opened by pcap_dump_open().
    /// TODO: Add definition of struct pcap_dumper_t
    pub fn pcap_dump_file(p: *mut ()) -> *mut libc::FILE;

    /// Flushes the output buffer to the ``savefile,''
    /// so that any packets written with pcap_dump()
    /// but not yet written to the ``savefile'' will be written.
    /// -1 is returned on error, 0 on success.
    /// TODO: Add definition of struct pcap_dumper_t
    pub fn pcap_dump_flush(p: *mut ()) -> libc::c_int;

    ///Closes a savefile.
    /// TODO: Add definition of struct pcap_dumper_t
    pub fn pcap_dump_close(p: *mut ());
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
