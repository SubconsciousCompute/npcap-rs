//use serde::{Deserialize, Serialize};

/*
 *
 * Packet { header: Header { id: 59244, query: true, opcode: StandardQuery, authoritative: false, truncated: false, recursion_desired: true, recursion_available: false, authenticated_data: false, checking_disabled: false, response_code: NoError, questions: 1, answers: 0, nameservers: 0, additional: 0 }, questions: [Question { qname: Name("prod-tp.sumo.mozit.cloud"), prefer_unicast: false, qtype: AAAA, qclass: IN }], answers: [], nameservers: [], additional: [], opt: None }
 *
Packet { header: Header { id: 59244, query: false, opcode: StandardQuery, authoritative: false, truncated: false, recursion_desired: true, recursion_available: true, authenticated_data: false, checking_disabled: false, response_code: NoError, questions: 1, answers: 0, nameservers: 1, additional: 0 }, questions: [Question { qname: Name("prod-tp.sumo.mozit.cloud"), prefer_unicast: false, qtype: AAAA, qclass: IN }], answers: [], nameservers: [ResourceRecord { name: Name("sumo.mozit.cloud"), multicast_unique: false, cls: IN, ttl: 600, data: SOA(Record { primary_ns: Name("ns-1513.awsdns-61.org"), mailbox: Name("awsdns-hostmaster.amazon.com"), serial: 1, refresh: 7200, retry: 900, expire: 1209600, minimum_ttl: 86400 }) }], additional: [], opt: None }
 */


//#[derive(Serialize, Deserialize, Debug)]
#[derive(Debug)]
pub struct Question {
    pub name: String,
    pub prefer_unicast: bool,
    pub query_type: dns_parser::QueryType,
}

#[derive(Debug)]
pub struct ResourceRecord {
    pub name: String,
    pub multicast_unique: bool,
    pub ttl: u32,
    pub data: Data,
}

#[derive(Debug)]
pub struct Soa {
    pub primary_ns: String,
    pub mailbox: String,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub min_ttl: u32,
}

#[derive(Debug)]
pub enum Data {
    A(std::net::Ipv4Addr),
    AAAA(String),
    CNAME(String),
    MX(u16, String),
    NS(String),
    PTR(String),
    SOA(Soa),
    SRV(u16, u16, u16, String),
    TXT
    //TXT(Vec<u8>),
}

#[derive(Debug)]
pub struct DNSInfo {
    pub query: bool,
    pub questions: Vec<Question>,
    pub answers: Vec<ResourceRecord>,
    pub nameservers: Vec<ResourceRecord>,
}

pub fn from_packet(packet: &dns_parser::Packet) -> DNSInfo {
    let mut questions: Vec<Question> = Vec::new();
    let mut answers: Vec<ResourceRecord> = Vec::new();
    let mut nameservers: Vec<ResourceRecord> = Vec::new();

    for q in &packet.questions {
        questions.push(Question {
            name: q.qname.to_string(),
            prefer_unicast: q.prefer_unicast,
            query_type: q.qtype,
        });
    }

    for ans in &packet.answers {
        let data = match &ans.data {
            dns_parser::RData::A(a) => Data::A(a.0),
            dns_parser::RData::AAAA(a) => Data::AAAA(a.0.to_string()),
            dns_parser::RData::CNAME(a) => Data::CNAME(a.0.to_string()),
            dns_parser::RData::MX(a) => Data::MX(a.preference, a.exchange.to_string()),
            dns_parser::RData::NS(a) => Data::NS(a.0.to_string()),
            dns_parser::RData::PTR(a) => Data::NS(a.0.to_string()),
            dns_parser::RData::SOA(a) => Data::SOA(Soa {
                primary_ns: a.primary_ns.to_string(),
                mailbox: a.mailbox.to_string(),
                serial: a.serial,
                refresh: a.refresh,
                retry: a.retry,
                expire: a.expire,
                min_ttl: a.minimum_ttl,
            }),
            dns_parser::RData::SRV(a) => Data::SRV(a.priority, a.weight, a.port, a.target.to_string()),
            dns_parser::RData::TXT(a) =>  {
                // idk what to do here honestly
                Data::TXT
            },
            _ => panic!("Eh"),
        };

        answers.push(ResourceRecord {
            data,
            name: ans.name.to_string(),
            multicast_unique: ans.multicast_unique,
            ttl: ans.ttl,
        });
    }


    for nameserver in &packet.nameservers {
        let data = match &nameserver.data {
            dns_parser::RData::A(a) => Data::A(a.0),
            dns_parser::RData::AAAA(a) => Data::AAAA(a.0.to_string()),
            dns_parser::RData::CNAME(a) => Data::CNAME(a.0.to_string()),
            dns_parser::RData::MX(a) => Data::MX(a.preference, a.exchange.to_string()),
            dns_parser::RData::NS(a) => Data::NS(a.0.to_string()),
            dns_parser::RData::PTR(a) => Data::NS(a.0.to_string()),
            dns_parser::RData::SOA(a) => Data::SOA(Soa {
                primary_ns: a.primary_ns.to_string(),
                mailbox: a.mailbox.to_string(),
                serial: a.serial,
                refresh: a.refresh,
                retry: a.retry,
                expire: a.expire,
                min_ttl: a.minimum_ttl,
            }),
            dns_parser::RData::SRV(a) => Data::SRV(a.priority, a.weight, a.port, a.target.to_string()),
            dns_parser::RData::TXT(a) =>  {
                // idk what to do here honestly
                Data::TXT
            },
            _ => panic!("Eh"),
        };

        nameservers.push(ResourceRecord {
            data,
            name: nameserver.name.to_string(),
            multicast_unique: nameserver.multicast_unique,
            ttl: nameserver.ttl,
        });
    }

    DNSInfo {
        questions,
        answers,
        nameservers,
        query: packet.header.query,
    }
}
