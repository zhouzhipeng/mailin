use resolv_conf::ParseError;
use std::io;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("{0} - bad dns query {1}")]
    DnsQuery(String, #[source] dnssector::Error),
    #[error("{0} - response packet has no answer")]
    EmptyResponse(String),
    #[error("{0} - extract ips")]
    ExtractIps(String, #[source] dnssector::Error),
    #[error("query - udp bind")]
    Bind(#[source] io::Error),
    #[error("query - udp connect to {0}")]
    Connect(String, #[source] io::Error),
    #[error("query - udp send to {0}")]
    Send(String, #[source] io::Error),
    #[error("query - receive dns response from {0}")]
    Recv(String, #[source] io::Error),
    #[error("{0} - cannot parse dns response")]
    ParseResponse(String, #[source] dnssector::Error),
    #[error("{0} - {1} requires TCP which is unsupported")]
    TcpUnsupported(String, String),
    #[error("{0} - parse error")]
    ResolvConfRead(String, #[source] io::Error),
    #[error("{0} - parse error")]
    ResolvConfParse(String, #[source] ParseError),
    #[error("{0} - no nameservers found")]
    NoNameservers(String),
    #[error("{0} - blocklist nameserver lookup failure")]
    BlockListNameserver(String, #[source] Box<Self>),
    #[error("{0} - cannot obtain ips for blocklist nameserver")]
    BlockListNameserverIp(String),
    #[error("{0} - blocklist lookup failure")]
    BlockListLookup(String, #[source] Box<Self>),
}
