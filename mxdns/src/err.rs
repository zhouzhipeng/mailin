use resolv_conf::ParseError;
use std::io;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("{0} - bad dns query {1}")]
    DnsQuery(String, #[source] io::Error),
    #[error("{0} - parse error")]
    ResolvConfRead(String, #[source] io::Error),
    #[error("{0} - parse error")]
    ResolvConfParse(String, #[source] ParseError),
    #[error("{0} - no nameservers found")]
    NoNameservers(String),
    #[error("{0} - blocklist nameserver lookup failure")]
    BlockListNameserver(String, #[source] io::Error),
    #[error("{0} - cannot obtain ips for blocklist nameserver")]
    BlockListNameserverIp(String),
    #[error("{0} - blocklist lookup failure")]
    BlockListLookup(String, #[source] io::Error),
    #[error("{0} - reverse lookup failure")]
    Reverse(String, #[source] io::Error),
}
