use resolv_conf::ParseError;
use std::io;

/// Result type that supports mxdns errors.
pub type Result<T> = std::result::Result<T, Error>;

/// Possible mxdns errors
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// The DNS server responded that was an error with the DNS query.
    #[error("{0} - bad dns query {1}")]
    DnsQuery(String, #[source] io::Error),
    /// There was an error reading the local resolv.conf
    #[error("{0} - read error")]
    ResolvConfRead(String, #[source] io::Error),
    /// There was an error parsing the local resolv.conf
    #[error("{0} - parse error")]
    ResolvConfParse(String, #[source] ParseError),
    /// There are no nameservers configured.
    #[error("{0} - no nameservers found")]
    NoNameservers(String),
    /// We were not able to find the nameserver that serves the blocklists.
    #[error("{0} - blocklist nameserver lookup failure")]
    BlockListNameserver(String, #[source] io::Error),
    /// It was not possible to extract the ip addresses of the blocklist nameserver.
    #[error("{0} - cannot obtain ips for blocklist nameserver")]
    BlockListNameserverIp(String),
    /// When querying the blocklist there was a lookup failure.
    #[error("{0} - blocklist lookup failure")]
    BlockListLookup(String, #[source] io::Error),
    /// The was a DNS error when performing a reverse lookup.
    #[error("{0} - reverse lookup failure")]
    Reverse(String, #[source] io::Error),
}
