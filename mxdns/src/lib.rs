//! DNS utilities for email servers.
//!
//! Currently, DNS based blocklists and reverse DNS lookups are supported.
//! The crate also supports forward confirmed reverse dns checks.
//!
//! # Examples
//! ```no_run
//! use mxdns::MxDns;
//!
//! let blocklists = vec!["zen.spamhaus.org.","dnsbl-1.uceprotect.net."];
//! let mxdns = MxDns::new(blocklists).unwrap();
//!
//! // Check if an IP Address is present on blocklists
//! let is_blocked = mxdns.is_blocked([127, 0, 0, 2]).unwrap();
//! assert!(is_blocked);
//!
//! // Reverse lookup a DNS address
//! let rdns = mxdns.reverse_dns([193, 25, 101, 5]).unwrap().unwrap();
//! assert_eq!(rdns, "mail.alienscience.org.");
//!
//! // Check that the ip resolved from the name obtained by the reverse dns matches the ip
//! assert!(mxdns.fcrdns([193, 25, 101, 5]).unwrap());
//! ```

mod err;

use crate::err::Error;
use resolv_conf;
use std::fs::File;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::str::FromStr;
use tokio::prelude::Future;
use tokio::runtime::current_thread::Runtime;
use trust_dns::client::{BasicClientHandle, ClientFuture, ClientHandle};
use trust_dns::proto::xfer::DnsMultiplexerSerialResponse;
use trust_dns::rr::{DNSClass, Name, RData, RecordType};
use trust_dns::udp::UdpClientStream;

const RESOLV_CONF: &str = "/etc/resolv.conf";

/// Utilities for looking up IP addresses on blocklists and doing reverse DNS
#[derive(Clone)]
pub struct MxDns {
    bootstrap: SocketAddr,
    blocklists: Vec<String>,
}

impl MxDns {
    /// Create a MxDns using the system provided nameserver config
    pub fn new<S>(blocklists_fqdn: S) -> Result<Self, Error>
    where
        S: IntoIterator,
        S::Item: Into<String>,
    {
        let mut buf = Vec::with_capacity(256);
        let mut file = File::open(RESOLV_CONF)?;
        file.read_to_end(&mut buf)?;
        let conf = resolv_conf::Config::parse(&buf)?;
        let nameservers = conf.get_nameservers_or_local();
        if let Some(ip) = nameservers.first() {
            let ip_addr: IpAddr = ip.into();
            Ok(Self::with_dns(ip_addr, blocklists_fqdn))
        } else {
            Err(Error::new(format!(
                "No nameservers found in {}",
                RESOLV_CONF
            )))
        }
    }

    /// Create a MxDns that uses the given DNS server for standard queries.
    pub fn with_dns<I, S>(bootstrap_dns: I, blocklists_fqdn: S) -> Self
    where
        I: Into<IpAddr>,
        S: IntoIterator,
        S::Item: Into<String>,
    {
        let ip = bootstrap_dns.into();
        let bootstrap = SocketAddr::new(ip, 53);
        let blocklists: Vec<String> = blocklists_fqdn.into_iter().map(|i| i.into()).collect();
        Self {
            bootstrap,
            blocklists,
        }
    }

    /// Queries blocklists for the given address
    /// Returns a vector where each entry indicates if the address is on the blocklist
    pub fn on_blocklists<A>(&self, addr: A) -> Vec<Result<bool, Error>>
    where
        A: Into<IpAddr>,
    {
        // Convert the address into a query for each blocklist
        let ip = addr.into();
        let ip = match to_ipv4(ip) {
            Ok(i) => i,
            Err(e) => return vec![Err(e)],
        };
        let query_fqdns = self
            .blocklists
            .iter()
            .map(|b| format_ipv4(&ip, &b))
            .collect::<Vec<String>>();

        // Spawn a task to make DNS queries to the bootstrap nameserver
        let (bootstrap_task, bootstrap_client) = connect_client(self.bootstrap);
        let mut runtime = Runtime::new().unwrap();
        runtime.spawn(bootstrap_task);

        // Get the nameservers to query for each blocklist
        let blocklist_addrs = self.blocklist_addrs(&mut runtime, bootstrap_client.clone());

        // Query each blocklist
        let mut is_blocked_futures = Vec::with_capacity(blocklist_addrs.len());
        for i in 0..blocklist_addrs.len() {
            let blocklist_client = if let Some(blocklist_ip) = blocklist_addrs[i] {
                let (blocklist_task, client) = connect_client(blocklist_ip);
                runtime.spawn(blocklist_task);
                client
            } else {
                bootstrap_client.clone()
            };
            let fut = lookup_ip(blocklist_client.clone(), &query_fqdns[i]).map(|ip| ip.is_some());
            is_blocked_futures.push(fut);
        }

        let mut ret = Vec::with_capacity(is_blocked_futures.len());
        for fut in is_blocked_futures {
            let res = runtime.block_on(fut).map_err(|err| err.into());
            ret.push(res);
        }
        ret
    }

    // Find the nameservers for each blocklist that can be directly queried for blocklist results
    fn blocklist_addrs(
        &self,
        runtime: &mut Runtime,
        client: BasicClientHandle<DnsMultiplexerSerialResponse>,
    ) -> Vec<Option<SocketAddr>> {
        let blocklist_addr_futures = self.blocklists.iter().map(|b| {
            lookup_ns(client.clone(), b)
                .and_then(|maybe_ns| maybe_ns.map(|ns| lookup_ip(client.clone(), &ns)))
                .map(|res| res.and_then(|maybe_ip| maybe_ip.map(|ip| SocketAddr::new(ip, 53))))
        });
        let mut ret = Vec::with_capacity(self.blocklists.len());
        for fut in blocklist_addr_futures {
            let blocklist_addr = runtime.block_on(fut).unwrap_or(None);
            ret.push(blocklist_addr);
        }
        ret
    }

    /// Returns true if the address is on any of the blocklists
    pub fn is_blocked<A>(&self, addr: A) -> Result<bool, Error>
    where
        A: Into<IpAddr>,
    {
        let mut res = self.on_blocklists(addr);
        if !res.is_empty() && res.iter().all(|r| r.is_err()) {
            res.pop().unwrap()
        } else {
            Ok(res.into_iter().any(|r| r.unwrap_or(false)))
        }
    }

    /// Does a reverse DNS lookup on the given ip address
    pub fn reverse_dns<A>(&self, ip: A) -> Result<Option<String>, Error>
    where
        A: Into<IpAddr>,
    {
        let ip = ip.into();
        let ip = to_ipv4(ip)?;
        let query = format_ipv4(&ip, "in-addr.arpa");
        let mut runtime = Runtime::new().unwrap();
        let (task, mut client) = connect_client(self.bootstrap);
        runtime.spawn(task);
        let rdns = lookup_ptr(&mut client, &query);
        runtime
            .block_on(rdns)
            .map(|o| o.map(|name| name.to_utf8()))
            .map_err(|err| err.into())
    }

    /// Does a Forward Confirmed Reverse DNS check on the given ip address
    /// This checks that the reverse lookup on the ip address gives a domain
    /// name that will resolve to the original ip address.
    pub fn fcrdns<A>(&self, ip: A) -> Result<bool, Error>
    where
        A: Into<IpAddr>,
    {
        let ipaddr = ip.into();
        let fqdn = match self.reverse_dns(ipaddr.clone())? {
            None => return Ok(false),
            Some(s) => s,
        };
        let (task, client) = connect_client(self.bootstrap);
        let mut runtime = Runtime::new().unwrap();
        runtime.spawn(task);
        let confirmed = lookup_ip(client, &fqdn);
        runtime
            .block_on(confirmed)
            .map(|maybe_ip| maybe_ip.filter(|c| c == &ipaddr).is_some())
    }
}

// Lookup the nameserver that handles the given fqdn
fn lookup_ns(
    mut client: BasicClientHandle<DnsMultiplexerSerialResponse>,
    fqdn: &str,
) -> impl Future<Item = Option<String>, Error = Error> {
    let name = Name::from_str(fqdn).unwrap(); // TODO: remove unwrap
    let query = client.query(name, DNSClass::IN, RecordType::NS);
    query
        .map(|response| {
            let answer = response.answers();
            answer.first().and_then(|r| {
                if let RData::NS(ns) = r.rdata() {
                    Some(ns.to_utf8())
                } else {
                    None
                }
            })
        })
        .map_err(|e| e.into())
}

// Lookup the IP address for a given fqdn
fn lookup_ip(
    mut client: BasicClientHandle<DnsMultiplexerSerialResponse>,
    fqdn: &str,
) -> impl Future<Item = Option<IpAddr>, Error = Error> {
    let name = Name::from_str(fqdn).unwrap(); // TODO: remove unwrap
    let query = client.query(name, DNSClass::IN, RecordType::A);
    query
        .map(|response| {
            let answer = response.answers();
            answer.first().and_then(|record| match record.rdata() {
                RData::A(ip) => Some(IpAddr::V4(ip.clone())),
                _ => None,
            })
        })
        .map_err(|e| e.into())
}

// Reverse lookup using the given inaddr-arpa fqdn
fn lookup_ptr(
    client: &mut BasicClientHandle<DnsMultiplexerSerialResponse>,
    fqdn: &str,
) -> impl Future<Item = Option<Name>, Error = Error> {
    let name = Name::from_str(fqdn).unwrap(); // TODO: remove unwrap
    let query = client.query(name, DNSClass::IN, RecordType::PTR);
    query
        .map(|response| {
            let answer = response.answers();
            answer.first().and_then(|record| match record.rdata() {
                RData::PTR(ptr) => Some(ptr.clone()),
                _ => None,
            })
        })
        .map_err(|e| e.into())
}

// Connect to the given dns server asynchronously
fn connect_client<A>(
    dns_addr: A,
) -> (
    impl Future<Item = (), Error = ()>,
    BasicClientHandle<DnsMultiplexerSerialResponse>,
)
where
    A: ToSocketAddrs,
{
    let mut addrs = dns_addr.to_socket_addrs().unwrap();
    let sock_addr = addrs.next().unwrap();
    let (stream, handle) = UdpClientStream::new(sock_addr);
    ClientFuture::new(stream, handle, None)
}

// Format an IPv4 address for a blocklist or reverse dns lookup
fn format_ipv4(ip: &Ipv4Addr, postfix: &str) -> String {
    let octets = ip.octets();
    format!(
        "{}.{}.{}.{}.{}",
        octets[3], octets[2], octets[1], octets[0], postfix
    )
}

// Convert an ip address into a Ipv4Addr
fn to_ipv4(ip: IpAddr) -> Result<Ipv4Addr, Error> {
    match ip {
        IpAddr::V4(ipv4) => Ok(ipv4),
        IpAddr::V6(ipv6) => ipv6
            .to_ipv4()
            .ok_or_else(|| Error::new("Cannot convert Ipv6 address to Ipv4 address")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use matches::matches;

    fn blocklists() -> Vec<(&'static str, bool)> {
        // Tuples are (fqdn, has_nameserver)
        vec![
            ("zen.spamhaus.org.", true),
            ("dnsrbl.org.", true),
            ("bl.spamcop.net.", false),
            ("dnsbl-1.uceprotect.net.", true),
            ("pbsl.surriel.com.", false),
        ]
    }

    fn build_mx_dns() -> MxDns {
        let bootstrap: IpAddr = "8.8.8.8".parse().unwrap();
        let blocklists = blocklists()
            .iter()
            .map(|t| t.0)
            .collect::<Vec<&'static str>>();
        MxDns::with_dns(bootstrap, blocklists)
    }

    #[test]
    fn empty_blocklists() {
        let bootstrap: IpAddr = "8.8.8.8".parse().unwrap();
        let empty: Vec<String> = Vec::new();
        let mxdns = MxDns::with_dns(bootstrap, empty);
        let blocked = mxdns.is_blocked(Ipv4Addr::new(127, 0, 0, 2)).unwrap();
        assert_eq!(blocked, false);
    }

    #[cfg_attr(feature = "no-network-tests", ignore)]
    #[test]
    fn blocklist_addrs() {
        let mxdns = build_mx_dns();
        let (bootstrap_task, bootstrap_client) = connect_client("8.8.8.8:53");
        let mut runtime = Runtime::new().unwrap();
        runtime.spawn(bootstrap_task);
        let addrs = mxdns.blocklist_addrs(&mut runtime, bootstrap_client);
        let blocklists = blocklists();
        for i in 0..blocklists.len() {
            let b = blocklists[i];
            if b.1 {
                assert!(matches!(addrs[i], Some(_)), "no NS for {}", b.0);
            } else {
                assert!(matches!(addrs[i], None), "unexpected NS for {}", b.0);
            }
        }
    }

    #[cfg_attr(feature = "no-network-tests", ignore)]
    #[test]
    fn not_blocked() {
        let mxdns = build_mx_dns();
        let blocked = mxdns.is_blocked([127, 0, 0, 1]).unwrap();
        assert_eq!(blocked, false);
    }

    #[cfg_attr(feature = "no-network-tests", ignore)]
    #[test]
    fn blocked() {
        let mxdns = build_mx_dns();
        let blocked = mxdns.is_blocked([127, 0, 0, 2]).unwrap();
        assert_eq!(blocked, true);
    }

    #[cfg_attr(feature = "no-network-tests", ignore)]
    #[test]
    fn pbl_blocked() {
        let mxdns = build_mx_dns();
        // Check an address known to be blocked by the spamhaus PBL
        let addr = "217.255.183.36".parse::<IpAddr>().unwrap();
        let blocked = mxdns.on_blocklists(addr);
        assert_eq!(blocked[0].as_ref().unwrap(), &true);
    }

    #[cfg_attr(feature = "no-network-tests", ignore)]
    #[test]
    fn reverse_lookup() {
        let mxdns = build_mx_dns();
        let addr = "88.198.127.200".parse::<IpAddr>().unwrap();
        let reverse = mxdns.reverse_dns(addr).unwrap().unwrap();
        assert_eq!(reverse, "mail.alienscience.org.uk.");
    }

    #[cfg_attr(feature = "no-network-tests", ignore)]
    #[test]
    fn fcrdns_ok() {
        let mxdns = build_mx_dns();
        assert!(mxdns.fcrdns([88, 198, 127, 200]).unwrap());
    }

    #[cfg_attr(feature = "no-network-tests", ignore)]
    #[test]
    fn fcrdns_fail() {
        let mxdns = build_mx_dns();
        // 127.0.0.2 -> localhost -> 127.0.0.1
        assert!(!mxdns.fcrdns([127, 0, 0, 2]).unwrap());
    }

}
