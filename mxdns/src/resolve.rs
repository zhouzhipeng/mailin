use crate::err::{Error, Result};
use dnssector::{
    constants::{Class, Type, DNS_MAX_COMPRESSED_SIZE},
    Compress, DNSIterable, DNSSector, ParsedPacket, RdataIterable, DNS_FLAG_TC, DNS_RR_HEADER_SIZE,
};
use smol::{future::FutureExt, net::UdpSocket, Timer};
use std::{
    io::{self, ErrorKind::TimedOut},
    net::{IpAddr, SocketAddr},
    time::Duration,
};

pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(2);
const DNS_PORT: u16 = 53;
const SOURCE_ADDR: &str = "0.0.0.0:0";

#[derive(Clone)]
pub struct Resolve {
    dns_server: SocketAddr,
    timeout: Duration,
}

impl Resolve {
    pub fn new<T: Into<IpAddr>>(dns_server_ip: T, timeout: Duration) -> Self {
        let addr = SocketAddr::new(dns_server_ip.into(), DNS_PORT);
        Self {
            dns_server: addr,
            timeout,
        }
    }

    pub async fn query_a(&self, name: &[u8]) -> Result<Vec<IpAddr>> {
        let query = dnssector::gen::query(name, Type::A, Class::IN)
            .map_err(|e| Error::DnsQuery(query_string(name), e))?;
        let response = self.query(query, name).await?;
        extract_ips(response, name)
    }

    pub async fn query_aaaa(&self, name: &[u8]) -> Result<Vec<IpAddr>> {
        let query = dnssector::gen::query(name, Type::AAAA, Class::IN)
            .map_err(|e| Error::DnsQuery(query_string(name), e))?;
        let response = self.query(query, name).await?;
        extract_ips(response, name)
    }

    pub async fn query_ptr(&self, ip: IpAddr) -> Result<Vec<u8>> {
        let in_addr = reverse_dns_query(ip);
        let query = dnssector::gen::query(&in_addr, Type::PTR, Class::IN)
            .map_err(|e| Error::DnsQuery(query_string(&in_addr), e))?;
        let response = self.query(query, &in_addr).await?;
        extract_names(response, &in_addr).map(|mut v| v.remove(0))
    }

    pub async fn query_ns(&self, domain: &[u8]) -> Result<Vec<Vec<u8>>> {
        let query = dnssector::gen::query(domain, Type::NS, Class::IN)
            .map_err(|e| Error::DnsQuery(query_string(domain), e))?;
        let response = self.query(query, domain).await?;
        extract_names(response, domain)
    }

    async fn query(&self, packet: ParsedPacket, name: &[u8]) -> Result<ParsedPacket> {
        let is_compressed = match packet.qtype_qclass() {
            Some((rr_type, __)) if rr_type == Type::NS as u16 => true,
            _ => false,
        };
        let raw_packet = packet.into_packet();
        let mut raw_response = self.query_raw_udp(&raw_packet).await?;
        if is_compressed {
            raw_response = Compress::uncompress(&raw_response)
                .map_err(|e| Error::ParseResponse(query_string(name), e))?;
        }
        let response = DNSSector::new(raw_response)
            .map_err(|e| Error::ParseResponse(query_string(name), e))?
            .parse()
            .map_err(|e| Error::ParseResponse(query_string(name), e))?;
        if response.flags() & DNS_FLAG_TC == DNS_FLAG_TC {
            return Err(Error::TcpUnsupported(
                query_string(name),
                self.dns_server.to_string(),
            ));
        }
        Ok(response)
    }

    async fn query_raw_udp(&self, packet: &[u8]) -> Result<Vec<u8>> {
        let socket = UdpSocket::bind(SOURCE_ADDR).await.map_err(Error::Bind)?;
        socket
            .connect(self.dns_server)
            .await
            .map_err(|e| Error::Connect(self.dns_server.to_string(), e))?;
        socket
            .send(&packet)
            .await
            .map_err(|e| Error::Send(self.dns_server.to_string(), e))?;
        let mut response = vec![0; DNS_MAX_COMPRESSED_SIZE];
        let len = socket
            .recv(&mut response)
            .or(self.timeout())
            .await
            .map_err(|e| Error::Recv(self.dns_server.to_string(), e))?;
        response.truncate(len);
        Ok(response)
    }

    async fn timeout(&self) -> io::Result<usize> {
        Timer::after(self.timeout).await;
        Err(TimedOut.into())
    }
}

// Reverse an IP address
pub fn reverse_ip(ip: &IpAddr) -> String {
    match ip {
        IpAddr::V4(i4) => {
            let octets = i4.octets();
            format!("{}.{}.{}.{}", octets[3], octets[2], octets[1], octets[0])
        }
        IpAddr::V6(i6) => {
            let nibbles: Vec<_> = i6
                .octets()
                .iter()
                .flat_map(|b| byte_to_nibbles(*b))
                .rev()
                .map(|n| n.to_string())
                .collect();
            nibbles.join(".")
        }
    }
}

fn extract_ips(mut packet: ParsedPacket, query_name: &[u8]) -> Result<Vec<IpAddr>> {
    use std::result::Result as StdResult;

    let mut ips = Vec::new();
    let mut response = packet.into_iter_answer();
    while let Some(i) = response {
        ips.push(i.rr_ip());
        response = i.next();
    }
    let (ips, errors): (Vec<_>, Vec<_>) = ips.into_iter().partition(StdResult::is_ok);
    if ips.is_empty() {
        if let Some(Err(e)) = errors.into_iter().nth(0) {
            let query = String::from_utf8_lossy(query_name).to_string();
            return Err(Error::ExtractIps(query, e));
        }
    }
    let ips: Vec<_> = ips.into_iter().map(StdResult::unwrap).collect();
    Ok(ips)
}

fn extract_names(mut packet: ParsedPacket, query_name: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut response = packet.into_iter_answer();
    let mut ret = Vec::new();
    while let Some(i) = response {
        let raw_name = &i.rdata_slice()[DNS_RR_HEADER_SIZE..];
        let name = parse_tlv_name(&raw_name);
        ret.push(name);
        response = i.next();
    }
    if ret.is_empty() {
        return Err(Error::EmptyResponse(query_string(query_name)));
    }
    Ok(ret)
}

fn query_string(query: &[u8]) -> String {
    String::from_utf8_lossy(query).to_string()
}

fn reverse_dns_query(ip: IpAddr) -> Vec<u8> {
    let prefix = reverse_ip(&ip);
    match ip {
        IpAddr::V4(_) => format!("{}.in-addr.arpa", prefix).into_bytes(),
        IpAddr::V6(_) => format!("{}.ip6.arpa", prefix).into_bytes(),
    }
}

fn byte_to_nibbles(b: u8) -> Vec<u8> {
    let hn = (b & 0xf0) >> 4;
    let ln = b & 0x0f;
    vec![hn, ln]
}

fn parse_tlv_name(raw: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(raw.len());
    let mut i = 0;
    let mut remaining = 0;
    while i < raw.len() && raw[i] != 0 {
        if remaining == 0 {
            remaining = raw[i];
            if i > 0 {
                result.push(b'.')
            }
        } else {
            result.push(raw[i]);
            remaining -= 1;
        }
        i += 1;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use display_bytes::display_bytes;
    use std::{
        matches,
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
    };

    const DNS_SERVER: IpAddr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
    const TIMEOUT: Duration = Duration::from_secs(2);
    const EXAMPLE_SERVER: &[u8] = b"mail.alienscience.org";
    const EXAMPLE_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(116, 203, 10, 186));
    const EXAMPLE_IPV6_SERVER: &[u8] = b"dns.google";
    const EXAMPLE_IPV6_IP: IpAddr =
        IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888));

    #[test]
    fn query_a() {
        let resolve = Resolve::new(DNS_SERVER, TIMEOUT);
        let addresses = smol::block_on(async { resolve.query_a(EXAMPLE_SERVER).await.unwrap() });
        let found = addresses.into_iter().any(|ip| ip == EXAMPLE_IP);
        assert!(
            found,
            "{} did not resolve to {}",
            display_bytes(EXAMPLE_SERVER),
            EXAMPLE_IP
        );
    }

    #[test]
    fn query_aaaa() {
        let resolve = Resolve::new(DNS_SERVER, TIMEOUT);
        let addresses =
            smol::block_on(async { resolve.query_aaaa(EXAMPLE_IPV6_SERVER).await.unwrap() });
        let found = addresses.iter().any(|ip| *ip == EXAMPLE_IPV6_IP);
        assert!(
            found,
            "{} resolved to {:?} expected {}",
            display_bytes(EXAMPLE_IPV6_SERVER),
            addresses,
            EXAMPLE_IPV6_IP
        );
    }

    #[test]
    fn query_cname() {
        const EXAMPLE_CNAME: &[u8] = b"www.alienscience.org";
        const EXAMPLE_CNAME_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(116, 203, 10, 186));
        let resolve = Resolve::new(DNS_SERVER, TIMEOUT);
        let addresses = smol::block_on(async { resolve.query_a(EXAMPLE_CNAME).await.unwrap() });
        let found = addresses.into_iter().any(|ip| ip == EXAMPLE_CNAME_IP);
        assert!(
            found,
            "{} did not resolve to {}",
            display_bytes(EXAMPLE_CNAME),
            EXAMPLE_CNAME_IP
        );
    }

    #[test]
    fn query_timeout() {
        let resolve = Resolve::new(DNS_SERVER, Duration::from_micros(1));
        let res = smol::block_on(async { resolve.query_a(EXAMPLE_SERVER).await });
        assert!(
            matches!(&res, Err(Error::Recv(_, err)) if err.kind() == TimedOut),
            "Unexpected result {:?}",
            res
        );
    }

    #[test]
    fn query_ptr_ipv4() {
        let resolve = Resolve::new(DNS_SERVER, TIMEOUT);
        let name = smol::block_on(async { resolve.query_ptr(EXAMPLE_IP).await.unwrap() });
        assert!(
            name == EXAMPLE_SERVER,
            "{} resolved to {:?} but expected {}",
            EXAMPLE_IP,
            &name,
            display_bytes(EXAMPLE_SERVER)
        );
    }

    #[test]
    fn query_ptr_ipv6() {
        let resolve = Resolve::new(DNS_SERVER, TIMEOUT);
        let name = smol::block_on(async { resolve.query_ptr(EXAMPLE_IPV6_IP).await.unwrap() });
        assert!(
            name == EXAMPLE_IPV6_SERVER,
            "{} resolved to {:?} but expected {}",
            EXAMPLE_IPV6_IP,
            &name,
            display_bytes(EXAMPLE_IPV6_SERVER)
        );
    }

    #[test]
    fn query_ns() {
        const EXAMPLE_DOMAIN: &[u8] = b"alienscience.org";
        const EXAMPLE_NS: &[u8] = b"ns1.tsodns.com";
        let resolve = Resolve::new(DNS_SERVER, TIMEOUT);
        let ns_servers = smol::block_on(async { resolve.query_ns(EXAMPLE_DOMAIN).await.unwrap() });
        let found = ns_servers.iter().any(|ns| ns == EXAMPLE_NS);
        assert!(
            found,
            "{} ns resolved to {}, expected {}",
            display_bytes(EXAMPLE_DOMAIN),
            display_bytes(&ns_servers[0]),
            display_bytes(EXAMPLE_NS)
        );
    }
}
