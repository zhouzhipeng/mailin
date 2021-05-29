use dnsclientx::{reverse_ip, DNSClient};

use crate::err::{Error, Result};
use std::net::IpAddr;

// TODO: TTL, multiple NS
pub struct BlockList {
    resolver: DNSClient,
    postfix: String,
}

impl BlockList {
    pub fn new(ns: DNSClient, blocklist: &str) -> Self {
        Self {
            resolver: ns,
            postfix: blocklist.to_string(),
        }
    }

    pub async fn lookup_ns(blocklist: &str, resolver: &DNSClient) -> Result<DNSClient> {
        let nameservers = resolver
            .query_ns(blocklist)
            .await
            .map_err(|e| Error::BlockListNameserver(blocklist.to_string(), e))?;
        if nameservers.is_empty() {
            return Ok(resolver.clone());
        }
        for ns in nameservers {
            let ips = resolver.query_a(&ns).await;
            let ips = match ips {
                Err(_) => continue,
                Ok(i) => i,
            };
            if let Some(ip) = ips.first() {
                let socket_addr = (*ip, 53).into();
                return Ok(DNSClient::new(vec![socket_addr]));
            }
        }
        Err(Error::BlockListNameserverIp(blocklist.to_string()))
    }

    pub async fn is_blocked(&self, ip: IpAddr) -> Result<bool> {
        let reversed = reverse_ip(&ip);
        let query_string = format!("{}.{}", reversed, self.postfix);
        let result = self
            .resolver
            .query_a(&query_string)
            .await
            .map_err(|e| Error::BlockListLookup(query_string, e))?;
        Ok(!result.is_empty())
    }
}
