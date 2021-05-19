use crate::{
    err::{Error, Result},
    resolve::{reverse_ip, Resolve, DEFAULT_TIMEOUT},
};
use std::net::IpAddr;

// TODO: TTL, multiple NS
pub struct BlockList {
    resolver: Resolve,
    postfix: String,
}

impl BlockList {
    pub fn new(ns: Resolve, blocklist: &str) -> Self {
        Self {
            resolver: ns,
            postfix: blocklist.to_string(),
        }
    }

    pub async fn lookup_ns(blocklist: &str, resolver: &Resolve) -> Result<Resolve> {
        let nameservers = resolver
            .query_ns(blocklist.as_bytes())
            .await
            .map_err(|e| Error::BlockListNameserver(blocklist.to_string(), Box::new(e)))?;
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
                return Ok(Resolve::new(*ip, DEFAULT_TIMEOUT));
            }
        }
        Err(Error::BlockListNameserverIp(blocklist.to_string()))
    }

    pub async fn is_blocked(&self, ip: IpAddr) -> Result<bool> {
        let reversed = reverse_ip(&ip);
        let query_string = format!("{}.{}", reversed, self.postfix);
        let query = query_string.as_bytes().to_vec();
        let result = self
            .resolver
            .query_a(&query)
            .await
            .map_err(|e| Error::BlockListLookup(query_string, Box::new(e)))?;
        Ok(!result.is_empty())
    }
}
