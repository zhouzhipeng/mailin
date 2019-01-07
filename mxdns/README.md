
# MX DNS

DNS utilities for mail servers. Currently this crate supports reverse DNS lookups
and lookups against dns based blocklists.

## Example

```rust
use mxdns::MxDns;
use std::net::Ipv4Addr;

// Use Google DNS servers to lookup DNS blocklist servers and for reverse DNS
let google_dns = "8.8.8.8:53";
let blocklists = vec!["zen.spamhaus.org.","dnsbl-1.uceprotect.net."];
let mxdns = MxDns::new(google_dns, blocklists).unwrap();

// Check if an IP Address is present on blocklists
let is_blocked = mxdns.is_blocked(Ipv4Addr::new(127, 0, 0, 2)).unwrap();
assert!(is_blocked);

// Reverse lookup a DNS address
let rdns = mxdns.reverse_dns(Ipv4Addr::new(193, 25, 101, 5)).unwrap().unwrap();
assert_eq!(rdns, "mail.alienscience.org.");
```
