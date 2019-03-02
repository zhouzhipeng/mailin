
# MX DNS

DNS utilities for mail servers. Currently this crate supports reverse DNS lookups
and lookups against dns based blocklists.

## Example

```rust
use mxdns::{MxDns, FCrDNS};

let blocklists = vec!["zen.spamhaus.org.","dnsbl-1.uceprotect.net."];
let mxdns = MxDns::new(blocklists).unwrap();

// Check if an IP Address is present on blocklists
let is_blocked = mxdns.is_blocked([127, 0, 0, 2]).unwrap();
assert!(is_blocked);

// Reverse lookup a DNS address
let rdns = mxdns.reverse_dns([193, 25, 101, 5]).unwrap().unwrap();
assert_eq!(rdns, "mail.alienscience.org.");

// Check that the ip resolved from the name obtained by the reverse dns matches the ip
if let Ok(FCrDNS::Confirmed(_domain)) = mxdns.fcrdns([193, 25, 101, 5]) {
   // _domain is Confirmed
}
```
