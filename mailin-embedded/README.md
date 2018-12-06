
A SMTP server that can be embedded into another program

This library provides a simple embeddable SMTP server. The
server uses blocking IO and a threadpool.

# Examples
```
use mailin_embedded::{Server, SslConfig, Handler};

#[derive(Clone)]
struct MyHandler {}
impl Handler for MyHandler{}

let addr = "127.0.0.1:25";
let domain = "example.com".to_owned();
let ssl_config = SslConfig::None;
let handler = MyHandler {};
let mut server = Server::new(handler);

server.with_name(domain).with_ssl(ssl_config);
server.serve_forever(addr);
```

