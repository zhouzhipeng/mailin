extern crate bufstream;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
extern crate mailin;
extern crate openssl;
extern crate threadpool;

mod running;
mod utils;

use failure::Error;
pub use mailin::{AuthMechanism, Handler};
pub use running::RunningServer;
use std::fmt::Display;
use std::net::ToSocketAddrs;

pub enum SslConfig {
    None,
    SelfSigned {
        cert_path: String,
        key_path: String,
    },
    Trusted {
        cert_path: String,
        key_path: String,
        chain_path: String,
    },
}

pub struct Server<H>
where
    H: Handler + Clone + Send + 'static,
{
    handler: H,
    name: String,
    ssl_config: SslConfig,
    num_threads: usize,
    auth: Vec<AuthMechanism>,
}

impl<H> Server<H>
where
    H: Handler + Clone + Send + 'static,
{
    pub fn new(handler: H) -> Self {
        Self {
            handler,
            name: "localhost".to_owned(),
            ssl_config: SslConfig::None,
            num_threads: 4,
            auth: Vec::with_capacity(4),
        }
    }

    pub fn with_name(&mut self, name: String) -> &mut Self {
        self.name = name;
        self
    }

    pub fn with_ssl(&mut self, ssl_config: SslConfig) -> &mut Self {
        self.ssl_config = ssl_config;
        self
    }

    pub fn with_num_threads(&mut self, num_threads: usize) -> &mut Self {
        self.num_threads = num_threads;
        self
    }

    pub fn with_auth(&mut self, auth: AuthMechanism) -> &mut Self {
        self.auth.push(auth);
        self
    }

    pub fn serve<A: ToSocketAddrs + Display>(self, address: A) -> Result<RunningServer, Error> {
        RunningServer::serve(address, self)
    }

    pub fn serve_forever<A: ToSocketAddrs + Display>(self, address: A) -> Result<(), Error> {
        let running = RunningServer::serve(address, self)?;
        running
            .join
            .join()
            .map_err(|_| format_err!("Error joining server"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct EmptyHandler {}
    impl Handler for EmptyHandler {}

    #[test]
    fn run_server() {
        let server = Server::new(EmptyHandler {});
        let running = server.serve("127.0.0.1:0").unwrap();
        running.stop();
    }

}
