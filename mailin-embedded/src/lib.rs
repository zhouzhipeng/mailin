//! A SMTP server that can be embedded into another program
//!
//! This library provides a simple embeddable SMTP server. The
//! server uses blocking IO and a threadpool.
//! # Examples
//! ```no_run
//! use mailin_embedded::{Server, SslConfig, Handler};
//!
//! #[derive(Clone)]
//! struct MyHandler {}
//! impl Handler for MyHandler{}
//!
//! let addr = "127.0.0.1:25";
//! let domain = "example.com".to_owned();
//! let ssl_config = SslConfig::None;
//! let handler = MyHandler {};
//! let mut server = Server::new(handler);
//!
//! server.with_name(domain)
//!    .with_ssl(ssl_config)
//!    .with_addr(addr)
//!    .unwrap();
//! server.serve_forever();
//! ```

mod running;
mod utils;

pub use crate::running::RunningServer;
use failure::format_err;
use failure::Error;
pub use mailin::{AuthMechanism, Handler};
use std::net::{SocketAddr, TcpListener, ToSocketAddrs};

/// `SslConfig` is used to configure the STARTTLS configuration of the server
pub enum SslConfig {
    /// Do not support STARTTLS
    None,
    /// Use a self-signed certificate for STARTTLS
    SelfSigned {
        /// Certificate path
        cert_path: String,
        /// Path to key file
        key_path: String,
    },
    /// Use a certificate from an authority
    Trusted {
        /// Certificate path
        cert_path: String,
        /// Key file path
        key_path: String,
        /// Path to CA bundle
        chain_path: String,
    },
}

/// `Server` is used to configure and start the SMTP server
pub struct Server<H>
where
    H: Handler + Clone + Send + 'static,
{
    handler: H,
    name: String,
    ssl_config: SslConfig,
    num_threads: usize,
    auth: Vec<AuthMechanism>,
    tcp_listener: Option<TcpListener>,
    socket_address: Vec<SocketAddr>,
}

impl<H> Server<H>
where
    H: Handler + Clone + Send + 'static,
{
    /// Create a new server with the given Handler
    pub fn new(handler: H) -> Self {
        Self {
            handler,
            name: "localhost".to_owned(),
            ssl_config: SslConfig::None,
            num_threads: 4,
            auth: Vec::with_capacity(4),
            tcp_listener: None,
            socket_address: Vec::with_capacity(4),
        }
    }

    /// Give the server a name
    pub fn with_name(&mut self, name: String) -> &mut Self {
        self.name = name;
        self
    }

    /// Set the SSL configuration of the server
    pub fn with_ssl(&mut self, ssl_config: SslConfig) -> &mut Self {
        self.ssl_config = ssl_config;
        self
    }

    /// Set the size of the threadpool which is equal to the maximum number of
    /// concurrent SMTP sessions.
    pub fn with_num_threads(&mut self, num_threads: usize) -> &mut Self {
        self.num_threads = num_threads;
        self
    }

    /// Add an authentication mechanism that will supported by the server
    pub fn with_auth(&mut self, auth: AuthMechanism) -> &mut Self {
        self.auth.push(auth);
        self
    }

    /// Set a tcp listener from an already open socket
    pub fn with_tcp_listener(&mut self, listener: TcpListener) -> &mut Self {
        self.tcp_listener = Some(listener);
        self
    }

    /// Add ip addresses and ports to listen on.
    /// Returns an error if the given socket addresses are not valid.
    /// ```
    /// # use mailin_embedded::{Server, Handler};
    /// # #[derive(Clone)]
    /// # struct EmptyHandler {}
    /// # impl Handler for EmptyHandler {}
    /// # let mut server = Server::new(EmptyHandler {});
    /// server.with_addr("127.0.0.1:25").unwrap();
    /// ```
    pub fn with_addr<A: ToSocketAddrs>(&mut self, addr: A) -> Result<&mut Self, Error> {
        for addr in addr.to_socket_addrs()? {
            self.socket_address.push(addr);
        }
        Ok(self)
    }

    /// Start the SMTP server in a background thread
    pub fn serve(self) -> Result<RunningServer, Error> {
        RunningServer::serve(self)
    }

    /// Start the SMTP server and run forever
    pub fn serve_forever(self) -> Result<(), Error> {
        let running = RunningServer::serve(self)?;
        running
            .join
            .join()
            .map_err(|_| format_err!("Error joining server"))
    }
}
