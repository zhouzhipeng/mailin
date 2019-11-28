//! A SMTP server that can be embedded into another program
//!
//! This library provides a simple embeddable SMTP server. The
//! server uses blocking IO and a threadpool.
//! # Examples
//! ```rust,no_run
//! use mailin_embedded::{Server, SslConfig, State, Error};
//! # use std::sync::Arc;
//!
//! let server = Server::new();
//! server
//!    .with_name("example.com")
//!    .with_ssl(SslConfig::None)?
//!    .with_addr("127.0.0.1:25")?
//!    .serve(Arc::new(|session| {
//!         let mut counter = 0;
//!         session.handle(|state| {
//!              counter += 1;
//!              match state {
//!                  State::Hello(hello) if (hello.domain == "spam.com") => {
//!                      hello.deny("Bad domain")
//!                  }
//!                  state => state.ok(),
//!              }
//!         });
//!    }));
//! # Ok::<(), Error>(())
//! ```

#![forbid(unsafe_code)]
// #![forbid(missing_docs)]

/// Custom error type for mailin_embedded
pub mod err;

#[cfg(feature = "ossl")]
mod ossl;
#[cfg(feature = "default")]
mod rtls;
mod running;
mod session;
mod ssl;

pub use crate::err::Error;
#[cfg(feature = "ossl")]
use crate::ossl::SslImpl;
#[cfg(feature = "default")]
use crate::rtls::SslImpl;
pub use crate::session::Session;
pub use crate::ssl::SslConfig;
pub use mailin::AuthMechanism;
pub use mailin::State;
use std::net::{SocketAddr, TcpListener, ToSocketAddrs};
use std::sync::Arc;

pub type HandlerFn = Arc<dyn Fn(&mut Session) + Send + Sync>;

/// `Server` is used to configure and start the SMTP server
pub struct Server {
    name: String,
    ssl: Option<SslImpl>,
    num_threads: u32,
    auth: Vec<AuthMechanism>,
    tcp_listener: Option<TcpListener>,
    socket_address: Vec<SocketAddr>,
}

impl Server {
    /// Create a new server
    pub fn new() -> Self {
        Self {
            name: "localhost".to_owned(),
            ssl: None,
            num_threads: 4,
            auth: Vec::with_capacity(4),
            tcp_listener: None,
            socket_address: Vec::with_capacity(4),
        }
    }

    /// Give the server a name
    pub fn with_name<T>(&mut self, name: T) -> &mut Self
    where
        T: Into<String>,
    {
        self.name = name.into();
        self
    }

    /// Set the SSL configuration of the server
    pub fn with_ssl(&mut self, ssl_config: SslConfig) -> Result<&mut Self, Error> {
        self.ssl = SslImpl::setup(ssl_config)?;
        Ok(self)
    }

    /// Set the size of the threadpool which is equal to the maximum number of
    /// concurrent SMTP sessions.
    pub fn with_num_threads(&mut self, num_threads: u32) -> &mut Self {
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
    /// # use mailin_embedded::Server;
    /// # use mailin_embedded::err::Error;
    /// # #[derive(Clone)]
    /// # let mut server = Server::new();
    /// # server.with_name("doc");
    /// server.with_addr("127.0.0.1:25")?;
    /// # Ok::<(), Error>(())
    /// ```
    pub fn with_addr<A: ToSocketAddrs>(&mut self, addr: A) -> Result<&mut Self, Error> {
        for addr in addr
            .to_socket_addrs()
            .map_err(|e| Error::with_source("Invalid socket address", e))?
        {
            self.socket_address.push(addr);
        }
        Ok(self)
    }

    /// Start the SMTP server and run forever
    pub fn serve<F>(self, handler: HandlerFn) -> Result<(), Error> {
        running::serve(self, handler)
    }
}
