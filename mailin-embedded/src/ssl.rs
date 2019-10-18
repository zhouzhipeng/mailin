use crate::Error;
use std::io::{Read, Write};
use std::net::TcpStream;

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

pub trait Stream: Read + Write {}

pub trait Ssl: Sized + Clone {
    fn setup(ssl_config: SslConfig) -> Result<Option<Self>, Error>;
    fn accept(&self, stream: TcpStream) -> Result<Box<dyn Stream>, Error>;
}
