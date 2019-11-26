use crate::ssl::SslConfig;
use crate::Error;
use rustls;
use rustls::{
    Certificate, NoClientAuth, PrivateKey, ServerConfig, ServerSession, StreamOwned, TLSError,
};
use std::fs;
use std::io::BufReader;
use std::net::TcpStream;
use std::sync::Arc;

// Rustls wrapper
#[derive(Clone)]
pub struct SslImpl {
    tls_config: Arc<ServerConfig>,
}

pub type SslStream = StreamOwned<ServerSession, TcpStream>;

impl From<TLSError> for Error {
    fn from(error: TLSError) -> Self {
        let msg = format!("{}", error);
        Error::with_source(msg, error)
    }
}

impl SslImpl {
    pub fn setup(ssl_config: SslConfig) -> Result<Option<Self>, Error> {
        let config = match ssl_config {
            SslConfig::Trusted {
                cert_path,
                key_path,
                chain_path,
            } => {
                let mut config = ServerConfig::new(NoClientAuth::new());
                let mut certs = load_certs(&cert_path)?;
                let mut chain = load_certs(&chain_path)?;
                certs.append(&mut chain);
                let key = load_key(&key_path)?;
                config.set_single_cert(certs, key)?;
                Some(config)
            }
            SslConfig::SelfSigned {
                cert_path,
                key_path,
            } => {
                let mut config = ServerConfig::new(NoClientAuth::new());
                let certs = load_certs(&cert_path)?;
                let key = load_key(&key_path)?;
                config.set_single_cert(certs, key)?;
                Some(config)
            }
            _ => None,
        };
        let ret = config.map(|c| SslImpl {
            tls_config: Arc::new(c),
        });
        Ok(ret)
    }

    pub fn accept(&self, stream: TcpStream) -> Result<SslStream, Error> {
        let session = ServerSession::new(&self.tls_config);
        let tls_stream = StreamOwned::new(session, stream);
        Ok(tls_stream)
    }
}

fn load_certs(filename: &str) -> Result<Vec<Certificate>, Error> {
    let certfile = fs::File::open(filename)?;
    let mut reader = BufReader::new(certfile);
    rustls::internal::pemfile::certs(&mut reader)
        .map_err(|_| Error::new("Unparseable certificates"))
}

fn load_key(filename: &str) -> Result<PrivateKey, Error> {
    let keyfile = fs::File::open(filename)?;
    let mut reader = BufReader::new(keyfile);
    let rsa_keys = rustls::internal::pemfile::rsa_private_keys(&mut reader)
        .map_err(|_| Error::new("Unparseable RSA key"))?;

    let keyfile = fs::File::open(filename)?;
    let mut reader = BufReader::new(keyfile);
    let pkcs8_keys = rustls::internal::pemfile::pkcs8_private_keys(&mut reader)
        .map_err(|_| Error::new("Unparseable PKCS8 key"))?;

    // Prefer to load pkcs8 keys
    pkcs8_keys
        .first()
        .or_else(|| rsa_keys.first())
        .map(|k| k.clone())
        .ok_or_else(|| Error::new("No RSA or PKCS8 keys found"))
}
