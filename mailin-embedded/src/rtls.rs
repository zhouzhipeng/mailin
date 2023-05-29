use crate::ssl::{SslConfig, Stream};
use crate::Error;
use rustls::{
    Certificate, Error as TLSError, PrivateKey, ServerConfig, ServerConnection, StreamOwned,
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

impl Stream for StreamOwned<ServerConnection, TcpStream> {}

impl From<TLSError> for Error {
    fn from(error: TLSError) -> Self {
        let msg = error.to_string();
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
                let mut certs = load_certs(&cert_path)?;
                let mut chain = load_certs(&chain_path)?;
                certs.append(&mut chain);
                let key = load_key(&key_path)?;
                let config = ServerConfig::builder()
                    .with_safe_defaults()
                    .with_no_client_auth()
                    .with_single_cert(certs, key)?;
                Some(config)
            }
            SslConfig::SelfSigned {
                cert_path,
                key_path,
            } => {
                let certs = load_certs(&cert_path)?;
                let key = load_key(&key_path)?;
                let config = ServerConfig::builder()
                    .with_safe_defaults()
                    .with_no_client_auth()
                    .with_single_cert(certs, key)?;
                Some(config)
            }
            _ => None,
        };
        let ret = config.map(|c| SslImpl {
            tls_config: Arc::new(c),
        });
        Ok(ret)
    }

    pub fn accept(&self, stream: TcpStream) -> Result<impl Stream, Error> {
        let session = ServerConnection::new(self.tls_config.clone())?;
        let tls_stream = StreamOwned::new(session, stream);
        Ok(tls_stream)
    }
}

fn load_certs(filename: &str) -> Result<Vec<Certificate>, Error> {
    let certfile = fs::File::open(filename)?;
    let mut reader = BufReader::new(certfile);
    let ret: Vec<Certificate> = rustls_pemfile::certs(&mut reader)
        .map_err(|_| Error::new("Unparseable certificates"))?
        .into_iter()
        .map(Certificate)
        .collect();
    Ok(ret)
}

fn load_key(filename: &str) -> Result<PrivateKey, Error> {
    let keyfile = fs::File::open(filename)?;
    let mut reader = BufReader::new(keyfile);
    let rsa_keys = rustls_pemfile::rsa_private_keys(&mut reader)
        .map_err(|_| Error::new("Unparseable RSA key"))?;
    let keyfile = fs::File::open(filename)?;
    let mut reader = BufReader::new(keyfile);
    let pkcs8_keys = rustls_pemfile::pkcs8_private_keys(&mut reader)
        .map_err(|_| Error::new("Unparseable PKCS8 key"))?;

    // Prefer to load pkcs8 keys
    pkcs8_keys
        .first()
        .or_else(|| rsa_keys.first())
        .cloned()
        .map(PrivateKey)
        .ok_or_else(|| Error::new("No RSA or PKCS8 keys found"))
}
