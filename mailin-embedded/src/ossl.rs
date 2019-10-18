use crate::ssl::{Ssl, SslConfig, Stream};
use crate::utils::slurp;
use crate::Error;
use openssl;
use openssl::pkey::PKey;
use openssl::ssl::{SslAcceptor, SslAcceptorBuilder, SslMethod, SslStream};
use openssl::x509::X509;
use std::net::TcpStream;
use std::sync::Arc;

// Openssl wrapper
#[derive(Clone)]
pub struct SslImpl {
    acceptor: Arc<SslAcceptor>,
}

impl Stream for SslStream<TcpStream> {}

impl Ssl for SslImpl {
    fn setup(ssl_config: SslConfig) -> Result<Option<Self>, Error> {
        let builder = match ssl_config {
            SslConfig::Trusted {
                cert_path,
                key_path,
                chain_path,
            } => {
                let mut builder = ssl_builder(cert_path, key_path)?;
                let chain_pem = slurp(chain_path)?;
                let chain = X509::stack_from_pem(&chain_pem)?;
                for cert in chain {
                    builder.add_extra_chain_cert(cert.as_ref().to_owned())?;
                }
                Some(builder)
            }
            SslConfig::SelfSigned {
                cert_path,
                key_path,
            } => {
                let builder = ssl_builder(cert_path, key_path)?;
                Some(builder)
            }
            _ => None,
        };
        let ssl = builder.map(|b| SslImpl {
            acceptor: Arc::new(b.build()),
        });
        Ok(ssl)
    }

    fn accept(&self, stream: TcpStream) -> Result<Box<dyn Stream>, Error> {
        let ret = self
            .acceptor
            .accept(stream)
            .map_err(|e| Error::with_source("Cannot upgrade to TLS", e))?;
        Ok(Box::new(ret))
    }
}

fn ssl_builder(cert_path: String, key_path: String) -> Result<SslAcceptorBuilder, Error> {
    let mut builder = SslAcceptor::mozilla_modern(SslMethod::tls())?;
    let cert_pem = slurp(cert_path)?;
    let cert = X509::from_pem(&cert_pem)?;
    let key_pem = slurp(key_path)?;
    let pkey = PKey::private_key_from_pem(&key_pem)?;
    builder.set_private_key(&pkey)?;
    builder.set_certificate(&cert)?;
    builder.check_private_key()?;
    Ok(builder)
}