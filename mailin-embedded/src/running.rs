use crate::err::Error;
#[cfg(feature = "ossl")]
use crate::ossl::SslImpl;
#[cfg(feature = "default")]
use crate::rtls::SslImpl;
use crate::session::Session;
use crate::ssl::Stream;
use crate::Server;
use bufstream::BufStream;
use lazy_static::lazy_static;
use log::{debug, error, info};
use mailin::{Action, Event, Response};
use scoped_threadpool::Pool;
use std::io::{BufRead, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::time::Duration;

lazy_static! {
    static ref FIVE_MINUTES: Duration = Duration::new(5 * 60, 0);
}

enum SessionResult {
    Finished,
    UpgradeTls,
}

struct ServerState {
    listener: TcpListener,
    session_builder: mailin::SessionBuilder,
    ssl: Option<SslImpl>,
    num_threads: u32,
}

pub(crate) fn serve<F>(config: Server, handler: F) -> Result<(), Error>
where
    F: Fn(&mut Session),
{
    let mut session_builder = mailin::SessionBuilder::new(config.name.clone());
    if config.ssl.is_some() {
        session_builder.enable_start_tls();
    }
    for auth in &config.auth {
        session_builder.enable_auth(auth.clone());
    }
    let listen = if let Some(listener) = config.tcp_listener {
        listener
    } else {
        let addr = config.socket_address;
        TcpListener::bind(&addr[..])
            .map_err(|err| Error::with_source("Cannot open listen address", err))?
    };
    let server_state = ServerState {
        listener: listen,
        session_builder,
        ssl: config.ssl,
        num_threads: config.num_threads,
    };
    run(&config.name, &server_state, handler)
}

fn run<F>(name: &str, server_state: &ServerState, handler: F) -> Result<(), Error>
where
    F: Fn(&mut Session),
{
    let mut pool = Pool::new(server_state.num_threads);
    let localaddr = server_state.listener.local_addr()?;
    info!("{} SMTP started on {}", name, localaddr);
    for conn in server_state.listener.incoming() {
        let stream = conn?;
        let builder = &server_state.session_builder;
        let acceptor = server_state.ssl.clone();
        pool.scoped(|scope| {
            scope.execute(move || handle_connection(stream, builder, acceptor, handler));
        });
    }
    Ok(())
}

fn write_response(mut writer: &mut dyn Write, res: &Response) -> Result<(), Error> {
    res.write_to(&mut writer)?;
    writer
        .flush()
        .map_err(|e| Error::with_source("Cannot write response", e))
}

fn upgrade_tls(stream: TcpStream, ssl: Option<SslImpl>) -> Result<impl Stream, Error> {
    if let Some(acceptor) = ssl {
        let ret = acceptor.accept(stream)?;
        Ok(ret)
    } else {
        Error::bail("Cannot upgrade to TLS without an SslAcceptor")
    }
}

fn start_session<F>(
    session_builder: &mailin::SessionBuilder,
    remote: IpAddr,
    mut stream: BufStream<TcpStream>,
    ssl: Option<SslImpl>,
    handler: F,
) -> Result<(), Error>
where
    F: Fn(&mut Session),
{
    let inner = session_builder.build(remote);
    let session = Session::new(&mut inner, &mut stream);
    session.greeting()?;
    handler(&mut session);
    Ok(())
}

fn handle_connection<F>(
    stream: TcpStream,
    session_builder: &mailin::SessionBuilder,
    ssl: Option<SslImpl>,
    handler: F,
) where
    F: Fn(&mut Session),
{
    let remote = stream
        .peer_addr()
        .map(|saddr| saddr.ip())
        .unwrap_or_else(|_| "0.0.0.0".parse().unwrap());
    debug!("New connection from {}", remote);
    stream.set_read_timeout(Some(*FIVE_MINUTES)).ok();
    stream.set_write_timeout(Some(*FIVE_MINUTES)).ok();
    let bufstream = BufStream::new(stream);
    if let Err(err) = start_session(session_builder, remote, bufstream, ssl, handler) {
        error!("({}) {}", remote, err);
    }
}
