use crate::err::Error;
use crate::Server;
use bufstream::BufStream;
use lazy_static::lazy_static;
use log::{debug, error, info, trace};
use mailin::{Action, Handler, Response, Session, SessionBuilder};
use openssl;
use openssl::ssl::{SslAcceptor, SslStream};
use std::io::{BufRead, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::thread::JoinHandle;
use std::time::Duration;
use threadpool::ThreadPool;

lazy_static! {
    static ref FIVE_MINUTES: Duration = Duration::new(5 * 60, 0);
}

enum SessionResult {
    Finished,
    UpgradeTls,
}

struct ServerState<H>
where
    H: Handler + Clone + Send,
{
    listener: TcpListener,
    handler: H,
    session_builder: SessionBuilder,
    ssl_acceptor: Option<Arc<SslAcceptor>>,
    num_threads: usize,
}

/// A running SMTP server
pub struct RunningServer {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    pub(crate) join_handle: JoinHandle<()>,
}

impl RunningServer {
    pub(crate) fn serve<H>(config: Server<H>) -> Result<Self, Error>
    where
        H: Handler + Clone + Send + 'static,
    {
        let mut session_builder = SessionBuilder::new(config.name.clone());
        if config.ssl_acceptor.is_some() {
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
        let local_addr = listen
            .local_addr()
            .map_err(|e| Error::with_source("Cannot get local address", e))?;
        let server_state = ServerState {
            listener: listen,
            handler: config.handler,
            session_builder,
            ssl_acceptor: config.ssl_acceptor.map(Arc::new),
            num_threads: config.num_threads,
        };
        let stop_flag = Arc::new(AtomicBool::new(false));
        Ok(Self {
            address: local_addr,
            stop: stop_flag.clone(),
            join_handle: Self::background_run(config.name, &local_addr, stop_flag, server_state)?,
        })
    }

    /// Stop a running SMTP server
    pub fn stop(self) {
        self.stop.store(true, Ordering::Relaxed);
        // Connect to the socket so that the accept loop is activated
        if let Err(_conn) = TcpStream::connect(&self.address) {
            error!("Stopping mailin-embedded but server is not actively listening");
        }
        if self.join_handle.join().is_err() {
            error!("Unknown error stopping mailin-embedded");
        }
    }

    fn background_run<H>(
        name: String,
        address: &SocketAddr,
        stop_flag: Arc<AtomicBool>,
        server_state: ServerState<H>,
    ) -> Result<JoinHandle<()>, Error>
    where
        H: Handler + Clone + Send + 'static,
    {
        let thread_name = format!("{}", address);
        thread::Builder::new()
            .name(thread_name)
            .spawn(move || {
                if let Err(err) = Self::run(&name, &stop_flag, &server_state) {
                    error!("{}, exiting", err);
                }
            })
            .map_err(|e| Error::with_source("Cannot spawn background thread", e))
    }

    fn run<H>(
        name: &str,
        stop_flag: &Arc<AtomicBool>,
        server_state: &ServerState<H>,
    ) -> Result<(), Error>
    where
        H: Handler + Clone + Send + 'static,
    {
        let pool = ThreadPool::with_name("handler".to_string(), server_state.num_threads);
        let localaddr = server_state.listener.local_addr()?;
        info!("{} SMTP started on {}", name, localaddr);
        for conn in server_state.listener.incoming() {
            if stop_flag.load(Ordering::Relaxed) {
                break;
            }
            let stream = conn?;
            let builder = server_state.session_builder.clone();
            let acceptor = server_state.ssl_acceptor.clone();
            let handler_clone = server_state.handler.clone();
            pool.execute(move || handle_connection(stream, &builder, acceptor, handler_clone))
        }
        pool.join();
        Ok(())
    }
}

//--- Helper functions ---------------------------------------------------------

fn handle_session<H, S>(session: &mut Session<H>, stream: &mut S) -> Result<SessionResult, Error>
where
    S: BufRead + Write,
    H: Handler,
{
    let mut line = Vec::with_capacity(80);
    loop {
        line.clear();
        let num_bytes = stream.read_until(b'\n', &mut line)?;
        if num_bytes == 0 {
            break;
        }
        let res = session.process(&line);
        match res.action {
            Action::Reply => {
                write_response(stream, &res)?;
            }
            Action::Close => {
                write_response(stream, &res)?;
                if res.is_error {
                    "SMTP error".to_string();
                } else {
                    return Ok(SessionResult::Finished);
                }
            }
            Action::UpgradeTls => {
                write_response(stream, &res)?;
                return Ok(SessionResult::UpgradeTls);
            }
            Action::NoReply => (),
        }
    }
    Error::bail("Unexpected Eof")
}

fn write_response(mut writer: &mut dyn Write, res: &Response) -> Result<(), Error> {
    res.write_to(&mut writer)?;
    writer
        .flush()
        .map_err(|e| Error::with_source("Cannot write response", e))
}

fn upgrade_tls(
    stream: TcpStream,
    ssl_acceptor: Option<Arc<SslAcceptor>>,
) -> Result<SslStream<TcpStream>, Error> {
    if let Some(acceptor) = ssl_acceptor {
        let ret = acceptor
            .accept(stream)
            .map_err(|e| Error::with_source("Cannot upgrade to TLS", e))?;
        trace!("Upgrade TLS successful");
        Ok(ret)
    } else {
        Error::bail("Cannot upgrade to TLS without an SslAcceptor")
    }
}

fn start_session<H: Handler>(
    session_builder: &SessionBuilder,
    remote: IpAddr,
    mut stream: BufStream<TcpStream>,
    ssl_acceptor: Option<Arc<SslAcceptor>>,
    handler: H,
) -> Result<(), Error> {
    // TODO: have an embedded relay server with authentication
    let mut session = session_builder.build(remote, handler);
    write_response(&mut stream, &session.greeting())?;
    let res = handle_session(&mut session, &mut stream)?;
    if let SessionResult::UpgradeTls = res {
        let inner_stream = stream
            .into_inner()
            .map_err(|e| Error::with_source("Cannot flush original TcpStream", e))?;
        let tls = upgrade_tls(inner_stream, ssl_acceptor)?;
        session.tls_active();
        let mut buf_tls = BufStream::new(tls);
        handle_session(&mut session, &mut buf_tls)?;
    }
    Ok(())
}

fn handle_connection<H: Handler>(
    stream: TcpStream,
    session_builder: &SessionBuilder,
    ssl_acceptor: Option<Arc<SslAcceptor>>,
    handler: H,
) {
    let remote = stream
        .peer_addr()
        .map(|saddr| saddr.ip())
        .unwrap_or_else(|_| "0.0.0.0".parse().unwrap());
    debug!("New connection from {}", remote);
    stream.set_read_timeout(Some(*FIVE_MINUTES)).ok();
    stream.set_write_timeout(Some(*FIVE_MINUTES)).ok();
    let bufstream = BufStream::new(stream);
    if let Err(err) = start_session(&session_builder, remote, bufstream, ssl_acceptor, handler) {
        error!("({}) {}", remote, err);
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
        let mut server = Server::new(EmptyHandler {});
        server.with_addr("127.0.0.1:0").unwrap();
        let running = server.serve().unwrap();
        running.stop();
    }

}
