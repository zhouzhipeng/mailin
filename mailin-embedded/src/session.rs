use crate::rtls::{SslImpl, SslStream};
use crate::Error;
use bufstream::BufStream;
use mailin::Response;
use mailin::{Action, Event, State};
use std::io;
use std::io::{BufRead, Write};
use std::mem;
use std::net::TcpStream;

enum Stream {
    Unencrypted(BufStream<TcpStream>),
    Encrypted(BufStream<SslStream>),
    Empty,
}

pub struct Session {
    inner: mailin::Session,
    stream: Stream,
    line: Vec<u8>,
    ssl: Option<SslImpl>,
}

impl Session {
    pub fn handle(&mut self, mut handler: impl FnMut(State) -> Response) {
        loop {
            self.line.clear();
            let read = match &mut self.stream {
                Stream::Unencrypted(s) => s.read_until(b'\n', &mut self.line),
                Stream::Encrypted(s) => s.read_until(b'\n', &mut self.line),
                Stream::Empty => Err(io::ErrorKind::NotConnected.into()),
            };
            match read {
                Err(_) | Ok(0) => return,
                _ => (),
            };
            let response = match self.inner.process(&self.line) {
                Event::SendReponse(res) => res,
                Event::ChangeState(state) => match state {
                    State::End => break,
                    _ => handler(state),
                },
            };
            if let Err(_) = self.respond(&response) {
                // TODO: log errors
                break;
            }
            if let Action::Close = response.action {
                break;
            }
        }
    }

    pub(crate) fn new(
        inner: mailin::Session,
        stream: BufStream<TcpStream>,
        ssl: Option<SslImpl>,
    ) -> Self {
        Self {
            inner,
            stream: Stream::Unencrypted(stream),
            line: Vec::with_capacity(100),
            ssl,
        }
    }

    pub(crate) fn greeting(&mut self) -> Result<(), Error> {
        write_response(&mut self.stream, &self.inner.greeting())
    }

    fn respond(&mut self, res: &Response) -> Result<(), Error> {
        match res.action {
            Action::Reply => write_response(&mut self.stream, &res),
            Action::Close => {
                let _ = write_response(&mut self.stream, &res);
                Ok(())
            }
            Action::UpgradeTls => {
                let written = write_response(&mut self.stream, &res);
                if let Ok(_) = written {
                    self.upgrade_tls()
                } else {
                    written
                }
            }
            Action::NoReply => Ok(()),
        }
    }

    fn upgrade_tls(&mut self) -> Result<(), Error> {
        let mut current = Stream::Empty;
        mem::swap(&mut current, &mut self.stream);
        match current {
            Stream::Encrypted(_) => Error::bail("Cannot upgrade to TLS from TLS"),
            Stream::Empty => Error::bail("Not connected"),
            Stream::Unencrypted(s) => {
                let inner_stream = s
                    .into_inner()
                    .map_err(|e| Error::with_source("Cannot flush original TcpStream", e))?;
                let tls = if let Some(acceptor) = &self.ssl {
                    acceptor.accept(inner_stream)?
                } else {
                    Error::bail("Cannot upgrade to TLS without an SslAcceptor")?
                };
                self.inner.tls_active();
                let buf_tls = BufStream::new(tls);
                self.stream = Stream::Encrypted(buf_tls);
                Ok(())
            }
        }
    }
}

fn write_response(writer: &mut Stream, res: &Response) -> Result<(), Error> {
    // TODO: log error
    match writer {
        Stream::Unencrypted(s) => write(s, res),
        Stream::Encrypted(s) => write(s, res),
        Stream::Empty => Error::bail("Not connected"),
    }
}

fn write(writer: &mut dyn Write, res: &Response) -> Result<(), Error> {
    res.write_to(writer)?;
    writer
        .flush()
        .map_err(|e| Error::with_source("Cannot write response", e))
}
