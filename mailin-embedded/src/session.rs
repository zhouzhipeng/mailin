use crate::Error;
use bufstream::BufStream;
use mailin::{Action, Event, State};
use std::io::{BufRead, Write};

struct Session<S>
where
    S: BufRead + Write,
{
    inner: mailin::Session,
    stream: S,
    line: Vec<u8>,
}

impl<S> Session<S>
where
    S: BufRead + Write,
{
    pub(crate) fn new(inner: mailin::Session, stream: S) -> Self {
        let line = Vec::with_capacity(100);
        Self {
            inner,
            stream,
            line,
        }
    }

    pub(crate) fn greeting(&mut self) -> Result<(), Error> {
        // TODO: self.write_response
        write_response(&mut self.stream, &self.inner.greeting())?
    }

    pub fn next(&mut self) -> State {
        loop {
            self.line.clear();
            let num_bytes = self.stream.read_until(b'\n', &mut self.line)?;
            if num_bytes == 0 {
                return State::End;
            }
            match self.inner.process(&self.line) {
                Event::SendReponse(res) => match res.action {
                    Action::Reply => {
                        write_response(self.stream, &res)?;
                    }
                    Action::Close => {
                        write_response(self.stream, &res)?;
                        return State::End;
                    }
                    Action::UpgradeTls => {
                        write_response(self.stream, &res)?;
                        self.upgrade_tls();
                    }
                    Action::NoReply => (),
                },
                Event::ChangeState(state) => return state,
            }
        }
    }

    pub fn respond(&self) {
        // TODO: implement
    }

    fn upgrade_tls(&mut self) -> Result<(), Error> {
        let inner_stream = stream
            .into_inner()
            .map_err(|e| Error::with_source("Cannot flush original TcpStream", e))?;
        let tls = if let Some(acceptor) = ssl {
            acceptor.accept(stream)?
        } else {
            Error::bail("Cannot upgrade to TLS without an SslAcceptor")?;
        };
        inner.tls_active();
        let buf_tls = BufStream::new(tls);
        self.stream = buf_tls;
    }
}

fn write_response(writer: &mut dyn Write, res: &Response) -> Result<(), Error> {
    res.write_to(&mut writer)?;
    writer
        .flush()
        .map_err(|e| Error::with_source("Cannot write response", e))
}
