use crate::auth::AuthMechanism;
use crate::cmd::Cmd;
use crate::parser::parse;
use crate::response::{Response, BAD_SEQUENCE_COMMANDS, INVALID_STATE, OK};
use crate::state::{Hello, Idle, Mail, State};
use std::net::IpAddr;

/// Builds an smtp `Session`
///
/// # Examples
/// ```rust,ignore
/// # use mailin::{Session, SessionBuilder, Handler, Action, AuthMechanism};
///
/// # use std::net::{IpAddr, Ipv4Addr};
/// # impl Handler for EmptyHandler{};
/// # let addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
/// # let handler = EmptyHandler{};
/// // Create a session builder that holds the configuration
/// let mut builder = SessionBuilder::new("server_name");
/// builder.enable_start_tls()
///        .enable_auth(AuthMechanism::Plain);
/// // Then when a client connects
/// let mut session = builder.build(addr, handler);
/// ```
pub struct SessionBuilder {
    name: String,
    start_tls_extension: bool,
    auth_mechanisms: Vec<AuthMechanism>,
}

impl SessionBuilder {
    /// Create a new session for the given mailserver name
    pub fn new<S: Into<String>>(name: S) -> Self {
        Self {
            name: name.into(),
            start_tls_extension: false,
            auth_mechanisms: Vec::with_capacity(4),
        }
    }

    /// Enable support for StartTls
    pub fn enable_start_tls(&mut self) -> &mut Self {
        self.start_tls_extension = true;
        self
    }

    /// Enable support for authentication
    pub fn enable_auth(&mut self, auth: AuthMechanism) -> &mut Self {
        self.auth_mechanisms.push(auth);
        self
    }

    /// Build a new session to handle a connection from the given ip address
    pub fn build(&self, remote: IpAddr) -> Session {
        Session {
            server_name: self.name.clone(),
            auth_mechanisms: self.auth_mechanisms.clone(),
            start_tls_extension: self.start_tls_extension,
            state: Some(State::Idle(Idle { ip: remote })),
        }
    }
}

pub struct Session<'a> {
    server_name: String,
    auth_mechanisms: Vec<AuthMechanism>,
    start_tls_extension: bool,
    state: Option<State<'a>>,
}

#[derive(Debug)]
pub enum Event<'a> {
    ChangeState(State<'a>),
    SendReponse(Response),
}

impl Session<'_> {
    pub fn process(&mut self, line: &[u8]) -> Event {
        match parse(line) {
            Err(response) => Event::SendReponse(response),
            Ok(cmd) => {
                if let Some(prev_state) = self.state.take() {
                    self.handle_cmd(prev_state, cmd)
                } else {
                    Event::SendReponse(INVALID_STATE)
                }
            }
        }
    }

    /// Returns a greeting to send to a client
    pub fn greeting(&self) -> Response {
        Response::dynamic(220, format!("{} ESMTP", self.server_name), Vec::new())
    }

    pub fn tls_active(&mut self) {
        // TODO: implement
    }

    fn handle_cmd(&mut self, prev_state: State, cmd: Cmd) -> Event {
        match (prev_state, cmd) {
            (State::Idle(idle), Cmd::Rset) => {
                self.next_state(State::Idle(idle));
                Event::SendReponse(OK)
            }
            (
                State::Hello(hello),
                Cmd::Mail {
                    reverse_path,
                    is8bit,
                },
            ) => to_event(Mail::from_hello(hello, reverse_path, is8bit)),
            (State::Mail(_), Cmd::Rcpt { .. }) => to_event(State::End),
            (State::End, _) => to_event(State::End),
            (state, Cmd::Helo { domain }) => to_event(Hello::from_state(state, false, domain)),
            (state, Cmd::Ehlo { domain }) => to_event(Hello::from_state(state, true, domain)),
            (state, Cmd::Rset) => {
                self.next_state(Hello::from_rset(state));
                Event::SendReponse(OK)
            }
            (state, _) => {
                self.next_state(state);
                Event::SendReponse(BAD_SEQUENCE_COMMANDS)
            }
        }
    }

    pub(crate) fn next_state<'a, S>(&'a mut self, next: S)
    where
        S: Into<State<'a>>,
    {
        self.state = Some(next.into());
    }

    pub(crate) fn state(&self) -> Option<&State> {
        self.state.as_ref()
    }
}

fn to_event<'a, S>(s: S) -> Event<'a>
where
    S: Into<State<'a>> + 'a,
{
    let state: State = s.into();
    Event::ChangeState(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use matches::matches;
    use std::net::Ipv4Addr;

    fn unexpected(ev: Event) -> Response {
        assert!(false, format!("Unexpected {:#?}", ev));
        INVALID_STATE
    }

    fn new_session() -> Session {
        let addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        SessionBuilder::new("some.name").build(addr)
    }

    #[test]
    fn helo_ehlo() {
        let mut session = new_session();
        let res = match session.process(b"helo a.domain\r\n") {
            Event::ChangeState(State::Hello(hello)) => {
                assert_eq!(hello.is_esmtp, false);
                hello.ok(&mut session)
            }
            ev => unexpected(ev),
        };
        assert_eq!(res.code, 250);
        assert!(matches!(session.state(), Some(State::Hello(Hello{is_esmtp: false, ..}))));
        let res = match session.process(b"ehlo b.domain\r\n") {
            Event::ChangeState(State::Hello(hello)) => {
                assert_eq!(hello.is_esmtp, true);
                hello.ok(&mut session)
            }
            ev => unexpected(ev),
        };
        assert_eq!(res.code, 250);
        assert!(matches!(session.state(), Some(State::Hello(Hello{is_esmtp: true, ..}))));
    }

    #[test]
    fn mail_from() {
        let mut session = new_session();
        let res = match session.process(b"helo a.domain\r\n") {
            Event::ChangeState(State::Hello(hello)) => {
                assert_eq!(hello.is_esmtp, false);
                hello.ok(&mut session)
            }
            ev => unexpected(ev),
        };
        assert_eq!(res.code, 250);
        let res = match session.process(b"mail from:<ship@sea.com>\r\n") {
            Event::ChangeState(State::Mail(mail)) => mail.ok(&mut session),
            ev => unexpected(ev),
        };
        assert_eq!(res.code, 250);
        assert!(matches!(session.state(), Some(State::Mail(_))));
    }

    #[test]
    fn domain_badchars() {
        let mut session = new_session();
        let res = session.process(b"helo world\x40\xff\r\n");
        assert!(matches!(
            res,
            Event::SendReponse(Response { code: 500, .. })
        ));
    }
}
