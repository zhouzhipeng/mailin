use crate::response::{Response, BAD_HELLO, NO_SERVICE, OK};
use crate::session::Session;
use std::net::IpAddr;

#[derive(Debug)]
pub enum State<'a> {
    Idle(Idle<'a>),
    Hello(Hello<'a>),
    Mail(Mail<'a>),
    End,
}

/// Mark a state transition as ok to continue
impl State<'_> {
    pub fn ok(self) -> Response {
        match self {
            Self::Idle(idle) => OK,
            Self::Hello(hello) => hello.ok(),
            Self::Mail(mail) => mail.ok(),
            End => OK,
        }
    }
}

//--- Convert from structs to State enum ---

impl<'a> From<Hello<'a>> for State<'a> {
    fn from(h: Hello<'a>) -> Self {
        Self::Hello(h)
    }
}

impl<'a> From<Mail<'a>> for State<'a> {
    fn from(m: Mail<'a>) -> Self {
        Self::Mail(m)
    }
}

//--- Convert between structs ---

impl<'a> From<Hello<'a>> for Idle<'a> {
    fn from(h: Hello<'a>) -> Self {
        Self { ip: h.ip }
    }
}

impl<'a> From<Mail<'a>> for Hello<'a> {
    fn from(m: Mail<'a>) -> Self {
        Self {
            ip: m.ip,
            is_esmtp: m.is_esmtp,
            domain: m.domain,
        }
    }
}

//--- Idle ---

#[derive(Debug)]
pub struct Idle<'a> {
    pub ip: IpAddr,
    session: &'a mut Session<'a>,
}

//--- Hello ---

#[derive(Debug)]
pub struct Hello<'a> {
    pub ip: IpAddr,
    pub is_esmtp: bool,
    pub domain: String,
    session: &'a mut Session<'a>,
}

impl Hello<'_> {
    pub(crate) fn from_state(state: State, is_esmtp: bool, domain: &str) -> Self {
        let ip = match state {
            State::Idle(idle) => idle.ip,
            State::Hello(hello) => hello.ip,
            State::Mail(mail) => mail.ip,
            State::End => unreachable!(),
        };
        Self {
            ip,
            is_esmtp,
            domain: domain.into(),
        }
    }

    pub(crate) fn from_rset(state: State) -> Self {
        match state {
            State::Idle(_) => unreachable!(),
            State::Hello(hello) => hello.into(),
            State::Mail(mail) => mail.into(),
            State::End => unreachable!(),
        }
    }

    pub fn ok(self) -> Response {
        self.session.next_state(self);
        OK
    }

    pub fn deny(self, _msg: &str) -> Response {
        self.session.next_state(State::Idle(self.into()));
        BAD_HELLO
    }
}

//--- Mail ---

#[derive(Debug)]
pub struct Mail {
    pub ip: IpAddr,
    pub domain: String,
    pub is_esmtp: bool,
    pub reverse_path: String,
    pub is8bit: bool,
}

impl Mail {
    pub fn ok(self, session: &mut Session) -> Response {
        session.next_state(self);
        OK
    }

    pub fn deny(self, session: &mut Session, _msg: &str) -> Response {
        session.next_state(State::Hello(self.into()));
        NO_SERVICE
    }

    pub(crate) fn from_hello(hello: Hello, reverse_path: &str, is8bit: bool) -> Self {
        Self {
            ip: hello.ip,
            domain: hello.domain,
            is_esmtp: hello.is_esmtp,
            reverse_path: String::from(reverse_path),
            is8bit,
        }
    }
}
