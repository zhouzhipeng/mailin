use crate::response::{Response, BAD_HELLO, NO_SERVICE, OK};
use crate::smtp::Smtp;
use std::net::IpAddr;

#[derive(Debug)]
pub enum State {
    Idle(Idle),
    Hello(Hello),
    Mail(Mail),
    End,
}

/// Mark a state transition as ok to continue
impl State {
    pub fn ok(self, smtp: &mut Smtp) -> Response {
        match self {
            Self::Hello(hello) => hello.ok(smtp),
            Self::Mail(mail) => mail.ok(smtp),
            _ => OK,
        }
    }
}

//--- Convert from structs to State enum ---

impl From<Hello> for State {
    fn from(h: Hello) -> Self {
        Self::Hello(h)
    }
}

impl From<Mail> for State {
    fn from(m: Mail) -> Self {
        Self::Mail(m)
    }
}

//--- Convert between structs ---

impl From<Hello> for Idle {
    fn from(h: Hello) -> Self {
        Self { ip: h.ip }
    }
}

impl From<Mail> for Hello {
    fn from(m: Mail) -> Self {
        Self {
            ip: m.ip,
            is_esmtp: m.is_esmtp,
            domain: m.domain,
        }
    }
}

//--- Idle ---

#[derive(Debug)]
pub struct Idle {
    pub ip: IpAddr,
}

//--- Hello ---

#[derive(Debug)]
pub struct Hello {
    pub ip: IpAddr,
    pub is_esmtp: bool,
    pub domain: String,
}

impl Hello {
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

    pub fn ok(self, smtp: &mut Smtp) -> Response {
        smtp.next_state(State::Hello(self));
        OK
    }

    pub fn deny(self, smtp: &mut Smtp, _msg: &str) -> Response {
        smtp.next_state(State::Idle(self.into()));
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
    pub fn ok(self, smtp: &mut Smtp) -> Response {
        smtp.next_state(State::Mail(self));
        OK
    }

    pub fn deny(self, smtp: &mut Smtp, _msg: &str) -> Response {
        smtp.next_state(State::Hello(self.into()));
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
