use crate::cmd::Cmd;
use crate::parser::parse;
use crate::response::{Response, BAD_SEQUENCE_COMMANDS, INVALID_STATE, OK};
use crate::state::{Hello, Idle, Mail, State};
use std::net::IpAddr;

pub struct Session {
    state: Option<State>,
}

#[derive(Debug)]
pub enum Event {
    ChangeState(State),
    SendReponse(Response),
}

impl Session {
    pub fn new(ip: IpAddr) -> Self {
        Self {
            state: Some(State::Idle(Idle { ip })),
        }
    }

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
                self.next_state(Hello::from_rset(state).into());
                Event::SendReponse(OK)
            }
            (state, _) => {
                self.next_state(state);
                Event::SendReponse(BAD_SEQUENCE_COMMANDS)
            }
        }
    }

    pub fn handle_client<F>(&mut self, handler: F)
    where
        F: Fn(&mut Self),
    {
        // Setup client then
        handler(self)
    }

    pub(crate) fn next_state(&mut self, next: State) {
        self.state = Some(next);
    }

    pub(crate) fn state(&self) -> Option<&State> {
        self.state.as_ref()
    }
}

fn to_event<S>(s: S) -> Event
where
    S: Into<State>,
{
    let state: State = s.into();
    Event::ChangeState(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use matches::matches;

    fn unexpected(ev: Event) -> Response {
        assert!(false, format!("Unexpected {:#?}", ev));
        INVALID_STATE
    }

    #[test]
    fn helo_ehlo() {
        let mut session = Session::new("127.0.0.1".parse().unwrap());
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
        let mut session = Session::new("127.0.0.1".parse().unwrap());
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
        let mut session = Session::new("127.0.0.1".parse().unwrap());
        let res = session.process(b"helo world\x40\xff\r\n");
        assert!(matches!(
            res,
            Event::SendReponse(Response { code: 500, .. })
        ));
    }
}
