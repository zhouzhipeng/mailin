use crate::cmd::Cmd;
use crate::parser::parse;
use crate::response::{Response, BAD_SEQUENCE_COMMANDS, INVALID_STATE, OK};
use crate::state::{Hello, Idle, Mail, State};
use std::net::IpAddr;

pub struct Smtp {
    state: Option<State>,
}

#[derive(Debug)]
pub enum Event {
    ChangeState(State),
    SendReponse(Response),
}

impl Smtp {
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
                    Event::SendReponse(INVALID_STATE.clone())
                }
            }
        }
    }

    fn handle_cmd(&mut self, prev_state: State, cmd: Cmd) -> Event {
        match (prev_state, cmd) {
            (State::Idle(_), Cmd::Rset) => Event::SendReponse(OK.clone()),
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
                Event::SendReponse(OK.clone())
            }
            (_, _) => Event::SendReponse(BAD_SEQUENCE_COMMANDS.clone()),
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

    fn unexpected(ev: Event) -> Response {
        assert!(false, format!("Unexpected {:#?}", ev));
        INVALID_STATE.clone()
    }

    #[test]
    fn helo_ehlo() {
        let mut smtp = Smtp::new("127.0.0.1".parse().unwrap());
        let res = match smtp.process(b"helo a.domain\r\n") {
            Event::ChangeState(State::Hello(hello)) => {
                assert_eq!(hello.is_ehlo, false);
                hello.ok(&mut smtp)
            }
            ev => unexpected(ev),
        };
        assert_eq!(res.code, 250);
        let res = match smtp.process(b"ehlo b.domain\r\n") {
            Event::ChangeState(State::Hello(hello)) => {
                assert_eq!(hello.is_ehlo, true);
                hello.ok(&mut smtp)
            }
            ev => unexpected(ev),
        };
        assert_eq!(res.code, 250);
    }
}
