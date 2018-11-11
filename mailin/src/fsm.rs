use parser::decode_sasl_plain;
use smtp::{
    AuthPlainCmd, AuthPlainEmptyCmd, AuthResponseCmd, Cmd, DataCmd, DataEndCmd, EhloCmd, HeloCmd,
    MailCmd, RcptCmd, RsetCmd, StartTlsCmd, VrfyCmd, AUTHENTICATION_REQUIRED,
    BAD_SEQUENCE_COMMANDS, EMPTY_RESPONSE, GOODBYE, START_DATA, START_TLS, VERIFY_RESPONSE,
};
use {Action, DataResult, Handler, HeloResult, Response, OK, TRANSACTION_FAILED};

use states::{Auth, AuthMechanism, Data, Helo, HeloAuth, Idle, Mail, Rcpt, State, States};
use std::io::{sink, Write};
use std::mem;
use std::net::IpAddr;

//------ Common functionality for states ---------------------------------------

// Return the next state depending on the response
fn handle_response<F, S1, S2>(state: S1, res: Response, next_state: F) -> (Response, States)
where
    F: FnOnce(S1) -> S2,
    S1: State,
    S2: State,
{
    if res.action == Action::Close {
        (res, States::Invalid)
    } else if res.is_error {
        (res, state.into())
    } else {
        (res, next_state(state).into())
    }
}

//------ StateChange -----------------------------------------------------------

// Change state on the given command, C to the next state N
trait StateChange<C: Sized>: State {
    // Execute the command and return the response, and the next state
    fn execute(self, handler: &mut Handler, cmd: C) -> (Response, States);
}

impl<'a, S: State> StateChange<HeloCmd<'a>> for S {
    fn execute(self, handler: &mut Handler, cmd: HeloCmd<'a>) -> (Response, States) {
        let res = Response::from(handler.helo(self.get_ip(), cmd.domain));
        self.handle_response(res, |s: Self| Helo {
            ip: s.get_ip(),
            domain: cmd.domain.to_owned(),
        })
    }
}

impl<'a, S: State> StateChange<EhloCmd<'a>> for S {
    fn execute(self, handler: &mut Handler, cmd: EhloCmd<'a>) -> (Response, States) {
        let res = match handler.helo(self.get_ip(), cmd.domain) {
            HeloResult::Ok => Response::ehlo_ok(),
            helo_res => Response::from(helo_res),
        };
        let helo = Helo {
            ip: self.get_ip(),
            domain: cmd.domain.to_owned(),
        };
        if self.require_auth() {
            self.handle_response(res, |_s: S| States::HeloAuth(helo))
        } else {
            self.handle_response(res, |_s: S| helo)
        }
    }
}

impl StateChange<StartTlsCmd> for Helo {
    fn execute(self, _handler: &mut Handler, _cmd: StartTlsCmd) -> (Response, States) {
        (START_TLS.clone(), Idle { ip: self.get_ip() }.into())
    }
}

impl StateChange<StartTlsCmd> for HeloAuth {
    fn execute(self, _handler: &mut Handler, _cmd: StartTlsCmd) -> (Response, States) {
        (
            START_TLS.clone(),
            States::IdleAuth(Idle { ip: self.get_ip() }).into(),
        )
    }
}

impl<'a> StateChange<MailCmd<'a>> for Helo {
    fn execute(self, handler: &mut Handler, cmd: MailCmd<'a>) -> (Response, States) {
        let res = Response::from(handler.mail(&self, cmd.reverse_path));
        self.handle_response(res, |s: Helo| Mail {
            ip: s.ip,
            domain: s.domain.clone(),
            reverse_path: cmd.reverse_path.to_owned(),
            is8bit: cmd.is8bit,
        })
    }
}

impl<'a> StateChange<AuthPlainCmd> for HeloAuth {
    fn execute(self, handler: &mut Handler, cmd: AuthPlainCmd) -> (Response, States) {
        let res = Response::from(handler.auth_plain(
            cmd.authorization_id.as_ref(),
            cmd.authentication_id.as_ref(),
            cmd.password.as_ref(),
        ));
        ternary!(res.is_error, (res, self.into()), (res, self.0.into()))
    }
}

impl<'a> StateChange<AuthPlainEmptyCmd> for HeloAuth {
    fn execute(self, _handler: &mut Handler, _cmd: AuthPlainEmptyCmd) -> (Response, States) {
        let state = Auth {
            ip: self.0.ip,
            domain: self.0.domain,
            mechanism: AuthMechanism::Plain,
        };
        (Response::fixed(334, ""), state.into())
    }
}

impl<'a> StateChange<AuthResponseCmd<'a>> for Auth {
    fn execute(self, handler: &mut Handler, cmd: AuthResponseCmd<'a>) -> (Response, States) {
        let auth_res = match self.mechanism {
            AuthMechanism::Plain => {
                let cmd = decode_sasl_plain(cmd.response);
                handler.auth_plain(
                    cmd.authorization_id.as_ref(),
                    cmd.authentication_id.as_ref(),
                    cmd.password.as_ref(),
                )
            }
        };
        let res = Response::from(auth_res);
        let helo = Helo {
            ip: self.ip,
            domain: self.domain,
        };
        if res.is_error {
            (res, States::HeloAuth(helo).into())
        } else {
            (res, helo.into())
        }
    }
}

impl StateChange<RsetCmd> for Helo {
    fn execute(self, _handler: &mut Handler, _cmd: RsetCmd) -> (Response, States) {
        (OK.clone(), self.into())
    }
}

impl StateChange<RsetCmd> for HeloAuth {
    fn execute(self, _handler: &mut Handler, _cmd: RsetCmd) -> (Response, States) {
        (OK.clone(), self.into())
    }
}

impl StateChange<VrfyCmd> for Helo {
    fn execute(self, _handler: &mut Handler, _cmd: VrfyCmd) -> (Response, States) {
        (VERIFY_RESPONSE.clone(), self.into())
    }
}

impl<'a> StateChange<RcptCmd<'a>> for Mail {
    fn execute(self, handler: &mut Handler, cmd: RcptCmd<'a>) -> (Response, States) {
        let res = Response::from(handler.rcpt(cmd.forward_path));
        self.handle_response(res, |s: Mail| Rcpt {
            ip: s.ip,
            domain: s.domain,
            reverse_path: s.reverse_path,
            is8bit: s.is8bit,
            forward_path: vec![cmd.forward_path.to_owned()],
        })
    }
}

impl StateChange<RsetCmd> for Mail {
    fn execute(self, _handler: &mut Handler, _cmd: RsetCmd) -> (Response, States) {
        let next_state = Helo {
            ip: self.ip,
            domain: self.domain,
        }.into();
        (OK.clone(), next_state)
    }
}

impl<'a> StateChange<RcptCmd<'a>> for Rcpt {
    fn execute(self, handler: &mut Handler, cmd: RcptCmd<'a>) -> (Response, States) {
        let res = Response::from(handler.rcpt(cmd.forward_path));
        self.handle_response(res, |s: Rcpt| {
            let mut fp = s.forward_path;
            fp.push(cmd.forward_path.to_owned());
            Rcpt {
                forward_path: fp,
                ..s
            }
        })
    }
}

impl StateChange<DataCmd> for Rcpt {
    fn execute(self, handler: &mut Handler, _cmd: DataCmd) -> (Response, States) {
        let (res, writer) = match handler.data(&self) {
            DataResult::Ok(w) => (START_DATA.clone(), w),
            r => (Response::from(r), Box::new(sink()) as Box<Write>),
        };
        self.handle_response(res, |s: Rcpt| Data {
            ip: s.ip,
            domain: s.domain,
            writer,
        })
    }
}

impl StateChange<RsetCmd> for Rcpt {
    fn execute(self, _handler: &mut Handler, _cmd: RsetCmd) -> (Response, States) {
        let next_state = Helo {
            ip: self.ip,
            domain: self.domain,
        }.into();
        (OK.clone(), next_state)
    }
}

impl StateChange<DataEndCmd> for Data {
    fn execute(self, _handler: &mut Handler, _cmd: DataEndCmd) -> (Response, States) {
        // Even if an error occurs, change state to Helo
        let state = Helo {
            ip: self.ip,
            domain: self.domain.clone(),
        };
        (OK.clone(), state.into())
    }
}

//------ StateMachine ----------------------------------------------------------

enum TlsState {
    Unavailable,
    Available,
    Active,
}

pub(crate) struct StateMachine {
    current: States,
    start_tls_extension: TlsState,
}

impl StateMachine {
    pub(crate) fn new(ip: IpAddr, tls_available: bool, require_auth: bool) -> Self {
        let idle = Idle { ip };
        Self {
            current: ternary!(
                require_auth,
                States::IdleAuth(States::IdleAuth(idle)),
                States::Idle(idle)
            ),
            start_tls_extension: ternary!(
                tls_available,
                TlsState::Available,
                TlsState::Unavailable
            ),
        }
    }

    pub(crate) fn enable_tls(&mut self) {
        self.start_tls_extension = TlsState::Active;
    }

    pub(crate) fn current_state(&self) -> &States {
        &self.current
    }

    pub(crate) fn data(&mut self, data: &[u8]) -> Response {
        // TODO: change state on error
        match self.current {
            States::Data(ref mut d) => match d.writer.write_all(data) {
                Ok(_) => EMPTY_RESPONSE.clone(),
                Err(e) => {
                    error!("Error saving message: {}", e);
                    TRANSACTION_FAILED.clone()
                }
            },
            _ => TRANSACTION_FAILED.clone(),
        }
    }

    // Respond and change state with the given command
    pub(crate) fn command(&mut self, handler: &mut Handler, cmd: Cmd) -> Response {
        let last_state = mem::replace(&mut self.current, States::Invalid);
        let (response, next_state) = match (last_state, cmd) {
            (States::Idle(st), Cmd::Helo(cmd)) => Self::switch_state(st, handler, cmd),
            (States::Idle(st), Cmd::Ehlo(cmd)) => Self::switch_state(st, handler, cmd),
            (States::Helo(st), Cmd::Mail(cmd)) => Self::switch_state(st, handler, cmd),
            (States::Helo(st), Cmd::Vrfy(cmd)) => Self::switch_state(st, handler, cmd),
            (States::Mail(st), Cmd::Rcpt(cmd)) => Self::switch_state(st, handler, cmd),
            (States::Rcpt(st), Cmd::Rcpt(cmd)) => Self::switch_state(st, handler, cmd),
            (States::Rcpt(st), Cmd::Data(cmd)) => Self::switch_state(st, handler, cmd),
            (States::Data(st), Cmd::DataEnd(cmd)) => Self::switch_state(st, handler, cmd),
            (States::Helo(st), Cmd::Rset(cmd)) => Self::switch_state(st, handler, cmd),
            (States::Mail(st), Cmd::Rset(cmd)) => Self::switch_state(st, handler, cmd),
            (States::Rcpt(st), Cmd::Rset(cmd)) => Self::switch_state(st, handler, cmd),
            (States::Helo(st), Cmd::Helo(cmd)) => Self::switch_state(st, handler, cmd),
            (States::Mail(st), Cmd::Helo(cmd)) => Self::switch_state(st, handler, cmd),
            (States::Rcpt(st), Cmd::Helo(cmd)) => Self::switch_state(st, handler, cmd),
            (States::Helo(st), Cmd::Ehlo(cmd)) => Self::switch_state(st, handler, cmd),
            (States::Mail(st), Cmd::Ehlo(cmd)) => Self::switch_state(st, handler, cmd),
            (States::Rcpt(st), Cmd::Ehlo(cmd)) => Self::switch_state(st, handler, cmd),
            (States::Helo(st), Cmd::StartTls(cmd)) => self.start_tls(st, handler, cmd),
            (States::IdleAuth(st), Cmd::Ehlo(cmd)) => Self::switch_state(st, handler, cmd),
            (States::HeloAuth(st), Cmd::Rset(cmd)) => Self::switch_state(st, handler, cmd),
            (States::HeloAuth(st), Cmd::StartTls(cmd)) => self.start_tls(st, handler, cmd),
            (States::HeloAuth(st), Cmd::AuthPlain(cmd)) => Self::switch_state(st, handler, cmd),
            (States::HeloAuth(st), Cmd::AuthPlainEmpty(cmd)) => {
                Self::switch_state(st, handler, cmd)
            }
            (States::Auth(st), Cmd::AuthResponse(cmd)) => Self::switch_state(st, handler, cmd),
            (_, Cmd::Quit(_)) => (GOODBYE.clone(), States::Invalid),
            (States::HeloAuth(st), _) => (AUTHENTICATION_REQUIRED.clone(), st.into()),
            (current, _) => (BAD_SEQUENCE_COMMANDS.clone(), current),
        };
        self.current = next_state;
        response
    }

    fn start_tls<C, S>(&self, state: S, handler: &mut Handler, cmd: C) -> (Response, States)
    where
        S: StateChange<C>,
    {
        match self.start_tls_extension {
            TlsState::Available => Self::switch_state(state, handler, cmd),
            _ => {
                error!("({}) STARTTLS received when not enabled", state.get_ip());
                (BAD_SEQUENCE_COMMANDS.clone(), state.into())
            }
        }
    }

    // Return the next state given a command
    fn switch_state<C, S>(state: S, handler: &mut Handler, cmd: C) -> (Response, States)
    where
        S: StateChange<C>,
    {
        let (res, next_state) = state.execute(handler, cmd);
        trace!("* {:?}", next_state);
        (res, next_state)
    }
}
