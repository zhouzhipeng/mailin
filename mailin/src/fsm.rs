use crate::parser::{decode_sasl_plain, parse};
use crate::smtp::{
    Cmd, BAD_SEQUENCE_COMMANDS, EMPTY_RESPONSE, GOODBYE, INVALID_STATE, START_DATA, START_TLS,
    VERIFY_RESPONSE,
};

use crate::{
    Action, AuthMechanism, AuthResult, DataResult, Handler, HeloResult, Response, BAD_HELLO, OK,
    TRANSACTION_FAILED,
};
use either::*;
use log::{error, trace};
use std::borrow::BorrowMut;
use std::io::{sink, Write};
use std::net::IpAddr;
use ternop::ternary;

#[cfg(test)]
#[derive(Debug)]
pub(crate) enum SmtpState {
    Invalid,
    Idle,
    Hello,
    HelloAuth,
    Auth,
    Mail,
    Rcpt,
    Data,
}

#[derive(PartialEq)]
enum TlsState {
    Unavailable,
    Inactive,
    Active,
}

enum AuthState {
    Unavailable,
    RequiresAuth,
    Authenticated,
}

trait State {
    #[cfg(test)]
    fn id(&self) -> SmtpState;

    // Handle an incoming command and return the next state
    fn handle(
        self: Box<Self>,
        fsm: &mut StateMachine,
        handler: &mut dyn Handler,
        cmd: Cmd,
    ) -> (Response, Option<Box<State>>);

    // Most state will convert an input line into a command.
    // Some states, e.g Data, need to process input lines differently and will
    // override this method.
    fn process_line<'a>(self: &mut Self, line: &'a [u8]) -> Either<Cmd<'a>, Response> {
        trace!("> {}", String::from_utf8_lossy(line));
        parse(line).map(Left).unwrap_or_else(Right)
    }
}

//------------------------------------------------------------------------------

// Return the next state depending on the response
fn next_state<F>(
    current: Box<State>,
    res: Response,
    next_state: F,
) -> (Response, Option<Box<State>>)
where
    F: FnOnce() -> Box<State>,
{
    if res.action == Action::Close {
        (res, None)
    } else if res.is_error {
        (res, Some(current))
    } else {
        (res, Some(next_state()))
    }
}

// Convert the current state to the next state depending on the response
fn transform_state<S, F>(
    current: Box<S>,
    res: Response,
    next_state: F,
) -> (Response, Option<Box<State>>)
where
    S: State + 'static,
    F: FnOnce(S) -> Box<State>,
{
    if res.action == Action::Close {
        (res, None)
    } else if res.is_error {
        (res, Some(current))
    } else {
        (res, Some(next_state(*current)))
    }
}

fn default_handler(
    current: Box<State>,
    fsm: &StateMachine,
    handler: &mut dyn Handler,
    cmd: &Cmd,
) -> (Response, Option<Box<State>>) {
    match *cmd {
        Cmd::Quit => (GOODBYE.clone(), None),
        Cmd::Helo { domain } => handle_helo(current, fsm, handler, domain),
        Cmd::Ehlo { domain } => handle_ehlo(current, fsm, handler, domain),
        _ => unhandled(current),
    }
}

fn unhandled(current: Box<State>) -> (Response, Option<Box<State>>) {
    (BAD_SEQUENCE_COMMANDS.clone(), Some(current))
}

fn handle_rset(fsm: &StateMachine, domain: &str) -> (Response, Option<Box<State>>) {
    match fsm.auth {
        AuthState::Unavailable => (
            OK.clone(),
            Some(Box::new(Hello {
                domain: domain.to_string(),
            })),
        ),
        _ => (
            OK.clone(),
            Some(Box::new(HelloAuth {
                domain: domain.to_string(),
            })),
        ),
    }
}

fn handle_helo(
    current: Box<State>,
    fsm: &StateMachine,
    handler: &mut dyn Handler,
    domain: &str,
) -> (Response, Option<Box<State>>) {
    match fsm.auth {
        AuthState::Unavailable => {
            let res = Response::from(handler.helo(fsm.ip, domain));
            next_state(current, res, || {
                Box::new(Hello {
                    domain: domain.to_owned(),
                })
            })
        }
        _ => {
            // If authentication is required the client should be using EHLO
            (BAD_HELLO.clone(), Some(current))
        }
    }
}

fn handle_ehlo(
    current: Box<State>,
    fsm: &StateMachine,
    handler: &mut dyn Handler,
    domain: &str,
) -> (Response, Option<Box<State>>) {
    let res = match handler.helo(fsm.ip, domain) {
        HeloResult::Ok => Response::ehlo_ok(),
        helo_res => Response::from(helo_res),
    };
    match fsm.auth {
        AuthState::Unavailable => next_state(current, res, || {
            Box::new(Hello {
                domain: domain.to_owned(),
            })
        }),
        AuthState::RequiresAuth | AuthState::Authenticated => next_state(current, res, || {
            Box::new(HelloAuth {
                domain: domain.to_owned(),
            })
        }),
    }
}

fn authenticate(
    fsm: &mut StateMachine,
    handler: &mut dyn Handler,
    authorization_id: &str,
    authentication_id: &str,
    password: &str,
) -> Response {
    let auth_res = handler.auth_plain(authorization_id, authentication_id, password);
    fsm.auth = match auth_res {
        AuthResult::Ok => AuthState::Authenticated,
        _ => AuthState::RequiresAuth,
    };
    Response::from(auth_res)
}

//------------------------------------------------------------------------------

struct Idle {}

impl State for Idle {
    #[cfg(test)]
    fn id(&self) -> SmtpState {
        SmtpState::Idle
    }

    fn handle(
        self: Box<Self>,
        fsm: &mut StateMachine,
        handler: &mut dyn Handler,
        cmd: Cmd,
    ) -> (Response, Option<Box<State>>) {
        match cmd {
            Cmd::StartedTls => {
                fsm.tls = TlsState::Active;
                (EMPTY_RESPONSE.clone(), Some(self))
            }
            Cmd::Rset => (OK.clone(), Some(self)),
            _ => default_handler(self, fsm, handler, &cmd),
        }
    }
}

//------------------------------------------------------------------------------

struct Hello {
    domain: String,
}

impl State for Hello {
    #[cfg(test)]
    fn id(&self) -> SmtpState {
        SmtpState::Hello
    }

    fn handle(
        self: Box<Self>,
        fsm: &mut StateMachine,
        handler: &mut dyn Handler,
        cmd: Cmd,
    ) -> (Response, Option<Box<State>>) {
        match cmd {
            Cmd::Mail {
                reverse_path,
                is8bit,
            } => {
                let res = Response::from(handler.mail(fsm.ip, &self.domain, reverse_path));
                transform_state(self, res, |s| {
                    Box::new(Mail {
                        domain: s.domain,
                        reverse_path: reverse_path.to_owned(),
                        is8bit,
                    })
                })
            }
            Cmd::StartTls if fsm.tls == TlsState::Inactive => {
                (START_TLS.clone(), Some(Box::new(Idle {})))
            }
            Cmd::Vrfy => (VERIFY_RESPONSE.clone(), Some(self)),
            Cmd::Rset => handle_rset(fsm, &self.domain),
            _ => default_handler(self, fsm, handler, &cmd),
        }
    }
}

//------------------------------------------------------------------------------

struct HelloAuth {
    domain: String,
}

impl State for HelloAuth {
    #[cfg(test)]
    fn id(&self) -> SmtpState {
        SmtpState::HelloAuth
    }

    fn handle(
        self: Box<Self>,
        fsm: &mut StateMachine,
        handler: &mut dyn Handler,
        cmd: Cmd,
    ) -> (Response, Option<Box<State>>) {
        match cmd {
            Cmd::StartTls => (START_TLS.clone(), Some(Box::new(Idle {}))),
            Cmd::AuthPlain {
                ref authorization_id,
                ref authentication_id,
                ref password,
            } if fsm.allow_auth_plain() => {
                let res = authenticate(fsm, handler, authorization_id, authentication_id, password);
                transform_state(self, res, |s| Box::new(Hello { domain: s.domain }))
            }
            Cmd::AuthPlainEmpty if fsm.allow_auth_plain() => {
                let domain = self.domain.clone();
                (
                    Response::fixed(334, ""),
                    Some(Box::new(Auth {
                        domain,
                        mechanism: AuthMechanism::Plain,
                    })),
                )
            }
            Cmd::Rset => handle_rset(fsm, &self.domain),
            _ => default_handler(self, fsm, handler, &cmd),
        }
    }
}

//------------------------------------------------------------------------------

struct Auth {
    domain: String,
    mechanism: AuthMechanism,
}

impl State for Auth {
    #[cfg(test)]
    fn id(&self) -> SmtpState {
        SmtpState::Auth
    }

    fn handle(
        self: Box<Self>,
        fsm: &mut StateMachine,
        handler: &mut dyn Handler,
        cmd: Cmd,
    ) -> (Response, Option<Box<State>>) {
        match cmd {
            Cmd::AuthResponse { response } => {
                let res = match self.mechanism {
                    AuthMechanism::Plain => {
                        let creds = decode_sasl_plain(response);
                        authenticate(
                            fsm,
                            handler,
                            &creds.authorization_id,
                            &creds.authentication_id,
                            &creds.password,
                        )
                    }
                };
                let domain = self.domain.clone();
                if res.is_error {
                    (res, Some(Box::new(HelloAuth { domain })))
                } else {
                    (res, Some(Box::new(Hello { domain })))
                }
            }
            _ => unhandled(self),
        }
    }

    fn process_line<'a>(self: &mut Self, line: &'a [u8]) -> Either<Cmd<'a>, Response> {
        Left(Cmd::AuthResponse { response: line })
    }
}

//------------------------------------------------------------------------------

struct Mail {
    domain: String,
    reverse_path: String,
    is8bit: bool,
}

impl State for Mail {
    #[cfg(test)]
    fn id(&self) -> SmtpState {
        SmtpState::Mail
    }

    fn handle(
        self: Box<Self>,
        fsm: &mut StateMachine,
        handler: &mut dyn Handler,
        cmd: Cmd,
    ) -> (Response, Option<Box<State>>) {
        match cmd {
            Cmd::Rcpt { forward_path } => {
                let res = Response::from(handler.rcpt(forward_path));
                transform_state(self, res, |s| {
                    let fp = vec![forward_path.to_owned()];
                    Box::new(Rcpt {
                        domain: s.domain,
                        reverse_path: s.reverse_path,
                        is8bit: s.is8bit,
                        forward_path: fp,
                    })
                })
            }
            Cmd::Rset => handle_rset(fsm, &self.domain),
            _ => default_handler(self, fsm, handler, &cmd),
        }
    }
}

//------------------------------------------------------------------------------

struct Rcpt {
    domain: String,
    reverse_path: String,
    is8bit: bool,
    forward_path: Vec<String>,
}

impl State for Rcpt {
    #[cfg(test)]
    fn id(&self) -> SmtpState {
        SmtpState::Rcpt
    }

    fn handle(
        self: Box<Self>,
        fsm: &mut StateMachine,
        handler: &mut dyn Handler,
        cmd: Cmd,
    ) -> (Response, Option<Box<State>>) {
        match cmd {
            Cmd::Data => {
                let (res, writer) = match handler.data(
                    &self.domain,
                    &self.reverse_path,
                    self.is8bit,
                    &self.forward_path,
                ) {
                    DataResult::Ok(w) => (START_DATA.clone(), w),
                    r => (Response::from(r), Box::new(sink()) as Box<Write>),
                };
                transform_state(self, res, |s| {
                    Box::new(Data {
                        domain: s.domain,
                        writer,
                    })
                })
            }
            Cmd::Rcpt { forward_path } => {
                let res = Response::from(handler.rcpt(forward_path));
                transform_state(self, res, |s| {
                    let mut fp = s.forward_path;
                    fp.push(forward_path.to_owned());
                    Box::new(Rcpt {
                        domain: s.domain,
                        reverse_path: s.reverse_path,
                        is8bit: s.is8bit,
                        forward_path: fp,
                    })
                })
            }
            Cmd::Rset => handle_rset(fsm, &self.domain),
            _ => default_handler(self, fsm, handler, &cmd),
        }
    }
}

//------------------------------------------------------------------------------

struct Data {
    domain: String,
    writer: Box<Write>,
}

impl State for Data {
    #[cfg(test)]
    fn id(&self) -> SmtpState {
        SmtpState::Data
    }

    fn handle(
        self: Box<Self>,
        _fsm: &mut StateMachine,
        _handler: &mut dyn Handler,
        cmd: Cmd,
    ) -> (Response, Option<Box<State>>) {
        match cmd {
            Cmd::DataEnd => (
                OK.clone(),
                Some(Box::new(Hello {
                    domain: self.domain.clone(),
                })),
            ),
            _ => unhandled(self),
        }
    }

    fn process_line<'a>(self: &mut Self, line: &'a [u8]) -> Either<Cmd<'a>, Response> {
        if line == b"." {
            trace!("> _data_");
            Left(Cmd::DataEnd)
        } else {
            match self.writer.write_all(line) {
                Ok(_) => Right(EMPTY_RESPONSE.clone()),
                Err(e) => {
                    error!("Error saving message: {}", e);
                    Right(TRANSACTION_FAILED.clone())
                }
            }
        }
    }
}
//------------------------------------------------------------------------------

pub(crate) struct StateMachine {
    ip: IpAddr,
    auth: AuthState,
    tls: TlsState,
    smtp: Option<Box<State>>,
    auth_plain: bool,
}

impl StateMachine {
    pub fn new(ip: IpAddr, auth_mechanisms: &[AuthMechanism], allow_start_tls: bool) -> Self {
        let auth = ternary!(
            auth_mechanisms.is_empty(),
            AuthState::Unavailable,
            AuthState::RequiresAuth
        );
        let tls = ternary!(allow_start_tls, TlsState::Inactive, TlsState::Unavailable);
        let mut ret = Self {
            ip,
            auth,
            tls,
            smtp: Some(Box::new(Idle {})),
            auth_plain: false,
        };
        for auth_mechanism in auth_mechanisms {
            match auth_mechanism {
                AuthMechanism::Plain => ret.auth_plain = true,
            }
        }
        ret
    }

    // Respond and change state with the given command
    pub fn command(&mut self, handler: &mut Handler, cmd: Cmd) -> Response {
        let (response, next_state) = match self.smtp.take() {
            Some(last_state) => last_state.handle(self, handler, cmd),
            None => (INVALID_STATE.clone(), None),
        };
        self.smtp = next_state;
        response
    }

    pub fn process_line<'a>(&mut self, line: &'a [u8]) -> Either<Cmd<'a>, Response> {
        match self.smtp {
            Some(ref mut s) => {
                let s: &mut State = s.borrow_mut();
                s.process_line(line)
            }
            None => Right(INVALID_STATE.clone()),
        }
    }

    #[cfg(test)]
    pub fn current_state(&self) -> SmtpState {
        let id = self.smtp.as_ref().map(|s| s.id());
        id.unwrap_or(SmtpState::Invalid)
    }

    fn allow_auth_plain(&self) -> bool {
        self.auth_plain && self.tls == TlsState::Active
    }
}
