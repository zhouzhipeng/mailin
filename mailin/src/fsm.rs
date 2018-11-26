use parser::{decode_sasl_plain, parse};
use smtp::{
    Cmd, BAD_SEQUENCE_COMMANDS, EMPTY_RESPONSE, GOODBYE, INVALID_STATE, START_DATA, START_TLS,
    VERIFY_RESPONSE,
};

use either::*;
use std::borrow::BorrowMut;
use std::io::{sink, Write};
use std::net::IpAddr;
use {
    Action, AuthMechanism, DataResult, Handler, HeloResult, Response, BAD_HELLO, OK,
    TRANSACTION_FAILED,
};

#[cfg(test)]
#[derive(Debug)]
pub(crate) enum States {
    Invalid,
    Idle,
    Hello,
    HelloAuth,
    Auth,
    Mail,
    Rcpt,
    Data,
}

trait State {
    #[cfg(test)]
    fn id(&self) -> States;

    // Handle an incoming command and return the next state
    fn handle(
        self: Box<Self>,
        config: &StateMachineConfig,
        handler: &mut Handler,
        cmd: Cmd,
    ) -> (Response, Option<Box<State>>);

    // Most state will convert an input line into a command.
    // Some states, e.g Data, need to process input lines differently and will
    // override this method.
    fn process_line<'a>(self: &mut Self, line: &'a [u8]) -> Either<Cmd<'a>, Response> {
        parse(line)
            .map(Left)
            .unwrap_or_else(Right)
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
    config: &StateMachineConfig,
    handler: &mut Handler,
    cmd: &Cmd,
) -> (Response, Option<Box<State>>) {
    match *cmd {
        Cmd::Quit => (GOODBYE.clone(), None),
        Cmd::Helo { domain } => handle_helo(current, config, handler, domain),
        Cmd::Ehlo { domain } => handle_ehlo(current, config, handler, domain),
        _ => unhandled(current),
    }
}

fn unhandled(current: Box<State>) -> (Response, Option<Box<State>>) {
    (BAD_SEQUENCE_COMMANDS.clone(), Some(current))
}

fn handle_helo(
    current: Box<State>,
    config: &StateMachineConfig,
    handler: &mut Handler,
    domain: &str,
) -> (Response, Option<Box<State>>) {
    if config.require_auth {
        // If authentication is required the client should be using EHLO
        (BAD_HELLO.clone(), Some(current))
    } else {
        let res = Response::from(handler.helo(config.ip, domain));
        next_state(current, res, || {
            Box::new(Hello {
                domain: domain.to_owned(),
            })
        })
    }
}

fn handle_ehlo(
    current: Box<State>,
    config: &StateMachineConfig,
    handler: &mut Handler,
    domain: &str,
) -> (Response, Option<Box<State>>) {
    let res = match handler.helo(config.ip, domain) {
        HeloResult::Ok => Response::ehlo_ok(),
        helo_res => Response::from(helo_res),
    };
    if config.require_auth {
        next_state(current, res, || {
            Box::new(HelloAuth {
                domain: domain.to_owned(),
            })
        })
    } else {
        next_state(current, res, || {
            Box::new(Hello {
                domain: domain.to_owned(),
            })
        })
    }
}

//------------------------------------------------------------------------------

struct Idle {}

impl State for Idle {
    #[cfg(test)]
    fn id(&self) -> States {
        States::Idle
    }

    fn handle(
        self: Box<Self>,
        config: &StateMachineConfig,
        handler: &mut Handler,
        cmd: Cmd,
    ) -> (Response, Option<Box<State>>) {
        default_handler(self, config, handler, &cmd)
    }
}

//------------------------------------------------------------------------------

struct Hello {
    domain: String,
}

impl State for Hello {
    #[cfg(test)]
    fn id(&self) -> States {
        States::Hello
    }

    fn handle(
        self: Box<Self>,
        config: &StateMachineConfig,
        handler: &mut Handler,
        cmd: Cmd,
    ) -> (Response, Option<Box<State>>) {
        match cmd {
            Cmd::Mail {
                reverse_path,
                is8bit,
            } => {
                let res = Response::from(handler.mail(config.ip, &self.domain, reverse_path));
                transform_state(self, res, |s| {
                    Box::new(Mail {
                        domain: s.domain,
                        reverse_path: reverse_path.to_owned(),
                        is8bit,
                    })
                })
            }
            Cmd::StartTls => (START_TLS.clone(), Some(Box::new(Idle {}))),
            Cmd::Vrfy => (VERIFY_RESPONSE.clone(), Some(self)),
            _ => default_handler(self, config, handler, &cmd),
        }
    }
}

//------------------------------------------------------------------------------

struct HelloAuth {
    domain: String,
}

impl State for HelloAuth {
    #[cfg(test)]
    fn id(&self) -> States {
        States::HelloAuth
    }

    fn handle(
        self: Box<Self>,
        config: &StateMachineConfig,
        handler: &mut Handler,
        cmd: Cmd,
    ) -> (Response, Option<Box<State>>) {
        match cmd {
            Cmd::StartTls => (START_TLS.clone(), Some(Box::new(Idle {}))),
            Cmd::AuthPlain {
                authorization_id,
                authentication_id,
                password,
            } => {
                let res = Response::from(handler.auth_plain(
                    &authorization_id,
                    &authentication_id,
                    &password,
                ));
                transform_state(self, res, |s| Box::new(Hello { domain: s.domain }))
            }
            Cmd::AuthPlainEmpty => {
                let domain = self.domain.clone();
                (
                    Response::fixed(334, ""),
                    Some(Box::new(Auth {
                        domain,
                        mechanism: AuthMechanism::Plain,
                    })),
                )
            }
            _ => default_handler(self, config, handler, &cmd),
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
    fn id(&self) -> States {
        States::Auth
    }

    fn handle(
        self: Box<Self>,
        _config: &StateMachineConfig,
        handler: &mut Handler,
        cmd: Cmd,
    ) -> (Response, Option<Box<State>>) {
        match cmd {
            Cmd::AuthResponse { response } => {
                let auth_res = match self.mechanism {
                    AuthMechanism::Plain => {
                        let creds = decode_sasl_plain(response);
                        handler.auth_plain(
                            &creds.authorization_id,
                            &creds.authentication_id,
                            &creds.password,
                        )
                    }
                };
                let res = Response::from(auth_res);
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
    fn id(&self) -> States {
        States::Mail
    }

    fn handle(
        self: Box<Self>,
        config: &StateMachineConfig,
        handler: &mut Handler,
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
            Cmd::Rset => (
                OK.clone(),
                Some(Box::new(Hello {
                    domain: self.domain.clone(),
                })),
            ),
            _ => default_handler(self, config, handler, &cmd),
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
    fn id(&self) -> States {
        States::Rcpt
    }

    fn handle(
        self: Box<Self>,
        config: &StateMachineConfig,
        handler: &mut Handler,
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
            Cmd::Rset => (
                OK.clone(),
                Some(Box::new(Hello {
                    domain: self.domain.clone(),
                })),
            ),
            _ => default_handler(self, config, handler, &cmd),
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
    fn id(&self) -> States {
        States::Data
    }

    fn handle(
        self: Box<Self>,
        _config: &StateMachineConfig,
        _handler: &mut Handler,
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

struct StateMachineConfig {
    ip: IpAddr,
    require_auth: bool,
}

pub(crate) struct StateMachine {
    config: StateMachineConfig,
    current: Option<Box<State>>,
}

impl StateMachine {
    pub fn new(ip: IpAddr, require_auth: bool) -> Self {
        Self {
            config: StateMachineConfig { ip, require_auth },
            current: Some(Box::new(Idle {})),
        }
    }

    // Respond and change state with the given command
    pub fn command(&mut self, handler: &mut Handler, cmd: Cmd) -> Response {
        let (response, next_state) = match self.current.take() {
            Some(last_state) => last_state.handle(&self.config, handler, cmd),
            None => (INVALID_STATE.clone(), None),
        };
        self.current = next_state;
        response
    }

    pub fn process_line<'a>(&mut self, line: &'a [u8]) -> Either<Cmd<'a>, Response> {
        match self.current {
            Some(ref mut s) => {
                let s: &mut State = s.borrow_mut();
                s.process_line(line)
            }
            None => Right(INVALID_STATE.clone()),
        }
    }

    #[cfg(test)]
    pub fn current_state(&self) -> States {
        let id = self.current.as_ref().map(|s| s.id());
        id.unwrap_or(States::Invalid)
    }
}
