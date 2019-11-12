use lazy_static::lazy_static;
use log::trace;
use std::io;
use std::io::Write;

//------ Responses -------------------------------------------------------------

pub const MISSING_PARAMETER: Response =
    Response::constant(502, "Missing parameter", true, Action::Reply);
pub const SYNTAX_ERROR: Response = Response::constant(500, "Syntax error", true, Action::Reply);
pub const EMPTY_RESPONSE: Response = Response::empty();
pub const START_TLS: Response =
    Response::constant(220, "Ready to start TLS", false, Action::UpgradeTls);
pub const GOODBYE: Response = Response::constant(221, "Goodbye", false, Action::Close);
pub const OK: Response = Response::constant(250, "OK", false, Action::Reply);
pub const VERIFY_RESPONSE: Response = Response::constant(252, "Maybe", false, Action::Reply);
pub const START_DATA: Response = Response::constant(
    354,
    "Start mail input; end with <CRLF>.<CRLF>",
    false,
    Action::Reply,
);
pub const INVALID_STATE: Response = Response::constant(
    421,
    "Internal service error, closing connection",
    true,
    Action::Close,
);
pub const NO_SERVICE: Response = Response::constant(
    421,
    "Service not available, closing connection",
    true,
    Action::Close,
);
pub const BAD_SEQUENCE_COMMANDS: Response =
    Response::constant(503, "Bad sequence of commands", true, Action::Reply);
pub const AUTHENTICATION_REQUIRED: Response =
    Response::constant(530, "Authentication required", true, Action::Reply);
pub const BAD_HELLO: Response = Response::constant(550, "Bad HELO", true, Action::Reply);

//------ Types -----------------------------------------------------------------

/// Response contains a code and message to be sent back to the client
#[derive(Clone, Debug)]
pub struct Response {
    /// The three digit response code
    pub code: u16,
    message: Message,
    /// Is the response an error response?
    pub is_error: bool,
    /// The action to take after sending the response to the client
    pub action: Action,
}

#[derive(Clone, Debug)]
pub(crate) enum Message {
    Dynamic(String, Vec<&'static str>),
    Fixed(&'static str),
    Empty,
}

/// Action indicates the recommended action to take on a response
#[derive(PartialEq, Clone, Debug)]
pub enum Action {
    /// Send the response and close the connection
    Close,
    /// Upgrade the connection to use TLS
    UpgradeTls,
    /// Do not reply, wait for the client to send more data
    NoReply,
    /// Send a reply and keep the connection open
    Reply,
}

impl Response {
    // A response that can be used in const definitions
    pub(crate) const fn constant(
        code: u16,
        message: &'static str,
        is_error: bool,
        action: Action,
    ) -> Self {
        Self {
            code,
            message: Message::Fixed(message),
            is_error,
            action,
        }
    }

    // An empty response
    pub(crate) const fn empty() -> Self {
        Self {
            code: 0,
            message: Message::Empty,
            is_error: false,
            action: Action::NoReply,
        }
    }

    // A response that uses a fixed static string
    // TODO: remove
    pub(crate) fn fixed(code: u16, message: &'static str) -> Self {
        let action = match code {
            221 | 421 => Action::Close,
            _ => Action::Reply,
        };
        Self::fixed_action(code, message, action)
    }

    // A response that uses a fixed static string and a given action
    // TODO: remove
    pub(crate) fn fixed_action(code: u16, message: &'static str, action: Action) -> Self {
        Self {
            code,
            message: Message::Fixed(message),
            is_error: (code < 200 || code >= 400),
            action,
        }
    }

    pub(crate) fn ehlo_ok() -> Self {
        Self {
            code: 250,
            message: Message::Fixed(""),
            is_error: false,
            action: Action::Reply,
        }
    }

    // A response that is built dynamically and can be a multiline response
    pub(crate) fn dynamic(code: u16, head: String, tail: Vec<&'static str>) -> Self {
        Self {
            code,
            message: Message::Dynamic(head, tail),
            is_error: false,
            action: Action::Reply,
        }
    }

    /// Write the response to the given writer
    pub fn write_to(&self, out: &mut dyn Write) -> io::Result<()> {
        match self.message {
            Message::Dynamic(ref head, ref tail) => {
                if tail.is_empty() {
                    write!(out, "{} {}\r\n", self.code, head)?;
                } else {
                    write!(out, "{}-{}\r\n", self.code, head)?;
                    for i in 0..tail.len() {
                        if tail.len() > 1 && i < tail.len() - 1 {
                            write!(out, "{}-{}\r\n", self.code, tail[i])?;
                        } else {
                            write!(out, "{} {}\r\n", self.code, tail[i])?;
                        }
                    }
                }
            }
            Message::Fixed(s) => write!(out, "{} {}\r\n", self.code, s)?,
            Message::Empty => (),
        };
        Ok(())
    }

    // Log the response
    fn log(&self) {
        match self.message {
            Message::Empty => (),
            _ => {
                let mut buf = Vec::new();
                let _ = self.write_to(&mut buf);
                trace!("< {}", String::from_utf8_lossy(&buf));
            }
        }
    }
}
