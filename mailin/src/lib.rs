//! A library for building smtp servers.
//!
//! The library supplies a parser and SMTP state machine. The user of the library
//! supplies I/O code and a `Handler` implementation for controlling SMTP sessions.
//!
//! The code using the library, sends
//! lines received to the `Session.process_line()` method. The user also supplies a
//! `Handler` implementation that makes decisions on whether to accept or reject email
//! messages. After consulting the `Handler` the `Session.process_line()` function will
//! return a response that can be sent back to the email client.
//!
//! # Pseudo Code
//! ```rust,ignore
//! // Create a handler which will control the SMTP session
//! let hander = create_handler();
//!
//! // Create a SMTP session when a new client connects
//! let session = SessionBuilder::new("mailserver_name").build(client_ip, handler);
//!
//! // Read a line from the client
//! let line = read_line(tcp_connection);
//! // Send the line to the session
//! let res = session.process(line);
//!
//! // Act on the response
//! match res.action {
//!     Action::Reply => {
//!         write_response(tcp_connection, &res)?;
//!     }
//!     Action::Close => {
//!         write_response(tcp_connection, &res)?;
//!         close(tcp_connection);
//!     }
//!     Action::NoReply => (), // No response needed
//! }
//! ```

// Use write! for /r/n
#![cfg_attr(feature = "cargo-clippy", allow(clippy::write_with_newline))]
#![forbid(unsafe_code)]
#![forbid(missing_docs)]

use lazy_static::lazy_static;
use log::trace;
use std::io;
use std::io::{sink, Write};
use std::net::IpAddr;
mod fsm;
mod parser;
mod smtp;

pub use crate::smtp::{Session, SessionBuilder};

/// A `Handler` makes decisions about incoming mail commands.
///
/// A Handler implementation must be provided by code using the mailin library.
///
/// All methods have a default implementation that does nothing. A separate handler instance
/// should be created for each connection.
///
/// # Examples
/// ```
/// # use mailin::{Handler, HeloResult, RcptResult, DataResult};
///
/// # use std::net::IpAddr;
/// # struct MyHandler{};
/// impl Handler for MyHandler {
///     fn helo(&mut self, ip: IpAddr, domain: &str) -> HeloResult {
///        if domain == "this.is.spam.com" {
///            HeloResult::BadHelo
///        } else {
///            HeloResult::Ok
///        }
///     }
///
///     fn rcpt(&mut self, to: &str) -> RcptResult {
///        if to == "alienscience" {
///            RcptResult::Ok
///        } else {
///            RcptResult::NoMailbox
///        }
///     }
/// }
/// ```
pub trait Handler {
    /// Called when a client sends a ehlo or helo message
    fn helo(&mut self, _ip: IpAddr, _domain: &str) -> HeloResult {
        HeloResult::Ok
    }

    /// Called when a mail message is started
    fn mail(&mut self, _ip: IpAddr, _domain: &str, _from: &str) -> MailResult {
        MailResult::Ok
    }

    /// Called when a mail recipient is set
    fn rcpt(&mut self, _to: &str) -> RcptResult {
        RcptResult::Ok
    }

    /// Called when a data command is received
    ///
    /// This function must return a writer and the email body will be written to
    /// this writer.
    fn data(&mut self, _domain: &str, _from: &str, _is8bit: bool, _to: &[String]) -> DataResult {
        DataResult::Ok(Box::new(sink()))
    }

    /// Called when a plain authentication request is received
    fn auth_plain(
        &mut self,
        _authorization_id: &str,
        _authentication_id: &str,
        _password: &str,
    ) -> AuthResult {
        AuthResult::InvalidCredentials
    }
}

#[derive(Debug, Clone)]
/// Supported authentication mechanisms
pub enum AuthMechanism {
    Plain,
}

impl AuthMechanism {
    // Show the AuthMechanism text as an SMTP extension
    fn extension(&self) -> &'static str {
        match self {
            AuthMechanism::Plain => "AUTH PLAIN",
        }
    }
}

//------ Response --------------------------------------------------------------

/// Response contains a code and message to be sent back to the client
#[derive(Clone, Debug)]
pub struct Response {
    pub code: u16,
    message: Message,
    pub is_error: bool,
    pub action: Action,
    ehlo_ok: bool, // This is an EHLO OK response
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
    // A response that uses a fixed static string
    pub(crate) fn fixed(code: u16, message: &'static str) -> Self {
        let action = match code {
            221 | 421 => Action::Close,
            _ => Action::Reply,
        };
        Self::fixed_action(code, message, action)
    }

    // A response that uses a fixed static string and a given action
    pub(crate) fn fixed_action(code: u16, message: &'static str, action: Action) -> Self {
        Self {
            code,
            message: Message::Fixed(message),
            is_error: (code < 200 || code >= 400),
            action,
            ehlo_ok: false,
        }
    }

    pub(crate) fn ehlo_ok() -> Self {
        Self {
            code: 250,
            message: Message::Fixed(""),
            is_error: false,
            action: Action::Reply,
            ehlo_ok: true,
        }
    }

    // A response that is built dynamically and can be a multiline response
    pub(crate) fn dynamic(code: u16, head: String, tail: Vec<&'static str>) -> Self {
        Self {
            code,
            message: Message::Dynamic(head, tail),
            is_error: false,
            action: Action::Reply,
            ehlo_ok: false,
        }
    }

    // An empty response
    pub(crate) fn empty() -> Self {
        Self {
            code: 0,
            message: Message::Empty,
            is_error: false,
            action: Action::NoReply,
            ehlo_ok: false,
        }
    }

    /// Write the response to the given writer
    pub fn write_to(&self, out: &mut Write) -> io::Result<()> {
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

//------ Results of Handler calls ----------------------------------------------

/// `HeloResult` is the result of an smtp HELO or EHLO command
pub enum HeloResult {
    /// Helo successful
    Ok,
    /// Return to indicate that Helo verification failed
    BadHelo,
    /// Return to indicate the ip address is on blocklists
    BlockedIp,
}

impl From<HeloResult> for Response {
    fn from(v: HeloResult) -> Response {
        match v {
            HeloResult::Ok => OK.clone(),
            HeloResult::BadHelo => BAD_HELLO.clone(),
            HeloResult::BlockedIp => BLOCKED_IP.clone(),
        }
    }
}

/// `MailResult` is the result of an smtp MAIL command
pub enum MailResult {
    /// Mail command successful
    Ok,
    /// Service not available, closing transmission channel
    NoService,
    /// Requested action aborted: local error in processing
    InternalError,
    /// Requested action not taken: insufficient system storage
    OutOfSpace,
    /// Authentication required
    AuthRequired,
    /// Exceeded storage allocation
    NoStorage,
}

impl From<MailResult> for Response {
    fn from(v: MailResult) -> Response {
        match v {
            MailResult::Ok => OK.clone(),
            MailResult::NoService => NO_SERVICE.clone(),
            MailResult::InternalError => INTERNAL_ERROR.clone(),
            MailResult::OutOfSpace => OUT_OF_SPACE.clone(),
            MailResult::AuthRequired => AUTH_REQUIRED.clone(),
            MailResult::NoStorage => NO_STORAGE.clone(),
        }
    }
}

/// `RcptResult` is the result of an smtp RCPT command
pub enum RcptResult {
    /// Recipient is valid
    Ok,
    /// No mailbox with the given name exists
    NoMailbox,
    /// The mailbox exceeded storage allocation
    NoStorage,
    /// The Mailbox name not allowed
    BadMailbox,
    /// Internal server error
    InternalError,
    /// System out of space
    OutOfSpace,
    /// <domain> Service not available, closing transmission channel
    NoService,
}

impl From<RcptResult> for Response {
    fn from(v: RcptResult) -> Response {
        match v {
            RcptResult::Ok => OK.clone(),
            RcptResult::NoMailbox => NO_MAILBOX.clone(),
            RcptResult::NoStorage => NO_STORAGE.clone(),
            RcptResult::BadMailbox => BAD_MAILBOX.clone(),
            RcptResult::InternalError => INTERNAL_ERROR.clone(),
            RcptResult::OutOfSpace => OUT_OF_SPACE.clone(),
            RcptResult::NoService => NO_SERVICE.clone(),
        }
    }
}

/// `DataResult` is the result of an smtp DATA command
pub enum DataResult {
    /// Message accepted, write bytes to Writer
    Ok(Box<Write>),
    /// Internal server error
    InternalError,
    /// Transaction failed
    TransactionFailed,
    /// <domain> Service not available, closing transmission channel
    NoService,
}

impl From<DataResult> for Response {
    fn from(v: DataResult) -> Response {
        match v {
            DataResult::InternalError => INTERNAL_ERROR.clone(),
            DataResult::TransactionFailed => TRANSACTION_FAILED.clone(),
            DataResult::NoService => NO_SERVICE.clone(),
            _ => unreachable!(),
        }
    }
}

/// `AuthResult` is the result of authenticating a smtp session
pub enum AuthResult {
    /// Authentication successful
    Ok,
    /// Temporary authentication failure
    TemporaryFailure,
    /// Invalid or insufficient credentials
    InvalidCredentials,
}

impl From<AuthResult> for Response {
    fn from(v: AuthResult) -> Response {
        match v {
            AuthResult::Ok => AUTH_OK.clone(),
            AuthResult::TemporaryFailure => TEMP_AUTH_FAILURE.clone(),
            AuthResult::InvalidCredentials => INVALID_CREDENTIALS.clone(),
        }
    }
}

lazy_static! {
    static ref AUTH_OK: Response = Response::fixed(235, "Authentication succeeded");
    static ref OK: Response = Response::fixed(250, "OK");
    static ref NO_SERVICE: Response =
        Response::fixed(421, "Service not available, closing connection");
    static ref INTERNAL_ERROR: Response =
        Response::fixed(451, "Aborted: local error in processing");
    static ref OUT_OF_SPACE: Response = Response::fixed(452, "Insufficient system storage");
    static ref TEMP_AUTH_FAILURE: Response =
        Response::fixed(454, "Temporary authentication failure");
    static ref NO_STORAGE: Response = Response::fixed(552, "Exceeded storage allocation");
    static ref AUTH_REQUIRED: Response = Response::fixed(530, "Authentication required");
    static ref INVALID_CREDENTIALS: Response = Response::fixed(535, "Invalid credentials");
    static ref NO_MAILBOX: Response = Response::fixed(550, "Mailbox unavailable");
    static ref BAD_HELLO: Response = Response::fixed(550, "Bad HELO");
    static ref BLOCKED_IP: Response = Response::fixed(550, "IP address on blocklists");
    static ref BAD_MAILBOX: Response = Response::fixed(553, "Mailbox name not allowed");
    static ref TRANSACTION_FAILED: Response = Response::fixed(554, "Transaction failed");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::net::Ipv4Addr;

    struct TestHandler {
        ip: IpAddr,
        domain: String,
        from: String,
        to: Vec<String>,
        is8bit: bool,
        expected_data: Vec<u8>,
        // Booleans set when callbacks are successful
        helo_called: bool,
        mail_called: bool,
        rcpt_called: bool,
        data_called: bool,
    }

    impl<'a> Handler for &'a mut TestHandler {
        fn helo(&mut self, ip: IpAddr, domain: &str) -> HeloResult {
            assert_eq!(self.ip, ip);
            assert_eq!(self.domain, domain);
            self.helo_called = true;
            HeloResult::Ok
        }

        // Called when a mail message is started
        fn mail(&mut self, ip: IpAddr, domain: &str, from: &str) -> MailResult {
            assert_eq!(self.ip, ip);
            assert_eq!(self.domain, domain);
            assert_eq!(self.from, from);
            self.mail_called = true;
            MailResult::Ok
        }

        // Called when a mail recipient is set
        fn rcpt(&mut self, to: &str) -> RcptResult {
            let valid_to = self.to.iter().any(|elem| elem == to);
            assert!(valid_to, "Invalid to address");
            self.rcpt_called = true;
            RcptResult::Ok
        }

        // Called to write an email message to a writer
        fn data(&mut self, domain: &str, from: &str, is8bit: bool, to: &[String]) -> DataResult {
            assert_eq!(self.domain, domain);
            assert_eq!(self.from, from);
            assert_eq!(self.to, to);
            assert_eq!(self.is8bit, is8bit);
            self.data_called = true;
            let test_writer = TestWriter {
                expected_data: self.expected_data.clone(),
                cursor: Cursor::new(Vec::with_capacity(80)),
            };
            DataResult::Ok(Box::new(test_writer))
        }
    }

    struct TestWriter {
        expected_data: Vec<u8>,
        cursor: Cursor<Vec<u8>>,
    }

    impl Write for TestWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.cursor.write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.cursor.flush()
        }
    }

    impl Drop for TestWriter {
        fn drop(&mut self) {
            let actual_data = self.cursor.get_ref();
            assert_eq!(actual_data, &self.expected_data);
        }
    }

    #[test]
    fn callbacks() {
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let domain = "some.domain";
        let from = "ship@sea.com";
        let to = vec!["fish@sea.com".to_owned(), "seaweed@sea.com".to_owned()];
        let data = vec![
            b"Hello 8bit world \x40\x7f\r\n" as &[u8],
            b"Hello again\r\n" as &[u8],
        ];
        let mut expected_data = Vec::with_capacity(2);
        for line in data.clone() {
            expected_data.extend(line);
        }
        let mut handler = TestHandler {
            ip: ip.clone(),
            domain: domain.to_owned(),
            from: from.to_owned(),
            to: to.clone(),
            is8bit: true,
            expected_data,
            helo_called: false,
            mail_called: false,
            rcpt_called: false,
            data_called: false,
        };
        let mut session =
            smtp::SessionBuilder::new("server.domain").build(ip.clone(), &mut handler);
        let helo = format!("helo {}\r\n", domain).into_bytes();
        session.process(&helo);
        let mail = format!("mail from:<{}> body=8bitmime\r\n", from).into_bytes();
        session.process(&mail);
        let rcpt0 = format!("rcpt to:<{}>\r\n", &to[0]).into_bytes();
        let rcpt1 = format!("rcpt to:<{}>\r\n", &to[1]).into_bytes();
        session.process(&rcpt0);
        session.process(&rcpt1);
        session.process(b"data\r\n");
        for line in data {
            session.process(line);
        }
        session.process(b".\r\n");
        assert_eq!(handler.helo_called, true);
        assert_eq!(handler.mail_called, true);
        assert_eq!(handler.rcpt_called, true);
        assert_eq!(handler.data_called, true);
    }
}
