use std::net::IpAddr;
use std::str;

use crate::fsm::StateMachine;
use crate::{Action, AuthMechanism, Handler, Response};
use either::{Left, Right};
use lazy_static::lazy_static;
use ternop::ternary;

//------ Responses -------------------------------------------------------------

lazy_static! {
    pub static ref EMPTY_RESPONSE: Response = Response::empty();
    pub static ref START_TLS: Response =
        Response::fixed_action(220, "Ready to start TLS", Action::UpgradeTls);
    pub static ref GOODBYE: Response = Response::fixed(221, "Goodbye");
    pub static ref VERIFY_RESPONSE: Response = Response::fixed(252, "Maybe");
    pub static ref START_DATA: Response =
        Response::fixed(354, "Start mail input; end with <CRLF>.<CRLF>");
    pub static ref INVALID_STATE: Response =
        Response::fixed(421, "Internal service error, closing connection");
    pub static ref SYNTAX_ERROR: Response = Response::fixed(500, "Syntax error");
    pub static ref MISSING_PARAMETER: Response = Response::fixed(502, "Missing parameter");
    pub static ref BAD_SEQUENCE_COMMANDS: Response =
        Response::fixed(503, "Bad sequence of commands");
    pub static ref AUTHENTICATION_REQUIRED: Response =
        Response::fixed(530, "Authentication required");
}

//------ Types -----------------------------------------------------------------

// Smtp commands sent by the client
#[derive(Clone)]
pub enum Cmd<'a> {
    Ehlo {
        domain: &'a str,
    },
    Helo {
        domain: &'a str,
    },
    Mail {
        reverse_path: &'a str,
        is8bit: bool,
    },
    Rcpt {
        forward_path: &'a str,
    },
    Data,
    Rset,
    Noop,
    StartTls,
    Quit,
    Vrfy,
    AuthPlain {
        authorization_id: String,
        authentication_id: String,
        password: String,
    },
    AuthPlainEmpty,
    // Dummy command containing client authentication
    AuthResponse {
        response: &'a [u8],
    },
    // Dummy command to signify end of data
    DataEnd,
    // Dummy command sent when STARTTLS was successful
    StartedTls,
}

pub(crate) struct Credentials {
    pub authorization_id: String,
    pub authentication_id: String,
    pub password: String,
}

/// A single smtp session connected to a single client
pub struct Session<H: Handler> {
    name: String,
    handler: H,
    fsm: StateMachine,
    start_tls_extension: bool,
    auth_mechanisms: Vec<AuthMechanism>,
}

#[derive(Clone)]
/// Builds an smtp `Session`
///
/// # Examples
/// ```
/// # use mailin::{Session, SessionBuilder, Handler, Action, AuthMechanism};
///
/// # use std::net::{IpAddr, Ipv4Addr};
/// # struct EmptyHandler{};
/// # impl Handler for EmptyHandler{};
/// # let addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
/// # let handler = EmptyHandler{};
/// // Create a session builder that holds the configuration
/// let mut builder = SessionBuilder::new("server_name");
/// builder.enable_start_tls()
///        .enable_auth(AuthMechanism::Plain);
/// // Then when a client connects
/// let mut session = builder.build(addr, handler);
///
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
    pub fn build<H: Handler>(&self, remote: IpAddr, handler: H) -> Session<H> {
        Session {
            name: self.name.clone(),
            handler,
            fsm: StateMachine::new(remote, &self.auth_mechanisms, self.start_tls_extension),
            start_tls_extension: self.start_tls_extension,
            auth_mechanisms: self.auth_mechanisms.clone(),
        }
    }
}

impl<H: Handler> Session<H> {
    /// Get a greeting to send to the client
    pub fn greeting(&self) -> Response {
        Response::dynamic(220, format!("{} ESMTP", self.name), Vec::new())
    }

    /// STARTTLS active
    pub fn tls_active(&mut self) {
        self.start_tls_extension = false;
        self.command(Cmd::StartedTls);
    }

    /// Process a line sent by the client.
    ///
    /// Returns a response that should be written back to the client.
    ///
    /// # Examples
    /// ```
    /// use mailin::{Session, SessionBuilder, Handler, Action};
    ///
    /// # use std::net::{IpAddr, Ipv4Addr};
    /// # struct EmptyHandler{};
    /// # impl Handler for EmptyHandler{};
    /// # let addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    /// # let handler = EmptyHandler{};
    /// # let mut session = SessionBuilder::new("name").build(addr, handler);
    /// let response = session.process(b"HELO example.com\r\n");
    ///
    /// // Check the response
    /// assert_eq!(response.is_error, false);
    /// assert_eq!(response.action, Action::Reply);
    ///
    /// // Write the response
    /// let mut msg = Vec::new();
    /// response.write_to(&mut msg);
    /// assert_eq!(&msg, b"250 OK\r\n");
    /// ```
    pub fn process(&mut self, line: &[u8]) -> Response {
        let response = match self.fsm.process_line(line) {
            Left(cmd) => {
                let res = self.command(cmd);
                self.fill_response(res)
            }
            Right(res) => res,
        };
        response.log();
        response
    }

    fn command(&mut self, cmd: Cmd) -> Response {
        self.fsm.command(&mut self.handler, cmd)
    }

    fn fill_response(&self, res: Response) -> Response {
        ternary!(res.ehlo_ok, self.ehlo_response(), res)
    }

    fn ehlo_response(&self) -> Response {
        let mut extensions = vec!["8BITMIME"];
        if self.start_tls_extension {
            extensions.push("STARTTLS");
        } else {
            for auth in &self.auth_mechanisms {
                extensions.push(auth.extension());
            }
        }
        Response::dynamic(250, format!("{} offers extensions:", self.name), extensions)
    }
}

//----- Tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsm::SmtpState;
    use crate::{Action, AuthResult, Message};
    use std::net::Ipv4Addr;

    struct EmptyHandler {}
    impl Handler for EmptyHandler {}

    // Check that the state machine matches the given state pattern
    macro_rules! assert_state {
        ($val:expr, $n:pat ) => {{
            assert!(
                match $val {
                    $n => true,
                    _ => false,
                },
                "{:?} !~ {}",
                $val,
                stringify!($n)
            )
        }};
    }

    fn new_session() -> Session<EmptyHandler> {
        let addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        SessionBuilder::new("some.name").build(addr, EmptyHandler {})
    }

    #[test]
    fn helo_ehlo() {
        let mut session = new_session();
        let res1 = session.process(b"helo a.domain\r\n");
        assert_eq!(res1.code, 250);
        assert_state!(session.fsm.current_state(), SmtpState::Hello);
        let res2 = session.process(b"ehlo b.domain\r\n");
        assert_eq!(res2.code, 250);
        assert_state!(session.fsm.current_state(), SmtpState::Hello);
    }

    #[test]
    fn mail_from() {
        let mut session = new_session();
        session.process(b"helo a.domain\r\n");
        let res = session.process(b"mail from:<ship@sea.com>\r\n");
        assert_eq!(res.code, 250);
        assert_state!(session.fsm.current_state(), SmtpState::Mail);
    }

    #[test]
    fn domain_badchars() {
        let mut session = new_session();
        let res = session.process(b"helo world\x40\xff\r\n");
        assert_eq!(res.code, 500);
        assert_state!(session.fsm.current_state(), SmtpState::Idle);
    }

    #[test]
    fn rcpt_to() {
        let mut session = new_session();
        session.process(b"helo a.domain\r\n");
        session.process(b"mail from:<ship@sea.com>\r\n");
        let res1 = session.process(b"rcpt to:<fish@sea.com>\r\n");
        assert_eq!(res1.code, 250);
        let res2 = session.process(b"rcpt to:<kraken@sea.com>\r\n");
        assert_eq!(res2.code, 250);
        assert_state!(session.fsm.current_state(), SmtpState::Rcpt);
    }

    #[test]
    fn data() {
        let mut session = new_session();
        session.process(b"helo a.domain\r\n");
        session.process(b"mail from:<ship@sea.com>\r\n");
        session.process(b"rcpt to:<fish@sea.com>\r\n");
        let res1 = session.process(b"data\r\n");
        assert_eq!(res1.code, 354);
        let res2 = session.process(b"Hello World\r\n");
        assert_eq!(res2.action, Action::NoReply);
        let res3 = session.process(b".\r\n");
        assert_eq!(res3.code, 250);
        assert_state!(session.fsm.current_state(), SmtpState::Hello);
    }

    #[test]
    fn data_8bit() {
        let mut session = new_session();
        session.process(b"helo a.domain\r\n");
        session.process(b"mail from:<ship@sea.com> body=8bitmime\r\n");
        session.process(b"rcpt to:<fish@sea.com>\r\n");
        let res1 = session.process(b"data\r\n");
        assert_eq!(res1.code, 354);
        // Send illegal utf-8 but valid 8bit mime
        let res2 = session.process(b"Hello 8bit world \x40\x7f\r\n");
        assert_eq!(res2.action, Action::NoReply);
        let res3 = session.process(b".\r\n");
        assert_eq!(res3.code, 250);
        assert_state!(session.fsm.current_state(), SmtpState::Hello);
    }

    #[test]
    fn rset_hello() {
        let mut session = new_session();
        session.process(b"helo some.domain\r\n");
        session.process(b"mail from:<ship@sea.com>\r\n");
        let res = session.process(b"rset\r\n");
        assert_eq!(res.code, 250);
        assert_state!(session.fsm.current_state(), SmtpState::Hello);
    }

    #[test]
    fn rset_idle() {
        let mut session = new_session();
        let res = session.process(b"rset\r\n");
        assert_eq!(res.code, 250);
        assert_state!(session.fsm.current_state(), SmtpState::Idle);
    }

    #[test]
    fn quit() {
        let mut session = new_session();
        session.process(b"helo a.domain\r\n");
        session.process(b"mail from:<ship@sea.com>\r\n");
        let res = session.process(b"quit\r\n");
        assert_eq!(res.code, 221);
        assert_eq!(res.action, Action::Close);
        assert_state!(session.fsm.current_state(), SmtpState::Invalid);
    }

    #[test]
    fn vrfy() {
        let mut session = new_session();
        session.process(b"helo a.domain\r\n");
        let res1 = session.process(b"vrfy kraken\r\n");
        assert_eq!(res1.code, 252);
        assert_state!(session.fsm.current_state(), SmtpState::Hello);
        session.process(b"mail from:<ship@sea.com>\r\n");
        let res2 = session.process(b"vrfy boat\r\n");
        assert_eq!(res2.code, 503);
        assert_state!(session.fsm.current_state(), SmtpState::Mail);
    }

    struct AuthHandler {}
    impl Handler for AuthHandler {
        fn auth_plain(
            &mut self,
            authorization_id: &str,
            authentication_id: &str,
            password: &str,
        ) -> AuthResult {
            ternary!(
                authorization_id == "test" && authentication_id == "test" && password == "1234",
                AuthResult::Ok,
                AuthResult::InvalidCredentials
            )
        }
    }

    fn new_auth_session(with_start_tls: bool) -> Session<AuthHandler> {
        let addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let mut builder = SessionBuilder::new("some.domain");
        builder.enable_auth(AuthMechanism::Plain);
        if with_start_tls {
            builder.enable_start_tls();
        }
        builder.build(addr, AuthHandler {})
    }

    fn start_tls(session: &mut Session<AuthHandler>) {
        let res = session.process(b"ehlo a.domain\r\n");
        assert_eq!(res.code, 250);
        assert_state!(session.fsm.current_state(), SmtpState::HelloAuth);
        let res = session.process(b"starttls\r\n");
        assert_eq!(res.code, 220);
        session.tls_active();
    }

    #[test]
    fn noauth_denied() {
        let mut session = new_auth_session(true);
        session.process(b"ehlo a.domain\r\n");
        let res = session.process(b"mail from:<ship@sea.com>\r\n");
        assert_eq!(res.code, 503);
        assert_state!(session.fsm.current_state(), SmtpState::HelloAuth);
    }

    #[test]
    fn auth_plain_param() {
        let mut session = new_auth_session(true);
        start_tls(&mut session);
        let mut res = session.process(b"ehlo a.domain\r\n");
        assert_eq!(res.code, 250);
        assert_state!(session.fsm.current_state(), SmtpState::HelloAuth);
        res = session.process(b"auth plain dGVzdAB0ZXN0ADEyMzQ=\r\n");
        assert_eq!(res.code, 235);
        assert_state!(session.fsm.current_state(), SmtpState::Hello);
    }

    #[test]
    fn bad_auth_plain_param() {
        let mut session = new_auth_session(true);
        start_tls(&mut session);
        let mut res = session.process(b"ehlo a.domain\r\n");
        assert_eq!(res.code, 250);
        assert_state!(session.fsm.current_state(), SmtpState::HelloAuth);
        res = session.process(b"auth plain eGVzdAB0ZXN0ADEyMzQ=\r\n");
        assert_eq!(res.code, 535);
        assert_state!(session.fsm.current_state(), SmtpState::HelloAuth);
    }

    #[test]
    fn auth_plain_challenge() {
        let mut session = new_auth_session(true);
        start_tls(&mut session);
        let res = session.process(b"ehlo a.domain\r\n");
        assert_eq!(res.code, 250);
        assert_state!(session.fsm.current_state(), SmtpState::HelloAuth);
        let res = session.process(b"auth plain\r\n");
        assert_eq!(res.code, 334);
        match res.message {
            Message::Fixed("") => {}
            _ => assert!(false, "Server did not send empty challenge"),
        };
        assert_state!(session.fsm.current_state(), SmtpState::Auth);
        let res = session.process(b"dGVzdAB0ZXN0ADEyMzQ=\r\n");
        assert_eq!(res.code, 235);
        assert_state!(session.fsm.current_state(), SmtpState::Hello);
    }

    #[test]
    fn auth_without_tls() {
        let mut session = new_auth_session(true);
        let mut res = session.process(b"ehlo a.domain\r\n");
        assert_eq!(res.code, 250);
        assert_state!(session.fsm.current_state(), SmtpState::HelloAuth);
        res = session.process(b"auth plain dGVzdAB0ZXN0ADEyMzQ=\r\n");
        assert_eq!(res.code, 503);
    }

    #[test]
    fn bad_auth_plain_challenge() {
        let mut session = new_auth_session(true);
        start_tls(&mut session);
        session.process(b"ehlo a.domain\r\n");
        session.process(b"auth plain\r\n");
        let res = session.process(b"eGVzdAB0ZXN0ADEyMzQ=\r\n");
        assert_eq!(res.code, 535);
        assert_state!(session.fsm.current_state(), SmtpState::HelloAuth);
    }

    #[test]
    fn rset_with_auth() {
        let mut session = new_auth_session(true);
        start_tls(&mut session);
        let res = session.process(b"ehlo some.domain\r\n");
        assert_eq!(res.code, 250);
        let res = session.process(b"auth plain dGVzdAB0ZXN0ADEyMzQ=\r\n");
        assert_eq!(res.code, 235);
        let res = session.process(b"mail from:<ship@sea.com>\r\n");
        assert_eq!(res.code, 250);
        let res = session.process(b"rset\r\n");
        assert_eq!(res.code, 250);
        assert_state!(session.fsm.current_state(), SmtpState::HelloAuth);
    }

}
