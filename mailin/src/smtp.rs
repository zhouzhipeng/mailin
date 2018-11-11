use std::net::IpAddr;
use std::str;

use fsm::{StateMachine, States};
use parser::parse;
use {Action, Handler, Response};

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
pub enum Cmd<'a> {
    Ehlo(EhloCmd<'a>),
    Helo(HeloCmd<'a>),
    Mail(MailCmd<'a>),
    Rcpt(RcptCmd<'a>),
    Data(DataCmd),
    Rset(RsetCmd),
    Noop(NoopCmd),
    StartTls(StartTlsCmd),
    Quit(QuitCmd),
    Vrfy(VrfyCmd),
    AuthPlain(AuthPlainCmd),
    AuthPlainEmpty(AuthPlainEmptyCmd),
    AuthResponse(AuthResponseCmd<'a>), // Dummy command containing client authentication
    DataEnd(DataEndCmd),               // Dummy command to signify end of data
}

pub struct EhloCmd<'a> {
    pub domain: &'a str,
}

pub struct HeloCmd<'a> {
    pub domain: &'a str,
}

pub struct MailCmd<'a> {
    pub reverse_path: &'a str,
    pub is8bit: bool,
}

pub struct RcptCmd<'a> {
    pub forward_path: &'a str,
}

pub struct AuthPlainCmd {
    pub authorization_id: String,
    pub authentication_id: String,
    pub password: String,
}

pub struct AuthResponseCmd<'a> {
    pub response: &'a [u8],
}

// Empty types needed by state machine
pub struct DataCmd {}
pub struct RsetCmd {}
pub struct NoopCmd {}
pub struct StartTlsCmd {}
pub struct QuitCmd {}
pub struct VrfyCmd {}
pub struct DataEndCmd {}
pub struct AuthPlainEmptyCmd {}

/// A single smtp session
pub struct Session<H: Handler> {
    name: String,
    handler: H,
    fsm: StateMachine,
    start_tls_extension: bool,
    auth_extension: bool,
}

#[derive(Clone)]
/// Builds smtp sessions.
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
/// // Create a session builder that holds the configuration
/// let mut builder = SessionBuilder::new("server_name");
/// builder.enable_start_tls()
///        .enable_auth();
/// // Then when a client connects
/// let mut session = builder.build(addr, handler);
///
pub struct SessionBuilder {
    name: String,
    start_tls_extension: bool,
    auth_extension: bool,
}

impl SessionBuilder {
    pub fn new<S: Into<String>>(name: S) -> Self {
        Self {
            name: name.into(),
            start_tls_extension: false,
            auth_extension: false,
        }
    }

    pub fn enable_start_tls(&mut self) -> &mut Self {
        let ret = self;
        ret.start_tls_extension = true;
        ret
    }

    pub fn enable_auth(&mut self) -> &mut Self {
        let ret = self;
        ret.auth_extension = true;
        ret
    }

    pub fn build<H: Handler>(&self, remote: IpAddr, handler: H) -> Session<H> {
        Session {
            name: self.name.clone(),
            handler,
            fsm: StateMachine::new(remote, self.start_tls_extension, self.auth_extension),
            start_tls_extension: self.start_tls_extension,
            auth_extension: self.auth_extension,
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
        self.fsm.enable_tls();
    }

    /// Process a line sent by the client.
    ///
    /// The parser assumes that the line does not contain the `\r\n` line ending.
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
    /// let response = session.process(b"HELO example.com");
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
        let response = match *self.fsm.current_state() {
            States::Data { .. } if line == b"." => {
                trace!("> _data_");
                self.command(Cmd::DataEnd(DataEndCmd {}))
            }
            States::Data { .. } => self.fsm.data(line),
            States::Auth { .. } => {
                self.command(Cmd::AuthResponse(AuthResponseCmd { response: line }))
            }
            States::Invalid => INVALID_STATE.clone(),
            _ => {
                trace!("> {}", String::from_utf8_lossy(line));
                match parse(line) {
                    Ok(cmd) => {
                        let res = self.command(cmd);
                        self.fill_response(res)
                    }
                    Err(err) => err,
                }
            }
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
        } else if self.auth_extension {
            extensions.push("AUTH PLAIN");
        }
        Response::dynamic(250, format!("{} offers extensions:", self.name), extensions)
    }
}

//----- Tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use {Action, AuthResult, Message};

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
        let res1 = session.process(b"helo a.domain");
        assert_eq!(res1.code, 250);
        assert_state!(session.fsm.current_state(), &States::Helo(_));
        let res2 = session.process(b"ehlo b.domain");
        assert_eq!(res2.code, 250);
        assert_state!(session.fsm.current_state(), &States::Helo(_));
    }

    #[test]
    fn mail_from() {
        let mut session = new_session();
        session.process(b"helo a.domain");
        let res = session.process(b"mail from:<ship@sea.com>");
        assert_eq!(res.code, 250);
        assert_state!(session.fsm.current_state(), &States::Mail(_));
    }

    #[test]
    fn domain_badchars() {
        let mut session = new_session();
        let res = session.process(b"helo world\x40\xff");
        assert_eq!(res.code, 500);
        assert_state!(session.fsm.current_state(), &States::Idle(_));
    }

    #[test]
    fn rcpt_to() {
        let mut session = new_session();
        session.process(b"helo a.domain");
        session.process(b"mail from:<ship@sea.com>");
        let res1 = session.process(b"rcpt to:<fish@sea.com>");
        assert_eq!(res1.code, 250);
        let res2 = session.process(b"rcpt to:<kraken@sea.com>");
        assert_eq!(res2.code, 250);
        assert_state!(session.fsm.current_state(), &States::Rcpt(_));
    }

    #[test]
    fn data() {
        let mut session = new_session();
        session.process(b"helo a.domain");
        session.process(b"mail from:<ship@sea.com>");
        session.process(b"rcpt to:<fish@sea.com>");
        let res1 = session.process(b"data");
        assert_eq!(res1.code, 354);
        let res2 = session.process(b"Hello World");
        assert_eq!(res2.action, Action::NoReply);
        let res3 = session.process(b".");
        assert_eq!(res3.code, 250);
        assert_state!(session.fsm.current_state(), &States::Helo(_));
    }

    #[test]
    fn data_8bit() {
        let mut session = new_session();
        session.process(b"helo a.domain");
        session.process(b"mail from:<ship@sea.com> body=8bitmime");
        session.process(b"rcpt to:<fish@sea.com>");
        let res1 = session.process(b"data");
        assert_eq!(res1.code, 354);
        // Send illegal utf-8 but valid 8bit mime
        let res2 = session.process(b"Hello 8bit world \x40\x7f");
        assert_eq!(res2.action, Action::NoReply);
        let res3 = session.process(b".");
        assert_eq!(res3.code, 250);
        assert_state!(session.fsm.current_state(), &States::Helo(_));
    }

    #[test]
    fn rset() {
        let mut session = new_session();
        session.process(b"helo some.domain");
        session.process(b"mail from:<ship@sea.com>");
        let res = session.process(b"rset");
        assert_eq!(res.code, 250);
        assert_state!(session.fsm.current_state(), &States::Helo(_));
    }

    #[test]
    fn quit() {
        let mut session = new_session();
        session.process(b"helo a.domain");
        session.process(b"mail from:<ship@sea.com>");
        let res = session.process(b"quit");
        assert_eq!(res.code, 221);
        assert_eq!(res.action, Action::Close);
        assert_state!(session.fsm.current_state(), &States::Invalid);
    }

    #[test]
    fn vrfy() {
        let mut session = new_session();
        session.process(b"helo a.domain");
        let res1 = session.process(b"vrfy kraken");
        assert_eq!(res1.code, 252);
        assert_state!(session.fsm.current_state(), &States::Helo(_));
        session.process(b"mail from:<ship@sea.com>");
        let res2 = session.process(b"vrfy boat");
        assert_eq!(res2.code, 503);
        assert_state!(session.fsm.current_state(), &States::Mail(_));
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

    fn new_auth_session() -> Session<AuthHandler> {
        let addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        SessionBuilder::new("some.domain")
            .enable_auth()
            .build(addr, AuthHandler {})
    }

    #[test]
    fn auth_plain_param() {
        let mut session = new_auth_session();
        let mut res = session.process(b"ehlo a.domain");
        assert_eq!(res.code, 250);
        assert_state!(session.fsm.current_state(), &States::HeloAuth(_));
        res = session.process(b"auth plain dGVzdAB0ZXN0ADEyMzQ=");
        assert_eq!(res.code, 235);
        assert_state!(session.fsm.current_state(), &States::Helo(_));
    }

    #[test]
    fn bad_auth_plain_param() {
        let mut session = new_auth_session();
        let mut res = session.process(b"ehlo a.domain");
        assert_eq!(res.code, 250);
        assert_state!(session.fsm.current_state(), &States::HeloAuth(_));
        res = session.process(b"auth plain eGVzdAB0ZXN0ADEyMzQ=");
        assert_eq!(res.code, 535);
        assert_state!(session.fsm.current_state(), &States::HeloAuth(_));
    }

    #[test]
    fn auth_plain_challenge() {
        let mut session = new_auth_session();
        let mut res = session.process(b"ehlo a.domain");
        assert_eq!(res.code, 250);
        assert_state!(session.fsm.current_state(), &States::HeloAuth(_));
        res = session.process(b"auth plain");
        assert_eq!(res.code, 334);
        match res.message {
            Message::Fixed("") => {}
            _ => assert!(false, "Server did not send empty challenge"),
        };
        assert_state!(session.fsm.current_state(), &States::Auth(_));
        res = session.process(b"dGVzdAB0ZXN0ADEyMzQ=");
        assert_eq!(res.code, 235);
        assert_state!(session.fsm.current_state(), &States::Helo(_));
    }

    #[test]
    fn bad_auth_plain_challenge() {
        let mut session = new_auth_session();
        session.process(b"ehlo a.domain");
        session.process(b"auth plain");
        let res = session.process(b"eGVzdAB0ZXN0ADEyMzQ=");
        assert_eq!(res.code, 535);
        assert_state!(session.fsm.current_state(), &States::HeloAuth(_));
    }

}
