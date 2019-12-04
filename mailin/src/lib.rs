//! A library for building smtp servers.
//!
//! The library supplies a parser and SMTP state machine. The user of the library
//! supplies I/O code and controls state changes of the SMTP session.
//!
//! The code using the library, sends
//! lines received to the `Session.process()` method. The user matches the returned
//! `Event` and makes decisions on whether to accept or reject email
//! messages. The resulting response can be sent back to the email client.
//!
//! # Examples
//! ```rust,no_run
//! # use mailin::{Session, SessionBuilder, Action, AuthMechanism, Event, State};
//!
//! # use std::net::{IpAddr, Ipv4Addr};
//! # let addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
//! // Create a session builder that holds the configuration
//! let mut builder = SessionBuilder::new("server_name");
//! builder.enable_start_tls()
//!        .enable_auth(AuthMechanism::Plain);
//! // Then when a client connects
//! let mut session = builder.build(addr);
//! // Process lines sent from the client
//! let response = match session.process(b"HELO some.domain\r\n") {
//!     // Act on events returned by the session
//!     Event::ChangeState(State::Hello(hello)) => hello.ok(&mut session),
//!     Event::ChangeState(st) => st.ok(&mut session),
//!     Event::SendResponse(r) => r,
//! };
//! // Then send the response back to the client
//! ```

#![forbid(unsafe_code)]
// #![forbid(missing_docs)]

mod auth;
mod cmd;
mod parser;
mod response;
mod session;
mod state;

pub use crate::auth::AuthMechanism;
pub use crate::response::{Action, Response};
pub use crate::session::{Event, Session, SessionBuilder};
pub use crate::state::{Hello, Idle, Mail, State};
