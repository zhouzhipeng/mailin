#[derive(Debug, Clone)]
/// Supported authentication mechanisms
pub enum AuthMechanism {
    /// Plain user/password over TLS
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
