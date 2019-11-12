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

pub struct Credentials {
    pub authorization_id: String,
    pub authentication_id: String,
    pub password: String,
}
