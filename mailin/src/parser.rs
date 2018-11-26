use base64;
use nom;
use nom::types::CompleteByteSlice;
use nom::{is_alphanumeric, space};

use smtp::{Cmd, Credentials, MISSING_PARAMETER, SYNTAX_ERROR};
use std::str;
use Response;

//----- Parser -----------------------------------------------------------------

// Parse a line from the client
pub fn parse(line: &[u8]) -> Result<Cmd, Response> {
    command(CompleteByteSlice(line))
        .map(|r| r.1)
        .map_err(|e| match e {
            nom::Err::Incomplete(_) => MISSING_PARAMETER.clone(),
            nom::Err::Error(_) => SYNTAX_ERROR.clone(),
            nom::Err::Failure(_) => SYNTAX_ERROR.clone(),
        })
}

named!(command(CompleteByteSlice) -> Cmd,
       terminated!(
           alt!(helo | ehlo | mail | rcpt | data | rset | quit |
                vrfy | noop | starttls | auth),
           eof!()
       )
);

named!(hello_domain(CompleteByteSlice) -> &str,
       map_res!(is_not!(" \t\r\n"), from_utf8)
);

named!(helo(CompleteByteSlice) -> Cmd,
       do_parse!(
           tag_no_case!("helo") >>
               space >>
               domain: hello_domain >>
               (Cmd::Helo{domain})
       )
);

named!(ehlo(CompleteByteSlice) -> Cmd,
       do_parse!(
           tag_no_case!("ehlo") >>
               space >>
               domain: hello_domain >>
               (Cmd::Ehlo{domain})
       )
);

//TODO: check grammar in RFC
named!(mail_path(CompleteByteSlice) -> &str,
       map_res!(is_not!(" <>\t\r\n"), from_utf8)
);

named!(take_all(CompleteByteSlice) -> &str,
       map_res!(is_not!("\r\n"), from_utf8)
);

named!(body_eq_8bit(CompleteByteSlice) -> bool,
       do_parse!(
           space >>
           tag_no_case!("body=") >>
           is8bit: alt!(value!(true, tag_no_case!("8bitmime")) |
                        value!(false, tag_no_case!("7bit"))) >>
           (is8bit)
       )
);

named!(is8bitmime(CompleteByteSlice) -> bool,
       alt!(value!(false, eof!()) | body_eq_8bit)
);

named!(mail(CompleteByteSlice) -> Cmd,
       do_parse!(
           tag_no_case!("mail") >>
               space >>
               tag_no_case!("from:<") >>
               path: mail_path >>
               tag!(">") >>
               is8bit: is8bitmime >>
               (Cmd::Mail{reverse_path: path, is8bit})
       )
);

named!(rcpt(CompleteByteSlice) -> Cmd,
       do_parse!(
           tag_no_case!("rcpt") >>
               space >>
               tag_no_case!("to:<") >>
               path: mail_path >>
               tag!(">") >>
               (Cmd::Rcpt{forward_path: path})
       )
);

named!(data(CompleteByteSlice) -> Cmd,
       do_parse!(
           tag_no_case!("data") >>
               (Cmd::Data)
       )
);

named!(rset(CompleteByteSlice) -> Cmd,
       do_parse!(
           tag_no_case!("rset") >>
               (Cmd::Rset)
       )
);

named!(quit(CompleteByteSlice) -> Cmd,
       do_parse!(
           tag_no_case!("quit") >>
               (Cmd::Quit)
       )
);

named!(vrfy(CompleteByteSlice) -> Cmd,
       do_parse!(
           tag_no_case!("vrfy") >>
               space >>
               take_all >>
               (Cmd::Vrfy)
       )
);

named!(noop(CompleteByteSlice) -> Cmd,
       do_parse!(
           tag_no_case!("noop") >>
               (Cmd::Noop)
       )
);

named!(starttls(CompleteByteSlice) -> Cmd,
       do_parse!(
           tag_no_case!("starttls") >>
               (Cmd::StartTls)
       )
);

fn is_base64(chr: u8) -> bool {
    is_alphanumeric(chr) || (chr == b'+') || (chr == b'/' || chr == b'=')
}

named!(auth_initial(CompleteByteSlice) -> &[u8],
       do_parse!(
           space >>
               initial: take_while!(is_base64) >>
               (*initial)
       )
);

named!(empty(CompleteByteSlice) -> &[u8],
       value!(b"" as &[u8], eof!())
);

named!(auth_plain(CompleteByteSlice) -> Cmd,
       do_parse!(
           tag_no_case!("plain") >>
               initial: alt!(empty | auth_initial) >>
               (sasl_plain_cmd(initial))
       )
);

named!(auth(CompleteByteSlice) -> Cmd,
       do_parse!(
          tag_no_case!("auth") >>
               space >>
               cmd: auth_plain >>
               (cmd)
       )
);

//---- Helper functions ---------------------------------------------------------

fn from_utf8(i: CompleteByteSlice) -> Result<&str, str::Utf8Error> {
    str::from_utf8(*i)
}

fn sasl_plain_cmd(param: &[u8]) -> Cmd {
    if param.is_empty() {
        Cmd::AuthPlainEmpty
    } else {
        let creds = decode_sasl_plain(param);
        Cmd::AuthPlain {
            authorization_id: creds.authorization_id,
            authentication_id: creds.authentication_id,
            password: creds.password,
        }
    }
}

// Decodes the base64 encoded plain authentication parameter
pub(crate) fn decode_sasl_plain(param: &[u8]) -> Credentials {
    let decoded = base64::decode(param);
    if let Ok(bytes) = decoded {
        let mut fields = bytes.split(|b| b == &0u8);
        let authorization_id = next_string(&mut fields);
        let authentication_id = next_string(&mut fields);
        let password = next_string(&mut fields);
        Credentials {
            authorization_id,
            authentication_id,
            password,
        }
    } else {
        Credentials {
            authorization_id: String::default(),
            authentication_id: String::default(),
            password: String::default(),
        }
    }
}

fn next_string(it: &mut Iterator<Item = &[u8]>) -> String {
    it.next()
        .map(|s| str::from_utf8(s).unwrap_or_default())
        .unwrap_or_default()
        .to_owned()
}

//---- Tests --------------------------------------------------------------------

mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn auth_initial() {
        let res = parse(b"auth plain dGVzdAB0ZXN0ADEyMzQ=");
        match res {
            Ok(Cmd::AuthPlain {
                authorization_id,
                authentication_id,
                password,
            }) => {
                assert_eq!(authorization_id, "test");
                assert_eq!(authentication_id, "test");
                assert_eq!(password, "1234");
            }
            _ => assert!(false, "Auth plain with initial response incorrectly parsed"),
        };
    }

    #[test]
    fn auth_empty() {
        let res = parse(b"auth plain");
        match res {
            Ok(Cmd::AuthPlainEmpty) => {}
            _ => assert!(
                false,
                "Auth plain without initial response incorrectly parsed"
            ),
        };
    }

}
