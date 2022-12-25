use nom::{
    branch::alt,
    bytes::complete::{tag, tag_no_case, take_while1},
    combinator::{map, opt},
    multi::separated_list1,
    sequence::{pair, preceded, terminated},
    IResult,
};
use snafu::prelude::*;

use crate::types::Command;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Line incomplete: {}", line))]
    Incomplete { line: String },
    #[snafu(display("Syntax error: {}", line))]
    Syntax { line: String },
}

pub fn parse_command(line: &[u8]) -> Result<Command, Error> {
    command(line).map(|r| r.1).map_err(|e| match e {
        nom::Err::Incomplete(_) => Error::Incomplete {
            line: copy_line(line),
        },
        nom::Err::Error(_) | nom::Err::Failure(_) => Error::Syntax {
            line: copy_line(line),
        },
    })
}

fn copy_line(line: &[u8]) -> String {
    String::from_utf8_lossy(line).into_owned()
}

fn command(buf: &[u8]) -> IResult<&[u8], Command> {
    terminated(alt((helo, ehlo)), tag(b"\r\n"))(buf)
}

// helo = "HELO" SP Domain CRLF
fn helo(buf: &[u8]) -> IResult<&[u8], Command> {
    let parse_domain = preceded(cmd(b"helo"), domain);
    map(parse_domain, |d| Command::Helo { domain: d })(buf)
}

// ehlo = "EHLO" SP ( Domain / address-literal ) CRLF
fn ehlo(buf: &[u8]) -> IResult<&[u8], Command> {
    let parse_domain = preceded(cmd(b"ehlo"), domain);
    map(parse_domain, |d| Command::Helo { domain: d })(buf)
}

// domain <- subdomain ( '.' subdomain )*
fn domain(buf: &[u8]) -> IResult<&[u8], Vec<u8>> {
    let parser = separated_list1(tag(b"."), subdomain);
    map(parser, |v| v.join(b".".as_slice()))(buf)
}

// sub-domain = ( Let-dig [Ldh-str] ) / U-label
// U-label is currently a superset of the ascii subdomain
fn subdomain(buf: &[u8]) -> IResult<&[u8], Vec<u8>> {
    ulabel(buf)
}

fn ulabel(buf: &[u8]) -> IResult<&[u8], Vec<u8>> {
    let parser = pair(uletterdigit, opt(uldhstr));
    map(parser, |(f, o)| [f, o.unwrap_or_default()].concat())(buf)
}

// Unicode version of:
// letDig <- alpha / digit
fn uletterdigit(buf: &[u8]) -> IResult<&[u8], &[u8]> {
    todo!()
}

// Unicode version of:
// Ldh-str = *( ALPHA / DIGIT / "-" ) Let-dig
fn uldhstr(buf: &[u8]) -> IResult<&[u8], &[u8]> {
    todo!()
}

//---- Helper functions ---------------------------------------------------------

// Return a parser to match the given command
fn cmd(cmd_tag: &[u8]) -> impl Fn(&[u8]) -> IResult<&[u8], &[u8]> + '_ {
    move |buf: &[u8]| terminated(tag(cmd_tag), space)(buf)
}

// Match one or more spaces
fn space(buf: &[u8]) -> IResult<&[u8], &[u8]> {
    take_while1(|b| b == b' ')(buf)
}
