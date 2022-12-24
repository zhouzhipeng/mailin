use nom::{
    branch::alt,
    bytes::complete::{tag, tag_no_case, take_while1},
    combinator::map,
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

fn helo(buf: &[u8]) -> IResult<&[u8], Command> {
    let parse_domain = preceded(cmd(b"helo"), domain);
    map(parse_domain, |d| Command::Helo { domain: d })(buf)
}

fn ehlo(buf: &[u8]) -> IResult<&[u8], Command> {
    let parse_domain = preceded(cmd(b"ehlo"), domain);
    map(parse_domain, |d| Command::Helo { domain: d })(buf)
}

// TODO: can this really be a str?
fn domain(buf: &[u8]) -> IResult<&[u8], &str> {
    todo!()
}

//---- Helper functions ---------------------------------------------------------

// TODO: Check against spec
// Return a parser to match the given command
fn cmd(cmd_tag: &[u8]) -> impl Fn(&[u8]) -> IResult<&[u8], (&[u8], &[u8])> + '_ {
    move |buf: &[u8]| -> Result<(&[u8], (&[u8], &[u8])), nom::Err<nom::error::Error<&[u8]>>> {
        pair(tag_no_case(cmd_tag), space)(buf)
    }
}

// TODO: Check against spec
// Match one or more spaces
fn space(buf: &[u8]) -> IResult<&[u8], &[u8]> {
    take_while1(|b| b == b' ')(buf)
}
