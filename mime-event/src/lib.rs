pub use crate::header::Header;
use crate::header_buffer::HeaderBuffer;
use display_bytes::display_bytes;
use std::collections::HashMap;
use std::fmt;
use std::io;
use std::io::Write;
use std::str;

mod header;
mod header_buffer;
mod parser;

/// Events sent to a Handler
#[derive(Debug, PartialEq)]
pub enum Event<'a> {
    /// Parsing has Started
    Start,
    /// Header line
    Header(Header<'a>),
    /// Start of a MIME multipart entity
    MultipartStart(Multipart),
    /// Start of a MIME mulitpart part
    PartStart { offset: usize },
    /// A line of an email body
    Body(&'a [u8]),
    /// End of a MIME mulitpart part
    PartEnd { offset: usize },
    /// End of a MIME multipart entity
    MultipartEnd,
    /// Parsing has finished
    End,
}

impl<'a> fmt::Display for Event<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Event::Header(header) => write!(f, "Header {}", header),
            Event::Body(block) => write!(f, "Body {{{}}}", display_bytes(block)),
            _ => write!(f, "{:?}", &self),
        }
    }
}

/// A Handler receives parser events
pub trait Handler {
    fn event<'a>(&mut self, ev: Event<'a>);
}

/// A MIME type
#[derive(Debug, Clone)]
pub enum Mime {
    /// A multipart MIME type
    Multipart(Multipart),
    /// Not a multipart MIME type
    Type(Vec<u8>),
}

/// Multipart MIME types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Multipart {
    Alternative,
    Mixed,
    Digest,
}

#[derive(Clone, Copy, Debug)]
enum State {
    Start,
    Header,
    MultipartHeader,
    MultipartPreamble,
    PartStart,
    Body,
}

struct MultipartState {
    content_type: Multipart,
    boundary: Vec<u8>,
}

/// EmailParser is an event driven email parser.
pub struct EmailParser<W: Write, H: Handler> {
    writer: W,
    state: State,
    offset: usize,
    handler: H,
    content_type: Mime,
    boundary: Option<Vec<u8>>,
    multipart_stack: Vec<MultipartState>,
    header_buffer: HeaderBuffer,
}

impl<W: Write, H: Handler> EmailParser<W, H> {
    /// Create a new EmailParser.
    /// Writing to the EmailParser will write to the writer.
    /// Writing to the EmailParser will produce events that are sent to the handler.
    pub fn new(writer: W, handler: H) -> Self {
        Self {
            writer,
            state: State::Start,
            offset: 0,
            handler,
            content_type: Mime::Type(b"text/plain".to_vec()),
            boundary: None,
            multipart_stack: Vec::default(),
            header_buffer: HeaderBuffer::default(),
        }
    }

    fn is_open_boundary(&self, buf: &[u8]) -> bool {
        self.boundary
            .as_ref()
            .filter(|b| buf.starts_with(b))
            .is_some()
    }

    fn is_close_boundary(&self, buf: &[u8]) -> bool {
        self.boundary
            .as_ref()
            .filter(|b| {
                let end = b.len();
                buf.starts_with(b) && buf.len() > end + 2 && buf.ends_with(b"--\r\n")
            })
            .is_some()
    }

    fn header_field(&mut self, buf: &[u8], state: State) -> io::Result<State> {
        if buf.starts_with(b"\r\n") {
            self.state = match state {
                State::MultipartHeader => State::MultipartPreamble,
                _ => State::Body,
            };
            Ok(self.state)
        } else {
            let token = parser::header(&buf)?;
            if let Header::ContentType {
                mime_type: mtype,
                parameters: params,
            } = token.clone()
            {
                self.content_type(mtype, params);
            }
            self.handler.event(Event::Header(token));
            if let Mime::Multipart(_) = self.content_type {
                Ok(State::MultipartHeader)
            } else {
                Ok(state)
            }
        }
    }

    // Handle Content-Type headers
    fn content_type(&mut self, mtype: &[u8], params: HashMap<&[u8], Vec<u8>>) {
        if let (Mime::Multipart(m), Some(b)) = (&self.content_type, &self.boundary) {
            self.multipart_stack.push(MultipartState {
                content_type: m.clone(),
                boundary: b.clone(),
            })
        }
        self.content_type = mime_type(mtype);
        if let Mime::Multipart(_) = &self.content_type {
            self.boundary = params.get(&(b"boundary")[..]).map(|boundary| {
                let mut full = b"--".to_vec();
                full.extend_from_slice(boundary);
                full
            });
        }
    }

    // Called when data is written to the writer
    fn handle_write(&mut self, buf: &[u8]) -> io::Result<()> {
        self.writer.write_all(buf)?;
        match self.state {
            State::Start => {
                self.handler.event(Event::Start);
                self.state = State::Header;
                self.handle_header(buf)
            }
            State::Header | State::MultipartHeader | State::PartStart => self.handle_header(buf),
            _ => self.handle_line(buf, buf.len()),
        }
    }

    fn handle_header(&mut self, buf: &[u8]) -> io::Result<()> {
        if buf.starts_with(b"\r\n") {
            if let Some((line, length)) = self.header_buffer.take() {
                self.handle_line(&line, length)?;
            }
            self.handle_line(buf, buf.len())
        } else if let Some((line, length)) = self.header_buffer.next_line(buf) {
            self.handle_line(&line, length)
        } else {
            Ok(())
        }
    }

    // Called when a complete line of data is available
    fn handle_line(&mut self, buf: &[u8], buf_len: usize) -> io::Result<()> {
        self.writer.write_all(buf)?;
        let next_state = match self.state {
            State::Start => unreachable!(),
            State::MultipartHeader => self.header_field(buf, State::MultipartHeader)?,
            State::Header => self.header_field(buf, State::Header)?,
            State::PartStart => {
                self.handler.event(Event::PartStart {
                    offset: self.offset,
                });
                self.header_field(buf, State::Header)?
            }
            State::MultipartPreamble => {
                if self.is_open_boundary(buf) {
                    if let Mime::Multipart(m) = self.content_type {
                        self.handler.event(Event::MultipartStart(m.clone()));
                    }
                    State::PartStart
                } else {
                    State::MultipartPreamble
                }
            }
            State::Body => {
                if self.is_close_boundary(buf) {
                    self.handler.event(Event::PartEnd {
                        offset: self.offset,
                    });
                    self.handler.event(Event::MultipartEnd);
                    // Use last multipart if available
                    if let Some(last) = self.multipart_stack.pop() {
                        self.content_type = Mime::Multipart(last.content_type);
                        self.boundary = Some(last.boundary);
                    }
                    State::Header
                } else if self.is_open_boundary(buf) {
                    self.handler.event(Event::PartEnd {
                        offset: self.offset,
                    });
                    State::PartStart
                } else {
                    self.handler.event(Event::Body(&buf));
                    State::Body
                }
            }
        };
        self.state = next_state;
        self.offset += buf_len;
        Ok(())
    }
}

/// Write data to the EmailParser to get parsing events.
impl<W: Write, H: Handler> Write for EmailParser<W, H> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.handle_write(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

/// The EmailParser is not finished until dropped
impl<W: Write, H: Handler> Drop for EmailParser<W, H> {
    fn drop(&mut self) {
        self.handler.event(Event::End);
    }
}

fn mime_type(v: &[u8]) -> Mime {
    let lower = str::from_utf8(v).map(|s| s.to_lowercase());
    if let Ok(s) = lower {
        match s.as_str() {
            "multipart/alternative" => Mime::Multipart(Multipart::Alternative),
            "multipart/mixed" => Mime::Multipart(Multipart::Mixed),
            "multipart/digest" => Mime::Multipart(Multipart::Digest),
            _ => Mime::Type(v.to_vec()),
        }
    } else {
        Mime::Type(v.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct TestHandler<'a> {
        is_error: bool, // Used to prevent panic during panic
        expected_events: Vec<Event<'a>>,
        current: usize,
    }

    impl<'a> TestHandler<'a> {
        fn new(expected_events: Vec<Event<'a>>) -> Self {
            Self {
                is_error: false,
                current: 0,
                expected_events,
            }
        }
    }

    impl<'a> Handler for TestHandler<'a> {
        fn event<'b>(&mut self, ev: Event<'b>) {
            self.is_error = true;
            println!("Event : {} : {}", self.current, ev);
            assert_eq!(self.expected_events[self.current], ev);
            self.current += 1;
            self.is_error = false;
        }
    }

    // Check that all events were received
    impl<'a> Drop for TestHandler<'a> {
        fn drop(&mut self) {
            if !self.is_error {
                if self.current < self.expected_events.len() {
                    assert!(
                        false,
                        "only saw {} events, missing {:?}",
                        self.current, self.expected_events[self.current]
                    )
                }
            }
        }
    }

    fn to_message_vec(msg: &[u8]) -> Vec<&[u8]> {
        msg.split(|b| *b == b'\n').skip(1).collect::<Vec<&[u8]>>()
    }

    fn parse_message(message: Vec<&[u8]>, handler: TestHandler) -> io::Result<()> {
        let writer = io::sink();
        let mut parser = EmailParser::new(writer, handler);
        for line in message {
            let mut buf = line.to_vec();
            buf.extend_from_slice(b"\r\n");
            parser.write_all(&buf)?;
        }
        Ok(())
    }

    fn unstructured_header<'a>(key: &'a str, value: &'a str) -> Event<'a> {
        Event::Header(Header::Unstructured(key.as_bytes(), value.as_bytes()))
    }

    fn header<'a>(header: Header<'a>) -> Event<'a> {
        Event::Header(header)
    }

    fn from<'a>(from: &'a str) -> Event<'a> {
        header(Header::From(from.as_bytes()))
    }

    fn to<'a>(to: &'a str) -> Event<'a> {
        header(Header::To(to.as_bytes()))
    }

    fn message_id<'a>(message_id: &'a str) -> Event<'a> {
        header(Header::MessageId(message_id.as_bytes()))
    }

    fn subject<'a>(subject: &'a str) -> Event<'a> {
        header(Header::Subject(subject.as_bytes()))
    }

    fn date<'a>(date: &'a str) -> Event<'a> {
        header(Header::Date(date.as_bytes()))
    }

    fn content_type<'a>(mime: &'a str, param_key: &'a str, param_value: &str) -> Event<'a> {
        Event::Header(Header::ContentType {
            mime_type: mime.as_bytes(),
            parameters: parameter_map(param_key, param_value),
        })
    }

    fn body<'a>(block: &'a str) -> Event<'a> {
        Event::Body(block.as_bytes())
    }

    fn parameter_map<'a>(key: &'a str, value: &str) -> HashMap<&'a [u8], Vec<u8>> {
        let mut ret = HashMap::new();
        ret.insert(key.as_bytes(), value.as_bytes().to_vec());
        ret
    }

    #[test]
    fn multipart_mixed() {
        let msg = br#"
X-sender: <sender@sendersdomain.com>
X-receiver: <somerecipient@recipientdomain.com>
From: "Senders Name" <sender@sendersdomain.com>
To: "Recipient Name" <somerecipient@recipientdomain.com>
Message-ID: <5bec11c119194c14999e592feb46e3cf@sendersdomain.com>
Date: Sat, 24 Sep 2005 15:06:49 -0400
Subject: Sample Multi-Part
MIME-Version: 1.0
Content-Type: multipart/alternative;
  boundary="----=_NextPart_DC7E1BB5_1105_4DB3_BAE3_2A6208EB099D"

------=_NextPart_DC7E1BB5_1105_4DB3_BAE3_2A6208EB099D
Content-type: text/plain; charset=iso-8859-1
Content-Transfer-Encoding: quoted-printable

Sample Text Content
------=_NextPart_DC7E1BB5_1105_4DB3_BAE3_2A6208EB099D
Content-type: text/html; charset=iso-8859-1
Content-Transfer-Encoding: quoted-printable

<html>
<head>
</head>
<body>
  <div style="FONT-SIZE: 10pt; FONT-FAMILY: Arial">Sample HTML =
  Content</div>
</body>
</html>

------=_NextPart_DC7E1BB5_1105_4DB3_BAE3_2A6208EB099D--"#;
        let msg_vec = to_message_vec(msg);
        let expected_events = vec![
            Event::Start,
            unstructured_header("X-sender", "<sender@sendersdomain.com>"),
            unstructured_header("X-receiver", "<somerecipient@recipientdomain.com>"),
            from(r#""Senders Name" <sender@sendersdomain.com>"#),
            to(r#""Recipient Name" <somerecipient@recipientdomain.com>"#),
            message_id("<5bec11c119194c14999e592feb46e3cf@sendersdomain.com>"),
            date("Sat, 24 Sep 2005 15:06:49 -0400"),
            subject("Sample Multi-Part"),
            unstructured_header("MIME-Version", "1.0"),
            content_type(
                "multipart/alternative",
                "boundary",
                "----=_NextPart_DC7E1BB5_1105_4DB3_BAE3_2A6208EB099D",
            ),
            Event::MultipartStart(Multipart::Alternative),
            Event::PartStart { offset: 507 },
            content_type("text/plain", "charset", "iso-8859-1"),
            unstructured_header("Content-Transfer-Encoding", "quoted-printable"),
            body("Sample Text Content\r\n"),
            Event::PartEnd { offset: 621 },
            Event::PartStart { offset: 676 },
            content_type("text/html", "charset", "iso-8859-1"),
            unstructured_header("Content-Transfer-Encoding", "quoted-printable"),
            body("<html>\r\n"),
            body("<head>\r\n"),
            body("</head>\r\n"),
            body("<body>\r\n"),
            body("  <div style=\"FONT-SIZE: 10pt; FONT-FAMILY: Arial\">Sample HTML =\r\n"),
            body("  Content</div>\r\n"),
            body("</body>\r\n"),
            body("</html>\r\n"),
            body("\r\n"),
            Event::PartEnd { offset: 904 },
            Event::MultipartEnd,
            Event::End,
        ];
        let handler = TestHandler::new(expected_events);
        parse_message(msg_vec, handler).unwrap();
    }

    #[test]
    fn multipart_digest() {
        let msg = br#"
From: Moderator-Address
To: Recipient-List
Date: Mon, 22 Mar 1994 13:34:51 +0000
Subject: Internet Digest, volume 42
MIME-Version: 1.0
Content-Type: multipart/mixed;
  boundary="---- main boundary ----"

------ main boundary ----

...Introductory text or table of contents...

------ main boundary ----
Content-Type: multipart/digest;
  boundary="---- next message ----"

------ next message ----

From: someone-else
Date: Fri, 26 Mar 1993 11:13:32 +0200
Subject: my opinion

...body goes here ...

------ next message ----

From: someone-else-again
Date: Fri, 26 Mar 1993 10:07:13 -0500
Subject: my different opinion

... another body goes here ...

------ next message ------
------ main boundary ------"#;
        let msg_vec = to_message_vec(msg);
        let expected_events = vec![
            Event::Start,
            from("Moderator-Address"),
            to("Recipient-List"),
            date("Mon, 22 Mar 1994 13:34:51 +0000"),
            subject("Internet Digest, volume 42"),
            unstructured_header("MIME-Version", "1.0"),
            content_type("multipart/mixed", "boundary", "---- main boundary ----"),
            Event::MultipartStart(Multipart::Mixed),
            Event::PartStart { offset: 239 },
            body("...Introductory text or table of contents...\r\n"),
            body("\r\n"),
            Event::PartEnd { offset: 289 },
            Event::PartStart { offset: 316 },
            content_type("multipart/digest", "boundary", "---- next message ----"),
            Event::MultipartStart(Multipart::Digest),
            Event::PartStart { offset: 414 },
            body("From: someone-else\r\n"),
            body("Date: Fri, 26 Mar 1993 11:13:32 +0200\r\n"),
            body("Subject: my opinion\r\n"),
            body("\r\n"),
            body("...body goes here ...\r\n"),
            body("\r\n"),
            Event::PartEnd { offset: 523 },
            Event::PartStart { offset: 549 },
            body("From: someone-else-again\r\n"),
            body("Date: Fri, 26 Mar 1993 10:07:13 -0500\r\n"),
            body("Subject: my different opinion\r\n"),
            body("\r\n"),
            body("... another body goes here ...\r\n"),
            body("\r\n"),
            Event::PartEnd { offset: 683 },
            Event::MultipartEnd,
            Event::End,
        ];
        let handler = TestHandler::new(expected_events);
        parse_message(msg_vec, handler).unwrap();
    }
}
