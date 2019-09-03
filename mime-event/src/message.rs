use crate::event::{mime_type, Event, Mime, Multipart};
use crate::header::Header;
use crate::parser::Handler;
use std::collections::HashMap;
use std::mem;

/// A simplified Email Message overview
#[derive(Default)]
pub struct Message {
    // Most fields are indices into the parts Vec
    top: usize,
    text: Option<usize>,
    html: Option<usize>,
    attachments: Vec<usize>,
    inlines: Vec<usize>,
    other: Vec<usize>,
    parts: Vec<Part>,
}

/// A part of an email message
#[derive(Default)]
pub struct Part {
    pub header: HeaderFields,
    pub content_type: Option<ContentType>,
    pub content_disposition: Option<ContentDisposition>,
    start: usize,
    body_start: usize,
    end: usize,
}

/// Common header fields
#[derive(Default)]
pub struct HeaderFields {
    pub message_id: Option<Vec<u8>>,
    pub from: Option<Vec<u8>>,
    pub to: Option<Vec<u8>>,
    pub date: Option<Vec<u8>>,
    pub subject: Option<Vec<u8>>,
    pub sender: Option<Vec<u8>>,
    pub reply_to: Option<Vec<u8>>,
}

pub struct ContentType {
    mime_type: Mime,
    parameters: HashMap<Vec<u8>, Vec<u8>>,
}

/// Information about how message parts should be displayed
pub struct ContentDisposition {
    pub disposition_type: Vec<u8>,
    pub parameters: HashMap<Vec<u8>, Vec<u8>>,
}

impl Part {
    /// Get start and length of the body
    pub fn body(&self) -> (usize, usize) {
        (self.body_start, self.end - self.body_start + 1)
    }
}

// TODO: Move into separate file ---

#[derive(Default)]
pub struct MessageHandler {
    target: Target,
    current_part: Part,
    message: Message,
}

#[derive(Debug, PartialEq)]
enum Target {
    Top,
    TopAlternative,
    Alternative,
    Attachments,
    Inlines,
    Other,
}

impl Default for Target {
    fn default() -> Self {
        Target::Top
    }
}

impl Handler for &mut MessageHandler {
    fn event<'a>(&mut self, ev: Event<'a>) {
        match ev {
            Event::Start => (),
            Event::Header(h) => self.handle_header(h),
            Event::MultipartStart(m) => self.multipart_start(m),
            Event::PartStart { offset } => self.part_start(offset),
            Event::PartEnd { offset } => self.part_end(offset),
            Event::Body(_) => (),
            Event::MultipartEnd => (),
            Event::End => (),
        }
    }
}

impl MessageHandler {
    pub fn get_message(self) -> Message {
        self.message
    }

    fn handle_header(&mut self, header: Header) {
        let target = &mut self.current_part.header;
        match header {
            Header::From(from) => target.from = Some(from.to_vec()),
            Header::To(to) => target.to = Some(to.to_vec()),
            Header::Date(date) => target.date = Some(date.to_vec()),
            Header::Subject(subject) => target.subject = Some(subject.to_vec()),
            Header::Sender(sender) => target.sender = Some(sender.to_vec()),
            Header::ReplyTo(reply_to) => target.reply_to = Some(reply_to.to_vec()),
            Header::ContentType {
                mime_type,
                parameters,
            } => self.content_type(mime_type, parameters),
            Header::ContentDisposition {
                disposition_type, ..
            } => self.content_disposition(disposition_type),
            _ => (),
        }
    }

    fn content_type(&mut self, mime_text: &[u8], parameter_refs: HashMap<&[u8], Vec<u8>>) {
        let mime_type = mime_type(mime_text);
        let parameters = parameter_refs
            .into_iter()
            .map(|(k, v)| (k.to_vec(), v))
            .collect();
        self.current_part.content_type.replace(ContentType {
            mime_type,
            parameters,
        });
    }

    fn content_disposition(&mut self, disposition_type: &[u8]) {
        // Use the content disposition to set a more accurate target for this part
        if self.target != Target::Top && self.target != Target::TopAlternative {
            self.target = match disposition_type {
                b"inline" => Target::Inlines,
                b"attachment" => Target::Attachments,
                _ => Target::Other,
            }
        }
    }

    fn multipart_start(&mut self, multipart: Multipart) {
        // Set the default target for all parts in this multipart
        self.target = match multipart {
            Multipart::Alternative if self.target == Target::Top => Target::TopAlternative,
            Multipart::Alternative => Target::Alternative,
            Multipart::Mixed => Target::Attachments,
            Multipart::Digest => Target::Attachments,
        }
    }

    fn part_start(&mut self, offset: usize) {
        self.current_part.start = offset;
    }

    fn part_end(&mut self, offset: usize) {
        self.current_part.end = offset;
        let content_type = &self.current_part.content_type;
        match self.target {
            Target::Top => self.message.top = self.take_current(),
            Target::TopAlternative if is_content(content_type, b"text/plain") => {
                self.message.top = self.take_current();
            }
            Target::TopAlternative if is_content(content_type, b"text/html") => {
                self.message.html = Some(self.take_current());
            }
            Target::TopAlternative => self.message.top = self.take_current(),
            Target::Alternative => self.add_attachment(),
            Target::Attachments => self.add_attachment(),
            Target::Inlines => self.add_inline(),
            Target::Other => self.add_other(),
        }
    }

    fn take_current(&mut self) -> Part {
        mem::replace(&mut self.current_part, Part::default())
    }

    fn add_attachment(&mut self) {
        let current = self.take_current();
        self.message.attachments.push(current);
    }

    fn add_inline(&mut self) {
        let current = self.take_current();
        self.message.inlines.push(current);
    }

    fn add_other(&mut self) {
        let current = self.take_current();
        self.message.other.push(current);
    }
}

fn is_content(content_type: &Option<ContentType>, check_is: &[u8]) -> bool {
    content_type
        .as_ref()
        .filter(|c| match &c.mime_type {
            Mime::Type(m) => m.as_slice() == check_is,
            _ => false,
        })
        .is_some()
}
