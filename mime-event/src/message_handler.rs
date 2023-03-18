use crate::event::{mime_type, Event, Mime, Multipart};
use crate::header::Header;
use crate::message::{ContentType, Message, Part};
use crate::parser::Handler;
use std::collections::HashMap;
use std::mem;

/// Event handler that builds Messages, used by the MessageParser
#[derive(Default)]
pub struct MessageHandler {
    is_multipart: bool,
    target: Target,
    current_part: Part,
    message: Message,
}

#[derive(Debug, PartialEq, Default)]
enum Target {
    #[default]
    Top,
    TopAlternative,
    Alternative,
    FirstMixed,
    Attachments,
    Inlines,
    Other,
}

impl Handler for MessageHandler {
    fn event(&mut self, ev: Event) {
        match ev {
            Event::Start => (),
            Event::Header(h) => self.handle_header(h),
            Event::MultipartStart(m) => self.multipart_start(m),
            Event::PartStart { offset } => self.part_start(offset),
            Event::PartEnd { offset } => self.part_end(offset),
            Event::BodyStart { offset } => self.body_start(offset),
            Event::Body(_) => (),
            Event::MultipartEnd => (),
            Event::End => self.end(),
        }
    }
}

impl MessageHandler {
    /// Get the parsed mail message
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
            Header::MessageId(msg_id) => target.message_id = Some(msg_id.to_vec()),
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
            Multipart::Mixed if self.target == Target::Top => Target::FirstMixed,
            Multipart::Mixed => Target::Attachments,
            Multipart::Digest => Target::Attachments,
        }
    }

    fn part_start(&mut self, offset: usize) {
        self.is_multipart = true;
        self.current_part.start = offset;
    }

    fn part_end(&mut self, offset: usize) {
        self.current_part.end = offset;
        let content_type = self.current_part.content_type.clone();
        let part_index = self.add_part();
        match self.target {
            Target::Top => {
                self.message.top = part_index;
                if is_content_text(&content_type) {
                    self.message.text = Some(part_index);
                }
            }
            Target::TopAlternative if is_content_text(&content_type) => {
                self.message.top = part_index;
                self.message.text = Some(part_index);
            }
            Target::TopAlternative if is_content(&content_type, b"text/html") => {
                self.message.html = Some(part_index);
            }
            Target::TopAlternative => self.message.top = part_index,
            Target::FirstMixed => {
                self.message.top = part_index;
                self.target = Target::Attachments;
            }
            Target::Alternative => self.message.attachments.push(part_index),
            Target::Attachments => self.message.attachments.push(part_index),
            Target::Inlines => self.message.inlines.push(part_index),
            Target::Other => self.message.other.push(part_index),
        }
    }

    fn body_start(&mut self, offset: usize) {
        self.current_part.body_start = offset;
    }

    fn take_current(&mut self) -> Part {
        mem::take(&mut self.current_part)
    }

    fn end(&mut self) {
        let content_type = self.current_part.content_type.clone();
        if !self.is_multipart {
            let part_index = self.add_part();
            self.message.top = part_index;
            if is_content_text(&content_type) {
                self.message.text = Some(part_index);
            }
        }
    }

    // Add a new part and return the index
    fn add_part(&mut self) -> usize {
        let current = self.take_current();
        self.message.parts.push(current);
        self.message.parts.len() - 1
    }
}

fn is_content_text(content_type: &Option<ContentType>) -> bool {
    content_type.is_none() || is_content(content_type, b"text/plain")
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
