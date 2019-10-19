use crate::debug::OptionDbg;
use crate::event::Mime;
use std::collections::HashMap;
use std::fmt;

/// A simplified Email Message overview
#[derive(Default, Debug)]
pub struct Message {
    // Most fields are indices into the parts Vec
    pub(crate) top: usize,
    pub(crate) text: Option<usize>,
    pub(crate) html: Option<usize>,
    pub(crate) attachments: Vec<usize>,
    pub(crate) inlines: Vec<usize>,
    pub(crate) other: Vec<usize>,
    pub(crate) parts: Vec<Part>,
}

/// A part of an email message
#[derive(Default, Debug)]
pub struct Part {
    /// Mail header
    pub header: HeaderFields,
    /// MIME content type
    pub content_type: Option<ContentType>,
    /// MIME content disposition
    pub content_disposition: Option<ContentDisposition>,
    pub(crate) start: usize,
    pub(crate) body_start: usize,
    pub(crate) end: usize,
}

/// Common header fields
#[derive(Default, PartialEq)]
pub struct HeaderFields {
    /// Id of the mail message
    pub message_id: Option<Vec<u8>>,
    /// Mail message From field
    pub from: Option<Vec<u8>>,
    /// Mail message To field
    pub to: Option<Vec<u8>>,
    /// Mail message Date field
    pub date: Option<Vec<u8>>,
    /// Mail message Subject field
    pub subject: Option<Vec<u8>>,
    /// SMTP From field
    pub sender: Option<Vec<u8>>,
    /// Mail message Reply-To field
    pub reply_to: Option<Vec<u8>>,
}

impl fmt::Debug for HeaderFields {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_struct("HeaderFields");
        d.field("message_id", &OptionDbg(&self.message_id));
        d.field("from", &OptionDbg(&self.from));
        d.field("to", &OptionDbg(&self.to));
        d.field("date", &OptionDbg(&self.date));
        d.field("subject", &OptionDbg(&self.subject));
        d.field("sender", &OptionDbg(&self.sender));
        d.field("reply_to", &OptionDbg(&self.reply_to));
        d.finish()
    }
}

#[derive(Clone, Debug)]
pub struct ContentType {
    pub(crate) mime_type: Mime,
    pub(crate) parameters: HashMap<Vec<u8>, Vec<u8>>,
}

/// Information about how message parts should be displayed
#[derive(Debug)]
pub struct ContentDisposition {
    pub disposition_type: Vec<u8>,
    pub parameters: HashMap<Vec<u8>, Vec<u8>>,
}

impl Part {
    /// Get start and length of the part
    pub fn position(&self) -> (usize, usize) {
        (self.start, self.end - self.start + 1)
    }

    /// Get start and length of the body
    pub fn body(&self) -> (usize, usize) {
        (self.body_start, self.end - self.body_start + 1)
    }
}

impl Message {
    /// The first part of the message
    pub fn top(&self) -> Option<&Part> {
        self.parts.get(self.top)
    }

    /// The first text part of the message
    pub fn text(&self) -> Option<&Part> {
        self.text.and_then(|i| self.parts.get(i))
    }

    /// The first HTML part of the message
    pub fn html(&self) -> Option<&Part> {
        self.html.and_then(|i| self.parts.get(i))
    }

    /// Parts with disposition type "attachment"
    pub fn attachments(&self) -> impl Iterator<Item = &Part> {
        self.attachments
            .iter()
            .flat_map(move |i| self.parts.get(*i))
    }
}
