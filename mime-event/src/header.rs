use display_bytes::display_bytes;
use std::collections::HashMap;
use std::fmt;

/// Header contains information about an email header event
#[derive(PartialEq, Clone)]
pub enum Header<'a> {
    /// A header containing unstructured information as key, value
    Unstructured(&'a [u8], &'a [u8]),
    /// A Content-Type header
    ContentType {
        mime_type: &'a [u8],
        parameters: HashMap<&'a [u8], Vec<u8>>,
    },
    /// Email From header
    From(&'a [u8]),
    /// Email To header
    To(&'a [u8]),
    /// An unparsed Email Date
    Date(&'a [u8]),
    /// Presentation information about a MIME part
    ContentDisposition {
        disposition_type: &'a [u8],
        parameters: HashMap<&'a [u8], Vec<u8>>,
    },
    // Description of a MIME part
    ContentDescription(&'a [u8]),
    /// Subject header
    Subject(&'a [u8]),
    /// The SMTP sender header
    Sender(&'a [u8]),
    /// Reply-To header
    ReplyTo(&'a [u8]),
    /// The Message-ID of the email message
    MessageId(&'a [u8]),
    End,
}

impl<'a> Header<'a> {
    fn fmt_params(
        &self,
        f: &mut fmt::Formatter,
        params: &HashMap<&'a [u8], Vec<u8>>,
    ) -> fmt::Result {
        for (parameter, value) in params {
            write!(
                f,
                " {} = {}",
                display_bytes(parameter),
                display_bytes(&value)
            )?;
        }
        Result::Ok(())
    }
}

impl<'a> fmt::Debug for Header<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Header::Unstructured(key, value) => write!(
                f,
                "Unstructured{{ key: {}, value: {}}}",
                display_bytes(key),
                display_bytes(value)
            ),
            Header::From(from) => write!(f, "From {{ {} }}", display_bytes(from)),
            Header::To(to) => write!(f, "To {{ {} }}", display_bytes(to)),
            Header::Subject(subject) => write!(f, "To {{ {} }}", display_bytes(subject)),
            Header::Sender(sender) => write!(f, "Sender {{ {} }}", display_bytes(sender)),
            Header::ReplyTo(reply_to) => write!(f, "ReplyTo {{ {} }}", display_bytes(reply_to)),
            Header::MessageId(message_id) => {
                write!(f, "Message-ID {{ {} }}", display_bytes(message_id))
            }
            Header::Date(date) => write!(f, "Date {{ {} }}", display_bytes(date)),
            Header::ContentDescription(desc) => {
                write!(f, "ContentDescription {{ {} }}", display_bytes(desc))
            }
            Header::ContentDisposition {
                disposition_type,
                parameters,
            } => {
                write!(
                    f,
                    "DispositionType{{ disposition_type: {}}}",
                    display_bytes(disposition_type)
                )?;
                self.fmt_params(f, parameters)
            }
            Header::ContentType {
                mime_type,
                parameters,
            } => {
                write!(f, "ContentType{{ mime_type: {}}}", display_bytes(mime_type))?;
                self.fmt_params(f, parameters)
            }
            Header::End => write!(f, "End"),
        }
    }
}
