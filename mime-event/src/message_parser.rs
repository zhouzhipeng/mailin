use crate::message::Message;
use crate::message_handler::MessageHandler;
use crate::parser::EventParser;
use std::io;
use std::io::Write;

/// Wraps an event parser to parse messages
/// # Example
/// ```
/// use mime_event::MessageParser;
/// # use std::io;
/// # use std::io::Write;
///
/// // Create a message parser that writes to io::sink()
/// let mut parser = MessageParser::new(io::sink());
///
/// // Write a message, one line at a time.
/// parser.write_all(b"Subject: Example\r\n");
/// parser.write_all(b"\r\n");
///
/// // When there is no more input, call .end()
/// let message = parser.end();
///
/// // The returned Message object contains the parsed contents of the message
/// let header = &message.top().unwrap().header;
/// assert_eq!(header.subject.as_ref().unwrap(), b"Example");
/// # Ok::<(), ()>(())
/// ```
pub struct MessageParser<W: Write> {
    event_parser: EventParser<W, MessageHandler>,
}

impl<W: Write> MessageParser<W> {
    /// Create a new MessageParser that will parse the message and forward
    /// the data to the given writer.
    pub fn new(writer: W) -> Self {
        Self {
            event_parser: EventParser::new(writer, MessageHandler::default()),
        }
    }

    /// Call this method to signal the end of a message. Will return the parsed message.
    pub fn end(self) -> Message {
        self.event_parser.end().get_message()
    }
}

/// Write data to the MessageParser to parse a Message
impl<W: Write> Write for MessageParser<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.event_parser.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.event_parser.flush()
    }
}
