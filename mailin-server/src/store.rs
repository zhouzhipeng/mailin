use log::info;
use mime_event::MessageParser;
use std::io;
use std::io::{Sink, Write};

pub struct MailStore {
    parser: Option<MessageParser<Sink>>,
}

impl Clone for MailStore {
    fn clone(&self) -> Self {
        Self { parser: None }
    }
}

impl MailStore {
    pub fn new() -> Self {
        Self { parser: None }
    }

    pub fn start_message(&mut self, _message_id: &[u8]) -> io::Result<()> {
        self.parser.replace(MessageParser::new(io::sink()));
        Ok(())
    }

    pub fn end_message(&mut self) -> io::Result<()> {
        self.parser
            .take()
            .map(|p| {
                let message = p.end();
                info!("{:#?}", message);
                Ok(())
            })
            .unwrap_or(Ok(()))
    }
}

impl Write for MailStore {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.parser
            .as_mut()
            .map(|p| p.write(buf))
            .unwrap_or_else(|| Ok(buf.len()))
    }

    fn flush(&mut self) -> io::Result<()> {
        self.parser.as_mut().map(|p| p.flush()).unwrap_or(Ok(()))
    }
}
