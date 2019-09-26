use mailin_embedded::DataResult;
use mime_event::{EventParser, MessageHandler};
use std::io;

pub fn save_message(recipients: &[String]) -> DataResult {
    let writer = io::sink(); // TODO: save to disk
    let parser = EventParser::new(writer, MessageHandler::default()); // TODO: MessageParser
    DataResult::Ok(Box::new(parser))
}
