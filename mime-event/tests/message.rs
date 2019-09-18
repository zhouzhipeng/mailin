use mime_event::{EventParser, HeaderFields, MessageHandler};
use std::io;
use std::io::Write;

#[test]
fn multipart_alternative() {
    let msg = include_bytes!("multipart_alternative.msg");
    let mut handler = MessageHandler::default();
    parse_message(&msg[..], &mut handler).unwrap();
    let message = handler.get_message();
    let expected_header = HeaderFields {
        message_id: None,
        from: field(br#""Senders Name" <sender@sendersdomain.com>"#),
        to: field(br#""Recipient Name" <somerecipient@recipientdomain.com>"#),
        date: field(b"Sat, 24 Sep 2005 15:06:49 -0400"),
        reply_to: None,
        sender: None,
        subject: field(b"Sample Multi-Part"),
    };
    let header = &message.text().unwrap().header;
    assert_eq!(header, &expected_header);
    let header = &message.top().unwrap().header;
    assert_eq!(header, &expected_header);
    assert_eq!(message.top().unwrap().body(), (600, 22));
    assert_eq!(message.html().unwrap().body(), (768, 137));
}

#[test]
fn multipart_mixed() {
    let msg = include_bytes!("multipart_mixed.msg");
    let mut handler = MessageHandler::default();
    parse_message(&msg[..], &mut handler).unwrap();
    let message = handler.get_message();
    let expected_top_header = HeaderFields {
        message_id: None,
        from: field(b"Moderator-Address"),
        to: field(b"Recipient-List"),
        date: field(b"Mon, 22 Mar 1994 13:34:51 +0000"),
        reply_to: None,
        sender: None,
        subject: field(b"Internet Digest, volume 42"),
    };
    let top_header = &message.top().unwrap().header;
    assert_eq!(top_header, &expected_top_header);
    assert_eq!(message.top().unwrap().body(), (241, 49));
    for (i, attachment) in message.attachments().enumerate() {
        match i {
            0 => assert_eq!(attachment.position(), (414, 110)),
            1 => assert_eq!(attachment.position(), (549, 135)),
            _ => assert!(false, "Unexpected attachment"),
        }
    }
}

fn field(value: &[u8]) -> Option<Vec<u8>> {
    Some(value.to_vec())
}

fn parse_message(message: &[u8], handler: &mut MessageHandler) -> io::Result<()> {
    let writer = io::sink();
    let mut parser = EventParser::new(writer, handler);
    for line in message.split(|ch| *ch == b'\n') {
        let mut buf = line.to_vec();
        buf.extend_from_slice(b"\r\n");
        parser.write_all(&buf)?;
    }
    Ok(())
}
