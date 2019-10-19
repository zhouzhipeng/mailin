# Mime Event

This MIME parsing library is intended for use in SMTP servers where it is useful to get metadata about an email message while saving it. Because the parser is event based, the message can be parsed while writing it to disk and the entire message does not need to be kept in memory.
