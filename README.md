# Mailin

This repository contains libraries for writing SMTP servers in Rust.

Send an email to `mailin@spamtastic.cc` to try out an example server.

## Directory structure

### mailin

The [mailin](mailin) directory contains the Mailin library. The library handles parsing, the SMTP state machine and building responses.

### mailin embedded

The [mailin-embedded](mailin-embedded) directory contains an SMTP server that can be embedded into another program. This can be used to receive email within a program or to build a standalone email server.

### mailin server

The  [mailin-server](mailin-server) directory contains an example standalone SMTP server that uses the mailin-embedded library.

### mxdns

The [mxdns](mxdns) directory contains utilities for looking up IP addresses on DNS based blocklists and for doing reverse dns lookups.

### mime event

The [mime-event](mime-event) directory contains an event driven MIME parser. This parser can parse MIME messages line by line without allocating memory for the whole message.
