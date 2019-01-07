# Mailin

This is a library for writing SMTP servers in Rust. The library handles parsing, the SMTP state machine and building responses.

Programs using the Mailin library are responsible for all IO including opening sockets and storing messages. Mailin makes the lifecycle of an SMTP session available by calling methods on an object that implements the `Handler` trait.

## Directory structure

### mailin

The [mailin](mailin) directory contains the Mailin library. 

### mailin embedded

The [mailin-embedded](mailin-embedded) directory contains an SMTP server that can be embedded into another program. This can be used to receive email within a program or to build a standalone email server.

### mailin server

The  [mailin-server](mailin-server) directory contains an example standalone SMTP server that uses the mailin-embedded library.

### mxdns

The [mxdns](mxdns) directory contains utilities for looking up IP addresses on DNS based blocklists and for doing reverse dns lookups.
