pub enum Command {
    Ehlo { domain: Vec<u8> },
    Helo { domain: Vec<u8> },
}
