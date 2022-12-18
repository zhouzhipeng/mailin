pub enum Command<'a> {
    Ehlo { domain: &'a str },
    Helo { domain: &'a str },
}
