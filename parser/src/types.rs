pub enum Command<'a> {
    Ehlo { domain: &'a [u8] },
    Helo { domain: &'a [u8] },
}
