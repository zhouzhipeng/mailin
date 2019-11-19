use mailin::State;

struct Session<S>
where
    S: BufRead + Write,
{
    inner: mailin::Session,
    stream: S,
}

impl<S> Session<S>
where
    S: BufRead + Write,
{
    pub(crate) fn new(inner: mailin::Session, stream: S) -> Self {
        Self { inner, stream }
    }

    pub fn next_state(&self) -> State {
        State::Idle // TODO: implement
    }

    pub fn respond(&self) {
        // TODO: implement
    }
}
