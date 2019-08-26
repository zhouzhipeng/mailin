use display_bytes::{display_bytes, display_bytes_string};
use std::collections::HashMap;
use std::fmt;

// Debug a single entry tuple
pub(crate) fn dbg_single(f: &mut fmt::Formatter<'_>, name: &str, value: &[u8]) -> fmt::Result {
    let mut d = f.debug_tuple(name);
    d.field(&display_bytes_string(value));
    d.finish()
}

pub(crate) struct ParamDbg<'a>(pub(crate) &'a HashMap<&'a [u8], Vec<u8>>);

impl fmt::Debug for ParamDbg<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_map();
        for (parameter, value) in self.0 {
            d.entry(
                &display_bytes_string(parameter),
                &display_bytes_string(value),
            );
        }
        d.finish()
    }
}

// Debug an optional byte vector
pub(crate) struct OptionDbg<'a>(pub(crate) &'a Option<Vec<u8>>);

impl fmt::Debug for OptionDbg<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OptionDbg(Some(v)) => write!(f, "Some({})", display_bytes(v)),
            OptionDbg(None) => write!(f, "None"),
        }
    }
}
