use crate::err::Error;
use std::fmt::Display;
use std::fs::File;
use std::io::Read;
use std::path::Path;

pub fn slurp<P>(path: P) -> Result<Vec<u8>, Error>
where
    P: AsRef<Path> + Display,
{
    let mut file =
        File::open(&path).map_err(|e| Error::with_source(format!("Cannot open {}", path), e))?;
    let mut ret = Vec::with_capacity(1024);
    file.read_to_end(&mut ret)?;
    Ok(ret)
}
