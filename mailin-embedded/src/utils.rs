use failure::format_err;
use failure::Error;
use std::fmt::Display;
use std::fs::File;
use std::io::Read;
use std::path::Path;

pub fn trim(line: &mut Vec<u8>) {
    if let Some(&b'\n') = line.last() {
        line.pop();
    }
    if let Some(&b'\r') = line.last() {
        line.pop();
    }
}

pub fn slurp<P>(path: P) -> Result<Vec<u8>, Error>
where
    P: AsRef<Path> + Display,
{
    let mut file = File::open(&path).map_err(|err| format_err!("Cannot open {}: {}", path, err))?;
    let mut ret = Vec::with_capacity(1024);
    file.read_to_end(&mut ret)?;
    Ok(ret)
}
