use failure::Fail;
use std::io;

// Convert an error that is not Sync into an io::Error
pub fn nonsync_err<E>(error: E) -> io::Error
where
    E: std::error::Error,
{
    let msg = format!("{}", error);
    // Use the ::from() provided by Box
    let error = Box::<dyn std::error::Error + Send + Sync>::from(msg);
    io::Error::new(io::ErrorKind::Other, error)
}

// Convert a failure::Fail into an io::Error
pub fn convert_failure<F: Fail>(fail: F) -> io::Error {
    let error = fail.compat();
    io::Error::new(io::ErrorKind::Other, Box::new(error))
}
