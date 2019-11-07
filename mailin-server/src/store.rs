use failure::Fail;
use log::info;
use mime_event::{Message, MessageParser};
use std::fmt::Debug;
use std::fs;
use std::fs::File;
use std::io;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, RwLock};
use std::time::SystemTime;
use tantivy::schema::{Field, Schema, STORED, TEXT};
use tantivy::{doc, IndexWriter};

pub struct MailStore {
    dir: PathBuf,
    counter: Arc<AtomicU32>,
    index: Arc<Index>,
    state: Option<State>,
}

struct Index {
    subject: Field,
    writer: RwLock<IndexWriter>,
}

struct State {
    path: PathBuf,
    parser: MessageParser<BufWriter<File>>,
}

impl Clone for MailStore {
    fn clone(&self) -> Self {
        Self {
            dir: self.dir.clone(),
            counter: self.counter.clone(),
            index: self.index.clone(),
            state: None,
        }
    }
}

impl MailStore {
    pub fn new<P>(dir: P) -> Result<Self, failure::Error>
    where
        P: Into<PathBuf> + Debug,
    {
        let dir = dir.into();
        let index = create_index(&dir)?;
        Ok(Self {
            dir,
            counter: Arc::new(AtomicU32::new(0)),
            index: Arc::new(index),
            state: None,
        })
    }

    pub fn start_message(&mut self) -> io::Result<()> {
        let mut path = self.dir.clone();
        path.push("tmp");
        fs::create_dir_all(&path)?;
        let message_file = self.message_file();
        path.push(message_file);
        info!("Writing message to {:#?}", path);
        let file = File::create(&path)?;
        let writer = BufWriter::new(file);
        self.state.replace(State {
            path,
            parser: MessageParser::new(writer),
        });
        Ok(())
    }

    pub fn end_message(&mut self) -> io::Result<()> {
        self.state
            .take()
            .map(|state| {
                let message = state.parser.end();
                info!("{:#?}", message);
                let dest = commit_file(&state.path)?;
                self.commit_index(&dest, &message).map(|_| ())
            })
            .unwrap_or(Ok(()))
    }

    fn message_file(&self) -> String {
        let mut filename = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_millis().to_string())
            .unwrap_or("0000".to_string());
        filename.push_str(".");
        filename.push_str(&process::id().to_string());
        filename.push_str(".");
        let count = self.counter.fetch_add(1, Ordering::Relaxed);
        filename.push_str(&count.to_string());
        filename
    }

    fn commit_index(&self, _dest: &Path, message: &Message) -> io::Result<u64> {
        let top = message.top().ok_or(io::ErrorKind::InvalidData)?;
        let subject = top
            .header
            .subject
            .as_ref()
            .ok_or(io::ErrorKind::InvalidData)
            .map(|s| String::from_utf8_lossy(s))?;
        let writer = self.index.writer.read().map_err(nonsync_err)?;
        writer.add_document(doc!(
            self.index.subject => subject.as_ref(),
        ));
        let mut writer = self.index.writer.write().map_err(nonsync_err)?;
        writer.commit().map_err(convert_failure)
    }
}

impl Write for MailStore {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.state
            .as_mut()
            .map(|state| state.parser.write(buf))
            .unwrap_or_else(|| Ok(buf.len()))
    }

    fn flush(&mut self) -> io::Result<()> {
        self.state
            .as_mut()
            .map(|state| state.parser.flush())
            .unwrap_or(Ok(()))
    }
}

fn commit_file(tmp_path: &Path) -> io::Result<PathBuf> {
    let filename = tmp_path.file_name().ok_or(io::ErrorKind::InvalidInput)?;
    let mut dest = tmp_path.to_path_buf();
    dest.pop();
    dest.pop();
    dest.push("new");
    fs::create_dir_all(&dest)?;
    dest.push(filename);
    fs::rename(tmp_path, &dest)?;
    Ok(dest)
}

// Convert an error that is not Sync into an io::Error
fn nonsync_err<E>(error: E) -> io::Error
where
    E: std::error::Error,
{
    let msg = format!("{}", error);
    // Use the ::from() provided by Box
    let error = Box::<dyn std::error::Error + Send + Sync>::from(msg);
    io::Error::new(io::ErrorKind::Other, error)
}

// Convert a failure::Fail into an io::Error
fn convert_failure<F: Fail>(fail: F) -> io::Error {
    let error = fail.compat();
    io::Error::new(io::ErrorKind::Other, Box::new(error))
}

fn create_index(dir: &Path) -> Result<Index, failure::Error> {
    let mut builder = Schema::builder();
    let subject = builder.add_text_field("subject", TEXT | STORED);
    let schema = builder.build();
    let index = tantivy::Index::create_in_dir(dir, schema)?;
    let writer = index.writer(4 * 1024 * 1024)?;
    let writer = RwLock::new(writer);
    Ok(Index { subject, writer })
}
