use std::mem;

// Concatenates header lines
#[derive(Default)]
pub(crate) struct HeaderBuffer {
    has_value: bool,
    length: usize, // Length of the incoming line
    line: Vec<u8>,
}

impl HeaderBuffer {
    // Add a, possibly incomplete, incoming line and retrieve the next complete line
    pub(crate) fn next_line(&mut self, line: &[u8]) -> Option<(Vec<u8>, usize)> {
        // Check for a continuation line
        if !self.has_value {
            self.line = line.to_vec();
            self.length = line.len();
            self.has_value = true;
            None
        } else if line.starts_with(b" ") {
            self.line.truncate(self.line.len() - 2); // Remove \r\n
            self.line.extend_from_slice(line);
            self.length += line.len();
            None
        } else {
            let length = self.length;
            let ret = mem::replace(&mut self.line, line.to_vec());
            self.length = line.len();
            Some((ret, length))
        }
    }

    // Get the remaining contents of the buffer and clear the buffer
    pub(crate) fn take(&mut self) -> Option<(Vec<u8>, usize)> {
        if self.has_value {
            self.has_value = false;
            let length = self.length;
            let buf = mem::replace(&mut self.line, Vec::new());
            self.length = 0;
            Some((buf, length))
        } else {
            None
        }
    }
}
