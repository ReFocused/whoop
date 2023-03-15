//! A raw HTTP request parser.
//! We do this manually because we don't need to parse the entire request body.

use std::cmp::Ordering;

use heapless::String;

#[derive(Default, Debug, Clone, Copy)]
pub enum Protocol {
    Http,
    #[default]
    Https,
}

impl Protocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Protocol::Http => "http",
            Protocol::Https => "https",
        }
    }
}

#[derive(Debug, Clone)]
pub enum Error {
    /// The protocol is invalid because the path
    /// doesn't start with `http://` or `https://`.
    InvalidProtocol,
    /// The domain or path is too long.
    /// The maximum length is 32 and 64 respectively.
    TooLong,
    /// Missing the path in the path.
    MissingPath,
    /// The method is invalid.
    InvalidMethod,
    /// The port is invalid.
    InvalidPort,
    /// The request is invalid.
    InvalidRequest,
}
impl Error {
    pub fn as_str(&self) -> &'static str {
        match self {
            Error::InvalidProtocol => {
                "Invalid protocol (the path must start with http:// or https://)"
            }
            Error::TooLong => {
                "The domain or path was too long (they have a max of 32 and 64 respectively)"
            }
            Error::MissingPath => {
                "Missing the path after the domain (if you want the root path, use /)"
            }
            Error::InvalidMethod => "Invalid request method",
            Error::InvalidPort => "Invalid port",
            Error::InvalidRequest => "Invalid request",
        }
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
impl std::error::Error for Error {}

#[derive(Default, Debug, Clone)]
pub enum RequestMethod {
    #[default]
    Get,
    Post,
    Put,
    Delete,
    Head,
    Options,
    Connect,
    Trace,
    Patch,
    Other(String<8>),
}

#[derive(Default, Debug, Clone)]
pub struct Parser {
    past_header: bool,
    finished: bool,
    /// The protocol of the request.
    pub protocol: Protocol,
    /// The domain of the request.
    pub addr: (String<32>, u16),
    /// The path of the request, not including the leading `/`.
    /// This includes the query string.
    pub path: String<64>,
    /// The method of the request.
    pub method: RequestMethod,
}

impl Parser {
    pub fn modify_stream(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        if self.finished {
            return Ok(memchr::memchr(b'\0', buf).unwrap_or(buf.len()));
        }

        let mut idx = 0;

        macro_rules! next_mut {
            () => {
                if let Some(byte) = buf.get_mut(idx) {
                    idx += 1;
                    Some(byte)
                } else {
                    None
                }
            };
        }
        macro_rules! next {
            () => {
                if let Some(&byte) = buf.get(idx) {
                    idx += 1;
                    Some(byte)
                } else {
                    None
                }
            };
        }
        macro_rules! next_loop {
            () => {{
                let byte = next!();
                if let Some(b) = byte {
                    b
                } else {
                    break;
                }
            }};
        }
        macro_rules! next_mut_loop {
            () => {{
                let byte = next_mut!();
                if let Some(b) = byte {
                    b
                } else {
                    break;
                }
            }};
        }
        macro_rules! peek {
            () => {
                if let Some(&byte) = buf.get(idx) {
                    Some(byte)
                } else {
                    None
                }
            };
        }
        macro_rules! peek_loop {
            () => {
                if let Some(byte) = peek!() {
                    byte
                } else {
                    break;
                }
            };
        }

        macro_rules! iter_loop {
            ($var:ident => $body:block) => {
                loop {
                    let $var = next_loop!();
                    $body
                }
            };
        }
        macro_rules! peek_iter_loop {
            ($var:ident => $body:block) => {
                loop {
                    let $var = peek_loop!();
                    $body
                }
            };
        }
        /// Removes the current byte from the buffer.
        macro_rules! remove {
            () => {
                if let Some(byte) = peek!() {
                    remove_from_slice(buf, idx);
                    Some(byte)
                } else {
                    None
                }
            };
        }
        macro_rules! remove_loop {
            () => {
                if let Some(byte) = remove!() {
                    byte
                } else {
                    break;
                }
            };
        }
        macro_rules! remove_iter_loop {
            ($var:ident => $body:block) => {
                loop {
                    let $var = remove_loop!();
                    $body
                }
            };
        }

        if !self.past_header {
            self.method = {
                let mut method = String::new();
                iter_loop!(byte => {
                    if byte == b' ' {
                        break;
                    }
                    method.push(byte as _).map_err(|_| Error::InvalidMethod)?;
                });
                match method.as_str() {
                    "GET" => RequestMethod::Get,
                    "POST" => RequestMethod::Post,
                    "PUT" => RequestMethod::Put,
                    "DELETE" => RequestMethod::Delete,
                    "HEAD" => RequestMethod::Head,
                    "OPTIONS" => RequestMethod::Options,
                    "CONNECT" => RequestMethod::Connect,
                    "TRACE" => RequestMethod::Trace,
                    "PATCH" => RequestMethod::Patch,
                    _ => RequestMethod::Other(method),
                }
            };

            assert_eq!(next!(), Some(b'/')); // skip the leading `/`

            // get the protocol
            let mut http = "http".bytes();

            let mut protocol = None;
            peek_iter_loop!(byte => {
                let next_byte = http.next();
                match next_byte {
                    Some(b) => {
                        remove!();
                        if b != byte {
                            break;
                        }
                    }
                    None => {
                        protocol.replace(if byte == b's' {
                            remove!();

                            Protocol::Https
                        } else {
                            Protocol::Http
                        });
                        break;
                    }
                }
            });

            self.protocol = protocol.ok_or(Error::InvalidProtocol)?;

            // skip the ://
            let Some(byte) = remove!() else {
                return Err(Error::InvalidProtocol);
            };
            if byte != b':' {
                return Err(Error::InvalidProtocol);
            }
            let Some(byte) = remove!() else {
                return Err(Error::InvalidProtocol);
            };
            if byte != b'/' {
                return Err(Error::InvalidProtocol);
            }
            let Some(byte) = remove!() else {
                return Err(Error::InvalidProtocol);
            };
            if byte != b'/' {
                return Err(Error::InvalidProtocol);
            }

            // get the domain and strip the domain from the buffer
            let mut domain = String::new();
            let mut port = String::<5>::new();

            remove_iter_loop!(byte => {
                if byte == b'/' {
                    break;
                } else if byte == b' ' {
                    return Err(Error::MissingPath);
                } else if byte == b':' {
                    remove_iter_loop!(byte => {
                        if byte == b'/' {
                            break;
                        } else if byte == b' ' {
                            return Err(Error::MissingPath);
                        }
                        port.push(byte as _).map_err(|_| Error::InvalidPort)?;
                    });
                    break;
                }
                domain.push(byte as _).map_err(|_| Error::TooLong)?;
            });
            let port = if port.is_empty() {
                80
            } else {
                port.parse().map_err(|_| Error::InvalidPort)?
            };
            self.addr = (domain, port);

            // get the path
            let mut path = String::new();
            iter_loop!(byte => {
                if byte == b' ' {
                    break;
                }
                path.push(byte as _).map_err(|_| Error::TooLong)?;
            });
            self.path = path;

            iter_loop!(byte => {
                if byte == b'\n' {
                    break;
                }
            });
            self.past_header = true;
        }

        let host_str = b"Host: ";
        let Some(host_idx) = memchr::memmem::find(buf, host_str) else {
            return Ok(idx)
        };

        idx = host_idx + host_str.len();

        let end = memchr::memchr(b'\n', &buf[idx..]).ok_or(Error::InvalidRequest)? - 2 /* \r\n */;

        let port_digits = num_digits(self.addr.1) as usize;

        let len_of_new_host = self.addr.0.len() + 1 + port_digits;

        match Ord::cmp(&len_of_new_host, &(idx + end)) {
            Ordering::Greater => {
                let diff = len_of_new_host - (idx + end);
                unsafe {
                    // SAFETY: we remove the host from the buffer in the header, so we can shift the remaining bytes
                    shift_right(buf, idx + end, diff);
                }
            }
            Ordering::Less => {
                let diff = (idx + end) - len_of_new_host;
                println!("diff: {}", diff);
                println!("end: {}", end);
                println!("idx: {}", idx);
                println!("len_of_new_host: {}", len_of_new_host);

                remove_n_from_slice(buf, diff, idx + end);
            }
            Ordering::Equal => {}
        }

        let host_bytes = self.addr.0.as_bytes();

        buf[idx..idx + host_bytes.len()].copy_from_slice(host_bytes);
        idx += len_of_new_host - host_bytes.len();
        buf[idx..idx + 1].copy_from_slice(b":");
        idx += 1;

        buf[idx..idx + port_digits].copy_from_slice(&num_to_bytes(self.addr.1)[..port_digits]);

        idx = memchr::memchr(b'\0', buf).unwrap_or(buf.len());

        self.finished = true;

        Ok(idx)
    }
}

/// Removes a number of elements from a slice.
fn remove_n_from_slice(slice: &mut [u8], index: usize, n: usize) {
    let len = slice.len();
    if index < len {
        unsafe {
            let ptr = slice.as_mut_ptr().add(index);
            std::ptr::copy(ptr.add(n), ptr, len - index - n);
        }
    }
}

/// Removes an element from a slice.
fn remove_from_slice(slice: &mut [u8], index: usize) {
    remove_n_from_slice(slice, index, 1);
}

/// Shifts all elements in a slice after the given index to the right n indices.
///
/// # Safety
/// This function does not check if the slice is long enough to shift the elements.
unsafe fn shift_right(slice: &mut [u8], index: usize, n: usize) {
    let len = slice.len();
    if index < len {
        let ptr = slice.as_mut_ptr().add(index);
        std::ptr::copy(ptr, ptr.add(n), len - index - n);
    }
}

/// Gets the number of digits in a number.
fn num_digits(mut n: u16) -> u8 {
    let mut digits = 0;
    while n > 0 {
        n /= 10;
        digits += 1;
    }
    digits
}

fn num_to_bytes(mut n: u16) -> [u8; 5] {
    let mut bytes = [0; 5];
    let mut i = 0;
    while n > 0 {
        bytes[i] = (n % 10) as u8 + b'0';
        n /= 10;
        i += 1;
    }
    bytes
}
