//! A raw HTTP request parser. We do this manually because we don't need to parse
//! the entire request body.
use heapless::String;
use std::{cmp::Ordering, fmt::Display, num::NonZeroU16, str::FromStr};

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Http,
    #[default]
    Https,
}

#[derive(Debug, Clone, Copy)]
pub enum Error {
    /// The protocol is invalid because the path doesn't start with `http://` or
    /// `https://`.
    InvalidProtocol,
    /// The domain or path is too long. The maximum length is 32 and 64 respectively.
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
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidProtocol => {
                "Invalid protocol (the path must start with http:// or https://)"
            }
            Self::TooLong => {
                "The domain or path was too long (they have a max of 32 and 64 respectively)"
            }
            Self::MissingPath => {
                "Missing the path after the domain (if you want the root path, use /)"
            }
            Self::InvalidMethod => "Invalid request method",
            Self::InvalidPort => "Invalid port",
            Self::InvalidRequest => "Invalid request",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Port(pub NonZeroU16);
impl Port {
    pub const fn as_u16(self) -> u16 {
        self.0.get()
    }
}
impl Default for Port {
    fn default() -> Self {
        Self(unsafe { NonZeroU16::new_unchecked(80) })
    }
}
impl FromStr for Port {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let port = s.parse().map_err(|_| Error::InvalidPort)?;
        Ok(Self(port))
    }
}
impl Display for Port {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_u16())
    }
}

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
    pub addr: (String<32>, Port),
    /// The path of the request, not including the leading `/`. This includes the query
    /// string.
    pub path: String<64>,
    /// The method of the request.
    pub method: RequestMethod,
}

impl Parser {
    #[allow(clippy::cognitive_complexity, clippy::too_many_lines)]
    pub fn modify_stream(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        if self.finished {
            return Ok(memchr::memchr(b'\0', buf).unwrap_or(buf.len()));
        }
        let mut idx = 0;

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
            ($var: ident => $body: block) => {
                loop {
                    let $var = next_loop!();
                    $body
                }
            };
        }

        macro_rules! peek_iter_loop {
            ($var: ident => $body: block) => {
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
            ($var: ident => $body: block) => {
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

            // skip the leading `/`
            assert_eq!(next!(), Some(b'/'));

            // get the protocol
            let mut http = "http".bytes();
            let mut protocol = None;
            peek_iter_loop!(byte => {
                let next_byte = http.next();
                if let Some(b) = next_byte {
                    remove!();
                    if b != byte {
                        break;
                    }
                } else {
                    protocol.replace(if byte == b's' {
                        remove!();
                        Protocol::Https
                    } else {
                        Protocol::Http
                    });
                    break;
                }
            });
            self.protocol = protocol.ok_or(Error::InvalidProtocol)?;

            // skip the ://
            let Some(byte) = remove !() else {
                return Err(Error::InvalidProtocol);
            };
            if byte != b':' {
                return Err(Error::InvalidProtocol);
            }
            let Some(byte) = remove !() else {
                return Err(Error::InvalidProtocol);
            };
            if byte != b'/' {
                return Err(Error::InvalidProtocol);
            }
            let Some(byte) = remove !() else {
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
            let port = port.parse().unwrap_or_default();
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

        let len_of_old_host = memchr::memchr(b'\n', &buf[idx..]).ok_or(Error::InvalidRequest)? - 1;

        let port_digits = num_digits(self.addr.1.as_u16()) as usize;
        let len_of_new_host = self.addr.0.len() + 1 + port_digits;

        match Ord::cmp(&len_of_new_host, &len_of_old_host) {
            Ordering::Greater => {
                shift_right(
                    buf,
                    idx + len_of_old_host,
                    len_of_new_host - len_of_old_host,
                );
            }
            Ordering::Less => {
                remove_n_from_slice(
                    buf,
                    idx + len_of_new_host,
                    len_of_old_host - len_of_new_host,
                );
            }
            Ordering::Equal => {}
        }

        let host_bytes = self.addr.0.as_bytes();
        buf[idx..idx + host_bytes.len()].copy_from_slice(host_bytes);
        idx += host_bytes.len();

        buf[idx..=idx].copy_from_slice(b":");
        idx += 1;

        buf[idx..idx + port_digits]
            .copy_from_slice(&num_to_bytes(self.addr.1.as_u16())[..port_digits]);

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
    } else {
        #[cfg(debug_assertions)]
        panic!("index out of bounds");
    }
}

/// Removes an element from a slice.
fn remove_from_slice(slice: &mut [u8], index: usize) {
    remove_n_from_slice(slice, index, 1);
}

/// Shifts all elements in a slice after the given index to the right n indices.
fn shift_right(slice: &mut [u8], index: usize, n: usize) {
    let len = slice.len();
    if index + n < len {
        unsafe {
            let ptr = slice.as_mut_ptr().add(index);
            std::ptr::copy(ptr, ptr.add(n), len - index - n);
        }
    } else {
        #[cfg(debug_assertions)]
        panic!("index out of bounds");
    }
}

/// Gets the number of digits in a number.
const fn num_digits(mut n: u16) -> u8 {
    let mut digits = 0;
    while n > 0 {
        n /= 10;
        digits += 1;
    }
    digits
}

const fn num_to_bytes(mut n: u16) -> [u8; 5] {
    let mut bytes = [0; 5];
    let mut i = 0;
    while n > 0 {
        bytes[i] = (n % 10) as u8 + b'0';
        n /= 10;
        i += 1;
    }
    // reverse the bytes
    let mut j = 0;
    while j < i / 2 {
        let tmp = bytes[j];
        bytes[j] = bytes[i - j - 1];
        bytes[i - j - 1] = tmp;
        j += 1;
    }
    bytes
}
