//! A raw HTTP request parser.
//! We do this manually because we don't need to parse the entire request body.

use std::iter::Peekable;

use heapless::String;

use crate::remove_from_slice;

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
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidProtocol => write!(
                f,
                "Invalid protocol (the path must start with http:// or https://)"
            ),
            Error::TooLong => write!(
                f,
                "The domain or path was too long (they have a max of 32 and 64 respectively)"
            ),
            Error::MissingPath => write!(
                f,
                "Missing the path after the domain (if you want the root path, use /)"
            ),
            Error::InvalidMethod => write!(f, "Invalid request method"),
            Error::InvalidPort => write!(f, "Invalid port"),
        }
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

fn skip_line(iter: &mut impl Iterator<Item = u8>) {
    while let Some(byte) = iter.next() {
        if byte == b'\r' {
            if let Some(b'\n') = iter.next() {
                break;
            }
        }
    }
}

#[derive(Default, Debug, Clone)]
pub struct Parser {
    past_header: bool,
    past_headers: bool,
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

fn copy_slice<const N: usize>(buf: &[u8; N]) -> [u8; N] {
    let mut new_buf = [0u8; N];
    unsafe {
        std::ptr::copy_nonoverlapping(buf.as_ptr(), new_buf.as_mut_ptr(), N);
    }
    new_buf
}

impl Parser {
    pub fn modify_stream<const N: usize>(&mut self, buf: &mut [u8; N]) -> Result<usize, Error> {
        let mut removed = 0;

        let iter = copy_slice(buf);
        let mut iter = iter.iter().copied().enumerate().peekable();
        if !self.past_header {
            removed += self.parse_header(buf, &mut iter)?;
            self.past_header = true;
        }

        Ok(removed)
    }

    fn parse_header<I: Iterator<Item = (usize, u8)>>(
        &mut self,
        buf: &mut [u8],
        iter: &mut Peekable<I>,
    ) -> Result<usize, Error> {
        let mut removed = 0;

        self.method = {
            let mut method = String::new();
            for (_, byte) in iter.by_ref() {
                if byte == b' ' {
                    break;
                }
                method.push(byte as _).map_err(|_| Error::InvalidMethod)?;
            }
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

        assert_eq!(iter.next().map(|(_, b)| b as char), Some('/')); // skip the leading `/`

        // get the protocol
        let mut http = "http".bytes();

        let mut protocol = None;
        while let Some(&(i, byte)) = iter.peek() {
            let next_byte = http.next();
            match next_byte {
                Some(b) => {
                    iter.next();
                    remove_from_slice(buf, i);
                    if b != byte {
                        break;
                    }
                    removed += 1;
                }
                None => {
                    protocol.replace(if byte == b's' {
                        iter.next();
                        remove_from_slice(buf, i);
                        removed += 1;
                        Protocol::Https
                    } else {
                        Protocol::Http
                    });
                    break;
                }
            }
        }

        self.protocol = protocol.ok_or(Error::InvalidProtocol)?;

        // skip the ://
        let Some((i, byte)) = iter.next() else {
                return Err(Error::InvalidProtocol);
            };
        if byte != b':' {
            return Err(Error::InvalidProtocol);
        }
        remove_from_slice(buf, i);
        removed += 1;
        let Some((i, byte)) = iter.next() else {
                return Err(Error::InvalidProtocol);
            };
        if byte != b'/' {
            return Err(Error::InvalidProtocol);
        }
        remove_from_slice(buf, i);
        removed += 1;
        let Some((i, byte)) = iter.next() else {
                return Err(Error::InvalidProtocol);
            };
        if byte != b'/' {
            return Err(Error::InvalidProtocol);
        }
        remove_from_slice(buf, i);
        removed += 1;

        // get the domain and strip the domain from the buffer
        let mut domain = String::new();
        let mut port = String::<5>::new();

        for (i, byte) in iter.by_ref() {
            if byte == b'/' {
                break;
            } else if byte == b' ' {
                return Err(Error::MissingPath);
            } else if byte == b':' {
                for (i, byte) in iter.by_ref() {
                    if byte == b'/' {
                        break;
                    } else if byte == b' ' {
                        return Err(Error::MissingPath);
                    }
                    port.push(byte as _).map_err(|_| Error::InvalidPort)?;
                    remove_from_slice(buf, i);
                    removed += 1;
                }
                break;
            }
            // TODO: optimize this
            remove_from_slice(buf, i);
            removed += 1;
            domain.push(byte as _).map_err(|_| Error::TooLong)?;
        }
        let port = if port.is_empty() {
            80
        } else {
            port.parse().map_err(|_| Error::InvalidPort)?
        };
        self.addr = (domain, port);

        // get the path
        let mut path = String::new();
        for (_, byte) in iter.by_ref() {
            if byte == b' ' {
                break;
            }
            path.push(byte as _).map_err(|_| Error::TooLong)?;
        }
        self.path = path;

        skip_line(&mut iter.map(|(_, b)| b));

        Ok(removed)
    }
}
