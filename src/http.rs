//! A raw HTTP request parser. We do this manually because we don't need to parse
//! the entire request body.
use heapless::String;
use memchr::memmem::find;
use std::{cmp::Ordering, num::NonZeroU16};

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
struct ContentLength {
    content_length: usize,
    bytes_given: usize,
}

impl ContentLength {
    pub const fn full(self) -> bool {
        self.content_length >= self.bytes_given
    }
}

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
    /// The domain or path is too long. The maximum length for both is 64 bytes.
    TooLong,
    /// Missing the path in the path.
    MissingPath,
    /// The port is invalid.
    InvalidPort,
    /// The request is invalid.
    InvalidRequest,
    /// The HTTP version number is unsupported.
    /// The only version numbers supported are 1.0 & 1.1
    UnsupportedHTTPVersion,
}

impl Error {
    pub const fn into_str(self) -> &'static str {
        match self {
            Self::InvalidProtocol => {
                "Invalid protocol (the path must start with http:// or https://)"
            }
            Self::TooLong => "The domain or path was too long (they have a max of 64 each)",
            Self::MissingPath => {
                "Missing the path after the domain (if you want the root path, use /)"
            }
            Self::InvalidPort => "Invalid port",
            Self::InvalidRequest => "Invalid request",
            Self::UnsupportedHTTPVersion => "The HTTP version number is unsupported. The only version numbers supported are 1.0 & 1.1",
        }
    }
    pub const fn code(self) -> u16 {
        match self {
            Self::TooLong => 414,
            Self::UnsupportedHTTPVersion => 505,
            _ => 400,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RequestInfo {
    /// The protocol of the request.
    pub protocol: Protocol,
    /// The address of the request.
    pub addr: String<64>,
    /// The port of the request.
    pub port: NonZeroU16,
}
impl Default for RequestInfo {
    fn default() -> Self {
        Self {
            protocol: Protocol::default(),
            addr: String::default(),
            port: unsafe { NonZeroU16::new_unchecked(80) },
        }
    }
}

#[derive(Default, Debug, Clone)]
pub struct Parser {
    past_heading: bool,
    past_host: bool,
    /// (bytes past heading, content length)
    content_len: Option<ContentLength>,
    pub finished: bool,
    pub info: Option<RequestInfo>,
}

impl Parser {
    #[allow(clippy::cognitive_complexity, clippy::too_many_lines)]
    pub fn modify_stream(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        if self.finished {
            return Ok(0);
        }

        let mut idx = 0;
        let mut removed = 0;

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

        macro_rules! iter_loop {
            ($var:ident => $body:block) => {
                loop {
                    let $var = next_loop!();
                    $body
                }
            };
        }

        /// Removes the current byte from the buffer.
        macro_rules! remove {
            () => {
                if let Some(byte) = peek!() {
                    remove_from_slice(buf, idx);
                    removed += 1;
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

        macro_rules! b_else_err {
            ($b:literal, $e:expr) => {
                if let Some(b) = next!().and_then(|b| if b == $b { Some(b) } else { None }) {
                    b
                } else {
                    return Err($e);
                }
            };
        }

        macro_rules! remove_b_else_err {
            ($b:literal, $e:expr) => {
                if let Some(b) = remove!().and_then(|b| if b == $b { Some(b) } else { None }) {
                    b
                } else {
                    return Err($e);
                }
            };
        }

        let mut info = self.info.take().unwrap_or_default();

        if !self.past_heading {
            // skip the method
            iter_loop!(byte => {
                if byte == b' ' {
                    break;
                }
            });

            // skip the leading `/`
            b_else_err!(b'/', Error::InvalidRequest);

            if peek!() == Some(b'?') {
                // give an alternate access point because double slashes are invalid in URLs
                remove!();
            }

            // get the protocol
            remove_b_else_err!(b'h', Error::InvalidProtocol);
            remove_b_else_err!(b't', Error::InvalidProtocol);
            remove_b_else_err!(b't', Error::InvalidProtocol);
            remove_b_else_err!(b'p', Error::InvalidProtocol);

            info.protocol = if peek!() == Some(b's') {
                remove!();
                Protocol::Https
            } else {
                Protocol::Http
            };

            // skip the ://
            remove_b_else_err!(b':', Error::InvalidProtocol);
            remove_b_else_err!(b'/', Error::InvalidProtocol);
            remove_b_else_err!(b'/', Error::InvalidProtocol);

            // get the domain and strip the domain from the buffer
            let mut addr = String::new();
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
                addr.push(byte as _).map_err(|_| Error::TooLong)?;
            });
            info.addr = addr;

            let port = port.parse().unwrap_or_else(|_| unsafe {
                NonZeroU16::new_unchecked(if info.protocol == Protocol::Http {
                    80
                } else {
                    443
                })
            });
            info.port = port;

            iter_loop!(byte => {
                if byte == b' ' {
                    break;
                }
            });
            b_else_err!(b'H', Error::InvalidRequest);
            b_else_err!(b'T', Error::InvalidRequest);
            b_else_err!(b'T', Error::InvalidRequest);
            b_else_err!(b'P', Error::InvalidRequest);
            b_else_err!(b'/', Error::InvalidRequest);

            b_else_err!(b'1', Error::UnsupportedHTTPVersion);
            b_else_err!(b'.', Error::UnsupportedHTTPVersion);
            if next!()
                .and_then(|b| {
                    if [b'0', b'1'].contains(&b) {
                        Some(b)
                    } else {
                        None
                    }
                })
                .is_none()
            {
                return Err(Error::UnsupportedHTTPVersion);
            };

            // skip the rest
            iter_loop!(byte => {
                if byte == b'\n' {
                    break;
                }
            });
            self.past_heading = true;
        }

        if !self.past_host {
            let r = Self::replace_host_header(&mut buf[idx..], &info)?;
            if r != 0 {
                self.past_host = true;
            }
            removed += r;
        }
        let heading_end = find(&buf[idx..], b"\r\n\r\n").map_or(0, |i| i + 4);

        self.get_content_len(&mut buf[idx..], heading_end)?;

        if (heading_end == 0 && self.content_len.map_or(false, ContentLength::full))
            || (heading_end != 0 && self.content_len.is_none())
        {
            self.finished = true;
        }

        self.info = Some(info);

        Ok(removed)
    }

    fn replace_host_header(buf: &mut [u8], info: &RequestInfo) -> Result<usize, Error> {
        let mut removed = 0;

        let host_str = b"Host: ";
        let Some(host_idx) = find(buf, host_str) else {
            return Ok(0);
        };
        let mut idx = host_idx + host_str.len();

        let len_of_old_host = memchr::memchr(b'\r', &buf[idx..]).ok_or(Error::InvalidRequest)?;

        let port = info.port.get();
        let (port_bytes, port_digits) = crate::num_to_bytes(port);
        let is_default_port = if info.protocol == Protocol::Http {
            port == 80
        } else {
            port == 443
        };
        let len_of_new_host = info.addr.len() + if is_default_port { 0 } else { 1 + port_digits };

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
                removed += len_of_old_host - len_of_new_host;
            }
            Ordering::Equal => {}
        }

        let host_bytes = info.addr.as_bytes();
        buf[idx..idx + host_bytes.len()].copy_from_slice(host_bytes);
        idx += host_bytes.len();

        if !is_default_port {
            buf[idx..=idx].copy_from_slice(b":");
            idx += 1;

            buf[idx..idx + port_digits].copy_from_slice(&port_bytes[..port_digits]);
        }

        Ok(removed)
    }

    fn get_content_len(&mut self, buf: &mut [u8], heading_end: usize) -> Result<(), Error> {
        let content_len_str = b"\nContent-Length: ";
        let Some(host_idx) = find(buf, content_len_str) else {
            return Ok(());
        };
        let idx = host_idx + content_len_str.len();

        let mut content_len = self.content_len.unwrap_or_default();
        let end = memchr::memchr(b'\r', &buf[idx..]).ok_or(Error::InvalidRequest)?;
        let total_content_len = std::str::from_utf8(&buf[idx..idx + end])
            .ok()
            .and_then(|s| s.parse().ok())
            .ok_or(Error::InvalidRequest)?;

        content_len.content_length = total_content_len;

        content_len.bytes_given += buf.len() - heading_end;

        self.content_len.replace(content_len);

        Ok(())
    }
}

/// Modifies an HTTP response by changing the CORS header to allow all origins.
pub fn modify_response(response: &mut [u8]) -> bool {
    let cors_header = b"Access-Control-Allow-Origin: ";
    let Some(start) = memchr::memmem::find(response, cors_header) else {
        return false;
    };
    let start = start + cors_header.len();
    let Some(end) = memchr::memchr(b'\n', &response[start..]) else {
        return false;
    };
    response[start] = b'*';

    remove_n_from_slice(response, start + 1, end - /* \r */ 1);
    true
}

/// Removes a number of elements from a slice.
fn remove_n_from_slice(slice: &mut [u8], index: usize, n: usize) {
    let len = slice.len();
    if index + n < len {
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
