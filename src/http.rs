//! A raw HTTP request parser. We do this manually because we don't need to parse
//! the entire request body.
use heapless::String;
use std::{cmp::Ordering, num::NonZeroU16};

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
}

impl Error {
    pub const fn as_str(self) -> &'static str {
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
    past_header: bool,
    pub info: Option<RequestInfo>,
}

impl Parser {
    #[allow(clippy::cognitive_complexity, clippy::too_many_lines)]
    pub fn modify_stream(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
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
            ($var: ident => $body: block) => {
                loop {
                    let $var = remove_loop!();
                    $body
                }
            };
        }

        let mut info = self.info.take().unwrap_or_default();

        if !self.past_header {
            // skip the method
            iter_loop!(byte => {
                if byte == b' ' {
                    break;
                }
            });

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
            info.protocol = protocol.ok_or(Error::InvalidProtocol)?;

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

            // skip the rest
            iter_loop!(byte => {
                if byte == b'\n' {
                    break;
                }
            });
            self.past_header = true;
        }

        let host_str = b"Host: ";
        let Some(host_idx) = memchr::memmem::find(buf, host_str) else {
            return Ok(removed)
        };
        idx = host_idx + host_str.len();

        let len_of_old_host = memchr::memchr(b'\n', &buf[idx..]).ok_or(Error::InvalidRequest)? - 1;

        let (port_bytes, port_digits) = num_to_bytes(info.port.get());
        let is_default_port = if info.protocol == Protocol::Http {
            info.port.get() == 80
        } else {
            info.port.get() == 443
        };
        let len_of_new_host = info.addr.len() + if is_default_port { 0 } else { 1 + port_digits };

        match Ord::cmp(&len_of_new_host, &len_of_old_host) {
            Ordering::Greater => {
                shift_right(
                    buf,
                    idx + len_of_old_host,
                    len_of_new_host - len_of_old_host,
                );
                removed -= len_of_new_host - len_of_old_host;
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

        let host_bytes = info.addr.as_bytes();
        buf[idx..idx + host_bytes.len()].copy_from_slice(host_bytes);
        idx += host_bytes.len();

        if !is_default_port {
            buf[idx..=idx].copy_from_slice(b":");
            idx += 1;

            buf[idx..idx + port_digits].copy_from_slice(&port_bytes[..port_digits]);
        }

        self.info = Some(info);

        Ok(removed)
    }
}

/// Modifies an HTTP response by changing the CORS header to allow all origins.
pub fn modify_response(response: &mut [u8]) {
    let cors_header = b"Access-Control-Allow-Origin: ";
    let Some(start) = memchr::memmem::find(response, cors_header) else {
        return;
    };
    let start = start + cors_header.len();
    let Some(end) = memchr::memchr(b'\n', &response[start..]) else {
        return;
    };
    response[start] = b'*';

    remove_n_from_slice(response, start + 1, end - /* \r */ 1);
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

const fn num_to_bytes(mut n: u16) -> ([u8; 5], usize) {
    let mut bytes = [0; 5];
    let mut i = 0;
    let mut digits = 0;

    while n > 0 {
        bytes[i] = (n % 10) as u8 + b'0';
        n /= 10;
        i += 1;
        digits += 1;
    }

    // reverse the array
    let mut j = 0;
    while j < i / 2 {
        let tmp = bytes[j];
        bytes[j] = bytes[i - j - 1];
        bytes[i - j - 1] = tmp;
        j += 1;
    }

    (bytes, digits)
}
