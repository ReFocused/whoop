//! A raw HTTP request parser.
//! We do this manually because we don't need to parse the entire request body.

use circular_buffer::CircularBuffer;
use heapless::String;

struct Assert<const N: usize>;
impl<const N: usize> Assert<N> {
    const LEN_GT_1024: () = assert!(N >= 1024);
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
pub enum Protocol {
    Http,
    #[default]
    Https,
}

#[derive(Debug, Clone)]
pub enum Error {
    InvalidProtocol,
    TooLong,
}

#[derive(Default, Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum State {
    #[default]
    New,
    PastHeader,
}

#[derive(Default, Debug, Clone)]
pub struct Parser {
    state: State,
    /// The domain of the request, not including the leading `http://`.
    domain: (Protocol, String<32>),
    /// The path of the request, not including the leading `/`.
    path: String<64>,
}

impl Parser {
    pub fn modify_stream<const N: usize>(
        &mut self,
        buf: &mut CircularBuffer<N, u8>,
    ) -> Result<(), Error> {
        #[allow(clippy::let_unit_value)]
        let _ = Assert::<N>::LEN_GT_1024;

        let mut iter = buf.iter().copied().enumerate().peekable();
        match self.state {
            State::New => {
                // skip the request method
                for (_, byte) in iter.by_ref() {
                    if byte == b' ' {
                        break;
                    }
                }
                // get the path
                assert!(iter.next().map(|(_, s)| s) == Some(b'/'));

                // get the protocol
                let mut http = "http".bytes();

                let mut protocol = None;

                while let Some(&(_, byte)) = iter.peek() {
                    let next_byte = http.next();
                    match next_byte {
                        Some(b) => {
                            if b != byte {
                                return Err(Error::InvalidProtocol);
                            }
                            iter.next();
                        }
                        None => {
                            protocol.replace(if byte == b's' {
                                iter.next();
                                Protocol::Https
                            } else {
                                Protocol::Http
                            });
                        }
                    }
                }

                // skip the ://
                iter.next();
                iter.next();
                iter.next();

                let protocol = protocol.ok_or(Error::InvalidProtocol)?;

                println!("{:?}", protocol);

                // get the domain
                let mut domain = String::new();
                for byte in iter.by_ref() {
                    if byte == b'/' {
                        break;
                    }
                    domain.push(byte as _).map_err(|_| Error::TooLong)?;
                }
                self.domain = (protocol, domain);

                // get the path
                let mut path = String::new();
                for byte in iter.by_ref() {
                    if byte == b' ' {
                        break;
                    }
                    path.push(byte as _).map_err(|_| Error::TooLong)?;
                }
                self.path = path;

                skip_line(&mut iter);
                self.state = State::PastHeader;
            }
            State::PastHeader { .. } => {
                // Skip the rest of the headers.
                while let Some(byte) = iter.next() {
                    if byte == b'\r' {
                        if let Some(b'\n') = iter.next() {
                            break;
                        }
                    }
                }
            }
        }

        Ok(())
    }
}
