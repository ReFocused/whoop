#![warn(clippy::pedantic, clippy::nursery, clippy::cargo)]
#![allow(clippy::multiple_crate_versions)]

use std::{net::Ipv4Addr, pin::Pin, sync::Arc};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tokio_rustls::{
    client::TlsStream,
    rustls::{OwnedTrustAnchor, RootCertStore, ServerName},
    TlsConnector,
};
use trust_dns_resolver::{
    config::{ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
};

use crate::http::modify_response;

mod http;

#[derive(Debug, Clone, Copy)]
enum Error {
    Http(http::Error),
    NotFound,
    LoopbackIp,
    DowngradeToHTTP,
    InternalServerError,
}
impl Error {
    pub const fn into_str(self) -> &'static str {
        match self {
            Self::Http(e) => e.into_str(),
            Self::NotFound => "Not Found",
            Self::LoopbackIp => "Don't use loopback IPs 😔",
            Self::DowngradeToHTTP => "",
            Self::InternalServerError => "Internal Server Error",
        }
    }
    pub const fn code(self) -> u16 {
        match self {
            Self::Http(e) => e.code(),
            Self::NotFound => 404,
            Self::LoopbackIp => 403,
            Self::DowngradeToHTTP => 308,
            Self::InternalServerError => 500,
        }
    }
}
impl From<http::Error> for Error {
    fn from(e: http::Error) -> Self {
        Self::Http(e)
    }
}
impl<T: std::error::Error + Send + Sync + 'static> From<T> for Error {
    #[allow(unused_variables)]
    fn from(e: T) -> Self {
        Self::InternalServerError
    }
}

async fn send_error(e: impl Into<Error> + Send + Sync, stream: &mut TcpStream) {
    let e = e.into();
    let err = e.into_str();
    let _ = stream.write_all(b"HTTP/1.0 ").await;
    {
        let (bytes, digits) = num_to_bytes(e.code());
        let _ = stream.write_all(&bytes[..digits]).await;
    }
    let _ = stream.write_all(b"\r\nContent-Length: ").await;

    {
        #[allow(clippy::cast_possible_truncation)] // the error length should never exceed a u16
        let (bytes, digits) = num_to_bytes(err.len() as _);
        let _ = stream.write_all(&bytes[..digits]).await;
    }
    let _ = stream
        .write_all(b"\r\nContent-Type: text/plain\r\n\r\n")
        .await;
    let _ = stream.write_all(err.as_bytes()).await;
}

macro_rules! stream_loop {
    ($stream: expr, $buf: ident, $n: pat => $body: block) => {
        loop {
            let mut $buf = [0u8; 1024];
            match timeout(std::time::Duration::from_secs(10), $stream.read(&mut $buf)).await {
                // timeout or EOF
                Err(_) | Ok(Ok(0)) => break,
                Ok(Ok($n)) => $body,
                Ok(Err(e)) => panic!("Error reading from stream: {}", e),
            };
        }
    };
}

#[tokio::main]
async fn main() {
    let port = std::env::var("PORT").map_or(8000, |p| p.parse().unwrap());
    let listener = TcpListener::bind((Ipv4Addr::new(0, 0, 0, 0), port))
        .await
        .unwrap();

    println!("Listening at http://localhost:{port}");

    std::fs::create_dir_all("http").unwrap();

    let dns_resolver = Arc::new(
        TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), ResolverOpts::default()).unwrap(),
    );

    let mut root_store = RootCertStore::empty();
    root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));
    let rustls_connector = TlsConnector::from(Arc::new(
        tokio_rustls::rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    ));

    while let Ok((mut stream, _)) = listener.accept().await {
        let dns_resolver = dns_resolver.clone();
        let rustls_connector = rustls_connector.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_stream(dns_resolver, rustls_connector, &mut stream).await {
                eprintln!("{e:#?}");
                send_error(e, &mut stream).await;
            }
        });
    }
}

async fn handle_stream(
    dns_resolver: Arc<TokioAsyncResolver>,
    rustls_connector: TlsConnector,
    stream: &mut TcpStream,
) -> Result<(), Error> {
    let mut parser = http::Parser::default();

    let mut connection = None;

    stream_loop!(stream, buf, n => {
        let buf = {
            let removed = parser.modify_stream(&mut buf)?;
            let n = n - removed;
            &buf[..n]
        };

        if let Some(ref info) = parser.info {
            let ip = if let Ok(ips) = dns_resolver.lookup_ip(&*info.addr).await {
                if let Some(ip) = ips.iter().find(|ip| !ip.is_loopback()) {
                    ip
                } else {
                    return Err(Error::NotFound);
                }
            } else {
                return Err(Error::NotFound);
            };

            if ip.is_loopback() {
                return Err(Error::LoopbackIp);
            }

            let mut conn = if let Some(c) = connection.take() {
                c
            } else {
                let c = match TcpStream::connect((ip, info.port.get())).await {
                    Ok(c) => c,
                    Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset && info.protocol == http::Protocol::Https => {
                        return Err(Error::DowngradeToHTTP);
                    },
                    Err(e) => return Err(Error::from(e)),
                };
                if info.protocol == http::Protocol::Https {
                    let c = rustls_connector.connect(
                        ServerName::try_from(&*info.addr).map_err(|_| Error::NotFound)?,
                        c
                    ).await?;

                    Connection::Https(c)
                } else {
                    Connection::Http(c)
                }
            };

            conn.write_all(buf).await?;
            conn.flush().await?;

            if parser.finished {
                let mut found_end = false;
                stream_loop!(conn, buf, n => {
                    let buf = &mut buf[..n];

                    if found_end {
                        stream.write_all(buf).await?;
                        continue;
                    }

                    if modify_response(buf) {
                        stream.write_all(buf).await?;
                        found_end = true;
                    } else {
                        let Some(end_idx) = memchr::memmem::find(buf, b"\r\n\r\n") else {
                            stream.write_all(buf).await?;
                            continue;
                        };
                        found_end = true;
                        stream.write_all(&buf[..end_idx]).await?;
                        stream.write_all(b"\r\nAccess-Control-Allow-Origin: *\r\n").await?;
                        stream.write_all(&buf[end_idx..]).await?;
                    }

                    stream.flush().await?;
                });
                break;
            }

            connection.replace(conn);
        }
    });

    Ok(())
}
enum Connection {
    Http(TcpStream),
    Https(TlsStream<TcpStream>),
}

impl AsyncWrite for Connection {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        match unsafe {
            // SAFETY: we do not move out of the pin; we only re-pin it
            Pin::into_inner_unchecked(self)
        } {
            Self::Http(c) => TcpStream::poll_write(
                unsafe {
                    // SAFETY: this was previously pinned
                    Pin::new_unchecked(c)
                },
                cx,
                buf,
            ),
            Self::Https(c) => TlsStream::poll_write(
                unsafe {
                    // SAFETY: this was previously pinned
                    Pin::new_unchecked(c)
                },
                cx,
                buf,
            ),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        match unsafe {
            // SAFETY: we do not move out of the pin; we only re-pin it
            Pin::into_inner_unchecked(self)
        } {
            Self::Http(c) => TcpStream::poll_flush(
                unsafe {
                    // SAFETY: this was previously pinned
                    Pin::new_unchecked(c)
                },
                cx,
            ),
            Self::Https(c) => TlsStream::poll_flush(
                unsafe {
                    // SAFETY: this was previously pinned
                    Pin::new_unchecked(c)
                },
                cx,
            ),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        match unsafe {
            // SAFETY: we do not move out of the pin; we only re-pin it
            Pin::into_inner_unchecked(self)
        } {
            Self::Http(c) => TcpStream::poll_shutdown(
                unsafe {
                    // SAFETY: this was previously pinned
                    Pin::new_unchecked(c)
                },
                cx,
            ),
            Self::Https(c) => TlsStream::poll_shutdown(
                unsafe {
                    // SAFETY: this was previously pinned
                    Pin::new_unchecked(c)
                },
                cx,
            ),
        }
    }
}
impl AsyncRead for Connection {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match unsafe {
            // SAFETY: we do not move out of the pin; we only re-pin it
            Pin::into_inner_unchecked(self)
        } {
            Self::Http(c) => TcpStream::poll_read(
                unsafe {
                    // SAFETY: this was previously pinned
                    Pin::new_unchecked(c)
                },
                cx,
                buf,
            ),
            Self::Https(c) => TlsStream::poll_read(
                unsafe {
                    // SAFETY: this was previously pinned
                    Pin::new_unchecked(c)
                },
                cx,
                buf,
            ),
        }
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
    #[allow(clippy::manual_swap)]
    while j < i / 2 {
        let tmp = bytes[j];
        bytes[j] = bytes[i - j - 1];
        bytes[i - j - 1] = tmp;
        j += 1;
    }

    (bytes, digits)
}
