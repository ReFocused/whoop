#![warn(clippy::pedantic, clippy::nursery, clippy::cargo)]
#![allow(clippy::multiple_crate_versions)]

use std::{
    net::{IpAddr, Ipv4Addr},
    pin::Pin,
    sync::Arc,
};
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

#[derive(Debug)]
enum Error {
    Http(http::Error),
    NotFound,
    IpNotSupported,
    LoopbackIp,
    InternalServerError(#[cfg(debug_assertions)] Box<dyn std::error::Error + Send + Sync>),
}
impl Error {
    fn into_str(self) -> &'static str {
        match self {
            Self::Http(e) => e.as_str(),
            Self::NotFound => "Not Found",
            Self::IpNotSupported => "IP addresses are not supported",
            Self::LoopbackIp => "Don't use loopback IPs 😔",
            #[cfg(not(debug_assertions))]
            Self::InternalServerError() => "Internal Server Error",
            #[cfg(debug_assertions)]
            Self::InternalServerError(e) => {
                Box::leak(format!("Internal Server Error: {e} ({e:#?})").into_boxed_str())
                // leaking is fine because we're running in debug mode
            }
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
        #[cfg(debug_assertions)]
        return Self::InternalServerError(Box::new(e));
        #[cfg(not(debug_assertions))]
        return Self::InternalServerError();
    }
}

async fn send_error(e: impl Into<Error> + std::fmt::Debug + Send + Sync, stream: &mut TcpStream) {
    let err = e.into().into_str();
    let _unneeded =
        stream
            .write_all(
                format!(
                    "HTTP/1.1 400 Bad Request\r\nContent-Length: {}\r\nContent-Type: text/plain\r\n\r\n{err}",
                    err.len()
                ).as_bytes(),
            )
            .await;
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
            let ip = if info.addr.parse::<IpAddr>().is_ok() {
                return Err(Error::IpNotSupported);
            } else if let Ok(ips) = dns_resolver.lookup_ip(&*info.addr).await {
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
                let c = TcpStream::connect((ip, info.port.get())).await?;
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

            // println!("{}", String::from_utf8_lossy(buf));
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
                        stream.write_all(b"Access-Control-Allow-Origin: *").await?;
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
