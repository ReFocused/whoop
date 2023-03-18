#![warn(clippy::pedantic, clippy::nursery, clippy::cargo)]
#![allow(clippy::multiple_crate_versions)]

use std::{
    future::Future,
    net::{IpAddr, Ipv4Addr},
    pin::Pin,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tokio_rustls::{
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
    LocalAddress,
    InternalServerError,
}
impl Error {
    const fn as_str(&self) -> &'static str {
        match self {
            Self::Http(e) => e.as_str(),
            Self::NotFound => "Not Found",
            Self::IpNotSupported => "IP addresses are not supported",
            Self::LocalAddress => "Don't try to connect to localhost 😔",
            Self::InternalServerError => "Internal Server Error",
        }
    }
}
impl From<http::Error> for Error {
    fn from(e: http::Error) -> Self {
        Self::Http(e)
    }
}
impl<T: std::error::Error> From<T> for Error {
    fn from(_: T) -> Self {
        Self::InternalServerError
    }
}

trait ResultExt<'a, T: Send + Sync + 'a, E: std::fmt::Debug + Send + Sync + 'a> {
    fn send_unwrap(
        self,
        stream: &'a mut TcpStream,
    ) -> Pin<Box<dyn Future<Output = T> + 'a + Send + Sync>>
    where
        E: Into<Error>;
    fn silent_unwrap(self) -> T;
}

async fn send_error(e: impl Into<Error> + Send + Sync, stream: &mut TcpStream) -> ! {
    let err = e.into().as_str();
    let _ =
        stream
            .write_all(
                format!(
                    "HTTP/1.1 400 Bad Request\r\nContent-Length: {}\r\nContent-Type: text/plain\r\n\r\n{err}",
                    err.len()
                ).as_bytes(),
            )
            .await;
    std::panic::resume_unwind(Box::new(()));
}

impl<'a, T: Send + Sync + 'a, E: std::fmt::Debug + Send + Sync + 'a> ResultExt<'a, T, E>
    for Result<T, E>
{
    fn send_unwrap(
        self,
        stream: &'a mut TcpStream,
    ) -> Pin<Box<dyn Future<Output = T> + 'a + Send + Sync>>
    where
        E: Into<Error>,
    {
        Box::pin(async move {
            match self {
                Ok(t) => t,
                Err(e) => send_error(e, stream).await,
            }
        })
    }
    fn silent_unwrap(self) -> T {
        match self {
            Ok(t) => t,
            Err(e) => {
                #[cfg(debug_assertions)]
                panic!("Called silent_unwrap on error: {e:?}");
                #[cfg(not(debug_assertions))]
                std::panic::resume_unwind(Box::new(()));
            }
        }
    }
}

macro_rules! stream_loop {
    ($timeout: expr, $stream: expr, $buf: ident, $n: pat => $body: block) => {
        loop {
            let mut $buf = [0u8; 1024];
            match timeout($timeout, $stream.read(&mut $buf)).await {
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
            let mut parser = http::Parser::default();

            stream_loop!(Duration::from_secs(10), stream, buf, n => {
                let buf = {
                    let removed = parser.modify_stream(&mut buf).send_unwrap(&mut stream).await;
                    let n = n - removed;
                    &buf[..n]
                };

                if let Some(ref info) = parser.info {
                    let ip = if info.addr.parse::<IpAddr>().is_ok() {
                        send_error(Error::IpNotSupported, &mut stream).await
                    } else if let Ok(ips) = dns_resolver.lookup_ip(&*info.addr).await {
                        if let Some(ip) = ips.iter().find(|ip| !ip.is_loopback()) {
                            ip
                        } else {
                            send_error(Error::NotFound, &mut stream).await
                        }
                    } else {
                        send_error(Error::NotFound, &mut stream).await
                    };

                    if ip.is_loopback() {
                        send_error(Error::LocalAddress, &mut stream).await;
                    }

                    macro_rules! end {
                        ($in_stream: ident => $out_stream: ident) => {
                            $in_stream.write_all(buf).await.unwrap();
                            $in_stream.flush().await.unwrap();

                            stream_loop!(Duration::from_secs(10), $in_stream, buf, n => {
                                let buf = &mut buf[..n];
                                modify_response(buf);
                                $out_stream.write_all(buf).await.unwrap();
                            });

                            $out_stream.flush().await.unwrap();
                        }
                    }

                    let mut conn_stream = TcpStream::connect((ip, info.port.get())).await.unwrap();

                    if info.protocol == http::Protocol::Https {
                        let mut conn_stream = rustls_connector.connect(
                            ServerName::try_from(&*info.addr).map_err(|_| Error::NotFound).send_unwrap(&mut stream).await,
                            conn_stream
                        ).await.unwrap();

                        conn_stream.write_all(buf).await.unwrap();
                        conn_stream.flush().await.unwrap();

                        end!(conn_stream => stream);
                    } else {
                        end!(conn_stream => stream);
                    }

                    break;
                }
            });
        });
    }
}
