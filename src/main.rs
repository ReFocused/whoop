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

mod http;

#[derive(Debug)]
enum Error {
    Http(http::Error),
    NotFound,
    InternalServerError,
}
impl Error {
    const fn as_str(&self) -> &'static str {
        match self {
            Self::Http(e) => e.as_str(),
            Self::NotFound => "Not Found",
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

trait ResultExt<'a, T: Send + Sync + 'a, E: Into<Error> + Send + Sync + 'a> {
    fn send_unwrap(
        self,
        stream: &'a mut TcpStream,
    ) -> Pin<Box<dyn Future<Output = T> + 'a + Send + Sync>>;
}

impl<'a, T: Send + Sync + 'a, E: Into<Error> + Send + Sync + 'a> ResultExt<'a, T, E>
    for Result<T, E>
{
    fn send_unwrap(
        self,
        stream: &'a mut TcpStream,
    ) -> Pin<Box<dyn Future<Output = T> + 'a + Send + Sync>> {
        Box::pin(async move {
            match self {
                Ok(t) => t,
                Err(e) => {
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
                    silent_panic();
                }
            }
        })
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

fn silent_panic() -> ! {
    std::panic::resume_unwind(Box::new(()));
}

#[tokio::main]
async fn main() {
    let port = std::env::var("PORT").map_or(8000, |p| p.parse().unwrap());
    let listener = TcpListener::bind((Ipv4Addr::new(0, 0, 0, 0), port))
        .await
        .unwrap();

    println!("Listening at http://localhost:{port}");

    let dns_resolver =
        TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), ResolverOpts::default()).unwrap();

    let mut root_store = RootCertStore::empty();
    root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));
    let rustls_config = Arc::new(
        tokio_rustls::rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    );

    let rustls_connector = TlsConnector::from(rustls_config.clone());

    while let Ok((mut stream, _)) = listener.accept().await {
        let dns_resolver = dns_resolver.clone();
        let rustls_connector = rustls_connector.clone();
        tokio::spawn(async move {
            let mut parser = http::Parser::default();

            stream_loop!(Duration::from_secs(10), stream, buf, _ => {
                let idx = parser.modify_stream(&mut buf).send_unwrap(&mut stream).await;

                let mut is_ip = false;
                let ip = if let Ok(ip) = parser.addr.0.parse::<IpAddr>() {
                    is_ip = true;
                    ip
                } else if let Ok(ips) = dns_resolver.lookup_ip(&*parser.addr.0).await {
                    if let Some(ip) = ips.iter().find(|ip| !ip.is_loopback()) {
                        ip
                    } else {
                        Err::<(), _>(Error::NotFound).send_unwrap(&mut stream).await;
                        unreachable!();
                    }
                } else {
                    Err::<(), _>(Error::NotFound).send_unwrap(&mut stream).await;
                    unreachable!();
                };
                if ip.is_loopback() {
                    stream
                        .write_all(
                            b"HTTP/1.1 403 Forbidden\r\nContent-Length: 11\r\nContent-Type: text/plain\r\n\r\nYou thought",
                        )
                        .await
                        .unwrap();
                    break;
                }
                let mut conn_stream = TcpStream::connect((ip, parser.addr.1.as_u16())).await.unwrap();
                if parser.protocol == http::Protocol::Https {
                    let mut stream = rustls_connector.connect(
                        if is_ip {
                            ServerName::IpAddress(ip)
                        } else {
                            ServerName::try_from(parser.addr.0.as_str()).map_err(|_| Error::NotFound).send_unwrap(&mut stream).await
                        },
                        &mut conn_stream
                    ).await.unwrap();

                    stream.write_all(&buf[..idx]).await.unwrap();
                    stream_loop!(Duration::from_secs(5), stream, buf, _ => {
                        stream.write_all(&buf).await.unwrap();
                    });
                } else {
                    conn_stream.write_all(&buf[..idx]).await.unwrap();
                    stream_loop!(Duration::from_secs(5), conn_stream, buf, _ => {
                        stream.write_all(&buf).await.unwrap();
                    });
                }

            });
        });
    }
}
