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
                    std::panic::resume_unwind(Box::new(()));
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

                if let Some(ref info) = parser.info {
                    let mut is_ip = false;
                    let ip = if let Ok(ip) = info.addr.parse::<IpAddr>() {
                        is_ip = true;
                        ip
                    } else if let Ok(ips) = dns_resolver.lookup_ip(&*info.addr).await {
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

                    macro_rules! end {
                        ($out_stream:ident, $in_stream:ident) => {{
                            $out_stream.write_all(&buf[..idx]).await.unwrap();
                            stream_loop!(Duration::from_secs(5), $in_stream, buf, n => {
                                modify_response(&mut buf);
                                println!("{}", String::from_utf8_lossy(&buf[..n]));
                                $out_stream.write_all(&buf[..n]).await.unwrap();
                            });
                        }};
                    }

                    let mut conn_stream = TcpStream::connect((ip, info.port.get())).await.unwrap();
                    if info.protocol == http::Protocol::Https {
                        let mut conn_stream = rustls_connector.connect(
                            if is_ip {
                                ServerName::IpAddress(ip)
                            } else {
                                ServerName::try_from(&*info.addr).map_err(|_| Error::NotFound).send_unwrap(&mut stream).await
                            },
                            conn_stream
                        ).await.unwrap();

                        end!(conn_stream, stream);
                    } else {
                        end!(stream, conn_stream);
                    }
                }
            });
        });
    }
}
