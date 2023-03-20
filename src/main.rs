#![warn(clippy::pedantic, clippy::nursery, clippy::cargo)]
#![allow(clippy::multiple_crate_versions)]

use std::{
    net::{IpAddr, Ipv4Addr},
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
    LoopbackIp,
    InternalServerError,
}
impl Error {
    const fn as_str(&self) -> &'static str {
        match self {
            Self::Http(e) => e.as_str(),
            Self::NotFound => "Not Found",
            Self::IpNotSupported => "IP addresses are not supported",
            Self::LoopbackIp => "Don't use loopback IPs 😔",
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
    panic!("{err}");
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
            if let Err(e) = handle_stream(dns_resolver, rustls_connector, &mut stream).await {
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

    stream_loop!(Duration::from_secs(10), stream, buf, n => {
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

            macro_rules! end {
                ($in_stream: ident => $out_stream: ident) => {
                    $in_stream.write_all(buf).await?;
                    $in_stream.flush().await?;

                    stream_loop!(Duration::from_secs(10), $in_stream, buf, n => {
                        let buf = &mut buf[..n];
                        modify_response(buf);
                        $out_stream.write_all(buf).await?;
                    });

                    $out_stream.flush().await?;
                }
            }

            let mut conn_stream = TcpStream::connect((ip, info.port.get())).await?;

            if info.protocol == http::Protocol::Https {
                let mut conn_stream = rustls_connector.connect(
                    ServerName::try_from(&*info.addr).map_err(|_| Error::NotFound)?,
                    conn_stream
                ).await?;

                conn_stream.write_all(buf).await?;
                conn_stream.flush().await?;

                end!(conn_stream => stream);
            } else {
                end!(conn_stream => stream);
            }

            break;
        }
    });

    Ok(())
}
