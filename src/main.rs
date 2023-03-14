use http::Error;
use std::{
    future::Future,
    net::{IpAddr, Ipv4Addr},
    pin::Pin,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};
use trust_dns_resolver::{
    config::{ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
};

mod http;

trait ResultExt<'a, T: Send + Sync + 'a> {
    fn send_unwrap(
        self,
        stream: &'a mut TcpStream,
    ) -> Pin<Box<dyn Future<Output = T> + 'a + Send + Sync>>;
}

impl<'a, T: Send + Sync + 'a> ResultExt<'a, T> for Result<T, Error> {
    fn send_unwrap(
        self,
        stream: &'a mut TcpStream,
    ) -> Pin<Box<dyn Future<Output = T> + 'a + Send + Sync>> {
        Box::pin(async move {
            match self {
                Ok(t) => t,
                Err(e) => {
                    let err = e.as_str();
                    let _ = stream.write_all(format!("HTTP/1.1 400 Bad Request\r\nContent-Length: {}\r\nContent-Type: text/plain\r\n\r\n{err}", err.len()).as_bytes()).await;
                    #[cfg(not(debug_assertions))]
                    std::panic::resume_unwind(Box::new(()));
                    #[cfg(debug_assertions)]
                    panic!("{e:#?}");
                }
            }
        })
    }
}

macro_rules! stream_loop {
    ($timeout:expr, $stream:expr, $buf:ident, $n:pat => $body:block) => {
        loop {
            let mut $buf = [0u8; 1024];
            match timeout($timeout, $stream.read(&mut $buf)).await {
                Err(_) | Ok(Ok(0)) => break, // timeout or EOF
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

    while let Ok((mut stream, _)) = listener.accept().await {
        tokio::spawn(async move {
            let mut parser = http::Parser::default();

            stream_loop!(Duration::from_secs(10), stream, buf, n => {
                let idx = parser.modify_stream(&mut buf[..n]).send_unwrap(&mut stream).await;
                let ip = if let Ok(ip) = parser.addr.0.parse::<IpAddr>() {
                    ip
                } else {
                    TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), ResolverOpts::default())
                        .unwrap()
                        .lookup_ip(&*parser.addr.0)
                        .await
                        .unwrap()
                        .iter()
                        .next()
                        .unwrap()
                };
                if ip.is_loopback() {
                    stream.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 11\r\nContent-Type: text/plain\r\n\r\nYou thought").await.unwrap();
                    break;
                }
                let mut conn_stream = TcpStream::connect((ip, parser.addr.1)).await.unwrap();
                std::fs::write("test.http", &buf[..idx]).unwrap();
                conn_stream.write_all(&buf[..idx]).await.unwrap();
                stream_loop!(Duration::from_secs(5), conn_stream, buf, _ => {
                    stream.write_all(&buf).await.unwrap();
                });
            });
        });
    }
}
