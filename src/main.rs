use std::{
    net::{IpAddr, Ipv4Addr},
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

async fn handle_error<T, E: std::error::Error>(
    stream: &mut TcpStream,
    result: Result<T, E>,
) -> Result<T, E> {
    if let Err(ref e) = result {
        let err = e.to_string();
        let _ = stream.write_all(format!("HTTP/1.1 500 Internal Server Error\r\nContent-Length: {}\r\nContent-Type: text/plain\r\n\r\n{err}", err.len()).as_bytes()).await;
    }

    result
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

    let addr = Ipv4Addr::new(127, 0, 0, 1);
    let listener = TcpListener::bind((Ipv4Addr::new(127, 0, 0, 1), port))
        .await
        .unwrap();

    println!("Listening at http://{addr}:{port}");

    while let Ok((mut stream, _)) = listener.accept().await {
        tokio::spawn(async move {
            let mut parser = http::Parser::default();

            stream_loop!(Duration::from_secs(10), stream, buf, n => {
                let removed = handle_error(&mut stream, parser.modify_stream(&mut buf)).await.unwrap();
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
                let mut conn_stream = TcpStream::connect((ip, parser.addr.1)).await.unwrap();
                std::fs::write("test.http", &buf[..n - removed]).unwrap();
                conn_stream.write_all(&buf[..n - removed]).await.unwrap();
                stream_loop!(Duration::from_secs(5), conn_stream, buf, _ => {
                    stream.write_all(&buf).await.unwrap();
                });
            });
        });
    }
}

/// Removes an element from a slice.
///
/// Runs in O(n) time.
fn remove_from_slice(slice: &mut [u8], index: usize) {
    let len = slice.len();
    if index < len {
        unsafe {
            let ptr = slice.as_mut_ptr().add(index);
            std::ptr::copy(ptr.add(1), ptr, len - index - 1);
            std::ptr::write_bytes(ptr.add(len - index - 1), 0, 1);
        }
    }
}
