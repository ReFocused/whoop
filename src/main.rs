use httparse::{Header, Response, EMPTY_HEADER};
use may::{go, net::TcpListener};
use std::{
    io::{Read, Write},
    net::Ipv4Addr,
};

fn calculate_response_size(res: &Response, body: &[u8]) -> usize {
    let mut size = 0;

    size += 12; // "HTTP/1.1 200 OK\r\n"

    for header in &*res.headers {
        size += header.name.len();
        size += 2; // ": "
        size += header.value.len();
        size += 2; // "\r\n"
    }

    size += 2; // "\r\n"

    size += body.len();

    size
}

fn generate_http_response(res: Response, body: &[u8]) -> Vec<u8> {
    let mut response = Vec::with_capacity(calculate_response_size(&res, body));

    response.extend_from_slice(b"HTTP/1.1 ");
    response.extend_from_slice(res.code.unwrap_or(200).to_string().as_bytes());
    response.extend_from_slice(b" ");
    response.extend_from_slice(res.reason.unwrap_or("OK").as_bytes());
    response.extend_from_slice(b"\r\n");

    for header in res.headers {
        response.extend_from_slice(header.name.as_bytes());
        response.extend_from_slice(b": ");
        response.extend_from_slice(header.value);
        response.extend_from_slice(b"\r\n");
    }

    response.extend_from_slice(b"Content-Length: ");
    response.extend_from_slice(body.len().to_string().as_bytes());

    response.extend_from_slice(b"\r\n\r\n");
    response.extend_from_slice(body);

    response
}

fn main() {
    let port = std::env::var("PORT").map_or(8000, |p| p.parse().unwrap());

    let addr = Ipv4Addr::new(127, 0, 0, 1);
    let listener = TcpListener::bind((Ipv4Addr::new(127, 0, 0, 1), port)).unwrap();
    println!("Listening at http://{addr}:{port}");

    while let Ok((mut stream, _)) = listener.accept() {
        go!(move || {
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(10)))
                .unwrap();
            stream
                .set_write_timeout(Some(std::time::Duration::from_secs(10)))
                .unwrap();

            let mut headers = [EMPTY_HEADER; 32];
            let mut req = httparse::Request::new(&mut headers);

            loop {
                let mut buf = vec![0; 1024];
                let n = stream.read(&mut buf).unwrap();

                if let Ok(httparse::Status::Complete(_)) = req.parse(&buf[..n]) {
                    break;
                };
            }

            let res = generate_http_response(
                httparse::Response {
                    version: Some(1),
                    code: Some(200),
                    reason: Some("OK"),
                    headers: &mut [Header {
                        name: "Content-Type",
                        value: b"text/plain",
                    }],
                },
                b"Hello, World!",
            );

            stream.write_all(&res).unwrap();
        });
    }
}
