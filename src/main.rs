use circular_buffer::CircularBuffer;
use may::{go, net::TcpListener};
use std::{
    io::{self, Read, Write},
    net::Ipv4Addr,
};

mod http;

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

            let mut buf = CircularBuffer::<2048, u8>::new();

            let mut parser = http::Parser::default();

            loop {
                let mut tmp = [0u8; 1024];
                match dbg!(stream.read(&mut tmp)) {
                    Ok(0) => break,
                    Ok(n) => {
                        buf.extend_from_slice(unsafe {
                            // SAFETY: `n` is the number of bytes pushed into the buffer.
                            tmp.get_unchecked(..n)
                        });
                        parser.modify_stream(&mut buf).unwrap();
                        println!("{parser:?}");
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        buf.clear();
                    }
                    Err(e) => {
                        println!("Error: {e}");
                        break;
                    }
                };
                buf.extend_from_slice(&tmp);
            }
        });
    }
}
