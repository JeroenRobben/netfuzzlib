# Rust HTTP server. std::net::TcpListener uses libc on Linux, so the
# nfl interceptors should fire just like for C/Python. No external
# crates, just stdlib.
FROM netfuzzlib-base

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        rustc \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/rustapp && cat > /opt/rustapp/server.rs <<'EOF'
use std::env;
use std::io::{Read, Write};
use std::net::TcpListener;

fn main() -> std::io::Result<()> {
    let host = env::var("HTTP_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let port = env::var("HTTP_PORT").unwrap_or_else(|_| "8085".into());
    let addr = format!("{}:{}", host, port);
    let listener = TcpListener::bind(&addr)?;
    eprintln!("listening on {}", addr);
    for stream in listener.incoming() {
        let mut s = stream?;
        let mut buf = [0u8; 1024];
        let _ = s.read(&mut buf);
        let body = "nfl-rust-ok\n";
        let resp = format!(
            "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        s.write_all(resp.as_bytes())?;
    }
    Ok(())
}
EOF
RUN cd /opt/rustapp && rustc -O server.rs -o server

COPY test/integration/docker/rust-http/run.sh /opt/nfl/targets/rust-http/run.sh
RUN chmod +x /opt/nfl/targets/rust-http/run.sh

ENV NFL_TARGET_NAME=rust-http \
    NFL_TARGET_RUN_SH=/opt/nfl/targets/rust-http/run.sh

ENTRYPOINT ["/opt/nfl/bin/nfl-entrypoint"]
CMD ["test"]
