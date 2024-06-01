use std::error::Error;
use hyper::Request;
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use http_body_util::Empty;
// use bytes::BytesMut;
use hyper::body::Bytes;
use std::{env, ops::Range, str};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let url = "https://backend.nodeguardians.io/api/users/statistics?key=general";

    let url = url.parse::<hyper::Uri>()?;

    fetch_url(url).await
}

async fn fetch_url(url: hyper::Uri) -> Result<(), Box<dyn Error>> {
    let server_domain = url.authority().unwrap().host();

    let server_port = url.port_u16().unwrap_or(443);
    let stream = TcpStream::connect((server_domain, server_port)).await?;
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake((io)).await?;

    tokio::task::spawn(async move {
        if let Err(err) = conn.await {
            eprintln!("Connection failed: {:?}", err);
        }
    });

    let authority = url.authority().unwrap().clone();
    let path_and_query = url.path_and_query().map(|v| v.as_str()).unwrap_or("/");

    let auth_token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6NTQxNiwiaWF0IjoxNzE3MTY4NjM2LCJleHAiOjE3MTc2MDA2MzZ9.2q4kL2-jJ_Q2igiAKmiY_6o0DfOF6viqLMXzrCiWNE0";
    let user_agent="Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/116.0";

    let request = Request::builder()
        .uri(format!(
            "https://backend.nodeguardians.io/{path_and_query}"
        ))
        .header("Host", "backend.nodeguardians.io")
        .header("Accept", "*/*")
        .header("Accept-Encoding", "identity")
        .header("Accept-Language", "en-US,en;q=0.9")
        .header("Authorization", format!("Bearer {auth_token}"))
        .header("User-Agent", user_agent)
        .header("Connection", "close")
        .body(Empty::<Bytes>::new())
        .unwrap();

    let mut response = sender.send_request(request).await?;

    println!("Response: {}", response.status());
    println!("Headers: {:#?}\n", response.headers());

    // // Stream the body, writing each chunk to stdout as we get it
    // // (instead of buffering and printing at the end).
    // let mut body = BytesMut::new();
    // while let Some(chunk) = response.body_mut().data().await {
    //     body.extend_from_slice(&chunk?);
    // }

    // tokio::io::stdout().write_all(&body).await?;

    println!("\n\nDone!");

    Ok(())
}