use reqwest::header::{ACCEPT, ACCEPT_ENCODING, ACCEPT_LANGUAGE, AUTHORIZATION, USER_AGENT};
use std::error::Error;
use http::Version;
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let url = "https://backend.nodeguardians.io/api/users/statistics?key=general";
    let client = reqwest::Client::new();
    let response = client
        .get(url)
        .header(ACCEPT, "application/json")
        .header(ACCEPT_ENCODING, "identity")
        .header(ACCEPT_LANGUAGE, "en-US,en;q=0.9")
        .header(AUTHORIZATION, "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6NTQxNiwiaWF0IjoxNzE3MTY4NjM2LCJleHAiOjE3MTc2MDA2MzZ9.2q4kL2-jJ_Q2igiAKmiY_6o0DfOF6viqLMXzrCiWNE0")
        .header(USER_AGENT, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")
        .send()
        .await?;

        let status = response.status();
        let version = response.version();
        let body = response.text().await?;
    
        println!("Status: {}", status);
        println!("Body: {}", body);
        println!("HTTP Version: {}", match version {
            Version::HTTP_11 => "HTTP/1.1",
            Version::HTTP_2 => "HTTP/2",
            Version::HTTP_09 => "HTTP/0.9",
            Version::HTTP_10 => "HTTP/1.0",
            _ => "Unknown",
        });
    Ok(())
}
