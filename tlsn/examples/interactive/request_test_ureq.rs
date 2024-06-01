use ureq::Agent;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let url = "https://backend.nodeguardians.io/api/users/statistics?key=general";
    let agent = Agent::new();
    let response = agent
        .get(url)
        .set("Accept", "application/json")
        .set("Accept-Encoding", "identity")
        .set("Accept-Language", "en-US,en;q=0.9")
        .set("Authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6NTQxNiwiaWF0IjoxNzE3MTY4NjM2LCJleHAiOjE3MTc2MDA2MzZ9.2q4kL2-jJ_Q2igiAKmiY_6o0DfOF6viqLMXzrCiWNE0")
        .set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")
        .call().unwrap();
    let status = response.status();
    let body = response.into_string().unwrap();

    println!("Status: {}", status);
    println!("Body: {}", body);

    Ok(())
}