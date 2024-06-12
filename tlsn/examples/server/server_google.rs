use std::net::SocketAddr;

use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::{body::Bytes, Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use hyper::header::{CONTENT_LENGTH, CONTENT_TYPE};
use hyper_tls::HttpsConnector;

use hyper::server::conn::http1;
use hyper::service::service_fn;

use tlsn_core::{proof::SessionInfo, Direction, RedactedTranscript};
use tlsn_prover::tls::{state::Prove, Prover, ProverConfig};
use tlsn_verifier::tls::{Verifier, VerifierConfig};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::instrument;

use regex::Regex;
use std::{clone, str};
use std::collections::HashMap;
use url::Url;
use serde_urlencoded;

use reqwest::Client;
use serde::Deserialize;

const SECRET: &str = "TLSNotary's private key 🤡";
const SERVER_DOMAIN: &str = "people.googleapis.com";

// to test:
// https://accounts.google.com/o/oauth2/v2/auth?client_id=16395376621-7pbfosl2qi9gnb0u7282vucp451k8m0h.apps.googleusercontent.com&response_type=code&redirect_uri=http://localhost:8000&scope=https://www.googleapis.com/auth/userinfo.email%20profile&access_type=offline


#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
    refresh_token: String,
    scope: String,
    token_type: String,
    id_token: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt::init();

    let addr = SocketAddr::from(([127, 0, 0, 1], 8000));
    let listener = TcpListener::bind(addr).await?;

    println!("Listening on http://{}", addr);
    
    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);

        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .serve_connection(io, service_fn(handle_request))
                .await
            {
                println!("Error serving connection: {:?}", err);
            }
        });
    }
}

async fn handle_request(
    req: Request<hyper::body::Incoming>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    match (req.method(), req.uri().path()) {
        // Serve some instructions at /
        (&Method::GET, "/") => {
            let query = req.uri().query().unwrap_or("");
            let parsed_query = Url::parse(&format!("http://localhost:8000/?{}", query)).unwrap();
            let code = parsed_query.query_pairs().find(|(key, _)| key == "code");

            match code {
                Some((_, value)) => {
                    let auth_code = value.to_string();

                    println!("");
                    let response_body = format!("Authorization Code: {}", value);
                    println!("{}", response_body);

                    let auth_str: &str = auth_code.as_str();
                    let access_token_result = get_access_token(auth_str).await;

                    if let Ok(access_token) = access_token_result {
                        // Convert String to &str
                        let access_token_str: &str = access_token.as_str();
                        println!("");
                        println!("Access Token: {}", access_token_str);
                        println!("");
                        tokio::task::spawn(service(access_token));
                    } else {
                        eprintln!("Failed to get access token: {:?}", access_token_result);
                    }

                    Ok(Response::new(full(response_body)))
                }
                None => {
                    let response_body = "Error: No authorization code received.";
                    let mut resp = Response::new(full(response_body));
                    *resp.status_mut() = StatusCode::BAD_REQUEST;
                    Ok(resp)
                }
            }
        }

        // Return the 404 Not Found for other routes.
        _ => {
            let mut not_found = Response::new(empty());
            *not_found.status_mut() = StatusCode::NOT_FOUND;
            Ok(not_found)
        }
    }
}

fn empty() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}

async fn get_access_token(auth_code: &str) -> Result<String, Box<dyn std::error::Error>> {
    let client = Client::new();

    let mut params = HashMap::new();
    params.insert("grant_type", "authorization_code");
    params.insert("code", auth_code);
    params.insert("client_id", "16395376621-7pbfosl2qi9gnb0u7282vucp451k8m0h.apps.googleusercontent.com");
    params.insert("client_secret", "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");
    params.insert("redirect_uri", "http://localhost:8000");

    let response = client.post("https://oauth2.googleapis.com/token")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .form(&params)
        .send()
        .await?
        .json::<TokenResponse>()
        .await?;

    Ok(response.access_token)
}

async fn service(bearer_token: String) {
    let uri = "https://people.googleapis.com/v1/people/me?personFields=emailAddresses";
    let id = "interactive verifier demo";

    // Connect prover and verifier.
    let (prover_socket, verifier_socket) = tokio::io::duplex(1 << 23);
    let prover = prover(prover_socket, uri, id, bearer_token);
    let verifier = verifier(verifier_socket, id);
    let (_, (sent, received, _session_info)) = tokio::join!(prover, verifier);

    println!("Successfully verified {}", &uri);
    println!(
        "Verified sent data:\n{}",
        bytes_to_redacted_string(sent.data())
    );
    println!(
        "Verified received data:\n{}",
        bytes_to_redacted_string(received.data())
    );
}

#[instrument(skip(verifier_socket))]
async fn prover<T: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
    verifier_socket: T,
    uri: &str,
    id: &str,
    bearer_token: String,
) {
    let uri = uri.parse::<Uri>().unwrap();
    assert_eq!(uri.scheme().unwrap().as_str(), "https");
    let host = uri.host().expect("uri has no host");
    let server_domain = uri.authority().unwrap().host();
    let server_port = uri.port_u16().unwrap_or(443);

    println!("");
    println!("Connecting to {}", &uri);
    println!("Server domain: {}", &server_domain);
    println!("Server host: {}", &host);
    println!("");

    // Create prover and connect to verifier.
    //
    // Perform the setup phase with the verifier.
    let prover = Prover::new(
        ProverConfig::builder()
            .id(id)
            .server_dns(server_domain)
            .build()
            .unwrap(),
    )
    .setup(verifier_socket.compat())
    .await
    .unwrap();

    // Connect to TLS Server.
    let tls_client_socket = tokio::net::TcpStream::connect((server_domain, server_port))
        .await
        .unwrap();

    // Pass server connection into the prover.
    let (mpc_tls_connection, prover_fut) =
        prover.connect(tls_client_socket.compat()).await.unwrap();

    // Grab a controller for the Prover so we can enable deferred decryption.
    let ctrl = prover_fut.control();

    // Wrap the connection in a TokioIo compatibility layer to use it with hyper.
    let mpc_tls_connection = TokioIo::new(mpc_tls_connection.compat());

    // Spawn the Prover to run in the background.
    let prover_task = tokio::spawn(prover_fut);

    // MPC-TLS Handshake.
    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(mpc_tls_connection)
            .await
            .unwrap();

    // Spawn the connection to run in the background.
    tokio::spawn(connection);

    // Enable deferred decryption. This speeds up the proving time, but doesn't
    // let us see the decrypted data until after the connection is closed.
    ctrl.defer_decryption().await.unwrap();

    // to test:
    // https://accounts.google.com/o/oauth2/v2/auth?client_id=16395376621-7pbfosl2qi9gnb0u7282vucp451k8m0h.apps.googleusercontent.com&response_type=code&redirect_uri=http://localhost:8000&scope=https://www.googleapis.com/auth/userinfo.email%20profile&access_type=offline

    // MPC-TLS: Send Request and wait for Response.
    let request = Request::builder()
        .uri(uri.to_string())
        .method("GET")
        .header("host", SERVER_DOMAIN)
        .header("accept", "application/json")
        .header("authorization", "Bearer ".to_string() + &bearer_token)
        .header("Connection", "close")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let response = request_sender.send_request(request).await.unwrap();

    // println!("Response: {:?}", response);

    // assert!(response.status() == StatusCode::OK);

    // Create proof for the Verifier.
    let mut prover = prover_task.await.unwrap().unwrap().start_prove();
    redact_and_reveal_received_data(&mut prover);
    redact_and_reveal_sent_data(&mut prover);
    prover.prove().await.unwrap();

    // Finalize.
    prover.finalize().await.unwrap()
}

#[instrument(skip(socket))]
async fn verifier<T: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static>(
    socket: T,
    id: &str,
) -> (RedactedTranscript, RedactedTranscript, SessionInfo) {
    // Setup Verifier.
    let verifier_config = VerifierConfig::builder().id(id).build().unwrap();
    let verifier = Verifier::new(verifier_config);

    // Verify MPC-TLS and wait for (redacted) data.
    let (sent, received, session_info) = verifier.verify(socket.compat()).await.unwrap();

    // Check send data: check host.
    let sent_data = String::from_utf8(sent.data().to_vec()).expect("Verifier expected sent data");
    sent_data
        .find(SERVER_DOMAIN)
        .unwrap_or_else(|| panic!("Verification failed: Expected host {}", SERVER_DOMAIN));

    // Check received data: check json and version number.
    let response =
        String::from_utf8(received.data().to_vec()).expect("Verifier expected received data");
    // response
    //     .find("BEGIN PUBLIC KEY")
    //     .expect("Expected valid public key in JSON response");

    // Check Session info: server name.
    assert_eq!(session_info.server_name.as_str(), SERVER_DOMAIN);

    (sent, received, session_info)
}

/// Redacts and reveals received data to the verifier.
fn redact_and_reveal_received_data(prover: &mut Prover<Prove>) {
    let recv_transcript_len = prover.recv_transcript().data().len();
    _ = prover.reveal(0..recv_transcript_len, Direction::Received);
}

/// Redacts and reveals sent data to the verifier.
fn redact_and_reveal_sent_data(prover: &mut Prover<Prove>) {
    let sent_transcript_len = prover.sent_transcript().data().len();
    _ = prover.reveal(0..sent_transcript_len, Direction::Sent);
}

/// Render redacted bytes as `🙈`.
fn bytes_to_redacted_string(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec())
        .unwrap()
        .replace('\0', "🙈")
}