use http_body_util::Empty;
use hyper::{body::Bytes, Request, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use regex::Regex;
use tlsn_core::{proof::SessionInfo, Direction, RedactedTranscript};
use tlsn_prover::tls::{state::Prove, Prover, ProverConfig};
use tlsn_verifier::tls::{Verifier, VerifierConfig};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::instrument;
use std::{env, ops::Range, str};

const SECRET: &str = "TLSNotary's private key 🤡";
const SERVER_DOMAIN: &str = "twitter.com";
const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36";
const ROUTE: &str = "i/api/1.1/dm/conversation";

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let uri = "https://twitter.com";
    let id = "interactive verifier demo";

    // Connect prover and verifier.
    let (prover_socket, verifier_socket) = tokio::io::duplex(1 << 23);
    let prover = prover(prover_socket, uri, id);
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
) {

    // Load secret variables frome environment for twitter server connection
    dotenv::dotenv().ok();
    
    let conversation_id = env::var("CONVERSATION_ID").unwrap();
    let auth_token = env::var("AUTH_TOKEN").unwrap();
    let access_token = env::var("ACCESS_TOKEN").unwrap();
    let csrf_token = env::var("CSRF_TOKEN").unwrap();

    let uri = uri.parse::<Uri>().unwrap();
    assert_eq!(uri.scheme().unwrap().as_str(), "https");
    let server_domain = uri.authority().unwrap().host();
    let server_port = uri.port_u16().unwrap_or(443);

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

    // Build the HTTP request to fetch the DMs
    let request = Request::builder()
        .uri(format!(
            "https://{SERVER_DOMAIN}/{ROUTE}/{conversation_id}.json"
        ))
        .header("Host", SERVER_DOMAIN)
        .header("Accept", "*/*")
        .header("Accept-Encoding", "identity")
        .header("Connection", "close")
        .header("User-Agent", USER_AGENT)
        .header("Authorization", format!("Bearer {access_token}"))
        .header(
            "Cookie",
            format!("auth_token={auth_token}; ct0={csrf_token}"),
        )
        .header("Authority", SERVER_DOMAIN)
        .header("X-Twitter-Auth-Type", "OAuth2Session")
        .header("x-twitter-active-user", "yes")
        .header("X-Csrf-Token", csrf_token.clone())
        .body(Empty::<Bytes>::new())
        .unwrap();
    let response = request_sender.send_request(request).await.unwrap();

    assert!(response.status() == StatusCode::OK);

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

    // println!("{:#?}", session_info.server_name.as_str.unwrap_or("None"));
    // Check Session info: server name.
    assert_eq!(session_info.server_name.as_str(), SERVER_DOMAIN);

    (sent, received, session_info)
}

/// Redacts and reveals received data to the verifier.
fn redact_and_reveal_received_data(prover: &mut Prover<Prove>) {
    let recv_transcript_len = prover.recv_transcript().data().len();

    // Get the commit hash from the received data.
    // let received_string = String::from_utf8(prover.recv_transcript().data().to_vec()).unwrap();
    // let re = Regex::new(r#""gitCommitHash"\s?:\s?"(.*?)""#).unwrap();
    // let commit_hash_match = re.captures(&received_string).unwrap().get(0).unwrap();

    // // Reveal everything except for the commit hash.
    // _ = prover.reveal(0..commit_hash_match.start(), Direction::Received);
    _ = prover.reveal(0..recv_transcript_len, Direction::Received);

}

/// Redacts and reveals sent data to the verifier.
fn redact_and_reveal_sent_data(prover: &mut Prover<Prove>) {
    let sent_transcript_len = prover.sent_transcript().data().len();

    // let sent_string = String::from_utf8(prover.sent_transcript().data().to_vec()).unwrap();
    // let secret_start = sent_string.find(SECRET).unwrap();

    // Reveal everything except for the SECRET.
    _ = prover.reveal(0..sent_transcript_len, Direction::Sent);
    // _ = prover.reveal(
    //     secret_start + SECRET.len()..sent_transcript_len,
    //     Direction::Sent,
    // );
}

/// Render redacted bytes as `🙈`.
fn bytes_to_redacted_string(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec())
        .unwrap()
        .replace('\0', "🙈")
}
