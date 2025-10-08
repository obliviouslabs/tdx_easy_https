use reqwest::Client;
use serde::{Deserialize, Serialize};
use rand::Rng;
use hex;
use base64::{Engine as _, engine::general_purpose};
use sha2::{Sha256, Sha512, Digest};
use tdx_quote;

#[derive(Serialize)]
struct AttestationRequest {
    domain: String,
    challenge: String,
}

#[derive(Deserialize)]
struct AttestationResponse {
    certificate: String,
    report: String,
}

#[derive(Serialize)]
struct AttestationData {
    domain: String,
    certificate_hash: Vec<u8>,
    challenge: Vec<u8>,
}

pub fn verify_attestation(domain: &str, challenge_hex: &str, certificate: &str, report_b64: &str) -> Result<bool, String> {
    // Decode the challenge from hex string to bytes
    let challenge_bytes = hex::decode(challenge_hex)
        .map_err(|e| format!("Failed to decode challenge: {}", e))?;

    // Ensure challenge is 32 bytes (256 bits)
    if challenge_bytes.len() != 32 {
        return Err("Challenge must be 32 bytes".to_string());
    }

    // Calculate SHA256 hash of the certificate
    let mut hasher = Sha256::new();
    hasher.update(certificate);
    let certificate_hash = hasher.finalize().to_vec();

    // Create attestation data structure
    let attestation_data = AttestationData {
        domain: domain.to_string(),
        certificate_hash,
        challenge: challenge_bytes,
    };

    // Serialize to JSON bytes and hash with SHA512 to get expected report data
    let attestation_bytes = serde_json::to_vec(&attestation_data)
        .map_err(|e| format!("Failed to serialize attestation data: {}", e))?;

    let mut report_hasher = Sha512::new();
    report_hasher.update(&attestation_bytes);
    let expected_report_data = report_hasher.finalize();

    // Decode the report from base64
    let report_bytes = general_purpose::STANDARD.decode(report_b64)
        .map_err(|e| format!("Failed to decode report: {}", e))?;

    // Verify the TDX quote
    let quote = tdx_quote::Quote::from_bytes(&report_bytes)
        .map_err(|e| format!("Failed to parse TDX quote: {:?}", e))?;

    // Verify the quote (this checks the signature and validity)
    quote.verify()
        .map_err(|e| format!("TDX quote verification failed: {:?}", e))?;

    // Check that the report data matches what we expect
    let quote_report_data = quote.report_input_data();

    if quote_report_data != expected_report_data.as_slice() {
        return Err("Report data does not match expected attestation data".to_string());
    }

    Ok(true)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <domain>", args[0]);
        return Ok(());
    }
    let domain = &args[1];
    let attestd_url = "http://localhost/attested";
    let echo_url = format!("https://{}?message=hello", domain);

    // Generate random challenge
    let mut rng = rand::thread_rng();
    let challenge_bytes: [u8; 32] = rng.gen();
    let challenge_hex = hex::encode(challenge_bytes);

    // Request attestation
    let client = Client::new();
    let req = AttestationRequest {
        domain: domain.to_string(),
        challenge: challenge_hex.clone(),
    };
    let res: AttestationResponse = client
        .post(attestd_url)
        .json(&req)
        .send()
        .await?
        .json()
        .await?;

    // Verify attestation
    if !verify_attestation(domain, &challenge_hex, &res.certificate, &res.report)? {
        eprintln!("Attestation verification failed");
        return Ok(());
    }
    println!("Attestation verified successfully");

    // Create client with pinned certificate (trust only this certificate as root)
    let cert = reqwest::Certificate::from_pem(res.certificate.as_bytes())?;
    let pinned_client = Client::builder()
        .tls_built_in_root_certs(false)
        .add_root_certificate(cert)
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.url().scheme() == "https" {
                attempt.follow()
            } else {
                attempt.stop()
            }
        }))
        .build()?;

    // Now this pinned client can be used to make requests using only the pinned https certificate.
    // Make request to echo service
    let resp = pinned_client.get(&echo_url).send().await?;
    let text = resp.text().await?;
    println!("Echo response: {}", text);

    Ok(())
}