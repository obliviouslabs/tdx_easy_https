use actix_web::{web, App, HttpServer, Result as ActixResult, HttpResponse};
use serde::{Deserialize, Serialize};
use std::fs;
use base64::{Engine as _, engine::general_purpose};
use tdx_quote;
use sha2::{Sha256, Sha512, Digest};

#[derive(Serialize)]
struct AttestationResponse {
    certificate: String,
    report: String,
}

#[derive(Deserialize)]
struct AttestationRequest {
    domain: String,
    challenge: String,
}

#[derive(Serialize)]
struct AttestationData {
    domain: String,
    certificate_hash: Vec<u8>,
    challenge: Vec<u8>,
}

#[actix_web::post("/")]
async fn attest(req: web::Json<AttestationRequest>) -> ActixResult<HttpResponse> {
    // Read the ACME certificate file
    let acme_data = fs::read_to_string("/acme/acme.json")
        .map_err(|e| {
            eprintln!("Failed to read ACME file: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to read certificate")
        })?;

    // Parse the JSON to extract the certificate
    let acme_json: serde_json::Value = serde_json::from_str(&acme_data)
        .map_err(|e| {
            eprintln!("Failed to parse ACME JSON: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to parse certificate")
        })?;

    // Extract the certificate from the ACME data
    // Traefik ACME JSON structure: Certificates array with domain and certificate
    let certificates = acme_json["le"]["Certificates"]
        .as_array()
        .ok_or_else(|| {
            actix_web::error::ErrorInternalServerError("Certificates not found in ACME data")
        })?;

    let certificate = certificates
        .iter()
        .find(|cert| cert["domain"]["main"] == req.domain)
        .and_then(|cert| cert["certificate"].as_str())
        .ok_or_else(|| {
            actix_web::error::ErrorInternalServerError(format!("Certificate for {} not found", req.domain))
        })?
        .to_string();

    // Decode the challenge from hex string to bytes
    let challenge_bytes = hex::decode(&req.challenge)
        .map_err(|e| {
            eprintln!("Failed to decode challenge: {}", e);
            actix_web::error::ErrorBadRequest("Invalid challenge format")
        })?;

    // Ensure challenge is 32 bytes (256 bits)
    if challenge_bytes.len() != 32 {
        return Err(actix_web::error::ErrorBadRequest("Challenge must be 32 bytes"));
    }

    // Calculate SHA256 hash of the certificate
    let mut hasher = Sha256::new();
    hasher.update(&certificate);
    let certificate_hash = hasher.finalize().to_vec();

    // Create attestation data structure
    let attestation_data = AttestationData {
        domain: req.domain.clone(),
        certificate_hash,
        challenge: challenge_bytes.clone(),
    };

    // Serialize to JSON bytes and hash with SHA512 to get exactly 64 bytes
    let attestation_bytes = serde_json::to_vec(&attestation_data)
        .map_err(|e| {
            eprintln!("Failed to serialize attestation data: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to prepare attestation data")
        })?;

    let mut report_hasher = Sha512::new();
    report_hasher.update(&attestation_bytes);
    let report_data_bytes = report_hasher.finalize().to_vec();

    // Create TDX attestation with the 64-byte hash of attestation data
    let report_data_b64 = general_purpose::STANDARD.encode(&report_data_bytes);
    
    let quote = tdx_attest::get_tdx_quote(report_data_b64).map_err(|e| {
        eprintln!("Failed to generate TDX quote: {:?}", e);
        actix_web::error::ErrorInternalServerError("Failed to generate attestation report")
    })?;

    // Encode the report as base64
    let report_b64 = general_purpose::STANDARD.encode(&quote);

    let response = AttestationResponse {
        certificate,
        report: report_b64,
    };

    Ok(HttpResponse::Ok().json(response))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Starting attestd server on port 80");

    HttpServer::new(|| {
        App::new()
            .service(attest)
    })
    .bind("0.0.0.0:80")?
    .run()
    .await
}