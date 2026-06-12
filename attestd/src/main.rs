use actix_web::{web, App, HttpRequest, HttpResponse, HttpServer, Result as ActixResult};
use base64::{
  engine::{general_purpose, general_purpose::URL_SAFE_NO_PAD},
  Engine as _,
};
use instant_acme::{
  Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt,
  NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

const TSM_REPORT_ROOT: &str = "/sys/kernel/config/tsm/report";
const DEFAULT_ACME_JSON_PATH: &str = "/acme/acme.json";
const DEFAULT_CERTIFICATE_PEM_PATH: &str = "/certs/tls.crt";
const DEFAULT_CERTIFICATE_KEY_PATH: &str = "/certs/tls.key";
const DEFAULT_ACME_STATE_DIR: &str = "/certs/acme";
const DEFAULT_TRAEFIK_CERTS_DYNAMIC_PATH: &str = "/certs/traefik-certs.yml";
const DEFAULT_WORKLOAD_MANIFEST_PATH: &str = "/measurement/workload-manifest.json";
const CONFIDENTIAL_SPACE_SOCKET: &str = "/run/container_launcher/teeserver.sock";
static REPORT_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Serialize)]
struct AttestationResponse {
  certificate: String,
  #[serde(skip_serializing_if = "Option::is_none")]
  report: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  workload_manifest: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  workload_digest_sha384: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  workload_rtmr3_expected: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  confidential_space_token: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  confidential_space_audience: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  confidential_space_nonce: Option<String>,
}

#[derive(Deserialize)]
struct AttestationRequest {
  domain: String,
  challenge: String,
  audience: Option<String>,
}

#[derive(Deserialize)]
struct AcmeStartRequest {
  domain: String,
  email: Option<String>,
  directory_url: Option<String>,
  extra_domains: Option<Vec<String>>,
}

#[derive(Clone, Serialize, Deserialize)]
struct AcmeDnsRecord {
  dns_type: String,
  dns_name: String,
  dns_value: String,
}

#[derive(Serialize)]
struct AcmeStartResponse {
  status: String,
  order_id: String,
  domain: String,
  dns_type: String,
  dns_name: String,
  dns_value: String,
  dns_records: Vec<AcmeDnsRecord>,
  directory_url: String,
}

#[derive(Deserialize)]
struct AcmeFinalizeRequest {
  order_id: String,
}

#[derive(Serialize)]
struct AcmeFinalizeResponse {
  status: String,
  domain: String,
  certificate_path: String,
  key_path: String,
  traefik_dynamic_config_path: String,
}

#[derive(Serialize, Deserialize)]
struct PendingAcmeOrder {
  order_id: String,
  domain: String,
  domains: Vec<String>,
  directory_url: String,
  order_url: String,
  private_key_pem: String,
  dns_name: String,
  dns_value: String,
  dns_records: Vec<AcmeDnsRecord>,
  created_unix: u64,
}

#[derive(Serialize)]
struct AttestationData {
  domain: String,
  certificate_hash: Vec<u8>,
  challenge: Vec<u8>,
  workload_digest_sha384: Vec<u8>,
  workload_rtmr3_expected: Vec<u8>,
}

struct TsmReportDir {
  path: PathBuf,
}

impl TsmReportDir {
  fn create() -> Result<Self, String> {
    let pid = std::process::id();
    for _ in 0..32 {
      let counter = REPORT_COUNTER.fetch_add(1, Ordering::Relaxed);
      let path = Path::new(TSM_REPORT_ROOT).join(format!("attestd-{pid}-{counter}"));
      match fs::create_dir(&path) {
        Ok(()) => return Ok(Self { path }),
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
        Err(err) => return Err(format!("failed to create TSM report directory: {err}")),
      }
    }
    Err("failed to allocate unique TSM report directory".to_string())
  }
}

impl Drop for TsmReportDir {
  fn drop(&mut self) {
    let _ = fs::remove_dir(&self.path);
  }
}

fn get_tdx_quote(report_data: &[u8]) -> Result<Vec<u8>, String> {
  if report_data.len() != 64 {
    return Err("TDX report data must be exactly 64 bytes".to_string());
  }

  let report_dir = TsmReportDir::create()?;
  fs::write(report_dir.path.join("inblob"), report_data)
    .map_err(|err| format!("failed to write TSM report data: {err}"))?;
  let quote = fs::read(report_dir.path.join("outblob"))
    .map_err(|err| format!("failed to read TSM quote: {err}"))?;
  if quote.is_empty() {
    return Err("TSM quote is empty".to_string());
  }
  Ok(quote)
}

fn workload_manifest_path() -> String {
  std::env::var("WORKLOAD_MANIFEST_PATH")
    .unwrap_or_else(|_| DEFAULT_WORKLOAD_MANIFEST_PATH.to_string())
}

fn acme_json_path() -> String {
  std::env::var("ACME_JSON_PATH").unwrap_or_else(|_| DEFAULT_ACME_JSON_PATH.to_string())
}

fn certificate_pem_path() -> String {
  std::env::var("CERTIFICATE_PEM_PATH").unwrap_or_else(|_| DEFAULT_CERTIFICATE_PEM_PATH.to_string())
}

fn certificate_key_path() -> String {
  std::env::var("CERTIFICATE_KEY_PATH").unwrap_or_else(|_| DEFAULT_CERTIFICATE_KEY_PATH.to_string())
}

fn acme_state_dir() -> PathBuf {
  PathBuf::from(
    std::env::var("ACME_STATE_DIR").unwrap_or_else(|_| DEFAULT_ACME_STATE_DIR.to_string()),
  )
}

fn acme_account_path(directory_url: &str) -> PathBuf {
  let digest = Sha256::digest(directory_url.as_bytes());
  acme_state_dir().join(format!("account-{}.json", hex::encode(&digest[..8])))
}

fn pending_order_path(order_id: &str) -> Result<PathBuf, String> {
  if !order_id.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '-') {
    return Err("invalid order_id".to_string());
  }
  Ok(acme_state_dir().join("orders").join(format!("{order_id}.json")))
}

fn traefik_certs_dynamic_path() -> String {
  std::env::var("TRAEFIK_CERTS_DYNAMIC_PATH")
    .unwrap_or_else(|_| DEFAULT_TRAEFIK_CERTS_DYNAMIC_PATH.to_string())
}

fn expected_single_event_rtmr3(event_digest: &[u8]) -> Vec<u8> {
  let mut hasher = Sha384::new();
  hasher.update([0u8; 48]);
  hasher.update(event_digest);
  hasher.finalize().to_vec()
}

fn confidential_space_nonce(domain: &str, certificate_hash: &[u8], challenge: &[u8]) -> String {
  let payload = format!(
    "safe-node-confidential-space-v1\n\
     domain={domain}\n\
     certificate_sha256=0x{}\n\
     challenge=0x{}\n",
    hex::encode(certificate_hash),
    hex::encode(challenge)
  );
  URL_SAFE_NO_PAD.encode(Sha256::digest(payload.as_bytes()))
}

fn confidential_space_audience(domain: &str, requested: Option<&str>) -> String {
  if let Ok(audience) = std::env::var("CONFIDENTIAL_SPACE_AUDIENCE") {
    return audience;
  }
  requested.map(str::to_string).unwrap_or_else(|| format!("safe-node:{domain}"))
}

fn should_use_confidential_space() -> bool {
  match std::env::var("GCP_ATTESTATION_MODE").unwrap_or_else(|_| "auto".to_string()).as_str() {
    "confidential-space" => true,
    "tdx" => false,
    _ => Path::new(CONFIDENTIAL_SPACE_SOCKET).exists(),
  }
}

fn parse_confidential_space_token(body: &str) -> String {
  let trimmed = body.trim();
  if let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) {
    if let Some(token) = value.as_str() {
      return token.to_string();
    }
    for key in ["token", "id_token", "attestation_token"] {
      if let Some(token) = value.get(key).and_then(|value| value.as_str()) {
        return token.to_string();
      }
    }
  }
  trimmed.to_string()
}

fn decode_http_body(headers: &str, body: &str) -> Result<String, String> {
  let chunked = headers.lines().any(|line| {
    let lower = line.to_ascii_lowercase();
    lower.starts_with("transfer-encoding:") && lower.contains("chunked")
  });
  if !chunked {
    return Ok(body.to_string());
  }

  let mut rest = body;
  let mut decoded = String::new();
  loop {
    let (size_hex, after_size) =
      rest.split_once("\r\n").ok_or_else(|| "malformed chunked token response".to_string())?;
    let size_text = size_hex.split(';').next().unwrap_or(size_hex).trim();
    let size = usize::from_str_radix(size_text, 16)
      .map_err(|err| format!("invalid chunk size in token response: {err}"))?;
    if size == 0 {
      break;
    }
    if after_size.len() < size + 2 {
      return Err("truncated chunked token response".to_string());
    }
    decoded.push_str(&after_size[..size]);
    rest = &after_size[size + 2..];
  }
  Ok(decoded)
}

fn get_confidential_space_token(audience: &str, nonce: &str) -> Result<String, String> {
  let body = serde_json::json!({
    "audience": audience,
    "token_type": "OIDC",
    "nonces": [nonce],
  })
  .to_string();

  let request = format!(
    "POST /v1/token HTTP/1.1\r\n\
     Host: localhost\r\n\
     Content-Type: application/json\r\n\
     Content-Length: {}\r\n\
     Connection: close\r\n\r\n{}",
    body.len(),
    body
  );

  let mut stream = UnixStream::connect(CONFIDENTIAL_SPACE_SOCKET)
    .map_err(|err| format!("failed to connect to Confidential Space launcher: {err}"))?;
  stream
    .write_all(request.as_bytes())
    .map_err(|err| format!("failed to request Confidential Space token: {err}"))?;

  let mut response = String::new();
  stream
    .read_to_string(&mut response)
    .map_err(|err| format!("failed to read Confidential Space token response: {err}"))?;

  let (headers, body) = response
    .split_once("\r\n\r\n")
    .ok_or_else(|| "malformed Confidential Space token response".to_string())?;
  if !headers.starts_with("HTTP/1.1 200") && !headers.starts_with("HTTP/1.0 200") {
    return Err(format!("Confidential Space token request failed: {}", response.trim()));
  }

  let decoded_body = decode_http_body(headers, body)?;
  Ok(parse_confidential_space_token(&decoded_body))
}

fn now_unix() -> u64 {
  SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

fn normalize_domain(domain: &str) -> Result<String, String> {
  let normalized = domain.trim().trim_end_matches('.').to_ascii_lowercase();
  if normalized.is_empty() || normalized.len() > 253 {
    return Err("invalid domain length".to_string());
  }
  if normalized.starts_with("*.") {
    return Err("wildcard certificates are not supported by this endpoint".to_string());
  }
  if normalized.contains("..") || !normalized.contains('.') {
    return Err("domain must be a public DNS name".to_string());
  }
  for label in normalized.split('.') {
    if label.is_empty() || label.len() > 63 {
      return Err("invalid DNS label length".to_string());
    }
    if label.starts_with('-') || label.ends_with('-') {
      return Err("DNS labels must not start or end with '-'".to_string());
    }
    if !label.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '-') {
      return Err("domain contains unsupported characters".to_string());
    }
  }
  Ok(normalized)
}

fn ensure_allowed_acme_domain(domain: &str) -> Result<(), String> {
  if let Ok(server_domain) = std::env::var("SERVER_DOMAIN") {
    let server_domain = normalize_domain(&server_domain)?;
    if domain != server_domain {
      return Err(format!("ACME issuance is restricted to {server_domain}"));
    }
  }
  Ok(())
}

fn ensure_allowed_extra_domain(primary_domain: &str, extra_domain: &str) -> Result<(), String> {
  if extra_domain == primary_domain {
    return Err("extra ACME domains must not repeat the primary domain".to_string());
  }
  let Some((_, base_domain)) = primary_domain.split_once('.') else {
    return Err("primary domain is not a subdomain".to_string());
  };
  if extra_domain.ends_with(&format!(".{base_domain}")) {
    Ok(())
  } else {
    Err(format!("extra ACME domain {extra_domain} is outside {base_domain}"))
  }
}

fn require_acme_auth(req: &HttpRequest) -> ActixResult<()> {
  let Ok(token) = std::env::var("ACME_ADMIN_TOKEN") else {
    return Ok(());
  };
  if token.is_empty() {
    return Ok(());
  }

  let expected = format!("Bearer {token}");
  let authorized = req
    .headers()
    .get("authorization")
    .and_then(|value| value.to_str().ok())
    .is_some_and(|value| value == expected);

  if authorized {
    Ok(())
  } else {
    Err(actix_web::error::ErrorUnauthorized("missing or invalid ACME token"))
  }
}

fn acme_directory_url(requested: Option<&str>) -> String {
  requested
    .map(str::to_string)
    .or_else(|| std::env::var("ACME_DIRECTORY_URL").ok())
    .unwrap_or_else(|| LetsEncrypt::Production.url().to_string())
}

fn acme_email(requested: Option<&str>) -> Result<String, String> {
  requested
    .map(str::to_string)
    .or_else(|| std::env::var("ACME_EMAIL").ok())
    .filter(|email| !email.trim().is_empty())
    .ok_or_else(|| "ACME email is required".to_string())
}

fn write_file_atomic(
  path: impl AsRef<Path>,
  contents: &[u8],
  mode: Option<u32>,
) -> Result<(), String> {
  let path = path.as_ref();
  if let Some(parent) = path.parent() {
    fs::create_dir_all(parent)
      .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
  }

  let tmp_path = path.with_extension(format!("tmp-{}", Uuid::new_v4()));
  {
    let mut file = fs::OpenOptions::new()
      .create_new(true)
      .write(true)
      .open(&tmp_path)
      .map_err(|err| format!("failed to create {}: {err}", tmp_path.display()))?;
    file
      .write_all(contents)
      .map_err(|err| format!("failed to write {}: {err}", tmp_path.display()))?;
    file.sync_all().map_err(|err| format!("failed to sync {}: {err}", tmp_path.display()))?;
  }
  if let Some(mode) = mode {
    fs::set_permissions(&tmp_path, fs::Permissions::from_mode(mode))
      .map_err(|err| format!("failed to chmod {}: {err}", tmp_path.display()))?;
  }
  fs::rename(&tmp_path, path)
    .map_err(|err| format!("failed to replace {}: {err}", path.display()))?;
  Ok(())
}

fn read_managed_certificate() -> Result<Option<String>, String> {
  let path = certificate_pem_path();
  match fs::read_to_string(&path) {
    Ok(certificate) if certificate.trim().is_empty() => {
      Err(format!("managed certificate at {path} is empty"))
    }
    Ok(certificate) => Ok(Some(certificate)),
    Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
    Err(err) => Err(format!("failed to read managed certificate at {path}: {err}")),
  }
}

fn read_traefik_acme_certificate(domain: &str) -> Result<String, String> {
  let acme_data = fs::read_to_string(acme_json_path())
    .map_err(|err| format!("failed to read Traefik ACME file: {err}"))?;
  let acme_json: serde_json::Value = serde_json::from_str(&acme_data)
    .map_err(|err| format!("failed to parse Traefik ACME JSON: {err}"))?;
  let certificates = acme_json["le"]["Certificates"]
    .as_array()
    .ok_or_else(|| "certificates not found in Traefik ACME data".to_string())?;

  certificates
    .iter()
    .find(|cert| cert["domain"]["main"].as_str() == Some(domain))
    .and_then(|cert| cert["certificate"].as_str())
    .map(str::to_string)
    .ok_or_else(|| format!("certificate for {domain} not found"))
}

fn certificate_for_domain(domain: &str) -> Result<String, String> {
  match read_managed_certificate()? {
    Some(certificate) => Ok(certificate),
    None => read_traefik_acme_certificate(domain),
  }
}

async fn load_or_create_acme_account(directory_url: &str, email: &str) -> Result<Account, String> {
  let account_path = acme_account_path(directory_url);
  if account_path.exists() {
    return load_acme_account(directory_url).await;
  }

  let contact = format!("mailto:{email}");
  let contacts = [contact.as_str()];
  let (account, credentials) = Account::builder()
    .map_err(|err| format!("failed to create ACME client: {err}"))?
    .create(
      &NewAccount {
        contact: &contacts,
        terms_of_service_agreed: true,
        only_return_existing: false,
      },
      directory_url.to_string(),
      None,
    )
    .await
    .map_err(|err| format!("failed to create ACME account: {err}"))?;

  let serialized = serde_json::to_vec_pretty(&credentials)
    .map_err(|err| format!("failed to serialize ACME account credentials: {err}"))?;
  write_file_atomic(account_path, &serialized, Some(0o600))?;
  Ok(account)
}

async fn load_acme_account(directory_url: &str) -> Result<Account, String> {
  let account_path = acme_account_path(directory_url);
  let credentials = fs::read_to_string(&account_path)
    .map_err(|err| format!("failed to read ACME account credentials: {err}"))?;
  let credentials = serde_json::from_str::<AccountCredentials>(&credentials)
    .map_err(|err| format!("failed to parse ACME account credentials: {err}"))?;
  Account::builder()
    .map_err(|err| format!("failed to create ACME client: {err}"))?
    .from_credentials(credentials)
    .await
    .map_err(|err| format!("failed to restore ACME account: {err}"))
}

fn save_pending_order(order: &PendingAcmeOrder) -> Result<(), String> {
  let path = pending_order_path(&order.order_id)?;
  let serialized = serde_json::to_vec_pretty(order)
    .map_err(|err| format!("failed to serialize pending ACME order: {err}"))?;
  write_file_atomic(path, &serialized, Some(0o600))
}

fn load_pending_order(order_id: &str) -> Result<PendingAcmeOrder, String> {
  let path = pending_order_path(order_id)?;
  let contents = fs::read_to_string(&path)
    .map_err(|err| format!("failed to read pending ACME order {order_id}: {err}"))?;
  serde_json::from_str(&contents)
    .map_err(|err| format!("failed to parse pending ACME order {order_id}: {err}"))
}

fn remove_pending_order(order_id: &str) {
  if let Ok(path) = pending_order_path(order_id) {
    let _ = fs::remove_file(path);
  }
}

fn write_traefik_certificate_config() -> Result<String, String> {
  let cert_path = certificate_pem_path();
  let key_path = certificate_key_path();
  let dynamic_path = traefik_certs_dynamic_path();
  let config = format!(
    "tls:\n  certificates:\n    - certFile: \"{cert_path}\"\n      keyFile: \"{key_path}\"\n"
  );
  write_file_atomic(&dynamic_path, config.as_bytes(), None)?;
  Ok(dynamic_path)
}

fn initialize_traefik_certificate_config() -> Result<(), String> {
  let dynamic_path = traefik_certs_dynamic_path();
  if Path::new(&dynamic_path).exists() {
    return Ok(());
  }
  write_file_atomic(dynamic_path, b"tls:\n  certificates: []\n", None)
}

fn acme_retry_policy() -> RetryPolicy {
  RetryPolicy::new()
    .initial_delay(Duration::from_secs(2))
    .backoff(1.5)
    .timeout(Duration::from_secs(180))
}

#[actix_web::post("/acme/start")]
async fn acme_start(
  http_req: HttpRequest,
  req: web::Json<AcmeStartRequest>,
) -> ActixResult<HttpResponse> {
  require_acme_auth(&http_req)?;

  let domain = normalize_domain(&req.domain).map_err(actix_web::error::ErrorBadRequest)?;
  ensure_allowed_acme_domain(&domain).map_err(actix_web::error::ErrorBadRequest)?;
  let mut domains = vec![domain.clone()];
  if let Some(extra_domains) = &req.extra_domains {
    for extra_domain in extra_domains {
      let extra_domain =
        normalize_domain(extra_domain).map_err(actix_web::error::ErrorBadRequest)?;
      ensure_allowed_extra_domain(&domain, &extra_domain)
        .map_err(actix_web::error::ErrorBadRequest)?;
      if !domains.contains(&extra_domain) {
        domains.push(extra_domain);
      }
    }
  }

  let email = acme_email(req.email.as_deref()).map_err(actix_web::error::ErrorBadRequest)?;
  let directory_url = acme_directory_url(req.directory_url.as_deref());
  let account = load_or_create_acme_account(&directory_url, &email).await.map_err(|err| {
    eprintln!("Failed to prepare ACME account: {err}");
    actix_web::error::ErrorInternalServerError("Failed to prepare ACME account")
  })?;

  let key_pair = KeyPair::generate().map_err(|err| {
    eprintln!("Failed to generate TLS key: {err}");
    actix_web::error::ErrorInternalServerError("Failed to generate TLS key")
  })?;
  let private_key_pem = key_pair.serialize_pem();

  let identifiers = domains.iter().cloned().map(Identifier::Dns).collect::<Vec<_>>();
  let mut order = account.new_order(&NewOrder::new(&identifiers)).await.map_err(|err| {
    eprintln!("Failed to create ACME order: {err}");
    actix_web::error::ErrorInternalServerError("Failed to create ACME order")
  })?;
  let order_url = order.url().to_string();

  let mut dns_records = Vec::new();
  let mut authorizations = order.authorizations();
  while let Some(result) = authorizations.next().await {
    let mut authz = result.map_err(|err| {
      eprintln!("Failed to read ACME authorization: {err}");
      actix_web::error::ErrorInternalServerError("Failed to read ACME authorization")
    })?;

    match authz.status {
      AuthorizationStatus::Pending => {}
      AuthorizationStatus::Valid => continue,
      status => {
        return Err(actix_web::error::ErrorInternalServerError(format!(
          "Unexpected ACME authorization status: {status:?}"
        )))
      }
    }

    let challenge = authz.challenge(ChallengeType::Dns01).ok_or_else(|| {
      actix_web::error::ErrorInternalServerError("ACME server did not offer DNS-01")
    })?;
    dns_records.push(AcmeDnsRecord {
      dns_type: "TXT".to_string(),
      dns_name: format!("_acme-challenge.{}.", challenge.identifier()),
      dns_value: challenge.key_authorization().dns_value(),
    });
  }

  let first_record = dns_records
    .first()
    .cloned()
    .ok_or_else(|| actix_web::error::ErrorInternalServerError("No pending DNS-01 authorization"))?;

  let order_id = Uuid::new_v4().to_string();
  let pending = PendingAcmeOrder {
    order_id: order_id.clone(),
    domain: domain.clone(),
    domains: domains.clone(),
    directory_url: directory_url.clone(),
    order_url,
    private_key_pem,
    dns_name: first_record.dns_name.clone(),
    dns_value: first_record.dns_value.clone(),
    dns_records: dns_records.clone(),
    created_unix: now_unix(),
  };
  save_pending_order(&pending).map_err(|err| {
    eprintln!("Failed to save pending ACME order: {err}");
    actix_web::error::ErrorInternalServerError("Failed to save pending ACME order")
  })?;

  Ok(HttpResponse::Ok().json(AcmeStartResponse {
    status: "dns_record_required".to_string(),
    order_id,
    domain,
    dns_type: first_record.dns_type,
    dns_name: first_record.dns_name,
    dns_value: first_record.dns_value,
    dns_records,
    directory_url,
  }))
}

#[actix_web::post("/acme/finalize")]
async fn acme_finalize(
  http_req: HttpRequest,
  req: web::Json<AcmeFinalizeRequest>,
) -> ActixResult<HttpResponse> {
  require_acme_auth(&http_req)?;

  let pending = load_pending_order(&req.order_id).map_err(actix_web::error::ErrorBadRequest)?;
  ensure_allowed_acme_domain(&pending.domain).map_err(actix_web::error::ErrorBadRequest)?;

  let account = load_acme_account(&pending.directory_url).await.map_err(|err| {
    eprintln!("Failed to restore ACME account: {err}");
    actix_web::error::ErrorInternalServerError("Failed to restore ACME account")
  })?;

  let mut order = account.order(pending.order_url.clone()).await.map_err(|err| {
    eprintln!("Failed to restore ACME order: {err}");
    actix_web::error::ErrorInternalServerError("Failed to restore ACME order")
  })?;

  {
    let mut authorizations = order.authorizations();
    while let Some(result) = authorizations.next().await {
      let mut authz = result.map_err(|err| {
        eprintln!("Failed to read ACME authorization: {err}");
        actix_web::error::ErrorInternalServerError("Failed to read ACME authorization")
      })?;
      match authz.status {
        AuthorizationStatus::Pending => {
          let mut challenge = authz.challenge(ChallengeType::Dns01).ok_or_else(|| {
            actix_web::error::ErrorInternalServerError("ACME server did not offer DNS-01")
          })?;
          challenge.set_ready().await.map_err(|err| {
            eprintln!("Failed to set ACME challenge ready: {err}");
            actix_web::error::ErrorInternalServerError("Failed to set ACME challenge ready")
          })?;
        }
        AuthorizationStatus::Valid => {}
        status => {
          return Err(actix_web::error::ErrorInternalServerError(format!(
            "Unexpected ACME authorization status: {status:?}"
          )))
        }
      }
    }
  }

  if order.state().status != OrderStatus::Ready && order.state().status != OrderStatus::Valid {
    let status = order.poll_ready(&acme_retry_policy()).await.map_err(|err| {
      eprintln!("ACME order did not become ready: {err}");
      actix_web::error::ErrorInternalServerError("ACME order did not become ready")
    })?;
    if status != OrderStatus::Ready {
      return Err(actix_web::error::ErrorInternalServerError(format!(
        "Unexpected ACME order status: {status:?}"
      )));
    }
  }

  if order.state().status != OrderStatus::Valid {
    let key_pair = KeyPair::from_pem(&pending.private_key_pem).map_err(|err| {
      eprintln!("Failed to parse pending TLS key: {err}");
      actix_web::error::ErrorInternalServerError("Failed to parse pending TLS key")
    })?;
    let mut params = CertificateParams::new(pending.domains.clone()).map_err(|err| {
      eprintln!("Failed to create CSR parameters: {err}");
      actix_web::error::ErrorInternalServerError("Failed to create CSR")
    })?;
    params.distinguished_name = DistinguishedName::new();
    let csr = params.serialize_request(&key_pair).map_err(|err| {
      eprintln!("Failed to create CSR: {err}");
      actix_web::error::ErrorInternalServerError("Failed to create CSR")
    })?;
    order.finalize_csr(csr.der().as_ref()).await.map_err(|err| {
      eprintln!("Failed to finalize ACME order: {err}");
      actix_web::error::ErrorInternalServerError("Failed to finalize ACME order")
    })?;
  }

  let certificate = order.poll_certificate(&acme_retry_policy()).await.map_err(|err| {
    eprintln!("Failed to retrieve ACME certificate: {err}");
    actix_web::error::ErrorInternalServerError("Failed to retrieve ACME certificate")
  })?;

  let cert_path = certificate_pem_path();
  let key_path = certificate_key_path();
  write_file_atomic(&cert_path, certificate.as_bytes(), Some(0o644)).map_err(|err| {
    eprintln!("Failed to write certificate: {err}");
    actix_web::error::ErrorInternalServerError("Failed to write certificate")
  })?;
  write_file_atomic(&key_path, pending.private_key_pem.as_bytes(), Some(0o600)).map_err(|err| {
    eprintln!("Failed to write TLS key: {err}");
    actix_web::error::ErrorInternalServerError("Failed to write TLS key")
  })?;

  let dynamic_path = write_traefik_certificate_config().map_err(|err| {
    eprintln!("Failed to write Traefik certificate config: {err}");
    actix_web::error::ErrorInternalServerError("Failed to write Traefik certificate config")
  })?;
  remove_pending_order(&pending.order_id);

  Ok(HttpResponse::Ok().json(AcmeFinalizeResponse {
    status: "issued".to_string(),
    domain: pending.domain,
    certificate_path: cert_path,
    key_path,
    traefik_dynamic_config_path: dynamic_path,
  }))
}

#[actix_web::post("/")]
async fn attest(req: web::Json<AttestationRequest>) -> ActixResult<HttpResponse> {
  let domain = normalize_domain(&req.domain).map_err(|err| {
    eprintln!("Invalid attestation domain: {err}");
    actix_web::error::ErrorBadRequest("Invalid domain")
  })?;

  let certificate = certificate_for_domain(&domain).map_err(|err| {
    eprintln!("Failed to read certificate: {err}");
    actix_web::error::ErrorInternalServerError("Failed to read certificate")
  })?;

  // Decode the challenge from hex string to bytes
  let challenge_bytes = hex::decode(&req.challenge).map_err(|e| {
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

  if should_use_confidential_space() {
    let audience = confidential_space_audience(&domain, req.audience.as_deref());
    let nonce = confidential_space_nonce(&domain, &certificate_hash, &challenge_bytes);
    let token = get_confidential_space_token(&audience, &nonce).map_err(|e| {
      eprintln!("Failed to get Confidential Space token: {e}");
      actix_web::error::ErrorInternalServerError("Failed to generate attestation token")
    })?;

    return Ok(HttpResponse::Ok().json(AttestationResponse {
      certificate,
      report: None,
      workload_manifest: None,
      workload_digest_sha384: None,
      workload_rtmr3_expected: None,
      confidential_space_token: Some(token),
      confidential_space_audience: Some(audience),
      confidential_space_nonce: Some(nonce),
    }));
  }

  let workload_manifest = fs::read_to_string(workload_manifest_path()).map_err(|e| {
    eprintln!("Failed to read workload manifest: {}", e);
    actix_web::error::ErrorInternalServerError("Failed to read workload manifest")
  })?;

  let workload_digest = Sha384::digest(workload_manifest.as_bytes()).to_vec();
  let workload_rtmr3_expected = expected_single_event_rtmr3(&workload_digest);

  // Create attestation data structure
  let attestation_data = AttestationData {
    domain: domain.clone(),
    certificate_hash,
    challenge: challenge_bytes.clone(),
    workload_digest_sha384: workload_digest.clone(),
    workload_rtmr3_expected: workload_rtmr3_expected.clone(),
  };

  // Serialize to JSON bytes and hash with SHA512 to get exactly 64 bytes
  let attestation_bytes = serde_json::to_vec(&attestation_data).map_err(|e| {
    eprintln!("Failed to serialize attestation data: {}", e);
    actix_web::error::ErrorInternalServerError("Failed to prepare attestation data")
  })?;

  let mut report_hasher = Sha512::new();
  report_hasher.update(&attestation_bytes);
  let report_data_bytes = report_hasher.finalize().to_vec();

  // Create TDX attestation with the 64-byte hash of attestation data
  let quote = get_tdx_quote(&report_data_bytes).map_err(|e| {
    eprintln!("Failed to generate TDX quote: {e}");
    actix_web::error::ErrorInternalServerError("Failed to generate attestation report")
  })?;

  // Encode the report as base64
  let report_b64 = general_purpose::STANDARD.encode(&quote);

  let response = AttestationResponse {
    certificate,
    report: Some(report_b64),
    workload_manifest: Some(workload_manifest),
    workload_digest_sha384: Some(format!("0x{}", hex::encode(workload_digest))),
    workload_rtmr3_expected: Some(format!("0x{}", hex::encode(workload_rtmr3_expected))),
    confidential_space_token: None,
    confidential_space_audience: None,
    confidential_space_nonce: None,
  };

  Ok(HttpResponse::Ok().json(response))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
  let listen_addr =
    std::env::var("ATTESTD_LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:80".to_string());
  if let Err(err) = initialize_traefik_certificate_config() {
    eprintln!("Failed to initialize Traefik certificate config: {err}");
  }
  println!("Starting attestd server on {listen_addr}");

  HttpServer::new(|| App::new().service(attest).service(acme_start).service(acme_finalize))
    .bind(listen_addr)?
    .run()
    .await
}
