#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import {
  createHash,
  createPublicKey,
  createVerify,
  randomBytes,
  X509Certificate,
} from 'node:crypto';
import http from 'node:http';
import https from 'node:https';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const DEFAULT_PHALA_VERIFY_API = 'https://cloud-api.phala.com/api/v1/attestations/verify';
const DSTACK_RUNTIME_EVENT_TYPE = 0x08000001;

function usage() {
  console.error(
    'Usage: node external/tdx_easy_https/client/node/verify_client_tdx.mjs <app-base-url> [expected-mrtd] [--strict-digests] [--attested-tls] [--gcp-attestd] [--gcp-confidential-space] [--expected-gcp-workload-digest <sha384>] [--expected-gcp-image-digest <sha256>] [--expected-gcp-env NAME=VALUE] [--gcp-audience <audience>] [--tls-domain <domain>] [--pccs-url <url>] [--verifier-bin <path>] [--dstack-verifier-url <url>] [--require-dstack-verifier] [--phala-api] [--simulator-fixture]'
  );
  console.error('Default behavior verifies the quote locally and does not call Phala.');
  console.error(
    '--simulator-fixture uses the dstack simulator zero-report-data quote fixture; use the default fresh challenge on real TDX.'
  );
}

function scriptDir() {
  return dirname(fileURLToPath(import.meta.url));
}

function tdxEasyHttpsRoot() {
  return resolve(scriptDir(), '../..');
}

function quoteVerifierRoot() {
  return resolve(scriptDir(), '../tdx_quote_verifier');
}

function normalizeHex(value, field) {
  if (typeof value !== 'string') {
    throw new Error(`${field} is missing`);
  }
  const hex = value.startsWith('0x') ? value.slice(2) : value;
  if (!/^[0-9a-fA-F]*$/.test(hex)) {
    throw new Error(`${field} is not hex`);
  }
  if (hex.length % 2 !== 0) {
    throw new Error(`${field} hex must contain an even number of characters`);
  }
  return hex.toLowerCase();
}

function fetchTextWithNodeHttp(url, options = {}, fetchOptions = {}) {
  const target = url instanceof URL ? url : new URL(url);
  const client = target.protocol === 'https:' ? https : http;
  return new Promise((resolve, reject) => {
    const request = client.request(
      target,
      {
        method: options.method || 'GET',
        headers: options.headers || {},
        rejectUnauthorized: fetchOptions.rejectUnauthorized !== false,
      },
      (response) => {
        const chunks = [];
        response.on('data', (chunk) => chunks.push(chunk));
        response.on('end', () => {
          resolve({
            ok: response.statusCode >= 200 && response.statusCode < 300,
            status: response.statusCode,
            body: Buffer.concat(chunks).toString('utf8'),
          });
        });
      }
    );
    request.on('error', reject);
    if (options.body) {
      request.write(options.body);
    }
    request.end();
  });
}

async function fetchJson(url, options, fetchOptions = {}) {
  if (fetchOptions.rejectUnauthorized === false) {
    const response = await fetchTextWithNodeHttp(url, options, fetchOptions);
    if (!response.ok) {
      throw new Error(`${url} returned HTTP ${response.status}: ${response.body}`);
    }
    try {
      return JSON.parse(response.body);
    } catch (err) {
      throw new Error(`${url} returned non-JSON body: ${err.message}`);
    }
  }

  const response = await fetch(url, options);
  const body = await response.text();
  if (!response.ok) {
    throw new Error(`${url} returned HTTP ${response.status}: ${body}`);
  }
  try {
    return JSON.parse(body);
  } catch (err) {
    throw new Error(`${url} returned non-JSON body: ${err.message}`);
  }
}

function eventLogEvents(eventLog) {
  if (!eventLog) {
    return [];
  }
  if (typeof eventLog === 'string') {
    try {
      return JSON.parse(eventLog);
    } catch {
      return [];
    }
  }
  return Array.isArray(eventLog) ? eventLog : [];
}

function parseJsonString(value) {
  if (typeof value !== 'string') {
    return value;
  }
  try {
    return JSON.parse(value);
  } catch {
    return value;
  }
}

function extractAppCompose(info) {
  const tcbInfo = parseJsonString(info?.tcb_info ?? info?.tcbInfo);
  return (
    tcbInfo?.app_compose ??
    tcbInfo?.appCompose ??
    info?.app_compose ??
    info?.appCompose ??
    null
  );
}

function dockerComposeFromAppCompose(appCompose) {
  if (!appCompose) {
    return null;
  }
  try {
    const parsed = typeof appCompose === 'string' ? JSON.parse(appCompose) : appCompose;
    return parsed?.docker_compose_file ?? parsed?.dockerComposeFile ?? null;
  } catch {
    return null;
  }
}

function checkPinnedImages(dockerComposeYaml) {
  if (!dockerComposeYaml) {
    return [];
  }
  return dockerComposeYaml
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.startsWith('image:'))
    .filter((line) => !line.includes('@sha256:'));
}

function parseArgs(argv) {
  const flags = {
    strictDigests: false,
    dstackVerifierUrl: process.env.DSTACK_VERIFIER_URL || '',
    requireDstackVerifier: false,
    phalaApi: false,
    simulatorFixture: false,
    attestedTls: false,
    gcpAttestd: false,
    gcpConfidentialSpace: false,
    tlsDomain: process.env.ATTESTED_TLS_DOMAIN || '',
    expectedGcpWorkloadDigest: process.env.EXPECTED_GCP_WORKLOAD_DIGEST || '',
    expectedGcpImageDigest: process.env.EXPECTED_GCP_IMAGE_DIGEST || '',
    expectedGcpEnv: new Map(),
    gcpAudience: process.env.GCP_CONFIDENTIAL_SPACE_AUDIENCE || '',
    allowGcpDebug: false,
    pccsUrl: process.env.PCCS_URL || '',
    verifierBin: process.env.TDX_QUOTE_VERIFIER_BIN || '',
  };
  const positional = [];
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--strict-digests') {
      flags.strictDigests = true;
    } else if (arg === '--require-dstack-verifier') {
      flags.requireDstackVerifier = true;
    } else if (arg === '--phala-api') {
      flags.phalaApi = true;
    } else if (arg === '--simulator-fixture') {
      flags.simulatorFixture = true;
    } else if (arg === '--attested-tls') {
      flags.attestedTls = true;
    } else if (arg === '--gcp-attestd') {
      flags.gcpAttestd = true;
    } else if (arg === '--gcp-confidential-space') {
      flags.gcpConfidentialSpace = true;
    } else if (arg === '--allow-gcp-debug') {
      flags.allowGcpDebug = true;
    } else if (arg === '--tls-domain') {
      flags.tlsDomain = argv[i + 1] || '';
      i += 1;
      if (!flags.tlsDomain) {
        throw new Error('missing value for --tls-domain');
      }
    } else if (arg === '--expected-gcp-workload-digest') {
      flags.expectedGcpWorkloadDigest = argv[i + 1] || '';
      i += 1;
      if (!flags.expectedGcpWorkloadDigest) {
        throw new Error('missing value for --expected-gcp-workload-digest');
      }
    } else if (arg === '--expected-gcp-image-digest') {
      flags.expectedGcpImageDigest = argv[i + 1] || '';
      i += 1;
      if (!flags.expectedGcpImageDigest) {
        throw new Error('missing value for --expected-gcp-image-digest');
      }
    } else if (arg === '--expected-gcp-env') {
      const pair = argv[i + 1] || '';
      i += 1;
      const separator = pair.indexOf('=');
      if (separator <= 0) {
        throw new Error('expected --expected-gcp-env value in NAME=VALUE form');
      }
      flags.expectedGcpEnv.set(pair.slice(0, separator), pair.slice(separator + 1));
    } else if (arg === '--gcp-audience') {
      flags.gcpAudience = argv[i + 1] || '';
      i += 1;
      if (!flags.gcpAudience) {
        throw new Error('missing value for --gcp-audience');
      }
    } else if (arg === '--dstack-verifier-url') {
      flags.dstackVerifierUrl = argv[i + 1] || '';
      i += 1;
      if (!flags.dstackVerifierUrl) {
        throw new Error('missing value for --dstack-verifier-url');
      }
    } else if (arg === '--pccs-url') {
      flags.pccsUrl = argv[i + 1] || '';
      i += 1;
      if (!flags.pccsUrl) {
        throw new Error('missing value for --pccs-url');
      }
    } else if (arg === '--verifier-bin') {
      flags.verifierBin = argv[i + 1] || '';
      i += 1;
      if (!flags.verifierBin) {
        throw new Error('missing value for --verifier-bin');
      }
    } else {
      positional.push(arg);
    }
  }
  if (positional.length < 1 || positional.length > 2) {
    usage();
    process.exit(2);
  }
  return {
    appBaseUrl: new URL(positional[0]),
    expectedMrtd: positional[1] ? normalizeHex(positional[1], 'expected MRTD') : null,
    ...flags,
  };
}

function verifierCommand(verifierBin) {
  if (verifierBin) {
    return { command: verifierBin, prefixArgs: [] };
  }

  const releaseBin = resolve(
    quoteVerifierRoot(),
    'target/release/tdx_quote_verifier'
  );
  const releaseProbe = spawnSync('test', ['-x', releaseBin]);
  if (releaseProbe.status === 0) {
    return { command: releaseBin, prefixArgs: [] };
  }

  const manifestPath = resolve(quoteVerifierRoot(), 'Cargo.toml');
  return {
    command: 'cargo',
    prefixArgs: ['run', '--release', '--quiet', '--manifest-path', manifestPath, '--'],
  };
}

function verifyQuoteLocally({ quote, reportData, expectedMrtd, pccsUrl, verifierBin }) {
  const { command, prefixArgs } = verifierCommand(verifierBin);
  const args = [
    ...prefixArgs,
    '--quote-hex',
    `0x${normalizeHex(quote, 'attestation.quote')}`,
    '--report-data-hex',
    `0x${reportData}`,
  ];
  if (expectedMrtd) {
    args.push('--expected-mrtd', `0x${expectedMrtd}`);
  }
  if (pccsUrl) {
    args.push('--pccs-url', pccsUrl);
  }

  const result = spawnSync(command, args, {
    cwd: tdxEasyHttpsRoot(),
    encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024,
  });
  if (result.status !== 0) {
    throw new Error((result.stderr || result.stdout || 'TDX quote verifier failed').trim());
  }
  return JSON.parse(result.stdout);
}

function sha256Hex(data) {
  return createHash('sha256').update(data).digest('hex');
}

function sha512Hex(data) {
  return createHash('sha512').update(data).digest('hex');
}

function sha384Hex(data) {
  return createHash('sha384').update(data).digest('hex');
}

function base64UrlSha256(data) {
  return createHash('sha256').update(data).digest('base64url');
}

function attestedTlsReportPayload(domain, certificateSha256, challenge) {
  return `domain=${domain}\ncertificate_sha256=0x${certificateSha256}\nchallenge=0x${challenge}\n`;
}

function confidentialSpaceNonce(domain, certificateSha256, challenge) {
  return base64UrlSha256(
    `safe-node-confidential-space-v1\n` +
      `domain=${domain}\n` +
      `certificate_sha256=0x${certificateSha256}\n` +
      `challenge=0x${challenge}\n`
  );
}

function certificatePublicKeyPin(certificatePem) {
  const certificate = new X509Certificate(certificatePem);
  const spkiDer = certificate.publicKey.export({ type: 'spki', format: 'der' });
  return `sha256//${createHash('sha256').update(spkiDer).digest('base64')}`;
}

function pemFromAttestdCertificate(certificate) {
  if (certificate.includes('BEGIN CERTIFICATE')) {
    return certificate;
  }
  return Buffer.from(certificate, 'base64').toString('utf8');
}

function base64UrlDecode(value) {
  return Buffer.from(value, 'base64url');
}

function parseJwtPart(value, name) {
  try {
    return JSON.parse(base64UrlDecode(value).toString('utf8'));
  } catch (err) {
    throw new Error(`failed to parse JWT ${name}: ${err.message}`);
  }
}

async function verifyGoogleOidcToken(token, audience) {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error('Confidential Space token is not a compact JWT');
  }

  const header = parseJwtPart(parts[0], 'header');
  const claims = parseJwtPart(parts[1], 'claims');
  if (header.alg !== 'RS256') {
    throw new Error(`unsupported Confidential Space token alg: ${header.alg}`);
  }

  const issuer = 'https://confidentialcomputing.googleapis.com';
  const wellKnown = await fetchJson(`${issuer}/.well-known/openid-configuration`);
  const jwks = await fetchJson(wellKnown.jwks_uri);
  const jwk = jwks.keys?.find((key) => key.kid === header.kid);
  if (!jwk) {
    throw new Error(`no Google Confidential Space JWK found for kid ${header.kid}`);
  }

  const verifier = createVerify('RSA-SHA256');
  verifier.update(`${parts[0]}.${parts[1]}`);
  verifier.end();
  const ok = verifier.verify(createPublicKey({ key: jwk, format: 'jwk' }), base64UrlDecode(parts[2]));
  if (!ok) {
    throw new Error('Confidential Space token signature is invalid');
  }

  const now = Math.floor(Date.now() / 1000);
  const skew = 300;
  if (claims.iss !== issuer) {
    throw new Error(`Confidential Space token issuer mismatch: ${claims.iss}`);
  }
  const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!audiences.includes(audience)) {
    throw new Error(`Confidential Space token audience mismatch: ${claims.aud}`);
  }
  if (typeof claims.exp !== 'number' || claims.exp + skew < now) {
    throw new Error('Confidential Space token is expired');
  }
  if (typeof claims.nbf === 'number' && claims.nbf - skew > now) {
    throw new Error('Confidential Space token is not valid yet');
  }

  return claims;
}

function normalizeSha256Digest(value, field) {
  const hex = normalizeHex(
    typeof value === 'string' && value.startsWith('sha256:') ? value.slice('sha256:'.length) : value,
    field
  );
  if (hex.length !== 64) {
    throw new Error(`${field} must be a SHA-256 digest`);
  }
  return `sha256:${hex}`;
}

function claimIncludes(value, expected) {
  if (Array.isArray(value)) {
    return value.includes(expected);
  }
  return value === expected;
}

const SAFE_NODE_GCP_ENV_ALLOWLIST = new Set([
  'ACME_ADMIN_TOKEN',
  'ACME_DIRECTORY_URL',
  'ACME_EMAIL',
  'ADMIN_API_KEY',
  'CONFIDENTIAL_SPACE_AUDIENCE',
  'ETH_NETWORK',
  'INITIAL_SYNC_BATCH_BLOCKS',
  'INITIAL_SYNC_BATCH_DELAY_MS',
  'INITIAL_SYNC_END_BLOCK',
  'INITIAL_NODE_SYNC_START_BLOCK',
  'INITIAL_SYNC_START_BLOCK',
  'LIGHTHOUSE_CHECKPOINT_SYNC_URL',
  'LOCAL_RPC_BATCH_REQUESTS',
  'LOCAL_NODE_SYNC_MODE',
  'NODE_MAP_CAPACITY',
  'RETH_DATA_SUBDIR',
  'RETH_RPC_ETH_PROOF_WINDOW',
  'RETH_RPC_URL',
  'RETH_STORAGE_MODE',
  'ROOT_MAP_CAPACITY',
  'RUN_RETH',
  'SEED_RPC_BATCH_REQUESTS',
  'SEED_RETH_RPC_URL',
  'SERVER_DOMAIN',
]);

function verifyGcpContainerLaunchPolicy(container, opts, domain, audience) {
  const expectedImageDigest = normalizeSha256Digest(
    opts.expectedGcpImageDigest,
    'expected GCP image digest'
  );
  if (container.image_digest !== expectedImageDigest) {
    throw new Error(
      `Confidential Space image digest mismatch: got ${container.image_digest}, expected ${expectedImageDigest}`
    );
  }

  if (Array.isArray(container.cmd_override) && container.cmd_override.length > 0) {
    throw new Error('Confidential Space token reports command overrides');
  }
  if (
    !Array.isArray(container.args) ||
    container.args.join('\0') !== '/usr/local/bin/safe-node-gcp-entrypoint'
  ) {
    throw new Error(
      `Confidential Space entrypoint mismatch: got ${JSON.stringify(container.args ?? null)}`
    );
  }

  const envOverride = container.env_override ?? {};
  if (
    envOverride === null ||
    typeof envOverride !== 'object' ||
    Array.isArray(envOverride)
  ) {
    throw new Error('Confidential Space env_override claim has an unexpected shape');
  }

  for (const key of Object.keys(envOverride)) {
    if (!SAFE_NODE_GCP_ENV_ALLOWLIST.has(key)) {
      throw new Error(`Confidential Space token reports unexpected environment override: ${key}`);
    }
  }

  const required = new Map([
    ['SERVER_DOMAIN', domain],
    ['CONFIDENTIAL_SPACE_AUDIENCE', audience],
    ['ETH_NETWORK', 'sepolia'],
  ]);
  for (const [key, value] of opts.expectedGcpEnv.entries()) {
    required.set(key, value);
  }

  for (const [key, expected] of required.entries()) {
    const actual = envOverride[key] ?? container.env?.[key];
    if (actual !== expected) {
      throw new Error(
        `Confidential Space ${key} mismatch: got ${JSON.stringify(actual)}, expected ${JSON.stringify(expected)}`
      );
    }
  }
}

async function verifyGcpAttestdCertificate(opts) {
  const domain = (opts.tlsDomain || opts.appBaseUrl.hostname).toLowerCase();
  const challenge = randomBytes(32).toString('hex');
  const response = await fetchJson(new URL('/attestd/', opts.appBaseUrl), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ domain, challenge }),
  }, { rejectUnauthorized: false });

  if (typeof response.certificate !== 'string') {
    throw new Error('/attestd/ did not return a certificate');
  }
  if (typeof response.report !== 'string') {
    throw new Error('/attestd/ did not return a report');
  }
  if (typeof response.workload_manifest !== 'string') {
    throw new Error('/attestd/ did not return a workload manifest');
  }

  const certificateHash = createHash('sha256').update(response.certificate).digest();
  const challengeBytes = Buffer.from(challenge, 'hex');
  const workloadDigest = sha384Hex(response.workload_manifest);
  const reportedWorkloadDigest = normalizeHex(
    response.workload_digest_sha384,
    'workload_digest_sha384'
  );
  if (workloadDigest !== reportedWorkloadDigest) {
    throw new Error(
      `GCP workload digest mismatch: calculated ${workloadDigest}, reported ${reportedWorkloadDigest}`
    );
  }
  if (opts.expectedGcpWorkloadDigest) {
    const expected = normalizeHex(opts.expectedGcpWorkloadDigest, 'expected GCP workload digest');
    if (workloadDigest !== expected) {
      throw new Error(`GCP workload digest mismatch: got ${workloadDigest}, expected ${expected}`);
    }
  }
  const expectedRtmr3 = sha384Hex(Buffer.concat([
    Buffer.alloc(48, 0),
    Buffer.from(workloadDigest, 'hex'),
  ]));
  const reportedExpectedRtmr3 = normalizeHex(
    response.workload_rtmr3_expected,
    'workload_rtmr3_expected'
  );
  if (expectedRtmr3 !== reportedExpectedRtmr3) {
    throw new Error(
      `GCP workload RTMR3 mismatch: calculated ${expectedRtmr3}, reported ${reportedExpectedRtmr3}`
    );
  }
  const reportPayload = JSON.stringify({
    domain,
    certificate_hash: Array.from(certificateHash),
    challenge: Array.from(challengeBytes),
    workload_digest_sha384: Array.from(Buffer.from(workloadDigest, 'hex')),
    workload_rtmr3_expected: Array.from(Buffer.from(expectedRtmr3, 'hex')),
  });
  const reportData = sha512Hex(reportPayload);
  const quote = Buffer.from(response.report, 'base64').toString('hex');
  const localQuote = verifyQuoteLocally({
    quote,
    reportData,
    expectedMrtd: opts.expectedMrtd,
    pccsUrl: opts.pccsUrl,
    verifierBin: opts.verifierBin,
  });
  if (localQuote.rtmr3 !== `0x${expectedRtmr3}`) {
    throw new Error(`GCP RTMR3 mismatch: quote ${localQuote.rtmr3}, expected 0x${expectedRtmr3}`);
  }
  const pin = certificatePublicKeyPin(pemFromAttestdCertificate(response.certificate));
  console.log('gcp_attestd_quote_verified=true');
  console.log(`gcp_attestd_domain=${domain}`);
  console.log(`gcp_attestd_certificate_blob_sha256=0x${certificateHash.toString('hex')}`);
  console.log(`gcp_workload_digest_sha384=0x${workloadDigest}`);
  console.log(`gcp_workload_rtmr3_expected=0x${expectedRtmr3}`);
  console.log(`attested_tls_pin=${pin}`);
  console.log(`tee_type=${localQuote.tee_type}`);
  console.log(`mrtd=${localQuote.mrtd}`);
  console.log(`rtmr0=${localQuote.rtmr0}`);
  console.log(`rtmr1=${localQuote.rtmr1}`);
  console.log(`rtmr2=${localQuote.rtmr2}`);
  console.log(`rtmr3=${localQuote.rtmr3}`);
}

async function verifyGcpConfidentialSpaceCertificate(opts) {
  if (!opts.expectedGcpImageDigest) {
    throw new Error('--expected-gcp-image-digest is required for --gcp-confidential-space');
  }

  const domain = (opts.tlsDomain || opts.appBaseUrl.hostname).toLowerCase();
  const audience = opts.gcpAudience || `safe-node:${domain}`;
  const challenge = randomBytes(32).toString('hex');
  const response = await fetchJson(new URL('/attestd/', opts.appBaseUrl), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ domain, challenge, audience }),
  }, { rejectUnauthorized: false });

  if (typeof response.certificate !== 'string') {
    throw new Error('/attestd/ did not return a certificate');
  }
  if (typeof response.confidential_space_token !== 'string') {
    throw new Error('/attestd/ did not return a Confidential Space token');
  }

  const certificateSha256 = sha256Hex(response.certificate);
  const expectedNonce = confidentialSpaceNonce(domain, certificateSha256, challenge);
  if (response.confidential_space_nonce !== expectedNonce) {
    throw new Error('Confidential Space nonce mismatch before JWT verification');
  }
  if (response.confidential_space_audience !== audience) {
    throw new Error('Confidential Space audience mismatch before JWT verification');
  }

  const claims = await verifyGoogleOidcToken(response.confidential_space_token, audience);
  const tokenNonces = Array.isArray(claims.eat_nonce) ? claims.eat_nonce : [claims.eat_nonce];
  if (!tokenNonces.includes(expectedNonce)) {
    throw new Error('Confidential Space token does not contain the expected nonce');
  }
  if (claims.swname !== 'CONFIDENTIAL_SPACE') {
    throw new Error(`unexpected Confidential Space swname: ${claims.swname}`);
  }
  if (!opts.allowGcpDebug && claims.dbgstat !== 'disabled-since-boot') {
    throw new Error(`Confidential Space debug status is not production-safe: ${claims.dbgstat}`);
  }
  if (claims.hwmodel !== 'GCP_INTEL_TDX') {
    throw new Error(`unexpected Confidential Space hardware model: ${claims.hwmodel}`);
  }
  if (claims.secboot !== true) {
    throw new Error('Confidential Space token does not report secure boot');
  }

  const support = claims.submods?.confidential_space?.support_attributes ?? [];
  if (!claimIncludes(support, 'STABLE')) {
    throw new Error('Confidential Space image is not marked STABLE');
  }

  const container = claims.submods?.container ?? {};
  verifyGcpContainerLaunchPolicy(container, opts, domain, audience);

  const pin = certificatePublicKeyPin(pemFromAttestdCertificate(response.certificate));
  console.log('gcp_confidential_space_verified=true');
  console.log(`gcp_confidential_space_domain=${domain}`);
  console.log(`gcp_confidential_space_audience=${audience}`);
  console.log(`gcp_confidential_space_nonce=${expectedNonce}`);
  console.log(`gcp_confidential_space_image_digest=${container.image_digest}`);
  console.log(`gcp_confidential_space_image_reference=${container.image_reference ?? ''}`);
  console.log(`gcp_confidential_space_swversion=${(claims.swversion ?? []).join(',')}`);
  console.log(`attested_tls_certificate_sha256=0x${certificateSha256}`);
  console.log(`attested_tls_pin=${pin}`);
}

async function verifyAttestedTlsCertificate(opts, info) {
  const domain = (opts.tlsDomain || opts.appBaseUrl.hostname).toLowerCase();
  const challenge = randomBytes(32).toString('hex');
  const url = new URL('/attested_tls_cert', opts.appBaseUrl);
  url.searchParams.set('domain', domain);
  url.searchParams.set('challenge', `0x${challenge}`);

  const response = await fetchJson(url);
  const certificate = response.certificate;
  if (typeof certificate !== 'string' || !certificate.includes('BEGIN CERTIFICATE')) {
    throw new Error('/attested_tls_cert did not return a PEM certificate');
  }
  if (response.domain !== domain) {
    throw new Error(`attested TLS domain mismatch: expected ${domain}, got ${response.domain}`);
  }
  if (normalizeHex(response.challenge, 'attested TLS challenge') !== challenge) {
    throw new Error('attested TLS challenge mismatch');
  }

  const certificateSha256 = sha256Hex(certificate);
  const reportedCertificateSha256 = normalizeHex(
    response.certificate_sha256,
    'attested TLS certificate_sha256'
  );
  if (certificateSha256 !== reportedCertificateSha256) {
    throw new Error(
      `attested TLS certificate hash mismatch: calculated ${certificateSha256}, reported ${reportedCertificateSha256}`
    );
  }

  const reportData = sha512Hex(attestedTlsReportPayload(domain, certificateSha256, challenge));
  const reportedReportData = normalizeHex(response.report_data, 'attested TLS report_data');
  if (reportData !== reportedReportData) {
    throw new Error(
      `attested TLS report_data mismatch: calculated ${reportData}, reported ${reportedReportData}`
    );
  }

  const attestation = response.attestation;
  const localQuote = verifyQuoteLocally({
    quote: attestation?.quote,
    reportData,
    expectedMrtd: opts.expectedMrtd,
    pccsUrl: opts.pccsUrl,
    verifierBin: opts.verifierBin,
  });
  verifyRtmr3EventLog(attestation, localQuote);
  verifyComposeHash(info, attestation, opts.strictDigests);
  const pin = certificatePublicKeyPin(certificate);
  console.log('attested_tls_quote_verified=true');
  console.log(`attested_tls_domain=${domain}`);
  console.log(`attested_tls_certificate_sha256=0x${certificateSha256}`);
  console.log(`attested_tls_pin=${pin}`);
  return { pin, localQuote };
}

function eventDigest(event, imr) {
  const eventType = Number(event.event_type ?? event.eventType);
  if (Number(event.imr) === 3 && eventType === DSTACK_RUNTIME_EVENT_TYPE) {
    const eventTypeBytes = Buffer.alloc(4);
    eventTypeBytes.writeUInt32LE(eventType);
    const payload = Buffer.from(
      normalizeHex(event.event_payload ?? event.eventPayload ?? '', `event payload for imr${imr}`),
      'hex'
    );
    const eventName = Buffer.from(event.event ?? '', 'utf8');
    return createHash('sha384')
      .update(Buffer.concat([eventTypeBytes, Buffer.from(':'), eventName, Buffer.from(':'), payload]))
      .digest();
  }

  return Buffer.from(normalizeHex(event.digest, `event digest for imr${imr}`), 'hex');
}

function replayRtmr(events, imr) {
  let mr = Buffer.alloc(48, 0);
  for (const event of events) {
    if (Number(event.imr) !== imr) {
      continue;
    }
    const digest = eventDigest(event, imr);
    if (digest.length > 48) {
      throw new Error(`event digest for imr${imr} is longer than 48 bytes`);
    }
    const padded = Buffer.alloc(48, 0);
    digest.copy(padded);
    mr = createHash('sha384').update(Buffer.concat([mr, padded])).digest();
  }
  return `0x${mr.toString('hex')}`;
}

function verifyRtmr3EventLog(attestation, localQuote) {
  const events = eventLogEvents(attestation.event_log ?? attestation.eventLog);
  if (events.length === 0) {
    console.warn('warning: event_log unavailable, skipping local RTMR3 replay');
    return;
  }
  const replayed = replayRtmr(events, 3);
  if (replayed !== localQuote.rtmr3) {
    throw new Error(`RTMR3 replay mismatch: replayed ${replayed}, quote ${localQuote.rtmr3}`);
  }
  console.log(`rtmr3_replay=${replayed}`);
}

function verifyComposeHash(info, attestation, strictDigests) {
  const appCompose = extractAppCompose(info);
  const events = eventLogEvents(attestation.event_log ?? attestation.eventLog);
  const composeEvent = events.find((event) => event.event === 'compose-hash');

  if (appCompose && composeEvent?.event_payload) {
    const appComposeBytes = typeof appCompose === 'string' ? appCompose : JSON.stringify(appCompose);
    const calculatedComposeHash = createHash('sha256').update(appComposeBytes).digest('hex');
    const attestedComposeHash = normalizeHex(composeEvent.event_payload, 'compose-hash event');
    if (calculatedComposeHash !== attestedComposeHash) {
      throw new Error(
        `compose-hash mismatch: calculated ${calculatedComposeHash}, attested ${attestedComposeHash}`
      );
    }
    console.log(`compose_hash=0x${calculatedComposeHash}`);
  } else {
    console.warn('warning: compose-hash check skipped because app_compose or event_log was unavailable');
  }

  const unpinnedImages = checkPinnedImages(dockerComposeFromAppCompose(appCompose));
  if (unpinnedImages.length > 0) {
    const message = `unpinned image references found: ${unpinnedImages.join(', ')}`;
    if (strictDigests) {
      throw new Error(message);
    }
    console.warn(`warning: ${message}`);
  }
}

async function verifyWithLocalDstackVerifier(verifierUrl, attestation, required) {
  if (!verifierUrl) {
    return;
  }
  try {
    const result = await fetchJson(new URL('/verify', verifierUrl), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(attestation),
    });
    if (result.is_valid !== true && result.success !== true) {
      throw new Error(JSON.stringify(result));
    }
    console.log('dstack_verifier=valid');
  } catch (err) {
    if (required) {
      throw err;
    }
    console.warn(`warning: local dstack-verifier check skipped/failed: ${err.message}`);
  }
}

async function compareWithPhalaApi(quote) {
  const verifyApi = process.env.PHALA_ATTESTATION_VERIFY_API || DEFAULT_PHALA_VERIFY_API;
  const verification = await fetchJson(verifyApi, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ hex: normalizeHex(quote, 'attestation.quote') }),
  });
  if (verification?.quote?.verified !== true) {
    throw new Error('Phala API comparison failed');
  }
  console.log(`phala_api_checksum=${verification.checksum ?? ''}`);
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.gcpConfidentialSpace) {
    await verifyGcpConfidentialSpaceCertificate(opts);
    return;
  }
  if (opts.gcpAttestd) {
    await verifyGcpAttestdCertificate(opts);
    return;
  }

  let reportData;
  if (process.env.REPORT_DATA_HEX) {
    reportData = normalizeHex(process.env.REPORT_DATA_HEX, 'REPORT_DATA_HEX');
  } else if (opts.simulatorFixture) {
    reportData = '0'.repeat(128);
  } else {
    reportData = randomBytes(32).toString('hex');
  }

  if (opts.simulatorFixture && !process.env.REPORT_DATA_HEX) {
    console.warn(
      'warning: using dstack simulator zero-report-data fixture; this verifies the fixture locally but is not a fresh challenge'
    );
  }

  if (reportData.length > 128) {
    throw new Error('REPORT_DATA_HEX must be at most 64 bytes');
  }

  const attestationUrl = new URL('/attestation', opts.appBaseUrl);
  attestationUrl.searchParams.set('report_data', `0x${reportData}`);
  const attestation = await fetchJson(attestationUrl);

  const localQuote = verifyQuoteLocally({
    quote: attestation.quote,
    reportData,
    expectedMrtd: opts.expectedMrtd,
    pccsUrl: opts.pccsUrl,
    verifierBin: opts.verifierBin,
  });
  verifyRtmr3EventLog(attestation, localQuote);

  let info = null;
  try {
    info = await fetchJson(new URL('/info', opts.appBaseUrl));
  } catch (err) {
    console.warn(`warning: /info unavailable, skipping compose checks: ${err.message}`);
  }
  verifyComposeHash(info, attestation, opts.strictDigests);

  if (opts.attestedTls) {
    await verifyAttestedTlsCertificate(opts, info);
  }

  await verifyWithLocalDstackVerifier(
    opts.dstackVerifierUrl,
    attestation,
    opts.requireDstackVerifier
  );

  if (opts.phalaApi) {
    await compareWithPhalaApi(attestation.quote);
  }

  console.log('local_quote_verified=true');
  console.log(`tee_type=${localQuote.tee_type}`);
  console.log(`mrtd=${localQuote.mrtd}`);
  console.log(`rtmr0=${localQuote.rtmr0}`);
  console.log(`rtmr1=${localQuote.rtmr1}`);
  console.log(`rtmr2=${localQuote.rtmr2}`);
  console.log(`rtmr3=${localQuote.rtmr3}`);
}

main().catch((err) => {
  console.error(`verification failed: ${err.message}`);
  process.exit(1);
});
