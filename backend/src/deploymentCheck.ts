import fs from "fs";
import path from "path";

type FindingLevel = "error" | "warning";

interface Finding {
  level: FindingLevel;
  message: string;
}

const DEFAULT_ENV_FILE = process.env.DEPLOYMENT_ENV_FILE || ".env.public-beta.example";
const PLACEHOLDER_PATTERN = /(replace-with|change-this|example\.com|\.example|placeholder)/i;

function loadEnvFile(filePath: string) {
  const resolved = path.resolve(process.cwd(), "..", filePath);
  const fallback = path.resolve(process.cwd(), filePath);
  const target = fs.existsSync(resolved) ? resolved : fallback;
  if (!fs.existsSync(target)) return;

  const lines = fs.readFileSync(target, "utf8").split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const separator = trimmed.indexOf("=");
    if (separator === -1) continue;
    const key = trimmed.slice(0, separator).trim();
    const value = trimmed.slice(separator + 1).trim().replace(/^['"]|['"]$/g, "");
    if (key && process.env[key] === undefined) {
      process.env[key] = value;
    }
  }
}

function env(name: string) {
  return process.env[name] || "";
}

function add(findings: Finding[], level: FindingLevel, message: string) {
  findings.push({ level, message });
}

function requireValue(findings: Finding[], name: string) {
  const value = env(name);
  if (!value) {
    add(findings, "error", `${name} is required.`);
    return "";
  }
  if (PLACEHOLDER_PATTERN.test(value)) {
    add(findings, "error", `${name} still contains a placeholder value.`);
  }
  return value;
}

function requireBoolean(findings: Finding[], name: string, expected: "true" | "false") {
  const value = requireValue(findings, name);
  if (value && value !== expected) {
    add(findings, "error", `${name} must be ${expected} for public deployment.`);
  }
}

function requirePositiveNumber(findings: Finding[], name: string) {
  const value = requireValue(findings, name);
  if (!value) return;
  const numeric = Number(value);
  if (!Number.isFinite(numeric) || numeric <= 0) {
    add(findings, "error", `${name} must be a positive number.`);
  }
}

function requireLongSecret(findings: Finding[], name: string, minLength = 32) {
  const value = requireValue(findings, name);
  if (value && value.length < minLength) {
    add(findings, "error", `${name} must be at least ${minLength} characters.`);
  }
}

function checkCors(findings: Finding[]) {
  const origins = requireValue(findings, "CORS_ORIGINS")
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean);

  if (origins.includes("*")) {
    add(findings, "error", "CORS_ORIGINS must not contain *.");
  }

  for (const origin of origins) {
    try {
      const parsed = new URL(origin);
      if (parsed.protocol !== "https:") {
        add(findings, "warning", `${origin} is not HTTPS. Use HTTPS for internet-facing deployments.`);
      }
    } catch {
      add(findings, "error", `${origin} is not a valid CORS origin.`);
    }
  }
}

function checkDatabase(findings: Finding[]) {
  const driver = requireValue(findings, "DATABASE_DRIVER").toLowerCase();
  if (driver !== "postgres" && driver !== "postgresql") {
    add(findings, "error", "DATABASE_DRIVER must be postgres for public deployment.");
  }
  const url = requireValue(findings, "DATABASE_URL");
  if (url && !/^postgres(ql)?:\/\//.test(url)) {
    add(findings, "error", "DATABASE_URL must be a PostgreSQL connection string.");
  }
  requireLongSecret(findings, "POSTGRES_PASSWORD", 24);
}

function checkStorage(findings: Finding[]) {
  const driver = requireValue(findings, "STORAGE_DRIVER").toLowerCase();
  if (driver !== "s3") {
    add(findings, "error", "STORAGE_DRIVER must be s3 for public deployment.");
  }
  requireValue(findings, "S3_ENDPOINT");
  requireValue(findings, "S3_BUCKET");
  requireLongSecret(findings, "S3_ACCESS_KEY", 16);
  requireLongSecret(findings, "S3_SECRET_KEY", 32);
}

function checkSessions(findings: Finding[]) {
  requireBoolean(findings, "SESSION_COOKIE_ENABLED", "true");
  requireBoolean(findings, "SESSION_RETURN_BEARER_TOKEN", "false");
  requireBoolean(findings, "SESSION_COOKIE_SECURE", "true");
  requireBoolean(findings, "VITE_SESSION_COOKIE_ENABLED", "true");
  requireLongSecret(findings, "SESSION_COOKIE_SECRET", 32);
  const sameSite = requireValue(findings, "SESSION_COOKIE_SAMESITE").toLowerCase();
  if (!["strict", "lax", "none"].includes(sameSite)) {
    add(findings, "error", "SESSION_COOKIE_SAMESITE must be strict, lax, or none.");
  }
  requirePositiveNumber(findings, "SESSION_TTL_MS");
  if (Number(env("SESSION_TTL_MS")) > 86_400_000) {
    add(findings, "warning", "SESSION_TTL_MS is longer than 24 hours.");
  }
}

function checkP2P(findings: Finding[]) {
  const turnUrls = requireValue(findings, "P2P_TURN_URLS");
  if (turnUrls.includes("127.0.0.1") || turnUrls.includes("localhost")) {
    add(findings, "error", "P2P_TURN_URLS must point to a reachable public TURN host.");
  }
  requireLongSecret(findings, "P2P_TURN_SHARED_SECRET", 32);
  if (env("P2P_TURN_USERNAME") || env("P2P_TURN_CREDENTIAL")) {
    add(findings, "error", "Static P2P_TURN_USERNAME/P2P_TURN_CREDENTIAL should be blank; use P2P_TURN_SHARED_SECRET for short-lived relay credentials.");
  }
  requirePositiveNumber(findings, "P2P_TURN_CREDENTIAL_TTL_MS");
  requirePositiveNumber(findings, "P2P_SIGNAL_MAX_BYTES");
  requirePositiveNumber(findings, "P2P_MAX_SOCKETS_PER_USER");
  requirePositiveNumber(findings, "P2P_MAX_ACTIVE_SESSIONS_PER_USER");
  requirePositiveNumber(findings, "P2P_MAX_SIGNALING_TICKETS_PER_USER");
}

function checkLimits(findings: Finding[]) {
  requirePositiveNumber(findings, "UPLOAD_FILE_LIMIT_BYTES");
  requirePositiveNumber(findings, "UPLOAD_FIELD_LIMIT_BYTES");
  requirePositiveNumber(findings, "VAULT_CHUNK_UPLOAD_LIMIT_BYTES");
  requirePositiveNumber(findings, "USER_STORAGE_QUOTA_BYTES");
  requirePositiveNumber(findings, "RATE_LIMIT_WINDOW_MS");
  requirePositiveNumber(findings, "RATE_LIMIT_MAX");
  requirePositiveNumber(findings, "AUTH_RATE_LIMIT_WINDOW_MS");
  requirePositiveNumber(findings, "AUTH_RATE_LIMIT_MAX");
}

async function checkLiveEndpoint(findings: Finding[]) {
  const endpoint = env("DEPLOYMENT_CHECK_READY_URL");
  if (!endpoint) return;

  try {
    const response = await fetch(endpoint);
    if (!response.ok) {
      add(findings, "error", `${endpoint} returned HTTP ${response.status}.`);
      return;
    }
    const body = await response.json() as { ready?: boolean; database?: { ready?: boolean }; storage?: { ready?: boolean } };
    if (!body.ready || !body.database?.ready || !body.storage?.ready) {
      add(findings, "error", `${endpoint} did not report ready database and storage.`);
    }
  } catch (err) {
    add(findings, "error", `Unable to reach ${endpoint}: ${err instanceof Error ? err.message : "unknown error"}.`);
  }
}

async function main() {
  loadEnvFile(DEFAULT_ENV_FILE);

  const findings: Finding[] = [];
  requireBoolean(findings, "CRYPSHARE_PUBLIC_DEPLOYMENT", "true");
  requireBoolean(findings, "TRUST_PROXY", "true");
  checkCors(findings);
  checkDatabase(findings);
  checkStorage(findings);
  checkSessions(findings);
  checkP2P(findings);
  checkLimits(findings);
  await checkLiveEndpoint(findings);

  const errors = findings.filter((finding) => finding.level === "error");
  const warnings = findings.filter((finding) => finding.level === "warning");

  for (const finding of findings) {
    const label = finding.level === "error" ? "ERROR" : "WARN";
    console.log(`${label}: ${finding.message}`);
  }

  if (errors.length > 0) {
    console.error(`Deployment check failed with ${errors.length} error(s) and ${warnings.length} warning(s).`);
    process.exitCode = 1;
    return;
  }

  console.log(`Deployment check passed with ${warnings.length} warning(s).`);
}

main().catch((err) => {
  console.error("Deployment check crashed.", err);
  process.exitCode = 1;
});
