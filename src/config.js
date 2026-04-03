const path = require("path");
const dotenv = require("dotenv");

dotenv.config({ path: path.resolve(process.cwd(), ".env") });

function readRequired(name) {
  const value = process.env[name];
  if (!value || !value.trim()) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value.trim();
}

function readOptional(name, fallback) {
  const value = process.env[name];
  if (value === undefined || value === null || value === "") {
    return fallback;
  }
  return value;
}

function readNumber(name, fallback) {
  const raw = readOptional(name, String(fallback));
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(`Environment variable ${name} must be a positive number.`);
  }
  return parsed;
}

const config = {
  nodeEnv: readOptional("NODE_ENV", "development"),
  port: readNumber("PORT", 3000),
  vaultauUrl: readRequired("VAULTAU_URL"),
  handoffSigningKey: readRequired("LTI_HANDOFF_SIGNING_KEY"),
  handoffIssuer: readOptional("LTI_HANDOFF_ISSUER", "lti-tool-bridge"),
  handoffAudience: readOptional("LTI_HANDOFF_AUDIENCE", "vaultau"),
  handoffExpSeconds: readNumber("LTI_HANDOFF_EXP_SECONDS", 300),
  allowedIssuer: readOptional("LTI_ALLOWED_ISSUER", "").trim(),
  ltiToolBaseUrl: readOptional("LTI_TOOL_BASE_URL", "").trim(),
  ltiLoginPath: readOptional("LTI_LOGIN_PATH", "/lti/login").trim(),
  ltiCallbackPath: readOptional("LTI_CALLBACK_PATH", "/lti/callback").trim(),
  ltiJwksPath: readOptional("LTI_JWKS_PATH", "/.well-known/jwks.json").trim(),
  ltiStateTtlSeconds: readNumber("LTI_STATE_TTL_SECONDS", 600),
  ltiPlatformIssuer: readOptional("LTI_PLATFORM_ISSUER", "").trim(),
  ltiPlatformClientId: readOptional("LTI_PLATFORM_CLIENT_ID", "").trim(),
  ltiPlatformAuthLoginUrl: readOptional("LTI_PLATFORM_AUTH_LOGIN_URL", "").trim(),
  ltiPlatformJwksUrl: readOptional("LTI_PLATFORM_JWKS_URL", "").trim(),
  ltiPlatformDeploymentId: readOptional(
    "LTI_PLATFORM_DEPLOYMENT_ID",
    ""
  ).trim(),
};

module.exports = { config };
