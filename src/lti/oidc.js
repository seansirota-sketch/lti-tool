const { createRemoteJWKSet, jwtVerify } = require("jose");
const { config } = require("../config");

function normalizeRoles(rolesClaim) {
  if (Array.isArray(rolesClaim)) {
    return rolesClaim;
  }
  if (!rolesClaim) {
    return [];
  }
  return [String(rolesClaim)];
}

function ensurePlatformConfig() {
  const missing = [];

  if (!config.ltiPlatformIssuer) missing.push("LTI_PLATFORM_ISSUER");
  if (!config.ltiPlatformClientId) missing.push("LTI_PLATFORM_CLIENT_ID");
  if (!config.ltiPlatformAuthLoginUrl) missing.push("LTI_PLATFORM_AUTH_LOGIN_URL");
  if (!config.ltiPlatformJwksUrl) missing.push("LTI_PLATFORM_JWKS_URL");
  if (!config.ltiPlatformDeploymentId) missing.push("LTI_PLATFORM_DEPLOYMENT_ID");

  if (missing.length > 0) {
    throw new Error(`Missing LTI platform config: ${missing.join(", ")}`);
  }
}

function getCallbackUrl(req) {
  if (config.ltiToolBaseUrl) {
    return new URL(config.ltiCallbackPath, config.ltiToolBaseUrl).toString();
  }

  const base = `${req.protocol}://${req.get("host")}`;
  return new URL(config.ltiCallbackPath, base).toString();
}

function createLoginRedirectUrl(req, params, interaction) {
  ensurePlatformConfig();

  const authUrl = new URL(config.ltiPlatformAuthLoginUrl);
  authUrl.searchParams.set("response_type", "id_token");
  authUrl.searchParams.set("response_mode", "form_post");
  authUrl.searchParams.set("scope", "openid");
  authUrl.searchParams.set("prompt", "none");
  authUrl.searchParams.set("client_id", config.ltiPlatformClientId);
  authUrl.searchParams.set("redirect_uri", getCallbackUrl(req));
  authUrl.searchParams.set("login_hint", params.login_hint);
  authUrl.searchParams.set("state", interaction.state);
  authUrl.searchParams.set("nonce", interaction.nonce);

  if (params.lti_message_hint) {
    authUrl.searchParams.set("lti_message_hint", params.lti_message_hint);
  }

  return authUrl.toString();
}

async function verifyLtiIdToken(idToken, expectedNonce) {
  ensurePlatformConfig();

  const remoteJwks = createRemoteJWKSet(new URL(config.ltiPlatformJwksUrl));
  const { payload } = await jwtVerify(idToken, remoteJwks, {
    issuer: config.ltiPlatformIssuer,
    audience: config.ltiPlatformClientId,
    nonce: expectedNonce,
  });

  const deploymentClaim =
    payload["https://purl.imsglobal.org/spec/lti/claim/deployment_id"];

  if (deploymentClaim !== config.ltiPlatformDeploymentId) {
    throw new Error("Invalid LTI deployment_id claim");
  }

  const contextClaim =
    payload["https://purl.imsglobal.org/spec/lti/claim/context"] || {};
  const resourceLinkClaim =
    payload["https://purl.imsglobal.org/spec/lti/claim/resource_link"] || {};

  return {
    issuer: payload.iss,
    userId: payload.sub,
    name: payload.name || payload.given_name || "",
    email: payload.email || "",
    courseId: contextClaim.id || "",
    contextTitle: contextClaim.title || "",
    resourceLinkId: resourceLinkClaim.id || "",
    roles: normalizeRoles(
      payload["https://purl.imsglobal.org/spec/lti/claim/roles"]
    ),
  };
}

module.exports = {
  createLoginRedirectUrl,
  verifyLtiIdToken,
  ensurePlatformConfig,
};
