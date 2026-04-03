const express = require("express");
const helmet = require("helmet");
const morgan = require("morgan");
const { config } = require("./config");
const { mintHandoffToken } = require("./token");
const { createInteraction, consumeInteraction } = require("./lti/stateStore");
const { initToolJwks, getPublicJwks } = require("./lti/jwks");
const {
  createLoginRedirectUrl,
  ensurePlatformConfig,
  verifyLtiIdToken,
} = require("./lti/oidc");

const app = express();

const startupEnvChecks = {
  VAULTAU_URL: Boolean(config.vaultauUrl),
  LTI_HANDOFF_SIGNING_KEY: Boolean(config.handoffSigningKey),
  LTI_PLATFORM_ISSUER: Boolean(config.ltiPlatformIssuer),
  LTI_PLATFORM_CLIENT_ID: Boolean(config.ltiPlatformClientId),
  LTI_PLATFORM_AUTH_LOGIN_URL: Boolean(config.ltiPlatformAuthLoginUrl),
  LTI_PLATFORM_JWKS_URL: Boolean(config.ltiPlatformJwksUrl),
  LTI_PLATFORM_DEPLOYMENT_ID: Boolean(config.ltiPlatformDeploymentId),
  LTI_TOOL_BASE_URL: Boolean(config.ltiToolBaseUrl),
};
console.log("[startup] required env present:", startupEnvChecks);

app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(morgan("dev"));

app.get("/health", (_req, res) => {
  res.status(200).json({ ok: true, service: "lti-tool-bridge" });
});

function getRequestParams(req) {
  return {
    ...req.query,
    ...req.body,
  };
}

app.all(config.ltiLoginPath, (req, res) => {
  try {
    ensurePlatformConfig();

    const params = getRequestParams(req);
    const iss = String(params.iss || "").trim();
    const loginHint = String(params.login_hint || "").trim();
    const targetLinkUri = String(params.target_link_uri || "").trim();

    if (!iss || !loginHint || !targetLinkUri) {
      return res.status(400).json({
        error: "Missing login initiation parameters: iss, login_hint, target_link_uri",
      });
    }

    if (iss !== config.ltiPlatformIssuer) {
      return res.status(403).json({ error: "Unrecognized platform issuer." });
    }

    const interaction = createInteraction({
      platformIssuer: iss,
      loginHint,
      targetLinkUri,
    });

    const redirectUrl = createLoginRedirectUrl(req, params, interaction);
    return res.redirect(302, redirectUrl);
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

async function handleLtiLaunch(req, res) {
  try {
    ensurePlatformConfig();

    const state = String(req.body.state || "").trim();
    const idToken = String(req.body.id_token || "").trim();

    if (!state || !idToken) {
      return res.status(400).json({ error: "Missing state or id_token." });
    }

    const interaction = consumeInteraction(state);
    if (!interaction) {
      return res.status(400).json({ error: "Invalid or expired OIDC state." });
    }

    const launch = await verifyLtiIdToken(idToken, interaction.nonce);

    if (config.allowedIssuer && launch.issuer !== config.allowedIssuer) {
      return res.status(403).json({ error: "Launch issuer is not allowed." });
    }

    if (!launch.userId || !launch.resourceLinkId) {
      return res.status(400).json({
        error: "Validated launch missing required claims: sub or resource_link.id.",
      });
    }

    const token = mintHandoffToken(launch);
    const redirectUrl = new URL(config.vaultauUrl);
    redirectUrl.searchParams.set("lti_handoff", token);

    return res.redirect(302, redirectUrl.toString());
  } catch (error) {
    console.error(error);
    return res.status(400).json({ error: `LTI launch validation failed: ${error.message}` });
  }
}

app.post(config.ltiCallbackPath, handleLtiLaunch);
app.post("/lti/launch", handleLtiLaunch);

app.get(config.ltiJwksPath, (_req, res) => {
  return res.status(200).json(getPublicJwks());
});

app.get("/dev/mock-launch", (_req, res) => {
  const token = mintHandoffToken({
    issuer: config.allowedIssuer || "https://moodle.local",
    userId: "moodle-user-123",
    name: "Demo User",
    email: "demo@example.com",
    courseId: "sandbox-course-1",
    contextTitle: "Sandbox Course",
    resourceLinkId: "resource-1",
    roles: ["Learner"],
  });

  const redirectUrl = new URL(config.vaultauUrl);
  redirectUrl.searchParams.set("lti_handoff", token);

  return res.redirect(302, redirectUrl.toString());
});

app.use((err, _req, res, _next) => {
  console.error(err);
  return res.status(500).json({ error: "Internal server error." });
});

async function start() {
  await initToolJwks();

  app.listen(config.port, () => {
    console.log(`LTI bridge listening on http://localhost:${config.port}`);
    console.log(`LTI login endpoint: ${config.ltiLoginPath}`);
    console.log(`LTI callback endpoint: ${config.ltiCallbackPath}`);
    console.log(`LTI JWKS endpoint: ${config.ltiJwksPath}`);
  });
}

start().catch((error) => {
  console.error("Failed to start service", error);
  process.exit(1);
});
