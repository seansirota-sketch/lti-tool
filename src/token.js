const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const { config } = require("./config");

function buildHandoffPayload(launch) {
  const now = Math.floor(Date.now() / 1000);

  return {
    sub: launch.userId,
    name: launch.name,
    email: launch.email,
    context_id: launch.courseId,
    course_id: launch.courseId,
    context_title: launch.contextTitle,
    resource_link_id: launch.resourceLinkId,
    roles: launch.roles,
    platform_issuer: launch.issuer,
    jti: crypto.randomUUID(),
    iat: now,
    nbf: now,
    exp: now + config.handoffExpSeconds,
    iss: config.handoffIssuer,
    aud: config.handoffAudience,
  };
}

function mintHandoffToken(launch) {
  const payload = buildHandoffPayload(launch);
  return jwt.sign(payload, config.handoffSigningKey, { algorithm: "HS256" });
}

module.exports = { mintHandoffToken };
