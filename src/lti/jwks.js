const crypto = require("crypto");
const { generateKeyPair, exportJWK } = require("jose");

let publicJwks = null;

async function initToolJwks() {
  if (publicJwks) {
    return publicJwks;
  }

  const { publicKey } = await generateKeyPair("RS256", { extractable: true });
  const publicJwk = await exportJWK(publicKey);
  publicJwk.use = "sig";
  publicJwk.alg = "RS256";
  publicJwk.kid = crypto.randomUUID();

  publicJwks = { keys: [publicJwk] };
  return publicJwks;
}

function getPublicJwks() {
  if (!publicJwks) {
    throw new Error("JWKS not initialized");
  }
  return publicJwks;
}

module.exports = {
  initToolJwks,
  getPublicJwks,
};
