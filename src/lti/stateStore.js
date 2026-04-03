const crypto = require("crypto");
const { config } = require("../config");

const interactions = new Map();

function nowSeconds() {
  return Math.floor(Date.now() / 1000);
}

function createInteraction(payload) {
  const state = crypto.randomUUID();
  const nonce = crypto.randomUUID();
  const expiresAt = nowSeconds() + config.ltiStateTtlSeconds;

  interactions.set(state, {
    ...payload,
    nonce,
    expiresAt,
  });

  return { state, nonce, expiresAt };
}

function consumeInteraction(state) {
  const entry = interactions.get(state);
  interactions.delete(state);

  if (!entry) {
    return null;
  }

  if (entry.expiresAt <= nowSeconds()) {
    return null;
  }

  return entry;
}

function cleanupExpiredInteractions() {
  const current = nowSeconds();
  for (const [state, entry] of interactions.entries()) {
    if (entry.expiresAt <= current) {
      interactions.delete(state);
    }
  }
}

setInterval(cleanupExpiredInteractions, 60 * 1000).unref();

module.exports = {
  createInteraction,
  consumeInteraction,
};
