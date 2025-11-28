const crypto = require('crypto');

const VERIFIER_CHARSET =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';

function randomString(length = 64) {
  const random = crypto.randomBytes(length);
  const chars = [];
  for (let i = 0; i < length; i += 1) {
    chars.push(VERIFIER_CHARSET[random[i] % VERIFIER_CHARSET.length]);
  }
  return chars.join('');
}

function base64UrlEncode(buffer) {
  return buffer
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

function createChallenge(verifier) {
  const hash = crypto.createHash('sha256').update(verifier).digest();
  return base64UrlEncode(hash);
}

function createPKCECodes() {
  const verifier = randomString(64);
  const challenge = createChallenge(verifier);
  return { verifier, challenge, method: 'S256' };
}

module.exports = {
  createPKCECodes,
};
