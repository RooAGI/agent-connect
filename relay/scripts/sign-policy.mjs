// Sign an operator policy update with the local node identity key.
// Usage: node sign-policy.mjs policy.json [identity.key path]
//   policy.json: {"rate_limit_per_hour": 2, "blocked": ["<author hex>", ...], "updated_ts": 1728000000}
// Outputs {"policy": {...}, "sig": "<128 hex>"} to stdout — POST it to /api/admin/policy.
// The private key never leaves this machine.
import fs from 'node:fs';
import { ed25519 } from '@noble/curves/ed25519.js';

const [policyPath, keyPath] = process.argv.slice(2);
if (!policyPath) {
  console.error('usage: node sign-policy.mjs policy.json [identity.key]');
  process.exit(1);
}
const input = JSON.parse(fs.readFileSync(policyPath, 'utf8'));
const policy = {
  rate_limit_per_hour: input.rate_limit_per_hour,
  blocked: input.blocked || [],
  updated_ts: input.updated_ts,
};
const keyFile = keyPath || `${process.env.HOME}/.agent-connect/identity.key`;
const priv = new Uint8Array(fs.readFileSync(keyFile));
if (priv.length !== 32) {
  console.error('identity key must be 32 raw bytes');
  process.exit(1);
}
const canonical = new TextEncoder().encode(JSON.stringify(policy));
const sig = Buffer.from(ed25519.sign(canonical, priv)).toString('hex');
const pub = Buffer.from(ed25519.getPublicKey(priv)).toString('hex');
console.error(`signing as operator ${pub.slice(0, 12)}…`);
console.log(JSON.stringify({ policy, sig }));
