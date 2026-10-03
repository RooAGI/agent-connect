// Deploy the bundled worker via the Cloudflare API (no wrangler needed).
// Env: CF_TOKEN, ACCOUNT_ID, KV_ID, SCRIPT_NAME (default agent-connect-relay),
//      PEERS (optional comma-separated peer relay URLs, default empty),
//      OPERATOR_PUBKEY (required: 64-hex ed25519 pubkey allowed to sign policy updates)
import fs from 'node:fs';

const { CF_TOKEN, ACCOUNT_ID, KV_ID, SCRIPT_NAME = 'agent-connect-relay', PEERS = '', OPERATOR_PUBKEY = '' } = process.env;
if (!CF_TOKEN || !ACCOUNT_ID || !KV_ID) {
  console.error('need CF_TOKEN, ACCOUNT_ID, KV_ID in env');
  process.exit(1);
}
if (!/^[0-9a-f]{64}$/.test(OPERATOR_PUBKEY)) {
  console.error('need OPERATOR_PUBKEY (64 hex chars) in env');
  process.exit(1);
}
const bundle = fs.readFileSync(new URL('../dist/worker.js', import.meta.url));
const metadata = {
  main_module: 'worker.js',
  compatibility_date: '2025-01-01',
  bindings: [
    { type: 'kv_namespace', name: 'PACKETS', namespace_id: KV_ID },
    { type: 'plain_text', name: 'PEERS', text: PEERS },
    { type: 'plain_text', name: 'OPERATOR_PUBKEY', text: OPERATOR_PUBKEY },
  ],
};
const form = new FormData();
form.append('metadata', new Blob([JSON.stringify(metadata)], { type: 'application/json' }));
form.append('worker.js', new Blob([bundle], { type: 'application/javascript+module' }), 'worker.js');

const res = await fetch(
  `https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}/workers/scripts/${SCRIPT_NAME}`,
  { method: 'PUT', headers: { Authorization: `Bearer ${CF_TOKEN}` }, body: form }
);
const data = await res.json();
if (!data.success) {
  console.error('deploy failed:', JSON.stringify(data.errors));
  process.exit(1);
}
console.log('deployed', SCRIPT_NAME);
