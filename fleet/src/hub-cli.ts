import { AgentDefenseHubServer } from './agent-defense-hub';

const port = Number(process.env.HUB_PORT || 8443);
const host = process.env.HUB_HOST || '0.0.0.0';

const hub = new AgentDefenseHubServer({ host, port });
hub
  .start()
  .then(({ baseUrl }) => {
    console.log(`🛡️  agent-defense-hub listening on ${baseUrl}`);
    console.log(`🔑 Ed25519 Policy Signer Fingerprint: ${hub.getPublicKeyFingerprint()}`);
  })
  .catch((err) => {
    console.error('Failed to start agent-defense-hub:', err);
    process.exit(1);
  });
