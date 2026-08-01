import { describe, expect, it } from "vitest";
import { runConnectivityCheck } from "../../src/lib/connectivity";
import "../../src/lib/connectivity-checks";

/**
 * The `acme-ca` check against a REAL ACME server that requires EAB.
 *
 * Opt-in — skipped unless PEBBLE_DIRECTORY is set, since it needs Docker:
 *
 *   docker run -d --name pebble-eab -p 14000:14000 \
 *     ghcr.io/letsencrypt/pebble:latest \
 *     -config /test/config/pebble-config-external-account-bindings.json
 *   # extract the trust root: docker cp <id>:/test/certs/pebble.minica.pem .
 *   PEBBLE_DIRECTORY=https://localhost:14000/dir \
 *   PEBBLE_CA_BUNDLE=$PWD/pebble.minica.pem \
 *     bun run --cwd apps/api test test/lib/acme-ca-pebble.smoke.test.ts
 *
 * This earns its place next to the fake-server unit tests rather than
 * duplicating them: the fake server is one I wrote, so it can only confirm the
 * directory shape I already assumed. A real CA caught a bug those tests could
 * not — Pebble rejects any request without a User-Agent (RFC 8555 §6.1) with
 * `400 malformed`, which made the check report "HTTP 400" against every real
 * ACME CA. That class of protocol-compliance bug is exactly what this covers.
 */

const DIR = process.env.PEBBLE_DIRECTORY;
const BUNDLE = process.env.PEBBLE_CA_BUNDLE ?? "";

describe.skipIf(!DIR)("acme-ca against a real Pebble (EAB required)", () => {
  it("passes with EAB configured and the private root trusted", async () => {
    const r = await runConnectivityCheck("acme-ca", {
      directoryUrl: DIR,
      caBundle: BUNDLE,
      eabConfigured: true,
    });
    expect(r).toMatchObject({ ok: true, code: "reachable" });
  });

  it("fails auth_failed when the CA requires EAB and the profile has none", async () => {
    const r = await runConnectivityCheck("acme-ca", {
      directoryUrl: DIR,
      caBundle: BUNDLE,
      eabConfigured: false,
    });
    expect(r).toMatchObject({ ok: false, code: "auth_failed" });
    expect(r.message).toContain("External Account Binding");
  });

  it("without the private root, the TLS failure is classified, not thrown", async () => {
    const r = await runConnectivityCheck("acme-ca", {
      directoryUrl: DIR,
      caBundle: null,
      eabConfigured: true,
    });
    expect(r.ok).toBe(false);
  });
});
