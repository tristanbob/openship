import { createServer, type Server } from "node:http";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { runConnectivityCheck } from "../../src/lib/connectivity";
import "../../src/lib/connectivity-checks"; // registers acme-ca

/**
 * The acme-ca check against a real (loopback) HTTP server — the config-time
 * failures #256 demands actionable errors for: a URL that isn't an ACME
 * directory, a CA that requires EAB when the profile has none, and the happy
 * path. TLS/trust-root behavior is exercised in the e2e smoke (step-ca), not
 * here.
 */

let server: Server;
let base: string;
/** What the fake directory responds with, set per test. */
let respond: () => { status: number; body: string };

beforeAll(async () => {
  server = createServer((req, res) => {
    const { status, body } = respond();
    res.writeHead(status, { "content-type": "application/json" });
    res.end(body);
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const addr = server.address();
  if (addr == null || typeof addr === "string") throw new Error("no port");
  base = `http://127.0.0.1:${addr.port}`;
});

afterAll(() => new Promise<void>((r) => server.close(() => r())));

const DIRECTORY = (extra: object = {}) =>
  JSON.stringify({
    newAccount: `${base}/acct`,
    newNonce: `${base}/nonce`,
    newOrder: `${base}/order`,
    ...extra,
  });

describe("acme-ca connectivity check", () => {
  it("accepts a well-formed directory", async () => {
    respond = () => ({ status: 200, body: DIRECTORY() });
    const r = await runConnectivityCheck("acme-ca", { directoryUrl: `${base}/dir`, eabConfigured: false });
    expect(r).toMatchObject({ ok: true, code: "reachable" });
    expect(r.latencyMs).toBeGreaterThanOrEqual(0);
  });

  it("names the missing RFC 8555 endpoints when the URL is not an ACME directory", async () => {
    respond = () => ({ status: 200, body: JSON.stringify({ hello: "world" }) });
    const r = await runConnectivityCheck("acme-ca", { directoryUrl: `${base}/dir`, eabConfigured: false });
    expect(r.ok).toBe(false);
    expect(r.code).toBe("protocol_error");
    expect(r.message).toContain("newAccount");
  });

  it("fails auth_failed when the CA requires EAB and the profile has none", async () => {
    respond = () => ({ status: 200, body: DIRECTORY({ meta: { externalAccountRequired: true } }) });
    const r = await runConnectivityCheck("acme-ca", { directoryUrl: `${base}/dir`, eabConfigured: false });
    expect(r).toMatchObject({ ok: false, code: "auth_failed" });
    expect(r.message).toContain("External Account Binding");
  });

  it("passes with EAB configured against an EAB-requiring CA", async () => {
    respond = () => ({ status: 200, body: DIRECTORY({ meta: { externalAccountRequired: true } }) });
    const r = await runConnectivityCheck("acme-ca", { directoryUrl: `${base}/dir`, eabConfigured: true });
    expect(r.ok).toBe(true);
  });

  it("classifies an unreachable directory instead of throwing", async () => {
    const r = await runConnectivityCheck("acme-ca", {
      directoryUrl: "http://127.0.0.1:1/dir",
      eabConfigured: false,
    });
    expect(r.ok).toBe(false);
    expect(r.code).toBe("unreachable");
  });

  it("flags an HTTP error status from the directory", async () => {
    respond = () => ({ status: 503, body: "backend down" });
    const r = await runConnectivityCheck("acme-ca", { directoryUrl: `${base}/dir`, eabConfigured: false });
    expect(r).toMatchObject({ ok: false, code: "protocol_error" });
    expect(r.message).toContain("503");
  });
});
