/**
 * Built-in connectivity checks. Self-register on import (like the backup
 * destination adapters), so any module that runs a check imports this file for
 * its side effect. Kept separate from the pure registry (`./connectivity`) so
 * the registry stays transport/env-free and unit-testable.
 *
 * We unify the CONTRACT, not the transport: each check uses whatever connection
 * fits — the cached `sshManager`/`SshExecutor` for management, the backup
 * adapter's own client for destinations (keeping heavy transfers off the shared
 * connection — the #34 isolation).
 */
import {
  createExecutor,
  isSshAuthError,
  resolveDestination,
  type BackupDestinationRow,
  type CommandExecutor,
  type SshConfig,
} from "@repo/adapters";
import { readFile } from "node:fs/promises";
import { request as httpsRequest } from "node:https";
import { request as httpRequest } from "node:http";
import { classifyConnectivityError, connFail, connOk, type ConnectivityResult } from "@repo/core";
import { registerConnectivityCheck } from "./connectivity";
import { sshManager } from "./ssh-manager";

const ECHO_TIMEOUT_MS = 15_000;

/** Shared SSH liveness proof: run a trivial echo and time the round-trip. */
async function sshEcho(executor: CommandExecutor): Promise<ConnectivityResult> {
  const startedAt = Date.now();
  const out = await executor.exec("echo ok", { timeout: ECHO_TIMEOUT_MS });
  if (out.trim() !== "ok") return connFail("protocol_error", "Unexpected response from host");
  return connOk(Date.now() - startedAt);
}

/** Turn a thrown SSH error into a result, preferring the precise auth signal. */
function sshError(err: unknown): ConnectivityResult {
  const { code, message } = classifyConnectivityError(err, isSshAuthError(err) ? "auth_failed" : undefined);
  return connFail(code, message);
}

/** Ad-hoc SSH from raw credentials (server add/edit + onboarding wizard). */
registerConnectivityCheck<SshConfig>("ssh", async (config) => {
  const executor = createExecutor(config);
  try {
    return await sshEcho(executor);
  } catch (err) {
    return sshError(err);
  } finally {
    await executor.dispose();
  }
});

/** A saved server by id — cheap TCP probe first, then an authenticated echo. */
registerConnectivityCheck<string>("ssh-server", async (serverId) => {
  const reachable = await sshManager.probeReachable(serverId).catch(() => false);
  if (!reachable) return connFail("unreachable", "Host is not reachable");
  try {
    return await sshManager.withExecutor(serverId, (e) => sshEcho(e));
  } catch (err) {
    return sshError(err);
  }
});

/** A backup destination (pre-resolved adapter row) — delegates to the adapter's
 *  own preflight (writes + deletes a probe), staying on its own connection. */
registerConnectivityCheck<BackupDestinationRow>("backup-destination", async (row) => {
  const startedAt = Date.now();
  const result = await resolveDestination(row).preflight();
  if (result.ok) return connOk(Date.now() - startedAt);
  const { code, message } = classifyConnectivityError(result.reason);
  return connFail(code, message);
});

// ─── ACME certificate authority ──────────────────────────────────────────────

export interface AcmeCaCheckInput {
  /** NULL/undefined = certbot's Let's Encrypt production default. */
  directoryUrl?: string | null;
  /** Trust-bundle path for private CAs — as seen by the CERTBOT environment,
   *  which may not be this API process; unreadable here is a soft condition. */
  caBundle?: string | null;
  /** Whether the profile carries EAB credentials (kid + stored HMAC). */
  eabConfigured: boolean;
}

const ACME_LE_PRODUCTION = "https://acme-v02.api.letsencrypt.org/directory";
const ACME_PROBE_TIMEOUT_MS = 10_000;

/**
 * RFC 8555 §6.1 REQUIRES an ACME client to send a User-Agent naming the ACME
 * software and the underlying HTTP client. This is not decorative: Pebble
 * rejects a request without one outright — `400 malformed: All requests MUST
 * include a User-Agent header` — so a probe missing it reports "HTTP 400"
 * against a real CA and the whole config-time check is useless.
 */
const ACME_USER_AGENT = `openship-acme-check/1 node/${process.versions.node}`;

/** Minimal GET with optional custom trust root; rejects on network/TLS errors. */
function fetchJson(
  url: URL,
  ca: string | undefined,
): Promise<{ status: number; body: string }> {
  const req = url.protocol === "https:" ? httpsRequest : httpRequest;
  return new Promise((resolve, reject) => {
    const r = req(
      url,
      {
        method: "GET",
        timeout: ACME_PROBE_TIMEOUT_MS,
        headers: { "user-agent": ACME_USER_AGENT, accept: "application/json" },
        ...(ca ? { ca } : {}),
      },
      (res) => {
        let body = "";
        res.setEncoding("utf8");
        res.on("data", (chunk) => { body += chunk; });
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body }));
      },
    );
    r.on("timeout", () => r.destroy(new Error(`Timed out after ${ACME_PROBE_TIMEOUT_MS}ms`)));
    r.on("error", reject);
    r.end();
  });
}

/**
 * An ACME CA profile — fetch the directory document and validate the contract
 * a certbot run will depend on: reachability (with the private trust root when
 * readable), the RFC 8555 endpoint set, and the CA's EAB requirement vs the
 * profile's credentials. Catches the config-time failures (#256: wrong URL,
 * missing EAB, untrusted private root) WITHOUT creating an ACME account — a
 * full EAB-signed registration probe is a possible follow-up, so a
 * cryptographically wrong HMAC still surfaces only at first issuance.
 */
registerConnectivityCheck<AcmeCaCheckInput>("acme-ca", async (input) => {
  const startedAt = Date.now();
  const url = new URL(input.directoryUrl || ACME_LE_PRODUCTION);

  // The bundle path belongs to the certbot environment (often the edge
  // container). Readable here → use it; not → probe on default trust and say so.
  let ca: string | undefined;
  let caNote = "";
  if (input.caBundle) {
    ca = await readFile(input.caBundle, "utf8").catch(() => undefined);
    if (!ca) caNote = ` (CA bundle ${input.caBundle} not readable from the API; probed with default trust)`;
  }

  let status: number;
  let body: string;
  try {
    ({ status, body } = await fetchJson(url, ca));
  } catch (err) {
    const { code, message } = classifyConnectivityError(err);
    return connFail(code, `${message}${caNote}`);
  }
  if (status >= 400) {
    return connFail("protocol_error", `Directory returned HTTP ${status}${caNote}`);
  }

  let directory: { newAccount?: unknown; newNonce?: unknown; newOrder?: unknown; meta?: { externalAccountRequired?: boolean } };
  try {
    directory = JSON.parse(body);
  } catch {
    return connFail("protocol_error", `Response is not JSON — is ${url} really an ACME directory?${caNote}`);
  }
  const missing = (["newAccount", "newNonce", "newOrder"] as const).filter((k) => typeof directory[k] !== "string");
  if (missing.length > 0) {
    return connFail("protocol_error", `Not an ACME directory: missing ${missing.join(", ")}${caNote}`);
  }

  if (directory.meta?.externalAccountRequired && !input.eabConfigured) {
    return connFail("auth_failed", "This CA requires External Account Binding — add EAB credentials to the profile");
  }
  if (input.eabConfigured && directory.meta?.externalAccountRequired === false) {
    // Not fatal for issuance, but almost always a mispasted directory URL.
    return connOk(Date.now() - startedAt, `Directory reachable; note: this CA does not require EAB${caNote}`);
  }

  return connOk(Date.now() - startedAt, `ACME directory reachable${caNote}`);
});
