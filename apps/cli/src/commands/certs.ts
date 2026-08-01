/**
 * `openship certs` — ACME certificate-authority profiles (#256).
 *
 * Grounded in apps/api/src/modules/system/system.routes.ts (mounted at
 * /api/system in app.ts). Each subcommand hits the real route:
 *   ca list         GET    /system/certificate-authorities
 *   ca add          POST   /system/certificate-authorities
 *   ca set-default  POST   /system/certificate-authorities/:id/set-default
 *   ca test         POST   /system/certificate-authorities/:id/test
 *   ca remove       DELETE /system/certificate-authorities/:id
 *
 * The EAB HMAC key is a long-lived issuance credential and is NEVER accepted
 * as a bare argument (argv leaks into shell history and process listings) —
 * it is read from an env var (--eab-hmac-key-env) or stdin
 * (--eab-hmac-key-stdin), mirroring the issue's security contract.
 */

import { Command } from "commander";
import chalk from "chalk";
import ora, { type Ora } from "ora";
import { apiRequest, ApiError } from "../lib/api-client";
import { printJson, printTable, isJsonMode, ok, err, info } from "../lib/output";

interface CaRow {
  id: string;
  name: string;
  kind: string;
  directoryUrl: string | null;
  eabKid: string | null;
  hasEabKey: boolean;
  isDefault: boolean;
  lastVerifiedAt: string | null;
  lastVerifyError: string | null;
}

const BASE = "/system/certificate-authorities";

function spin(text: string): Ora | null {
  return isJsonMode() ? null : ora(text).start();
}

function fail(e: unknown): never {
  if (e instanceof ApiError) {
    err(`  ${e.message}${e.status ? chalk.dim(` (${e.status})`) : ""}`);
  } else {
    err(`  ${e instanceof Error ? e.message : String(e)}`);
  }
  process.exit(1);
}

function caRow(r: CaRow): Record<string, unknown> {
  return {
    id: r.id,
    name: r.name,
    kind: r.kind,
    directory: r.directoryUrl ?? "(Let's Encrypt default)",
    eab: r.hasEabKey ? "yes" : "",
    default: r.isDefault ? "yes" : "",
    verified: r.lastVerifiedAt ? "yes" : r.lastVerifyError ? "FAILED" : "",
  };
}

/** Resolve a profile by name or id — names are what operators type. */
async function resolveCa(nameOrId: string): Promise<CaRow> {
  const res = await apiRequest<{ data: CaRow[] }>(BASE);
  const row = res.data.find((r) => r.id === nameOrId || r.name === nameOrId);
  if (!row) throw new ApiError(`No certificate authority named "${nameOrId}"`, 404, null);
  return row;
}

async function readStdin(): Promise<string> {
  let data = "";
  for await (const chunk of process.stdin) data += chunk;
  return data.trim();
}

/** The HMAC sources, mutually exclusive, never bare argv. Exported for tests;
 *  `readInput` is injectable so tests don't have to drive process.stdin. */
export async function resolveHmac(
  opts: { eabHmacKeyEnv?: string; eabHmacKeyStdin?: boolean },
  readInput: () => Promise<string> = readStdin,
): Promise<string | undefined> {
  if (opts.eabHmacKeyEnv && opts.eabHmacKeyStdin) {
    throw new Error("Use either --eab-hmac-key-env or --eab-hmac-key-stdin, not both");
  }
  if (opts.eabHmacKeyEnv) {
    const value = process.env[opts.eabHmacKeyEnv]?.trim();
    if (!value) throw new Error(`Environment variable ${opts.eabHmacKeyEnv} is empty or unset`);
    return value;
  }
  if (opts.eabHmacKeyStdin) {
    const value = await readInput();
    if (!value) throw new Error("No HMAC key received on stdin");
    return value;
  }
  return undefined;
}

// ─── Subcommands ─────────────────────────────────────────────────────────────

const listCmd = new Command("list")
  .description("List certificate-authority profiles")
  .action(async () => {
    try {
      const res = await apiRequest<{ data: CaRow[] }>(BASE);
      if (isJsonMode()) return printJson(res.data);
      if (res.data.length === 0) {
        info("  No CA profiles — issuance uses OPENSHIP_ACME_* env vars or Let's Encrypt.");
        return;
      }
      printTable(res.data.map(caRow), ["id", "name", "kind", "directory", "eab", "default", "verified"]);
    } catch (e) {
      fail(e);
    }
  });

const addCmd = new Command("add")
  .description("Add a certificate-authority profile")
  .argument("<name>", "Profile name (e.g. zerossl)")
  .option("--kind <kind>", "letsencrypt | letsencrypt-staging | zerossl | google | custom", "custom")
  .option("--directory <url>", "ACME directory URL (required for --kind custom)")
  .option("--email <email>", "ACME account contact email")
  .option("--eab-kid <kid>", "EAB key identifier (public half — safe in argv)")
  .option("--eab-hmac-key-env <var>", "Name of an environment variable holding the EAB HMAC key")
  .option("--eab-hmac-key-stdin", "Read the EAB HMAC key from stdin", false)
  .option("--key-type <type>", "ec256 | ec384 | rsa2048 | rsa4096")
  .option("--ca-bundle <path>", "Trust-bundle path in the certbot environment (private CAs)")
  .option("--default", "Make this the instance default CA", false)
  .action(async (name: string, opts) => {
    const sp = spin(`Adding CA profile ${name}…`);
    try {
      const eabHmacKey = await resolveHmac(opts);
      const res = await apiRequest<{ data: CaRow }>(BASE, {
        method: "POST",
        body: JSON.stringify({
          name,
          kind: opts.kind,
          directoryUrl: opts.directory,
          acmeEmail: opts.email,
          eabKid: opts.eabKid,
          eabHmacKey,
          keyType: opts.keyType,
          caBundle: opts.caBundle,
          isDefault: !!opts.default,
        }),
      });
      sp?.succeed(`Added ${res.data.name}${res.data.isDefault ? " (default)" : ""}`);
      if (isJsonMode()) printJson(res.data);
      else info(`  Run \`openship certs ca test ${res.data.name}\` to verify it before issuance.`);
    } catch (e) {
      sp?.fail("Add failed");
      fail(e);
    }
  });

const setDefaultCmd = new Command("set-default")
  .description("Make a profile the instance default CA")
  .argument("<name>", "Profile name or id")
  .action(async (name: string) => {
    try {
      const row = await resolveCa(name);
      const res = await apiRequest<{ data: CaRow }>(`${BASE}/${row.id}/set-default`, { method: "POST" });
      if (isJsonMode()) return printJson(res.data);
      ok(`  ${res.data.name} is now the default CA`);
    } catch (e) {
      fail(e);
    }
  });

const testCmd = new Command("test")
  .description("Validate a profile against its ACME directory (issues nothing)")
  .argument("<name>", "Profile name or id")
  .action(async (name: string) => {
    const sp = spin(`Testing ${name}…`);
    try {
      const row = await resolveCa(name);
      const res = await apiRequest<{ data: { ok: boolean; code: string; message: string } }>(
        `${BASE}/${row.id}/test`,
        { method: "POST" },
      );
      if (res.data.ok) {
        sp?.succeed(res.data.message);
      } else {
        sp?.fail(`${res.data.message} ${chalk.dim(`(${res.data.code})`)}`);
      }
      if (isJsonMode()) printJson(res.data);
      if (!res.data.ok) process.exit(1);
    } catch (e) {
      sp?.fail("Test failed");
      fail(e);
    }
  });

const removeCmd = new Command("remove")
  .description("Remove a certificate-authority profile")
  .argument("<name>", "Profile name or id")
  .action(async (name: string) => {
    try {
      const row = await resolveCa(name);
      await apiRequest(`${BASE}/${row.id}`, { method: "DELETE" });
      if (isJsonMode()) return printJson({ ok: true, id: row.id });
      ok(`  Removed ${row.name}`);
    } catch (e) {
      fail(e);
    }
  });

const caCmd = new Command("ca")
  .description("Manage ACME certificate authorities")
  .addCommand(listCmd)
  .addCommand(addCmd)
  .addCommand(setDefaultCmd)
  .addCommand(testCmd)
  .addCommand(removeCmd);

export const certsCommand = new Command("certs")
  .description("Certificate issuance configuration")
  .addCommand(caCmd);
