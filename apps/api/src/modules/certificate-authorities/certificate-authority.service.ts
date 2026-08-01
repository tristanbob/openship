/**
 * ACME certificate-authority profiles — instance-scoped CRUD + test (#256).
 *
 * Secret contract mirrors the instance SMTP settings (setup.controller.ts):
 * the EAB HMAC is sealed with the enc1 envelope (lib/credential-encryption),
 * serialized rows carry only a `hasEabKey` boolean, and a blank/masked value
 * on update keeps the stored ciphertext. Test runs the `acme-ca` connectivity
 * check and stamps lastVerifiedAt / lastVerifyError on the row, exactly like
 * backup-destination preflight — so the dashboard can show verified/broken
 * state without re-probing.
 *
 * No SSRF guard on the directory URL, deliberately: private/internal ACME
 * servers (step-ca on a LAN) are a headline use case, and every write route
 * is owner-gated — the operator already controls this box.
 */

import { repos, type CertificateAuthority } from "@repo/db";
import { isMaskedValue } from "@repo/core";
import { encryptSecretField } from "../../lib/credential-encryption";
import { runConnectivityCheck } from "../../lib/connectivity";
import "../../lib/connectivity-checks"; // registers acme-ca

export type CaKind = "letsencrypt" | "letsencrypt-staging" | "zerossl" | "google" | "custom";

/** Preset directories, materialized into `directoryUrl` at write time so
 *  resolution (lib/acme-config.ts) never needs this table. NULL = certbot's
 *  Let's Encrypt production default. */
const PRESET_DIRECTORY: Record<CaKind, string | null> = {
  letsencrypt: null,
  "letsencrypt-staging": "https://acme-staging-v02.api.letsencrypt.org/directory",
  zerossl: "https://acme.zerossl.com/v2/DV90",
  google: "https://dv.acme-v02.api.pki.goog/directory",
  custom: null,
};

const KEY_TYPES = ["ec256", "ec384", "rsa2048", "rsa4096"] as const;

export interface CaProfileInput {
  name?: string;
  kind?: CaKind;
  directoryUrl?: string | null;
  acmeEmail?: string | null;
  keyType?: string | null;
  caBundle?: string | null;
  tosAgreed?: boolean;
  eabKid?: string | null;
  /** Plaintext HMAC. Blank/masked = keep stored; null = clear (with the kid). */
  eabHmacKey?: string | null;
  isDefault?: boolean;
}

/** The wire shape — NEVER carries the HMAC (plaintext or ciphertext). */
export interface CaProfileView {
  id: string;
  name: string;
  kind: string;
  directoryUrl: string | null;
  acmeEmail: string | null;
  keyType: string | null;
  caBundle: string | null;
  tosAgreed: boolean;
  eabKid: string | null;
  hasEabKey: boolean;
  isDefault: boolean;
  lastVerifiedAt: string | null;
  lastVerifyError: string | null;
  createdAt: string;
}

export function serializeCa(row: CertificateAuthority): CaProfileView {
  return {
    id: row.id,
    name: row.name,
    kind: row.kind,
    directoryUrl: row.directoryUrl,
    acmeEmail: row.acmeEmail,
    keyType: row.keyType,
    caBundle: row.caBundle,
    tosAgreed: row.tosAgreed,
    eabKid: row.eabKid,
    hasEabKey: !!row.eabHmacKeyEnc,
    isDefault: row.isDefault,
    lastVerifiedAt: row.lastVerifiedAt?.toISOString() ?? null,
    lastVerifyError: row.lastVerifyError,
    createdAt: row.createdAt.toISOString(),
  };
}

/** Same rules the NginxProvider constructor re-checks (adapters must not trust
 *  the API layer) — enforced HERE first so the operator gets a 400 with the
 *  field named, not a failed deploy later. */
function validate(input: {
  directoryUrl: string | null;
  eabKid: string | null;
  hasHmac: boolean;
  eabHmacKey?: string | null;
  keyType: string | null;
  caBundle: string | null;
  kind: CaKind;
}): void {
  if (input.kind === "custom" && !input.directoryUrl) {
    throw new Error("A custom CA requires a directory URL");
  }
  if (input.directoryUrl) {
    let url: URL;
    try {
      url = new URL(input.directoryUrl);
    } catch {
      throw new Error("Directory must be a valid http(s) URL");
    }
    if (url.protocol !== "https:" && url.protocol !== "http:") {
      throw new Error("Directory must use http or https");
    }
  }
  if (!!input.eabKid !== input.hasHmac) {
    throw new Error("EAB requires both a key identifier and an HMAC key");
  }
  if (input.eabKid && (!/^[\x20-\x7E]+$/.test(input.eabKid) || input.eabKid.length > 512)) {
    throw new Error("EAB key identifier must be printable ASCII (maximum 512 characters)");
  }
  if (input.eabHmacKey && !/^[A-Za-z0-9_-]+={0,2}$/.test(input.eabHmacKey)) {
    throw new Error("EAB HMAC key must be base64url encoded");
  }
  if (input.keyType && !KEY_TYPES.includes(input.keyType as (typeof KEY_TYPES)[number])) {
    throw new Error(`Key type must be one of: ${KEY_TYPES.join(", ")}`);
  }
  if (input.caBundle && !input.caBundle.startsWith("/")) {
    throw new Error("CA bundle must be an absolute path in the certbot environment");
  }
}

const trimmed = (v: string | null | undefined): string | null => {
  const t = v?.trim();
  return t ? t : null;
};

export async function listCas(): Promise<CaProfileView[]> {
  return (await repos.certificateAuthority.list()).map(serializeCa);
}

export async function createCa(input: CaProfileInput): Promise<CaProfileView> {
  const name = trimmed(input.name);
  if (!name) throw new Error("A profile name is required");
  const kind = (input.kind ?? "custom") as CaKind;
  if (!(kind in PRESET_DIRECTORY)) throw new Error(`Unknown CA kind "${kind}"`);

  const directoryUrl = trimmed(input.directoryUrl) ?? PRESET_DIRECTORY[kind];
  const eabKid = trimmed(input.eabKid);
  const eabHmacKey = trimmed(input.eabHmacKey);
  const keyType = trimmed(input.keyType);
  const caBundle = trimmed(input.caBundle);
  validate({ directoryUrl, eabKid, hasHmac: !!eabHmacKey, eabHmacKey, keyType, caBundle, kind });

  const row = await repos.certificateAuthority.create({
    name,
    kind,
    directoryUrl,
    acmeEmail: trimmed(input.acmeEmail),
    keyType,
    caBundle,
    tosAgreed: input.tosAgreed ?? true,
    eabKid,
    eabHmacKeyEnc: encryptSecretField(eabHmacKey),
  });
  const finalRow = input.isDefault
    ? ((await repos.certificateAuthority.setDefault(row.id)) ?? row)
    : row;
  return serializeCa(finalRow);
}

export async function updateCa(id: string, input: CaProfileInput): Promise<CaProfileView> {
  const existing = await repos.certificateAuthority.findById(id);
  if (!existing) throw new Error("Certificate authority not found");

  const kind = (input.kind ?? existing.kind) as CaKind;
  if (!(kind in PRESET_DIRECTORY)) throw new Error(`Unknown CA kind "${kind}"`);
  const directoryUrl =
    input.directoryUrl !== undefined
      ? (trimmed(input.directoryUrl) ?? PRESET_DIRECTORY[kind])
      : existing.directoryUrl;
  const eabKid = input.eabKid !== undefined ? trimmed(input.eabKid) : existing.eabKid;

  // Blank or masked HMAC = keep the stored ciphertext (the SMTP contract);
  // explicit null clears it; a new value replaces it.
  let eabHmacKeyEnc = existing.eabHmacKeyEnc;
  let newPlain: string | null | undefined;
  if (input.eabHmacKey === null) {
    eabHmacKeyEnc = null;
  } else if (typeof input.eabHmacKey === "string" && input.eabHmacKey.trim() && !isMaskedValue(input.eabHmacKey)) {
    newPlain = input.eabHmacKey.trim();
    eabHmacKeyEnc = encryptSecretField(newPlain);
  }

  const keyType = input.keyType !== undefined ? trimmed(input.keyType) : existing.keyType;
  const caBundle = input.caBundle !== undefined ? trimmed(input.caBundle) : existing.caBundle;
  validate({ directoryUrl, eabKid, hasHmac: !!eabHmacKeyEnc, eabHmacKey: newPlain, keyType, caBundle, kind });

  const row = await repos.certificateAuthority.update(id, {
    name: input.name !== undefined ? (trimmed(input.name) ?? existing.name) : existing.name,
    kind,
    directoryUrl,
    acmeEmail: input.acmeEmail !== undefined ? trimmed(input.acmeEmail) : existing.acmeEmail,
    keyType,
    caBundle,
    tosAgreed: input.tosAgreed ?? existing.tosAgreed,
    eabKid,
    eabHmacKeyEnc,
    // Any config change invalidates the last verification result.
    lastVerifiedAt: null,
    lastVerifyError: null,
  });
  if (!row) throw new Error("Certificate authority not found");
  if (input.isDefault === true && !row.isDefault) {
    return serializeCa((await repos.certificateAuthority.setDefault(id)) ?? row);
  }
  return serializeCa(row);
}

export async function setDefaultCa(id: string): Promise<CaProfileView> {
  const row = await repos.certificateAuthority.setDefault(id);
  if (!row) throw new Error("Certificate authority not found");
  return serializeCa(row);
}

export async function deleteCa(id: string): Promise<void> {
  const existing = await repos.certificateAuthority.findById(id);
  if (!existing) throw new Error("Certificate authority not found");
  await repos.certificateAuthority.softDelete(id);
}

/** Run the acme-ca connectivity check and stamp the outcome on the row. */
export async function testCa(id: string): Promise<{ result: CaProfileView; ok: boolean; code: string; message: string }> {
  const row = await repos.certificateAuthority.findById(id);
  if (!row) throw new Error("Certificate authority not found");

  const check = await runConnectivityCheck("acme-ca", {
    directoryUrl: row.directoryUrl,
    caBundle: row.caBundle,
    eabConfigured: !!row.eabKid && !!row.eabHmacKeyEnc,
  });

  const stamped = await repos.certificateAuthority.update(id, {
    lastVerifiedAt: check.ok ? new Date() : null,
    lastVerifyError: check.ok ? null : check.message,
  });
  return {
    result: serializeCa(stamped ?? row),
    ok: check.ok,
    code: check.code,
    message: check.message,
  };
}
