import { describe, it, expect, beforeEach, vi } from "vitest";
import type { CertificateAuthority } from "@repo/db";

/** In-memory stand-in for repos.certificateAuthority. */
const store = new Map<string, CertificateAuthority>();
let nextId = 0;

vi.mock("@repo/db", () => ({
  repos: {
    certificateAuthority: {
      findById: async (id: string) => {
        const row = store.get(id);
        return row && !row.deletedAt ? row : undefined;
      },
      list: async () => [...store.values()].filter((r) => !r.deletedAt),
      create: async (data: Partial<CertificateAuthority>) => {
        const row = {
          id: `ca_${++nextId}`,
          isDefault: false,
          lastVerifiedAt: null,
          lastVerifyError: null,
          deletedAt: null,
          createdAt: new Date(),
          updatedAt: new Date(),
          ...data,
        } as CertificateAuthority;
        store.set(row.id, row);
        return row;
      },
      update: async (id: string, data: Partial<CertificateAuthority>) => {
        const row = store.get(id);
        if (!row || row.deletedAt) return undefined;
        const next = { ...row, ...data, updatedAt: new Date() } as CertificateAuthority;
        store.set(id, next);
        return next;
      },
      setDefault: async (id: string) => {
        for (const r of store.values()) r.isDefault = false;
        const row = store.get(id);
        if (!row || row.deletedAt) return undefined;
        row.isDefault = true;
        return row;
      },
      softDelete: async (id: string) => {
        const row = store.get(id);
        if (row) row.deletedAt = new Date();
      },
    },
  },
}));

vi.mock("../../lib/credential-encryption", () => ({
  encryptSecretField: (plain: string | null | undefined) => (plain ? `enc1:${plain}` : null),
}));

let checkResult: { ok: boolean; code: string; message: string };
vi.mock("../../lib/connectivity", () => ({
  runConnectivityCheck: async () => checkResult,
}));
vi.mock("../../lib/connectivity-checks", () => ({}));

const svc = await import("./certificate-authority.service");

const HMAC = "c3VwZXItc2VjcmV0";

beforeEach(() => {
  store.clear();
  nextId = 0;
  checkResult = { ok: true, code: "reachable", message: "ok" };
});

describe("certificate-authority service", () => {
  it("no serialized view ever carries the HMAC — plaintext or ciphertext", async () => {
    const created = await svc.createCa({ name: "zerossl", kind: "zerossl", eabKid: "kid", eabHmacKey: HMAC });
    const listed = await svc.listCas();
    const tested = await svc.testCa(created.id);
    for (const payload of [created, listed, tested]) {
      const json = JSON.stringify(payload);
      expect(json).not.toContain(HMAC);
      expect(json).not.toContain("enc1:");
    }
    expect(created.hasEabKey).toBe(true);
  });

  it("presets materialize their directory at write time", async () => {
    const row = await svc.createCa({ name: "staging", kind: "letsencrypt-staging" });
    expect(row.directoryUrl).toBe("https://acme-staging-v02.api.letsencrypt.org/directory");
    // letsencrypt production stays NULL = certbot's own default.
    const le = await svc.createCa({ name: "le", kind: "letsencrypt" });
    expect(le.directoryUrl).toBeNull();
  });

  it("blank and masked HMAC keep the stored ciphertext; null clears it", async () => {
    const created = await svc.createCa({ name: "z", kind: "zerossl", eabKid: "kid", eabHmacKey: HMAC });

    await svc.updateCa(created.id, { eabHmacKey: "" });
    expect(store.get(created.id)!.eabHmacKeyEnc).toBe(`enc1:${HMAC}`);

    await svc.updateCa(created.id, { eabHmacKey: "••••••••" });
    expect(store.get(created.id)!.eabHmacKeyEnc).toBe(`enc1:${HMAC}`);

    await svc.updateCa(created.id, { eabHmacKey: "bmV3" });
    expect(store.get(created.id)!.eabHmacKeyEnc).toBe("enc1:bmV3");

    // Clearing must drop the kid too or validation refuses the half-pair.
    const cleared = await svc.updateCa(created.id, { eabHmacKey: null, eabKid: null });
    expect(cleared.hasEabKey).toBe(false);
  });

  it("rejects the config-time invalid states with the field named", async () => {
    await expect(svc.createCa({ name: "x", kind: "custom" })).rejects.toThrow(/directory URL/);
    await expect(svc.createCa({ name: "x", kind: "zerossl", eabKid: "kid-only" })).rejects.toThrow(/both/);
    await expect(
      svc.createCa({ name: "x", kind: "zerossl", eabKid: "kid", eabHmacKey: "not base64/+" }),
    ).rejects.toThrow(/base64url/);
    await expect(
      svc.createCa({ name: "x", kind: "custom", directoryUrl: "https://ca.test/dir", caBundle: "relative.pem" }),
    ).rejects.toThrow(/absolute/);
  });

  it("testCa stamps lastVerifiedAt on success and lastVerifyError on failure", async () => {
    const created = await svc.createCa({ name: "z", kind: "zerossl", eabKid: "kid", eabHmacKey: HMAC });

    const ok = await svc.testCa(created.id);
    expect(ok.ok).toBe(true);
    expect(ok.result.lastVerifiedAt).not.toBeNull();
    expect(ok.result.lastVerifyError).toBeNull();

    checkResult = { ok: false, code: "auth_failed", message: "CA requires EAB" };
    const bad = await svc.testCa(created.id);
    expect(bad.ok).toBe(false);
    expect(bad.result.lastVerifiedAt).toBeNull();
    expect(bad.result.lastVerifyError).toBe("CA requires EAB");
  });

  it("a config change invalidates the previous verification stamp", async () => {
    const created = await svc.createCa({ name: "z", kind: "zerossl", eabKid: "kid", eabHmacKey: HMAC });
    await svc.testCa(created.id);
    const updated = await svc.updateCa(created.id, { directoryUrl: "https://other.test/dir" });
    expect(updated.lastVerifiedAt).toBeNull();
  });
});
