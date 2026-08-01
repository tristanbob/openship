import { describe, it, expect, beforeEach, vi } from "vitest";
import type { CertificateAuthority } from "@repo/db";

/** Swappable per test: what repos.certificateAuthority returns. */
let findDefaultImpl: () => Promise<CertificateAuthority | undefined>;
let findByIdImpl: (id: string) => Promise<CertificateAuthority | undefined>;

vi.mock("@repo/db", () => ({
  repos: {
    certificateAuthority: {
      findDefault: () => findDefaultImpl(),
      findById: (id: string) => findByIdImpl(id),
    },
  },
}));

vi.mock("../config/env", () => ({
  env: {
    OPENSHIP_ACME_EMAIL: "env-ops@example.test",
    OPENSHIP_ACME_DIRECTORY_URL: "https://env.acme.example.test/directory",
    OPENSHIP_ACME_EAB_KID: "env-kid",
    OPENSHIP_ACME_EAB_HMAC_KEY: "env-hmac",
    OPENSHIP_ACME_KEY_TYPE: "ec256",
    OPENSHIP_ACME_CA_BUNDLE: "/env/root.pem",
    OPENSHIP_ACME_TOS_AGREED: true,
  },
}));

vi.mock("./credential-encryption", () => ({
  decryptSecretField: (stored: string | null | undefined) =>
    stored == null ? undefined : `plain(${stored})`,
}));

const mod = await import("./acme-config");

const PROFILE: CertificateAuthority = {
  id: "ca_1",
  name: "zerossl",
  kind: "zerossl",
  directoryUrl: "https://acme.zerossl.com/v2/DV90",
  acmeEmail: "profile-ops@example.test",
  keyType: "ec384",
  caBundle: null,
  tosAgreed: true,
  eabKid: "profile-kid",
  eabHmacKeyEnc: "enc1:sealed",
  lastVerifiedAt: null,
  lastVerifyError: null,
  isDefault: true,
  deletedAt: null,
  createdAt: new Date(),
  updatedAt: new Date(),
};

beforeEach(() => {
  findDefaultImpl = async () => undefined;
  findByIdImpl = async () => undefined;
});

describe("resolveAcmeProviderOptions — source order", () => {
  it("the DB default profile wins over the env layer entirely", async () => {
    findDefaultImpl = async () => PROFILE;
    const opts = await mod.resolveAcmeProviderOptions();
    expect(opts.acmeDirectoryUrl).toBe("https://acme.zerossl.com/v2/DV90");
    expect(opts.acmeEabKid).toBe("profile-kid");
    expect(opts.acmeEabHmacKey).toBe("plain(enc1:sealed)");
    expect(opts.acmeKeyType).toBe("ec384");
    // Profile NULL means "certbot default", NOT "fall through to env": the env
    // CA bundle must not leak into a profile that doesn't declare one.
    expect(opts.acmeCaBundle).toBeUndefined();
  });

  it("no profile → the env layer, unchanged pre-table behavior", async () => {
    const opts = await mod.resolveAcmeProviderOptions();
    expect(opts.acmeDirectoryUrl).toBe("https://env.acme.example.test/directory");
    expect(opts.acmeEabKid).toBe("env-kid");
    expect(opts.acmeEabHmacKey).toBe("env-hmac");
    expect(opts.acmeCaBundle).toBe("/env/root.pem");
  });

  it("a DB failure falls back to env instead of failing the deploy", async () => {
    findDefaultImpl = async () => {
      throw new Error("relation does not exist");
    };
    const opts = await mod.resolveAcmeProviderOptions();
    expect(opts.acmeDirectoryUrl).toBe("https://env.acme.example.test/directory");
  });

  it("profile email is the one field that falls back to OPENSHIP_ACME_EMAIL", async () => {
    findDefaultImpl = async () => ({ ...PROFILE, acmeEmail: null });
    const opts = await mod.resolveAcmeProviderOptions();
    expect(opts.acmeEmail).toBe("env-ops@example.test");
  });
});

describe("resolveDomainAcmeOptions — the full per-domain chain", () => {
  const PINNED: CertificateAuthority = {
    ...PROFILE,
    id: "ca_pinned",
    name: "internal",
    directoryUrl: "https://ca.internal.test/acme/directory",
    isDefault: false,
  };

  it("a domain-pinned profile beats the instance default", async () => {
    findDefaultImpl = async () => PROFILE;
    findByIdImpl = async (id) => (id === "ca_pinned" ? PINNED : undefined);
    const opts = await mod.resolveDomainAcmeOptions("ca_pinned");
    expect(opts.acmeDirectoryUrl).toBe("https://ca.internal.test/acme/directory");
  });

  it("no pin → the instance default profile", async () => {
    findDefaultImpl = async () => PROFILE;
    const opts = await mod.resolveDomainAcmeOptions(null);
    expect(opts.acmeDirectoryUrl).toBe("https://acme.zerossl.com/v2/DV90");
  });

  it("a dangling pin degrades to inherit — never blocks issuance", async () => {
    findDefaultImpl = async () => PROFILE;
    findByIdImpl = async () => undefined;
    const opts = await mod.resolveDomainAcmeOptions("ca_deleted");
    expect(opts.acmeDirectoryUrl).toBe("https://acme.zerossl.com/v2/DV90");
  });

  it("no pin, no default → the env layer", async () => {
    const opts = await mod.resolveDomainAcmeOptions(undefined);
    expect(opts.acmeDirectoryUrl).toBe("https://env.acme.example.test/directory");
  });
});
