import { describe, it, expect, afterEach } from "vitest";
import { resolveHmac } from "../../src/commands/certs";

/**
 * The EAB HMAC never rides argv — it arrives via env var or stdin, exclusively.
 * These are the paths a mistake would silently weaken (empty env var, both
 * sources at once), so each failure must be loud.
 */

afterEach(() => {
  delete process.env.TEST_EAB_HMAC;
});

describe("certs ca add — HMAC input contract", () => {
  it("reads the key from the named env var", async () => {
    process.env.TEST_EAB_HMAC = "  c2VjcmV0  ";
    await expect(resolveHmac({ eabHmacKeyEnv: "TEST_EAB_HMAC" })).resolves.toBe("c2VjcmV0");
  });

  it("an empty/unset env var is an error, not a silent no-EAB profile", async () => {
    process.env.TEST_EAB_HMAC = "   ";
    await expect(resolveHmac({ eabHmacKeyEnv: "TEST_EAB_HMAC" })).rejects.toThrow(/empty or unset/);
    await expect(resolveHmac({ eabHmacKeyEnv: "TEST_EAB_HMAC_MISSING" })).rejects.toThrow(/empty or unset/);
  });

  it("reads from stdin when asked", async () => {
    await expect(
      resolveHmac({ eabHmacKeyStdin: true }, async () => "c2VjcmV0\n".trim()),
    ).resolves.toBe("c2VjcmV0");
    await expect(resolveHmac({ eabHmacKeyStdin: true }, async () => "")).rejects.toThrow(/stdin/);
  });

  it("refuses both sources at once", async () => {
    await expect(
      resolveHmac({ eabHmacKeyEnv: "X", eabHmacKeyStdin: true }),
    ).rejects.toThrow(/not both/);
  });

  it("no source → undefined (a profile without EAB)", async () => {
    await expect(resolveHmac({})).resolves.toBeUndefined();
  });
});
