import { describe, it, expect } from "vitest";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { PGlite } from "@electric-sql/pglite";
import { drizzle } from "drizzle-orm/pglite";
import { migrate } from "drizzle-orm/pglite/migrator";
import * as schema from "../schema";
import { createCertificateAuthorityRepo } from "./certificate-authority.repo";

const MIGRATIONS_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "../../drizzle");

/**
 * Real (in-memory PGlite) integration test — runs the actual migrations, so it
 * also proves the hand-written 0082_certificate_authority.sql matches the
 * drizzle schema (the two are maintained by hand and CAN drift).
 */
async function freshRepo() {
  const client = new PGlite("memory://");
  const db = drizzle(client, { schema });
  await migrate(db, { migrationsFolder: MIGRATIONS_DIR });
  return createCertificateAuthorityRepo(db);
}

const ZEROSSL = {
  name: "zerossl",
  kind: "zerossl",
  directoryUrl: "https://acme.zerossl.com/v2/DV90",
  eabKid: "kid-1",
  eabHmacKeyEnc: "enc1:sealed",
} as const;

describe("certificate-authority repo", () => {
  it("setDefault makes exactly ONE profile the default, whoever held it before", async () => {
    const repo = await freshRepo();
    const a = await repo.create({ ...ZEROSSL, isDefault: true });
    const b = await repo.create({ ...ZEROSSL, name: "internal", kind: "custom" });

    await repo.setDefault(b.id);

    expect((await repo.findDefault())?.id).toBe(b.id);
    expect((await repo.findById(a.id))?.isDefault).toBe(false);
  });

  it("soft delete frees the name for reuse and never resurrects the old row", async () => {
    const repo = await freshRepo();
    const first = await repo.create(ZEROSSL);
    await repo.softDelete(first.id);

    // The partial unique index only covers live rows — same name re-creates.
    const second = await repo.create(ZEROSSL);
    expect(second.id).not.toBe(first.id);

    expect(await repo.findById(first.id)).toBeUndefined();
    expect((await repo.findByName("zerossl"))?.id).toBe(second.id);
    expect((await repo.list()).map((r) => r.id)).toEqual([second.id]);
  });

  it("deleting the default clears it — resolution must fall back, not follow a ghost", async () => {
    const repo = await freshRepo();
    const row = await repo.create({ ...ZEROSSL, isDefault: true });
    await repo.softDelete(row.id);
    expect(await repo.findDefault()).toBeUndefined();
  });

  it("a live duplicate name is rejected by the partial unique index", async () => {
    const repo = await freshRepo();
    await repo.create(ZEROSSL);
    await expect(repo.create(ZEROSSL)).rejects.toThrow();
  });
});
