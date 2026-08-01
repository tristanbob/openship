import { and, eq, isNull } from "drizzle-orm";
import { generateId } from "@repo/core";
import type { Database } from "../client";
import { certificateAuthority } from "../schema";

// ─── Types ───────────────────────────────────────────────────────────────────

export type CertificateAuthority = typeof certificateAuthority.$inferSelect;
export type NewCertificateAuthority = typeof certificateAuthority.$inferInsert;

// ─── Repository ──────────────────────────────────────────────────────────────

/** Live (non-soft-deleted) rows only — every read goes through this filter. */
const live = () => isNull(certificateAuthority.deletedAt);

export function createCertificateAuthorityRepo(db: Database) {
  return {
    async findById(id: string): Promise<CertificateAuthority | undefined> {
      return db.query.certificateAuthority.findFirst({
        where: and(eq(certificateAuthority.id, id), live()),
      });
    },

    async findByName(name: string): Promise<CertificateAuthority | undefined> {
      return db.query.certificateAuthority.findFirst({
        where: and(eq(certificateAuthority.name, name), live()),
      });
    },

    /** The profile issuance uses when nothing more specific pins one. */
    async findDefault(): Promise<CertificateAuthority | undefined> {
      return db.query.certificateAuthority.findFirst({
        where: and(eq(certificateAuthority.isDefault, true), live()),
      });
    },

    async list(): Promise<CertificateAuthority[]> {
      return db.query.certificateAuthority.findMany({
        where: live(),
        orderBy: (t, { asc }) => [asc(t.createdAt)],
      });
    },

    async create(
      data: Omit<NewCertificateAuthority, "id" | "createdAt" | "updatedAt">,
    ): Promise<CertificateAuthority> {
      const [row] = await db
        .insert(certificateAuthority)
        .values({ id: generateId("ca"), ...data })
        .returning();
      return row;
    },

    async update(
      id: string,
      data: Partial<Omit<NewCertificateAuthority, "id" | "createdAt">>,
    ): Promise<CertificateAuthority | undefined> {
      const [row] = await db
        .update(certificateAuthority)
        .set({ ...data, updatedAt: new Date() })
        .where(and(eq(certificateAuthority.id, id), live()))
        .returning();
      return row;
    },

    /**
     * Make `id` THE default, clearing any other, in one transaction — two
     * concurrent calls settle on exactly one default either way.
     */
    async setDefault(id: string): Promise<CertificateAuthority | undefined> {
      return db.transaction(async (tx) => {
        await tx
          .update(certificateAuthority)
          .set({ isDefault: false, updatedAt: new Date() })
          .where(eq(certificateAuthority.isDefault, true));
        const [row] = await tx
          .update(certificateAuthority)
          .set({ isDefault: true, updatedAt: new Date() })
          .where(and(eq(certificateAuthority.id, id), live()))
          .returning();
        return row;
      });
    },

    /**
     * Soft delete (frees the name via the partial unique index). Also clears
     * isDefault so resolution falls back to env/Let's Encrypt rather than a
     * ghost default.
     */
    async softDelete(id: string): Promise<void> {
      await db
        .update(certificateAuthority)
        .set({ deletedAt: new Date(), isDefault: false, updatedAt: new Date() })
        .where(and(eq(certificateAuthority.id, id), live()));
    },
  };
}
