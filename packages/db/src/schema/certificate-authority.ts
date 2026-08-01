import {
  pgTable,
  text,
  timestamp,
  boolean,
  uniqueIndex,
} from "drizzle-orm/pg-core";
import { sql } from "drizzle-orm";

// ─── certificate_authority ───────────────────────────────────────────────────

/**
 * A named ACME certificate-authority profile (issue #256): directory URL, EAB
 * credentials, key type and trust bundle, selectable as the instance default
 * and (later) per domain. Shape mirrors `backup_destination` — public
 * connection identity vs `enc1:`-encrypted credential columns, `isDefault`,
 * verification provenance, soft delete.
 *
 * INSTANCE-scoped, deliberately unlike the org-scoped backup_destination: the
 * managed edge (OpenResty + certbot) is shared infrastructure for the whole
 * box, so the CA choice is an operator decision, not a per-org one.
 *
 * Resolution precedence lives in exactly one place —
 * `resolveAcmeProviderOptions` (apps/api/src/lib/acme-config.ts): default
 * profile → `OPENSHIP_ACME_*` env vars → certbot's Let's Encrypt default.
 */
export const certificateAuthority = pgTable(
  "certificate_authority",
  {
    id: text("id").primaryKey(), // "ca_..."

    /** Operator-supplied display name (`openship certs ca add <name>`). */
    name: text("name").notNull(),
    /** "letsencrypt" | "letsencrypt-staging" | "zerossl" | "google" | "custom".
     *  Presets materialize their directory URL into `directoryUrl` at CREATE
     *  time (API layer), so resolution never needs the preset table. */
    kind: text("kind").notNull(),

    /* ── Public connection identity (never encrypted) ───────────────── */
    /** ACME directory URL. NULL = certbot's Let's Encrypt production default. */
    directoryUrl: text("directory_url"),
    /** Account contact email. NULL = fall back to OPENSHIP_ACME_EMAIL. */
    acmeEmail: text("acme_email"),
    /** "ec256" | "ec384" | "rsa2048" | "rsa4096". NULL = certbot default. */
    keyType: text("key_type"),
    /** Trust-bundle path visible to the certbot environment (private CAs). */
    caBundle: text("ca_bundle"),
    tosAgreed: boolean("tos_agreed").notNull().default(true),
    /** EAB key identifier — public half of the credential pair. */
    eabKid: text("eab_kid"),

    /* ── Encrypted credentials (enc1: envelope) ─────────────────────── */
    eabHmacKeyEnc: text("eab_hmac_key_enc"),

    /* ── Provenance / UI affordances ────────────────────────────────── */
    lastVerifiedAt: timestamp("last_verified_at"),
    lastVerifyError: text("last_verify_error"),
    /** The profile issuance uses when a domain doesn't pin one. */
    isDefault: boolean("is_default").notNull().default(false),

    deletedAt: timestamp("deleted_at"),
    createdAt: timestamp("created_at").notNull().defaultNow(),
    updatedAt: timestamp("updated_at").notNull().defaultNow(),
  },
  (table) => [
    // Name is unique among live profiles; soft-deleted rows free the name.
    uniqueIndex("uq_certificate_authority_name_active")
      .on(table.name)
      .where(sql`${table.deletedAt} IS NULL`),
  ],
);
