-- Named ACME certificate-authority profiles (issue #256).
--
-- Shape mirrors `backup_destination` (public connection identity vs
-- `enc1:`-encrypted credential columns, is_default, verification provenance,
-- soft delete) but is INSTANCE-scoped — no organization_id — because the
-- managed edge (OpenResty + certbot) is shared infrastructure for the whole
-- box: which CA issues its certificates is an operator decision, not a
-- per-org one.
--
-- Resolution precedence lives in apps/api/src/lib/acme-config.ts
-- (resolveAcmeProviderOptions): default profile → OPENSHIP_ACME_* env vars →
-- certbot's Let's Encrypt default. No backfill: zero rows means the env layer
-- keeps working exactly as before this table existed.
CREATE TABLE IF NOT EXISTS "certificate_authority" (
	"id" text PRIMARY KEY NOT NULL,
	"name" text NOT NULL,
	"kind" text NOT NULL,
	"directory_url" text,
	"acme_email" text,
	"key_type" text,
	"ca_bundle" text,
	"tos_agreed" boolean DEFAULT true NOT NULL,
	"eab_kid" text,
	"eab_hmac_key_enc" text,
	"last_verified_at" timestamp,
	"last_verify_error" text,
	"is_default" boolean DEFAULT false NOT NULL,
	"deleted_at" timestamp,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
-- Name is unique among LIVE profiles; soft-deleted rows free the name.
CREATE UNIQUE INDEX IF NOT EXISTS "uq_certificate_authority_name_active"
	ON "certificate_authority" ("name") WHERE "certificate_authority"."deleted_at" IS NULL;
