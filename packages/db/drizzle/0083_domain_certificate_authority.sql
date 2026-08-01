-- Per-domain ACME CA pin (#256): "internal CA for *.internal, public CA for
-- customer-facing domains".
--
-- NULL = inherit — the rollbackWindow pattern: default certificate_authority
-- profile → OPENSHIP_ACME_* env → Let's Encrypt. Resolved in exactly one
-- place (resolveDomainAcmeOptions, apps/api/src/lib/acme-config.ts). ON
-- DELETE SET NULL so removing a profile degrades its domains to inherit
-- instead of blocking their issuance/renewal. No backfill: NULL is exactly
-- right for every pre-existing row.
ALTER TABLE "domain" ADD COLUMN IF NOT EXISTS "certificate_authority_id" text
	REFERENCES "certificate_authority"("id") ON DELETE SET NULL;
