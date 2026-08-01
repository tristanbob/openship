import type { NginxProviderOptions } from "@repo/adapters";
import { repos, type CertificateAuthority } from "@repo/db";
import { env } from "../config/env";
import { decryptSecretField } from "./credential-encryption";

export type AcmeProviderOptions = Pick<
  NginxProviderOptions,
  | "acmeEmail"
  | "acmeDirectoryUrl"
  | "acmeEabKid"
  | "acmeEabHmacKey"
  | "acmeKeyType"
  | "acmeCaBundle"
  | "acmeTosAgreed"
>;

const present = (value: string | undefined): string | undefined => value?.trim() || undefined;

/**
 * The env-var layer of the ACME source order — `OPENSHIP_ACME_*` translated
 * without logging or returning the EAB secret. Exported separately because the
 * BOOT-time platform init (`resolvePlatformConfig`) is synchronous and cannot
 * read the DB; that boot provider is only the last-resort SSL anchor
 * (domain-ssl.ts resolves per call), so env-only is acceptable there.
 */
export function envAcmeProviderOptions(): AcmeProviderOptions {
  return {
    acmeEmail: present(env.OPENSHIP_ACME_EMAIL),
    acmeDirectoryUrl: present(env.OPENSHIP_ACME_DIRECTORY_URL),
    acmeEabKid: present(env.OPENSHIP_ACME_EAB_KID),
    acmeEabHmacKey: present(env.OPENSHIP_ACME_EAB_HMAC_KEY),
    acmeKeyType: env.OPENSHIP_ACME_KEY_TYPE,
    acmeCaBundle: present(env.OPENSHIP_ACME_CA_BUNDLE),
    acmeTosAgreed: env.OPENSHIP_ACME_TOS_AGREED,
  };
}

/**
 * Translate a stored CA profile into provider options. Pure except for the
 * HMAC decrypt (enc1 envelope, lib/credential-encryption). A profile is a
 * complete CA description — its NULLs mean "certbot default", NOT "fall
 * through to env" — except the account email, which is instance-wide contact
 * info and falls back to OPENSHIP_ACME_EMAIL.
 */
export function acmeOptionsFromProfile(profile: CertificateAuthority): AcmeProviderOptions {
  return {
    acmeEmail: present(profile.acmeEmail ?? undefined) ?? present(env.OPENSHIP_ACME_EMAIL),
    acmeDirectoryUrl: present(profile.directoryUrl ?? undefined),
    acmeEabKid: present(profile.eabKid ?? undefined),
    acmeEabHmacKey: decryptSecretField(profile.eabHmacKeyEnc),
    acmeKeyType: (profile.keyType ?? undefined) as AcmeProviderOptions["acmeKeyType"],
    acmeCaBundle: present(profile.caBundle ?? undefined),
    acmeTosAgreed: profile.tosAgreed,
  };
}

/**
 * The ACME source order, resolved fresh per call (deploys, takeovers, renewals
 * all pass through here via resolveTargetPlatform — a dashboard change applies
 * without an API restart):
 *
 *   1. The DEFAULT certificate_authority profile (DB, operator-managed).
 *   2. `OPENSHIP_ACME_*` env vars — the deployment fallback layer, same role
 *      as SMTP_HOST/USER/PASS in lib/mail.ts's source order.
 *   3. Nothing → certbot's Let's Encrypt default.
 *
 * A DB failure (boot ordering, pending migration) falls back to env rather
 * than failing the deploy — the env layer is the always-available floor.
 */
export async function resolveAcmeProviderOptions(): Promise<AcmeProviderOptions> {
  const profile = await repos.certificateAuthority.findDefault().catch(() => undefined);
  if (profile) return acmeOptionsFromProfile(profile);
  return envAcmeProviderOptions();
}

/**
 * The FULL precedence chain, for operations that act on one domain — the ONLY
 * place it lives (the rollbackWindow rule: one resolver, no second reader):
 *
 *   domain-pinned profile → default profile → env → Let's Encrypt.
 *
 * Takes the domain row's `certificateAuthorityId` (the caller already loaded
 * the row). A dangling id degrades to inherit — same posture as the FK's
 * ON DELETE SET NULL — rather than blocking issuance.
 */
export async function resolveDomainAcmeOptions(
  pinnedCaId: string | null | undefined,
): Promise<AcmeProviderOptions> {
  if (pinnedCaId) {
    const profile = await repos.certificateAuthority.findById(pinnedCaId).catch(() => undefined);
    if (profile) return acmeOptionsFromProfile(profile);
  }
  return resolveAcmeProviderOptions();
}
