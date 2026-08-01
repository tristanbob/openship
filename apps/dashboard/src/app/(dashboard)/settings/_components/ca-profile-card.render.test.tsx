// No DOM needed: renderToStaticMarkup runs no effects, and the card is pure.
import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { I18nProvider } from "@/components/i18n-provider";
import { CaProfileCard } from "./CertificateAuthorities";
import type { CaProfile } from "@/lib/api/system";

const BASE: CaProfile = {
  id: "ca_1",
  name: "zerossl",
  kind: "zerossl",
  directoryUrl: "https://acme.zerossl.com/v2/DV90",
  acmeEmail: null,
  keyType: null,
  caBundle: null,
  tosAgreed: true,
  eabKid: "kid-1",
  hasEabKey: true,
  isDefault: true,
  lastVerifiedAt: "2026-08-01T00:00:00.000Z",
  lastVerifyError: null,
  createdAt: "2026-08-01T00:00:00.000Z",
};

function render(profile: CaProfile) {
  return renderToStaticMarkup(
    <I18nProvider>
      <CaProfileCard profile={profile} />
    </I18nProvider>,
  );
}

/** Strip tags so assertions read against what the user actually sees. */
function text(html: string) {
  return html
    .replace(/<[^>]+>/g, " ")
    .replace(/&#x27;|&#39;/g, "'")
    .replace(/\s+/g, " ")
    .trim();
}

describe("CaProfileCard", () => {
  it("shows the profile's identity plus EAB/default/verified state", () => {
    const out = text(render(BASE));
    expect(out).toContain("zerossl");
    expect(out).toContain("ZeroSSL");
    expect(out).toContain("https://acme.zerossl.com/v2/DV90");
    expect(out).toContain("EAB");
    expect(out).toContain("Default");
    expect(out).toContain("Verified");
  });

  it("a NULL directory reads as the Let's Encrypt default, not as blank", () => {
    const out = text(render({ ...BASE, kind: "letsencrypt", directoryUrl: null }));
    expect(out).toContain("Let's Encrypt default");
  });

  it("a failed check is labeled, with the error in the tooltip — and the HMAC nowhere", () => {
    const html = render({
      ...BASE,
      lastVerifiedAt: null,
      lastVerifyError: "CA rejected EAB key",
    });
    expect(text(html)).toContain("Check failed");
    expect(html).toContain("CA rejected EAB key");
    // The wire type has no field that could carry the key, but pin the
    // rendering anyway: nothing that looks like key material.
    expect(html).not.toMatch(/hmac/i);
  });
});
