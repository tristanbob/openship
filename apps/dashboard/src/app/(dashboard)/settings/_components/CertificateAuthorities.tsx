"use client";

import { useState, useEffect, useCallback } from "react";
import { Loader2, ShieldCheck, Plus } from "lucide-react";
import { systemApi, type CaProfile, type CaProfileInput } from "@/lib/api/system";
import { getApiErrorMessage } from "@/lib/api/client";
import { useToast } from "@/context/ToastContext";
import { SettingsSection } from "./SettingsSection";
import { useI18n } from "@/components/i18n-provider";

/**
 * ACME certificate-authority profiles (#256) — which CA issues this instance's
 * HTTPS certificates. Same secret contract as EmailSettings: the EAB HMAC is
 * write-only. The field is blank on load, a blank save keeps the stored key
 * (`hasEabKey` is the only readback), and the API never returns the value.
 * Lives in the Instance tab next to the other "this install" edge panels.
 */

const INPUT =
  "w-full px-3.5 py-2.5 rounded-xl border border-border/50 bg-muted/30 text-sm text-foreground placeholder:text-muted-foreground/50 outline-none transition-all focus:ring-2 focus:ring-primary/20";
const LABEL = "block text-sm font-medium text-muted-foreground mb-1.5";
const KINDS = ["letsencrypt", "letsencrypt-staging", "zerossl", "google", "custom"] as const;
const KEY_TYPES = ["ec256", "ec384", "rsa2048", "rsa4096"] as const;

/** Pure profile row — exported for the render test. */
export function CaProfileCard({ profile }: { profile: CaProfile }) {
  const { t } = useI18n();
  const ca = t.settings.certificateAuthorities;
  const kindLabel = (ca.kinds as Record<string, string>)[profile.kind] ?? profile.kind;
  return (
    <div className="flex flex-wrap items-center gap-2 rounded-xl border border-border/50 bg-muted/20 px-3.5 py-2.5">
      <span className="text-sm font-medium text-foreground">{profile.name}</span>
      <span className="text-xs text-muted-foreground">{kindLabel}</span>
      <span className="text-xs text-muted-foreground/70 break-all">
        {profile.directoryUrl ?? ca.letsEncryptDefault}
      </span>
      <span className="ml-auto flex items-center gap-1.5">
        {profile.hasEabKey && (
          <span className="rounded-full bg-primary/10 px-2 py-0.5 text-xs text-primary">{ca.eabBadge}</span>
        )}
        {profile.isDefault && (
          <span className="rounded-full bg-primary/10 px-2 py-0.5 text-xs text-primary">{ca.defaultBadge}</span>
        )}
        {profile.lastVerifiedAt ? (
          <span className="rounded-full bg-emerald-500/10 px-2 py-0.5 text-xs text-emerald-600">{ca.verifiedBadge}</span>
        ) : profile.lastVerifyError ? (
          <span
            className="rounded-full bg-red-500/10 px-2 py-0.5 text-xs text-red-600"
            title={profile.lastVerifyError}
          >
            {ca.failedBadge}
          </span>
        ) : (
          <span className="rounded-full bg-muted px-2 py-0.5 text-xs text-muted-foreground">{ca.notTested}</span>
        )}
      </span>
    </div>
  );
}

const EMPTY_FORM: CaProfileInput = { kind: "custom", tosAgreed: true };

export function CertificateAuthorities() {
  const { showToast } = useToast();
  const { t } = useI18n();
  const ca = t.settings.certificateAuthorities;

  const [loading, setLoading] = useState(true);
  const [profiles, setProfiles] = useState<CaProfile[]>([]);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState<CaProfileInput>(EMPTY_FORM);
  const [saving, setSaving] = useState(false);

  const load = useCallback(async () => {
    try {
      setLoading(true);
      const res = await systemApi.listCertificateAuthorities();
      setProfiles(res.data);
    } catch (err) {
      showToast(getApiErrorMessage(err, ca.loadFailed), "error", ca.toastTitle);
    } finally {
      setLoading(false);
    }
  }, [showToast, ca.loadFailed, ca.toastTitle]);

  useEffect(() => {
    load();
  }, [load]);

  const set = (patch: Partial<CaProfileInput>) => setForm((f) => ({ ...f, ...patch }));

  async function save() {
    if (!form.name?.trim()) {
      showToast(ca.nameRequired, "error", ca.toastTitle);
      return;
    }
    setSaving(true);
    try {
      await systemApi.createCertificateAuthority(form);
      showToast(ca.saved, "success", ca.toastTitle);
      setForm(EMPTY_FORM);
      setShowForm(false);
      await load();
    } catch (err) {
      showToast(getApiErrorMessage(err, ca.saveFailed), "error", ca.toastTitle);
    } finally {
      setSaving(false);
    }
  }

  async function run(id: string, action: () => Promise<unknown>, successMsg?: string) {
    setBusyId(id);
    try {
      await action();
      if (successMsg) showToast(successMsg, "success", ca.toastTitle);
      await load();
    } catch (err) {
      showToast(getApiErrorMessage(err, ca.saveFailed), "error", ca.toastTitle);
    } finally {
      setBusyId(null);
    }
  }

  async function test(id: string) {
    setBusyId(id);
    try {
      const res = await systemApi.testCertificateAuthority(id);
      showToast(res.data.message, res.data.ok ? "success" : "error", ca.toastTitle);
      await load();
    } catch (err) {
      showToast(getApiErrorMessage(err, ca.saveFailed), "error", ca.toastTitle);
    } finally {
      setBusyId(null);
    }
  }

  return (
    <SettingsSection icon={ShieldCheck} title={ca.title} description={ca.description}>
      <p className="text-sm text-muted-foreground mb-4">{ca.intro}</p>

      {loading ? (
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" /> {ca.loading}
        </div>
      ) : (
        <div className="space-y-2">
          {profiles.length === 0 && !showForm && (
            <p className="text-sm text-muted-foreground/70">{ca.empty}</p>
          )}
          {profiles.map((p) => (
            <div key={p.id} className="space-y-1.5">
              <CaProfileCard profile={p} />
              <div className="flex gap-3 pl-1 text-xs">
                <button
                  className="text-primary hover:underline disabled:opacity-50"
                  disabled={busyId === p.id}
                  onClick={() => test(p.id)}
                >
                  {ca.test}
                </button>
                {!p.isDefault && (
                  <button
                    className="text-primary hover:underline disabled:opacity-50"
                    disabled={busyId === p.id}
                    onClick={() => run(p.id, () => systemApi.setDefaultCertificateAuthority(p.id))}
                  >
                    {ca.setDefault}
                  </button>
                )}
                <button
                  className="text-red-500 hover:underline disabled:opacity-50"
                  disabled={busyId === p.id}
                  onClick={() => run(p.id, () => systemApi.removeCertificateAuthority(p.id), ca.removed)}
                >
                  {ca.remove}
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {!showForm ? (
        <button
          className="mt-4 inline-flex items-center gap-1.5 rounded-xl border border-border/50 px-3.5 py-2 text-sm text-foreground hover:bg-muted/30"
          onClick={() => setShowForm(true)}
        >
          <Plus className="h-4 w-4" /> {ca.add}
        </button>
      ) : (
        <div className="mt-4 space-y-3 rounded-xl border border-border/50 p-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className={LABEL}>{ca.name}</label>
              <input className={INPUT} value={form.name ?? ""} onChange={(e) => set({ name: e.target.value })} />
            </div>
            <div>
              <label className={LABEL}>{ca.kind}</label>
              <select className={INPUT} value={form.kind ?? "custom"} onChange={(e) => set({ kind: e.target.value })}>
                {KINDS.map((k) => (
                  <option key={k} value={k}>
                    {(ca.kinds as Record<string, string>)[k]}
                  </option>
                ))}
              </select>
            </div>
          </div>
          {form.kind === "custom" && (
            <div>
              <label className={LABEL}>{ca.directoryUrl}</label>
              <input
                className={INPUT}
                placeholder="https://ca.internal.example/acme/directory"
                value={form.directoryUrl ?? ""}
                onChange={(e) => set({ directoryUrl: e.target.value })}
              />
            </div>
          )}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className={LABEL}>{ca.email}</label>
              <input className={INPUT} value={form.acmeEmail ?? ""} onChange={(e) => set({ acmeEmail: e.target.value })} />
            </div>
            <div>
              <label className={LABEL}>{ca.keyType}</label>
              <select
                className={INPUT}
                value={form.keyType ?? ""}
                onChange={(e) => set({ keyType: e.target.value || null })}
              >
                <option value="">{ca.keyTypeDefault}</option>
                {KEY_TYPES.map((k) => (
                  <option key={k} value={k}>
                    {k}
                  </option>
                ))}
              </select>
            </div>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className={LABEL}>{ca.eabKid}</label>
              <input className={INPUT} value={form.eabKid ?? ""} onChange={(e) => set({ eabKid: e.target.value })} />
            </div>
            <div>
              <label className={LABEL}>{ca.eabHmacKey}</label>
              {/* Write-only: never prefilled; a blank save keeps the stored key. */}
              <input
                className={INPUT}
                type="password"
                autoComplete="off"
                placeholder={ca.eabHmacKeyKeepHint}
                value={form.eabHmacKey ?? ""}
                onChange={(e) => set({ eabHmacKey: e.target.value })}
              />
            </div>
          </div>
          <div>
            <label className={LABEL}>{ca.caBundle}</label>
            <input
              className={INPUT}
              placeholder="/etc/ssl/private/acme-root.pem"
              value={form.caBundle ?? ""}
              onChange={(e) => set({ caBundle: e.target.value })}
            />
          </div>
          <label className="flex items-center gap-2 text-sm text-muted-foreground">
            <input
              type="checkbox"
              checked={!!form.isDefault}
              onChange={(e) => set({ isDefault: e.target.checked })}
            />
            {ca.setDefault}
          </label>
          <div className="flex gap-2">
            <button
              className="rounded-xl bg-primary px-4 py-2 text-sm text-primary-foreground disabled:opacity-50"
              disabled={saving}
              onClick={save}
            >
              {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : ca.save}
            </button>
            <button
              className="rounded-xl border border-border/50 px-4 py-2 text-sm"
              onClick={() => {
                setShowForm(false);
                setForm(EMPTY_FORM);
              }}
            >
              {ca.cancel}
            </button>
          </div>
        </div>
      )}
    </SettingsSection>
  );
}
