"use client";

import { useState } from "react";
import { Check, Copy, FileUp, TriangleAlert } from "lucide-react";
import { ciWorkflow } from "@/lib/security/ci";
import { MAX_SARIF_BYTES } from "@/lib/security/sarif-import";
import type { FindingSet } from "@/lib/security/types";
import { sourceLabel } from "./securityUi";

const when = (t?: number) => (t ? new Date(t).toLocaleString() : "");

/** Where findings come from besides our own checks, whether each source worked, how to add more, and the CI workflow for live testing. */
export function SecuritySources({ repo, set, onImported }: { repo: string; set: FindingSet; onImported: () => void }) {
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [showCi, setShowCi] = useState(false);
  const [copied, setCopied] = useState(false);
  const entries = Object.entries(set.sources ?? {});

  const upload = async (file: File | undefined) => {
    if (!file) return;
    setMsg(null);
    if (file.size > MAX_SARIF_BYTES) { setMsg({ ok: false, text: "That file is too large (5 MB limit)." }); return; }
    setBusy(true);
    try {
      const r = await fetch(`/api/security/import?repo=${encodeURIComponent(repo)}`, { method: "POST", headers: { "content-type": "application/json" }, body: await file.text() });
      const d = (await r.json().catch(() => null)) as { error?: string; tool?: string; imported?: number; skipped?: number; warnings?: string[] } | null;
      if (!r.ok) throw new Error(d?.error ?? `Import failed (${r.status}).`);
      setMsg({ ok: true, text: `Imported ${d?.imported ?? 0} finding${d?.imported === 1 ? "" : "s"} from ${d?.tool}.${d?.warnings?.length ? ` ${d.warnings.join(" ")}` : ""}` });
      onImported();
    } catch (e) { setMsg({ ok: false, text: e instanceof Error ? e.message : "Import failed." }); } finally { setBusy(false); }
  };

  const remove = async (name: string) => {
    setMsg(null);
    try {
      const r = await fetch(`/api/security/import?repo=${encodeURIComponent(repo)}&source=${encodeURIComponent(name)}`, { method: "DELETE" });
      const d = (await r.json().catch(() => null)) as { error?: string; removed?: number } | null;
      if (!r.ok) throw new Error(d?.error ?? `Could not remove it (${r.status}).`);
      setMsg({ ok: true, text: `Removed ${d?.removed ?? 0} finding${d?.removed === 1 ? "" : "s"}.` });
      onImported();
    } catch (e) { setMsg({ ok: false, text: e instanceof Error ? e.message : "Could not remove it." }); }
  };

  let yaml = "", yamlError = "";
  if (showCi) { try { yaml = ciWorkflow({ origin: window.location.origin }); } catch { yamlError = "Live testing needs this site to be served over https."; } }

  return (
    <details className="group rounded-lg border border-line bg-raised/60 p-2.5" aria-label="Sources and integrations">
      <summary className="cursor-pointer select-none text-[11px] font-medium uppercase tracking-wider text-ink-faint">Sources and live testing</summary>
      <ul className="mt-2 space-y-1.5 text-[11px]">
        <li className="flex items-start gap-1.5 text-ink-dim"><Check size={12} className="mt-0.5 shrink-0 text-nominal" aria-hidden /><span>Built-in checks <span className="text-ink-faint">· dependencies, secrets, pipelines, containers, code</span></span></li>
        {entries.map(([name, s]) => (
          <li key={name} className="flex items-start gap-1.5" data-source={name}>
            {s.status === "ok" ? <Check size={12} className="mt-0.5 shrink-0 text-nominal" aria-hidden /> : <TriangleAlert size={12} className="mt-0.5 shrink-0 text-degraded" aria-hidden />}
            <span className="min-w-0 text-ink-dim">
              {sourceLabel(name, s.label)} <span className="text-ink-faint">· {s.status === "ok" ? `${s.count} finding${s.count === 1 ? "" : "s"}` : "unavailable"}{s.via === "ci" ? " · from CI" : s.via === "upload" ? " · uploaded" : ""}{s.importedAt && name.startsWith("sarif:") ? ` · ${when(s.importedAt)}` : ""}</span>
              {s.message && <span className={`block leading-snug ${s.status === "ok" ? "text-ink-faint" : "text-degraded"}`}>{s.message}</span>}
              {name.startsWith("sarif:") && <button onClick={() => void remove(name)} aria-label={`Remove ${sourceLabel(name, s.label)}`} className="mt-0.5 block text-ink-faint underline-offset-2 hover:text-failing hover:underline">Remove</button>}
              {s.by?.workflow && <span className="block text-ink-faint">workflow “{s.by.workflow}”{s.by.ref ? `, ${s.by.ref.replace("refs/heads/", "")}` : ""}{s.by.actor ? `, started by ${s.by.actor}` : ""}</span>}
            </span>
          </li>
        ))}
      </ul>

      <div className="mt-3 flex flex-wrap items-center gap-2">
        <label className={`flex cursor-pointer items-center gap-1.5 rounded-md border border-line px-2 py-1 text-[11px] text-ink-dim hover:text-ink ${busy ? "opacity-60" : ""}`}>
          <FileUp size={12} aria-hidden /> {busy ? "Importing…" : "Import a SARIF report"}
          <input type="file" accept=".sarif,.json,application/json" className="sr-only" disabled={busy} aria-label="Import a SARIF report" onChange={(e) => { void upload(e.target.files?.[0]); e.target.value = ""; }} />
        </label>
        <button onClick={() => setShowCi((v) => !v)} aria-expanded={showCi} className="rounded-md border border-line px-2 py-1 text-[11px] text-ink-dim hover:text-ink">{showCi ? "Hide" : "Add live testing to your CI"}</button>
      </div>
      <p className="mt-1.5 text-[10.5px] leading-snug text-ink-faint">Reports from Semgrep, CodeQL, Trivy, ZAP, Nuclei, gitleaks and other tools that write SARIF can be imported. A new report from the same tool replaces its previous one.</p>
      {msg && <p role={msg.ok ? "status" : "alert"} className={`mt-1.5 text-[11px] leading-snug ${msg.ok ? "text-nominal" : "text-failing"}`}>{msg.text}</p>}

      {showCi && (
        <div className="mt-3 space-y-2 text-[11px] leading-snug text-ink-dim" aria-label="Live testing in your CI">
          <p>This runs <span className="text-ink">in your own repository</span>, on GitHub&apos;s servers, against a staging site <span className="text-ink">you</span> name. Mission Control sends no test traffic anywhere. It signs in with GitHub&apos;s own short-lived token, so no secret is stored.</p>
          <ol className="list-decimal space-y-0.5 pl-4">
            <li>Save the file below as <code className="font-mono text-ink">.github/workflows/security-test.yml</code> in this repository.</li>
            <li>In the repository&apos;s Actions <span className="text-ink">Variables</span>, set <code className="font-mono text-ink">SECURITY_TEST_TARGET</code> to your staging URL.</li>
            <li>Set <code className="font-mono text-ink">SECURITY_TEST_CONFIRM_OWNER</code> to <code className="font-mono text-ink">yes</code> only if you own that site or are authorised to test it.</li>
            <li>Run it from the Actions tab. Results appear here as <span className="text-ink">Live testing</span>.</li>
          </ol>
          {yamlError ? <p role="alert" className="text-degraded">{yamlError}</p> : (
            <>
              <pre className="max-h-56 overflow-auto rounded-md border border-line bg-void p-2 font-mono text-[10.5px] leading-relaxed text-ink-dim" aria-label="Workflow file">{yaml}</pre>
              <button onClick={async () => { try { await navigator.clipboard.writeText(yaml); setCopied(true); setTimeout(() => setCopied(false), 1500); } catch { setMsg({ ok: false, text: "Copy failed. Select the text and copy it." }); } }} className="flex items-center gap-1.5 rounded-md border border-line px-2 py-1 text-ink-dim hover:text-ink">{copied ? <Check size={12} aria-hidden /> : <Copy size={12} aria-hidden />} Copy workflow</button>
            </>
          )}
        </div>
      )}
    </details>
  );
}
