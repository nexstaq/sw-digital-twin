import type { TwinGraph, TwinNode } from "@/lib/graph/types";
import { nodeFor } from "@/lib/security/map";
import type { Finding, FindingSet } from "@/lib/security/types";
import { sha256Hex } from "./sha256";
import {
  METHODS, WRITE_METHODS,
  type AbuseClass, type DatastoreSpec, type EmulatorSpec, type EndpointSpec, type Method, type PayloadClass, type RangeSpec, type Role, type Weakness, type WeaknessKind,
} from "./types";

/**
 * Builds a range from a stored map and the scanner's findings. Pure and deterministic: the same inputs give a byte-identical spec
 * (and the same `specHash`). It reads graph METADATA only (ids, labels, kinds, edges) and a few fields of each finding (id, rule,
 * severity, category, file). It never reads node summaries or narratives, a finding's reason text, a secret's kind or masked hint,
 * source code, or anything else that could carry a secret.
 */

const EMULATED = new Set(["endpoint", "service", "datastore", "queue", "external", "env", "job"]);
const ROUTE = new RegExp(`^(${METHODS.join("|")})\\s+(/\\S*)$`);
const BASE_LATENCY: Record<string, number> = { endpoint: 15, service: 35, datastore: 8, queue: 5, external: 120, env: 1, job: 1 };
// a sign-in style route. "reset" alone is deliberately not here: /admin/reset is not a sign-in, and reset-password is caught by "password".
const LOGIN = /(?:^|\/)(?:log-?in|sign-?in|auth|token|password|passwd|forgot|otp|2fa|mfa|verify)(?:\/|$|[-_])/i;
const isParam = (seg: string) => seg.startsWith(":") || (seg.startsWith("[") && seg.endsWith("]")) || (seg.startsWith("{") && seg.endsWith("}"));
const TABLE_NAMES = ["accounts", "orders", "sessions", "invoices", "events", "messages", "products", "audit"];

/** keys sorted, so the hash never depends on insertion order */
export function canonical(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  if (v && typeof v === "object") return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonical((v as Record<string, unknown>)[k])}`).join(",")}}`;
  return JSON.stringify(v) ?? "null";
}
const sha = sha256Hex;
const intFrom = (s: string, mod: number) => parseInt(sha(s).slice(0, 8), 16) % mod;
const safe = (s: string) => s.replace(/[^A-Za-z0-9]/g, "").slice(0, 40);

const ACCESS = new Set<string>(["idor", "missing-authz", "mass-assignment", "no-rate-limit", "weak-session", "skip-step", "replay"]);
const SESSION_ABUSES: AbuseClass[] = ["stale-session", "fixed-session"];

/**
 * CWE ids that imported reports (Semgrep, ZAP, Nuclei, a pen tester's SARIF...) use for access-control weaknesses. The built-in scanner does not find
 * these, so this is how they reach the range: nothing is modelled unless a report said so.
 */
const BY_CWE: Record<string, { kind: WeaknessKind; abuses?: AbuseClass[] }> = {
  "CWE-639": { kind: "idor" }, "CWE-566": { kind: "idor" },
  "CWE-862": { kind: "missing-authz" }, "CWE-285": { kind: "missing-authz" }, "CWE-863": { kind: "missing-authz" }, "CWE-425": { kind: "missing-authz" },
  "CWE-915": { kind: "mass-assignment", abuses: ["privileged-field"] }, "CWE-269": { kind: "mass-assignment", abuses: ["privileged-field"] },
  "CWE-307": { kind: "no-rate-limit" }, "CWE-770": { kind: "no-rate-limit" }, "CWE-799": { kind: "no-rate-limit" },
  "CWE-384": { kind: "weak-session", abuses: SESSION_ABUSES }, "CWE-613": { kind: "weak-session", abuses: SESSION_ABUSES },
  "CWE-841": { kind: "skip-step", abuses: ["skip-step"] }, "CWE-840": { kind: "skip-step", abuses: ["skip-step"] },
  "CWE-294": { kind: "replay", abuses: ["replay"] },
};

/** finding -> how the range models it, or null when it has no emulation yet (and is counted in the notes) */
export function classify(f: Pick<Finding, "ruleId" | "category"> & { cwe?: readonly string[] }): { kind: WeaknessKind; payload?: PayloadClass; abuses?: AbuseClass[] } | null {
  switch (f.ruleId) {
    case "CODE/sql-injection": return { kind: "sql-injection", payload: "sqli" };
    case "CODE/command-injection": return { kind: "command-injection", payload: "cmdi" };
    case "CODE/eval": return { kind: "code-injection", payload: "code-injection" };
    case "CODE/path-traversal": return { kind: "path-traversal", payload: "path-traversal" };
    case "CODE/ssrf": return { kind: "ssrf", payload: "ssrf" };
    case "CODE/xss-react": case "CODE/xss-dom": return { kind: "xss", payload: "xss" };
    case "CODE/open-redirect": return { kind: "open-redirect", payload: "open-redirect" };
    case "CODE/no-auth-seen": return { kind: "no-auth" };
    case "GHA/pwn-request": case "GHA/script-injection": return { kind: "pipeline-injection" };
  }
  for (const c of f.cwe ?? []) if (BY_CWE[c]) return BY_CWE[c];
  if (f.category === "secret") return { kind: "exposed-credential" };
  if (f.category === "dependency") return { kind: "vulnerable-dependency" };
  if (f.category === "pipeline") return { kind: "pipeline-misconfig" };
  if (f.category === "container") return { kind: "container-misconfig" };
  return null;
}

export function buildRange(snap: { sha: string; graph: TwinGraph }, set: FindingSet | null, opts: { seed?: number } = {}): RangeSpec {
  // Sorted copies: the map's owner lookup breaks ties by iteration order, so without this the range would depend on how the
  // snapshot happened to be ordered.
  const graph: TwinGraph = { ...snap.graph, nodes: [...snap.graph.nodes].sort((a, b) => a.id.localeCompare(b.id)), edges: [...snap.graph.edges].sort((a, b) => a.id.localeCompare(b.id)) };
  const notes: string[] = [];
  const byId = new Map(graph.nodes.map((n) => [n.id, n]));
  const hasKids = new Set(graph.nodes.map((n) => n.parentId).filter((p): p is string => !!p));

  // 1. which nodes become emulators: concrete runtime parts and CI jobs, not the level-0 clusters that only group them
  // A level-0 block that only groups things is not emulated; a level-0 job that has stages IS a workflow. A route group is not
  // emulated, but an endpoint that is a single named entry point (no routes inside it) is: it can be walked like any service.
  // A top-level SERVICE that directly holds routes is a real service (a small repository is one package with its routes inside), not a grouping.
  const kidsOf = new Map<string, TwinNode[]>();
  for (const n of graph.nodes) if (n.parentId) (kidsOf.get(n.parentId) ?? kidsOf.set(n.parentId, []).get(n.parentId)!).push(n);
  // "Directly holds routes" means its children are routes (and files), with no other services or data inside it: that would make it a grouping.
  const holdsRoutes = (n: TwinNode) => { const k = kidsOf.get(n.id) ?? []; return n.kind === "service" && k.some((c) => c.kind === "endpoint") && !k.some((c) => ["service", "datastore", "queue", "external", "job", "env"].includes(c.kind)); };
  const isCluster = (n: TwinNode) => n.level === 0 && hasKids.has(n.id) && n.kind !== "job" && !holdsRoutes(n);
  const isRoute = (n: TwinNode) => n.kind === "endpoint" && ROUTE.test(n.label);
  const emulated = graph.nodes.filter((n) => EMULATED.has(n.kind) && !isCluster(n) && (n.kind !== "endpoint" || isRoute(n) || !hasKids.has(n.id)));
  const emuIds = new Set(emulated.map((n) => n.id));
  const skipped = graph.nodes.filter((n) => !emuIds.has(n.id)).length;
  if (skipped) notes.push(`${skipped} map nodes were not emulated (clusters, route groups, packages and files).`);

  const emulators: EmulatorSpec[] = emulated
    .map((n): EmulatorSpec => ({
      nodeId: n.id, kind: n.kind, label: n.label, ...(n.parentId ? { parentId: n.parentId } : {}),
      latencyMs: BASE_LATENCY[n.kind] ?? 10, jitterMs: Math.max(1, Math.round((BASE_LATENCY[n.kind] ?? 10) / 5)),
      ...(n.kind === "job" ? { durationMs: 20_000 + intFrom(`${n.id}:dur`, 40_000) } : {}),
    }))
    .sort((a, b) => a.nodeId.localeCompare(b.nodeId));

  // 2. routes
  const ownerOf = (n: TwinNode): string => {
    for (let p = n.parentId; p; p = byId.get(p)?.parentId) { const a = byId.get(p); if (a && a.kind === "service" && emuIds.has(a.id)) return a.id; if (!a) break; }
    return emuIds.has(n.parentId ?? "") ? n.parentId! : n.id;
  };
  const endpoints: EndpointSpec[] = emulated.filter(isRoute).map((n) => {
    const m = ROUTE.exec(n.label)!;
    const method = m[1] as Method, path = m[2];
    const segments = path.split("/").filter(Boolean);
    // Assumptions, labelled as such: anything under an `admin` path is for admins and needs a sign-in; other writes need a sign-in; reads are open.
    const admin = segments.some((x) => x.toLowerCase() === "admin");
    const login = !admin && LOGIN.test(path);
    // a sign-in route has to be open to someone who is not signed in yet; everything else that writes, or sits under /admin, needs a sign-in
    const auth: EndpointSpec["auth"] = !admin && login ? "public-read" : admin || WRITE_METHODS.has(method) ? "required" : "public-read";
    const minRole: Role = admin ? "admin" : auth === "required" ? "user" : "anonymous";
    return { nodeId: n.id, ownerId: ownerOf(n), method, path, segments, auth, authSource: "assumed", minRole, object: segments.some(isParam), login } satisfies EndpointSpec;
  }).sort((a, b) => a.nodeId.localeCompare(b.nodeId));
  const endpointsInFile = new Map<string, EndpointSpec[]>();
  for (const e of endpoints) for (const ev of byId.get(e.nodeId)!.evidence) (endpointsInFile.get(ev.path) ?? endpointsInFile.set(ev.path, []).get(ev.path)!).push(e);

  // 3. weaknesses: only from findings, never invented
  const weaknesses: Weakness[] = [];
  let unmodelled = 0, unplaced = 0;
  const findings = [...(set?.findings ?? [])].sort((a, b) => a.id.localeCompare(b.id));
  for (const f of findings) {
    const c = classify(f);
    if (!c) { unmodelled++; continue; }
    const writes = (xs: EndpointSpec[]) => xs.filter((e) => WRITE_METHODS.has(e.method));
    const owner = nodeFor(graph, f);
    if (!owner) { unplaced++; continue; }
    const inFile = endpointsInFile.get(f.path) ?? [];
    let endpointIds: string[] = [];
    let reachable = false;
    if (c.payload) { endpointIds = inFile.map((e) => e.nodeId); reachable = endpointIds.length > 0; }
    else if (c.kind === "no-auth") {
      for (const e of inFile) if (WRITE_METHODS.has(e.method)) { e.auth = "none"; e.authSource = "finding"; endpointIds.push(e.nodeId); }
      reachable = endpointIds.length > 0;
    } else if (c.kind === "pipeline-injection") reachable = owner.startsWith("job:") || owner.startsWith("wf:");
    else if (ACCESS.has(c.kind)) {
      // an access-control weakness applies only to routes where the behaviour exists at all (ownership needs an object, a rate limit needs a login-like route...)
      const where: Record<string, EndpointSpec[]> = {
        idor: inFile.filter((e) => e.object), "missing-authz": inFile.filter((e) => e.minRole === "admin" && e.auth !== "none"), "mass-assignment": writes(inFile),
        "no-rate-limit": inFile.filter((e) => e.login), "weak-session": inFile.filter((e) => e.auth === "required"), "skip-step": writes(inFile), replay: writes(inFile),
      };
      endpointIds = (where[c.kind] ?? []).map((e) => e.nodeId);
      reachable = endpointIds.length > 0;
    }
    weaknesses.push({
      id: `w_${safe(f.id)}`, kind: c.kind, findingId: f.id, ruleId: f.ruleId, severity: f.severity, nodeId: owner,
      endpointIds: endpointIds.sort(), ...(c.payload ? { payload: c.payload } : {}), ...(c.abuses ? { abuses: c.abuses } : {}), proof: `SIM-PROOF-${safe(f.id)}`, reachable,
    });
  }
  if (unmodelled) notes.push(`${unmodelled} findings have no emulation yet and are not in the range.`);
  if (unplaced) notes.push(`${unplaced} findings could not be placed on a map node and are not in the range.`);
  if (!set) notes.push("No security scan was available, so the range has no weaknesses.");
  const latent = weaknesses.filter((w) => !w.reachable).length;
  if (latent) notes.push(`${latent} weaknesses are recorded but nothing in the range can exercise them yet.`);

  // 4. datastores: synthetic tables only
  const datastores: DatastoreSpec[] = emulated.filter((n) => n.kind === "datastore").map((n) => {
    const count = 2 + intFrom(`${n.id}:tables`, 3);
    const start = intFrom(`${n.id}:names`, TABLE_NAMES.length);
    return {
      nodeId: n.id, crown: `SIM-CROWN-${safe(n.id)}-${sha(n.id).slice(0, 6)}`,
      tables: Array.from({ length: count }, (_, i) => ({ name: TABLE_NAMES[(start + i) % TABLE_NAMES.length], rows: 5 + intFrom(`${n.id}:rows:${i}`, 96) })),
    };
  }).sort((a, b) => a.nodeId.localeCompare(b.nodeId));

  // An edge to a grouping block ("reads the data stores") means the things inside it: the data stores, queues and outside services in
  // that group. Edges FROM a group are not expanded (which member does the calling is not known).
  const ASSET = new Set(["datastore", "queue", "external"]);
  const assetsIn = (id: string, seen = new Set<string>()): string[] => {
    if (seen.has(id)) return [];
    seen.add(id);
    return (kidsOf.get(id) ?? []).flatMap((k) => (emuIds.has(k.id) && ASSET.has(k.kind) ? [k.id] : assetsIn(k.id, seen)));
  };
  const edges = graph.edges.flatMap((e) => {
    if (!emuIds.has(e.from)) return [];
    if (emuIds.has(e.to)) return [{ id: e.id, from: e.from, to: e.to, kind: e.kind }];
    return assetsIn(e.to).map((to) => ({ id: `${e.id}>${to}`, from: e.from, to, kind: e.kind }));
  }).sort((a, b) => a.id.localeCompare(b.id));

  const body = { version: 1 as const, repo: graph.repo, sha: snap.sha, seed: opts.seed ?? 1, emulators, endpoints, datastores, edges, weaknesses, notes };
  const specHash = sha(canonical(body)).slice(0, 16);
  return { ...body, id: `range_${specHash}`, specHash };
}
