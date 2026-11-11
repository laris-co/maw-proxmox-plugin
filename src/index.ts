// maw proxmox: READ-ONLY view of a Proxmox VE host through its REST API (/api2/json).
//
//   maw proxmox status                       node cpu / mem / rootfs / uptime / version
//   maw proxmox vms                          every qemu VM: vmid name status cpus mem uptime
//   maw proxmox vm <vmid>                    status/current + config of one VM
//   maw proxmox tasks [--failed] [--limit N] recent tasks; failed ones are marked FAIL
//   maw proxmox task-log <upid>              log lines of one task
//   maw proxmox backups                      backup jobs (/cluster/backup) + backup archives on every storage
//   maw proxmox ours                         only the VMs in PVE_OURS (or --ours 1,2,3) with backup coverage
//   maw proxmox storage                      pools: used / total
//   --json  machine output   --insecure  accept a self-signed cert   --debug  auth diagnostics (no secrets)
//
//   maw proxmox firewall [<vmid>]            firewall state: datacenter, node, VMs with NIC firewall=1 (GET only)
//
//   maw proxmox create haos|ubuntu ...      write (src/create.ts): plan by default, writes need --apply --yes
//   maw proxmox firewall lock|unlock ...    write (src/firewall.ts): plan by default, writes need --apply --yes
//
// Every other command only sends GET requests, plus POST /access/ticket to log in. All write calls live in
// src/create.ts and src/firewall.ts; this file holds none.
//
// Nothing about any particular host lives in this file. Everything comes from the environment:
//   PVE_HOST          required. host, host:port or https://host:port (port defaults to 8006)
//   PVE_NODE          node name; if unset it is auto-detected via GET /nodes (must be exactly one node)
//   PVE_INSECURE=1    accept a self-signed certificate (same as --insecure)
//   PVE_TOKEN_ID + PVE_TOKEN_SECRET     API token auth (preferred)
//   PVE_USER + PVE_PASSWORD             ticket login, or PVE_USER + PVE_PASS_ENTRY (read with `pass show`)
//   PVE_OURS          comma/space list of vmids for `ours`
//   PVE_ALLOWED_NETS / PVE_DENY_NETS / PVE_RAM_RESERVE_GIB / PVE_GW / PVE_DNS / PVE_STORAGE_VM / PVE_STORAGE_IMG /
//   PVE_BRIDGE        guards and defaults for `create`

import { runCreate, type CreateDeps, type ProbeResult } from "./create";
import { runFirewall } from "./firewall";

type InvokeContext = { source: "cli" | string; args: string[] };
type PluginResult = { ok: boolean; output?: string; error?: string };
type Env = Record<string, string | undefined>;
type FetchFn = (url: string, init?: RequestInit & { tls?: { rejectUnauthorized?: boolean } }) => Promise<Response>;
type PassFn = (entry: string) => string | null;
export type Store = {
  readConfig(): J; writeConfig(c: J): void; configPath(): string;
  readTicket(): J | null; writeTicket(t: J | null): void;
  now(): number;
};
type Deps = { env: Env; fetch: FetchFn; pass: PassFn; log: (s: string) => void; store?: Store; create?: Partial<CreateDeps> };
type J = Record<string, any>;

const HELP = `maw proxmox — Proxmox VE view (read-only) + guarded VM creation and VM firewall lock

  maw proxmox status                        node cpu / mem / rootfs / uptime / version
  maw proxmox vms                           all qemu VMs: vmid name status cpus mem uptime
  maw proxmox vm <vmid>                     status/current + config of one VM
  maw proxmox inventory [--only-ours]       every VM: what it is (note, os, tags), size, ours, backup age
  maw proxmox tasks [--failed] [--limit N]  recent tasks (default 50); failed ones marked FAIL
  maw proxmox task-log <upid>               log lines of one task
  maw proxmox backups                       backup jobs + backup archives on every storage
  maw proxmox ours [--ours 1,2,3]           only the listed VMs (default $PVE_OURS) with backup coverage
  maw proxmox storage                       storage pools: used / total
  maw proxmox firewall [<vmid>]             firewall: datacenter / node enable + rule counts, VMs with a NIC
                                            firewall=1; with <vmid>: its options, rules and net* lines

  maw proxmox create haos   --vmid N --name NAME --ip A.B.C.D/24 [--gw IP] [--dns IP,IP] [--cores 2] [--ram 2048]
                            [--disk 48] [--image haos_ova-18.2.qcow2] [--storage-vm ssd] [--storage-img local]
                            [--bridge vmbr0] [--iface enp6s18] [--wait-min 5] [--apply --yes]
  maw proxmox create ubuntu --vmid N --name NAME --ip A.B.C.D/24 --ssh-key PATH [--ciuser ubuntu] [--disk 40]
                            [--image noble-server-cloudimg-amd64.qcow2] [same options as haos] [--apply --yes]
      default = PLAN ONLY: runs every check and prints the exact API calls, writes nothing.
      writes only with BOTH --apply and --yes, and only when every check passes:
      vmid + name free, ip inside allowed_nets and not in deny_nets, ip silent (tcp 22/80/443 + ping) and not on
      any guest, RAM headroom (running maxmem + new <= physical - ram_reserve_gib), storage >= disk + 10%,
      image present in <storage-img>:import/, ubuntu: --ssh-key is a public key.

  maw proxmox firewall lock   <vmid> --name NAME [--apply --yes]
      drop all inbound traffic to one VM (outbound-started traffic, e.g. Tailscale, still works). PLAN by default.
      checks: VM exists and is named NAME, in ours (if set), host firewall off first, no other VM starts being
      filtered when the datacenter firewall goes on. calls, in order (each skipped if already so):
      PUT node firewall enable=0, PUT VM config net<N>=<same value>,firewall=1,
      PUT VM firewall enable=1 policy_in=DROP policy_out=ACCEPT, PUT datacenter firewall enable=1
  maw proxmox firewall unlock <vmid> --name NAME [--apply --yes]
      PUT VM firewall enable=0. The datacenter firewall is left on (turn it off by hand if nothing needs it).

  maw proxmox config                        show saved settings (and the file path)
  maw proxmox config set k=v [k=v ...]      save: host node user pass_entry token_id insecure ours
                                            allowed_nets deny_nets ram_reserve_gib gw dns storage_vm storage_img bridge
  maw proxmox config unset <key>            remove one saved setting
  maw proxmox logout                        forget the cached login ticket

  --json  JSON output    --insecure  accept self-signed cert ($PVE_INSECURE=1)    --debug  auth diagnostics

  env: PVE_HOST (required) PVE_NODE (auto-detected if unset)
       PVE_TOKEN_ID + PVE_TOKEN_SECRET      or   PVE_USER + PVE_PASSWORD | PVE_PASS_ENTRY (pass show)
       PVE_OURS  vmid list for 'ours'
  saved config (~/.config/maw-proxmox/config.json) fills in anything env leaves unset; env always wins.
  passwords / token secrets are never saved; a ticket login is cached ~1h50m (0600) and reused.
  every command except 'create' and 'firewall lock|unlock' is read-only (GET only). 'create' never touches an
  existing VM; 'firewall lock|unlock' touches only firewall settings and the named VM's NIC firewall flag.`;

// ---------- args ----------
export function parse(args: string[]) {
  const rest: string[] = [];
  let json = false, failed = false, insecure = false, debug = false, onlyOurs = false, limit = 50, ours: string | undefined;
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (a === "--json") json = true;
    else if (a === "--failed") failed = true;
    else if (a === "--only-ours" || a === "--mine") onlyOurs = true;
    else if (a === "--insecure" || a === "-k") insecure = true;
    else if (a === "--debug") debug = true;
    else if (a === "--limit" || a === "-n") limit = Number(args[++i] ?? limit);
    else if (a.startsWith("--limit=")) limit = Number(a.slice(8));
    else if (a === "--ours") ours = args[++i];
    else if (a.startsWith("--ours=")) ours = a.slice(7);
    else if (a === "-h" || a === "--help") rest.unshift("help");
    else rest.push(a);
  }
  if (!Number.isFinite(limit) || limit < 1) limit = 50;
  return { verb: rest[0] ?? "help", rest: rest.slice(1), json, failed, insecure, debug, onlyOurs, limit: Math.floor(limit), ours };
}

export function baseUrl(host: string | undefined): string {
  if (!host || !host.trim()) throw new Error("PVE_HOST is not set (host, host:port or https://host:port)");
  let h = host.trim().replace(/\/+$/, "");
  if (!/^https?:\/\//.test(h)) h = "https://" + h;
  const u = new URL(h);
  if (!u.port && u.protocol === "https:") u.port = "8006";
  const path = u.pathname.replace(/\/+$/, "");
  return `${u.protocol}//${u.host}${path.endsWith("/api2/json") ? path : path + "/api2/json"}`;
}

export function vmidList(s: string | undefined): number[] {
  return (s ?? "").split(/[\s,]+/).filter(Boolean).map(Number).filter((n) => Number.isInteger(n) && n > 0);
}

const truthy = (v: string | undefined) => !!v && /^(1|true|yes|on)$/i.test(v);

// ---------- saved config ----------
// key in config.json -> env var it fills. Secrets (password, token secret) are deliberately absent.
export const CONFIG_KEYS: Record<string, string> = {
  host: "PVE_HOST", node: "PVE_NODE", user: "PVE_USER", pass_entry: "PVE_PASS_ENTRY",
  token_id: "PVE_TOKEN_ID", insecure: "PVE_INSECURE", ours: "PVE_OURS",
  allowed_nets: "PVE_ALLOWED_NETS", deny_nets: "PVE_DENY_NETS", ram_reserve_gib: "PVE_RAM_RESERVE_GIB",
  gw: "PVE_GW", dns: "PVE_DNS", storage_vm: "PVE_STORAGE_VM", storage_img: "PVE_STORAGE_IMG", bridge: "PVE_BRIDGE",
};
const SECRET_KEYS = ["password", "pass", "token_secret", "secret", "ticket"];

/** env wins; saved config fills only what env leaves unset or empty. */
export function mergeEnv(env: Env, cfg: J): Env {
  const out: Env = { ...env };
  for (const [k, v] of Object.entries(CONFIG_KEYS)) {
    if ((out[v] === undefined || out[v] === "") && cfg[k] !== undefined && cfg[k] !== "") out[v] = String(cfg[k]);
  }
  return out;
}

export function configSet(cfg: J, pairs: string[]): J {
  const next = { ...cfg };
  const items: [string, string][] = [];
  if (pairs.length === 2 && !pairs[0]!.includes("=")) items.push([pairs[0]!, pairs[1]!]);
  else for (const p of pairs) {
    const i = p.indexOf("=");
    if (i < 1) throw new Error(`expected key=value, got: ${p}`);
    items.push([p.slice(0, i), p.slice(i + 1)]);
  }
  if (!items.length) throw new Error("usage: maw proxmox config set key=value [key=value ...]");
  for (const [rawK, v] of items) {
    const k = rawK.toLowerCase().replace(/-/g, "_");
    if (SECRET_KEYS.includes(k)) throw new Error(`refusing to save '${k}': secrets stay in pass or env, never in the config file (use pass_entry)`);
    if (!(k in CONFIG_KEYS)) throw new Error(`unknown key '${rawK}'. keys: ${Object.keys(CONFIG_KEYS).join(" ")}`);
    next[k] = v;
  }
  return next;
}

// ---------- auth ----------
export type Auth = { kind: "token" | "ticket"; headers: Record<string, string> };

export function describeCreds(env: Env) {
  // Booleans and lengths only — never values.
  return {
    host: !!env.PVE_HOST,
    node: env.PVE_NODE ? "set" : "auto",
    tokenId: (env.PVE_TOKEN_ID ?? "").length,
    tokenSecret: (env.PVE_TOKEN_SECRET ?? "").length,
    user: (env.PVE_USER ?? "").length,
    password: (env.PVE_PASSWORD ?? "").length,
    passEntry: !!env.PVE_PASS_ENTRY,
    insecure: truthy(env.PVE_INSECURE),
  };
}

export const NO_CREDS = `no Proxmox credentials found. Set one of:
  PVE_TOKEN_ID=user@realm!name PVE_TOKEN_SECRET=...          (API token, preferred)
  PVE_USER=user@realm PVE_PASSWORD=...                        (ticket login)
  PVE_USER=user@realm PVE_PASS_ENTRY=<pass entry>             (password read with 'pass show')`;

export class Api {
  base: string;
  node?: string;
  auth?: Auth;
  cachedTicket = false;
  /** CSRFPreventionToken from the ticket login; required on POST/PUT with ticket auth (token auth needs none). */
  csrf?: string;
  constructor(private d: Deps, private insecure: boolean) {
    this.base = baseUrl(d.env.PVE_HOST);
    this.node = d.env.PVE_NODE || undefined;
  }
  init(extra: RequestInit = {}) {
    return { ...extra, ...(this.insecure ? { tls: { rejectUnauthorized: false } } : {}) };
  }
  async login(): Promise<Auth> {
    if (this.auth) return this.auth;
    const e = this.d.env;
    if (e.PVE_TOKEN_ID && e.PVE_TOKEN_SECRET) {
      return (this.auth = { kind: "token", headers: { Authorization: `PVEAPIToken=${e.PVE_TOKEN_ID}=${e.PVE_TOKEN_SECRET}` } });
    }
    const st = this.d.store;
    const cached = st?.readTicket();
    if (cached && cached.base === this.base && cached.user === e.PVE_USER && Number(cached.expires) > (st!.now())) {
      this.cachedTicket = true;
      this.csrf = cached.csrf || undefined;
      return (this.auth = { kind: "ticket", headers: { Cookie: `PVEAuthCookie=${cached.ticket}` } });
    }
    let pw = e.PVE_PASSWORD;
    if (!pw && e.PVE_USER && e.PVE_PASS_ENTRY) pw = this.d.pass(e.PVE_PASS_ENTRY) ?? undefined;
    if (!e.PVE_USER || !pw) throw new Error(NO_CREDS);
    const body = new URLSearchParams({ username: e.PVE_USER, password: pw });
    const r = await this.d.fetch(`${this.base}/access/ticket`, this.init({ method: "POST", body, headers: { "Content-Type": "application/x-www-form-urlencoded" } }));
    if (!r.ok) throw new Error(`ticket login failed: HTTP ${r.status} (check PVE_USER / password)`);
    const data = ((await r.json()) as J)?.data;
    const t = data?.ticket;
    if (!t) throw new Error("ticket login failed: no ticket in response");
    this.csrf = data?.CSRFPreventionToken || undefined;
    // Proxmox tickets live 2h; reuse for 1h50m.
    st?.writeTicket({ base: this.base, user: e.PVE_USER, ticket: t, csrf: this.csrf, expires: st.now() + 110 * 60 * 1000 });
    return (this.auth = { kind: "ticket", headers: { Cookie: `PVEAuthCookie=${t}` } });
  }
  async get<T = any>(path: string): Promise<T> {
    let a = await this.login();
    let r = await this.d.fetch(`${this.base}${path}`, this.init({ method: "GET", headers: a.headers }));
    if (r.status === 401 && this.cachedTicket) {
      // stale cached ticket: forget it and log in once more
      this.d.store?.writeTicket(null); this.auth = undefined; this.cachedTicket = false;
      a = await this.login();
      r = await this.d.fetch(`${this.base}${path}`, this.init({ method: "GET", headers: a.headers }));
    }
    if (r.status === 401) throw new Error(`HTTP 401 on ${path} (${a.kind} auth rejected)`);
    if (!r.ok) throw new Error(`HTTP ${r.status} on ${path}: ${(await r.text()).slice(0, 200)}`);
    return ((await r.json()) as J).data as T;
  }
  /** Auth headers for a POST/PUT: ticket auth adds the CSRF token (a cached ticket without one forces a fresh login). */
  async writeHeaders(): Promise<Record<string, string>> {
    let a = await this.login();
    if (a.kind === "token") return a.headers;
    if (!this.csrf) {
      this.d.store?.writeTicket(null); this.auth = undefined; this.cachedTicket = false;
      a = await this.login();
    }
    if (!this.csrf) throw new Error("ticket login returned no CSRFPreventionToken; refusing to write");
    return { ...a.headers, CSRFPreventionToken: this.csrf };
  }
  /** Raw request for src/create.ts (the only caller that writes). */
  fetchRaw(path: string, init: RequestInit) { return this.d.fetch(`${this.base}${path}`, this.init(init)); }
  async nodeName(): Promise<string> {
    if (this.node) return this.node;
    const ns = await this.get<J[]>("/nodes");
    if (ns.length !== 1) throw new Error(`PVE_NODE not set and the cluster has ${ns.length} nodes (${ns.map((n) => n.node).join(", ")}); set PVE_NODE`);
    return (this.node = String(ns[0]!.node));
  }
  async n(path: string) { return this.get(`/nodes/${encodeURIComponent(await this.nodeName())}${path}`); }
}

// ---------- formatting ----------
export function bytes(n: unknown): string {
  const v = Number(n);
  if (!Number.isFinite(v) || n == null) return "-";
  const u = ["B", "K", "M", "G", "T", "P"];
  let i = 0, x = v;
  while (x >= 1024 && i < u.length - 1) { x /= 1024; i++; }
  return `${x >= 100 || i === 0 ? x.toFixed(0) : x.toFixed(1)}${u[i]}`;
}
export function dur(s: unknown): string {
  const v = Number(s);
  if (!Number.isFinite(v) || v <= 0) return "-";
  const d = Math.floor(v / 86400), h = Math.floor((v % 86400) / 3600), m = Math.floor((v % 3600) / 60);
  return d ? `${d}d${h}h` : h ? `${h}h${m}m` : `${m}m`;
}
export function ts(epoch: unknown, tz = process.env.TZ): string {
  const v = Number(epoch);
  if (!Number.isFinite(v) || !v) return "-";
  const d = new Date(v * 1000);
  const p = new Intl.DateTimeFormat("sv-SE", { timeZone: tz || undefined, year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false }).format(d);
  return p.replace("T", " ");
}
const pct = (a: unknown, b: unknown) => (Number(b) ? `${((Number(a) / Number(b)) * 100).toFixed(0)}%` : "-");

export function table(head: string[], rows: unknown[][]): string {
  const cells = [head, ...rows.map((r) => r.map((c) => (c == null ? "-" : String(c))))];
  const w = head.map((_, i) => Math.max(...cells.map((r) => (r[i] ?? "").length)));
  return cells.map((r) => r.map((c, i) => (i === r.length - 1 ? c : c.padEnd(w[i]!))).join("  ").trimEnd()).join("\n");
}

export function taskState(t: J): "running" | "ok" | "warn" | "fail" {
  if (t.status == null || t.status === "") return "running";
  if (t.status === "OK") return "ok";
  if (String(t.status).startsWith("WARNINGS")) return "warn";
  return "fail";
}

// Which vmids a backup job covers: all (minus exclude) or an explicit list. Pool-based jobs are reported as "pool:<name>".
export function jobCovers(job: J, vmid: number): boolean {
  if (Number(job.enabled ?? 1) === 0) return false;
  if (Number(job.all ?? 0) === 1) return !vmidList(job.exclude).includes(vmid);
  return vmidList(job.vmid).includes(vmid);
}

// ---------- data ----------
async function backupFiles(api: Api): Promise<J[]> {
  const stores = await api.n("/storage?content=backup") as J[];
  const out: J[] = [];
  for (const s of stores) {
    if (Number(s.active ?? 1) === 0) continue;
    const items = await api.n(`/storage/${encodeURIComponent(s.storage)}/content?content=backup`).catch(() => [] as J[]) as J[];
    for (const it of items) out.push({ storage: s.storage, ...it });
  }
  return out.sort((a, b) => Number(b.ctime ?? 0) - Number(a.ctime ?? 0));
}

// ---------- handler ----------
export async function run(args: string[], d: Deps): Promise<PluginResult> {
  const o = parse(args);
  const ok = (output: string): PluginResult => ({ ok: true, output });
  const js = (v: unknown): PluginResult => ok(JSON.stringify(v, null, 1));
  const fail = (error: string): PluginResult => ({ ok: false, error });
  if (o.verb === "help") return ok(HELP);

  if (o.verb === "config") {
    if (!d.store) return fail("no config store available");
    try {
      const cfg = d.store.readConfig();
      const sub = o.rest[0];
      if (!sub || sub === "show") {
        if (o.json) return js({ path: d.store.configPath(), config: cfg });
        const rows = Object.keys(CONFIG_KEYS).map((k) => [k, cfg[k] ?? "-", d.env[CONFIG_KEYS[k]!] ? `env ${CONFIG_KEYS[k]} overrides` : ""]);
        return ok(`${d.store.configPath()}\n${table(["key", "saved", "note"], rows)}`);
      }
      if (sub === "path") return ok(d.store.configPath());
      if (sub === "set") { const next = configSet(cfg, o.rest.slice(1)); d.store.writeConfig(next); return ok(`saved to ${d.store.configPath()}`); }
      if (sub === "unset") {
        const k = (o.rest[1] ?? "").toLowerCase().replace(/-/g, "_");
        if (!(k in CONFIG_KEYS)) return fail(`unknown key '${o.rest[1] ?? ""}'. keys: ${Object.keys(CONFIG_KEYS).join(" ")}`);
        const next = { ...cfg }; delete next[k]; d.store.writeConfig(next); return ok(`removed ${k}`);
      }
      return fail(`usage: maw proxmox config [show|path|set k=v ...|unset key]`);
    } catch (e) { return fail((e as Error).message); }
  }
  if (o.verb === "logout") { d.store?.writeTicket(null); return ok("cached ticket removed"); }

  if (d.store) d = { ...d, env: mergeEnv(d.env, d.store.readConfig()) };
  const known = ["status", "vms", "vm", "inventory", "tasks", "task-log", "backups", "ours", "storage", "firewall", "create"];
  if (!known.includes(o.verb)) return fail(`unknown command: ${o.verb}\n\n${HELP}`);

  try {
    if (o.debug) d.log(`[debug] ${JSON.stringify(describeCreds(d.env))}`);
    const api = new Api(d, o.insecure || truthy(d.env.PVE_INSECURE));

    if (o.verb === "create") return await runCreate(api, o.rest, { ...realCreateDeps(), env: d.env, log: d.log, ...d.create } as CreateDeps);
    if (o.verb === "firewall") return await runFirewall(api, o.rest, { env: o.ours !== undefined ? { ...d.env, PVE_OURS: o.ours } : d.env, log: d.log, json: o.json });

    if (o.verb === "status") {
      const s = await api.n("/status") as J;
      const out = {
        node: await api.nodeName(), cpu: s.cpu, cpus: s.cpuinfo?.cpus, loadavg: s.loadavg,
        memory: s.memory, rootfs: s.rootfs, uptime: s.uptime, pveversion: s.pveversion, kversion: s.kversion,
      };
      if (o.json) return js(out);
      return ok(table(["field", "value"], [
        ["node", out.node],
        ["version", out.pveversion],
        ["cpu", `${(Number(s.cpu ?? 0) * 100).toFixed(1)}% of ${out.cpus ?? "?"} cpus  load ${(s.loadavg ?? []).join(" ")}`],
        ["memory", `${bytes(s.memory?.used)} / ${bytes(s.memory?.total)} (${pct(s.memory?.used, s.memory?.total)})`],
        ["rootfs", `${bytes(s.rootfs?.used)} / ${bytes(s.rootfs?.total)} (${pct(s.rootfs?.used, s.rootfs?.total)})`],
        ["uptime", dur(s.uptime)],
      ]));
    }

    if (o.verb === "vms") {
      const vms = (await api.n("/qemu") as J[]).sort((a, b) => Number(a.vmid) - Number(b.vmid));
      if (o.json) return js(vms);
      return ok(table(["vmid", "name", "status", "cpus", "mem", "maxmem", "uptime"],
        vms.map((v) => [v.vmid, v.name, v.status, v.cpus, v.status === "running" ? bytes(v.mem) : "-", bytes(v.maxmem), dur(v.uptime)])));
    }

    if (o.verb === "vm") {
      const id = Number(o.rest[0]);
      if (!Number.isInteger(id) || id <= 0) return fail("usage: maw proxmox vm <vmid>");
      const [st, cfg] = await Promise.all([api.n(`/qemu/${id}/status/current`), api.n(`/qemu/${id}/config`)]) as [J, J];
      if (o.json) return js({ status: st, config: cfg });
      const head = table(["field", "value"], [
        ["vmid", id], ["name", st.name ?? cfg.name], ["status", st.status], ["qmpstatus", st.qmpstatus],
        ["cpu", `${(Number(st.cpu ?? 0) * 100).toFixed(1)}% of ${st.cpus ?? "?"}`],
        ["memory", `${bytes(st.mem)} / ${bytes(st.maxmem)}`], ["uptime", dur(st.uptime)],
        ["net in/out", `${bytes(st.netin)} / ${bytes(st.netout)}`], ["agent", st.agent ?? "-"],
      ]);
      const conf = table(["key", "value"], Object.keys(cfg).filter((k) => k !== "digest").sort().map((k) => [k, cfg[k]]));
      return ok(`${head}\n\nconfig\n${conf}`);
    }

    if (o.verb === "inventory") {
      // what every VM IS: name, size, OS, tags, the note its owner wrote, backup coverage. Read-only.
      const vms = (await api.n("/qemu") as J[]).sort((a, b) => Number(a.vmid) - Number(b.vmid));
      const cfgs = await Promise.all(vms.map((v) => api.n(`/qemu/${v.vmid}/config`).catch(() => ({})))) as J[];
      const jobs = await api.get<J[]>("/cluster/backup").catch(() => [] as J[]);
      const files = await backupFiles(api).catch(() => [] as J[]);
      const ours = vmidList(o.ours ?? d.env.PVE_OURS);
      const nowS = Math.floor(Date.now() / 1000);
      if (o.onlyOurs && !ours.length) return fail("--only-ours needs a VM list: maw proxmox config set ours=101,102 (or --ours 101,102)");
      const rowsAll = vms.map((v, i) => {
        const c = cfgs[i] ?? {};
        const id = Number(v.vmid);
        const covered = jobs.some((j) => jobCovers(j, id));
        const mine = files.filter((f) => Number(f.vmid) === id);
        const newest = mine.length ? Math.max(...mine.map((f) => Number(f.ctime ?? 0))) : 0;
        const note = String(c.description ?? "").split("\n").map((l) => l.trim()).find((l) => l && !l.startsWith("<")) ?? "";
        return {
          vmid: id, name: v.name, status: v.status, ours: ours.includes(id), cpus: v.cpus, maxmem: v.maxmem, maxdisk: v.maxdisk,
          ostype: c.ostype ?? "", tags: c.tags ?? "", note, backup_job: covered,
          backup_newest: newest || null, backup_age_days: newest ? Math.floor((nowS - newest) / 86400) : null,
        };
      });
      const rows = o.onlyOurs ? rowsAll.filter((x) => x.ours) : rowsAll;
      if (o.json) return js(rows);
      return ok(table(["vmid", "name", "status", "ours", "cpus", "mem", "disk", "os", "backup", "note"],
        rows.map((r) => [r.vmid, String(r.name ?? "").slice(0, 26), r.status, r.ours ? "*" : "", r.cpus, bytes(r.maxmem), bytes(r.maxdisk),
          r.ostype || "-", !r.backup_job ? "none" : r.backup_age_days === null ? "no file" : `${r.backup_age_days}d`, r.note.slice(0, 60) || "-"])));
    }

    if (o.verb === "tasks") {
      const q = new URLSearchParams({ limit: String(o.limit), ...(o.failed ? { errors: "1" } : {}) });
      let ts_ = await api.n(`/tasks?${q}`) as J[];
      if (o.failed) ts_ = ts_.filter((t) => taskState(t) === "fail" || taskState(t) === "warn");
      const rows = ts_.map((t) => ({ ...t, state: taskState(t) }));
      if (o.json) return js(rows);
      const nf = rows.filter((t) => t.state === "fail").length;
      const body = table(["start", "end", "type", "id", "user", "state", "status"],
        rows.map((t) => [ts(t.starttime), ts(t.endtime), t.type, t.id || "-", t.user, t.state === "fail" ? "FAIL" : t.state.toUpperCase(), t.status ?? "running"]));
      const tail = nf ? `\n\n${nf} failed — maw proxmox task-log <upid>; upids: maw proxmox tasks --failed --json` : "";
      return ok(body + tail);
    }

    if (o.verb === "task-log") {
      const upid = o.rest[0];
      if (!upid || !upid.startsWith("UPID:")) return fail("usage: maw proxmox task-log <UPID:...>");
      const nodeFromUpid = upid.split(":")[1];
      if (!d.env.PVE_NODE && nodeFromUpid) api.node = nodeFromUpid;
      const lines = await api.n(`/tasks/${encodeURIComponent(upid)}/log?limit=5000`) as J[];
      if (o.json) return js(lines);
      return ok(lines.map((l) => l.t).join("\n"));
    }

    if (o.verb === "backups") {
      const [jobs, files] = await Promise.all([api.get<J[]>("/cluster/backup"), backupFiles(api)]);
      if (o.json) return js({ jobs, files });
      const jt = table(["id", "enabled", "schedule", "storage", "mode", "vms", "next"],
        jobs.map((j) => [j.id, Number(j.enabled ?? 1) ? "yes" : "no", j.schedule, j.storage, j.mode,
          Number(j.all ?? 0) ? `all${j.exclude ? ` -${j.exclude}` : ""}` : j.pool ? `pool:${j.pool}` : j.vmid, ts(j["next-run"])]));
      const ft = table(["created", "vmid", "storage", "size", "volid"], files.map((f) => [ts(f.ctime), f.vmid, f.storage, bytes(f.size), f.volid]));
      return ok(`backup jobs (${jobs.length})\n${jt}\n\nbackup archives (${files.length})\n${ft}`);
    }

    if (o.verb === "ours") {
      const want = vmidList(o.ours ?? d.env.PVE_OURS);
      if (!want.length) return fail("no VM list: set PVE_OURS=101,102 or pass --ours 101,102");
      const [vms, jobs, files] = await Promise.all([api.n("/qemu") as Promise<J[]>, api.get<J[]>("/cluster/backup"), backupFiles(api)]);
      const rows = want.map((id) => {
        const v = vms.find((x) => Number(x.vmid) === id);
        const mine = files.filter((f) => Number(f.vmid) === id);
        const covering = jobs.filter((j) => jobCovers(j, id)).map((j) => j.id);
        return {
          vmid: id, name: v?.name ?? null, status: v?.status ?? "missing", uptime: v?.uptime ?? null,
          jobs: covering, archives: mine.length, latest: mine[0]?.ctime ?? null, latestSize: mine[0]?.size ?? null,
        };
      });
      if (o.json) return js(rows);
      const warn = rows.filter((r) => r.status !== "missing" && (!r.jobs.length || !r.archives));
      return ok(table(["vmid", "name", "status", "uptime", "jobs", "archives", "latest backup", "size"],
        rows.map((r) => [r.vmid, r.name, r.status, dur(r.uptime), r.jobs.join(",") || "NONE", r.archives, ts(r.latest), bytes(r.latestSize)]))
        + (warn.length ? `\n\nno backup coverage: ${warn.map((r) => r.vmid).join(", ")}` : ""));
    }

    if (o.verb === "storage") {
      const ss = (await api.n("/storage") as J[]).sort((a, b) => String(a.storage).localeCompare(String(b.storage)));
      if (o.json) return js(ss);
      return ok(table(["storage", "type", "active", "used", "total", "avail", "use%", "content"],
        ss.map((s) => [s.storage, s.type, Number(s.active ?? 0) ? "yes" : "no", bytes(s.used), bytes(s.total), bytes(s.avail), pct(s.used, s.total), s.content])));
    }
    return fail(`unknown command: ${o.verb}`);
  } catch (e) {
    return fail((e as Error).message);
  }
}

// ---------- real deps ----------
export function tcpProbe(host: string, port: number, timeoutMs: number): Promise<ProbeResult> {
  const net = require("node:net") as typeof import("node:net");
  return new Promise((resolve) => {
    const s = new net.Socket();
    let done = false;
    const end = (r: ProbeResult) => { if (!done) { done = true; s.destroy(); resolve(r); } };
    s.setTimeout(timeoutMs, () => end("silent"));
    s.once("connect", () => end("open"));
    s.once("error", (e: NodeJS.ErrnoException) => end(e.code === "ECONNREFUSED" ? "refused" : "silent"));
    s.connect(port, host);
  });
}
async function pingOnce(host: string): Promise<boolean | null> {
  if (!Bun.which("ping")) return null;
  // macOS ping -W is milliseconds, Linux -W is seconds
  const args = process.platform === "darwin" ? ["-c", "1", "-W", "1000"] : ["-c", "1", "-W", "1"];
  const p = Bun.spawn(["ping", ...args, host], { stdout: "ignore", stderr: "ignore" });
  const t = setTimeout(() => p.kill(), 3000);
  const code = await p.exited;
  clearTimeout(t);
  return code === 0;
}
function realCreateDeps(): Omit<CreateDeps, "env" | "log"> {
  const fs = require("node:fs") as typeof import("node:fs");
  const os = require("node:os") as typeof import("node:os");
  return {
    probe: tcpProbe, ping: pingOnce, sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
    readFile: (p) => { try { return fs.readFileSync(p.replace(/^~(?=\/)/, os.homedir()), "utf8"); } catch { return null; } },
    hostname: () => os.hostname(), today: () => new Date().toISOString().slice(0, 10),
  };
}
function passShow(entry: string): string | null {
  try {
    const p = Bun.spawnSync(["pass", "show", entry], { stdout: "pipe", stderr: "pipe" });
    if (p.exitCode !== 0) return null;
    const first = p.stdout.toString().split("\n")[0]?.trim();
    return first || null;
  } catch {
    return null;
  }
}

export function fileStore(env: Env = process.env): Store {
  const { readFileSync, writeFileSync, mkdirSync, chmodSync, existsSync, renameSync } = require("node:fs") as typeof import("node:fs");
  const { join, dirname } = require("node:path") as typeof import("node:path");
  const home = env.HOME ?? "";
  const cfgPath = join(env.XDG_CONFIG_HOME || join(home, ".config"), "maw-proxmox", "config.json");
  const tktPath = join(env.XDG_CACHE_HOME || join(home, ".cache"), "maw-proxmox", "ticket.json");
  const read = (p: string): J | null => { try { return JSON.parse(readFileSync(p, "utf8")); } catch { return null; } };
  const write = (p: string, v: J) => {
    mkdirSync(dirname(p), { recursive: true, mode: 0o700 });
    const tmp = `${p}.tmp`;
    writeFileSync(tmp, JSON.stringify(v, null, 2) + "\n", { mode: 0o600 });
    chmodSync(tmp, 0o600); renameSync(tmp, p);
  };
  return {
    configPath: () => cfgPath,
    readConfig: () => read(cfgPath) ?? {},
    writeConfig: (c) => write(cfgPath, c),
    readTicket: () => read(tktPath),
    writeTicket: (t) => { if (t) write(tktPath, t); else if (existsSync(tktPath)) write(tktPath, {}); },
    now: () => Date.now(),
  };
}

// maw prints a plugin's returned output and exits right away; when stdout is a pipe only the first
// 64 KiB (one pipe buffer) gets out — `tasks --json --limit 300` was cut mid-string (2026-11-11).
// Big CLI output is therefore written here, synchronously, before returning.
export const DIRECT_WRITE_BYTES = 16 * 1024;
export function writeAllSync(fd: number, text: string, write: (fd: number, b: Uint8Array) => number = defaultWrite): void {
  const buf = new TextEncoder().encode(text);
  let off = 0, spins = 0;
  while (off < buf.length) {
    try {
      const n = write(fd, buf.subarray(off));
      off += n; spins = 0;
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "EAGAIN" && spins++ < 10000) { Bun.sleepSync(1); continue; }
      throw e;
    }
  }
}
function defaultWrite(fd: number, b: Uint8Array): number {
  return (require("node:fs") as typeof import("node:fs")).writeSync(fd, b);
}

export async function handler(ctx: InvokeContext): Promise<PluginResult> {
  const r = await run(ctx.args, { env: process.env, fetch: fetch as unknown as FetchFn, pass: passShow, log: (s) => console.error(s), store: fileStore() });
  if (ctx.source === "cli" && r.output && r.output.length > DIRECT_WRITE_BYTES) {
    writeAllSync(1, r.output.endsWith("\n") ? r.output : r.output + "\n");
    return { ok: r.ok, ...(r.error ? { error: r.error } : {}) };
  }
  return r;
}

export default handler;

if (import.meta.main) {
  const result = await handler({ source: "cli", args: process.argv.slice(2) });
  if (result.output) console.log(result.output);
  if (result.error) console.error(result.error);
  process.exit(result.ok ? 0 : 1);
}
