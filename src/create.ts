// maw proxmox create — guarded VM creation. Writes live only here and in src/firewall.ts (which reuses send()).
//
//   maw proxmox create haos   --vmid N --name NAME --ip A.B.C.D/24 [options] [--apply --yes]
//   maw proxmox create ubuntu --vmid N --name NAME --ip A.B.C.D/24 --ssh-key PATH [options] [--apply --yes]
//
// Default is PLAN ONLY: every preflight check is run (GET requests + local probes) and the exact API calls
// that would be sent are printed. Nothing is written unless BOTH --apply and --yes are given AND every check
// passes. Ported from two scripts proven on a real host (HAOS via console sendkey, Ubuntu via cloud-init).

import type { Api } from "./index";

type J = Record<string, any>;
type Env = Record<string, string | undefined>;
export type ProbeResult = "open" | "refused" | "silent";
export type CreateDeps = {
  env: Env;
  log: (s: string) => void;
  /** TCP connect to host:port. "refused" (RST) still means a host answered. */
  probe: (host: string, port: number, timeoutMs: number) => Promise<ProbeResult>;
  /** true = replied, false = no reply, null = ping not available here */
  ping: (host: string) => Promise<boolean | null>;
  sleep: (ms: number) => Promise<void>;
  readFile: (path: string) => string | null;
  hostname: () => string;
  today: () => string;
};

export type Call = { method: "GET" | "POST" | "PUT"; path: string; params?: Record<string, string>; note?: string };
export type Check = { name: string; ok: boolean; detail: string };

const HAOS_DEFAULTS = { cores: 2, ram: 2048, disk: 48, image: "haos_ova-18.2.qcow2" };
const UBUNTU_DEFAULTS = { cores: 2, ram: 2048, disk: 40, image: "noble-server-cloudimg-amd64.qcow2" };
const PROBE_PORTS = [22, 80, 443];
const GIB = 2 ** 30;

export const ONBOARDING_WARNING = "HAOS onboarding is open until the first user is created";

// ---------- ipv4 ----------
export function ip2int(ip: string): number | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip.trim());
  if (!m) return null;
  const p = m.slice(1).map(Number);
  if (p.some((x) => x > 255)) return null;
  return ((p[0]! << 24) >>> 0) + (p[1]! << 16) + (p[2]! << 8) + p[3]!;
}
export function parseCidr(s: string): { ip: string; addr: number; bits: number } | null {
  const [ip, b] = s.trim().split("/");
  const addr = ip2int(ip ?? "");
  const bits = Number(b);
  if (addr === null || b === undefined || !Number.isInteger(bits) || bits < 1 || bits > 32) return null;
  return { ip: ip!, addr, bits };
}
const mask = (bits: number) => (bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0);
export function inNet(ip: number, net: string): boolean {
  const n = parseCidr(net);
  if (!n) return false;
  return ((ip & mask(n.bits)) >>> 0) === ((n.addr & mask(n.bits)) >>> 0);
}
export const netList = (s: string | undefined) => (s ?? "").split(/[\s,]+/).filter(Boolean);

// ---------- sendkey ----------
// Same keymap as the proven pve-sendkeys.sh (US layout): '-' '.' '/' and digits are unshifted keys.
const KEYS: Record<string, string> = {
  " ": "spc", "-": "minus", ".": "dot", "/": "slash", ",": "comma", "=": "equal", ";": "semicolon", "'": "apostrophe",
  "[": "bracket_left", "]": "bracket_right", "\\": "backslash", "`": "grave_accent",
  ":": "shift-semicolon", "_": "shift-minus", "+": "shift-equal", "?": "shift-slash", "\"": "shift-apostrophe",
  "<": "shift-comma", ">": "shift-dot", "|": "shift-backslash", "~": "shift-grave_accent",
  "!": "shift-1", "@": "shift-2", "#": "shift-3", "$": "shift-4", "%": "shift-5", "^": "shift-6", "&": "shift-7",
  "*": "shift-8", "(": "shift-9", ")": "shift-0",
};
export function charKey(c: string): string | null {
  if (/^[a-z0-9]$/.test(c)) return c;
  if (/^[A-Z]$/.test(c)) return `shift-${c.toLowerCase()}`;
  return KEYS[c] ?? null;
}
/** QEMU keynames for typing `text` then Enter. Throws on a character that has no key (nothing is skipped silently). */
export function sendkeySequence(text: string): string[] {
  const out: string[] = [];
  for (const c of text) {
    const k = charKey(c);
    if (!k) throw new Error(`no QEMU key for character ${JSON.stringify(c)} in console command`);
    out.push(k);
  }
  out.push("ret");
  return out;
}

/** Sent before typing: release any modifier a console viewer left held, then clear the ha> line. */
export const RESET_KEYS = ["shift", "shift_r", "ctrl", "ctrl_r", "alt", "alt_r", "ctrl-u"];
export const KEY_DELAY_MS = 150;

export function haosNetworkCommand(iface: string, ipCidr: string, gw: string, dns: string[]): string {
  return `network update ${iface} --ipv4-method static --ipv4-address ${ipCidr} --ipv4-gateway ${gw}` +
    dns.map((n) => ` --ipv4-nameserver ${n}`).join("");
}

/** Percent-encode like Python urllib.parse.quote(s, safe=''). URLSearchParams then encodes once more on the
 *  wire, the API decodes once, and Proxmox gets the percent-encoded key it stores (pve-vm-install.sh). */
export function encodeSshKeys(s: string): string {
  return encodeURIComponent(s).replace(/[!'()*]/g, (c) => "%" + c.charCodeAt(0).toString(16).toUpperCase());
}
export function looksLikePublicKey(s: string): boolean {
  if (/PRIVATE KEY/.test(s)) return false;
  const lines = s.trim().split("\n").filter((l) => l.trim() && !l.trim().startsWith("#"));
  if (!lines.length) return false;
  return lines.every((l) => /^(ssh-(ed25519|rsa|dss)|ecdsa-sha2-nistp(256|384|521)|sk-(ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com) [A-Za-z0-9+/]+=*( .*)?$/.test(l.trim()));
}

// ---------- args ----------
export type CreateOpts = {
  kind: "haos" | "ubuntu"; vmid: number; name: string; ipCidr: string; gw: string; dns: string[];
  cores: number; ram: number; disk: number; image: string; storageVm: string; storageImg: string; bridge: string;
  sshKey?: string; ciuser: string; iface: string; waitMin: number; bootWaitS: number; apply: boolean; yes: boolean;
};

export function parseCreate(rest: string[], env: Env): CreateOpts | string {
  const kind = rest[0];
  if (kind !== "haos" && kind !== "ubuntu") return "usage: maw proxmox create haos|ubuntu --vmid N --name NAME --ip A.B.C.D/24 [...] (see --help)";
  const def = kind === "haos" ? HAOS_DEFAULTS : UBUNTU_DEFAULTS;
  const f: Record<string, string> = {};
  let apply = false, yes = false;
  const valued = ["vmid", "name", "ip", "gw", "dns", "cores", "ram", "disk", "image", "storage-vm", "storage-img", "bridge", "ssh-key", "ciuser", "iface", "wait-min", "boot-wait"];
  for (let i = 1; i < rest.length; i++) {
    const a = rest[i]!;
    if (a === "--apply") { apply = true; continue; }
    if (a === "--yes" || a === "-y") { yes = true; continue; }
    const m = /^--([a-z-]+)(?:=(.*))?$/.exec(a);
    if (!m || !valued.includes(m[1]!)) return `unknown option for create: ${a}`;
    const v = m[2] ?? rest[++i];
    if (v === undefined) return `--${m[1]} needs a value`;
    f[m[1]!] = v;
  }
  const num = (k: string, d: number) => (f[k] === undefined ? d : Number(f[k]));
  const o: CreateOpts = {
    kind, vmid: num("vmid", NaN), name: f.name ?? "", ipCidr: f.ip ?? "",
    gw: f.gw ?? env.PVE_GW ?? "", dns: netList(f.dns ?? env.PVE_DNS ?? "1.1.1.1,8.8.8.8"),
    cores: num("cores", def.cores), ram: num("ram", def.ram), disk: num("disk", def.disk), image: f.image ?? def.image,
    storageVm: f["storage-vm"] ?? env.PVE_STORAGE_VM ?? "ssd", storageImg: f["storage-img"] ?? env.PVE_STORAGE_IMG ?? "local",
    bridge: f.bridge ?? env.PVE_BRIDGE ?? "vmbr0", sshKey: f["ssh-key"], ciuser: f.ciuser ?? "ubuntu",
    iface: f.iface ?? "enp6s18", waitMin: num("wait-min", 5), bootWaitS: num("boot-wait", 150), apply, yes,
  };
  return o;
}

// ---------- the call list (plan and apply use the same one) ----------
export function createParams(o: CreateOpts, today: string, sshKeyText?: string): Record<string, string> {
  const disk0 = `${o.storageVm}:0,import-from=${o.storageImg}:import/${o.image},discard=on,ssd=1`;
  if (o.kind === "haos") {
    return {
      vmid: String(o.vmid), name: o.name, ostype: "l26", machine: "q35", bios: "ovmf",
      efidisk0: `${o.storageVm}:0,efitype=4m,pre-enrolled-keys=0`,
      cores: String(o.cores), sockets: "1", cpu: "host", memory: String(o.ram), scsihw: "virtio-scsi-pci",
      scsi0: disk0, net0: `virtio,bridge=${o.bridge}`, agent: "1", onboot: "1", tablet: "0", localtime: "1",
      boot: "order=scsi0",
      description: `Home Assistant OS (${o.image}) - created by maw proxmox create haos on ${today}.`,
    };
  }
  return {
    vmid: String(o.vmid), name: o.name, ostype: "l26",
    cores: String(o.cores), sockets: "1", cpu: "host", memory: String(o.ram), scsihw: "virtio-scsi-pci",
    scsi0: disk0, ide2: `${o.storageVm}:cloudinit,media=cdrom`, net0: `virtio,bridge=${o.bridge}`,
    ipconfig0: `ip=${o.ipCidr},gw=${o.gw}`, nameserver: o.dns.join(" "), ciuser: o.ciuser,
    sshkeys: encodeSshKeys((sshKeyText ?? "").trim()),
    agent: "1", onboot: "1", boot: "order=scsi0",
    description: `Ubuntu cloud image (${o.image}) - created by maw proxmox create ubuntu on ${today}. cpu=host.`,
  };
}

export function plannedCalls(o: CreateOpts, node: string, today: string, sshKeyText?: string): Call[] {
  const n = `/nodes/${encodeURIComponent(node)}`;
  const calls: Call[] = [
    { method: "POST", path: `${n}/qemu`, params: createParams(o, today, sshKeyText), note: "create VM + import disk (returns a task UPID)" },
    { method: "GET", path: `${n}/tasks/<upid>/status`, note: "poll until stopped; exitstatus must be OK" },
    { method: "PUT", path: `${n}/qemu/${o.vmid}/resize`, params: { disk: "scsi0", size: `${o.disk}G` }, note: "imported disk is the image's size; grow it" },
    { method: "POST", path: `${n}/qemu/${o.vmid}/status/start`, note: "start (task UPID, waited)" },
    { method: "GET", path: `${n}/qemu/${o.vmid}/status/current`, note: "must be running" },
  ];
  if (o.kind === "haos") {
    const cmd = haosNetworkCommand(o.iface, o.ipCidr, o.gw, o.dns);
    const keys = sendkeySequence(cmd);
    calls.push({ method: "PUT", path: `${n}/qemu/${o.vmid}/sendkey`, params: { key: "<one per key>" },
      note: `after ${o.bootWaitS}s boot wait: ${keys.length} keys typing at the ha> prompt: ${cmd} + Enter` });
  }
  return calls;
}

// ---------- preflight ----------
const gib = (b: number) => `${(b / GIB).toFixed(1)}G`;

function guestIps(cfg: J): string[] {
  const out: string[] = [];
  for (const [k, v] of Object.entries(cfg)) {
    if (!/^(ipconfig|net)\d+$/.test(k)) continue;
    const m = /(?:^|,)ip=([0-9.]+)/.exec(String(v));
    if (m) out.push(m[1]!);
  }
  return out;
}

export async function preflight(api: Api, o: CreateOpts, d: CreateDeps): Promise<{ checks: Check[]; node: string; sshKeyText?: string }> {
  const checks: Check[] = [];
  const add = (name: string, ok: boolean, detail: string) => checks.push({ name, ok, detail });
  const node = await api.nodeName();
  const N = `/nodes/${encodeURIComponent(node)}`;

  // 0. arguments
  const argErr: string[] = [];
  if (!Number.isInteger(o.vmid) || o.vmid < 100 || o.vmid > 999999999) argErr.push("--vmid must be an integer >= 100");
  if (!/^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/.test(o.name)) argErr.push("--name must be a DNS name (letters, digits, '-')");
  for (const [k, v] of [["cores", o.cores], ["ram", o.ram], ["disk", o.disk]] as const)
    if (!Number.isInteger(v) || v < 1) argErr.push(`--${k} must be a positive integer`);
  if (o.ram < 512) argErr.push("--ram is in MiB and must be >= 512");
  add("arguments", !argErr.length, argErr.join("; ") || `vmid ${o.vmid} name ${o.name} cores ${o.cores} ram ${o.ram}M disk ${o.disk}G`);

  // 1. vmid free
  const [qemu, lxc] = await Promise.all([api.get<J[]>(`${N}/qemu`), api.get<J[]>(`${N}/lxc`).catch(() => [] as J[])]);
  const guests = [...qemu.map((g) => ({ ...g, type: "qemu" })), ...lxc.map((g) => ({ ...g, type: "lxc" }))];
  const clash = guests.find((g) => Number(g.vmid) === o.vmid);
  add("vmid free", !clash, clash ? `${o.vmid} is already ${clash.type} "${clash.name ?? ""}" (${clash.status})` : `${o.vmid} not used by any of ${qemu.length} qemu / ${lxc.length} lxc guests`);
  const sameName = guests.find((g) => String(g.name ?? "") === o.name);
  add("name free", !sameName, sameName ? `"${o.name}" is already vmid ${sameName.vmid}` : `no guest is named "${o.name}"`);

  // 2. ip: allowed, not denied, silent, not configured on any guest
  const c = parseCidr(o.ipCidr);
  const allowed = netList(d.env.PVE_ALLOWED_NETS), denied = netList(d.env.PVE_DENY_NETS);
  if (!c) {
    add("ip allowed", false, `--ip must be A.B.C.D/NN, got "${o.ipCidr}"`);
  } else {
    const hostPart = (c.addr & ~mask(c.bits)) >>> 0;
    const broadcast = (~mask(c.bits)) >>> 0;
    const inAllowed = allowed.find((n) => inNet(c.addr, n));
    const inDenied = denied.find((n) => inNet(c.addr, n));
    const why = !allowed.length ? "no allowed_nets configured (maw proxmox config set allowed_nets=A.B.C.0/24) - refusing every IP"
      : inDenied ? `${c.ip} is inside deny_nets ${inDenied}`
      : !inAllowed ? `${c.ip} is outside allowed_nets ${allowed.join(",")}`
      : c.bits < 31 && (hostPart === 0 || hostPart === broadcast) ? `${c.ip} is the network or broadcast address of /${c.bits}`
      : "";
    add("ip allowed", !why, why || `${c.ip} in ${inAllowed}${denied.length ? `; not in deny_nets ${denied.join(",")}` : ""}`);

    const gwInt = ip2int(o.gw);
    const gwWhy = !o.gw ? "no gateway: pass --gw or maw proxmox config set gw=A.B.C.D"
      : gwInt === null ? `--gw is not an IPv4 address: ${o.gw}`
      : !inNet(gwInt, `${c.ip}/${c.bits}`) ? `gateway ${o.gw} is outside ${c.ip}/${c.bits}` : gwInt === c.addr ? "gateway equals the new IP" : "";
    const dnsBad = o.dns.filter((x) => ip2int(x) === null);
    add("gateway / dns", !gwWhy && !dnsBad.length && o.dns.length > 0,
      gwWhy || (dnsBad.length ? `bad dns: ${dnsBad.join(",")}` : !o.dns.length ? "no dns" : `gw ${o.gw} dns ${o.dns.join(",")}`));

    const res = await Promise.all(PROBE_PORTS.map(async (p) => [p, await d.probe(c.ip, p, 1200)] as const));
    const pong = await d.ping(c.ip);
    const answered = res.filter(([, r]) => r !== "silent").map(([p, r]) => `tcp ${p} ${r}`);
    if (pong) answered.push("ping replied");
    add("ip silent", !answered.length, answered.length ? `${c.ip} answers: ${answered.join(", ")}`
      : `tcp ${PROBE_PORTS.join("/")} no answer, ping ${pong === null ? "not available" : "no reply"} (probed from ${d.hostname()})`);

    // configured addresses: cloud-init ipconfigN / lxc netN, plus guest-agent addresses of running VMs
    const cfgs = await Promise.all([
      ...qemu.map((g) => ({ ...g, type: "qemu" })).map((g) => api.get<J>(`${N}/qemu/${g.vmid}/config`).then((x) => ({ g, x })).catch(() => ({ g, x: {} as J }))),
      ...lxc.map((g) => ({ ...g, type: "lxc" })).map((g) => api.get<J>(`${N}/lxc/${g.vmid}/config`).then((x) => ({ g, x })).catch(() => ({ g, x: {} as J }))),
    ]);
    const known: { ip: string; vmid: number; src: string }[] = [];
    for (const { g, x } of cfgs) for (const ip of guestIps(x)) known.push({ ip, vmid: Number(g.vmid), src: "config" });
    const agentVms = cfgs.filter(({ g, x }) => g.type === "qemu" && g.status === "running" && /^(1|enabled=1)/.test(String(x.agent ?? "")));
    let agentAnswered = 0;
    await Promise.all(agentVms.map(async ({ g }) => {
      const r = await api.get<J>(`${N}/qemu/${g.vmid}/agent/network-get-interfaces`).catch(() => null);
      if (!r) return;
      agentAnswered++;
      for (const ifc of (r.result ?? []) as J[]) for (const a of (ifc["ip-addresses"] ?? []) as J[])
        if (a["ip-address-type"] === "ipv4") known.push({ ip: String(a["ip-address"]), vmid: Number(g.vmid), src: "agent" });
    }));
    const hit = known.find((k) => k.ip === c.ip);
    add("ip not on a guest", !hit, hit ? `${c.ip} is configured on vmid ${hit.vmid} (${hit.src})`
      : `not in any guest ipconfig/net (${cfgs.length} configs) or guest-agent address (${agentAnswered}/${agentVms.length} agents answered)`);
  }

  // 3. RAM headroom
  const st = await api.get<J>(`${N}/status`);
  const total = Number(st.memory?.total ?? 0);
  const reserveGib = d.env.PVE_RAM_RESERVE_GIB !== undefined && d.env.PVE_RAM_RESERVE_GIB !== "" ? Number(d.env.PVE_RAM_RESERVE_GIB) : 5;
  const running = guests.filter((g) => g.status === "running");
  const used = running.reduce((s, g) => s + Number(g.maxmem ?? 0), 0);
  const want = o.ram * 2 ** 20;
  const limit = total - reserveGib * GIB;
  add("ram headroom", Number.isFinite(reserveGib) && total > 0 && used + want <= limit,
    `running guests ${gib(used)} (${running.length}) + new ${gib(want)} = ${gib(used + want)} ${used + want <= limit ? "<=" : ">"} ` +
    `physical ${gib(total)} - reserve ${reserveGib}G = ${gib(limit)}`);

  // 4. storage
  const stores = await api.get<J[]>(`${N}/storage`);
  const sv = stores.find((s) => s.storage === o.storageVm);
  const need = o.disk * GIB * 1.1;
  add("storage space", !!sv && Number(sv.active ?? 1) !== 0 && Number(sv.avail ?? 0) >= need,
    !sv ? `storage "${o.storageVm}" not found on ${node}` : Number(sv.active ?? 1) === 0 ? `storage "${o.storageVm}" is not active`
      : `${o.storageVm} avail ${gib(Number(sv.avail ?? 0))} ${Number(sv.avail ?? 0) >= need ? ">=" : "<"} ${gib(need)} (${o.disk}G + 10%)`);

  // 5. image
  const volid = `${o.storageImg}:import/${o.image}`;
  const content = await api.get<J[]>(`${N}/storage/${encodeURIComponent(o.storageImg)}/content?content=import`).catch(() => null);
  const have = !!content?.some((x) => x.volid === volid);
  add("image present", have, have ? volid
    : content === null ? `cannot list ${o.storageImg} content=import`
    : `${volid} not found; import images: ${content.map((x) => x.volid).join(", ") || "(none)"}`);

  // 6. ssh key (ubuntu)
  let sshKeyText: string | undefined;
  if (o.kind === "ubuntu") {
    if (!o.sshKey) add("ssh key", false, "--ssh-key PATH is required for ubuntu");
    else {
      const t = d.readFile(o.sshKey);
      const good = t !== null && looksLikePublicKey(t);
      if (good) sshKeyText = t!.trim();
      add("ssh key", good, t === null ? `cannot read ${o.sshKey}` : good ? `${o.sshKey}: ${t!.trim().split(/\s+/)[0]} public key` : `${o.sshKey} does not look like an OpenSSH public key`);
    }
  }
  return { checks, node, sshKeyText };
}

// ---------- render ----------
function shortParam(k: string, v: string): string {
  if (k === "sshkeys") return `${v.slice(0, 32)}... (${v.length} chars, percent-encoded once here; the form encoding adds the second layer)`;
  return v;
}
export function renderPlan(o: CreateOpts, node: string, checks: Check[], calls: Call[], mode: string): string {
  const w = Math.max(...checks.map((c) => c.name.length));
  const lines = [
    `maw proxmox create ${o.kind} - ${mode}`,
    "",
    `target  node ${node}  vmid ${o.vmid}  name ${o.name}  ip ${o.ipCidr}  gw ${o.gw || "-"}  dns ${o.dns.join(",")}`,
    `        cores ${o.cores}  ram ${o.ram}M  disk ${o.disk}G  image ${o.storageImg}:import/${o.image}  vm storage ${o.storageVm}  bridge ${o.bridge}`,
    "",
    "checks",
    ...checks.map((c) => `  ${c.ok ? "PASS" : "FAIL"}  ${c.name.padEnd(w)}  ${c.detail}`),
    "",
    "api calls that --apply --yes would send, in order",
  ];
  calls.forEach((c, i) => {
    lines.push(`  ${i + 1}. ${c.method.padEnd(4)} ${c.path}${c.note ? `    # ${c.note}` : ""}`);
    if (c.params) for (const [k, v] of Object.entries(c.params)) lines.push(`        ${k}=${shortParam(k, v)}`);
  });
  lines.push("", "verify after apply: task exitstatus OK, VM running, " +
    (o.kind === "haos" ? `ping/tcp on ${o.ipCidr.split("/")[0]} within ${o.waitMin} min, observer :4357, :80/:8123` : `tcp 22 open on ${o.ipCidr.split("/")[0]} within ${o.waitMin} min`));
  if (o.kind === "haos") lines.push(`warning: ${ONBOARDING_WARNING}`);
  return lines.join("\n");
}

// ---------- apply ----------
export async function send(api: Api, method: "POST" | "PUT", path: string, params: Record<string, string> = {}): Promise<any> {
  const h = await api.writeHeaders();
  const r = await api.fetchRaw(path, { method, body: new URLSearchParams(params), headers: { ...h, "Content-Type": "application/x-www-form-urlencoded" } });
  const text = await r.text();
  if (!r.ok) throw new Error(`${method} ${path} -> HTTP ${r.status}: ${text.slice(0, 300)}`);
  try { return (JSON.parse(text) as J).data; } catch { return null; }
}

async function waitTask(api: Api, d: CreateDeps, node: string, upid: unknown, label: string, maxMs = 30 * 60 * 1000): Promise<void> {
  if (typeof upid !== "string" || !upid.startsWith("UPID:")) return; // synchronous call, nothing to wait for
  const path = `/nodes/${encodeURIComponent(node)}/tasks/${encodeURIComponent(upid)}/status`;
  for (let waited = 0; waited <= maxMs; waited += 3000) {
    const s = await api.get<J>(path);
    if (s.status === "stopped") {
      if (s.exitstatus !== "OK") throw new Error(`${label} task failed: ${s.exitstatus} (maw proxmox task-log '${upid}')`);
      d.log(`${label}: OK`);
      return;
    }
    await d.sleep(3000);
  }
  throw new Error(`${label} task still running after ${Math.round(maxMs / 60000)} min: ${upid}`);
}

async function waitFor(d: CreateDeps, minutes: number, f: () => Promise<boolean>): Promise<number | null> {
  const t = Math.max(1, Math.round((minutes * 60) / 5));
  for (let i = 0; i < t; i++) {
    if (await f()) return i * 5;
    await d.sleep(5000);
  }
  return null;
}

export async function applyCreate(api: Api, o: CreateOpts, d: CreateDeps, node: string, calls: Call[]): Promise<string[]> {
  const summary: string[] = [];
  const ip = o.ipCidr.split("/")[0]!;
  const [create, , resize, start, status] = calls as [Call, Call, Call, Call, Call];
  d.log(`creating VM ${o.vmid} (${o.name})`);
  await waitTask(api, d, node, await send(api, "POST", create.path, create.params), "vm create");
  d.log(`resizing scsi0 to ${o.disk}G`);
  await waitTask(api, d, node, await send(api, "PUT", resize.path, resize.params), "resize");
  d.log(`starting VM ${o.vmid}`);
  await waitTask(api, d, node, await send(api, "POST", start.path), "start");
  const cur = await api.get<J>(status.path);
  if (cur.status !== "running") throw new Error(`VM ${o.vmid} is ${cur.status} after start, expected running`);
  summary.push(`vm ${o.vmid} ${o.name}: created, disk ${o.disk}G, running`);

  if (o.kind === "haos") {
    d.log(`waiting ${o.bootWaitS}s for the HAOS ha> prompt`);
    await d.sleep(o.bootWaitS * 1000);
    const cmd = haosNetworkCommand(o.iface, o.ipCidr, o.gw, o.dns);
    const keys = sendkeySequence(cmd);
    d.log(`typing on the console (${keys.length} keys): ${cmd}`);
    const sk = `/nodes/${encodeURIComponent(node)}/qemu/${o.vmid}/sendkey`;
    // A console viewer (noVNC) left open can inject a modifier mid-typing: a Cmd-Shift-4 screenshot on the
    // human's Mac left Shift held and every key after it came out shifted (2026-11-11, VM 115). Release
    // every modifier and clear the line first, and type slower than the proven 60 ms.
    for (const key of RESET_KEYS) { await send(api, "PUT", sk, { key }); await d.sleep(200); }
    for (const key of keys) { await send(api, "PUT", sk, { key }); await d.sleep(KEY_DELAY_MS); }
    await d.sleep(25000);
    const up = await waitFor(d, o.waitMin, async () => (await d.ping(ip)) === true || (await d.probe(ip, 4357, 2000)) !== "silent");
    summary.push(up === null ? `WARNING: ${ip} not answering after ${o.waitMin} min - open the console` : `${ip} answers (~${up + 25}s after typing)`);
    for (const p of [4357, 80, 8123]) summary.push(`  tcp ${p}: ${await d.probe(ip, p, 2000)}`);
    summary.push(`Home Assistant: http://${ip}:8123   observer: http://${ip}:4357 (Core download takes 5-20 min)`);
    summary.push(`warning: ${ONBOARDING_WARNING}`);
  } else {
    const up = await waitFor(d, o.waitMin, async () => (await d.probe(ip, 22, 3000)) === "open");
    summary.push(up === null ? `WARNING: tcp 22 on ${ip} not open after ${o.waitMin} min - the guest may be hung; check the console` : `ssh: tcp 22 open on ${ip} after ~${up}s (login: ${o.ciuser}@${ip})`);
  }
  return summary;
}

// ---------- entry ----------
export async function runCreate(api: Api, rest: string[], d: CreateDeps): Promise<{ ok: boolean; output?: string; error?: string }> {
  const o = parseCreate(rest, d.env);
  if (typeof o === "string") return { ok: false, error: o };
  const { checks, node, sshKeyText } = await preflight(api, o, d);
  const today = d.today();
  let calls: Call[];
  try { calls = plannedCalls(o, node, today, sshKeyText); }
  catch (e) { checks.push({ name: "console command", ok: false, detail: (e as Error).message }); calls = []; }
  const failed = checks.filter((c) => !c.ok);
  const mode = o.apply && o.yes ? "APPLY" : "PLAN ONLY (nothing is written; add --apply --yes to create)";
  const plan = renderPlan(o, node, checks, calls, mode);
  if (failed.length) return { ok: false, output: plan, error: `REFUSED: ${failed.length} check(s) failed: ${failed.map((c) => c.name).join(", ")}. Nothing was written.` };
  if (o.apply && !o.yes) return { ok: false, output: plan, error: "REFUSED: --apply needs --yes as well. Nothing was written." };
  if (!o.apply) return { ok: true, output: plan + "\n\nall checks passed. Nothing was written (plan only)." };
  try {
    const summary = await applyCreate(api, o, d, node, calls);
    return { ok: true, output: `${plan}\n\nresult\n${summary.map((s) => `  ${s}`).join("\n")}` };
  } catch (e) {
    return { ok: false, output: plan, error: `apply stopped: ${(e as Error).message}` };
  }
}
