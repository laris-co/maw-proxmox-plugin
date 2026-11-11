// maw proxmox firewall — view the Proxmox firewall, and lock one VM so only outbound-started traffic
// (for example a Tailscale tunnel) reaches it: inbound policy DROP at the VM firewall.
//
//   maw proxmox firewall [<vmid>] [--json]                           READ-ONLY (GET only)
//   maw proxmox firewall lock   <vmid> --name <expected> [--apply --yes]
//   maw proxmox firewall unlock <vmid> --name <expected> [--apply --yes]
//
// lock / unlock follow the same rule as create: default is PLAN ONLY (checks + the exact API calls, nothing
// written). Writes are sent only with BOTH --apply and --yes, and only when every check passes.
//
// Proxmox returns {} for options left at their defaults:
//   datacenter enable  default 0 (off)
//   node enable        default 1 - the host is filtered as soon as the datacenter firewall is on
//   VM enable          default 0 (off)
// A VM is filtered only when the datacenter firewall is on, its own firewall is on, AND the NIC has firewall=1.

import type { Api } from "./index";
import { send, type Call, type Check } from "./create";

type J = Record<string, any>;
type Env = Record<string, string | undefined>;
export type FirewallDeps = { env: Env; log: (s: string) => void; json: boolean };
type Result = { ok: boolean; output?: string; error?: string };

const on = (v: unknown) => v !== undefined && v !== null && v !== "" && Number(v) === 1;
const isOff = (v: unknown) => v !== undefined && v !== null && v !== "" && Number(v) === 0;
export const dcEnableText = (o: J) => (o.enable === undefined ? "default (off)" : on(o.enable) ? "1 (on)" : "0 (off)");
export const nodeEnableText = (o: J) => (o.enable === undefined ? "default (on when datacenter on)" : on(o.enable) ? "1 (on)" : "0 (off)");
export const vmEnableText = (o: J) => (on(o.enable) ? "on" : "off");

const netKeys = (cfg: J) => Object.keys(cfg).filter((k) => /^net\d+$/.test(k)).sort((a, b) => Number(a.slice(3)) - Number(b.slice(3)));
export const nicFirewallOn = (v: string) => /(^|,)firewall=1(,|$)/.test(v);
/** The NIC value with firewall on: the existing value byte-for-byte + ",firewall=1" (or an explicit
 *  firewall=0 flipped in place, since a duplicate key would be rejected). */
export function withFirewall(v: string): string {
  if (nicFirewallOn(v)) return v;
  if (/(^|,)firewall=0(,|$)/.test(v)) return v.replace(/(^|,)firewall=0(?=,|$)/, "$1firewall=1");
  return `${v},firewall=1`;
}
const others = (o: J) => Object.entries(o).filter(([k]) => k !== "enable" && k !== "digest").map(([k, v]) => `${k}=${v}`).join(" ");

type Guest = { type: "qemu" | "lxc"; vmid: number; name: string; cfg: J; fwNics: string[]; vmFw?: J };

async function gather(api: Api, node: string, withLxc: boolean) {
  const N = `/nodes/${encodeURIComponent(node)}`;
  const [dc, nodeOpts, dcRules, nodeRules, qemu, lxc] = await Promise.all([
    api.get<J>("/cluster/firewall/options"),
    api.get<J>(`${N}/firewall/options`),
    api.get<J[]>("/cluster/firewall/rules"),
    api.get<J[]>(`${N}/firewall/rules`),
    api.get<J[]>(`${N}/qemu`),
    withLxc ? api.get<J[]>(`${N}/lxc`).catch(() => [] as J[]) : Promise.resolve([] as J[]),
  ]);
  const list = [...qemu.map((g) => ({ g, type: "qemu" as const })), ...lxc.map((g) => ({ g, type: "lxc" as const }))]
    .sort((a, b) => Number(a.g.vmid) - Number(b.g.vmid));
  const guests: Guest[] = await Promise.all(list.map(async ({ g, type }) => {
    const cfg = await api.get<J>(`${N}/${type}/${g.vmid}/config`).catch(() => ({} as J));
    const fwNics = netKeys(cfg).filter((k) => nicFirewallOn(String(cfg[k])));
    const vmFw = fwNics.length ? await api.get<J>(`${N}/${type}/${g.vmid}/firewall/options`).catch(() => ({} as J)) : undefined;
    return { type, vmid: Number(g.vmid), name: String(g.name ?? cfg.name ?? cfg.hostname ?? ""), cfg, fwNics, vmFw };
  }));
  return { N, dc, nodeOpts, dcRules, nodeRules, guests };
}

// ---------- read ----------
async function show(api: Api, rest: string[], d: FirewallDeps): Promise<Result> {
  const node = await api.nodeName();
  const vmid = rest[0] === undefined ? undefined : Number(rest[0]);
  if (vmid !== undefined && (!Number.isInteger(vmid) || vmid <= 0)) return { ok: false, error: "usage: maw proxmox firewall [<vmid>] | lock|unlock <vmid> --name NAME" };
  const s = await gather(api, node, false);
  const filtered = s.guests.filter((g) => g.fwNics.length);
  let vm: J | undefined;
  if (vmid !== undefined) {
    const [opts, rules, cfg] = await Promise.all([
      api.get<J>(`${s.N}/qemu/${vmid}/firewall/options`), api.get<J[]>(`${s.N}/qemu/${vmid}/firewall/rules`), api.get<J>(`${s.N}/qemu/${vmid}/config`),
    ]);
    vm = { vmid, name: cfg.name ?? null, options: opts, rules, nets: Object.fromEntries(netKeys(cfg).map((k) => [k, cfg[k]])) };
  }
  if (d.json) {
    return { ok: true, output: JSON.stringify({
      node, datacenter: { options: s.dc, rules: s.dcRules.length }, node_firewall: { options: s.nodeOpts, rules: s.nodeRules.length },
      nic_firewall_vms: filtered.map((g) => ({ vmid: g.vmid, name: g.name, nics: g.fwNics, vm_firewall: g.vmFw ?? {} })),
      ...(vm ? { vm } : {}),
    }, null, 1) };
  }
  const lines = [
    `datacenter  enable ${dcEnableText(s.dc)}${others(s.dc) ? `  ${others(s.dc)}` : ""}  rules ${s.dcRules.length}`,
    `node ${node}  enable ${nodeEnableText(s.nodeOpts)}${others(s.nodeOpts) ? `  ${others(s.nodeOpts)}` : ""}  rules ${s.nodeRules.length}`,
    "",
    `VMs with a NIC firewall=1 (${filtered.length})`,
    ...(filtered.length
      ? filtered.map((g) => `  ${g.vmid}  ${g.name}  nics ${g.fwNics.join(",")}  vm firewall ${vmEnableText(g.vmFw ?? {})}${on(g.vmFw?.enable) && g.vmFw?.policy_in ? ` policy_in=${g.vmFw.policy_in}` : ""}`)
      : ["  (none)"]),
  ];
  if (vm) {
    lines.push("", `vm ${vm.vmid} ${vm.name ?? "-"}`,
      `  firewall ${vmEnableText(vm.options)}${others(vm.options) ? `  ${others(vm.options)}` : ""}`,
      `  rules ${vm.rules.length}`,
      ...vm.rules.map((r: J) => `    ${r.pos ?? "-"} ${r.type ?? ""} ${r.action ?? ""}${r.macro ? ` macro=${r.macro}` : ""}${r.proto ? ` proto=${r.proto}` : ""}${r.source ? ` src=${r.source}` : ""}${r.dport ? ` dport=${r.dport}` : ""}${Number(r.enable ?? 1) ? "" : " (disabled)"}`),
      ...Object.entries(vm.nets as J).map(([k, v]) => `  ${k}  ${v}`));
  }
  return { ok: true, output: lines.join("\n") };
}

// ---------- lock / unlock ----------
export type LockOpts = { action: "lock" | "unlock"; vmid: number; name: string; apply: boolean; yes: boolean };
export function parseLock(rest: string[]): LockOpts | string {
  const action = rest[0];
  if (action !== "lock" && action !== "unlock") return "usage: maw proxmox firewall lock|unlock <vmid> --name NAME [--apply --yes]";
  let name = "", apply = false, yes = false, vmid = NaN;
  for (let i = 1; i < rest.length; i++) {
    const a = rest[i]!;
    if (a === "--apply") apply = true;
    else if (a === "--yes" || a === "-y") yes = true;
    else if (a === "--name") { const v = rest[++i]; if (v === undefined) return "--name needs a value"; name = v; }
    else if (a.startsWith("--name=")) name = a.slice(7);
    else if (/^\d+$/.test(a) && Number.isNaN(vmid)) vmid = Number(a);
    else return `unknown argument for firewall ${action}: ${a}`;
  }
  if (!Number.isInteger(vmid) || vmid < 100) return `usage: maw proxmox firewall ${action} <vmid> --name NAME [--apply --yes]`;
  if (!name) return `--name is required: the VM's current name, so the wrong VM is never touched`;
  return { action, vmid, name, apply, yes };
}

async function planLock(api: Api, o: LockOpts, env: Env): Promise<{ node: string; checks: Check[]; calls: Call[]; hints: string[] }> {
  const node = await api.nodeName();
  const s = await gather(api, node, true);
  const N = s.N;
  const checks: Check[] = [];
  const add = (name: string, ok: boolean, detail: string) => checks.push({ name, ok, detail });
  const calls: Call[] = [];
  const hints: string[] = [];

  const me = s.guests.find((g) => g.type === "qemu" && g.vmid === o.vmid);
  add("vm exists", !!me, me ? `qemu ${o.vmid} on ${node}` : `no qemu VM ${o.vmid} on ${node}`);
  if (!me) return { node, checks, calls, hints };
  add("vm name", me.name === o.name, me.name === o.name ? `${o.vmid} is "${me.name}"` : `REFUSE: ${o.vmid} is "${me.name}", not "${o.name}"`);

  const ours = (env.PVE_OURS ?? "").split(/[\s,]+/).filter(Boolean).map(Number);
  add("in ours", !ours.length || ours.includes(o.vmid),
    !ours.length ? "no ours list configured (maw proxmox config set ours=...)" : ours.includes(o.vmid) ? `${o.vmid} is in ours` : `${o.vmid} is not in ours (${ours.join(",")})`);

  const vmOpts = await api.get<J>(`${N}/qemu/${o.vmid}/firewall/options`);
  const vmPath = `${N}/qemu/${o.vmid}/firewall/options`;

  if (o.action === "unlock") {
    if (on(vmOpts.enable)) calls.push({ method: "PUT", path: vmPath, params: { enable: "0" }, note: "VM firewall off (inbound open again)" });
    hints.push("the datacenter firewall is left as it is (other VMs may rely on it).",
      `if no VM needs it any more, turn it off by hand in the Proxmox UI: Datacenter > Firewall > Options > Firewall = No (now ${dcEnableText(s.dc)}).`,
      "NIC firewall=1 flags are left in place; with the VM firewall off they filter nothing.");
    return { node, checks, calls, hints };
  }

  // lock
  const nets = netKeys(me.cfg);
  add("vm has a NIC", nets.length > 0, nets.length ? nets.join(",") : "no net* in the VM config");

  const nodeIsOff = isOff(s.nodeOpts.enable);
  add("host not filtered", true, nodeIsOff ? `node ${node} firewall enable=0 already`
    : `node ${node} firewall is ${nodeEnableText(s.nodeOpts)}: call 1 sets enable=0 BEFORE the datacenter goes on`);

  const dcOn = on(s.dc.enable);
  const victims = s.guests.filter((g) => !(g.type === "qemu" && g.vmid === o.vmid) && g.fwNics.length && on(g.vmFw?.enable));
  const vText = victims.map((g) => `${g.type} ${g.vmid} "${g.name}" (${g.fwNics.join(",")})`).join(", ");
  add("no other VM newly filtered", dcOn || !victims.length,
    dcOn ? `datacenter firewall already on; nothing else changes state${victims.length ? ` (already filtered: ${vText})` : ""}`
      : victims.length ? `REFUSE: turning the datacenter on would start filtering ${vText}`
      : `no other guest has VM firewall on + a NIC firewall=1 (${s.guests.filter((g) => g.fwNics.length && g.vmid !== o.vmid).length} with NIC flag only, VM firewall off: not filtered)`);

  if (!nodeIsOff) calls.push({ method: "PUT", path: `${N}/firewall/options`, params: { enable: "0" }, note: "host firewall off first, so the host is never filtered" });
  for (const k of nets) {
    const v = String(me.cfg[k]);
    if (!nicFirewallOn(v)) calls.push({ method: "PUT", path: `${N}/qemu/${o.vmid}/config`, params: { [k]: withFirewall(v) }, note: `${k}: existing value kept, firewall=1 added` });
  }
  const vmDone = on(vmOpts.enable) && vmOpts.policy_in === "DROP" && (vmOpts.policy_out ?? "ACCEPT") === "ACCEPT";
  if (!vmDone) calls.push({ method: "PUT", path: vmPath, params: { enable: "1", policy_in: "DROP", policy_out: "ACCEPT" }, note: "VM firewall on, inbound dropped" });
  if (!dcOn) calls.push({ method: "PUT", path: "/cluster/firewall/options", params: { enable: "1" }, note: "datacenter firewall on (last)" });
  hints.push(`rollback: maw proxmox firewall unlock ${o.vmid} --name ${o.name}`);
  const rules = await api.get<J[]>(`${N}/qemu/${o.vmid}/firewall/rules`).catch(() => [] as J[]);
  const inAccept = rules.filter((r) => Number(r.enable ?? 1) && String(r.type).toLowerCase() === "in" && String(r.action).toUpperCase() === "ACCEPT");
  if (inAccept.length) hints.push(`note: VM ${o.vmid} has ${inAccept.length} enabled inbound ACCEPT rule(s); see maw proxmox firewall ${o.vmid}`);
  return { node, checks, calls, hints };
}

function render(o: LockOpts, node: string, checks: Check[], calls: Call[], hints: string[], mode: string): string {
  const w = Math.max(...checks.map((c) => c.name.length));
  const lines = [
    `maw proxmox firewall ${o.action} - ${mode}`, "",
    `target  node ${node}  vmid ${o.vmid}  name ${o.name}`, "",
    "checks", ...checks.map((c) => `  ${c.ok ? "PASS" : "FAIL"}  ${c.name.padEnd(w)}  ${c.detail}`), "",
  ];
  if (!calls.length) lines.push("api calls: none - already in the wanted state (no-op)");
  else {
    lines.push("api calls that --apply --yes would send, in order");
    calls.forEach((c, i) => {
      lines.push(`  ${i + 1}. ${c.method.padEnd(4)} ${c.path}${c.note ? `    # ${c.note}` : ""}`);
      if (c.params) for (const [k, v] of Object.entries(c.params)) lines.push(`        ${k}=${v}`);
    });
  }
  if (hints.length) lines.push("", ...hints);
  return lines.join("\n");
}

async function lock(api: Api, rest: string[], d: FirewallDeps): Promise<Result> {
  const o = parseLock(rest);
  if (typeof o === "string") return { ok: false, error: o };
  const { node, checks, calls, hints } = await planLock(api, o, d.env);
  const failed = checks.filter((c) => !c.ok);
  const mode = o.apply && o.yes ? "APPLY" : `PLAN ONLY (nothing is written; add --apply --yes to ${o.action})`;
  const plan = d.json ? JSON.stringify({ action: o.action, node, vmid: o.vmid, name: o.name, mode, checks, calls, hints }, null, 1)
    : render(o, node, checks, calls, hints, mode);
  if (failed.length) return { ok: false, output: plan, error: `REFUSED: ${failed.length} check(s) failed: ${failed.map((c) => c.name).join(", ")}. Nothing was written.` };
  if (o.apply && !o.yes) return { ok: false, output: plan, error: "REFUSED: --apply needs --yes as well. Nothing was written." };
  if (!o.apply) return { ok: true, output: plan + (d.json ? "" : "\n\nall checks passed. Nothing was written (plan only).") };
  if (!calls.length) return { ok: true, output: plan + (d.json ? "" : "\n\nnothing to send.") };
  const done: string[] = [];
  try {
    for (const c of calls) {
      d.log(`${c.method} ${c.path} ${Object.entries(c.params ?? {}).map(([k, v]) => `${k}=${v}`).join(" ")}`);
      await send(api, c.method as "PUT", c.path, c.params);
      done.push(`${c.method} ${c.path}`);
    }
  } catch (e) {
    return { ok: false, output: plan + (done.length ? `\n\nsent before the error:\n${done.map((x) => `  ${x}`).join("\n")}` : ""), error: `apply stopped: ${(e as Error).message}` };
  }
  const N = `/nodes/${encodeURIComponent(node)}`;
  const [vmOpts, dc] = await Promise.all([api.get<J>(`${N}/qemu/${o.vmid}/firewall/options`), api.get<J>("/cluster/firewall/options")]);
  return { ok: true, output: `${plan}\n\nresult: ${calls.length} call(s) sent\n  vm ${o.vmid} firewall ${vmEnableText(vmOpts)}${vmOpts.policy_in ? ` policy_in=${vmOpts.policy_in}` : ""}\n  datacenter enable ${dcEnableText(dc)}` };
}

// ---------- entry ----------
export async function runFirewall(api: Api, rest: string[], d: FirewallDeps): Promise<Result> {
  if (rest[0] === "lock" || rest[0] === "unlock") return lock(api, rest, d);
  return show(api, rest, d);
}
