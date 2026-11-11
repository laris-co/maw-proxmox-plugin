import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { run, type Store } from "./index";
import { encodeSshKeys, haosNetworkCommand, inNet, ip2int, looksLikePublicKey, ONBOARDING_WARNING, sendkeySequence, type ProbeResult } from "./create";

// All values are fake: pve.example.test, node "pve-a", documentation range 203.0.113.0/24, deny 198.51.100.0/24.
const HOST = "pve.example.test";
const BASE = `https://${HOST}:8006/api2/json`;
const N = "/nodes/pve-a";
const GIB = 2 ** 30;
const UPID_CREATE = "UPID:pve-a:00000001:00000001:00000001:qmcreate:120:root@pam:";
const UPID_START = "UPID:pve-a:00000002:00000002:00000002:qmstart:120:root@pam:";
const PUBKEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyFakeKeyFakeKeyFakeKeyFakeKeyFake+/= test@example";

function fixtures(): Record<string, unknown> {
  return {
    "/nodes": [{ node: "pve-a" }],
    [`${N}/qemu`]: [
      { vmid: 201, name: "vm-a", status: "running", maxmem: 4 * GIB },
      { vmid: 202, name: "vm-b", status: "stopped", maxmem: 8 * GIB },
      { vmid: 203, name: "vm-c", status: "running", maxmem: 1 * GIB },
    ],
    [`${N}/lxc`]: [{ vmid: 301, name: "ct-a", status: "running", maxmem: 1 * GIB }],
    [`${N}/qemu/201/config`]: { name: "vm-a", agent: "1", ipconfig0: "ip=203.0.113.21/24,gw=203.0.113.254" },
    [`${N}/qemu/202/config`]: { name: "vm-b" },
    [`${N}/qemu/203/config`]: { name: "vm-c", agent: "enabled=1" },
    [`${N}/lxc/301/config`]: { hostname: "ct-a", net0: "name=eth0,bridge=vmbr0,ip=203.0.113.31/24,gw=203.0.113.254" },
    [`${N}/qemu/203/agent/network-get-interfaces`]: { result: [{ name: "enp6s18", "ip-addresses": [{ "ip-address-type": "ipv4", "ip-address": "203.0.113.23" }] }] },
    [`${N}/status`]: { memory: { total: 32 * GIB, used: 10 * GIB } },
    [`${N}/storage`]: [{ storage: "ssd", active: 1, avail: 200 * GIB }, { storage: "local", active: 1, avail: 50 * GIB }],
    [`${N}/storage/local/content?content=import`]: [
      { volid: "local:import/haos_ova-18.2.qcow2" }, { volid: "local:import/noble-server-cloudimg-amd64.qcow2" },
    ],
    [`${N}/qemu/120/status/current`]: { status: "running" },
    [`${N}/tasks/${encodeURIComponent(UPID_CREATE)}/status`]: { status: "stopped", exitstatus: "OK" },
    [`${N}/tasks/${encodeURIComponent(UPID_START)}/status`]: { status: "stopped", exitstatus: "OK" },
  };
}

type Call = { method: string; path: string; headers: Record<string, string>; body?: string };
function mock(fix = fixtures()) {
  const calls: Call[] = [];
  const fetch = async (url: string, init: any = {}) => {
    const path = url.slice(BASE.length);
    const method = init.method ?? "GET";
    calls.push({ method, path, headers: init.headers ?? {}, body: init.body?.toString() });
    if (path === "/access/ticket") return Response.json({ data: { ticket: "PVE:fake-ticket", CSRFPreventionToken: "csrf-fake" } });
    if (method === "POST" && path === `${N}/qemu`) return Response.json({ data: UPID_CREATE });
    if (method === "PUT" && path === `${N}/qemu/120/resize`) return Response.json({ data: null });
    if (method === "POST" && path === `${N}/qemu/120/status/start`) return Response.json({ data: UPID_START });
    if (method === "PUT" && path === `${N}/qemu/120/sendkey`) return Response.json({ data: null });
    if (method !== "GET" || !(path in fix)) return new Response("not found", { status: 404 });
    return Response.json({ data: fix[path] });
  };
  return { calls, fetch };
}

const ENV = {
  PVE_HOST: HOST, PVE_TOKEN_ID: "ops@pve!t", PVE_TOKEN_SECRET: "00000000-fake",
  PVE_ALLOWED_NETS: "203.0.113.0/24", PVE_DENY_NETS: "198.51.100.0/24", PVE_GW: "203.0.113.254",
};
type Opts = { env?: Record<string, string>; probe?: (h: string, p: number) => ProbeResult; ping?: boolean | null; m?: ReturnType<typeof mock>; files?: Record<string, string>; store?: Store };
async function go(args: string[], o: Opts = {}) {
  const m = o.m ?? mock();
  const logs: string[] = [];
  const sleeps: number[] = [];
  const r = await run(args, {
    env: o.env ?? ENV, fetch: m.fetch as any, pass: () => "pw", log: (s) => logs.push(s), store: o.store,
    create: {
      probe: async (h, p) => (o.probe ?? (() => "silent" as ProbeResult))(h, p),
      ping: async () => (o.ping === undefined ? false : o.ping),
      sleep: async (ms) => { sleeps.push(ms); },
      readFile: (p) => (o.files ?? { "/keys/id.pub": PUBKEY, "/keys/id": "-----BEGIN OPENSSH PRIVATE KEY-----\nx\n" })[p] ?? null,
      hostname: () => "probe-host", today: () => "2026-01-02",
    },
  });
  return { r, calls: m.calls, logs, sleeps };
}
const HAOS = ["create", "haos", "--vmid", "120", "--name", "ha-test", "--ip", "203.0.113.56/24"];
const UBUNTU = ["create", "ubuntu", "--vmid", "120", "--name", "ub-test", "--ip", "203.0.113.57/24", "--ssh-key", "/keys/id.pub"];
const writes = (c: Call[]) => c.filter((x) => x.method !== "GET" && x.path !== "/access/ticket");

test("ipv4 helpers", () => {
  expect(ip2int("203.0.113.1")).toBe(0xcb007101);
  expect(ip2int("256.0.0.1")).toBeNull();
  expect(inNet(ip2int("203.0.113.56")!, "203.0.113.0/24")).toBe(true);
  expect(inNet(ip2int("203.0.114.56")!, "203.0.113.0/24")).toBe(false);
});

test("plan (default): every check shown, exact calls printed, no write sent", async () => {
  const { r, calls } = await go(HAOS);
  expect(r.ok).toBe(true);
  expect(writes(calls)).toEqual([]);
  const out = r.output!;
  expect(out).toContain("PLAN ONLY");
  for (const name of ["vmid free", "name free", "ip allowed", "gateway / dns", "ip silent", "ip not on a guest", "ram headroom", "storage space", "image present"])
    expect(out).toMatch(new RegExp(`PASS  ${name}`));
  expect(out).not.toContain("FAIL");
  expect(out).toContain(`1. POST ${N}/qemu`);
  expect(out).toContain("efidisk0=ssd:0,efitype=4m,pre-enrolled-keys=0");
  expect(out).toContain("scsi0=ssd:0,import-from=local:import/haos_ova-18.2.qcow2,discard=on,ssd=1");
  expect(out).toContain(`3. PUT  ${N}/qemu/120/resize`);
  expect(out).toContain("size=48G");
  expect(out).toContain(`4. POST ${N}/qemu/120/status/start`);
  expect(out).toContain("network update enp6s18 --ipv4-method static --ipv4-address 203.0.113.56/24 --ipv4-gateway 203.0.113.254 --ipv4-nameserver 1.1.1.1 --ipv4-nameserver 8.8.8.8");
  // running guests 4G + 1G (qemu) + 1G (lxc) = 6G, + 2G new = 8G <= 32G - 5G
  expect(out).toMatch(/running guests 6\.0G \(3\) \+ new 2\.0G = 8\.0G <= physical 32\.0G - reserve 5G = 27\.0G/);
  expect(out).toContain(ONBOARDING_WARNING);
  expect(out).toContain("probed from probe-host");
});

test("--yes alone is still a plan", async () => {
  const { r, calls } = await go([...HAOS, "--yes"]);
  expect(r.ok).toBe(true);
  expect(writes(calls)).toEqual([]);
});

test("--apply without --yes refuses and writes nothing", async () => {
  const { r, calls } = await go([...HAOS, "--apply"]);
  expect(r.ok).toBe(false);
  expect(r.error).toMatch(/--apply needs --yes/);
  expect(writes(calls)).toEqual([]);
});

async function refused(args: string[], check: string, o: Opts = {}, detail?: RegExp) {
  const { r, calls } = await go([...args, "--apply", "--yes"], o);
  expect(r.ok).toBe(false);
  expect(r.error).toContain("REFUSED");
  expect(r.error).toContain(check);
  expect(r.output).toContain(`FAIL  ${check}`);
  if (detail) expect(r.output).toMatch(detail);
  expect(writes(calls)).toEqual([]);
}

test("refuse: vmid taken (qemu and lxc)", async () => {
  await refused(["create", "haos", "--vmid", "202", "--name", "x1", "--ip", "203.0.113.56/24"], "vmid free", {}, /already qemu "vm-b"/);
  await refused(["create", "haos", "--vmid", "301", "--name", "x1", "--ip", "203.0.113.56/24"], "vmid free", {}, /already lxc/);
});

test("refuse: name taken", async () => {
  await refused(["create", "haos", "--vmid", "120", "--name", "vm-a", "--ip", "203.0.113.56/24"], "name free");
});

test("refuse: no allowed_nets, outside allowed, inside deny, broadcast", async () => {
  const { PVE_ALLOWED_NETS: _, ...noAllow } = ENV;
  await refused(HAOS, "ip allowed", { env: noAllow }, /no allowed_nets configured/);
  await refused(["create", "haos", "--vmid", "120", "--name", "x1", "--ip", "192.0.2.5/24", "--gw", "192.0.2.1"], "ip allowed", {}, /outside allowed_nets/);
  await refused(["create", "haos", "--vmid", "120", "--name", "x1", "--ip", "198.51.100.5/24", "--gw", "198.51.100.1"], "ip allowed",
    { env: { ...ENV, PVE_ALLOWED_NETS: "198.51.0.0/16" } }, /inside deny_nets/);
  await refused(["create", "haos", "--vmid", "120", "--name", "x1", "--ip", "203.0.113.255/24"], "ip allowed", {}, /broadcast/);
  await refused(["create", "haos", "--vmid", "120", "--name", "x1", "--ip", "203.0.113.56"], "ip allowed", {}, /A\.B\.C\.D\/NN/);
});

test("refuse: gateway missing or outside the subnet", async () => {
  const { PVE_GW: _, ...noGw } = ENV;
  await refused(HAOS, "gateway / dns", { env: noGw }, /no gateway/);
  await refused([...HAOS, "--gw", "192.0.2.1"], "gateway / dns", {}, /outside/);
});

test("refuse: ip answers on tcp (open or refused) or ping", async () => {
  await refused(HAOS, "ip silent", { probe: (_h, p) => (p === 443 ? "open" : "silent") }, /tcp 443 open/);
  await refused(HAOS, "ip silent", { probe: (_h, p) => (p === 22 ? "refused" : "silent") }, /tcp 22 refused/);
  await refused(HAOS, "ip silent", { ping: true }, /ping replied/);
});

test("refuse: ip already on a guest (ipconfig0, lxc net0, guest agent)", async () => {
  await refused(["create", "haos", "--vmid", "120", "--name", "x1", "--ip", "203.0.113.21/24"], "ip not on a guest", {}, /vmid 201 \(config\)/);
  await refused(["create", "haos", "--vmid", "120", "--name", "x1", "--ip", "203.0.113.31/24"], "ip not on a guest", {}, /vmid 301 \(config\)/);
  await refused(["create", "haos", "--vmid", "120", "--name", "x1", "--ip", "203.0.113.23/24"], "ip not on a guest", {}, /vmid 203 \(agent\)/);
});

test("refuse: RAM headroom", async () => {
  await refused([...HAOS, "--ram", "24576"], "ram headroom", {}, /= 30\.0G > physical 32\.0G - reserve 5G = 27\.0G/);
  await refused(HAOS, "ram headroom", { env: { ...ENV, PVE_RAM_RESERVE_GIB: "25" } });
});

test("refuse: storage too small", async () => {
  await refused([...HAOS, "--disk", "190"], "storage space", {}, /avail 200\.0G < 209\.0G/);
  await refused([...HAOS, "--storage-vm", "nope"], "storage space", {}, /not found/);
});

test("refuse: image missing", async () => {
  await refused([...HAOS, "--image", "haos_ova-99.qcow2"], "image present", {}, /not found; import images: local:import\/haos_ova-18\.2\.qcow2/);
});

test("refuse: ubuntu ssh key missing / unreadable / private", async () => {
  await refused(["create", "ubuntu", "--vmid", "120", "--name", "ub", "--ip", "203.0.113.57/24"], "ssh key", {}, /required/);
  await refused(["create", "ubuntu", "--vmid", "120", "--name", "ub", "--ip", "203.0.113.57/24", "--ssh-key", "/nope"], "ssh key", {}, /cannot read/);
  await refused(["create", "ubuntu", "--vmid", "120", "--name", "ub", "--ip", "203.0.113.57/24", "--ssh-key", "/keys/id"], "ssh key", {}, /does not look like/);
  expect(looksLikePublicKey(PUBKEY)).toBe(true);
});

test("bad arguments are refused", async () => {
  await refused(["create", "haos", "--vmid", "abc", "--name", "x1", "--ip", "203.0.113.56/24"], "arguments");
  await refused(["create", "haos", "--vmid", "120", "--name", "bad_name", "--ip", "203.0.113.56/24"], "arguments");
  expect((await go(["create", "windows"])).r.ok).toBe(false);
  expect((await go([...HAOS, "--bogus", "1"])).r.error).toMatch(/unknown option/);
});

test("apply haos: exact POST/PUT sequence, CSRF header on ticket auth, verify + summary", async () => {
  const env = { ...ENV, PVE_TOKEN_ID: "", PVE_TOKEN_SECRET: "", PVE_USER: "ops@pve", PVE_PASSWORD: "pw", PVE_NODE: "pve-a" };
  let created = false;
  const m = mock();
  const inner = m.fetch;
  m.fetch = async (url: string, init: any = {}) => { if (init.method === "POST" && url.endsWith(`${N}/qemu`)) created = true; return inner(url, init); };
  const { r, calls, sleeps } = await go([...HAOS, "--apply", "--yes"], { env, m, probe: (_h, p) => (created && p === 4357 ? "open" : "silent") });
  expect(r.error).toBeUndefined();
  expect(r.ok).toBe(true);
  const w = writes(calls);
  const cmd = haosNetworkCommand("enp6s18", "203.0.113.56/24", "203.0.113.254", ["1.1.1.1", "8.8.8.8"]);
  const keys = sendkeySequence(cmd);
  expect(w.map((c) => `${c.method} ${c.path}`)).toEqual([
    `POST ${N}/qemu`, `PUT ${N}/qemu/120/resize`, `POST ${N}/qemu/120/status/start`,
    ...keys.map(() => `PUT ${N}/qemu/120/sendkey`),
  ]);
  expect(w.slice(3).map((c) => new URLSearchParams(c.body).get("key"))).toEqual(keys);
  const p = new URLSearchParams(w[0]!.body);
  expect(Object.fromEntries(p)).toMatchObject({
    vmid: "120", name: "ha-test", ostype: "l26", machine: "q35", bios: "ovmf", efidisk0: "ssd:0,efitype=4m,pre-enrolled-keys=0",
    cores: "2", sockets: "1", cpu: "host", memory: "2048", scsihw: "virtio-scsi-pci",
    scsi0: "ssd:0,import-from=local:import/haos_ova-18.2.qcow2,discard=on,ssd=1", net0: "virtio,bridge=vmbr0",
    agent: "1", onboot: "1", tablet: "0", localtime: "1", boot: "order=scsi0",
  });
  expect(p.get("description")).toContain("2026-01-02");
  expect(Object.fromEntries(new URLSearchParams(w[1]!.body))).toEqual({ disk: "scsi0", size: "48G" });
  for (const c of w) expect(c.headers.CSRFPreventionToken).toBe("csrf-fake");
  expect(sleeps).toContain(150_000);
  expect(r.output).toContain("vm 120 ha-test: created, disk 48G, running");
  expect(r.output).toContain("tcp 4357: open");
  expect(r.output).toContain(ONBOARDING_WARNING);
});

test("apply ubuntu: cloud-init params, double-encoded sshkeys, no ovmf, tcp 22 verify", async () => {
  const m = mock();
  let created = false;
  const inner = m.fetch;
  m.fetch = async (url: string, init: any = {}) => { if (init.method === "POST" && url.endsWith(`${N}/qemu`)) created = true; return inner(url, init); };
  const { r, calls } = await go([...UBUNTU, "--apply", "--yes", "--ciuser", "ops"], { m, probe: (_h, p) => (created && p === 22 ? "open" : "silent") });
  expect(r.ok).toBe(true);
  const w = writes(calls);
  expect(w.map((c) => `${c.method} ${c.path}`)).toEqual([`POST ${N}/qemu`, `PUT ${N}/qemu/120/resize`, `POST ${N}/qemu/120/status/start`]);
  for (const c of w) expect(c.headers.Authorization).toBe("PVEAPIToken=ops@pve!t=00000000-fake");
  const body = w[0]!.body!;
  const p = new URLSearchParams(body);
  expect(p.get("bios")).toBeNull(); expect(p.get("efidisk0")).toBeNull(); expect(p.get("machine")).toBeNull();
  expect(Object.fromEntries(p)).toMatchObject({
    cpu: "host", ide2: "ssd:cloudinit,media=cdrom", ipconfig0: "ip=203.0.113.57/24,gw=203.0.113.254",
    nameserver: "1.1.1.1 8.8.8.8", ciuser: "ops", agent: "1", onboot: "1",
    scsi0: "ssd:0,import-from=local:import/noble-server-cloudimg-amd64.qcow2,discard=on,ssd=1",
  });
  // after one form-decode the API sees the key still percent-encoded once
  expect(p.get("sshkeys")).toBe(encodeSshKeys(PUBKEY));
  expect(p.get("sshkeys")).toContain("ssh-ed25519%20AAAA");
  expect(p.get("sshkeys")).toContain("%2B%2F%3D%20test%40example");
  // on the wire it is encoded twice
  expect(body).toContain("sshkeys=ssh-ed25519%2520AAAA");
  expect(Object.fromEntries(new URLSearchParams(w[1]!.body))).toEqual({ disk: "scsi0", size: "40G" });
  expect(r.output).toMatch(/tcp 22 open on 203\.0\.113\.57/);
});

test("encodeSshKeys matches python quote(safe='')", () => {
  expect(encodeSshKeys("ssh-rsa AB+/= me@h (x)!*'")).toBe("ssh-rsa%20AB%2B%2F%3D%20me%40h%20%28x%29%21%2A%27");
});

test("sendkey sequence for a sample command", () => {
  expect(sendkeySequence("network update enp6s18 --ipv4-address 203.0.113.5/24")).toEqual([
    ..."network".split(""), "spc", ..."update".split(""), "spc", ..."enp6s18".split(""), "spc",
    "minus", "minus", "i", "p", "v", "4", "minus", "a", "d", "d", "r", "e", "s", "s", "spc",
    "2", "0", "3", "dot", "0", "dot", "1", "1", "3", "dot", "5", "slash", "2", "4", "ret",
  ]);
  expect(sendkeySequence("A:_")).toEqual(["shift-a", "shift-semicolon", "shift-minus", "ret"]);
  expect(() => sendkeySequence("é")).toThrow(/no QEMU key/);
});

test("apply stops when the create task fails", async () => {
  const fix = fixtures();
  fix[`${N}/tasks/${encodeURIComponent(UPID_CREATE)}/status`] = { status: "stopped", exitstatus: "storage full" };
  const { r, calls } = await go([...HAOS, "--apply", "--yes"], { m: mock(fix) });
  expect(r.ok).toBe(false);
  expect(r.error).toMatch(/vm create task failed: storage full/);
  expect(writes(calls).map((c) => c.method + " " + c.path)).toEqual([`POST ${N}/qemu`]);
});

test("allowed_nets etc. can be saved with config set", async () => {
  const st = { cfg: {} as Record<string, any> };
  const store: Store = {
    configPath: () => "/fake/config.json", readConfig: () => ({ ...st.cfg }), writeConfig: (c) => { st.cfg = c; },
    readTicket: () => null, writeTicket: () => {}, now: () => 0,
  };
  const r = await run(["config", "set", "allowed_nets=203.0.113.0/24", "deny_nets=198.51.100.0/24", "ram_reserve_gib=5", "gw=203.0.113.254"],
    { env: {}, fetch: (async () => new Response("")) as any, pass: () => null, log: () => {}, store });
  expect(r.ok).toBe(true);
  expect(st.cfg).toEqual({ allowed_nets: "203.0.113.0/24", deny_nets: "198.51.100.0/24", ram_reserve_gib: "5", gw: "203.0.113.254" });
  const { PVE_ALLOWED_NETS: _a, PVE_DENY_NETS: _d, PVE_GW: _g, ...bare } = ENV;
  const { r: plan } = await go(HAOS, { env: bare, store });
  expect(plan.ok).toBe(true);
});

test("all write code lives in create.ts", () => {
  const src = readFileSync(join(import.meta.dir, "create.ts"), "utf8");
  for (const s of ["/resize", "/status/start", "/sendkey", "\"PUT\"", "\"POST\""]) expect(src.includes(s)).toBe(true);
  for (const bad of ["/status/stop", "/status/shutdown", "/status/reboot", "\"DELETE\"", "/clone", "vzdump"]) expect(src.includes(bad)).toBe(false);
});
