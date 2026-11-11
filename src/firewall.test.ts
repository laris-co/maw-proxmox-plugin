import { expect, test } from "bun:test";
import { run } from "./index";
import { withFirewall } from "./firewall";

// All values are fake: pve.example.test, node "pve-a", vm 120 "ha-test", others vm-a / vm-b / ct-a.
const HOST = "pve.example.test";
const BASE = `https://${HOST}:8006/api2/json`;
const N = "/nodes/pve-a";
const NET0 = "virtio=AA:BB:CC:DD:EE:01,bridge=vmbr0";
const NET1 = "e1000=AA:BB:CC:DD:EE:02,bridge=vmbr1,tag=20";

function fixtures(): Record<string, unknown> {
  return {
    "/nodes": [{ node: "pve-a" }],
    "/cluster/firewall/options": {},
    "/cluster/firewall/rules": [],
    [`${N}/firewall/options`]: {},
    [`${N}/firewall/rules`]: [{ pos: 0 }],
    [`${N}/qemu`]: [{ vmid: 201, name: "vm-a" }, { vmid: 120, name: "ha-test" }, { vmid: 202, name: "vm-b" }],
    [`${N}/lxc`]: [{ vmid: 301, name: "ct-a" }],
    [`${N}/qemu/120/config`]: { name: "ha-test", net0: NET0, net1: NET1, digest: "x" },
    [`${N}/qemu/201/config`]: { name: "vm-a", net0: "virtio=AA:BB:CC:DD:EE:03,bridge=vmbr0,firewall=1" },
    [`${N}/qemu/202/config`]: { name: "vm-b", net0: "virtio=AA:BB:CC:DD:EE:04,bridge=vmbr0" },
    [`${N}/lxc/301/config`]: { hostname: "ct-a", net0: "name=eth0,bridge=vmbr0,ip=203.0.113.31/24" },
    [`${N}/qemu/201/firewall/options`]: {},
    [`${N}/qemu/120/firewall/options`]: {},
    [`${N}/qemu/120/firewall/rules`]: [],
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
    if (method === "PUT") return Response.json({ data: null });
    if (method !== "GET" || !(path in fix)) return new Response("not found", { status: 404 });
    return Response.json({ data: fix[path] });
  };
  return { calls, fetch, fix };
}
const ENV = { PVE_HOST: HOST, PVE_TOKEN_ID: "ops@pve!t", PVE_TOKEN_SECRET: "00000000-fake" };
async function go(args: string[], m = mock(), env: Record<string, string> = ENV) {
  const r = await run(args, { env, fetch: m.fetch as any, pass: () => "pw", log: () => {} });
  return { r, calls: m.calls };
}
const writes = (c: Call[]) => c.filter((x) => x.method !== "GET" && x.path !== "/access/ticket");
const LOCK = ["firewall", "lock", "120", "--name", "ha-test"];

test("firewall (read): defaults shown in words, NIC firewall VMs listed, GET only", async () => {
  const { r, calls } = await go(["firewall"]);
  expect(r.ok).toBe(true);
  expect(r.output).toContain("datacenter  enable default (off)  rules 0");
  expect(r.output).toContain("node pve-a  enable default (on when datacenter on)  rules 1");
  expect(r.output).toMatch(/201  vm-a  nics net0  vm firewall off/);
  expect(r.output).not.toMatch(/202  vm-b/);
  expect(writes(calls)).toEqual([]);
});

test("firewall <vmid>: options, rules, net lines; --json", async () => {
  const { r, calls } = await go(["firewall", "120"]);
  expect(r.ok).toBe(true);
  expect(r.output).toContain("vm 120 ha-test");
  expect(r.output).toContain("firewall off");
  expect(r.output).toContain(`net0  ${NET0}`);
  expect(r.output).toContain(`net1  ${NET1}`);
  const j = await go(["firewall", "120", "--json"]);
  const o = JSON.parse(j.r.output!);
  expect(o.vm.nets).toEqual({ net0: NET0, net1: NET1 });
  expect(o.nic_firewall_vms.map((v: any) => v.vmid)).toEqual([201]);
  expect(writes([...calls, ...j.calls])).toEqual([]);
  expect((await go(["firewall", "abc"])).r.ok).toBe(false);
});

test("withFirewall keeps the value byte-for-byte and appends ,firewall=1", () => {
  expect(withFirewall(NET0)).toBe(`${NET0},firewall=1`);
  expect(withFirewall(`${NET0},firewall=1`)).toBe(`${NET0},firewall=1`);
  expect(withFirewall("virtio=AA:BB:CC:DD:EE:01,firewall=0,bridge=vmbr0")).toBe("virtio=AA:BB:CC:DD:EE:01,firewall=1,bridge=vmbr0");
});

test("lock plan (default): checks pass, exact calls listed, no write sent", async () => {
  const { r, calls } = await go(LOCK);
  expect(r.ok).toBe(true);
  expect(writes(calls)).toEqual([]);
  const out = r.output!;
  expect(out).toContain("PLAN ONLY");
  expect(out).not.toContain("FAIL");
  expect(out).toContain(`1. PUT  ${N}/firewall/options`);
  expect(out).toContain(`2. PUT  ${N}/qemu/120/config`);
  expect(out).toContain(`net0=${NET0},firewall=1`);
  expect(out).toContain(`3. PUT  ${N}/qemu/120/config`);
  expect(out).toContain(`net1=${NET1},firewall=1`);
  expect(out).toContain(`4. PUT  ${N}/qemu/120/firewall/options`);
  expect(out).toContain("5. PUT  /cluster/firewall/options");
  expect(out).toContain("rollback: maw proxmox firewall unlock 120 --name ha-test");
  // --yes alone and --apply alone are still no-write
  expect(writes((await go([...LOCK, "--yes"])).calls)).toEqual([]);
  const a = await go([...LOCK, "--apply"]);
  expect(a.r.ok).toBe(false); expect(a.r.error).toMatch(/needs --yes/); expect(writes(a.calls)).toEqual([]);
});

test("lock apply: exactly the listed PUTs, in order, exact params", async () => {
  const { r, calls } = await go([...LOCK, "--apply", "--yes"]);
  expect(r.ok).toBe(true);
  const w = writes(calls).map((c) => [c.method, c.path, Object.fromEntries(new URLSearchParams(c.body))]);
  expect(w).toEqual([
    ["PUT", `${N}/firewall/options`, { enable: "0" }],
    ["PUT", `${N}/qemu/120/config`, { net0: `${NET0},firewall=1` }],
    ["PUT", `${N}/qemu/120/config`, { net1: `${NET1},firewall=1` }],
    ["PUT", `${N}/qemu/120/firewall/options`, { enable: "1", policy_in: "DROP", policy_out: "ACCEPT" }],
    ["PUT", "/cluster/firewall/options", { enable: "1" }],
  ]);
  expect(r.output).toContain("result: 5 call(s) sent");
});

test("lock apply with ticket auth sends the CSRF token on every write", async () => {
  const env = { PVE_HOST: HOST, PVE_USER: "ops@pve", PVE_PASSWORD: "pw" };
  const { r, calls } = await go([...LOCK, "--apply", "--yes"], mock(), env);
  expect(r.ok).toBe(true);
  const w = writes(calls);
  expect(w.length).toBe(5);
  for (const c of w) expect(c.headers.CSRFPreventionToken).toBe("csrf-fake");
});

test("lock skips what is already done; node already off; fully locked VM is a no-op", async () => {
  const m = mock();
  m.fix[`${N}/firewall/options`] = { enable: 0 };
  m.fix[`${N}/qemu/120/config`] = { name: "ha-test", net0: `${NET0},firewall=1` };
  const a = await go([...LOCK, "--apply", "--yes"], m);
  expect(a.r.ok).toBe(true);
  expect(writes(a.calls).map((c) => c.path)).toEqual([`${N}/qemu/120/firewall/options`, "/cluster/firewall/options"]);

  const m2 = mock();
  m2.fix["/cluster/firewall/options"] = { enable: 1 };
  m2.fix[`${N}/firewall/options`] = { enable: 0 };
  m2.fix[`${N}/qemu/120/config`] = { name: "ha-test", net0: `${NET0},firewall=1` };
  m2.fix[`${N}/qemu/120/firewall/options`] = { enable: 1, policy_in: "DROP" };
  const plan = await go(LOCK, m2);
  expect(plan.r.ok).toBe(true);
  expect(plan.r.output).toContain("api calls: none - already in the wanted state (no-op)");
  const b = await go([...LOCK, "--apply", "--yes"], m2);
  expect(b.r.ok).toBe(true);
  expect(writes([...plan.calls, ...b.calls])).toEqual([]);
});

test("lock refuses on name mismatch, with no write", async () => {
  const { r, calls } = await go(["firewall", "lock", "120", "--name", "other", "--apply", "--yes"]);
  expect(r.ok).toBe(false);
  expect(r.error).toMatch(/REFUSED.*vm name/);
  expect(r.output).toContain('REFUSE: 120 is "ha-test", not "other"');
  expect(writes(calls)).toEqual([]);
  expect((await go(["firewall", "lock", "120"])).r.error).toMatch(/--name is required/);
  const missing = await go(["firewall", "lock", "999", "--name", "ha-test", "--apply", "--yes"]);
  expect(missing.r.ok).toBe(false); expect(writes(missing.calls)).toEqual([]);
});

test("lock refuses when another VM would start being filtered", async () => {
  const m = mock();
  m.fix[`${N}/qemu/201/firewall/options`] = { enable: 1 };
  const { r, calls } = await go([...LOCK, "--apply", "--yes"], m);
  expect(r.ok).toBe(false);
  expect(r.error).toMatch(/no other VM newly filtered/);
  expect(r.output).toContain('qemu 201 "vm-a" (net0)');
  expect(writes(calls)).toEqual([]);
  // an lxc guest counts too
  const m2 = mock();
  m2.fix[`${N}/lxc/301/config`] = { hostname: "ct-a", net0: "name=eth0,bridge=vmbr0,firewall=1" };
  m2.fix[`${N}/lxc/301/firewall/options`] = { enable: 1 };
  const b = await go([...LOCK, "--apply", "--yes"], m2);
  expect(b.r.ok).toBe(false); expect(b.r.output).toContain('lxc 301 "ct-a"'); expect(writes(b.calls)).toEqual([]);
});

test("lock refuses a VM outside the ours list", async () => {
  const { r, calls } = await go([...LOCK, "--apply", "--yes"], mock(), { ...ENV, PVE_OURS: "201,202" });
  expect(r.ok).toBe(false); expect(r.error).toMatch(/in ours/); expect(writes(calls)).toEqual([]);
  expect((await go(LOCK, mock(), { ...ENV, PVE_OURS: "120" })).r.ok).toBe(true);
  expect((await go([...LOCK, "--ours", "120"], mock(), { ...ENV, PVE_OURS: "201" })).r.ok).toBe(true);
});

test("unlock: plan writes nothing, apply sends only VM enable=0, datacenter left on", async () => {
  const m = mock();
  m.fix["/cluster/firewall/options"] = { enable: 1 };
  m.fix[`${N}/qemu/120/firewall/options`] = { enable: 1, policy_in: "DROP" };
  const UN = ["firewall", "unlock", "120", "--name", "ha-test"];
  const p = await go(UN, m);
  expect(p.r.ok).toBe(true);
  expect(writes(p.calls)).toEqual([]);
  expect(p.r.output).toContain("datacenter firewall is left as it is");
  const a = await go([...UN, "--apply", "--yes"], m);
  expect(a.r.ok).toBe(true);
  expect(writes(a.calls).map((c) => [c.path, c.body])).toEqual([[`${N}/qemu/120/firewall/options`, "enable=0"]]);
  const m2 = mock(); m2.fix[`${N}/qemu/120/firewall/options`] = { enable: 1 };
  const bad = await go(["firewall", "unlock", "120", "--name", "nope", "--apply", "--yes"], m2);
  expect(bad.r.ok).toBe(false); expect(writes(bad.calls)).toEqual([]);
});
