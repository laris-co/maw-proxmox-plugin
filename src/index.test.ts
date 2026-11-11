import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { baseUrl, bytes, dur, jobCovers, NO_CREDS, parse, run, table, taskState, vmidList } from "./index";

// All values here are fake: pve.example.test, node "pve-a", VMs "vm-a"/"vm-b"/"vm-c".
const HOST = "pve.example.test";
const BASE = `https://${HOST}:8006/api2/json`;
const FAILED_UPID = "UPID:pve-a:0000ABCD:00112233:6731A000:vzdump::backup@pam:";

const FIX: Record<string, unknown> = {
  "/nodes": [{ node: "pve-a", status: "online" }],
  "/nodes/pve-a/status": { cpu: 0.125, cpuinfo: { cpus: 8 }, loadavg: ["0.5", "0.4", "0.3"], memory: { used: 8 * 2 ** 30, total: 32 * 2 ** 30 }, rootfs: { used: 50 * 2 ** 30, total: 100 * 2 ** 30 }, uptime: 90061, pveversion: "pve-manager/9.0.0" },
  "/nodes/pve-a/qemu": [
    { vmid: 202, name: "vm-b", status: "stopped", cpus: 2, mem: 0, maxmem: 2 ** 31, uptime: 0 },
    { vmid: 201, name: "vm-a", status: "running", cpus: 4, mem: 2 ** 30, maxmem: 2 ** 32, uptime: 3600 },
    { vmid: 203, name: "vm-c", status: "running", cpus: 1, mem: 2 ** 29, maxmem: 2 ** 30, uptime: 120 },
  ],
  "/nodes/pve-a/qemu/201/status/current": { name: "vm-a", status: "running", qmpstatus: "running", cpu: 0.02, cpus: 4, mem: 2 ** 30, maxmem: 2 ** 32, uptime: 3600, netin: 1000, netout: 2000 },
  "/nodes/pve-a/qemu/201/config": { name: "vm-a", cores: 4, memory: "4096", net0: "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0", digest: "x" },
  "/nodes/pve-a/tasks?limit=50": [
    { upid: FAILED_UPID, type: "vzdump", id: "", user: "backup@pam", starttime: 1731200000, endtime: 1731200600, status: "job errors" },
    { upid: "UPID:pve-a:1:2:3:qmstart:201:a@pam:", type: "qmstart", id: "201", user: "a@pam", starttime: 1731100000, endtime: 1731100005, status: "OK" },
    { upid: "UPID:pve-a:1:2:4:vncproxy:201:a@pam:", type: "vncproxy", id: "201", user: "a@pam", starttime: 1731300000 },
  ],
  "/nodes/pve-a/tasks?limit=50&errors=1": [
    { upid: FAILED_UPID, type: "vzdump", id: "", user: "backup@pam", starttime: 1731200000, endtime: 1731200600, status: "job errors" },
  ],
  [`/nodes/pve-a/tasks/${encodeURIComponent(FAILED_UPID)}/log?limit=5000`]: [{ n: 1, t: "INFO: starting backup" }, { n: 2, t: "ERROR: Backup of VM 203 failed - no space left" }],
  "/cluster/backup": [{ id: "backup-1", enabled: 1, schedule: "03:30", storage: "store-b", mode: "snapshot", vmid: "201,202" }],
  "/nodes/pve-a/storage?content=backup": [{ storage: "store-b", active: 1 }],
  "/nodes/pve-a/storage/store-b/content?content=backup": [
    { volid: "store-b:backup/vzdump-qemu-201-old.vma.zst", vmid: 201, size: 2 ** 30, ctime: 1731000000 },
    { volid: "store-b:backup/vzdump-qemu-201-new.vma.zst", vmid: 201, size: 2 ** 31, ctime: 1731200000 },
  ],
  "/nodes/pve-a/storage": [{ storage: "store-b", type: "dir", active: 1, used: 25, total: 100, avail: 75, content: "backup,iso" }],
};

type Call = { url: string; method: string; headers: Record<string, string>; body?: string; tls?: unknown };
function mock(opts: { ticketStatus?: number } = {}) {
  const calls: Call[] = [];
  const fetch = async (url: string, init: any = {}) => {
    calls.push({ url, method: init.method ?? "GET", headers: init.headers ?? {}, body: init.body?.toString(), tls: init.tls });
    if (url === `${BASE}/access/ticket`) {
      const st = opts.ticketStatus ?? 200;
      return new Response(JSON.stringify(st === 200 ? { data: { ticket: "PVE:fake-ticket", CSRFPreventionToken: "c" } } : { data: null }), { status: st });
    }
    const path = url.slice(BASE.length);
    if (!(path in FIX)) return new Response("not found", { status: 404 });
    return new Response(JSON.stringify({ data: FIX[path] }), { status: 200 });
  };
  return { calls, fetch };
}
const TOKEN_ENV = { PVE_HOST: HOST, PVE_TOKEN_ID: "reader@pve!ro", PVE_TOKEN_SECRET: "00000000-fake" };
async function go(args: string[], env: Record<string, string> = TOKEN_ENV, m = mock(), pass = (_: string) => null as string | null) {
  const logs: string[] = [];
  const r = await run(args, { env, fetch: m.fetch as any, pass, log: (s) => logs.push(s) });
  return { r, calls: m.calls, logs };
}

test("parse flags", () => {
  expect(parse(["tasks", "--failed", "--limit", "5", "--json"])).toMatchObject({ verb: "tasks", failed: true, limit: 5, json: true });
  expect(parse([]).verb).toBe("help");
  expect(parse(["vm", "201", "-k"])).toMatchObject({ verb: "vm", rest: ["201"], insecure: true });
  expect(parse(["tasks", "--limit", "x"]).limit).toBe(50);
});

test("baseUrl normalises host forms", () => {
  expect(baseUrl("pve.example.test")).toBe("https://pve.example.test:8006/api2/json");
  expect(baseUrl("10.0.0.5:9000")).toBe("https://10.0.0.5:9000/api2/json");
  expect(baseUrl("https://10.0.0.5:8006/api2/json/")).toBe("https://10.0.0.5:8006/api2/json");
  expect(() => baseUrl(undefined)).toThrow(/PVE_HOST/);
});

test("helpers", () => {
  expect(vmidList("201, 202 x 0 203")).toEqual([201, 202, 203]);
  expect(bytes(1536)).toBe("1.5K");
  expect(bytes(undefined)).toBe("-");
  expect(dur(90061)).toBe("1d1h");
  expect(taskState({ status: "OK" })).toBe("ok");
  expect(taskState({ status: "job errors" })).toBe("fail");
  expect(taskState({ status: "WARNINGS: 2" })).toBe("warn");
  expect(taskState({})).toBe("running");
  expect(jobCovers({ all: 1, exclude: "202" }, 201)).toBe(true);
  expect(jobCovers({ all: 1, exclude: "202" }, 202)).toBe(false);
  expect(jobCovers({ vmid: "201,202", enabled: 0 }, 201)).toBe(false);
  expect(table(["a", "bb"], [["xxx", 1]])).toBe("a    bb\nxxx  1");
});

test("no credentials -> clear error, no request sent", async () => {
  const { r, calls } = await go(["vms"], { PVE_HOST: HOST, PVE_NODE: "pve-a" });
  expect(r.ok).toBe(false);
  expect(r.error).toBe(NO_CREDS);
  expect(calls.length).toBe(0);
});

test("missing PVE_HOST -> error", async () => {
  const { r } = await go(["vms"], { PVE_TOKEN_ID: "a", PVE_TOKEN_SECRET: "b" });
  expect(r.ok).toBe(false);
  expect(r.error).toMatch(/PVE_HOST/);
});

test("token auth header + node auto-detect + vms table sorted", async () => {
  const { r, calls } = await go(["vms"]);
  expect(r.ok).toBe(true);
  expect(calls[0]!.url).toBe(`${BASE}/nodes`);
  expect(calls[0]!.headers.Authorization).toBe("PVEAPIToken=reader@pve!ro=00000000-fake");
  const lines = r.output!.split("\n");
  expect(lines[0]).toMatch(/^vmid\s+name\s+status/);
  expect(lines.slice(1).map((l) => l.split(/\s+/)[0])).toEqual(["201", "202", "203"]);
  expect(calls[0]!.tls).toBeUndefined();
});

test("insecure TLS is opt-in (env or flag)", async () => {
  const a = await go(["status"], { ...TOKEN_ENV, PVE_INSECURE: "1" });
  expect(a.calls.every((c) => (c.tls as any)?.rejectUnauthorized === false)).toBe(true);
  const b = await go(["status", "--insecure"]);
  expect(b.calls.every((c) => (c.tls as any)?.rejectUnauthorized === false)).toBe(true);
});

test("ticket login with password from pass, cookie used, secrets never logged", async () => {
  const seen: string[] = [];
  const env = { PVE_HOST: HOST, PVE_NODE: "pve-a", PVE_USER: "reader@pve", PVE_PASS_ENTRY: "some/entry" };
  const { r, calls, logs } = await go(["status", "--debug"], env, mock(), (e) => (seen.push(e), "s3cret-pw"));
  expect(r.ok).toBe(true);
  expect(seen).toEqual(["some/entry"]);
  expect(calls[0]!.method).toBe("POST");
  expect(calls[0]!.body).toBe("username=reader%40pve&password=s3cret-pw");
  expect(calls[1]!.headers.Cookie).toBe("PVEAuthCookie=PVE:fake-ticket");
  expect(logs.join("\n")).not.toContain("s3cret");
  expect(logs.join("\n")).toContain('"passEntry":true');
  expect(r.output).toMatch(/12\.5% of 8 cpus/);
});

test("ticket login failure is reported", async () => {
  const env = { PVE_HOST: HOST, PVE_NODE: "pve-a", PVE_USER: "reader@pve", PVE_PASSWORD: "wrong" };
  const { r } = await go(["vms"], env, mock({ ticketStatus: 401 }));
  expect(r.ok).toBe(false);
  expect(r.error).toMatch(/ticket login failed: HTTP 401/);
});

test("only GET requests (besides the ticket POST) across every command", async () => {
  const m = mock();
  for (const a of [["status"], ["vms"], ["vm", "201"], ["tasks"], ["tasks", "--failed"], ["task-log", FAILED_UPID], ["backups"], ["ours", "--ours", "201,203"], ["storage"]]) {
    const { r } = await go(a, TOKEN_ENV, m);
    expect(r.ok).toBe(true);
  }
  expect(m.calls.filter((c) => c.method !== "GET")).toEqual([]);
});

test("tasks marks failed jobs; --failed filters", async () => {
  const all = await go(["tasks"]);
  expect(all.r.output).toMatch(/vzdump .*FAIL\s+job errors/);
  expect(all.r.output).toMatch(/RUNNING\s+running/);
  expect(all.r.output).toContain("1 failed");
  const f = await go(["tasks", "--failed", "--json"]);
  const rows = JSON.parse(f.r.output!);
  expect(rows.length).toBe(1);
  expect(rows[0].state).toBe("fail");
  expect(f.calls.at(-1)!.url).toBe(`${BASE}/nodes/pve-a/tasks?limit=50&errors=1`);
});

test("task-log takes node from the UPID and prints lines", async () => {
  const { r, calls } = await go(["task-log", FAILED_UPID]);
  expect(r.output).toBe("INFO: starting backup\nERROR: Backup of VM 203 failed - no space left");
  expect(calls.some((c) => c.url.endsWith("/nodes"))).toBe(false);
  expect((await go(["task-log", "nope"])).r.ok).toBe(false);
});

test("vm shows status + config without digest", async () => {
  const { r } = await go(["vm", "201"]);
  expect(r.output).toMatch(/name\s+vm-a/);
  expect(r.output).toMatch(/net0\s+virtio=/);
  expect(r.output).not.toMatch(/digest/);
  expect((await go(["vm", "abc"])).r.ok).toBe(false);
});

test("backups lists jobs and archives newest first", async () => {
  const { r } = await go(["backups", "--json"]);
  const o = JSON.parse(r.output!);
  expect(o.jobs[0].id).toBe("backup-1");
  expect(o.files.map((f: any) => f.volid)).toEqual(["store-b:backup/vzdump-qemu-201-new.vma.zst", "store-b:backup/vzdump-qemu-201-old.vma.zst"]);
});

test("ours: coverage per VM from PVE_OURS, flags uncovered", async () => {
  const { r } = await go(["ours", "--json"], { ...TOKEN_ENV, PVE_OURS: "201,203,299" });
  const rows = JSON.parse(r.output!);
  expect(rows.map((x: any) => [x.vmid, x.name, x.status, x.jobs, x.archives])).toEqual([
    [201, "vm-a", "running", ["backup-1"], 2],
    [203, "vm-c", "running", [], 0],
    [299, null, "missing", [], 0],
  ]);
  expect(rows[0].latest).toBe(1731200000);
  const plain = await go(["ours"], { ...TOKEN_ENV, PVE_OURS: "201 203" });
  expect(plain.r.output).toContain("no backup coverage: 203");
  expect((await go(["ours"])).r.error).toMatch(/PVE_OURS/);
});

test("storage table", async () => {
  const { r } = await go(["storage"]);
  expect(r.output).toMatch(/store-b\s+dir\s+yes\s+25B\s+100B\s+75B\s+25%\s+backup,iso/);
});

test("help and unknown command", async () => {
  expect((await go(["--help"])).r.output).toContain("read-only");
  expect((await go(["start", "201"])).r.ok).toBe(false);
});

test("source has no write endpoints", () => {
  const src = readFileSync(join(import.meta.dir, "index.ts"), "utf8");
  for (const bad of ["/status/start", "/status/stop", "/status/shutdown", "/status/reboot", "method: \"PUT\"", "method: \"DELETE\"", "vzdump\"", "/clone", "/resize"]) {
    expect(src.includes(bad)).toBe(false);
  }
});
