# maw-proxmox-plugin

`maw proxmox` is a **read-only** view of a Proxmox VE host through its REST API (`/api2/json`).

## Install

```
maw plugin install laris-co/maw-proxmox-plugin
maw proxmox --help
```

Update: `maw plugin update proxmox`

## Quick start

Save your settings once (stored in `~/.config/maw-proxmox/config.json`, mode 0600). Passwords are never saved: point `pass_entry` at your `pass` store instead.

```
maw proxmox config set host=<host>:8006 user=<user>@pve pass_entry=<pass/entry> insecure=1 ours=<vmid,vmid>
maw proxmox config            # show what is saved
maw proxmox status
maw proxmox vms
maw proxmox tasks --failed
```

After the first login the ticket is cached for ~1h50m (`~/.cache/maw-proxmox/ticket.json`, 0600), so `pass`/gpg is not asked again on every command. `maw proxmox logout` forgets it. Environment variables always override the saved config.

```
maw proxmox status                        node cpu / mem / rootfs / uptime / version
maw proxmox vms                           all qemu VMs: vmid name status cpus mem uptime
maw proxmox vm <vmid>                     status/current + config of one VM
maw proxmox inventory                     every VM: what it is (note, os, tags), size, ours, backup age
maw proxmox tasks [--failed] [--limit N]  recent tasks (default 50); failed ones marked FAIL
maw proxmox task-log <upid>               log lines of one task
maw proxmox backups                       backup jobs + backup archives on every storage
maw proxmox ours [--ours 1,2,3]           only the listed VMs (default $PVE_OURS) with backup coverage
maw proxmox storage                       storage pools: used / total

--json  JSON output    --insecure  accept a self-signed cert    --debug  auth diagnostics (lengths/booleans only)
```

## Configuration

Nothing about any host is stored in this repo. Everything comes from the environment:

| Variable | Meaning |
|---|---|
| `PVE_HOST` | **required.** `host`, `host:port` or `https://host:port` (port defaults to 8006) |
| `PVE_NODE` | node name. If unset it is read from `GET /nodes` (works when the cluster has one node) |
| `PVE_INSECURE=1` | accept a self-signed certificate (same as `--insecure`). Off by default. A fresh Proxmox install uses a self-signed cert, so you will usually need this unless you pinned a real cert |
| `PVE_TOKEN_ID` + `PVE_TOKEN_SECRET` | API token auth, sent as `Authorization: PVEAPIToken=ID=SECRET`. Preferred; use a token with a read-only role (`PVEAuditor`) |
| `PVE_USER` + `PVE_PASSWORD` | ticket login (`POST /access/ticket`, then the `PVEAuthCookie`) |
| `PVE_USER` + `PVE_PASS_ENTRY` | same, with the password read from `pass show <entry>` (first line) |
| `PVE_OURS` | comma or space list of vmids for `maw proxmox ours` |

Each of these can also be saved with `maw proxmox config set` (keys `host node user pass_entry token_id insecure ours`). Env wins over the saved file.

The token is used if both token variables are set; otherwise ticket login. With neither, the command stops with a message listing these options and sends no request. Secrets are never printed; `--debug` prints only lengths and booleans.

Example:

```
export PVE_HOST=pve.example.test PVE_INSECURE=1 PVE_USER=reader@pve PVE_OURS=201,203
PVE_PASSWORD="$(pass show <your-entry>)" maw proxmox vms
```

## Read-only, on purpose

v1 sends only `GET` requests (plus the login `POST`). There is no start, stop, shutdown, reboot, create, clone, delete, backup-now or config-write call anywhere in the code, and a test fails if one appears.

A host may run VMs that belong to someone else (for example a client's VM). Any future write command must refuse VMs outside an explicit allow-list, and acting on a VM that is not yours needs the host owner's sign-off first.

## Notes

- `tasks --failed` uses the API's `errors=1` filter. A failed scheduled backup shows as type `vzdump` with a status such as `job errors`; read the details with `maw proxmox task-log <upid>` (get the upid from `tasks --failed --json`).
- `task-log` reads the node name from the UPID, so it works without `PVE_NODE`.
- `ours` counts a VM as covered by a job when the job is enabled and lists the vmid, or is an `all` job that does not exclude it. Pool-based jobs are not resolved and are shown as `pool:<name>` in `backups`.
- Times are shown in the local time zone (`TZ`).

## Development

```
ghq get https://github.com/laris-co/maw-proxmox-plugin
maw plugin install ~/Code/github.com/laris-co/maw-proxmox-plugin
bun test
```
