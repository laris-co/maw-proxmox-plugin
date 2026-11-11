# maw-proxmox-plugin

`maw proxmox` is a **read-only** view of a Proxmox VE host through its REST API (`/api2/json`), plus one guarded write command, `maw proxmox create`, that makes a new Home Assistant OS or Ubuntu VM (plan by default, see [Creating VMs (write)](#creating-vms-write)).

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
maw proxmox inventory [--only-ours]       every VM: what it is (note, os, tags), size, ours, backup age
maw proxmox tasks [--failed] [--limit N]  recent tasks (default 50); failed ones marked FAIL
maw proxmox task-log <upid>               log lines of one task
maw proxmox backups                       backup jobs + backup archives on every storage
maw proxmox ours [--ours 1,2,3]           only the listed VMs (default $PVE_OURS) with backup coverage
maw proxmox storage                       storage pools: used / total
maw proxmox create haos|ubuntu ...        new VM: plan only unless --apply --yes (the only write)

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
| `PVE_ALLOWED_NETS` | `create` only: comma list of CIDRs a new VM's IP must be inside. Unset = every IP refused |
| `PVE_DENY_NETS` | `create` only: CIDRs a new VM's IP must never be in (wins over allowed) |
| `PVE_RAM_RESERVE_GIB` | `create` only: RAM kept free for the host (default 5) |
| `PVE_GW` / `PVE_DNS` | `create` only: default gateway / nameservers (DNS default `1.1.1.1,8.8.8.8`) |
| `PVE_STORAGE_VM` / `PVE_STORAGE_IMG` / `PVE_BRIDGE` | `create` only: disk storage (default `ssd`), import-image storage (default `local`), bridge (default `vmbr0`) |

Each of these can also be saved with `maw proxmox config set` (keys `host node user pass_entry token_id insecure ours allowed_nets deny_nets ram_reserve_gib gw dns storage_vm storage_img bridge`). Env wins over the saved file.

The token is used if both token variables are set; otherwise ticket login. With neither, the command stops with a message listing these options and sends no request. Secrets are never printed; `--debug` prints only lengths and booleans.

Example:

```
export PVE_HOST=pve.example.test PVE_INSECURE=1 PVE_USER=reader@pve PVE_OURS=201,203
PVE_PASSWORD="$(pass show <your-entry>)" maw proxmox vms
```

## Read-only, on purpose

Every command except `create` sends only `GET` requests (plus the login `POST`). There is no start, stop, shutdown, reboot, clone, delete, backup-now or config-write call for an existing VM anywhere in the code. All write calls live in `src/create.ts`; a test fails if `src/index.ts` gains one, and another runs every other command and fails on any non-GET request.

A host may run VMs that belong to someone else (for example a client's VM). Any future write command must refuse VMs outside an explicit allow-list, and acting on a VM that is not yours needs the host owner's sign-off first.

## Creating VMs (write)

```
maw proxmox config set allowed_nets=203.0.113.0/24 deny_nets=198.51.100.0/24 gw=203.0.113.254 ram_reserve_gib=5

maw proxmox create haos   --vmid 120 --name ha-test --ip 203.0.113.56/24              # plan only
maw proxmox create haos   --vmid 120 --name ha-test --ip 203.0.113.56/24 --apply --yes # create
maw proxmox create ubuntu --vmid 121 --name ub-test --ip 203.0.113.57/24 --ssh-key ~/.ssh/id_ed25519.pub
```

Options: `--gw --dns --cores (2) --ram MiB (2048) --disk GiB (haos 48, ubuntu 40) --image --storage-vm (ssd) --storage-img (local) --bridge (vmbr0)`; haos also `--iface (enp6s18) --boot-wait s (150)`; ubuntu `--ssh-key PATH (required) --ciuser (ubuntu)`; both `--wait-min (5)`.

**Plan is the default.** Without flags the command runs every check, prints PASS/FAIL for each, and prints the exact API calls (method, path, every parameter) that would be sent. It writes nothing. It writes only with **both** `--apply` and `--yes`; `--apply` alone is refused.

**Guards.** If any check fails the command exits non-zero and sends no write:

1. vmid not used by any qemu or lxc guest; name not used either.
2. IP inside `allowed_nets` (none configured = refuse everything), not inside `deny_nets`, not the network/broadcast address; gateway inside the same subnet.
3. IP is silent: no answer on tcp 22/80/443 (a refused connection counts as an answer) and no ping reply, probed from the machine running the command; and the IP is not in any guest's `ipconfigN`/`netN` or guest-agent address list.
4. RAM: sum of `maxmem` of running guests + new RAM <= physical RAM - `ram_reserve_gib` (default 5). The numbers are printed.
5. Target storage has free space >= disk size + 10%.
6. The image is in `<storage-img>:import/` (`GET .../content?content=import`).
7. Ubuntu: `--ssh-key` is readable and is an OpenSSH public key (a private key is refused).

**What apply sends.** `POST /nodes/{node}/qemu` (create + `import-from` the image), waits for the task and requires exitstatus `OK`, `PUT .../resize` scsi0 to `--disk`, `POST .../status/start`, then checks the VM is `running`.

- **haos**: UEFI (`bios=ovmf`, `machine=q35`, `efidisk0 ... pre-enrolled-keys=0`; with pre-enrolled keys HAOS does not boot). HAOS has no SSH, so after a boot wait the static IP is typed at the `ha >` prompt through `PUT .../sendkey`, one key per call: `network update enp6s18 --ipv4-method static --ipv4-address ... --ipv4-gateway ... --ipv4-nameserver ...`. Then it waits for ping or the observer (:4357) and probes :4357, :80 and :8123. **HAOS onboarding is open until the first user is created** - finish onboarding at `http://<ip>:8123` right away.
- **ubuntu**: legacy SeaBIOS (no `bios`/`efidisk0`; OVMF hangs the cloud image), `cpu=host`, cloud-init (`ide2 cloudinit`, `ipconfig0`, `nameserver`, `ciuser`, `sshkeys`). `sshkeys` is percent-encoded once before the form encoding, because Proxmox stores it percent-encoded and rejects a raw key. Then it waits for tcp 22.

With ticket auth, writes send the `CSRFPreventionToken` from the login (API tokens need none). The account needs `VM.Allocate`, `VM.Config.*`, `VM.PowerMgmt`, `VM.Console` and `Datastore.AllocateSpace` on the target storage. `create` never modifies or deletes an existing VM; if a step fails it stops and leaves the half-made VM for a human to inspect.

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
