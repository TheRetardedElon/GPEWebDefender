# Deploy samples

Two ways to get a running manager. Both are real. Pick one.

## Method A — script

From the repo, as root, on Linux with systemd:

```sh
chmod +x deploy/install-manager.sh deploy/install-agent.sh

# one box that already has the access log
sudo ./deploy/install-manager.sh --all-in-one --tail /var/log/nginx/access.log --journal

# or a dedicated monitor, then an agent on each web box
sudo ./deploy/install-manager.sh
sudo ./deploy/install-agent.sh --url http://MONITOR:8787 --name web-1 --tail /var/log/nginx/access.log --journal

# later, if you want that host to take block orders from the dashboard:
# Settings → Paired hosts → invent a phrase → Pair a host… then:
sudo ./deploy/install-agent.sh --url http://MONITOR:8787 --name web-1 \
  --tail /var/log/nginx/access.log --journal --code ABCD-2341 --block fail2ban
```

The manager script writes `/etc/gpewebdefender/env` (token) if it is missing, installs systemd, copies `rules/` + `dochub/`.

Then from your laptop:

```sh
ssh -L 8787:127.0.0.1:8787 user@THEBOX
```

Open http://127.0.0.1:8787/login and create the first admin.

## Method B — copy the examples

| File | For |
|------|-----|
| `gpewebdefender.service.example` | Manager systemd unit |
| `gpewebdefender-agent.service.example` | Agent on each web host |
| `env.example` | Shared ingest token (`/etc/gpewebdefender/env`) |
| `nginx-gwd.conf.example` | Optional HTTPS UI |
| `siem.example` | Optional `/usr/local/bin/siem` helper (`siem restart`, `siem logs`) |
| `install-manager.sh` | Method A for the manager |
| `install-agent.sh` | Method A for an agent (`--code` / `--block` optional) |
| `fail2ban-gpesiem.jail` + `.filter` | Dedicated jail for dashboard bans (not the sshd jail) |

Typical path:

1. One monitor box: binary + `rules/` + `dochub/` + manager unit + token file.
2. Optional: drop `geoip.mmdb` in the manager working directory.
3. Each host that has HTTP access logs: same binary + agent unit + the **same** token.
4. Firewall: ingest port only from those web hosts.
5. Optional nginx: extra login for humans. Deny `/api/ingest` on the public vhost.
6. Open Settings (or `/login`) and create the first admin (or set `SIEM_ADMIN_USER` / `SIEM_ADMIN_PASSWORD` once, then remove the password). The ingest token cannot manage users.
7. Optional containment: Settings → Paired hosts → phrase → mint a code → `gpewebdefender pair` (or `install-agent.sh --code`) on that box → Approve. DocHub **20**. The ingest token still cannot ban.
8. Optional Status: after Approve, open Status and click Check (manager works without pairing). DocHub **21**. Nothing is polled until you click.
9. Optional: copy `siem.example` to `/usr/local/bin/siem`. Do **not** put this Go binary under PM2 — systemd already supervises it.

Nothing in this folder is an inventory of a real deployment. Fill in *your* names on *your* boxes.
