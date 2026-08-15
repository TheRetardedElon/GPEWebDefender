# Deploy samples

Placeholders only. Copy onto **your** boxes and fill in **your** values.

| File | For |
|------|-----|
| `gpewebdefender.service.example` | Manager systemd unit |
| `gpewebdefender-agent.service.example` | Agent on each web host |
| `env.example` | Shared ingest token (`/etc/gpewebdefender/env`) |
| `nginx-gwd.conf.example` | Optional HTTPS UI + basic auth |

Typical path:

1. One monitor box: binary + `rules/` + `dochub/` + manager unit + token file.
2. Optional: drop `geoip.mmdb` in the manager working directory.
3. Each host that has HTTP access logs: same binary + agent unit + the **same** token.
4. Firewall: ingest port only from those web hosts.
5. Optional nginx: extra basic auth for humans. Deny `/api/ingest` on the public vhost.
6. Open Settings (or `/login`) and create the first admin (or set `SIEM_ADMIN_USER` / `SIEM_ADMIN_PASSWORD` once, then remove the password). The ingest token cannot manage users.
7. Optional: copy `siem.example` to `/usr/local/bin/siem` so `siem restart` / `siem logs` work. Do **not** put this Go binary under PM2 — systemd already supervises it.

Nothing in this folder is an inventory of a real deployment.
