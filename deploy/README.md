# Deploy samples

Placeholders only. Copy onto **your** boxes and fill in **your** values.

| File | For |
|------|-----|
| `gpewebdefender.service.example` | Manager systemd unit |
| `gpewebdefender-agent.service.example` | Agent on each web host |
| `env.example` | Shared ingest token (`/etc/gpewebdefender/env`) |
| `nginx-siem.conf.example` | Optional HTTPS UI + basic auth |

Typical path:

1. One monitor box: binary + `rules/` + `dochub/` + manager unit + token file.
2. Optional: drop `geoip.mmdb` in the manager working directory.
3. Each host that has HTTP access logs: same binary + agent unit + the **same** token.
4. Firewall: ingest port only from those web hosts.
5. Optional nginx: UI login for humans. Deny `/api/ingest` on the public vhost.

Nothing in this folder is an inventory of a real deployment.
