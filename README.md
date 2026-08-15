# GPEWebDefender

A **web-attack monitor**. It sits next to nginx / Caddy / the app, tails access logs, and tells you when a site is being probed or exploited. If this process dies, the site keeps serving.

It is not Wazuh, not OSSEC, and not a WAF.

The command is `gpewebdefender`. Hosts, tokens, map pins, GeoIP, and log paths are flags or env files — nothing about a specific company or server is compiled in. Copy `deploy/*.example` and fill in *your* values on *your* boxes.

Docs: [`dochub/index.html`](dochub/index.html), or `/docs/` on a running manager.

## What it watches

Anything that shows up in an access log:

- SQL injection, XSS, path traversal, command injection, SSTI, PHP wrappers
- Log4Shell / Spring4Shell / cloud-metadata SSRF in the URL or UA
- Secret-file and admin hunting (`.env`, `.git`, phpMyAdmin, wp-login, actuators)
- Known scanners (sqlmap, nuclei, nikto, ffuf, …)
- 404 storms, 401/403 hammering, login brute force, request floods

It **cannot** see POST bodies unless you log them (you usually should not). GET/query/path/UA/status is what access logs give you. That still catches almost every internet scanner and most opportunistic web attacks.

## Run

```bat
go build -o gpewebdefender.exe .\cmd\gpewebdefender
gpewebdefender.exe demo
```

Open http://127.0.0.1:8787

Against a real access log:

```bat
gpewebdefender.exe serve --tail C:\path\to\access.log --listen 127.0.0.1:8787
```

From another server:

```bat
gpewebdefender.exe agent --url http://siem-host:8787 --token SECRET --tail /var/log/nginx/access.log
```

Manager must be started with the same `--token`.

## Log formats

- nginx / Apache combined (default)
- nginx / Caddy / Traefik JSON (`remote_addr` / `request_uri` / `status` / …)

JSON access logs are worth switching to. Example nginx snippet:

```nginx
log_format json_gwd escape=json
  '{'
    '"remote_addr":"$remote_addr",'
    '"request_method":"$request_method",'
    '"request_uri":"$request_uri",'
    '"status":$status,'
    '"body_bytes_sent":$body_bytes_sent,'
    '"http_user_agent":"$http_user_agent",'
    '"http_referer":"$http_referer",'
    '"host":"$host",'
    '"time_iso8601":"$time_iso8601"'
  '}';
access_log /var/log/nginx/access.json json_gwd;
```

## Rules

Built-in: `rules/web.yaml`. Add your own with `--rules path/to/more.yaml`.

```yaml
rules:
  - id: web.admin.probe
    title: Admin path probe
    severity: medium
    category: recon
    fields: [path]
    pattern: '(?i)^/(admin|backoffice)/'
```

## Resource target

One static Go binary + SQLite. A dedicated **2 CPU / 2 GB** box is plenty. No JVM, no OpenSearch, no Elasticsearch.

## Publish

This tree is the public product. It has no inventory, tokens, or hostnames.

```bat
go test ./...
set GOOS=linux
set GOARCH=amd64
set CGO_ENABLED=0
go build -o gpewebdefender-linux-amd64 .\cmd\gpewebdefender
```

Then `git init` (already done if you cloned) and push to the public remote you choose. Keep live fleet config out of this repository.
