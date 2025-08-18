# Botnet/C2 Fingerprinting: ERMAC 3.x Panels and Exfil Servers

{{#include ../../banners/hacktricks-training.md}}

## Overview

When Android overlay trojans like ERMAC are run as Malware-as-a-Service (MaaS), the operator infrastructure often exposes highly fingerprintable traits that defenders and threat hunters can leverage for internet-scale discovery and takedown workflows.

This page summarizes concrete, testable indicators for ERMAC v3.x control planes and exfiltration servers, plus practical queries and probes you can adopt across OSINT platforms and your own scanners.

> Important: Only use the techniques below in lawful contexts (defensive hunting, incident response, takedown coordination, or with explicit authorization). Many panels found on the internet are criminal infrastructure.

---

## ERMAC 3.x infrastructure components

- Laravel/PHP C2 backend + React operator panel
  - Session cookie: ermac_session
  - Title: ERMAC 3.0 PANEL
  - API path prefix: /api/v1/*
  - Inject HTML served under: /public/injects
- Standalone Go exfiltration server (HTTP)
  - Frequently protected by Basic auth with realm: LOGIN | ERMAC
  - Used to decouple high-volume log ingestion from the main Laravel C2

---

## Internet-scale discovery queries

### Shodan

- Panels by HTML title:
  - shodan search 'http.title:"ERMAC 3.0 PANEL"'
- Panels by Laravel session cookie name:
  - shodan search 'http.headers.set_cookie:"ermac_session"'
- Go exfil servers by Basic realm string:
  - shodan search '"WWW-Authenticate: Basic realm=\"LOGIN | ERMAC\""'

### Censys (v2/v3)

- Panels by title:
  - services.http.response.html_title: "ERMAC 3.0 PANEL"
- Panels by cookie:
  - services.http.response.headers.set_cookie: ermac_session
- Exfil servers by Basic realm:
  - services.http.response.headers.www_authenticate: "LOGIN | ERMAC"

### FOFA/ZoomEye/Quake examples

- FOFA:
  - title="ERMAC 3.0 PANEL"
  - header="ermac_session"
  - header="LOGIN | ERMAC"

> The cookie/title/realm trio yields high-confidence pivots across engines.

---

## Probing at scale (httpx / nuclei)

- Extract titles/cookies/headers from candidate hosts:

```bash
cat hosts.txt \
  | httpx -silent -title -status-code -content-length -set-cookie -server \
  | tee httpx.out

# Filter ERMAC candidates
grep -E 'ERMAC 3\.0 PANEL|ermac_session|LOGIN \| ERMAC' httpx.out
```

- Minimal nuclei template for the panel title and cookie:

```yaml
id: ermac-panel-fingerprint
info:
  name: ERMAC 3.x Panel Fingerprint
  severity: info
requests:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers-condition: or
    matchers:
      - type: word
        words:
          - "<title>ERMAC 3.0 PANEL</title>"
      - type: regex
        regex:
          - "(?i)set-cookie: [^\r\n]*ermac_session"
```

- Minimal nuclei template for the Go exfil server realm:

```yaml
id: ermac-exfil-basic-realm
info:
  name: ERMAC Go Exfil Server Basic Realm
  severity: info
requests:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: word
        part: header
        words:
          - 'WWW-Authenticate: Basic realm="LOGIN | ERMAC"'
```

---

## Operator-side weaknesses to test (only if authorized)

The ERMAC v3.0 source leak highlights several recurring misconfigurations in live panels:

- Default credentials: root / changemeplease
- Open operator self-registration (some deployments)
- JWT signed with a hardcoded HS* secret:
  - h3299xK7gdARLk85rsMyawT7K4yGbxYbkKoJo8gO3lMdl9XwJCKh2tMkdCmeeSeK
- Static admin bearer token embedded in code (varies by build)

Example checks:

```bash
# 1) Test default creds against panel login (React frontend)
curl -sk -c cookies.txt -X POST \
  -H 'Content-Type: application/json' \
  -d '{"email":"root","password":"changemeplease"}' \
  https://panel.example.com/api/v1/sign-in

# 2) Check if self-registration is open (varies per build/route)
# Look for endpoints enabling account creation without auth
# e.g., /api/v1/sign-up or misused accounts APIs

# 3) If JWT HS256 secret is in use, mint a token (POC)
python3 - <<'PY'
import jwt, time
key = 'h3299xK7gdARLk85rsMyawT7K4yGbxYbkKoJo8gO3lMdl9XwJCKh2tMkdCmeeSeK'
payload = {"sub":"1","role":"admin","iat":int(time.time()),"exp":int(time.time())+3600}
print(jwt.encode(payload, key, algorithm='HS256'))
PY
# Then hit an authenticated route with: Authorization: Bearer <token>
```

> Warning: Never access or manipulate criminal infrastructure without explicit legal authorization. Prefer coordinated disclosure/takedown with providers and LE.

---

## Useful backend routes (triage)

Observed API surface in leaked v3.0 codebase (Laravel):

- Unauthenticated:
  - POST /api/v1/sign-in
  - POST /api/v1/smartInjections/{sessionId}
  - POST /api/v1/smartInjections/session/list
  - PUT  /api/v1/smartInjections/session/{session}
- Authenticated (cookie ermac_session and/or Bearer JWT):
  - GET    /api/v1/getUserInfo
  - POST   /api/v1/injects/getInjectionsList
  - POST   /api/v1/injects/createInjection
  - DELETE /api/v1/injects/deleteInjection
  - POST   /api/v1/injects/{injection}/editInjection
  - POST   /api/v1/sendBotsCommand
  - DELETE /api/v1/deleteBot
  - DELETE /api/v1/deleteAllRemovedApp
  - PUT    /api/v1/{bot}/setBotType
  - GET    /api/v1/{bot}/commands/getCommandsList
  - PUT    /api/v1/{bot}/settings/updateBotSettings
  - PUT    /api/v1/{bot}/injects/updateBotInjections
  - DELETE /api/v1/deleteLog
  - PUT    /api/v1/editLogComment
  - POST   /api/v1/accounts/getAccountsList
  - POST   /api/v1/accounts/createAccount
  - PUT    /api/v1/accounts/{user}/editAccount
  - DELETE /api/v1/accounts/{user}/deleteAccount
  - POST   /api/v1/permissions/getPermissionsList
  - PUT    /api/v1/permissions/updatePermission
  - POST   /api/v1/counts/getCounts
  - POST   /api/v1/counts/getStats
  - POST   /api/v1/autoCommands/getAutoCommandsList
  - PUT    /api/v1/autoCommands/updateAutoCommand
  - POST   /api/v1/search

Use these paths to fingerprint panels behind custom brands or non-default titles.

---

## Hunting exposed injects and exfil endpoints

- Panels commonly store overlay HTML under /public/injects. If directory listing is enabled or access controls are weak, you may enumerate or retrieve templates for detection/poisoning (defender-only).

```bash
# Quick probe
curl -sk https://panel.example.com/public/injects/ | head
```

- Exfiltration servers (Go) often advertise Basic realm "LOGIN | ERMAC" and accept logs/device data over minimal HTTP endpoints. Fingerprint and block these hosts even when the main C2 is hidden behind other infrastructure.

---

## Defender workflow

1. Enumerate candidates across engines using the cookie/title/realm pivots.
2. Verify with httpx/nuclei.
3. In authorized contexts, assess operator auth (default creds, open registration) and token schemes (leaked HS secret).
4. Coordinate sinkholing/takedown of exfil servers; watch for CRUD changes in /public/injects across known panels.

---

## References

- [Hunt.io — ERMAC V3.0 Banking Trojan: Full Source Code Leak and Infrastructure Analysis](https://hunt.io/blog/ermac-v3-banking-trojan-source-code-leak)

{{#include ../../banners/hacktricks-training.md}}