# Android Overlay Trojans: ERMAC 3.x Case Study (Infra + TTPs)

{{#include ../../banners/hacktricks-training.md}}

## Why this page

Android banking/credential-stealing malware families frequently rely on HTML overlays ("form injects") displayed on top of targeted apps to phish credentials and exfiltrate data. The ERMAC 3.x leak provides a rare, full-source view into this pipeline, from APK builder to backend C2 and exfiltration services. This page distills practical indicators and techniques you can use in malware analysis, detection engineering, and incident response.

---

## High-level architecture (ERMAC 3.x)

- Builder (operator tool): compiles the trojanized APK with operator-selected C2 URLs, AES key, locales, feature flags, and app-target inject list.
- Android implant (Kotlin): phones home, requests high-risk permissions, performs environment checks, polls for operator commands, renders HTML overlays, and exfiltrates via a WebView JavaScript bridge.
- Laravel/PHP backend (C2): stores bots, logs, injects (HTML under /public/injects), users/permissions; exposes a rich /api/v1/* surface consumed by a React operator panel.
- Go exfil server: minimal HTTP service commonly used as the ingestion front for logs and device data, often shielded with Basic auth realm "LOGIN | ERMAC".

Data flow:

1) APK → Exfil server: device fingerprint, logs, overlay captures. 2) Operator panel → Laravel C2: CRUD of inject templates and device commands. 3) Implant → C2: periodic polling for commands/inject list.

---

## Overlay theft pipeline (Android)

- Inject templates: on the server at /public/injects/<target>.html
- Implant loads HTML into a WebView and bridges JavaScript to native code via addJavascriptInterface under the name "Android".
- Exfiltration happens from the page with a JS callback:

```js
// From injected HTML overlay
Android.send_log_injects(JSON.stringify({
  pkg: targetPackage,
  form: { user: u, pass: p, extra: x },
  ts: Date.now()
}))
```

- Device is then driven (if needed) via notifications or Accessibility/UI automation to bring the target app to foreground and display the overlay.

Static triage tips:

- Grep decompiled sources/smali for:
  - addJavascriptInterface(.*, "Android")
  - send_log_injects( or "send_log_injects"
  - webkit.WebView and hard-coded overlay URLs (e.g., "/public/injects")
- Manifest indicators: requests Device Admin, SMS, Accessibility, package management, overlay/notification privileges.

---

## Crypto and traffic detection

- C2 comms use AES-CBC with PKCS5 padding and a fixed IV:
  - IV string: 0123456789abcdef
  - Key: operator-configured (from builder/panel)

Security impact:

- The static IV leaks patterns and makes traffic reliably decryptable once the key is known/obtained on a seized panel or builder.

Python snippet to decrypt when key is known:

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

iv  = b"0123456789abcdef"
key = bytes.fromhex("<hex-encoded-16/24/32-byte-key>")  # example if stored as hex

def dec(ct):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size)
```

Network heuristics:

- Look for repeated CBC blocks and fixed 16-byte IV prefix in first encrypted requests.
- Couple with infra IOCs below to raise confidence.

---

## Operator command set (implant excerpts)

Observed commands in ERMAC 3.x (non-exhaustive):

- sendsms, sendsmsall, getsms
- getcontacts, getaccounts, logaccounts, getinstallapps
- startinject, startapp, openurl, push
- startussd, forwardcall, calling
- startadmin, deleteapplication, clearcache/clearcash, killme
- updateinjectandlistapps
- gmailtitles, getgmailmessage
- fmmanager (e.g., ls, dl)
- takephoto

These map to fraud operations (ODF), credential theft, device control, and persistence.

---

## C2/back-end fingerprints (for IR and takedown)

- React panel title: ERMAC 3.0 PANEL
- Cookie name: ermac_session (Laravel session cookie)
- Inject storage: /public/injects on the panel host
- Go exfil server: Basic realm "LOGIN | ERMAC"
- Common API routes (Laravel):
  - Unauth: POST /api/v1/sign-in, POST /api/v1/smartInjections/{sessionId}, POST /api/v1/smartInjections/session/list, PUT /api/v1/smartInjections/session/{session}
  - Auth: GET /api/v1/getUserInfo, POST /api/v1/injects/getInjectionsList, POST /api/v1/sendBotsCommand, ... (see full list in the infra page below)

See the infra hunting playbook with Shodan/Censys/nuclei queries:

{{#ref}}
../../generic-methodologies-and-resources/external-recon-methodology/botnet-c2-fingerprinting-ermac.md
{{#endref}}

---

## Operator-side weaknesses observed in the leak

- Hardcoded JWT HS* secret (enables forging of API tokens where used):
  - h3299xK7gdARLk85rsMyawT7K4yGbxYbkKoJo8gO3lMdl9XwJCKh2tMkdCmeeSeK
- Static admin bearer token present in some builds
- Default credentials: root / changemeplease
- Open operator self-registration on some panels

Use only for authorized disruption/takedown and IR simulations. Do not access criminal infrastructure without legal authority.

---

## Detection and DFIR playbook

Mobile endpoint/AV/MDM:

- Flag apps using WebView bridges named "Android" exposing sensitive methods; alert on JavaScript invoking send_log_injects.
- Heuristic on permission set correlation: BIND_DEVICE_ADMIN, READ_SMS/RECEIVE_SMS, REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, PACKAGE_USAGE_STATS, MANAGE_OVERLAY/Accessibility usage.
- Detect Accessibility-based automation and overlay windows on sensitive app UIs.

Network/SOC:

- Pivot on infra IOCs: ermac_session cookie, title ERMAC 3.0 PANEL, Basic realm LOGIN | ERMAC.
- Block/sinkhole Go exfil endpoints; monitor CRUD and retrieval under /public/injects across known panels.
- Leverage the static IV to build signatures for ERMAC CBC payload shapes; decrypt captured traffic when the server key is obtained during takedown.

Forensic tips:

- On device: collect APK, decompile with jadx; search for WebView.addJavascriptInterface and send_log_injects strings; extract operator C2 URLs and AES key from builder-configured constants.
- On panel: dump /public/injects and /api/v1/* usage to map targeting and operator actions; extract JWT/bearer secrets from config when possible.

---

## References

- [Hunt.io — ERMAC V3.0 Banking Trojan: Full Source Code Leak and Infrastructure Analysis](https://hunt.io/blog/ermac-v3-banking-trojan-source-code-leak)
- [Android WebView addJavascriptInterface documentation](https://developer.android.com/reference/android/webkit/WebView#addJavascriptInterface(java.lang.Object,%20java.lang.String))
- [Why static IVs break CBC security](https://crypto.stackexchange.com/questions/20941/why-must-iv-be-random-in-cbc-mode)

{{#include ../../banners/hacktricks-training.md}}