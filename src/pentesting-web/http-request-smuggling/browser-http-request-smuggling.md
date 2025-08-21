# Browser HTTP Request Smuggling

{{#include ../../banners/hacktricks-training.md}}

Browser-powered desync (aka client-side request smuggling) abuses the victim’s browser to enqueue a mis-framed request onto a shared connection so that subsequent requests are parsed out-of-sync by a downstream component. Unlike classic FE↔BE smuggling, payloads are constrained by what a browser can legally send cross-origin.

Key constraints and tips
- Only use headers and syntax that a browser can emit via navigation, fetch, or form submission. Header obfuscations (LWS tricks, duplicate TE, invalid CL) generally won’t send.
- Target endpoints and intermediaries that reflect inputs or cache responses. Useful impacts include cache poisoning, leaking front-end injected headers, or bypassing front-end path/method controls.
- Reuse matters: align the crafted request so it shares the same HTTP/1.1 or H2 connection as a high-value victim request. Connection-locked/stateful behaviors amplify impact.
- Prefer primitives that do not require custom headers: path confusion, query-string injection, and body shaping via form-encoded POSTs.
- Validate genuine server-side desync vs. mere pipelining artifacts by re-testing without reuse, or by using the HTTP/2 nested-response check.

For end-to-end techniques and PoCs see:
- PortSwigger Research – Browser‑Powered Desync Attacks: https://portswigger.net/research/browser-powered-desync-attacks
- PortSwigger Academy – client‑side desync: https://portswigger.net/web-security/request-smuggling/browser/client-side-desync

## References
- [https://portswigger.net/research/browser-powered-desync-attacks](https://portswigger.net/research/browser-powered-desync-attacks)
- [https://portswigger.net/web-security/request-smuggling/browser/client-side-desync](https://portswigger.net/web-security/request-smuggling/browser/client-side-desync)
- Distinguishing pipelining vs smuggling (background on reuse false-positives): https://portswigger.net/research/how-to-distinguish-http-pipelining-from-request-smuggling

{{#include ../../banners/hacktricks-training.md}}
