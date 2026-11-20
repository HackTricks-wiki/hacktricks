# HackTricks organization guide

## Principles

- One home per mechanism; entry points retain prerequisites and link; split by task/prerequisite, not size.
- Main: general techniques; Cloud: provider/IAM; use public URLs.
- Removed chapters need whole-page redirects; preserve content/current links.
- Keep PoCs with mechanisms; code size does not justify splitting.

## Canonical locations and boundaries

- Rlogin/Rsh trusted-host → `src/network-services-pentesting/pentesting-rlogin.md`; Rexec separate.
- SCM/SCMR execution (PsExec, WinExec, SMBExec, SCMExec, SharpMove) → `src/windows-hardening/lateral-movement/psexec-and-winexec.md`; scheduler, DCOM, WMI, WinRM and RDP stay separate.
- POSIX CPU timer TOCTOU/IRQ/task-work, ptrace PoCs, Chronomaly → `src/binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md`; Linux Hardening links; exploits in Binary, assessment in Linux.
- Board/side-channel/fault/signal → Hardware Hacking; physical, firmware, radio separate.
- Model execution, fine-tuning, serving and hosted tools → `src/AI/AI-Model-Tools-and-Platforms.md`, separate from attacks and architecture. Burp Intruder, extensions and Session Switcher → `src/pentesting-web/burp-suite.md`, separate from checklist and IDOR.
- OT safety/planning → `src/industrial-control-systems/README.md`; Modbus → `src/network-services-pentesting/pentesting-modbus.md`; OPC UA/BACnet → Network Services.
- Android acquisition/imaging/LiME → `src/generic-methodologies-and-resources/basic-forensic-methodology/android-forensics.md`; Mobile owns app testing; malware separate.
- Firmware acquisition, decryption, updates and boot → `src/hardware-physical-access/firmware-analysis/README.md`; XFlash Carbonara and Synology PAT/SPK stay there.
- Relocated from TODO: Rust → `src/generic-methodologies-and-resources/rust-basics.md`; investment terms → `src/blockchain/blockchain-and-crypto-currencies/investment-terms.md`; cookies → `src/welcome/cookies-policy.md`; recon/reputation/breach APIs → `src/generic-methodologies-and-resources/external-recon-methodology/reconnaissance-and-threat-intelligence-apis.md`.
- Referer leakage and Referrer-Policy → `src/pentesting-web/referer-header-and-referrer-policy.md`; OAuth links there. Exfiltration overview maps other routes.
- UTF-16 script and ICO image-width sniffing → `src/pentesting-web/xs-search/README.md#content-sniffing-leaks-utf-16-scripts-and-ico-image-widths`; XSSI, HTTP headers and exfiltration pages link there. Old Sniff Leak URL redirects; both citations remain.
- XSS exfiltration script → `src/pentesting-web/xss-cross-site-scripting/xss-information-exfiltration-payload.md`.
- Blockchain → top-level Blockchain; Bitcoin P2P stays in Network, DApp tests in Web, cryptocurrency privacy in Privacy.
- Electron renderer/IPC → `src/desktop-application-security/electron-desktop-apps/README.md` and context-isolation siblings; updater → sibling `electron-auto-update-trust-boundaries.md`; local ASAR/snapshot → sibling `electron-local-code-injection-and-snapshot-tampering.md`. Linux/macOS retain OS-local injection; 80/443 is a client pivot.
- VM guest surfaces → `src/binary-exploitation/vm-escape-and-hypervisor-exploitation.md`, linking QEMU/KVM, VirtualBox and VMware chapters. Slirp allocator stays in `libc-heap/` but appears with guest-to-host cases in SUMMARY.
- SOAP/REST API methodology → `src/pentesting-web/web-api-pentesting.md`; GraphQL endpoint/security testing → `src/pentesting-web/graphql.md` beneath it in SUMMARY. 80/443 links to both; Cloud keeps provider APIs.
- Firebase Realtime Database rules/REST queries → `src/pentesting-web/firebase-realtime-database.md` beneath Web APIs, linked from Android/iOS; do not group it with object-storage buckets. Bucket enumeration stays in Cloud via public URL from web/recon/upload entry points; old bucket hub and Firebase URLs redirect.
- Go `net/http` `ServeMux` `CONNECT` path canonicalization → `src/pentesting-web/403-and-401-bypasses.md#go-nethttp-servemux-connect-path-canonicalization`; 80/443 and TiDB link there. This is a method/path authorization mismatch, not a Go product guide.
- RDPexec → `src/network-services-pentesting/pentesting-rdp.md#remote-command-execution-with-an-authenticated-rdp-session`; Windows Lateral Movement links directly there, avoiding a procedure-free stub.
- Python `venv` and wheel builds → `src/generic-methodologies-and-resources/python/basic-python.md#virtual-environments-and-wheel-builds-venv`; the Python hub links to this heading, not a thin setup page.
- 401/403 authorization bypasses → `src/pentesting-web/403-and-401-bypasses.md`; broader request/response behavior → `src/pentesting-web/special-http-headers.md`. The 80/443 service overview links to both and retains product discovery; old routes redirect.
- Public HTTP/TCP relay exposure → `src/generic-hacking/expose-local-to-the-internet.md`, beside tunneling.
- PHP multipart temp-upload LFI race/PHP 7.0–7.2 crash variant → `src/pentesting-web/file-inclusion/lfi2rce-via-temp-file-uploads.md#segmentation-fault-variant-on-php-70-and-72`; phpinfo, session upload progress and filters are distinct primitives.
- Chosen-input MD5 suffix/`0e` search → `src/crypto/hashes/README.md#chosen-input-md5-hash-searches`; PHP type-juggling/version caveats → `network-services-pentesting/pentesting-web/php-tricks-esp/README.md#loose-comparisons-and-type-juggling`. Distinct, cross-linked.
- WSGI/uWSGI, Zabbix, CCTV stay under Network 80/443; Web/SSRF link to WSGI.
- AI fuzzing/PoV/patching → `src/AI/AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md`; source review/mobile/kernel audits → `src/AI/AI-Assisted-Source-Review-and-Vulnerability-Validation.md`. Split by research task, not platform.
- Python expression-evaluation confirmation (`"+str(True)+"`) → `src/generic-methodologies-and-resources/python/bypass-python-sandboxes/README.md#python-expression-evaluation-probe`; HTTP/web entry links directly there, not to a generic Python web-tech stub.
- Remote MCP testing → `src/AI/AI-MCP-Servers.md#remote-mcp-server-testing-workflow`; local CLI delivery → `src/generic-methodologies-and-resources/phishing-methodology/ai-agent-abuse-local-ai-cli-tools-and-mcp.md`. Distinct prerequisites.
- eSIM/eUICC, Java Card and OTA/APDU → `src/mobile-pentesting/esim-javacard-exploitation.md`; modem/IMS stays in `android-app-pentesting/baseband-and-soc-isolation-exploitation.md`.
- Cross-platform collection tools → `src/generic-methodologies-and-resources/post-exploitation-collection-tools.md`; OS-specific procedures stay local.
- macOS interpreter startup (PHP, Lua, Julia, Octave, R, Ruby, Erlang/Elixir) → `src/macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-interpreter-startup-file-injection.md`; runtime prerequisites stay under headings, distinct from shell/Python/PowerShell.
- MIFARE Classic balance tampering → `src/hardware-physical-access/radio-hacking/pentesting-rfid.md#mifare-classic-offline-stored-value-tampering-broken-crypto1`; Proxmark remains tool reference.
- PostgreSQL `lo_import`/`dblink_connect` exfiltration → `src/pentesting-web/sql-injection/postgresql-injection/README.md`; other dblink tasks remain separate.
- Legacy PHP `safe_mode` Windows command-path, `fopen`, Linux `proc_open` → `src/network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/legacy-php-safe-mode-bypasses.md`; Perl extension stays separate.
- PHP `pcntl_exec` → `src/network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/README.md#pcntl_exec-command-execution-with-disabled-functions`; Apache `mod_cgi` stays separate.
- Recursive CSS `@import` stays with CSS injection; LESS compilation is distinct.
- Format-string arbitrary-write `FmtStr` template → `src/binary-exploitation/format-strings/README.md#pwntools-template`; arbitrary-read examples stay separate. Old URL redirects.
- Rails synthetic `_json` body-parameter collision → `src/pentesting-web/parameter-pollution.md#ruby-on-rails-_json-parameter-pollution`, not deserialization. Ruby tricks and deserialization context link directly; the old standalone URL redirects. Keep Rails parser/version caveat and example with JSON injection.
- Adobe Reader PDF-upload XXE/SOP → `src/pentesting-web/file-upload/README.md#pdf-upload-adobe-reader-xxe-and-same-origin-policy-bypass`; Web XXE links there.
- FTP bounce scan → `src/network-services-pentesting/pentesting-ftp/ftp-bounce-attack.md`; relay/retrieval → `src/network-services-pentesting/pentesting-ftp/ftp-bounce-protocol-relay.md`. Distinct tasks.
- Cookie-bomb → Cookies; `onerror` oracle → XS-Leaks.
- Office VBA junk/UserForms → `src/generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/office-file-analysis.md#vba-macro-analysis-junk-code-and-userforms`; Revit RFA OLE/ECC exploit → `src/binary-exploitation/revit-rfa-ole-compound-file-exploitation.md` (separate parser task).

- Cross-surface tool catalog → `src/generic-methodologies-and-resources/third-party-tools-and-resources.md`; OSINT/web/Windows/firmware discovery index, linked from task pages.
- SQLMap request/detection/flags/`--eval`/tamper → `src/pentesting-web/sql-injection/sqlmap.md`; delayed stored-payload workflow → `sqlmap/second-order-injection-sqlmap.md`. Keep one tool cheatsheet; old nested index redirects.

## Researcher lookup terms

- Same-site leaks (SS-Leaks) → `src/pentesting-web/dangling-markup-html-scriptless-injection/README.md#same-site-leaks-ss-leaks`, unlike XS-Leaks. Old URL redirects.
- `nosniff`/ICO width → XS-Leaks; cross-origin script inclusion → XSSI; in-origin script injection → XSS.

## Deferred

- Audit mixed `network-services-pentesting/pentesting-web/`; move only with a clear mechanism/API-task home.
- Blockchain/Privacy cryptocurrency need a union audit.
