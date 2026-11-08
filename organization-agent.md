# HackTricks organization guide

## Principles

- One substantive home per mechanism; service/platform/tool entry points link to it and keep distinct prerequisites.
- Use headings for one task/mechanism; split by transport, prerequisites or task, not size.
- Main owns general techniques; Cloud owns provider/IAM pivots; use public URLs.
- Removed chapters need whole-page `book.toml` redirects; preserve content and current links, not historical fragments.
- Recheck paths and PR overlap.
- Keep implementation PoCs beside their mechanism heading when they share the same prerequisites; code size alone does not justify a separate page.

## Canonical locations and boundaries

- Trusted-host Rlogin (513/TCP) and Rsh (514/TCP) → `src/network-services-pentesting/pentesting-rlogin.md`; Rexec (512/TCP) stays separate because it uses passwords and a distinct wire protocol.
- SCM/SCMR execution (PsExec, WinExec, SMBExec, SCMExec, SharpMove) → `src/windows-hardening/lateral-movement/psexec-and-winexec.md`; scheduler, DCOM, WMI, WinRM and RDP are separate interfaces. Cloud pivots stay in Cloud.
- POSIX CPU timer TOCTOU/IRQ/task-work, ptrace PoCs and Chronomaly → `src/binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md`; Linux Hardening links there. Kernel exploitation belongs in Binary Exploitation; host assessment in Linux Hardening.
- Board, side-channel, fault and signal work → `src/hardware-physical-access/hardware-hacking/`; physical access → `physical-attacks.md`; firmware → `firmware-analysis/`; radio/iButton → `radio-hacking/`.
- Model execution, fine-tuning, serving and hosted tools → `src/AI/AI-Model-Tools-and-Platforms.md`, separate from attacks and architecture. Burp Intruder, extensions and Session Switcher → `src/pentesting-web/burp-suite.md`, separate from checklist and IDOR.
- OT/ICS process-safety and planning are at `src/industrial-control-systems/README.md`; Modbus protocol models and testing are at `src/network-services-pentesting/pentesting-modbus.md`. OPC UA and BACnet remain protocol-specific Network Services chapters.
- Android acquisition, locked-device options, physical/ADB imaging and LiME → `src/generic-methodologies-and-resources/basic-forensic-methodology/android-forensics.md`. Mobile owns app testing; malware post-exploitation is separate.
- Firmware acquisition, package decryption, updates and early boot → `src/hardware-physical-access/firmware-analysis/README.md`; XFlash Carbonara and Synology PAT/SPK stay under firmware, not Stack Overflow.
- TODO relocations: Rust → `src/generic-methodologies-and-resources/rust-basics.md`; investment terms → `src/blockchain/blockchain-and-crypto-currencies/investment-terms.md`; cookies → `src/welcome/cookies-policy.md`; recon/reputation/breach APIs → `src/generic-methodologies-and-resources/external-recon-methodology/reconnaissance-and-threat-intelligence-apis.md`.
- `src/pentesting-web/referer-header-and-referrer-policy.md` owns Referer leakage, Referrer-Policy and injected meta behavior; OAuth links there. `sensitive-information-exfiltration.md` maps private-page routes across CORS/XSS/dangling markup/clickjacking.
- UTF-16 script and ICO image-width sniffing → `src/pentesting-web/xs-search/README.md#content-sniffing-leaks-utf-16-scripts-and-ico-image-widths`; XSSI, HTTP headers and exfiltration pages link there. Old Sniff Leak URL redirects; both citations remain.
- XSS exfiltration script → `src/pentesting-web/xss-cross-site-scripting/xss-information-exfiltration-payload.md`.
- Blockchain chapters → top-level Blockchain & Smart Contract Security (`blockchain-and-crypto-currencies/README.md` entry). Bitcoin P2P stays in Network Services, DApp tests in Web, cryptocurrency privacy in Privacy.
- VM guest surfaces → `src/binary-exploitation/vm-escape-and-hypervisor-exploitation.md`, linking QEMU/KVM, VirtualBox and VMware chapters. Slirp allocator stays in `libc-heap/` but appears with guest-to-host cases in SUMMARY.
- SOAP/REST/GraphQL testing → `src/pentesting-web/web-api-pentesting.md`; the 80/443 overview links there. Cloud keeps provider-specific APIs.
- Go `net/http` `ServeMux` `CONNECT` path canonicalization → `src/pentesting-web/403-and-401-bypasses.md#go-nethttp-servemux-connect-path-canonicalization`; 80/443 and TiDB link there. This is a method/path authorization mismatch, not a Go product guide.
- RDPexec → `src/network-services-pentesting/pentesting-rdp.md#remote-command-execution-with-an-authenticated-rdp-session`; Windows Lateral Movement links directly there, avoiding a procedure-free stub.
- Python `venv` and wheel builds → `src/generic-methodologies-and-resources/python/basic-python.md#virtual-environments-and-wheel-builds-venv`; the Python hub links to this heading, not a thin setup page.
- 401/403 authorization bypasses → `src/pentesting-web/403-and-401-bypasses.md`; broader request/response behavior → `src/pentesting-web/special-http-headers.md`. The 80/443 service overview links to both and retains product discovery; old routes redirect.
- Public HTTP/TCP relay exposure → `src/generic-hacking/expose-local-to-the-internet.md`, beside tunneling; old reverse-shell route redirects.
- PHP multipart temporary-upload LFI races, including the PHP 7.0/7.2 crash/cleanup variant → `src/pentesting-web/file-inclusion/lfi2rce-via-temp-file-uploads.md#segmentation-fault-variant-on-php-70-and-72`. Keep phpinfo disclosure, session upload-progress files and filter-only payloads separate: different primitives.
- Chosen-input MD5 suffix and `0e` numeric-zero searches are headings at `src/crypto/hashes/README.md#chosen-input-md5-hash-searches`, not Python sandbox topics. PHP type-juggling behavior and version caveats stay in `network-services-pentesting/pentesting-web/php-tricks-esp/README.md#loose-comparisons-and-type-juggling`; both entry points link directly to the relevant explanation.
- WSGI/uWSGI, Zabbix and CCTV products remain in `network-services-pentesting/pentesting-web/`, nested under 80/443 rather than Kerberos. Web triage and SSRF/Gopher link to WSGI; port/side-service caveats stay with products.
- AI fuzzing seeds/harnesses/PoV/patching → `src/AI/AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md`; source review, mobile entry-point tasks and kernel audits → `src/AI/AI-Assisted-Source-Review-and-Vulnerability-Validation.md`. Split by research task, not platform; both stay in AI.
- Remote MCP OAuth, JSON-RPC enumeration, authorization and interception → `src/AI/AI-MCP-Servers.md#remote-mcp-server-testing-workflow`; local CLI delivery, repo config, secrets and artifacts → `src/generic-methodologies-and-resources/phishing-methodology/ai-agent-abuse-local-ai-cli-tools-and-mcp.md`. Server testing and client delivery are distinct.
- eSIM/eUICC, Java Card and OTA/APDU → `src/mobile-pentesting/esim-javacard-exploitation.md`; modem/IMS stays in `android-app-pentesting/baseband-and-soc-isolation-exploitation.md`.

- Cross-platform collection tools → `src/generic-methodologies-and-resources/post-exploitation-collection-tools.md`; OS-specific procedures stay in OS chapters.
- macOS interpreter startup (PHP, Lua, Julia, Octave, R, Ruby, Erlang/Elixir) → `src/macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-interpreter-startup-file-injection.md`; runtime prerequisites stay under headings, distinct from shell/Python/PowerShell.
- MIFARE Classic balance tampering → `src/hardware-physical-access/radio-hacking/pentesting-rfid.md#mifare-classic-offline-stored-value-tampering-broken-crypto1`; `proxmark-3.md` keeps generic tool commands.
- PostgreSQL `lo_import`/`dblink_connect` exfiltration → `src/pentesting-web/sql-injection/postgresql-injection/README.md`; other dblink tasks remain separate.
- Legacy PHP `safe_mode` Windows command-path, `fopen`, and Linux `proc_open` → `src/network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/legacy-php-safe-mode-bypasses.md`. Group by restriction, split prerequisites by heading; Perl extension remains separate for modern CGI loading and broader bypasses.

- Recursive CSS `@import` exfiltration PoC → `src/pentesting-web/xs-search/css-injection/README.md#recursive-import-css-exfiltration-poc`; attribute-selector mechanism and complete commented server/victim code belong together; the former code-only URL redirects. LESS compilation remains separate (server-side prerequisite).
- Format-string arbitrary-write `FmtStr` GOT-overwrite template (local/TCP/SSH, offset discovery, padding, `.fini_array` option) → `src/binary-exploitation/format-strings/README.md#pwntools-template`; the separate arbitrary-read examples stay in their own chapter because they demonstrate a different exploitation objective. Old URL redirects.

## Researcher entry points

- Board debug/serial/glitching → Hardware; RFID/NFC → Radio. OT safety → ICS; OT protocols → Network Services. Android images → Forensics; app tests/eSIM → Mobile; guest surfaces → VM Escape.
- SOAP/REST/GraphQL → Web APIs; 401/403 → Web authorization; LFI upload race → Web File Inclusion.
- Browser `nosniff`, UTF-16 script, ICO width → XS-Leaks; executable cross-origin script inclusion → XSSI; in-origin script injection → XSS.
- `R_PROFILE`, `RUBYOPT`, `ERL_AFLAGS` → macOS interpreter startup chapter.
- Same-site HTML-injection leaks (SS-Leaks) → `src/pentesting-web/dangling-markup-html-scriptless-injection/README.md#same-site-leaks-ss-leaks`; unlike cross-origin XS-Leaks, injection and the probed page share an origin. Former standalone page redirects.

## Deferred

- `network-services-pentesting/pentesting-web/` is mixed; audit links/prerequisites before moves, not ownership alone.
- `todo/more-tools.md`: audit cross-domain destinations before splitting; coordinate SaaS tools with Cloud.
- Blockchain and Privacy cryptocurrency need a union audit.
- Audit long escalation/iOS chapters by task, not length.
