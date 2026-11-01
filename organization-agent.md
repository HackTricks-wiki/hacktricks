# HackTricks organization guide

## Principles

- Give each reusable mechanism one substantive home; service/platform/tool entry points keep distinct prerequisites and link to the relevant heading.
- Use headings when variants share mechanism and task; split when transport, prerequisites, or task differ. Size alone is not decisive.
- Main HackTricks owns general security techniques; HackTricks Cloud owns provider/service/IAM-specific pivots. Use verified public URLs for cross-book links.
- A removed Markdown chapter needs a whole-page mdBook redirect in `book.toml`. Update current local links; historical fragments are out of scope. Preserve unique content before deleting a source.
- Recheck paths and pending PR overlap; this guide describes the target clone, not merged status.

## Canonical locations and boundaries in the target clone

- Trusted-host Rlogin (513/TCP) and Rsh (514/TCP) → `src/network-services-pentesting/pentesting-rlogin.md`; Rexec (512/TCP) stays separate because it uses passwords and a distinct wire protocol.
- SCM/SCMR execution (PsExec, WinExec, SMBExec, SCMExec, SharpMove) → `src/windows-hardening/lateral-movement/psexec-and-winexec.md`; scheduler, DCOM, WMI, WinRM and RDP are separate interfaces. Cloud pivots stay in Cloud.
- POSIX CPU timer TOCTOU/IRQ/task-work, ptrace reproducer, PoC variants, and Chronomaly are at `src/binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md`; Linux Hardening's `kernel-lpe-cves/README.md` links there. Memory corruption/kernel exploitation belongs in Binary Exploitation; host assessment belongs in Linux Hardening.
- Board, side-channel, fault and signal work → `src/hardware-physical-access/hardware-hacking/`; physical access → `physical-attacks.md`; firmware → `firmware-analysis/`; radio/iButton → `radio-hacking/`.
- Model execution, fine-tuning, serving and hosted tools → `src/AI/AI-Model-Tools-and-Platforms.md`, separate from attacks and architecture. Burp Intruder, extensions and Session Switcher → `src/pentesting-web/burp-suite.md`, separate from checklist and IDOR.
- OT/ICS process-safety and planning are at `src/industrial-control-systems/README.md`; Modbus protocol models and testing are at `src/network-services-pentesting/pentesting-modbus.md`. OPC UA and BACnet remain protocol-specific Network Services chapters.
- Android acquisition, locked-device options, physical/ADB imaging and LiME → `src/generic-methodologies-and-resources/basic-forensic-methodology/android-forensics.md`. Mobile owns app testing; malware post-exploitation is separate.
- Firmware acquisition, package decryption, updates and early boot → `src/hardware-physical-access/firmware-analysis/README.md`; XFlash Carbonara and Synology PAT/SPK stay under firmware, not Stack Overflow.
- TODO relocations: Rust → `src/generic-methodologies-and-resources/rust-basics.md`; investment terms → `src/blockchain/blockchain-and-crypto-currencies/investment-terms.md`; cookies → `src/welcome/cookies-policy.md`; recon/reputation/breach APIs → `src/generic-methodologies-and-resources/external-recon-methodology/reconnaissance-and-threat-intelligence-apis.md`.
- `src/pentesting-web/referer-header-and-referrer-policy.md` owns browser Referer leakage, Referrer-Policy, and injected referrer meta behavior; OAuth retains its specific consequences and links there. `src/pentesting-web/sensitive-information-exfiltration.md` is a route map for private pages across CORS/XSS/dangling markup/clickjacking; its cited Apache case stays there.
- UTF-16 script and ICO image-width sniffing → `src/pentesting-web/xs-search/README.md#content-sniffing-leaks-utf-16-scripts-and-ico-image-widths`; XSSI, HTTP headers and exfiltration pages link there. Old Sniff Leak URL redirects; both citations remain.
- XSS exfiltration script → `src/pentesting-web/xss-cross-site-scripting/xss-information-exfiltration-payload.md`.
- Blockchain chapters → top-level Blockchain & Smart Contract Security (`blockchain-and-crypto-currencies/README.md` entry). Bitcoin P2P stays in Network Services, DApp tests in Web, cryptocurrency privacy in Privacy.
- VM escape entry point `src/binary-exploitation/vm-escape-and-hypervisor-exploitation.md` maps guest network/display/storage/shared-folder surfaces to QEMU/KVM, VirtualBox, and VMware cases; substantive chapters retain their paths. Slirp's custom-allocator mechanism stays under `libc-heap/`, but its SUMMARY entry belongs with guest-to-host cases.
- General Web API testing (SOAP/REST/GraphQL discovery, CXF XOP and tRPC cases, tools) is at `src/pentesting-web/web-api-pentesting.md`; the 80/443 service overview links directly to it. Cloud retains provider-specific API control-plane semantics.
- RDPexec → `src/network-services-pentesting/pentesting-rdp.md#remote-command-execution-with-an-authenticated-rdp-session`; Windows Lateral Movement links directly there, avoiding a procedure-free stub.
- Python `venv` and wheel builds → `src/generic-methodologies-and-resources/python/basic-python.md#virtual-environments-and-wheel-builds-venv`; the Python hub links to this heading, not a thin setup page.
- General 401/403 bypasses live at `src/pentesting-web/403-and-401-bypasses.md`; broader request/response header behavior lives at `src/pentesting-web/special-http-headers.md`. Keep separate: authorization bypass is one task, header behavior is a reference. The Network Services 80/443 overview links to both while retaining service/product discovery; old routes redirect.
- Public HTTP/TCP relay exposure → `src/generic-hacking/expose-local-to-the-internet.md`, beside tunneling; old reverse-shell route redirects.
- PHP multipart temporary-upload LFI races, including the PHP 7.0/7.2 crash/cleanup variant → `src/pentesting-web/file-inclusion/lfi2rce-via-temp-file-uploads.md#segmentation-fault-variant-on-php-70-and-72`. Keep phpinfo disclosure, session upload-progress files and filter-only payloads separate: different primitives.
- Chosen-input MD5 suffix and `0e` numeric-zero searches are headings at `src/crypto/hashes/README.md#chosen-input-md5-hash-searches`, not Python sandbox topics. PHP type-juggling behavior and version caveats stay in `network-services-pentesting/pentesting-web/php-tricks-esp/README.md#loose-comparisons-and-type-juggling`; both entry points link directly to the relevant explanation.
- WSGI/uWSGI, Zabbix and CCTV products remain in `network-services-pentesting/pentesting-web/`, nested under 80/443 rather than Kerberos. Web triage and SSRF/Gopher link to WSGI; port/side-service caveats stay with products.
- AI fuzzing seeds/harnesses/PoV/patching → `src/AI/AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md`; source review, mobile entry-point tasks and kernel audits → `src/AI/AI-Assisted-Source-Review-and-Vulnerability-Validation.md`. Split by research task, not platform; both stay in AI.

- Remote MCP OAuth, JSON-RPC enumeration, authorization and interception → `src/AI/AI-MCP-Servers.md#remote-mcp-server-testing-workflow`; local CLI delivery, repo config, secrets and artifacts → `src/generic-methodologies-and-resources/phishing-methodology/ai-agent-abuse-local-ai-cli-tools-and-mcp.md`. Server testing and client delivery are distinct.
- eSIM/eUICC profile management, Java Card VM type confusion, OTA/APDU and local card tests → `src/mobile-pentesting/esim-javacard-exploitation.md`. It targets a mobile subscription secure element, not generic hacking or Android app internals; modem/IMS exploitation remains in `android-app-pentesting/baseband-and-soc-isolation-exploitation.md` with a direct contrast link.

- Former TODO web topics: Host poisoning → `pentesting-web/reset-password.md`; session auth → `pentesting-web/403-and-401-bypasses.md`; signup/email change → `pentesting-web/registration-vulnerabilities.md`; Jira service desk → `network-services-pentesting/pentesting-web/jira.md`; TRACE → `pentesting-web/hacking-with-cookies/README.md`.
- Cross-platform host/SaaS collection-tool reference → `src/generic-methodologies-and-resources/post-exploitation-collection-tools.md`; OS-specific procedures stay in OS chapters. Its old TODO route redirects here.

- macOS environment-controlled PHP, Lua, Julia and Octave startup files → `src/macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-interpreter-startup-file-injection.md`. Keep broader shell, Python, PowerShell and framework injection chapters separate; runtime-specific prerequisites and mitigations remain under headings.
- MIFARE Classic stored-value tampering (Crypto1, balance diff/integrity, Proxmark3 transcript, magic UID caveats) → `src/hardware-physical-access/radio-hacking/pentesting-rfid.md#mifare-classic-offline-stored-value-tampering-broken-crypto1`; `proxmark-3.md` keeps generic tool commands and links to this tool-independent card-balance task.

## Researcher entry points

- Board debug/serial/glitching → Hardware Hacking; RFID/NFC/radio/iButton → Radio Hacking.
- OT safety → ICS; Modbus/OPC UA/BACnet → Network Services. Android image → Forensics; app tests → Mobile.
- Guest surfaces → VM Escape; SOAP/REST/GraphQL → Web APIs; 401/403 → Web authorization; header behavior → Special HTTP Headers.
- LFI/PHP upload race → Web File Inclusion; eSIM/Java Card → Mobile eSIM; modem/SoC → Android baseband.
- Browser `nosniff`, UTF-16 script, ICO width → XS-Leaks; executable cross-origin script inclusion → XSSI; in-origin script injection → XSS.

## Deferred

- `network-services-pentesting/pentesting-web/` is mixed (~91 pages); audit inbound links and product prerequisites before wholesale moves. Web ownership alone does not justify URL churn.
- `todo/more-tools.md` is an uncurated cross-domain list; audit destinations before splitting. SaaS collection tools in Main warrant coordinated Cloud ownership review.
- Blockchain overview and Privacy cryptocurrency need a union audit before consolidation.
- Audit long escalation, macOS startup and iOS exploitation by task and links, not length alone.
