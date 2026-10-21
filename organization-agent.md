# HackTricks organization guide

## Principles

- Give each reusable mechanism one substantive home; service/platform/tool entry points keep distinct prerequisites and link to the relevant heading.
- Use headings when variants share mechanism and task; split when transport, prerequisites, or task differ. Size alone is not decisive.
- Main HackTricks owns general security techniques; HackTricks Cloud owns provider/service/IAM-specific pivots. Use verified public URLs for cross-book links.
- A removed Markdown chapter needs a whole-page mdBook redirect in `book.toml`. Update current local links; historical fragments are out of scope. Preserve unique content before deleting a source.
- Recheck paths and pending PR overlap; this guide describes the target clone, not merged status.

## Canonical locations and boundaries in the target clone

- SCM/SCMR service execution (PsExec, WinExec, SMBExec, SCMExec, SharpMove) → `src/windows-hardening/lateral-movement/psexec-and-winexec.md`; scheduler, DCOM, WMI, WinRM, RDP have different interfaces. Cloud-specific movement stays in Cloud.
- POSIX CPU timer TOCTOU/IRQ/task-work, ptrace reproducer, PoC variants, and Chronomaly are at `src/binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md`; Linux Hardening's `kernel-lpe-cves/README.md` links there. Memory corruption/kernel exploitation belongs in Binary Exploitation; host assessment belongs in Linux Hardening.
- Board interfaces, side channels, fault injection and signal analysis → `src/hardware-physical-access/hardware-hacking/`; system access → `physical-attacks.md`; firmware → `firmware-analysis/`; radio/iButton credentials → `radio-hacking/`.
- Model execution, fine-tuning, serving, and hosted try-out tools are at `src/AI/AI-Model-Tools-and-Platforms.md`, distinct from AI attack methods and model architecture. Burp Intruder payloads, extensions, and Session Switcher identity-differential testing are at `src/pentesting-web/burp-suite.md`, distinct from the web checklist and IDOR chapter.
- OT/ICS process-safety and planning are at `src/industrial-control-systems/README.md`; Modbus protocol models and testing are at `src/network-services-pentesting/pentesting-modbus.md`. OPC UA and BACnet remain protocol-specific Network Services chapters. Cloud has no substantive Modbus/OT chapter in the supplied clone.
- Android device acquisition, locked-device options, physical/ADB imaging, and LiME memory capture are at `src/generic-methodologies-and-resources/basic-forensic-methodology/android-forensics.md`. Mobile Pentesting's Android chapter owns app testing and links to acquisition; malware post-exploitation is a different forensic task.
- Firmware acquisition, package decryption, update path, and early boot are indexed at `src/hardware-physical-access/firmware-analysis/README.md`. MediaTek XFlash Carbonara and Synology PAT/SPK chapters retain their firmware-analysis paths. Their former Stack Overflow SUMMARY nesting was a navigation error; product overlap does not make archive decryption a stack-overflow technique.
- TODO relocations: Rust → `src/generic-methodologies-and-resources/rust-basics.md`; investment terms → `src/blockchain/blockchain-and-crypto-currencies/investment-terms.md`; cookies → `src/welcome/cookies-policy.md`; recon/reputation/breach APIs → `src/generic-methodologies-and-resources/external-recon-methodology/reconnaissance-and-threat-intelligence-apis.md`.
- `src/pentesting-web/referer-header-and-referrer-policy.md` owns browser Referer leakage, Referrer-Policy, and injected referrer meta behavior; OAuth retains its specific consequences and links there. `src/pentesting-web/sensitive-information-exfiltration.md` is a route map for private pages across CORS/XSS/dangling markup/clickjacking; its cited Apache case stays there.
- Blockchain chapters → top-level Blockchain & Smart Contract Security (`blockchain-and-crypto-currencies/README.md` entry). Bitcoin P2P stays in Network Services, DApp tests in Web, cryptocurrency privacy in Privacy.
- VM escape entry point `src/binary-exploitation/vm-escape-and-hypervisor-exploitation.md` maps guest network/display/storage/shared-folder surfaces to QEMU/KVM, VirtualBox, and VMware cases; substantive chapters retain their paths. Slirp's custom-allocator mechanism stays under `libc-heap/`, but its SUMMARY entry belongs with guest-to-host cases.
- General Web API testing (SOAP/REST/GraphQL discovery, CXF XOP and tRPC cases, tools) is at `src/pentesting-web/web-api-pentesting.md`; the 80/443 service overview links directly to it. Cloud retains provider-specific API control-plane semantics.
- RDPexec → `src/network-services-pentesting/pentesting-rdp.md#remote-command-execution-with-an-authenticated-rdp-session`; Windows Lateral Movement links directly there, avoiding a procedure-free stub.
- Python `venv` and wheel builds → `src/generic-methodologies-and-resources/python/basic-python.md#virtual-environments-and-wheel-builds-venv`; the Python hub links to this heading, not a thin setup page.
- General 401/403 bypasses live at `src/pentesting-web/403-and-401-bypasses.md`; broader request/response header behavior lives at `src/pentesting-web/special-http-headers.md`. Keep separate: authorization bypass is one task, header behavior is a reference. The Network Services 80/443 overview links to both while retaining service/product discovery; old routes redirect.
- PHP multipart temporary-upload LFI races, including the PHP 7.0/7.2 crash/cleanup variant → `src/pentesting-web/file-inclusion/lfi2rce-via-temp-file-uploads.md#segmentation-fault-variant-on-php-70-and-72`. Keep phpinfo disclosure, session upload-progress files and filter-only payloads separate: different primitives.
- Chosen-input MD5 suffix and `0e` numeric-zero searches are headings at `src/crypto/hashes/README.md#chosen-input-md5-hash-searches`, not Python sandbox topics. PHP type-juggling behavior and version caveats stay in `network-services-pentesting/pentesting-web/php-tricks-esp/README.md#loose-comparisons-and-type-juggling`; both entry points link directly to the relevant explanation.
- WSGI/uWSGI, Zabbix, and ZoneMinder/motionEye/Motion remain in `network-services-pentesting/pentesting-web/`; SUMMARY nests them under 80/443 web methodology, not Kerberos. Web triage links to WSGI; SSRF/Gopher links to its pivot heading. Zabbix TCP/10051 and CCTV side-service caveats stay in their chapters.
- AI fuzzing seeds/harnesses/PoV/patching → `src/AI/AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md`; source review, mobile entry-point tasks and kernel audits → `src/AI/AI-Assisted-Source-Review-and-Vulnerability-Validation.md`. Split by research task, not platform; both stay in AI.

- Remote MCP OAuth, JSON-RPC enumeration, authorization and interception → `src/AI/AI-MCP-Servers.md#remote-mcp-server-testing-workflow`; local CLI delivery, repo config, secrets and artifacts → `src/generic-methodologies-and-resources/phishing-methodology/ai-agent-abuse-local-ai-cli-tools-and-mcp.md`. Server testing and client delivery are distinct.
- eSIM/eUICC profile management, Java Card VM type confusion, OTA/APDU and local card tests → `src/mobile-pentesting/esim-javacard-exploitation.md`. It targets a mobile subscription secure element, not generic hacking or Android app internals; modem/IMS exploitation remains in `android-app-pentesting/baseband-and-soc-isolation-exploitation.md` with a direct contrast link.

- Former TODO web miscellany: Host poisoning → `src/pentesting-web/reset-password.md`; session-state auth → `src/pentesting-web/403-and-401-bypasses.md`; signup/email change → `src/pentesting-web/registration-vulnerabilities.md`; Atlassian service desk → `src/network-services-pentesting/pentesting-web/jira.md`; TRACE → `src/pentesting-web/hacking-with-cookies/README.md`. Old route redirects to the web checklist.
- Cross-platform host/SaaS collection-tool reference → `src/generic-methodologies-and-resources/post-exploitation-collection-tools.md`; OS-specific procedures stay in OS chapters. Its old TODO route redirects here.

- MIFARE Classic stored-value tampering (Crypto1, balance diff/integrity, Proxmark3 transcript, magic UID caveats) → `src/hardware-physical-access/radio-hacking/pentesting-rfid.md#mifare-classic-offline-stored-value-tampering-broken-crypto1`; `proxmark-3.md` keeps generic tool commands and links to this tool-independent card-balance task.

## Researcher entry points

- SMB/RPC SCM rights (PsExec/SMBExec/WinExec/SharpMove) → Windows Lateral Movement; POSIX CPU timers/IRQ/ptrace/Chronomaly → Binary Exploitation / Linux kernel.
- Board pads/debug headers/serial/memory leakage/glitching → Hardware Hacking; RFID/NFC/sub-GHz/IR/BLE/LoRaWAN/iButton → Radio Hacking.
- OT process safety → ICS; Modbus/OPC UA/BACnet → Network Services. Android device/image → Forensics; app tests → Mobile.
- Guest network/display/storage/shared folders → VM Escape; SOAP/REST/GraphQL → Web APIs; HTTP 401/403/verbs/proxy/path → Web authorization; generic header behavior → Special HTTP Headers.
- LFI plus PHP multipart/upload/segfault → Web File Inclusion. eSIM/eUICC/Java Card/OTA/RAM keys → Mobile eSIM; modem/SoC → Android baseband.

## Deferred audits

- `network-services-pentesting/pentesting-web/` is mixed (~91 pages); audit inbound links, discovery entry points, and product prerequisites before a wholesale move. Web ownership alone does not justify URL churn.
- `todo/more-tools.md` is an uncurated cross-domain link list; audit every destination before splitting. SaaS collection tools in Main still warrant coordinated Cloud ownership review without dropping unique details.
- Blockchain overview and Privacy's cryptocurrency chapter need a full union audit before consolidation.
- Audit long escalation, macOS startup, and iOS exploitation by task and inbound links before splitting; length alone is insufficient.
