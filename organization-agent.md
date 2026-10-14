# HackTricks organization guide

## Organization principles

- Give a reusable mechanism one substantive home. Use short contextual links from service, platform, or tool entry points rather than another procedure.
- Prefer an existing chapter and a precise heading when variants share the mechanism and reader task. Keep a separate chapter when the transport, prerequisite, or task changes. Do not merge merely because a page is short.
- Main HackTricks owns general host/security techniques; HackTricks Cloud owns provider, service, and IAM-specific pivots. Cross-book links should use canonical public URLs.
- A removed Markdown chapter needs a whole-page mdBook redirect in `book.toml`; update current local links, but do not preserve historical URL fragments.

## Canonical locations and boundaries (verified in this clone; proposed until merged)

- Windows SCM/SCMR remote-service execution (PsExec, WinExec/ScExec, SMBExec, SCMExec) lives in `src/windows-hardening/lateral-movement/psexec-and-winexec.md`, with SharpMove at `#scmexec-with-sharpmove`. Shared service rights do not imply identical `ADMIN$` staging/output needs. The old `scmexec.md` route redirects here.
- `src/network-services-pentesting/pentesting-smb/README.md` keeps SMB discovery and a short context link to the service-execution chapter, not a second PsExec/SMBExec procedure. `src/windows-hardening/ntlm/README.md` links directly to the Impacket PsExec examples for Pass-the-Hash.
- Keep Task Scheduler (`atexec.md`), DCOM (`dcomexec.md`), WMI (`wmiexec.md`), WinRM (`winrm.md`), and RDP (`rdpexec.md`) separate: their execution interfaces and prerequisites differ from SCM service creation. `lateral-movement/README.md` is a curated route map, not a duplicate technique chapter.
- Azure/Entra-to-AD pivots remain in Cloud's `pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/`; a cloud use of PsExec does not transfer general Windows SCM ownership there.

- POSIX CPU timer TOCTOU/IRQ/task-work, ptrace reproducer, PoC variants, and Chronomaly are canonical at `src/binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md`. Linux Hardening's `kernel-lpe-cves/README.md` links to the root cause; the duplicate article redirects. Kernel exploitation belongs in Binary Exploitation, host assessment in Linux Hardening.

- Board interfaces live under `src/hardware-physical-access/hardware-hacking/` (JTAG/SWD, UART, I²C, SPI, side channels, fault injection, signal analysis); old TODO routes redirect. `physical-attacks.md` is system-level access, `firmware-analysis/` interprets firmware and links to UART/SPI acquisition. Protocol-specific wireless/proximity work is under adjacent radio-hacking.

- Former `todo/radio-hacking/` chapters (RFID/NFC, sub-GHz, infrared, BLE, LPWAN, iButton, Flipper Zero, Proxmark3, FISSURE) live at `src/hardware-physical-access/radio-hacking/`; old routes redirect, directory depth preserves asset paths. Keep SigDigger signal analysis in `hardware-hacking/radio.md`; iButton is a contact interface grouped by proximity-credential task.

- Model execution, fine-tuning, serving, and hosted try-out tools are at `src/AI/AI-Model-Tools-and-Platforms.md`, with an entry from `AI/README.md`; the former `todo/test-llms.md` route redirects there. Keep this practical tooling task separate from AI attack-methodology and model-architecture chapters.
- Burp Intruder payload types, extensions, and Session Switcher identity-differential testing are at `src/pentesting-web/burp-suite.md`, linked from the web methodology; the former `todo/burp-suite.md` route redirects there. Keep the tool workflow separate from the vulnerability-class checklist and IDOR technique chapter.

- OT/ICS process-safety and assessment planning is at `src/industrial-control-systems/README.md`, with direct routes to Modbus, OPC UA, and BACnet. Modbus application/serial/TCP models and the offensive protocol workflow share the canonical `src/network-services-pentesting/pentesting-modbus.md`; the two old TODO routes redirect respectively to the OT overview and this Modbus chapter. Keep process safety distinct from protocol commands; Cloud has no substantive Modbus/OT chapter here.
- Android device acquisition, locked-device options, physical/ADB imaging, and LiME memory capture are at `src/generic-methodologies-and-resources/basic-forensic-methodology/android-forensics.md`, not TODO or Android app pentesting. The app chapter links to it when evidence acquisition is the task; malware post-exploitation is a different forensic task and stays separate.
- Firmware-image acquisition, package decryption, update-path and early-boot work is indexed under **Hardware/Physical Access → Firmware Analysis**, including the MediaTek XFlash Carbonara DA2 hash-bypass and Synology PAT/SPK archive-decryption chapters. Both existing chapters stay at their `hardware-physical-access/firmware-analysis/` paths; their former Stack Overflow SUMMARY nesting was a navigation error, not a reason to move or merge content. Firmware Analysis's overview links to each directly. Keep stack-overflow methods under Binary Exploitation; a product shared with a stack-overflow case study does not make archive decryption a stack-overflow technique.

- Former TODO chapters moved whole: Rust basics → `src/generic-methodologies-and-resources/rust-basics.md`; spot/futures/options/leverage → `src/blockchain/blockchain-and-crypto-currencies/investment-terms.md`; site cookie policy → `src/welcome/cookies-policy.md`. Preserve their old-route redirects.

- Browser `Referer` leakage, `Referrer-Policy`, and injected referrer meta behavior are at `src/pentesting-web/referer-header-and-referrer-policy.md`. OAuth code/state leakage links there; OAuth-specific consequences stay in OAuth. The former TODO route redirects here.
- `src/pentesting-web/sensitive-information-exfiltration.md` maps session-dependent sensitive pages to CORS, XSS, dangling markup, and clickjacking without duplicating those chapters. Its cited Apache case stays with the map. Keep this focused choice-of-path task separate from the broad web checklist; the former TODO route redirects here.

## Researcher lookup terms

- For a remote Windows host where service-creation rights, SMB/RPC, or an already staged executable are available, look under **Lateral Movement → Remote Service Execution**; search terms include SCM, SCMR, SCMExec, PsExec, SMBExec, WinExec, ScExec, `sc.exe`, and SharpMove.

- For POSIX CPU-timer races, search **Binary Exploitation → Linux kernel exploitation** for CVE-2025-38352, `CONFIG_POSIX_CPU_TIMERS_TASK_WORK`, IRQ expiry, `timer_delete`, ptrace/waitpid, UAF, and Chronomaly. Linux host operators should enter through **Linux Hardening → Kernel/LPE/CVE material**.

- For a board with exposed pads, a debug header, serial console, memory chip, measurable leakage, or glitchable signals, enter **Hardware/Physical Access → Hardware Hacking**. Search JTAG/SWD, UART, I²C, SPI, Bus Pirate, flashrom, side-channel analysis, fault injection, and SigDigger.

- For an RFID/NFC badge, sub-GHz remote, infrared receiver, BLE device, LoRaWAN endpoint, or contact iButton key, enter **Hardware/Physical Access → Radio Hacking**. Use SigDigger under Hardware Hacking for unknown-signal analysis; use the family chapters for protocol behavior and tools.

- For OT assets, search **Industrial Control Systems / OT** for process constraints and **Network Services → Modbus, OPC UA, BACnet** for protocol-specific assessment. For a locked Android device or acquired image, search **Basic Forensic Methodology → Android Forensics**; use **Mobile Pentesting → Android Applications** for app testing, not acquisition.

- For guest-controlled network, display, storage, or shared-folder surfaces, use **Binary Exploitation → VM Escape**.

## Revisit only with evidence

- Split the remote-service chapter only if a variant develops an independent reader task or prerequisites that make the shared flow misleading; code size alone is not a reason. Recheck repository paths, pending PR overlap, and cross-book ownership before using this guide in a later run.
- VM-escape navigation: `src/binary-exploitation/vm-escape-and-hypervisor-exploitation.md` maps guest surfaces to QEMU/KVM, VirtualBox NAT/VMSVGA, and VMware cases. Substantive chapters retain their paths. Slirp uses a custom allocator and stays at `libc-heap/`, but its SUMMARY entry belongs with guest-to-host cases. The hub is navigation only.
- The MIFARE Classic stored-value workflow appears in both `radio-hacking/pentesting-rfid.md` and `radio-hacking/proxmark-3.md`, with different command contexts and caveats. Audit the complete union before consolidating; do not drop either example as a mere duplicate.
- Audit `network-services-pentesting/pentesting-web/` (91 pages) against the Web section before moving it; service entry points and inbound links need a coordinated migration. Do not merge macOS runtime startup-injection pages until their per-runtime caveats can be preserved coherently.
