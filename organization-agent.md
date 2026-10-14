# HackTricks organization guide

## Organization principles

- Give a reusable mechanism one substantive home. Use short contextual links from service, platform, or tool entry points rather than another procedure.
- Prefer an existing chapter and a precise heading when variants share the mechanism and reader task. Keep a separate chapter when the transport, prerequisite, or task changes. Do not merge merely because a page is short.
- Main HackTricks owns general host/security techniques; HackTricks Cloud owns provider, service, and IAM-specific pivots. Cross-book links should use canonical public URLs.
- A removed Markdown chapter needs a whole-page mdBook redirect in `book.toml`; update current local links, but do not preserve historical URL fragments.

## Canonical locations and boundaries (verified in this clone; proposed until merged)

- Windows remote service execution through SCM/SCMR—PsExec, WinExec/ScExec, SMBExec, and SCMExec—belongs in `src/windows-hardening/lateral-movement/psexec-and-winexec.md`. The SharpMove SCM example has its own `#scmexec-with-sharpmove` heading. These variants share remote service creation/start and local service rights; whether `ADMIN$` is needed depends on staging/output, so keep that distinction in the chapter. The former `scmexec.md` route redirects here.
- `src/network-services-pentesting/pentesting-smb/README.md` keeps SMB discovery and a short context link to the service-execution chapter, not a second PsExec/SMBExec procedure. `src/windows-hardening/ntlm/README.md` links directly to the Impacket PsExec examples for Pass-the-Hash.
- Keep Task Scheduler (`atexec.md`), DCOM (`dcomexec.md`), WMI (`wmiexec.md`), WinRM (`winrm.md`), and RDP (`rdpexec.md`) separate: their execution interfaces and prerequisites differ from SCM service creation. `lateral-movement/README.md` is a curated route map, not a duplicate technique chapter.
- Azure/Entra-to-AD pivots remain in Cloud's `pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/`; a cloud use of PsExec does not transfer general Windows SCM ownership there.

- POSIX CPU timer expiry/deletion TOCTOU, its IRQ/task-work distinction, ptrace/reaping reproducer, PoC reliability variants, and Chronomaly chain have one home at `src/binary-exploitation/linux-kernel-exploitation/posix-cpu-timers-toctou-cve-2025-38352.md`. Linux Hardening's `kernel-lpe-cves/README.md` is an enumeration entry point linking straight to the root-cause section; the duplicate Linux-Hardening article is removed with a whole-page redirect. Keep kernel memory-corruption research under Binary Exploitation, while host assessment/checklists stay in Linux Hardening. Revisit the boundary only if a genuinely separate host-assessment task develops.

- Board-level hardware interface work belongs under `src/hardware-physical-access/hardware-hacking/`, not TODO. Its hub retains JTAG/SWD fundamentals and links directly to JTAG, UART, I²C, SPI, side-channel, fault-injection, and radio-signal chapters. `physical-attacks.md` remains the system-level physical-access chapter; `firmware-analysis/` remains the firmware interpretation chapter, with links to acquisition via UART and SPI. Former `todo/hardware-hacking/` whole-page routes redirect to the same-named chapters here. See the adjacent radio-hacking family for protocol-specific wireless and proximity tasks.

- The former `todo/radio-hacking/` family is now at `src/hardware-physical-access/radio-hacking/`, retaining its RFID/NFC, sub-GHz, infrared, BLE, LPWAN/LoRaWAN, iButton, Flipper Zero, Proxmark3, and FISSURE chapters. The directory depth is unchanged, preserving local image/include/reference paths; every old whole-page route redirects to the corresponding chapter. Keep `hardware-hacking/radio.md` for the existing SigDigger signal-analysis workflow and link to the family for protocol-specific tasks. iButton is a contact interface, grouped here for proximity-credential lookup rather than described as radio.

- Model execution, fine-tuning, serving, and hosted try-out tools are at `src/AI/AI-Model-Tools-and-Platforms.md`, with an entry from `AI/README.md`; the former `todo/test-llms.md` route redirects there. Keep this practical tooling task separate from AI attack-methodology and model-architecture chapters.
- Burp Intruder payload types, extensions, and Session Switcher identity-differential testing are at `src/pentesting-web/burp-suite.md`, linked from the web methodology; the former `todo/burp-suite.md` route redirects there. Keep the tool workflow separate from the vulnerability-class checklist and IDOR technique chapter.

- OT/ICS process-safety and assessment planning is at `src/industrial-control-systems/README.md`, with direct routes to Modbus, OPC UA, and BACnet. Modbus application/serial/TCP models and the offensive protocol workflow share the canonical `src/network-services-pentesting/pentesting-modbus.md`; the two old TODO routes redirect respectively to the OT overview and this Modbus chapter. Keep process-level safety context distinct from protocol-specific commands. The Cloud book has no corresponding substantive Modbus/OT chapter in this clone.
- Android device acquisition, locked-device options, physical/ADB imaging, and LiME memory capture are at `src/generic-methodologies-and-resources/basic-forensic-methodology/android-forensics.md`, not TODO or Android app pentesting. The app chapter links to it when evidence acquisition is the task; malware post-exploitation is a different forensic task and stays separate.
- Firmware-image acquisition, package decryption, update-path and early-boot work is indexed under **Hardware/Physical Access → Firmware Analysis**, including the MediaTek XFlash Carbonara DA2 hash-bypass and Synology PAT/SPK archive-decryption chapters. Both existing chapters stay at their `hardware-physical-access/firmware-analysis/` paths; their former Stack Overflow SUMMARY nesting was a navigation error, not a reason to move or merge content. Firmware Analysis's overview links to each directly. Keep stack-overflow methods under Binary Exploitation; a product shared with a stack-overflow case study does not make archive decryption a stack-overflow technique.

- Browser `Referer` leakage, `Referrer-Policy`, and injected referrer meta behavior are at `src/pentesting-web/referer-header-and-referrer-policy.md`. OAuth code/state leakage links there; OAuth-specific consequences stay in OAuth. The former TODO route redirects here.
- `src/pentesting-web/sensitive-information-exfiltration.md` maps session-dependent sensitive pages to CORS, XSS, dangling markup, and clickjacking without duplicating those chapters. Its cited Apache case stays with the map. Keep this focused choice-of-path task separate from the broad web checklist; the former TODO route redirects here.

## Researcher lookup terms

- For a remote Windows host where service-creation rights, SMB/RPC, or an already staged executable are available, look under **Lateral Movement → Remote Service Execution**; search terms include SCM, SCMR, SCMExec, PsExec, SMBExec, WinExec, ScExec, `sc.exe`, and SharpMove.

- For POSIX CPU-timer races, search **Binary Exploitation → Linux kernel exploitation** for CVE-2025-38352, `CONFIG_POSIX_CPU_TIMERS_TASK_WORK`, IRQ expiry, `timer_delete`, ptrace/waitpid, UAF, and Chronomaly. Linux host operators should enter through **Linux Hardening → Kernel/LPE/CVE material**.

- For a board with exposed pads, a debug header, serial console, memory chip, measurable leakage, or glitchable signals, enter **Hardware/Physical Access → Hardware Hacking**. Search JTAG/SWD, UART, I²C, SPI, Bus Pirate, flashrom, side-channel analysis, fault injection, and SigDigger.

- For an RFID/NFC badge, sub-GHz remote, infrared receiver, BLE device, LoRaWAN endpoint, or contact iButton key, enter **Hardware/Physical Access → Radio Hacking**. Use SigDigger under Hardware Hacking for unknown-signal analysis; use the family chapters for protocol behavior and tools.

- For OT assets, search **Industrial Control Systems / OT** for process constraints and **Network Services → Modbus, OPC UA, BACnet** for protocol-specific assessment. For a locked Android device or acquired image, search **Basic Forensic Methodology → Android Forensics**; use **Mobile Pentesting → Android Applications** for app testing, not acquisition.

## Revisit only with evidence

- Split the remote-service chapter only if a variant develops an independent reader task or prerequisites that make the shared flow misleading; code size alone is not a reason. Recheck repository paths, pending PR overlap, and cross-book ownership before using this guide in a later run.
- The VirtualBox Slirp NAT packet-heap case study remains nested under Write What Where 2 Exec in SUMMARY while its chapter path and contextual link are under Libc Heap. It uses a custom zone allocator, not libc, and develops an arbitrary-write primitive before guest-to-host execution. Audit researcher entry points and the surrounding VM-escape cases before choosing a better navigation home; do not mechanically move it under Libc Heap merely because of its path.
- The MIFARE Classic stored-value workflow appears in both `radio-hacking/pentesting-rfid.md` and `radio-hacking/proxmark-3.md`, with different command contexts and caveats. Audit the complete union before consolidating; do not drop either example as a mere duplicate.
- Audit `network-services-pentesting/pentesting-web/` (91 pages) against the Web section before moving it; service entry points and inbound links need a coordinated migration. Do not merge macOS runtime startup-injection pages until their per-runtime caveats can be preserved coherently.
