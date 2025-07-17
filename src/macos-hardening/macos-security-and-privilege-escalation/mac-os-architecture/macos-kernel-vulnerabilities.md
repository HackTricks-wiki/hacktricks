# macOS Kernel Vulnerabilities

{{#include ../../../banners/hacktricks-training.md}}

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

[**In diesem Bericht**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) werden mehrere Schwachstellen erklärt, die es ermöglichten, den Kernel zu kompromittieren und den Software-Updater zu gefährden.\
[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722).

---

## 2024: In-the-wild Kernel 0-days (CVE-2024-23225 & CVE-2024-23296)

Apple hat im März 2024 zwei Speicherbeschädigungsfehler gepatcht, die aktiv gegen iOS und macOS ausgenutzt wurden (behoben in macOS 14.4/13.6.5/12.7.4).

* **CVE-2024-23225 – Kernel**
• Out-of-bounds-Schreibvorgang im XNU-Virtual-Memory-Subsystem ermöglicht es einem unprivilegierten Prozess, beliebige Lese-/Schreibzugriffe im Kernel-Adressraum zu erhalten und PAC/KTRR zu umgehen.
• Aus dem Userspace ausgelöst über eine manipulierte XPC-Nachricht, die einen Puffer in `libxpc` überläuft und dann in den Kernel wechselt, wenn die Nachricht analysiert wird.
* **CVE-2024-23296 – RTKit**
• Speicherbeschädigung im Apple Silicon RTKit (Echtzeit-Co-Prozessor).
• Beobachtete Ausnutzungs-Ketten verwendeten CVE-2024-23225 für Kernel R/W und CVE-2024-23296, um den sicheren Co-Prozessor-Sandbox zu verlassen und PAC zu deaktivieren.

Patch-Level-Erkennung:
```bash
sw_vers                 # ProductVersion 14.4 or later is patched
authenticate sudo sysctl kern.osversion  # 23E214 or later for Sonoma
```
Wenn ein Upgrade nicht möglich ist, mildern Sie das Risiko, indem Sie anfällige Dienste deaktivieren:
```bash
launchctl disable system/com.apple.analyticsd
launchctl disable system/com.apple.rtcreportingd
```
---

## 2023: MIG Typverwirrung – CVE-2023-41075

`mach_msg()`-Anfragen, die an einen unprivilegierten IOKit-Benutzerclient gesendet werden, führen zu einer **Typverwirrung** im von MIG generierten Kleber-Code. Wenn die Antwortnachricht mit einem größeren Out-of-Line-Deskriptor, als ursprünglich zugewiesen, neu interpretiert wird, kann ein Angreifer einen kontrollierten **OOB-Schreibvorgang** in Kernel-Heap-Zonen erreichen und schließlich zu `root` eskalieren.

Primitive Übersicht (Sonoma 14.0-14.1, Ventura 13.5-13.6):
```c
// userspace stub
typed_port_t p = get_user_client();
uint8_t spray[0x4000] = {0x41};
// heap-spray via IOSurfaceFastSetValue
io_service_open_extended(...);
// malformed MIG message triggers confusion
mach_msg(&msg.header, MACH_SEND_MSG|MACH_RCV_MSG, ...);
```
Öffentliche Exploits nutzen den Fehler aus, indem sie:
1. `ipc_kmsg`-Puffer mit aktiven Portzeigern sprühen.
2. `ip_kobject` eines hängenden Ports überschreiben.
3. Zu Shellcode springen, der an einer PAC-fälschung Adresse mit `mprotect()` abgebildet ist.

---

## 2024-2025: SIP-Umgehung durch Drittanbieter-Kexts – CVE-2024-44243 (auch bekannt als “Sigma”)

Sicherheitsforscher von Microsoft zeigten, dass der hochprivilegierte Daemon `storagekitd` gezwungen werden kann, eine **nicht signierte Kernel-Erweiterung** zu laden und somit **System Integrity Protection (SIP)** auf vollständig gepatchtem macOS (vor 15.2) vollständig zu deaktivieren. Der Angriffsfluss ist:

1. Missbrauch des privaten Anspruchs `com.apple.storagekitd.kernel-management`, um einen Helfer unter Kontrolle des Angreifers zu starten.
2. Der Helfer ruft `IOService::AddPersonalitiesFromKernelModule` mit einem gestalteten Info-Dictionary auf, das auf ein bösartiges Kext-Bundle verweist.
3. Da die SIP-Vertrauensprüfungen *nach* dem Staging des Kext durch `storagekitd` durchgeführt werden, wird der Code in Ring-0 vor der Validierung ausgeführt und SIP kann mit `csr_set_allow_all(1)` deaktiviert werden.

Erkennungstipps:
```bash
kmutil showloaded | grep -v com.apple   # list non-Apple kexts
log stream --style syslog --predicate 'senderImagePath contains "storagekitd"'   # watch for suspicious child procs
```
Sofortige Abhilfe besteht darin, auf macOS Sequoia 15.2 oder höher zu aktualisieren.

---

### Schnelle Aufzählung Cheatsheet
```bash
uname -a                          # Kernel build
kmutil showloaded                 # List loaded kernel extensions
kextstat | grep -v com.apple      # Legacy (pre-Catalina) kext list
sysctl kern.kaslr_enable          # Verify KASLR is ON (should be 1)
csrutil status                    # Check SIP from RecoveryOS
spctl --status                    # Confirms Gatekeeper state
```
---

## Fuzzing & Research Tools

* **Luftrauser** – Mach-Nachrichten-Fuzzer, der MIG-Subsysteme anvisiert (`github.com/preshing/luftrauser`).
* **oob-executor** – IPC-Out-of-Bounds-Primitiv-Generator, der in der CVE-2024-23225-Forschung verwendet wird.
* **kmutil inspect** – Eingebaute Apple-Dienstprogramm (macOS 11+), um kexts vor dem Laden statisch zu analysieren: `kmutil inspect -b io.kext.bundleID`.



## References

* Apple. “About the security content of macOS Sonoma 14.4.” https://support.apple.com/en-us/120895
* Microsoft Security Blog. “Analyzing CVE-2024-44243, a macOS System Integrity Protection bypass through kernel extensions.” https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/
{{#include ../../../banners/hacktricks-training.md}}
