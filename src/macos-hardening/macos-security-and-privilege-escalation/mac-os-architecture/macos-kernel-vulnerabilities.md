# macOS-Kernel-Schwachstellen

{{#include ../../../banners/hacktricks-training.md}}

Bei der modernen macOS-Kernel-Exploitation geht es weniger darum, einen „trivialen unsigned kext zu laden und Ring 0 zu erhalten“, sondern vielmehr darum, **Mach/MIG-Parser**, **IOKit-User-Clients**, **Data-only-Races innerhalb von XNU** und **speziell berechtigte Daemons** auszunutzen, die weiterhin die Kernel-Angriffsfläche erneut öffnen können. Für das Reverse Engineering der konkreten Schnittstellen siehe auch die Seiten zu [**IOKit**](macos-iokit.md) und [**Kernel Extensions / Kernelcache-Extraktion**](macos-kernel-extensions.md).

## Angriffsflächen, die weiterhin relevant sind

- **Mach/MIG-Handler** in System-Daemons und Kernel-nahen Diensten: manipulierte Deskriptoren, Out-of-line-(OOL-)Daten und zustandsbehaftete Abläufe über mehrere Nachrichten.
- **IOKit-User-Clients**: Selector-spezifisches Parsing, durch Entitlements geschützte Methoden sowie Wrapper-Bibliotheken/Daemons, die den tatsächlichen Call-Graph verbergen.
- **XNU-Data-only-Primitives**: Races im Zusammenhang mit Credentials, SMR-geschützten Zeigern, schreibgeschützten Zones und anderen Stellen, an denen eine Beschädigung die Policy verändert, ohne zuvor die Kontrolle über RIP/PC zu erlangen.
- **Kernel-Code von Drittanbietern / zusätzlicher Kernel-Code**: Legacy-kexts sind seltener, aber Enterprise-Flotten, Apple-Silicon-Systeme mit reduzierter Sicherheit und Anbieter-`.fs`- / Helper-Bundles schaffen weiterhin hochwertige Kernel-nahe Pfade.

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

In [**diesem Bericht**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) werden mehrere Bugs in der OTA-/Update-Kette kombiniert, um durch den Missbrauch der Software-Update-Pipeline und Rootless-bezogener Fähigkeiten eine Kernel-Kompromittierung zu erreichen.<sup>[3]</sup>

[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722).

---

## 2024: In-the-wild-Kette zum Umgehen des Kernel-Schutzes (CVE-2024-23225 & CVE-2024-23296)

Apples [**macOS-Sicherheitsupdates vom März 2024**](https://support.apple.com/en-us/120895) behoben zwei **aktiv ausgenutzte** Probleme:

- **CVE-2024-23225 – Kernel**: ein Memory-Corruption-Bug, durch den ein Angreifer mit beliebigem Kernel-Read/Write den Kernel-Speicherschutz umgehen konnte.
- **CVE-2024-23296 – RTKit**: ein zweiter Memory-Corruption-Bug mit derselben öffentlichen Auswirkungsbeschreibung.

Öffentlich zugängliche Details zur Root Cause sind weiterhin rar, aber das Paar erinnert daran, dass moderne Apple-Exploit-Ketten oft **mehr als „nur“ Kernel-R/W** benötigen: Post-Exploitation gegen Speicherschutzmechanismen, Coprozessor-nahen Code oder sekundäre Vertrauensgrenzen ist häufig der Punkt, an dem die eigentliche Kette stabilisiert wird.

Schnelle Patch-Triage:
```bash
sw_vers
uname -v
softwareupdate --history | tail -n 20
```
---

## 2025: SMR + read-only credential race (CVE-2025-24118)

Joseph Ravichandrans [**TRAVERTINE write-up**](https://jprx.io/cve-2025-24118/) ist eine sehr gute moderne Fallstudie zu XNU, da es sich **nicht** um einen klassischen buffer overflow handelt:<sup>[1]</sup>

- `proc_ro.p_ucred` ist ein **SMR-geschützter Pointer**, der in einem **read-only**-`proc_ro`-Objekt gespeichert ist.
- Writer müssen diesen Pointer **atomar** aktualisieren.
- `kauth_cred_proc_update()` verwendete `zalloc_ro_mut(...)`, um `p_ucred` zu verändern; auf x86_64 erreicht dieser Pfad schließlich `memcpy` / `rep movsb`, sodass ein nebenläufiger Reader einen **fragmentierten Pointer** beobachten kann.
- Der Bug wird zu einer **data-only privilege escalation**: Wenn der beschädigte Credential-Pointer auf ein anderes gültiges Credential-Objekt zeigt, kann der aktuelle Thread einen privilegierteren Status übernehmen, ohne zuvor eine offensichtliche control-flow hijack zu erreichen.

Minimales Trigger-Muster:
```c
// writer thread: force frequent credential swaps
while (1) {
setgid(real_gid);
setgid(saved_or_effective_gid);
}

// reader thread: repeatedly dereference current credentials
while (1) {
(void)getgid();
}
```
Nützliche Audit-Heuristik: Sobald ein Kernel-Pfad **SMR readers**, **read-only zone mutation** und **credential or task metadata** kombiniert, sollte überprüft werden, ob Updates die atomaren `zalloc_ro_mut_*`-Varianten statt copy-based helpers verwenden.

---

## 2024-2025: SIP bypass, der Kernel-Ladepfade wieder öffnet (CVE-2024-44243)

Microsoft zeigte, dass `storagekitd` missbraucht werden konnte, um **SIP zu umgehen** und anschließend Third-Party-Kernel-Code auf Geräten wieder relevant zu machen, die ansonsten wie "post-kext" aussehen würden. Die zentrale Idee ist:<sup>[2]</sup>

1. Ein bösartiges `.fs`-Bundle unter `/Library/Filesystems` ablegen oder überschreiben.
2. `storagekitd` über Disk Utility oder `diskutil` auslösen.
3. Den speziell berechtigten Daemon Bundle-Executables ohne ordnungsgemäßes Abgeben von Privilegien bzw. ohne korrekte Validierung des Pfads starten lassen.
4. Den resultierenden SIP bypass nutzen, um geschützten File-System-Status zu verändern und in Microsofts Demonstration die Kernel-Extension-Exclusion-List zu überschreiben.

Für Kernel-Forscher ist die wichtige Erkenntnis, dass **die Kernel-Angriffsfläche durch Userland-Management-Daemons wieder eingeführt werden kann**, selbst wenn das direkte Laden von Third-Party-kexts stark eingeschränkt ist.

Nützliche Triage:
```bash
ls -la /Library/Filesystems
find /Library/Filesystems -maxdepth 3 -type f \( -name 'mount_*' -o -name 'fsck_*' -o -name 'newfs_*' \) 2>/dev/null
log stream --style syslog --predicate 'process == "storagekitd" || process == "diskarbitrationd"'
kmutil showloaded --collection aux
```
---

## Fuzzing & Forschungsworkflow

Wenn du aktiv nach dieser Fehlerklasse suchst, weist die aktuelle öffentliche Forschung in dieselbe Richtung:

- [**KextFuzz**](https://www.usenix.org/conference/usenixsecurity23/presentation/yin) ist weiterhin eine der besten Referenzen für Kernel-Forschung im Apple-Silicon-Zeitalter. Es verwendet **static binary rewriting**, um Coverage wiederherzustellen, deaktiviert beim Testing **entitlement-gated** Pfade und leitet die Struktur von Interfaces aus Userspace-Wrappern ab.<sup>[4]</sup>
- Project Zeros [**Simple macOS kernel extension fuzzing in userspace with IDA and TinyInst**](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html) zeigt einen sehr praxisnahen Workflow für das **Rebasing eines kext / fileset in den Userspace**, sodass parser-lastiger Code mit deutlich höherer Geschwindigkeit gefuzzed werden kann, bevor die Reproduktion auf dem Gerät erfolgt.<sup>[5]</sup>
- Für Mach-lastige Ziele solltest du Harnesses auf Basis von **realen Message-Layouts und Multi-Call-State-Machines** erstellen, nicht nur auf Basis einzelner Selector-Blobs. Aktuelle CoreAudio/Mach-Forschung von Project Zero sowie Konferenzvorträge wie **Fuzzing at Mach Speed** zeigen, warum sich Stateful Message-Sequenzen weiterhin auszahlen.

Schnelle lokale Befehle, die du tatsächlich häufig verwenden wirst:
```bash
# Loaded auxiliary / 3rd party kernel code
kmutil showloaded --collection aux

# Fileset entries in the boot kernel collection
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Diffable version info before matching a KDK / symbols pack
sw_vers
uname -a
```
## Kurzes Enumeration-Cheatsheet
```bash
uname -a                          # Kernel build
sw_vers                           # ProductVersion / BuildVersion
kmutil showloaded                 # List loaded kernel extensions
kmutil showloaded --collection aux  # Auxiliary / 3rd party collections
kextstat 2>/dev/null | grep -v com.apple
csrutil status                    # Check SIP state
spctl --status                    # Confirm Gatekeeper state
```
## Referenzen

- [1] [Joseph Ravichandran - TRAVERTINE: CVE-2025-24118](https://jprx.io/cve-2025-24118/)
- [2] [Microsoft Security Blog - Analyse von CVE-2024-44243, einem macOS System Integrity Protection bypass durch Kernel extensions](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [3] [Mickey Jin - Der Albtraum von Apples OTA Update: Umgehen der Signature Verification und Pwning des Kernels](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [4] [Tingting Yin et al. - KextFuzz: Fuzzing von macOS Kernel EXTensions auf Apple Silicon durch das Ausnutzen von Mitigations (USENIX Security '23)](https://www.usenix.org/conference/usenixsecurity23/presentation/yin)
- [5] [Ivan Fratric (Project Zero) - Einfaches macOS Kernel extension fuzzing im Userspace mit IDA und TinyInst](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html)

{{#include ../../../banners/hacktricks-training.md}}
