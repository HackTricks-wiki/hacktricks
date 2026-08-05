# macOS Kernel-Schwachstellen

{{#include ../../../banners/hacktricks-training.md}}

Bei der Ausnutzung des macOS-Kernels geht es heute weniger darum, „ein triviales unsigniertes kext zu laden und Ring-0 zu erhalten“, sondern eher darum, **Mach/MIG-Parser**, **IOKit user clients**, **data-only races innerhalb von XNU** und **speziell privilegierte Daemons** auszunutzen, die weiterhin Kernel-Angriffsflächen öffnen können. Für das Reversing der konkreten Interfaces siehe auch die Seiten zu [**IOKit**](macos-iokit.md) und [**kernel extensions / kernelcache extraction**](macos-kernel-extensions.md).

## Angriffsflächen, die weiterhin relevant sind

- **Mach/MIG-Handler** in System-Daemons und Kernel-nahen Services: fehlerhafte Deskriptoren, out-of-line (OOL) data und zustandsbehaftete Abläufe über mehrere Messages hinweg.
- **IOKit user clients**: Selector-spezifisches Parsing, durch Entitlements geschützte Methoden und Wrapper-Libraries/Daemons, die den tatsächlichen Call-Graph verbergen.
- **XNU data-only primitives**: Races rund um Credentials, durch SMR geschützte Pointer, Read-only-Zones und andere Stellen, an denen Korruption die Policy verändert, ohne zunächst die Kontrolle über RIP/PC zu erlangen.
- **Third-party / auxiliary kernel code**: Legacy-kexts sind seltener, aber Enterprise-Flotten, Apple-Silicon-Systeme mit reduzierter Sicherheit und herstellerspezifische `.fs`- / Helper-Bundles schaffen weiterhin hochwertige Kernel-nahe Pfade.

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

In [**diesem Report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) werden mehrere Bugs in der OTA-/Update-Chain kombiniert, um durch den Missbrauch der Software-Update-Pipeline und Rootless-bezogener Fähigkeiten eine Kernel-Kompromittierung zu erreichen.<sup>[[3]](#references)</sup>

[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722).

---

## 2024: In-the-wild-Umgehung der Kernel-Schutzmechanismen (CVE-2024-23225 & CVE-2024-23296)

Apples [**macOS-Sicherheitsupdates vom März 2024**](https://support.apple.com/en-us/120895) behoben zwei **aktiv ausgenutzte** Schwachstellen:

- **CVE-2024-23225 – Kernel**: ein Memory-Corruption-Bug, durch den ein Angreifer mit beliebigem Kernel-Read/Write die Kernel-Memory-Protection umgehen konnte.
- **CVE-2024-23296 – RTKit**: ein zweiter Memory-Corruption-Bug mit derselben öffentlich beschriebenen Auswirkung.

Öffentlich zugängliche Details zur Root Cause sind weiterhin rar, aber das Paar erinnert daran, dass moderne Apple-Exploit-Chains häufig **mehr als „nur“ Kernel-R/W** benötigen: Post-Exploitation gegen Memory-Protections, Coprocessor-nahen Code oder sekundäre Trust Boundaries ist häufig der Punkt, an dem die eigentliche Chain stabilisiert wird.

Schnelle Patch-Triage:
```bash
sw_vers
uname -v
softwareupdate --history | tail -n 20
```
---

## 2025: SMR + Read-only-Credential-Race (CVE-2025-24118)

Joseph Ravichandrans [**TRAVERTINE write-up**](https://jprx.io/cve-2025-24118/) ist eine sehr gute moderne XNU-Fallstudie, da es sich **nicht** um einen klassischen Buffer Overflow handelt:<sup>[[1]](#references)</sup>

- `proc_ro.p_ucred` ist ein **SMR-geschützter Pointer**, der in einem **Read-only-`proc_ro`-Objekt** gespeichert ist.
- Writer müssen diesen Pointer **atomar** aktualisieren.
- `kauth_cred_proc_update()` verwendete `zalloc_ro_mut(...)`, um `p_ucred` zu verändern; auf x86_64 landet dieser Pfad schließlich bei `memcpy` / `rep movsb`, sodass ein nebenläufiger Reader einen **Torn Pointer** beobachten kann.
- Der Bug wird zu einer **Data-only Privilege Escalation**: Wenn der korrumpierte Credential-Pointer auf ein anderes gültiges Credential-Objekt zeigt, kann der aktuelle Thread einen privilegierteren Zustand übernehmen, ohne zuvor einen offensichtlichen Control-Flow-Hijack erfolgreich durchführen zu müssen.

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
Nützliche Audit-Heuristik: Wann immer ein Kernel-Pfad **SMR readers**, **read-only zone mutation** sowie **credential oder task metadata** miteinander kombiniert, sollte überprüft werden, ob Updates die atomaren `zalloc_ro_mut_*`-Varianten statt copy-basierter Helfer verwenden.

---

## 2024-2025: SIP bypass, der Kernel-Ladepfade erneut öffnet (CVE-2024-44243)

Microsoft zeigte, dass `storagekitd` missbraucht werden konnte, um **SIP zu umgehen** und anschließend Third-Party-Kernel-Code auf Rechnern wieder relevant zu machen, die ansonsten wie "post-kext" aussehen würden. Die zentrale Idee ist:<sup>[[2]](#references)</sup>

1. Ein schädliches `.fs`-Bundle unter `/Library/Filesystems` ablegen oder überschreiben.
2. `storagekitd` über das Festplattendienstprogramm oder `diskutil` auslösen.
3. Den speziell berechtigten Daemon Bundle-Executables starten lassen, **ohne Berechtigungen ordnungsgemäß abzugeben / den Pfad zu validieren**.
4. Den daraus resultierenden SIP bypass verwenden, um geschützten Dateisystemstatus zu verändern und in Microsofts Demonstration die Kernel-Extension-Exclusion-List zu überschreiben.

Für Kernel-Forscher ist die wichtige Erkenntnis, dass **Kernel-Angriffsfläche aus Userland-Management-Daemons wieder eingeführt werden kann**, selbst wenn das direkte Laden von Third-Party-kexts stark eingeschränkt ist.

Nützliche Triage:
```bash
ls -la /Library/Filesystems
find /Library/Filesystems -maxdepth 3 -type f \( -name 'mount_*' -o -name 'fsck_*' -o -name 'newfs_*' \) 2>/dev/null
log stream --style syslog --predicate 'process == "storagekitd" || process == "diskarbitrationd"'
kmutil showloaded --collection aux
```
---

## Fuzzing- und Research-Workflow

Wenn du aktiv nach dieser Bug-Klasse suchst, weist die aktuelle öffentliche Forschung in dieselbe Richtung:

- [**KextFuzz**](https://www.usenix.org/conference/usenixsecurity23/presentation/yin) ist weiterhin eine der besten Referenzen für Kernel-Research im Apple-Silicon-Zeitalter. Es verwendet **static binary rewriting**, um Coverage wiederherzustellen, deaktiviert beim Testing **entitlement-gated** Pfade und leitet die Struktur von Interfaces aus Userspace-Wrappern ab.<sup>[[4]](#references)</sup>
- Project Zeros [**Simple macOS kernel extension fuzzing in userspace with IDA and TinyInst**](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html) zeigt einen sehr praktischen Workflow, um ein **kext / fileset in den Userspace zu rebasen**, damit parserlastiger Code mit deutlich höherer Geschwindigkeit gefuzzed werden kann, bevor die Reproduktion auf dem Gerät erfolgt.<sup>[[5]](#references)</sup>
- Für Mach-lastige Targets solltest du Harnesses rund um **echte Message-Layouts und Multi-Call-State-Machines** erstellen, nicht nur um einzelne Selector-Blobs. Aktuelle CoreAudio/Mach-Research von Project Zero und Konferenzvorträge wie **Fuzzing at Mach Speed** zeigen, warum sich Stateful-Message-Sequenzen weiterhin lohnen.

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
- [2] [Microsoft Security Blog - Analyse von CVE-2024-44243, einem macOS System Integrity Protection-Bypass durch Kernel extensions](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [3] [Mickey Jin - Der Albtraum von Apples OTA Update: Umgehen der Signature Verification und Übernehmen des Kernels](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [4] [Tingting Yin et al. - KextFuzz: Fuzzing von macOS Kernel EXTensions auf Apple Silicon durch das Ausnutzen von Mitigations (USENIX Security '23)](https://www.usenix.org/conference/usenixsecurity23/presentation/yin)
- [5] [Ivan Fratric (Project Zero) - Einfaches macOS Kernel extension fuzzing im Userspace mit IDA und TinyInst](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html)

{{#include ../../../banners/hacktricks-training.md}}
