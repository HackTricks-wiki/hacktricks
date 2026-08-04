# macOS-Kernel-Schwachstellen

{{#include ../../../banners/hacktricks-training.md}}

Bei aktuellen macOS-Kernel-Exploits geht es weniger darum, ein „triviales unsigniertes kext zu laden und Ring 0 zu erreichen“, sondern vielmehr darum, **Mach/MIG-Parser**, **IOKit user clients**, **Data-only-Races innerhalb von XNU** und **speziell berechtigte Daemons** auszunutzen, die weiterhin Kernel-Angriffsflächen erneut öffnen können. Für das Reverse Engineering der konkreten Schnittstellen siehe auch die Seiten zu [**IOKit**](macos-iokit.md) und zur [**Extraktion von Kernel-Erweiterungen / Kernelcache**](macos-kernel-extensions.md).

## Angriffsflächen, die weiterhin relevant sind

- **Mach/MIG-Handler** in System-Daemons und kernelnahen Diensten: manipulierte Deskriptoren, Out-of-line-(OOL-)Daten und zustandsbehaftete Abläufe über mehrere Nachrichten.
- **IOKit user clients**: selector-spezifisches Parsing, durch Entitlements geschützte Methoden sowie Wrapper-Bibliotheken/Daemons, die den tatsächlichen Call-Graph verbergen.
- **XNU-Data-only-Primitives**: Races im Zusammenhang mit Credentials, durch SMR geschützten Pointern, schreibgeschützten Zones und anderen Stellen, an denen eine Korruption die Policy verändert, ohne zunächst die Kontrolle über RIP/PC zu erlangen.
- **Kernel-Code von Drittanbietern / zusätzlicher Kernel-Code**: Legacy-kexts sind seltener, aber Enterprise-Flotten, Apple-Silicon-Systeme mit reduzierter Sicherheit und Anbieter-`.fs`- / Helper-Bundles schaffen weiterhin hochwertige kernelnahe Pfade.

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

In [**diesem Bericht**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) werden mehrere Bugs in der OTA-/Update-Kette kombiniert, um durch den Missbrauch der Software-Update-Pipeline und von Rootless-bezogenen Fähigkeiten eine Kompromittierung des Kernels zu erreichen.

[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722).

---

## 2024: In-the-wild-Umgehung der Kernel-Schutzmechanismen (CVE-2024-23225 & CVE-2024-23296)

Apples [**macOS-Sicherheitsupdates vom März 2024**](https://support.apple.com/en-us/120895) behoben zwei **aktiv ausgenutzte** Probleme:

- **CVE-2024-23225 – Kernel**: ein Memory-Corruption-Bug, durch den ein Angreifer mit beliebigem Kernel-Lese-/Schreibzugriff die Kernel-Speicherschutzmechanismen umgehen konnte.
- **CVE-2024-23296 – RTKit**: ein zweiter Memory-Corruption-Bug mit derselben öffentlich beschriebenen Auswirkung.

Öffentlich zugängliche Details zur Root Cause sind weiterhin rar. Das Paar erinnert jedoch daran, dass moderne Apple-Exploit-Ketten häufig **mehr als „nur“ Kernel-R/W** benötigen: Post-Exploitation gegen Speicherschutzmechanismen, coprozessornahe Komponenten oder sekundäre Trust Boundaries ist oft der Punkt, an dem die eigentliche Kette stabilisiert wird.

Schnelle Patch-Triage:
```bash
sw_vers
uname -v
softwareupdate --history | tail -n 20
```
---

## 2025: SMR + Race bei schreibgeschützten Credentials (CVE-2025-24118)

Joseph Ravichandrans [**TRAVERTINE write-up**](https://jprx.io/cve-2025-24118/) ist eine sehr gute moderne XNU-Fallstudie, da es sich **nicht** um einen klassischen buffer overflow handelt:

- `proc_ro.p_ucred` ist ein **SMR-geschützter Zeiger**, der in einem **schreibgeschützten** `proc_ro`-Objekt gespeichert ist.
- Writer müssen diesen Zeiger **atomar** aktualisieren.
- `kauth_cred_proc_update()` verwendete `zalloc_ro_mut(...)`, um `p_ucred` zu verändern; auf x86_64 führt dieser Pfad letztendlich zu `memcpy` / `rep movsb`, sodass ein nebenläufiger Reader einen **zerrissenen Zeiger** beobachten kann.
- Der Bug führt zu einer **data-only privilege escalation**: Wenn der korrumpierte Credential-Zeiger auf ein anderes gültiges Credential-Objekt zeigt, kann der aktuelle Thread einen privilegierteren Status übernehmen, ohne zuvor eine offensichtliche control-flow hijack zu erreichen.

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
Nützliche Audit-Heuristik: Wenn ein Kernel-Pfad **SMR readers**, **read-only zone mutation** sowie **credential oder task metadata** kombiniert, sollte überprüft werden, ob Updates die atomaren `zalloc_ro_mut_*`-Varianten statt copy-basierter Helfer verwenden.

---

## 2024-2025: SIP bypass, der Kernel-Ladepfade erneut öffnet (CVE-2024-44243)

Microsoft zeigte, dass `storagekitd` missbraucht werden konnte, um **SIP zu umgehen** und anschließend Code von Drittanbietern im Kernel wieder relevant zu machen – auf Rechnern, die ansonsten als „post-kext“ erscheinen würden. Die zentrale Idee ist:

1. Ein bösartiges `.fs`-Bundle unter `/Library/Filesystems` ablegen oder überschreiben.
2. `storagekitd` über das Festplattendienstprogramm oder `diskutil` auslösen.
3. Den speziell berechtigten Daemon Bundle-Executables starten lassen, **ohne Berechtigungen ordnungsgemäß abzugeben oder den Pfad zu validieren**.
4. Den daraus resultierenden SIP bypass verwenden, um geschützten Dateisystemstatus zu ändern und in Microsofts Demonstration die Ausschlussliste für Kernel-Erweiterungen zu überschreiben.

Für Kernel-Forscher ist die wichtige Erkenntnis, dass **Kernel-Angriffsfläche aus Userland-Verwaltungs-Daemons heraus wieder eingeführt werden kann**, selbst wenn das direkte Laden von Kexts von Drittanbietern stark eingeschränkt ist.

Nützliche Triage:
```bash
ls -la /Library/Filesystems
find /Library/Filesystems -maxdepth 3 -type f \( -name 'mount_*' -o -name 'fsck_*' -o -name 'newfs_*' \) 2>/dev/null
log stream --style syslog --predicate 'process == "storagekitd" || process == "diskarbitrationd"'
kmutil showloaded --collection aux
```
---

## Fuzzing- und Recherche-Workflow

Wenn du aktiv nach dieser Klasse von Bugs suchst, weist die aktuelle öffentliche Forschung weiterhin in dieselbe Richtung:

- [**KextFuzz**](https://www.usenix.org/conference/usenixsecurity23/presentation/yin) ist nach wie vor eine der besten Referenzen für Kernel-Forschung im Apple-Silicon-Zeitalter. Es verwendet **statisches Binary-Rewriting**, um Coverage wiederherzustellen, deaktiviert beim Testen **entitlement-gesteuerte** Pfade und leitet die Struktur von Schnittstellen aus Userspace-Wrappern ab.
- Project Zeros [**Simple macOS kernel extension fuzzing in userspace with IDA and TinyInst**](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html) zeigt einen sehr praxisnahen Workflow zum **Rebasen eines kext / fileset in den Userspace**, sodass parserlastiger Code mit deutlich höherer Geschwindigkeit gefuzzed werden kann, bevor die Reproduktion auf dem Gerät erfolgt.
- Für Mach-lastige Ziele solltest du Harnesses rund um **reale Nachrichtenlayouts und Zustandsautomaten mit mehreren Aufrufen** erstellen, nicht nur um einzelne Selector-Blobs. Aktuelle CoreAudio/Mach-Forschung von Project Zero und Konferenzvorträge wie **Fuzzing at Mach Speed** zeigen, warum sich zustandsbehaftete Nachrichtenfolgen weiterhin auszahlen.

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
## Schneller Enumeration-Spickzettel
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

* Joseph Ravichandran. „TRAVERTINE: CVE-2025-24118.“ https://jprx.io/cve-2025-24118/
* Microsoft Security Blog. „Analyse von CVE-2024-44243, einem Bypass von macOS System Integrity Protection durch Kernel Extensions.“ https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/
{{#include ../../../banners/hacktricks-training.md}}
