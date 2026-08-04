# macOS Kernel-kwesbaarhede

{{#include ../../../banners/hacktricks-training.md}}

Onlangse macOS kernel exploitation gaan minder daaroor om ’n "trivial unsigned kext" te laai en ring-0 te verkry, en meer daaroor om **Mach/MIG parsers**, **IOKit user clients**, **data-only races inside XNU**, en **specially entitled daemons** te misbruik wat steeds die kernel-aanvaloppervlak kan heropen. Vir die ontleding van die konkrete interfaces, kyk ook na die bladsye oor [**IOKit**](macos-iokit.md) en [**kernel extensions / kernelcache extraction**](macos-kernel-extensions.md).

## Aanvalsoppervlakke wat steeds saak maak

- **Mach/MIG handlers** in stelseldaemons en kernel-facing services: malformed descriptors, out-of-line (OOL) data, en stateful multi-message flows.
- **IOKit user clients**: selector-specific parsing, entitlement-gated methods, en wrapper libraries/daemons wat die werklike call graph verberg.
- **XNU data-only primitives**: races rondom credentials, SMR-protected pointers, read-only zones, en ander plekke waar corruption policy verander sonder om eers beheer oor RIP/PC te verkry.
- **Third-party / auxiliary kernel code**: legacy kexts is skaarser, maar enterprise fleets, reduced-security Apple Silicon-stelsels, en vendor `.fs` / helper bundles skep steeds hoëwaarde kernel-adjacent paths.

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

In [**hierdie verslag**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) word verskeie OTA/update-chain bugs gekombineer om kernel compromise te bereik deur die software update pipeline en rootless-related capabilities te misbruik.

[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722).

---

## 2024: In-the-wild kernel protection bypass chain (CVE-2024-23225 & CVE-2024-23296)

Apple se [**March 2024 macOS security releases**](https://support.apple.com/en-us/120895) het twee issues reggestel wat **actively exploited** is:

- **CVE-2024-23225 – Kernel**: ’n memory-corruption bug waar ’n aanvaller met arbitrary kernel read/write kernel memory protections kon omseil.
- **CVE-2024-23296 – RTKit**: ’n tweede memory-corruption bug met dieselfde openbare impact statement.

Publieke root-cause details is steeds skaars, maar die paar is ’n goeie herinnering dat moderne Apple exploit chains dikwels **meer as "net" kernel R/W** benodig: post-exploitation-werk teen memory protections, coprocessor-adjacent code, of secondary trust boundaries is dikwels waar die werklike chain gestabiliseer word.

Vinnige patch-triage:
```bash
sw_vers
uname -v
softwareupdate --history | tail -n 20
```
---

## 2025: SMR + read-only credential race (CVE-2025-24118)

Joseph Ravichandran se [**TRAVERTINE write-up**](https://jprx.io/cve-2025-24118/) is 'n baie goeie moderne XNU-case study omdat dit **nie** 'n klassieke buffer overflow is nie:

- `proc_ro.p_ucred` is 'n **SMR-protected pointer** wat in 'n **read-only** `proc_ro`-object gestoor word.
- Writers moet daardie pointer **atomies** opdateer.
- `kauth_cred_proc_update()` het `zalloc_ro_mut(...)` gebruik om `p_ucred` te muteer; op x86_64 bereik daardie pad uiteindelik `memcpy` / `rep movsb`, sodat 'n concurrent reader 'n **torn pointer** kan waarneem.
- Die bug verander in 'n **data-only privilege escalation**: indien die korrupte credential pointer na 'n ander geldige credential object verwys, kan die huidige thread meer bevoorregte state oorneem sonder om eers 'n ooglopende control-flow hijack te wen.

Minimale trigger pattern:
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
Nuttige audit-heuristiek: wanneer ’n kernel path **SMR readers**, **read-only zone mutation** en **credential- of task-metadata** kombineer, verifieer dat updates die atomiese `zalloc_ro_mut_*`-variante gebruik eerder as copy-based helpers.

---

## 2024-2025: SIP bypass wat kernel-loading paths heropen (CVE-2024-44243)

Microsoft het getoon dat `storagekitd` misbruik kon word om **SIP te bypass** en daarna third-party kernel code weer relevant te maak op masjiene wat andersins soos "post-kext" sou lyk. Die kernidee is:

1. Drop of overwrite ’n malicious `.fs` bundle onder `/Library/Filesystems`.
2. Trigger `storagekitd` via Disk Utility of `diskutil`.
3. Laat die specially entitled daemon bundle executables spawn **sonder om privileges behoorlik te laat sak / die path te valideer**.
4. Gebruik die gevolglike SIP bypass om protected file-system state te wysig en, in Microsoft se demonstrasie, die kernel extension exclusion list te override.

Vir kernel researchers is die belangrike les dat **kernel attack surface weer vanuit userland management daemons ingestel kan word**, selfs wanneer direct third-party kext loading streng beperk word.

Nuttige triage:
```bash
ls -la /Library/Filesystems
find /Library/Filesystems -maxdepth 3 -type f \( -name 'mount_*' -o -name 'fsck_*' -o -name 'newfs_*' \) 2>/dev/null
log stream --style syslog --predicate 'process == "storagekitd" || process == "diskarbitrationd"'
kmutil showloaded --collection aux
```
---

## Fuzzing & navorsingswerkvloei

As jy aktief na hierdie klas bugs soek, wys die onlangse publieke werk in dieselfde rigting:

- [**KextFuzz**](https://www.usenix.org/conference/usenixsecurity23/presentation/yin) is steeds een van die beste verwysings vir kernel-navorsing in die Apple-Silicon-era. Dit gebruik **static binary rewriting** om coverage te herstel, deaktiveer **entitlement-gated** paaie tydens toetsing, en lei die interfacestruktuur uit userspace-wrappers af.
- Project Zero se [**Simple macOS kernel extension fuzzing in userspace with IDA and TinyInst**](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html) wys ’n baie praktiese workflow vir die **rebasing van ’n kext / fileset na userspace** sodat parser-swaar kode teen ’n veel hoër spoed gefuzz kan word voordat dit op die toestel gereproduseer word.
- Vir Mach-swaar teikens, bou harnesses rondom **werklike message layouts en multi-call state machines**, nie net enkele selector blobs nie. Onlangse CoreAudio/Mach-navorsing van Project Zero en konferensietoesprake soos **Fuzzing at Mach Speed** wys waarom stateful message sequences steeds vrugte afwerp.

Vinnige plaaslike opdragte wat jy gereeld sal gebruik:
```bash
# Loaded auxiliary / 3rd party kernel code
kmutil showloaded --collection aux

# Fileset entries in the boot kernel collection
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Diffable version info before matching a KDK / symbols pack
sw_vers
uname -a
```
## Vinnige Enumeration Cheatsheet
```bash
uname -a                          # Kernel build
sw_vers                           # ProductVersion / BuildVersion
kmutil showloaded                 # List loaded kernel extensions
kmutil showloaded --collection aux  # Auxiliary / 3rd party collections
kextstat 2>/dev/null | grep -v com.apple
csrutil status                    # Check SIP state
spctl --status                    # Confirm Gatekeeper state
```
## Verwysings

* Joseph Ravichandran. “TRAVERTINE: CVE-2025-24118.” https://jprx.io/cve-2025-24118/
* Microsoft Security Blog. “Ontleding van CVE-2024-44243, ’n macOS System Integrity Protection-bypassing deur kernel extensions.” https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/
{{#include ../../../banners/hacktricks-training.md}}
