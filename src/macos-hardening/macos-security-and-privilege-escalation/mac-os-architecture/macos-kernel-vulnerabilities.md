# macOS Kernel Vulnerabilities

{{#include ../../../banners/hacktricks-training.md}}

Onlangse macOS-kernel exploitation gaan minder daaroor om "'n triviale unsigned kext te laai en ring-0 te verkry" en meer daaroor om **Mach/MIG-parsers**, **IOKit user clients**, **data-only races binne XNU**, en **spesiaal ge-enteitelde daemons** te misbruik wat steeds die kernel-aanvalsoppervlak kan heropen. Vir die reverse engineering van die konkrete interfaces, kyk ook na die bladsye oor [**IOKit**](macos-iokit.md) en [**kernel extensions / kernelcache extraction**](macos-kernel-extensions.md).

## Aanvalsoppervlakke wat steeds saak maak

- **Mach/MIG-handlers** in stelseldaemons en kernel-facing services: misvormde descriptors, out-of-line (OOL)-data, en stateful multi-message flows.
- **IOKit user clients**: selector-spesifieke parsing, entitlement-gated methods, en wrapper libraries/daemons wat die werklike call graph verberg.
- **XNU data-only primitives**: races rondom credentials, SMR-protected pointers, read-only zones, en ander plekke waar corruption beleid verander sonder om eers beheer oor RIP/PC te verkry.
- **Third-party / auxiliary kernel code**: legacy kexts is skaarser, maar enterprise fleets, reduced-security Apple Silicon-stelsels, en vendor `.fs` / helper bundles skep steeds waardevolle kernel-adjacent paths.

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

In [**hierdie verslag**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) word verskeie OTA/update-chain bugs gekombineer om kernel compromise te bereik deur die software update pipeline en rootless-verwante capabilities te misbruik.<sup>[3]</sup>

[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722).

---

## 2024: In-the-wild kernel protection bypass chain (CVE-2024-23225 & CVE-2024-23296)

Apple se [**macOS-sekuriteitsvrystellings van Maart 2024**](https://support.apple.com/en-us/120895) het twee kwessies reggestel wat **aktief uitgebuit is**:

- **CVE-2024-23225 – Kernel**: 'n memory-corruption bug waar 'n aanvaller met arbitrary kernel read/write kernel memory protections kon omseil.
- **CVE-2024-23296 – RTKit**: 'n tweede memory-corruption bug met dieselfde openbare impact statement.

Openbare root-cause-besonderhede is steeds skaars, maar die paar is 'n goeie herinnering dat moderne Apple-exploit chains dikwels **meer as "net" kernel R/W** benodig: post-exploitation-werk teen memory protections, coprocessor-adjacent code, of sekondêre trust boundaries is dikwels waar die werklike chain gestabiliseer word.

Vinnige patch triage:
```bash
sw_vers
uname -v
softwareupdate --history | tail -n 20
```
---

## 2025: SMR + read-only credential race (CVE-2025-24118)

Joseph Ravichandran se [**TRAVERTINE write-up**](https://jprx.io/cve-2025-24118/) is 'n baie goeie moderne XNU-gevallestudie omdat dit **nie** 'n klassieke buffer overflow is nie:<sup>[1]</sup>

- `proc_ro.p_ucred` is 'n **SMR-protected pointer** wat in 'n **read-only** `proc_ro`-objek gestoor word.
- Writers moet daardie pointer **atomically** bywerk.
- `kauth_cred_proc_update()` het `zalloc_ro_mut(...)` gebruik om `p_ucred` te wysig; op x86_64 bereik daardie pad uiteindelik `memcpy` / `rep movsb`, sodat 'n gelyktydige reader 'n **torn pointer** kan waarneem.
- Die bug verander in 'n **data-only privilege escalation**: indien die korrupte credential pointer na 'n ander geldige credential-objek resolve, kan die huidige thread meer privileged state erf sonder om eers 'n ooglopende control-flow hijack te wen.

Minimal trigger pattern:
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
Nuttige ouditheuristiek: wanneer ’n kernel-pad **SMR readers**, **read-only zone mutation** en **credential- of taakmetadata** kombineer, verifieer dat opdaterings die atomiese `zalloc_ro_mut_*`-variante gebruik eerder as copy-based helpers.

---

## 2024-2025: SIP bypass wat kernel-laaipaaie heropen (CVE-2024-44243)

Microsoft het gewys dat `storagekitd` misbruik kon word om **SIP te omseil** en daarna derdeparty-kernelcode weer relevant te maak op masjiene wat andersins as "post-kext" beskou sou word. Die kernidee is:<sup>[2]</sup>

1. Plaas of oorskryf ’n kwaadwillige `.fs`-bundel onder `/Library/Filesystems`.
2. Aktiveer `storagekitd` via Disk Utility of `diskutil`.
3. Laat die daemon met spesiale regte bundeluitvoerbare lêers voortbring **sonder om voorregte behoorlik te laat vaar / die pad te valideer**.
4. Gebruik die gevolglike SIP bypass om beskermde lêerstelseltoestand te wysig en, in Microsoft se demonstrasie, die kernel extension-exclusion list te oorskryf.

Vir kernel-navorsers is die belangrike les dat **kernel-aanvalsoppervlak vanuit userland-bestuursdaemons heringestel kan word**, selfs wanneer direkte laai van derdeparty-kexts sterk beperk word.

Nuttige triage:
```bash
ls -la /Library/Filesystems
find /Library/Filesystems -maxdepth 3 -type f \( -name 'mount_*' -o -name 'fsck_*' -o -name 'newfs_*' \) 2>/dev/null
log stream --style syslog --predicate 'process == "storagekitd" || process == "diskarbitrationd"'
kmutil showloaded --collection aux
```
---

## Fuzzing- en navorsingsworkflow

As jy aktief na hierdie klas bugs soek, wys die onlangse openbare werk in dieselfde rigting:

- [**KextFuzz**](https://www.usenix.org/conference/usenixsecurity23/presentation/yin) is steeds een van die beste verwysings vir kernel-navorsing in die Apple-Silicon-era. Dit gebruik **static binary rewriting** om coverage te herwin, deaktiveer **entitlement-gated** paaie tydens testing, en lei die interfacestruktuur uit userspace-wrappers af.<sup>[4]</sup>
- Project Zero se [**Simple macOS kernel extension fuzzing in userspace with IDA and TinyInst**](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html) wys ’n baie praktiese workflow vir die **rebasing van ’n kext / fileset na userspace**, sodat parser-swaar code teen veel hoër spoed gefuzz kan word voordat dit op die toestel gereproduseer word.<sup>[5]</sup>
- Vir Mach-swaar targets, bou harnesses rondom **real message layouts en multi-call state machines**, nie net single selector blobs nie. Onlangse CoreAudio/Mach-navorsing van Project Zero en konferensietoesprake soos **Fuzzing at Mach Speed** wys waarom stateful message-sequences steeds resultate lewer.

Vinnige plaaslike commands wat jy in werklikheid baie sal gebruik:
```bash
# Loaded auxiliary / 3rd party kernel code
kmutil showloaded --collection aux

# Fileset entries in the boot kernel collection
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Diffable version info before matching a KDK / symbols pack
sw_vers
uname -a
```
## Vinnige enumerasie-cheatsheet
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

- [1] [Joseph Ravichandran - TRAVERTINE: CVE-2025-24118](https://jprx.io/cve-2025-24118/)
- [2] [Microsoft Security Blog - Ontleding van CVE-2024-44243, 'n macOS System Integrity Protection-bypass deur kernel extensions](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [3] [Mickey Jin - Die nagmerrie van Apple se OTA Update: Om die Signature Verification te omseil en die Kernel oor te neem](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [4] [Tingting Yin et al. - KextFuzz: Fuzzing van macOS Kernel EXTensions op Apple Silicon deur Mitigations te ontgin (USENIX Security '23)](https://www.usenix.org/conference/usenixsecurity23/presentation/yin)
- [5] [Ivan Fratric (Project Zero) - Eenvoudige macOS kernel extension-fuzzing in userspace met IDA en TinyInst](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html)

{{#include ../../../banners/hacktricks-training.md}}
