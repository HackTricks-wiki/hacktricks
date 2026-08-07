# macOS Kernel Vulnerabilities

{{#include ../../../banners/hacktricks-training.md}}

हालिया macOS kernel exploitation अब "एक trivial unsigned kext load करके ring-0 प्राप्त करने" से कम और **Mach/MIG parsers**, **IOKit user clients**, **XNU के अंदर data-only races**, तथा **specially entitled daemons** का abuse करने से अधिक संबंधित है, जो kernel attack surface को फिर से खोल सकते हैं। Concrete interfaces को reverse करने के लिए [**IOKit**](macos-iokit.md) और [**kernel extensions / kernelcache extraction**](macos-kernel-extensions.md) से संबंधित pages भी देखें।

## वे attack surfaces जो अभी भी महत्वपूर्ण हैं

- system daemons और kernel-facing services में **Mach/MIG handlers**: malformed descriptors, out-of-line (OOL) data और stateful multi-message flows।
- **IOKit user clients**: selector-specific parsing, entitlement-gated methods और wrapper libraries/daemons जो वास्तविक call graph को छिपाते हैं।
- **XNU data-only primitives**: credentials, SMR-protected pointers, read-only zones और अन्य स्थानों के आसपास races, जहां corruption पहले RIP/PC control प्राप्त किए बिना policy बदल सकता है।
- **Third-party / auxiliary kernel code**: legacy kexts अब कम सामान्य हैं, लेकिन enterprise fleets, reduced-security Apple Silicon systems और vendor `.fs` / helper bundles अभी भी high-value kernel-adjacent paths बनाते हैं।

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

[**इस report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) में कई OTA/update-chain bugs को combine करके software update pipeline और rootless-related capabilities का abuse करते हुए kernel compromise तक पहुंच बनाई जाती है।<sup>[[3]](#references)</sup>

[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722).

---

## 2024: In-the-wild kernel protection bypass chain (CVE-2024-23225 & CVE-2024-23296)

Apple की [**March 2024 macOS security releases**](https://support.apple.com/en-us/120895) ने दो ऐसी समस्याओं को fix किया जो **actively exploited** थीं:<sup>[[6]](#references)</sup>

- **CVE-2024-23225 – Kernel**: एक memory-corruption bug, जिसमें arbitrary kernel read/write वाला attacker kernel memory protections को bypass कर सकता था।
- **CVE-2024-23296 – RTKit**: इसी public impact statement वाला दूसरा memory-corruption bug।

Public root-cause details अभी भी scarce हैं, लेकिन यह pair एक अच्छा reminder है कि modern Apple exploit chains को अक्सर **"सिर्फ" kernel R/W से अधिक** की आवश्यकता होती है: memory protections, coprocessor-adjacent code या secondary trust boundaries के विरुद्ध post-exploitation work अक्सर वह चरण होता है जहां वास्तविक chain को stabilize किया जाता है।

Quick patch triage:
```bash
sw_vers
uname -v
softwareupdate --history | tail -n 20
```
---

## 2025: SMR + read-only credential race (CVE-2025-24118)

Joseph Ravichandran का [**TRAVERTINE write-up**](https://jprx.io/cve-2025-24118/) एक बहुत अच्छा आधुनिक XNU case study है, क्योंकि यह **classic buffer overflow** नहीं है:<sup>[[1]](#references)</sup>

- `proc_ro.p_ucred` एक **SMR-protected pointer** है, जो एक **read-only** `proc_ro` object में stored है।
- Writers को उस pointer को **atomically** update करना आवश्यक है।
- `kauth_cred_proc_update()` ने `p_ucred` को mutate करने के लिए `zalloc_ro_mut(...)` का उपयोग किया; x86_64 पर वह path अंततः `memcpy` / `rep movsb` तक पहुंचता है, इसलिए एक concurrent reader **torn pointer** देख सकता है।
- यह bug एक **data-only privilege escalation** में बदल जाता है: यदि corrupted credential pointer किसी अलग valid credential object पर resolve होता है, तो current thread बिना किसी स्पष्ट control-flow hijack में पहले सफल हुए अधिक privileged state inherit कर सकता है।

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
उपयोगी audit heuristic: जब भी कोई kernel path **SMR readers**, **read-only zone mutation**, और **credential या task metadata** को मिलाता है, तो सत्यापित करें कि updates copy-based helpers के बजाय atomic `zalloc_ro_mut_*` variants का उपयोग करते हैं।

---

## 2024-2025: SIP bypass जो kernel loading paths को फिर से खोलता है (CVE-2024-44243)

Microsoft ने दिखाया कि `storagekitd` का दुरुपयोग करके **SIP bypass** किया जा सकता है और फिर third-party kernel code को उन machines पर दोबारा relevant बनाया जा सकता है जो अन्यथा "post-kext" दिखाई देतीं। मुख्य विचार यह है:<sup>[[2]](#references)</sup>

1. `/Library/Filesystems` के अंतर्गत एक malicious `.fs` bundle को drop या overwrite करें।
2. Disk Utility या `diskutil` के माध्यम से `storagekitd` को trigger करें।
3. विशेष रूप से entitled daemon को **privileges को properly drop किए बिना / path को validate किए बिना** bundle executables spawn करने दें।
4. परिणामी SIP bypass का उपयोग protected file-system state को बदलने और, Microsoft के demonstration में, kernel extension exclusion list को override करने के लिए करें।

Kernel researchers के लिए महत्वपूर्ण lesson यह है कि **kernel attack surface को userland management daemons से फिर से introduce किया जा सकता है**, भले ही direct third-party kext loading पर कड़े restrictions हों।

उपयोगी triage:
```bash
ls -la /Library/Filesystems
find /Library/Filesystems -maxdepth 3 -type f \( -name 'mount_*' -o -name 'fsck_*' -o -name 'newfs_*' \) 2>/dev/null
log stream --style syslog --predicate 'process == "storagekitd" || process == "diskarbitrationd"'
kmutil showloaded --collection aux
```
---

## Fuzzing और research workflow

यदि आप सक्रिय रूप से इस श्रेणी के bugs खोज रहे हैं, तो हालिया public work इसी दिशा की ओर संकेत कर रहा है:

- [**KextFuzz**](https://www.usenix.org/conference/usenixsecurity23/presentation/yin) अभी भी Apple-Silicon-era kernel research के लिए सबसे अच्छे references में से एक है। यह coverage recover करने के लिए **static binary rewriting** का उपयोग करता है, testing के दौरान **entitlement-gated** paths को disable करता है, और userspace wrappers से interface structure का अनुमान लगाता है।<sup>[[4]](#references)</sup>
- Project Zero का [**Simple macOS kernel extension fuzzing in userspace with IDA and TinyInst**](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html) **kext / fileset को userspace में rebase करने** का एक बहुत practical workflow दिखाता है, ताकि parser-heavy code को device पर reproduce करने से पहले काफी अधिक speed पर fuzz किया जा सके।<sup>[[5]](#references)</sup>
- Mach-heavy targets के लिए harnesses को केवल single selector blobs के बजाय **real message layouts और multi-call state machines** के आसपास build करें। Project Zero की हालिया CoreAudio/Mach research और **Fuzzing at Mach Speed** जैसी conference talks दिखाती हैं कि stateful message sequences लगातार बेहतर परिणाम क्यों देती हैं।

Quick local commands, जिन्हें आप वास्तव में अक्सर इस्तेमाल करेंगे:
```bash
# Loaded auxiliary / 3rd party kernel code
kmutil showloaded --collection aux

# Fileset entries in the boot kernel collection
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Diffable version info before matching a KDK / symbols pack
sw_vers
uname -a
```
## त्वरित Enumeration Cheatsheet
```bash
uname -a                          # Kernel build
sw_vers                           # ProductVersion / BuildVersion
kmutil showloaded                 # List loaded kernel extensions
kmutil showloaded --collection aux  # Auxiliary / 3rd party collections
kextstat 2>/dev/null | grep -v com.apple
csrutil status                    # Check SIP state
spctl --status                    # Confirm Gatekeeper state
```
## संदर्भ

- [1] [Joseph Ravichandran - TRAVERTINE: CVE-2025-24118](https://jprx.io/cve-2025-24118/)
- [2] [Microsoft Security Blog - CVE-2024-44243 का विश्लेषण: kernel extensions के माध्यम से macOS System Integrity Protection bypass](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [3] [Mickey Jin - Apple's OTA Update का Nightmare: Signature Verification को Bypassing और Kernel को Pwning](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [4] [Tingting Yin et al. - KextFuzz: Mitigations का Exploiting करके Apple Silicon पर macOS Kernel EXTensions की Fuzzing (USENIX Security '23)](https://www.usenix.org/conference/usenixsecurity23/presentation/yin)
- [5] [Ivan Fratric (Project Zero) - IDA और TinyInst के साथ userspace में Simple macOS kernel extension fuzzing](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html)
- [6] [macOS Sonoma 14.4 के security content के बारे में - Apple Support](https://support.apple.com/en-us/120895)

{{#include ../../../banners/hacktricks-training.md}}
