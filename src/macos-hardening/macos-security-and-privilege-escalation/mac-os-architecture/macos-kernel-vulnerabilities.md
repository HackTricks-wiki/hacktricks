# Udhaifu wa Kernel ya macOS

{{#include ../../../banners/hacktricks-training.md}}

Udukuzi wa kernel ya macOS wa hivi karibuni hauhusu tena sana "kupakia kext isiyosainiwa iliyo rahisi na kupata ring-0", bali unahusu kutumia vibaya **Mach/MIG parsers**, **IOKit user clients**, **data-only races ndani ya XNU**, na **daemons zilizopewa entitlements maalum** ambazo bado zinaweza kufungua tena attack surface ya kernel. Kwa ajili ya kureverse interfaces halisi, pia angalia kurasa kuhusu [**IOKit**](macos-iokit.md) na [**kernel extensions / kernelcache extraction**](macos-kernel-extensions.md).

## Attack surfaces ambazo bado ni muhimu

- **Mach/MIG handlers** katika system daemons na services zinazowasiliana na kernel: descriptors zilizoundwa vibaya, data ya out-of-line (OOL), na mtiririko wa stateful wenye ujumbe mwingi.
- **IOKit user clients**: uchanganuzi unaotegemea selector, methods zinazohitaji entitlement, na wrapper libraries/daemons zinazoficha call graph halisi.
- **XNU data-only primitives**: races zinazohusu credentials, pointers zinazolindwa na SMR, read-only zones, na maeneo mengine ambapo corruption hubadilisha policy bila kwanza kupata udhibiti wa RIP/PC.
- **Third-party / auxiliary kernel code**: kexts za zamani ni chache zaidi, lakini enterprise fleets, mifumo ya Apple Silicon yenye reduced security, na vendor `.fs` / helper bundles bado huunda njia zenye thamani kubwa zilizo karibu na kernel.

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

Katika [**ripoti hii**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) bugs kadhaa za OTA/update-chain zinaunganishwa ili kufikia compromise ya kernel kwa kutumia vibaya software update pipeline na capabilities zinazohusiana na rootless.<sup>[[3]](#references)</sup>

[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722).

---

## 2024: Mnyororo wa bypass ya ulinzi wa kernel uliotumika in-the-wild (CVE-2024-23225 & CVE-2024-23296)

[**MacOS security releases za Machi 2024**](https://support.apple.com/en-us/120895) za Apple zilirekebisha issues mbili ambazo **zilitumiwa kikamilifu**:

- **CVE-2024-23225 – Kernel**: bug ya memory-corruption ambapo attacker mwenye arbitrary kernel read/write angeweza kupita ulinzi wa memory ya kernel.
- **CVE-2024-23296 – RTKit**: bug ya pili ya memory-corruption yenye public impact statement sawa.

Maelezo ya public root cause bado ni machache, lakini jozi hii ni ukumbusho mzuri kwamba exploit chains za kisasa za Apple mara nyingi huhitaji **zaidi ya "kernel R/W tu"**: kazi za post-exploitation dhidi ya ulinzi wa memory, code iliyo karibu na coprocessor, au trust boundaries za ziada mara nyingi ndizo huimarisha chain halisi.

Triage ya haraka ya patch:
```bash
sw_vers
uname -v
softwareupdate --history | tail -n 20
```
---

## 2025: SMR + read-only credential race (CVE-2025-24118)

[**TRAVERTINE write-up**](https://jprx.io/cve-2025-24118/) ya Joseph Ravichandran ni case study nzuri sana ya kisasa ya XNU kwa sababu hii si **classic buffer overflow**:<sup>[[1]](#references)</sup>

- `proc_ro.p_ucred` ni **SMR-protected pointer** iliyohifadhiwa katika object ya `proc_ro` iliyo **read-only**.
- Waandishi lazima wasasishe pointer hiyo **atomically**.
- `kauth_cred_proc_update()` ilitumia `zalloc_ro_mut(...)` kubadilisha `p_ucred`; kwenye x86_64, njia hiyo hatimaye hufikia `memcpy` / `rep movsb`, hivyo reader anayeendesha kwa wakati mmoja anaweza kuona **torn pointer**.
- Bug hii hubadilika kuwa **data-only privilege escalation**: ikiwa credential pointer iliyoharibika itaelekeza kwenye credential object nyingine halali, thread ya sasa inaweza kurithi state yenye privileges zaidi bila kwanza kufanikiwa kufanya control-flow hijack iliyo wazi.

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
Heuristic muhimu ya ukaguzi: kila mara njia ya kernel inapochanganya **SMR readers**, **read-only zone mutation**, na **credential au task metadata**, thibitisha kwamba masasisho yanatumia variants za atomic `zalloc_ro_mut_*` badala ya helpers za copy-based.

---

## 2024-2025: SIP bypass inayofungua tena njia za kernel loading (CVE-2024-44243)

Microsoft ilionyesha kwamba `storagekitd` inaweza kutumiwa **bypass SIP** na kisha kufanya third-party kernel code iwe muhimu tena kwenye mashine ambazo vinginevyo zingeonekana kuwa "post-kext". Wazo kuu ni:<sup>[[2]](#references)</sup>

1. Weka au overwrite bundle hasidi ya `.fs` chini ya `/Library/Filesystems`.
2. Trigger `storagekitd` kupitia Disk Utility au `diskutil`.
3. Ruhusu daemon yenye entitlement maalum i-spawn bundle executables **bila kuondoa privileges ipasavyo / kuthibitisha path**.
4. Tumia SIP bypass iliyopatikana kubadilisha protected file-system state na, katika demonstration ya Microsoft, override kernel extension exclusion list.

Kwa watafiti wa kernel, somo muhimu ni kwamba **kernel attack surface inaweza kuletwa tena kutoka kwa userland management daemons**, hata wakati direct third-party kext loading imewekewa restrictions kali.

Triage muhimu:
```bash
ls -la /Library/Filesystems
find /Library/Filesystems -maxdepth 3 -type f \( -name 'mount_*' -o -name 'fsck_*' -o -name 'newfs_*' \) 2>/dev/null
log stream --style syslog --predicate 'process == "storagekitd" || process == "diskarbitrationd"'
kmutil showloaded --collection aux
```
---

## Fuzzing na mtiririko wa kazi wa utafiti

Ikiwa unatafuta kwa vitendo aina hii ya bugs, kazi ya hivi karibuni ya umma inaelekea upande huo huo:

- [**KextFuzz**](https://www.usenix.org/conference/usenixsecurity23/presentation/yin) bado ni mojawapo ya marejeleo bora kwa utafiti wa kernel wa enzi ya Apple Silicon. Inatumia **static binary rewriting** kurejesha coverage, inazima njia za **entitlement-gated** wakati wa testing, na inakisia muundo wa interface kutoka kwa userspace wrappers.<sup>[[4]](#references)</sup>
- [**Simple macOS kernel extension fuzzing in userspace with IDA and TinyInst**](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html) ya Project Zero inaonyesha workflow ya vitendo sana ya **kurebase kext / fileset katika userspace**, ili code yenye parser nyingi iweze kufanyiwa fuzzing kwa kasi kubwa zaidi kabla ya kuirudia kwenye kifaa.<sup>[[5]](#references)</sup>
- Kwa targets zenye Mach nyingi, tengeneza harnesses zinazozingatia **real message layouts na multi-call state machines**, badala ya single selector blobs pekee. Utafiti wa hivi karibuni wa CoreAudio/Mach kutoka Project Zero na mawasilisho ya conference kama **Fuzzing at Mach Speed** unaonyesha kwa nini stateful message sequences zinaendelea kuwa na matokeo mazuri.

Commands za haraka za local utakazotumia mara nyingi sana:
```bash
# Loaded auxiliary / 3rd party kernel code
kmutil showloaded --collection aux

# Fileset entries in the boot kernel collection
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Diffable version info before matching a KDK / symbols pack
sw_vers
uname -a
```
## Muhtasari wa Haraka wa Enumeration
```bash
uname -a                          # Kernel build
sw_vers                           # ProductVersion / BuildVersion
kmutil showloaded                 # List loaded kernel extensions
kmutil showloaded --collection aux  # Auxiliary / 3rd party collections
kextstat 2>/dev/null | grep -v com.apple
csrutil status                    # Check SIP state
spctl --status                    # Confirm Gatekeeper state
```
## Marejeo

- [1] [Joseph Ravichandran - TRAVERTINE: CVE-2025-24118](https://jprx.io/cve-2025-24118/)
- [2] [Microsoft Security Blog - Uchambuzi wa CVE-2024-44243, bypass ya macOS System Integrity Protection kupitia kernel extensions](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [3] [Mickey Jin - Jinamizi la Apple OTA Update: Kupita Signature Verification na Ku-pwn Kernel](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [4] [Tingting Yin et al. - KextFuzz: Kufanya Fuzzing ya macOS Kernel EXTensions kwenye Apple Silicon kwa kutumia Exploiting Mitigations (USENIX Security '23)](https://www.usenix.org/conference/usenixsecurity23/presentation/yin)
- [5] [Ivan Fratric (Project Zero) - Kufanya fuzzing rahisi ya macOS kernel extension katika userspace kwa kutumia IDA na TinyInst](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html)

{{#include ../../../banners/hacktricks-training.md}}
