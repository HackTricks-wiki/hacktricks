# Vulnerabilities za Kernel ya macOS

{{#include ../../../banners/hacktricks-training.md}}

Exploitation ya kernel ya macOS ya hivi karibuni inahusu kwa kiwango kidogo "kupakia kext isiyosainiwa ya kawaida na kupata ring-0", na zaidi kutumia vibaya **Mach/MIG parsers**, **IOKit user clients**, **data-only races ndani ya XNU**, pamoja na **daemons zenye entitlements maalum** ambazo bado zinaweza kufungua tena attack surface ya kernel. Kwa kureverse interfaces halisi, pia angalia kurasa kuhusu [**IOKit**](macos-iokit.md) na [**kernel extensions / kernelcache extraction**](macos-kernel-extensions.md).

## Attack surfaces ambazo bado ni muhimu

- **Mach/MIG handlers** katika system daemons na services zinazoelekea kernel: descriptors zilizoharibika, data ya out-of-line (OOL), na flows za stateful zenye messages nyingi.
- **IOKit user clients**: parsing maalum kwa kila selector, methods zinazohitaji entitlement, na wrapper libraries/daemons zinazoficha call graph halisi.
- **XNU data-only primitives**: races zinazohusu credentials, pointers zinazolindwa na SMR, read-only zones, na maeneo mengine ambapo corruption hubadilisha policy bila kwanza kudhibiti RIP/PC.
- **Third-party / auxiliary kernel code**: kexts za legacy ni chache zaidi, lakini enterprise fleets, mifumo ya Apple Silicon yenye reduced-security, na vendor `.fs` / helper bundles bado huunda paths zenye thamani kubwa zilizo karibu na kernel.

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

Katika [**ripoti hii**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) bugs kadhaa za OTA/update-chain zimeunganishwa ili kufikia kernel compromise kwa kutumia vibaya software update pipeline na capabilities zinazohusiana na rootless.<sup>[[3]](#references)</sup>

[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722).

---

## 2024: Chain ya kernel protection bypass iliyotumiwa in-the-wild (CVE-2024-23225 & CVE-2024-23296)

[**MacOS security releases za Machi 2024**](https://support.apple.com/en-us/120895) za Apple zilirekebisha issues mbili ambazo **zilikuwa zikitumiwa kikamilifu**:<sup>[[6]](#references)</sup>

- **CVE-2024-23225 – Kernel**: bug ya memory-corruption ambapo attacker mwenye arbitrary kernel read/write angeweza kupita kernel memory protections.
- **CVE-2024-23296 – RTKit**: bug ya pili ya memory-corruption yenye public impact statement ileile.

Maelezo ya public root-cause bado ni machache, lakini jozi hii ni ukumbusho mzuri kwamba exploit chains za kisasa za Apple mara nyingi huhitaji **zaidi ya "kernel R/W tu"**: kazi ya post-exploitation dhidi ya memory protections, code iliyo karibu na coprocessor, au secondary trust boundaries mara nyingi ndiyo sehemu ambako chain halisi huimarishwa.

Tathmini ya haraka ya patch:
```bash
sw_vers
uname -v
softwareupdate --history | tail -n 20
```
---

## 2025: SMR + read-only credential race (CVE-2025-24118)

[**TRAVERTINE write-up**](https://jprx.io/cve-2025-24118/) ya Joseph Ravichandran ni case study nzuri sana ya kisasa ya XNU kwa sababu hii **si buffer overflow** ya kawaida:<sup>[[1]](#references)</sup>

- `proc_ro.p_ucred` ni **SMR-protected pointer** iliyohifadhiwa katika object ya `proc_ro` iliyo **read-only**.
- Waandishi lazima wasasishe pointer hiyo **atomically**.
- `kauth_cred_proc_update()` ilitumia `zalloc_ro_mut(...)` kubadilisha `p_ucred`; kwenye x86_64, path hiyo hatimaye hufikia `memcpy` / `rep movsb`, hivyo reader anayefanya kazi kwa wakati mmoja anaweza kuona **torn pointer**.
- Bug hii hubadilika kuwa **data-only privilege escalation**: ikiwa credential pointer iliyoharibika itaelekeza kwenye credential object nyingine halali, thread ya sasa inaweza kurithi state yenye privileges zaidi bila kwanza kushinda control-flow hijack iliyo wazi.

Muundo mdogo wa trigger:
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
Heuristic muhimu ya ukaguzi: kila mara kernel path inapochanganya **SMR readers**, **read-only zone mutation**, na **credential au task metadata**, thibitisha kwamba masasisho yanatumia variants za atomic `zalloc_ro_mut_*` badala ya helpers zinazotegemea copy.

---

## 2024-2025: SIP bypass inayofungua tena kernel loading paths (CVE-2024-44243)

Microsoft ilionyesha kwamba `storagekitd` inaweza kutumiwa **kupita SIP** na hivyo kufanya third-party kernel code iwe muhimu tena kwenye mashine ambazo vinginevyo zingeonekana kuwa "post-kext". Wazo kuu ni:<sup>[[2]](#references)</sup>

1. Weka au overwrite bundle hasidi ya `.fs` chini ya `/Library/Filesystems`.
2. Trigger `storagekitd` kupitia Disk Utility au `diskutil`.
3. Ruhusu daemon yenye entitlement maalum i-spawn bundle executables **bila ku-drop privileges ipasavyo / ku-validate path**.
4. Tumia SIP bypass iliyopatikana kubadilisha protected file-system state na, katika demonstration ya Microsoft, override kernel extension exclusion list.

Kwa kernel researchers, somo muhimu ni kwamba **kernel attack surface inaweza kuletwa tena kutoka userland management daemons**, hata wakati direct third-party kext loading imezuiwa kwa kiwango kikubwa.

Triage muhimu:
```bash
ls -la /Library/Filesystems
find /Library/Filesystems -maxdepth 3 -type f \( -name 'mount_*' -o -name 'fsck_*' -o -name 'newfs_*' \) 2>/dev/null
log stream --style syslog --predicate 'process == "storagekitd" || process == "diskarbitrationd"'
kmutil showloaded --collection aux
```
---

## Fuzzing na workflow ya utafiti

Ikiwa unatafuta kwa bidii aina hii ya bugs, kazi za hivi karibuni za umma zinaelekea upande huohuo:

- [**KextFuzz**](https://www.usenix.org/conference/usenixsecurity23/presentation/yin) bado ni mojawapo ya marejeo bora kwa utafiti wa kernel wa enzi ya Apple Silicon. Hutumia **static binary rewriting** kurejesha coverage, huzima njia zinazohitaji **entitlement** wakati wa testing, na hukadiria muundo wa interface kutoka kwa userspace wrappers.<sup>[[4]](#references)</sup>
- [**Simple macOS kernel extension fuzzing in userspace with IDA and TinyInst**](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html) ya Project Zero inaonyesha workflow ya vitendo sana ya **ku-rebase kext / fileset katika userspace** ili code yenye parser nyingi iweze kufanyiwa fuzzing kwa kasi kubwa zaidi kabla ya kuzalisha tena tatizo kwenye kifaa.<sup>[[5]](#references)</sup>
- Kwa targets zinazotumia Mach kwa kiwango kikubwa, tengeneza harnesses zinazozunguka **real message layouts na multi-call state machines**, badala ya selector blobs za simu moja tu. Utafiti wa hivi karibuni wa CoreAudio/Mach kutoka Project Zero na mawasilisho ya conference kama **Fuzzing at Mach Speed** unaonyesha kwa nini sequences za messages zenye state zinaendelea kuwa na manufaa.

Commands za haraka za local ambazo utazitumia mara nyingi:
```bash
# Loaded auxiliary / 3rd party kernel code
kmutil showloaded --collection aux

# Fileset entries in the boot kernel collection
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Diffable version info before matching a KDK / symbols pack
sw_vers
uname -a
```
## Karatasi ya Kumbukumbu ya Haraka ya Enumeration
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
- [2] [Microsoft Security Blog - Kuchanganua CVE-2024-44243, bypass ya macOS System Integrity Protection kupitia kernel extensions](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [3] [Mickey Jin - Jinamizi la Apple's OTA Update: Kupita Signature Verification na Ku-pwn Kernel](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [4] [Tingting Yin et al. - KextFuzz: Kufanya fuzzing ya macOS Kernel EXTensions kwenye Apple Silicon kupitia Exploiting Mitigations (USENIX Security '23)](https://www.usenix.org/conference/usenixsecurity23/presentation/yin)
- [5] [Ivan Fratric (Project Zero) - Kufanya simple macOS kernel extension fuzzing katika userspace kwa IDA na TinyInst](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html)
- [6] [Kuhusu maudhui ya usalama ya macOS Sonoma 14.4 - Apple Support](https://support.apple.com/en-us/120895)

{{#include ../../../banners/hacktricks-training.md}}
