# Vulnerabilities za Kernel ya macOS

{{#include ../../../banners/hacktricks-training.md}}

Udukuzi wa kernel ya macOS wa hivi karibuni hauhusu tena sana "kupakia kext isiyotiwa saini isiyo na ugumu na kupata ring-0", bali unahusu kutumia vibaya **Mach/MIG parsers**, **IOKit user clients**, **data-only races ndani ya XNU**, na **daemons zenye entitlements maalum** ambazo bado zinaweza kufungua tena attack surface ya kernel. Kwa kureverse interfaces halisi, pia angalia kurasa kuhusu [**IOKit**](macos-iokit.md) na [**kernel extensions / kernelcache extraction**](macos-kernel-extensions.md).

## Attack surfaces ambazo bado ni muhimu

- **Mach/MIG handlers** katika system daemons na services zinazoelekea kwenye kernel: descriptors zilizoharibika, data ya out-of-line (OOL), na mtiririko wa stateful wa messages nyingi.
- **IOKit user clients**: uchanganuzi maalum kwa kila selector, methods zinazohitaji entitlement, na wrapper libraries/daemons zinazoficha call graph halisi.
- **XNU data-only primitives**: races zinazohusu credentials, pointers zinazolindwa na SMR, read-only zones, na maeneo mengine ambapo corruption hubadilisha policy bila kwanza kupata udhibiti wa RIP/PC.
- **Third-party / auxiliary kernel code**: kexts za zamani si nyingi tena, lakini enterprise fleets, mifumo ya Apple Silicon yenye reduced security, na vendor `.fs` / helper bundles bado huunda paths zenye thamani kubwa zinazoelekea au zinazohusiana na kernel.

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

Katika [**this report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) bugs kadhaa za OTA/update-chain zimeunganishwa ili kufikia kernel compromise kwa kutumia vibaya software update pipeline na capabilities zinazohusiana na rootless.

[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722).

---

## 2024: In-the-wild kernel protection bypass chain (CVE-2024-23225 & CVE-2024-23296)

[**March 2024 macOS security releases**](https://support.apple.com/en-us/120895) za Apple zilirekebisha issues mbili ambazo **zilikuwa zikitumiwa kikamilifu**:

- **CVE-2024-23225 – Kernel**: bug ya memory-corruption ambapo attacker mwenye arbitrary kernel read/write angeweza kupita kernel memory protections.
- **CVE-2024-23296 – RTKit**: bug ya pili ya memory-corruption yenye public impact statement ileile.

Maelezo ya public root-cause bado ni machache, lakini jozi hii ni ukumbusho mzuri kwamba exploit chains za kisasa za Apple mara nyingi huhitaji **zaidi ya "kernel R/W tu"**: kazi ya post-exploitation dhidi ya memory protections, code iliyo karibu na coprocessor, au secondary trust boundaries mara nyingi ndiyo sehemu ambako chain halisi huimarishwa.

Quick patch triage:
```bash
sw_vers
uname -v
softwareupdate --history | tail -n 20
```
---

## 2025: SMR + read-only credential race (CVE-2025-24118)

[**TRAVERTINE write-up**](https://jprx.io/cve-2025-24118/) ya Joseph Ravichandran ni case study nzuri sana ya kisasa ya XNU kwa sababu hii **si classic buffer overflow**:

- `proc_ro.p_ucred` ni **SMR-protected pointer** iliyohifadhiwa katika object ya `proc_ro` iliyo **read-only**.
- Writers lazima wasasishe pointer hiyo **atomically**.
- `kauth_cred_proc_update()` ilitumia `zalloc_ro_mut(...)` kubadilisha `p_ucred`; kwenye x86_64, njia hiyo hatimaye hufikia `memcpy` / `rep movsb`, hivyo reader anayeendesha kwa wakati mmoja anaweza kuona **torn pointer**.
- Bug hii hubadilika kuwa **data-only privilege escalation**: ikiwa corrupted credential pointer itaelekeza kwenye credential object nyingine halali, thread ya sasa inaweza kurithi state yenye privilege zaidi bila kwanza kufanikiwa na **control-flow hijack** iliyo wazi.

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
Heuristic muhimu ya ukaguzi: kila wakati njia ya kernel inapochanganya **SMR readers**, **read-only zone mutation**, na **credential or task metadata**, thibitisha kuwa masasisho yanatumia variants za atomiki za `zalloc_ro_mut_*` badala ya helpers zinazotegemea kunakili.

---

## 2024-2025: SIP bypass inayofungua tena njia za upakiaji wa kernel (CVE-2024-44243)

Microsoft ilionyesha kuwa `storagekitd` inaweza kutumiwa vibaya ili **bypass SIP** na kisha kufanya third-party kernel code iwe muhimu tena kwenye mashine ambazo vinginevyo zingeonekana kuwa za "post-kext". Wazo kuu ni:

1. Weka au overwrite bundle hasidi ya `.fs` chini ya `/Library/Filesystems`.
2. Trigger `storagekitd` kupitia Disk Utility au `diskutil`.
3. Ruhusu daemon yenye entitlements maalum ku-spawn bundle executables **bila kuondoa privileges ipasavyo / kuthibitisha path**.
4. Tumia SIP bypass inayotokana na hilo kubadilisha hali ya file system iliyolindwa na, katika demonstration ya Microsoft, override kernel extension exclusion list.

Kwa watafiti wa kernel, somo muhimu ni kwamba **kernel attack surface inaweza kuletwa tena kutoka kwa userland management daemons**, hata wakati direct third-party kext loading imezuiwa kwa kiwango kikubwa.

Uchambuzi wa awali unaofaa:
```bash
ls -la /Library/Filesystems
find /Library/Filesystems -maxdepth 3 -type f \( -name 'mount_*' -o -name 'fsck_*' -o -name 'newfs_*' \) 2>/dev/null
log stream --style syslog --predicate 'process == "storagekitd" || process == "diskarbitrationd"'
kmutil showloaded --collection aux
```
---

## Fuzzing & mtiririko wa utafiti

Ikiwa unatafuta kikamilifu aina hii ya bugs, kazi ya hivi karibuni ya umma inaelekea katika mwelekeo huohuo:

- [**KextFuzz**](https://www.usenix.org/conference/usenixsecurity23/presentation/yin) bado ni mojawapo ya marejeleo bora kwa utafiti wa kernel wa enzi ya Apple Silicon. Inatumia **static binary rewriting** kurejesha coverage, huzima njia za **entitlement-gated** wakati wa testing, na kubashiri muundo wa interface kutoka kwa userspace wrappers.
- [**Simple macOS kernel extension fuzzing in userspace with IDA and TinyInst**](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html) ya Project Zero inaonyesha workflow ya vitendo sana ya **rebasing kext / fileset into userspace**, ili code inayohusika zaidi na parser iweze kufanyiwa fuzzing kwa kasi kubwa zaidi kabla ya kuirudia kwenye kifaa.
- Kwa targets zinazotumia Mach kwa kiasi kikubwa, tengeneza harnesses zinazozingatia **real message layouts and multi-call state machines**, badala ya selector blobs za single pekee. Utafiti wa hivi karibuni wa CoreAudio/Mach kutoka Project Zero na talks za conference kama vile **Fuzzing at Mach Speed** unaonyesha kwa nini stateful message sequences zinaendelea kutoa matokeo.

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
## Mwongozo mfupi wa Enumeration
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

* Joseph Ravichandran. “TRAVERTINE: CVE-2025-24118.” https://jprx.io/cve-2025-24118/
* Microsoft Security Blog. “Uchambuzi wa CVE-2024-44243, bypass ya macOS System Integrity Protection kupitia kernel extensions.” https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/
{{#include ../../../banners/hacktricks-training.md}}
