# Ranjivosti macOS kernela

{{#include ../../../banners/hacktricks-training.md}}

Savremena eksploatacija macOS kernela se manje zasniva na tome da se „učita trivijalan unsigned kext i dobije ring-0“, a više na zloupotrebi **Mach/MIG parsera**, **IOKit user client-a**, **data-only race-ova unutar XNU-a** i **posebno privilegovanih daemona** koji i dalje mogu ponovo da otvore attack surface kernela. Za reversing konkretnih interfejsa pogledajte i stranice o [**IOKit-u**](macos-iokit.md) i [**kernel extensions / kernelcache extraction**](macos-kernel-extensions.md).

## Attack surface-i koji su i dalje važni

- **Mach/MIG handleri** u sistemskim daemonima i servisima koji komuniciraju sa kernelom: neispravni descriptor-i, out-of-line (OOL) podaci i stateful tokovi sa više poruka.
- **IOKit user client-i**: parsing specifičan za selector, metode ograničene entitlement-ima i wrapper biblioteke/daemoni koji skrivaju stvarni call graph.
- **XNU data-only primitive**: race-ovi oko credential-a, SMR-zaštićeni pointeri, read-only zone i druga mesta gde korupcija menja policy bez prethodnog preuzimanja kontrole nad RIP/PC-jem.
- **Third-party / pomoćni kernel kod**: legacy kext-ovi su ređi, ali enterprise flote, Apple Silicon sistemi sa smanjenom bezbednošću i vendor `.fs` / helper bundle-ovi i dalje stvaraju high-value putanje bliske kernelu.

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

U [**ovom izveštaju**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) nekoliko bugova u OTA/update-chain-u je kombinovano kako bi se došlo do kompromitovanja kernela zloupotrebom software update pipeline-a i rootless-povezanih mogućnosti.<sup>[[3]](#references)</sup>

[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722).

---

## 2024: In-the-wild chain za zaobilaženje kernel zaštite (CVE-2024-23225 & CVE-2024-23296)

Apple-ova [**macOS security izdanja iz marta 2024.**](https://support.apple.com/en-us/120895) ispravila su dva problema koja su bila **actively exploited**:<sup>[[6]](#references)</sup>

- **CVE-2024-23225 – Kernel**: bug sa korupcijom memorije gde je attacker sa proizvoljnim kernel read/write pristupom mogao da zaobiđe zaštite kernel memorije.
- **CVE-2024-23296 – RTKit**: drugi bug sa korupcijom memorije i istom javno navedenom posledicom.

Javno dostupni detalji o root cause-u su i dalje oskudni, ali ovaj par je dobar podsetnik da moderni Apple exploit chain-ovi često zahtevaju **više od „samo“ kernel R/W-a**: post-exploitation rad protiv zaštita memorije, koda bliskog coprocessor-u ili sekundarnih trust boundary-ja često je mesto gde se stvarni chain stabilizuje.

Brzi triage zakrpa:
```bash
sw_vers
uname -v
softwareupdate --history | tail -n 20
```
---

## 2025: SMR + read-only credential race (CVE-2025-24118)

[**TRAVERTINE write-up**](https://jprx.io/cve-2025-24118/) autora Josepha Ravichandran-a predstavlja veoma dobar savremeni XNU case study, jer ovo **nije** klasičan buffer overflow:<sup>[[1]](#references)</sup>

- `proc_ro.p_ucred` je **SMR-protected pointer** uskladišten u **read-only** `proc_ro` objektu.
- Writers moraju da ažuriraju taj pointer **atomically**.
- `kauth_cred_proc_update()` je koristio `zalloc_ro_mut(...)` za izmenu `p_ucred`; na x86_64 taj put na kraju dolazi do `memcpy` / `rep movsb`, pa concurrent reader može da vidi **torn pointer**.
- Bug se pretvara u **data-only privilege escalation**: ako se corrupted credential pointer razreši u drugi validan credential objekat, trenutni thread može da nasledi privilegovanije stanje, a da prethodno ne mora da ostvari očigledan control-flow hijack.

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
Korisna heuristika za audit: kad god kernel putanja kombinuje **SMR readers**, **read-only zone mutation** i **credential ili task metadata**, proverite da li ažuriranja koriste atomske `zalloc_ro_mut_*` varijante, a ne helpers zasnovane na kopiranju.

---

## 2024-2025: SIP bypass koji ponovo otvara kernel loading putanje (CVE-2024-44243)

Microsoft je pokazao da se `storagekitd` može zloupotrebiti za **bypass SIP-a**, a zatim ponovo učiniti relevantnim third-party kernel code na mašinama koje bi inače izgledale kao "post-kext". Ključna ideja je:<sup>[[2]](#references)</sup>

1. Odbaciti ili prepisati maliciozni `.fs` bundle u `/Library/Filesystems`.
2. Pokrenuti `storagekitd` preko Disk Utility-ja ili `diskutil`-a.
3. Omogućiti posebno privileged daemon-u da pokrene bundle executables **bez pravilnog uklanjanja privilegija / validacije putanje**.
4. Iskoristiti dobijeni SIP bypass za izmenu zaštićenog file-system state-a i, u Microsoft-ovoj demonstraciji, prepisati kernel extension exclusion list.

Za kernel istraživače, važna pouka je da se **kernel attack surface može ponovo uvesti iz userland management daemon-a**, čak i kada je direktno učitavanje third-party kext-ova strogo ograničeno.

Korisna trijaža:
```bash
ls -la /Library/Filesystems
find /Library/Filesystems -maxdepth 3 -type f \( -name 'mount_*' -o -name 'fsck_*' -o -name 'newfs_*' \) 2>/dev/null
log stream --style syslog --predicate 'process == "storagekitd" || process == "diskarbitrationd"'
kmutil showloaded --collection aux
```
---

## Workflow za fuzzing i istraživanje

Ako aktivno tražite ovu klasu bugova, nedavni javno dostupni radovi ukazuju u istom smeru:

- [**KextFuzz**](https://www.usenix.org/conference/usenixsecurity23/presentation/yin) je i dalje jedna od najboljih referenci za kernel istraživanje u Apple-Silicon eri. Koristi **static binary rewriting** za obnavljanje coverage-a, onemogućava **entitlement-gated** putanje tokom testiranja i zaključuje strukturu interfejsa na osnovu userspace wrappera.<sup>[[4]](#references)</sup>
- Project Zero-ov [**Simple macOS kernel extension fuzzing in userspace with IDA and TinyInst**](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html) prikazuje veoma praktičan workflow za **rebasing kext / fileset-a u userspace**, kako bi parser-heavy code mogao da se fuzz-uje mnogo većom brzinom pre reprodukcije na uređaju.<sup>[[5]](#references)</sup>
- Za Mach-heavy mete pravite harness-e oko **real message layouts i multi-call state machines**, a ne samo oko pojedinačnih selector blobova. Nedavna CoreAudio/Mach istraživanja kompanije Project Zero i konferencijska predavanja kao što je **Fuzzing at Mach Speed** pokazuju zašto stateful message sequences i dalje daju dobre rezultate.

Brze lokalne komande koje ćete zaista često koristiti:
```bash
# Loaded auxiliary / 3rd party kernel code
kmutil showloaded --collection aux

# Fileset entries in the boot kernel collection
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Diffable version info before matching a KDK / symbols pack
sw_vers
uname -a
```
## Brzi podsetnik za enumeraciju
```bash
uname -a                          # Kernel build
sw_vers                           # ProductVersion / BuildVersion
kmutil showloaded                 # List loaded kernel extensions
kmutil showloaded --collection aux  # Auxiliary / 3rd party collections
kextstat 2>/dev/null | grep -v com.apple
csrutil status                    # Check SIP state
spctl --status                    # Confirm Gatekeeper state
```
## Reference

- [1] [Joseph Ravichandran - TRAVERTINE: CVE-2025-24118](https://jprx.io/cve-2025-24118/)
- [2] [Microsoft Security Blog - Analiza CVE-2024-44243, zaobilaženja macOS System Integrity Protection kroz kernel extensions](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [3] [Mickey Jin - Noćna mora Apple OTA Update-a: Zaobilaženje verifikacije potpisa i preuzimanje kontrole nad kernelom](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [4] [Tingting Yin et al. - KextFuzz: Fuzzing macOS Kernel EXTensions na Apple Silicon-u iskorišćavanjem mitigacija (USENIX Security '23)](https://www.usenix.org/conference/usenixsecurity23/presentation/yin)
- [5] [Ivan Fratric (Project Zero) - Jednostavan fuzzing macOS kernel extension-a u userspace-u pomoću IDA-e i TinyInst-a](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html)
- [6] [O bezbednosnom sadržaju macOS Sonoma 14.4 - Apple Support](https://support.apple.com/en-us/120895)

{{#include ../../../banners/hacktricks-training.md}}
