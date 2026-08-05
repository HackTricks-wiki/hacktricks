# macOS Kernel ranjivosti

{{#include ../../../banners/hacktricks-training.md}}

Nedavna eksploatacija macOS kernela manje se svodi na „učitavanje trivijalnog unsigned kext-a i dobijanje ring-0“ a više na zloupotrebu **Mach/MIG parsera**, **IOKit user client-a**, **data-only race** uslova unutar XNU-a i **posebno privilegovanih daemon-a** koji i dalje mogu ponovo otvoriti attack surface kernela. Za reverzno analiziranje konkretnih interfejsa pogledajte i stranice o [**IOKit**](macos-iokit.md) i [**kernel extensions / kernelcache extraction**](macos-kernel-extensions.md).

## Attack surface-i koji su i dalje važni

- **Mach/MIG handler-i** u sistemskim daemon-ima i servisima koji komuniciraju sa kernelom: neispravni descriptor-i, out-of-line (OOL) podaci i stateful tokovi sa više poruka.
- **IOKit user client-i**: parsing specifičan za selector, metode ograničene entitlement-ima i wrapper biblioteke/daemon-i koji skrivaju stvarni call graph.
- **XNU data-only primitive**: race uslovi oko credential-a, pokazivači zaštićeni pomoću SMR-a, read-only zone i druga mesta gde korupcija menja policy bez prethodnog preuzimanja kontrole nad RIP/PC-jem.
- **Third-party / pomoćni kernel kod**: legacy kext-ovi su ređi, ali enterprise fleet-ovi, Apple Silicon sistemi sa smanjenom bezbednošću i vendor `.fs` / helper bundle-ovi i dalje stvaraju visokovredne putanje u blizini kernela.

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

U [**ovom izveštaju**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) nekoliko bug-ova u OTA/update chain-u je kombinovano kako bi se došlo do kompromitovanja kernela zloupotrebom pipeline-a za software update i mogućnosti povezanih sa rootless-om.<sup>[3]</sup>

[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722).

---

## 2024: Chain zaobilaženja kernel zaštite u divljini (CVE-2024-23225 & CVE-2024-23296)

Apple-ova [**macOS bezbednosna izdanja iz marta 2024.**](https://support.apple.com/en-us/120895) ispravila su dva problema koji su bili **aktivno eksploatisani**:

- **CVE-2024-23225 – Kernel**: bug sa korupcijom memorije kod kog je attacker sa proizvoljnim kernel read/write pristupom mogao da zaobiđe zaštite kernel memorije.
- **CVE-2024-23296 – RTKit**: drugi bug sa korupcijom memorije i istom javno navedenom posledicom.

Javno dostupni detalji o root cause-u i dalje su oskudni, ali ovaj par dobro podseća da moderni Apple exploit chain-ovi često zahtevaju **više od „samo“ kernel R/W-a**: post-exploitation rad protiv zaštita memorije, koda u blizini coprocessor-a ili sekundarnih trust boundary-ja često je mesto gde se stvarni chain stabilizuje.

Brza procena zakrpe:
```bash
sw_vers
uname -v
softwareupdate --history | tail -n 20
```
---

## 2025: SMR + read-only credential race (CVE-2025-24118)

[**TRAVERTINE write-up** Josepha Ravichandran-a](https://jprx.io/cve-2025-24118/) je veoma dobra moderna studija XNU slučaja, jer ovo **nije** klasičan buffer overflow:<sup>[1]</sup>

- `proc_ro.p_ucred` je **SMR-protected pointer** uskladišten u **read-only** `proc_ro` objektu.
- Writers moraju da ažuriraju taj pointer **atomically**.
- `kauth_cred_proc_update()` je koristio `zalloc_ro_mut(...)` za izmenu `p_ucred`; na x86_64 ta putanja na kraju dolazi do `memcpy` / `rep movsb`, pa konkurentni reader može da uoči **torn pointer**.
- Bug se pretvara u **data-only privilege escalation**: ako se corrupted credential pointer razreši u drugi validan credential objekat, trenutni thread može da nasledi privilegovanije stanje, a da prethodno ne mora da izvede očigledan control-flow hijack.

Minimalni trigger pattern:
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
Korisna heuristika za audit: kad god kernel putanja kombinuje **SMR readers**, **read-only zone mutation** i **credential ili task metadata**, proverite da li ažuriranja koriste atomske `zalloc_ro_mut_*` varijante umesto helpera zasnovanih na kopiranju.

---

## 2024-2025: SIP bypass koji ponovo otvara kernel loading putanje (CVE-2024-44243)

Microsoft je pokazao da se `storagekitd` može zloupotrebiti za **bypass SIP-a**, a zatim ponovo učiniti third-party kernel code relevantnim na mašinama koje bi inače izgledale kao "post-kext". Ključna ideja je:<sup>[2]</sup>

1. Ubaciti ili prepisati maliciozni `.fs` bundle u `/Library/Filesystems`.
2. Pokrenuti `storagekitd` preko Disk Utility-ja ili `diskutil`-a.
3. Dozvoliti posebno privilegovanom daemonu da pokrene bundle executables **bez pravilnog uklanjanja privilegija / validacije putanje**.
4. Iskoristiti dobijeni SIP bypass za izmenu zaštićenog file-system state-a i, u Microsoftovoj demonstraciji, prepisati kernel extension exclusion list.

Za kernel istraživače, važna lekcija je da se **kernel attack surface može ponovo uvesti preko userland management daemon-a**, čak i kada je direktno third-party kext učitavanje strogo ograničeno.

Korisna trijaža:
```bash
ls -la /Library/Filesystems
find /Library/Filesystems -maxdepth 3 -type f \( -name 'mount_*' -o -name 'fsck_*' -o -name 'newfs_*' \) 2>/dev/null
log stream --style syslog --predicate 'process == "storagekitd" || process == "diskarbitrationd"'
kmutil showloaded --collection aux
```
---

## Fuzzing i istraživački workflow

Ako aktivno tražite ovu klasu bugova, nedavni javno dostupni radovi ukazuju u istom smeru:

- [**KextFuzz**](https://www.usenix.org/conference/usenixsecurity23/presentation/yin) je i dalje jedna od najboljih referenci za kernel istraživanja u eri Apple Silicon-a. Koristi **static binary rewriting** za obnavljanje coverage-a, onemogućava **entitlement-gated** putanje tokom testiranja i zaključuje strukturu interfejsa iz userspace wrappera.<sup>[4]</sup>
- Project Zero-ov [**Simple macOS kernel extension fuzzing in userspace with IDA and TinyInst**](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html) prikazuje veoma praktičan workflow za **rebasing kext / fileset-a u userspace**, kako bi parser-heavy code mogao da se fuzzuje znatno većom brzinom pre reprodukcije na uređaju.<sup>[5]</sup>
- Za Mach-heavy ciljeve, pravite harnesses oko **realnih layouta poruka i state machines sa više poziva**, a ne samo oko pojedinačnih selector blobova. Nedavna CoreAudio/Mach istraživanja iz Project Zero-a i predavanja na konferencijama, kao što je **Fuzzing at Mach Speed**, pokazuju zašto stateful sekvence poruka nastavljaju da daju rezultate.

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
- [2] [Microsoft Security Blog - Analiza CVE-2024-44243, zaobilaženja macOS System Integrity Protection putem kernel ekstenzija](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [3] [Mickey Jin - Noćna mora Apple OTA Update-a: Zaobilaženje verifikacije potpisa i preuzimanje kontrole nad kernelom](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [4] [Tingting Yin et al. - KextFuzz: Fuzzing macOS Kernel EXTensions na Apple Silicon platformi iskorišćavanjem mitigacija (USENIX Security '23)](https://www.usenix.org/conference/usenixsecurity23/presentation/yin)
- [5] [Ivan Fratric (Project Zero) - Jednostavan userspace fuzzing macOS kernel ekstenzija pomoću IDA-e i TinyInst-a](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html)

{{#include ../../../banners/hacktricks-training.md}}
