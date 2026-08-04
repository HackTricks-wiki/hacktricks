# macOS Kernel Vulnerabilities

{{#include ../../../banners/hacktricks-training.md}}

Nedavna eksploatacija macOS kernela manje se zasniva na tome da se „učita trivijalan unsigned kext i dobije ring-0“, a više na zloupotrebi **Mach/MIG parsera**, **IOKit user client-a**, **data-only race-ova unutar XNU-a** i **daemona sa posebnim entitlements**, koji i dalje mogu ponovo otvoriti attack surface kernela. Za reverse engineering konkretnih interfejsa pogledajte i stranice o [**IOKit**](macos-iokit.md) i [**kernel extensions / kernelcache extraction**](macos-kernel-extensions.md).

## Attack surfaces koji su i dalje važni

- **Mach/MIG handleri** u sistemskim daemonima i servisima koji komuniciraju sa kernelom: neispravno formirani deskriptori, out-of-line (OOL) podaci i stateful tokovi sa više poruka.
- **IOKit user client-i**: parsiranje specifično za selector, metode zaštićene entitlement-ima i wrapper biblioteke/daemoni koji skrivaju stvarni call graph.
- **XNU data-only primitive**: race-ovi oko credentials, SMR-zaštićenih pointera, read-only zona i drugih mesta gde korupcija menja policy bez prethodnog preuzimanja kontrole nad RIP/PC.
- **Third-party / pomoćni kernel kod**: legacy kext-ovi su ređi, ali enterprise flote, Apple Silicon sistemi sa smanjenom bezbednošću i vendor `.fs` / helper bundle-ovi i dalje stvaraju vredne kernel-adjacent putanje.

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

U [**ovom izveštaju**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) nekoliko bugova u OTA/update-chain-u kombinovano je kako bi se došlo do kompromitovanja kernela zloupotrebom software update pipeline-a i rootless-related capabilities.

[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722).

---

## 2024: In-the-wild chain za zaobilaženje kernel zaštite (CVE-2024-23225 & CVE-2024-23296)

Apple-ova [**macOS security izdanja iz marta 2024.**](https://support.apple.com/en-us/120895) popravila su dva problema koji su bili **aktivno eksploatisani**:

- **CVE-2024-23225 – Kernel**: bug sa korupcijom memorije pri kojem napadač sa proizvoljnim kernel read/write-om može zaobići zaštite kernel memorije.
- **CVE-2024-23296 – RTKit**: drugi bug sa korupcijom memorije i istom javno navedenom posledicom.

Javno dostupni detalji o root cause-u i dalje su oskudni, ali ovaj par je dobar podsetnik da moderne Apple exploit chain-e često zahtevaju **više od „samo“ kernel R/W-a**: post-exploitation rad protiv zaštita memorije, coprocessor-adjacent koda ili sekundarnih trust boundary-ja često je deo u kojem se stvarni chain stabilizuje.

Brza triage procena zakrpa:
```bash
sw_vers
uname -v
softwareupdate --history | tail -n 20
```
---

## 2025: SMR + race usled read-only credentials (CVE-2025-24118)

[**TRAVERTINE write-up**](https://jprx.io/cve-2025-24118/) autora Josepha Ravichandran-a predstavlja veoma dobru modernu studiju slučaja XNU-a, jer nije u pitanju klasičan buffer overflow:

- `proc_ro.p_ucred` je **SMR-protected pointer** sačuvan u **read-only** objektu `proc_ro`.
- Writers moraju da ažuriraju taj pointer **atomically**.
- `kauth_cred_proc_update()` je koristio `zalloc_ro_mut(...)` za izmenu `p_ucred`; na x86_64 taj put na kraju dolazi do `memcpy` / `rep movsb`, pa konkurentni reader može da uoči **torn pointer**.
- Bug se pretvara u **data-only privilege escalation**: ako se oštećeni credential pointer razreši u drugi validan credential objekat, trenutna nit može da nasledi privilegovanije stanje bez prethodnog očiglednog preuzimanja kontrole toka izvršavanja.

Minimalni obrazac za pokretanje:
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
Korisna heuristika za audit: kad god kernel path kombinuje **SMR readers**, **read-only zone mutation** i **credential ili task metadata**, proverite da li ažuriranja koriste atomske `zalloc_ro_mut_*` varijante umesto helpera zasnovanih na kopiranju.

---

## 2024-2025: SIP bypass koji ponovo otvara kernel loading paths (CVE-2024-44243)

Microsoft je pokazao da se `storagekitd` može zloupotrebiti za **bypass SIP-a**, a zatim ponovo učiniti relevantnim third-party kernel code na mašinama koje bi inače izgledale kao "post-kext". Ključna ideja je:

1. Ostaviti ili prepisati maliciozni `.fs` bundle u `/Library/Filesystems`.
2. Pokrenuti `storagekitd` preko Disk Utility-ja ili `diskutil`.
3. Dozvoliti posebno privileged daemon-u da pokrene bundle executables **bez pravilnog uklanjanja privilegija / validacije path-a**.
4. Iskoristiti dobijeni SIP bypass za izmenu zaštićenog file-system state-a i, u Microsoft-ovoj demonstraciji, override-ovati kernel extension exclusion list.

Za kernel istraživače, važna lekcija je da **kernel attack surface može ponovo biti uveden iz userland management daemon-a**, čak i kada je direktno učitavanje third-party kext-ova strogo ograničeno.

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

- [**KextFuzz**](https://www.usenix.org/conference/usenixsecurity23/presentation/yin) i dalje je jedna od najboljih referenci za istraživanje kernela u eri Apple Silicon-a. Koristi **static binary rewriting** za obnavljanje coverage-a, onemogućava putanje zaštićene **entitlement**-ima tokom testiranja i zaključuje strukturu interfejsa na osnovu userspace wrapper-a.
- Project Zero-ov rad [**Simple macOS kernel extension fuzzing in userspace with IDA and TinyInst**](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html) prikazuje veoma praktičan workflow za **rebasing kext-a / fileset-a u userspace**, kako bi parser-heavy kod mogao da se fuzz-uje mnogo većom brzinom pre reprodukcije na uređaju.
- Za Mach-heavy mete, pravite harness-e oko **real message layout-a i multi-call state machine-a**, a ne samo oko blob-ova pojedinačnih selector-a. Nedavna CoreAudio/Mach istraživanja Project Zero-a i predavanja na konferencijama, kao što je **Fuzzing at Mach Speed**, pokazuju zašto stateful sekvence poruka i dalje daju dobre rezultate.

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

* Joseph Ravichandran. „TRAVERTINE: CVE-2025-24118.” https://jprx.io/cve-2025-24118/
* Microsoft Security Blog. „Analiza CVE-2024-44243, zaobilaženje macOS System Integrity Protection mehanizma putem kernel ekstenzija.” https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/
{{#include ../../../banners/hacktricks-training.md}}
