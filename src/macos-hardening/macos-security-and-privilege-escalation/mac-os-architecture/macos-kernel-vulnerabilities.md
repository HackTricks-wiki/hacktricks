# macOS kernel ranjivosti

{{#include ../../../banners/hacktricks-training.md}}

Nedavna macOS kernel exploitation manje se odnosi na „učitavanje trivijalnog unsigned kext-a i dobijanje ring-0“ a više na zloupotrebu **Mach/MIG parsera**, **IOKit user client-a**, **data-only race-ova unutar XNU-a** i **posebno privilegovanih daemon-a** koji i dalje mogu ponovo otvoriti kernel attack surface. Za reverzovanje konkretnih interfejsa pogledajte i stranice o [**IOKit-u**](macos-iokit.md) i [**kernel extensions / kernelcache extraction**](macos-kernel-extensions.md).

## Attack surfaces koji su i dalje važni

- **Mach/MIG handler-i** u system daemon-ima i servisima koji komuniciraju sa kernelom: neispravni descriptor-i, out-of-line (OOL) podaci i stateful tokovi sa više poruka.
- **IOKit user client-i**: parsing specifičan za selector, metode ograničene entitlement-ima i wrapper biblioteke/daemon-i koji skrivaju stvarni call graph.
- **XNU data-only primitive-i**: race-ovi oko credential-a, SMR-om zaštićenih pointer-a, read-only zona i drugih mesta gde corruption menja policy bez prethodnog preuzimanja kontrole nad RIP/PC-jem.
- **Third-party / pomoćni kernel kod**: legacy kext-ovi su ređi, ali enterprise fleet-ovi, Apple Silicon sistemi sa smanjenom bezbednošću i vendor `.fs` / helper bundle-ovi i dalje stvaraju high-value kernel-adjacent putanje.

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

U [**ovom izveštaju**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) nekoliko bug-ova u OTA/update chain-u kombinovano je kako bi se došlo do kernel compromise-a zloupotrebom software update pipeline-a i rootless-related capabilities.<sup>[[3]](#references)</sup>

[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722).

---

## 2024: In-the-wild kernel protection bypass chain (CVE-2024-23225 & CVE-2024-23296)

Apple-ova [**macOS security izdanja iz marta 2024.**](https://support.apple.com/en-us/120895) ispravila su dva problema koja su bila **aktivno iskorišćavana**:

- **CVE-2024-23225 – Kernel**: memory-corruption bug kod kog je attacker sa arbitrary kernel read/write mogućnošću mogao da zaobiđe kernel memory protections.
- **CVE-2024-23296 – RTKit**: drugi memory-corruption bug sa istom javno navedenom posledicom.

Javni detalji o root cause-u i dalje su oskudni, ali ovaj par je dobar podsetnik da moderni Apple exploit chain-ovi često zahtevaju **više od „samo“ kernel R/W**: post-exploitation rad protiv memory protections, coprocessor-adjacent koda ili sekundarnih trust boundary-ja često je mesto gde se stvarni chain stabilizuje.

Brza analiza zakrpa:
```bash
sw_vers
uname -v
softwareupdate --history | tail -n 20
```
---

## 2025: SMR + read-only credential race (CVE-2025-24118)

[**TRAVERTINE write-up**](https://jprx.io/cve-2025-24118/) autora Josepha Ravichandrana predstavlja veoma dobar savremeni XNU case study, jer ovo **nije** klasičan buffer overflow:<sup>[[1]](#references)</sup>

- `proc_ro.p_ucred` je **SMR-protected pointer** uskladišten u **read-only** `proc_ro` objektu.
- Writers moraju da ažuriraju taj pointer **atomically**.
- `kauth_cred_proc_update()` je koristio `zalloc_ro_mut(...)` za izmenu `p_ucred`; na x86_64 ta putanja na kraju dolazi do `memcpy` / `rep movsb`, pa concurrent reader može da uoči **torn pointer**.
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
Korisna heuristika za audit: kad god kernel putanja kombinuje **SMR čitače**, **mutaciju zone samo za čitanje** i **credential ili task metapodatke**, proverite da li se ažuriranja obavljaju korišćenjem atomskih `zalloc_ro_mut_*` varijanti, a ne helperima zasnovanim na kopiranju.

---

## 2024-2025: SIP bypass koji ponovo otvara putanje za učitavanje kernela (CVE-2024-44243)

Microsoft je pokazao da se `storagekitd` može zloupotrebiti za **bypass SIP-a**, a zatim ponovo učiniti relevantnim third-party kernel code na mašinama koje bi inače izgledale kao "post-kext". Ključna ideja je:<sup>[[2]](#references)</sup>

1. Odbaciti ili prepisati zlonamerni `.fs` bundle u `/Library/Filesystems`.
2. Pokrenuti `storagekitd` putem Disk Utility-ja ili `diskutil`-a.
3. Dozvoliti posebno privilegovanom daemonu da pokrene bundle executables **bez pravilnog odbacivanja privilegija / validacije putanje**.
4. Iskoristiti dobijeni SIP bypass za izmenu zaštićenog stanja file-systema i, u Microsoftovoj demonstraciji, prepisati listu izuzetaka kernel extension-a.

Za kernel istraživače, važna pouka je da se **kernel attack surface može ponovo uvesti iz userlanda putem management daemona**, čak i kada je direktno učitavanje third-party kext-ova strogo ograničeno.

Korisna triage provera:
```bash
ls -la /Library/Filesystems
find /Library/Filesystems -maxdepth 3 -type f \( -name 'mount_*' -o -name 'fsck_*' -o -name 'newfs_*' \) 2>/dev/null
log stream --style syslog --predicate 'process == "storagekitd" || process == "diskarbitrationd"'
kmutil showloaded --collection aux
```
---

## Fuzzing i istraživački tok rada

Ako aktivno tražite ovu klasu bugova, nedavni javno dostupni radovi ukazuju u istom smeru:

- [**KextFuzz**](https://www.usenix.org/conference/usenixsecurity23/presentation/yin) je i dalje jedna od najboljih referenci za kernel istraživanja u Apple Silicon eri. Koristi **static binary rewriting** za obnavljanje coverage-a, onemogućava putanje zaštićene pomoću **entitlement-gated** mehanizama tokom testiranja i zaključuje strukturu interfejsa na osnovu userspace wrappera.<sup>[[4]](#references)</sup>
- Project Zero-ov [**Simple macOS kernel extension fuzzing in userspace with IDA and TinyInst**](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html) prikazuje veoma praktičan workflow za **rebasing kext-a / fileset-a u userspace**, kako bi parser-heavy kod mogao da se fuzz-uje mnogo većom brzinom pre reprodukcije na uređaju.<sup>[[5]](#references)</sup>
- Za Mach-heavy mete, pravite harness-e oko **real message layout-a i multi-call state machine-a**, a ne samo oko pojedinačnih selector blobova. Nedavna CoreAudio/Mach istraživanja Project Zero-a i konferencijska predavanja, kao što je **Fuzzing at Mach Speed**, pokazuju zašto stateful sekvence poruka i dalje daju rezultate.

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
- [2] [Microsoft Security Blog - Analiza CVE-2024-44243, zaobilaženja macOS System Integrity Protection kroz kernel ekstenzije](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [3] [Mickey Jin - Noćna mora Apple-ovog OTA Update-a: zaobilaženje verifikacije potpisa i preuzimanje kontrole nad kernelom](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [4] [Tingting Yin et al. - KextFuzz: Fuzzing macOS Kernel EXTensions na Apple Silicon-u iskorišćavanjem mitigacija (USENIX Security '23)](https://www.usenix.org/conference/usenixsecurity23/presentation/yin)
- [5] [Ivan Fratric (Project Zero) - Jednostavan macOS kernel extension fuzzing u userspace-u pomoću alata IDA i TinyInst](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html)

{{#include ../../../banners/hacktricks-training.md}}
