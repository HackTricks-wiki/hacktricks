# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext i amfid

Fokusira se na sprovođenje integriteta koda koji se izvršava na sistemu, pružajući logiku koja stoji iza XNU provere code signature. Takođe može da proverava entitlements i obavlja druge osetljive zadatke, kao što su omogućavanje debugging-a ili dobijanje task port-ova.

Pored toga, za neke operacije kext preferira kontakt sa user space daemon-om `/usr/libexec/amfid`. Ovaj odnos poverenja je zloupotrebljen u nekoliko jailbreak-ova.

Na novijim verzijama macOS-a, AMFI više nije praktično izložen kao samostalan kext na disku, pa reversing obično podrazumeva rad sa **kernelcache** ili **KDK**, umesto pregledanja direktorijuma `/System/Library/Extensions`.

AMFI koristi **MACF** policies i registruje svoje hooks u trenutku pokretanja. Takođe, sprečavanje njegovog učitavanja ili njegovo unload-ovanje može izazvati kernel panic. Međutim, postoje boot arguments koji omogućavaju onesposobljavanje AMFI-ja:

- `amfi_unrestricted_task_for_pid`: Omogućava task_for_pid bez potrebnih entitlements
- `amfi_allow_any_signature`: Omogućava bilo koji code signature
- `cs_enforcement_disable`: Sistemski argument koji se koristi za onemogućavanje code signing enforcement-a
- `amfi_prevent_old_entitled_platform_binaries`: Poništava platform binaries sa entitlements
- `amfi_get_out_of_my_way`: Potpuno onemogućava amfi

Ovo su neke od MACF policies koje registruje:<sup>[[1]](#references)</sup>

- **`cred_check_label_update_execve:`** Izvršiće se ažuriranje label-a i biće vraćena vrednost 1
- **`cred_label_associate`**: Ažurira AMFI-jev mac label slot sa label-om
- **`cred_label_destroy`**: Uklanja AMFI-jev mac label slot
- **`cred_label_init`**: Premešta 0 u AMFI-jev mac label slot
- **`cred_label_update_execve:`** Proverava entitlements procesa da bi utvrdio da li mu treba dozvoliti izmenu label-ova.
- **`file_check_mmap:`** Proverava da li mmap pribavlja memoriju i postavlja je kao executable. U tom slučaju proverava da li je potrebna library validation i, ako jeste, poziva library validation function.
- **`file_check_library_validation`** Poziva library validation function koja, između ostalog, proverava da li platform binary učitava drugi platform binary ili da li proces i novo učitani fajl imaju isti TeamID. Određeni entitlements takođe omogućavaju učitavanje bilo koje library.
- **`policy_initbsd`**: Podešava trusted NVRAM Keys
- **`policy_syscall`**: Proverava DYLD policies, kao što su to da li binary ima unrestricted segments i da li treba dozvoliti env vars... Ovo se takođe poziva kada se proces pokrene preko `amfi_check_dyld_policy_self()`.
- **`proc_check_inherit_ipc_ports`**: Proverava da li, kada proces izvrši novi binary, drugi procesi sa SEND pravima nad task port-om tog procesa treba da ih zadrže ili ne. Platform binaries su dozvoljeni, `get-task-allow` entitlement to omogućava, `task_for_pid-allow` entitlements su dozvoljeni, kao i binaries sa istim TeamID-om.
- **`proc_check_expose_task`**: Sprovodi entitlements
- **`amfi_exc_action_check_exception_send`**: Debugger-u se šalje exception message
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: Životni ciklus label-a tokom exception handling-a (debugging)
- **`proc_check_get_task`**: Proverava entitlements kao što je `get-task-allow`, koji drugim procesima omogućava dobijanje task port-a procesa, i `task_for_pid-allow`, koji procesu omogućava dobijanje task port-ova drugih procesa. Ako nijedan od njih nije prisutan, poziva `amfid permitunrestricteddebugging` da proveri da li je to dozvoljeno.
- **`proc_check_mprotect`**: Odbija zahtev ako se `mprotect` pozove sa flag-om `VM_PROT_TRUSTED`, koji ukazuje da region treba tretirati kao da ima validan code signature.
- **`vnode_check_exec`**: Poziva se kada se executable fajlovi učitavaju u memoriju i postavlja `cs_hard | cs_kill`, što će ubiti proces ako bilo koja stranica postane nevažeća<sup>[[2]](#references)</sup>
- **`vnode_check_getextattr`**: MacOS: Proverava `com.apple.root.installed` i `isVnodeQuarantined()`
- **`vnode_check_setextattr`**: Kao get + `com.apple.private.allow-bless` i internal-installer-equivalent entitlement
- **`vnode_check_signature`**: Kod koji poziva XNU radi provere code signature koristeći entitlements, trust cache i `amfid`<sup>[[3]](#references)</sup>
- **`proc_check_run_cs_invalid`**: Presreće `ptrace()` calls (`PT_ATTACH` i `PT_TRACE_ME`). Proverava entitlements `get-task-allow`, `run-invalid-allow` i `run-unsigned-code`, a ako nijedan nije prisutan, proverava da li je debugging dozvoljen.
- **`proc_check_map_anon`**: Ako se `mmap` pozove sa flag-om **`MAP_JIT`**, AMFI će proveriti `dynamic-codesigning` entitlement.

`AMFI.kext` takođe izlaže API za druge kernel extensions, a njegove dependencies moguće je pronaći pomoću:
```bash
kextstat | grep " 19 " | cut -c2-5,50- | cut -d '(' -f1
Executing: /usr/bin/kmutil showloaded
No variant specified, falling back to release
8   com.apple.kec.corecrypto
19   com.apple.driver.AppleMobileFileIntegrity
22   com.apple.security.sandbox
24   com.apple.AppleSystemPolicy
67   com.apple.iokit.IOUSBHostFamily
70   com.apple.driver.AppleUSBTDM
71   com.apple.driver.AppleSEPKeyStore
74   com.apple.iokit.EndpointSecurity
81   com.apple.iokit.IOUserEthernet
101   com.apple.iokit.IO80211Family
102   com.apple.driver.AppleBCMWLANCore
118   com.apple.driver.AppleEmbeddedUSBHost
134   com.apple.iokit.IOGPUFamily
135   com.apple.AGXG13X
137   com.apple.iokit.IOMobileGraphicsFamily
138   com.apple.iokit.IOMobileGraphicsFamily-DCP
162   com.apple.iokit.IONVMeFamily
```
## amfid

Ovo je daemon koji radi u korisničkom režimu i koji će `AMFI.kext` koristiti za proveru code signatures u korisničkom režimu.\
Da bi `AMFI.kext` komunicirao sa daemon-om, koristi mach messages preko porta `HOST_AMFID_PORT`, koji predstavlja specijalni port `18`.

Imajte na umu da u macOS-u root procesi više ne mogu da preotmu specijalne portove, jer su zaštićeni pomoću `SIP`-a i samo launchd može da ih dobije. U iOS-u se proverava da li proces koji šalje odgovor ima CDHash hardkodovan za `amfid`.

Moguće je videti kada se od `amfid`-a traži da proveri binary i njegov odgovor tako što se on debuguje i postavi breakpoint u `mach_msg`.

Kada se poruka primi preko specijalnog porta, **MIG** se koristi za prosleđivanje svake funkcije funkciji koju poziva. Glavne funkcije su reverse-engineer-ovane i objašnjene u knjizi.

### DYLD politika i validacija biblioteka

Novije verzije `dyld`-a pozivaju `amfi_check_dyld_policy_self()` veoma rano iz `configureProcessRestrictions()` kako bi pitale AMFI da li proces sme da koristi `DYLD_*` path promenljive, interposing, fallback paths, embedded variables ili da toleriše neuspešnu library insertion. Zato, prilikom trijaže injection surface-a, nije dovoljno pregledati samo Mach-O load commands: potrebno je pregledati i entitlements i runtime flags koje će AMFI prevesti u `dyld` policy.

Praktičan triage loop je:
```bash
BIN=/path/to/app/Contents/MacOS/binary

# Interesting AMFI-related entitlements
codesign -d --entitlements :- "$BIN" 2>&1 | \
egrep "disable-library-validation|clear-library-validation|allow-dyld-environment-variables|allow-jit|allow-unsigned-executable-memory|disable-executable-page-protection|get-task-allow"

# Runtime flags / TeamID / hardened-runtime metadata
codesign -dvvv "$BIN" 2>&1 | egrep "TeamIdentifier=|Runtime Version|flags="
```
Na modernom macOS-u mnogi Apple binarni fajlovi više ne sadrže direktno `com.apple.security.cs.disable-library-validation`, već umesto toga koriste `com.apple.private.security.clear-library-validation`. U tom slučaju validacija biblioteka nije onemogućena u trenutku `execve`: proces mora sam nad sobom da pozove `csops(..., CS_OPS_CLEAR_LV, ...)`, a XNU dozvoljava tu operaciju samo procesu koji je poziva kada je entitlement prisutan. Iz ofanzivne perspektive, ovo je važno zato što cilj može postati podložan injection-u tek nakon što dođe do putanje koda koja eksplicitno uklanja LV, na primer neposredno pre učitavanja opcionih plugin-ova.<sup>[[4]](#references)[[5]](#references)</sup>

## Provisioning Profiles

Provisioning profile može da se koristi za potpisivanje koda. Postoje **Developer** profili koji mogu da se koriste za potpisivanje koda i njegovo testiranje, kao i **Enterprise** profili koji mogu da se koriste na svim uređajima.

Nakon što se aplikacija pošalje u Apple Store i bude odobrena, Apple je potpisuje i provisioning profile više nije potreban.

Profil obično koristi ekstenziju `.mobileprovision` ili `.provisionprofile` i može se izbaciti pomoću:
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
Iako se ponekad nazivaju certificiranim, ovi provisioning profili sadrže više od samog sertifikata:

- **AppIDName:** Identifikator aplikacije
- **AppleInternalProfile**: Označava da je ovo Apple Internal profil
- **ApplicationIdentifierPrefix**: Dodaje se ispred AppIDName (isto što i TeamIdentifier)
- **CreationDate**: Datum u formatu `YYYY-MM-DDTHH:mm:ssZ`
- **DeveloperCertificates**: Niz od (obično jednog) sertifikata, kodiran kao Base64 data
- **Entitlements**: Dozvoljeni entitlements za ovaj profil
- **ExpirationDate**: Datum isteka u formatu `YYYY-MM-DDTHH:mm:ssZ`
- **Name**: Naziv aplikacije, isti kao AppIDName
- **ProvisionedDevices**: Niz (za developerske sertifikate) UDID-ova za koje je ovaj profil važeći
- **ProvisionsAllDevices**: Boolean vrednost (true za enterprise sertifikate)
- **TeamIdentifier**: Niz (obično jednog) alfanumeričkog stringa koji se koristi za identifikaciju developera u svrhe inter-app interakcije
- **TeamName**: Čitljiv naziv koji se koristi za identifikaciju developera
- **TimeToLive**: Važenje sertifikata (u danima)
- **UUID**: Universally Unique Identifier za ovaj profil
- **Version**: Trenutno postavljeno na 1

Imajte na umu da će entitlements stavka sadržati ograničen skup entitlements i da će provisioning profil moći da dodeli samo te konkretne entitlements, kako bi se sprečilo dodeljivanje Apple private entitlements.

Imajte na umu da se profili obično nalaze u `/var/MobileDeviceProvisioningProfiles` i da ih je moguće proveriti pomoću **`security cms -D -i /path/to/profile`**

## **libmis.dylib**

Ovo je external library koju `amfid` poziva kako bi proverio da li nešto treba da dozvoli ili ne. Istorijski je zloupotrebljavana u jailbreaking-u pokretanjem backdoored verzije koja bi dozvolila sve.

U macOS-u se nalazi unutar `MobileDevice.framework`.

## AMFI Trust Caches

Trust caches nisu samo iOS koncept. Na modernom macOS-u, naročito na **Apple silicon** uređajima, static trust cache i loadable trust caches deo su Secure Boot lanca. Kada je **CodeDirectory hash** Mach-O-a prisutan u njima, AMFI mu može dodeliti **platform privilege** bez dodatnih provera autentičnosti prilikom pokretanja. To takođe znači da Apple može zaključati platform binaries na određenu verziju OS-a i sprečiti replay starijih Apple-signed binaries na novijim sistemima.<sup>[[6]](#references)</sup>

Na novijim macOS izdanjima, trust-cache metadata je takođe povezana sa **launch constraints**, pa kopirane sistemske aplikacije i binaries pokrenuti iz pogrešnog parent/location mogu biti odbijeni od strane AMFI-ja čak i ako su i dalje Apple-signed. Detaljan workflow za extraction i reversing obrađen je u:

{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

U iOS i jailbreak istraživanju i dalje ćete pronaći tradicionalni model **loadable trust caches** koji se koristi za whitelist ad-hoc signed binaries.

## Reference

- [1] [XNU — `security/mac_policy.h` (MACF policy ops AMFI registers, incl. `mpo_policy_syscall`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `osfmk/kern/cs_blobs.h` (`CS_*` code-signing flags AMFI sets)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [3] [XNU — `bsd/kern/ubc_subr.c` (code-signature blob parsing and validation)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/ubc_subr.c)
- [4] [XNU — `bsd/sys/codesign.h` (`CS_OPS_*` operations and `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [5] [XNU — `bsd/kern/kern_proc.c` (`csops` / `CS_OPS_CLEAR_LV` handler)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [6] [Apple Platform Security Guide — Trust caches](https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web)

{{#include ../../../banners/hacktricks-training.md}}
