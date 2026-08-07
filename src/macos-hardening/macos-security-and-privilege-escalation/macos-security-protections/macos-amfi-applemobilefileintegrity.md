# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext i amfid

Fokusira se na sprovođenje integriteta koda koji se izvršava na sistemu, pružajući logiku koja stoji iza XNU-ove verifikacije code signature. Takođe može da proverava entitlements i da obrađuje druge osetljive zadatke, kao što su omogućavanje debugging-a ili dobijanje task port-ova.

Pored toga, za neke operacije kext preferira da kontaktira daemon koji se izvršava u user space-u: `/usr/libexec/amfid`. Ovo poverenje je zloupotrebljeno u nekoliko jailbreak-ova.

Na novijim verzijama macOS-a, AMFI više nije praktično izložen kao standalone kext na disku, pa reversing obično podrazumeva rad iz **kernelcache-a** ili KDK-a, umesto pregledanja direktorijuma `/System/Library/Extensions`.

AMFI koristi **MACF** policies i registruje svoje hooks čim se pokrene. Takođe, sprečavanje njegovog učitavanja ili njegovo unload-ovanje može izazvati kernel panic. Međutim, postoje boot arguments koji omogućavaju onesposobljavanje AMFI-ja:

- `amfi_unrestricted_task_for_pid`: Omogućava da task_for_pid bude dozvoljen bez potrebnih entitlements
- `amfi_allow_any_signature`: Dozvoljava bilo koju code signature
- `cs_enforcement_disable`: System-wide argument koji se koristi za onemogućavanje sprovođenja code signing-a
- `amfi_prevent_old_entitled_platform_binaries`: Poništava platform binaries sa entitlements
- `amfi_get_out_of_my_way`: Potpuno onemogućava amfi

Ovo su neke od MACF policies koje registruje:<sup>[[1]](#references)</sup>

- **`cred_check_label_update_execve:`** Ažuriranje label-a će biti izvršeno i biće vraćena vrednost 1
- **`cred_label_associate`**: Ažurira AMFI-jev mac label slot pomoću label-a
- **`cred_label_destroy`**: Uklanja AMFI-jev mac label slot
- **`cred_label_init`**: Postavlja vrednost 0 u AMFI-jev mac label slot
- **`cred_label_update_execve`:** Proverava entitlements procesa da bi utvrdio da li mu treba dozvoliti izmenu label-a.
- **`file_check_mmap`:** Proverava da li mmap dobija memoriju i postavlja je kao executable. U tom slučaju proverava da li je potrebna library validation i, ako jeste, poziva funkciju za library validation.
- **`file_check_library_validation`**: Poziva funkciju za library validation, koja između ostalog proverava da li platform binary učitava drugi platform binary ili da li proces i novo učitani file imaju isti TeamID. Određeni entitlements takođe omogućavaju učitavanje bilo koje library.
- **`policy_initbsd`**: Podešava trusted NVRAM Keys
- **`policy_syscall`**: Proverava DYLD policies, kao što su da li binary ima unrestricted segments i da li treba dozvoliti env vars... Ovo se takođe poziva kada se proces pokrene pomoću `amfi_check_dyld_policy_self()`.
- **`proc_check_inherit_ipc_ports`**: Proverava da li, kada proces izvrši novi binary, drugi procesi sa SEND pravima nad task port-om tog procesa treba da ih zadrže ili ne. Platform binaries su dozvoljeni, `get-task-allow` entitlement to omogućava, `task_for_pid-allow` entitlements su dozvoljeni, kao i binaries sa istim TeamID-jem.
- **`proc_check_expose_task`**: Sprovodi entitlements
- **`amfi_exc_action_check_exception_send`**: Exception message se šalje debugger-u
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: Životni ciklus label-a tokom obrade exception-a (debugging)
- **`proc_check_get_task`**: Proverava entitlements kao što je `get-task-allow`, koji drugim procesima omogućava dobijanje task port-a, i `task_for_pid-allow`, koji procesu omogućava dobijanje task port-ova drugih procesa. Ako nijedan od njih nije prisutan, poziva `amfid permitunrestricteddebugging` da proveri da li je to dozvoljeno.
- **`proc_check_mprotect`**: Odbija zahtev ako se `mprotect` pozove sa flag-om `VM_PROT_TRUSTED`, koji označava da region mora biti tretiran kao da ima validnu code signature.
- **`vnode_check_exec`**: Poziva se kada se executable files učitavaju u memoriju i postavlja `cs_hard | cs_kill`, što će prekinuti proces ako bilo koja stranica postane nevalidna<sup>[[2]](#references)</sup>
- **`vnode_check_getextattr`**: MacOS: Proverava `com.apple.root.installed` i `isVnodeQuarantined()`
- **`vnode_check_setextattr`**: Kao get + `com.apple.private.allow-bless` i internal-installer-equivalent entitlement
- **`vnode_check_signature`**: Code koji poziva XNU da proveri code signature pomoću entitlements, trust cache-a i `amfid`<sup>[[3]](#references)</sup>
- **`proc_check_run_cs_invalid`**: Presreće `ptrace()` calls (`PT_ATTACH` i `PT_TRACE_ME`). Proverava da li postoji neki od entitlements `get-task-allow`, `run-invalid-allow` i `run-unsigned-code`, a ako nijedan nije prisutan, proverava da li je debugging dozvoljen.
- **`proc_check_map_anon`**: Ako se mmap pozove sa flag-om **`MAP_JIT`**, AMFI proverava `dynamic-codesigning` entitlement.

`AMFI.kext` takođe izlaže API za druge kernel extensions, a njegove dependencies je moguće pronaći pomoću:
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

Ovo je daemon koji se izvršava u user mode-u i koji će `AMFI.kext` koristiti za proveru code signatures u user mode-u.\
Da bi `AMFI.kext` komunicirao sa daemon-om, koristi mach messages preko porta `HOST_AMFID_PORT`, koji predstavlja specijalni port `18`.

Imajte na umu da u macOS-u root procesi više ne mogu da preuzmu specijalne portove, jer su zaštićeni pomoću `SIP`-a i samo launchd može da ih dobije. U iOS-u se proverava da li proces koji šalje odgovor nazad ima hardkodovani CDHash od `amfid`-a.

Moguće je videti kada se od `amfid`-a zahteva da proveri binary i njegov odgovor tako što ćete ga debug-ovati i postaviti breakpoint u `mach_msg`.

Kada se poruka primi preko specijalnog porta, **MIG** se koristi za slanje svake funkcije funkciji koju poziva. Glavne funkcije su reverse-ovane i objašnjene u knjizi.

### DYLD policy and library validation

Novije verzije `dyld`-a veoma rano pozivaju `amfi_check_dyld_policy_self()` iz `configureProcessRestrictions()` da bi pitale AMFI da li proces sme da koristi `DYLD_*` path variables, interposing, fallback paths, embedded variables ili da toleriše neuspešno ubacivanje library-ja. Zato, prilikom triage-a injection surface-a, nije dovoljno pregledati samo Mach-O load commands: potrebno je pregledati i entitlements i runtime flags koje će AMFI prevesti u `dyld` policy.

Praktična triage petlja je:
```bash
BIN=/path/to/app/Contents/MacOS/binary

# Interesting AMFI-related entitlements
codesign -d --entitlements :- "$BIN" 2>&1 | \
egrep "disable-library-validation|clear-library-validation|allow-dyld-environment-variables|allow-jit|allow-unsigned-executable-memory|disable-executable-page-protection|get-task-allow"

# Runtime flags / TeamID / hardened-runtime metadata
codesign -dvvv "$BIN" 2>&1 | egrep "TeamIdentifier=|Runtime Version|flags="
```
Na modernom macOS-u mnogi Apple binarni fajlovi više ne sadrže direktno `com.apple.security.cs.disable-library-validation`, već se isporučuju sa `com.apple.private.security.clear-library-validation`. U tom slučaju library validation nije onemogućen u trenutku `execve`: proces mora da pozove `csops(..., CS_OPS_CLEAR_LV, ...)` nad samim sobom, a XNU dozvoljava tu operaciju nad pozivajućim procesom samo kada je entitlement prisutan. Iz ofanzivne perspektive, ovo je važno zato što cilj može postati pogodan za injection tek nakon što dođe do putanje koda koja eksplicitno čisti LV (na primer, neposredno pre učitavanja opcionalnih pluginova).<sup>[[4]](#references)[[5]](#references)</sup>

## Provisioning Profiles

Provisioning profile može da se koristi za potpisivanje koda. Postoje **Developer** profili koji mogu da se koriste za potpisivanje koda i njegovo testiranje, kao i **Enterprise** profili koji mogu da se koriste na svim uređajima.

Nakon što se App pošalje u Apple Store i bude odobren, Apple ga potpisuje, pa provisioning profile više nije potreban.

Profil obično koristi ekstenziju `.mobileprovision` ili `.provisionprofile` i može da se dumpuje pomoću:
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
Iako se ponekad nazivaju sertifikovanim, ovi provisioning profiles sadrže više od jednog sertifikata:

- **AppIDName:** Identifikator aplikacije
- **AppleInternalProfile**: Označava da je ovo interni Apple profile
- **ApplicationIdentifierPrefix**: Dodaje se ispred AppIDName (isto što i TeamIdentifier)
- **CreationDate**: Datum u formatu `YYYY-MM-DDTHH:mm:ssZ`
- **DeveloperCertificates**: Niz od (obično jednog) sertifikata, kodiranih kao Base64 podaci
- **Entitlements**: Entitlements dozvoljeni za ovaj profile
- **ExpirationDate**: Datum isteka u formatu `YYYY-MM-DDTHH:mm:ssZ`
- **Name**: Naziv aplikacije, isti kao AppIDName
- **ProvisionedDevices**: Niz UDID-ova za koje ovaj profile važi (za developer sertifikate)
- **ProvisionsAllDevices**: Boolean vrednost (true za enterprise sertifikate)
- **TeamIdentifier**: Niz od (obično jednog) alfanumeričkog stringa koji se koristi za identifikaciju developera u svrhe interakcije između aplikacija
- **TeamName**: Čitljiv naziv koji se koristi za identifikaciju developera
- **TimeToLive**: Važenje sertifikata (u danima)
- **UUID**: Universally Unique Identifier za ovaj profile
- **Version**: Trenutno postavljeno na 1

Imajte na umu da će unos entitlements sadržati ograničen skup entitlements, a provisioning profile će moći da dodeli samo ta specifična entitlements, čime se sprečava dodeljivanje Apple privatnih entitlements.

Imajte na umu da se profiles obično nalaze u `/var/MobileDeviceProvisioningProfiles` i da ih je moguće proveriti pomoću **`security cms -D -i /path/to/profile`**

## **libmis.dylib**

Ovo je eksterna biblioteka koju `amfid` poziva da bi proverio da li nešto treba dozvoliti ili ne. Istorijski je zloupotrebljavana u jailbreaking-u pokretanjem backdoored verzije koja bi dozvolila sve.

U macOS-u se nalazi unutar `MobileDevice.framework`.

## AMFI Trust Caches

Trust caches nisu samo iOS koncept. Na modernom macOS-u, naročito na **Apple silicon** uređajima, static trust cache i loadable trust caches deo su Secure Boot lanca. Kada je **CodeDirectory hash** Mach-O datoteke prisutan u njima, AMFI joj može dodeliti **platform privilege** bez dodatnih provera autentičnosti prilikom pokretanja. To takođe znači da Apple može zaključati platform binaries za određenu verziju OS-a i sprečiti replay starijih Apple-signed binaries na novijim sistemima.<sup>[[6]](#references)</sup>

Na novijim macOS izdanjima, metadata trust cache-a je takođe povezana sa **launch constraints**, pa system apps i binaries kopirane i pokrenute iz pogrešnog parent-a/lokacije mogu biti odbijene od strane AMFI-ja čak i ako su i dalje Apple-signed. Detaljan workflow za ekstrakciju i reversing obrađen je u:

{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

U iOS-u i jailbreak istraživanju i dalje ćete nailaziti na tradicionalni model **loadable trust caches**, koji se koristi za whitelisting ad-hoc signed binaries.

## Reference

- [1] [XNU — `security/mac_policy.h` (MACF policy ops AMFI registers, incl. `mpo_policy_syscall`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `osfmk/kern/cs_blobs.h` (`CS_*` code-signing flags AMFI sets)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [3] [XNU — `bsd/kern/ubc_subr.c` (code-signature blob parsing and validation)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/ubc_subr.c)
- [4] [XNU — `bsd/sys/codesign.h` (`CS_OPS_*` operations and `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [5] [XNU — `bsd/kern/kern_proc.c` (`csops` / `CS_OPS_CLEAR_LV` handler)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [6] [Apple Platform Security Guide — Trust caches](https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web)

{{#include ../../../banners/hacktricks-training.md}}
