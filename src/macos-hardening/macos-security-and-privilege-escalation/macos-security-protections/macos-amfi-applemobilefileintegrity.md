# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext i amfid

Fokusira se na sprovođenje integriteta koda koji se izvršava na sistemu, pružajući logiku iza verifikacije potpisa koda XNU-a. Takođe može da proveri prava i obavlja druge osetljive zadatke kao što su omogućavanje debagovanja ili dobijanje portova zadataka.

Štaviše, za neke operacije, kext preferira da kontaktira korisnički prostor koji pokreće demon `/usr/libexec/amfid`. Ova međusobna poverenja su zloupotrebljena u nekoliko jailbreak-ova.

AMFI koristi **MACF** politike i registruje svoje hook-ove u trenutku kada se pokrene. Takođe, sprečavanje njegovog učitavanja ili isključivanja može izazvati kernel panic. Međutim, postoje neki boot argumenti koji omogućavaju oslabiti AMFI:

- `amfi_unrestricted_task_for_pid`: Dozvoljava task_for_pid bez potrebnih prava
- `amfi_allow_any_signature`: Dozvoljava bilo koji potpis koda
- `cs_enforcement_disable`: Argument na sistemskom nivou koji se koristi za onemogućavanje sprovođenja potpisivanja koda
- `amfi_prevent_old_entitled_platform_binaries`: Odbacuje platforme binarne sa pravima
- `amfi_get_out_of_my_way`: Potpuno onemogućava amfi

Ovo su neke od MACF politika koje registruje:

- **`cred_check_label_update_execve:`** Ažuriranje oznake će biti izvršeno i vratiće 1
- **`cred_label_associate`**: Ažurira AMFI-ovu mac oznaku
- **`cred_label_destroy`**: Uklanja AMFI-ovu mac oznaku
- **`cred_label_init`**: Postavlja 0 u AMFI-ovu mac oznaku
- **`cred_label_update_execve`:** Proverava prava procesa da vidi da li bi trebalo da mu bude dozvoljeno da menja oznake.
- **`file_check_mmap`:** Proverava da li mmap stiče memoriju i postavlja je kao izvršivu. U tom slučaju proverava da li je potrebna validacija biblioteke i, ako jeste, poziva funkciju za validaciju biblioteke.
- **`file_check_library_validation`**: Poziva funkciju za validaciju biblioteke koja proverava, između ostalog, da li platforma binarna učitava drugu platformu binarnu ili da li proces i novo učitani fajl imaju isti TeamID. Određena prava će takođe omogućiti učitavanje bilo koje biblioteke.
- **`policy_initbsd`**: Postavlja poverljive NVRAM ključeve
- **`policy_syscall`**: Proverava DYLD politike kao što su da li binarna ima neograničene segmente, da li bi trebalo da dozvoli env varijable... ovo se takođe poziva kada se proces pokrene putem `amfi_check_dyld_policy_self()`.
- **`proc_check_inherit_ipc_ports`**: Proverava da li kada proces izvršava novu binarnu, drugi procesi sa SEND pravima nad portom zadatka procesa treba da ih zadrže ili ne. Platforme binarne su dozvoljene, `get-task-allow` pravo to omogućava, `task_for_pid-allow` prava su dozvoljena i binarne sa istim TeamID.
- **`proc_check_expose_task`**: sprovodi prava
- **`amfi_exc_action_check_exception_send`**: Poruka izuzetka se šalje debageru
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: Životni ciklus oznake tokom obrade izuzetaka (debugging)
- **`proc_check_get_task`**: Proverava prava kao što su `get-task-allow` koja omogućava drugim procesima da dobiju port zadatka i `task_for_pid-allow`, koja omogućava procesu da dobije portove zadataka drugih procesa. Ako nijedno od toga nije, poziva `amfid permitunrestricteddebugging` da proveri da li je dozvoljeno.
- **`proc_check_mprotect`**: Odbija ako je `mprotect` pozvan sa oznakom `VM_PROT_TRUSTED` koja ukazuje da se region mora tretirati kao da ima važeći potpis koda.
- **`vnode_check_exec`**: Poziva se kada se izvršne datoteke učitavaju u memoriju i postavlja `cs_hard | cs_kill` što će ubiti proces ako neka od stranica postane nevažeća
- **`vnode_check_getextattr`**: MacOS: Proverava `com.apple.root.installed` i `isVnodeQuarantined()`
- **`vnode_check_setextattr`**: Kao get + com.apple.private.allow-bless i interno-instalater-ekvivalentno pravo
- &#x20;**`vnode_check_signature`**: Kod koji poziva XNU da proveri potpis koda koristeći prava, trust cache i `amfid`
- &#x20;**`proc_check_run_cs_invalid`**: Presreće `ptrace()` pozive (`PT_ATTACH` i `PT_TRACE_ME`). Proverava za bilo koje od prava `get-task-allow`, `run-invalid-allow` i `run-unsigned-code` i ako nijedno, proverava da li je debagovanje dozvoljeno.
- **`proc_check_map_anon`**: Ako je mmap pozvan sa oznakom **`MAP_JIT`**, AMFI će proveriti `dynamic-codesigning` pravo.

`AMFI.kext` takođe izlaže API za druge kernel ekstenzije, i moguće je pronaći njegove zavisnosti sa:
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

Ovo je demon koji radi u korisničkom režimu i koji će `AMFI.kext` koristiti za proveru potpisa koda u korisničkom režimu.\
Da bi `AMFI.kext` komunicirao sa demonom, koristi mach poruke preko porta `HOST_AMFID_PORT`, koji je poseban port `18`.

Napomena: u macOS-u više nije moguće da root procesi preuzmu posebne portove jer su zaštićeni `SIP`-om i samo launchd može da ih dobije. U iOS-u se proverava da proces koji šalje odgovor ima hardkodovani CDHash `amfid`.

Moguće je videti kada se `amfid` traži da proveri binarni fajl i odgovor na to tako što se debaguje i postavi breakpoint u `mach_msg`.

Kada se poruka primi preko posebnog porta, **MIG** se koristi za slanje svake funkcije funkciji koju poziva. Glavne funkcije su obrnute i objašnjene unutar knjige.

## Provisioning Profiles

Provisioning profil se može koristiti za potpisivanje koda. Postoje **Developer** profili koji se mogu koristiti za potpisivanje koda i testiranje, i **Enterprise** profili koji se mogu koristiti na svim uređajima.

Nakon što je aplikacija poslata u Apple Store, ako je odobrena, potpisuje je Apple i provisioning profil više nije potreban.

Profil obično koristi ekstenziju `.mobileprovision` ili `.provisionprofile` i može se dumpovati sa:
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
Iako se ponekad nazivaju sertifikovanim, ovi profili za postavljanje imaju više od sertifikata:

- **AppIDName:** Identifikator aplikacije
- **AppleInternalProfile**: Oznaka da je ovo Apple interni profil
- **ApplicationIdentifierPrefix**: Prependovan na AppIDName (isto kao TeamIdentifier)
- **CreationDate**: Datum u formatu `YYYY-MM-DDTHH:mm:ssZ`
- **DeveloperCertificates**: Niz (obično jedan) sertifikat(a), kodiran kao Base64 podaci
- **Entitlements**: Prava dozvoljena sa pravima za ovaj profil
- **ExpirationDate**: Datum isteka u formatu `YYYY-MM-DDTHH:mm:ssZ`
- **Name**: Ime aplikacije, isto kao AppIDName
- **ProvisionedDevices**: Niz (za sertifikate programera) UDID-ova za koje je ovaj profil važeći
- **ProvisionsAllDevices**: Boolean (true za preduzetničke sertifikate)
- **TeamIdentifier**: Niz (obično jedan) alfanumeričkih stringova koji se koriste za identifikaciju programera u svrhe interakcije između aplikacija
- **TeamName**: Ime koje je lako čitljivo i koristi se za identifikaciju programera
- **TimeToLive**: Važenje (u danima) sertifikata
- **UUID**: Univerzalno jedinstveni identifikator za ovaj profil
- **Version**: Trenutno postavljeno na 1

Napomena da će unos prava sadržati ograničen skup prava i da će profil za postavljanje moći da dodeli samo ta specifična prava kako bi se sprečilo dodeljivanje Apple privatnih prava.

Napomena da se profili obično nalaze u `/var/MobileDeviceProvisioningProfiles` i moguće je proveriti ih sa **`security cms -D -i /path/to/profile`**

## **libmis.dyld**

Ovo je spoljašnja biblioteka koju `amfid` poziva kako bi pitao da li treba da dozvoli nešto ili ne. Ovo je istorijski zloupotrebljavano u jailbreak-u pokretanjem verzije sa backdoor-om koja bi dozvolila sve.

U macOS-u ovo se nalazi unutar `MobileDevice.framework`.

## AMFI Trust Caches

iOS AMFI održava listu poznatih hash-eva koji su potpisani ad-hoc, nazvanu **Trust Cache** i nalazi se u `__TEXT.__const` sekciji kext-a. Napomena da je u vrlo specifičnim i osetljivim operacijama moguće proširiti ovu Trust Cache sa spoljnim fajlom.

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)

{{#include ../../../banners/hacktricks-training.md}}
