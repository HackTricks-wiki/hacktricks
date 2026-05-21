# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext i amfid

Fokusira se na primenu integriteta koda koji se izvršava na sistemu, obezbeđujući logiku iza XNU-ove provere code signature. Takođe može da proverava entitlements i da rukuje drugim osetljivim zadacima kao što su dozvoljavanje debugging-a ili dobijanje task ports.

Pored toga, za neke operacije, kext preferira da kontaktira daemon u user space-u `/usr/libexec/amfid`. Ovaj trust relationship je zloupotrebljen u nekoliko jailbreaks.

Na novijim verzijama macOS-a, AMFI više nije zgodno izložen kao samostalni kext na disku, pa reverse obično znači rad iz **kernelcache** ili **KDK** umesto pregledanja `/System/Library/Extensions`.

AMFI koristi **MACF** policies i registruje svoje hook-ove čim se pokrene. Takođe, sprečavanje njegovog učitavanja ili njegovo uklanjanje može da izazove kernel panic. Međutim, postoje neki boot arguments koji omogućavaju da se AMFI oslabi:

- `amfi_unrestricted_task_for_pid`: Dozvoljava da `task_for_pid` bude dozvoljen bez potrebnih entitlements
- `amfi_allow_any_signature`: Dozvoljava bilo koji code signature
- `cs_enforcement_disable`: Argument za ceo sistem koji se koristi da isključi code signing enforcement
- `amfi_prevent_old_entitled_platform_binaries`: Uklanja validnost platform binaries sa entitlements
- `amfi_get_out_of_my_way`: Potpuno isključuje amfi

Ovo su neke od MACF policies koje registruje:

- **`cred_check_label_update_execve:`** Ažuriranje label-a će biti izvršeno i vratiće 1
- **`cred_label_associate`**: Ažurira AMFI-jevo mac label polje sa label-om
- **`cred_label_destroy`**: Uklanja AMFI-jevo mac label polje
- **`cred_label_init`**: Postavlja 0 u AMFI-jevo mac label polje
- **`cred_label_update_execve`:** Proverava entitlements procesa da vidi da li treba da bude dozvoljeno da menja label-e.
- **`file_check_mmap`:** Proverava da li `mmap` dobija memoriju i postavlja je kao izvršnu. U tom slučaju proverava da li je potrebna library validation i, ako jeste, poziva funkciju za library validation.
- **`file_check_library_validation`**: Poziva funkciju za library validation koja, između ostalog, proverava da li platform binary učitava drugi platform binary ili da li proces i novoučitana datoteka imaju isti TeamID. Određeni entitlements će takođe dozvoliti učitavanje bilo koje biblioteke.
- **`policy_initbsd`**: Podešava trusted NVRAM Keys
- **`policy_syscall`**: Proverava DYLD policies kao što su da li binary ima unrestricted segments, da li treba dozvoliti env vars... ovo se takođe poziva kada se proces pokreće preko `amfi_check_dyld_policy_self()`.
- **`proc_check_inherit_ipc_ports`**: Proverava da li, kada proces izvrši novi binary, drugi procesi sa SEND pravima nad task port-om tog procesa treba da ih zadrže ili ne. Platform binaries su dozvoljeni, `get-task-allow` entitlement to dozvoljava, `task_for_pid-allow` entitlements su dozvoljeni i binaries sa istim TeamID-jem.
- **`proc_check_expose_task`**: Primenjuje entitlements
- **`amfi_exc_action_check_exception_send`**: Poruka o izuzetku se šalje debugger-u
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: Životni ciklus label-a tokom obrade izuzetka (debugging)
- **`proc_check_get_task`**: Proverava entitlements kao što je `get-task-allow` koji omogućava drugim procesima da dobiju task port, i `task_for_pid-allow`, koji omogućavaju procesu da dobije task ports drugih procesa. Ako nijedan od njih ne važi, poziva `amfid permitunrestricteddebugging` da proveri da li je dozvoljeno.
- **`proc_check_mprotect`**: Zabranjuje ako se `mprotect` pozove sa flag-om `VM_PROT_TRUSTED` koji ukazuje da region mora da se tretira kao da ima validan code signature.
- **`vnode_check_exec`**: Poziva se kada se izvršne datoteke učitavaju u memoriju i postavlja `cs_hard | cs_kill`, što će ubiti proces ako bilo koja od stranica postane nevažeća
- **`vnode_check_getextattr`**: MacOS: Proverava `com.apple.root.installed` i `isVnodeQuarantined()`
- **`vnode_check_setextattr`**: Kao get + com.apple.private.allow-bless i internal-installer-equivalent entitlement
- **`vnode_check_signature`**: Kod koji poziva XNU da proveri code signature koristeći entitlements, trust cache i `amfid`
- **`proc_check_run_cs_invalid`**: Presreće `ptrace()` pozive (`PT_ATTACH` i `PT_TRACE_ME`). Proverava bilo koji od entitlements `get-task-allow`, `run-invalid-allow` i `run-unsigned-code`, a ako nijedan ne postoji, proverava da li je debugging dozvoljen.
- **`proc_check_map_anon`**: Ako se `mmap` pozove sa **`MAP_JIT`** flag-om, AMFI će proveriti `dynamic-codesigning` entitlement.

`AMFI.kext` takođe izlaže API za druge kernel extensions, i moguće je pronaći njegove dependencies sa:
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

Ovo je daemon u user mode-u koji `AMFI.kext` koristi za proveru code signatures u user mode-u.\
Da bi `AMFI.kext` komunicirao sa daemon-om, koristi mach messages preko porta `HOST_AMFID_PORT`, koji je specijalni port `18`.

Imajte na umu da u macOS-u više nije moguće da root procesi hijack-uju specijalne portove jer su zaštićeni pomoću `SIP` i samo `launchd` može da ih dobije. U iOS-u se proverava da proces koji šalje odgovor ima hardcoded CDHash od `amfid`.

Moguće je videti kada se od `amfid` traži da proveri binary i njegov odgovor tako što ga debug-ujete i postavite breakpoint u `mach_msg`.

Kada se poruka primi preko specijalnog porta, koristi se **MIG** da pošalje svaku funkciju funkciji koju poziva. Glavne funkcije su reverse-ovane i objašnjene unutar knjige.

### DYLD policy and library validation

Novije `dyld` verzije veoma rano pozivaju `amfi_check_dyld_policy_self()` iz `configureProcessRestrictions()` da pitaju AMFI da li proces sme da koristi `DYLD_*` path variables, interposing, fallback paths, embedded variables, ili da toleriše neuspeli library insertion. Zato, pri triage-u injection surface-a, nije dovoljno da proverite samo Mach-O load commands: potrebno je da proverite i entitlements i runtime flags koje će AMFI prevesti u `dyld` policy.

Praktična triage petlja je:
```bash
BIN=/path/to/app/Contents/MacOS/binary

# Interesting AMFI-related entitlements
codesign -d --entitlements :- "$BIN" 2>&1 | \
egrep "disable-library-validation|clear-library-validation|allow-dyld-environment-variables|allow-jit|allow-unsigned-executable-memory|disable-executable-page-protection|get-task-allow"

# Runtime flags / TeamID / hardened-runtime metadata
codesign -dvvv "$BIN" 2>&1 | egrep "TeamIdentifier=|Runtime Version|flags="
```
Na modernom macOS-u mnogi Apple binari više ne nose `com.apple.security.cs.disable-library-validation` direktno, već umesto toga koriste `com.apple.private.security.clear-library-validation`. U tom slučaju library validation nije onemogućen u trenutku `execve`: proces mora da pozove `csops(..., CS_OPS_CLEAR_LV, ...)` na samom sebi, a XNU dozvoljava tu operaciju samo na pozivajućem procesu kada je entitlement prisutan. Sa ofanzivne perspektive, ovo je važno jer meta može postati injektabilna tek **nakon** što dođe do code path-a koji eksplicitno čisti LV (na primer, neposredno pre učitavanja opcionih plugins).

## Provisioning Profiles

Provisioning profile može da se koristi za potpisivanje code-a. Postoje **Developer** profile koji mogu da se koriste za potpisivanje code-a i testiranje, i **Enterprise** profile koji mogu da se koriste na svim uređajima.

Nakon što se App pošalje u Apple Store, ako bude odobren, potpisuje ga Apple i provisioning profile više nije potreban.

Profile obično koristi ekstenziju `.mobileprovision` ili `.provisionprofile` i može da se dump-uje pomoću:
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
Iako se ponekad nazivaju certificated, ovi provisioning profiles imaju više od sertifikata:

- **AppIDName:** Identifikator aplikacije
- **AppleInternalProfile**: Označava ovo kao Apple Internal profile
- **ApplicationIdentifierPrefix**: Dodaje se ispred AppIDName (isto kao TeamIdentifier)
- **CreationDate**: Datum u formatu `YYYY-MM-DDTHH:mm:ssZ`
- **DeveloperCertificates**: Niz (obično jednog) sertifikata, kodiranih kao Base64 data
- **Entitlements**: Entitlements dozvoljeni sa entitlements za ovaj profile
- **ExpirationDate**: Datum isteka u formatu `YYYY-MM-DDTHH:mm:ssZ`
- **Name**: Naziv aplikacije, isto kao AppIDName
- **ProvisionedDevices**: Niz (za developer certificates) UDID-ova za koje je ovaj profile validan
- **ProvisionsAllDevices**: Boolean (true za enterprise certificates)
- **TeamIdentifier**: Niz (obično jednog) alfanumeričkog stringa koji se koristi za identifikaciju developera u svrhe inter-app interaction
- **TeamName**: Čitljivo ime koje se koristi za identifikaciju developera
- **TimeToLive**: Validnost (u danima) sertifikata
- **UUID**: Universally Unique Identifier za ovaj profile
- **Version**: Trenutno podešeno na 1

Napomena da će entitlements entry sadržati ograničen skup entitlements i provisioning profile će moći da dodeli samo te specifične entitlements kako bi se sprečilo davanje Apple private entitlements.

Napomena da se profiles obično nalaze u `/var/MobileDeviceProvisioningProfiles` i moguće ih je proveriti sa **`security cms -D -i /path/to/profile`**

## **libmis.dylib**

Ovo je eksterna biblioteka koju `amfid` poziva da pita da li nešto treba da dozvoli ili ne. Ovo je istorijski zloupotrebljavano u jailbreaking-u pokretanjem backdoored verzije iste koja bi dozvolila sve.

U macOS ovo je unutar `MobileDevice.framework`.

## AMFI Trust Caches

Trust caches nisu samo iOS koncept. Na modernom macOS-u, posebno na **Apple silicon**, static trust cache i loadable trust caches su deo Secure Boot lanca. Kada je **CodeDirectory hash** nekog Mach-O-a prisutan tamo, AMFI može da mu dodeli **platform privilege** bez dodatnih autentikacionih provera pri launch time. Ovo takođe znači da Apple može da zaključa platform binaries na određenu OS verziju i spreči da se stariji Apple-signed binaries replay-uju na novijim sistemima.

Na novijim macOS izdanjima, trust-cache metadata je takođe vezana za **launch constraints**, tako da se kopirane system apps i binaries pokrenute iz pogrešnog parent/location mogu biti odbijene od strane AMFI čak i ako su i dalje Apple-signed. Detaljan workflow za extraction i reversing je pokriven u:

{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

U iOS i jailbreak research-u i dalje ćete pronaći tradicionalni model **loadable trust caches** koji se koristi za whitelisting ad-hoc signed binaries.

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)
- [https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/)
- [https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web](https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web)

{{#include ../../../banners/hacktricks-training.md}}
