# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext en amfid

Dit fokus op die afdwinging van die integriteit van die kode wat op die stelsel loop en bied die logika agter XNU se kodehandtekeningverifikasie. Dit is ook in staat om regte te kontroleer en ander sensitiewe take te hanteer, soos om foutopsporing toe te laat of taakpoorte te verkry.

Boonop verkies die kext om vir sommige operasies die gebruikersruimte wat die daemon `/usr/libexec/amfid` uitvoer, te kontak. Hierdie vertrouensverhouding is in verskeie jailbreaks misbruik.

AMFI gebruik **MACF** beleide en registreer sy haakplekke die oomblik wat dit begin. Ook, om sy laai of ontlaai te verhoed, kan 'n kernpaniek veroorsaak. Daar is egter 'n paar opstartargumente wat AMFI kan verlam:

- `amfi_unrestricted_task_for_pid`: Laat task_for_pid toe sonder vereiste regte
- `amfi_allow_any_signature`: Laat enige kodehandtekening toe
- `cs_enforcement_disable`: Stelselswye argument wat gebruik word om kodehandtekening afdwinging te deaktiveer
- `amfi_prevent_old_entitled_platform_binaries`: Ongeldig platformbinaries met regte
- `amfi_get_out_of_my_way`: Deaktiveer amfi heeltemal

Hierdie is 'n paar van die MACF beleide wat dit registreer:

- **`cred_check_label_update_execve:`** Etiketopdatering sal uitgevoer word en 1 teruggee
- **`cred_label_associate`**: Werk AMFI se mac etiketgleuf met etiket op
- **`cred_label_destroy`**: Verwyder AMFI se mac etiketgleuf
- **`cred_label_init`**: Beweeg 0 in AMFI se mac etiketgleuf
- **`cred_label_update_execve`:** Dit kontroleer die regte van die proses om te sien of dit toegelaat moet word om die etikette te wysig.
- **`file_check_mmap`:** Dit kontroleer of mmap geheue verkry en dit as uitvoerbaar stel. In daardie geval kontroleer dit of biblioteekvalidasie nodig is en indien wel, roep dit die biblioteekvalidasiefunksie aan.
- **`file_check_library_validation`**: Roep die biblioteekvalidasiefunksie aan wat onder andere kontroleer of 'n platformbinarie 'n ander platformbinarie laai of of die proses en die nuwe gelaaide lêer dieselfde TeamID het. Sekere regte sal ook toelaat om enige biblioteek te laai.
- **`policy_initbsd`**: Stel vertroude NVRAM-sleutels op
- **`policy_syscall`**: Dit kontroleer DYLD-beleide soos of die binarie onbeperkte segmente het, of dit omgewingsveranderlikes moet toelaat... dit word ook genoem wanneer 'n proses via `amfi_check_dyld_policy_self()` begin word.
- **`proc_check_inherit_ipc_ports`**: Dit kontroleer of wanneer 'n proses 'n nuwe binarie uitvoer, ander prosesse met SEND-regte oor die taakpoort van die proses dit moet hou of nie. Platformbinaries is toegelaat, `get-task-allow` regte laat dit toe, `task_for_pid-allow` regte is toegelaat en binaries met dieselfde TeamID.
- **`proc_check_expose_task`**: afdwing regte
- **`amfi_exc_action_check_exception_send`**: 'n Uitsonderingboodskap word na die foutopsporing gestuur
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: Etiketlewe tydens uitsonderinghantering (foutopsporing)
- **`proc_check_get_task`**: Kontroleer regte soos `get-task-allow` wat ander prosesse toelaat om die taakpoort te verkry en `task_for_pid-allow`, wat die proses toelaat om ander prosesse se taakpoorte te verkry. As geen van daardie, roep dit `amfid permitunrestricteddebugging` aan om te kontroleer of dit toegelaat word.
- **`proc_check_mprotect`**: Weier as `mprotect` met die vlag `VM_PROT_TRUSTED` aangeroep word wat aandui dat die streek asof dit 'n geldige kodehandtekening het, behandel moet word.
- **`vnode_check_exec`**: Word aangeroep wanneer uitvoerbare lêers in geheue gelaai word en stel `cs_hard | cs_kill` wat die proses sal doodmaak as enige van die bladsye ongeldig word
- **`vnode_check_getextattr`**: MacOS: Kontroleer `com.apple.root.installed` en `isVnodeQuarantined()`
- **`vnode_check_setextattr`**: Soos kry + com.apple.private.allow-bless en interne-installer-ekwivalente regte
- &#x20;**`vnode_check_signature`**: Kode wat XNU aanroep om die kodehandtekening te kontroleer met behulp van regte, vertrou cache en `amfid`
- &#x20;**`proc_check_run_cs_invalid`**: Dit onderskep `ptrace()` aanroepe (`PT_ATTACH` en `PT_TRACE_ME`). Dit kontroleer vir enige van die regte `get-task-allow`, `run-invalid-allow` en `run-unsigned-code` en as geen, kontroleer dit of foutopsporing toegelaat word.
- **`proc_check_map_anon`**: As mmap met die **`MAP_JIT`** vlag aangeroep word, sal AMFI die `dynamic-codesigning` regte kontroleer.

`AMFI.kext` stel ook 'n API vir ander kernuitbreidings bloot, en dit is moontlik om sy afhanklikhede te vind met:
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

Dit is die gebruikersmodus wat daemons wat `AMFI.kext` sal gebruik om kode-handtekeninge in gebruikersmodus te kontroleer.\
Vir `AMFI.kext` om met die daemon te kommunikeer, gebruik dit mach-boodskappe oor die poort `HOST_AMFID_PORT` wat die spesiale poort `18` is.

Let daarop dat dit in macOS nie meer moontlik is vir root prosesse om spesiale poorte te kap nie, aangesien dit deur `SIP` beskerm word en slegs launchd dit kan verkry. In iOS word dit nagegaan dat die proses wat die antwoord terugstuur die CDHash van `amfid` hardgecodeer het.

Dit is moontlik om te sien wanneer `amfid` versoek word om 'n binêre te kontroleer en die antwoord daarvan deur dit te debugeer en 'n breekpunt in `mach_msg` te stel.

Sodra 'n boodskap ontvang word via die spesiale poort, word **MIG** gebruik om elke funksie na die funksie wat dit aanroep te stuur. Die hooffunksies is omgekeerd en binne die boek verduidelik.

## Provisioning Profiles

'n Provisioning-profiel kan gebruik word om kode te teken. Daar is **Developer** profiele wat gebruik kan word om kode te teken en dit te toets, en **Enterprise** profiele wat in alle toestelle gebruik kan word.

Nadat 'n app by die Apple Store ingedien is, indien goedgekeur, word dit deur Apple geteken en is die provisioning-profiel nie meer nodig nie.

'n Profiel gebruik gewoonlik die uitbreiding `.mobileprovision` of `.provisionprofile` en kan gedump word met:
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
Alhoewel dit soms as gesertifiseer verwys word, het hierdie voorsieningsprofiele meer as 'n sertifikaat:

- **AppIDName:** Die Aansoek Identifiseerder
- **AppleInternalProfile**: Dui dit aan as 'n Apple Interne profiel
- **ApplicationIdentifierPrefix**: Voorafgegaan aan AppIDName (dieselfde as TeamIdentifier)
- **CreationDate**: Datum in `YYYY-MM-DDTHH:mm:ssZ` formaat
- **DeveloperCertificates**: 'n Array van (gewoonlik een) sertifikaat(e), gekodeer as Base64 data
- **Entitlements**: Die regte wat toegelaat word met regte vir hierdie profiel
- **ExpirationDate**: Vervaldatum in `YYYY-MM-DDTHH:mm:ssZ` formaat
- **Name**: Die Aansoek Naam, dieselfde as AppIDName
- **ProvisionedDevices**: 'n Array (vir ontwikkelaar sertifikate) van UDIDs waarvoor hierdie profiel geldig is
- **ProvisionsAllDevices**: 'n boolean (waar vir ondernemingssertifikate)
- **TeamIdentifier**: 'n Array van (gewoonlik een) alfanumeriese string(e) wat gebruik word om die ontwikkelaar te identifiseer vir inter-app interaksie doeleindes
- **TeamName**: 'n Menslike leesbare naam wat gebruik word om die ontwikkelaar te identifiseer
- **TimeToLive**: Geldigheid (in dae) van die sertifikaat
- **UUID**: 'n Universeel Unieke Identifiseerder vir hierdie profiel
- **Version**: Huidiglik ingestel op 1

Let daarop dat die regte inskrywing 'n beperkte stel regte sal bevat en die voorsieningsprofiel slegs daardie spesifieke regte kan gee om te voorkom dat Apple private regte gee.

Let daarop dat profiele gewoonlik geleë is in `/var/MobileDeviceProvisioningProfiles` en dit moontlik is om dit te kontroleer met **`security cms -D -i /path/to/profile`**

## **libmis.dyld**

Dit is die eksterne biblioteek wat `amfid` aanroep om te vra of dit iets moet toelaat of nie. Dit is histories misbruik in jailbreaking deur 'n backdoored weergawe daarvan te loop wat alles sou toelaat.

In macOS is dit binne `MobileDevice.framework`.

## AMFI Trust Caches

iOS AMFI hou 'n lys van bekende hashes wat ad-hoc gesertifiseer is, genoem die **Trust Cache** en gevind in die kext se `__TEXT.__const` afdeling. Let daarop dat dit in baie spesifieke en sensitiewe operasies moontlik is om hierdie Trust Cache met 'n eksterne lêer uit te brei.

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)

{{#include ../../../banners/hacktricks-training.md}}
