# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext and amfid

Dit fokus op die afdwing van die integriteit van die code wat op die stelsel loop en verskaf die logika agter XNU se code signature verification. Dit kan ook entitlements nagaan en ander sensitiewe take hanteer, soos om debugging toe te laat of task ports te verkry.

Verder, vir sommige operasies verkies die kext om die user space lopende daemon `/usr/libexec/amfid` te kontak. Hierdie trust relationship is in verskeie jailbreaks misbruik.

Op onlangse macOS-weergawes word AMFI nie meer gerieflik as 'n selfstandige on-disk kext blootgestel nie, so reversing beteken gewoonlik om vanaf die **kernelcache** of 'n **KDK** te werk in plaas van om `/System/Library/Extensions` te blaai.

AMFI gebruik **MACF** policies en registreer sy hooks op die oomblik wat dit begin. Ook kan die verhoed van laai of die unload daarvan 'n kernel panic veroorsaak. Daar is egter sommige boot arguments wat toelaat om AMFI te debilitate:

- `amfi_unrestricted_task_for_pid`: Laat task_for_pid toe sonder die vereiste entitlements
- `amfi_allow_any_signature`: Laat enige code signature toe
- `cs_enforcement_disable`: Stelselwye argument wat gebruik word om code signing enforcement te deaktiveer
- `amfi_prevent_old_entitled_platform_binaries`: Maak platform binaries met entitlements ongeldig
- `amfi_get_out_of_my_way`: Deaktiveer amfi heeltemal

Dit is sommige van die MACF policies wat dit registreer:

- **`cred_check_label_update_execve:`** Label update sal uitgevoer word en 1 terugkeer
- **`cred_label_associate`**: Werk AMFI se mac label slot by met label
- **`cred_label_destroy`**: Verwyder AMFI se mac label slot
- **`cred_label_init`**: Verskuif 0 in AMFI se mac label slot
- **`cred_label_update_execve`:** Dit kontroleer die entitlements van die proses om te sien of dit toegelaat moet word om die labels te wysig.
- **`file_check_mmap`:** Dit kontroleer of mmap geheue verkry en dit as executable stel. In daardie geval kontroleer dit of library validation nodig is en indien wel, roep dit die library validation function aan.
- **`file_check_library_validation`**: Roep die library validation function aan wat onder andere kontroleer of 'n platform binary 'n ander platform binary laai of of die proses en die nuutgelaaide file dieselfde TeamID het. Sekere entitlements sal ook toelaat om enige library te laai.
- **`policy_initbsd`**: Stel vertroude NVRAM Keys op
- **`policy_syscall`**: Dit kontroleer DYLD policies soos of die binary onbeperkte segments het, of dit env vars moet toelaat... dit word ook geroep wanneer 'n proses via `amfi_check_dyld_policy_self()` begin word.
- **`proc_check_inherit_ipc_ports`**: Dit kontroleer of, wanneer 'n proses 'n nuwe binary uitvoer, ander prosesse met SEND rights oor die task port van die proses dit moet behou of nie. Platform binaries word toegelaat, `get-task-allow` entitled laat dit toe, `task_for_pid-allow` entitles word toegelaat en binaries met dieselfde TeamID.
- **`proc_check_expose_task`**: dwing entitlements af
- **`amfi_exc_action_check_exception_send`**: 'n exception message word na debugger gestuur
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: Label lifecycle tydens exception handling (debugging)
- **`proc_check_get_task`**: Kontroleer entitlements soos `get-task-allow` wat ander prosesse toelaat om die tasks port te kry en `task_for_pid-allow`, wat die proses toelaat om ander prosesse se tasks ports te kry. As nie een van dié bestaan nie, roep dit op na `amfid permitunrestricteddebugging` om te kontroleer of dit toegelaat is.
- **`proc_check_mprotect`**: Weier as `mprotect` geroep word met die vlag `VM_PROT_TRUSTED` wat aandui dat die region behandel moet word asof dit 'n geldige code signature het.
- **`vnode_check_exec`**: Word geroep wanneer executable files in memory gelaai word en stel `cs_hard | cs_kill`, wat die proses sal doodmaak as enige van die pages ongeldig word
- **`vnode_check_getextattr`**: MacOS: Kontroleer `com.apple.root.installed` en `isVnodeQuarantined()`
- **`vnode_check_setextattr`**: Soos get + com.apple.private.allow-bless en internal-installer-equivalent entitlement
- **`vnode_check_signature`**: Code wat XNU aanroep om die code signature te kontroleer met behulp van entitlements, trust cache en `amfid`
- **`proc_check_run_cs_invalid`**: Dit onderskep `ptrace()` calls (`PT_ATTACH` en `PT_TRACE_ME`). Dit kontroleer vir enige van die entitlements `get-task-allow`, `run-invalid-allow` en `run-unsigned-code` en as geeneen nie, kontroleer dit of debugging toegelaat word.
- **`proc_check_map_anon`**: As mmap geroep word met die **`MAP_JIT`** vlag, sal AMFI die `dynamic-codesigning` entitlement kontroleer.

`AMFI.kext` stel ook 'n API bloot vir ander kernel extensions, en dit is moontlik om sy dependencies te vind met:
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

Dit is die user mode draaiende daemon wat `AMFI.kext` sal gebruik om te kyk vir code signatures in user mode.\
Vir `AMFI.kext` om met die daemon te kommunikeer, gebruik dit mach messages oor die poort `HOST_AMFID_PORT` wat die spesiale poort `18` is.

Let daarop dat dit in macOS nie meer moontlik is vir root processes om special ports te hijack nie, aangesien hulle deur `SIP` beskerm word en slegs launchd hulle kan kry. In iOS word gekontroleer dat die process wat die response terugstuur die CDHash hardcoded van `amfid` het.

Dit is moontlik om te sien wanneer `amfid` gevra word om 'n binary te check en die response daarvan deur dit te debug en 'n breakpoint in `mach_msg` te stel.

Sodra 'n message via die spesiale poort ontvang is, word **MIG** gebruik om elke function te stuur na die function waarna dit roep. Die hoof functions is in die boek reversed en verduidelik.

### DYLD policy and library validation

Onlangse `dyld` weergawes roep `amfi_check_dyld_policy_self()` baie vroeg aan vanaf `configureProcessRestrictions()` om AMFI te vra of die process `DYLD_*` path variables, interposing, fallback paths, embedded variables mag gebruik, of mislukte library insertion kan verdra. Daarom, wanneer 'n injection surface getriage word, is dit nie genoeg om net Mach-O load commands te inspekteer nie: jy moet ook die entitlements en runtime flags inspekteer wat AMFI in `dyld` policy sal vertaal.

'n Praktiese triage loop is:
```bash
BIN=/path/to/app/Contents/MacOS/binary

# Interesting AMFI-related entitlements
codesign -d --entitlements :- "$BIN" 2>&1 | \
egrep "disable-library-validation|clear-library-validation|allow-dyld-environment-variables|allow-jit|allow-unsigned-executable-memory|disable-executable-page-protection|get-task-allow"

# Runtime flags / TeamID / hardened-runtime metadata
codesign -dvvv "$BIN" 2>&1 | egrep "TeamIdentifier=|Runtime Version|flags="
```
Op moderne macOS dra baie Apple-binaries nie meer direk `com.apple.security.cs.disable-library-validation` nie en word in plaas daarvan met `com.apple.private.security.clear-library-validation` gestuur. In daardie geval is library validation nie by `execve`-tyd gedeaktiveer nie: die proses moet `csops(..., CS_OPS_CLEAR_LV, ...)` op homself roep, en XNU laat daardie operasie net toe op die roepende proses wanneer die entitlement teenwoordig is. Vanuit ’n offensiewe perspektief is dit belangrik omdat ’n teiken eers injectable kan word **nadat** dit die kodepad bereik wat LV uitdruklik skoonmaak (byvoorbeeld, kort voor dit opsionele plugins laai).

## Provisioning Profiles

’n provisioning profile kan gebruik word om code te sign. Daar is **Developer** profiles wat gebruik kan word om code te sign en dit te toets, en **Enterprise** profiles wat op al devices gebruik kan word.

Nadat ’n App na die Apple Store ingedien is, as dit goedgekeur word, word dit deur Apple gesign en die provisioning profile is nie meer nodig nie.

’n profile gebruik gewoonlik die extension `.mobileprovision` of `.provisionprofile` en kan gedump word met:
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
Alhoewel soms as gesertifiseer verwys, het hierdie provisioning profiles meer as ’n certificate:

- **AppIDName:** Die Application Identifier
- **AppleInternalProfile**: Dui aan dat dit ’n Apple Internal profile is
- **ApplicationIdentifierPrefix**: Voorafgeplaas by AppIDName (dieselfde as TeamIdentifier)
- **CreationDate**: Datum in `YYYY-MM-DDTHH:mm:ssZ` formaat
- **DeveloperCertificates**: ’n Skikking van (gewoonlik een) certificate(s), gekodeer as Base64 data
- **Entitlements**: Die entitlements wat toegelaat word met entitlements vir hierdie profile
- **ExpirationDate**: Vervaldatum in `YYYY-MM-DDTHH:mm:ssZ` formaat
- **Name**: Die Application Name, dieselfde as AppIDName
- **ProvisionedDevices**: ’n Skikking (vir developer certificates) van UDIDs waarvoor hierdie profile geldig is
- **ProvisionsAllDevices**: ’n Boolean (true vir enterprise certificates)
- **TeamIdentifier**: ’n Skikking van (gewoonlik een) alfanumeriese string(s) wat gebruik word om die developer te identifiseer vir inter-app interaction doeleindes
- **TeamName**: ’n Mens-lesbare naam wat gebruik word om die developer te identifiseer
- **TimeToLive**: Geldigheid (in dae) van die certificate
- **UUID**: ’n Universally Unique Identifier vir hierdie profile
- **Version**: Tans ingestel op 1

Let daarop dat die entitlements entry ’n beperkte stel entitlements sal bevat en die provisioning profile sal net in staat wees om daardie spesifieke entitlements toe te ken om te verhinder dat Apple private entitlements gegee word.

Let daarop dat profiles gewoonlik in `/var/MobileDeviceProvisioningProfiles` geleë is en dit moontlik is om hulle met **`security cms -D -i /path/to/profile`** na te gaan

## **libmis.dylib**

Dit is die eksterne library wat `amfid` aanroep om te vra of dit iets moet toelaat of nie. Dit is histories misbruik in jailbreaking deur ’n backdoored weergawe daarvan te laat loop wat alles sou toelaat.

In macOS is dit binne `MobileDevice.framework`.

## AMFI Trust Caches

Trust caches is nie net ’n iOS-konsep nie. Op moderne macOS, veral op **Apple silicon**, is die static trust cache en loadable trust caches deel van die Secure Boot chain. Wanneer ’n Mach-O se **CodeDirectory hash** daar teenwoordig is, kan AMFI dit **platform privilege** gee sonder om verdere authenticity checks by launch time uit te voer. Dit beteken ook Apple kan platform binaries aan ’n spesifieke OS version vaspen en keer dat ouer Apple-signed binaries op nuwer systems hergebruik word.

Op onlangse macOS releases is trust-cache metadata ook aan **launch constraints** gekoppel, so gekopieerde system apps en binaries wat vanaf die verkeerde parent/location begin word, kan deur AMFI verwerp word, selfs al is hulle steeds Apple-signed. Die gedetailleerde extraction en reversing workflow word behandel in:

{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

In iOS en jailbreak research sal jy steeds die tradisionele model van **loadable trust caches** vind wat gebruik word om ad-hoc signed binaries te whitelist.

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)
- [https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/)
- [https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web](https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web)

{{#include ../../../banners/hacktricks-training.md}}
