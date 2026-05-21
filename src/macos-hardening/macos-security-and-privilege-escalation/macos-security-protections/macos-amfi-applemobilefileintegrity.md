# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext and amfid

Dit fokus op die afdwinging van die integriteit van die code wat op die stelsel loop deur die logika agter XNU se code signature verification te verskaf. Dit kan ook entitlements kontroleer en ander sensitiewe take hanteer soos om debugging toe te laat of task ports te bekom.

Verder, vir sekere operasies verkies die kext om die user space lopende daemon `/usr/libexec/amfid` te kontak. Hierdie trust relationship is in verskeie jailbreaks misbruik.

Op onlangse macOS-weergawes is AMFI nie meer gerieflik blootgestel as 'n standalone on-disk kext nie, so reversing beteken gewoonlik om vanaf die **kernelcache** of 'n **KDK** te werk in plaas daarvan om deur `/System/Library/Extensions` te blaai.

AMFI gebruik **MACF** policies en registreer sy hooks die oomblik wat dit begin. Ook kan die voorkoming van sy laai of die unload daarvan 'n kernel panic veroorsaak. Daar is egter sommige boot arguments wat toelaat om AMFI te debilitate:

- `amfi_unrestricted_task_for_pid`: Laat task_for_pid toe sonder vereiste entitlements
- `amfi_allow_any_signature`: Laat enige code signature toe
- `cs_enforcement_disable`: Stelselwye argument wat gebruik word om code signing enforcement te deaktiveer
- `amfi_prevent_old_entitled_platform_binaries`: Void platform binaries met entitlements
- `amfi_get_out_of_my_way`: Deaktiveer amfi heeltemal

Dit is sommige van die MACF policies wat dit registreer:

- **`cred_check_label_update_execve:`** Label update sal uitgevoer word en 1 teruggee
- **`cred_label_associate`**: Werk AMFI se mac label slot op met label
- **`cred_label_destroy`**: Verwyder AMFI se mac label slot
- **`cred_label_init`**: Skuif 0 in AMFI se mac label slot
- **`cred_label_update_execve`:** Dit kontroleer die entitlements van die proses om te sien of dit toegelaat moet word om die labels te wysig.
- **`file_check_mmap`:** Dit kontroleer of mmap geheue verkry en dit as executable stel. In daardie geval kontroleer dit of library validation nodig is en indien wel, roep dit die library validation-funksie aan.
- **`file_check_library_validation`**: Roep die library validation-funksie aan wat onder andere kontroleer of 'n platform binary 'n ander platform binary laai of of die proses en die nuutgelaaide lêer dieselfde TeamID het. Sekere entitlements sal ook toelaat om enige library te laai.
- **`policy_initbsd`**: Stel trusted NVRAM Keys op
- **`policy_syscall`**: Dit kontroleer DYLD policies soos of die binary onbeperkte segments het, of dit env vars moet toelaat... dit word ook aangeroep wanneer 'n proses via `amfi_check_dyld_policy_self()` begin word.
- **`proc_check_inherit_ipc_ports`**: Dit kontroleer of wanneer 'n proses 'n nuwe binary uitvoer ander prosesse met SEND rights oor die task port van die proses hulle moet behou of nie. Platform binaries word toegelaat, `get-task-allow` entitled laat dit toe, `task_for_pid-allow` entitles word toegelaat en binaries met dieselfde TeamID.
- **`proc_check_expose_task`**: dwing entitlements af
- **`amfi_exc_action_check_exception_send`**: 'n Exception message word aan debugger gestuur
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: Label lifecycle tydens exception handling (debugging)
- **`proc_check_get_task`**: Kontroleer entitlements soos `get-task-allow` wat ander prosesse toelaat om die tasks port te kry en `task_for_pid-allow`, wat die proses toelaat om ander prosesse se tasks ports te kry. As nie een van dié nie, roep dit op na `amfid permitunrestricteddebugging` om te kontroleer of dit toegelaat is.
- **`proc_check_mprotect`**: Weier as `mprotect` geroep word met die flag `VM_PROT_TRUSTED` wat aandui dat die region behandel moet word asof dit 'n geldige code signature het.
- **`vnode_check_exec`**: Word aangeroep wanneer executable files in memory gelaai word en stel `cs_hard | cs_kill` wat die proses sal doodmaak as enige van die pages ongeldig raak
- **`vnode_check_getextattr`**: MacOS: Kontroleer `com.apple.root.installed` en `isVnodeQuarantined()`
- **`vnode_check_setextattr`**: Soos get + com.apple.private.allow-bless en internal-installer-equivalent entitlement
- **`vnode_check_signature`**: Code wat XNU aanroep om die code signature te kontroleer deur entitlements, trust cache en `amfid`
- **`proc_check_run_cs_invalid`**: Dit onderskep `ptrace()` calls (`PT_ATTACH` en `PT_TRACE_ME`). Dit kontroleer vir enige van die entitlements `get-task-allow`, `run-invalid-allow` en `run-unsigned-code` en indien nie, kontroleer dit of debugging toegelaat word.
- **`proc_check_map_anon`**: As mmap geroep word met die **`MAP_JIT`** flag, sal AMFI die `dynamic-codesigning` entitlement kontroleer.

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
Vir `AMFI.kext` om met die daemon te kommunikeer gebruik dit mach messages oor die port `HOST_AMFID_PORT` wat die spesiale port `18` is.

Let daarop dat in macOS dit nie meer moontlik is vir root processes om special ports te hijack nie, aangesien hulle beskerm word deur `SIP` en slegs launchd hulle kan kry. In iOS word gekontroleer dat die process wat die response terugstuur die CDHash hardcoded van `amfid` het.

Dit is moontlik om te sien wanneer `amfid` versoek word om 'n binary te check en die response daarvan deur dit te debug en 'n breakpoint in `mach_msg` te stel.

Sodra 'n message via die special port ontvang word, word **MIG** gebruik om elke function te stuur na die function waarna dit roep. Die hoof functions is binne die boek reversed en verduidelik.

### DYLD policy and library validation

Onlangse `dyld` versies roep `amfi_check_dyld_policy_self()` baie vroeg vanaf `configureProcessRestrictions()` om vir AMFI te vra of die process `DYLD_*` path variables, interposing, fallback paths, embedded variables, of failed library insertion mag gebruik. Daarom, wanneer jy 'n injection surface triage, is dit nie genoeg om net Mach-O load commands te inspekteer nie: jy moet ook die entitlements en runtime flags inspekteer wat AMFI in `dyld` policy sal vertaal.

'n Praktiese triage loop is:
```bash
BIN=/path/to/app/Contents/MacOS/binary

# Interesting AMFI-related entitlements
codesign -d --entitlements :- "$BIN" 2>&1 | \
egrep "disable-library-validation|clear-library-validation|allow-dyld-environment-variables|allow-jit|allow-unsigned-executable-memory|disable-executable-page-protection|get-task-allow"

# Runtime flags / TeamID / hardened-runtime metadata
codesign -dvvv "$BIN" 2>&1 | egrep "TeamIdentifier=|Runtime Version|flags="
```
Op moderne macOS dra baie Apple-binaries nie meer direk `com.apple.security.cs.disable-library-validation` nie en word eerder met `com.apple.private.security.clear-library-validation` gestuur. In daardie geval word library validation nie by `execve`-tyd gedeaktiveer nie: die proses moet `csops(..., CS_OPS_CLEAR_LV, ...)` op homself aanroep, en XNU laat daardie operasie net toe op die roepende proses wanneer die entitlement teenwoordig is. Vanuit `n offensiewe perspektief maak dit saak omdat `n teiken eers injectable kan word **ná** dit die code path bereik wat LV eksplisiet skoonmaak (byvoorbeeld, kort voordat opsionele plugins gelaai word).

## Provisioning Profiles

`n provisioning profile kan gebruik word om code te sign. Daar is **Developer** profiles wat gebruik kan word om code te sign en dit te toets, en **Enterprise** profiles wat op alle devices gebruik kan word.

Nadat `n App by die Apple Store ingedien is, as dit goedgekeur word, word dit deur Apple gesign en die provisioning profile is nie meer nodig nie.

`n profile gebruik gewoonlik die extension `.mobileprovision` of `.provisionprofile` en kan gedump word met:
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
Alhoewel soms daarna verwys word as certificated, het hierdie provisioning profiles meer as ’n certificate:

- **AppIDName:** Die Application Identifier
- **AppleInternalProfile**: Dui hierdie aan as ’n Apple Internal profile
- **ApplicationIdentifierPrefix**: Voorvoegsel by AppIDName (dieselfde as TeamIdentifier)
- **CreationDate**: Datum in `YYYY-MM-DDTHH:mm:ssZ` formaat
- **DeveloperCertificates**: ’n Array van (gewoonlik een) certificate(s), gekodeer as Base64 data
- **Entitlements**: Die entitlements wat met entitlements vir hierdie profile toegelaat word
- **ExpirationDate**: Vervaldatum in `YYYY-MM-DDTHH:mm:ssZ` formaat
- **Name**: Die Application Name, dieselfde as AppIDName
- **ProvisionedDevices**: ’n Array (vir developer certificates) van UDIDs waarvoor hierdie profile geldig is
- **ProvisionsAllDevices**: ’n Boolean (true vir enterprise certificates)
- **TeamIdentifier**: ’n Array van (gewoonlik een) alfanumeriese string(s) wat gebruik word om die developer te identifiseer vir inter-app interaction doeleindes
- **TeamName**: ’n Mensleesbare naam wat gebruik word om die developer te identifiseer
- **TimeToLive**: Geldigheid (in dae) van die certificate
- **UUID**: ’n Universally Unique Identifier vir hierdie profile
- **Version**: Tans ingestel op 1

Let daarop dat die entitlements entry ’n beperkte stel entitlements sal bevat en dat die provisioning profile net daardie spesifieke entitlements sal kan gee om te voorkom dat Apple private entitlements gegee word.

Let daarop dat profiles gewoonlik in `/var/MobileDeviceProvisioningProfiles` geleë is en dat dit moontlik is om hulle met **`security cms -D -i /path/to/profile`** te kontroleer

## **libmis.dylib**

Dit is die external library wat `amfid` aanroep om te vra of dit iets moet toelaat of nie. Dit is histories misbruik in jailbreaking deur ’n backdoored version daarvan te laat loop wat alles sou toelaat.

In macOS is dit binne **MobileDevice.framework**.

## AMFI Trust Caches

Trust caches is nie net ’n iOS-konsep nie. Op moderne macOS, veral op **Apple silicon**, is die static trust cache en loadable trust caches deel van die Secure Boot chain. Wanneer ’n Mach-O se **CodeDirectory hash** daarteenwoordig is, kan AMFI dit **platform privilege** gee sonder om by launch time verdere authenticity checks te doen. Dit beteken ook Apple kan platform binaries aan ’n spesifieke OS version vaspen en voorkom dat ouer Apple-signed binaries op nuwer systems hergebruik word.

Op onlangse macOS releases is trust-cache metadata ook gekoppel aan **launch constraints**, so gekopieerde system apps en binaries wat vanaf die verkeerde parent/location begin word, kan deur AMFI geweier word selfs al is hulle nog Apple-signed. Die gedetailleerde extraction en reversing workflow word gedek in:

{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

In iOS en jailbreak research sal jy steeds die tradisionele model van **loadable trust caches** vind wat gebruik word om ad-hoc signed binaries te whitelist.

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)
- [https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/)
- [https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web](https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web)

{{#include ../../../banners/hacktricks-training.md}}
