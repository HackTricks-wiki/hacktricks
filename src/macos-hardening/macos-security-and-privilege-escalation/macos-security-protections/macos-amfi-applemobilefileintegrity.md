# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext and amfid

Dit fokus op die afdwing van die integriteit van die code wat op die stelsel loop, en verskaf die logika agter XNU se code signature verification. Dit kan ook entitlements kontroleer en ander sensitiewe take hanteer, soos om debugging toe te laat of task ports te verkry.

Verder, vir sekere operasies verkies die kext om die user space-draende daemon `/usr/libexec/amfid` te kontak. Hierdie vertrouensverhouding is al in verskeie jailbreaks misbruik.

Op onlangse macOS-weergawes word AMFI nie meer gerieflik as 'n standalone on-disk kext blootgestel nie, so reversing beteken gewoonlik om vanaf die **kernelcache** of 'n **KDK** te werk eerder as om deur `/System/Library/Extensions` te blaai.

AMFI gebruik **MACF** policies en registreer sy hooks die oomblik wanneer dit begin. Ook kan die verhoed van laai of die unloading daarvan 'n kernel panic veroorsaak. Daar is egter sekere boot arguments wat toelaat om AMFI te verlam:

- `amfi_unrestricted_task_for_pid`: Laat task_for_pid toe sonder vereiste entitlements
- `amfi_allow_any_signature`: Laat enige code signature toe
- `cs_enforcement_disable`: Stelselwye argument wat gebruik word om code signing enforcement te deaktiveer
- `amfi_prevent_old_entitled_platform_binaries`: Maak platform binaries met entitlements ongeldig
- `amfi_get_out_of_my_way`: Deaktiveer amfi heeltemal

Dit is sommige van die MACF policies wat dit registreer:

- **`cred_check_label_update_execve:`** Label update sal uitgevoer word en 1 teruggee
- **`cred_label_associate`**: Werk AMFI se mac label-slot by met label
- **`cred_label_destroy`**: Verwyder AMFI se mac label-slot
- **`cred_label_init`**: Beweeg 0 in AMFI se mac label-slot
- **`cred_label_update_execve`:** Dit kontroleer die entitlements van die proses om te sien of dit toegelaat moet word om die labels te wysig.
- **`file_check_mmap`:** Dit kontroleer of mmap geheue verkry en dit as executable stel. In daardie geval kontroleer dit of library validation nodig is en indien wel, roep dit die library validation funksie aan.
- **`file_check_library_validation`**: Roep die library validation funksie aan wat onder andere kontroleer of 'n platform binary 'n ander platform binary laai of of die proses en die nuwe gelaaide file dieselfde TeamID het. Sekere entitlements sal ook toelaat om enige library te laai.
- **`policy_initbsd`**: Stel vertroude NVRAM Keys op
- **`policy_syscall`**: Dit kontroleer DYLD policies soos of die binary onbeperkte segments het, of dit env vars moet toelaat... dit word ook geroep wanneer 'n proses via `amfi_check_dyld_policy_self()` begin word.
- **`proc_check_inherit_ipc_ports`**: Dit kontroleer of wanneer 'n proses 'n nuwe binary uitvoer ander prosesse met SEND-regte oor die task port van die proses dit moet behou of nie. Platform binaries word toegelaat, `get-task-allow` entitled laat dit toe, `task_for_pid-allow` entitles word toegelaat en binaries met dieselfde TeamID.
- **`proc_check_expose_task`**: enforce entitlements
- **`amfi_exc_action_check_exception_send`**: 'n Exception message word na debugger gestuur
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: Label lifecycle tydens exception handling (debugging)
- **`proc_check_get_task`**: Kontroleer entitlements soos `get-task-allow` wat ander prosesse toelaat om die task port te kry, en `task_for_pid-allow`, wat die proses toelaat om ander prosesse se task ports te kry. As nie een van dié nie, roep dit op na `amfid permitunrestricteddebugging` om te kontroleer of dit toegelaat is.
- **`proc_check_mprotect`**: Weier as `mprotect` met die vlag `VM_PROT_TRUSTED` geroep word, wat aandui dat die region behandel moet word asof dit 'n geldige code signature het.
- **`vnode_check_exec`**: Word geroep wanneer executable files in memory gelaai word en stel `cs_hard | cs_kill` wat die proses sal doodmaak as enige van die pages ongeldig word
- **`vnode_check_getextattr`**: MacOS: Kontroleer `com.apple.root.installed` en `isVnodeQuarantined()`
- **`vnode_check_setextattr`**: Soos get + com.apple.private.allow-bless en internal-installer-equivalent entitlement
- **`vnode_check_signature`**: Code wat XNU aanroep om die code signature met behulp van entitlements, trust cache en `amfid` te kontroleer
- **`proc_check_run_cs_invalid`**: Dit onderskep `ptrace()` calls (`PT_ATTACH` and `PT_TRACE_ME`). Dit kontroleer vir enige van die entitlements `get-task-allow`, `run-invalid-allow` en `run-unsigned-code` en as geen daarvan nie, kontroleer dit of debugging toegelaat word.
- **`proc_check_map_anon`**: As mmap met die **`MAP_JIT`** vlag geroep word, sal AMFI die `dynamic-codesigning` entitlement kontroleer.

`AMFI.kext` stel ook 'n API vir ander kernel extensions bloot, en dit is moontlik om sy dependencies te vind met:
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

Dit is die user mode-running daemon wat `AMFI.kext` sal gebruik om te kyk vir code signatures in user mode.\
Vir `AMFI.kext` om met die daemon te kommunikeer, gebruik dit mach messages oor die port `HOST_AMFID_PORT` wat die spesiale port `18` is.

Let daarop dat dit in macOS nie meer moontlik is vir root processes om special ports te hijack nie, aangesien hulle deur `SIP` beskerm word en net launchd hulle kan kry. In iOS word gekontroleer dat die process wat die response terugstuur die CDHash hardcoded van `amfid` het.

Dit is moontlik om te sien wanneer `amfid` versoek word om ’n binary te check en die response daarvan deur dit te debug en ’n breakpoint in `mach_msg` te stel.

Sodra ’n message via die special port ontvang word, word **MIG** gebruik om elke function na die function te stuur wat dit aanroep. Die main functions is binne die boek gereverse en verduidelik.

### DYLD policy and library validation

Onlangse `dyld` versions roep `amfi_check_dyld_policy_self()` baie vroeg vanuit `configureProcessRestrictions()` aan om AMFI te vra of die process `DYLD_*` path variables, interposing, fallback paths, embedded variables mag gebruik, of failed library insertion mag tolerate. Daarom, wanneer jy ’n injection surface triage, is dit nie genoeg om net Mach-O load commands te inspect nie: jy moet ook die entitlements en runtime flags inspect wat AMFI na `dyld` policy sal translate.

’n Praktiese triage loop is:
```bash
BIN=/path/to/app/Contents/MacOS/binary

# Interesting AMFI-related entitlements
codesign -d --entitlements :- "$BIN" 2>&1 | \
egrep "disable-library-validation|clear-library-validation|allow-dyld-environment-variables|allow-jit|allow-unsigned-executable-memory|disable-executable-page-protection|get-task-allow"

# Runtime flags / TeamID / hardened-runtime metadata
codesign -dvvv "$BIN" 2>&1 | egrep "TeamIdentifier=|Runtime Version|flags="
```
Op moderne macOS dra baie Apple binaries nie meer direk `com.apple.security.cs.disable-library-validation` nie, en gebruik eerder `com.apple.private.security.clear-library-validation`. In daardie geval word library validation nie by `execve`-tyd gedeaktiveer nie: die proses moet `csops(..., CS_OPS_CLEAR_LV, ...)` op homself aanroep, en XNU laat daardie operasie net toe op die oproepende proses wanneer die entitlement teenwoordig is. Vanuit ’n offensiewe perspektief is dit belangrik omdat ’n teiken eers injectable kan word **nadat** dit die code path bereik wat LV eksplisiet skoonmaak (byvoorbeeld, net voor die laai van opsionele plugins).

## Provisioning Profiles

’n Provisioning profile kan gebruik word om code te teken. Daar is **Developer** profiles wat gebruik kan word om code te teken en te toets, en **Enterprise** profiles wat op alle devices gebruik kan word.

Nadat ’n App by die Apple Store ingedien is, as dit goedgekeur word, word dit deur Apple geteken en die provisioning profile is nie meer nodig nie.

’n Profile gebruik gewoonlik die uitbreiding `.mobileprovision` of `.provisionprofile` en kan gedump word met:
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
Alhoewel daar soms na verwys word as certificated, het hierdie provisioning profiles meer as net ’n certificate:

- **AppIDName:** Die Application Identifier
- **AppleInternalProfile**: Wys dit aan as ’n Apple Internal profile
- **ApplicationIdentifierPrefix**: Voorafgeplaas by AppIDName (dieselfde as TeamIdentifier)
- **CreationDate**: Datum in `YYYY-MM-DDTHH:mm:ssZ` formaat
- **DeveloperCertificates**: ’n Skikking van (gewoonlik een) certificate(s), gekodeer as Base64 data
- **Entitlements**: Die entitlements wat met entitlements vir hierdie profile toegelaat word
- **ExpirationDate**: Vervaldatum in `YYYY-MM-DDTHH:mm:ssZ` formaat
- **Name**: Die Application Name, dieselfde as AppIDName
- **ProvisionedDevices**: ’n Skikking (vir developer certificates) van UDIDs waarvoor hierdie profile geldig is
- **ProvisionsAllDevices**: ’n Booleaanse waarde (true vir enterprise certificates)
- **TeamIdentifier**: ’n Skikking van (gewoonlik een) alfanumeriese string(s) wat gebruik word om die developer te identifiseer vir inter-app interaction doeleindes
- **TeamName**: ’n Mensleesbare naam wat gebruik word om die developer te identifiseer
- **TimeToLive**: Geldigheid (in dae) van die certificate
- **UUID**: ’n Universally Unique Identifier vir hierdie profile
- **Version**: Tans ingestel op 1

Let daarop dat die entitlements entry ’n beperkte stel entitlements sal bevat en die provisioning profile sal slegs daardie spesifieke entitlements kan gee om te verhoed dat Apple private entitlements gegee word.

Let daarop dat profiles gewoonlik in `/var/MobileDeviceProvisioningProfiles` geleë is en dit moontlik is om hulle met **`security cms -D -i /path/to/profile`** te kontroleer

## **libmis.dylib**

Dit is die eksterne library wat `amfid` aanroep om te vra of dit iets moet toelaat of nie. Dit is histories misbruik in jailbreaking deur ’n backdoored weergawe daarvan te laat loop wat alles sou toelaat.

In macOS is dit binne `MobileDevice.framework`.

## AMFI Trust Caches

Trust caches is nie net ’n iOS-konsep nie. Op moderne macOS, veral op **Apple silicon**, is die static trust cache en loadable trust caches deel van die Secure Boot-ketting. Wanneer ’n Mach-O se **CodeDirectory hash** daar teenwoordig is, kan AMFI dit **platform privilege** gee sonder om verdere authenticity checks by launch time te doen. Dit beteken ook Apple kan platform binaries aan ’n spesifieke OS version vaspen en voorkom dat ouer Apple-signed binaries op nuwer systems hergebruik word.

Op onlangse macOS-releases is trust-cache metadata ook gekoppel aan **launch constraints**, so gekopieerde system apps en binaries wat vanaf die verkeerde parent/location begin word, kan deur AMFI verwerp word, selfs al is hulle steeds Apple-signed. Die gedetailleerde extraction en reversing workflow word gedek in:

{{#ref}}
macos-launch-environment-constraints.md
{{endref}}

In iOS en jailbreak research sal jy steeds die tradisionele model van **loadable trust caches** vind wat gebruik word om ad-hoc signed binaries te whitelists.

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)
- [https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/)
- [https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web](https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web)

{{#include ../../../banners/hacktricks-training.md}}
