# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext en amfid

Dit fokus op die afdwinging van die integriteit van die kode wat op die stelsel loop, en verskaf die logika agter XNU se kode-handtekeningverifikasie. Dit kan ook entitlements nagaan en ander sensitiewe take hanteer, soos om debugging toe te laat of task ports te verkry.

Verder verkies die kext om vir sommige bewerkings met die user space-daemon `/usr/libexec/amfid` te kommunikeer. Hierdie trust relationship is in verskeie jailbreaks misbruik.

Op onlangse macOS-weergawes word AMFI nie meer gerieflik as ’n selfstandige on-disk kext blootgestel nie, dus beteken reversing gewoonlik dat daar vanaf die **kernelcache** of ’n **KDK** gewerk word, eerder as om deur `/System/Library/Extensions` te blaai.

AMFI gebruik **MACF**-policies en registreer sy hooks sodra dit begin word. Die voorkoming van die laai daarvan, of die unloading daarvan, kan ook ’n kernel panic veroorsaak. Daar is egter sommige boot arguments wat AMFI kan verswak:

- `amfi_unrestricted_task_for_pid`: Laat task_for_pid toe sonder die vereiste entitlements
- `amfi_allow_any_signature`: Laat enige code signature toe
- `cs_enforcement_disable`: Stelselwye argument wat gebruik word om code signing enforcement te deaktiveer
- `amfi_prevent_old_entitled_platform_binaries`: Maak platform binaries met entitlements ongeldig
- `amfi_get_out_of_my_way`: Deaktiveer amfi volledig

Hierdie is sommige van die MACF-policies wat dit registreer:<sup>[[1]](#references)</sup>

- **`cred_check_label_update_execve:`** Label update sal uitgevoer word en 1 teruggee
- **`cred_label_associate`**: Werk AMFI se mac label-slot met die label by
- **`cred_label_destroy`**: Verwyder AMFI se mac label-slot
- **`cred_label_init`**: Skuif 0 na AMFI se mac label-slot
- **`cred_label_update_execve:`** Dit kontroleer die proses se entitlements om te bepaal of dit toegelaat moet word om die labels te wysig.
- **`file_check_mmap:`** Dit kontroleer of mmap memory verkry en dit as executable stel. In daardie geval kontroleer dit of library validation nodig is en, indien wel, roep dit die library validation-funksie aan.
- **`file_check_library_validation`**: Roep die library validation-funksie aan, wat onder andere kontroleer of ’n platform binary ’n ander platform binary laai, of die proses en die nuwe gelaaide file dieselfde TeamID het. Sekere entitlements sal dit ook toelaat om enige library te laai.
- **`policy_initbsd`**: Stel trusted NVRAM Keys op
- **`policy_syscall`**: Dit kontroleer DYLD-policies, soos of die binary unrestricted segments het en of dit env vars moet toelaat... dit word ook geroep wanneer ’n proses via `amfi_check_dyld_policy_self()` begin word.
- **`proc_check_inherit_ipc_ports`**: Dit kontroleer of ander prosesse met SEND-regte oor die task port van die proses dit moet behou wanneer ’n proses ’n nuwe binary uitvoer. Platform binaries word toegelaat, `get-task-allow` entitled laat dit toe, `task_for_pid-allow` entitlements word toegelaat, asook binaries met dieselfde TeamID.
- **`proc_check_expose_task`**: dwing entitlements af
- **`amfi_exc_action_check_exception_send`**: ’n Exception message word na die debugger gestuur
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: Label-lifecycle tydens exception handling (debugging)
- **`proc_check_get_task`**: Kontroleer entitlements soos `get-task-allow`, wat ander prosesse toelaat om die task port te verkry, en `task_for_pid-allow`, wat die proses toelaat om ander prosesse se task ports te verkry. Indien nie een van die twee teenwoordig is nie, roep dit `amfid permitunrestricteddebugging` aan om te kontroleer of dit toegelaat word.
- **`proc_check_mprotect`**: Weier indien `mprotect` geroep word met die flag `VM_PROT_TRUSTED`, wat aandui dat die region behandel moet word asof dit ’n geldige code signature het.
- **`vnode_check_exec`**: Word geroep wanneer executable files in memory gelaai word en stel `cs_hard | cs_kill`, wat die proses sal terminate indien enige van die pages ongeldig word<sup>[[2]](#references)</sup>
- **`vnode_check_getextattr`**: MacOS: Kontroleer `com.apple.root.installed` en `isVnodeQuarantined()`
- **`vnode_check_setextattr`**: Soos get + `com.apple.private.allow-bless` en internal-installer-equivalent entitlement
- **`vnode_check_signature`**: Kode wat XNU roep om die code signature na te gaan deur entitlements, trust cache en `amfid` te gebruik<sup>[[3]](#references)</sup>
- **`proc_check_run_cs_invalid`**: Dit onderskep `ptrace()`-calls (`PT_ATTACH` en `PT_TRACE_ME`). Dit kontroleer vir enige van die entitlements `get-task-allow`, `run-invalid-allow` en `run-unsigned-code`, en indien geen daarvan teenwoordig is nie, kontroleer dit of debugging toegelaat word.
- **`proc_check_map_anon`**: Indien mmap met die **`MAP_JIT`**-flag geroep word, sal AMFI die `dynamic-codesigning`-entitlement kontroleer.

`AMFI.kext` stel ook ’n API vir ander kernel extensions bloot, en dit is moontlik om sy dependencies te vind met:
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

Dit is die daemon wat in user mode loop en wat `AMFI.kext` sal gebruik om vir code signatures in user mode te kontroleer.\
Om `AMFI.kext` met die daemon te laat kommunikeer, gebruik dit mach messages oor die port `HOST_AMFID_PORT`, wat die spesiale port `18` is.

Let daarop dat dit in macOS nie meer moontlik is vir root-prosesse om spesiale ports te kaap nie, aangesien hulle deur `SIP` beskerm word en slegs launchd toegang daartoe kan kry. In iOS word daar gekontroleer dat die proses wat die response terugstuur, die hardgekodeerde CDHash van `amfid` het.

Dit is moontlik om te sien wanneer `amfid` versoek word om ’n binary te kontroleer en wat sy response is deur dit te debug en ’n breakpoint in `mach_msg` te stel.

Sodra ’n message via die spesiale port ontvang is, word **MIG** gebruik om elke funksie na die funksie wat dit oproep, te stuur. Die hooffunksies is omgekeer en binne die boek verduidelik.

### DYLD-beleid en library validation

Onlangse `dyld`-weergawes roep `amfi_check_dyld_policy_self()` baie vroeg vanuit `configureProcessRestrictions()` aan om AMFI te vra of die proses `DYLD_*`-path variables, interposing, fallback paths en embedded variables mag gebruik, of mislukte library insertion mag verdra. Wanneer ’n injection surface dus getrieer word, is dit nie genoeg om slegs Mach-O load commands te inspekteer nie: jy moet ook die entitlements en runtime flags inspekteer wat AMFI na `dyld`-beleid sal vertaal.

’n Praktiese triage-lus is:
```bash
BIN=/path/to/app/Contents/MacOS/binary

# Interesting AMFI-related entitlements
codesign -d --entitlements :- "$BIN" 2>&1 | \
egrep "disable-library-validation|clear-library-validation|allow-dyld-environment-variables|allow-jit|allow-unsigned-executable-memory|disable-executable-page-protection|get-task-allow"

# Runtime flags / TeamID / hardened-runtime metadata
codesign -dvvv "$BIN" 2>&1 | egrep "TeamIdentifier=|Runtime Version|flags="
```
Op moderne macOS bevat baie Apple-binaries nie meer direk `com.apple.security.cs.disable-library-validation` nie, en word dit eerder met `com.apple.private.security.clear-library-validation` verskeep. In daardie geval word library validation nie tydens `execve` gedeaktiveer nie: die proses moet self `csops(..., CS_OPS_CLEAR_LV, ...)` aanroep, en XNU laat daardie bewerking slegs op die aanroepende proses toe wanneer die entitlement teenwoordig is. Vanuit ’n aanvallersperspektief is dit belangrik omdat ’n teiken eers **nadat** dit die kodepad bereik wat LV uitdruklik skoonmaak, injectable kan word (byvoorbeeld kort voordat opsionele plugins gelaai word).<sup>[[4]](#references)[[5]](#references)</sup>

## Provisioning-profiele

’n Provisioning profile kan gebruik word om code te sign. Daar is **Developer**-profiele wat gebruik kan word om code te sign en te toets, en **Enterprise**-profiele wat op alle devices gebruik kan word.

Nadat ’n App by die Apple Store ingedien is, word dit, indien dit goedgekeur word, deur Apple gesign, en die provisioning profile is nie meer nodig nie.

’n Profile gebruik gewoonlik die uitbreiding `.mobileprovision` of `.provisionprofile` en kan met die volgende gedump word:
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
Hoewel daar soms na verwys word as certificated, bevat hierdie provisioning profiles meer as net ’n certificate:

- **AppIDName:** Die Application Identifier
- **AppleInternalProfile**: Dui aan dat dit ’n Apple Internal profile is
- **ApplicationIdentifierPrefix**: Word voor AppIDName geplaas (dieselfde as TeamIdentifier)
- **CreationDate**: Datum in `YYYY-MM-DDTHH:mm:ssZ`-formaat
- **DeveloperCertificates**: ’n Array van (gewoonlik een) certificate(s), as Base64-data geënkodeer
- **Entitlements**: Die entitlements wat met entitlements vir hierdie profile toegelaat word
- **ExpirationDate**: Vervaldatum in `YYYY-MM-DDTHH:mm:ssZ`-formaat
- **Name**: Die Application Name, dieselfde as AppIDName
- **ProvisionedDevices**: ’n Array (vir developer certificates) van UDIDs waarvoor hierdie profile geldig is
- **ProvisionsAllDevices**: ’n Boolean (true vir enterprise certificates)
- **TeamIdentifier**: ’n Array van (gewoonlik een) alfanumeriese string(s) wat gebruik word om die developer vir inter-app-interaksiedoeleindes te identifiseer
- **TeamName**: ’n Mensleesbare naam wat gebruik word om die developer te identifiseer
- **TimeToLive**: Geldigheid (in dae) van die certificate
- **UUID**: ’n Universally Unique Identifier vir hierdie profile
- **Version**: Tans op 1 gestel

Let daarop dat die entitlements-inskrywing ’n beperkte stel entitlements sal bevat, en dat die provisioning profile slegs daardie spesifieke entitlements sal kan verskaf om te voorkom dat Apple private entitlements verskaf word.

Let daarop dat profiles gewoonlik in `/var/MobileDeviceProvisioningProfiles` geleë is en dat dit moontlik is om hulle met **`security cms -D -i /path/to/profile`** na te gaan.

## **libmis.dylib**

Dit is die eksterne library wat `amfid` aanroep om te vra of dit iets moet toelaat of nie. Dit is histories in jailbreaking misbruik deur ’n backdoored weergawe daarvan te laat loop wat alles sou toelaat.

In macOS is dit binne `MobileDevice.framework`.

## AMFI Trust Caches

Trust caches is nie net ’n iOS-konsep nie. Op moderne macOS, veral op **Apple silicon**, is die static trust cache en loadable trust caches deel van die Secure Boot-ketting. Wanneer ’n Mach-O se **CodeDirectory hash** daar teenwoordig is, kan AMFI dit **platform privilege** gee sonder om verdere authenticity checks tydens launch uit te voer. Dit beteken ook dat Apple platform binaries aan ’n spesifieke OS-weergawe kan bind en kan voorkom dat ouer Apple-signed binaries op nuwer stelsels replay word.<sup>[[6]](#references)</sup>

Op onlangse macOS-releases is trust-cache-metadata ook aan **launch constraints** gekoppel, sodat gekopieerde system apps en binaries wat vanaf die verkeerde parent/location gestart word, deur AMFI rejected kan word, selfs al is hulle steeds Apple-signed. Die gedetailleerde extraction- en reversing-workflow word gedek in:

{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

In iOS- en jailbreak-research sal jy steeds die tradisionele model van **loadable trust caches** vind wat gebruik word om ad-hoc signed binaries te whitelist.

## Verwysings

- [1] [XNU — `security/mac_policy.h` (MACF policy ops AMFI registers, incl. `mpo_policy_syscall`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `osfmk/kern/cs_blobs.h` (`CS_*` code-signing flags AMFI sets)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [3] [XNU — `bsd/kern/ubc_subr.c` (code-signature blob parsing and validation)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/ubc_subr.c)
- [4] [XNU — `bsd/sys/codesign.h` (`CS_OPS_*` operations and `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [5] [XNU — `bsd/kern/kern_proc.c` (`csops` / `CS_OPS_CLEAR_LV` handler)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [6] [Apple Platform Security Guide — Trust caches](https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web)

{{#include ../../../banners/hacktricks-training.md}}
