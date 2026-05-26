# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext and amfid

Dit fokus op die handhawing van die integriteit van die code wat op die stelsel loop, en bied die logika agter XNU se code signature verification. Dit kan ook entitlements kontroleer en ander sensitiewe take hanteer soos om debugging toe te laat of task ports te bekom.

Verder, vir sommige operasies verkies die kext om die user space draaiende daemon `/usr/libexec/amfid` te kontak. Hierdie trust relationship is in verskeie jailbreaks misbruik.

Op onlangse macOS weergawes word AMFI nie meer gerieflik blootgestel as ’n selfstandige on-disk kext nie, so reversing beteken gewoonlik om vanaf die **kernelcache** of ’n **KDK** te werk eerder as om deur `/System/Library/Extensions` te blaai.

AMFI gebruik **MACF** policies en registreer sy hooks op die oomblik dat dit begin. Ook kan die voorkoming van laai of die unloading daarvan ’n kernel panic veroorsaak. Daar is egter sommige boot arguments wat toelaat om AMFI te debilitate:

- `amfi_unrestricted_task_for_pid`: Allow task_for_pid to be allowed without required entitlements
- `amfi_allow_any_signature`: Allow any code signature
- `cs_enforcement_disable`: System-wide argument used to disable code signing enforcement
- `amfi_prevent_old_entitled_platform_binaries`: Void platform binaries with entitlements
- `amfi_get_out_of_my_way`: Disables amfi completely

Dit is sommige van die MACF policies wat dit registreer:

- **`cred_check_label_update_execve:`** Label update will be performed and return 1
- **`cred_label_associate`**: Update AMFI's mac label slot with label
- **`cred_label_destroy`**: Remove AMFI’s mac label slot
- **`cred_label_init`**: Move 0 in AMFI's mac label slot
- **`cred_label_update_execve`:** It checks the entitlements of the process to see it should be allowed to modify the labels.
- **`file_check_mmap`:** It checks if mmap is acquiring memory and setting it as executable. In that case it check if library validation is needed and if so, it calls the library validation function.
- **`file_check_library_validation`**: Calls the library validation function which checks among other things if a platform binary is loading another platform binary or if the process and the new loaded file have the same TeamID. Certain entitlements will also allow to load any library.
- **`policy_initbsd`**: Sets up trusted NVRAM Keys
- **`policy_syscall`**: It checks DYLD policies like if the binary has unrestricted segments, if it should allow env vars... this is also called when a process is started via `amfi_check_dyld_policy_self()`.
- **`proc_check_inherit_ipc_ports`**: It checks if when a processes executes a new binary other processes with SEND rights over the task port of the process should keep them or not. Platform binaries are allowed, `get-task-allow` entitled allows it, `task_for_pid-allow` entitles are allowed and binaries with the same TeamID.
- **`proc_check_expose_task`**: enforce entitlements
- **`amfi_exc_action_check_exception_send`**: An exception message is sent to debugger
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: Label lifecycle during exception handling (debugging)
- **`proc_check_get_task`**: Checks entitlements like `get-task-allow` which allows other processes to get the tasks port and `task_for_pid-allow`, which allow the process to get other processes tasks ports. If neither of those, it calls up to `amfid permitunrestricteddebugging` to check if it's allowed.
- **`proc_check_mprotect`**: Deny if `mprotect` is called with the flag `VM_PROT_TRUSTED` which indicates that the region must be treated as if it has a valid code signature.
- **`vnode_check_exec`**: Gets called when a executable files are loaded in memory and sets `cs_hard | cs_kill` which will kill the process if any of the pages becomes invalid
- **`vnode_check_getextattr`**: MacOS: Check `com.apple.root.installed` and `isVnodeQuarantined()`
- **`vnode_check_setextattr`**: As get + com.apple.private.allow-bless and internal-installer-equivalent entitlement
- **`vnode_check_signature`**: Code that calls XNU to check the code signature using entitlements, trust cache and `amfid`
- **`proc_check_run_cs_invalid`**: It intercepts `ptrace()` calls (`PT_ATTACH` and `PT_TRACE_ME`). It checks for any of the entitlements `get-task-allow`, `run-invalid-allow` and `run-unsigned-code` and if none, it checks if debugging is permitted.
- **`proc_check_map_anon`**: If mmap is called with the **`MAP_JIT`** flag, AMFI will checks for the `dynamic-codesigning` entitlement.

`AMFI.kext` also exposes an API for other kernel extensions, and it's possible to find its dependencies with:
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

Dit is die user mode loop daemon wat `AMFI.kext` sal gebruik om te kyk vir code signatures in user mode.\
Vir `AMFI.kext` om met die daemon te kommunikeer, gebruik dit mach messages oor die port `HOST_AMFID_PORT` wat die spesiale port `18` is.

Let daarop dat dit in macOS nie meer moontlik is vir root processes om special ports te hijack nie, aangesien hulle deur `SIP` beskerm word en slegs launchd hulle kan kry. In iOS word gekontroleer dat die process wat die response terugstuur die CDHash hardcoded van `amfid` het.

Dit is moontlik om te sien wanneer `amfid` gevra word om ’n binary te check en die response daarvan deur dit te debug en ’n breakpoint in `mach_msg` te stel.

Sodra ’n message via die special port ontvang word, word **MIG** gebruik om elke function te stuur na die function waarna dit roep. Die hoof functions is binne die book reverse en verduidelik.

### DYLD policy and library validation

Onlangse `dyld` versions roep `amfi_check_dyld_policy_self()` baie vroeg vanaf `configureProcessRestrictions()` om AMFI te vra of die process `DYLD_*` path variables, interposing, fallback paths, embedded variables, of failed library insertion mag gebruik. Daarom, wanneer jy ’n injection surface triage, is dit nie genoeg om net Mach-O load commands te inspekteer nie: jy moet ook die entitlements en runtime flags inspekteer wat AMFI na `dyld` policy sal vertaal.

’n Praktiese triage loop is:
```bash
BIN=/path/to/app/Contents/MacOS/binary

# Interesting AMFI-related entitlements
codesign -d --entitlements :- "$BIN" 2>&1 | \
egrep "disable-library-validation|clear-library-validation|allow-dyld-environment-variables|allow-jit|allow-unsigned-executable-memory|disable-executable-page-protection|get-task-allow"

# Runtime flags / TeamID / hardened-runtime metadata
codesign -dvvv "$BIN" 2>&1 | egrep "TeamIdentifier=|Runtime Version|flags="
```
Op moderne macOS dra baie Apple binaries nie meer `com.apple.security.cs.disable-library-validation` direk nie en gebruik eerder `com.apple.private.security.clear-library-validation`. In daardie geval word library validation nie by `execve`-tyd gedeaktiveer nie: die proses moet `csops(..., CS_OPS_CLEAR_LV, ...)` op homself aanroep, en XNU laat daardie operasie net toe op die oproepende proses wanneer die entitlement teenwoordig is. Vanuit ’n offensiewe perspektief maak dit saak omdat ’n teiken eers injectable kan word **nadat** dit die kodepad bereik wat LV eksplisiet skoonmaak (byvoorbeeld net voor die laai van opsionele plugins).

## Provisioning Profiles

’n provisioning profile kan gebruik word om code te sign. Daar is **Developer** profiles wat gebruik kan word om code te sign en te toets, en **Enterprise** profiles wat op alle devices gebruik kan word.

Nadat ’n App by die Apple Store ingedien is, as dit goedgekeur word, word dit deur Apple ge-sign en die provisioning profile is nie meer nodig nie.

’n profile gebruik gewoonlik die uitbreiding `.mobileprovision` of `.provisionprofile` en kan gedump word met:
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
Alhoewel soms as certificated na verwys, het hierdie provisioning profiles meer as net ’n certificate:

- **AppIDName:** Die Application Identifier
- **AppleInternalProfile**: Wys dit aan as ’n Apple Internal profile
- **ApplicationIdentifierPrefix**: Voorgeplaas by AppIDName (selfs as TeamIdentifier)
- **CreationDate**: Datum in `YYYY-MM-DDTHH:mm:ssZ` formaat
- **DeveloperCertificates**: ’n Skikking van (gewoonlik een) certificate(s), gekodeer as Base64 data
- **Entitlements**: Die entitlements toegelaat met entitlements vir hierdie profile
- **ExpirationDate**: Verval datum in `YYYY-MM-DDTHH:mm:ssZ` formaat
- **Name**: Die Application Name, dieselfde as AppIDName
- **ProvisionedDevices**: ’n Skikking (vir developer certificates) van UDIDs waarvoor hierdie profile geldig is
- **ProvisionsAllDevices**: ’n Boolean (true vir enterprise certificates)
- **TeamIdentifier**: ’n Skikking van (gewoonlik een) alfanumeriese string(s) gebruik om die developer te identifiseer vir inter-app interaction doeleindes
- **TeamName**: ’n Mens-lesbare naam gebruik om die developer te identifiseer
- **TimeToLive**: Geldigheid (in dae) van die certificate
- **UUID**: ’n Universally Unique Identifier vir hierdie profile
- **Version**: Tans gestel op 1

Let daarop dat die entitlements entry ’n beperkte stel entitlements sal bevat en die provisioning profile sal slegs daardie spesifieke entitlements kan gee om te voorkom dat Apple private entitlements gegee word.

Let daarop dat profiles gewoonlik in `/var/MobileDeviceProvisioningProfiles` geleë is en dit moontlik is om hulle te kontroleer met **`security cms -D -i /path/to/profile`**

## **libmis.dylib**

Dit is die external library wat `amfid` aanroep om te vra of dit iets moet toelaat of nie. Dit is histories misbruik in jailbreaking deur ’n backdoored weergawe daarvan te laat loop wat alles sou toelaat.

In macOS is dit binne `MobileDevice.framework`.

## AMFI Trust Caches

Trust caches is nie net ’n iOS-konsep nie. Op moderne macOS, veral op **Apple silicon**, is die static trust cache en loadable trust caches deel van die Secure Boot chain. Wanneer ’n Mach-O se **CodeDirectory hash** daar teenwoordig is, kan AMFI dit **platform privilege** gee sonder om verdere authenticity checks by launch time te doen. Dit beteken ook Apple kan platform binaries aan ’n spesifieke OS version vaspen en keer dat ouer Apple-signed binaries op nuwer systems herhaal word.

Op onlangse macOS releases is trust-cache metadata ook gekoppel aan **launch constraints**, so gekopieerde system apps en binaries wat vanaf die verkeerde parent/location begin word, kan deur AMFI verwerp word selfs al is hulle steeds Apple-signed. Die gedetailleerde extraction en reversing workflow word gedek in:

{{#ref}}
macos-launch-environment-constraints.md
{{endref}}

In iOS en jailbreak research sal jy steeds die tradisionele model van **loadable trust caches** vind wat gebruik word om ad-hoc signed binaries te whitelist.

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)
- [https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/)
- [https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web](https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web)

{{#include ../../../banners/hacktricks-training.md}}
