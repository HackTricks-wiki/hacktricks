# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext and amfid

Inalenga kwenye kulazimisha uadilifu wa code inayoendeshwa kwenye system kwa kutoa logic iliyo nyuma ya XNU's code signature verification. Pia ina uwezo wa kuangalia entitlements na kushughulikia kazi nyingine nyeti kama kuruhusu debugging au kupata task ports.

Zaidi ya hayo, kwa baadhi ya operations, kext hupendelea kuwasiliana na user space running daemon `/usr/libexec/amfid`. Uhusiano huu wa trust umetumiwa vibaya katika jailbreaks kadhaa.

Kwenye matoleo ya hivi karibuni ya macOS, AMFI haionyeshwi tena kwa urahisi kama standalone on-disk kext, hivyo reversing kwa kawaida humaanisha kufanya kazi kutoka kwenye **kernelcache** au **KDK** badala ya kuvinjari `/System/Library/Extensions`.

AMFI hutumia **MACF** policies na husajili hooks zake mara tu inapoanza. Pia, kuzuia kupakiwa kwake au kuiondoa kunaweza kuanzisha kernel panic. Hata hivyo, kuna baadhi ya boot arguments zinazoruhusu kudhoofisha AMFI:

- `amfi_unrestricted_task_for_pid`: Ruhusu task_for_pid kuruhusiwa bila entitlements zinazohitajika
- `amfi_allow_any_signature`: Ruhusu code signature yoyote
- `cs_enforcement_disable`: System-wide argument inayotumika kuzima code signing enforcement
- `amfi_prevent_old_entitled_platform_binaries`: Void platform binaries zenye entitlements
- `amfi_get_out_of_my_way`: Huzima amfi kabisa

Hizi ni baadhi ya MACF policies inazosajili:

- **`cred_check_label_update_execve:`** Label update itafanywa na kurudisha 1
- **`cred_label_associate`**: Sasisha mac label slot ya AMFI na label
- **`cred_label_destroy`**: Ondoa mac label slot ya AMFI
- **`cred_label_init`**: Hamisha 0 kwenye mac label slot ya AMFI
- **`cred_label_update_execve`:** Huangalia entitlements za process ili kuona kama inapaswa kuruhusiwa kurekebisha labels.
- **`file_check_mmap`:** Huangalia kama mmap inapata memory na kuiweka kama executable. Katika hali hiyo huangalia kama library validation inahitajika na ikiwa ni hivyo, huita function ya library validation.
- **`file_check_library_validation`**: Huita function ya library validation ambayo huangalia, miongoni mwa mambo mengine, kama platform binary inaload platform binary nyingine au kama process na file mpya iliyopakiwa zina TeamID ile ile. Certain entitlements pia zitaruhusu kupakia library yoyote.
- **`policy_initbsd`**: Huweka trusted NVRAM Keys
- **`policy_syscall`**: Huangalia DYLD policies kama binary ina unrestricted segments, kama inapaswa kuruhusu env vars... hii pia huitwa wakati process inapoanzishwa kupitia `amfi_check_dyld_policy_self()`.
- **`proc_check_inherit_ipc_ports`**: Huangalia kama wakati process inaendesha binary mpya processes nyingine zenye SEND rights juu ya task port ya process zinapaswa kuziacha au la. Platform binaries zinaruhusiwa, `get-task-allow` entitied huruhusu, `task_for_pid-allow` entitles zinaruhusiwa na binaries zenye TeamID ile ile.
- **`proc_check_expose_task`**: enforce entitlements
- **`amfi_exc_action_check_exception_send`**: Exception message inatumwa kwa debugger
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: Mzunguko wa maisha wa label wakati wa kushughulikia exception (debugging)
- **`proc_check_get_task`**: Huangalia entitlements kama `get-task-allow` ambazo huruhusu processes nyingine kupata task port na `task_for_pid-allow`, ambazo huruhusu process kupata task ports za processes nyingine. Ikiwa hakuna hata moja kati ya hizo, hupanda hadi `amfid permitunrestricteddebugging` kuangalia kama inaruhusiwa.
- **`proc_check_mprotect`**: Kataa ikiwa `mprotect` inaitwa na flag `VM_PROT_TRUSTED` ambayo inaonyesha kwamba region lazima itibiwe kana kwamba ina code signature halali.
- **`vnode_check_exec`**: Huitwa wakati executable files zinapopakiwa kwenye memory na huweka `cs_hard | cs_kill` ambayo itaua process ikiwa yoyote ya pages itakuwa invalid
- **`vnode_check_getextattr`**: MacOS: Angalia `com.apple.root.installed` na `isVnodeQuarantined()`
- **`vnode_check_setextattr`**: Kama get + `com.apple.private.allow-bless` na internal-installer-equivalent entitlement
- **`vnode_check_signature`**: Code inayomuita XNU kuangalia code signature kwa kutumia entitlements, trust cache na `amfid`
- **`proc_check_run_cs_invalid`**: Huzuia `ptrace()` calls (`PT_ATTACH` na `PT_TRACE_ME`). Huangalia entitlements zozote za `get-task-allow`, `run-invalid-allow` na `run-unsigned-code` na ikiwa hakuna, huangalia kama debugging inaruhusiwa.
- **`proc_check_map_anon`**: Ikiwa mmap inaitwa na flag **`MAP_JIT`**, AMFI itaangalia entitlement ya `dynamic-codesigning`.

`AMFI.kext` pia hufichua API kwa ajili ya other kernel extensions, na inawezekana kupata dependencies zake kwa:
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

Hii ni daemon inayofanya kazi katika user mode ambayo `AMFI.kext` itatumia kuangalia code signatures katika user mode.\
Ili `AMFI.kext` iweze kuwasiliana na daemon hii hutumia mach messages kupitia port `HOST_AMFID_PORT` ambayo ni special port `18`.

Kumbuka kwamba katika macOS haiwezekani tena kwa root processes kuteka special ports kwa sababu zinalindwa na `SIP` na ni launchd pekee inaweza kuzipata. Katika iOS hukaguliwa kwamba process inayotuma jibu kurudi ina CDHash hardcoded ya `amfid`.

Inawezekana kuona wakati `amfid` inaombwa kuangalia binary na response yake kwa ku-debug na kuweka breakpoint katika `mach_msg`.

Mara ujumbe unapopokelewa kupitia special port **MIG** hutumika kutuma kila function kwenda kwa function inayoiita. Main functions zilireversed na kuelezwa ndani ya kitabu.

### DYLD policy and library validation

Toleo za hivi karibuni za `dyld` huita `amfi_check_dyld_policy_self()` mapema sana kutoka `configureProcessRestrictions()` ili kuuliza AMFI iwapo process inaweza kutumia `DYLD_*` path variables, interposing, fallback paths, embedded variables, au kuvumilia library insertion iliyofeli. Kwa hiyo, unapochambua injection surface haitoshi kuangalia tu Mach-O load commands: pia unahitaji kuchunguza entitlements na runtime flags ambazo AMFI itatafsiri kuwa `dyld` policy.

Mzunguko wa practical triage ni:
```bash
BIN=/path/to/app/Contents/MacOS/binary

# Interesting AMFI-related entitlements
codesign -d --entitlements :- "$BIN" 2>&1 | \
egrep "disable-library-validation|clear-library-validation|allow-dyld-environment-variables|allow-jit|allow-unsigned-executable-memory|disable-executable-page-protection|get-task-allow"

# Runtime flags / TeamID / hardened-runtime metadata
codesign -dvvv "$BIN" 2>&1 | egrep "TeamIdentifier=|Runtime Version|flags="
```
Kwenye macOS ya kisasa, binaries nyingi za Apple hazibebi tena `com.apple.security.cs.disable-library-validation` moja kwa moja, na badala yake huja na `com.apple.private.security.clear-library-validation`. Katika hali hiyo, library validation haizimwi wakati wa `execve`: process lazima ijitumie yenyewe `csops(..., CS_OPS_CLEAR_LV, ...)`, na XNU huruhusu operesheni hiyo tu kwa calling process wakati entitlement hiyo ipo. Kwa mtazamo wa offensive, hili ni muhimu kwa sababu target inaweza kuwa injectable tu **baada** kufikia code path inayofuta LV kwa uwazi (kwa mfano, muda mfupi kabla ya kupakia optional plugins).

## Provisioning Profiles

Provisioning profile inaweza kutumika kusaini code. Kuna profiles za **Developer** ambazo zinaweza kutumika kusaini code na kuijaribu, na **Enterprise** profiles ambazo zinaweza kutumika kwenye devices zote.

Baada ya App kuwasilishwa kwa Apple Store, ikikubaliwa, husainiwa na Apple na provisioning profile haihitajiki tena.

Profile kwa kawaida hutumia extension `.mobileprovision` au `.provisionprofile` na inaweza kutolewa kwa:
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
Ingawa wakati mwingine huitwa certificated, provisioning profiles hizi zina zaidi ya certificate:

- **AppIDName:** Kitambulisho cha Application
- **AppleInternalProfile**: Hii huiweka kama Apple Internal profile
- **ApplicationIdentifierPrefix**: Huongezwa mwanzoni mwa AppIDName (sawa na TeamIdentifier)
- **CreationDate**: Tarehe katika umbizo `YYYY-MM-DDTHH:mm:ssZ`
- **DeveloperCertificates**: Safu ya (kawaida moja) certificate(s), zilizosimbwa kama Base64 data
- **Entitlements**: Entitlements zinazoruhusiwa pamoja na entitlements kwa profile hii
- **ExpirationDate**: Tarehe ya kuisha katika umbizo `YYYY-MM-DDTHH:mm:ssZ`
- **Name**: Jina la Application, sawa na AppIDName
- **ProvisionedDevices**: Safu (kwa developer certificates) ya UDIDs ambazo profile hii ni halali kwao
- **ProvisionsAllDevices**: Thamani ya boolean (true kwa enterprise certificates)
- **TeamIdentifier**: Safu ya (kawaida moja) alphanumeric string(s) zinazotumika kutambua developer kwa madhumuni ya inter-app interaction
- **TeamName**: Jina linalosomeka na binadamu linalotumika kutambua developer
- **TimeToLive**: Uhalali (kwa siku) wa certificate
- **UUID**: Universally Unique Identifier ya profile hii
- **Version**: Kwa sasa imewekwa kuwa 1

Kumbuka kuwa ingizo la entitlements litakuwa na seti iliyozuiliwa ya entitlements na provisioning profile itaweza tu kutoa entitlements hizo maalum ili kuzuia kutoa Apple private entitlements.

Kumbuka kuwa profiles kwa kawaida ziko katika `/var/MobileDeviceProvisioningProfiles` na inawezekana kuzichunguza kwa **`security cms -D -i /path/to/profile`**

## **libmis.dylib**

Hii ni external library ambayo `amfid` huita ili kuuliza kama inapaswa kuruhusu kitu fulani au la. Hii kihistoria imetumiwa vibaya katika jailbreaking kwa kuendesha backdoored version yake ambayo ingeruhusu kila kitu.

Katika macOS hii iko ndani ya `MobileDevice.framework`.

## AMFI Trust Caches

Trust caches si tu wazo la iOS. Kwenye macOS ya kisasa, hasa kwenye **Apple silicon**, static trust cache na loadable trust caches ni sehemu ya Secure Boot chain. Wakati **CodeDirectory hash** ya Mach-O ipo humo, AMFI inaweza kuipa **platform privilege** bila kufanya uthibitishaji zaidi wa authenticity wakati wa launch. Hii pia inamaanisha Apple inaweza kufunga platform binaries kwa OS version maalum na kuzuia older Apple-signed binaries zisichezwe tena kwenye mifumo mipya.

Kwenye matoleo ya hivi karibuni ya macOS, trust-cache metadata pia imeunganishwa na **launch constraints**, hivyo copied system apps na binaries zilizoanzishwa kutoka kwa parent/location isiyo sahihi zinaweza kukataliwa na AMFI hata kama bado zimesainiwa na Apple. Mchakato wa kina wa extraction na reversing umefunikwa katika:

{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

Katika iOS na jailbreak research bado utapata traditional model ya **loadable trust caches** ikitumiwa kuwhitelist ad-hoc signed binaries.

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)
- [https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/)
- [https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web](https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web)

{{#include ../../../banners/hacktricks-training.md}}
