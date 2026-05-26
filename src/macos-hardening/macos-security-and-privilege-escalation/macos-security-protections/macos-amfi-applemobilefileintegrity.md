# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext and amfid

Inalenga katika kutekeleza uadilifu wa code inayoendesha kwenye mfumo, ikitoa logic nyuma ya XNU's code signature verification. Pia inaweza kuangalia entitlements na kushughulikia kazi nyingine nyeti kama kuruhusu debugging au kupata task ports.

Zaidi ya hayo, kwa baadhi ya operations, kext hupendelea kuwasiliana na user space running daemon `/usr/libexec/amfid`. Uhusiano huu wa trust umetumiwa vibaya katika jailbreaks kadhaa.

Kwenye matoleo ya hivi karibuni ya macOS, AMFI haiwezi tena kupatikana kwa urahisi kama standalone on-disk kext, hivyo reversing kwa kawaida humaanisha kufanya kazi kutoka **kernelcache** au **KDK** badala ya kuvinjari `/System/Library/Extensions`.

AMFI hutumia **MACF** policies na husajili hooks zake mara tu inapoanzishwa. Pia, kuzuia kupakiwa kwake au kuiondoa kunaweza kusababisha kernel panic. Hata hivyo, kuna baadhi ya boot arguments zinazoruhusu kudhoofisha AMFI:

- `amfi_unrestricted_task_for_pid`: Ruhusu task_for_pid kuruhusiwa bila entitlements zinazohitajika
- `amfi_allow_any_signature`: Ruhusu code signature yoyote
- `cs_enforcement_disable`: System-wide argument inayotumika kuzima code signing enforcement
- `amfi_prevent_old_entitled_platform_binaries`: Void platform binaries zenye entitlements
- `amfi_get_out_of_my_way`: Inazima amfi kabisa

Hizi ni baadhi ya MACF policies inazosajili:

- **`cred_check_label_update_execve:`** Label update itafanywa na kurudisha 1
- **`cred_label_associate`**: Sasisha mac label slot ya AMFI kwa label
- **`cred_label_destroy`**: Ondoa mac label slot ya AMFI
- **`cred_label_init`**: Weka 0 kwenye mac label slot ya AMFI
- **`cred_label_update_execve`:** Inaangalia entitlements za process ili kuona kama inapaswa kuruhusiwa kurekebisha labels.
- **`file_check_mmap`:** Inaangalia kama mmap inapata memory na kuiweka kuwa executable. Katika hali hiyo inaangalia kama library validation inahitajika na ikiwa ndivyo, inaita library validation function.
- **`file_check_library_validation`**: Inaita library validation function ambayo huangalia miongoni mwa mambo mengine kama platform binary inapakia platform binary nyingine au kama process na file mpya iliyopakiwa zina TeamID sawa. Certain entitlements pia zitaruhusu kupakia library yoyote.
- **`policy_initbsd`**: Huanzisha trusted NVRAM Keys
- **`policy_syscall`**: Inaangalia DYLD policies kama binary ina unrestricted segments, kama inapaswa kuruhusu env vars... hii pia huitwa wakati process inaanzishwa kupitia `amfi_check_dyld_policy_self()`.
- **`proc_check_inherit_ipc_ports`**: Inaangalia kama wakati process inatekeleza binary mpya processes nyingine zenye SEND rights juu ya task port ya process zinapaswa kuzihifadhi au la. Platform binaries zinaruhusiwa, `get-task-allow` entitlement inaruhusu, `task_for_pid-allow` entitles zinaruhusiwa na binaries zenye TeamID sawa.
- **`proc_check_expose_task`**: enforce entitlements
- **`amfi_exc_action_check_exception_send`**: exception message inatumwa kwa debugger
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: Mzunguko wa maisha wa label wakati wa exception handling (debugging)
- **`proc_check_get_task`**: Inaangalia entitlements kama `get-task-allow` ambayo inaruhusu processes nyingine kupata task port na `task_for_pid-allow`, ambazo huruhusu process kupata task ports za processes nyingine. Iwapo hakuna mojawapo ya hizo, hupanda hadi `amfid permitunrestricteddebugging` ili kuangalia kama inaruhusiwa.
- **`proc_check_mprotect`**: Kataa ikiwa `mprotect` inaitwa na flag `VM_PROT_TRUSTED` ambayo inaonyesha kuwa eneo lazima litibiwe kana kwamba lina valid code signature.
- **`vnode_check_exec`**: Huitwa wakati executable files zinapopakiwa kwenye memory na huweka `cs_hard | cs_kill` ambayo itaua process ikiwa mojawapo ya pages itakuwa invalid
- **`vnode_check_getextattr`**: MacOS: Angalia `com.apple.root.installed` na `isVnodeQuarantined()`
- **`vnode_check_setextattr`**: Kama get + com.apple.private.allow-bless na internal-installer-equivalent entitlement
- **`vnode_check_signature`**: Code inayomwita XNU kuangalia code signature kwa kutumia entitlements, trust cache na `amfid`
- **`proc_check_run_cs_invalid`**: Huzuia `ptrace()` calls (`PT_ATTACH` and `PT_TRACE_ME`). Inaangalia entitlements zozote za `get-task-allow`, `run-invalid-allow` na `run-unsigned-code` na kama hakuna, inaangalia kama debugging inaruhusiwa.
- **`proc_check_map_anon`**: Ikiwa mmap inaitwa na **`MAP_JIT`** flag, AMFI itaangalia entitlement ya `dynamic-codesigning`.

`AMFI.kext` pia hutoa API kwa ajili ya other kernel extensions, na inawezekana kupata dependencies zake kwa:
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

Hii ni daemon inayofanya kazi kwenye user mode ambayo `AMFI.kext` itatumia kuangalia code signatures kwenye user mode.\
Ili `AMFI.kext` iweze kuwasiliana na daemon, hutumia mach messages kupitia port `HOST_AMFID_PORT` ambayo ni special port `18`.

Kumbuka kuwa katika macOS si tena inawezekana kwa root processes ku-hijack special ports kwa sababu zinalindwa na `SIP` na ni launchd pekee inayoweza kuzipata. Katika iOS hukaguliwa kwamba process inayotuma response kurudi ina CDHash iliyohardcodewa ya `amfid`.

Inawezekana kuona wakati `amfid` inapoombwa ku-check binary na response yake kwa ku-debug na kuweka breakpoint kwenye `mach_msg`.

Mara message inapopokelewa kupitia special port, **MIG** hutumika kutuma kila function kwenda kwenye function ambayo inaita. Main functions zilireversed na kuelezwa ndani ya book.

### DYLD policy and library validation

Toleo za hivi karibuni za `dyld` huita `amfi_check_dyld_policy_self()` mapema sana kutoka `configureProcessRestrictions()` ili kuuliza AMFI kama process inaweza kutumia `DYLD_*` path variables, interposing, fallback paths, embedded variables, au kustahimili failed library insertion. Kwa hiyo, unapochambua injection surface haitoshi kukagua tu Mach-O load commands: pia unahitaji kukagua entitlements na runtime flags ambazo AMFI itatafsiri kuwa `dyld` policy.

Mtiririko wa practical triage ni:
```bash
BIN=/path/to/app/Contents/MacOS/binary

# Interesting AMFI-related entitlements
codesign -d --entitlements :- "$BIN" 2>&1 | \
egrep "disable-library-validation|clear-library-validation|allow-dyld-environment-variables|allow-jit|allow-unsigned-executable-memory|disable-executable-page-protection|get-task-allow"

# Runtime flags / TeamID / hardened-runtime metadata
codesign -dvvv "$BIN" 2>&1 | egrep "TeamIdentifier=|Runtime Version|flags="
```
Kwenye macOS ya kisasa, binaries nyingi za Apple hazibebi `com.apple.security.cs.disable-library-validation` moja kwa moja tena, na badala yake huja na `com.apple.private.security.clear-library-validation`. Katika hali hiyo, library validation haizimwi wakati wa `execve`: mchakato lazima utumie `csops(..., CS_OPS_CLEAR_LV, ...)` kwenye yenyewe, na XNU huruhusu tu operesheni hiyo kwa mchakato unaopiga simu wakati entitlement hiyo ipo. Kutoka upande wa offensive, hii ni muhimu kwa sababu target inaweza kuwa injectable tu **baada ya** kufika kwenye code path inayofuta LV waziwazi (kwa mfano, muda mfupi kabla ya kupakia optional plugins).

## Provisioning Profiles

provisioning profile inaweza kutumika kusaini code. Zipo profile za **Developer** ambazo zinaweza kutumika kusaini code na kuijaribu, na **Enterprise** profiles ambazo zinaweza kutumika kwenye devices zote.

Baada ya App kuwasilishwa kwenye Apple Store, ikikubaliwa, husainiwa na Apple na provisioning profile haihitajiki tena.

Profile kwa kawaida hutumia extension `.mobileprovision` au `.provisionprofile` na inaweza dumped kwa kutumia:
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
Ingawa wakati mwingine huitwa certificated, provisioning profiles hizi zina zaidi ya certificate moja:

- **AppIDName:** Kitambulisho cha Application
- **AppleInternalProfile**: Hii huashiria kuwa ni profile ya Apple Internal
- **ApplicationIdentifierPrefix**: Huongezwa mbele ya AppIDName (sawa na TeamIdentifier)
- **CreationDate**: Tarehe katika muundo `YYYY-MM-DDTHH:mm:ssZ`
- **DeveloperCertificates**: Safu ya (kawaida moja) certificate(s), iliyosimbwa kama Base64 data
- **Entitlements**: Entitlements zinazoruhusiwa pamoja na entitlements za profile hii
- **ExpirationDate**: Tarehe ya kuisha katika muundo `YYYY-MM-DDTHH:mm:ssZ`
- **Name**: Jina la Application, sawa na AppIDName
- **ProvisionedDevices**: Safu (kwa developer certificates) ya UDIDs ambazo profile hii ni halali kwao
- **ProvisionsAllDevices**: Boolean (true kwa enterprise certificates)
- **TeamIdentifier**: Safu ya (kawaida moja) mfuatano wa herufi na nambari unaotumiwa kumtambua developer kwa madhumuni ya inter-app interaction
- **TeamName**: Jina linalosomeka kwa binadamu linalotumiwa kumtambua developer
- **TimeToLive**: Uhalali (kwa siku) wa certificate
- **UUID**: Universal Unique Identifier ya profile hii
- **Version**: Kwa sasa imewekwa kuwa 1

Kumbuka kuwa ingizo la entitlements litakuwa na seti iliyozuiliwa ya entitlements na provisioning profile itaweza tu kutoa entitlements hizo mahususi ili kuzuia kutoa Apple private entitlements.

Kumbuka kwamba profiles kwa kawaida hupatikana katika `/var/MobileDeviceProvisioningProfiles` na inawezekana kuzikagua kwa **`security cms -D -i /path/to/profile`**

## **libmis.dylib**

Hili ni external library ambalo `amfid` huita ili kuuliza kama inapaswa kuruhusu kitu fulani au la. Hili limekuwa likitumiwa vibaya kihistoria katika jailbreaking kwa kuendesha toleo lenye backdoor la hilo ambalo lingeiruhusu kila kitu.

Katika macOS hili liko ndani ya `MobileDevice.framework`.

## AMFI Trust Caches

Trust caches si dhana ya iOS pekee. Kwenye macOS ya kisasa, hasa kwenye **Apple silicon**, static trust cache na loadable trust caches ni sehemu ya Secure Boot chain. Wakati **CodeDirectory hash** ya Mach-O ipo humo, AMFI inaweza kuipa **platform privilege** bila kufanya uthibitishaji zaidi wa authenticity wakati wa launch. Hii pia inamaanisha Apple inaweza kuifunga platform binaries kwa toleo mahususi la OS na kuzuia Apple-signed binaries za zamani zisirudishwe kutumika kwenye mifumo mipya.

Kwenye matoleo ya hivi karibuni ya macOS, trust-cache metadata pia imeunganishwa na **launch constraints**, hivyo copied system apps na binaries zinapoanzishwa kutoka parent/location isiyo sahihi zinaweza kukataliwa na AMFI hata kama bado zime-signiwa na Apple. Mchakato wa kina wa extraction na reversing umeelezewa katika:

{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

Katika iOS na jailbreak research bado utaona modeli ya jadi ya **loadable trust caches** ikitumika kuwhitelist ad-hoc signed binaries.

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)
- [https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/)
- [https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web](https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web)

{{#include ../../../banners/hacktricks-training.md}}
