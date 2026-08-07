# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext na amfid

Inalenga kutekeleza uadilifu wa code inayotekelezwa kwenye mfumo, ikitoa mantiki iliyo nyuma ya uthibitishaji wa code signature wa XNU. Pia inaweza kukagua entitlements na kushughulikia kazi nyingine nyeti kama kuruhusu debugging au kupata task ports.

Zaidi ya hayo, kwa baadhi ya operesheni, kext hupendelea kuwasiliana na daemon ya user space `/usr/libexec/amfid`. Uhusiano huu wa trust umetumiwa vibaya katika jailbreaks kadhaa.

Kwenye matoleo ya hivi karibuni ya macOS, AMFI haipatikani tena kwa urahisi kama kext standalone iliyo kwenye disk, hivyo reversing kwa kawaida humaanisha kufanya kazi kutoka kwenye **kernelcache** au **KDK** badala ya kuvinjari `/System/Library/Extensions`.

AMFI hutumia policies za **MACF** na husajili hooks zake mara tu inapoanzishwa. Pia, kuzuia kupakiwa kwake au kuiondoa kunaweza kusababisha kernel panic. Hata hivyo, kuna boot arguments zinazowezesha kudhoofisha AMFI:

- `amfi_unrestricted_task_for_pid`: Huruhusu task_for_pid bila entitlements zinazohitajika
- `amfi_allow_any_signature`: Huruhusu code signature yoyote
- `cs_enforcement_disable`: Argument ya mfumo mzima inayotumiwa kuzima utekelezaji wa code signing
- `amfi_prevent_old_entitled_platform_binaries`: Hubatilisha platform binaries zenye entitlements
- `amfi_get_out_of_my_way`: Huzima amfi kabisa

Hizi ni baadhi ya policies za MACF inazojisajili:<sup>[[1]](#references)</sup>

- **`cred_check_label_update_execve:`** Label update itafanywa na irejeshe 1
- **`cred_label_associate`**: Husasisha mac label slot ya AMFI kwa kutumia label
- **`cred_label_destroy`**: Huondoa mac label slot ya AMFI
- **`cred_label_init`**: Hupeleka 0 kwenye mac label slot ya AMFI
- **`cred_label_update_execve`:** Hukagua entitlements za process ili kuona kama inapaswa kuruhusiwa kurekebisha labels.
- **`file_check_mmap`:** Hukagua kama mmap inapata memory na kuiweka executable. Katika hali hiyo hukagua kama library validation inahitajika na, ikiwa inahitajika, huita library validation function.
- **`file_check_library_validation`**: Huita library validation function ambayo hukagua, miongoni mwa mambo mengine, kama platform binary inapakia platform binary nyingine au kama process na file mpya iliyopakiwa zina TeamID sawa. Entitlements fulani pia zitaruhusu kupakia library yoyote.
- **`policy_initbsd`**: Huandaa trusted NVRAM Keys
- **`policy_syscall`**: Hukagua policies za DYLD kama binary ina segments zisizo na vikwazo, kama inapaswa kuruhusu env vars... hii pia huitwa process inapoanzishwa kupitia `amfi_check_dyld_policy_self()`.
- **`proc_check_inherit_ipc_ports`**: Hukagua kama process inapotekeleza binary mpya, processes nyingine zenye SEND rights kwenye task port ya process hiyo zinapaswa kuendelea kuzimiliki au la. Platform binaries zinaruhusiwa, entitlement ya `get-task-allow` inaruhusu, entitlements za `task_for_pid-allow` zinaruhusiwa, pamoja na binaries zenye TeamID sawa.
- **`proc_check_expose_task`**: Hutekeleza entitlements
- **`amfi_exc_action_check_exception_send`**: Exception message hutumwa kwa debugger
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: Lifecycle ya label wakati wa exception handling (debugging)
- **`proc_check_get_task`**: Hukagua entitlements kama `get-task-allow`, ambayo huruhusu processes nyingine kupata task port ya process, na `task_for_pid-allow`, ambayo huruhusu process kupata task ports za processes nyingine. Ikiwa hakuna yoyote kati ya hizo, huita `amfid permitunrestricteddebugging` ili kukagua kama inaruhusiwa.
- **`proc_check_mprotect`**: Hukataa ikiwa `mprotect` inaitwa na flag `VM_PROT_TRUSTED`, ambayo inaashiria kuwa region inapaswa kushughulikiwa kana kwamba ina code signature halali.
- **`vnode_check_exec`**: Huitwa executable files zinapopakiwa kwenye memory na kuweka `cs_hard | cs_kill`, ambayo itaua process ikiwa ukurasa wowote utakuwa invalid<sup>[[2]](#references)</sup>
- **`vnode_check_getextattr`**: MacOS: Hukagua `com.apple.root.installed` na `isVnodeQuarantined()`
- **`vnode_check_setextattr`**: Kama get + entitlement ya `com.apple.private.allow-bless` na `internal-installer-equivalent`
- **`vnode_check_signature`**: Code inayoiita XNU kukagua code signature kwa kutumia entitlements, trust cache na `amfid`<sup>[[3]](#references)</sup>
- **`proc_check_run_cs_invalid`**: Huingilia calls za `ptrace()` (`PT_ATTACH` na `PT_TRACE_ME`). Hukagua kama kuna entitlements yoyote kati ya `get-task-allow`, `run-invalid-allow` na `run-unsigned-code`; ikiwa hakuna, hukagua kama debugging inaruhusiwa.
- **`proc_check_map_anon`**: Ikiwa mmap inaitwa na flag **`MAP_JIT`**, AMFI itakagua entitlement ya `dynamic-codesigning`.

`AMFI.kext` pia hufichua API kwa kernel extensions nyingine, na inawezekana kupata dependencies zake kwa:
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

Hii ni daemon inayoendesha katika user mode ambayo `AMFI.kext` itatumia kukagua code signatures katika user mode.\
Ili `AMFI.kext` iwasiliane na daemon, hutumia mach messages kupitia port `HOST_AMFID_PORT`, ambayo ni special port `18`.

Kumbuka kwamba katika macOS haiwezekani tena kwa root processes kuteka special ports, kwa sababu zinalindwa na `SIP` na ni launchd pekee inayoweza kuzipata. Katika iOS, hukaguliwa kwamba process inayotuma jibu ina CDHash ya `amfid` iliyowekwa hardcoded.

Inawezekana kuona wakati `amfid` inapoombwa kukagua binary na jibu lake kwa ku-debug na kuweka breakpoint katika `mach_msg`.

Mara ujumbe unapopokelewa kupitia special port, **MIG** hutumiwa kutuma kila function kwenye function inayoiita. Main functions zili-reverse-engineer na kuelezwa ndani ya kitabu.

### DYLD policy and library validation

Matoleo ya hivi karibuni ya `dyld` huita `amfi_check_dyld_policy_self()` mapema sana kutoka `configureProcessRestrictions()` ili kuuliza AMFI ikiwa process inaweza kutumia `DYLD_*` path variables, interposing, fallback paths, embedded variables, au kuvumilia library insertion iliyoshindwa. Kwa hivyo, wakati wa kuchunguza injection surface, haitoshi kukagua Mach-O load commands pekee: unahitaji pia kukagua entitlements na runtime flags ambazo AMFI itatafsiri kuwa `dyld` policy.

Mzunguko wa vitendo wa triage ni:
```bash
BIN=/path/to/app/Contents/MacOS/binary

# Interesting AMFI-related entitlements
codesign -d --entitlements :- "$BIN" 2>&1 | \
egrep "disable-library-validation|clear-library-validation|allow-dyld-environment-variables|allow-jit|allow-unsigned-executable-memory|disable-executable-page-protection|get-task-allow"

# Runtime flags / TeamID / hardened-runtime metadata
codesign -dvvv "$BIN" 2>&1 | egrep "TeamIdentifier=|Runtime Version|flags="
```
Kwenye macOS za kisasa, Apple binaries nyingi hazibebi tena `com.apple.security.cs.disable-library-validation` moja kwa moja, bali husafirisha `com.apple.private.security.clear-library-validation`. Katika hali hiyo, library validation haizimwi wakati wa `execve`: mchakato lazima uite `csops(..., CS_OPS_CLEAR_LV, ...)` dhidi yake wenyewe, na XNU inaruhusu operesheni hiyo kwenye mchakato unaoiita pekee wakati entitlement ipo. Kwa mtazamo wa offensive, hili ni muhimu kwa sababu target inaweza kuwa injectable **baada tu** ya kufikia code path inayofuta LV waziwazi (kwa mfano, muda mfupi kabla ya kupakia optional plugins).<sup>[[4]](#references)[[5]](#references)</sup>

## Provisioning Profiles

Provisioning profile inaweza kutumika kusaini code. Kuna profile za **Developer** zinazoweza kutumika kusaini code na kuifanyia majaribio, na profile za **Enterprise** zinazoweza kutumika kwenye devices zote.

Baada ya App kuwasilishwa kwenye Apple Store, ikiwa imeidhinishwa, husainiwa na Apple na provisioning profile haihitajiki tena.

Profile kwa kawaida hutumia extension `.mobileprovision` au `.provisionprofile` na inaweza kutolewa kwa:
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
Ingawa wakati mwingine huitwa certificated, hizi provisioning profiles zina zaidi ya certificate moja:

- **AppIDName:** Application Identifier
- **AppleInternalProfile**: Huainisha hii kama Apple Internal profile
- **ApplicationIdentifierPrefix**: Huongezwa mwanzoni mwa AppIDName (sawa na TeamIdentifier)
- **CreationDate**: Tarehe katika muundo wa `YYYY-MM-DDTHH:mm:ssZ`
- **DeveloperCertificates**: Array ya certificate (kwa kawaida moja), iliyosimbwa kama Base64 data
- **Entitlements**: Entitlements zinazoruhusiwa kwa entitlements za profile hii
- **ExpirationDate**: Tarehe ya kuisha katika muundo wa `YYYY-MM-DDTHH:mm:ssZ`
- **Name**: Application Name, sawa na AppIDName
- **ProvisionedDevices**: Array (kwa developer certificates) ya UDIDs ambazo profile hii ni halali kwao
- **ProvisionsAllDevices**: Boolean (true kwa enterprise certificates)
- **TeamIdentifier**: Array ya string(s) za alphanumeric (kwa kawaida moja) zinazotumika kumtambua developer kwa madhumuni ya inter-app interaction
- **TeamName**: Jina linaloweza kusomeka na binadamu linalotumika kumtambua developer
- **TimeToLive**: Uhalali (kwa siku) wa certificate
- **UUID**: Universally Unique Identifier ya profile hii
- **Version**: Kwa sasa imewekwa kuwa 1

Kumbuka kwamba entry ya entitlements itakuwa na seti iliyowekewa mipaka ya entitlements, na provisioning profile itaweza kutoa entitlements hizo maalum pekee ili kuzuia kutoa Apple private entitlements.

Kumbuka kwamba profiles kwa kawaida hupatikana katika `/var/MobileDeviceProvisioningProfiles`, na inawezekana kuzikagua kwa **`security cms -D -i /path/to/profile`**

## **libmis.dylib**

Hii ni external library ambayo `amfid` huiita ili kuuliza ikiwa inapaswa kuruhusu kitu au la. Kihistoria, imetumiwa vibaya katika jailbreaking kwa kuendesha toleo lake lenye backdoor ambalo lingeruhusu kila kitu.

Katika macOS, hii iko ndani ya `MobileDevice.framework`.

## AMFI Trust Caches

Trust caches si dhana ya iOS pekee. Katika macOS za kisasa, hasa kwenye **Apple silicon**, static trust cache na loadable trust caches ni sehemu ya Secure Boot chain. Wakati **CodeDirectory hash** ya Mach-O inapopatikana humo, AMFI inaweza kuipa **platform privilege** bila kufanya authenticity checks zaidi wakati wa launch. Hii pia inamaanisha kwamba Apple inaweza kufunga platform binaries kwenye toleo maalum la OS na kuzuia Apple-signed binaries za zamani zisireplayiwe kwenye systems mpya.<sup>[[6]](#references)</sup>

Kwenye matoleo ya hivi karibuni ya macOS, trust-cache metadata pia imeunganishwa na **launch constraints**, kwa hiyo system apps na binaries zilizonakiliwa na kuanzishwa kutoka kwa parent/location isiyo sahihi zinaweza kukataliwa na AMFI hata kama bado zina Apple signature. Workflow ya kina ya extraction na reversing imeelezwa katika:

{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

Katika iOS na utafiti wa jailbreak bado utapata traditional model ya **loadable trust caches** ikitumiwa ku-whitelist binaries zilizosainiwa kwa ad-hoc.

## References

- [1] [XNU — `security/mac_policy.h` (MACF policy ops AMFI registers, incl. `mpo_policy_syscall`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `osfmk/kern/cs_blobs.h` (`CS_*` code-signing flags AMFI sets)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [3] [XNU — `bsd/kern/ubc_subr.c` (code-signature blob parsing and validation)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/ubc_subr.c)
- [4] [XNU — `bsd/sys/codesign.h` (`CS_OPS_*` operations and `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [5] [XNU — `bsd/kern/kern_proc.c` (`csops` / `CS_OPS_CLEAR_LV` handler)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [6] [Apple Platform Security Guide — Trust caches](https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web)

{{#include ../../../banners/hacktricks-training.md}}
