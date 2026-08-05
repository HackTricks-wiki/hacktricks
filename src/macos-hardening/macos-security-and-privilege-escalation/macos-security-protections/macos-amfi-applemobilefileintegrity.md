# macOS - AMFI - AppleMobileFileIntegrity

{{#include ../../../banners/hacktricks-training.md}}

## AppleMobileFileIntegrity.kext na amfid

Inalenga kutekeleza uadilifu wa code inayotumika kwenye mfumo, huku ikitoa logic iliyo nyuma ya uthibitishaji wa code signature wa XNU. Pia inaweza kukagua entitlements na kushughulikia kazi nyingine nyeti kama kuruhusu debugging au kupata task ports.

Zaidi ya hayo, kwa baadhi ya operations, kext hupendelea kuwasiliana na daemon ya user space `/usr/libexec/amfid`. Uhusiano huu wa trust umetumiwa vibaya katika jailbreaks kadhaa.

Kwenye matoleo ya hivi karibuni ya macOS, AMFI haionyeshwi tena kwa urahisi kama kext inayojitegemea kwenye disk, hivyo reversing kwa kawaida humaanisha kufanya kazi kutoka kwa **kernelcache** au **KDK** badala ya kuvinjari `/System/Library/Extensions`.

AMFI hutumia policies za **MACF** na husajili hooks zake mara tu inapoanzishwa. Pia, kuzuia kupakiwa kwake au kuiondoa kunaweza kusababisha kernel panic. Hata hivyo, kuna boot arguments zinazowezesha kudhoofisha AMFI:

- `amfi_unrestricted_task_for_pid`: Huruhusu task_for_pid bila entitlements zinazohitajika
- `amfi_allow_any_signature`: Huruhusu code signature yoyote
- `cs_enforcement_disable`: Argument ya mfumo mzima inayotumika kuzima utekelezaji wa code signing
- `amfi_prevent_old_entitled_platform_binaries`: Hubatilisha platform binaries zilizo na entitlements
- `amfi_get_out_of_my_way`: Huzima amfi kabisa

Hizi ni baadhi ya policies za MACF inazozisajili:<sup>[1]</sup>

- **`cred_check_label_update_execve:`** Label update itafanywa na irejeshe 1
- **`cred_label_associate`**: Husasisha AMFI's mac label slot kwa kutumia label
- **`cred_label_destroy`**: Huondoa AMFI’s mac label slot
- **`cred_label_init`**: Hupeleka 0 kwenye AMFI's mac label slot
- **`cred_label_update_execve`:** Hukagua entitlements za process ili kuona kama inapaswa kuruhusiwa kurekebisha labels.
- **`file_check_mmap`:** Hukagua kama mmap inapata memory na kuiweka kama executable. Katika hali hiyo hukagua kama library validation inahitajika na, ikiwa inahitajika, huita library validation function.
- **`file_check_library_validation`**: Huita library validation function ambayo hukagua, miongoni mwa mambo mengine, kama platform binary inapakia platform binary nyingine au kama process na file mpya iliyopakiwa zina TeamID sawa. Entitlements fulani pia zitaruhusu kupakia library yoyote.
- **`policy_initbsd`**: Huandaa Trusted NVRAM Keys
- **`policy_syscall`**: Hukagua DYLD policies kama binary ina unrestricted segments, kama inapaswa kuruhusu env vars... pia hii huitwa process inapoanzishwa kupitia `amfi_check_dyld_policy_self()`.
- **`proc_check_inherit_ipc_ports`**: Hukagua kama process inapotekeleza binary mpya, processes nyingine zenye SEND rights juu ya task port ya process hiyo zinapaswa kuendelea kuzitumia au la. Platform binaries zinaruhusiwa, entitlement ya `get-task-allow` inaruhusu, entitlements za `task_for_pid-allow` zinaruhusiwa, pamoja na binaries zenye TeamID sawa.
- **`proc_check_expose_task`**: Hutekeleza entitlements
- **`amfi_exc_action_check_exception_send`**: Ujumbe wa exception hutumwa kwa debugger
- **`amfi_exc_action_label_associate & amfi_exc_action_label_copy/populate & amfi_exc_action_label_destroy & amfi_exc_action_label_init & amfi_exc_action_label_update`**: Mzunguko wa maisha wa label wakati wa kushughulikia exception (debugging)
- **`proc_check_get_task`**: Hukagua entitlements kama `get-task-allow`, inayoruhusu processes nyingine kupata task port ya process, na `task_for_pid-allow`, inayoruhusu process kupata task ports za processes nyingine. Ikiwa hakuna kati ya hizo, huita `amfid permitunrestricteddebugging` ili kukagua kama inaruhusiwa.
- **`proc_check_mprotect`**: Hukataa ikiwa `mprotect` inaitwa ikiwa na flag ya `VM_PROT_TRUSTED`, inayoonyesha kuwa region inapaswa kuchukuliwa kana kwamba ina code signature halali.
- **`vnode_check_exec`**: Huitwa executable files zinapopakiwa kwenye memory na kuweka `cs_hard | cs_kill`, ambayo itaua process ikiwa page yoyote itakuwa invalid<sup>[2]</sup>
- **`vnode_check_getextattr`**: MacOS: Hukagua `com.apple.root.installed` na `isVnodeQuarantined()`
- **`vnode_check_setextattr`**: Kama get + com.apple.private.allow-bless na internal-installer-equivalent entitlement
- **`vnode_check_signature`**: Code inayoiita XNU ili ikague code signature kwa kutumia entitlements, trust cache na `amfid`<sup>[3]</sup>
- **`proc_check_run_cs_invalid`**: Huingilia calls za `ptrace()` (`PT_ATTACH` na `PT_TRACE_ME`). Hukagua uwepo wa entitlements `get-task-allow`, `run-invalid-allow` na `run-unsigned-code`, na ikiwa hakuna, hukagua kama debugging inaruhusiwa.
- **`proc_check_map_anon`**: Ikiwa mmap inaitwa ikiwa na flag ya **`MAP_JIT`**, AMFI itakagua entitlement ya `dynamic-codesigning`.

`AMFI.kext` pia hutoa API kwa kernel extensions nyingine, na inawezekana kupata dependencies zake kwa kutumia:
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

Hii ni daemon inayotumika katika user mode ambayo `AMFI.kext` itatumia kukagua code signatures katika user mode.\
Ili `AMFI.kext` iwasiliane na daemon, hutumia mach messages kupitia port `HOST_AMFID_PORT`, ambayo ni special port `18`.

Kumbuka kwamba katika macOS, root processes hawawezi tena kuteka special ports, kwa sababu zinalindwa na `SIP` na ni launchd pekee inayoweza kuzipata. Katika iOS, hukaguliwa kwamba process inayotuma response ni ile iliyo na CDHash ya `amfid` iliyowekwa hardcoded.

Inawezekana kuona wakati `amfid` inapoulizwa kukagua binary na response yake kwa ku-debug na kuweka breakpoint katika `mach_msg`.

Mara ujumbe unapopokelewa kupitia special port, **MIG** hutumiwa kutuma kila function kwenye function inayoiita. Main functions zilibadilishwa reverse engineering na kuelezwa ndani ya kitabu.

### Sera ya DYLD na uthibitishaji wa library

Matoleo ya hivi karibuni ya `dyld` huita `amfi_check_dyld_policy_self()` mapema sana kutoka `configureProcessRestrictions()` ili kuuliza AMFI ikiwa process inaweza kutumia path variables za `DYLD_*`, interposing, fallback paths, embedded variables, au kuvumilia library insertion iliyoshindikana. Kwa hiyo, wakati wa kuchambua injection surface, haitoshi kukagua Mach-O load commands pekee: unahitaji pia kukagua entitlements na runtime flags ambazo AMFI itatafsiri kuwa sera ya `dyld`.

Mchakato wa vitendo wa triage ni:
```bash
BIN=/path/to/app/Contents/MacOS/binary

# Interesting AMFI-related entitlements
codesign -d --entitlements :- "$BIN" 2>&1 | \
egrep "disable-library-validation|clear-library-validation|allow-dyld-environment-variables|allow-jit|allow-unsigned-executable-memory|disable-executable-page-protection|get-task-allow"

# Runtime flags / TeamID / hardened-runtime metadata
codesign -dvvv "$BIN" 2>&1 | egrep "TeamIdentifier=|Runtime Version|flags="
```
Kwenye macOS za kisasa, binary nyingi za Apple hazibebi tena `com.apple.security.cs.disable-library-validation` moja kwa moja, na badala yake huja na `com.apple.private.security.clear-library-validation`. Katika hali hiyo, library validation haizimwi wakati wa `execve`: mchakato lazima uite `csops(..., CS_OPS_CLEAR_LV, ...)` wenyewe, na XNU huruhusu operesheni hiyo kwenye mchakato unaoiita tu wakati entitlement ipo. Kwa mtazamo wa offensive, hili ni muhimu kwa sababu target inaweza kuwa injectable **baada tu** ya kufikia code path inayofuta LV waziwazi (kwa mfano, muda mfupi kabla ya kupakia optional plugins).<sup>[4][5]</sup>

## Provisioning Profiles

Provisioning profile inaweza kutumika kusaini code. Kuna profiles za **Developer** zinazoweza kutumika kusaini code na kuifanyia majaribio, na profiles za **Enterprise** zinazoweza kutumika kwenye vifaa vyote.

Baada ya App kuwasilishwa kwenye Apple Store, ikikubaliwa, husainiwa na Apple na provisioning profile haihitajiki tena.

Profile kwa kawaida hutumia extension `.mobileprovision` au `.provisionprofile` na inaweza kudumpiwa kwa:
```bash
openssl asn1parse -inform der -in /path/to/profile

# Or

security cms -D -i /path/to/profile
```
Ingawa wakati mwingine huitwa certificated, hizi provisioning profiles zina zaidi ya certificate moja:

- **AppIDName:** Kitambulisho cha Application
- **AppleInternalProfile**: Huashiria kwamba hii ni Apple Internal profile
- **ApplicationIdentifierPrefix**: Huongezwa mwanzoni mwa AppIDName (sawa na TeamIdentifier)
- **CreationDate**: Tarehe katika muundo wa `YYYY-MM-DDTHH:mm:ssZ`
- **DeveloperCertificates**: Array ya certificate moja au zaidi (kwa kawaida moja), iliyosimbwa kama data ya Base64
- **Entitlements**: Entitlements zinazoruhusiwa pamoja na entitlements za profile hii
- **ExpirationDate**: Tarehe ya kuisha katika muundo wa `YYYY-MM-DDTHH:mm:ssZ`
- **Name**: Jina la Application, sawa na AppIDName
- **ProvisionedDevices**: Array (kwa developer certificates) ya UDIDs ambazo profile hii ni halali kwake
- **ProvisionsAllDevices**: Boolean (true kwa enterprise certificates)
- **TeamIdentifier**: Array ya string moja au zaidi za alphanumeric (kwa kawaida moja), zinazotumika kumtambua developer kwa madhumuni ya inter-app interaction
- **TeamName**: Jina linaloweza kusomeka na binadamu linalotumika kumtambua developer
- **TimeToLive**: Uhalali wa certificate (kwa siku)
- **UUID**: Kitambulisho cha kipekee kote ulimwenguni cha profile hii
- **Version**: Kwa sasa imewekwa kuwa 1

Kumbuka kwamba entry ya entitlements itakuwa na seti iliyozuiwa ya entitlements, na provisioning profile itaweza kutoa entitlements hizo maalum pekee ili kuzuia kutolewa kwa Apple private entitlements.

Kumbuka kwamba profiles kwa kawaida hupatikana katika `/var/MobileDeviceProvisioningProfiles`, na inawezekana kuzikagua kwa **`security cms -D -i /path/to/profile`**

## **libmis.dylib**

Hii ni external library ambayo `amfid` huiita ili kuuliza kama inapaswa kuruhusu kitu au la. Kwa kihistoria, imetumiwa vibaya katika jailbreaking kwa kuendesha toleo lake lililo na backdoor ambalo lingeruhusu kila kitu.

Katika macOS, hii imo ndani ya `MobileDevice.framework`.

## AMFI Trust Caches

Trust caches si dhana ya iOS pekee. Katika macOS za kisasa, hasa kwenye **Apple silicon**, static trust cache na loadable trust caches ni sehemu ya Secure Boot chain. Hash ya **CodeDirectory** ya Mach-O inapokuwepo humo, AMFI inaweza kuipa **platform privilege** bila kufanya authenticity checks zaidi wakati wa kuizindua. Hii pia inamaanisha kwamba Apple inaweza kufunga platform binaries kwenye toleo maalum la OS na kuzuia Apple-signed binaries za zamani kuchezeshwa tena kwenye systems mpya.<sup>[6]</sup>

Kwenye matoleo ya hivi karibuni ya macOS, metadata ya trust cache pia inahusishwa na **launch constraints**, kwa hivyo system apps na binaries zilizonakiliwa na kuanzishwa kutoka kwa parent/location isiyofaa zinaweza kukataliwa na AMFI hata kama bado zina Apple signature. Workflow ya kina ya extraction na reversing imeelezwa katika:

{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

Katika iOS na jailbreak research bado utapata traditional model ya **loadable trust caches** ikitumika kuweka kwenye whitelist binaries zilizosainiwa kwa ad-hoc.

## References

- [1] [XNU — `security/mac_policy.h` (MACF policy ops AMFI registers, incl. `mpo_policy_syscall`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `osfmk/kern/cs_blobs.h` (`CS_*` code-signing flags AMFI sets)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [3] [XNU — `bsd/kern/ubc_subr.c` (code-signature blob parsing and validation)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/ubc_subr.c)
- [4] [XNU — `bsd/sys/codesign.h` (`CS_OPS_*` operations and `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [5] [XNU — `bsd/kern/kern_proc.c` (`csops` / `CS_OPS_CLEAR_LV` handler)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [6] [Apple Platform Security Guide — Trust caches](https://support.apple.com/guide/security/trust-caches-sec7d38fbf97/web)

{{#include ../../../banners/hacktricks-training.md}}
