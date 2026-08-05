# macOS Sandbox

{{#include ../../../../banners/hacktricks-training.md}}

## Taarifa za Msingi

MacOS Sandbox (hapo awali iliitwa Seatbelt) **huzuia applications** zinazoendeshwa ndani ya sandbox kutekeleza **vitendo vilivyoruhusiwa vilivyobainishwa kwenye Sandbox profile** ambayo app inaendeshwa nayo. Hii husaidia kuhakikisha kuwa **application itafikia rasilimali zinazotarajiwa pekee**.

App yoyote yenye **entitlement** **`com.apple.security.app-sandbox`** itaendeshwa ndani ya sandbox. **Apple binaries** kwa kawaida huendeshwa ndani ya Sandbox, na applications zote kutoka **App Store zina entitlement hiyo**. Kwa hiyo, applications kadhaa zitaendeshwa ndani ya sandbox.<sup>[4]</sup>

Ili kudhibiti kile ambacho process inaweza au haiwezi kufanya, **Sandbox ina hooks** katika karibu kila operation ambayo process inaweza kujaribu (ikiwemo syscalls nyingi), kwa kutumia **MACF**. Hata hivyo, k**ulingana** na **entitlements** za app, Sandbox inaweza kuwa yenye ruhusa zaidi kwa process.

Baadhi ya vipengele muhimu vya Sandbox ni:

- **kernel extension** `/System/Library/Extensions/Sandbox.kext`
- **private framework** `/System/Library/PrivateFrameworks/AppSandbox.framework`
- **daemon** inayoendesha katika userland `/usr/libexec/sandboxd`
- **containers** `~/Library/Containers`

### Containers

Kila application iliyo ndani ya sandbox itakuwa na container yake katika `~/Library/Containers/{CFBundleIdentifier}` :
```bash
ls -l ~/Library/Containers
total 0
drwx------@ 4 username  staff  128 May 23 20:20 com.apple.AMPArtworkAgent
drwx------@ 4 username  staff  128 May 23 20:13 com.apple.AMPDeviceDiscoveryAgent
drwx------@ 4 username  staff  128 Mar 24 18:03 com.apple.AVConference.Diagnostic
drwx------@ 4 username  staff  128 Mar 25 14:14 com.apple.Accessibility-Settings.extension
drwx------@ 4 username  staff  128 Mar 25 14:10 com.apple.ActionKit.BundledIntentHandler
[...]
```
Ndani ya kila folda ya bundle id, unaweza kupata **plist** na **Data directory** ya App yenye muundo unaofanana na Home folder:
```bash
cd /Users/username/Library/Containers/com.apple.Safari
ls -la
total 104
drwx------@   4 username  staff    128 Mar 24 18:08 .
drwx------  348 username  staff  11136 May 23 20:57 ..
-rw-r--r--    1 username  staff  50214 Mar 24 18:08 .com.apple.containermanagerd.metadata.plist
drwx------   13 username  staff    416 Mar 24 18:05 Data

ls -l Data
total 0
drwxr-xr-x@  8 username  staff   256 Mar 24 18:08 CloudKit
lrwxr-xr-x   1 username  staff    19 Mar 24 18:02 Desktop -> ../../../../Desktop
drwx------   2 username  staff    64 Mar 24 18:02 Documents
lrwxr-xr-x   1 username  staff    21 Mar 24 18:02 Downloads -> ../../../../Downloads
drwx------  35 username  staff  1120 Mar 24 18:08 Library
lrwxr-xr-x   1 username  staff    18 Mar 24 18:02 Movies -> ../../../../Movies
lrwxr-xr-x   1 username  staff    17 Mar 24 18:02 Music -> ../../../../Music
lrwxr-xr-x   1 username  staff    20 Mar 24 18:02 Pictures -> ../../../../Pictures
drwx------   2 username  staff    64 Mar 24 18:02 SystemData
drwx------   2 username  staff    64 Mar 24 18:02 tmp
```
> [!CAUTION]
> Kumbuka kwamba hata kama symlinks zipo ili "escape" kutoka kwenye Sandbox na kufikia folders nyingine, App bado inahitaji **kuwa na permissions** za kuzifikia. Permissions hizi ziko ndani ya **`.plist`** katika `RedirectablePaths`.

**`SandboxProfileData`** ni sandbox profile ya CFData iliyocompiliwa na ku-escape kuwa B64.
```bash
# Get container config
## You need FDA to access the file, not even just root can read it
plutil -convert xml1 .com.apple.containermanagerd.metadata.plist -o -

# Binary sandbox profile
<key>SandboxProfileData</key>
<data>
AAAhAboBAAAAAAgAAABZAO4B5AHjBMkEQAUPBSsGPwsgASABHgEgASABHwEf...

# In this file you can find the entitlements:
<key>Entitlements</key>
<dict>
<key>com.apple.MobileAsset.PhishingImageClassifier2</key>
<true/>
<key>com.apple.accounts.appleaccount.fullaccess</key>
<true/>
<key>com.apple.appattest.spi</key>
<true/>
<key>keychain-access-groups</key>
<array>
<string>6N38VWS5BX.ru.keepcoder.Telegram</string>
<string>6N38VWS5BX.ru.keepcoder.TelegramShare</string>
</array>
[...]

# Some parameters
<key>Parameters</key>
<dict>
<key>_HOME</key>
<string>/Users/username</string>
<key>_UID</key>
<string>501</string>
<key>_USER</key>
<string>username</string>
[...]

# The paths it can access
<key>RedirectablePaths</key>
<array>
<string>/Users/username/Downloads</string>
<string>/Users/username/Documents</string>
<string>/Users/username/Library/Calendars</string>
<string>/Users/username/Desktop</string>
<key>RedirectedPaths</key>
<array/>
[...]
```
> [!WARNING]
> Kila kitu kilichoundwa/kirekebishwa na application iliyo kwenye Sandbox kitapata **quarantine attribut**e. Hii itazuia nafasi ya sandbox kwa kuanzisha Gatekeeper ikiwa sandbox app itajaribu kutekeleza kitu kwa kutumia **`open`**.

## Sandbox Profiles

Sandbox profiles ni faili za usanidi zinazoonyesha kile kitakachokuwa **kimeruhusiwa/kimekatazwa** katika hiyo **Sandbox**. Inatumia **Sandbox Profile Language (SBPL)**, ambayo hutumia lugha ya programming ya [**Scheme**](<https://en.wikipedia.org/wiki/Scheme_(programming_language)>).

Hapa unaweza kupata mfano:
```scheme
(version 1) ; First you get the version

(deny default) ; Then you shuold indicate the default action when no rule applies

(allow network*) ; You can use wildcards and allow everything

(allow file-read* ; You can specify where to apply the rule
(subpath "/Users/username/")
(literal "/tmp/afile")
(regex #"^/private/etc/.*")
)

(allow mach-lookup
(global-name "com.apple.analyticsd")
)
```
> [!TIP]
> Angalia [**research**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) hii **ili kukagua actions zaidi ambazo zinaweza kuruhusiwa au kukataliwa.**<sup>[5]</sup>
>
> Kumbuka kuwa katika toleo lililocompile la profile, majina ya operations yanabadilishwa na entries zao katika array inayojulikana na dylib na kext, hivyo kufanya toleo lililocompile kuwa fupi na gumu zaidi kusomeka.

**system services** muhimu pia huendesha ndani ya **sandbox** yao maalum, kama vile service ya `mdnsresponder`. Unaweza kuangalia **sandbox profiles** hizi ndani ya:

- **`/usr/share/sandbox`**
- **`/System/Library/Sandbox/Profiles`**
- Sandbox profiles nyingine zinaweza kukaguliwa katika [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles).
- Katika iOS, platform profile ziko ndani ya `.kext` ya sandbox, kwenye `_platform_profile_data` ndani ya binary.

Apps za **App Store** hutumia **profile** **`/System/Library/Sandbox/Profiles/application.sb`**. Unaweza kuangalia katika profile hii jinsi entitlements kama **`com.apple.security.network.server`** zinavyoruhusu process kutumia network.

Kisha, baadhi ya **Apple daemon services** hutumia profiles tofauti zilizoko katika `/System/Library/Sandbox/Profiles/*.sb` au `/usr/share/sandbox/*.sb`. Sandboxes hizi hutumika katika main function inayoiita API `sandbox_init_XXX`.<sup>[3]</sup>

**SIP** ni Sandbox profile inayoitwa platform_profile katika `/System/Library/Sandbox/rootless.conf`.

### Mifano ya Sandbox Profile

Ili kuanzisha application kwa kutumia **sandbox profile maalum**, unaweza kutumia:
```bash
sandbox-exec -f example.sb /Path/To/The/Application
sandbox-exec -n no-internet ping 8.8.8.8
```
{{#tabs}}
{{#tab name="touch"}}
```scheme:touch.sb
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
```

```bash
# This will fail because default is denied, so it cannot execute touch
sandbox-exec -f touch.sb touch /tmp/hacktricks.txt
# Check logs
log show --style syslog --predicate 'eventMessage contains[c] "sandbox"' --last 30s
[...]
2023-05-26 13:42:44.136082+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) process-exec* /usr/bin/touch
2023-05-26 13:42:44.136100+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /usr/bin/touch
2023-05-26 13:42:44.136321+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
2023-05-26 13:42:52.701382+0200  localhost kernel[0]: (Sandbox) 5 duplicate reports for Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
[...]
```

```scheme:touch2.sb
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
; This will also fail because:
; 2023-05-26 13:44:59.840002+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/bin/touch
; 2023-05-26 13:44:59.840016+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin/touch
; 2023-05-26 13:44:59.840028+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin
; 2023-05-26 13:44:59.840034+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/lib/dyld
; 2023-05-26 13:44:59.840050+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) sysctl-read kern.bootargs
; 2023-05-26 13:44:59.840061+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /
```

```scheme:touch3.sb
(version 1)
(deny default)
(allow file* (literal "/private/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
(allow file-read-data (literal "/"))
; This one will work
```
{{#endtab}}
{{#endtabs}}

> [!TIP]
> Kumbuka kwamba **software** iliyoandikwa na **Apple** inayotumika kwenye **Windows** **haina tahadhari za ziada za kiusalama**, kama vile application sandboxing.

Mifano ya bypasses:

- [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)<sup>[6]</sup>
- [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (wanaweza kuandika files nje ya sandbox ambayo jina lake huanza na `~$`).<sup>[7]</sup>

### Ufuatiliaji wa Sandbox

#### Kupitia profile

Inawezekana kufuatilia checks zote ambazo sandbox hufanya kila mara action inapokaguliwa. Ili kufanya hivyo, tengeneza profile ifuatayo:
```scheme:trace.sb
(version 1)
(trace /tmp/trace.out)
```
Na kisha tekeleza tu kitu ukitumia hiyo profile:
```bash
sandbox-exec -f /tmp/trace.sb /bin/ls
```
Katika `/tmp/trace.out` utaweza kuona kila ukaguzi wa sandbox uliofanywa kila mara ulipoitwa (kwa hiyo, kuna nakala nyingi zinazorudiwa).

Pia inawezekana kufuatilia sandbox kwa kutumia parameter ya **`-t`**: `sandbox-exec -t /path/trace.out -p "(version 1)" /bin/ls`

#### Kupitia API

Function `sandbox_set_trace_path` iliyotolewa na `libsystem_sandbox.dylib` inaruhusu kubainisha jina la faili la trace ambapo ukaguzi wa sandbox utaandikwa.\
Pia inawezekana kufanya kitu kama hicho kwa kuita `sandbox_vtrace_enable()` na kisha kupata error logs kutoka kwenye buffer kwa kuita `sandbox_vtrace_report()`.

### Ukaguzi wa Sandbox

`libsandbox.dylib` inatoa function inayoitwa sandbox_inspect_pid ambayo hutoa orodha ya hali ya sandbox ya process (ikiwemo extensions). Hata hivyo, ni platform binaries pekee zinazoweza kutumia function hii.

### MacOS & iOS Sandbox Profiles

MacOS huhifadhi sandbox profiles za mfumo katika maeneo mawili: **/usr/share/sandbox/** na **/System/Library/Sandbox/Profiles**.

Na ikiwa third-party application ina _**com.apple.security.app-sandbox**_ entitlement, mfumo hutumia profile ya **/System/Library/Sandbox/Profiles/application.sb** kwa process hiyo.

Katika iOS, profile chaguo-msingi inaitwa **container** na hatuna uwasilishaji wa maandishi wa SBPL. Kwenye memory, sandbox hii huwakilishwa kama mti wa binary wa Allow/Deny kwa kila permission ya sandbox.

### Custom SBPL in App Store apps

Inawezekana kampuni zikaendesha apps zao **kwa kutumia custom Sandbox profiles** (badala ya ile ya chaguo-msingi). Zinahitaji kutumia entitlement **`com.apple.security.temporary-exception.sbpl`**, ambayo inahitaji kuidhinishwa na Apple.

Inawezekana kuangalia definition ya entitlement hii katika **`/System/Library/Sandbox/Profiles/application.sb:`**
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
Hii **ita-eval string baada ya entitlement hii** kama Sandbox profile.

### Ku-compile & ku-decompile Sandbox Profile

Tool ya **`sandbox-exec`** hutumia functions `sandbox_compile_*` kutoka `libsandbox.dylib`. Functions kuu zilizo-export ni: `sandbox_compile_file` (inatarajia file path, param `-f`), `sandbox_compile_string` (inatarajia string, param `-p`), `sandbox_compile_name` (inatarajia jina la container, param `-n`), `sandbox_compile_entitlements` (inatarajia entitlements plist).

Toleo hili lililofanyiwa reverse na [**open sourced version of the tool sandbox-exec**](https://newosxbook.com/src.jl?tree=listings&file=/sandbox_exec.c) linaruhusu kufanya **`sandbox-exec`** iandike sandbox profile iliyocompile kwenye file.

Zaidi ya hayo, ili ku-confine process ndani ya container, inaweza kuita `sandbox_spawnattrs_set[container/profilename]` na kupitisha container au profile iliyokuwepo awali.

## Debug & Bypass Sandbox

Kwenye macOS, tofauti na iOS ambapo processes husandboxiwa na kernel tangu mwanzo, **processes lazima zijijumuishe kwenye sandbox zenyewe**. Hii inamaanisha kuwa kwenye macOS, process haizuiwi na sandbox hadi iamue kuingia ndani yake, ingawa apps za App Store huwa sandboxed kila wakati.

Processes husandboxiwa automatically kutoka userland zinapoanza ikiwa zina entitlement: `com.apple.security.app-sandbox`. Kwa maelezo ya kina kuhusu process hii, angalia:


{{#ref}}
macos-sandbox-debug-and-bypass/
{{#endref}}

## **Sandbox Extensions**

Extensions huruhusu kuipa object privileges zaidi na hutolewa kwa kuita mojawapo ya functions hizi:

- `sandbox_issue_extension`
- `sandbox_extension_issue_file[_with_new_type]`
- `sandbox_extension_issue_mach`
- `sandbox_extension_issue_iokit_user_client_class`
- `sandbox_extension_issue_iokit_registry_rentry_class`
- `sandbox_extension_issue_generic`
- `sandbox_extension_issue_posix_ipc`

Extensions huhifadhiwa katika MACF label slot ya pili inayofikiwa kutoka kwenye process credentials. **`sbtool`** ifuatayo inaweza kufikia taarifa hii.

Kumbuka kuwa extensions kwa kawaida hutolewa na processes zinazoruhusiwa; kwa mfano, `tccd` itatoa extension token ya `com.apple.tcc.kTCCServicePhotos` wakati process ilijaribu kufikia photos na ikaruhusiwa kupitia ujumbe wa XPC. Kisha process itahitaji kutumia extension token hiyo ili iongezwe kwake.\
Kumbuka kuwa extension tokens ni hexadecimal ndefu zinazoweka kwa njia ya encoding permissions zilizotolewa. Hata hivyo, hazina PID iliyoruhusiwa ikiwa hardcoded, jambo linalomaanisha kuwa process yoyote yenye access kwa token hiyo inaweza **kutumiwa na processes nyingi**.

Kumbuka kuwa extensions pia zinahusiana sana na entitlements; hivyo, kuwa na entitlements fulani kunaweza kutoa extensions fulani automatically.

### **Kukagua PID Privileges**

[**Kulingana na hii**](https://www.youtube.com/watch?v=mG715HcDgO8&t=3011s), functions za **`sandbox_check`** (ni `__mac_syscall`), zinaweza kukagua **ikiwa operation inaruhusiwa au la** na sandbox katika PID, audit token au unique ID fulani.<sup>[8]</sup>

[**Tool sbtool**](http://newosxbook.com/src.jl?tree=listings&file=sbtool.c) (ipate ikiwa [ime-compile hapa](https://newosxbook.com/articles/hitsb.html)) inaweza kukagua ikiwa PID inaweza kutekeleza actions fulani:
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explanation of the sandbox profile and extensions
sbtool <pid> all
```
### \[un]suspend

Pia inawezekana kususpend na ku-unsuspend sandbox kwa kutumia functions `sandbox_suspend` na `sandbox_unsuspend` kutoka `libsystem_sandbox.dylib`.

Kumbuka kwamba ili kuita suspend function, baadhi ya entitlements hukaguliwa ili kumruhusu caller kuiita, kama vile:

- com.apple.private.security.sandbox-manager
- com.apple.security.print
- com.apple.security.temporary-exception.audio-unit-host

## mac_syscall

System call hii (#381) inatarajia argument ya kwanza ikiwa string moja inayoonyesha module ya kuendesha, kisha code katika argument ya pili inayoonyesha function ya kuendesha. Argument ya tatu itategemea function iliyotekelezwa.<sup>[2]</sup>

Function `___sandbox_ms` hufanya wrapper ya `mac_syscall` kwa kuonyesha `"Sandbox"` katika argument ya kwanza, kama vile `___sandbox_msp` ilivyo wrapper ya `mac_set_proc` (#387). Kisha, baadhi ya codes zinazoungwa mkono na `___sandbox_ms` zinaweza kupatikana katika jedwali hili:

- **set_profile (#0)**: Tumia profile iliyocompilewa au yenye jina kwa process.
- **platform_policy (#1)**: Tekeleza ukaguzi wa policy maalum ya platform (hutofautiana kati ya macOS na iOS).
- **check_sandbox (#2)**: Fanya ukaguzi wa manually wa sandbox operation maalum.
- **note (#3)**: Ongeza annotation kwenye Sandbox.
- **container (#4)**: Ambatisha annotation kwenye sandbox, kwa kawaida kwa debugging au identification.
- **extension_issue (#5)**: Tengeneza extension mpya kwa process.
- **extension_consume (#6)**: Tumia extension iliyotolewa.
- **extension_release (#7)**: Toa memory iliyohusishwa na extension iliyotumiwa.
- **extension_update_file (#8)**: Rekebisha parameters za file extension iliyopo ndani ya sandbox.
- **extension_twiddle (#9)**: Rekebisha au badilisha file extension iliyopo (kwa mfano, TextEdit, rtf, rtfd).
- **suspend (#10)**: Suspend kwa muda ukaguzi wote wa sandbox (inahitajika entitlements zinazofaa).
- **unsuspend (#11)**: Endeleza tena ukaguzi wote wa sandbox uliokuwa suspended.
- **passthrough_access (#12)**: Ruhusu direct passthrough access kwa resource, ukipita ukaguzi wa sandbox.
- **set_container_path (#13)**: (iOS pekee) Weka container path kwa app group au signing ID.
- **container_map (#14)**: (iOS pekee) Pata container path kutoka `containermanagerd`.
- **sandbox_user_state_item_buffer_send (#15)**: (iOS 10+) Weka metadata ya user mode ndani ya sandbox.
- **inspect (#16)**: Toa debug information kuhusu process iliyo sandboxed.
- **dump (#18)**: (macOS 11) Dump profile ya sasa ya sandbox kwa ajili ya analysis.
- **vtrace (#19)**: Trace sandbox operations kwa monitoring au debugging.
- **builtin_profile_deactivate (#20)**: (macOS < 11) Deactivate profiles zenye majina (kwa mfano, `pe_i_can_has_debugger`).
- **check_bulk (#21)**: Fanya operations nyingi za `sandbox_check` katika call moja.
- **reference_retain_by_audit_token (#28)**: Tengeneza reference ya audit token kwa matumizi katika sandbox checks.
- **reference_release (#29)**: Toa audit token reference iliyokuwa retained.
- **rootless_allows_task_for_pid (#30)**: Thibitisha kama `task_for_pid` inaruhusiwa (sawa na ukaguzi wa `csr`).
- **rootless_whitelist_push (#31)**: (macOS) Tumia System Integrity Protection (SIP) manifest file.
- **rootless_whitelist_check (preflight) (#32)**: Kagua SIP manifest file kabla ya execution.
- **rootless_protected_volume (#33)**: (macOS) Tumia SIP protections kwenye disk au partition.
- **rootless_mkdir_protected (#34)**: Tumia SIP/DataVault protection kwenye mchakato wa kuunda directory.

## Sandbox.kext

Kumbuka kwamba katika iOS kernel extension ina **profiles zote hardcoded** ndani ya segment ya `__TEXT.__const` ili kuzuia zisibadilishwe. Zifuatazo ni baadhi ya functions zinazovutia kutoka kwenye kernel extension:

- **`hook_policy_init`**: Inahook `mpo_policy_init` na huitwa baada ya `mac_policy_register`. Inafanya sehemu kubwa ya initializations za Sandbox. Pia huinitialize SIP.
- **`hook_policy_initbsd`**: Huandaa sysctl interface kwa kusajili `security.mac.sandbox.sentinel`, `security.mac.sandbox.audio_active` na `security.mac.sandbox.debug_mode` (ikiwa imebootiwa na `PE_i_can_has_debugger`).
- **`hook_policy_syscall`**: Huitwa na `mac_syscall` ikiwa `"Sandbox"` ndiyo argument ya kwanza na code inayoonyesha operation ikiwa ya pili. Switch hutumiwa kupata code ya kuendesha kulingana na code iliyoombwa.

### MACF Hooks

**`Sandbox.kext`** hutumia zaidi ya hooks mia moja kupitia MACF. Nyingi ya hooks zitaangalia tu cases rahisi zinazoruhusu action kufanywa; ikiwa haziruhusu, zitaita **`cred_sb_evalutate`** kwa kutumia **credentials** kutoka MACF, namba inayolingana na **operation** ya kufanywa na **buffer** kwa output.<sup>[1]</sup>

Mfano mzuri wa hili ni function **`_mpo_file_check_mmap`**, ambayo inahook **`mmap`** na kuanza kuangalia kama memory mpya itakuwa writable (na ikiwa si hivyo kuruhusu execution), kisha itaangalia kama inatumika kwa dyld shared cache na ikiwa ni hivyo kuruhusu execution, na mwishowe itaita **`sb_evaluate_internal`** (au mojawapo ya wrappers zake) kufanya allowance checks zaidi.

Zaidi ya hooks mia moja zinazotumiwa na Sandbox, kuna 3 hasa zinazovutia sana:

- `mpo_proc_check_for`: Hutumia profile ikiwa inahitajika na ikiwa haikuwa imetumika hapo awali.
- `mpo_vnode_check_exec`: Huitwa process inapoload binary inayohusishwa; kisha profile check hufanywa pamoja na check inayokataza executions za SUID/SGID.
- `mpo_cred_label_update_execve`: Hii huitwa label inapowekwa. Hii ndiyo ndefu zaidi kwa sababu huitwa binary inapokuwa imepakiwa kikamilifu lakini bado haijaexecutiwa. Itafanya actions kama kuunda sandbox object, kuattach sandbox struct kwenye kauth credentials, kuondoa access kwa mach ports...

Kumbuka kwamba **`_cred_sb_evalutate`** ni wrapper juu ya **`sb_evaluate_internal`**, na function hii hupokea credentials zilizopitishwa kisha kufanya evaluation kwa kutumia function ya **`eval`**, ambayo kwa kawaida huevaluate **platform profile** inayotumika kwa default kwa processes zote, na kisha **specific process profile**. Kumbuka kwamba platform profile ni mojawapo ya components kuu za **SIP** katika macOS.

## Sandboxd

Sandbox pia ina user daemon inayoendesha na kufichua XPC Mach service `com.apple.sandboxd`, pamoja na ku-bind special port 14 (`HOST_SEATBELT_PORT`) ambayo kernel extension hutumia kuwasiliana nayo. Hufichua baadhi ya functions kwa kutumia MIG.

## References

- [1] [XNU — `security/mac_policy.h` (MACF hooks the Sandbox kext registers)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `security/mac_base.c` (`__mac_syscall`, the entry point behind `__sandbox_ms`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_base.c)
- [3] [`sandbox_init(3)` man page](https://keith.github.io/xcode-man-pages/sandbox_init.3.html)
- [4] [Apple Developer — App Sandbox](https://developer.apple.com/documentation/security/app-sandbox)
- [5] [Apple Sandbox Guide v1.0](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/)
- [6] [Mac sandbox escape](https://lapcatsoftware.com/articles/sandbox-escape.html)
- [7] [Office365 MacOS Sandbox Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [8] [HITBGSEC 2016 SG - The Apple Sandbox: Deeper Into The Quagmire - Jonathan Levin](https://www.youtube.com/watch?v=mG715HcDgO8&t=3011s)

{{#include ../../../../banners/hacktricks-training.md}}
