# macOS Sandbox

{{#include ../../../../banners/hacktricks-training.md}}

## Basic Information

MacOS Sandbox (awali ilijulikana kama Seatbelt) **inapunguza programu** zinazotembea ndani ya sandbox kwa **vitendo vilivyokubaliwa vilivyobainishwa katika profaili ya Sandbox** ambayo programu inatumia. Hii husaidia kuhakikisha kwamba **programu itakuwa inapata rasilimali zinazotarajiwa tu**.

Programu yoyote yenye **entitlement** **`com.apple.security.app-sandbox`** itatekelezwa ndani ya sandbox. **Apple binaries** kwa kawaida hutekelezwa ndani ya Sandbox, na programu zote kutoka kwa **App Store zina entitlement hiyo**. Hivyo, programu kadhaa zitatekelezwa ndani ya sandbox.

Ili kudhibiti kile mchakato unaweza au hawezi kufanya, **Sandbox ina hooks** katika karibu kila operesheni ambayo mchakato unaweza kujaribu (ikiwemo syscalls nyingi) kwa kutumia **MACF**. Hata hivyo, **kutegemea** na **entitlements** za programu, Sandbox inaweza kuwa na uvumilivu zaidi kwa mchakato.

Baadhi ya vipengele muhimu vya Sandbox ni:

- **kernel extension** `/System/Library/Extensions/Sandbox.kext`
- **private framework** `/System/Library/PrivateFrameworks/AppSandbox.framework`
- **daemon** inayotembea katika userland `/usr/libexec/sandboxd`
- **containers** `~/Library/Containers`

### Containers

Kila programu iliyo ndani ya sandbox itakuwa na kontena yake mwenyewe katika `~/Library/Containers/{CFBundleIdentifier}` :
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
Ndani ya kila folda ya kitambulisho cha kifurushi unaweza kupata **plist** na **Data directory** ya App yenye muundo unaofanana na folda ya Nyumbani:
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
> Kumbuka kwamba hata kama symlinks zipo ili "kutoroka" kutoka Sandbox na kufikia folda nyingine, App bado inahitaji **kuwa na ruhusa** za kuzifikia. Ruhusa hizi ziko ndani ya **`.plist`** katika `RedirectablePaths`.

**`SandboxProfileData`** ni profaili ya sandbox iliyokusanywa CFData iliyokwepwa hadi B64.
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
> Kila kitu kilichoundwa/kilibadilishwa na programu ya Sandboxed kitapata **sifa ya karantini**. Hii itazuia nafasi ya sandbox kwa kuanzisha Gatekeeper ikiwa programu ya sandbox itajaribu kutekeleza kitu kwa **`open`**.

## Profaili za Sandbox

Profaili za Sandbox ni faili za usanidi zinazoonyesha kile kitakachokuwa **kuruhusiwa/kuzuiwa** katika hiyo **Sandbox**. Inatumia **Sandbox Profile Language (SBPL)**, ambayo inatumia lugha ya programu ya [**Scheme**](<https://en.wikipedia.org/wiki/Scheme_(programming_language)>).

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
> Angalia hii [**utafiti**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) **kuangalia hatua zaidi ambazo zinaweza kuruhusiwa au kukataliwa.**
>
> Kumbuka kwamba katika toleo lililokusanywa la wasifu, majina ya operesheni yanabadilishwa na entries zao katika array inayojulikana na dylib na kext, na kufanya toleo lililokusanywa kuwa fupi na gumu kusoma.

Huduma muhimu za **sistimu** pia zinafanya kazi ndani ya **sandbox** zao maalum kama huduma ya `mdnsresponder`. Unaweza kuona hizi **sandbox profiles** maalum ndani ya:

- **`/usr/share/sandbox`**
- **`/System/Library/Sandbox/Profiles`**
- Wasifu wengine wa sandbox wanaweza kuangaliwa katika [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles).

Programu za **App Store** zinatumia **wasifu** **`/System/Library/Sandbox/Profiles/application.sb`**. Unaweza kuangalia katika wasifu huu jinsi ruhusa kama **`com.apple.security.network.server`** inavyoruhusu mchakato kutumia mtandao.

Kisha, baadhi ya **huduma za daemon za Apple** zinatumia wasifu tofauti zilizoko katika `/System/Library/Sandbox/Profiles/*.sb` au `/usr/share/sandbox/*.sb`. Sandboxes hizi zinatumika katika kazi kuu inayopiga simu kwa API `sandbox_init_XXX`.

**SIP** ni wasifu wa Sandbox unaoitwa platform_profile katika `/System/Library/Sandbox/rootless.conf`.

### Mifano ya Wasifu wa Sandbox

Ili kuanzisha programu na **wasifu maalum wa sandbox** unaweza kutumia:
```bash
sandbox-exec -f example.sb /Path/To/The/Application
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

> [!NOTE]
> Kumbuka kwamba **programu** **iliyoundwa na Apple** inayofanya kazi kwenye **Windows** **haina tahadhari za ziada za usalama**, kama vile sandboxing ya programu.

Mifano ya kupita:

- [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)
- [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (wanaweza kuandika faili nje ya sandbox ambayo jina lake linaanza na `~$`).

### Ufuatiliaji wa Sandbox

#### Kupitia profaili

Inawezekana kufuatilia ukaguzi wote sandbox inafanya kila wakati kitendo kinapokaguliwa. Kwa hivyo, tengeneza profaili ifuatayo:
```scheme:trace.sb
(version 1)
(trace /tmp/trace.out)
```
Na kisha tekeleza kitu chochote kwa kutumia profaili hiyo:
```bash
sandbox-exec -f /tmp/trace.sb /bin/ls
```
Katika `/tmp/trace.out` utaweza kuona kila ukaguzi wa sandbox uliofanywa kila wakati ulipokuwa ukitolewa (hivyo, kuna nakala nyingi).

Pia inawezekana kufuatilia sandbox kwa kutumia **`-t`** parameter: `sandbox-exec -t /path/trace.out -p "(version 1)" /bin/ls`

#### Kupitia API

Kazi `sandbox_set_trace_path` iliyosafirishwa na `libsystem_sandbox.dylib` inaruhusu kubainisha jina la faili la kufuatilia ambapo ukaguzi wa sandbox utaandikwa.\
Pia inawezekana kufanya kitu kama hicho kwa kuita `sandbox_vtrace_enable()` na kisha kupata makosa ya log kutoka kwenye buffer kwa kuita `sandbox_vtrace_report()`.

### Ukaguzi wa Sandbox

`libsandbox.dylib` inasafirisha kazi inayoitwa sandbox_inspect_pid ambayo inatoa orodha ya hali ya sandbox ya mchakato (ikiwemo nyongeza). Hata hivyo, ni binaries za jukwaa pekee ndizo zinaweza kutumia kazi hii.

### MacOS & iOS Sandbox Profiles

MacOS inahifadhi wasifu wa sandbox wa mfumo katika maeneo mawili: **/usr/share/sandbox/** na **/System/Library/Sandbox/Profiles**.

Na ikiwa programu ya upande wa tatu ina _**com.apple.security.app-sandbox**_ ruhusa, mfumo unatumia wasifu **/System/Library/Sandbox/Profiles/application.sb** kwa mchakato huo.

Katika iOS, wasifu wa kawaida unaitwa **container** na hatuna uwakilishi wa maandiko wa SBPL. Katika kumbukumbu, sandbox hii inawakilishwa kama mti wa binary wa Ruhusu/Kataa kwa kila ruhusa kutoka sandbox.

### SBPL Maalum katika programu za App Store

Inawezekana kwa kampuni kufanya programu zao zifanye kazi **na wasifu wa Sandbox maalum** (badala ya wa kawaida). Wanahitaji kutumia ruhusa **`com.apple.security.temporary-exception.sbpl`** ambayo inahitaji kuidhinishwa na Apple.

Inawezekana kuangalia ufafanuzi wa ruhusa hii katika **`/System/Library/Sandbox/Profiles/application.sb:`**
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
Hii itakuwa **eval string baada ya haki hii** kama profaili ya Sandbox.

### Kuunda & Kuondoa Profaili ya Sandbox

Zana ya **`sandbox-exec`** inatumia kazi `sandbox_compile_*` kutoka `libsandbox.dylib`. Kazi kuu zilizotolewa ni: `sandbox_compile_file` (inatarajia njia ya faili, param `-f`), `sandbox_compile_string` (inatarajia string, param `-p`), `sandbox_compile_name` (inatarajia jina la kontena, param `-n`), `sandbox_compile_entitlements` (inatarajia entitlements plist).

Toleo hili lililogeuzwa na [**toleo la wazi la zana sandbox-exec**](https://newosxbook.com/src.jl?tree=listings&file=/sandbox_exec.c) linaruhusu **`sandbox-exec`** kuandika kwenye faili profaili ya sandbox iliyokusanywa.

Zaidi ya hayo, ili kufunga mchakato ndani ya kontena inaweza kuita `sandbox_spawnattrs_set[container/profilename]` na kupitisha kontena au profaili iliyopo.

## Debug & Kupita Sandbox

Katika macOS, tofauti na iOS ambapo michakato imewekwa kwenye sandbox tangu mwanzo na kernel, **michakato lazima ijitolee kwenye sandbox yenyewe**. Hii inamaanisha katika macOS, mchakato haujawekewa vizuizi na sandbox hadi uamuzi wa kuingia, ingawa programu za App Store daima zimewekwa kwenye sandbox.

Michakato huwekwa kwenye Sandbox moja kwa moja kutoka userland wanapoanza ikiwa wana haki: `com.apple.security.app-sandbox`. Kwa maelezo ya kina kuhusu mchakato huu angalia:

{{#ref}}
macos-sandbox-debug-and-bypass/
{{#endref}}

## **Marekebisho ya Sandbox**

Marekebisho yanaruhusu kutoa haki zaidi kwa kitu na yanatoa wito kwa moja ya kazi:

- `sandbox_issue_extension`
- `sandbox_extension_issue_file[_with_new_type]`
- `sandbox_extension_issue_mach`
- `sandbox_extension_issue_iokit_user_client_class`
- `sandbox_extension_issue_iokit_registry_rentry_class`
- `sandbox_extension_issue_generic`
- `sandbox_extension_issue_posix_ipc`

Marekebisho yanawekwa katika slot ya pili ya lebo ya MACF inayoweza kufikiwa kutoka kwa akidi za mchakato. Zana ifuatayo **`sbtool`** inaweza kufikia habari hii.

Kumbuka kwamba marekebisho kwa kawaida yanatolewa na michakato inayoruhusiwa, kwa mfano, `tccd` itatoa token ya marekebisho ya `com.apple.tcc.kTCCServicePhotos` wakati mchakato unajaribu kufikia picha na kuruhusiwa katika ujumbe wa XPC. Kisha, mchakato utahitaji kutumia token ya marekebisho ili iongezwe kwake.\
Kumbuka kwamba token za marekebisho ni nambari ndefu za hexadecimal zinazokodisha ruhusa zilizotolewa. Hata hivyo hazina PID inayoruhusiwa iliyowekwa kwa hivyo mchakato wowote wenye ufikiaji wa token unaweza **kutumiwa na michakato mingi**.

Kumbuka kwamba marekebisho yanahusiana sana na haki pia, hivyo kuwa na haki fulani kunaweza kutoa kiotomatiki marekebisho fulani.

### **Angalia Haki za PID**

[**Kulingana na hii**](https://www.youtube.com/watch?v=mG715HcDgO8&t=3011s), kazi za **`sandbox_check`** (ni `__mac_syscall`), zinaweza kuangalia **kama operesheni inaruhusiwa au la** na sandbox katika PID fulani, token ya ukaguzi au kitambulisho cha kipekee.

[**Zana sbtool**](http://newosxbook.com/src.jl?tree=listings&file=sbtool.c) (ipate [iliyokusanywa hapa](https://newosxbook.com/articles/hitsb.html)) inaweza kuangalia ikiwa PID inaweza kutekeleza vitendo fulani:
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explanation of the sandbox profile and extensions
sbtool <pid> all
```
### \[un]suspend

Inawezekana pia kusitisha na kuondoa kusitishwa kwa sandbox kwa kutumia kazi `sandbox_suspend` na `sandbox_unsuspend` kutoka `libsystem_sandbox.dylib`.

Kumbuka kwamba ili kuita kazi ya kusitisha, haki fulani zinakaguliwa ili kuidhinisha mwitikiaji kuitumia kama:

- com.apple.private.security.sandbox-manager
- com.apple.security.print
- com.apple.security.temporary-exception.audio-unit-host

## mac_syscall

Kito hiki cha mfumo (#381) kinatarajia hoja ya kwanza ya maandiko ambayo itaonyesha moduli ya kuendesha, na kisha nambari katika hoja ya pili ambayo itaonyesha kazi ya kuendesha. Kisha hoja ya tatu itategemea kazi iliyotekelezwa.

Kazi `___sandbox_ms` inafunga `mac_syscall` ikionyesha katika hoja ya kwanza `"Sandbox"` kama vile `___sandbox_msp` ni kifungashio cha `mac_set_proc` (#387). Kisha, baadhi ya nambari zinazoungwa mkono na `___sandbox_ms` zinaweza kupatikana katika jedwali hili:

- **set_profile (#0)**: Tumia wasifu uliokamilishwa au uliopewa jina kwa mchakato.
- **platform_policy (#1)**: Lazimisha ukaguzi wa sera maalum za jukwaa (hubadilika kati ya macOS na iOS).
- **check_sandbox (#2)**: Fanya ukaguzi wa mkono wa operesheni maalum ya sandbox.
- **note (#3)**: Ongeza maelezo kwa Sandbox
- **container (#4)**: Unganisha maelezo kwa sandbox, kawaida kwa ajili ya ufuatiliaji au utambulisho.
- **extension_issue (#5)**: Tengeneza nyongeza mpya kwa mchakato.
- **extension_consume (#6)**: Tumia nyongeza iliyotolewa.
- **extension_release (#7)**: Achilia kumbukumbu iliyohusishwa na nyongeza iliyotumiwa.
- **extension_update_file (#8)**: Badilisha vigezo vya nyongeza iliyopo ndani ya sandbox.
- **extension_twiddle (#9)**: Rekebisha au badilisha nyongeza iliyopo (mfano, TextEdit, rtf, rtfd).
- **suspend (#10)**: Kusitisha kwa muda ukaguzi wote wa sandbox (inahitaji haki zinazofaa).
- **unsuspend (#11)**: Anza tena ukaguzi wote wa sandbox uliositishwa hapo awali.
- **passthrough_access (#12)**: Ruhusu ufikiaji wa moja kwa moja kwa rasilimali, ukipita ukaguzi wa sandbox.
- **set_container_path (#13)**: (iOS pekee) Weka njia ya kontena kwa kikundi cha programu au kitambulisho cha saini.
- **container_map (#14)**: (iOS pekee) Pata njia ya kontena kutoka `containermanagerd`.
- **sandbox_user_state_item_buffer_send (#15)**: (iOS 10+) Weka metadata ya hali ya mtumiaji katika sandbox.
- **inspect (#16)**: Toa taarifa za ufuatiliaji kuhusu mchakato wa sandboxed.
- **dump (#18)**: (macOS 11) Tupa wasifu wa sasa wa sandbox kwa ajili ya uchambuzi.
- **vtrace (#19)**: Fuata operesheni za sandbox kwa ajili ya ufuatiliaji au ufuatiliaji.
- **builtin_profile_deactivate (#20)**: (macOS < 11) Zima wasifu uliopewa jina (mfano, `pe_i_can_has_debugger`).
- **check_bulk (#21)**: Fanya operesheni nyingi za `sandbox_check` katika wito mmoja.
- **reference_retain_by_audit_token (#28)**: Tengeneza rejeleo kwa tokeni ya ukaguzi kwa matumizi katika ukaguzi wa sandbox.
- **reference_release (#29)**: Achilia rejeleo la tokeni ya ukaguzi iliyoshikiliwa hapo awali.
- **rootless_allows_task_for_pid (#30)**: Thibitisha ikiwa `task_for_pid` inaruhusiwa (kama `csr` ukaguzi).
- **rootless_whitelist_push (#31)**: (macOS) Tumia faili ya orodha ya Ulinzi wa Uadilifu wa Mfumo (SIP).
- **rootless_whitelist_check (preflight) (#32)**: Kagua faili ya orodha ya SIP kabla ya utekelezaji.
- **rootless_protected_volume (#33)**: (macOS) Tumia ulinzi wa SIP kwa diski au sehemu.
- **rootless_mkdir_protected (#34)**: Tumia ulinzi wa SIP/DataVault kwa mchakato wa kuunda directory.

## Sandbox.kext

Kumbuka kwamba katika iOS, nyongeza ya kernel ina **wasifu wote waliowekwa kwa nguvu** ndani ya sehemu ya `__TEXT.__const` ili kuzuia kubadilishwa. Hapa kuna baadhi ya kazi za kuvutia kutoka kwa nyongeza ya kernel:

- **`hook_policy_init`**: Inachanganya `mpo_policy_init` na inaitwa baada ya `mac_policy_register`. Inatekeleza sehemu kubwa ya uanzishaji wa Sandbox. Pia inaanzisha SIP.
- **`hook_policy_initbsd`**: Inatayarisha interface ya sysctl ikijiandikisha `security.mac.sandbox.sentinel`, `security.mac.sandbox.audio_active` na `security.mac.sandbox.debug_mode` (ikiwa imeboreshwa na `PE_i_can_has_debugger`).
- **`hook_policy_syscall`**: Inaitwa na `mac_syscall` ikiwa na "Sandbox" kama hoja ya kwanza na nambari ikionyesha operesheni katika ya pili. Switch inatumika kupata nambari ya kuendesha kulingana na nambari iliyohitajika.

### MACF Hooks

**`Sandbox.kext`** inatumia zaidi ya mia moja ya hooks kupitia MACF. Mengi ya hooks haya yatakagua tu hali fulani za kawaida ambazo zinaruhusu kutekeleza kitendo, ikiwa sivyo, zitaita **`cred_sb_evalutate`** na **credentials** kutoka MACF na nambari inayohusiana na **operesheni** ya kutekeleza na **buffer** kwa ajili ya matokeo.

Mfano mzuri wa hiyo ni kazi **`_mpo_file_check_mmap`** ambayo inachanganya **`mmap`** na ambayo itaanza kukagua ikiwa kumbukumbu mpya itakuwa inayoandikwa (na ikiwa sivyo ruhusu utekelezaji), kisha itakagua ikiwa inatumika kwa cache ya pamoja ya dyld na ikiwa ndivyo ruhusu utekelezaji, na hatimaye itaita **`sb_evaluate_internal`** (au moja ya vifungashio vyake) ili kufanya ukaguzi zaidi wa ruhusa.

Zaidi ya hayo, kati ya mia kadhaa ya hooks ambazo Sandbox inatumia, kuna 3 kwa haswa ambazo ni za kuvutia sana:

- `mpo_proc_check_for`: Inatumia wasifu ikiwa inahitajika na ikiwa haijatumika hapo awali
- `mpo_vnode_check_exec`: Inaitwa wakati mchakato unapoleta binary inayohusiana, kisha ukaguzi wa wasifu unafanywa na pia ukaguzi unaozuia utekelezaji wa SUID/SGID.
- `mpo_cred_label_update_execve`: Hii inaitwa wakati lebo inatolewa. Hii ni ndefu zaidi kwani inaitwa wakati binary imepakiwa kikamilifu lakini haijatekelezwa bado. Itafanya vitendo kama kuunda kitu cha sandbox, kuunganisha muundo wa sandbox kwa credentials za kauth, kuondoa ufikiaji kwa bandari za mach...

Kumbuka kwamba **`_cred_sb_evalutate`** ni kifungashio juu ya **`sb_evaluate_internal`** na kazi hii inapata credentials zilizopitishwa na kisha inafanya tathmini kwa kutumia kazi ya **`eval`** ambayo kawaida inakagua **wasifu wa jukwaa** ambao kwa default unatumika kwa mchakato wote na kisha **wasifu maalum wa mchakato**. Kumbuka kwamba wasifu wa jukwaa ni moja ya sehemu kuu za **SIP** katika macOS.

## Sandboxd

Sandbox pia ina daemon ya mtumiaji inayofanya kazi ikionyesha huduma ya XPC Mach `com.apple.sandboxd` na kuunganisha bandari maalum 14 (`HOST_SEATBELT_PORT`) ambayo nyongeza ya kernel inatumia kuwasiliana nayo. Inatoa baadhi ya kazi kwa kutumia MIG.

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)

{{#include ../../../../banners/hacktricks-training.md}}
