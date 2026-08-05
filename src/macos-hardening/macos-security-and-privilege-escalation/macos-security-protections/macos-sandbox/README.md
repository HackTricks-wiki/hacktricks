# macOS Sandbox

{{#include ../../../../banners/hacktricks-training.md}}

## Basiese Inligting

macOS Sandbox (aanvanklik Seatbelt genoem) **beperk toepassings** wat binne die sandbox loop tot die **toegelate aksies wat in die Sandbox-profiel gespesifiseer word** waarmee die toepassing loop. Dit help verseker dat **die toepassing slegs toegang tot verwagte hulpbronne verkry**.

Enige toepassing met die **entitlement** **`com.apple.security.app-sandbox`** sal binne die sandbox uitgevoer word. **Apple-binaries** word gewoonlik binne 'n Sandbox uitgevoer, en alle toepassings van die **App Store het daardie entitlement**. Dus sal verskeie toepassings binne die sandbox uitgevoer word.<sup>[4]</sup>

Om te beheer wat 'n proses kan of nie kan doen nie, het die **Sandbox hooks** in bykans enige bewerking wat 'n proses kan probeer (insluitend die meeste syscalls), deur **MACF** te gebruik. Afhangend van die **entitlements** van die toepassing, kan die Sandbox egter meer permissief teenoor die proses wees.

Enkele belangrike komponente van die Sandbox is:

- Die **kernel extension** `/System/Library/Extensions/Sandbox.kext`
- Die **private framework** `/System/Library/PrivateFrameworks/AppSandbox.framework`
- 'n **daemon** wat in userland loop: `/usr/libexec/sandboxd`
- Die **containers** `~/Library/Containers`

### Containers

Elke sandboxed toepassing sal sy eie container in `~/Library/Containers/{CFBundleIdentifier}` hê:
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
Binne elke bundle id-lêergids kan jy die **plist** en die **Data directory** van die App vind, met 'n struktuur wat die Home-lêergids naboots:
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
> Let daarop dat selfs al is die symlinks daar om uit die Sandbox te "escape" en toegang tot ander vouers te verkry, die App steeds **toestemmings** moet hê om toegang daartoe te verkry. Hierdie toestemmings is binne die **`.plist`** in `RedirectablePaths`.

Die **`SandboxProfileData`** is die gekompileerde sandbox-profiel CFData, ge-escape na B64.
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
> Alles wat deur 'n Sandboxed-toepassing geskep/gewysig word, sal die **quarantine-attribuut** kry. Dit sal 'n sandbox-ruimte verhoed deur Gatekeeper te aktiveer indien die sandbox-toepassing iets met **`open`** probeer uitvoer.

## Sandbox-profiele

Die Sandbox-profiele is konfigurasielêers wat aandui wat in daardie **Sandbox** **toegelaat/verbied** gaan word. Dit gebruik die **Sandbox Profile Language (SBPL)**, wat die [**Scheme**](<https://en.wikipedia.org/wiki/Scheme_(programming_language)>)-programmeertaal gebruik.

Hier kan jy 'n voorbeeld vind:
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
> Gaan hierdie [**research**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) na **om meer aksies te kontroleer wat toegelaat of geweier kan word.**<sup>[5]</sup>
>
> Let daarop dat die name van die operasies in die compiled weergawe van 'n profile vervang word deur hul inskrywings in 'n array wat aan die dylib en die kext bekend is, wat die compiled weergawe korter en moeiliker maak om te lees.

Belangrike **system services** loop ook binne hul eie pasgemaakte **sandbox**, soos die `mdnsresponder`-service. Jy kan hierdie pasgemaakte **sandbox profiles** binne die volgende bekyk:

- **`/usr/share/sandbox`**
- **`/System/Library/Sandbox/Profiles`**
- Ander sandbox profiles kan nagegaan word by [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles).
- In iOS is die platform profile binne die sandbox `.kext` in `_platform_profile_data` binne die binary.

**App Store**-apps gebruik die **profile** **`/System/Library/Sandbox/Profiles/application.sb`**. Jy kan in hierdie profile nagaan hoe entitlements soos **`com.apple.security.network.server`** 'n process toelaat om die network te gebruik.

Daarna gebruik sommige **Apple daemon services** verskillende profiles wat in `/System/Library/Sandbox/Profiles/*.sb` of `/usr/share/sandbox/*.sb` geleë is. Hierdie sandboxes word in die hoof-funciton toegepas wat die API `sandbox_init_XXX` aanroep.<sup>[3]</sup>

**SIP** is 'n Sandbox profile genaamd platform_profile in `/System/Library/Sandbox/rootless.conf`.

### Sandbox Profile Examples

Om 'n application met 'n **spesifieke sandbox profile** te begin, kan jy die volgende gebruik:
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
> Let daarop dat die **Apple-authored** **sagteware** wat op **Windows** loop, **geen bykomende sekuriteitsmaatreëls** het nie, soos application sandboxing.

Voorbeelde van Bypasses:

- [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)<sup>[6]</sup>
- [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (hulle kan lêers buite die sandbox skryf waarvan die naam met `~$` begin).<sup>[7]</sup>

### Sandbox Tracing

#### Via profiel

Dit is moontlik om al die kontroles wat sandbox uitvoer elke keer wanneer ’n aksie nagegaan word, te trace. Hiervoor moet jy net die volgende profiel skep:
```scheme:trace.sb
(version 1)
(trace /tmp/trace.out)
```
En voer dan net iets uit deur daardie profiel te gebruik:
```bash
sandbox-exec -f /tmp/trace.sb /bin/ls
```
In `/tmp/trace.out` sal jy elke Sandbox-check kan sien wat uitgevoer is elke keer wanneer dit geroep is (dus baie duplikate).

Dit is ook moontlik om die Sandbox te trace deur die **`-t`**-parameter te gebruik: `sandbox-exec -t /path/trace.out -p "(version 1)" /bin/ls`

#### Via API

Die funksie `sandbox_set_trace_path` wat deur `libsystem_sandbox.dylib` uitgevoer word, laat toe dat ’n trace-lêernaam gespesifiseer word waarheen Sandbox-checks geskryf sal word.\
Dit is ook moontlik om iets soortgelyks te doen deur `sandbox_vtrace_enable()` te roep en dan die foutlogboeke uit die buffer te kry deur `sandbox_vtrace_report()` te roep.

### Sandbox-inspeksie

`libsandbox.dylib` voer ’n funksie genaamd sandbox_inspect_pid uit wat ’n lys van die Sandbox-toestand van ’n proses gee (insluitend extensions). Slegs platform binaries kan egter hierdie funksie gebruik.

### macOS & iOS Sandbox-profiele

macOS stoor system Sandbox-profiele op twee plekke: **/usr/share/sandbox/** en **/System/Library/Sandbox/Profiles**.

En indien ’n third-party application die _**com.apple.security.app-sandbox**_-entitlement het, pas die stelsel die **/System/Library/Sandbox/Profiles/application.sb**-profiel op daardie proses toe.

In iOS word die verstekprofiel **container** genoem, en ons het nie die SBPL-teksverteenwoordiging nie. In geheue word hierdie Sandbox voorgestel as ’n Allow/Deny binary tree vir elke toestemming van die Sandbox.

### Custom SBPL in App Store-apps

Dit is moontlik vir maatskappye om hul apps met **custom Sandbox-profiele** te laat loop (in plaas van die verstekprofiel). Hulle moet die entitlement **`com.apple.security.temporary-exception.sbpl`** gebruik, wat deur Apple gemagtig moet word.

Dit is moontlik om die definisie van hierdie entitlement in **`/System/Library/Sandbox/Profiles/application.sb:`** na te gaan.
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
This sal die string ná hierdie entitlement **eval** as ’n Sandbox profile.

### Kompilering & dekompilering van ’n Sandbox Profile

Die **`sandbox-exec`**-tool gebruik die funksies `sandbox_compile_*` van `libsandbox.dylib`. Die belangrikste uitgevoerde funksies is: `sandbox_compile_file` (verwag ’n lêerpad, param `-f`), `sandbox_compile_string` (verwag ’n string, param `-p`), `sandbox_compile_name` (verwag die naam van ’n container, param `-n`), `sandbox_compile_entitlements` (verwag entitlements plist).

Hierdie omgekeerde en [**open source-weergawe van die tool sandbox-exec**](https://newosxbook.com/src.jl?tree=listings&file=/sandbox_exec.c) laat ’n mens toe om **`sandbox-exec`** ’n lêer met die gekompileerde Sandbox profile te laat skryf.

Verder, om ’n process binne ’n container te beperk, kan dit `sandbox_spawnattrs_set[container/profilename]` aanroep en ’n container of bestaande profile deurgee.

## Debug & Bypass Sandbox

Op macOS, anders as iOS waar processes van die begin af deur die kernel gesandbox word, **moet processes self vir die Sandbox opt-in**. Dit beteken dat ’n process op macOS nie deur die Sandbox beperk word voordat dit aktief besluit om dit binne te gaan nie, hoewel App Store-apps altyd gesandbox word.

Processes word outomaties vanuit userland gesandbox wanneer hulle begin as hulle die entitlement `com.apple.security.app-sandbox` het. Vir ’n gedetailleerde verduideliking van hierdie proses, kyk:


{{#ref}}
macos-sandbox-debug-and-bypass/
{{#endref}}

## **Sandbox Extensions**

Extensions laat toe dat verdere privileges aan ’n object gegee word, en word verleen deur een van die volgende funksies aan te roep:

- `sandbox_issue_extension`
- `sandbox_extension_issue_file[_with_new_type]`
- `sandbox_extension_issue_mach`
- `sandbox_extension_issue_iokit_user_client_class`
- `sandbox_extension_issue_iokit_registry_rentry_class`
- `sandbox_extension_issue_generic`
- `sandbox_extension_issue_posix_ipc`

Die extensions word in die tweede MACF-labelslot gestoor, wat vanaf die process se credentials toeganklik is. Die volgende **`sbtool`** kan toegang tot hierdie inligting verkry.

Let daarop dat extensions gewoonlik deur toegelate processes verleen word; byvoorbeeld, `tccd` sal die extension-token van `com.apple.tcc.kTCCServicePhotos` verleen wanneer ’n process probeer om toegang tot die foto’s te verkry en in ’n XPC-boodskap toegelaat is. Daarna sal die process die extension-token moet consume sodat dit by die process gevoeg word.\
Let daarop dat die extension-tokens lang heksadesimale waardes is wat die verleende permissions enkodeer. Hulle het egter nie die toegelate PID hardcoded nie, wat beteken dat enige process met toegang tot die token dit deur **multiple processes** kan laat **consume**.

Let daarop dat extensions ook nou verwant is aan entitlements; daarom kan sekere entitlements outomaties sekere extensions verleen.

### **Check PID Privileges**

[**Volgens hierdie**](https://www.youtube.com/watch?v=mG715HcDgO8&t=3011s) kan die **`sandbox_check`**-funksies (dit is ’n `__mac_syscall`) nagaan **of ’n operasie deur die Sandbox toegelaat word of nie** vir ’n sekere PID, audit-token of unique ID.<sup>[8]</sup>

Die [**tool sbtool**](http://newosxbook.com/src.jl?tree=listings&file=sbtool.c) (vind dit [hier gekompileer](https://newosxbook.com/articles/hitsb.html)) kan nagaan of ’n PID sekere aksies kan uitvoer:
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explanation of the sandbox profile and extensions
sbtool <pid> all
```
### \[un]suspend

Dit is ook moontlik om die sandbox op te skort en die opskorting daarvan op te hef met die funksies `sandbox_suspend` en `sandbox_unsuspend` vanaf `libsystem_sandbox.dylib`.

Let daarop dat sommige entitlements nagegaan word voordat die suspend-funksie geroep kan word, om die caller te magtig om dit te roep, soos:

- com.apple.private.security.sandbox-manager
- com.apple.security.print
- com.apple.security.temporary-exception.audio-unit-host

## mac_syscall

Hierdie system call (#381) verwag eers een string-argument wat die module aandui wat uitgevoer moet word, en daarna ’n kode in die tweede argument wat die funksie aandui wat uitgevoer moet word. Die derde argument sal dan van die uitgevoerde funksie afhang.<sup>[2]</sup>

Die funksie `___sandbox_ms` is ’n wrapper om `mac_syscall`, wat `"Sandbox"` in die eerste argument aandui, net soos `___sandbox_msp` ’n wrapper vir `mac_set_proc` (#387) is. Die volgende is sommige van die ondersteunde kodes deur `___sandbox_ms`:

- **set_profile (#0)**: Pas ’n saamgestelde of benoemde profiel op ’n proses toe.
- **platform_policy (#1)**: Dwing platform-spesifieke beleidskontroles af (dit wissel tussen macOS en iOS).
- **check_sandbox (#2)**: Voer ’n handmatige kontrole van ’n spesifieke sandbox-operasie uit.
- **note (#3)**: Voeg ’n annotasie by ’n Sandbox.
- **container (#4)**: Heg ’n annotasie aan ’n sandbox, gewoonlik vir debugging of identifikasie.
- **extension_issue (#5)**: Genereer ’n nuwe extension vir ’n proses.
- **extension_consume (#6)**: Consume ’n gegewe extension.
- **extension_release (#7)**: Stel die geheue vry wat aan ’n consumed extension gekoppel is.
- **extension_update_file (#8)**: Wysig parameters van ’n bestaande file extension binne die sandbox.
- **extension_twiddle (#9)**: Pas ’n bestaande file extension aan of wysig dit (byvoorbeeld TextEdit, rtf, rtfd).
- **suspend (#10)**: Suspend tydelik alle sandbox-kontroles (vereis toepaslike entitlements).
- **unsuspend (#11)**: Hervat alle sandbox-kontroles wat voorheen gesuspend is.
- **passthrough_access (#12)**: Laat direkte passthrough-toegang tot ’n resource toe, waardeur sandbox-kontroles omseil word.
- **set_container_path (#13)**: (Slegs iOS) Stel ’n container path vir ’n app group of signing ID.
- **container_map (#14)**: (Slegs iOS) Haal ’n container path van `containermanagerd` af.
- **sandbox_user_state_item_buffer_send (#15)**: (iOS 10+) Stel user-mode metadata in die sandbox.
- **inspect (#16)**: Verskaf debug-inligting oor ’n sandboxed proses.
- **dump (#18)**: (macOS 11) Dump die huidige profiel van ’n sandbox vir analysis.
- **vtrace (#19)**: Trace sandbox-operasies vir monitoring of debugging.
- **builtin_profile_deactivate (#20)**: (macOS < 11) Deaktiveer benoemde profiele (byvoorbeeld `pe_i_can_has_debugger`).
- **check_bulk (#21)**: Voer verskeie `sandbox_check`-operasies in ’n enkele call uit.
- **reference_retain_by_audit_token (#28)**: Skep ’n reference vir ’n audit token vir gebruik in sandbox-kontroles.
- **reference_release (#29)**: Stel ’n voorheen retained audit token-reference vry.
- **rootless_allows_task_for_pid (#30)**: Verifieer of `task_for_pid` toegelaat word (soortgelyk aan `csr`-kontroles).
- **rootless_whitelist_push (#31)**: (macOS) Pas ’n System Integrity Protection (SIP)-manifestlêer toe.
- **rootless_whitelist_check (preflight) (#32)**: Kontroleer die SIP-manifestlêer voordat dit uitgevoer word.
- **rootless_protected_volume (#33)**: (macOS) Pas SIP-beskerming op ’n skyf of partisie toe.
- **rootless_mkdir_protected (#34)**: Pas SIP/DataVault-beskerming op ’n gids se creation process toe.

## Sandbox.kext

Let daarop dat die kernel extension in iOS **al die profiele hardcoded** binne die `__TEXT.__const`-segment bevat om te voorkom dat hulle gewysig word. Die volgende is sommige interessante funksies van die kernel extension:

- **`hook_policy_init`**: Dit hook `mpo_policy_init` en word geroep nadat `mac_policy_register` geroep is. Dit voer die meeste van die Sandbox se initializations uit. Dit initialiseer ook SIP.
- **`hook_policy_initbsd`**: Dit stel die sysctl-interface op deur `security.mac.sandbox.sentinel`, `security.mac.sandbox.audio_active` en `security.mac.sandbox.debug_mode` te registreer (indien dit met `PE_i_can_has_debugger` geboot is).
- **`hook_policy_syscall`**: Dit word deur `mac_syscall` geroep met `"Sandbox"` as die eerste argument en ’n kode wat die operasie in die tweede argument aandui. ’n Switch word gebruik om die kode te vind wat volgens die aangevraagde kode uitgevoer moet word.

### MACF Hooks

**`Sandbox.kext`** gebruik meer as honderd hooks via MACF. Die meeste hooks sal slegs sommige triviale gevalle kontroleer wat toelaat dat die aksie uitgevoer word; indien nie, sal hulle **`cred_sb_evalutate`** roep met die **credentials** van MACF, ’n nommer wat ooreenstem met die **operation** wat uitgevoer moet word, en ’n **buffer** vir die output.<sup>[1]</sup>

’n Goeie voorbeeld hiervan is die funksie **`_mpo_file_check_mmap`**, wat **`mmap`** hook en begin deur te kontroleer of die nuwe geheue skryfbaar gaan wees (en, indien nie, die execution toelaat). Daarna kontroleer dit of dit vir die dyld shared cache gebruik word en laat dit die execution toe indien dit wel die geval is. Laastens roep dit **`sb_evaluate_internal`** (of een van sy wrappers) om verdere allowance checks uit te voer.

Verder, uit die honderde hooks wat Sandbox gebruik, is daar 3 wat besonder interessant is:

- `mpo_proc_check_for`: Dit pas die profiel toe indien nodig en indien dit nie reeds toegepas is nie.
- `mpo_vnode_check_exec`: Word geroep wanneer ’n proses die geassosieerde binary laai; daarna word ’n profielkontrole uitgevoer, asook ’n kontrole wat SUID/SGID-executions verbied.
- `mpo_cred_label_update_execve`: Dit word geroep wanneer die label toegeken word. Dit is die langste een, aangesien dit geroep word wanneer die binary volledig gelaai is, maar nog nie uitgevoer is nie. Dit voer aksies uit soos om die sandbox-object te skep, die sandbox-struct aan die kauth-credentials te heg, toegang tot mach ports te verwyder...

Let daarop dat **`_cred_sb_evalutate`** ’n wrapper oor **`sb_evaluate_internal`** is, en hierdie funksie die credentials ontvang en dan die evaluering uitvoer deur die **`eval`**-funksie te gebruik, wat gewoonlik die **platform profile** evalueer wat by verstek op alle prosesse toegepas word, en daarna die **specific process profile**. Let daarop dat die platform profile een van die hoofkomponente van **SIP** in macOS is.

## Sandboxd

Sandbox het ook ’n user daemon wat loop en die XPC Mach service `com.apple.sandboxd` blootstel, asook die spesiale port 14 (`HOST_SEATBELT_PORT`) bind wat die kernel extension gebruik om daarmee te kommunikeer. Dit stel sommige funksies deur MIG bloot.

## References

- [1] [XNU — `security/mac_policy.h` (MACF hooks wat deur die Sandbox kext geregistreer word)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `security/mac_base.c` (`__mac_syscall`, die entry point agter `__sandbox_ms`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_base.c)
- [3] [`sandbox_init(3)` man page](https://keith.github.io/xcode-man-pages/sandbox_init.3.html)
- [4] [Apple Developer — App Sandbox](https://developer.apple.com/documentation/security/app-sandbox)
- [5] [Apple Sandbox Guide v1.0](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/)
- [6] [Mac sandbox escape](https://lapcatsoftware.com/articles/sandbox-escape.html)
- [7] [Office365 MacOS Sandbox Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [8] [HITBGSEC 2016 SG - The Apple Sandbox: Deeper Into The Quagmire - Jonathan Levin](https://www.youtube.com/watch?v=mG715HcDgO8&t=3011s)

{{#include ../../../../banners/hacktricks-training.md}}
