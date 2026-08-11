# macOS Sandbox

{{#include ../../../../banners/hacktricks-training.md}}

## Basiese inligting

MacOS Sandbox (aanvanklik Seatbelt genoem) **beperk toepassings** wat binne die sandbox loop tot die **toegelate aksies wat in die Sandbox-profiel gespesifiseer word** waarmee die toepassing loop. Dit help om te verseker dat **die toepassing slegs toegang tot verwagte hulpbronne sal verkry**.

Enige toepassing met die **entitlement** **`com.apple.security.app-sandbox`** sal binne die sandbox uitgevoer word. **Apple-binaries** word gewoonlik binne ’n Sandbox uitgevoer, en alle toepassings vanaf die **App Store het daardie entitlement**. Dus sal verskeie toepassings binne die sandbox uitgevoer word.<sup>[[4]](#references)</sup>

Om te beheer wat ’n proses kan of nie kan doen nie, **het die Sandbox hooks** in bykans enige bewerking wat ’n proses kan probeer (insluitend die meeste syscalls), deur **MACF** te gebruik. Afhangend van die **entitlements** van die toepassing, kan die Sandbox egter meer permissief teenoor die proses wees.

Enkele belangrike komponente van die Sandbox is:

- Die **kernel extension** `/System/Library/Extensions/Sandbox.kext`
- Die **private framework** `/System/Library/PrivateFrameworks/AppSandbox.framework`
- ’n **daemon** wat in userland loop: `/usr/libexec/sandboxd`
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
Binne elke bundle id-lêergids kan jy die **plist** en die **Data directory** van die App vind, met ’n struktuur wat die Tuis-lêergids naboots:
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
> Let daarop dat selfs al is die symlinks daar om uit die Sandbox te “escape” en toegang tot ander vouers te verkry, die App steeds **toestemmings moet hê** om toegang daartoe te verkry. Hierdie toestemmings is binne die **`.plist`** in die `RedirectablePaths`.

Die **`SandboxProfileData`** is die saamgestelde sandbox-profiel-CFData wat na B64 escaped is.
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
> Alles wat deur 'n Sandboxed-toepassing geskep of gewysig word, sal die **quarantine attribute** kry. Dit sal 'n sandbox-ruimte voorkom deur Gatekeeper te aktiveer indien die sandbox-toepassing iets met **`open`** probeer uitvoer.

## Sandbox-profiele

Die Sandbox-profiele is konfigurasielêers wat aandui wat in daardie **Sandbox** **toegelaat/verbied** gaan word. Dit gebruik die **Sandbox Profile Language (SBPL)**, wat die [**Scheme**](<https://en.wikipedia.org/wiki/Scheme_(programming_language)>)-programmeertaal gebruik.

Hier kan jy 'n voorbeeld vind:
```scheme
(version 1) ; First you get the version

(deny default) ; Then you should indicate the default action when no rule applies

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
> Kyk na hierdie [**research**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) **om meer aksies te sien wat toegelaat of geweier kan word.**<sup>[[5]](#references)</sup>
>
> Let daarop dat die name van die bewerkings in die compiled weergawe van ’n profiel vervang word deur hul inskrywings in ’n array wat aan die dylib en die kext bekend is, wat die compiled weergawe korter en moeiliker maak om te lees.

Belangrike **system services** loop ook binne hul eie pasgemaakte **sandbox**, soos die `mdnsresponder`-diens. Jy kan hierdie pasgemaakte **sandbox profiles** binne die volgende sien:

- **`/usr/share/sandbox`**
- **`/System/Library/Sandbox/Profiles`**
- Ander sandbox profiles kan nagegaan word by [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles).
- In iOS is die platform profile binne die sandbox `.kext` in die `_platform_profile_data` binne die binary.

**App Store**-apps gebruik die **profile** **`/System/Library/Sandbox/Profiles/application.sb`**. Jy kan in hierdie profile sien hoe entitlements soos **`com.apple.security.network.server`** ’n proses toelaat om die network te gebruik.

Daarna gebruik sommige **Apple daemon services** verskillende profiles wat in `/System/Library/Sandbox/Profiles/*.sb` of `/usr/share/sandbox/*.sb` geleë is. Hierdie sandboxes word in die main function toegepas wat die API `sandbox_init_XXX` aanroep.<sup>[[3]](#references)</sup>

**SIP** is ’n Sandbox profile genaamd platform_profile in `/System/Library/Sandbox/rootless.conf`.

### Sandbox Profile Examples

Om ’n application met ’n **spesifieke sandbox profile** te begin, kan jy die volgende gebruik:
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
> Let daarop dat **Apple-geskrewe** **sagteware** wat op **Windows** loop, **geen bykomende sekuriteitsvoorsorgmaatreëls** het nie, soos application sandboxing.

Voorbeelde van Bypasses:

- [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)<sup>[[6]](#references)</sup>
- [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (hulle kan lêers buite die sandbox skryf waarvan die naam met `~$` begin).<sup>[[7]](#references)</sup>

### Nasporing van Sandbox

#### Via profiel

Dit is moontlik om al die checks na te spoor wat sandbox uitvoer elke keer wanneer ’n aksie nagegaan word. Skep daarvoor eenvoudig die volgende profiel:
```scheme:trace.sb
(version 1)
(trace /tmp/trace.out)
```
En voer dan eenvoudig iets uit met daardie profiel:
```bash
sandbox-exec -f /tmp/trace.sb /bin/ls
```
In `/tmp/trace.out` sal jy elke sandbox-kontrole kan sien wat uitgevoer is elke keer wanneer dit geroep is (dus baie duplikate).

Dit is ook moontlik om die sandbox met die **`-t`**-parameter te trace: `sandbox-exec -t /path/trace.out -p "(version 1)" /bin/ls`

#### Via API

Die funksie `sandbox_set_trace_path`, wat deur `libsystem_sandbox.dylib` uitgevoer word, laat toe dat 'n trace-lêernaam gespesifiseer word waar sandbox-kontroles geskryf sal word.\
Dit is ook moontlik om iets soortgelyks te doen deur `sandbox_vtrace_enable()` te roep en dan die foutlogs uit die buffer te verkry deur `sandbox_vtrace_report()` te roep.

### Sandbox-inspeksie

`libsandbox.dylib` exporteer 'n funksie genaamd sandbox_inspect_pid wat 'n lys van die sandbox-toestand van 'n proses (insluitend extensions) verskaf. Slegs platform binaries kan egter hierdie funksie gebruik.

### macOS & iOS Sandbox Profiles

macOS stoor system sandbox profiles op twee plekke: **/usr/share/sandbox/** en **/System/Library/Sandbox/Profiles**.

En indien 'n third-party application die _**com.apple.security.app-sandbox**_-entitlement bevat, pas die system die **/System/Library/Sandbox/Profiles/application.sb**-profiel op daardie proses toe.

In iOS word die default profile **container** genoem, en ons het nie die SBPL-teksrepresentasie nie. In memory word hierdie sandbox voorgestel as 'n Allow/Deny binary tree vir elke permission van die sandbox.

### Custom SBPL in App Store apps

Dit kan moontlik wees vir companies om hul apps **met custom Sandbox profiles** te laat loop (in plaas van die default een). Hulle moet die entitlement **`com.apple.security.temporary-exception.sbpl`** gebruik, wat deur Apple gemagtig moet word.

Dit is moontlik om die definisie van hierdie entitlement in **`/System/Library/Sandbox/Profiles/application.sb:`** na te gaan.
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
Dit sal die **string ná hierdie entitlement eval** as 'n Sandbox-profiel.

### Kompilering en dekompilering van 'n Sandbox-profiel

Die **`sandbox-exec`**-tool gebruik die funksies `sandbox_compile_*` vanaf `libsandbox.dylib`. Die hoof-funksies wat uitgevoer word, is: `sandbox_compile_file` (verwag 'n lêerpad, param `-f`), `sandbox_compile_string` (verwag 'n string, param `-p`), `sandbox_compile_name` (verwag 'n naam van 'n container, param `-n`), `sandbox_compile_entitlements` (verwag entitlements plist).

Hierdie omgekeerde en [**open source-weergawe van die tool sandbox-exec**](https://newosxbook.com/src.jl?tree=listings&file=/sandbox_exec.c) laat toe dat **`sandbox-exec`** die gekompileerde Sandbox-profiel na 'n lêer skryf.

Om 'n proses binne 'n container te beperk, kan dit ook `sandbox_spawnattrs_set[container/profilename]` oproep en 'n container of voorafbestaande profiel deurgee.

## Debug & Bypass Sandbox

Op macOS, anders as iOS waar prosesse van die begin af deur die kernel gesandbox word, moet **prosesse self vir die Sandbox kies**. Dit beteken dat 'n proses op macOS nie deur die Sandbox beperk word totdat dit aktief besluit om dit binne te gaan nie, alhoewel App Store-apps altyd gesandbox word.

Prosesse word outomaties vanuit userland gesandbox wanneer hulle begin as hulle die entitlement: `com.apple.security.app-sandbox` het. Vir 'n gedetailleerde verduideliking van hierdie proses, kyk:


{{#ref}}
macos-sandbox-debug-and-bypass/
{{#endref}}

## **Sandbox-uitbreidings**

Extensions laat toe dat verdere voorregte aan 'n objek gegee word en word toegestaan deur een van die volgende funksies aan te roep:

- `sandbox_issue_extension`
- `sandbox_extension_issue_file[_with_new_type]`
- `sandbox_extension_issue_mach`
- `sandbox_extension_issue_iokit_user_client_class`
- `sandbox_extension_issue_iokit_registry_rentry_class`
- `sandbox_extension_issue_generic`
- `sandbox_extension_issue_posix_ipc`

Die extensions word in die tweede MACF-labelslot gestoor wat vanaf die proses se credentials toeganklik is. Die volgende **`sbtool`** kan toegang tot hierdie inligting verkry.

Let daarop dat extensions gewoonlik deur toegelate prosesse toegestaan word; byvoorbeeld, `tccd` sal die extension-token van `com.apple.tcc.kTCCServicePhotos` toestaan wanneer 'n proses probeer om toegang tot die foto's te verkry en in 'n XPC-boodskap toegelaat is. Daarna sal die proses die extension-token moet consume sodat dit daarby gevoeg word.\
Let daarop dat die extension-tokens lang heksadesimale waardes is wat die toegestane toestemmings enkodeer. Hulle het egter nie die toegelate PID hardgekodeer nie, wat beteken dat enige proses met toegang tot die token deur **multiple prosesse consumed kan word**.

Let daarop dat extensions ook baie nou met entitlements verband hou; daarom kan sekere entitlements outomaties sekere extensions toestaan.

### **Gaan PID-voorregte na**

[**Volgens hierdie**](https://www.youtube.com/watch?v=mG715HcDgO8&t=3011s) kan die **`sandbox_check`**-funksies (dit is 'n `__mac_syscall`) kontroleer **of 'n operasie deur die Sandbox toegelaat word of nie** in 'n sekere PID, audit token of unieke ID.<sup>[[8]](#references)</sup>

Die [**tool sbtool**](http://newosxbook.com/src.jl?tree=listings&file=sbtool.c) (vind dit [hier gekompileer](https://newosxbook.com/articles/hitsb.html)) kan kontroleer of 'n PID sekere aksies kan uitvoer:
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explanation of the sandbox profile and extensions
sbtool <pid> all
```
### \[un]suspend

Dit is ook moontlik om die sandbox te suspend en unsuspend deur die funksies `sandbox_suspend` en `sandbox_unsuspend` van `libsystem_sandbox.dylib` te gebruik.

Let daarop dat sommige entitlements nagegaan word om die caller te magtig om die suspend-funksie aan te roep, soos:

- com.apple.private.security.sandbox-manager
- com.apple.security.print
- com.apple.security.temporary-exception.audio-unit-host

## mac_syscall

Hierdie system call (#381) verwag eers een string-argument wat die module aandui wat uitgevoer moet word, en daarna ’n kode in die tweede argument wat die funksie aandui wat uitgevoer moet word. Die derde argument sal dan van die uitgevoerde funksie afhang.<sup>[[2]](#references)</sup>

Die funksie `___sandbox_ms` roep `mac_syscall` aan en dui `"Sandbox"` in die eerste argument aan, net soos `___sandbox_msp` ’n wrapper vir `mac_set_proc` (#387) is. Die volgende ondersteunde kodes deur `___sandbox_ms` kan in hierdie tabel gevind word:

- **set_profile (#0)**: Pas ’n compiled of named profile op ’n process toe.
- **platform_policy (#1)**: Dwing platform-spesifieke policy checks af (dit verskil tussen macOS en iOS).
- **check_sandbox (#2)**: Voer ’n manual check van ’n spesifieke sandbox-operasie uit.
- **note (#3)**: Voeg ’n annotation by ’n Sandbox.
- **container (#4)**: Heg ’n annotation aan ’n sandbox, tipies vir debugging of identification.
- **extension_issue (#5)**: Genereer ’n nuwe extension vir ’n process.
- **extension_consume (#6)**: Consume ’n gegewe extension.
- **extension_release (#7)**: Release die geheue wat aan ’n consumed extension gekoppel is.
- **extension_update_file (#8)**: Wysig parameters van ’n bestaande file extension binne die sandbox.
- **extension_twiddle (#9)**: Pas ’n bestaande file extension aan of wysig dit (byvoorbeeld TextEdit, rtf, rtfd).
- **suspend (#10)**: Suspend alle sandbox checks tydelik (vereis toepaslike entitlements).
- **unsuspend (#11)**: Hervat alle sandbox checks wat voorheen suspended is.
- **passthrough_access (#12)**: Laat direkte passthrough access tot ’n resource toe en bypass sandbox checks.
- **set_container_path (#13)**: (Slegs iOS) Stel ’n container path vir ’n app group of signing ID.
- **container_map (#14)**: (Slegs iOS) Haal ’n container path uit `containermanagerd` op.
- **sandbox_user_state_item_buffer_send (#15)**: (iOS 10+) Stel user-mode metadata in die sandbox.
- **inspect (#16)**: Verskaf debug-inligting oor ’n sandboxed process.
- **dump (#18)**: (macOS 11) Dump die huidige profile van ’n sandbox vir analysis.
- **vtrace (#19)**: Trace sandbox-operasies vir monitoring of debugging.
- **builtin_profile_deactivate (#20)**: (macOS < 11) Deaktiveer named profiles (byvoorbeeld `pe_i_can_has_debugger`).
- **check_bulk (#21)**: Voer verskeie `sandbox_check`-operasies in ’n enkele call uit.
- **reference_retain_by_audit_token (#28)**: Skep ’n reference vir ’n audit token vir gebruik in sandbox checks.
- **reference_release (#29)**: Release ’n reference na ’n audit token wat voorheen retained is.
- **rootless_allows_task_for_pid (#30)**: Verifieer of `task_for_pid` toegelaat word (soortgelyk aan `csr` checks).
- **rootless_whitelist_push (#31)**: (macOS) Pas ’n System Integrity Protection (SIP)-manifestlêer toe.
- **rootless_whitelist_check (preflight) (#32)**: Check die SIP-manifestlêer voor execution.
- **rootless_protected_volume (#33)**: (macOS) Pas SIP-protections op ’n disk of partition toe.
- **rootless_mkdir_protected (#34)**: Pas SIP/DataVault-protection op ’n directory creation process toe.

## Sandbox.kext

Let daarop dat die kernel extension in iOS **al die profiles hardcoded** binne die `__TEXT.__const`-segment bevat om te voorkom dat hulle modified word. Die volgende is sommige interessante funksies van die kernel extension:

- **`hook_policy_init`**: Dit hook `mpo_policy_init` en word ná `mac_policy_register` called. Dit voer die meeste van die initializations van die Sandbox uit. Dit initializeer ook SIP.
- **`hook_policy_initbsd`**: Dit stel die sysctl-interface op en registreer `security.mac.sandbox.sentinel`, `security.mac.sandbox.audio_active` en `security.mac.sandbox.debug_mode` (indien dit met `PE_i_can_has_debugger` geboote is).
- **`hook_policy_syscall`**: Dit word deur `mac_syscall` called met `"Sandbox"` as die eerste argument en ’n kode wat die operasie in die tweede argument aandui. ’n Switch word gebruik om die kode te vind wat volgens die requested code uitgevoer moet word.

### MACF Hooks

**`Sandbox.kext`** gebruik meer as honderd hooks via MACF. Die meeste hooks sal slegs sommige trivial cases check wat die aksie toelaat indien dit nie die geval is nie; hulle sal **`cred_sb_evalutate`** aanroep met die **credentials** van MACF, ’n nommer wat ooreenstem met die **operation** wat uitgevoer moet word, en ’n **buffer** vir die output.<sup>[[1]](#references)</sup>

’n Goeie voorbeeld hiervan is die funksie **`_mpo_file_check_mmap`**, wat `mmap` hook en begin check of die nuwe geheue writable gaan wees (en, indien nie, die execution toelaat). Daarna check dit of dit vir die dyld shared cache gebruik word en laat dit, indien wel, die execution toe. Uiteindelik roep dit **`sb_evaluate_internal`** (of een van sy wrappers) aan om verdere allowance checks uit te voer.

Boonop is daar, uit die honderd of meer hooks wat Sandbox gebruik, 3 wat besonder interessant is:

- `mpo_proc_check_for`: Dit pas die profile toe indien nodig en indien dit nie voorheen toegepas is nie.
- `mpo_vnode_check_exec`: Word called wanneer ’n process die geassosieerde binary laai; daarna word ’n profile check uitgevoer, asook ’n check wat SUID/SGID executions verbied.
- `mpo_cred_label_update_execve`: Dit word called wanneer die label toegeken word. Dit is die langste een, aangesien dit called word wanneer die binary volledig gelaai is, maar nog nie uitgevoer is nie. Dit voer aksies uit soos om die sandbox-object te skep, die sandbox-struct aan die kauth credentials te attach, toegang tot mach ports te remove...

Let daarop dat **`_cred_sb_evalutate`** ’n wrapper oor **`sb_evaluate_internal`** is, en dat hierdie funksie die credentials ontvang wat deurgegee is en dan die evaluation uitvoer deur die **`eval`**-funksie te gebruik, wat gewoonlik die **platform profile** evalueer wat by verstek op alle processes toegepas word, en daarna die **specific process profile**. Let daarop dat die platform profile een van die hoofkomponente van **SIP** in macOS is.

## Sandboxd

Sandbox het ook ’n user daemon wat loop en die XPC Mach service `com.apple.sandboxd` blootstel, asook die special port 14 (`HOST_SEATBELT_PORT`) bind wat die kernel extension gebruik om daarmee te kommunikeer. Dit stel sommige funksies deur MIG bloot.

## References

- [1] [XNU — `security/mac_policy.h` (MACF hooks wat die Sandbox kext registreer)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `security/mac_base.c` (`__mac_syscall`, die entry point agter `__sandbox_ms`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_base.c)
- [3] [`sandbox_init(3)` man page](https://keith.github.io/xcode-man-pages/sandbox_init.3.html)
- [4] [Apple Developer — App Sandbox](https://developer.apple.com/documentation/security/app-sandbox)
- [5] [Apple Sandbox Guide v1.0](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/)
- [6] [Mac sandbox escape](https://lapcatsoftware.com/articles/sandbox-escape.html)
- [7] [Office365 MacOS Sandbox Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [8] [HITBGSEC 2016 SG - The Apple Sandbox: Deeper Into The Quagmire - Jonathan Levin](https://www.youtube.com/watch?v=mG715HcDgO8&t=3011s)
{{#include ../../../../banners/hacktricks-training.md}}
