# macOS Sandbox

{{#include ../../../../banners/hacktricks-training.md}}

## Osnovne informacije

MacOS Sandbox (prvobitno nazvan Seatbelt) **ograničava aplikacije** koje se izvršavaju unutar Sandbox-a na **dozvoljene radnje navedene u Sandbox profilu** sa kojim se aplikacija izvršava. Ovo pomaže da se osigura da će **aplikacija pristupati samo očekivanim resursima**.

Svaka aplikacija sa **entitlement-om** **`com.apple.security.app-sandbox`** izvršavaće se unutar Sandbox-a. **Apple binaries** se obično izvršavaju unutar Sandbox-a, a sve aplikacije iz **App Store-a imaju taj entitlement**. Zbog toga će se više aplikacija izvršavati unutar Sandbox-a.<sup>[[4]](#references)</sup>

Da bi kontrolisao šta proces može ili ne može da uradi, **Sandbox ima hooks** u gotovo svakoj operaciji koju proces može pokušati (uključujući većinu syscalls), koristeći **MACF**. Međutim, **zavisno** od **entitlements** aplikacije, Sandbox može biti permisivniji prema procesu.

Neke važne komponente Sandbox-a su:

- **kernel extension** `/System/Library/Extensions/Sandbox.kext`
- **private framework** `/System/Library/PrivateFrameworks/AppSandbox.framework`
- **daemon** koji se izvršava u userland-u `/usr/libexec/sandboxd`
- **containers** `~/Library/Containers`

### Containers

Svaka sandboxed aplikacija ima svoj container u `~/Library/Containers/{CFBundleIdentifier}` :
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
Unutar svakog foldera sa bundle id možete pronaći **plist** i **Data directory** aplikacije sa strukturom koja oponaša Home folder:
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
> Imajte na umu da, čak i ako su symlinks prisutni kako bi se „pobeglo“ iz Sandbox-a i pristupilo drugim folderima, App i dalje mora da **ima permissions** za pristup njima. Ove permissions se nalaze u **`.plist`** datoteci, u `RedirectablePaths`.

**`SandboxProfileData`** je kompajlirani sandbox profil CFData escape-ovan u B64.
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
> Sve što kreira/izmeni Sandboxed aplikacija dobiće **atribut karantina**. Ovo će sprečiti prostor sandboxa tako što će pokrenuti Gatekeeper ako sandbox aplikacija pokuša da izvrši nešto pomoću **`open`**.

## Sandbox Profiles

Sandbox profiles su konfiguracione datoteke koje određuju šta će biti **dozvoljeno/zabranjeno** u tom **Sandboxu**. Koristi **Sandbox Profile Language (SBPL)**, koji koristi programski jezik [**Scheme**](<https://en.wikipedia.org/wiki/Scheme_(programming_language)>).

Ovde možete pronaći primer:
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
> Pogledajte ovo [**istraživanje**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) **da biste proverili koje još radnje mogu biti dozvoljene ili odbijene.**<sup>[[5]](#references)</sup>
>
> Imajte na umu da su u kompajliranoj verziji profila nazivi operacija zamenjeni njihovim unosima u nizu koji su poznati dylib-u i kext-u, čime kompajlirana verzija postaje kraća i teža za čitanje.

Važne **sistemske usluge** takođe rade unutar sopstvenog prilagođenog **sandbox-a**, kao što je usluga `mdnsresponder`. Ove prilagođene **sandbox profile** možete pronaći u:

- **`/usr/share/sandbox`**
- **`/System/Library/Sandbox/Profiles`**
- Ostali sandbox profili mogu se proveriti na [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles).
- U iOS-u se platform profile nalazi unutar sandbox `.kext`-a, u `_platform_profile_data`, unutar binarne datoteke.

Aplikacije iz **App Store-a** koriste **profil** **`/System/Library/Sandbox/Profiles/application.sb`**. U ovom profilu možete proveriti kako entitlements kao što je **`com.apple.security.network.server`** omogućavaju procesu da koristi mrežu.

Zatim, neke **Apple daemon usluge** koriste različite profile koji se nalaze u `/System/Library/Sandbox/Profiles/*.sb` ili `/usr/share/sandbox/*.sb`. Ovi sandbox-i se primenjuju u glavnoj funkciji koja poziva API `sandbox_init_XXX`.<sup>[[3]](#references)</sup>

**SIP** je sandbox profil pod nazivom platform_profile u `/System/Library/Sandbox/rootless.conf`.

### Primeri Sandbox profila

Da biste pokrenuli aplikaciju sa **određenim sandbox profilom**, možete koristiti:
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
> Imajte na umu da **software** čiji je autor **Apple**, a koji radi na **Windows-u**, nema dodatne bezbednosne mere, kao što je application sandboxing.

Primeri zaobilaženja:

- [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)<sup>[[6]](#references)</sup>
- [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (u mogućnosti su da upisuju fajlove izvan sandbox-a čiji naziv počinje sa `~$`).<sup>[[7]](#references)</sup>

### Praćenje Sandbox-a

#### Putem profile

Moguće je pratiti sve provere koje sandbox izvršava svaki put kada se proverava neka radnja. Da biste to uradili, samo kreirajte sledeći profil:
```scheme:trace.sb
(version 1)
(trace /tmp/trace.out)
```
A zatim samo izvršite nešto koristeći taj profil:
```bash
sandbox-exec -f /tmp/trace.sb /bin/ls
```
U `/tmp/trace.out` možete videti svaku proveru sandbox-a izvršenu svaki put kada je pozvana (dakle, mnogo duplikata).

Sandbox je takođe moguće pratiti pomoću parametra **`-t`**: `sandbox-exec -t /path/trace.out -p "(version 1)" /bin/ls`

#### Putem API-ja

Funkcija `sandbox_set_trace_path`, koju eksportuje `libsystem_sandbox.dylib`, omogućava navođenje imena trace datoteke u koju će se upisivati sandbox provere.\
Nešto slično je moguće pozivanjem `sandbox_vtrace_enable()`, a zatim preuzimanjem logova grešaka iz bafera pozivanjem `sandbox_vtrace_report()`.

### Inspekcija sandbox-a

`libsandbox.dylib` eksportuje funkciju pod nazivom sandbox_inspect_pid, koja daje listu stanja sandbox-a procesa (uključujući ekstenzije). Međutim, ovu funkciju mogu koristiti samo platform binaries.

### MacOS i iOS Sandbox profili

MacOS čuva sistemske Sandbox profile na dve lokacije: **/usr/share/sandbox/** i **/System/Library/Sandbox/Profiles**.

Ako aplikacija treće strane ima entitlement _**com.apple.security.app-sandbox**_, sistem primenjuje profil **/System/Library/Sandbox/Profiles/application.sb** na taj proces.

U iOS-u se podrazumevani profil zove **container**, a nemamo njegovu SBPL tekstualnu reprezentaciju. U memoriji je ovaj sandbox predstavljen kao Allow/Deny binarno stablo za svaku dozvolu sandbox-a.

### Prilagođeni SBPL u App Store aplikacijama

Moguće je da kompanije svoje aplikacije pokreću **sa prilagođenim Sandbox profilima** (umesto sa podrazumevanim). Potrebno je da koriste entitlement **`com.apple.security.temporary-exception.sbpl`**, koji mora da odobri Apple.

Definiciju ovog entitlement-a moguće je proveriti u **`/System/Library/Sandbox/Profiles/application.sb:`**
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
Ovo će **eval string nakon ovog entitlement-a** kao Sandbox profile.

### Kompajliranje i dekompajliranje Sandbox Profile-a

Alat **`sandbox-exec`** koristi funkcije `sandbox_compile_*` iz `libsandbox.dylib`. Glavne eksportovane funkcije su: `sandbox_compile_file` (očekuje putanju do fajla, parametar `-f`), `sandbox_compile_string` (očekuje string, parametar `-p`), `sandbox_compile_name` (očekuje ime container-a, parametar `-n`), `sandbox_compile_entitlements` (očekuje entitlements plist).

Ova reverzno analizirana i [**open sourced verzija alata sandbox-exec**](https://newosxbook.com/src.jl?tree=listings&file=/sandbox_exec.c) omogućava da **`sandbox-exec`** upiše kompajlirani Sandbox profile u fajl.

Pored toga, da bi ograničio proces unutar container-a, može pozvati `sandbox_spawnattrs_set[container/profilename]` i proslediti container ili postojeći profile.

## Debug i Bypass Sandbox-a

Na macOS-u, za razliku od iOS-a, gde kernel sandbox-uje procese od samog početka, **procesi moraju sami da se opredele za Sandbox**. To znači da na macOS-u proces nije ograničen Sandbox-om dok aktivno ne odluči da u njega uđe, iako su App Store aplikacije uvek sandbox-ovane.

Procesi se automatski sandbox-uju iz userland-a pri pokretanju ako imaju entitlement: `com.apple.security.app-sandbox`. Za detaljno objašnjenje ovog procesa pogledajte:


{{#ref}}
macos-sandbox-debug-and-bypass/
{{#endref}}

## **Sandbox Extensions**

Extensions omogućavaju davanje dodatnih privilegija objektu i dobijaju se pozivanjem neke od sledećih funkcija:

- `sandbox_issue_extension`
- `sandbox_extension_issue_file[_with_new_type]`
- `sandbox_extension_issue_mach`
- `sandbox_extension_issue_iokit_user_client_class`
- `sandbox_extension_issue_iokit_registry_rentry_class`
- `sandbox_extension_issue_generic`
- `sandbox_extension_issue_posix_ipc`

Extensions se čuvaju u drugom MACF label slotu dostupnom iz credentials procesa. Sledeći **`sbtool`** može da pristupi ovim informacijama.

Imajte na umu da extensions obično dodeljuju dozvoljeni procesi; na primer, `tccd` će dodeliti extension token za `com.apple.tcc.kTCCServicePhotos` kada proces pokuša da pristupi fotografijama i to mu bude dozvoljeno u XPC poruci. Zatim proces mora da iskoristi extension token kako bi mu on bio dodat.\
Imajte na umu da su extension tokens dugački heksadecimalni nizovi koji kodiraju dodeljene dozvole. Međutim, oni nemaju hardkodovan dozvoljeni PID, što znači da bilo koji proces koji ima pristup tokenu može biti **iskorišćen od strane više procesa**.

Imajte na umu da su extensions takođe usko povezani sa entitlements-ima, pa posedovanje određenih entitlements-a može automatski dodeliti određene extensions.

### **Provera PID privilegija**

[**Prema ovome**](https://www.youtube.com/watch?v=mG715HcDgO8&t=3011s), funkcije **`sandbox_check`** (to je `__mac_syscall`) mogu da provere **da li je određena operacija dozvoljena ili nije** od strane Sandbox-a za određeni PID, audit token ili unique ID.<sup>[[8]](#references)</sup>

Alat [**sbtool**](http://newosxbook.com/src.jl?tree=listings&file=sbtool.c) (pronađite ga [kompajliranog ovde](https://newosxbook.com/articles/hitsb.html)) može da proveri da li PID može da izvrši određene radnje:
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explanation of the sandbox profile and extensions
sbtool <pid> all
```
### \[un]suspend

Takođe je moguće suspendovati i ponovo aktivirati sandbox pomoću funkcija `sandbox_suspend` i `sandbox_unsuspend` iz `libsystem_sandbox.dylib`.

Imajte na umu da se pri pozivanju funkcije za suspendovanje proveravaju određena entitlements kako bi se pozivalac autorizovao za njeno pozivanje, kao što su:

- com.apple.private.security.sandbox-manager
- com.apple.security.print
- com.apple.security.temporary-exception.audio-unit-host

## mac_syscall

Ovaj sistemski poziv (#381) očekuje jedan string kao prvi argument, koji označava modul koji treba pokrenuti, a zatim kod u drugom argumentu, koji označava funkciju koju treba pokrenuti. Treći argument zavisi od izvršene funkcije.<sup>[[2]](#references)</sup>

Funkcija `___sandbox_ms` poziva `mac_syscall`, navodeći `"Sandbox"` kao prvi argument, baš kao što je `___sandbox_msp` wrapper za `mac_set_proc` (#387). Neki od podržanih kodova funkcije `___sandbox_ms` mogu se pronaći u sledećoj tabeli:

- **set_profile (#0)**: Primeni kompajlirani ili imenovani profil na proces.
- **platform_policy (#1)**: Primeni provere politike specifične za platformu (razlikuju se između macOS-a i iOS-a).
- **check_sandbox (#2)**: Ručno proveri određenu sandbox operaciju.
- **note (#3)**: Dodaj anotaciju u Sandbox.
- **container (#4)**: Dodaj anotaciju sandboxu, obično radi debagovanja ili identifikacije.
- **extension_issue (#5)**: Generiši novu ekstenziju za proces.
- **extension_consume (#6)**: Iskoristi datu ekstenziju.
- **extension_release (#7)**: Oslobodi memoriju povezanu sa iskorišćenom ekstenzijom.
- **extension_update_file (#8)**: Izmeni parametre postojeće file ekstenzije unutar sandboxa.
- **extension_twiddle (#9)**: Prilagodi ili izmeni postojeću file ekstenziju (npr. TextEdit, rtf, rtfd).
- **suspend (#10)**: Privremeno suspenduj sve sandbox provere (zahteva odgovarajuće entitlements).
- **unsuspend (#11)**: Nastavi sve prethodno suspendovane sandbox provere.
- **passthrough_access (#12)**: Dozvoli direktan passthrough pristup resursu, zaobilazeći sandbox provere.
- **set_container_path (#13)**: (samo iOS) Postavi putanju containera za app group ili signing ID.
- **container_map (#14)**: (samo iOS) Preuzmi putanju containera iz `containermanagerd`.
- **sandbox_user_state_item_buffer_send (#15)**: (iOS 10+) Postavi metadata korisničkog režima u sandboxu.
- **inspect (#16)**: Pruži debug informacije o sandboxovanom procesu.
- **dump (#18)**: (macOS 11) Izbaci trenutni profil sandboxa radi analize.
- **vtrace (#19)**: Prati sandbox operacije radi nadzora ili debagovanja.
- **builtin_profile_deactivate (#20)**: (macOS < 11) Deaktiviraj imenovane profile (npr. `pe_i_can_has_debugger`).
- **check_bulk (#21)**: Izvrši više `sandbox_check` operacija u jednom pozivu.
- **reference_retain_by_audit_token (#28)**: Kreiraj referencu za audit token radi korišćenja u sandbox proverama.
- **reference_release (#29)**: Oslobodi prethodno zadržanu referencu audit tokena.
- **rootless_allows_task_for_pid (#30)**: Proveri da li je `task_for_pid` dozvoljen (slično `csr` proverama).
- **rootless_whitelist_push (#31)**: (macOS) Primeni manifest fajl System Integrity Protection (SIP).
- **rootless_whitelist_check (preflight) (#32)**: Proveri SIP manifest fajl pre izvršavanja.
- **rootless_protected_volume (#33)**: (macOS) Primeni SIP zaštite na disk ili particiju.
- **rootless_mkdir_protected (#34)**: Primeni SIP/DataVault zaštitu na proces kreiranja direktorijuma.

## Sandbox.kext

Imajte na umu da kernel ekstenzija u iOS-u sadrži **hardkodirane sve profile** unutar segmenta `__TEXT.__const` kako bi se sprečilo njihovo menjanje. Slede neke zanimljive funkcije kernel ekstenzije:

- **`hook_policy_init`**: Hook-uje `mpo_policy_init` i poziva se nakon `mac_policy_register`. Obavlja većinu inicijalizacije Sandboxa. Takođe inicijalizuje SIP.
- **`hook_policy_initbsd`**: Postavlja sysctl interfejs, registrujući `security.mac.sandbox.sentinel`, `security.mac.sandbox.audio_active` i `security.mac.sandbox.debug_mode` (ako je sistem bootovan sa `PE_i_can_has_debugger`).
- **`hook_policy_syscall`**: Poziva ga `mac_syscall` sa `"Sandbox"` kao prvim argumentom i kodom koji u drugom argumentu označava operaciju. Switch se koristi za pronalaženje koda koji treba pokrenuti na osnovu zahtevanog koda.

### MACF Hooks

**`Sandbox.kext`** koristi više od stotinu hook-ova putem MACF-a. Većina hook-ova samo proverava neke trivijalne slučajeve koji omogućavaju izvršavanje akcije; u suprotnom pozivaju **`cred_sb_evalutate`** sa **credentials** iz MACF-a, brojem koji odgovara **operaciji** koju treba izvršiti i **bufferom** za izlazni rezultat.<sup>[[1]](#references)</sup>

Dobar primer je funkcija **`_mpo_file_check_mmap`**, koja hook-uje **`mmap`** i počinje proverom da li će nova memorija biti upisiva (a ako neće, dozvoljava izvršavanje). Zatim proverava da li se koristi za dyld shared cache i, ako je tako, dozvoljava izvršavanje. Na kraju poziva **`sb_evaluate_internal`** (ili jedan od njegovih wrapper-a) radi dodatnih provera dozvola.

Pored stotina hook-ova koje Sandbox koristi, 3 su posebno zanimljiva:

- `mpo_proc_check_for`: Primeni profil ako je to potrebno i ako prethodno nije bio primenjen.
- `mpo_vnode_check_exec`: Poziva se kada proces učita povezani binary; zatim se vrši provera profila, kao i provera kojom se zabranjuje SUID/SGID izvršavanje.
- `mpo_cred_label_update_execve`: Poziva se kada se dodeljuje label. Ovo je najduža funkcija, jer se poziva kada je binary u potpunosti učitan, ali još nije izvršen. Obavlja radnje kao što su kreiranje sandbox objekta, dodavanje sandbox strukture kauth credentials objektu, uklanjanje pristupa mach portovima...

Imajte na umu da je **`_cred_sb_evalutate`** wrapper preko **`sb_evaluate_internal`**. Ova funkcija dobija prosleđeni credentials i zatim vrši evaluaciju pomoću funkcije **`eval`**, koja obično prvo evaluira **platform profile**, koji se podrazumevano primenjuje na sve procese, a zatim **specific process profile**. Imajte na umu da je platform profile jedna od glavnih komponenti **SIP-a** u macOS-u.

## Sandboxd

Sandbox takođe ima user daemon koji izlaže XPC Mach servis `com.apple.sandboxd` i vezuje special port 14 (`HOST_SEATBELT_PORT`), koji kernel ekstenzija koristi za komunikaciju sa njim. Izlaže neke funkcije koristeći MIG.

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
