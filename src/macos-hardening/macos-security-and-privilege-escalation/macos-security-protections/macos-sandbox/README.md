# macOS Sandbox

{{#include ../../../../banners/hacktricks-training.md}}

## Osnovne informacije

MacOS Sandbox (u početku nazivan Seatbelt) **ograničava aplikacije** koje se izvršavaju unutar sandbox-a na **dozvoljene radnje navedene u Sandbox profilu** sa kojim se aplikacija izvršava. Ovo pomaže da se osigura da će **aplikacija pristupati samo očekivanim resursima**.

Svaka aplikacija sa **entitlement-om** **`com.apple.security.app-sandbox`** izvršavaće se unutar sandbox-a. **Apple binarije** se obično izvršavaju unutar Sandbox-a, a sve aplikacije iz **App Store-a imaju taj entitlement**. Zato će se više aplikacija izvršavati unutar sandbox-a.<sup>[4]</sup>

Da bi kontrolisao šta proces može ili ne može da uradi, **Sandbox ima hooks** u gotovo svakoj operaciji koju proces može pokušati da izvrši (uključujući većinu syscall-ova), koristeći **MACF**. Međutim, u**zavisnosti** od **entitlement-a** aplikacije, Sandbox može biti permisivniji prema procesu.

Neke važne komponente Sandbox-a su:

- **kernel extension** `/System/Library/Extensions/Sandbox.kext`
- **private framework** `/System/Library/PrivateFrameworks/AppSandbox.framework`
- **daemon** koji se izvršava u userland-u `/usr/libexec/sandboxd`
- **containers** `~/Library/Containers`

### Containers

Svaka sandboxed aplikacija imaće sopstveni container u `~/Library/Containers/{CFBundleIdentifier}` :
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
Unutar fascikle svakog bundle id-a možete pronaći **plist** i **Data direktorijum** aplikacije, sa strukturom koja oponaša Home folder:
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
> Imajte na umu da, čak i ako su symlinks prisutni da bi „izašli“ iz Sandbox-a i pristupili drugim fasciklama, App i dalje mora da **ima dozvole** za njihov pristup. Te dozvole se nalaze unutar **`.plist`** datoteke u `RedirectablePaths`.

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
> Sve što kreira/menja aplikacija koja se izvršava u Sandbox-u dobiće **quarantine attribut**e. Ovo će sprečiti sandbox prostor pokretanjem Gatekeeper-a ako sandbox aplikacija pokuša da izvrši nešto pomoću **`open`**.

## Sandbox Profiles

Sandbox profili su konfiguracione datoteke koje određuju šta će biti **dozvoljeno/zabranjeno** u tom **Sandbox-u**. Koristi **Sandbox Profile Language (SBPL)**, koji koristi programski jezik [**Scheme**](<https://en.wikipedia.org/wiki/Scheme_(programming_language)>).

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
> Pogledajte ovo [**istraživanje**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) **da biste proverili još radnji koje mogu biti dozvoljene ili zabranjene.**<sup>[5]</sup>
>
> Imajte na umu da su u kompajliranoj verziji profila nazivi operacija zamenjeni njihovim unosima u nizu koji su poznati dylib-u i kext-u, zbog čega je kompajlirana verzija kraća i teža za čitanje.

Važne **sistemske usluge** takođe rade unutar sopstvenog prilagođenog **sandbox**-a, kao što je usluga `mdnsresponder`. Ove prilagođene **sandbox profile** možete pronaći u:

- **`/usr/share/sandbox`**
- **`/System/Library/Sandbox/Profiles`**
- Ostali sandbox profili mogu se proveriti na [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles).
- U iOS-u se platform profile nalazi unutar sandbox `.kext`-a, u `_platform_profile_data` delu binarne datoteke.

Aplikacije iz **App Store**-a koriste **profil** **`/System/Library/Sandbox/Profiles/application.sb`**. U ovom profilu možete proveriti kako prava kao što je **`com.apple.security.network.server`** dozvoljavaju procesu da koristi mrežu.

Zatim, neke **Apple daemon usluge** koriste različite profile smeštene u `/System/Library/Sandbox/Profiles/*.sb` ili `/usr/share/sandbox/*.sb`. Ovi sandbox-i se primenjuju u glavnoj funkciji koja poziva API `sandbox_init_XXX`.<sup>[3]</sup>

**SIP** je Sandbox profil pod nazivom platform_profile u `/System/Library/Sandbox/rootless.conf`.

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
> Imajte na umu da **software** čiji je autor **Apple**, a koji radi na **Windows** sistemu, **nema dodatne bezbednosne mere**, kao što je sandboxing aplikacija.

Primeri bypass-a:

- [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)<sup>[6]</sup>
- [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (u mogućnosti su da upisuju fajlove izvan sandbox-a čiji naziv počinje sa `~$`).<sup>[7]</sup>

### Praćenje sandbox-a

#### Putem profila

Moguće je pratiti sve provere koje sandbox obavlja svaki put kada se proverava neka radnja. Da biste to uradili, jednostavno kreirajte sledeći profil:
```scheme:trace.sb
(version 1)
(trace /tmp/trace.out)
```
A zatim samo izvršite nešto koristeći taj profil:
```bash
sandbox-exec -f /tmp/trace.sb /bin/ls
```
U datoteci `/tmp/trace.out` možete videti svaku proveru sandbox-a svaki put kada je pozvana (zbog toga ima mnogo duplikata).

Sandbox je takođe moguće pratiti pomoću parametra **`-t`**: `sandbox-exec -t /path/trace.out -p "(version 1)" /bin/ls`

#### Putem API-ja

Funkcija `sandbox_set_trace_path`, koju eksportuje `libsystem_sandbox.dylib`, omogućava navođenje imena trace datoteke u koju će se upisivati provere sandbox-a.\
Nešto slično je moguće uraditi pozivanjem `sandbox_vtrace_enable()`, a zatim preuzimanjem error logova iz bafera pomoću `sandbox_vtrace_report()`.

### Inspekcija sandbox-a

`libsandbox.dylib` eksportuje funkciju pod nazivom sandbox_inspect_pid, koja daje listu stanja sandbox-a procesa (uključujući extensions). Međutim, ovu funkciju mogu koristiti samo platform binaries.

### macOS i iOS Sandbox profili

macOS čuva sistemske Sandbox profile na dve lokacije: **/usr/share/sandbox/** i **/System/Library/Sandbox/Profiles**.

Ako aplikacija treće strane poseduje entitlement _**com.apple.security.app-sandbox**_, sistem na taj proces primenjuje profil **/System/Library/Sandbox/Profiles/application.sb**.

Na iOS-u podrazumevani profil se zove **container**, a nemamo tekstualnu SBPL reprezentaciju. U memoriji je ovaj sandbox predstavljen kao Allow/Deny binarno stablo za svaku dozvolu sandbox-a.

### Prilagođeni SBPL u App Store aplikacijama

Kompanije bi mogle da omoguće rad svojih aplikacija **sa prilagođenim Sandbox profilima** (umesto sa podrazumevanim profilom). Potrebno je da koriste entitlement **`com.apple.security.temporary-exception.sbpl`**, koji mora odobriti Apple.

Definiciju ovog entitlement-a moguće je proveriti u **`/System/Library/Sandbox/Profiles/application.sb:`**
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
Ovo će **eval string nakon ovog entitlement-a** kao Sandbox profil.

### Kompajliranje i dekompajliranje Sandbox profila

Alat **`sandbox-exec`** koristi funkcije `sandbox_compile_*` iz `libsandbox.dylib`. Glavne eksportovane funkcije su: `sandbox_compile_file` (očekuje putanju do fajla, parametar `-f`), `sandbox_compile_string` (očekuje string, parametar `-p`), `sandbox_compile_name` (očekuje ime container-a, parametar `-n`), `sandbox_compile_entitlements` (očekuje entitlements plist).

Ova reverzovana i [**open sourced verzija alata sandbox-exec**](https://newosxbook.com/src.jl?tree=listings&file=/sandbox_exec.c) omogućava da **`sandbox-exec`** upiše kompajlirani Sandbox profil u fajl.

Takođe, da bi ograničio proces unutar container-a, on može pozvati `sandbox_spawnattrs_set[container/profilename]` i proslediti container ili postojeći profil.

## Debug i Bypass Sandbox-a

Na macOS-u, za razliku od iOS-a gde kernel sandbox-uje procese od samog početka, **procesi moraju sami da se opredele za Sandbox**. To znači da na macOS-u proces nije ograničen Sandbox-om dok aktivno ne odluči da uđe u njega, iako su App Store aplikacije uvek sandbox-ovane.

Procesi se automatski sandbox-uju iz userland-a pri pokretanju ako imaju entitlement: `com.apple.security.app-sandbox`. Za detaljno objašnjenje ovog procesa pogledajte:


{{#ref}}
macos-sandbox-debug-and-bypass/
{{#endref}}

## **Sandbox Extensions**

Extensions omogućavaju davanje dodatnih privilegija objektu i dodeljuju se pozivanjem jedne od sledećih funkcija:

- `sandbox_issue_extension`
- `sandbox_extension_issue_file[_with_new_type]`
- `sandbox_extension_issue_mach`
- `sandbox_extension_issue_iokit_user_client_class`
- `sandbox_extension_issue_iokit_registry_rentry_class`
- `sandbox_extension_issue_generic`
- `sandbox_extension_issue_posix_ipc`

Extensions se čuvaju u drugom MACF label slot-u dostupnom iz credentials procesa. Sledeći **`sbtool`** može pristupiti ovim informacijama.

Imajte na umu da extensions obično dodeljuju dozvoljeni procesi; na primer, `tccd` će dodeliti extension token za `com.apple.tcc.kTCCServicePhotos` kada proces pokuša da pristupi fotografijama i dobije dozvolu u XPC poruci. Zatim će proces morati da potroši extension token kako bi mu on bio dodat.\
Imajte na umu da su extension token-i dugi heksadecimalni nizovi koji kodiraju dodeljene dozvole. Međutim, oni nemaju hardkodovan dozvoljeni PID, što znači da bilo koji proces koji ima pristup token-u može biti **iskorišćen od strane više procesa**.

Imajte na umu da su extensions takođe veoma povezani sa entitlements-ima, pa posedovanje određenih entitlements-a može automatski dodeliti određene extensions.

### **Provera privilegija PID-a**

[**Prema ovome**](https://www.youtube.com/watch?v=mG715HcDgO8&t=3011s), funkcije **`sandbox_check`** (to je `__mac_syscall`) mogu proveriti **da li je operacija dozvoljena ili nije** od strane Sandbox-a u određenom PID-u, audit token-u ili unique ID-u.<sup>[8]</sup>

Alat [**sbtool**](http://newosxbook.com/src.jl?tree=listings&file=sbtool.c) (pronađite ga [kompajliranog ovde](https://newosxbook.com/articles/hitsb.html)) može proveriti da li PID može da izvrši određene radnje:
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explanation of the sandbox profile and extensions
sbtool <pid> all
```
### \[un]suspend

Takođe je moguće suspendovati i ponovo aktivirati sandbox pomoću funkcija `sandbox_suspend` i `sandbox_unsuspend` iz `libsystem_sandbox.dylib`.

Imajte na umu da se pri pozivanju funkcije za suspendovanje proveravaju određena prava kako bi se pozivaocu dozvolilo da je pozove, kao što su:

- com.apple.private.security.sandbox-manager
- com.apple.security.print
- com.apple.security.temporary-exception.audio-unit-host

## mac_syscall

Ovaj sistemski poziv (#381) očekuje jedan string kao prvi argument, koji određuje modul koji treba pokrenuti, a zatim kod u drugom argumentu, koji određuje funkciju koju treba pokrenuti. Treći argument zavisi od funkcije koja se izvršava.<sup>[2]</sup>

Funkcija `___sandbox_ms` obavija poziv `mac_syscall`, navodeći `"Sandbox"` kao prvi argument, baš kao što je `___sandbox_msp` omotač za `mac_set_proc` (#387). Neki od podržanih kodova funkcije `___sandbox_ms` mogu se pronaći u ovoj tabeli:

- **set_profile (#0)**: Primeni kompajlirani ili imenovani profil na proces.
- **platform_policy (#1)**: Primeni provere pravila specifične za platformu (razlikuju se između macOS-a i iOS-a).
- **check_sandbox (#2)**: Ručno proveri određenu sandbox operaciju.
- **note (#3)**: Dodaj anotaciju u Sandbox.
- **container (#4)**: Priloži anotaciju sandboxu, obično radi debugovanja ili identifikacije.
- **extension_issue (#5)**: Generiši novu ekstenziju za proces.
- **extension_consume (#6)**: Iskoristi datu ekstenziju.
- **extension_release (#7)**: Oslobodi memoriju povezanu sa iskorišćenom ekstenzijom.
- **extension_update_file (#8)**: Izmeni parametre postojeće ekstenzije datoteke unutar sandboxa.
- **extension_twiddle (#9)**: Podesi ili izmeni postojeću ekstenziju datoteke (npr. TextEdit, rtf, rtfd).
- **suspend (#10)**: Privremeno suspenduj sve sandbox provere (zahteva odgovarajuća prava).
- **unsuspend (#11)**: Nastavi sve prethodno suspendovane sandbox provere.
- **passthrough_access (#12)**: Dozvoli direktan passthrough pristup resursu, zaobilazeći sandbox provere.
- **set_container_path (#13)**: (Samo iOS) Postavi putanju kontejnera za grupu aplikacija ili ID potpisivanja.
- **container_map (#14)**: (Samo iOS) Preuzmi putanju kontejnera iz `containermanagerd`.
- **sandbox_user_state_item_buffer_send (#15)**: (iOS 10+) Postavi metapodatke korisničkog režima u sandboxu.
- **inspect (#16)**: Pruži debug informacije o sandboxovanom procesu.
- **dump (#18)**: (macOS 11) Izbaci trenutni profil sandboxa radi analize.
- **vtrace (#19)**: Prati sandbox operacije radi nadgledanja ili debugovanja.
- **builtin_profile_deactivate (#20)**: (macOS < 11) Deaktiviraj imenovane profile (npr. `pe_i_can_has_debugger`).
- **check_bulk (#21)**: Izvrši više `sandbox_check` operacija u jednom pozivu.
- **reference_retain_by_audit_token (#28)**: Kreiraj referencu za audit token radi korišćenja u sandbox proverama.
- **reference_release (#29)**: Oslobodi prethodno zadržanu referencu audit tokena.
- **rootless_allows_task_for_pid (#30)**: Proveri da li je `task_for_pid` dozvoljen (slično `csr` proverama).
- **rootless_whitelist_push (#31)**: (macOS) Primeni manifest datoteku za System Integrity Protection (SIP).
- **rootless_whitelist_check (preflight) (#32)**: Proveri manifest datoteku za SIP pre izvršavanja.
- **rootless_protected_volume (#33)**: (macOS) Primeni SIP zaštite na disk ili particiju.
- **rootless_mkdir_protected (#34)**: Primeni SIP/DataVault zaštitu na proces kreiranja direktorijuma.

## Sandbox.kext

Imajte na umu da kernel ekstenzija u iOS-u sadrži **hardcoded sve profile** unutar segmenta `__TEXT.__const`, kako bi se sprečilo njihovo menjanje. U nastavku su navedene neke zanimljive funkcije kernel ekstenzije:

- **`hook_policy_init`**: Hook-uje `mpo_policy_init` i poziva se nakon `mac_policy_register`. Izvršava većinu inicijalizacije Sandboxa. Takođe inicijalizuje SIP.
- **`hook_policy_initbsd`**: Podešava sysctl interfejs registrujući `security.mac.sandbox.sentinel`, `security.mac.sandbox.audio_active` i `security.mac.sandbox.debug_mode` (ako je sistem bootovan sa `PE_i_can_has_debugger`).
- **`hook_policy_syscall`**: Poziva ga `mac_syscall` sa `"Sandbox"` kao prvim argumentom i kodom koji u drugom argumentu označava operaciju. Koristi se switch kako bi se pronašao kod koji treba izvršiti na osnovu zahtevanog koda.

### MACF Hooks

**`Sandbox.kext`** koristi više od stotinu hook-ova preko MACF-a. Većina hook-ova samo proverava neke trivijalne slučajeve koji omogućavaju izvršavanje radnje; ako to nije moguće, pozvaće **`cred_sb_evalutate`** sa **credentials** iz MACF-a, brojem koji odgovara **operation** koju treba izvršiti i **bufferom** za izlaz.<sup>[1]</sup>

Dobar primer za to je funkcija **`_mpo_file_check_mmap`**, koja hook-uje **`mmap`** i počinje proverom da li će nova memorija biti upisiva (i, ako neće, dozvoljava izvršavanje), zatim proverava da li se koristi za dyld shared cache i, ako se koristi, dozvoljava izvršavanje, a na kraju poziva **`sb_evaluate_internal`** (ili jedan od njegovih omotača) radi dodatnih provera dozvola.

Pored stotina hook-ova koje Sandbox koristi, posebno su zanimljiva sledeća 3:

- `mpo_proc_check_for`: Primeni profil ako je potrebno i ako prethodno nije bio primenjen.
- `mpo_vnode_check_exec`: Poziva se kada proces učita pridruženi binary; zatim se izvršava provera profila, kao i provera koja zabranjuje SUID/SGID izvršavanja.
- `mpo_cred_label_update_execve`: Poziva se kada se label dodeljuje. Ovo je najduža funkcija, jer se poziva kada je binary u potpunosti učitan, ali još nije izvršen. Izvršava radnje kao što su kreiranje sandbox objekta, dodavanje sandbox strukture kauth credentials objektu, uklanjanje pristupa mach portovima...

Imajte na umu da je **`_cred_sb_evalutate`** omotač preko **`sb_evaluate_internal`** i da ova funkcija preuzima prosleđene credentials, a zatim izvršava evaluaciju pomoću funkcije **`eval`**, koja obično evaluira **platform profile**, koji se podrazumevano primenjuje na sve procese, a zatim i **specific process profile**. Imajte na umu da je platform profile jedna od glavnih komponenti **SIP-a** u macOS-u.

## Sandboxd

Sandbox takođe ima korisnički daemon koji izlaže XPC Mach servis `com.apple.sandboxd` i vezuje specijalni port 14 (`HOST_SEATBELT_PORT`), koji kernel ekstenzija koristi za komunikaciju sa njim. Izlaže neke funkcije pomoću MIG-a.

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
