# macOS Sandbox

{{#include ../../../../banners/hacktricks-training.md}}

## Osnovne informacije

MacOS Sandbox (prvobitno nazvan Seatbelt) **ograničava aplikacije** koje se izvršavaju unutar sandboxes-a na **dozvoljene radnje navedene u Sandbox profilu** sa kojim aplikacija radi. Ovo pomaže da se osigura da **aplikacija pristupa samo očekivanim resursima**.

Svaka aplikacija sa **entitlement** **`com.apple.security.app-sandbox`** će se izvršavati unutar sandboxes-a. **Apple binarni** obično se izvršavaju unutar Sandbox-a, a sve aplikacije iz **App Store-a imaju tu entitlement**. Tako će se nekoliko aplikacija izvršavati unutar sandboxes-a.

Da bi se kontrolisalo šta proces može ili ne može da radi, **Sandbox ima hooks** u skoro svakoj operaciji koju proces može pokušati (uključujući većinu syscalls) koristeći **MACF**. Međutim, **zavisno** od **entitlements** aplikacije, Sandbox može biti permisivniji prema procesu.

Neki važni sastavni delovi Sandbox-a su:

- **kernel ekstenzija** `/System/Library/Extensions/Sandbox.kext`
- **privatni framework** `/System/Library/PrivateFrameworks/AppSandbox.framework`
- **daemon** koji se izvršava u userland-u `/usr/libexec/sandboxd`
- **kontejneri** `~/Library/Containers`

### Kontejneri

Svaka sandboxed aplikacija će imati svoj vlastiti kontejner u `~/Library/Containers/{CFBundleIdentifier}` :
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
Unutar svake fascikle sa bundle id možete pronaći **plist** i **Data direktorijum** aplikacije sa strukturom koja oponaša Home fasciklu:
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
> Imajte na umu da čak i ako su simboličke veze tu da "pobegnu" iz Sandbox-a i pristupe drugim folderima, aplikacija i dalje mora **imati dozvole** da im pristupi. Ove dozvole su unutar **`.plist`** u `RedirectablePaths`.

**`SandboxProfileData`** je kompajlirani sandbox profil CFData kodiran u B64.
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
> Sve što kreira/menja aplikacija u Sandbox-u dobiće **atribut karantina**. To će sprečiti prostor sandboksiranja aktiviranjem Gatekeeper-a ako aplikacija u sandboksu pokuša da izvrši nešto sa **`open`**.

## Sandbox Profili

Sandbox profili su konfiguracione datoteke koje označavaju šta će biti **dozvoljeno/zabranjeno** u tom **Sandbox-u**. Koristi **Sandbox Profile Language (SBPL)**, koja koristi [**Scheme**](<https://en.wikipedia.org/wiki/Scheme_(programming_language)>) programski jezik.

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
> Proverite ovo [**istraživanje**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) **da biste proverili više akcija koje mogu biti dozvoljene ili odbijene.**
>
> Imajte na umu da su u kompajliranoj verziji profila imena operacija zamenjena njihovim unosima u nizu poznatom od strane dylib i kext, što čini kompajliranu verziju kraćom i teže čitljivom.

Važne **sistemske usluge** takođe rade unutar svojih prilagođenih **sandbox-a** kao što je usluga `mdnsresponder`. Ove prilagođene **sandbox profile** možete pregledati unutar:

- **`/usr/share/sandbox`**
- **`/System/Library/Sandbox/Profiles`**
- Ostale sandbox profile možete proveriti na [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles).

**App Store** aplikacije koriste **profil** **`/System/Library/Sandbox/Profiles/application.sb`**. Možete proveriti u ovom profilu kako ovlašćenja kao što je **`com.apple.security.network.server`** omogućavaju procesu da koristi mrežu.

Zatim, neki **Apple daemon servisi** koriste različite profile smeštene u `/System/Library/Sandbox/Profiles/*.sb` ili `/usr/share/sandbox/*.sb`. Ovi sandbox-i se primenjuju u glavnoj funkciji koja poziva API `sandbox_init_XXX`.

**SIP** je Sandbox profil nazvan platform_profile u `/System/Library/Sandbox/rootless.conf`.

### Primeri Sandbox Profila

Da biste pokrenuli aplikaciju sa **specifičnim sandbox profilom** možete koristiti:
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
> Imajte na umu da **softver** koji je **napisao Apple** i koji radi na **Windows-u** **nema dodatnih bezbednosnih mera**, kao što je aplikaciono sandboxing.

Primeri zaobilaženja:

- [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)
- [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (mogu da pišu datoteke van sandbox-a čije ime počinje sa `~$`).

### Praćenje Sandbox-a

#### Putem profila

Moguće je pratiti sve provere koje sandbox obavlja svaki put kada se akcija proverava. Za to jednostavno kreirajte sledeći profil:
```scheme:trace.sb
(version 1)
(trace /tmp/trace.out)
```
Zatim jednostavno izvršite nešto koristeći taj profil:
```bash
sandbox-exec -f /tmp/trace.sb /bin/ls
```
U `/tmp/trace.out` moći ćete da vidite svaku proveru sandboxes koja je izvršena svaki put kada je pozvana (dakle, puno duplikata).

Takođe je moguće pratiti sandbox koristeći **`-t`** parametar: `sandbox-exec -t /path/trace.out -p "(version 1)" /bin/ls`

#### Putem API-ja

Funkcija `sandbox_set_trace_path` koju izlaže `libsystem_sandbox.dylib` omogućava da se odredi ime datoteke za praćenje u koju će se zapisivati provere sandboxes.\
Takođe je moguće uraditi nešto slično pozivajući `sandbox_vtrace_enable()` i zatim dobijajući logove grešaka iz bafera pozivajući `sandbox_vtrace_report()`.

### Inspekcija Sandboxes

`libsandbox.dylib` izlaže funkciju pod nazivom sandbox_inspect_pid koja daje listu stanja sandboxes procesa (uključujući ekstenzije). Međutim, samo platforme binarnih datoteka mogu koristiti ovu funkciju.

### MacOS & iOS Sandbox profili

MacOS čuva sistemske sandbox profile na dve lokacije: **/usr/share/sandbox/** i **/System/Library/Sandbox/Profiles**.

I ako aplikacija treće strane nosi _**com.apple.security.app-sandbox**_ pravo, sistem primenjuje **/System/Library/Sandbox/Profiles/application.sb** profil na taj proces.

U iOS-u, podrazumevani profil se zove **container** i nemamo SBPL tekstualnu reprezentaciju. U memoriji, ovaj sandbox je predstavljen kao binarno stablo Dozvoli/Zabranjeno za svaku dozvolu iz sandboxes.

### Prilagođeni SBPL u aplikacijama App Store-a

Moguće je da kompanije učine da njihove aplikacije rade **sa prilagođenim Sandbox profilima** (umesto sa podrazumevanim). Moraju koristiti pravo **`com.apple.security.temporary-exception.sbpl`** koje mora biti odobreno od strane Apple-a.

Moguće je proveriti definiciju ovog prava u **`/System/Library/Sandbox/Profiles/application.sb:`**
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
Ovo će **evalirati string nakon ovog prava** kao Sandbox profil.

### Kompilacija i dekompilacija Sandbox profila

Alat **`sandbox-exec`** koristi funkcije `sandbox_compile_*` iz `libsandbox.dylib`. Glavne funkcije koje se izvoze su: `sandbox_compile_file` (očekuje putanju do datoteke, parametar `-f`), `sandbox_compile_string` (očekuje string, parametar `-p`), `sandbox_compile_name` (očekuje ime kontejnera, parametar `-n`), `sandbox_compile_entitlements` (očekuje entitlements plist).

Ova obrnuta i [**open sourced verzija alata sandbox-exec**](https://newosxbook.com/src.jl?tree=listings&file=/sandbox_exec.c) omogućava da **`sandbox-exec`** piše u datoteku kompajlirani sandbox profil.

Pored toga, da bi se proces ograničio unutar kontejnera, može pozvati `sandbox_spawnattrs_set[container/profilename]` i proslediti kontejner ili prethodno postojeći profil.

## Debug & Bypass Sandbox

Na macOS-u, za razliku od iOS-a gde su procesi od početka sandboxovani od strane kernela, **procesi moraju sami da se prijave za sandbox**. To znači da na macOS-u, proces nije ograničen sandbox-om dok aktivno ne odluči da uđe u njega, iako su aplikacije iz App Store-a uvek sandboxovane.

Procesi se automatski sandboxuju iz userlanda kada počnu ako imaju pravo: `com.apple.security.app-sandbox`. Za detaljno objašnjenje ovog procesa pogledajte:

{{#ref}}
macos-sandbox-debug-and-bypass/
{{#endref}}

## **Sandbox Ekstenzije**

Ekstenzije omogućavaju dodatne privilegije objektu i pozivaju jednu od funkcija:

- `sandbox_issue_extension`
- `sandbox_extension_issue_file[_with_new_type]`
- `sandbox_extension_issue_mach`
- `sandbox_extension_issue_iokit_user_client_class`
- `sandbox_extension_issue_iokit_registry_rentry_class`
- `sandbox_extension_issue_generic`
- `sandbox_extension_issue_posix_ipc`

Ekstenzije se čuvaju u drugom MACF label slotu koji je dostupan iz kredencijala procesa. Sledeći **`sbtool`** može pristupiti ovim informacijama.

Napomena da se ekstenzije obično dodeljuju odobrenim procesima, na primer, `tccd` će dodeliti token ekstenzije `com.apple.tcc.kTCCServicePhotos` kada je proces pokušao da pristupi fotografijama i bio je odobren u XPC poruci. Tada će proces morati da iskoristi token ekstenzije kako bi bio dodat njemu.\
Napomena da su tokeni ekstenzije dugi heksadecimalni brojevi koji kodiraju dodeljene dozvole. Međutim, nemaju hardkodirani dozvoljeni PID, što znači da bilo koji proces sa pristupom tokenu može biti **iskorišćen od strane više procesa**.

Napomena da su ekstenzije veoma povezane sa pravima, tako da posedovanje određenih prava može automatski dodeliti određene ekstenzije.

### **Proveri PID privilegije**

[**Prema ovome**](https://www.youtube.com/watch?v=mG715HcDgO8&t=3011s), funkcije **`sandbox_check`** (to je `__mac_syscall`), mogu proveriti **da li je operacija dozvoljena ili ne** od strane sandbox-a u određenom PID-u, audit tokenu ili jedinstvenom ID-u.

[**Alat sbtool**](http://newosxbook.com/src.jl?tree=listings&file=sbtool.c) (pronađite ga [kompajliran ovde](https://newosxbook.com/articles/hitsb.html)) može proveriti da li PID može izvršiti određene akcije:
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explanation of the sandbox profile and extensions
sbtool <pid> all
```
### \[un]suspend

Takođe je moguće suspendovati i ponovo aktivirati sandbox koristeći funkcije `sandbox_suspend` i `sandbox_unsuspend` iz `libsystem_sandbox.dylib`.

Napomena da se prilikom pozivanja funkcije suspend proveravaju neka prava kako bi se autorizovao pozivalac da je pozove, kao što su:

- com.apple.private.security.sandbox-manager
- com.apple.security.print
- com.apple.security.temporary-exception.audio-unit-host

## mac_syscall

Ovaj sistemski poziv (#381) očekuje jedan string kao prvi argument koji će označiti modul koji treba pokrenuti, a zatim kod u drugom argumentu koji će označiti funkciju koja treba da se izvrši. Tada će treći argument zavisiti od izvršene funkcije.

Poziv funkcije `___sandbox_ms` obavija `mac_syscall` označavajući u prvom argumentu `"Sandbox"` baš kao što je `___sandbox_msp` obavijač `mac_set_proc` (#387). Tada se neki od podržanih kodova od strane `___sandbox_ms` mogu naći u ovoj tabeli:

- **set_profile (#0)**: Primeni kompajlirani ili imenovani profil na proces.
- **platform_policy (#1)**: Sprovodi provere politike specifične za platformu (razlikuje se između macOS i iOS).
- **check_sandbox (#2)**: Izvrši ručnu proveru specifične sandbox operacije.
- **note (#3)**: Dodaje anotaciju sandboxu.
- **container (#4)**: Priključuje anotaciju sandboxu, obično za debagovanje ili identifikaciju.
- **extension_issue (#5)**: Generiše novu ekstenziju za proces.
- **extension_consume (#6)**: Konzumira datu ekstenziju.
- **extension_release (#7)**: Oslobađa memoriju vezanu za konzumiranu ekstenziju.
- **extension_update_file (#8)**: Menja parametre postojeće ekstenzije datoteke unutar sandboxa.
- **extension_twiddle (#9)**: Prilagođava ili menja postojeću ekstenziju datoteke (npr. TextEdit, rtf, rtfd).
- **suspend (#10)**: Privremeno suspenduje sve sandbox provere (zahteva odgovarajuća prava).
- **unsuspend (#11)**: Nastavlja sve prethodno suspendovane sandbox provere.
- **passthrough_access (#12)**: Omogućava direktan pristup resursu, zaobilazeći sandbox provere.
- **set_container_path (#13)**: (samo iOS) Postavlja putanju kontejnera za grupu aplikacija ili ID potpisivanja.
- **container_map (#14)**: (samo iOS) Preuzima putanju kontejnera iz `containermanagerd`.
- **sandbox_user_state_item_buffer_send (#15)**: (iOS 10+) Postavlja metapodatke korisničkog režima u sandboxu.
- **inspect (#16)**: Pruža informacije za debagovanje o sandboxovanom procesu.
- **dump (#18)**: (macOS 11) Dumpuje trenutni profil sandboxa za analizu.
- **vtrace (#19)**: Prati sandbox operacije za monitoring ili debagovanje.
- **builtin_profile_deactivate (#20)**: (macOS < 11) Deaktivira imenovane profile (npr. `pe_i_can_has_debugger`).
- **check_bulk (#21)**: Izvršava više `sandbox_check` operacija u jednom pozivu.
- **reference_retain_by_audit_token (#28)**: Kreira referencu za audit token za korišćenje u sandbox proverama.
- **reference_release (#29)**: Oslobađa prethodno zadržanu referencu audit tokena.
- **rootless_allows_task_for_pid (#30)**: Proverava da li je `task_for_pid` dozvoljen (slično `csr` proverama).
- **rootless_whitelist_push (#31)**: (macOS) Primeni manifest fajl za zaštitu integriteta sistema (SIP).
- **rootless_whitelist_check (preflight) (#32)**: Proverava SIP manifest fajl pre izvršenja.
- **rootless_protected_volume (#33)**: (macOS) Primeni SIP zaštite na disk ili particiju.
- **rootless_mkdir_protected (#34)**: Primeni SIP/DataVault zaštitu na proces kreiranja direktorijuma.

## Sandbox.kext

Napomena da u iOS kernel ekstenzija sadrži **hardkodirane sve profile** unutar `__TEXT.__const` segmenta kako bi se izbegle izmene. Sledeće su neke zanimljive funkcije iz kernel ekstenzije:

- **`hook_policy_init`**: Hook-uje `mpo_policy_init` i poziva se nakon `mac_policy_register`. Izvršava većinu inicijalizacija Sandbox-a. Takođe inicijalizuje SIP.
- **`hook_policy_initbsd`**: Postavlja sysctl interfejs registrujući `security.mac.sandbox.sentinel`, `security.mac.sandbox.audio_active` i `security.mac.sandbox.debug_mode` (ako je podignut sa `PE_i_can_has_debugger`).
- **`hook_policy_syscall`**: Poziva se od strane `mac_syscall` sa "Sandbox" kao prvim argumentom i kodom koji označava operaciju u drugom. Koristi se switch za pronalaženje koda koji treba izvršiti prema traženom kodu.

### MACF Hooks

**`Sandbox.kext`** koristi više od stotinu hook-ova putem MACF. Većina hook-ova će samo proveriti neke trivijalne slučajeve koji omogućavaju izvršenje akcije, ako ne, pozvaće **`cred_sb_evalutate`** sa **akreditivima** iz MACF i brojem koji odgovara **operaciji** koja treba da se izvrši i **baferom** za izlaz.

Dobar primer toga je funkcija **`_mpo_file_check_mmap`** koja hook-uje **`mmap`** i koja će početi da proverava da li nova memorija može biti zapisiva (i ako ne, dozvoliti izvršenje), zatim će proveriti da li se koristi za dyld deljenu keš memoriju i ako jeste, dozvoliti izvršenje, i na kraju će pozvati **`sb_evaluate_internal`** (ili jedan od njegovih obavijača) da izvrši dalja provere dozvola.

Štaviše, od stotina hook-ova koje Sandbox koristi, postoje 3 koja su posebno zanimljiva:

- `mpo_proc_check_for`: Primeni profil ako je potrebno i ako prethodno nije primenjen.
- `mpo_vnode_check_exec`: Poziva se kada proces učita povezanu binarnu datoteku, zatim se vrši provera profila i takođe provera koja zabranjuje SUID/SGID izvršenja.
- `mpo_cred_label_update_execve`: Ovo se poziva kada se dodeljuje oznaka. Ovo je najduže jer se poziva kada je bina potpuno učitana, ali još nije izvršena. Izvršiće akcije kao što su kreiranje sandbox objekta, povezivanje sandbox strukture sa kauth akreditivima, uklanjanje pristupa mach portovima...

Napomena da je **`_cred_sb_evalutate`** obavijač preko **`sb_evaluate_internal`** i ova funkcija dobija akreditive koji su prosleđeni i zatim izvršava evaluaciju koristeći funkciju **`eval`** koja obično evaluira **platformski profil** koji se po defaultu primenjuje na sve procese, a zatim **specifični procesni profil**. Napomena da je platformski profil jedan od glavnih komponenti **SIP** u macOS-u.

## Sandboxd

Sandbox takođe ima korisnički daemon koji radi i izlaže XPC Mach servis `com.apple.sandboxd` i vezuje poseban port 14 (`HOST_SEATBELT_PORT`) koji kernel ekstenzija koristi za komunikaciju sa njim. Izlaže neke funkcije koristeći MIG.

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)

{{#include ../../../../banners/hacktricks-training.md}}
