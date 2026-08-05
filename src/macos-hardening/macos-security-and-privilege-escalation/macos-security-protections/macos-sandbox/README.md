# macOS Sandbox

{{#include ../../../../banners/hacktricks-training.md}}

## Informazioni di base

MacOS Sandbox (inizialmente chiamato Seatbelt) **limita le applicazioni** eseguite all'interno del sandbox alle **azioni consentite specificate nel profilo Sandbox** con cui l'app viene eseguita. Questo aiuta a garantire che **l'applicazione acceda solo alle risorse previste**.

Qualsiasi app con l'**entitlement** **`com.apple.security.app-sandbox`** verrà eseguita all'interno del sandbox. I **binari Apple** vengono generalmente eseguiti all'interno di un Sandbox e tutte le applicazioni dell'**App Store hanno tale entitlement**. Pertanto, diverse applicazioni verranno eseguite all'interno del sandbox.<sup>[4]</sup>

Per controllare cosa un processo possa o non possa fare, il **Sandbox dispone di hooks** in quasi tutte le operazioni che un processo potrebbe tentare (inclusa la maggior parte delle syscall), utilizzando **MACF**. Tuttavia, **in base agli** **entitlement** dell'app, il Sandbox potrebbe essere più permissivo nei confronti del processo.

Alcuni componenti importanti del Sandbox sono:

- L'**estensione del kernel** `/System/Library/Extensions/Sandbox.kext`
- Il **framework privato** `/System/Library/PrivateFrameworks/AppSandbox.framework`
- Un **daemon** in esecuzione in userland `/usr/libexec/sandboxd`
- I **containers** `~/Library/Containers`

### Containers

Ogni applicazione sandboxed avrà il proprio container in `~/Library/Containers/{CFBundleIdentifier}` :
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
All'interno di ciascuna cartella del bundle id puoi trovare il **plist** e la **Data directory** dell'app, con una struttura che imita la cartella Home:
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
> Nota che anche se i symlink sono presenti per "evadere" dal Sandbox e accedere ad altre cartelle, l'App deve comunque **avere i permessi** per accedervi. Questi permessi si trovano nel **`.plist`** in `RedirectablePaths`.

Il **`SandboxProfileData`** è il profilo sandbox compilato CFData codificato in B64.
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
> Tutto ciò che viene creato/modificato da un'applicazione in Sandbox riceverà l'**attributo di quarantena**. Questo impedirà a uno spazio Sandbox di attivare Gatekeeper se l'applicazione in Sandbox tenta di eseguire qualcosa con **`open`**.

## Profili Sandbox

I profili Sandbox sono file di configurazione che indicano cosa sarà **consentito/vietato** in quella **Sandbox**. Utilizzano il **Sandbox Profile Language (SBPL)**, che a sua volta utilizza il linguaggio di programmazione [**Scheme**](<https://en.wikipedia.org/wiki/Scheme_(programming_language)>).

Qui puoi trovare un esempio:
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
> Consulta questa [**ricerca**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) **per verificare altre azioni che potrebbero essere consentite o negate.**<sup>[5]</sup>
>
> Nota che nella versione compilata di un profilo, i nomi delle operazioni vengono sostituiti dalle relative posizioni in un array noto alla dylib e al kext, rendendo la versione compilata più breve e difficile da leggere.

Anche importanti **servizi di sistema** vengono eseguiti all'interno del proprio **sandbox** personalizzato, come il servizio `mdnsresponder`. Puoi visualizzare questi **profili sandbox** personalizzati in:

- **`/usr/share/sandbox`**
- **`/System/Library/Sandbox/Profiles`**
- Altri profili sandbox possono essere consultati su [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles).
- In iOS, il profilo della piattaforma si trova nel `.kext` sandbox, all'interno di `_platform_profile_data` nel binario.

Le app dell'**App Store** utilizzano il **profilo** **`/System/Library/Sandbox/Profiles/application.sb`**. In questo profilo puoi verificare come gli entitlement, come **`com.apple.security.network.server`**, consentano a un processo di utilizzare la rete.

Inoltre, alcuni servizi daemon **Apple** utilizzano profili diversi, situati in `/System/Library/Sandbox/Profiles/*.sb` o `/usr/share/sandbox/*.sb`. Questi sandbox vengono applicati nella funzione main che chiama l'API `sandbox_init_XXX`.<sup>[3]</sup>

**SIP** è un profilo Sandbox chiamato platform_profile in `/System/Library/Sandbox/rootless.conf`.

### Esempi di profili Sandbox

Per avviare un'applicazione con uno **specifico profilo sandbox**, puoi utilizzare:
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
> Nota che il **software** **scritto da Apple** che viene eseguito su **Windows** **non dispone di precauzioni di sicurezza aggiuntive**, come l'application sandboxing.

Esempi di bypass:

- [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)<sup>[6]</sup>
- [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (riescono a scrivere file al di fuori del sandbox il cui nome inizia con `~$`).<sup>[7]</sup>

### Tracciamento del Sandbox

#### Tramite profilo

È possibile tracciare tutti i controlli eseguiti dal sandbox ogni volta che viene verificata un'azione. A tale scopo, è sufficiente creare il seguente profilo:
```scheme:trace.sb
(version 1)
(trace /tmp/trace.out)
```
E poi esegui semplicemente qualcosa utilizzando quel profilo:
```bash
sandbox-exec -f /tmp/trace.sb /bin/ls
```
In `/tmp/trace.out` sarà possibile visualizzare ogni controllo sandbox eseguito ogni volta che è stato chiamato (quindi, molte duplicazioni).

È anche possibile tracciare la sandbox usando il parametro **`-t`**: `sandbox-exec -t /path/trace.out -p "(version 1)" /bin/ls`

#### Via API

La funzione `sandbox_set_trace_path` esportata da `libsystem_sandbox.dylib` consente di specificare un nome file di trace in cui verranno scritti i controlli sandbox.\
È anche possibile fare qualcosa di simile chiamando `sandbox_vtrace_enable()` e ottenendo successivamente i log degli errori dal buffer tramite `sandbox_vtrace_report()`.

### Ispezione della Sandbox

`libsandbox.dylib` esporta una funzione chiamata sandbox_inspect_pid che fornisce un elenco dello stato sandbox di un processo (incluse le estensioni). Tuttavia, solo i platform binaries possono utilizzare questa funzione.

### Profili Sandbox di MacOS e iOS

MacOS memorizza i profili sandbox di sistema in due posizioni: **/usr/share/sandbox/** e **/System/Library/Sandbox/Profiles**.

Inoltre, se un'applicazione di terze parti possiede l'entitlement _**com.apple.security.app-sandbox**_, il sistema applica il profilo **/System/Library/Sandbox/Profiles/application.sb** a tale processo.

In iOS, il profilo predefinito è chiamato **container** e non disponiamo della rappresentazione testuale SBPL. In memoria, questa sandbox è rappresentata come un albero binario Allow/Deny per ciascuna autorizzazione della sandbox.

### SBPL personalizzato nelle app dell'App Store

Potrebbe essere possibile per le aziende fare in modo che le proprie app vengano eseguite **con profili Sandbox personalizzati** (invece di quello predefinito). Devono utilizzare l'entitlement **`com.apple.security.temporary-exception.sbpl`**, che deve essere autorizzato da Apple.

È possibile verificare la definizione di questo entitlement in **`/System/Library/Sandbox/Profiles/application.sb:`**
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
Questo farà **eval della stringa dopo questo entitlement** come profilo Sandbox.

### Compilazione e decompilazione di un profilo Sandbox

Lo strumento **`sandbox-exec`** utilizza le funzioni `sandbox_compile_*` di `libsandbox.dylib`. Le funzioni principali esportate sono: `sandbox_compile_file` (si aspetta un percorso di file, parametro `-f`), `sandbox_compile_string` (si aspetta una stringa, parametro `-p`), `sandbox_compile_name` (si aspetta il nome di un container, parametro `-n`), `sandbox_compile_entitlements` (si aspetta un plist di entitlements).

Questa versione reverse-engineered e [**open source dello strumento sandbox-exec**](https://newosxbook.com/src.jl?tree=listings&file=/sandbox_exec.c) consente di fare in modo che **`sandbox-exec`** scriva in un file il profilo Sandbox compilato.

Inoltre, per confinare un processo all'interno di un container, potrebbe chiamare `sandbox_spawnattrs_set[container/profilename]` e passare un container o un profilo preesistente.

## Debug e bypass della Sandbox

Su macOS, a differenza di iOS, dove i processi sono sottoposti a sandbox fin dall'avvio dal kernel, **i processi devono optare autonomamente per la sandbox**. Ciò significa che su macOS un processo non è limitato dalla sandbox finché non decide attivamente di entrarvi, sebbene le app dell'App Store siano sempre sottoposte a sandbox.

I processi vengono automaticamente sottoposti a Sandbox dallo userland all'avvio se dispongono dell'entitlement: `com.apple.security.app-sandbox`. Per una spiegazione dettagliata di questo processo, consulta:


{{#ref}}
macos-sandbox-debug-and-bypass/
{{#endref}}

## **Sandbox Extensions**

Le extensions consentono di concedere ulteriori privilegi a un oggetto e vengono concesse chiamando una delle funzioni:

- `sandbox_issue_extension`
- `sandbox_extension_issue_file[_with_new_type]`
- `sandbox_extension_issue_mach`
- `sandbox_extension_issue_iokit_user_client_class`
- `sandbox_extension_issue_iokit_registry_rentry_class`
- `sandbox_extension_issue_generic`
- `sandbox_extension_issue_posix_ipc`

Le extensions sono memorizzate nel secondo slot dell'etichetta MACF, accessibile dalle credenziali del processo. Il seguente **`sbtool`** può accedere a queste informazioni.

Nota che le extensions vengono generalmente concesse dai processi autorizzati; ad esempio, `tccd` concederà il token di extension `com.apple.tcc.kTCCServicePhotos` quando un processo tenta di accedere alle foto e viene autorizzato in un messaggio XPC. Successivamente, il processo dovrà consumare il token di extension affinché questo venga aggiunto al processo.\
Nota che i token di extension sono valori esadecimali lunghi che codificano i permessi concessi. Tuttavia, non contengono il PID autorizzato hardcoded, il che significa che qualsiasi processo con accesso al token potrebbe essere **consumato da più processi**.

Nota che le extensions sono strettamente correlate anche agli entitlements, quindi il possesso di determinati entitlements potrebbe concedere automaticamente determinate extensions.

### **Controllo dei privilegi del PID**

[**Secondo questo**](https://www.youtube.com/watch?v=mG715HcDgO8&t=3011s), le funzioni **`sandbox_check`** (è una `__mac_syscall`) possono verificare **se un'operazione è consentita o meno** dalla sandbox in uno specifico PID, audit token o unique ID.<sup>[8]</sup>

Lo [**strumento sbtool**](http://newosxbook.com/src.jl?tree=listings&file=sbtool.c) (trovalo [compilato qui](https://newosxbook.com/articles/hitsb.html)) può verificare se un PID può eseguire determinate azioni:
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explanation of the sandbox profile and extensions
sbtool <pid> all
```
### \[un]suspend

È inoltre possibile sospendere e riattivare il sandbox usando le funzioni `sandbox_suspend` e `sandbox_unsuspend` di `libsystem_sandbox.dylib`.

Nota che, per chiamare la funzione di sospensione, vengono verificati alcuni entitlements per autorizzare il chiamante a eseguirla, come:

- com.apple.private.security.sandbox-manager
- com.apple.security.print
- com.apple.security.temporary-exception.audio-unit-host

## mac_syscall

Questa system call (#381) prevede come primo argomento una stringa che indica il modulo da eseguire e come secondo argomento un codice che indica la funzione da eseguire. Il terzo argomento dipenderà quindi dalla funzione eseguita.<sup>[2]</sup>

La funzione `___sandbox_ms` avvolge `mac_syscall`, indicando `"Sandbox"` come primo argomento, proprio come `___sandbox_msp` è un wrapper di `mac_set_proc` (#387). I codici supportati da `___sandbox_ms` sono riportati nella seguente tabella:

- **set_profile (#0)**: Applica un profilo compilato o denominato a un processo.
- **platform_policy (#1)**: Impone controlli delle policy specifici della piattaforma (variano tra macOS e iOS).
- **check_sandbox (#2)**: Esegue un controllo manuale di una specifica operazione del sandbox.
- **note (#3)**: Aggiunge un'annotazione a un Sandbox.
- **container (#4)**: Collega un'annotazione a un sandbox, in genere per il debugging o l'identificazione.
- **extension_issue (#5)**: Genera una nuova extension per un processo.
- **extension_consume (#6)**: Consuma una extension fornita.
- **extension_release (#7)**: Rilascia la memoria associata a una extension consumata.
- **extension_update_file (#8)**: Modifica i parametri di una file extension esistente all'interno del sandbox.
- **extension_twiddle (#9)**: Regola o modifica una file extension esistente (ad esempio TextEdit, rtf, rtfd).
- **suspend (#10)**: Sospende temporaneamente tutti i controlli del sandbox (richiede gli entitlements appropriati).
- **unsuspend (#11)**: Riprende tutti i controlli del sandbox precedentemente sospesi.
- **passthrough_access (#12)**: Consente l'accesso diretto a una risorsa, bypassando i controlli del sandbox.
- **set_container_path (#13)**: (solo iOS) Imposta un container path per un app group o un signing ID.
- **container_map (#14)**: (solo iOS) Recupera un container path da `containermanagerd`.
- **sandbox_user_state_item_buffer_send (#15)**: (iOS 10+) Imposta i metadati in user mode nel sandbox.
- **inspect (#16)**: Fornisce informazioni di debug su un processo sandboxed.
- **dump (#18)**: (macOS 11) Esegue il dump del profilo corrente di un sandbox per l'analisi.
- **vtrace (#19)**: Traccia le operazioni del sandbox per il monitoraggio o il debugging.
- **builtin_profile_deactivate (#20)**: (macOS < 11) Disattiva i profili denominati (ad esempio `pe_i_can_has_debugger`).
- **check_bulk (#21)**: Esegue più operazioni `sandbox_check` in una singola chiamata.
- **reference_retain_by_audit_token (#28)**: Crea un riferimento a un audit token da usare nei controlli del sandbox.
- **reference_release (#29)**: Rilascia un riferimento a un audit token precedentemente mantenuto.
- **rootless_allows_task_for_pid (#30)**: Verifica se `task_for_pid` è consentito (in modo simile ai controlli `csr`).
- **rootless_whitelist_push (#31)**: (macOS) Applica un file manifest di System Integrity Protection (SIP).
- **rootless_whitelist_check (preflight) (#32)**: Controlla il file manifest di SIP prima dell'esecuzione.
- **rootless_protected_volume (#33)**: (macOS) Applica le protezioni SIP a un disco o a una partizione.
- **rootless_mkdir_protected (#34)**: Applica la protezione SIP/DataVault al processo di creazione di una directory.

## Sandbox.kext

Nota che in iOS l'estensione del kernel contiene **tutti i profili hardcoded** all'interno del segmento `__TEXT.__const` per impedirne la modifica. Di seguito sono riportate alcune funzioni interessanti dell'estensione del kernel:

- **`hook_policy_init`**: Effettua l'hook di `mpo_policy_init` e viene chiamata dopo `mac_policy_register`. Esegue la maggior parte delle inizializzazioni del Sandbox. Inizializza inoltre SIP.
- **`hook_policy_initbsd`**: Configura l'interfaccia sysctl registrando `security.mac.sandbox.sentinel`, `security.mac.sandbox.audio_active` e `security.mac.sandbox.debug_mode` (se avviato con `PE_i_can_has_debugger`).
- **`hook_policy_syscall`**: Viene chiamata da `mac_syscall` con `"Sandbox"` come primo argomento e con il codice che indica l'operazione come secondo argomento. Viene usato uno switch per trovare il codice da eseguire in base al codice richiesto.

### MACF Hooks

**`Sandbox.kext`** usa più di cento hook tramite MACF. La maggior parte degli hook controlla semplicemente alcuni casi banali che consentono di eseguire l'azione; in caso contrario, chiamerà **`cred_sb_evalutate`** con le **credentials** provenienti da MACF, un numero corrispondente all'**operazione** da eseguire e un **buffer** per l'output.<sup>[1]</sup>

Un buon esempio è la funzione **`_mpo_file_check_mmap`**, che effettua l'hook di **`mmap`** e inizia controllando se la nuova memoria sarà scrivibile (e, in caso contrario, consente l'esecuzione); quindi verifica se viene usata per la dyld shared cache e, in tal caso, consente l'esecuzione; infine chiama **`sb_evaluate_internal`** (o uno dei suoi wrapper) per eseguire ulteriori controlli di autorizzazione.

Inoltre, tra le centinaia di hook usati da Sandbox, ce ne sono 3 particolarmente interessanti:

- `mpo_proc_check_for`: Applica il profilo se necessario e se non è stato applicato in precedenza.
- `mpo_vnode_check_exec`: Viene chiamata quando un processo carica il binary associato; quindi viene eseguito un controllo del profilo e anche un controllo che impedisce le esecuzioni SUID/SGID.
- `mpo_cred_label_update_execve`: Viene chiamata quando viene assegnata la label. È la funzione più lunga, poiché viene chiamata quando il binary è stato caricato completamente ma non è ancora stato eseguito. Esegue azioni come la creazione dell'oggetto sandbox, il collegamento della struct del sandbox alle credentials kauth, la rimozione dell'accesso alle mach ports...

Nota che **`_cred_sb_evalutate`** è un wrapper di **`sb_evaluate_internal`** e che questa funzione riceve le credentials passate ed esegue la valutazione usando la funzione **`eval`**, che normalmente valuta il **platform profile**, applicato per default a tutti i processi, e quindi il **profilo specifico del processo**. Nota che il platform profile è uno dei componenti principali di **SIP** in macOS.

## Sandboxd

Sandbox dispone inoltre di un user daemon che espone il servizio XPC Mach `com.apple.sandboxd` e si collega alla special port 14 (`HOST_SEATBELT_PORT`), usata dall'estensione del kernel per comunicare con esso. Espone alcune funzioni usando MIG.

## References

- [1] [XNU — `security/mac_policy.h` (MACF hooks registrati da Sandbox kext)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `security/mac_base.c` (`__mac_syscall`, l'entry point dietro `__sandbox_ms`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_base.c)
- [3] [`sandbox_init(3)` man page](https://keith.github.io/xcode-man-pages/sandbox_init.3.html)
- [4] [Apple Developer — App Sandbox](https://developer.apple.com/documentation/security/app-sandbox)
- [5] [Apple Sandbox Guide v1.0](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/)
- [6] [Mac sandbox escape](https://lapcatsoftware.com/articles/sandbox-escape.html)
- [7] [Office365 MacOS Sandbox Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [8] [HITBGSEC 2016 SG - The Apple Sandbox: Deeper Into The Quagmire - Jonathan Levin](https://www.youtube.com/watch?v=mG715HcDgO8&t=3011s)

{{#include ../../../../banners/hacktricks-training.md}}
