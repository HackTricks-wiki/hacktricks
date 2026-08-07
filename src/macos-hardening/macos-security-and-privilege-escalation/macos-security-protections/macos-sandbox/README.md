# macOS Sandbox

{{#include ../../../../banners/hacktricks-training.md}}

## Grundlegende Informationen

Die macOS Sandbox (ursprünglich Seatbelt genannt) **beschränkt Anwendungen**, die innerhalb der Sandbox ausgeführt werden, auf die **zulässigen Aktionen, die im Sandbox-Profil angegeben sind**, mit dem die App ausgeführt wird. Dies trägt dazu bei, sicherzustellen, dass **die Anwendung nur auf erwartete Ressourcen zugreift**.

Jede App mit dem **entitlement** **`com.apple.security.app-sandbox`** wird innerhalb der Sandbox ausgeführt. **Apple-Binärdateien** werden normalerweise innerhalb einer Sandbox ausgeführt, und alle Anwendungen aus dem **App Store verfügen über dieses entitlement**. Daher werden mehrere Anwendungen innerhalb der Sandbox ausgeführt.<sup>[[4]](#references)</sup>

Um zu kontrollieren, was ein Prozess tun darf oder nicht, verfügt die **Sandbox über Hooks** für nahezu jede Operation, die ein Prozess versuchen könnte (einschließlich der meisten Syscalls), und verwendet dafür **MACF**. Je nach den **entitlements** der App kann die Sandbox den Prozess jedoch möglicherweise weniger restriktiv behandeln.

Einige wichtige Komponenten der Sandbox sind:

- Die **Kernel-Erweiterung** `/System/Library/Extensions/Sandbox.kext`
- Das **private Framework** `/System/Library/PrivateFrameworks/AppSandbox.framework`
- Ein im userland laufender **Daemon** `/usr/libexec/sandboxd`
- Die **Container** `~/Library/Containers`

### Container

Jede sandboxed Anwendung verfügt über ihren eigenen Container unter `~/Library/Containers/{CFBundleIdentifier}` :
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
In jedem Bundle-ID-Ordner findest du die **plist** und das **Data directory** der App mit einer Struktur, die den Home-Ordner nachbildet:
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
> Beachte, dass die App selbst dann **Berechtigungen** benötigt, um auf andere Ordner zuzugreifen, wenn die Symlinks vorhanden sind, um die Sandbox zu „verlassen“. Diese Berechtigungen befinden sich in der **`.plist`** unter `RedirectablePaths`.

Die **`SandboxProfileData`** enthält das kompilierte Sandbox-Profil als CFData, das in B64 maskiert ist.
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
> Alles, was von einer Sandboxed-Anwendung erstellt oder geändert wird, erhält das **Quarantäneattribut**. Dadurch wird eine Sandbox-Umgebung verhindert, indem Gatekeeper ausgelöst wird, wenn die Sandbox-Anwendung versucht, etwas mit **`open`** auszuführen.

## Sandbox-Profile

Die Sandbox-Profile sind Konfigurationsdateien, die angeben, was in dieser **Sandbox** **erlaubt/verboten** ist. Sie verwenden die **Sandbox Profile Language (SBPL)**, die die Programmiersprache [**Scheme**](<https://en.wikipedia.org/wiki/Scheme_(programming_language)>) nutzt.

Hier findest du ein Beispiel:
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
> Prüfe diese [**research**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/), um **weitere Aktionen zu überprüfen, die erlaubt oder verweigert werden könnten.**<sup>[[5]](#references)</sup>
>
> Beachte, dass in der kompilierten Version eines Profils die Namen der Operationen durch ihre Einträge in einem Array ersetzt werden, das der dylib und dem kext bekannt ist. Dadurch wird die kompilierte Version kürzer und schwieriger zu lesen.

Wichtige **system services** laufen ebenfalls innerhalb ihrer eigenen benutzerdefinierten **sandbox**, beispielsweise der `mdnsresponder`-Dienst. Du kannst diese benutzerdefinierten **sandbox profiles** in folgenden Verzeichnissen anzeigen:

- **`/usr/share/sandbox`**
- **`/System/Library/Sandbox/Profiles`**
- Weitere sandbox profiles können unter [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles) überprüft werden.
- In iOS befinden sich die platform profiles im sandbox `.kext`, innerhalb von `_platform_profile_data` in der Binärdatei.

**App Store**-Apps verwenden das **profile** **`/System/Library/Sandbox/Profiles/application.sb`**. In diesem Profil kannst du überprüfen, wie Entitlements wie **`com.apple.security.network.server`** einem Prozess die Nutzung des Netzwerks erlauben.

Anschließend verwenden einige **Apple daemon services** verschiedene profiles, die sich in `/System/Library/Sandbox/Profiles/*.sb` oder `/usr/share/sandbox/*.sb` befinden. Diese Sandboxes werden in der Hauptfunktion angewendet, die die API `sandbox_init_XXX` aufruft.<sup>[[3]](#references)</sup>

**SIP** ist ein Sandbox profile namens platform_profile in `/System/Library/Sandbox/rootless.conf`.

### Beispiele für Sandbox Profiles

Um eine Anwendung mit einem **bestimmten sandbox profile** zu starten, kannst du Folgendes verwenden:
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
> Beachte, dass die von **Apple verfasste** **Software**, die unter **Windows** läuft, keine zusätzlichen Sicherheitsvorkehrungen wie application sandboxing besitzt.

Beispiele für Bypasses:

- [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)<sup>[[6]](#references)</sup>
- [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (sie können Dateien außerhalb der Sandbox schreiben, deren Name mit `~$` beginnt).<sup>[[7]](#references)</sup>

### Sandbox-Tracing

#### Über ein Profil

Es ist möglich, alle Prüfungen zu verfolgen, die die Sandbox jedes Mal durchführt, wenn eine Aktion überprüft wird. Erstelle dazu einfach das folgende Profil:
```scheme:trace.sb
(version 1)
(trace /tmp/trace.out)
```
Und dann führe einfach etwas unter Verwendung dieses Profils aus:
```bash
sandbox-exec -f /tmp/trace.sb /bin/ls
```
In `/tmp/trace.out` können Sie jede durchgeführte Sandbox-Prüfung sehen, jeweils bei ihrem Aufruf (also viele Duplikate).

Es ist auch möglich, die Sandbox mit dem Parameter **`-t`** zu tracen: `sandbox-exec -t /path/trace.out -p "(version 1)" /bin/ls`

#### Via API

Die von `libsystem_sandbox.dylib` exportierte Funktion `sandbox_set_trace_path` ermöglicht die Angabe eines Trace-Dateinamens, in den Sandbox-Prüfungen geschrieben werden.\
Etwas Ähnliches ist auch durch den Aufruf von `sandbox_vtrace_enable()` möglich. Anschließend können die Fehlerprotokolle aus dem Buffer mit `sandbox_vtrace_report()` abgerufen werden.

### Sandbox-Inspektion

`libsandbox.dylib` exportiert eine Funktion namens sandbox_inspect_pid, die eine Liste des Sandbox-Status eines Prozesses (einschließlich Extensions) liefert. Diese Funktion kann jedoch nur von platform binaries verwendet werden.

### macOS- und iOS-Sandbox-Profile

macOS speichert System-Sandbox-Profile an zwei Orten: **/usr/share/sandbox/** und **/System/Library/Sandbox/Profiles**.

Wenn eine Drittanbieteranwendung das Entitlement _**com.apple.security.app-sandbox**_ besitzt, wendet das System das Profil **/System/Library/Sandbox/Profiles/application.sb** auf diesen Prozess an.

In iOS wird das Standardprofil **container** genannt, und es gibt keine SBPL-Textdarstellung davon. Im Speicher wird diese Sandbox für jede Berechtigung der Sandbox als binärer Allow/Deny-Baum dargestellt.

### Benutzerdefiniertes SBPL in App-Store-Apps

Unternehmen können ihre Apps möglicherweise **mit benutzerdefinierten Sandbox-Profilen** (anstatt mit dem Standardprofil) ausführen lassen. Dafür müssen sie das Entitlement **`com.apple.security.temporary-exception.sbpl`** verwenden, das von Apple autorisiert werden muss.

Die Definition dieses Entitlements kann in **`/System/Library/Sandbox/Profiles/application.sb:`** überprüft werden.
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
This wird den String nach diesem Entitlement als Sandbox-Profil **eval**uieren.

### Kompilieren und Dekompilieren eines Sandbox-Profils

Das Tool **`sandbox-exec`** verwendet die Funktionen `sandbox_compile_*` aus `libsandbox.dylib`. Die wichtigsten exportierten Funktionen sind: `sandbox_compile_file` (erwartet einen Dateipfad, Parameter `-f`), `sandbox_compile_string` (erwartet einen String, Parameter `-p`), `sandbox_compile_name` (erwartet den Namen eines Containers, Parameter `-n`), `sandbox_compile_entitlements` (erwartet eine Entitlements-plist).

Diese reverse-engineerte und [**Open-Source-Version des Tools sandbox-exec**](https://newosxbook.com/src.jl?tree=listings&file=/sandbox_exec.c) ermöglicht es, dass **`sandbox-exec`** das kompilierte Sandbox-Profil in eine Datei schreibt.

Um einen Prozess außerdem innerhalb eines Containers einzuschränken, kann er `sandbox_spawnattrs_set[container/profilename]` aufrufen und einen Container oder ein bereits vorhandenes Profil übergeben.

## Debugging und Umgehen der Sandbox

Unter macOS müssen sich **Prozesse selbst für die Sandbox entscheiden**, anders als unter iOS, wo Prozesse von Anfang an durch den Kernel sandboxed werden. Das bedeutet, dass ein Prozess unter macOS erst dann durch die Sandbox eingeschränkt wird, wenn er sich aktiv dafür entscheidet, sie zu betreten, obwohl Apps aus dem App Store immer sandboxed sind.

Prozesse werden automatisch aus dem Userland heraus sandboxed, wenn sie das Entitlement `com.apple.security.app-sandbox` besitzen. Eine ausführliche Erklärung dieses Prozesses findest du hier:


{{#ref}}
macos-sandbox-debug-and-bypass/
{{#endref}}

## **Sandbox-Erweiterungen**

Erweiterungen ermöglichen es, einem Objekt weitere Berechtigungen zu geben, und werden durch den Aufruf einer der folgenden Funktionen vergeben:

- `sandbox_issue_extension`
- `sandbox_extension_issue_file[_with_new_type]`
- `sandbox_extension_issue_mach`
- `sandbox_extension_issue_iokit_user_client_class`
- `sandbox_extension_issue_iokit_registry_rentry_class`
- `sandbox_extension_issue_generic`
- `sandbox_extension_issue_posix_ipc`

Die Erweiterungen werden im zweiten MACF-Label-Slot gespeichert, der über die Prozess-Credentials zugänglich ist. Das folgende **`sbtool`** kann auf diese Informationen zugreifen.

Beachte, dass Erweiterungen normalerweise von berechtigten Prozessen vergeben werden. Beispielsweise vergibt `tccd` das Extension-Token `com.apple.tcc.kTCCServicePhotos`, wenn ein Prozess versucht, auf die Fotos zuzugreifen, und dies in einer XPC-Nachricht erlaubt wurde. Anschließend muss der Prozess das Extension-Token verbrauchen, damit es ihm hinzugefügt wird.\
Beachte, dass die Extension-Tokens lange hexadezimale Werte sind, die die vergebenen Berechtigungen codieren. Sie enthalten jedoch nicht die erlaubte PID fest kodiert, was bedeutet, dass jeder Prozess mit Zugriff auf das Token dieses **von mehreren Prozessen verbraucht werden kann**.

Beachte außerdem, dass Erweiterungen eng mit Entitlements verbunden sind. Bestimmte Entitlements können daher automatisch bestimmte Erweiterungen vergeben.

### **PID-Berechtigungen prüfen**

[**Laut dieser Quelle**](https://www.youtube.com/watch?v=mG715HcDgO8&t=3011s) können die Funktionen **`sandbox_check`** (dies ist ein `__mac_syscall`) überprüfen, **ob eine Operation von der Sandbox erlaubt wird oder nicht**, und zwar für eine bestimmte PID, ein Audit-Token oder eine eindeutige ID.<sup>[[8]](#references)</sup>

Das [**Tool sbtool**](http://newosxbook.com/src.jl?tree=listings&file=sbtool.c) (hier [kompiliert verfügbar](https://newosxbook.com/articles/hitsb.html)) kann überprüfen, ob eine PID bestimmte Aktionen ausführen kann:
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explanation of the sandbox profile and extensions
sbtool <pid> all
```
### \[un]suspend

Es ist ebenfalls möglich, die Sandbox mithilfe der Funktionen `sandbox_suspend` und `sandbox_unsuspend` aus `libsystem_sandbox.dylib` zu suspendieren und die Suspendierung aufzuheben.

Beachte, dass beim Aufruf der Suspendierungsfunktion einige Entitlements überprüft werden, um den Aufrufer zur Nutzung zu autorisieren, darunter:

- com.apple.private.security.sandbox-manager
- com.apple.security.print
- com.apple.security.temporary-exception.audio-unit-host

## mac_syscall

Dieser Systemaufruf (#381) erwartet als erstes Argument einen String, der das auszuführende Modul angibt, und als zweites Argument einen Code, der die auszuführende Funktion angibt. Das dritte Argument hängt anschließend von der ausgeführten Funktion ab.<sup>[[2]](#references)</sup>

Die Funktion `___sandbox_ms` kapselt den Aufruf von `mac_syscall`, wobei sie im ersten Argument `"Sandbox"` angibt, genau wie `___sandbox_msp` ein Wrapper für `mac_set_proc` (#387) ist. Die folgenden von `___sandbox_ms` unterstützten Codes sind in dieser Tabelle aufgeführt:

- **set_profile (#0)**: Ein kompiliertes oder benanntes Profil auf einen Prozess anwenden.
- **platform_policy (#1)**: Plattformspezifische Policy-Prüfungen erzwingen (unterscheidet sich zwischen macOS und iOS).
- **check_sandbox (#2)**: Eine manuelle Prüfung einer bestimmten Sandbox-Operation durchführen.
- **note (#3)**: Eine Annotation zu einer Sandbox hinzufügen.
- **container (#4)**: Eine Annotation an eine Sandbox anhängen, typischerweise zum Debugging oder zur Identifikation.
- **extension_issue (#5)**: Eine neue Extension für einen Prozess erzeugen.
- **extension_consume (#6)**: Eine angegebene Extension verwenden.
- **extension_release (#7)**: Den an eine verwendete Extension gebundenen Speicher freigeben.
- **extension_update_file (#8)**: Parameter einer vorhandenen Datei-Extension innerhalb der Sandbox ändern.
- **extension_twiddle (#9)**: Eine vorhandene Datei-Extension anpassen oder ändern (z. B. TextEdit, rtf, rtfd).
- **suspend (#10)**: Alle Sandbox-Prüfungen vorübergehend suspendieren (erfordert entsprechende Entitlements).
- **unsuspend (#11)**: Alle zuvor suspendierten Sandbox-Prüfungen fortsetzen.
- **passthrough_access (#12)**: Direkten Passthrough-Zugriff auf eine Ressource erlauben und dabei Sandbox-Prüfungen umgehen.
- **set_container_path (#13)**: (nur iOS) Einen Container-Pfad für eine App-Gruppe oder eine Signing-ID festlegen.
- **container_map (#14)**: (nur iOS) Einen Container-Pfad von `containermanagerd` abrufen.
- **sandbox_user_state_item_buffer_send (#15)**: (iOS 10+) User-Mode-Metadaten in der Sandbox festlegen.
- **inspect (#16)**: Debug-Informationen über einen sandboxed Prozess bereitstellen.
- **dump (#18)**: (macOS 11) Das aktuelle Profil einer Sandbox zur Analyse ausgeben.
- **vtrace (#19)**: Sandbox-Operationen zur Überwachung oder zum Debugging nachverfolgen.
- **builtin_profile_deactivate (#20)**: (macOS < 11) Benannte Profile deaktivieren (z. B. `pe_i_can_has_debugger`).
- **check_bulk (#21)**: Mehrere `sandbox_check`-Operationen in einem einzigen Aufruf durchführen.
- **reference_retain_by_audit_token (#28)**: Eine Referenz für ein Audit-Token zur Verwendung in Sandbox-Prüfungen erstellen.
- **reference_release (#29)**: Eine zuvor beibehaltene Audit-Token-Referenz freigeben.
- **rootless_allows_task_for_pid (#30)**: Überprüfen, ob `task_for_pid` erlaubt ist (ähnlich wie `csr`-Prüfungen).
- **rootless_whitelist_push (#31)**: (macOS) Eine System Integrity Protection (SIP)-Manifestdatei anwenden.
- **rootless_whitelist_check (preflight) (#32)**: Die SIP-Manifestdatei vor der Ausführung überprüfen.
- **rootless_protected_volume (#33)**: (macOS) SIP-Schutz auf eine Festplatte oder Partition anwenden.
- **rootless_mkdir_protected (#34)**: SIP-/DataVault-Schutz auf die Erstellung eines Verzeichnisses anwenden.

## Sandbox.kext

Beachte, dass die Kernel Extension unter iOS **alle Profile hardcoded** im Segment `__TEXT.__const` enthält, um zu verhindern, dass sie geändert werden. Im Folgenden werden einige interessante Funktionen der Kernel Extension aufgeführt:

- **`hook_policy_init`**: Sie hookt `mpo_policy_init` und wird nach `mac_policy_register` aufgerufen. Sie führt den Großteil der Initialisierungen der Sandbox durch. Außerdem initialisiert sie SIP.
- **`hook_policy_initbsd`**: Sie richtet die sysctl-Schnittstelle ein und registriert `security.mac.sandbox.sentinel`, `security.mac.sandbox.audio_active` und `security.mac.sandbox.debug_mode` (wenn mit `PE_i_can_has_debugger` gebootet wurde).
- **`hook_policy_syscall`**: Sie wird von `mac_syscall` mit `"Sandbox"` als erstem Argument und einem Code, der die Operation im zweiten Argument angibt, aufgerufen. Mithilfe eines Switches wird anhand des angeforderten Codes der auszuführende Code gefunden.

### MACF Hooks

**`Sandbox.kext`** verwendet über hundert Hooks über MACF. Die meisten Hooks prüfen lediglich einige triviale Fälle, die die Aktion erlauben, falls sie zutreffen. Andernfalls rufen sie **`cred_sb_evalutate`** mit den **Credentials** von MACF, einer Nummer entsprechend der auszuführenden **Operation** und einem **Buffer** für die Ausgabe auf.<sup>[[1]](#references)</sup>

Ein gutes Beispiel dafür ist die Funktion **`_mpo_file_check_mmap`**, die `mmap` hookt. Sie prüft zunächst, ob der neue Speicher beschreibbar sein wird (und erlaubt die Ausführung, falls dies nicht der Fall ist). Anschließend prüft sie, ob er für den dyld Shared Cache verwendet wird, und erlaubt in diesem Fall die Ausführung. Schließlich ruft sie **`sb_evaluate_internal`** (oder einen ihrer Wrapper) auf, um weitere Allowance-Prüfungen durchzuführen.

Unter den Hunderten von Hooks, die Sandbox verwendet, sind außerdem insbesondere die folgenden 3 sehr interessant:

- `mpo_proc_check_for`: Wendet das Profil an, falls erforderlich und falls es zuvor noch nicht angewendet wurde.
- `mpo_vnode_check_exec`: Wird aufgerufen, wenn ein Prozess die zugehörige Binary lädt. Anschließend wird eine Profilprüfung durchgeführt sowie eine Prüfung, die SUID-/SGID-Ausführungen verbietet.
- `mpo_cred_label_update_execve`: Dies wird aufgerufen, wenn das Label zugewiesen wird. Dies ist der längste Hook, da er aufgerufen wird, wenn die Binary vollständig geladen, aber noch nicht ausgeführt wurde. Er führt Aktionen wie das Erstellen des Sandbox-Objekts, das Anhängen der Sandbox-Struktur an die kauth-Credentials und das Entfernen des Zugriffs auf Mach-Ports durch.

Beachte, dass **`_cred_sb_evalutate`** ein Wrapper über **`sb_evaluate_internal`** ist. Diese Funktion übernimmt die übergebenen Credentials und führt anschließend mithilfe der Funktion **`eval`** die Evaluation durch, die normalerweise zunächst das **platform profile** evaluiert, das standardmäßig auf alle Prozesse angewendet wird, und danach das **specific process profile**. Beachte, dass das platform profile eine der Hauptkomponenten von **SIP** in macOS ist.

## Sandboxd

Sandbox verfügt außerdem über einen User-Daemon, der den XPC-Mach-Service `com.apple.sandboxd` bereitstellt und den speziellen Port 14 (`HOST_SEATBELT_PORT`) bindet, über den die Kernel Extension mit ihm kommuniziert. Er stellt mithilfe von MIG einige Funktionen bereit.

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
