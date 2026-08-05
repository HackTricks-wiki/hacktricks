# macOS Sandbox

{{#include ../../../../banners/hacktricks-training.md}}

## Grundlegende Informationen

Die MacOS Sandbox (ursprünglich Seatbelt genannt) **beschränkt Anwendungen**, die innerhalb der Sandbox ausgeführt werden, auf die **zulässigen Aktionen, die im Sandbox-Profil festgelegt sind**, mit dem die Anwendung ausgeführt wird. Dies trägt dazu bei, sicherzustellen, dass **die Anwendung nur auf erwartete Ressourcen zugreift**.

Jede Anwendung mit dem **Entitlement** **`com.apple.security.app-sandbox`** wird innerhalb der Sandbox ausgeführt. **Apple-Binaries** werden normalerweise innerhalb einer Sandbox ausgeführt, und alle Anwendungen aus dem **App Store verfügen über dieses Entitlement**. Daher werden mehrere Anwendungen innerhalb der Sandbox ausgeführt.<sup>[[4]](#references)</sup>

Um zu kontrollieren, was ein Prozess tun darf oder nicht, verfügt die **Sandbox über Hooks** für nahezu jede Operation, die ein Prozess versuchen könnte (einschließlich der meisten Syscalls), wobei **MACF** verwendet wird. Je nach **Entitlements** der Anwendung kann die Sandbox den Prozess jedoch weniger restriktiv behandeln.

Einige wichtige Komponenten der Sandbox sind:

- Die **Kernel Extension** `/System/Library/Extensions/Sandbox.kext`
- Das **private Framework** `/System/Library/PrivateFrameworks/AppSandbox.framework`
- Ein im Userland ausgeführter **Daemon** `/usr/libexec/sandboxd`
- Die **Container** `~/Library/Containers`

### Container

Jede sandboxed Anwendung verfügt über einen eigenen Container in `~/Library/Containers/{CFBundleIdentifier}` :
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
In jedem Bundle-ID-Ordner findest du die **plist** und das **Data-Verzeichnis** der App mit einer Struktur, die den Home-Ordner nachahmt:
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
> Beachte, dass die App selbst dann, wenn die Symlinks vorhanden sind, um aus der Sandbox „auszubrechen“ und auf andere Ordner zuzugreifen, weiterhin **Berechtigungen** für den Zugriff darauf benötigt. Diese Berechtigungen befinden sich in der **`.plist`** unter `RedirectablePaths`.

Die **`SandboxProfileData`** sind das kompilierte Sandbox-Profil-CFData, das in B64 escaped wurde.
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
> Alles, was von einer Sandbox-Anwendung erstellt oder geändert wird, erhält das **Quarantäneattribut**. Dadurch wird verhindert, dass eine Sandbox-Umgebung durch Gatekeeper ausgelöst wird, wenn die Sandbox-Anwendung versucht, etwas mit **`open`** auszuführen.

## Sandbox-Profile

Die Sandbox-Profile sind Konfigurationsdateien, die angeben, was in dieser **Sandbox** **erlaubt/verboten** ist. Sie verwenden die **Sandbox Profile Language (SBPL)**, die die Programmiersprache [**Scheme**](<https://en.wikipedia.org/wiki/Scheme_(programming_language)>) nutzt.

Hier finden Sie ein Beispiel:
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
> Sieh dir diese [**Forschung**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) an, um weitere Aktionen zu prüfen, die erlaubt oder verweigert werden könnten.<sup>[[5]](#references)</sup>
>
> Beachte, dass in der kompilierten Version eines Profils die Namen der Operationen durch ihre Einträge in einem Array ersetzt werden, das der dylib und dem kext bekannt ist. Dadurch wird die kompilierte Version kürzer und schwieriger zu lesen.

Wichtige **system services** laufen ebenfalls innerhalb ihrer eigenen benutzerdefinierten **sandbox**, beispielsweise der `mdnsresponder`-Service. Diese benutzerdefinierten **sandbox profiles** findest du unter:

- **`/usr/share/sandbox`**
- **`/System/Library/Sandbox/Profiles`**
- Weitere sandbox profiles können unter [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles) überprüft werden.
- In iOS befinden sich die platform profile innerhalb des sandbox `.kext` im `_platform_profile_data` innerhalb des Binaries.

**App Store**-Apps verwenden das **profile** **`/System/Library/Sandbox/Profiles/application.sb`**. In diesem Profil kannst du prüfen, wie Entitlements wie **`com.apple.security.network.server`** einem Prozess die Nutzung des Netzwerks erlauben.

Anschließend verwenden einige **Apple daemon services** verschiedene Profile, die sich in `/System/Library/Sandbox/Profiles/*.sb` oder `/usr/share/sandbox/*.sb` befinden. Diese Sandboxes werden in der Hauptfunktion angewendet, die die API `sandbox_init_XXX` aufruft.<sup>[[3]](#references)</sup>

**SIP** ist ein Sandbox-Profil namens platform_profile in `/System/Library/Sandbox/rootless.conf`.

### Beispiele für Sandbox-Profile

Um eine Anwendung mit einem **bestimmten Sandbox-Profil** zu starten, kannst du Folgendes verwenden:
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
> Beachten Sie, dass die von **Apple verfasste** **Software**, die unter **Windows** läuft, keine zusätzlichen Sicherheitsvorkehrungen wie application sandboxing bietet.

Beispiele für Bypasses:

- [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)<sup>[[6]](#references)</sup>
- [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (sie können Dateien außerhalb der sandbox schreiben, deren Name mit `~$` beginnt).<sup>[[7]](#references)</sup>

### Sandbox-Tracing

#### Über ein Profil

Es ist möglich, alle Prüfungen zu verfolgen, die die sandbox jedes Mal durchführt, wenn eine Aktion geprüft wird. Erstellen Sie dazu einfach das folgende Profil:
```scheme:trace.sb
(version 1)
(trace /tmp/trace.out)
```
Und dann einfach etwas unter Verwendung dieses Profils ausführen:
```bash
sandbox-exec -f /tmp/trace.sb /bin/ls
```
In `/tmp/trace.out` können Sie jede durchgeführte Sandbox-Prüfung sehen, und zwar jedes Mal, wenn sie aufgerufen wurde (also mit vielen Duplikaten).

Es ist auch möglich, die Sandbox mit dem Parameter **`-t`** zu tracen: `sandbox-exec -t /path/trace.out -p "(version 1)" /bin/ls`

#### Via API

Die von `libsystem_sandbox.dylib` exportierte Funktion `sandbox_set_trace_path` ermöglicht die Angabe eines Trace-Dateinamens, in den Sandbox-Prüfungen geschrieben werden.\
Etwas Ähnliches ist auch möglich, indem `sandbox_vtrace_enable()` aufgerufen und anschließend der Fehler-Log aus dem Buffer mit `sandbox_vtrace_report()` abgerufen wird.

### Sandbox Inspection

`libsandbox.dylib` exportiert eine Funktion namens sandbox_inspect_pid, die eine Liste des Sandbox-Status eines Prozesses (einschließlich Extensions) liefert. Allerdings können nur Platform-Binaries diese Funktion verwenden.

### MacOS & iOS Sandbox Profiles

MacOS speichert System-Sandbox-Profile an zwei Orten: **/usr/share/sandbox/** und **/System/Library/Sandbox/Profiles**.

Wenn eine Third-Party-Anwendung das Entitlement _**com.apple.security.app-sandbox**_ besitzt, wendet das System das Profil **/System/Library/Sandbox/Profiles/application.sb** auf diesen Prozess an.

In iOS wird das Standardprofil **container** genannt, und es gibt keine SBPL-Textdarstellung davon. Im Speicher wird diese Sandbox für jede Berechtigung der Sandbox als binärer Allow/Deny-Baum dargestellt.

### Custom SBPL in App Store apps

Es wäre möglich, dass Unternehmen ihre Apps **mit Custom-Sandbox-Profilen** (anstatt mit dem Standardprofil) ausführen lassen. Dafür müssen sie das Entitlement **`com.apple.security.temporary-exception.sbpl`** verwenden, das von Apple autorisiert werden muss.

Die Definition dieses Entitlements kann in **`/System/Library/Sandbox/Profiles/application.sb:`** überprüft werden.
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
Dies wird den String nach diesem Entitlement als Sandbox-Profil **eval**-uieren.

### Kompilieren und Dekompilieren eines Sandbox-Profils

Das Tool **`sandbox-exec`** verwendet die Funktionen `sandbox_compile_*` aus `libsandbox.dylib`. Die wichtigsten exportierten Funktionen sind: `sandbox_compile_file` (erwartet einen Dateipfad, Parameter `-f`), `sandbox_compile_string` (erwartet einen String, Parameter `-p`), `sandbox_compile_name` (erwartet den Namen eines Containers, Parameter `-n`), `sandbox_compile_entitlements` (erwartet eine Entitlements-Plist).

Diese reverse-engineerte und [**Open-Source-Version des Tools sandbox-exec**](https://newosxbook.com/src.jl?tree=listings&file=/sandbox_exec.c) ermöglicht es, **`sandbox-exec`** die kompilierte Sandbox-Profildefinition in eine Datei schreiben zu lassen.

Um einen Prozess innerhalb eines Containers einzuschränken, kann er außerdem `sandbox_spawnattrs_set[container/profilename]` aufrufen und einen Container oder ein bereits vorhandenes Profil übergeben.

## Debugging und Umgehung der Sandbox

Unter macOS müssen Prozesse im Gegensatz zu iOS, wo sie von Anfang an durch den Kernel sandboxed werden, die Sandbox selbst aktivieren. Das bedeutet, dass ein Prozess unter macOS erst dann durch die Sandbox eingeschränkt wird, wenn er sich aktiv dafür entscheidet, sie zu betreten, obwohl Apps aus dem App Store immer sandboxed sind.

Prozesse werden aus dem Userland automatisch sandboxed, sobald sie über das Entitlement `com.apple.security.app-sandbox` verfügen. Eine ausführliche Erklärung dieses Prozesses findest du hier:


{{#ref}}
macos-sandbox-debug-and-bypass/
{{#endref}}

## **Sandbox Extensions**

Extensions ermöglichen es, einem Objekt weitere Berechtigungen zu erteilen, und werden durch den Aufruf einer der folgenden Funktionen vergeben:

- `sandbox_issue_extension`
- `sandbox_extension_issue_file[_with_new_type]`
- `sandbox_extension_issue_mach`
- `sandbox_extension_issue_iokit_user_client_class`
- `sandbox_extension_issue_iokit_registry_rentry_class`
- `sandbox_extension_issue_generic`
- `sandbox_extension_issue_posix_ipc`

Die Extensions werden im zweiten MACF-Label-Slot gespeichert, der über die Prozess-Credentials zugänglich ist. Das folgende **`sbtool`** kann auf diese Informationen zugreifen.

Beachte, dass Extensions normalerweise von erlaubten Prozessen vergeben werden. Beispielsweise vergibt `tccd` das Extension-Token von `com.apple.tcc.kTCCServicePhotos`, wenn ein Prozess versucht, auf die Fotos zuzugreifen, und dies in einer XPC-Nachricht erlaubt wurde. Anschließend muss der Prozess das Extension-Token konsumieren, damit es ihm hinzugefügt wird.\
Beachte, dass die Extension-Tokens aus langen Hexadezimalwerten bestehen, die die erteilten Berechtigungen codieren. Sie enthalten jedoch nicht die erlaubte PID fest codiert, was bedeutet, dass jeder Prozess mit Zugriff auf das Token von **mehreren Prozessen konsumiert** werden kann.

Beachte außerdem, dass Extensions eng mit Entitlements verbunden sind. Bestimmte Entitlements können daher bestimmte Extensions automatisch gewähren.

### **Berechtigungen einer PID prüfen**

[**Laut dieser Quelle**](https://www.youtube.com/watch?v=mG715HcDgO8&t=3011s) können die Funktionen **`sandbox_check`** (ein `__mac_syscall`) prüfen, **ob eine Operation** von der Sandbox für eine bestimmte PID, ein Audit-Token oder eine eindeutige ID erlaubt ist.<sup>[[8]](#references)</sup>

Das [**Tool sbtool**](http://newosxbook.com/src.jl?tree=listings&file=sbtool.c) (hier [kompiliert verfügbar](https://newosxbook.com/articles/hitsb.html)) kann prüfen, ob eine PID bestimmte Aktionen ausführen kann:
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explanation of the sandbox profile and extensions
sbtool <pid> all
```
### \[un]suspend

Es ist ebenfalls möglich, die Sandbox mithilfe der Funktionen `sandbox_suspend` und `sandbox_unsuspend` aus `libsystem_sandbox.dylib` zu suspendieren und die Suspendierung aufzuheben.

Beachte, dass zum Aufrufen der Suspend-Funktion einige Entitlements geprüft werden, um den Aufrufer zur Verwendung der Funktion zu autorisieren, darunter:

- com.apple.private.security.sandbox-manager
- com.apple.security.print
- com.apple.security.temporary-exception.audio-unit-host

## mac_syscall

Dieser Systemaufruf (#381) erwartet als erstes Argument einen String, der das auszuführende Modul angibt, und anschließend als zweites Argument einen Code, der die auszuführende Funktion angibt. Das dritte Argument hängt dann von der ausgeführten Funktion ab.<sup>[[2]](#references)</sup>

Die Funktion `___sandbox_ms` umschließt den Aufruf von `mac_syscall`, wobei sie im ersten Argument `"Sandbox"` angibt, so wie `___sandbox_msp` ein Wrapper für `mac_set_proc` (#387) ist. Einige der von `___sandbox_ms` unterstützten Codes sind in dieser Tabelle aufgeführt:

- **set_profile (#0)**: Wendet ein kompiliertes oder benanntes Profil auf einen Prozess an.
- **platform_policy (#1)**: Erzwingt plattformspezifische Policy-Prüfungen (unterscheidet sich zwischen macOS und iOS).
- **check_sandbox (#2)**: Führt eine manuelle Prüfung einer bestimmten Sandbox-Operation durch.
- **note (#3)**: Fügt einer Sandbox eine Annotation hinzu.
- **container (#4)**: Hängt eine Annotation an eine Sandbox an, typischerweise zu Debugging- oder Identifikationszwecken.
- **extension_issue (#5)**: Generiert eine neue Extension für einen Prozess.
- **extension_consume (#6)**: Verwendet eine angegebene Extension.
- **extension_release (#7)**: Gibt den Speicher frei, der an eine verwendete Extension gebunden ist.
- **extension_update_file (#8)**: Ändert Parameter einer bestehenden File-Extension innerhalb der Sandbox.
- **extension_twiddle (#9)**: Passt eine bestehende File-Extension an oder ändert sie (z. B. TextEdit, rtf, rtfd).
- **suspend (#10)**: Suspendiert vorübergehend alle Sandbox-Prüfungen (erfordert entsprechende Entitlements).
- **unsuspend (#11)**: Setzt alle zuvor suspendierten Sandbox-Prüfungen fort.
- **passthrough_access (#12)**: Erlaubt direkten Passthrough-Zugriff auf eine Ressource und umgeht dabei Sandbox-Prüfungen.
- **set_container_path (#13)**: (Nur iOS) Setzt einen Container-Pfad für eine App-Gruppe oder eine Signing-ID.
- **container_map (#14)**: (Nur iOS) Ruft einen Container-Pfad von `containermanagerd` ab.
- **sandbox_user_state_item_buffer_send (#15)**: (iOS 10+) Setzt User-Mode-Metadaten in der Sandbox.
- **inspect (#16)**: Stellt Debug-Informationen über einen sandboxed Prozess bereit.
- **dump (#18)**: (macOS 11) Gibt das aktuelle Profil einer Sandbox zur Analyse aus.
- **vtrace (#19)**: Zeichnet Sandbox-Operationen zu Monitoring- oder Debugging-Zwecken auf.
- **builtin_profile_deactivate (#20)**: (macOS < 11) Deaktiviert benannte Profile (z. B. `pe_i_can_has_debugger`).
- **check_bulk (#21)**: Führt mehrere `sandbox_check`-Operationen in einem einzigen Aufruf durch.
- **reference_retain_by_audit_token (#28)**: Erstellt eine Referenz auf ein Audit-Token zur Verwendung bei Sandbox-Prüfungen.
- **reference_release (#29)**: Gibt eine zuvor beibehaltene Audit-Token-Referenz frei.
- **rootless_allows_task_for_pid (#30)**: Prüft, ob `task_for_pid` zulässig ist (ähnlich wie `csr`-Prüfungen).
- **rootless_whitelist_push (#31)**: (macOS) Wendet eine System-Integrity-Protection-(SIP)-Manifestdatei an.
- **rootless_whitelist_check (preflight) (#32)**: Prüft die SIP-Manifestdatei vor der Ausführung.
- **rootless_protected_volume (#33)**: (macOS) Wendet SIP-Schutz auf einen Datenträger oder eine Partition an.
- **rootless_mkdir_protected (#34)**: Wendet SIP-/DataVault-Schutz auf einen Verzeichniserstellungsprozess an.

## Sandbox.kext

Beachte, dass die Kernel-Extension unter iOS **alle Profile hardcoded** im Segment `__TEXT.__const` enthält, um zu verhindern, dass sie verändert werden. Im Folgenden sind einige interessante Funktionen der Kernel-Extension aufgeführt:

- **`hook_policy_init`**: Hookt `mpo_policy_init` und wird nach `mac_policy_register` aufgerufen. Die Funktion führt den Großteil der Initialisierung der Sandbox durch. Außerdem initialisiert sie SIP.
- **`hook_policy_initbsd`**: Richtet das sysctl-Interface ein und registriert `security.mac.sandbox.sentinel`, `security.mac.sandbox.audio_active` und `security.mac.sandbox.debug_mode` (wenn mit `PE_i_can_has_debugger` gebootet wurde).
- **`hook_policy_syscall`**: Wird von `mac_syscall` mit `"Sandbox"` als erstem Argument und einem Code, der die Operation im zweiten Argument angibt, aufgerufen. Mithilfe eines switch wird der auszuführende Code anhand des angeforderten Codes ermittelt.

### MACF Hooks

**`Sandbox.kext`** verwendet über hundert Hooks über MACF. Die meisten Hooks prüfen lediglich einige triviale Fälle, die die Ausführung der Aktion erlauben. Andernfalls rufen sie **`cred_sb_evalutate`** mit den Credentials von MACF, einer Nummer, die der auszuführenden **Operation** entspricht, und einem **Buffer** für die Ausgabe auf.<sup>[[1]](#references)</sup>

Ein gutes Beispiel dafür ist die Funktion **`_mpo_file_check_mmap`**, die `mmap` hookt. Sie beginnt mit der Prüfung, ob der neue Speicher beschreibbar sein wird (und erlaubt die Ausführung, falls dies nicht der Fall ist). Anschließend prüft sie, ob der Speicher für den dyld Shared Cache verwendet wird, und erlaubt in diesem Fall die Ausführung. Schließlich ruft sie **`sb_evaluate_internal`** (oder einen ihrer Wrapper) auf, um weitere Berechtigungsprüfungen durchzuführen.

Unter den Hunderten von Hooks, die Sandbox verwendet, sind insbesondere die folgenden 3 sehr interessant:

- `mpo_proc_check_for`: Wendet das Profil bei Bedarf an, sofern es nicht bereits zuvor angewendet wurde.
- `mpo_vnode_check_exec`: Wird aufgerufen, wenn ein Prozess das zugehörige Binary lädt. Anschließend wird eine Profilprüfung durchgeführt sowie eine Prüfung, die SUID-/SGID-Ausführungen verbietet.
- `mpo_cred_label_update_execve`: Wird aufgerufen, wenn das Label zugewiesen wird. Dies ist die längste Funktion, da sie aufgerufen wird, wenn das Binary vollständig geladen, aber noch nicht ausgeführt wurde. Sie führt unter anderem Aktionen wie das Erstellen des Sandbox-Objekts, das Anhängen der Sandbox-Struktur an die kauth-Credentials und das Entfernen des Zugriffs auf Mach-Ports durch.

Beachte, dass **`_cred_sb_evalutate`** ein Wrapper über **`sb_evaluate_internal`** ist. Diese Funktion übernimmt die übergebenen Credentials und führt anschließend die Auswertung mithilfe der Funktion **`eval`** durch, die normalerweise zuerst das **Platform Profile** auswertet, das standardmäßig auf alle Prozesse angewendet wird, und danach das **spezifische Prozessprofil**. Beachte, dass das Platform Profile eine der Hauptkomponenten von **SIP** in macOS ist.

## Sandboxd

Sandbox verfügt außerdem über einen User-Daemon, der den XPC-Mach-Service `com.apple.sandboxd` bereitstellt und den speziellen Port 14 (`HOST_SEATBELT_PORT`) bindet, über den die Kernel-Extension mit ihm kommuniziert. Über MIG stellt er einige Funktionen bereit.

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
