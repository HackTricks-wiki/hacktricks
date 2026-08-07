# macOS-Sicherheitsmaßnahmen

{{#include ../../../banners/hacktricks-training.md}}

## Gatekeeper

Gatekeeper bezeichnet üblicherweise die Kombination aus **Quarantine + Gatekeeper + XProtect**, drei macOS-Sicherheitsmodulen, die versuchen, **Benutzer daran zu hindern, potenziell schädliche heruntergeladene Software auszuführen**.

Weitere Informationen unter:


{{#ref}}
macos-gatekeeper.md
{{#endref}}

## Prozessbeschränkungen

### MACF

### SIP - System Integrity Protection


{{#ref}}
macos-sip.md
{{#endref}}

### Sandbox

Die MacOS Sandbox **beschränkt Anwendungen**, die innerhalb der Sandbox ausgeführt werden, auf die **zulässigen Aktionen, die im Sandbox-Profil angegeben sind**, mit dem die App ausgeführt wird. Dies trägt dazu bei sicherzustellen, dass **die Anwendung nur auf erwartete Ressourcen zugreift**.


{{#ref}}
macos-sandbox/
{{#endref}}

### TCC - **Transparency, Consent, and Control**

**TCC (Transparency, Consent, and Control)** ist ein Sicherheits-Framework. Es wurde entwickelt, um **die Berechtigungen** von Anwendungen zu **verwalten**, insbesondere indem der Zugriff auf sensible Funktionen geregelt wird. Dazu gehören **Ortungsdienste, Kontakte, Fotos, Mikrofon, Kamera, Bedienungshilfen und vollständiger Festplattenzugriff**. TCC stellt sicher, dass Apps nur nach ausdrücklicher Zustimmung des Benutzers auf diese Funktionen zugreifen können, und stärkt dadurch den Datenschutz und die Kontrolle über persönliche Daten.


{{#ref}}
macos-tcc/
{{#endref}}

### Launch/Environment Constraints & Trust Cache

Launch Constraints sind in macOS eine Sicherheitsfunktion zur **Regulierung des Prozessstarts**, indem definiert wird, **wer** einen Prozess **wie** und **von wo aus starten** darf. Sie wurden in macOS Ventura eingeführt und kategorisieren System-Binaries innerhalb eines **Trust Cache** in Constraint-Kategorien. Jede ausführbare Binärdatei verfügt über festgelegte **Regeln** für ihren **Start**, einschließlich **Self-**, **Parent-** und **Responsible-Constraints**. Diese in macOS Sonoma als **Environment Constraints** auf Drittanbieter-Apps erweiterten Funktionen helfen dabei, potenzielle System-Exploitation zu vermindern, indem sie die Bedingungen für den Prozessstart kontrollieren.


{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

## MRT - Malware Removal Tool

Das Malware Removal Tool (MRT) ist ein weiterer Bestandteil der macOS-Sicherheitsinfrastruktur. Wie der Name nahelegt, besteht die Hauptfunktion von MRT darin, **bekannte Malware von infizierten Systemen zu entfernen**.

Sobald Malware auf einem Mac erkannt wird (entweder durch XProtect oder auf andere Weise), kann MRT verwendet werden, um **die Malware automatisch zu entfernen**. MRT arbeitet unbemerkt im Hintergrund und wird normalerweise ausgeführt, sobald das System aktualisiert oder eine neue Malware-Definition heruntergeladen wird (es sieht so aus, als befänden sich die Regeln, anhand derer MRT Malware erkennt, innerhalb des Binaries).

Obwohl sowohl XProtect als auch MRT Teil der macOS-Sicherheitsmaßnahmen sind, erfüllen sie unterschiedliche Funktionen:

- **XProtect** ist ein präventives Tool. Es **überprüft Dateien, sobald sie heruntergeladen werden** (über bestimmte Anwendungen), und verhindert, wenn es bekannte Malware-Typen erkennt, **das Öffnen der Datei**. Dadurch wird verhindert, dass die Malware das System überhaupt erst infiziert.
- **MRT** hingegen ist ein **reaktives Tool**. Es wird ausgeführt, nachdem Malware auf einem System erkannt wurde, mit dem Ziel, die schädliche Software zu entfernen und das System zu bereinigen.

Die MRT-Anwendung befindet sich in **`/Library/Apple/System/Library/CoreServices/MRT.app`**

## Verwaltung von Hintergrundaufgaben

**macOS** **warnt** jetzt jedes Mal, wenn ein Tool eine bekannte **Technik zur Persistenz von Codeausführung** verwendet (z. B. Login Items, Daemons ...), damit der Benutzer besser weiß, **welche Software persistiert**.<sup>[[3]](#references)</sup>

<figure><img src="../../../images/image (1183).png" alt=""><figcaption></figcaption></figure>

Dies wird mit einem **Daemon** ausgeführt, der sich unter `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` befindet, sowie mit dem **Agent** unter `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`<sup>[[1]](#references)</sup>

Die **`backgroundtaskmanagementd`** erkennt, dass etwas in einem persistenten Ordner installiert wurde, indem es die **FSEvents** abruft und dafür einige **Handler** erstellt.<sup>[[1]](#references)</sup>

Darüber hinaus gibt es eine plist-Datei mit **bekannten Anwendungen**, die häufig persistieren und von Apple gepflegt wird. Sie befindet sich unter: `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`<sup>[[3]](#references)</sup>
```json
[...]
"us.zoom.ZoomDaemon" => {
"AssociatedBundleIdentifiers" => [
0 => "us.zoom.xos"
]
"Attribution" => "Zoom"
"Program" => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
"ProgramArguments" => [
0 => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
]
"TeamIdentifier" => "BJ4HAAB9B3"
}
[...]
```
### Enumeration

Es ist möglich, **alle** konfigurierten Hintergrundelemente mit dem Apple-CLI-Tool aufzulisten:<sup>[[3]](#references)</sup>
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
Darüber hinaus ist es auch möglich, diese Informationen mit [**DumpBTM**](https://github.com/objective-see/DumpBTM) aufzulisten.<sup>[[2]](#references)</sup>
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
Diese Information wird in **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`** gespeichert, und das Terminal benötigt FDA.<sup>[[2]](#references)</sup>

### Mit BTM herumspielen

Wenn eine neue persistence gefunden wird, wird ein Ereignis vom Typ **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`** ausgelöst. Daher hilft jede Möglichkeit, zu **verhindern**, dass dieses **Ereignis** gesendet wird, oder den **Agenten daran zu hindern, den Benutzer zu alarmieren**, einem Angreifer dabei, BTM zu _**umgehen**_.<sup>[[1]](#references)</sup>

- **Zurücksetzen der Datenbank**: Mit dem folgenden Befehl wird die Datenbank zurückgesetzt (sie sollte von Grund auf neu erstellt werden). Aus irgendeinem Grund werden jedoch nach dessen Ausführung **keine neuen persistence-Vorgänge gemeldet, bis das System neu gestartet wird**.<sup>[[1]](#references)</sup>
- **root** ist erforderlich.
```bash
# Reset the database
sfltool resettbtm
```
- **Agent stoppen**: Es ist möglich, ein Stoppsignal an den Agent zu senden, sodass er den **Benutzer nicht benachrichtigt**, wenn neue Erkennungen gefunden werden.<sup>[[1]](#references)</sup>
```bash
# Get PID
pgrep BackgroundTaskManagementAgent
1011

# Stop it
kill -SIGSTOP 1011

# Check it's stopped (a T means it's stopped)
ps -o state 1011
T
```
- **Bug**: Wenn der **Prozess, der die Persistence erstellt hat, direkt danach beendet wird**, versucht der Daemon, **Informationen** über ihn abzurufen, **scheitert** und kann das **Event** nicht senden, das anzeigt, dass etwas Neues persistent wird.<sup>[[1]](#references)</sup>

## Referenzen

- [1] [OBTS v6.0: „Demystifying (& Bypassing) macOS's Background Task Management“ – Patrick Wardle & Chris Lopez](https://youtu.be/9hjUmT031tc?t=26481)
- [2] [Neues (Developer-)Tool: „DumpBTM“ – Patrick Wardle (Patreon)](https://www.patreon.com/posts/new-developer-77420730?l=fr)
- [3] [Login-Items und Hintergrundaufgaben auf dem Mac verwalten – Apple Platform Deployment](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

{{#include ../../../banners/hacktricks-training.md}}
