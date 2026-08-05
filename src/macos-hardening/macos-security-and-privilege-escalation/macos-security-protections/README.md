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

Die macOS Sandbox **beschränkt Anwendungen**, die innerhalb der Sandbox ausgeführt werden, auf die **zulässigen Aktionen, die im Sandbox-Profil** der jeweiligen App festgelegt sind. Dies trägt dazu bei sicherzustellen, **dass die Anwendung nur auf erwartete Ressourcen zugreift**.


{{#ref}}
macos-sandbox/
{{#endref}}

### TCC - **Transparency, Consent, and Control**

**TCC (Transparency, Consent, and Control)** ist ein Sicherheits-Framework. Es wurde entwickelt, um **die Berechtigungen** von Anwendungen zu **verwalten**, insbesondere indem der Zugriff auf sensible Funktionen geregelt wird. Dazu gehören unter anderem **Ortungsdienste, Kontakte, Fotos, Mikrofon, Kamera, Bedienungshilfen und vollständiger Festplattenzugriff**. TCC stellt sicher, dass Apps erst nach ausdrücklicher Zustimmung des Benutzers auf diese Funktionen zugreifen können, wodurch der Datenschutz und die Kontrolle über persönliche Daten verbessert werden.


{{#ref}}
macos-tcc/
{{#endref}}

### Launch/Environment Constraints & Trust Cache

Launch Constraints sind in macOS eine Sicherheitsfunktion zur **Regulierung der Prozessinitialisierung**, indem festgelegt wird, **wer** einen Prozess **wie** und **von wo aus starten** darf. Sie wurden in macOS Ventura eingeführt und kategorisieren System-Binaries innerhalb eines **Trust Cache** in Constraint-Kategorien. Jede ausführbare Binärdatei verfügt über festgelegte **Regeln** für ihren **Start**, einschließlich **Self-, Parent- und Responsible-Constraints**. Diese in macOS Sonoma als **Environment Constraints** auf Drittanbieter-Apps ausgeweiteten Funktionen tragen dazu bei, potenzielle System-Exploitation zu begrenzen, indem die Bedingungen für den Prozessstart geregelt werden.


{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

## MRT - Malware Removal Tool

Das Malware Removal Tool (MRT) ist ein weiterer Bestandteil der macOS-Sicherheitsinfrastruktur. Wie der Name bereits andeutet, besteht die Hauptfunktion von MRT darin, **bekannte Malware von infizierten Systemen zu entfernen**.

Sobald Malware auf einem Mac erkannt wird (entweder durch XProtect oder auf andere Weise), kann MRT verwendet werden, um **die Malware automatisch zu entfernen**. MRT arbeitet unauffällig im Hintergrund und wird normalerweise ausgeführt, wenn das System aktualisiert oder eine neue Malware-Definition heruntergeladen wird (es scheint, dass sich die Regeln, anhand derer MRT Malware erkennt, innerhalb der Binärdatei befinden).

Obwohl XProtect und MRT beide Bestandteil der macOS-Sicherheitsmaßnahmen sind, erfüllen sie unterschiedliche Funktionen:

- **XProtect** ist ein präventives Tool. Es **überprüft Dateien, sobald sie heruntergeladen werden** (über bestimmte Anwendungen), und verhindert, wenn es bekannte Malware-Typen erkennt, **das Öffnen der Datei**. Dadurch wird verhindert, dass die Malware das System überhaupt erst infiziert.
- **MRT** hingegen ist ein **reaktives Tool**. Es wird ausgeführt, nachdem Malware auf einem System erkannt wurde, mit dem Ziel, die schädliche Software zu entfernen und das System zu bereinigen.

Die MRT-Anwendung befindet sich unter **`/Library/Apple/System/Library/CoreServices/MRT.app`**

## Verwaltung von Hintergrundaufgaben

**macOS** **warnt** jetzt jedes Mal, wenn ein Tool eine bekannte **Technik zur Persistenz der Codeausführung** verwendet (z. B. Login Items, Daemons ...), damit der Benutzer besser weiß, **welche Software persistent bleibt**.<sup>[3]</sup>

<figure><img src="../../../images/image (1183).png" alt=""><figcaption></figcaption></figure>

Dies wird von einem **Daemon** unter `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` und dem **Agenten** unter `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app` ausgeführt.<sup>[1]</sup>

**`backgroundtaskmanagementd`** erkennt, dass etwas in einem persistenten Ordner installiert wurde, indem es die **FSEvents** abruft und dafür einige **Handler** erstellt.<sup>[1]</sup>

Darüber hinaus gibt es eine plist-Datei mit **bekannten Anwendungen**, die häufig Persistenz einrichten und von Apple gepflegt wird. Sie befindet sich unter: `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`<sup>[3]</sup>
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

Es ist möglich, **alle** konfigurierten Hintergrundelemente zu **enumerieren**, indem das Apple-CLI-Tool ausgeführt wird:<sup>[3]</sup>
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
Außerdem ist es auch möglich, diese Informationen mit [**DumpBTM**](https://github.com/objective-see/DumpBTM) aufzulisten.<sup>[2]</sup>
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
Diese Informationen werden in **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`** gespeichert, und das Terminal benötigt FDA.<sup>[2]</sup>

### Manipulation von BTM

Wenn eine neue Persistenz gefunden wird, wird ein Ereignis vom Typ **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`** ausgelöst. Daher hilft jede Möglichkeit, zu **verhindern**, dass dieses **Ereignis** gesendet wird, oder den **Agent daran zu hindern, den Benutzer zu benachrichtigen**, einem Angreifer dabei, BTM zu _**umgehen**_.<sup>[1]</sup>

- **Zurücksetzen der Datenbank**: Durch Ausführen des folgenden Befehls wird die Datenbank zurückgesetzt (sie sollte von Grund auf neu erstellt werden). Aus irgendeinem Grund werden jedoch nach der Ausführung dieses Befehls **keine neuen Persistenzen gemeldet, bis das System neu gestartet wird**.<sup>[1]</sup>
- **root** ist erforderlich.
```bash
# Reset the database
sfltool resettbtm
```
- **Agent stoppen**: Es ist möglich, ein Stoppsignal an den Agenten zu senden, sodass er den Benutzer **nicht benachrichtigt**, wenn neue Erkennungen gefunden werden.<sup>[1]</sup>
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
- **Bug**: If the **process that created the persistence exits right after it**, the daemon will try to **get information** about it, **fail**, and **won't be able to send the event** indicating that a new thing is persisting.<sup>[1]</sup>

## References

- [1] [OBTS v6.0: "Demystifying (& Bypassing) macOS's Background Task Management" - Patrick Wardle & Chris Lopez](https://youtu.be/9hjUmT031tc?t=26481)
- [2] [New (Developer) Tool: "DumpBTM" - Patrick Wardle (Patreon)](https://www.patreon.com/posts/new-developer-77420730?l=fr)
- [3] [Manage login items and background tasks on Mac - Apple Platform Deployment](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

{{#include ../../../banners/hacktricks-training.md}}
