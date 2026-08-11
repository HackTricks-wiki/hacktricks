# macOS-Sicherheitsmaßnahmen

{{#include ../../../banners/hacktricks-training.md}}

## Gatekeeper

Gatekeeper wird normalerweise als Bezeichnung für die Kombination aus **Quarantine + Gatekeeper + XProtect** verwendet, drei macOS-Sicherheitsmodulen, die versuchen, **Benutzer daran zu hindern, potenziell schädliche heruntergeladene Software auszuführen**.

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

Die macOS Sandbox **beschränkt Anwendungen**, die innerhalb der Sandbox ausgeführt werden, auf die **zulässigen Aktionen, die im Sandbox-Profil** angegeben sind, mit dem die App ausgeführt wird. Dies trägt dazu bei sicherzustellen, dass **die Anwendung nur auf erwartete Ressourcen zugreift**.


{{#ref}}
macos-sandbox/
{{#endref}}

### TCC - **Transparency, Consent, and Control**

**TCC (Transparency, Consent, and Control)** ist ein Sicherheits-Framework. Es wurde entwickelt, um **die Berechtigungen** von Anwendungen zu **verwalten**, insbesondere indem der Zugriff auf sensible Funktionen geregelt wird. Dazu gehören **Standortdienste, Kontakte, Fotos, Mikrofon, Kamera, Bedienungshilfen und vollständiger Festplattenzugriff**. TCC stellt sicher, dass Apps nur nach ausdrücklicher Zustimmung des Benutzers auf diese Funktionen zugreifen können, wodurch der Datenschutz und die Kontrolle über persönliche Daten verbessert werden.


{{#ref}}
macos-tcc/
{{#endref}}

### Launch/Environment Constraints & Trust Cache

Launch constraints sind in macOS eine Sicherheitsfunktion zur **Regulierung des Prozessstarts**, indem festgelegt wird, **wer** einen Prozess **wie** und **von wo aus starten** darf. Sie wurden in macOS Ventura eingeführt und kategorisieren System-Binaries innerhalb eines **trust cache** in Constraint-Kategorien. Jede ausführbare Binärdatei verfügt über festgelegte **Regeln** für ihren **Start**, einschließlich **self-, parent- und responsible-Constraints**. In macOS Sonoma wurden diese Funktionen als **Environment Constraints** auf Drittanbieter-Apps ausgeweitet. Sie helfen dabei, potenzielle Systemausnutzungen zu verhindern, indem sie die Bedingungen für den Prozessstart steuern.


{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

## MRT - Malware Removal Tool

Das Malware Removal Tool (MRT) ist ein weiterer Bestandteil der macOS-Sicherheitsinfrastruktur. Wie der Name bereits andeutet, besteht die Hauptfunktion von MRT darin, **bekannte Malware von infizierten Systemen zu entfernen**.

Sobald Malware auf einem Mac erkannt wird (entweder durch XProtect oder auf andere Weise), kann MRT verwendet werden, um die **Malware automatisch zu entfernen**. MRT arbeitet unauffällig im Hintergrund und wird normalerweise ausgeführt, sobald das System aktualisiert oder eine neue Malware-Definition heruntergeladen wird (es sieht so aus, als befänden sich die Regeln, anhand derer MRT Malware erkennt, innerhalb der Binärdatei).

Obwohl sowohl XProtect als auch MRT Teil der macOS-Sicherheitsmaßnahmen sind, erfüllen sie unterschiedliche Funktionen:

- **XProtect** ist ein präventives Tool. Es **überprüft Dateien, während sie heruntergeladen werden** (über bestimmte Anwendungen), und wenn es bekannte Malware-Typen erkennt, **verhindert es das Öffnen der Datei**. Dadurch wird verhindert, dass die Malware das System überhaupt erst infiziert.
- **MRT** hingegen ist ein **reaktives Tool**. Es arbeitet, nachdem Malware auf einem System erkannt wurde, mit dem Ziel, die schädliche Software zu entfernen und das System zu bereinigen.

Die MRT-Anwendung befindet sich unter **`/Library/Apple/System/Library/CoreServices/MRT.app`**

## Verwaltung von Hintergrundaufgaben

**macOS** **warnt** jetzt jedes Mal, wenn ein Tool eine bekannte **Technik zur dauerhaften Ausführung von Code** verwendet (z. B. Login Items, Daemons ...), damit der Benutzer besser weiß, **welche Software persistent bleibt**.<sup>[[3]](#references)</sup>

<figure><img src="../../../images/image (1183).png" alt=""><figcaption></figcaption></figure>

Dies wird mit einem **Daemon** ausgeführt, der sich unter `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` befindet, sowie mit dem **Agent** unter `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`<sup>[[1]](#references)</sup>

**`backgroundtaskmanagementd`** erkennt, dass etwas in einem persistenten Ordner installiert wurde, indem es die **FSEvents** abruft und dafür einige **Handler** erstellt.<sup>[[1]](#references)</sup>

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

Es ist möglich, alle konfigurierten Hintergrundelemente mit dem Apple cli tool aufzulisten:<sup>[[3]](#references)</sup>
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
Diese Informationen werden in **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`** gespeichert, und das Terminal benötigt FDA.<sup>[[2]](#references)</sup>

### Manipulation von BTM

Wenn eine neue persistence gefunden wird, wird ein Ereignis des Typs **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`** ausgelöst. Daher hilft jede Möglichkeit, das Senden dieses **Ereignisses** oder das **Warnen des Benutzers durch den agent** zu **verhindern**, einem Angreifer dabei, BTM zu _**umgehen**_.<sup>[[1]](#references)</sup>

- **Zurücksetzen der Datenbank**: Der folgende Befehl setzt die Datenbank zurück (sie sollte dadurch von Grund auf neu erstellt werden). Danach werden jedoch **bis zum Neustart des Systems keine neuen persistence-Warnungen angezeigt**.<sup>[[1]](#references)</sup>
- **root** ist erforderlich.
```bash
# Reset the database
sfltool resettbtm
```
- **Agent stoppen**: Es ist möglich, ein Stoppsignal an den Agent zu senden, sodass er den Benutzer **nicht benachrichtigt**, wenn neue Erkennungen gefunden werden.<sup>[[1]](#references)</sup>
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
- **Bug**: Wenn der **Prozess, der die Persistenz erstellt hat, unmittelbar danach beendet wird**, versucht der Daemon, **Informationen** darüber abzurufen, scheitert dabei und **kann das Ereignis nicht senden**, das angibt, dass ein neues Element persistiert.<sup>[[1]](#references)</sup>

## References

- [1] [OBTS v6.0: "Entmystifizierung (und Umgehung) der macOS-Hintergrundaufgabenverwaltung" - Patrick Wardle & Chris Lopez](https://youtu.be/9hjUmT031tc?t=26481)
- [2] [Neues (Entwickler-)Tool: "DumpBTM" - Patrick Wardle (Patreon)](https://www.patreon.com/posts/new-developer-77420730?l=fr)
- [3] [Anmeldeobjekte und Hintergrundaufgaben auf dem Mac verwalten - Apple Platform Deployment](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)
{{#include ../../../banners/hacktricks-training.md}}
