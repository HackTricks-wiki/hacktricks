# Windows-Artefakte

{{#include ../../../banners/hacktricks-training.md}}

## Allgemeine Windows-Artefakte

### Windows 10-Benachrichtigungen

Die Benachrichtigungsdatenbank pro Benutzer befindet sich unter `%LOCALAPPDATA%\Microsoft\Windows\Notifications` (zum Beispiel `C:\Users\<username>\AppData\Local\Microsoft\Windows\Notifications`). Frühere Windows-10-Versionen verwendeten `appdb.dat`; mit dem Anniversary Update (1607) wurde `wpndatabase.db` eingeführt. Die SQLite-Datenbank enthält eine `Notification`-Tabelle mit Benachrichtigungsdaten und Zeitfeldern. Die Aufbewahrung und die verfügbaren Daten variieren jedoch je nach Version und Bereinigungsrichtlinie.<sup>[[3]](#references)</sup>

### Windows Timeline

Windows Timeline ist eine Funktion für den Aktivitätsverlauf, die Datensätze für unterstützte Anwendungen, Dokumente und andere Benutzeraktivitäten enthalten kann. Die Abdeckung hängt von der Anwendung und der Windows-Version ab.<sup>[[4]](#references)</sup>

Die Datenbank befindet sich unter `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Sie kann mit SQLite geöffnet oder mit [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) geparst werden. Die Ausgabe kann mit [**Timeline Explorer**](https://ericzimmerman.github.io/#!index.md) überprüft werden.<sup>[[4]](#references)[[5]](#references)</sup>

### ADS (Alternate Data Streams)

Dateien, die von außerhalb der lokalen Vertrauensgrenze heruntergeladen wurden, können den **alternativen Datenstrom `Zone.Identifier`** enthalten. Dieser zeichnet Zoneninformationen auf und kann Herkunftsmetadaten wie eine URL enthalten. Das Vorhandensein und die enthaltenen Felder hängen vom Ersteller und den Systemrichtlinien ab.<sup>[[6]](#references)</sup>

## **Dateisicherungen**

### Papierkorb

Unter Vista und späteren Versionen befindet sich der **Papierkorb** im Ordner **`$Recycle.bin`** im Stammverzeichnis des Laufwerks (zum Beispiel `C:\$Recycle.bin`).\
Wenn eine Datei in diesem Ordner gelöscht wird, werden zwei bestimmte Dateien erstellt:

- `$I{id}`: Dateiinformationen, einschließlich Löschzeitpunkt und ursprünglichem Pfad
- `$R{id}`: Inhalt der Datei

![Dateisicherungen - Papierkorb: $R{id}: Inhalt der Datei](<../../../images/image (1029).png>)

Mit diesen Dateien können Sie [**Rifiuti2**](https://github.com/abelcheung/rifiuti2) verwenden, um den ursprünglichen Pfad und den Löschzeitpunkt zu extrahieren (verwenden Sie die für die jeweilige Windows-Version passende Version).<sup>[[7]](#references)</sup>
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![Dateisicherungen - Papierkorb: rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### Volume Shadow Copies

Der Volume Shadow Copy Service (VSS) kann zeitpunktbezogene Schattenkopien von Volumes erstellen, während Dateien verwendet werden; eine Schattenkopie ist kein Ersatz für ein forensisches Image.<sup>[[8]](#references)</sup>

Die Metadaten der Kopie sind normalerweise dem Verzeichnis `\System Volume Information` im Volume-Stammverzeichnis zugeordnet. Die darin enthaltenen Bezeichner unterscheiden sich je nach System:

![Papierkorb - Volume Shadow Copies: Diese Sicherungen befinden sich normalerweise im Verzeichnis System Volume Information im Stammverzeichnis des Dateisystems, und der Name besteht aus den in der Abbildung gezeigten UIDs.](<../../../images/image (94).png>)

Nach dem Mounten eines Images mit einem geeigneten forensischen Mounter kann [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) verfügbare VSS-Snapshots aufzählen und Dateien daraus durchsuchen oder kopieren.<sup>[[9]](#references)</sup>

![Papierkorb - Volume Shadow Copies: Nach dem Mounten des forensischen Images mit dem ArsenalImageMounter kann das Tool ShadowCopyView verwendet werden, um eine Schattenkopie zu untersuchen und sogar die Dateien zu extrahieren.](<../../../images/image (576).png>)

Die Konfiguration des VSS-Registry-Writers enthält `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore`. Dort können Dateien und Schlüssel angegeben werden, die von der Sicherung ausgeschlossen sind:<sup>[[10]](#references)[[11]](#references)</sup>

![Papierkorb - Volume Shadow Copies: Der Registry-Eintrag HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore enthält die Dateien und Schlüssel, die nicht gesichert werden sollen.](<../../../images/image (254).png>)

Der Schlüssel `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` enthält ebenfalls die Konfiguration des VSS-Dienstes.<sup>[[8]](#references)</sup>

### Automatisch gespeicherte Office-Dateien

Die Speicherorte von AutoRecover unterscheiden sich je nach Office-Anwendung, Version und Konfiguration. Für Word dokumentiert Microsoft `%APPDATA%\Microsoft\Word` als Standardspeicherort. Prüfe die Anwendungseinstellungen auf den aktuell verwendeten Pfad.<sup>[[12]](#references)</sup>

## Shell Items

Ein Shell Item ist ein Element, das Informationen darüber enthält, wie auf eine andere Datei zugegriffen wird.

### Zuletzt verwendete Dokumente (LNK)

Windows erstellt üblicherweise Verknüpfungen zu zuletzt verwendeten Elementen, wenn ein Benutzer ein Element öffnet oder anderweitig darauf zugreift:

- Win7-Win10: `%APPDATA%\Microsoft\Windows\Recent\`
- Office: `%APPDATA%\Microsoft\Office\Recent\`

Der Zugriff auf einen Ordner kann ebenfalls Verknüpfungen für den Ordner und zugehörige übergeordnete Ordner erstellen.

Diese Verknüpfungsdateien können den Zieltyp, die MAC-Zeitstempel des Ziels, Volume-Informationen und den Zielpfad enthalten. Diese Metadaten können dabei helfen, ein entferntes Ziel zu identifizieren. Das Artefakt allein ist jedoch kein Beweis dafür, dass das Ziel von einem bestimmten Benutzer geöffnet wurde.<sup>[[13]](#references)[[14]](#references)</sup>

Die eigenen Dateisystem-Zeitstempel der LNK und die eingebetteten Zeitstempel des Ziels sind voneinander unabhängig. Interpretiere die Erstellung der Verknüpfung nicht ohne unterstützende Artefakte als erste Verwendung und die Änderung der Verknüpfung nicht als letzte Verwendung. Das Format speichert die Zeitstempel des Ziels getrennt von den Zeitstempeln der Verknüpfungsdatei.<sup>[[13]](#references)[[14]](#references)</sup>

Der vorhandene Link zu [**LinkParser**](http://4discovery.com/our-tools/) bleibt als historische Option erhalten, die Dokumentation war während der Überprüfung jedoch nicht verfügbar. Verwende für einen dokumentierten Kommandozeilenparser [**LECmd**](https://github.com/EricZimmerman/LECmd).<sup>[[15]](#references)</sup>

Diese Tools zeigen üblicherweise zwei Gruppen von Zeitstempeln an:

- **Zeitstempel des Ziels:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
- **Zeitstempel der Verknüpfungsdatei:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

Die erste Gruppe bezieht sich auf das Ziel, die zweite Gruppe auf die LNK-Datei selbst. Interpretiere beide Gruppen anhand der Dokumentation des Parsers und des Dateisystemkontexts.<sup>[[14]](#references)[[15]](#references)</sup>

Du kannst dieselben Informationen mit dem Windows-CLI-Tool [**LECmd.exe**](https://github.com/EricZimmerman/LECmd) abrufen.<sup>[[15]](#references)</sup>
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
In diesem Fall werden die Informationen in einer CSV-Datei gespeichert.

### Jumplists

Jump Lists sind anwendungsspezifische Listen mit kürzlich verwendeten oder aufgabenbezogenen Elementen und können automatisch oder benutzerdefiniert sein.<sup>[[13]](#references)</sup>

Automatische Jump Lists werden unter `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` gespeichert und verwenden Namen wie `{id}.automaticDestinations-ms`, wobei die ID die Anwendung identifiziert.

Benutzerdefinierte Jump Lists werden unter `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\` gespeichert; die Anwendung steuert, welche Aufgaben- oder Elementeinträge sie erstellt.

Die Erstellungs- und Änderungszeiten des Dateisystems beschreiben die Jump-List-Datei und nicht automatisch den ersten und letzten Zugriff auf jedes aufgeführte Ziel. Korrelieren Sie analysierte Einträge mit den Zeitstempeln der Datei und anderen Artefakten.<sup>[[13]](#references)</sup>

Sie können die Jump Lists mit [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md) untersuchen.<sup>[[5]](#references)</sup>

![Recent Documents (LNK) - Jumplists: Sie können die Jumplists mit JumplistExplorer untersuchen](<../../../images/image (168).png>)

(_Beachten Sie, dass sich die von JumplistExplorer bereitgestellten Zeitstempel auf die Jumplist-Datei selbst beziehen_)

### Shellbags

[**Folgen Sie diesem Link, um zu erfahren, was Shellbags sind.**](interesting-windows-registry-keys.md#shellbags)

## Verwendung von Windows-USBs

Die Verwendung von USB-Geräten kann manchmal durch Artefakte bestätigt werden, die beim Zugriff auf Dateien von Wechselmedien erstellt werden, darunter:

- Windows Recent Folder
- Microsoft Office Recent Folder
- Jumplists

Tools wie [**USBDetective**](https://usbdetective.com) korrelieren diese Artefakte mit USB-Geräteaufzeichnungen. Die Verfügbarkeit der Artefakte hängt jedoch von der Windows-Version und der Anwendung ab.<sup>[[18]](#references)</sup>

Bei Tests, die für MTP-Workflows unter Windows XP und Windows 7 dokumentiert wurden, verwiesen einige LNKs auf einen `WPDNSE`-Ordner anstelle des ursprünglichen Pfads.<sup>[[16]](#references)</sup>

![Shellbags - Verwendung von Windows-USBs: Beachten Sie, dass einige LNK-Dateien nicht auf den ursprünglichen Pfad, sondern auf den WPDNSE-Ordner verweisen](<../../../images/image (218).png>)

Diese Studie stellte Kopien unter `%LOCALAPPDATA%\Temp\WPDNSE\{FolderGUID}` fest. Die temporären Inhalte blieben in den Tests nach einem Neustart nicht erhalten, und die GUID konnte mit Shellbag-Daten korreliert werden. Betrachten Sie dies als ein vom Betriebssystem, Gerät und der Anwendung abhängiges Verhalten und nicht als allgemeingültige Regel.<sup>[[16]](#references)</sup>

### Registry-Informationen

[Auf dieser Seite erfahren Sie](interesting-windows-registry-keys.md#usb-information), welche Registry-Schlüssel interessante Informationen über verbundene USB-Geräte enthalten.

### setupapi

Unter Vista und späteren Versionen können Sie `C:\Windows\inf\setupapi.dev.log` auf Aktivitäten zur Geräteinstallation untersuchen. Abschnittsüberschriften enthalten Zeitstempel für `Section start`; sie dokumentieren die Setup-Verarbeitung und sollten mit anderen Verbindungsnachweisen korreliert werden, anstatt als exakte Zeit des physischen Einsteckens behandelt zu werden.<sup>[[17]](#references)</sup>

![Registry-Informationen - setupapi: Überprüfen Sie die Datei C: Windows inf setupapi.dev.log, um die Zeitstempel der USB-Verbindung zu erhalten (suchen Sie nach Section start)](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) kann verwendet werden, um Informationen über USB-Geräte abzurufen, die mit einem Abbild verbunden waren.<sup>[[18]](#references)</sup>

![setupapi - USB Detective: USBDetective kann verwendet werden, um Informationen über USB-Geräte abzurufen, die mit einem Abbild verbunden waren](<../../../images/image (452).png>)

### Plug and Play Cleanup

Die geplante Aufgabe `Plug and Play Cleanup` entfernt veraltete Treiberversionen. Eine von Adam Harrison dokumentierte Windows-10-Aufgabendefinition zielt außerdem auf Treiber ab, die 30 Tage lang inaktiv waren. Daher können Nachweise zu Wechseldatenträger-Treibern bereinigt werden. Bestätigen Sie die lokale Aufgabendefinition und den Windows-Build, bevor Sie dieses Verhalten verallgemeinern.<sup>[[1]](#references)</sup>

Die Aufgabe befindet sich unter folgendem Pfad: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

![XML-Definition der geplanten Windows-Aufgabe Plug and Play Cleanup](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Wichtige Komponenten und Einstellungen der Aufgabe:**

- **pnpclean.dll**: Diese DLL ist für den eigentlichen Bereinigungsvorgang verantwortlich.
- **UseUnifiedSchedulingEngine**: Auf `TRUE` gesetzt, was die Verwendung der generischen Aufgabenplanungs-Engine angibt.
- **MaintenanceSettings**:
- **Period ('P1M')**: Weist den Task Scheduler an, die Bereinigungsaufgabe während der regulären Automatic-Wartung monatlich zu starten.
- **Deadline ('P2M')**: Weist den Task Scheduler an, die Aufgabe während der Notfallwartung auszuführen, wenn sie zwei aufeinanderfolgende Monate fehlschlägt.

Diese Konfiguration plant regelmäßige Wartung und Wiederholungen nach aufeinanderfolgenden Fehlern. Die genaue XML-Struktur und das Verhalten hängen von der Version ab.<sup>[[1]](#references)</sup>

**Weitere Informationen finden Sie unter:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html).<sup>[[1]](#references)</sup>

## E-Mails

E-Mails enthalten **2 interessante Bestandteile: die Header und den Inhalt** der E-Mail. In den **Headern** finden Sie Informationen wie:

- **Wer** die E-Mails gesendet hat (E-Mail-Adresse, IP-Adresse, Mailserver, die die E-Mail weitergeleitet haben)
- **Wann** die E-Mail gesendet wurde

Außerdem können die Header `References` und `In-Reply-To` Nachrichten-IDs enthalten, die zur Zuordnung von Antworten zu einer Unterhaltung verwendet werden.<sup>[[76]](#references)</sup>

![Plug and Play Cleanup - E-Mails: Wann wurde die E-Mail gesendet](<../../../images/image (593).png>)

### Windows Mail App

Diese Anwendung speichert E-Mail-Inhalte in zusätzlichen Text- oder HTML-Dateien unter Pfaden wie `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`; die genaue Struktur der nummerierten Ordner und Dateien kann je nach Artefakt variieren.<sup>[[75]](#references)</sup>

Die **Metadaten** der E-Mails und die **Kontakte** befinden sich in der **ESE-Datenbank** `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`.<sup>[[75]](#references)</sup>

`store.vol` verwendet das Extensible Storage Engine (ESE)-Format. Arbeiten Sie mit einer Kopie und verwenden Sie einen ESE-Parser wie [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html). Wenn ein Tool die Endung `.edb` benötigt, benennen Sie nur die Kopie um und überprüfen Sie das Tabellenschema, bevor Sie sich auf eine Tabelle `Message` verlassen.<sup>[[19]](#references)[[75]](#references)</sup>

### Microsoft Outlook

Bei der Untersuchung von Outlook-MAPI-Eigenschaften gehören folgende kanonische Eigenschaften dazu:

- `PidTagClientSubmitTime`: die UTC-Zeit, zu der der Client die Nachricht übermittelt hat.
- `PidTagConversationIndex`: die relative Position der Nachricht innerhalb eines Unterhaltungs-Threads.
- `PidTagEntryId`: eine Kennung für das Nachrichtenobjekt.
- `PidTagMessageFlags`: Statusflags wie übermittelt, gelesen, ungelesen oder mit Anhängen.
- `PidTagLastVerbExecuted`: der zuletzt für die Nachricht aufgezeichnete Vorgang, etwa Öffnen, Antworten oder Weiterleiten.<sup>[[20]](#references)[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Die Speicherorte der Outlook-Datendateien variieren je nach Version und Kontotyp. Microsoft dokumentiert diese gängigen Speicherorte für PST-/OST-Dateien:

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

Der Registry-Pfad `HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` kann das Outlook-Profil und die zugehörige Konfiguration der Datendateien identifizieren.

PST-Dateien können Nachrichten, Kontakte, Kalenderdaten und andere Outlook-Elemente enthalten. Sie können eine Kopie mit [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html) untersuchen.<sup>[[25]](#references)[[67]](#references)</sup>

![Windows Mail App - Microsoft Outlook: Sie können die PST-Datei mit dem Tool Kernel PST Viewer öffnen](<../../../images/image (498).png>)

### Microsoft Outlook OST Files

Eine **OST-Datei** ist ein lokaler Cache für Exchange- oder Microsoft-365-Konten. Der Cached Exchange Mode gilt nicht für POP- oder IMAP-Konten. Der Offlinezeitraum ist konfigurierbar und beträgt standardmäßig häufig 12 Monate, während die Größenbeschränkungen für PST/OST separate konfigurierbare Einstellungen sind. Zum Anzeigen einer OST-Datei kann der [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html) verwendet werden.<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[68]](#references)</sup>

### Anhänge abrufen

Verlorene Anhänge können möglicherweise wiederhergestellt werden aus:

- Für ältere Outlook-/IE-Konfigurationen: `%LOCALAPPDATA%\Temporary Internet Files\Content.Outlook`
- Für neuere Outlook-/IE11-Konfigurationen: `%LOCALAPPDATA%\Microsoft\Windows\INetCache\Content.Outlook`.<sup>[[65]](#references)</sup>

### Thunderbird MBOX Files

**Thunderbird** speichert Profildaten unter `%APPDATA%\Thunderbird\Profiles`; Mail-Ordner verwenden üblicherweise Dateien ohne Dateiendung im mbox-Format in kontospezifischen Verzeichnissen `Mail` oder `ImapMail`.<sup>[[29]](#references)[[30]](#references)</sup>

### Bildminiaturen

- **Windows XP**: Miniaturvorschauen wurden üblicherweise in `thumbs.db`-Dateien pro Ordner gespeichert.
- **Netzwerkordner**: Für einen UNC-Ordner kann weiterhin eine `thumbs.db`-Datei erstellt werden, wenn das entsprechende Verhalten für Miniaturansichten aktiviert ist. Gehen Sie nicht davon aus, dass jede Windows-Version oder Richtlinie eine solche Datei erstellt.
- **Windows Vista und neuer**: Der zentrale Miniaturcache des Systems befindet sich unter `%USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer` und enthält Dateien wie **thumbcache_xxx.db**. [**Thumbsviewer**](https://thumbsviewer.github.io) kann veraltete `Thumbs.db`-Dateien analysieren, während [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) moderne Miniaturcache-Datenbanken analysieren kann.<sup>[[31]](#references)[[32]](#references)[[33]](#references)</sup>

### Informationen zur Windows Registry

Die Windows Registry, in der System- und Benutzerkonfigurationsdaten gespeichert werden, befindet sich in Hive-Dateien unter:

- `%WINDIR%\System32\Config` für die Maschinen-Hives, die verschiedene `HKEY_LOCAL_MACHINE`-Unterschlüssel unterstützen.
- `%USERPROFILE%\NTUSER.DAT` für den `HKEY_CURRENT_USER`-Hive eines Benutzers.
- Einige ältere Windows-Installationen enthalten Kopien unter `%WINDIR%\System32\Config\RegBack\`; Windows 10 Version 1803 und spätere Versionen befüllen dieses Verzeichnis nicht automatisch, sofern keine regelmäßige Sicherung aktiviert ist.<sup>[[34]](#references)[[35]](#references)</sup>
- Pro-Benutzer-Shell- und Klassenregistrierungsdaten werden unter modernen Windows-Versionen ebenfalls häufig in `%LOCALAPPDATA%\Microsoft\Windows\UsrClass.dat` gespeichert.<sup>[[34]](#references)[[66]](#references)</sup>

### Tools

Einige Tools eignen sich zur Analyse von Registry-Hives. Überprüfen Sie vor der Verwendung eines Outputs das von jedem Tool unterstützte Hive-Format und die Version:

- **Registry Editor**: Dieses Tool ist in Windows installiert. Es bietet eine GUI zur Navigation durch die Windows Registry der aktuellen Sitzung.
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): Damit können Sie die Registry-Datei laden und über eine GUI darin navigieren. Außerdem enthält es Bookmarks, die Schlüssel mit interessanten Informationen hervorheben.
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): Auch dieses Tool verfügt über eine GUI zur Navigation durch die geladene Registry und enthält Plugins, die interessante Informationen innerhalb der geladenen Registry hervorheben.
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): Eine weitere GUI-Anwendung, die Informationen aus einem geladenen Registry-Hive extrahieren kann.<sup>[[5]](#references)[[36]](#references)[[37]](#references)</sup>

### Gelöschte Elemente wiederherstellen

Gelöschte Hive-Zellen können erhalten bleiben, bis ihr Speicherplatz wiederverwendet wird. Die Wiederherstellung hängt jedoch vom Zustand des Hives und vom Parser ab. Behandeln Sie wiederhergestellte gelöschte Schlüssel daher als validierungsbedürftige Beweise und nicht als garantiert vollständige Aufzeichnungen.

### Letzte Schreibzeit

Registry-Schlüssel enthalten einen Zeitstempel des letzten Schreibvorgangs. Windows stellt diesen für den Schlüssel oder einen seiner Werte bereit. Ein Wert besitzt daher nicht zwangsläufig einen eigenen unabhängigen Änderungszeitstempel.<sup>[[69]](#references)</sup>

### SAM

Der **SAM**-Hive enthält Daten zu lokalen Benutzer- und Gruppenkonten, einschließlich Passwort-Hashes, die durch das Boot-Key-Material des Systems geschützt sind.<sup>[[38]](#references)[[39]](#references)</sup>

Unter `SAM\Domains\Account\Users` können Sie Kontoidentifikatoren sowie einige Anmelde- und Richtlinienfelder abrufen. Für die Offline-Extraktion von Hashes ist außerdem der `SYSTEM`-Hive erforderlich, um das relevante Boot-Key-Material wiederherzustellen.<sup>[[38]](#references)[[39]](#references)</sup>

### Interessante Einträge in der Windows Registry


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Ausgeführte Programme

### Grundlegende Windows-Prozesse

Ein vorhandener [Beitrag zu häufigen Windows-Prozessen](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) wird als zusätzliche Lektüre beibehalten. Bestätigen Sie Aussagen zum Prozessverhalten mit aktueller Windows-Dokumentation und lokalen Nachweisen.<sup>[[2]](#references)</sup>

### Windows Recent APPs

Unter Windows-10-Versionen, die dieses Artefakt bereitstellen, enthält `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps` anwendungsspezifische Unterschlüssel mit Feldern wie dem Zeitpunkt der letzten Verwendung und der Startanzahl. Das Artefakt wurde aus späteren Versionen entfernt; überprüfen Sie daher den Ziel-Build.<sup>[[64]](#references)</sup>

### BAM (Background Activity Moderator)

Auf Systemen, die den Background Activity Moderator bereitstellen, untersuchen Sie `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` oder den neueren Pfad `...\bam\State\UserSettings\{SID}`. Die Werte sind nach der Benutzer-SID geordnet und können überwachte ausführbare Pfade sowie ausführungbezogene Daten im FILETIME-Format enthalten. Das Artefakt ist versionsabhängig und sollte mit anderen Nachweisen bestätigt werden.<sup>[[63]](#references)</sup>

### Windows Prefetch

Prefetching cached Ressourcen und Startmetadaten, damit Programme schneller gestartet werden können.

Prefetch-Dateien werden als `.pf`-Dateien in `C:\Windows\Prefetch` gespeichert. Format, Aufbewahrung und Dateianzahlbeschränkungen variieren je nach Windows-Version. Microsoft dokumentiert für Windows 8 und spätere Versionen die Aufbewahrung der letzten acht Ausführungszeiten und von bis zu 1024 Dateien. Ältere Zusammenfassungen mit festen Grenzwerten sollten daher nicht verallgemeinert werden.<sup>[[13]](#references)</sup>

Der Dateiname verwendet üblicherweise `{program_name}-{hash}.pf`, wobei der Hash aus dem Ausführungskontext wie Pfad und Argumenten abgeleitet wird. Windows 10 und spätere Versionen können die Datei komprimieren. Das Vorhandensein ist ein nützlicher Nachweis für eine Ausführung, beweist jedoch allein nicht die Ausführung durch einen Benutzer und sollte mit anderen Artefakten korreliert werden.<sup>[[13]](#references)</sup>

Zur Untersuchung dieser Dateien können Sie [**PECmd.exe**](https://github.com/EricZimmerman/PECmd) verwenden. Das Tool dokumentiert die Analyse von Verzeichnissen, die Ausgabe in CSV/HTML sowie die Dekomprimierungsunterstützung für entsprechende Windows-10-Prefetch-Dateien.<sup>[[40]](#references)</sup>
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

**Superfetch/SysMain** ergänzt Prefetch, indem es historische Nutzungsmuster verwendet, um das Laden zu verbessern. Auf Systemen, die diese Dateien erzeugen, befinden sich die Datenbankdateien üblicherweise unter `C:\Windows\Prefetch\Ag*.db`; Format und Vorhandensein sind versionsabhängig.<sup>[[41]](#references)</sup>

Diese Datenbanken können Anwendungsnamen, Nutzungszähler, aufgerufene Dateien oder Volumes, Pfade und Zeitbereiche enthalten, sollten jedoch nicht als exaktes Ausführungsprotokoll betrachtet werden.<sup>[[41]](#references)</sup>

Der vorhandene Link zu [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) bleibt als möglicher Parser erhalten; prüfe vor der Verwendung anhand der Dokumentation des Tools dessen aktuelle Verfügbarkeit und unterstützte Ausgabe.

### SRUM

**System Resource Usage Monitor** (SRUM) zeichnet die Ressourcennutzung durch Anwendungen und Benutzer auf. Es wurde in Windows 8 eingeführt und speichert Daten in der ESE-Datenbank `C:\Windows\System32\sru\SRUDB.dat`.<sup>[[13]](#references)</sup>

Es liefert die folgenden Informationen:

- AppID und Pfad
- Dem Datensatz zugeordneter Benutzer/SID
- Gesendete Bytes
- Empfangene Bytes
- Netzwerkschnittstelle
- Verbindungsdauer
- Prozessdauer

Erfassungsintervall und Aufbewahrungsdauer sind implementationsabhängig; gehe nicht davon aus, dass jeder Datensatz ein exaktes Ausführungsintervall von 60 Minuten darstellt.<sup>[[13]](#references)</sup>

Du kannst Daten mit [**srum_dump**](https://github.com/MarkBaggett/srum-dump) extrahieren und überprüfen, wobei du die von der aktuellen Tool-Version dokumentierten Optionen verwendest.<sup>[[42]](#references)</sup>
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -o C:\Users\student\Desktop\srum --NO_CONFIRM
```
### AppCompatCache (ShimCache)

Der **AppCompatCache**, auch als **ShimCache** bekannt, ist Bestandteil der Windows-Infrastruktur für Anwendungskompatibilität und zeichnet Dateimetadaten für Kompatibilitätsentscheidungen auf. Der Hive-Pfad, das Datensatzformat, die gespeicherte Kapazität und die Felder variieren je nach Windows-Version; unter modernen Windows-Versionen kann der ShimCache allein nicht beweisen, dass ein Benutzer eine Datei ausgeführt hat. Analysiere den relevanten `SYSTEM`-Hive mit dem [**AppCompatCacheParser tool**](https://github.com/EricZimmerman/AppCompatCacheParser) und gleiche dessen Ausgabe mit Ausführungsartefakten ab.<sup>[[13]](#references)[[43]](#references)</sup>

![SRUM - AppCompatCache (ShimCache): Zum Parsen der gespeicherten Informationen wird die Verwendung des AppCompatCacheParser tools empfohlen](<../../../images/image (75).png>)

### Amcache

Die Datei **Amcache.hve** ist ein Registry-Hive, der von Windows beobachtete Anwendungen und Dateien inventarisiert. Sie befindet sich typischerweise unter `C:\Windows\AppCompat\Programs\Amcache.hve`.

Sie kann zugehörige und nicht zugehörige Dateieinträge, Pfade und SHA1-Werte enthalten, doch ihr Vorhandensein ist ein Inventarbeleg und beweist nicht allein, dass ein Prozess ausgeführt wurde.<sup>[[13]](#references)[[44]](#references)</sup>

Verwende zum Extrahieren und Analysieren von **Amcache.hve** das Tool [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser). Dieser Befehl parst den Hive und schreibt die Ausgabe im CSV-Format.<sup>[[44]](#references)</sup>

Zum Beispiel:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
Unter den generierten CSV-Dateien kann `Amcache_Unassociated file entries` bei der Untersuchung von Dateien nützlich sein, die keinem erkannten Programm zugeordnet sind.<sup>[[44]](#references)</sup>

### RecentFileCache

Auf Windows-7-Systemen kann `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` Informationen über kürzlich beobachtete Binärdateien enthalten; Verfügbarkeit und Bedeutung sind versionsabhängig.

Sie können [**RecentFileCacheParser**](https://github.com/EricZimmerman/RecentFileCacheParser) verwenden, um die Datei zu analysieren.<sup>[[45]](#references)</sup>

### Geplante Aufgaben

Beweise zu geplanten Aufgaben können sich bei modernen Aufgaben in `C:\Windows\System32\Tasks` und bei älteren Aufgaben mit `.job`-Dateien in `C:\Windows\Tasks` befinden; untersuchen Sie das für das Betriebssystem geeignete Format der Aufgabendefinition.<sup>[[73]](#references)[[74]](#references)</sup>

### Dienste

Die Datenbank des Service Control Managers befindet sich unter `SYSTEM\CurrentControlSet\Services` (bei einer offline SYSTEM-Hive ist der entsprechende Control-Set-Schlüssel zu untersuchen); sie enthält die Konfiguration von Diensten und Treibern, beispielsweise ausführbare Pfade und Starttypen.<sup>[[72]](#references)</sup>

### **Windows Store**

Installierte Windows-Store-Anwendungen können unter `\ProgramData\Microsoft\Windows\AppRepository\` repräsentiert sein, einschließlich der Datenbank **`StateRepository-Machine.srd`**. Schema und Pfade unterscheiden sich je nach Windows-Version.<sup>[[71]](#references)</sup>

Die Datenbank kann Anwendungskennungen, Paketnummern und Anzeigenamen enthalten. Lücken in den Kennungen sind allein kein Beweis dafür, dass eine Anwendung deinstalliert wurde; gleichen Sie dies mit dem Paket- und Registrierungsstatus ab.

Paketregistrierungen können auch unter `HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\` erscheinen. Microsoft dokumentiert einen versionsspezifischen `Deprovisioned`-Unterschlüssel für entfernte bereitgestellte Apps; gehen Sie nicht davon aus, dass auf jedem Build ein `Deleted`-Unterschlüssel existiert.<sup>[[70]](#references)</sup>

## Windows-Ereignisse

Abhängig vom Provider können Windows-Ereignisse Folgendes enthalten:

- Was passiert ist
- Einen `TimeCreated`-Zeitstempel, der anhand des Ereignisschemas und des Zeitkontexts des Hosts interpretiert werden muss
- Beteiligte Benutzer
- Beteiligte Hosts (Hostname, IP)
- Aufgerufene Ressourcen (Dateien, Ordner, Drucker oder Dienste).<sup>[[49]](#references)</sup>

Vor Windows Vista verwendeten Ereignisprotokolle im Allgemeinen das ältere Binärformat unter `C:\Windows\System32\config`; Vista und spätere Versionen verwenden das Windows-Event-Log-Format, normalerweise unter `C:\Windows\System32\winevt\Logs`, wobei `.evtx`-Dateien XML-dargestellte Ereignisdaten enthalten.<sup>[[46]](#references)[[47]](#references)</sup>

Die SYSTEM-Registry speichert die Kanalkonfiguration unter **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**, einschließlich des konfigurierten Dateipfads und der Aufbewahrungseinstellungen.<sup>[[47]](#references)</sup>

Sie können mit der Windows-Ereignisanzeige (**`eventvwr.msc`**) oder Tools wie [**Event Log Explorer**](https://eventlogxp.com) und [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md) angezeigt werden.<sup>[[5]](#references)[[48]](#references)[[61]](#references)</sup>

## Windows-Sicherheitsereignisprotokollierung verstehen

Unter Vista und späteren Versionen wird der Security-Kanal üblicherweise unter `C:\Windows\System32\winevt\Logs\Security.evtx` gespeichert. Maximale Größe und Aufbewahrungsrichtlinie sind konfigurierbar; bei zirkulärer Protokollierung können ältere Datensätze überschrieben werden, wenn die Datei ihre Begrenzung erreicht. Der Kanal kann Authentifizierungs-, Abmelde-, Berechtigungs-, Überwachungsrichtlinien- und Objektzugriffsereignisse aufzeichnen, wenn die entsprechende Überwachung aktiviert ist.<sup>[[46]](#references)[[47]](#references)</sup>

### Wichtige Ereignis-IDs für die Benutzerauthentifizierung:

- **Event ID 4624**: Eine erfolgreiche Kontoanmeldung.<sup>[[50]](#references)</sup>
- **Event ID 4625**: Eine fehlgeschlagene Kontoanmeldung.<sup>[[51]](#references)</sup>
- **Event ID 4634**: Eine Anmeldesitzung wurde beendet.<sup>[[52]](#references)</sup>
- **Event ID 4647**: Ein Benutzer hat eine Abmeldung eingeleitet.<sup>[[53]](#references)</sup>
- **Event ID 4672**: Einer neuen Anmeldung wurden besondere Berechtigungen zugewiesen; dies ist bei System- und Administratorkonten üblich und allein daher kein Beweis für bösartige Aktivitäten.<sup>[[54]](#references)</sup>

#### Häufig in 4624, 4625, 4634 und 4647 aufgezeichnete Anmeldetypen:

- **Interactive (2)**: Eine interaktive lokale Anmeldung.
- **Network (3)**: Zugriff auf eine freigegebene Ressource.
- **Batch (4)**: Eine Anmeldung durch einen Batch-Prozess.
- **Service (5)**: Eine Dienstanmeldung.
- **Unlock (7)**: Das Entsperren einer Workstation.
- **NetworkCleartext (8)**: Eine Netzwerkanmeldung, bei der Anmeldeinformationen im Klartext an das Authentifizierungspaket übermittelt werden.
- **NewCredentials (9)**: Eine Anmeldung mit bereitgestellten alternativen Anmeldeinformationen für ausgehende Verbindungen.
- **RemoteInteractive (10)**: Eine Anmeldung über Remote Desktop oder Terminal Services.
- **CachedInteractive (11)**: Eine interaktive Anmeldung mit zwischengespeicherten Domänenanmeldeinformationen.
- **CachedRemoteInteractive (12)**: Eine zwischengespeicherte Remote-interaktive Anmeldung.
- **CachedUnlock (13)**: Ein Entsperren mit zwischengespeicherten Anmeldeinformationen.<sup>[[50]](#references)[[51]](#references)</sup>

#### Status- und Substatuscodes für EventID 4625:

- **0xC0000064**: Kein solcher Benutzer.
- **0xC000006A**: Korrekte Benutzername, aber falsches Passwort.
- **0xC0000234**: Konto gesperrt.
- **0xC0000072**: Konto deaktiviert.
- **0xC000006F**: Anmeldung außerhalb der zulässigen Zeiten.
- **0xC0000070**: Verstoß gegen eine Workstation-Einschränkung.
- **0xC0000193**: Konto abgelaufen.
- **0xC0000071**: Passwort abgelaufen.
- **0xC0000133**: Der Zeitunterschied zwischen Client und Server ist zu groß.
- **0xC0000224**: Das Konto muss sein Passwort ändern.
- **0xC0000225**: `STATUS_NOT_FOUND`; der Code allein identifiziert weder einen Systemfehler noch einen Angriff.
- **0xC000015B**: Der angeforderte Anmeldetyp ist für das Konto nicht zulässig.<sup>[[51]](#references)[[55]](#references)</sup>

#### EventID 4616:

- **Time Change**: Die Systemzeit wurde geändert. Viele Ereignisse spiegeln routinemäßige Korrekturen durch den Zeitdienst wider; korrelieren Sie daher den Akteur und die Zeitquelle, bevor Sie von einer Manipulation ausgehen.<sup>[[56]](#references)</sup>

#### Event-IDs 12, 13, 1074, 6005, 6006, 6008 und 6009:

- **Stromversorgungs- und Dienstkontext**: Ereignis 12 zeichnet den Start des Betriebssystems auf, 13 das Herunterfahren des Betriebssystems, 1074 ein geplantes Herunterfahren oder einen geplanten Neustart, 6008 ein unerwartetes Herunterfahren und 6009 die Windows-Version beim Systemstart. Die Ereignisse 6005 und 6006 zeigen jeweils an, dass der Event-Log-Dienst gestartet und beendet wurde; sie sind selbst kein Beweis für den Start und das Herunterfahren des Betriebssystems.<sup>[[57]](#references)[[58]](#references)</sup>

#### EventID 1102:

- **Protokolllöschung**: Ereignis 1102 zeichnet auf, dass das Security-Überwachungsprotokoll gelöscht wurde; untersuchen Sie den Akteur und die umgebenden Ereignisse, anstatt allein aus diesem Ereignis auf eine Absicht zu schließen.<sup>[[62]](#references)</sup>

#### EventIDs für die Verfolgung von USB-Geräten:

- **20001 / 20003**: `UserPnp`-Ereignisse zur Geräteinstallation, die dabei helfen können, erstmalige Nutzung oder Installationsaktivität festzustellen.
- **10000 / 10100**: `DriverFrameworks-UserMode`-Ereignisse, die mit Geräteaktivität einhergehen können.
- **Event ID 112**: `DeviceSetupManager/Admin`-Aktivität, die zeitliche Angaben zum Einstecken liefern kann.
- Provider, Kanal und Ereignisbedeutung unterscheiden sich je nach Windows-Version; untersuchen Sie den Providernamen und die Ereignisnutzdaten, bevor Sie eine Bedeutung zuweisen.<sup>[[59]](#references)</sup>

Praktische Beispiele zu Anmeldetypen und den zugehörigen Anmeldeinformationsdaten finden Sie im [detaillierten Leitfaden von Altered Security](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).<sup>[[60]](#references)</sup>

Ereignisdetails, einschließlich Anmeldetyp, Status, Substatus, Quelladresse und Prozessfelder, liefern Kontext für Event ID 4625; ein Statuscode oder ein wiederholtes Fehlermuster ist ein Ermittlungsansatz, keine Schlussfolgerung.<sup>[[51]](#references)[[55]](#references)</sup>

### Windows-Ereignisse wiederherstellen

Da Ereignisprotokolle häufig zirkulär sind, können vom Logger überschriebene Datensätze nicht wiederherstellbar sein. Sichern Sie ein forensisches Abbild oder eine Arbeitskopie, bevor Sie mit einem Live-System interagieren; verwenden Sie einen validierten Parser oder Carver wie **Bulk_extractor** erst, nachdem Sie bestätigt haben, dass die Toolversion die betreffenden `.evtx`-Daten unterstützt, und trennen Sie ein laufendes System nicht ausschließlich zum Versuch, Ereignisse wiederherzustellen.<sup>[[46]](#references)</sup>

### Häufige Angriffe anhand von Windows-Ereignissen identifizieren

Eine praktische Referenz zu Ereignis-IDs finden Sie im vorhandenen Link [Red Team Recipe](https://redteamrecipe.com/event-codes/); validieren Sie dessen Beispiele anhand der oben genannten Provider-Dokumentation.

#### Brute-Force-Angriffe

Korrelieren Sie wiederholte Fehler mit Event ID 4625 mit einem späteren Erfolg durch 4624, dem Anmeldetyp, Status, der Quelle und dem Kontokontext; die Sequenz ist ein Indikator für weitere Untersuchungen, kein Beweis für einen Angriff.<sup>[[50]](#references)[[51]](#references)</sup>

#### Zeitänderung

Event ID 4616 zeichnet Änderungen der Systemzeit auf, die die Zeitleistenanalyse erschweren können; vergleichen Sie das Ereignis mit Beweisen des Zeitdienstes und des Hosts.<sup>[[56]](#references)</sup>

#### USB-Geräteverfolgung

USB-Ereignis-IDs sind providerspezifisch; korrelieren Sie `UserPnp` 20001/20003, `DriverFrameworks-UserMode` 10000/10100 und `DeviceSetupManager/Admin` 112 mit SetupAPI- und Registry-Artefakten.<sup>[[17]](#references)[[59]](#references)</sup>

#### Systemereignisse der Stromversorgung

Verwenden Sie 12/13/1074/6008/6009 für den Kontext von Betriebssystemstart, Herunterfahren, Neustart und unerwarteter Stromversorgung; 6005/6006 markieren den Start bzw. das Beenden des Event-Log-Dienstes.<sup>[[57]](#references)[[58]](#references)</sup>

#### Protokolllöschung

Security Event ID 1102 zeichnet auf, dass das Security-Überwachungsprotokoll gelöscht wurde, und sollte mit dem verantwortlichen Konto und Prozess korreliert werden.<sup>[[62]](#references)</sup>

## References

- [1] [Bereinigung von Windows Plug and Play](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)
- [2] [jonahacks.medium.com - Untersuchung häufiger Windows-Prozesse](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)
- [3] [Eine digitale forensische Sicht auf Windows-10-Benachrichtigungen](https://iconline.ipleiria.pt/server/api/core/bitstreams/833e160a-e382-46b4-82ad-fb2c8c995d62/content)
- [4] [WxTCmd](https://github.com/EricZimmerman/WxTCmd)
- [5] [Forensische Tools von Eric Zimmerman](https://ericzimmerman.github.io/#!index.md)
- [6] [Zone.Identifier und alternative Datenströme](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/6e3f7352-d11c-4d76-8c39-2516a9df36e8)
- [7] [Rifiuti2](https://github.com/abelcheung/rifiuti2)
- [8] [Volume Shadow Copy Service](https://learn.microsoft.com/en-us/windows/server/storage/file-server/volume-shadow-copy-service)
- [9] [ShadowCopyView](https://www.nirsoft.net/utils/shadow_copy_view.html)
- [10] [Registry-Sicherungs- und Wiederherstellungsvorgänge unter VSS](https://learn.microsoft.com/en-us/windows/win32/vss/registry-backup-and-restore-operations-under-vss)
- [11] [Registry-Schlüssel für Sicherung und Wiederherstellung](https://learn.microsoft.com/en-us/windows/win32/backup/registry-keys-for-backup-and-restore)
- [12] [Word-Leistungsproblem am AutoRecover-Speicherort](https://learn.microsoft.com/en-us/previous-versions/troubleshoot/microsoft-365/microsoft-365-apps/word/performance-issue-on-autorecover-location)
- [13] [Leitfaden zur Incident Response](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/final/en-us/microsoft-brand/documents/IR-Guidebook-Final.pdf)
- [14] [MS-SHLLINK: Binärdateiformat von Shell Links](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/c3376b21-0931-45e4-b2fc-a48ac0e60d15)
- [15] [LECmd](https://github.com/EricZimmerman/LECmd)
- [16] [USB-MTP-Forensik: Identifizierung von Datenexfiltrationsartefakten](https://studylib.net/doc/8690663/usb-devices-and-media-transfer-protocol)
- [17] [SetupAPI-Protokolleinträge zur Geräteinstallation](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/setupapi-device-installation-log-entries)
- [18] [USB Detective](https://usbdetective.com)
- [19] [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)
- [20] [PidTagClientSubmitTime](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/ca98145f-7f87-42b4-b0ef-124c6c6f8d83)
- [21] [PidTagConversationIndex](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/57f8de0f-5f53-423a-8947-7943dd959997)
- [22] [EntryID und verwandte Typen](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcdata/57e8bcbf-11d0-40fe-8833-5558bb9c0c89)
- [23] [PidTagMessageFlags](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcmsg/a0c52fe2-3014-43a7-942d-f43f6f91c366)
- [24] [PidTagLastVerbExecuted](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxomsg/87a8b6b8-59a4-4859-9dcd-8b0f36e3d729?redirectedfrom=MSDN)
- [25] [Outlook-Datendateien suchen und übertragen](https://support.microsoft.com/en-us/outlook/find-and-transfer-outlook-data-files-from-one-computer-to-another)
- [26] [Cached Exchange Mode aktivieren](https://support.microsoft.com/en-us/outlook/turn-on-cached-exchange-mode)
- [27] [Nur eine Teilmenge der Elemente wird synchronisiert](https://learn.microsoft.com/en-us/troubleshoot/outlook/user-interface/only-subset-items-synchronized)
- [28] [Größenbeschränkungen für Outlook-Datendateien konfigurieren](https://learn.microsoft.com/en-us/microsoft-365-apps/outlook/data-files/configure-size-limit-outlook-data-files)
- [29] [Profile - Wo Thunderbird Benutzerdaten speichert](https://support.mozilla.org/bm/kb/profiles-where-thunderbird-stores-user-data)
- [30] [Thunderbird-Kontoeinstellungen und mbox-Verzeichnisse](https://support.mozilla.org/en-US/kb/dangerous-directories-Thunderbird-account-settings)
- [31] [IThumbnailCache-Schnittstelle](https://learn.microsoft.com/en-us/windows/win32/api/thumbcache/nn-thumbcache-ithumbnailcache)
- [32] [Thumbs Viewer](https://thumbsviewer.github.io)
- [33] [Thumbcache Viewer](https://thumbcacheviewer.github.io)
- [34] [Registry-Hives](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives)
- [35] [System-Registry wird nicht in RegBack gesichert](https://learn.microsoft.com/en-gb/troubleshoot/windows-client/installing-updates-features-roles/system-registry-no-backed-up-regback-folder)
- [36] [RegRipper 3.0](https://github.com/keydet89/RegRipper3.0)
- [37] [Windows Registry Recovery](https://www.mitec.cz/wrr.html)
- [38] [Registry remote bearbeiten](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/remotely-edit-the-registry)
- [39] [Technische Übersicht zu Passwörtern](https://learn.microsoft.com/en-us/windows-server/security/kerberos/passwords-technical-overview)
- [40] [PECmd](https://github.com/EricZimmerman/PECmd)
- [41] [Superfetch-Beweise](https://kb.binalyze.com/air/features/acquisition/supported-evidence/windows-collections-detail/superfetch)
- [42] [srum-dump](https://github.com/MarkBaggett/srum-dump)
- [43] [AppCompatCacheParser](https://github.com/EricZimmerman/AppCompatCacheParser)
- [44] [AmcacheParser](https://github.com/EricZimmerman/AmcacheParser)
- [45] [RecentFileCacheParser](https://github.com/EricZimmerman/RecentFileCacheParser)
- [46] [Dateiformat des Ereignisprotokolls](https://learn.microsoft.com/en-us/windows/win32/eventlog/event-log-file-format)
- [47] [Eventlog-Registry-Schlüssel](https://learn.microsoft.com/en-us/windows/win32/eventlog/eventlog-key)
- [48] [Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.5)
- [49] [TimeCreated-Ereigniseigenschaft](https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-timecreated-systempropertiestype-element)
- [50] [Ereignis 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624)
- [51] [Ereignis 4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)
- [52] [Ereignis 4634](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4634)
- [53] [Ereignis 4647](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4647)
- [54] [Ereignis 4672](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672)
- [55] [MS-ERREF: NTSTATUS-Werte](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55)
- [56] [Ereignis 4616](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4616)
- [57] [Unerwartete Neustarts mithilfe von Systemereignisprotokollen beheben](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
- [58] [Fehler beim Herunterfahren während eines laufenden Prozesses beheben](https://learn.microsoft.com/en-us/troubleshoot/windows-server/installing-updates-features-roles/troubleshoot-error-shutdown-in-process)
- [59] [Forensik von USB-Speichergeräten für Windows 10](https://www.researchgate.net/publication/318514858_USB_Storage_Device_Forensics_for_Windows_10)
- [60] [Fantastische Windows-Anmeldetypen](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)
- [61] [Event Log Explorer](https://eventlogxp.com)
- [62] [Ereignis 1102](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102)
- [63] [Moderator für Hintergrundaktivitäten](https://winreg-kb.readthedocs.io/en/latest/sources/system-keys/Background-activity-moderator.html)
- [64] [Registry - RecentApps](https://artefacts.help/windows_registry_recentapps.html)
- [65] [Quick Print beendet das Drucken von PDF-Anhängen in Outlook Desktop](https://support.microsoft.com/en-gb/office/quick-print-stops-printing-pdf-attachments-in-outlook-desktop-512fdeb0-6a88-4e6c-9285-cf957290aad2)
- [66] [Windows-Registry-Dateien](https://winreg-kb.readthedocs.io/en/latest/sources/windows-registry/Files.html)
- [67] [Kernel PST Viewer](https://www.nucleustechnologies.com/es/visor-de-pst.html)
- [68] [Kernel OST Viewer](https://www.nucleustechnologies.com/ost-viewer.html)
- [69] [RegQueryInfoKeyA](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryinfokeya)
- [70] [Verhindern, dass entfernte Apps während eines Updates zurückkehren](https://learn.microsoft.com/en-us/windows/application-management/remove-provisioned-apps-during-update)
- [71] [NIST CFTT: Testergebnisse von FTK und Registry Viewer](https://www.dhs.gov/sites/default/files/publications/test_results_nist_windows_registry_forensic_tool_ftk_7.0.0.163_registry_viewer_2.0.0.7_april_2019.pdf)
- [72] [Datenbank der installierten Dienste](https://learn.microsoft.com/en-us/windows/win32/services/database-of-installed-services)
- [73] [Aufgaben](https://learn.microsoft.com/en-us/windows/win32/taskschd/tasks)
- [74] [Geplante Aufgaben schlagen mit dem Fehler „Task Scheduler Service Is Not Available“ fehl](https://learn.microsoft.com/en-us/troubleshoot/windows-client/system-management-components/task-schedular-service-is-not-available)
- [75] [Navigation durch die Windows-Mail-Datenbank](https://eprints.whiterose.ac.uk/133161/1/Navigating_the_Windows_Mail_database_accepted.pdf)
- [76] [RFC 5322: Internet-Nachrichtenformat](https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.4)
{{#include ../../../banners/hacktricks-training.md}}
