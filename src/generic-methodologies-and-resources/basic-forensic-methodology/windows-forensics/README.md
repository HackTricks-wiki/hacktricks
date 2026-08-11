# Windows-Artefakte

{{#include ../../../banners/hacktricks-training.md}}

## Allgemeine Windows-Artefakte

### Windows 10-Benachrichtigungen

Die Benachrichtigungsdatenbank pro Benutzer befindet sich unter `%LOCALAPPDATA%\Microsoft\Windows\Notifications` (zum Beispiel `C:\Users\<username>\AppData\Local\Microsoft\Windows\Notifications`). Frühere Windows-10-Versionen verwendeten `appdb.dat`; mit dem Anniversary Update (1607) wurde `wpndatabase.db` eingeführt. Die SQLite-Datenbank enthält eine `Notification`-Tabelle mit Benachrichtigungs-Payloads und Zeitfeldern, wobei Aufbewahrungsdauer und verfügbare Daten je nach Version und Bereinigungsrichtlinie variieren.<sup>[[3]](#references)</sup>

### Zeitachse

Windows Timeline ist eine Funktion zur Aktivitätsverlauf, die Datensätze für unterstützte Anwendungen, Dokumente und andere Benutzeraktivitäten enthalten kann; der Umfang hängt von der Anwendung und der Windows-Version ab.<sup>[[4]](#references)</sup>

Die Datenbank befindet sich unter `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Sie kann mit SQLite geöffnet oder mit [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) geparst werden. Die Ausgabe kann mit [**Timeline Explorer**](https://ericzimmerman.github.io/#!index.md) überprüft werden.<sup>[[4]](#references)[[5]](#references)</sup>

### ADS (Alternate Data Streams)

Dateien, die außerhalb der lokalen Vertrauensgrenze heruntergeladen wurden, können den **alternativen Datenstrom `Zone.Identifier`** enthalten, der Zoneninformationen speichert und Herkunftsmetadaten wie eine URL enthalten kann. Das Vorhandensein und die Felder hängen vom Ersteller und der Systemrichtlinie ab.<sup>[[6]](#references)</sup>

## **Dateisicherungen**

### Papierkorb

Unter Vista und später ist der **Papierkorb** im Ordner **`$Recycle.bin`** im Stammverzeichnis des Laufwerks zu finden (zum Beispiel `C:\$Recycle.bin`).\
Wenn eine Datei in diesem Ordner gelöscht wird, werden 2 bestimmte Dateien erstellt:

- `$I{id}`: Dateiinformationen, einschließlich Löschzeitpunkt und ursprünglichem Pfad
- `$R{id}`: Inhalt der Datei

![Dateisicherungen - Papierkorb: $R{id}: Inhalt der Datei](<../../../images/image (1029).png>)

Mit diesen Dateien kann [**Rifiuti2**](https://github.com/abelcheung/rifiuti2) verwendet werden, um den ursprünglichen Pfad und den Löschzeitpunkt zu extrahieren (verwende die für die jeweilige Windows-Version geeignete Version).<sup>[[7]](#references)</sup>
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![Dateisicherungen - Papierkorb: rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### Volumeschattenkopien

Der Volume Shadow Copy Service (VSS) kann Point-in-Time-Schattenkopien von Volumes erstellen, während Dateien verwendet werden; eine Schattenkopie ist kein Ersatz für ein forensisches Abbild.<sup>[[8]](#references)</sup>

Die Metadaten der Kopie sind normalerweise dem Verzeichnis `\System Volume Information` im Volume-Stammverzeichnis zugeordnet. Die Bezeichner unterscheiden sich je nach System:

![Papierkorb - Volumeschattenkopien: Diese Sicherungen befinden sich normalerweise im System Volume Information im Stammverzeichnis des Dateisystems, und der Name besteht aus den in der... angezeigten UIDs](<../../../images/image (94).png>)

Nach dem Einbinden eines Abbilds mit einem geeigneten forensischen Mounter kann [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) verfügbare VSS-Snapshots auflisten sowie Dateien daraus durchsuchen oder kopieren.<sup>[[9]](#references)</sup>

![Papierkorb - Volumeschattenkopien: Nach dem Einbinden des forensischen Abbilds mit dem ArsenalImageMounter kann das Tool ShadowCopyView verwendet werden, um eine Schattenkopie zu untersuchen und sogar die Dateien zu extrahieren...](<../../../images/image (576).png>)

Die Konfiguration des VSS-Registry-Writers enthält `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore`. Dort können Dateien und Schlüssel angegeben werden, die von der Sicherung ausgeschlossen sind:<sup>[[10]](#references)[[11]](#references)</sup>

![Papierkorb - Volumeschattenkopien: Der Registry-Eintrag HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore enthält die Dateien und Schlüssel, die nicht gesichert werden sollen](<../../../images/image (254).png>)

Der Schlüssel `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` enthält ebenfalls die Konfiguration des VSS-Dienstes.<sup>[[8]](#references)</sup>

### Automatisch gespeicherte Office-Dateien

Die Speicherorte von AutoRecover unterscheiden sich je nach Office-Anwendung, Version und Konfiguration. Für Word dokumentiert Microsoft `%APPDATA%\Microsoft\Word` als Standardspeicherort. Prüfe die Anwendungseinstellungen auf den aktiven Pfad.<sup>[[12]](#references)</sup>

## Shell-Elemente

Ein Shell-Element enthält Informationen darüber, wie auf eine andere Datei zugegriffen werden kann.

### Zuletzt verwendete Dokumente (LNK)

Windows erstellt üblicherweise Verknüpfungen zu zuletzt verwendeten Elementen, wenn ein Benutzer ein Element öffnet oder anderweitig darauf zugreift:

- Win7-Win10: `%APPDATA%\Microsoft\Windows\Recent\`
- Office: `%APPDATA%\Microsoft\Office\Recent\`

Der Zugriff auf einen Ordner kann außerdem Verknüpfungen für den Ordner und zugehörige übergeordnete Ordner erstellen.

Diese Verknüpfungsdateien können den Zieltyp, die MAC-Zeitstempel des Ziels, Volume-Informationen und den Zielpfad enthalten. Diese Metadaten können dabei helfen, ein entferntes Ziel zu identifizieren. Das Artefakt ist jedoch kein Beweis dafür, dass das Ziel von einem bestimmten Benutzer geöffnet wurde.<sup>[[13]](#references)[[14]](#references)</sup>

Die eigenen Dateisystem-Zeitstempel der LNK und die eingebetteten Zeitstempel des Ziels sind voneinander unabhängig. Interpretiere die Erstellung der Verknüpfung nicht ohne weitere bestätigende Artefakte als erste Nutzung und die Änderung der Verknüpfung nicht als letzte Nutzung. Das Format speichert die Zeitstempel des Ziels getrennt von den Zeitstempeln der Verknüpfungsdatei.<sup>[[13]](#references)[[14]](#references)</sup>

Der vorhandene [**LinkParser**](http://4discovery.com/our-tools/) wird als historische Option beibehalten, seine Dokumentation war während der Überprüfung jedoch nicht verfügbar. Verwende für einen dokumentierten Parser für die Kommandozeile [**LECmd**](https://github.com/EricZimmerman/LECmd).<sup>[[15]](#references)</sup>

Diese Tools zeigen üblicherweise zwei Gruppen von Zeitstempeln an:

- **Zeitstempel des Ziels:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
- **Zeitstempel der Verknüpfungsdatei:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

Die erste Gruppe bezieht sich auf das Ziel, die zweite auf die LNK-Datei selbst. Interpretiere beide anhand der Dokumentation des Parsers und des Dateisystemkontexts.<sup>[[14]](#references)[[15]](#references)</sup>

Du kannst dieselben Informationen mit dem Windows-CLI-Tool [**LECmd.exe**](https://github.com/EricZimmerman/LECmd) abrufen.<sup>[[15]](#references)</sup>
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
In diesem Fall werden die Informationen in einer CSV-Datei gespeichert.

### Jumplists

Jump Lists sind anwendungsspezifische Listen mit kürzlich verwendeten oder aufgabenbezogenen Elementen und können automatisch oder benutzerdefiniert sein.<sup>[[13]](#references)</sup>

Automatische Jump Lists werden unter `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` gespeichert und verwenden Namen wie `{id}.automaticDestinations-ms`, wobei die ID die Anwendung identifiziert.

Benutzerdefinierte Jump Lists werden unter `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\` gespeichert. Die Anwendung bestimmt, welche Aufgaben- oder Elementeinträge erstellt werden.

Die Erstellungs- und Änderungszeiten des Dateisystems beschreiben die Jump-List-Datei und nicht automatisch den ersten und letzten Zugriff auf jedes aufgelistete Ziel. Korrelieren Sie die analysierten Einträge mit den Zeitstempeln der Datei und anderen Artefakten.<sup>[[13]](#references)</sup>

Sie können die Jump Lists mit [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md) untersuchen.<sup>[[5]](#references)</sup>

![Recent Documents (LNK) - Jumplists: You can inspect the jumplists using JumplistExplorer](<../../../images/image (168).png>)

(_Beachten Sie, dass sich die von JumplistExplorer bereitgestellten Zeitstempel auf die Jumplist-Datei selbst beziehen_)

### Shellbags

[**Folgen Sie diesem Link, um zu erfahren, was Shellbags sind.**](interesting-windows-registry-keys.md#shellbags)

## Verwendung von Windows-USBs

Die Verwendung von USB-Geräten kann manchmal durch Artefakte bestätigt werden, die beim Zugriff auf Dateien von Wechseldatenträgern erstellt werden, darunter:

- Windows Recent Folder
- Microsoft Office Recent Folder
- Jumplists

Tools wie [**USBDetective**](https://usbdetective.com) korrelieren diese Artefakte mit Datensätzen von USB-Geräten. Die Verfügbarkeit der Artefakte hängt jedoch von der Windows-Version und der Anwendung ab.<sup>[[18]](#references)</sup>

Bei für Windows XP und Windows 7 dokumentierten MTP-Workflows zeigten einige LNKs auf einen `WPDNSE`-Ordner statt auf den ursprünglichen Pfad.<sup>[[16]](#references)</sup>

![Shellbags - Use of Windows USBs: Note that some LNK file instead of pointing to the original path, points to the WPDNSE folder](<../../../images/image (218).png>)

Diese Studie beobachtete Kopien unter `%LOCALAPPDATA%\Temp\WPDNSE\{FolderGUID}`. Die temporären Inhalte blieben in den Tests nach einem Neustart nicht erhalten, und die GUID konnte mit Shellbag-Daten korreliert werden. Betrachten Sie dies als ein vom Betriebssystem, Gerät und der Anwendung abhängiges Verhalten und nicht als allgemeingültige Regel.<sup>[[16]](#references)</sup>

### Registry-Informationen

[Auf dieser Seite erfahren Sie](interesting-windows-registry-keys.md#usb-information), welche Registry-Schlüssel interessante Informationen über verbundene USB-Geräte enthalten.

### setupapi

Unter Vista und späteren Versionen können Sie `C:\Windows\inf\setupapi.dev.log` auf Aktivitäten zur Geräteinstallation untersuchen. Abschnittsüberschriften enthalten Zeitstempel für `Section start`; sie dokumentieren die Setup-Verarbeitung und sollten mit anderen Verbindungsnachweisen korreliert werden, anstatt als exakter Zeitpunkt des physischen Einsteckens betrachtet zu werden.<sup>[[17]](#references)</sup>

![Registry Information - setupapi: Check the file C: Windows inf setupapi.dev.log to get the timestamps about when the USB connection was produced (search for Section start)](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) kann verwendet werden, um Informationen über USB-Geräte abzurufen, die mit einem Image verbunden waren.<sup>[[18]](#references)</sup>

![setupapi - USB Detective: USBDetective can be used to obtain information about the USB devices that have been connected to an image](<../../../images/image (452).png>)

### Plug and Play Cleanup

Die als `Plug and Play Cleanup` bekannte geplante Aufgabe entfernt veraltete Treiberversionen. Eine von Adam Harrison dokumentierte Aufgabendefinition für Windows 10 zielt außerdem auf Treiber ab, die 30 Tage lang inaktiv waren. Daher können Nachweise zu Treibern von Wechseldatenträgern bereinigt werden. Prüfen Sie die lokale Aufgabendefinition und den Windows-Build, bevor Sie dieses Verhalten verallgemeinern.<sup>[[1]](#references)</sup>

Die Aufgabe befindet sich unter folgendem Pfad: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

**Wichtige Komponenten und Einstellungen der Aufgabe:**

- **pnpclean.dll**: Diese DLL ist für den eigentlichen Bereinigungsprozess verantwortlich.
- **UseUnifiedSchedulingEngine**: Auf `TRUE` gesetzt, was die Verwendung der generischen Aufgabenplanungs-Engine angibt.
- **MaintenanceSettings**:
- **Period ('P1M')**: Weist den Task Scheduler an, die Bereinigungsaufgabe während der regulären Automatic maintenance monatlich zu starten.
- **Deadline ('P2M')**: Weist den Task Scheduler an, die Aufgabe während der Notfallwartung auszuführen, wenn die Aufgabe zwei aufeinanderfolgende Monate lang fehlschlägt.

Diese Konfiguration plant die regelmäßige Wartung und Wiederholungen nach aufeinanderfolgenden Fehlern. Die genaue XML-Struktur und das Verhalten hängen von der Version ab.<sup>[[1]](#references)</sup>

**Weitere Informationen finden Sie unter:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html).<sup>[[1]](#references)</sup>

## E-Mails

E-Mails enthalten **2 interessante Teile: die Header und den Inhalt** der E-Mail. In den **Headern** finden Sie Informationen wie:

- **Wer** die E-Mails gesendet hat (E-Mail-Adresse, IP-Adresse, Mailserver, die die E-Mail weitergeleitet haben)
- **Wann** die E-Mail gesendet wurde

Außerdem können die Header `References` und `In-Reply-To` message IDs enthalten, die zur Zuordnung von Antworten zu einer Konversation verwendet werden.<sup>[[76]](#references)</sup>

![Plug and Play Cleanup - Emails: When was the email sent](<../../../images/image (593).png>)

### Windows Mail App

Diese Anwendung speichert E-Mail-Inhalte in zusätzlichen Text- oder HTML-Dateien unter Pfaden wie `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`; die genaue Struktur der nummerierten Ordner und Dateien kann je nach Artefakt variieren.<sup>[[75]](#references)</sup>

Die **Metadaten** der E-Mails und die **Kontakte** befinden sich in der **ESE-Datenbank** `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`.<sup>[[75]](#references)</sup>

`store.vol` verwendet das Extensible Storage Engine (ESE)-Format. Arbeiten Sie mit einer Kopie und verwenden Sie einen ESE-Parser wie [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html). Wenn ein Tool die Endung `.edb` voraussetzt, benennen Sie nur die Kopie um und überprüfen Sie das Tabellenschema, bevor Sie sich auf eine `Message`-Tabelle verlassen.<sup>[[19]](#references)[[75]](#references)</sup>

### Microsoft Outlook

Bei der Untersuchung von Outlook-MAPI-Eigenschaften gehören folgende kanonische Eigenschaften dazu:

- `PidTagClientSubmitTime`: der UTC-Zeitpunkt, zu dem der Client die Nachricht übermittelt hat.
- `PidTagConversationIndex`: die relative Position der Nachricht innerhalb eines Konversationsthreads.
- `PidTagEntryId`: eine Kennung für das Nachrichtenobjekt.
- `PidTagMessageFlags`: Statusflags wie übermittelt, gelesen, ungelesen oder mit Anhängen.
- `PidTagLastVerbExecuted`: die letzte für die Nachricht aufgezeichnete Operation, beispielsweise Öffnen, Antworten oder Weiterleiten.<sup>[[20]](#references)[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Die Speicherorte von Outlook-Datendateien variieren je nach Version und Kontotyp. Microsoft dokumentiert folgende gängige Speicherorte für PST/OST-Dateien:

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

Der Registry-Pfad `HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` kann das Outlook-Profil und die zugehörige Konfiguration der Datendatei identifizieren.

PST-Dateien können Nachrichten, Kontakte, Kalenderdaten und andere Outlook-Elemente enthalten. Sie können eine Kopie mit [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html) untersuchen.<sup>[[25]](#references)[[67]](#references)</sup>

![Windows Mail App - Microsoft Outlook: You can open the PST file using the tool Kernel PST Viewer](<../../../images/image (498).png>)

### Microsoft Outlook OST Files

Eine **OST-Datei** ist ein lokaler Cache für Exchange- oder Microsoft 365-Konten. Cached Exchange Mode gilt nicht für POP- oder IMAP-Konten. Der Offlinezeitraum ist konfigurierbar und beträgt standardmäßig häufig 12 Monate. Die Größenlimits für PST/OST sind separate konfigurierbare Einstellungen. Zum Anzeigen einer OST-Datei kann der [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html) verwendet werden.<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[68]](#references)</sup>

### Abrufen von Anhängen

Verlorene Anhänge können möglicherweise aus folgenden Verzeichnissen wiederhergestellt werden:

- Für ältere Outlook/IE-Konfigurationen: `%LOCALAPPDATA%\Temporary Internet Files\Content.Outlook`
- Für neuere Outlook/IE11-Konfigurationen: `%LOCALAPPDATA%\Microsoft\Windows\INetCache\Content.Outlook`.<sup>[[65]](#references)</sup>

### Thunderbird MBOX Files

**Thunderbird** speichert Profildaten unter `%APPDATA%\Thunderbird\Profiles`; Mailordner verwenden üblicherweise Dateien ohne Dateiendung im mbox-Format innerhalb kontenspezifischer `Mail`- oder `ImapMail`-Verzeichnisse.<sup>[[29]](#references)[[30]](#references)</sup>

### Image Thumbnails

- **Windows XP**: Vorschaubilder wurden üblicherweise in `thumbs.db`-Dateien pro Ordner gespeichert.
- **Netzwerkordner**: Für einen UNC-Ordner kann weiterhin eine `thumbs.db`-Datei erstellt werden, wenn das entsprechende Verhalten für Vorschaubilder aktiviert ist. Gehen Sie nicht davon aus, dass jede Windows-Version oder Richtlinie eine solche Datei erstellt.
- **Windows Vista und neuer**: Der Systemcache für Vorschaubilder ist zentral unter `%USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer` gespeichert und enthält Dateien wie **thumbcache_xxx.db**. [**Thumbsviewer**](https://thumbsviewer.github.io) kann ältere `Thumbs.db`-Dateien analysieren, während [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) moderne Datenbanken des Vorschaubild-Caches analysieren kann.<sup>[[31]](#references)[[32]](#references)[[33]](#references)</sup>

### Windows Registry Information

Die Windows Registry, in der System- und Benutzerkonfigurationsdaten gespeichert werden, befindet sich in Hive-Dateien unter:

- `%WINDIR%\System32\Config` für die Computer-Hives, die verschiedene `HKEY_LOCAL_MACHINE`-Unterschlüssel unterstützen.
- `%USERPROFILE%\NTUSER.DAT` für den `HKEY_CURRENT_USER`-Hive eines Benutzers.
- Einige ältere Windows-Installationen enthalten Kopien unter `%WINDIR%\System32\Config\RegBack\`; Windows 10 Version 1803 und später befüllen dieses Verzeichnis nicht automatisch, sofern keine regelmäßige Sicherung aktiviert ist.<sup>[[34]](#references)[[35]](#references)</sup>
- Shell- und Klassenregistrierungsdaten pro Benutzer werden unter modernen Windows-Versionen ebenfalls häufig in `%LOCALAPPDATA%\Microsoft\Windows\UsrClass.dat` gespeichert.<sup>[[34]](#references)[[66]](#references)</sup>

### Tools

Einige Tools sind für die Analyse von Registry-Hives hilfreich. Überprüfen Sie vor dem Vertrauen in eine Ausgabe, welche Hive-Formate und Versionen das jeweilige Tool unterstützt:

- **Registry Editor**: Ist in Windows installiert. Es handelt sich um eine GUI zur Navigation durch die Windows Registry der aktuellen Sitzung.
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): Ermöglicht das Laden einer Registry-Datei und die Navigation durch diese über eine GUI. Enthält außerdem Bookmarks, die Schlüssel mit interessanten Informationen hervorheben.
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): Verfügt ebenfalls über eine GUI, mit der durch die geladene Registry navigiert werden kann, sowie über Plugins, die interessante Informationen innerhalb der geladenen Registry hervorheben.
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): Eine weitere GUI-Anwendung, die Informationen aus einem geladenen Registry-Hive extrahieren kann.<sup>[[5]](#references)[[36]](#references)[[37]](#references)</sup>

### Wiederherstellung gelöschter Elemente

Gelöschte Hive-Zellen können erhalten bleiben, bis ihr Speicherplatz wiederverwendet wird. Die Wiederherstellung hängt jedoch vom Zustand des Hives und vom Parser ab. Behandeln Sie wiederhergestellte gelöschte Schlüssel als überprüfungsbedürftige Beweise und nicht als garantiert vollständige Datensätze.

### Last Write Time

Registry-Schlüssel enthalten einen Zeitstempel für die letzte Änderung. Windows stellt diesen für den Schlüssel oder einen seiner Werte bereit, sodass ein Wert nicht zwangsläufig einen eigenen unabhängigen Änderungszeitstempel besitzt.<sup>[[69]](#references)</sup>

### SAM

Der **SAM**-Hive enthält Daten zu lokalen Benutzer- und Gruppenkonten, einschließlich Passwort-Hashes, die durch das Boot-Key-Material des Systems geschützt sind.<sup>[[38]](#references)[[39]](#references)</sup>

Unter `SAM\Domains\Account\Users` können Sie Kontoidentifikatoren sowie einige Anmelde- und Richtlinienfelder abrufen. Die Offline-Extraktion von Hashes erfordert außerdem den `SYSTEM`-Hive, um das relevante Boot-Key-Material wiederherzustellen.<sup>[[38]](#references)[[39]](#references)</sup>

### Interessante Einträge in der Windows Registry


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Ausgeführte Programme

### Grundlegende Windows-Prozesse

Ein vorhandener [Beitrag zu verbreiteten Windows-Prozessen](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) bleibt als zusätzliche Lektüre erhalten. Bestätigen Sie Aussagen zum Prozessverhalten mit aktueller Windows-Dokumentation und lokalen Nachweisen.<sup>[[2]](#references)</sup>

### Windows Recent APPs

Unter Windows-10-Versionen, die dieses Artefakt bereitstellen, enthält `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps` anwendungsspezifische Unterschlüssel mit Feldern wie der letzten Verwendungszeit und der Startanzahl. Das Artefakt wurde aus späteren Releases entfernt; überprüfen Sie daher den Ziel-Build.<sup>[[64]](#references)</sup>

### BAM (Background Activity Moderator)

Auf Systemen, die den Background Activity Moderator bereitstellen, untersuchen Sie `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` oder den neueren Pfad `...\bam\State\UserSettings\{SID}`. Die Werte sind nach der Benutzer-SID strukturiert und können erfasste Pfade zu ausführbaren Dateien sowie Ausführungsdaten ähnlich FILETIME enthalten. Das Artefakt ist versionsabhängig und sollte durch andere Nachweise bestätigt werden.<sup>[[63]](#references)</sup>

### Windows Prefetch

Prefetching cached Ressourcen und Startmetadaten, damit Programme schneller gestartet werden können.

Prefetch-Dateien werden als `.pf`-Dateien unter `C:\Windows\Prefetch` gespeichert. Format, Aufbewahrung und Dateianzahl-Limits variieren je nach Windows-Version. Microsoft dokumentiert die Aufbewahrung der letzten acht Ausführungszeiten und von bis zu 1024 Dateien unter Windows 8 und späteren Versionen. Ältere Zusammenfassungen mit festen Limits sollten daher nicht verallgemeinert werden.<sup>[[13]](#references)</sup>

Der Dateiname verwendet üblicherweise das Format `{program_name}-{hash}.pf`, wobei der Hash aus dem Ausführungskontext wie Pfad und Argumenten abgeleitet wird. Windows 10 und spätere Versionen können die Datei komprimieren. Das Vorhandensein ist ein nützlicher Hinweis auf eine Ausführung, stellt jedoch allein keinen Beweis für die Ausführung durch einen Benutzer dar und sollte mit anderen Artefakten korreliert werden.<sup>[[13]](#references)</sup>

Zur Untersuchung dieser Dateien können Sie [**PECmd.exe**](https://github.com/EricZimmerman/PECmd) verwenden. Das Tool dokumentiert die Verzeichnisanalyse, die CSV-/HTML-Ausgabe und die Dekomprimierungsunterstützung für entsprechende Windows-10-Prefetch-Dateien.<sup>[[40]](#references)</sup>
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

**Superfetch/SysMain** ergänzt Prefetch, indem historische Nutzungsmuster verwendet werden, um das Laden zu verbessern. Auf Systemen, die solche Dateien erzeugen, befinden sich die Datenbankdateien üblicherweise unter `C:\Windows\Prefetch\Ag*.db`; Format und Vorhandensein sind versionsabhängig.<sup>[[41]](#references)</sup>

Diese Datenbanken können Anwendungsnamen, Nutzungszahlen, aufgerufene Dateien oder Volumes, Pfade und Zeitbereiche enthalten, sollten jedoch nicht als exaktes Ausführungsprotokoll betrachtet werden.<sup>[[41]](#references)</sup>

Der vorhandene Link zu [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) bleibt als möglicher Parser erhalten. Überprüfe vor der Verwendung anhand der Dokumentation des Tools dessen aktuelle Verfügbarkeit und die unterstützten Ausgabeformate.

### SRUM

**System Resource Usage Monitor** (SRUM) zeichnet die Ressourcennutzung durch Anwendungen und Benutzer auf. Es wurde in Windows 8 eingeführt und speichert Daten in der ESE-Datenbank `C:\Windows\System32\sru\SRUDB.dat`.<sup>[[13]](#references)</sup>

Es liefert folgende Informationen:

- AppID und Pfad
- Mit dem Datensatz verknüpfter Benutzer/SID
- Gesendete Bytes
- Empfangene Bytes
- Netzwerkschnittstelle
- Verbindungsdauer
- Prozessdauer

Erfassungsintervall und Aufbewahrungsdauer sind implementationsabhängig; gehe nicht davon aus, dass jeder Datensatz ein exaktes Ausführungsintervall von 60 Minuten darstellt.<sup>[[13]](#references)</sup>

Du kannst Daten mit [**srum_dump**](https://github.com/MarkBaggett/srum-dump) extrahieren und überprüfen, wobei du die in der aktuellen Toolversion dokumentierten Optionen verwendest.<sup>[[42]](#references)</sup>
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -o C:\Users\student\Desktop\srum --NO_CONFIRM
```
### AppCompatCache (ShimCache)

Der **AppCompatCache**, auch als **ShimCache** bezeichnet, ist Bestandteil der Windows-Infrastruktur für Anwendungskompatibilität und zeichnet Dateimetadaten für Kompatibilitätsentscheidungen auf. Der Hive-Pfad, das Datensatzformat, die vorgehaltene Kapazität und die Felder unterscheiden sich je nach Windows-Version. Unter modernen Windows-Versionen kann der ShimCache allein nicht beweisen, dass ein Benutzer eine Datei ausgeführt hat. Analysiere den relevanten `SYSTEM`-Hive mit dem Tool [**AppCompatCacheParser**](https://github.com/EricZimmerman/AppCompatCacheParser) und gleiche die Ausgabe mit Ausführungsartefakten ab.<sup>[[13]](#references)[[43]](#references)</sup>

![SRUM - AppCompatCache (ShimCache): Zum Parsen der gespeicherten Informationen wird die Verwendung des Tools AppCompatCacheParser empfohlen](<../../../images/image (75).png>)

### Amcache

Die Datei **Amcache.hve** ist ein Registry-Hive, der von Windows beobachtete Anwendungen und Dateien erfasst. Sie befindet sich typischerweise unter `C:\Windows\AppCompat\Programs\Amcache.hve`.

Sie kann zugehörige und nicht zugehörige Dateieinträge, Pfade und SHA1-Werte enthalten. Ihr Vorhandensein ist jedoch ein Inventarnachweis und beweist allein nicht, dass ein Prozess ausgeführt wurde.<sup>[[13]](#references)[[44]](#references)</sup>

Zum Extrahieren und Analysieren von **Amcache.hve** verwende das Tool [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser). Dieser Befehl parst den Hive und schreibt die Ausgabe im CSV-Format.<sup>[[44]](#references)</sup>

Zum Beispiel:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
Unter den generierten CSV-Dateien kann `Amcache_Unassociated file entries` bei der Untersuchung von Dateien hilfreich sein, die keinem erkannten Programm zugeordnet sind.<sup>[[44]](#references)</sup>

### RecentFileCache

Auf Windows-7-Systemen kann `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` Informationen über kürzlich beobachtete Binärdateien enthalten; Verfügbarkeit und Semantik sind versionsabhängig.

Sie können [**RecentFileCacheParser**](https://github.com/EricZimmerman/RecentFileCacheParser) verwenden, um die Datei zu analysieren.<sup>[[45]](#references)</sup>

### Geplante Tasks

Beweise für geplante Tasks können sich bei modernen Tasks in `C:\Windows\System32\Tasks` und bei Legacy-Tasks in `C:\Windows\Tasks` mit `.job`-Dateien befinden; untersuchen Sie das für das Betriebssystem geeignete Format der Taskdefinition.<sup>[[73]](#references)[[74]](#references)</sup>

### Services

Die Datenbank des Service Control Managers befindet sich unter `SYSTEM\CurrentControlSet\Services` (bei einer offline vorliegenden SYSTEM-Hive ist der entsprechende Control-Set-Schlüssel zu untersuchen); sie enthält die Konfiguration von Services und Treibern, etwa ausführbare Pfade und Starttypen.<sup>[[72]](#references)</sup>

### **Windows Store**

Installierte Windows-Store-Anwendungen können unter `\ProgramData\Microsoft\Windows\AppRepository\` repräsentiert sein, einschließlich der Datenbank **`StateRepository-Machine.srd`**. Schema und Pfade unterscheiden sich je nach Windows-Version.<sup>[[71]](#references)</sup>

Die Datenbank kann Anwendungsbezeichner, Paketnummern und Anzeigenamen enthalten. Lücken in den Bezeichnern sind für sich genommen kein Beweis dafür, dass eine Anwendung deinstalliert wurde; gleichen Sie dies mit dem Paket- und Registry-Status ab.

Paketregistrierungen können auch unter `HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\` erscheinen. Microsoft dokumentiert einen versionsspezifischen `Deprovisioned`-Unterschlüssel für entfernte bereitgestellte Apps; gehen Sie nicht davon aus, dass auf jedem Build ein `Deleted`-Unterschlüssel existiert.<sup>[[70]](#references)</sup>

## Windows-Ereignisse

Je nach Provider können Windows-Ereignisse Folgendes enthalten:

- Was geschehen ist
- Einen `TimeCreated`-Zeitstempel, der anhand des Ereignisschemas und des Zeitkontexts des Hosts interpretiert werden muss
- Beteiligte Benutzer
- Beteiligte Hosts (Hostname, IP)
- Zugegriffene Assets (Dateien, Ordner, Drucker oder Services).<sup>[[49]](#references)</sup>

Vor Windows Vista verwendeten Ereignisprotokolle im Allgemeinen das Legacy-Binärformat unter `C:\Windows\System32\config`; Vista und spätere Versionen verwenden das Windows-Event-Log-Format, normalerweise unter `C:\Windows\System32\winevt\Logs`, wobei `.evtx`-Dateien XML-dargestellte Ereignisdaten enthalten.<sup>[[46]](#references)[[47]](#references)</sup>

Die SYSTEM-Registry speichert die Kanalkonfiguration unter **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**, einschließlich des konfigurierten Dateipfads und der Aufbewahrungseinstellungen.<sup>[[47]](#references)</sup>

Sie können mit der Windows-Ereignisanzeige (**`eventvwr.msc`**) oder Tools wie [**Event Log Explorer**](https://eventlogxp.com) und [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md) angezeigt werden.<sup>[[5]](#references)[[48]](#references)[[61]](#references)</sup>

## Understanding Windows Security Event Logging

Unter Vista und späteren Versionen wird der Security-Kanal üblicherweise unter `C:\Windows\System32\winevt\Logs\Security.evtx` gespeichert. Seine maximale Größe und Aufbewahrungsrichtlinie sind konfigurierbar; bei zirkulärer Protokollierung können ältere Datensätze überschrieben werden, sobald die Datei ihr Limit erreicht. Der Kanal kann Authentifizierungs-, Abmelde-, Berechtigungs-, Audit-Policy- und Objektzugriffsereignisse aufzeichnen, wenn die entsprechende Überwachung aktiviert ist.<sup>[[46]](#references)[[47]](#references)</sup>

### Wichtige Event IDs für die Benutzerauthentifizierung:

- **Event ID 4624**: Eine erfolgreiche Kontoanmeldung.<sup>[[50]](#references)</sup>
- **Event ID 4625**: Eine fehlgeschlagene Kontoanmeldung.<sup>[[51]](#references)</sup>
- **Event ID 4634**: Eine Anmeldesitzung wurde beendet.<sup>[[52]](#references)</sup>
- **Event ID 4647**: Ein Benutzer hat eine Abmeldung eingeleitet.<sup>[[53]](#references)</sup>
- **Event ID 4672**: Einer neuen Anmeldung wurden spezielle Berechtigungen zugewiesen; dies ist bei System- und Administratorkonten üblich und daher für sich genommen kein Beweis für bösartige Aktivitäten.<sup>[[54]](#references)</sup>

#### Häufig in 4624, 4625, 4634 und 4647 aufgezeichnete Anmeldetypen:

- **Interactive (2)**: Eine interaktive lokale Anmeldung.
- **Network (3)**: Zugriff auf eine freigegebene Ressource.
- **Batch (4)**: Eine Batch-Prozess-Anmeldung.
- **Service (5)**: Eine Service-Anmeldung.
- **Unlock (7)**: Das Entsperren einer Workstation.
- **NetworkCleartext (8)**: Eine Netzwerkanmeldung, bei der Anmeldedaten im Klartext an das Authentifizierungspaket übermittelt werden.
- **NewCredentials (9)**: Eine Anmeldung, bei der bereitgestellte alternative Anmeldedaten für ausgehende Verbindungen verwendet werden.
- **RemoteInteractive (10)**: Eine Anmeldung über Remote Desktop oder Terminal Services.
- **CachedInteractive (11)**: Eine interaktive Anmeldung unter Verwendung zwischengespeicherter Domänenanmeldedaten.
- **CachedRemoteInteractive (12)**: Eine zwischengespeicherte Remote-Interactive-Anmeldung.
- **CachedUnlock (13)**: Ein Entsperren unter Verwendung zwischengespeicherter Anmeldedaten.<sup>[[50]](#references)[[51]](#references)</sup>

#### Status- und Substatuscodes für EventID 4625:

- **0xC0000064**: Kein solcher Benutzer.
- **0xC000006A**: Korrekteter Benutzername, aber falsches Passwort.
- **0xC0000234**: Konto gesperrt.
- **0xC0000072**: Konto deaktiviert.
- **0xC000006F**: Anmeldung außerhalb der erlaubten Zeiten.
- **0xC0000070**: Verstoß gegen eine Workstation-Einschränkung.
- **0xC0000193**: Konto abgelaufen.
- **0xC0000071**: Passwort abgelaufen.
- **0xC0000133**: Der Zeitunterschied zwischen Client und Server ist zu groß.
- **0xC0000224**: Das Konto muss sein Passwort ändern.
- **0xC0000225**: `STATUS_NOT_FOUND`; der Code allein weist weder auf einen Systemfehler noch auf einen Angriff hin.
- **0xC000015B**: Der angeforderte Anmeldetyp ist für das Konto nicht zulässig.<sup>[[51]](#references)[[55]](#references)</sup>

#### EventID 4616:

- **Time Change**: Die Systemzeit wurde geändert. Viele Ereignisse spiegeln eine routinemäßige Korrektur durch den Zeitdienst wider. Korrelieren Sie daher den Akteur und die Zeitquelle, bevor Sie dies als Manipulation betrachten.<sup>[[56]](#references)</sup>

#### Event IDs 12, 13, 1074, 6005, 6006, 6008 und 6009:

- **Power and service context**: Event 12 zeichnet den Start des Betriebssystems auf, 13 die Beendigung des Betriebssystems, 1074 eine geplante Beendigung oder einen geplanten Neustart, 6008 eine unerwartete Beendigung und 6009 die Windows-Version beim Booten. Die Events 6005 und 6006 zeigen an, dass der Event-Log-Service gestartet beziehungsweise beendet wurde; sie sind für sich genommen kein Beweis für den Start und die Beendigung des Betriebssystems.<sup>[[57]](#references)[[58]](#references)</sup>

#### EventID 1102:

- **Log Deletion**: Event 1102 zeichnet auf, dass das Security-Audit-Log geleert wurde; untersuchen Sie den Akteur und die umliegenden Ereignisse, statt allein aus diesem Event auf eine Absicht zu schließen.<sup>[[62]](#references)</sup>

#### EventIDs für USB-Geräteüberwachung:

- **20001 / 20003**: `UserPnp`-Ereignisse zur Geräteinstallation, die dabei helfen können, die erstmalige Nutzung oder Installationsaktivität festzustellen.
- **10000 / 10100**: `DriverFrameworks-UserMode`-Ereignisse, die mit Geräteaktivität einhergehen können.
- **Event ID 112**: `DeviceSetupManager/Admin`-Aktivität, die Zeitstempel im Zusammenhang mit dem Einstecken liefern kann.
- Provider, Kanal und Ereignissemantik unterscheiden sich je nach Windows-Version. Prüfen Sie den Providernamen und die Ereignisnutzdaten, bevor Sie eine Bedeutung zuweisen.<sup>[[59]](#references)</sup>

Praktische Beispiele zu Anmeldetypen und den zugehörigen Anmeldedaten finden Sie im [detaillierten Leitfaden von Altered Security](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).<sup>[[60]](#references)</sup>

Ereignisdetails, einschließlich Anmeldetyp, Status, Substatus, Quelladresse und Prozessfeldern, liefern Kontext für Event ID 4625; ein Statuscode oder ein wiederholtes Fehlermuster ist ein Ermittlungsansatz, keine Schlussfolgerung.<sup>[[51]](#references)[[55]](#references)</sup>

### Windows-Ereignisse wiederherstellen

Da Ereignisprotokolle üblicherweise zirkulär sind, können vom Logger überschriebenen Datensätze möglicherweise nicht wiederhergestellt werden. Sichern Sie ein forensisches Abbild oder eine Arbeitskopie, bevor Sie mit einem Live-System interagieren. Verwenden Sie einen validierten Parser oder Carver wie **Bulk_extractor** erst, nachdem Sie bestätigt haben, dass die Tool-Version die Ziel-`.evtx`-Daten unterstützt, und trennen Sie ein laufendes System nicht allein zum Versuch, Ereignisse wiederherzustellen.<sup>[[46]](#references)</sup>

### Häufige Angriffe anhand von Windows-Ereignissen identifizieren

Eine praktische Referenz zu Event IDs finden Sie im vorhandenen Link [Red Team Recipe](https://redteamrecipe.com/event-codes/). Validieren Sie dessen Beispiele anhand der oben genannten Provider-Dokumentation.

#### Brute-Force-Angriffe

Korrelieren Sie wiederholte fehlgeschlagene Event-ID-4625-Anmeldungen mit einem späteren Erfolg von 4624, dem Anmeldetyp, Status, der Quelle und dem Kontokontext. Die Sequenz ist ein Indikator für weitere Untersuchungen, kein Beweis für einen Angriff.<sup>[[50]](#references)[[51]](#references)</sup>

#### Zeitänderung

Event ID 4616 zeichnet Änderungen der Systemzeit auf, die eine Zeitleistenanalyse erschweren können; vergleichen Sie das Ereignis mit Zeitdienst- und Hostdaten.<sup>[[56]](#references)</sup>

#### USB-Geräteüberwachung

USB-Event-IDs sind providerspezifisch. Korrelieren Sie `UserPnp` 20001/20003, `DriverFrameworks-UserMode` 10000/10100 und `DeviceSetupManager/Admin` 112 mit SetupAPI- und Registry-Artefakten.<sup>[[17]](#references)[[59]](#references)</sup>

#### System-Energieereignisse

Verwenden Sie 12/13/1074/6008/6009 für den Kontext von Betriebssystemstart, Beendigung, Neustart und unerwarteter Stromversorgung; 6005/6006 markieren den Start beziehungsweise das Beenden des Event-Log-Services.<sup>[[57]](#references)[[58]](#references)</sup>

#### Löschen von Logs

Die Security Event ID 1102 zeichnet auf, dass das Security-Audit-Log geleert wurde, und sollte mit dem verantwortlichen Konto und Prozess korreliert werden.<sup>[[62]](#references)</sup>

## References

- [1] [Bereinigung von Windows Plug and Play](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)
- [2] [jonahacks.medium.com - Untersuchung gängiger Windows-Prozesse](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)
- [3] [Eine digitale forensische Betrachtung von Windows-10-Benachrichtigungen](https://iconline.ipleiria.pt/server/api/core/bitstreams/833e160a-e382-46b4-82ad-fb2c8c995d62/content)
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
- [17] [Einträge im SetupAPI-Geräteinstallationslog](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/setupapi-device-installation-log-entries)
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
- [28] [Größenlimits für Outlook-Datendateien konfigurieren](https://learn.microsoft.com/en-us/microsoft-365-apps/outlook/data-files/configure-size-limit-outlook-data-files)
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
- [39] [Technischer Überblick über Passwörter](https://learn.microsoft.com/en-us/windows-server/security/kerberos/passwords-technical-overview)
- [40] [PECmd](https://github.com/EricZimmerman/PECmd)
- [41] [Superfetch-Beweise](https://kb.binalyze.com/air/features/acquisition/supported-evidence/windows-collections-detail/superfetch)
- [42] [srum-dump](https://github.com/MarkBaggett/srum-dump)
- [43] [AppCompatCacheParser](https://github.com/EricZimmerman/AppCompatCacheParser)
- [44] [AmcacheParser](https://github.com/EricZimmerman/AmcacheParser)
- [45] [RecentFileCacheParser](https://github.com/EricZimmerman/RecentFileCacheParser)
- [46] [Dateiformat des Event Logs](https://learn.microsoft.com/en-us/windows/win32/eventlog/event-log-file-format)
- [47] [Eventlog-Registry-Schlüssel](https://learn.microsoft.com/en-us/windows/win32/eventlog/eventlog-key)
- [48] [Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.5)
- [49] [TimeCreated-Ereigniseigenschaft](https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-timecreated-systempropertiestype-element)
- [50] [Event 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624)
- [51] [Event 4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)
- [52] [Event 4634](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4634)
- [53] [Event 4647](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4647)
- [54] [Event 4672](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672)
- [55] [MS-ERREF: NTSTATUS-Werte](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55)
- [56] [Event 4616](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4616)
- [57] [Unerwartete Neustarts mithilfe von Systemereignisprotokollen beheben](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
- [58] [Fehlerbehebung beim Herunterfahren während eines Vorgangs](https://learn.microsoft.com/en-us/troubleshoot/windows-server/installing-updates-features-roles/troubleshoot-error-shutdown-in-process)
- [59] [Forensik von USB-Speichergeräten unter Windows 10](https://www.researchgate.net/publication/318514858_USB_Storage_Device_Forensics_for_Windows_10)
- [60] [Fantastische Windows-Anmeldetypen](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)
- [61] [Event Log Explorer](https://eventlogxp.com)
- [62] [Event 1102](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102)
- [63] [Moderator für Hintergrundaktivitäten](https://winreg-kb.readthedocs.io/en/latest/sources/system-keys/Background-activity-moderator.html)
- [64] [Registry - RecentApps](https://artefacts.help/windows_registry_recentapps.html)
- [65] [Schnelldruck beendet das Drucken von PDF-Anhängen in Outlook Desktop](https://support.microsoft.com/en-gb/office/quick-print-stops-printing-pdf-attachments-in-outlook-desktop-512fdeb0-6a88-4e6c-9285-cf957290aad2)
- [66] [Windows-Registry-Dateien](https://winreg-kb.readthedocs.io/en/latest/sources/windows-registry/Files.html)
- [67] [Kernel PST Viewer](https://www.nucleustechnologies.com/es/visor-de-pst.html)
- [68] [Kernel OST Viewer](https://www.nucleustechnologies.com/ost-viewer.html)
- [69] [RegQueryInfoKeyA](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryinfokeya)
- [70] [Verhindern, dass entfernte Apps während eines Updates zurückkehren](https://learn.microsoft.com/en-us/windows/application-management/remove-provisioned-apps-during-update)
- [71] [NIST CFTT: Testergebnisse von FTK und Registry Viewer](https://www.dhs.gov/sites/default/files/publications/test_results_nist_windows_registry_forensic_tool_ftk_7.0.0.163_registry_viewer_2.0.0.7_april_2019.pdf)
- [72] [Datenbank der installierten Services](https://learn.microsoft.com/en-us/windows/win32/services/database-of-installed-services)
- [73] [Tasks](https://learn.microsoft.com/en-us/windows/win32/taskschd/tasks)
- [74] [Geplante Tasks schlagen mit dem Fehler „Task Scheduler Service Is Not Available“ fehl](https://learn.microsoft.com/en-us/troubleshoot/windows-client/system-management-components/task-schedular-service-is-not-available)
- [75] [Navigation in der Windows-Mail-Datenbank](https://eprints.whiterose.ac.uk/133161/1/Navigating_the_Windows_Mail_database_accepted.pdf)
- [76] [RFC 5322: Internet-Nachrichtenformat](https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.4)
{{#include ../../../banners/hacktricks-training.md}}
