# Windows-Artefakte

{{#include ../../../banners/hacktricks-training.md}}

## Allgemeine Windows-Artefakte

### Windows 10-Benachrichtigungen

Die Benachrichtigungsdatenbank pro Benutzer befindet sich unter `%LOCALAPPDATA%\Microsoft\Windows\Notifications` (zum Beispiel `C:\Users\<username>\AppData\Local\Microsoft\Windows\Notifications`). Frühere Windows-10-Versionen verwendeten `appdb.dat`; mit dem Anniversary Update (1607) wurde `wpndatabase.db` eingeführt. Die SQLite-Datenbank enthält eine `Notification`-Tabelle mit Benachrichtigungsinhalten und Zeitangaben. Aufbewahrungsdauer und verfügbare Daten hängen jedoch von der Version und den Bereinigungsrichtlinien ab.<sup>[[3]](#references)</sup>

### Timeline

Windows Timeline ist eine Aktivitätsverlaufsfunktion, die Einträge zu unterstützten Anwendungen, Dokumenten und anderen Benutzeraktivitäten enthalten kann. Die Abdeckung hängt von der Anwendung und der Windows-Version ab.<sup>[[4]](#references)</sup>

Die Datenbank befindet sich unter `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Sie lässt sich mit SQLite öffnen oder mit [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) auswerten. Die Ausgabe kann mit [**Timeline Explorer**](https://ericzimmerman.github.io/#!index.md) überprüft werden.<sup>[[4]](#references)[[5]](#references)</sup>

### Windows Recall-Snapshots (Copilot+ PCs)

Recall ist auf unterstützten Windows 11 Copilot+ PCs optional. In aktuellen Builds werden Snapshots und ihr Index mit Schlüsseln verschlüsselt, die an Windows Hello und eine VBS-Enklave gebunden sind. Eine Offline-Kopie des Speichers sollte nicht als Klartext-SQLite-Datenbank behandelt werden; die Vorschau von 2024 und das veröffentlichte Design weisen unterschiedliche Zugriffsmöglichkeiten auf.<sup>[[77]](#references)</sup>

Bei einer **aktiven Recall-Sitzung** ist der Rendering-Prozess `AIXHost.exe` desselben Benutzers eine andere Zugriffsmöglichkeit. Der Proof of Concept TotalRecall Reloaded injiziert eine DLL in diesen Prozess und ruft dessen Recall-COM-Schnittstellen auf. Für die Extraktion des gesamten Verlaufs muss sich der Benutzer weiterhin mit Windows Hello authentifizieren; dies ist weder eine Offline-Entschlüsselung noch eine Umgehung von Hello. Der Forscher dokumentierte das Tool unter Windows 11 ARM64. Prüfe daher die Kompatibilität mit dem Ziel-Build, bevor du dich darauf verlässt.<sup>[[78]](#references)[[77]](#references)</sup>

```powershell
totalrecall.exe --preauth  # Most recent capture and settings; no Hello prompt
totalrecall.exe --wait     # Wait for the user to open Recall and authenticate
```

`--preauth` verwendet `GetRecentCaptureThumbnail`, um ohne Hello eine große Version der neuesten Aufnahme anzufordern. Nach der Autorisierung kann `--wait` Screenshots, OCR-Text und Metadaten zu einzelnen Aufnahmen extrahieren, einschließlich Anwendung und Fensterkontext. Die Ausgabe wird in einem Verzeichnis namens `extraction_*` mit Zeitstempel gespeichert. Diese Erkenntnisse stammen aus dem Proof of Concept und sind abhängig vom Build. Sie garantieren weder, dass Recall aktiviert ist, noch, dass jeder Bildschirm erfasst wurde.<sup>[[78]](#references)</sup>

### ADS (Alternate Data Streams)

Dateien, die von außerhalb der lokalen Vertrauensgrenze heruntergeladen werden, können den alternativen Datenstrom **`Zone.Identifier`** enthalten. Dieser speichert Zoneninformationen und kann Herkunftsmetadaten wie eine URL enthalten. Ob er vorhanden ist und welche Felder er enthält, hängt vom Ersteller und den Systemrichtlinien ab.<sup>[[6]](#references)</sup>

## **Dateisicherungen**

### Papierkorb

Unter Vista und späteren Versionen befindet sich der **Papierkorb** im Ordner **`$Recycle.bin`** im Stammverzeichnis des Laufwerks (zum Beispiel `C:\$Recycle.bin`).\
Wenn eine Datei in diesem Ordner gelöscht wird, werden zwei bestimmte Dateien erstellt:

- `$I{id}`: Datei-Informationen, einschließlich Löschzeitpunkt und ursprünglichem Pfad
- `$R{id}`: Inhalt der Datei

![Dateisicherungen - Papierkorb: $R{id}: Inhalt der Datei](<../../../images/image (1029).png>)

Mit diesen Dateien kannst du [**Rifiuti2**](https://github.com/abelcheung/rifiuti2) verwenden, um den ursprünglichen Pfad und den Löschzeitpunkt zu extrahieren (verwende die Version, die zur Windows-Version des Ziels passt).<sup>[[7]](#references)</sup>

```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```

![Dateisicherungen – Papierkorb: rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### Volume Shadow Copies

Der Volume Shadow Copy Service (VSS) kann zeitpunktbezogene Schattenkopien von Volumes erstellen, während Dateien verwendet werden; eine Schattenkopie ist kein Ersatz für ein forensisches Abbild.<sup>[[8]](#references)</sup>

Die Metadaten der Kopien sind normalerweise `\System Volume Information` im Stammverzeichnis des Volumes zugeordnet; die Bezeichner variieren je nach System:

![Papierkorb – Volume Shadow Copies: Diese Sicherungen befinden sich üblicherweise in System Volume Information im Stammverzeichnis des Dateisystems. Der Name besteht aus UIDs, die in der...](<../../../images/image (94).png>)

Nach dem Einbinden eines Abbilds mit einem geeigneten forensischen Einbindungsprogramm kann [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) verfügbare VSS-Snapshots auflisten und Dateien darin durchsuchen oder kopieren.<sup>[[9]](#references)</sup>

![Papierkorb – Volume Shadow Copies: Nach dem Einbinden des forensischen Abbilds mit ArsenalImageMounter kann das Tool ShadowCopyView verwendet werden, um eine Schattenkopie zu untersuchen und sogar Dateien daraus zu extrahieren...](<../../../images/image (576).png>)

Die Konfiguration des VSS-Registry-Writers umfasst `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore`, wo Dateien und Schlüssel angegeben werden können, die von der Sicherung ausgeschlossen sind:<sup>[[10]](#references)[[11]](#references)</sup>

![Papierkorb – Volume Shadow Copies: Der Registry-Eintrag HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore enthält die Dateien und Schlüssel, die nicht gesichert werden sollen](<../../../images/image (254).png>)

Der Schlüssel `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` enthält ebenfalls die Konfiguration des VSS-Dienstes.<sup>[[8]](#references)</sup>

### Automatisch gespeicherte Office-Dateien

Die AutoRecover-Speicherorte variieren je nach Office-Anwendung, Version und Konfiguration. Für Word nennt Microsoft `%APPDATA%\Microsoft\Word` als Standardspeicherort; prüfen Sie in den Anwendungseinstellungen den aktuell verwendeten Pfad.<sup>[[12]](#references)</sup>

## Shell-Elemente

Ein Shell-Element enthält Informationen zum Zugriff auf eine andere Datei.

### Zuletzt verwendete Dokumente (LNK)

Windows erstellt häufig Verknüpfungen zu zuletzt verwendeten Elementen, wenn ein Benutzer ein Element öffnet oder anderweitig darauf zugreift:

- Win7-Win10: `%APPDATA%\Microsoft\Windows\Recent\`
- Office: `%APPDATA%\Microsoft\Office\Recent\`

Beim Zugriff auf einen Ordner können auch Verknüpfungen zum Ordner und zu übergeordneten Ordnern erstellt werden.

Diese Verknüpfungsdateien können den Zieltyp, die MAC-Zeitstempel des Ziels, Volume-Informationen und den Zielpfad enthalten. Diese Metadaten können dabei helfen, ein entferntes Ziel zu identifizieren, doch das Artefakt allein beweist nicht, dass ein bestimmter Benutzer das Ziel geöffnet hat.<sup>[[13]](#references)[[14]](#references)</sup>

Die Dateisystem-Zeitstempel der LNK-Datei selbst und die darin eingebetteten Zeitstempel des Ziels sind voneinander unabhängig. Interpretieren Sie die Erstellung der Verknüpfung nicht ohne weitere bestätigende Artefakte als erste Verwendung und ihre Änderung nicht als letzte Verwendung; das Format speichert die Zeitstempel des Ziels getrennt von denen der Verknüpfungsdatei.<sup>[[13]](#references)[[14]](#references)</sup>

Der vorhandene Verweis auf [**LinkParser**](http://4discovery.com/our-tools/) bleibt als historische Option erhalten, die Dokumentation war während der Überprüfung jedoch nicht verfügbar. Für einen dokumentierten Parser für die Befehlszeile verwenden Sie [**LECmd**](https://github.com/EricZimmerman/LECmd).<sup>[[15]](#references)</sup>

Diese Tools zeigen üblicherweise zwei Gruppen von Zeitstempeln an:

- **Zeitstempel des Ziels:**
  1. FileModifiedDate
  2. FileAccessDate
  3. FileCreationDate
- **Zeitstempel der Verknüpfungsdatei:**
  1. LinkModifiedDate
  2. LinkAccessDate
  3. LinkCreationDate.

Die erste Gruppe bezieht sich auf das Ziel, die zweite auf die LNK-Datei selbst. Interpretieren Sie beide Gruppen anhand der Dokumentation des Parsers und des Dateisystemkontexts.<sup>[[14]](#references)[[15]](#references)</sup>

Dieselben Informationen erhalten Sie, indem Sie das Windows-CLI-Tool [**LECmd.exe**](https://github.com/EricZimmerman/LECmd) ausführen.<sup>[[15]](#references)</sup>

```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```

In diesem Fall werden die Informationen in einer CSV-Datei gespeichert.

### Jumplists

Jump Lists sind anwendungsspezifische Listen mit zuletzt verwendeten oder aufgabenbezogenen Elementen und können automatisch oder benutzerdefiniert sein.<sup>[[13]](#references)</sup>

Automatische Jump Lists werden unter `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` gespeichert. Sie verwenden Namen wie `{id}.automaticDestinations-ms`, wobei die ID die Anwendung identifiziert.

Benutzerdefinierte Jump Lists werden unter `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\` gespeichert. Die Anwendung steuert, welche Aufgaben- oder Elemente-Einträge sie erstellt.

Die Erstellungs- und Änderungszeiten des Dateisystems beziehen sich auf die Jump-List-Datei, nicht automatisch auf den ersten und letzten Zugriff auf jedes aufgeführte Ziel. Gleichen Sie geparste Einträge mit den Zeitstempeln der Datei und anderen Artefakten ab.<sup>[[13]](#references)</sup>

Sie können die Jump Lists mit [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md) untersuchen.<sup>[[5]](#references)</sup>

![Zuletzt verwendete Dokumente (LNK) - Jumplists: Mit JumplistExplorer können Sie die Jumplists untersuchen](<../../../images/image (168).png>)

(_Beachten Sie, dass sich die von JumplistExplorer angegebenen Zeitstempel auf die Jumplist-Datei selbst beziehen._)

### Shellbags

[**Folgen Sie diesem Link, um zu erfahren, was Shellbags sind.**](interesting-windows-registry-keys.md#shellbags)

## Verwendung von Windows-USB-Geräten

Die Verwendung von USB-Geräten lässt sich manchmal durch Artefakte bestätigen, die beim Zugriff auf Dateien von Wechselmedien erstellt werden. Dazu gehören:

- Windows-Ordner „Recent“
- Ordner „Microsoft Office Recent“
- Jumplists

Tools wie [**USBDetective**](https://usbdetective.com) gleichen diese Artefakte mit USB-Geräteaufzeichnungen ab. Welche Artefakte verfügbar sind, hängt jedoch von der Windows-Version und der Anwendung ab.<sup>[[18]](#references)</sup>

Bei Tests, die für MTP-Workflows unter Windows XP und Windows 7 dokumentiert wurden, verwiesen einige LNK-Dateien auf einen `WPDNSE`-Ordner statt auf den ursprünglichen Pfad.<sup>[[16]](#references)</sup>

![Shellbags - Verwendung von Windows-USB-Geräten: Beachten Sie, dass einige LNK-Dateien statt auf den ursprünglichen Pfad auf den WPDNSE-Ordner verweisen](<../../../images/image (218).png>)

In dieser Studie wurden Kopien unter `%LOCALAPPDATA%\Temp\WPDNSE\{FolderGUID}` beobachtet. Die temporären Inhalte blieben in den Tests nach einem Neustart nicht erhalten, und die GUID ließ sich mit Shellbag-Daten abgleichen. Betrachten Sie dies als ein vom Betriebssystem, Gerät und der Anwendung abhängiges Verhalten und nicht als allgemeingültige Regel.<sup>[[16]](#references)</sup>

### Registrierungsinformationen

[Auf dieser Seite erfahren Sie](interesting-windows-registry-keys.md#usb-information), welche Registrierungsschlüssel interessante Informationen zu angeschlossenen USB-Geräten enthalten.

### setupapi

Untersuchen Sie unter Vista und späteren Versionen `C:\Windows\inf\setupapi.dev.log` auf Aktivitäten zur Geräteinstallation. Abschnittsüberschriften enthalten Zeitstempel für `Section start`. Sie dokumentieren die Setup-Verarbeitung und sollten mit anderen Verbindungsnachweisen abgeglichen werden, statt als exakter Zeitpunkt des physischen Anschließens behandelt zu werden.<sup>[[17]](#references)</sup>

![Registrierungsinformationen - setupapi: Prüfen Sie die Datei C: Windows inf setupapi.dev.log auf Zeitstempel, die angeben, wann die USB-Verbindung hergestellt wurde (suchen Sie nach Section start)](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

Mit [**USBDetective**](https://usbdetective.com) können Informationen zu USB-Geräten ermittelt werden, die mit einem Image verbunden waren.<sup>[[18]](#references)</sup>

![setupapi - USB Detective: Mit USBDetective können Informationen zu USB-Geräten ermittelt werden, die mit einem Image verbunden waren](<../../../images/image (452).png>)

### Plug and Play Cleanup

Die geplante Aufgabe `Plug and Play Cleanup` entfernt veraltete Treiberversionen. Eine von Adam Harrison dokumentierte Aufgabendefinition für Windows 10 zielt außerdem auf Treiber ab, die 30 Tage lang inaktiv waren. Daher können Nachweise zu Treibern von Wechselgeräten bereinigt werden. Überprüfen Sie die lokale Aufgabendefinition und den Windows-Build, bevor Sie dieses Verhalten verallgemeinern.<sup>[[1]](#references)</sup>

Die Aufgabe befindet sich unter folgendem Pfad: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

![XML-Definition der geplanten Windows-Aufgabe Plug and Play Cleanup](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Wichtige Komponenten und Einstellungen der Aufgabe:**

- **pnpclean.dll**: Diese DLL ist für den eigentlichen Bereinigungsvorgang verantwortlich.
- **UseUnifiedSchedulingEngine**: Auf `TRUE` gesetzt; dies weist auf die Verwendung der allgemeinen Aufgabenplanungs-Engine hin.
- **MaintenanceSettings**:
  - **Period ('P1M')**: Weist den Aufgabenplaner an, die Bereinigungsaufgabe während der regulären automatischen Wartung monatlich zu starten.
  - **Deadline ('P2M')**: Weist den Aufgabenplaner an, die Aufgabe während der automatischen Notfallwartung auszuführen, wenn sie zwei Monate in Folge fehlschlägt.

Diese Konfiguration plant regelmäßige Wartung und erneute Versuche nach aufeinanderfolgenden Fehlern. Die genaue XML-Definition und das Verhalten hängen von der Version ab.<sup>[[1]](#references)</sup>

**Weitere Informationen finden Sie unter:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html).<sup>[[1]](#references)</sup>

## E-Mails

E-Mails enthalten **2 interessante Bestandteile: die Header und den Inhalt** der E-Mail. In den **Headern** finden Sie Informationen wie:

- **Wer** die E-Mails gesendet hat (E-Mail-Adresse, IP, Mailserver, über die die E-Mail weitergeleitet wurde)
- **Wann** die E-Mail gesendet wurde

Auch die Header `References` und `In-Reply-To` können Nachrichten-IDs enthalten, mit denen sich Antworten einer Unterhaltung zuordnen lassen.<sup>[[76]](#references)</sup>

![Plug and Play Cleanup - E-Mails: Wann wurde die E-Mail gesendet](<../../../images/image (593).png>)

### Windows Mail App

Diese Anwendung speichert E-Mail-Inhalte in zusätzlichen Text- oder HTML-Dateien unter Pfaden wie `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`. Die genaue Nummerierung der Ordner und Dateien kann je nach Artefakt variieren.<sup>[[75]](#references)</sup>

Die **Metadaten** der E-Mails und die **Kontakte** befinden sich in der **ESE-Datenbank** `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`.<sup>[[75]](#references)</sup>

`store.vol` verwendet das Extensible Storage Engine (ESE)-Format. Arbeiten Sie mit einer Kopie und verwenden Sie einen ESE-Parser wie [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html). Wenn ein Tool die Erweiterung `.edb` voraussetzt, benennen Sie nur die Kopie um und überprüfen Sie das Tabellenschema, bevor Sie sich auf eine Tabelle namens `Message` verlassen.<sup>[[19]](#references)[[75]](#references)</sup>

### Microsoft Outlook

Bei der Untersuchung von Outlook-MAPI-Eigenschaften sind folgende kanonische Eigenschaften relevant:

- `PidTagClientSubmitTime`: der UTC-Zeitpunkt, zu dem der Client die Nachricht übermittelt hat.
- `PidTagConversationIndex`: die relative Position der Nachricht in einem Unterhaltungsverlauf.
- `PidTagEntryId`: eine Kennung des Nachrichtenobjekts.
- `PidTagMessageFlags`: Statusflags, etwa für übermittelt, gelesen, ungelesen oder mit Anhängen.
- `PidTagLastVerbExecuted`: der zuletzt für die Nachricht aufgezeichnete Vorgang, etwa Öffnen, Antworten oder Weiterleiten.<sup>[[20]](#references)[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Die Speicherorte von Outlook-Datendateien variieren je nach Version und Kontotyp. Microsoft nennt folgende gängige Speicherorte für PST-/OST-Dateien:

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

Der Registrierungspfad `HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` kann das Outlook-Profil und die zugehörige Konfiguration der Datendateien identifizieren.

PST-Dateien können Nachrichten, Kontakte, Kalenderdaten und andere Outlook-Elemente enthalten. Sie können eine Kopie mit [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html) untersuchen.<sup>[[25]](#references)[[67]](#references)</sup>

![Windows Mail App - Microsoft Outlook: Mit dem Tool Kernel PST Viewer können Sie die PST-Datei öffnen](<../../../images/image (498).png>)

### Microsoft Outlook OST Files

Eine **OST-Datei** ist ein lokaler Cache für Exchange- oder Microsoft 365-Konten. Der Exchange-Cache-Modus gilt nicht für POP- oder IMAP-Konten. Der Offlinezeitraum ist konfigurierbar und beträgt standardmäßig häufig 12 Monate. Die Größenbeschränkungen für PST-/OST-Dateien sind davon unabhängig und ebenfalls konfigurierbar. Zum Anzeigen einer OST-Datei kann der [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html) verwendet werden.<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[68]](#references)</sup>

### Anhänge wiederherstellen

Verlorene Anhänge können möglicherweise wiederhergestellt werden aus:

- Älteren Outlook-/IE-Konfigurationen: `%LOCALAPPDATA%\Temporary Internet Files\Content.Outlook`
- Neueren Outlook-/IE11-Konfigurationen: `%LOCALAPPDATA%\Microsoft\Windows\INetCache\Content.Outlook`.<sup>[[65]](#references)</sup>

### Thunderbird-MBOX-Dateien

**Thunderbird** speichert Profildaten unter `%APPDATA%\Thunderbird\Profiles`. E-Mail-Ordner verwenden häufig Dateien ohne Erweiterung im mbox-Format, die sich in kontospezifischen Verzeichnissen namens `Mail` oder `ImapMail` befinden.<sup>[[29]](#references)[[30]](#references)</sup>

### Miniaturansichten von Bildern

- **Windows XP**: Vorschauen von Miniaturansichten wurden häufig in `thumbs.db`-Dateien pro Ordner gespeichert.
- **Netzwerkordner**: Für einen UNC-Ordner kann weiterhin eine `thumbs.db`-Datei erstellt werden, wenn das entsprechende Verhalten für Miniaturansichten aktiviert ist. Gehen Sie nicht davon aus, dass jede Windows-Version oder Richtlinie eine solche Datei erstellt.
- **Windows Vista und neuer**: Der Systemcache für Miniaturansichten befindet sich zentral unter `%USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer` und enthält Dateien wie **thumbcache_xxx.db**. [**Thumbsviewer**](https://thumbsviewer.github.io) kann ältere `Thumbs.db`-Dateien parsen, während [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) moderne Datenbanken für Miniaturansichten parsen kann.<sup>[[31]](#references)[[32]](#references)[[33]](#references)</sup>

### Informationen zur Windows-Registrierung

Die Windows-Registrierung speichert System- und Benutzerkonfigurationsdaten in Hive-Dateien an folgenden Speicherorten:

- `%WINDIR%\System32\Config` für die Computer-Hives, die verschiedenen `HKEY_LOCAL_MACHINE`-Unterschlüsseln zugrunde liegen.
- `%USERPROFILE%\NTUSER.DAT` für den `HKEY_CURRENT_USER`-Hive eines Benutzers.
- Einige ältere Windows-Installationen enthalten Kopien unter `%WINDIR%\System32\Config\RegBack\`. Ab Windows 10, Version 1803, wird dieses Verzeichnis nicht mehr automatisch befüllt, sofern keine regelmäßige Sicherung aktiviert ist.<sup>[[34]](#references)[[35]](#references)</sup>
- Daten zu Benutzer-Shells und Klassenregistrierungen werden unter modernen Windows-Versionen häufig ebenfalls in `%LOCALAPPDATA%\Microsoft\Windows\UsrClass.dat` gespeichert.<sup>[[34]](#references)[[66]](#references)</sup>

### Tools

Einige Tools eignen sich zur Analyse von Registrierungs-Hives. Überprüfen Sie vor der Verwendung einer Ausgabe, welche Hive-Formate und Versionen das jeweilige Tool unterstützt:

- **Registry Editor**: Ist in Windows installiert. Über diese GUI können Sie die Windows-Registrierung der aktuellen Sitzung durchsuchen.
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): Damit können Sie die Registrierungsdatei laden und über eine GUI durchsuchen. Außerdem enthält das Tool Lesezeichen, die auf Schlüssel mit interessanten Informationen hinweisen.
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): Dieses Tool bietet ebenfalls eine GUI zum Durchsuchen der geladenen Registrierung und enthält Plugins, die interessante Informationen darin hervorheben.
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): Eine weitere GUI-Anwendung, die Informationen aus einem geladenen Registrierungs-Hive extrahieren kann.<sup>[[5]](#references)[[36]](#references)[[37]](#references)</sup>

### Gelöschte Elemente wiederherstellen

Gelöschte Hive-Zellen können erhalten bleiben, bis ihr Speicherplatz wiederverwendet wird. Die Wiederherstellung hängt jedoch vom Zustand des Hives und vom Parser ab. Betrachten Sie wiederhergestellte gelöschte Schlüssel als Nachweise, die validiert werden müssen, und nicht als garantiert vollständige Datensätze.

### Zeitpunkt der letzten Änderung

Registrierungsschlüssel enthalten einen Zeitstempel der letzten Änderung. Windows stellt diesen für den Schlüssel oder einen seiner Wert-Einträge bereit. Ein Wert hat daher nicht notwendigerweise einen eigenen, unabhängigen Änderungszeitstempel.<sup>[[69]](#references)</sup>

### SAM

Der **SAM**-Hive enthält lokale Benutzer- und Gruppenaccount-Daten, einschließlich Passwort-Hashes, die durch das Boot-Key-Material des Systems geschützt sind.<sup>[[38]](#references)[[39]](#references)</sup>

Unter `SAM\Domains\Account\Users` können Sie Konto-IDs sowie einige Anmelde- und Richtlinienfelder abrufen. Für die Offline-Extraktion von Hashes wird außerdem der `SYSTEM`-Hive benötigt, um das entsprechende Boot-Key-Material wiederherzustellen.<sup>[[38]](#references)[[39]](#references)</sup>

### Interessante Einträge in der Windows-Registrierung


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Ausgeführte Programme

### Grundlegende Windows-Prozesse

Ein vorhandener [Beitrag zu häufigen Windows-Prozessen](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) dient als weiterführende Lektüre. Gleichen Sie Behauptungen zum Prozessverhalten mit aktueller Windows-Dokumentation und lokalen Nachweisen ab.<sup>[[2]](#references)</sup>

### Zuletzt verwendete Windows-Apps

Unter Windows-10-Versionen, die diesen Artefakt bereitstellen, enthält `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps` Unterschlüssel pro Anwendung mit Feldern wie dem Zeitpunkt der letzten Verwendung und der Anzahl der Starts. In späteren Versionen wurde das Artefakt entfernt. Überprüfen Sie daher den Ziel-Build.<sup>[[64]](#references)</sup>

### BAM (Background Activity Moderator)

Untersuchen Sie auf Systemen, die den Background Activity Moderator bereitstellen, den Pfad `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` oder den neueren Pfad `...\bam\State\UserSettings\{SID}`. Die Werte sind nach Benutzer-SID indiziert und können überwachte ausführbare Dateipfade sowie Ausführungsdaten im FILETIME-ähnlichen Format enthalten. Das Artefakt ist versionsabhängig und sollte durch andere Nachweise bestätigt werden.<sup>[[63]](#references)</sup>

### Windows Prefetch

Prefetching speichert Ressourcen und Startmetadaten zwischen, damit Programme schneller gestartet werden können.

Prefetch-Dateien werden als `.pf`-Dateien unter `C:\Windows\Prefetch` gespeichert. Format, Aufbewahrungsdauer und Dateianzahlbegrenzungen variieren je nach Windows-Version. Microsoft dokumentiert für Windows 8 und höher die Aufbewahrung der letzten acht Ausführungszeitpunkte und von bis zu 1024 Dateien. Ältere Zusammenfassungen mit festen Grenzwerten sollten daher nicht verallgemeinert werden.<sup>[[13]](#references)</sup>

Der Dateiname hat üblicherweise das Format `{program_name}-{hash}.pf`. Der Hash wird aus dem Ausführungskontext, etwa Pfad und Argumenten, abgeleitet. Windows 10 und höher können die Datei komprimieren. Das Vorhandensein ist ein nützlicher Ausführungsnachweis, beweist für sich genommen jedoch nicht, dass ein Benutzer das Programm ausgeführt hat. Es sollte mit anderen Artefakten abgeglichen werden.<sup>[[13]](#references)</sup>

Zum Untersuchen dieser Dateien können Sie [**PECmd.exe**](https://github.com/EricZimmerman/PECmd) verwenden. Das Tool dokumentiert das Parsen von Verzeichnissen, die CSV-/HTML-Ausgabe und die Dekomprimierung unterstützter Windows-10-Prefetch-Dateien.<sup>[[40]](#references)</sup>

```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```

![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

**Superfetch/SysMain** ergänzt Prefetch, indem es historische Nutzungsmuster nutzt, um das Laden zu verbessern. Auf Systemen, die solche Dateien erstellen, befinden sich die Datenbankdateien üblicherweise unter `C:\Windows\Prefetch\Ag*.db`; Format und Vorhandensein sind versionsabhängig.<sup>[[41]](#references)</sup>

Diese Datenbanken können Anwendungsnamen, Nutzungshäufigkeiten, aufgerufene Dateien oder Volumes, Pfade und Zeiträume enthalten, sollten aber nicht als exaktes Ausführungsprotokoll betrachtet werden.<sup>[[41]](#references)</sup>

Der vorhandene Link zu [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) bleibt als möglicher Parser erhalten. Prüfen Sie vor der Verwendung anhand der Dokumentation des Tools, ob es aktuell verfügbar ist und welche Ausgabeformate unterstützt werden.

### SRUM

**System Resource Usage Monitor** (SRUM) zeichnet die Ressourcennutzung durch Anwendungen und Benutzer auf. Es wurde mit Windows 8 eingeführt und speichert Daten in der ESE-Datenbank `C:\Windows\System32\sru\SRUDB.dat`.<sup>[[13]](#references)</sup>

Es liefert die folgenden Informationen:

- AppID und Pfad
- Dem Datensatz zugeordneter Benutzer/SID
- Gesendete Bytes
- Empfangene Bytes
- Netzwerkschnittstelle
- Verbindungsdauer
- Prozessdauer

Erfassungsintervall und Aufbewahrungsdauer hängen von der Implementierung ab; nehmen Sie nicht an, dass jeder Datensatz ein exaktes Ausführungsintervall von 60 Minuten darstellt.<sup>[[13]](#references)</sup>

Sie können Daten mit [**srum_dump**](https://github.com/MarkBaggett/srum-dump) extrahieren und prüfen. Verwenden Sie dabei die Optionen, die in der Dokumentation der aktuellen Toolversion beschrieben sind.<sup>[[42]](#references)</sup>

```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -o C:\Users\student\Desktop\srum --NO_CONFIRM
```

### AppCompatCache (ShimCache)

Der **AppCompatCache**, auch bekannt als **ShimCache**, ist Teil der Windows-Infrastruktur für Anwendungskompatibilität und zeichnet Dateimetadaten für Kompatibilitätsentscheidungen auf. Der Pfad der Hive, das Datensatzformat, die gespeicherte Kapazität und die Felder variieren je nach Windows-Version; unter modernen Windows-Versionen kann ShimCache allein nicht beweisen, dass ein Benutzer eine Datei ausgeführt hat. Parse die relevante `SYSTEM`-Hive mit dem Tool [**AppCompatCacheParser**](https://github.com/EricZimmerman/AppCompatCacheParser) und gleiche die Ausgabe mit Ausführungsartefakten ab.<sup>[[13]](#references)[[43]](#references)</sup>

![SRUM - AppCompatCache (ShimCache): Zum Parsen der gespeicherten Informationen wird die Verwendung des Tools AppCompatCacheParser empfohlen](<../../../images/image (75).png>)

### Amcache

Die Datei **Amcache.hve** ist eine Registrierungs-Hive, in der Windows Anwendungen und Dateien erfasst, die vom System beobachtet wurden. Sie befindet sich üblicherweise unter `C:\Windows\AppCompat\Programs\Amcache.hve`.

Sie kann zugeordnete und nicht zugeordnete Dateieinträge, Pfade und SHA1-Werte enthalten. Ihr Vorhandensein ist jedoch ein Inventarnachweis und beweist für sich allein nicht, dass ein Prozess ausgeführt wurde.<sup>[[13]](#references)[[44]](#references)</sup>

Verwende zum Extrahieren und Analysieren von **Amcache.hve** das Tool [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser). Dieser Befehl parst die Hive und schreibt die Ausgabe im CSV-Format.<sup>[[44]](#references)</sup>

Zum Beispiel:

```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```

Unter den erzeugten CSV-Dateien kann `Amcache_Unassociated file entries` bei der Untersuchung von Dateien hilfreich sein, die keinem erkannten Programm zugeordnet sind.<sup>[[44]](#references)</sup>

### RecentFileCache

Auf Windows-7-Systemen kann `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` Informationen über kürzlich beobachtete Binärdateien enthalten; Verfügbarkeit und Bedeutung hängen von der Version ab.

Mit [**RecentFileCacheParser**](https://github.com/EricZimmerman/RecentFileCacheParser) können Sie die Datei auswerten.<sup>[[45]](#references)</sup>

### Geplante Tasks

Belege zu geplanten Tasks können bei modernen Tasks unter `C:\Windows\System32\Tasks` und bei älteren Tasks in `.job`-Dateien unter `C:\Windows\Tasks` zu finden sein; untersuchen Sie das für das jeweilige Betriebssystem passende Format der Taskdefinition.<sup>[[73]](#references)[[74]](#references)</sup>

### Dienste

Die Datenbank des Service Control Manager befindet sich unter `SYSTEM\CurrentControlSet\Services` (bei einer offline eingebundenen SYSTEM-Hive untersuchen Sie den entsprechenden Control-Set-Schlüssel). Sie enthält Konfigurationen für Dienste und Treiber, etwa ausführbare Pfade und Starttypen.<sup>[[72]](#references)</sup>

### **Windows Store**

Installierte Windows-Store-Anwendungen können unter `\ProgramData\Microsoft\Windows\AppRepository\` erfasst sein, einschließlich der Datenbank **`StateRepository-Machine.srd`**. Schema und Pfade unterscheiden sich je nach Windows-Version.<sup>[[71]](#references)</sup>

Die Datenbank kann Anwendungskennungen, Paketnummern und Anzeigenamen enthalten. Lücken bei den Kennungen sind für sich genommen kein Beleg dafür, dass eine Anwendung deinstalliert wurde; gleichen Sie die Angaben mit dem Paket- und Registrierungsstatus ab.

Paketregistrierungen können auch unter `HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\` erscheinen. Microsoft dokumentiert für entfernte bereitgestellte Apps einen versionsspezifischen `Deprovisioned`-Unterschlüssel; gehen Sie nicht davon aus, dass auf jedem Build ein `Deleted`-Unterschlüssel vorhanden ist.<sup>[[70]](#references)</sup>

## Windows-Ereignisse

Je nach Provider können Windows-Ereignisse Folgendes enthalten:

- Was passiert ist
- Einen `TimeCreated`-Zeitstempel, der anhand des Ereignisschemas und des Zeitkontexts des Hosts interpretiert werden muss
- Beteiligte Benutzer
- Beteiligte Hosts (Hostname, IP)
- Aufgerufene Ressourcen (Dateien, Ordner, Drucker oder Dienste).<sup>[[49]](#references)</sup>

Vor Windows Vista verwendeten Ereignisprotokolle im Allgemeinen das ältere Binärformat unter `C:\Windows\System32\config`. Vista und neuere Versionen verwenden das Windows-Ereignisprotokollformat, normalerweise unter `C:\Windows\System32\winevt\Logs`, wobei `.evtx`-Dateien XML-gerenderte Ereignisdaten enthalten.<sup>[[46]](#references)[[47]](#references)</sup>

Die SYSTEM-Registrierung speichert die Kanalkonfiguration unter **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**, einschließlich des konfigurierten Dateipfads und der Aufbewahrungseinstellungen.<sup>[[47]](#references)</sup>

Sie können mit der Windows-Ereignisanzeige (**`eventvwr.msc`**) oder Tools wie [**Event Log Explorer**](https://eventlogxp.com) und [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md) angezeigt werden.<sup>[[5]](#references)[[48]](#references)[[61]](#references)</sup>

## Windows-Sicherheitsereignisprotokollierung verstehen

Unter Vista und neueren Versionen wird der Security-Kanal üblicherweise unter `C:\Windows\System32\winevt\Logs\Security.evtx` gespeichert. Seine maximale Größe und Aufbewahrungsrichtlinie sind konfigurierbar; bei zyklischer Protokollierung können ältere Einträge überschrieben werden, sobald die Datei ihre Größenbegrenzung erreicht. Wenn die entsprechende Überwachung aktiviert ist, kann der Kanal Authentifizierungs-, Abmelde-, Berechtigungs-, Überwachungsrichtlinien- und Objektzugriffsereignisse aufzeichnen.<sup>[[46]](#references)[[47]](#references)</sup>

### Wichtige Event-IDs für die Benutzerauthentifizierung:

- **Event ID 4624**: Eine Kontoanmeldung war erfolgreich.<sup>[[50]](#references)</sup>
- **Event ID 4625**: Eine Kontoanmeldung ist fehlgeschlagen.<sup>[[51]](#references)</sup>
- **Event ID 4634**: Eine Anmeldesitzung wurde beendet.<sup>[[52]](#references)</sup>
- **Event ID 4647**: Ein Benutzer hat eine Abmeldung eingeleitet.<sup>[[53]](#references)</sup>
- **Event ID 4672**: Einer neuen Anmeldung wurden spezielle Berechtigungen zugewiesen; dies ist bei System- und Administratorkonten üblich und daher für sich genommen kein Beleg für böswillige Aktivität.<sup>[[54]](#references)</sup>

#### Häufig in 4624, 4625, 4634 und 4647 aufgezeichnete Anmeldetypen:

- **Interactive (2)**: Eine interaktive lokale Anmeldung.
- **Network (3)**: Zugriff auf eine freigegebene Ressource.
- **Batch (4)**: Eine Anmeldung durch einen Batch-Prozess.
- **Service (5)**: Eine Dienstanmeldung.
- **Unlock (7)**: Das Entsperren einer Arbeitsstation.
- **NetworkCleartext (8)**: Eine Netzwerkanmeldung, bei der Anmeldedaten im Klartext an das Authentifizierungspaket übergeben werden.
- **NewCredentials (9)**: Eine Anmeldung mit bereitgestellten alternativen Anmeldedaten für ausgehende Verbindungen.
- **RemoteInteractive (10)**: Eine Anmeldung über Remotedesktop oder Terminaldienste.
- **CachedInteractive (11)**: Eine interaktive Anmeldung mit zwischengespeicherten Domänenanmeldedaten.
- **CachedRemoteInteractive (12)**: Eine zwischengespeicherte Remote-Interactive-Anmeldung.
- **CachedUnlock (13)**: Ein Entsperren mit zwischengespeicherten Anmeldedaten.<sup>[[50]](#references)[[51]](#references)</sup>

#### Status- und Substatuscodes für EventID 4625:

- **0xC0000064**: Kein Benutzer mit diesem Namen vorhanden.
- **0xC000006A**: Benutzername korrekt, aber Passwort falsch.
- **0xC0000234**: Konto gesperrt.
- **0xC0000072**: Konto deaktiviert.
- **0xC000006F**: Anmeldung außerhalb der zulässigen Zeiten.
- **0xC0000070**: Verstoß gegen eine Arbeitsstationsbeschränkung.
- **0xC0000193**: Konto abgelaufen.
- **0xC0000071**: Passwort abgelaufen.
- **0xC0000133**: Die Zeitdifferenz zwischen Client und Server ist zu groß.
- **0xC0000224**: Das Konto muss sein Passwort ändern.
- **0xC0000225**: `STATUS_NOT_FOUND`; der Code allein weist weder auf einen Systemfehler noch auf einen Angriff hin.
- **0xC000015B**: Dem Konto ist der angeforderte Anmeldetyp nicht gewährt.<sup>[[51]](#references)[[55]](#references)</sup>

#### EventID 4616:

- **Zeitänderung**: Die Systemzeit wurde geändert. Viele Ereignisse spiegeln routinemäßige Korrekturen durch den Zeitdienst wider; prüfen Sie daher den Akteur und die Zeitquelle, bevor Sie von Manipulation ausgehen.<sup>[[56]](#references)</sup>

#### Event-IDs 12, 13, 1074, 6005, 6006, 6008 und 6009:

- **Kontext zu Stromversorgung und Diensten**: Ereignis 12 zeichnet den Start des Betriebssystems auf, 13 das Herunterfahren des Betriebssystems, 1074 ein geplantes Herunterfahren oder einen Neustart, 6008 ein unerwartetes Herunterfahren und 6009 die Windows-Version beim Start. Die Ereignisse 6005 und 6006 zeigen an, dass der Event-Log-Dienst gestartet bzw. beendet wurde; sie sind für sich genommen kein Beleg für den Start oder das Herunterfahren des Betriebssystems.<sup>[[57]](#references)[[58]](#references)</sup>

#### EventID 1102:

- **Löschen des Protokolls**: Ereignis 1102 zeichnet auf, dass das Security-Überwachungsprotokoll geleert wurde; untersuchen Sie den Akteur und die umgebenden Ereignisse, statt allein aus diesem Ereignis auf eine Absicht zu schließen.<sup>[[62]](#references)</sup>

#### Event-IDs zur USB-Geräteverfolgung:

- **20001 / 20003**: `UserPnp`-Ereignisse zur Geräteinstallation, die dabei helfen können, die erste Nutzung oder Installationsaktivität festzustellen.
- **10000 / 10100**: `DriverFrameworks-UserMode`-Ereignisse, die mit Geräteaktivitäten einhergehen können.
- **Event ID 112**: `DeviceSetupManager/Admin`-Aktivität, die Zeitstempel im Zusammenhang mit dem Anschließen eines Geräts liefern kann.
- Provider, Kanal und Bedeutung der Ereignisse unterscheiden sich je nach Windows-Version; prüfen Sie den Providernamen und die Ereignisdaten, bevor Sie ihnen eine Bedeutung zuweisen.<sup>[[59]](#references)</sup>

Praktische Beispiele zu Anmeldetypen und den zugehörigen Anmeldedaten finden Sie im [ausführlichen Leitfaden von Altered Security](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).<sup>[[60]](#references)</sup>

Ereignisdetails wie Anmeldetyp, Status, Substatus, Quelladresse und Prozessfelder liefern Kontext zu Event ID 4625; ein Statuscode oder wiederholte Fehlversuche sind Ermittlungsansätze, aber keine Schlussfolgerung.<sup>[[51]](#references)[[55]](#references)</sup>

### Windows-Ereignisse wiederherstellen

Da Ereignisprotokolle häufig zyklisch geführt werden, sind vom Logger überschriebene Einträge möglicherweise nicht wiederherstellbar. Sichern Sie ein forensisches Abbild oder eine Arbeitskopie, bevor Sie mit einem laufenden System interagieren. Verwenden Sie einen geprüften Parser oder Carver wie **Bulk_extractor** erst, nachdem Sie bestätigt haben, dass die Toolversion die betreffenden `.evtx`-Daten unterstützt, und trennen Sie ein laufendes System nicht allein deshalb vom Strom, um Ereignisse wiederherzustellen.<sup>[[46]](#references)</sup>

### Häufige Angriffe anhand von Windows-Ereignissen erkennen

Eine praktische Referenz zu Event-IDs finden Sie über den vorhandenen Link zum [Red Team Recipe](https://redteamrecipe.com/event-codes); überprüfen Sie die dortigen Beispiele anhand der oben genannten Provider-Dokumentation.

#### Brute-Force-Angriffe

Setzen Sie wiederholte fehlgeschlagene Anmeldungen mit Event ID 4625 in Beziehung zu einem späteren erfolgreichen Ereignis 4624, dem Anmeldetyp, Status, der Quelle und dem Kontokontext; diese Abfolge ist ein Untersuchungsindikator, aber kein Beweis für einen Angriff.<sup>[[50]](#references)[[51]](#references)</sup>

#### Zeitänderung

Event ID 4616 zeichnet Änderungen der Systemzeit auf, die die Zeitleistenanalyse erschweren können; vergleichen Sie das Ereignis mit Zeitdienst- und Hostdaten.<sup>[[56]](#references)</sup>

#### USB-Geräteverfolgung

USB-Event-IDs sind providerspezifisch; setzen Sie `UserPnp` 20001/20003, `DriverFrameworks-UserMode` 10000/10100 und `DeviceSetupManager/Admin` 112 mit SetupAPI- und Registrierungsartefakten in Beziehung.<sup>[[17]](#references)[[59]](#references)</sup>

#### Systemereignisse zur Stromversorgung

Verwenden Sie 12/13/1074/6008/6009 für den Kontext zu Betriebssystemstart, Herunterfahren, Neustart und unerwartetem Stromausfall; 6005/6006 kennzeichnen den Start bzw. das Beenden des Event-Log-Dienstes.<sup>[[57]](#references)[[58]](#references)</sup>

#### Löschen des Protokolls

Security Event ID 1102 zeichnet auf, dass das Security-Überwachungsprotokoll geleert wurde, und sollte mit dem verantwortlichen Konto und Prozess in Beziehung gesetzt werden.<sup>[[62]](#references)</sup>



## References

- [1] [Windows Plug-and-Play-Bereinigung](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)
- [2] [jonahacks.medium.com – Untersuchung gängiger Windows-Prozesse](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)
- [3] [Eine digitalforensische Betrachtung der Windows-10-Benachrichtigungen](https://iconline.ipleiria.pt/server/api/core/bitstreams/833e160a-e382-46b4-82ad-fb2c8c995d62/content)
- [4] [WxTCmd](https://github.com/EricZimmerman/WxTCmd)
- [5] [Forensik-Tools von Eric Zimmerman](https://ericzimmerman.github.io/#!index.md)
- [6] [Zone.Identifier und Alternate Data Streams](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/6e3f7352-d11c-4d76-8c39-2516a9df36e8)
- [7] [Rifiuti2](https://github.com/abelcheung/rifiuti2)
- [8] [Volume Shadow Copy Service](https://learn.microsoft.com/en-us/windows/server/storage/file-server/volume-shadow-copy-service)
- [9] [ShadowCopyView](https://www.nirsoft.net/utils/shadow_copy_view.html)
- [10] [Sicherungs- und Wiederherstellungsvorgänge für die Registrierung unter VSS](https://learn.microsoft.com/en-us/windows/win32/vss/registry-backup-and-restore-operations-under-vss)
- [11] [Registrierungsschlüssel für Sicherung und Wiederherstellung](https://learn.microsoft.com/en-us/windows/win32/backup/registry-keys-for-backup-and-restore)
- [12] [Word-Leistungsproblem am AutoRecover-Speicherort](https://learn.microsoft.com/en-us/previous-versions/troubleshoot/microsoft-365/microsoft-365-apps/word/performance-issue-on-autorecover-location)
- [13] [Leitfaden zur Reaktion auf Sicherheitsvorfälle](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/final/en-us/microsoft-brand/documents/IR-Guidebook-Final.pdf)
- [14] [MS-SHLLINK: Binärdateiformat für Shell-Verknüpfungen](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/c3376b21-0931-45e4-b2fc-a48ac0e60d15)
- [15] [LECmd](https://github.com/EricZimmerman/LECmd)
- [16] [USB-MTP-Forensik: Erkennen von Datenexfiltrationsartefakten](https://studylib.net/doc/8690663/usb-devices-and-media-transfer-protocol)
- [17] [Einträge im SetupAPI-Geräteinstallationsprotokoll](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/setupapi-device-installation-log-entries)
- [18] [USB Detective](https://usbdetective.com)
- [19] [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)
- [20] [PidTagClientSubmitTime](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/ca98145f-7f87-42b4-b0ef-124c6c6f8d83)
- [21] [PidTagConversationIndex](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/57f8de0f-5f53-423a-8947-7943dd959997)
- [22] [EntryID und verwandte Typen](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcdata/57e8bcbf-11d0-40fe-8833-5558bb9c0c89)
- [23] [PidTagMessageFlags](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcmsg/a0c52fe2-3014-43a7-942d-f43f6f91c366)
- [24] [PidTagLastVerbExecuted](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxomsg/87a8b6b8-59a4-4859-9dcd-8b0f36e3d729?redirectedfrom=MSDN)
- [25] [Outlook-Datendateien finden und übertragen](https://support.microsoft.com/en-us/outlook/find-and-transfer-outlook-data-files-from-one-computer-to-another)
- [26] [Cached Exchange Mode aktivieren](https://support.microsoft.com/en-us/outlook/turn-on-cached-exchange-mode)
- [27] [Nur eine Teilmenge der Elemente wird synchronisiert](https://learn.microsoft.com/en-us/troubleshoot/outlook/user-interface/only-subset-items-synchronized)
- [28] [Größenbeschränkungen für Outlook-Datendateien konfigurieren](https://learn.microsoft.com/en-us/microsoft-365-apps/outlook/data-files/configure-size-limit-outlook-data-files)
- [29] [Profile – Wo Thunderbird Benutzerdaten speichert](https://support.mozilla.org/bm/kb/profiles-where-thunderbird-stores-user-data)
- [30] [Thunderbird-Kontoeinstellungen und mbox-Verzeichnisse](https://support.mozilla.org/en-US/kb/dangerous-directories-Thunderbird-account-settings)
- [31] [IThumbnailCache-Schnittstelle](https://learn.microsoft.com/en-us/windows/win32/api/thumbcache/nn-thumbcache-ithumbnailcache)
- [32] [Thumbs Viewer](https://thumbsviewer.github.io)
- [33] [Thumbcache Viewer](https://thumbcacheviewer.github.io)
- [34] [Registrierungs-Hives](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives)
- [35] [Systemregistrierung wird nicht in RegBack gesichert](https://learn.microsoft.com/en-gb/troubleshoot/windows-client/installing-updates-features-roles/system-registry-no-backed-up-regback-folder)
- [36] [RegRipper 3.0](https://github.com/keydet89/RegRipper3.0)
- [37] [Windows-Registrierungswiederherstellung](https://www.mitec.cz/wrr.html)
- [38] [Registrierung remote bearbeiten](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/remotely-edit-the-registry)
- [39] [Technischer Überblick über Passwörter](https://learn.microsoft.com/en-us/windows-server/security/kerberos/passwords-technical-overview)
- [40] [PECmd](https://github.com/EricZimmerman/PECmd)
- [41] [Superfetch-Belege](https://kb.binalyze.com/air/features/acquisition/supported-evidence/windows-collections-detail/superfetch)
- [42] [srum-dump](https://github.com/MarkBaggett/srum-dump)
- [43] [AppCompatCacheParser](https://github.com/EricZimmerman/AppCompatCacheParser)
- [44] [AmcacheParser](https://github.com/EricZimmerman/AmcacheParser)
- [45] [RecentFileCacheParser](https://github.com/EricZimmerman/RecentFileCacheParser)
- [46] [Ereignisprotokolldateiformat](https://learn.microsoft.com/en-us/windows/win32/eventlog/event-log-file-format)
- [47] [Registrierungsschlüssel für das Ereignisprotokoll](https://learn.microsoft.com/en-us/windows/win32/eventlog/eventlog-key)
- [48] [Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.5)
- [49] [TimeCreated-Ereigniseigenschaft](https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-timecreated-systempropertiestype-element)
- [50] [Ereignis 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624)
- [51] [Ereignis 4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)
- [52] [Ereignis 4634](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4634)
- [53] [Ereignis 4647](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4647)
- [54] [Ereignis 4672](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672)
- [55] [MS-ERREF: NTSTATUS-Werte](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55)
- [56] [Ereignis 4616](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4616)
- [57] [Unerwartete Neustarts mithilfe von Systemereignisprotokollen untersuchen](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
- [58] [Herunterfahren während eines Prozesses untersuchen](https://learn.microsoft.com/en-us/troubleshoot/windows-server/installing-updates-features-roles/troubleshoot-error-shutdown-in-process)
- [59] [Forensik von USB-Speichergeräten unter Windows 10](https://www.researchgate.net/publication/318514858_USB_Storage_Device_Forensics_for_Windows_10)
- [60] [Die verschiedenen Windows-Anmeldetypen](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)
- [61] [Event Log Explorer](https://eventlogxp.com)
- [62] [Ereignis 1102](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102)
- [63] [Hintergrundaktivitätsmoderator](https://winreg-kb.readthedocs.io/en/latest/sources/system-keys/Background-activity-moderator.html)
- [64] [Registrierung – RecentApps](https://artefacts.help/windows_registry_recentapps.html)
- [65] [Quick Print druckt keine PDF-Anlagen mehr in Outlook Desktop](https://support.microsoft.com/en-gb/office/quick-print-stops-printing-pdf-attachments-in-outlook-desktop-512fdeb0-6a88-4e6c-9285-cf957290aad2)
- [66] [Windows-Registrierungsdateien](https://winreg-kb.readthedocs.io/en/latest/sources/windows-registry/Files.html)
- [67] [Kernel PST Viewer](https://www.nucleustechnologies.com/es/visor-de-pst.html)
- [68] [Kernel OST Viewer](https://www.nucleustechnologies.com/ost-viewer.html)
- [69] [RegQueryInfoKeyA](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryinfokeya)
- [70] [Verhindern, dass entfernte Apps während eines Updates wiederhergestellt werden](https://learn.microsoft.com/en-us/windows/application-management/remove-provisioned-apps-during-update)
- [71] [NIST CFTT: Testergebnisse für FTK und Registry Viewer](https://www.dhs.gov/sites/default/files/publications/test_results_nist_windows_registry_forensic_tool_ftk_7.0.0.163_registry_viewer_2.0.0.7_april_2019.pdf)
- [72] [Datenbank installierter Dienste](https://learn.microsoft.com/en-us/windows/win32/services/database-of-installed-services)
- [73] [Tasks](https://learn.microsoft.com/en-us/windows/win32/taskschd/tasks)
- [74] [Geplante Tasks schlagen mit dem Fehler „Task Scheduler Service Is Not Available“ fehl](https://learn.microsoft.com/en-us/troubleshoot/windows-client/system-management-components/task-schedular-service-is-not-available)
- [75] [Die Windows-Mail-Datenbank erkunden](https://eprints.whiterose.ac.uk/133161/1/Navigating_the_Windows_Mail_database_accepted.pdf)
- [76] [RFC 5322: Internet-Nachrichtenformat](https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.4)
- [77] [Recall für Windows-Clients verwalten](https://learn.microsoft.com/en-us/windows/client-management/manage-recall)
- [78] [TotalRecall Reloaded](https://github.com/xaitax/TotalRecall)
{{#include ../../../banners/hacktricks-training.md}}
