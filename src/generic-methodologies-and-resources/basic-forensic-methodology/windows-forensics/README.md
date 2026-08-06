# Windows-Artefakte

{{#include ../../../banners/hacktricks-training.md}}

## Allgemeine Windows-Artefakte

### Windows 10-Benachrichtigungen

Im Pfad `\Users\<username>\AppData\Local\Microsoft\Windows\Notifications` finden Sie die Datenbank `appdb.dat` (vor Windows Anniversary) oder `wpndatabase.db` (nach Windows Anniversary).

In dieser SQLite-Datenbank finden Sie die Tabelle `Notification` mit allen Benachrichtigungen (im XML-Format), die interessante Daten enthalten können.

### Timeline

Timeline ist eine Windows-Funktion, die eine **chronologische Historie** besuchter Webseiten, bearbeiteter Dokumente und ausgeführter Anwendungen bereitstellt.

Die Datenbank befindet sich im Pfad `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Diese Datenbank kann mit einem SQLite-Tool oder mit dem Tool [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) geöffnet werden, **das 2 Dateien erzeugt, die mit dem Tool** [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md) geöffnet werden können.

### ADS (Alternate Data Streams)

Heruntergeladene Dateien können den **ADS Zone.Identifier** enthalten, der angibt, **wie** sie aus dem Intranet, dem Internet usw. **heruntergeladen** wurden. Manche Software (z. B. Browser) fügt normalerweise noch **mehr** **Informationen** hinzu, etwa die **URL**, von der die Datei heruntergeladen wurde.

## **Dateisicherungen**

### Papierkorb

Unter Vista/Win7/Win8/Win10 befindet sich der **Papierkorb** im Ordner **`$Recycle.bin`** im Stammverzeichnis des Laufwerks (`C:\$Recycle.bin`).\
Wenn eine Datei in diesem Ordner gelöscht wird, werden 2 bestimmte Dateien erstellt:

- `$I{id}`: Dateiinformationen (Datum, an dem sie gelöscht wurde}
- `$R{id}`: Inhalt der Datei

![Dateisicherungen – Papierkorb: $R{id}: Inhalt der Datei](<../../../images/image (1029).png>)

Mit diesen Dateien können Sie das Tool [**Rifiuti**](https://github.com/abelcheung/rifiuti2) verwenden, um den ursprünglichen Speicherort der gelöschten Dateien und das Datum ihrer Löschung zu ermitteln (verwenden Sie `rifiuti-vista.exe` für Vista – Win10).
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![Dateisicherungen - Papierkorb: rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### Volume Shadow Copies

Shadow Copy ist eine in Microsoft Windows enthaltene Technologie, die **Sicherungskopien** oder Snapshots von Computerdateien oder Volumes erstellen kann, selbst wenn diese verwendet werden.

Diese Sicherungen befinden sich normalerweise im Verzeichnis `\System Volume Information` im Stammverzeichnis des Dateisystems, und der Name besteht aus **UIDs**, wie im folgenden Bild dargestellt:

![Papierkorb - Volume Shadow Copies: Diese Sicherungen befinden sich normalerweise im Verzeichnis System Volume Information im Stammverzeichnis des Dateisystems, und der Name besteht aus UIDs, wie im ...](<../../../images/image (94).png>)

Beim Einbinden des Forensik-Images mit dem **ArsenalImageMounter** kann das Tool [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) verwendet werden, um eine Shadow Copy zu untersuchen und sogar die **Dateien** aus den Sicherungen der Shadow Copy zu **extrahieren**.

![Papierkorb - Volume Shadow Copies: Beim Einbinden des Forensik-Images mit dem ArsenalImageMounter kann das Tool ShadowCopyView verwendet werden, um eine Shadow Copy zu untersuchen und sogar die Dateien ...](<../../../images/image (576).png>)

Der Registry-Eintrag `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` enthält die Dateien und Schlüssel, die **nicht gesichert werden sollen**:

![Papierkorb - Volume Shadow Copies: Der Registry-Eintrag HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore enthält die Dateien und Schlüssel, die nicht gesichert werden sollen](<../../../images/image (254).png>)

Die Registry `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` enthält ebenfalls Konfigurationsinformationen über die `Volume Shadow Copies`.

### Automatisch gespeicherte Office-Dateien

Die automatisch gespeicherten Office-Dateien befinden sich unter: `C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## Shell Items

Ein Shell Item ist ein Element, das Informationen darüber enthält, wie auf eine andere Datei zugegriffen werden kann.

### Zuletzt verwendete Dokumente (LNK)

Windows **erstellt** diese **Verknüpfungen** **automatisch**, wenn der Benutzer eine Datei **öffnet, verwendet oder erstellt**, unter:

- Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
- Office: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

Wenn ein Ordner erstellt wird, wird außerdem eine Verknüpfung zum Ordner, zum übergeordneten Ordner und zum Großelternordner erstellt.

Diese automatisch erstellten Verknüpfungsdateien **enthalten Informationen über den Ursprung**, z. B. ob es sich um eine **Datei** oder einen **Ordner** handelt, die **MAC**-**Zeitstempel** dieser Datei, Informationen über das **Volume**, auf dem die Datei gespeichert ist, sowie den **Ordner der Zieldatei**. Diese Informationen können nützlich sein, um die Dateien wiederherzustellen, falls sie entfernt wurden.

Außerdem ist das **Erstellungsdatum der Verknüpfungsdatei** der erste **Zeitpunkt**, zu dem die ursprüngliche Datei **erstmals** **verwendet** wurde, und das **Änderungsdatum** der Verknüpfungsdatei ist der letzte **Zeitpunkt**, zu dem die Ursprungsdatei verwendet wurde.

Zur Untersuchung dieser Dateien kann [**LinkParser**](http://4discovery.com/our-tools/) verwendet werden.

In diesem Tool finden Sie **2 Gruppen** von Zeitstempeln:

- **Erste Gruppe:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
- **Zweite Gruppe:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

Die erste Gruppe von Zeitstempeln bezieht sich auf die **Zeitstempel der Datei selbst**. Die zweite Gruppe bezieht sich auf die **Zeitstempel der verknüpften Datei**.

Dieselben Informationen können mit dem Windows-CLI-Tool [**LECmd.exe**](https://github.com/EricZimmerman/LECmd) abgerufen werden.
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
In diesem Fall werden die Informationen in einer CSV-Datei gespeichert.

### Jumplists

Hierbei handelt es sich um die pro Anwendung angegebenen zuletzt verwendeten Dateien. Dies ist die Liste der **zuletzt von einer Anwendung verwendeten Dateien**, auf die Sie in jeder Anwendung zugreifen können. Sie können **automatisch oder benutzerdefiniert** erstellt werden.

Die **automatisch** erstellten **Jumplists** werden unter `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` gespeichert. Die **Jumplists** werden nach dem Format `{id}.autmaticDestinations-ms` benannt, wobei die anfängliche ID die ID der Anwendung ist.

Die benutzerdefinierten **Jumplists** werden unter `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\` gespeichert und normalerweise von der Anwendung erstellt, weil etwas **Wichtiges** mit der Datei passiert ist (z. B. weil sie als Favorit markiert wurde).

Die **Erstellungszeit** jeder **Jumplist** gibt an, **wann erstmals auf die Datei zugegriffen wurde**, und die **Änderungszeit**, wann dies zuletzt geschah.

Sie können die **Jumplists** mit [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md) untersuchen.

![Recent Documents (LNK) - Jumplists: Sie können die Jumplists mit JumplistExplorer untersuchen](<../../../images/image (168).png>)

(_Beachten Sie, dass sich die von JumplistExplorer bereitgestellten Zeitstempel auf die Jumplist-Datei selbst beziehen._)

### Shellbags

[**Folgen Sie diesem Link, um zu erfahren, was Shellbags sind.**](interesting-windows-registry-keys.md#shellbags)

## Verwendung von Windows-USBs

Anhand der Erstellung folgender Elemente kann festgestellt werden, dass ein USB-Gerät verwendet wurde:

- Windows Recent Folder
- Microsoft Office Recent Folder
- Jumplists

Beachten Sie, dass einige LNK-Dateien nicht auf den ursprünglichen Pfad, sondern auf den WPDNSE-Ordner verweisen:

![Shellbags - Verwendung von Windows-USBs: Beachten Sie, dass einige LNK-Dateien nicht auf den ursprünglichen Pfad, sondern auf den WPDNSE-Ordner verweisen](<../../../images/image (218).png>)

Die Dateien im Ordner WPDNSE sind Kopien der Originaldateien und überstehen daher keinen Neustart des PCs. Die GUID stammt aus einem Shellbag.

### Registry-Informationen

[Auf dieser Seite erfahren Sie](interesting-windows-registry-keys.md#usb-information), welche Registry-Schlüssel interessante Informationen über verbundene USB-Geräte enthalten.

### setupapi

Überprüfen Sie die Datei `C:\Windows\inf\setupapi.dev.log`, um die Zeitstempel für die USB-Verbindung zu erhalten (suchen Sie nach `Section start`).

![Registry-Informationen - setupapi: Überprüfen Sie die Datei C: Windows inf setupapi.dev.log, um die Zeitstempel für die USB-Verbindung zu erhalten (suchen Sie nach Section start)](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) kann verwendet werden, um Informationen über USB-Geräte abzurufen, die mit einem Abbild verbunden waren.

![setupapi - USB Detective: USBDetective kann verwendet werden, um Informationen über USB-Geräte abzurufen, die mit einem Abbild verbunden waren](<../../../images/image (452).png>)

### Plug and Play Cleanup

Die geplante Aufgabe mit dem Namen „Plug and Play Cleanup“ dient hauptsächlich zum Entfernen veralteter Treiberversionen. Entgegen ihrem angegebenen Zweck, die neueste Version des Treiberpakets beizubehalten, deuten Onlinequellen darauf hin, dass sie auch Treiber entfernt, die 30 Tage lang inaktiv waren. Folglich können Treiber für entfernbare Geräte, die in den vergangenen 30 Tagen nicht verbunden waren, gelöscht werden.<sup>[[1]](#references)</sup>

Die Aufgabe befindet sich unter folgendem Pfad: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

Ein Screenshot mit dem Inhalt der Aufgabe ist verfügbar: ![USB Detective - Plug and Play Cleanup: Die Aufgabe befindet sich unter folgendem Pfad: C: Windows System32 Tasks Microsoft Windows Plug and Play Plug and Play Cleanup](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Wichtige Komponenten und Einstellungen der Aufgabe:**

- **pnpclean.dll**: Diese DLL ist für den eigentlichen Bereinigungsvorgang verantwortlich.
- **UseUnifiedSchedulingEngine**: Auf `TRUE` gesetzt, was die Verwendung der generischen Aufgabenplanungs-Engine anzeigt.
- **MaintenanceSettings**:
- **Period ('P1M')**: Weist den Task Scheduler an, die Bereinigungsaufgabe monatlich während der regulären automatischen Wartung zu starten.
- **Deadline ('P2M')**: Weist den Task Scheduler an, die Aufgabe während der automatischen Notfallwartung auszuführen, wenn sie zwei aufeinanderfolgende Monate lang fehlschlägt.

Diese Konfiguration gewährleistet die regelmäßige Wartung und Bereinigung von Treibern und sieht eine erneute Ausführung der Aufgabe bei aufeinanderfolgenden Fehlern vor.

**Weitere Informationen finden Sie unter:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)<sup>[[1]](#references)</sup>

## E-Mails

E-Mails enthalten **2 interessante Bestandteile: die Header und den Inhalt** der E-Mail. In den **Headern** finden Sie Informationen wie:

- **Wer** die E-Mails gesendet hat (E-Mail-Adresse, IP-Adresse, Mailserver, die die E-Mail weitergeleitet haben)
- **Wann** die E-Mail gesendet wurde

In den Headern `References` und `In-Reply-To` können Sie außerdem die ID der Nachrichten finden:

![Plug and Play Cleanup - E-Mails: Wann wurde die E-Mail gesendet](<../../../images/image (593).png>)

### Windows Mail App

Diese Anwendung speichert E-Mails im HTML- oder Textformat. Sie finden die E-Mails in Unterordnern innerhalb von `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`. Die E-Mails werden mit der Erweiterung `.dat` gespeichert.

Die **Metadaten** der E-Mails und die **Kontakte** befinden sich in der **EDB-Datenbank**: `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`

**Ändern Sie die Dateierweiterung** von `.vol` in `.edb`. Anschließend können Sie das Tool [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) verwenden, um die Datei zu öffnen. In der Tabelle `Message` können Sie die E-Mails anzeigen.

### Microsoft Outlook

Wenn Exchange-Server oder Outlook-Clients verwendet werden, gibt es einige MAPI-Header:

- `Mapi-Client-Submit-Time`: Systemzeitpunkt, zu dem die E-Mail gesendet wurde
- `Mapi-Conversation-Index`: Anzahl der untergeordneten Nachrichten des Threads und Zeitstempel jeder Nachricht des Threads
- `Mapi-Entry-ID`: Nachrichtenkennung.
- `Mappi-Message-Flags` und `Pr_last_Verb-Executed`: Informationen über den MAPI-Client (Nachricht gelesen? Nicht gelesen? Beantwortet? Weitergeleitet? Abwesenheitsnotiz?)

Im Microsoft Outlook-Client werden alle gesendeten/empfangenen Nachrichten, Kontaktdaten und Kalenderdaten in einer PST-Datei gespeichert unter:

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

Der Registry-Pfad `HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` gibt die verwendete Datei an.

Sie können die PST-Datei mit dem Tool [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html) öffnen.

![Windows Mail App - Microsoft Outlook: Sie können die PST-Datei mit dem Tool Kernel PST Viewer öffnen](<../../../images/image (498).png>)

### Microsoft Outlook OST Files

Eine **OST-Datei** wird von Microsoft Outlook erzeugt, wenn es mit einem **IMAP-** oder einem **Exchange-Server** konfiguriert ist, und speichert ähnliche Informationen wie eine PST-Datei. Diese Datei wird mit dem Server synchronisiert, behält Daten der **letzten 12 Monate** bis zu einer **maximalen Größe von 50 GB** bei und befindet sich im selben Verzeichnis wie die PST-Datei. Zum Anzeigen einer OST-Datei kann der [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html) verwendet werden.

### Abrufen von Anhängen

Verlorene Anhänge können möglicherweise wiederhergestellt werden aus:

- Für **IE10**: `%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook`
- Für **IE11 und höher**: `%APPDATA%\Local\Microsoft\InetCache\Content.Outlook`

### Thunderbird MBOX Files

**Thunderbird** verwendet **MBOX-Dateien** zum Speichern von Daten. Diese befinden sich unter `\Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles`.

### Miniaturansichten von Bildern

- **Windows XP und 8-8.1**: Beim Zugriff auf einen Ordner mit Miniaturansichten wird eine Datei `thumbs.db` erstellt, in der Bildvorschauen gespeichert werden, auch nach deren Löschung.
- **Windows 7/10**: `thumbs.db` wird erstellt, wenn über einen UNC-Pfad auf das Netzwerk zugegriffen wird.
- **Windows Vista und neuer**: Miniaturansichten werden zentral unter `%userprofile%\AppData\Local\Microsoft\Windows\Explorer` in Dateien mit dem Namen **thumbcache_xxx.db** gespeichert. [**Thumbsviewer**](https://thumbsviewer.github.io) und [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) sind Tools zum Anzeigen dieser Dateien.

### Windows Registry-Informationen

Die Windows Registry, in der umfangreiche System- und Benutzeraktivitätsdaten gespeichert werden, befindet sich in Dateien unter:

- `%windir%\System32\Config` für verschiedene `HKEY_LOCAL_MACHINE`-Unterschlüssel.
- `%UserProfile%{User}\NTUSER.DAT` für `HKEY_CURRENT_USER`.
- Windows Vista und spätere Versionen sichern Registry-Dateien von `HKEY_LOCAL_MACHINE` unter `%Windir%\System32\Config\RegBack\`.
- Zusätzlich werden Informationen zur Programmausführung ab Windows Vista und Windows 2008 Server unter `%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT` gespeichert.

### Tools

Einige Tools sind für die Analyse der Registry-Dateien nützlich:

- **Registry Editor**: Ist in Windows installiert. Es handelt sich um eine GUI zur Navigation durch die Windows Registry der aktuellen Sitzung.
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): Ermöglicht das Laden einer Registry-Datei und die Navigation durch sie über eine GUI. Außerdem enthält es Bookmarks, die auf Schlüssel mit interessanten Informationen hinweisen.
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): Verfügt ebenfalls über eine GUI, mit der die geladene Registry durchsucht werden kann, und enthält außerdem Plugins, die interessante Informationen innerhalb der geladenen Registry hervorheben.
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): Eine weitere GUI-Anwendung, die wichtige Informationen aus der geladenen Registry extrahieren kann.

### Wiederherstellen gelöschter Elemente

Wenn ein Schlüssel gelöscht wird, wird er entsprechend markiert. Solange der von ihm belegte Speicherplatz jedoch nicht benötigt wird, wird er nicht entfernt. Daher ist es mit Tools wie **Registry Explorer** möglich, diese gelöschten Schlüssel wiederherzustellen.

### Last Write Time

Jedes Schlüssel-Wert-Paar enthält einen **Zeitstempel**, der den Zeitpunkt der letzten Änderung angibt.

### SAM

Die Datei/der Hive **SAM** enthält die Hashes der **Benutzer, Gruppen und Benutzerpasswörter** des Systems.

Unter `SAM\Domains\Account\Users` erhalten Sie den Benutzernamen, die RID, den letzten Login, die letzte fehlgeschlagene Anmeldung, den Anmeldezähler, die Kennwortrichtlinie und den Zeitpunkt der Kontoerstellung. Um die **Hashes** abzurufen, benötigen Sie außerdem die Datei/den Hive **SYSTEM**.

### Interessante Einträge in der Windows Registry


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Ausgeführte Programme

### Grundlegende Windows-Prozesse

In [diesem Beitrag](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) erfahren Sie mehr über die gängigen Windows-Prozesse, mit denen sich verdächtiges Verhalten erkennen lässt.<sup>[[2]](#references)</sup>

### Kürzlich verwendete Windows-Apps

In der Registry `NTUSER.DAT` können Sie unter dem Pfad `Software\Microsoft\Current Version\Search\RecentApps` Unterschlüssel mit Informationen über die **ausgeführte Anwendung**, den **Zeitpunkt der letzten Ausführung** und die **Anzahl der Starts** finden.

### BAM (Background Activity Moderator)

Sie können die Datei `SYSTEM` mit einem Registry-Editor öffnen. Unter dem Pfad `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` finden Sie Informationen über die **von jedem Benutzer ausgeführten Anwendungen** (beachten Sie `{SID}` im Pfad) und darüber, **wann** sie ausgeführt wurden (die Zeit befindet sich im Data-Wert der Registry).

### Windows Prefetch

Prefetching ist eine Technik, mit der ein Computer stillschweigend **die erforderlichen Ressourcen abruft, die zum Anzeigen von Inhalten benötigt werden**, auf die ein Benutzer **in naher Zukunft möglicherweise zugreift**, damit schneller auf die Ressourcen zugegriffen werden kann.

Windows Prefetch erstellt **Caches der ausgeführten Programme**, damit diese schneller geladen werden können. Diese Caches werden als `.pf`-Dateien unter dem Pfad `C:\Windows\Prefetch` erstellt. Unter XP/VISTA/WIN7 gibt es ein Limit von 128 Dateien, unter Win8/Win10 von 1024 Dateien.

Der Dateiname wird als `{program_name}-{hash}.pf` erstellt (der Hash basiert auf dem Pfad und den Argumenten der ausführbaren Datei). Unter W10 werden diese Dateien komprimiert. Beachten Sie, dass allein das Vorhandensein der Datei anzeigt, dass **das Programm irgendwann ausgeführt wurde**.

Die Datei `C:\Windows\Prefetch\Layout.ini` enthält die **Namen der Ordner der vorab abgerufenen Dateien**. Diese Datei enthält **Informationen über die Anzahl der Ausführungen**, **Ausführungsdaten** und die vom Programm **geöffneten** **Dateien**.

Zur Untersuchung dieser Dateien können Sie das Tool [**PEcmd.exe**](https://github.com/EricZimmerman/PECmd) verwenden:
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

**Superprefetch** hat dasselbe Ziel wie Prefetch: **Programme schneller laden**, indem vorhergesagt wird, was als Nächstes geladen wird. Es ersetzt den Prefetch-Dienst jedoch nicht.\
Dieser Dienst erzeugt Datenbankdateien in `C:\Windows\Prefetch\Ag*.db`.

In diesen Datenbanken finden Sie den **Namen** des **Programms**, die **Anzahl** der **Ausführungen**, **geöffnete** **Dateien**, das **zugegriffene** **Volume**, den **vollständigen** **Pfad**, **Zeiträume** und **Zeitstempel**.

Sie können auf diese Informationen mit dem Tool [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) zugreifen.

### SRUM

**System Resource Usage Monitor** (SRUM) **überwacht** die von einem **Prozess** **verbrauchten** **Ressourcen**. Es wurde in W8 eingeführt und speichert die Daten in einer ESE-Datenbank unter `C:\Windows\System32\sru\SRUDB.dat`.

Es liefert die folgenden Informationen:

- AppID und Pfad
- Benutzer, der den Prozess ausgeführt hat
- Gesendete Bytes
- Empfangene Bytes
- Netzwerkschnittstelle
- Verbindungsdauer
- Prozessdauer

Diese Informationen werden alle 60 Minuten aktualisiert.

Sie können die Daten aus dieser Datei mit dem Tool [**srum_dump**](https://github.com/MarkBaggett/srum-dump) extrahieren.
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```
### AppCompatCache (ShimCache)

Der **AppCompatCache**, auch bekannt als **ShimCache**, ist Teil der von **Microsoft** entwickelten **Application Compatibility Database**, um Probleme mit der Anwendungskompatibilität zu beheben. Diese Systemkomponente zeichnet verschiedene Dateimetadaten auf, darunter:

- Vollständiger Pfad der Datei
- Größe der Datei
- Zeitpunkt der letzten Änderung unter **$Standard_Information** (SI)
- Zeitpunkt der letzten Aktualisierung des ShimCache
- Process Execution Flag

Diese Daten werden abhängig von der Version des Betriebssystems an bestimmten Speicherorten in der Registry gespeichert:

- Unter XP werden die Daten unter `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache` mit einer Kapazität von 96 Einträgen gespeichert.
- Unter Server 2003 sowie Windows 2008, 2012, 2016, 7, 8 und 10 lautet der Speicherpfad `SYSTEM\CurrentControlSet\Control\SessionManager\AppCompatCache\AppCompatCache`; dabei werden jeweils 512 beziehungsweise 1024 Einträge unterstützt.

Zum Parsen der gespeicherten Informationen wird die Verwendung des [**AppCompatCacheParser tool**](https://github.com/EricZimmerman/AppCompatCacheParser) empfohlen.

![SRUM - AppCompatCache (ShimCache): Zum Parsen der gespeicherten Informationen wird die Verwendung des AppCompatCacheParser tool empfohlen](<../../../images/image (75).png>)

### Amcache

Die Datei **Amcache.hve** ist im Wesentlichen ein Registry-Hive, der Details zu Anwendungen protokolliert, die auf einem System ausgeführt wurden. Sie befindet sich normalerweise unter `C:\Windows\AppCompat\Programas\Amcache.hve`.

Diese Datei ist dafür bekannt, Datensätze kürzlich ausgeführter Prozesse zu speichern, einschließlich der Pfade zu den ausführbaren Dateien und ihrer SHA1-Hashes. Diese Informationen sind äußerst wertvoll, um die Aktivitäten von Anwendungen auf einem System nachzuverfolgen.

Zum Extrahieren und Analysieren der Daten aus **Amcache.hve** kann das Tool [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser) verwendet werden. Der folgende Befehl zeigt beispielhaft, wie AmcacheParser zum Parsen des Inhalts der Datei **Amcache.hve** und zur Ausgabe der Ergebnisse im CSV-Format verwendet wird:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
Unter den generierten CSV-Dateien ist `Amcache_Unassociated file entries` aufgrund der umfangreichen Informationen zu nicht zugeordneten Dateieinträgen besonders bemerkenswert.

Die interessanteste generierte CSV-Datei ist `Amcache_Unassociated file entries`.

### RecentFileCache

Dieses Artefakt ist nur in W7 unter `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` zu finden und enthält Informationen über die kürzliche Ausführung einiger Binärdateien.

Du kannst das Tool [**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser) verwenden, um die Datei zu parsen.

### Geplante Tasks

Du kannst sie aus `C:\Windows\Tasks` oder `C:\Windows\System32\Tasks` extrahieren und als XML lesen.

### Dienste

Du findest sie in der Registry unter `SYSTEM\ControlSet001\Services`. Dort kannst du sehen, was ausgeführt wird und wann.

### **Windows Store**

Die installierten Anwendungen befinden sich unter `\ProgramData\Microsoft\Windows\AppRepository\`\
Dieses Repository enthält ein **Log** mit **jeder im System installierten Anwendung** in der Datenbank **`StateRepository-Machine.srd`**.

In der Application-Tabelle dieser Datenbank können die Spalten „Application ID“, „PackageNumber“ und „Display Name“ gefunden werden. Diese Spalten enthalten Informationen über vorinstallierte und installierte Anwendungen. Außerdem kann festgestellt werden, ob Anwendungen deinstalliert wurden, da die IDs installierter Anwendungen sequenziell sein sollten.

Es ist außerdem möglich, **installierte Anwendungen** im Registry-Pfad `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`\
zu finden und **deinstallierte** **Anwendungen** unter: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`

## Windows-Ereignisse

In Windows-Ereignissen enthaltene Informationen sind:

- Was passiert ist
- Zeitstempel (UTC + 0)
- Beteiligte Benutzer
- Beteiligte Hosts (Hostname, IP)
- Aufgerufene Assets (Dateien, Ordner, Drucker, Dienste)

Die Logs befinden sich vor Windows Vista unter `C:\Windows\System32\config` und nach Windows Vista unter `C:\Windows\System32\winevt\Logs`. Vor Windows Vista lagen die Ereignis-Logs im Binärformat vor. Danach liegen sie im **XML-Format** vor und verwenden die Erweiterung **`.evtx`**.

Der Speicherort der Ereignisdateien kann in der SYSTEM-Registry unter **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`** gefunden werden.

Sie können über die Windows-Ereignisanzeige (**`eventvwr.msc`**) oder mit anderen Tools wie [**Event Log Explorer**](https://eventlogxp.com) **oder** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)** visualisiert werden.**

## Windows Security Event Logging verstehen

Zugriffsereignisse werden in der Security-Konfigurationsdatei unter `C:\Windows\System32\winevt\Security.evtx` aufgezeichnet. Die Größe dieser Datei kann angepasst werden. Wenn ihre Kapazität erreicht ist, werden ältere Ereignisse überschrieben. Zu den aufgezeichneten Ereignissen gehören Benutzeran- und -abmeldungen, Benutzeraktionen und Änderungen an den Security-Einstellungen sowie Zugriffe auf Dateien, Ordner und gemeinsam genutzte Assets.

### Wichtige Event IDs für die Benutzerauthentifizierung:

- **EventID 4624**: Gibt an, dass sich ein Benutzer erfolgreich authentifiziert hat.
- **EventID 4625**: Signalisiert einen Authentifizierungsfehler.
- **EventIDs 4634/4647**: Stellen Benutzerabmeldeereignisse dar.
- **EventID 4672**: Bezeichnet eine Anmeldung mit administrativen Rechten.

#### Untertypen innerhalb von EventID 4634/4647:

- **Interactive (2)**: Direkte Benutzeranmeldung.
- **Network (3)**: Zugriff auf gemeinsam genutzte Ordner.
- **Batch (4)**: Ausführung von Batch-Prozessen.
- **Service (5)**: Starten von Diensten.
- **Proxy (6)**: Proxy-Authentifizierung.
- **Unlock (7)**: Entsperren des Bildschirms mit einem Passwort.
- **Network Cleartext (8)**: Übertragung eines Klartextpassworts, häufig von IIS.
- **New Credentials (9)**: Verwendung anderer Credentials für den Zugriff.
- **Remote Interactive (10)**: Anmeldung über Remote Desktop oder Terminal Services.
- **Cache Interactive (11)**: Anmeldung mit gecachten Credentials ohne Kontakt zu einem Domain Controller.
- **Cache Remote Interactive (12)**: Remote-Anmeldung mit gecachten Credentials.
- **Cached Unlock (13)**: Entsperren mit gecachten Credentials.

#### Status- und Substatus-Codes für EventID 4625:

- **0xC0000064**: Benutzername existiert nicht – könnte auf einen Username-Enumeration-Angriff hindeuten.
- **0xC000006A**: Korrekter Benutzername, aber falsches Passwort – möglicher Password-Guessing- oder Brute-Force-Versuch.
- **0xC0000234**: Benutzerkonto gesperrt – kann auf einen Brute-Force-Angriff mit mehreren fehlgeschlagenen Anmeldungen folgen.
- **0xC0000072**: Konto deaktiviert – unbefugte Zugriffsversuche auf deaktivierte Konten.
- **0xC000006F**: Anmeldung außerhalb der erlaubten Zeit – weist auf Zugriffsversuche außerhalb der festgelegten Anmeldezeiten hin und kann ein Zeichen für unbefugten Zugriff sein.
- **0xC0000070**: Verletzung von Workstation-Einschränkungen – könnte ein Versuch sein, sich von einem nicht autorisierten Standort anzumelden.
- **0xC0000193**: Konto abgelaufen – Zugriffsversuche mit abgelaufenen Benutzerkonten.
- **0xC0000071**: Passwort abgelaufen – Anmeldeversuche mit veralteten Passwörtern.
- **0xC0000133**: Probleme bei der Zeitsynchronisierung – große Zeitabweichungen zwischen Client und Server können auf ausgefeiltere Angriffe wie Pass-the-Ticket hindeuten.
- **0xC0000224**: Obligatorische Passwortänderung erforderlich – häufige obligatorische Änderungen könnten auf einen Versuch hindeuten, die Kontosicherheit zu destabilisieren.
- **0xC0000225**: Weist eher auf einen Systemfehler als auf ein Security-Problem hin.
- **0xC000015b**: Anmeldetyp verweigert – Zugriffsversuch mit einem nicht autorisierten Anmeldetyp, etwa wenn ein Benutzer versucht, eine Service-Anmeldung auszuführen.

#### EventID 4616:

- **Time Change**: Änderung der Systemzeit, wodurch die zeitliche Abfolge von Ereignissen verschleiert werden könnte.

#### EventID 6005 und 6006:

- **Systemstart und -herunterfahren**: EventID 6005 zeigt den Systemstart an, während EventID 6006 das Herunterfahren markiert.

#### EventID 1102:

- **Löschen von Logs**: Security-Logs werden gelöscht, was häufig ein Warnsignal für das Verschleiern unerlaubter Aktivitäten ist.

#### EventIDs zur Nachverfolgung von USB-Geräten:

- **20001 / 20003 / 10000**: Erstmalige Verbindung eines USB-Geräts.
- **10100**: Aktualisierung des USB-Treibers.
- **EventID 112**: Zeitpunkt des Einsteckens eines USB-Geräts.

Praktische Beispiele zur Simulation dieser Anmeldetypen und von Möglichkeiten zum Credential Dumping findest du im detaillierten Leitfaden von [Altered Security](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).

Ereignisdetails, einschließlich Status- und Substatus-Codes, liefern weitere Einblicke in die Ursachen von Ereignissen, was insbesondere bei Event ID 4625 relevant ist.

### Windows-Ereignisse wiederherstellen

Um die Chancen auf die Wiederherstellung gelöschter Windows-Ereignisse zu erhöhen, empfiehlt es sich, den verdächtigen Computer durch direktes Ziehen des Netzsteckers auszuschalten. **Bulk_extractor**, ein Recovery-Tool, das die Erweiterung `.evtx` angibt, wird empfohlen, um die Wiederherstellung solcher Ereignisse zu versuchen.

### Häufige Angriffe anhand von Windows-Ereignissen identifizieren

Eine umfassende Anleitung zur Verwendung von Windows Event IDs zur Identifizierung häufiger Cyberangriffe findest du bei [Red Team Recipe](https://redteamrecipe.com/event-codes/).

#### Brute-Force-Angriffe

Erkennbar an mehreren EventID-4625-Einträgen, gefolgt von einer EventID 4624, wenn der Angriff erfolgreich ist.

#### Time Change

Wird durch EventID 4616 aufgezeichnet. Änderungen an der Systemzeit können die forensische Analyse erschweren.

#### Nachverfolgung von USB-Geräten

Nützliche System-EventIDs zur Nachverfolgung von USB-Geräten sind 20001/20003/10000 für die erstmalige Verwendung, 10100 für Treiberaktualisierungen und EventID 112 von DeviceSetupManager für Zeitstempel des Einsteckens.

#### System-Power-Ereignisse

EventID 6005 zeigt den Systemstart an, während EventID 6006 das Herunterfahren markiert.

#### Löschen von Logs

Security EventID 1102 signalisiert das Löschen von Logs – ein kritisches Ereignis für die forensische Analyse.

## Referenzen

- [1] [Windows Plug and Play Cleanup](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)
- [2] [jonahacks.medium.com - Investigating Common Windows Processes](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)

{{#include ../../../banners/hacktricks-training.md}}
