# Windows-Artefakte

{{#include ../../../banners/hacktricks-training.md}}

## Allgemeine Windows-Artefakte

### Windows-10-Benachrichtigungen

Im Pfad `\Users\<username>\AppData\Local\Microsoft\Windows\Notifications` finden Sie die Datenbank `appdb.dat` (vor Windows Anniversary) oder `wpndatabase.db` (nach Windows Anniversary).

In dieser SQLite-Datenbank finden Sie die Tabelle `Notification` mit allen Benachrichtigungen (im XML-Format), die interessante Daten enthalten können.

### Timeline

Timeline ist eine Windows-Funktion, die eine **chronologische Historie** besuchter Webseiten, bearbeiteter Dokumente und ausgeführter Anwendungen bereitstellt.

Die Datenbank befindet sich im Pfad `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Diese Datenbank kann mit einem SQLite-Tool oder mit dem Tool [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) geöffnet werden, **das 2 Dateien erzeugt, die mit dem Tool** [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md) geöffnet werden können.

### ADS (Alternate Data Streams)

Heruntergeladene Dateien können den **ADS Zone.Identifier** enthalten, der angibt, **wie** sie aus dem Intranet, Internet usw. **heruntergeladen** wurden. Einige Software (z. B. Browser) fügt normalerweise noch **mehr** **Informationen** hinzu, beispielsweise die **URL**, von der die Datei heruntergeladen wurde.

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

Diese Sicherungen befinden sich normalerweise im Verzeichnis `\System Volume Information` im Stammverzeichnis des Dateisystems, und der Name besteht aus den **UIDs**, die im folgenden Bild angezeigt werden:

![Papierkorb - Volume Shadow Copies: Diese Sicherungen befinden sich normalerweise im System Volume Information im Stammverzeichnis des Dateisystems, und der Name besteht aus den im folgenden Bild angezeigten UIDs](<../../../images/image (94).png>)

Nach dem Mounten des Forensik-Images mit dem **ArsenalImageMounter** kann das Tool [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) verwendet werden, um eine Shadow Copy zu untersuchen und sogar die **Dateien** aus den Sicherungen der Shadow Copy zu **extrahieren**.

![Papierkorb - Volume Shadow Copies: Nach dem Mounten des Forensik-Images mit dem ArsenalImageMounter kann das Tool ShadowCopyView verwendet werden, um eine Shadow Copy zu untersuchen und sogar die Dateien aus den Sicherungen zu extrahieren](<../../../images/image (576).png>)

Der Registry-Eintrag `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` enthält die Dateien und Schlüssel, die **nicht gesichert werden sollen**:

![Papierkorb - Volume Shadow Copies: Der Registry-Eintrag HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore enthält die Dateien und Schlüssel, die nicht gesichert werden sollen](<../../../images/image (254).png>)

Die Registry `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` enthält ebenfalls Konfigurationsinformationen zu den `Volume Shadow Copies`.

### Automatisch gespeicherte Office-Dateien

Die automatisch gespeicherten Office-Dateien befinden sich unter: `C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## Shell-Elemente

Ein Shell-Element ist ein Element, das Informationen darüber enthält, wie auf eine andere Datei zugegriffen werden kann.

### Zuletzt verwendete Dokumente (LNK)

Windows **erstellt** diese **Verknüpfungen** **automatisch**, wenn der Benutzer eine Datei **öffnet, verwendet oder erstellt**, unter:

- Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
- Office: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

Wenn ein Ordner erstellt wird, wird außerdem eine Verknüpfung zum Ordner, zum übergeordneten Ordner und zum übergeordneten Ordner der nächsthöheren Ebene erstellt.

Diese automatisch erstellten Verknüpfungsdateien **enthalten Informationen über den Ursprung**, etwa ob es sich um eine **Datei** **oder** einen **Ordner** handelt, die **MAC**-**Zeitstempel** dieser Datei, Informationen über das **Volume**, auf dem die Datei gespeichert ist, sowie den **Ordner der Zieldatei**. Diese Informationen können nützlich sein, um diese Dateien wiederherzustellen, falls sie entfernt wurden.

Außerdem entspricht das **Erstellungsdatum der Verknüpfungsdatei** dem ersten **Zeitpunkt**, zu dem die ursprüngliche Datei **erstmals** **verwendet** wurde, und das **Änderungsdatum** der Verknüpfungsdatei dem letzten **Zeitpunkt**, zu dem die Ursprungsdatei verwendet wurde.

Zur Untersuchung dieser Dateien kann [**LinkParser**](http://4discovery.com/our-tools/) verwendet werden.

In diesem Tool finden Sie **2 Sätze** von Zeitstempeln:

- **Erster Satz:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
- **Zweiter Satz:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

Der erste Satz von Zeitstempeln bezieht sich auf die **Zeitstempel der Datei selbst**. Der zweite Satz bezieht sich auf die **Zeitstempel der verknüpften Datei**.

Dieselben Informationen können mit dem Windows-CLI-Tool [**LECmd.exe**](https://github.com/EricZimmerman/LECmd) abgerufen werden.
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
In diesem Fall werden die Informationen in einer CSV-Datei gespeichert.

### Jumplists

Hierbei handelt es sich um die für jede Anwendung angegebenen zuletzt verwendeten Dateien. Es ist die Liste der **zuletzt von einer Anwendung verwendeten Dateien**, auf die Sie in jeder Anwendung zugreifen können. Sie können **automatisch oder benutzerdefiniert** erstellt werden.

Die **automatisch** erstellten **Jumplists** werden unter `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` gespeichert. Die **Jumplists** werden nach dem Format `{id}.autmaticDestinations-ms` benannt, wobei die anfängliche ID die ID der Anwendung ist.

Die benutzerdefinierten **Jumplists** werden unter `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\` gespeichert und normalerweise von der Anwendung erstellt, weil etwas **Wichtiges** mit der Datei passiert ist (beispielsweise wurde sie als Favorit markiert).

Die **Erstellungszeit** einer **Jumplist** gibt bei jeder **Jumplist** an, **wann zum ersten Mal auf die Datei zugegriffen wurde**, und die **Änderungszeit, wann zuletzt** darauf zugegriffen wurde.

Sie können die **Jumplists** mit [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md) untersuchen.

![Zuletzt verwendete Dokumente (LNK) – Jumplists: Sie können die Jumplists mit JumplistExplorer untersuchen](<../../../images/image (168).png>)

(_Beachten Sie, dass sich die von JumplistExplorer bereitgestellten Zeitstempel auf die Jumplist-Datei selbst beziehen._)

### Shellbags

[**Folgen Sie diesem Link, um zu erfahren, was Shellbags sind.**](interesting-windows-registry-keys.md#shellbags)

## Verwendung von Windows-USBs

Anhand der Erstellung folgender Elemente kann festgestellt werden, dass ein USB-Gerät verwendet wurde:

- Windows Recent Folder
- Microsoft Office Recent Folder
- Jumplists

Beachten Sie, dass einige LNK-Dateien nicht auf den ursprünglichen Pfad, sondern auf den WPDNSE-Ordner verweisen:

![Shellbags – Verwendung von Windows-USBs: Beachten Sie, dass einige LNK-Dateien nicht auf den ursprünglichen Pfad, sondern auf den WPDNSE-Ordner verweisen](<../../../images/image (218).png>)

Die Dateien im Ordner WPDNSE sind Kopien der ursprünglichen Dateien. Sie bleiben daher nach einem Neustart des PCs nicht erhalten, und die GUID stammt aus einem Shellbag.

### Registry-Informationen

[Auf dieser Seite erfahren Sie](interesting-windows-registry-keys.md#usb-information), welche Registry-Schlüssel interessante Informationen über verbundene USB-Geräte enthalten.

### setupapi

Überprüfen Sie die Datei `C:\Windows\inf\setupapi.dev.log`, um die Zeitstempel der USB-Verbindung zu erhalten (suchen Sie nach `Section start`).

![Registry-Informationen – setupapi: Überprüfen Sie die Datei C: Windows inf setupapi.dev.log, um die Zeitstempel der USB-Verbindung zu erhalten (suchen Sie nach Section start)](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) kann verwendet werden, um Informationen über USB-Geräte zu erhalten, die mit einem Image verbunden waren.

![setupapi – USB Detective: USBDetective kann verwendet werden, um Informationen über USB-Geräte zu erhalten, die mit einem Image verbunden waren](<../../../images/image (452).png>)

### Plug and Play Cleanup

Die geplante Aufgabe namens „Plug and Play Cleanup“ dient hauptsächlich zum Entfernen veralteter Treiberversionen. Entgegen ihrem angegebenen Zweck, die neueste Treiberpaketversion beizubehalten, legen Online-Quellen nahe, dass sie auch Treiber entfernt, die 30 Tage lang inaktiv waren. Folglich können Treiber von Wechseldatenträgern, die in den vergangenen 30 Tagen nicht verbunden waren, gelöscht werden.<sup>[[1]](#references)</sup>

Die Aufgabe befindet sich unter folgendem Pfad: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

Ein Screenshot mit dem Inhalt der Aufgabe ist hier zu sehen: ![USB Detective – Plug and Play Cleanup: Die Aufgabe befindet sich unter folgendem Pfad: C: Windows System32 Tasks Microsoft Windows Plug and Play Plug and Play Cleanup](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Wichtige Komponenten und Einstellungen der Aufgabe:**

- **pnpclean.dll**: Diese DLL ist für den eigentlichen Bereinigungsvorgang verantwortlich.
- **UseUnifiedSchedulingEngine**: Auf `TRUE` gesetzt, was die Verwendung der generischen Aufgabenplanungs-Engine angibt.
- **MaintenanceSettings**:
- **Period ('P1M')**: Weist den Task Scheduler an, die Bereinigungsaufgabe während der regulären automatischen Wartung monatlich zu starten.
- **Deadline ('P2M')**: Weist den Task Scheduler an, die Aufgabe während der automatischen Notfallwartung auszuführen, wenn die Aufgabe zwei aufeinanderfolgende Monate lang fehlschlägt.

Diese Konfiguration stellt eine regelmäßige Wartung und Bereinigung der Treiber sicher und sieht eine erneute Ausführung der Aufgabe im Fall aufeinanderfolgender Fehler vor.

**Weitere Informationen finden Sie unter:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)

## E-Mails

E-Mails enthalten **2 interessante Teile: die Header und den Inhalt** der E-Mail. In den **Headern** finden Sie Informationen wie:

- **Wer** die E-Mails gesendet hat (E-Mail-Adresse, IP-Adresse, Mailserver, die die E-Mail weitergeleitet haben)
- **Wann** die E-Mail gesendet wurde

Außerdem können Sie in den Headern `References` und `In-Reply-To` die ID der Nachrichten finden:

![Plug and Play Cleanup – E-Mails: Wann wurde die E-Mail gesendet](<../../../images/image (593).png>)

### Windows Mail App

Diese Anwendung speichert E-Mails im HTML- oder Textformat. Sie finden die E-Mails in Unterordnern innerhalb von `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`. Die E-Mails werden mit der Erweiterung `.dat` gespeichert.

Die **Metadaten** der E-Mails und die **Kontakte** befinden sich in der **EDB-Datenbank**: `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`

**Ändern Sie die Erweiterung** der Datei von `.vol` in `.edb`; anschließend können Sie das Tool [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) verwenden, um sie zu öffnen. In der Tabelle `Message` können Sie die E-Mails sehen.

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

![Windows Mail App – Microsoft Outlook: Sie können die PST-Datei mit dem Tool Kernel PST Viewer öffnen](<../../../images/image (498).png>)

### Microsoft Outlook OST Files

Eine **OST-Datei** wird von Microsoft Outlook erzeugt, wenn es mit einem **IMAP**- oder einem **Exchange**-Server konfiguriert ist, und speichert ähnliche Informationen wie eine PST-Datei. Diese Datei wird mit dem Server synchronisiert, wobei Daten für **die letzten 12 Monate** bis zu einer **maximalen Größe von 50 GB** gespeichert werden. Sie befindet sich im selben Verzeichnis wie die PST-Datei. Zum Anzeigen einer OST-Datei kann der [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html) verwendet werden.

### Abrufen von Anhängen

Verlorene Anhänge können möglicherweise wiederhergestellt werden aus:

- Für **IE10**: `%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook`
- Für **IE11 und höher**: `%APPDATA%\Local\Microsoft\InetCache\Content.Outlook`

### Thunderbird MBOX Files

**Thunderbird** verwendet **MBOX-Dateien** zum Speichern von Daten. Diese befinden sich unter `\Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles`.

### Miniaturansichten von Bildern

- **Windows XP und 8-8.1**: Beim Zugriff auf einen Ordner mit Miniaturansichten wird eine `thumbs.db`-Datei mit Bildvorschauen erstellt, die auch nach dem Löschen erhalten bleiben.
- **Windows 7/10**: `thumbs.db` wird erstellt, wenn über einen UNC-Pfad über ein Netzwerk auf den Ordner zugegriffen wird.
- **Windows Vista und neuer**: Miniaturansichten werden zentral in `%userprofile%\AppData\Local\Microsoft\Windows\Explorer` gespeichert. Die Dateien werden **thumbcache_xxx.db** genannt. [**Thumbsviewer**](https://thumbsviewer.github.io) und [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) sind Tools zum Anzeigen dieser Dateien.

### Windows Registry-Informationen

Die Windows Registry, in der umfangreiche System- und Benutzeraktivitätsdaten gespeichert werden, befindet sich in Dateien unter:

- `%windir%\System32\Config` für verschiedene `HKEY_LOCAL_MACHINE`-Unterschlüssel.
- `%UserProfile%{User}\NTUSER.DAT` für `HKEY_CURRENT_USER`.
- Windows Vista und spätere Versionen sichern Registry-Dateien von `HKEY_LOCAL_MACHINE` unter `%Windir%\System32\Config\RegBack\`.
- Zusätzlich werden Informationen zur Programmausführung ab Windows Vista und Windows 2008 Server unter `%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT` gespeichert.

### Tools

Einige Tools sind zur Analyse der Registry-Dateien hilfreich:

- **Registry Editor**: Es ist in Windows installiert. Dabei handelt es sich um eine GUI zur Navigation durch die Windows Registry der aktuellen Sitzung.
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): Damit können Sie die Registry-Datei laden und sie über eine GUI durchsuchen. Es enthält außerdem Bookmarks, die Schlüssel mit interessanten Informationen hervorheben.
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): Auch dieses Tool verfügt über eine GUI, mit der Sie durch die geladene Registry navigieren können. Außerdem enthält es Plugins, die interessante Informationen innerhalb der geladenen Registry hervorheben.
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): Eine weitere GUI-Anwendung, die wichtige Informationen aus der geladenen Registry extrahieren kann.

### Wiederherstellung gelöschter Elemente

Wenn ein Schlüssel gelöscht wird, wird er als solcher markiert. Er wird jedoch erst entfernt, wenn der von ihm belegte Speicherplatz benötigt wird. Daher ist es mit Tools wie **Registry Explorer** möglich, diese gelöschten Schlüssel wiederherzustellen.

### Last Write Time

Jeder Schlüssel-Wert enthält einen **Zeitstempel**, der angibt, wann er zuletzt geändert wurde.

### SAM

Die Datei bzw. der Hive **SAM** enthält die **Hashes der Benutzer-, Gruppen- und Benutzerpasswörter** des Systems.

Unter `SAM\Domains\Account\Users` erhalten Sie den Benutzernamen, die RID, den letzten Login, die letzte fehlgeschlagene Anmeldung, den Anmeldezähler, die Kennwortrichtlinie und den Zeitpunkt der Kontoerstellung. Um die **Hashes** zu erhalten, benötigen Sie außerdem die Datei bzw. den Hive **SYSTEM**.

### Interessante Einträge in der Windows Registry


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Ausgeführte Programme

### Grundlegende Windows-Prozesse

In [diesem Beitrag](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) erfahren Sie mehr über häufige Windows-Prozesse, mit denen sich verdächtiges Verhalten erkennen lässt.

### Kürzlich verwendete Windows-Apps

In der Registry `NTUSER.DAT` können Sie unter dem Pfad `Software\Microsoft\Current Version\Search\RecentApps` Unterschlüssel mit Informationen über die **ausgeführte Anwendung**, den **Zeitpunkt der letzten** Ausführung und die **Anzahl der** Starts finden.

### BAM (Background Activity Moderator)

Sie können die Datei `SYSTEM` mit einem Registry-Editor öffnen. Unter dem Pfad `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` finden Sie Informationen über die **von jedem Benutzer ausgeführten Anwendungen** (beachten Sie `{SID}` im Pfad) sowie darüber, **wann** sie ausgeführt wurden (der Zeitpunkt befindet sich im Data-Wert der Registry).

### Windows Prefetch

Prefetching ist eine Technik, mit der ein Computer die erforderlichen Ressourcen, die zum Anzeigen von Inhalten benötigt werden und auf die ein Benutzer **in naher Zukunft möglicherweise zugreift**, unbemerkt **abrufen** kann, damit schneller auf die Ressourcen zugegriffen werden kann.

Windows Prefetch erstellt **Caches der ausgeführten Programme**, damit diese schneller geladen werden können. Diese Caches werden als `.pf`-Dateien im Pfad `C:\Windows\Prefetch` erstellt. In XP/VISTA/WIN7 sind maximal 128 Dateien und in Win8/Win10 maximal 1024 Dateien zulässig.

Der Dateiname wird als `{program_name}-{hash}.pf` erstellt (der Hash basiert auf dem Pfad und den Argumenten der ausführbaren Datei). In W10 werden diese Dateien komprimiert. Beachten Sie, dass das bloße Vorhandensein der Datei angibt, dass **das Programm irgendwann ausgeführt wurde**.

Die Datei `C:\Windows\Prefetch\Layout.ini` enthält die **Namen der Ordner der vorab abgerufenen Dateien**. Diese Datei enthält **Informationen über die Anzahl der Ausführungen**, die **Ausführungszeitpunkte** sowie die vom Programm **geöffneten** **Dateien**.

Zur Untersuchung dieser Dateien können Sie das Tool [**PEcmd.exe**](https://github.com/EricZimmerman/PECmd) verwenden:
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

**Superprefetch** verfolgt dasselbe Ziel wie Prefetch: **Programme schneller zu laden**, indem vorhergesagt wird, was als Nächstes geladen wird. Es ersetzt jedoch nicht den Prefetch-Dienst.\
Dieser Dienst erzeugt Datenbankdateien in `C:\Windows\Prefetch\Ag*.db`.

In diesen Datenbanken finden Sie den **Namen** des **Programms**, die **Anzahl** der **Ausführungen**, **geöffnete** **Dateien**, das **aufgerufene** **Volume**, den **vollständigen** **Pfad**, **Zeiträume** und **Zeitstempel**.

Sie können mit dem Tool [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) auf diese Informationen zugreifen.

### SRUM

**System Resource Usage Monitor** (**SRUM**) **überwacht** die von einem **Prozess** **verbrauchten** **Ressourcen**. Es wurde in W8 eingeführt und speichert die Daten in einer ESE-Datenbank unter `C:\Windows\System32\sru\SRUDB.dat`.

Es liefert die folgenden Informationen:

- AppID und Pfad
- Benutzer, der den Prozess ausgeführt hat
- Gesendete Bytes
- Empfangene Bytes
- Netzwerkschnittstelle
- Verbindungsdauer
- Prozessdauer

Diese Informationen werden alle 60 Minuten aktualisiert.

Sie können das Datum aus dieser Datei mit dem Tool [**srum_dump**](https://github.com/MarkBaggett/srum-dump) abrufen.
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```
### AppCompatCache (ShimCache)

Der **AppCompatCache**, auch als **ShimCache** bezeichnet, ist Bestandteil der von **Microsoft** entwickelten **Application Compatibility Database**, die Probleme mit der Anwendungskompatibilität beheben soll. Diese Systemkomponente zeichnet verschiedene Dateimetadaten auf, darunter:

- Vollständiger Pfad der Datei
- Größe der Datei
- Zeitpunkt der letzten Änderung unter **$Standard_Information** (SI)
- Zeitpunkt der letzten Aktualisierung des ShimCache
- Process Execution Flag

Diese Daten werden abhängig von der Version des Betriebssystems an bestimmten Speicherorten in der Registry gespeichert:

- Unter XP werden die Daten unter `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache` gespeichert, mit einer Kapazität von 96 Einträgen.
- Für Server 2003 sowie für die Windows-Versionen 2008, 2012, 2016, 7, 8 und 10 lautet der Speicherpfad `SYSTEM\CurrentControlSet\Control\SessionManager\AppCompatCache\AppCompatCache`; dabei werden jeweils 512 bzw. 1024 Einträge aufgenommen.

Zum Parsen der gespeicherten Informationen wird die Verwendung des Tools [**AppCompatCacheParser**](https://github.com/EricZimmerman/AppCompatCacheParser) empfohlen.

![SRUM - AppCompatCache (ShimCache): Zum Parsen der gespeicherten Informationen wird die Verwendung des Tools AppCompatCacheParser empfohlen](<../../../images/image (75).png>)

### Amcache

Die Datei **Amcache.hve** ist im Wesentlichen ein Registry-Hive, der Details zu Anwendungen protokolliert, die auf einem System ausgeführt wurden. Sie befindet sich normalerweise unter `C:\Windows\AppCompat\Programas\Amcache.hve`.

Diese Datei ist dafür bekannt, Datensätze kürzlich ausgeführter Prozesse zu speichern, einschließlich der Pfade zu den ausführbaren Dateien und deren SHA1-Hashes. Diese Informationen sind für die Nachverfolgung der Aktivitäten von Anwendungen auf einem System von unschätzbarem Wert.

Zum Extrahieren und Analysieren der Daten aus **Amcache.hve** kann das Tool [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser) verwendet werden. Der folgende Befehl zeigt beispielhaft, wie AmcacheParser verwendet wird, um den Inhalt der Datei **Amcache.hve** zu parsen und die Ergebnisse im CSV-Format auszugeben:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
Unter den generierten CSV-Dateien ist `Amcache_Unassociated file entries` aufgrund der umfangreichen Informationen, die sie über nicht zugeordnete Dateieinträge liefert, besonders bemerkenswert.

Die interessanteste generierte CVS-Datei ist `Amcache_Unassociated file entries`.

### RecentFileCache

Dieses Artefakt ist in W7 nur unter `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` zu finden und enthält Informationen über die kürzliche Ausführung einiger Binärdateien.

Du kannst das Tool [**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser) verwenden, um die Datei zu parsen.

### Geplante Tasks

Du kannst sie aus `C:\Windows\Tasks` oder `C:\Windows\System32\Tasks` extrahieren und als XML lesen.

### Services

Du findest sie in der Registry unter `SYSTEM\ControlSet001\Services`. Du kannst sehen, was ausgeführt wird und wann dies geschieht.

### **Windows Store**

Die installierten Anwendungen befinden sich unter `\ProgramData\Microsoft\Windows\AppRepository\`\
Dieses Repository enthält in der Datenbank **`StateRepository-Machine.srd`** ein **Log** mit **jeder im System installierten Anwendung**.

In der Application-Tabelle dieser Datenbank können die Spalten „Application ID“, „PackageNumber“ und „Display Name“ gefunden werden. Diese Spalten enthalten Informationen über vorinstallierte und installierte Anwendungen. Es kann festgestellt werden, ob Anwendungen deinstalliert wurden, da die IDs installierter Anwendungen sequenziell sein sollten.

Es ist außerdem möglich, **installierte Anwendungen** im Registry-Pfad `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`\
und **deinstallierte** **Anwendungen** unter `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\` zu finden.

## Windows-Ereignisse

Informationen, die in Windows-Ereignissen erscheinen, sind:

- Was passiert ist
- Zeitstempel (UTC + 0)
- Beteiligte Benutzer
- Beteiligte Hosts (Hostname, IP)
- Aufgerufene Assets (Dateien, Ordner, Drucker, Services)

Die Logs befinden sich vor Windows Vista unter `C:\Windows\System32\config` und ab Windows Vista unter `C:\Windows\System32\winevt\Logs`. Vor Windows Vista lagen die Ereignis-Logs im Binärformat vor; danach liegen sie im **XML-Format** vor und verwenden die Erweiterung **.evtx**.

Der Speicherort der Ereignisdateien kann in der SYSTEM-Registry unter **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`** gefunden werden.

Sie können über die Windows-Ereignisanzeige (**`eventvwr.msc`**) oder mit anderen Tools wie [**Event Log Explorer**](https://eventlogxp.com) **oder** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)** visualisiert werden.**

## Windows Security Event Logging verstehen

Zugriffsereignisse werden in der Security-Konfigurationsdatei unter `C:\Windows\System32\winevt\Security.evtx` aufgezeichnet. Die Größe dieser Datei kann angepasst werden. Wenn ihre Kapazität erreicht ist, werden ältere Ereignisse überschrieben. Zu den aufgezeichneten Ereignissen gehören Benutzeran- und -abmeldungen, Benutzeraktionen und Änderungen an den Security-Einstellungen sowie der Zugriff auf Dateien, Ordner und gemeinsam genutzte Assets.

### Wichtige Event IDs für die Benutzerauthentifizierung:

- **EventID 4624**: Gibt an, dass ein Benutzer erfolgreich authentifiziert wurde.
- **EventID 4625**: Signalisiert einen Authentifizierungsfehler.
- **EventIDs 4634/4647**: Stellen Benutzerabmeldungen dar.
- **EventID 4672**: Bezeichnet eine Anmeldung mit administrativen Berechtigungen.

#### Subtypen innerhalb von EventID 4634/4647:

- **Interactive (2)**: Direkte Benutzeranmeldung.
- **Network (3)**: Zugriff auf gemeinsam genutzte Ordner.
- **Batch (4)**: Ausführung von Batch-Prozessen.
- **Service (5)**: Start von Services.
- **Proxy (6)**: Proxy-Authentifizierung.
- **Unlock (7)**: Entsperren des Bildschirms mit einem Passwort.
- **Network Cleartext (8)**: Übertragung eines Passworts im Klartext, häufig über IIS.
- **New Credentials (9)**: Verwendung anderer Credentials für den Zugriff.
- **Remote Interactive (10)**: Anmeldung über Remote Desktop oder Terminal Services.
- **Cache Interactive (11)**: Anmeldung mit zwischengespeicherten Credentials ohne Kontakt zu einem Domain Controller.
- **Cache Remote Interactive (12)**: Remote-Anmeldung mit zwischengespeicherten Credentials.
- **Cached Unlock (13)**: Entsperren mit zwischengespeicherten Credentials.

#### Status- und Substatus-Codes für EventID 4625:

- **0xC0000064**: Der Benutzername existiert nicht – könnte auf einen Angriff zur Enumeration von Benutzernamen hindeuten.
- **0xC000006A**: Der korrekte Benutzername, aber ein falsches Passwort – möglicher Versuch von Password Guessing oder Brute Force.
- **0xC0000234**: Das Benutzerkonto wurde gesperrt – kann auf einen Brute-Force-Angriff mit mehreren fehlgeschlagenen Anmeldungen folgen.
- **0xC0000072**: Das Konto ist deaktiviert – nicht autorisierte Versuche, auf deaktivierte Konten zuzugreifen.
- **0xC000006F**: Anmeldung außerhalb der erlaubten Zeit – weist auf Zugriffsversuche außerhalb der festgelegten Anmeldezeiten hin und kann ein Anzeichen für unbefugten Zugriff sein.
- **0xC0000070**: Verletzung von Workstation-Einschränkungen – könnte ein Versuch sein, sich von einem nicht autorisierten Standort anzumelden.
- **0xC0000193**: Ablauf des Kontos – Zugriffsversuche mit abgelaufenen Benutzerkonten.
- **0xC0000071**: Abgelaufenes Passwort – Anmeldeversuche mit veralteten Passwörtern.
- **0xC0000133**: Probleme bei der Zeitsynchronisierung – große Zeitabweichungen zwischen Client und Server können auf ausgefeiltere Angriffe wie Pass-the-Ticket hindeuten.
- **0xC0000224**: Eine obligatorische Passwortänderung ist erforderlich – häufige obligatorische Änderungen könnten auf einen Versuch hindeuten, die Kontosicherheit zu destabilisieren.
- **0xC0000225**: Weist eher auf einen Systemfehler als auf ein Security-Problem hin.
- **0xC000015b**: Nicht erlaubter Anmeldungstyp – Zugriffsversuch mit einem nicht autorisierten Anmeldungstyp, beispielsweise wenn ein Benutzer versucht, eine Service-Anmeldung auszuführen.

#### EventID 4616:

- **Time Change**: Änderung der Systemzeit, wodurch die zeitliche Abfolge von Ereignissen verschleiert werden könnte.

#### EventID 6005 und 6006:

- **Systemstart und Herunterfahren**: EventID 6005 zeigt an, dass das System gestartet wurde, während EventID 6006 das Herunterfahren kennzeichnet.

#### EventID 1102:

- **Löschen von Logs**: Security-Logs wurden gelöscht, was häufig ein Warnsignal für die Verschleierung illegaler Aktivitäten ist.

#### EventIDs für das Tracking von USB-Geräten:

- **20001 / 20003 / 10000**: Erste Verbindung eines USB-Geräts.
- **10100**: Aktualisierung des USB-Treibers.
- **EventID 112**: Zeitpunkt des Einsteckens eines USB-Geräts.

Praktische Beispiele zur Simulation dieser Anmeldungstypen und von Möglichkeiten zum Credential Dumping findest du im [detaillierten Leitfaden von Altered Security](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).

Ereignisdetails, einschließlich Status- und Substatus-Codes, liefern weitere Erkenntnisse über die Ursachen von Ereignissen, insbesondere bei Event ID 4625.

### Wiederherstellung von Windows-Ereignissen

Um die Wahrscheinlichkeit der Wiederherstellung gelöschter Windows-Ereignisse zu erhöhen, sollte der verdächtige Computer durch direktes Ziehen des Netzsteckers ausgeschaltet werden. **Bulk_extractor**, ein Recovery-Tool, für das die Erweiterung `.evtx` angegeben wird, wird empfohlen, um zu versuchen, solche Ereignisse wiederherzustellen.

### Identifizierung häufiger Angriffe über Windows-Ereignisse

Eine umfassende Anleitung zur Verwendung von Windows Event IDs bei der Identifizierung häufiger Cyberangriffe findest du unter [Red Team Recipe](https://redteamrecipe.com/event-codes/).

#### Brute-Force-Angriffe

Erkennbar an mehreren EventID-4625-Einträgen, gefolgt von einer EventID 4624, wenn der Angriff erfolgreich ist.

#### Zeitänderung

Wird durch EventID 4616 aufgezeichnet. Änderungen an der Systemzeit können die forensische Analyse erschweren.

#### Tracking von USB-Geräten

Nützliche System-EventIDs für das Tracking von USB-Geräten sind 20001/20003/10000 für die erstmalige Verwendung, 10100 für Treiberaktualisierungen und EventID 112 von DeviceSetupManager für Zeitstempel des Einsteckens.

#### System-Energieereignisse

EventID 6005 zeigt den Systemstart an, während EventID 6006 das Herunterfahren kennzeichnet.

#### Löschen von Logs

Security EventID 1102 signalisiert das Löschen von Logs, ein kritisches Ereignis für die forensische Analyse.

## Referenzen

- [1] [Windows Plug and Play Cleanup](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)

{{#include ../../../banners/hacktricks-training.md}}
