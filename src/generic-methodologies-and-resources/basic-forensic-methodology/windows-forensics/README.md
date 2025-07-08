# Windows Artefakte

{{#include ../../../banners/hacktricks-training.md}}

## Generische Windows Artefakte

### Windows 10 Benachrichtigungen

Im Pfad `\Users\<username>\AppData\Local\Microsoft\Windows\Notifications` finden Sie die Datenbank `appdb.dat` (vor dem Windows Jubiläum) oder `wpndatabase.db` (nach dem Windows Jubiläum).

In dieser SQLite-Datenbank finden Sie die Tabelle `Notification` mit allen Benachrichtigungen (im XML-Format), die interessante Daten enthalten können.

### Zeitachse

Die Zeitachse ist ein Windows-Feature, das eine **chronologische Historie** der besuchten Webseiten, bearbeiteten Dokumente und ausgeführten Anwendungen bereitstellt.

Die Datenbank befindet sich im Pfad `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. Diese Datenbank kann mit einem SQLite-Tool oder mit dem Tool [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) **geöffnet werden, das 2 Dateien generiert, die mit dem Tool** [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md) **geöffnet werden können.**

### ADS (Alternative Datenströme)

Heruntergeladene Dateien können den **ADS Zone.Identifier** enthalten, der angibt, **wie** sie **heruntergeladen** wurden, z. B. aus dem Intranet, Internet usw. Einige Software (wie Browser) fügt normalerweise sogar **mehr** **Informationen** hinzu, wie die **URL**, von der die Datei heruntergeladen wurde.

## **Dateisicherungen**

### Papierkorb

In Vista/Win7/Win8/Win10 befindet sich der **Papierkorb** im Ordner **`$Recycle.bin`** im Stammverzeichnis des Laufwerks (`C:\$Recycle.bin`).\
Wenn eine Datei in diesem Ordner gelöscht wird, werden 2 spezifische Dateien erstellt:

- `$I{id}`: Dateiinformationen (Datum, an dem sie gelöscht wurde)
- `$R{id}`: Inhalt der Datei

![](<../../../images/image (1029).png>)

Mit diesen Dateien können Sie das Tool [**Rifiuti**](https://github.com/abelcheung/rifiuti2) verwenden, um die ursprüngliche Adresse der gelöschten Dateien und das Datum, an dem sie gelöscht wurden, zu erhalten (verwenden Sie `rifiuti-vista.exe` für Vista – Win10).
```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```
![](<../../../images/image (495) (1) (1) (1).png>)

### Volume Shadow Copies

Shadow Copy ist eine Technologie, die in Microsoft Windows enthalten ist und **Sicherungs kopien** oder Schnappschüsse von Computerdateien oder -volumes erstellen kann, selbst wenn sie verwendet werden.

Diese Sicherungen befinden sich normalerweise im `\System Volume Information` im Stammverzeichnis des Dateisystems, und der Name besteht aus **UIDs**, die im folgenden Bild angezeigt werden:

![](<../../../images/image (94).png>)

Durch das Einbinden des forensischen Images mit dem **ArsenalImageMounter** kann das Tool [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) verwendet werden, um eine Schattenkopie zu inspizieren und sogar **die Dateien** aus den Schattenkopien zu extrahieren.

![](<../../../images/image (576).png>)

Der Registrierungseintrag `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` enthält die Dateien und Schlüssel **die nicht gesichert werden sollen**:

![](<../../../images/image (254).png>)

Die Registrierung `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` enthält ebenfalls Konfigurationsinformationen über die `Volume Shadow Copies`.

### Office AutoSaved Files

Die automatisch gespeicherten Office-Dateien finden Sie unter: `C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## Shell Items

Ein Shell-Element ist ein Element, das Informationen darüber enthält, wie auf eine andere Datei zugegriffen werden kann.

### Recent Documents (LNK)

Windows **erstellt automatisch** diese **Verknüpfungen**, wenn der Benutzer **eine Datei öffnet, verwendet oder erstellt** in:

- Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
- Office: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

Wenn ein Ordner erstellt wird, wird auch ein Link zu dem Ordner, dem übergeordneten Ordner und dem Großelternordner erstellt.

Diese automatisch erstellten Linkdateien **enthalten Informationen über den Ursprung**, wie ob es sich um eine **Datei** **oder** einen **Ordner** handelt, **MAC** **Zeiten** dieser Datei, **Volumeninformationen**, wo die Datei gespeichert ist, und **Ordner der Zieldatei**. Diese Informationen können nützlich sein, um diese Dateien wiederherzustellen, falls sie entfernt wurden.

Außerdem ist das **Erstellungsdatum der Linkdatei** die erste **Zeit**, zu der die Originaldatei **zum ersten Mal** **verwendet** wurde, und das **Änderungsdatum** der Linkdatei ist die **letzte** **Zeit**, zu der die Ursprungsdatei verwendet wurde.

Um diese Dateien zu inspizieren, können Sie [**LinkParser**](http://4discovery.com/our-tools/) verwenden.

In diesem Tool finden Sie **2 Sätze** von Zeitstempeln:

- **Erster Satz:**
1. FileModifiedDate
2. FileAccessDate
3. FileCreationDate
- **Zweiter Satz:**
1. LinkModifiedDate
2. LinkAccessDate
3. LinkCreationDate.

Der erste Satz von Zeitstempeln bezieht sich auf die **Zeitstempel der Datei selbst**. Der zweite Satz bezieht sich auf die **Zeitstempel der verlinkten Datei**.

Sie können die gleichen Informationen erhalten, indem Sie das Windows-CLI-Tool [**LECmd.exe**](https://github.com/EricZimmerman/LECmd) ausführen.
```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```
In diesem Fall werden die Informationen in einer CSV-Datei gespeichert.

### Jumplists

Dies sind die zuletzt verwendeten Dateien, die pro Anwendung angezeigt werden. Es ist die Liste der **zuletzt von einer Anwendung verwendeten Dateien**, auf die Sie in jeder Anwendung zugreifen können. Sie können **automatisch oder benutzerdefiniert** erstellt werden.

Die **jumplists**, die automatisch erstellt werden, werden in `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` gespeichert. Die jumplists sind nach dem Format `{id}.autmaticDestinations-ms` benannt, wobei die ursprüngliche ID die ID der Anwendung ist.

Die benutzerdefinierten jumplists werden in `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\` gespeichert und werden normalerweise von der Anwendung erstellt, weil mit der Datei etwas **Wichtiges** passiert ist (vielleicht als Favorit markiert).

Die **Erstellungszeit** einer jumplist gibt die **erste Zeit an, zu der die Datei aufgerufen wurde**, und die **Änderungszeit die letzte Zeit**.

Sie können die jumplists mit [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md) inspizieren.

![](<../../../images/image (168).png>)

(_Beachten Sie, dass die von JumplistExplorer bereitgestellten Zeitstempel sich auf die jumplist-Datei selbst beziehen_)

### Shellbags

[**Folgen Sie diesem Link, um zu erfahren, was die Shellbags sind.**](interesting-windows-registry-keys.md#shellbags)

## Verwendung von Windows-USBs

Es ist möglich zu identifizieren, dass ein USB-Gerät verwendet wurde, dank der Erstellung von:

- Windows Recent Folder
- Microsoft Office Recent Folder
- Jumplists

Beachten Sie, dass einige LNK-Dateien anstelle des ursprünglichen Pfads auf den WPDNSE-Ordner verweisen:

![](<../../../images/image (218).png>)

Die Dateien im WPDNSE-Ordner sind eine Kopie der ursprünglichen, überstehen also keinen Neustart des PCs, und die GUID wird aus einer Shellbag entnommen.

### Registrierungsinformationen

[Überprüfen Sie diese Seite, um zu erfahren](interesting-windows-registry-keys.md#usb-information), welche Registrierungs-Schlüssel interessante Informationen über angeschlossene USB-Geräte enthalten.

### setupapi

Überprüfen Sie die Datei `C:\Windows\inf\setupapi.dev.log`, um die Zeitstempel zu erhalten, wann die USB-Verbindung hergestellt wurde (suchen Sie nach `Section start`).

![](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) kann verwendet werden, um Informationen über die USB-Geräte zu erhalten, die mit einem Bild verbunden wurden.

![](<../../../images/image (452).png>)

### Plug and Play Cleanup

Die geplante Aufgabe, die als 'Plug and Play Cleanup' bekannt ist, dient hauptsächlich der Entfernung veralteter Treiberversionen. Entgegen ihrem angegebenen Zweck, die neueste Treiberpaketversion beizubehalten, deuten Online-Quellen darauf hin, dass sie auch Treiber anvisiert, die seit 30 Tagen inaktiv sind. Folglich können Treiber für abnehmbare Geräte, die in den letzten 30 Tagen nicht verbunden waren, gelöscht werden.

Die Aufgabe befindet sich unter folgendem Pfad: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

Ein Screenshot, der den Inhalt der Aufgabe zeigt, ist bereitgestellt: ![](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Wichtige Komponenten und Einstellungen der Aufgabe:**

- **pnpclean.dll**: Diese DLL ist für den eigentlichen Bereinigungsprozess verantwortlich.
- **UseUnifiedSchedulingEngine**: Auf `TRUE` gesetzt, was die Verwendung der generischen Aufgabenplanung anzeigt.
- **MaintenanceSettings**:
- **Period ('P1M')**: Weist den Task Scheduler an, die Bereinigungsaufgabe monatlich während der regulären automatischen Wartung zu starten.
- **Deadline ('P2M')**: Weist den Task Scheduler an, die Aufgabe während der Notfallautomatik-Wartung auszuführen, wenn die Aufgabe zwei Monate hintereinander fehlschlägt.

Diese Konfiguration stellt eine regelmäßige Wartung und Bereinigung der Treiber sicher, mit Bestimmungen für einen erneuten Versuch der Aufgabe im Falle aufeinanderfolgender Fehler.

**Für weitere Informationen siehe:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)

## E-Mails

E-Mails enthalten **2 interessante Teile: Die Header und den Inhalt** der E-Mail. In den **Headern** finden Sie Informationen wie:

- **Wer** die E-Mails gesendet hat (E-Mail-Adresse, IP, Mail-Server, die die E-Mail umgeleitet haben)
- **Wann** die E-Mail gesendet wurde

Außerdem finden Sie in den Headern `References` und `In-Reply-To` die ID der Nachrichten:

![](<../../../images/image (593).png>)

### Windows Mail App

Diese Anwendung speichert E-Mails in HTML oder Text. Sie finden die E-Mails in Unterordnern unter `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`. Die E-Mails werden mit der Erweiterung `.dat` gespeichert.

Die **Metadaten** der E-Mails und die **Kontakte** können in der **EDB-Datenbank** gefunden werden: `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`

**Ändern Sie die Erweiterung** der Datei von `.vol` in `.edb`, und Sie können das Tool [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) verwenden, um es zu öffnen. In der `Message`-Tabelle können Sie die E-Mails sehen.

### Microsoft Outlook

Wenn Exchange-Server oder Outlook-Clients verwendet werden, gibt es einige MAPI-Header:

- `Mapi-Client-Submit-Time`: Zeit des Systems, als die E-Mail gesendet wurde
- `Mapi-Conversation-Index`: Anzahl der Kindnachrichten des Threads und Zeitstempel jeder Nachricht des Threads
- `Mapi-Entry-ID`: Nachrichtenidentifikator.
- `Mappi-Message-Flags` und `Pr_last_Verb-Executed`: Informationen über den MAPI-Client (Nachricht gelesen? nicht gelesen? geantwortet? umgeleitet? nicht im Büro?)

Im Microsoft Outlook-Client werden alle gesendeten/empfangenen Nachrichten, Kontaktdaten und Kalenderdaten in einer PST-Datei gespeichert unter:

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

Der Registrierungs-Pfad `HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` zeigt die verwendete Datei an.

Sie können die PST-Datei mit dem Tool [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html) öffnen.

![](<../../../images/image (498).png>)

### Microsoft Outlook OST-Dateien

Eine **OST-Datei** wird von Microsoft Outlook erstellt, wenn es mit **IMAP** oder einem **Exchange**-Server konfiguriert ist und ähnliche Informationen wie eine PST-Datei speichert. Diese Datei wird mit dem Server synchronisiert und behält Daten für **die letzten 12 Monate** bis zu einer **maximalen Größe von 50 GB** und befindet sich im selben Verzeichnis wie die PST-Datei. Um eine OST-Datei anzuzeigen, kann der [**Kernel OST Viewer**](https://www.nucleustechnologies.com/ost-viewer.html) verwendet werden.

### Wiederherstellung von Anhängen

Verlorene Anhänge könnten wiederhergestellt werden aus:

- Für **IE10**: `%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook`
- Für **IE11 und höher**: `%APPDATA%\Local\Microsoft\InetCache\Content.Outlook`

### Thunderbird MBOX-Dateien

**Thunderbird** verwendet **MBOX-Dateien**, um Daten zu speichern, die sich unter `\Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles` befinden.

### Bildvorschauen

- **Windows XP und 8-8.1**: Der Zugriff auf einen Ordner mit Thumbnails erzeugt eine `thumbs.db`-Datei, die Bildvorschauen speichert, selbst nach der Löschung.
- **Windows 7/10**: `thumbs.db` wird erstellt, wenn über ein Netzwerk über UNC-Pfad zugegriffen wird.
- **Windows Vista und neuer**: Thumbnail-Vorschauen sind zentral in `%userprofile%\AppData\Local\Microsoft\Windows\Explorer` mit Dateien namens **thumbcache_xxx.db** gespeichert. [**Thumbsviewer**](https://thumbsviewer.github.io) und [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) sind Tools zum Anzeigen dieser Dateien.

### Windows-Registrierungsinformationen

Die Windows-Registrierung, die umfangreiche System- und Benutzeraktivitätsdaten speichert, befindet sich in Dateien in:

- `%windir%\System32\Config` für verschiedene `HKEY_LOCAL_MACHINE`-Unterschlüssel.
- `%UserProfile%{User}\NTUSER.DAT` für `HKEY_CURRENT_USER`.
- Windows Vista und spätere Versionen sichern `HKEY_LOCAL_MACHINE`-Registrierungsdateien in `%Windir%\System32\Config\RegBack\`.
- Darüber hinaus werden Informationen zur Programmausführung in `%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT` ab Windows Vista und Windows 2008 Server gespeichert.

### Tools

Einige Tools sind nützlich, um die Registrierungsdateien zu analysieren:

- **Registrierungs-Editor**: Er ist in Windows installiert. Es ist eine GUI, um durch die Windows-Registrierung der aktuellen Sitzung zu navigieren.
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): Es ermöglicht Ihnen, die Registrierungsdatei zu laden und durch sie mit einer GUI zu navigieren. Es enthält auch Lesezeichen, die Schlüssel mit interessanten Informationen hervorheben.
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): Es hat ebenfalls eine GUI, die es ermöglicht, durch die geladene Registrierung zu navigieren und enthält auch Plugins, die interessante Informationen innerhalb der geladenen Registrierung hervorheben.
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): Eine weitere GUI-Anwendung, die in der Lage ist, wichtige Informationen aus der geladenen Registrierung zu extrahieren.

### Wiederherstellung gelöschter Elemente

Wenn ein Schlüssel gelöscht wird, wird er als solcher markiert, aber bis der Platz, den er einnimmt, benötigt wird, wird er nicht entfernt. Daher ist es möglich, mit Tools wie **Registry Explorer** diese gelöschten Schlüssel wiederherzustellen.

### Letzte Schreibzeit

Jeder Schlüssel-Wert enthält einen **Zeitstempel**, der die letzte Zeit angibt, zu der er geändert wurde.

### SAM

Die Datei/Hive **SAM** enthält die **Benutzer, Gruppen und Benutzerpasswort**-Hashes des Systems.

In `SAM\Domains\Account\Users` können Sie den Benutzernamen, die RID, die letzte Anmeldung, die letzte fehlgeschlagene Anmeldung, den Anmeldezähler, die Passwort-Richtlinie und wann das Konto erstellt wurde, abrufen. Um die **Hashes** zu erhalten, benötigen Sie auch die Datei/Hive **SYSTEM**.

### Interessante Einträge in der Windows-Registrierung

{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Ausgeführte Programme

### Grundlegende Windows-Prozesse

In [diesem Beitrag](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) können Sie mehr über die gängigen Windows-Prozesse erfahren, um verdächtiges Verhalten zu erkennen.

### Windows Recent APPs

Im Registrierungs-`NTUSER.DAT` unter dem Pfad `Software\Microsoft\Current Version\Search\RecentApps` finden Sie Unterschlüssel mit Informationen über die **ausgeführte Anwendung**, **letzte Ausführungszeit** und **Anzahl der Starts**.

### BAM (Background Activity Moderator)

Sie können die `SYSTEM`-Datei mit einem Registrierungseditor öffnen, und im Pfad `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` finden Sie Informationen über die **von jedem Benutzer ausgeführten Anwendungen** (beachten Sie das `{SID}` im Pfad) und **zu welcher Zeit** sie ausgeführt wurden (die Zeit befindet sich im Datenwert der Registrierung).

### Windows Prefetch

Prefetching ist eine Technik, die es einem Computer ermöglicht, stillschweigend **die notwendigen Ressourcen abzurufen, die benötigt werden, um Inhalte anzuzeigen**, auf die ein Benutzer **in naher Zukunft zugreifen könnte**, damit Ressourcen schneller abgerufen werden können.

Windows Prefetch besteht darin, **Caches der ausgeführten Programme** zu erstellen, um sie schneller laden zu können. Diese Caches werden als `.pf`-Dateien im Pfad `C:\Windows\Prefetch` erstellt. Es gibt eine Begrenzung von 128 Dateien in XP/VISTA/WIN7 und 1024 Dateien in Win8/Win10.

Der Dateiname wird als `{program_name}-{hash}.pf` erstellt (der Hash basiert auf dem Pfad und den Argumenten der ausführbaren Datei). In W10 sind diese Dateien komprimiert. Beachten Sie, dass die bloße Anwesenheit der Datei anzeigt, dass **das Programm zu einem bestimmten Zeitpunkt ausgeführt wurde**.

Die Datei `C:\Windows\Prefetch\Layout.ini` enthält die **Namen der Ordner der Dateien, die vorab geladen werden**. Diese Datei enthält **Informationen über die Anzahl der Ausführungen**, **Daten** der Ausführung und **Dateien**, die **vom Programm geöffnet** wurden.

Um diese Dateien zu inspizieren, können Sie das Tool [**PEcmd.exe**](https://github.com/EricZimmerman/PECmd) verwenden:
```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```
![](<../../../images/image (315).png>)

### Superprefetch

**Superprefetch** hat dasselbe Ziel wie Prefetch, **Programme schneller zu laden**, indem vorhergesagt wird, was als Nächstes geladen wird. Es ersetzt jedoch nicht den Prefetch-Dienst.\
Dieser Dienst generiert Datenbankdateien in `C:\Windows\Prefetch\Ag*.db`.

In diesen Datenbanken finden Sie den **Namen** des **Programms**, die **Anzahl** der **Ausführungen**, die **geöffneten** **Dateien**, das **zugreifende** **Volume**, den **kompletten** **Pfad**, **Zeitrahmen** und **Zeitstempel**.

Sie können auf diese Informationen mit dem Tool [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) zugreifen.

### SRUM

**System Resource Usage Monitor** (SRUM) **überwacht** die **Ressourcen**, die von einem Prozess **verbraucht** werden. Es erschien in W8 und speichert die Daten in einer ESE-Datenbank, die sich in `C:\Windows\System32\sru\SRUDB.dat` befindet.

Es gibt die folgenden Informationen:

- AppID und Pfad
- Benutzer, der den Prozess ausgeführt hat
- Gesendete Bytes
- Empfangene Bytes
- Netzwerk-Schnittstelle
- Verbindungsdauer
- Prozessdauer

Diese Informationen werden alle 60 Minuten aktualisiert.

Sie können das Datum aus dieser Datei mit dem Tool [**srum_dump**](https://github.com/MarkBaggett/srum-dump) abrufen.
```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```
### AppCompatCache (ShimCache)

Der **AppCompatCache**, auch bekannt als **ShimCache**, ist Teil der **Application Compatibility Database**, die von **Microsoft** entwickelt wurde, um Probleme mit der Anwendungskompatibilität zu beheben. Dieses Systemkomponente zeichnet verschiedene Stücke von Dateimetadaten auf, die Folgendes umfassen:

- Vollständiger Pfad der Datei
- Größe der Datei
- Letzte Änderungszeit unter **$Standard_Information** (SI)
- Letzte Aktualisierungszeit des ShimCache
- Prozessausführungsflag

Solche Daten werden im Registrierungseditor an bestimmten Orten basierend auf der Version des Betriebssystems gespeichert:

- Für XP werden die Daten unter `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache` mit einer Kapazität von 96 Einträgen gespeichert.
- Für Server 2003 sowie für Windows-Versionen 2008, 2012, 2016, 7, 8 und 10 ist der Speicherpfad `SYSTEM\CurrentControlSet\Control\SessionManager\AppcompatCache\AppCompatCache`, der 512 bzw. 1024 Einträge aufnehmen kann.

Um die gespeicherten Informationen zu analysieren, wird das [**AppCompatCacheParser**-Tool](https://github.com/EricZimmerman/AppCompatCacheParser) empfohlen.

![](<../../../images/image (75).png>)

### Amcache

Die **Amcache.hve**-Datei ist im Wesentlichen ein Registrierungs-Hive, der Details über Anwendungen protokolliert, die auf einem System ausgeführt wurden. Sie befindet sich typischerweise unter `C:\Windows\AppCompat\Programas\Amcache.hve`.

Diese Datei ist bemerkenswert, da sie Aufzeichnungen über kürzlich ausgeführte Prozesse speichert, einschließlich der Pfade zu den ausführbaren Dateien und deren SHA1-Hashes. Diese Informationen sind von unschätzbarem Wert, um die Aktivität von Anwendungen auf einem System zu verfolgen.

Um die Daten aus **Amcache.hve** zu extrahieren und zu analysieren, kann das [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser)-Tool verwendet werden. Der folgende Befehl ist ein Beispiel dafür, wie man AmcacheParser verwendet, um den Inhalt der **Amcache.hve**-Datei zu parsen und die Ergebnisse im CSV-Format auszugeben:
```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```
Unter den generierten CSV-Dateien ist die `Amcache_Unassociated file entries` besonders bemerkenswert, da sie reichhaltige Informationen über nicht zugeordnete Dateieinträge bietet.

Die interessanteste CVS-Datei, die generiert wurde, ist die `Amcache_Unassociated file entries`.

### RecentFileCache

Dieses Artefakt ist nur in W7 unter `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` zu finden und enthält Informationen über die kürzliche Ausführung einiger Binärdateien.

Sie können das Tool [**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser) verwenden, um die Datei zu analysieren.

### Geplante Aufgaben

Sie können sie aus `C:\Windows\Tasks` oder `C:\Windows\System32\Tasks` extrahieren und als XML lesen.

### Dienste

Sie finden sie in der Registrierung unter `SYSTEM\ControlSet001\Services`. Sie können sehen, was ausgeführt wird und wann.

### **Windows Store**

Die installierten Anwendungen finden Sie unter `\ProgramData\Microsoft\Windows\AppRepository\`\
Dieses Repository hat ein **Log** mit **jeder installierten Anwendung** im System innerhalb der Datenbank **`StateRepository-Machine.srd`**.

In der Anwendungstabelle dieser Datenbank ist es möglich, die Spalten: "Application ID", "PackageNumber" und "Display Name" zu finden. Diese Spalten enthalten Informationen über vorinstallierte und installierte Anwendungen und es kann festgestellt werden, ob einige Anwendungen deinstalliert wurden, da die IDs der installierten Anwendungen sequenziell sein sollten.

Es ist auch möglich, **installierte Anwendungen** im Registrierungspfad: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`\
Und **deinstallierte** **Anwendungen** in: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\` zu finden.

## Windows-Ereignisse

Informationen, die in Windows-Ereignissen erscheinen, sind:

- Was passiert ist
- Zeitstempel (UTC + 0)
- Beteiligte Benutzer
- Beteiligte Hosts (Hostname, IP)
- Zugängliche Assets (Dateien, Ordner, Drucker, Dienste)

Die Protokolle befinden sich in `C:\Windows\System32\config` vor Windows Vista und in `C:\Windows\System32\winevt\Logs` nach Windows Vista. Vor Windows Vista waren die Ereignisprotokolle im Binärformat und danach sind sie im **XML-Format** und verwenden die **.evtx**-Erweiterung.

Der Speicherort der Ereignisdateien kann in der SYSTEM-Registrierung unter **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`** gefunden werden.

Sie können sie über die Windows-Ereignisanzeige (**`eventvwr.msc`**) oder mit anderen Tools wie [**Event Log Explorer**](https://eventlogxp.com) **oder** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)** visualisieren.**

## Verständnis der Windows-Sicherheitsereignisprotokollierung

Zugriffsereignisse werden in der Sicherheitskonfigurationsdatei aufgezeichnet, die sich unter `C:\Windows\System32\winevt\Security.evtx` befindet. Die Größe dieser Datei ist anpassbar, und wenn ihre Kapazität erreicht ist, werden ältere Ereignisse überschrieben. Aufgezeichnete Ereignisse umfassen Benutzeranmeldungen und -abmeldungen, Benutzeraktionen und Änderungen an Sicherheitseinstellungen sowie den Zugriff auf Dateien, Ordner und gemeinsame Assets.

### Schlüsselereignis-IDs für die Benutzerauthentifizierung:

- **EventID 4624**: Zeigt an, dass sich ein Benutzer erfolgreich authentifiziert hat.
- **EventID 4625**: Signalisiert einen Authentifizierungsfehler.
- **EventIDs 4634/4647**: Stellen Benutzerabmeldeereignisse dar.
- **EventID 4672**: Bezeichnet die Anmeldung mit administrativen Rechten.

#### Untertypen innerhalb von EventID 4634/4647:

- **Interaktiv (2)**: Direkte Benutzeranmeldung.
- **Netzwerk (3)**: Zugriff auf freigegebene Ordner.
- **Batch (4)**: Ausführung von Batch-Prozessen.
- **Dienst (5)**: Dienststarts.
- **Proxy (6)**: Proxy-Authentifizierung.
- **Entsperren (7)**: Bildschirm mit einem Passwort entsperrt.
- **Netzwerk-Klartext (8)**: Übertragung von Klartextpasswörtern, oft von IIS.
- **Neue Anmeldeinformationen (9)**: Verwendung anderer Anmeldeinformationen für den Zugriff.
- **Remote-Interaktiv (10)**: Remote-Desktop- oder Terminaldienste-Anmeldung.
- **Cache-Interaktiv (11)**: Anmeldung mit zwischengespeicherten Anmeldeinformationen ohne Kontakt zum Domänencontroller.
- **Cache-Remote-Interaktiv (12)**: Remote-Anmeldung mit zwischengespeicherten Anmeldeinformationen.
- **Zwischengespeichertes Entsperren (13)**: Entsperren mit zwischengespeicherten Anmeldeinformationen.

#### Status- und Unterstatuscodes für EventID 4625:

- **0xC0000064**: Benutzername existiert nicht - Könnte auf einen Benutzernamen-Enumeration-Angriff hinweisen.
- **0xC000006A**: Richtiger Benutzername, aber falsches Passwort - Möglicher Passwort-Ratenangriff oder Brute-Force-Versuch.
- **0xC0000234**: Benutzerkonto gesperrt - Kann einem Brute-Force-Angriff folgen, der zu mehreren fehlgeschlagenen Anmeldungen führt.
- **0xC0000072**: Konto deaktiviert - Unbefugte Versuche, auf deaktivierte Konten zuzugreifen.
- **0xC000006F**: Anmeldung außerhalb der erlaubten Zeit - Zeigt Versuche an, außerhalb der festgelegten Anmeldezeiten zuzugreifen, ein mögliches Zeichen für unbefugten Zugriff.
- **0xC0000070**: Verletzung der Arbeitsplatzbeschränkungen - Könnte ein Versuch sein, sich von einem unbefugten Standort anzumelden.
- **0xC0000193**: Konto abgelaufen - Zugriffsversuche mit abgelaufenen Benutzerkonten.
- **0xC0000071**: Abgelaufenes Passwort - Anmeldeversuche mit veralteten Passwörtern.
- **0xC0000133**: Zeit-Synchronisationsprobleme - Große Zeitabweichungen zwischen Client und Server können auf ausgeklügeltere Angriffe wie Pass-the-Ticket hinweisen.
- **0xC0000224**: Pflichtänderung des Passworts erforderlich - Häufige verpflichtende Änderungen könnten auf einen Versuch hinweisen, die Kontosicherheit zu destabilisieren.
- **0xC0000225**: Zeigt einen Systemfehler an, nicht ein Sicherheitsproblem.
- **0xC000015b**: Verweigerter Anmeldetyp - Zugriffsversuch mit unbefugtem Anmeldetyp, z. B. ein Benutzer, der versucht, eine Dienstanmeldung auszuführen.

#### EventID 4616:

- **Zeitänderung**: Änderung der Systemzeit, könnte den Zeitablauf der Ereignisse verschleiern.

#### EventID 6005 und 6006:

- **Systemstart und -herunterfahren**: EventID 6005 zeigt den Systemstart an, während EventID 6006 das Herunterfahren markiert.

#### EventID 1102:

- **Protokolllöschung**: Sicherheitsprotokolle werden gelöscht, was oft ein Warnsignal für das Vertuschen illegaler Aktivitäten ist.

#### EventIDs zur Verfolgung von USB-Geräten:

- **20001 / 20003 / 10000**: Erste Verbindung des USB-Geräts.
- **10100**: USB-Treiberaktualisierung.
- **EventID 112**: Zeitpunkt des Einsteckens des USB-Geräts.

Für praktische Beispiele zur Simulation dieser Anmeldetypen und Möglichkeiten zum Abrufen von Anmeldeinformationen siehe [Altered Securitys detaillierte Anleitung](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).

Ereignisdetails, einschließlich Status- und Unterstatuscodes, bieten weitere Einblicke in die Ursachen von Ereignissen, insbesondere bemerkenswert in Event ID 4625.

### Wiederherstellung von Windows-Ereignissen

Um die Chancen auf die Wiederherstellung gelöschter Windows-Ereignisse zu erhöhen, ist es ratsam, den verdächtigen Computer durch direktes Abziehen vom Stromnetz herunterzufahren. **Bulk_extractor**, ein Wiederherstellungstool, das die Erweiterung `.evtx` angibt, wird empfohlen, um solche Ereignisse wiederherzustellen.

### Identifizierung häufiger Angriffe über Windows-Ereignisse

Für eine umfassende Anleitung zur Nutzung von Windows-Ereignis-IDs zur Identifizierung häufiger Cyberangriffe besuchen Sie [Red Team Recipe](https://redteamrecipe.com/event-codes/).

#### Brute-Force-Angriffe

Erkennbar an mehreren EventID 4625-Datensätzen, gefolgt von einer EventID 4624, wenn der Angriff erfolgreich ist.

#### Zeitänderung

Aufgezeichnet durch EventID 4616, können Änderungen an der Systemzeit die forensische Analyse komplizieren.

#### USB-Geräteverfolgung

Nützliche System-Ereignis-IDs zur Verfolgung von USB-Geräten sind 20001/20003/10000 für die erste Nutzung, 10100 für Treiberaktualisierungen und EventID 112 von DeviceSetupManager für Einsteckzeitstempel.

#### Systemstromereignisse

EventID 6005 zeigt den Systemstart an, während EventID 6006 das Herunterfahren markiert.

#### Protokolllöschung

Sicherheits-EventID 1102 signalisiert die Löschung von Protokollen, ein kritisches Ereignis für die forensische Analyse.

{{#include ../../../banners/hacktricks-training.md}}
