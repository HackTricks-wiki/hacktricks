# macOS SIP

{{#include ../../../banners/hacktricks-training.md}}

## **Grundlegende Informationen**

**System Integrity Protection (SIP)** in macOS ist ein Mechanismus, der selbst die privilegiertesten Benutzer daran hindern soll, nicht autorisierte Änderungen an wichtigen Systemordnern vorzunehmen. Diese Funktion spielt eine entscheidende Rolle bei der Aufrechterhaltung der Integrität des Systems, indem sie Aktionen wie das Hinzufügen, Ändern oder Löschen von Dateien in geschützten Bereichen einschränkt. Zu den wichtigsten durch SIP geschützten Ordnern gehören:

- **/System**
- **/bin**
- **/sbin**
- **/usr**

Die Regeln, die das Verhalten von SIP bestimmen, sind in der Konfigurationsdatei unter **`/System/Library/Sandbox/rootless.conf`** definiert. In dieser Datei kennzeichnen Pfade, denen ein Sternchen (\*) vorangestellt ist, Ausnahmen von den ansonsten strengen SIP-Einschränkungen.

Betrachten Sie das folgende Beispiel:
```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
Dieser Ausschnitt deutet darauf hin, dass SIP zwar grundsätzlich das Verzeichnis **`/usr`** schützt, Änderungen jedoch in bestimmten Unterverzeichnissen (`/usr/libexec/cups`, `/usr/local` und `/usr/share/man`) zulässig sind, wie durch das vorangestellte Sternchen (\*) bei ihren Pfaden angezeigt wird.

Um zu überprüfen, ob ein Verzeichnis oder eine Datei durch SIP geschützt ist, können Sie den Befehl **`ls -lOd`** verwenden und prüfen, ob das Flag **`restricted`** oder **`sunlnk`** vorhanden ist. Zum Beispiel:
```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```
In diesem Fall bedeutet das **`sunlnk`**-Flag, dass das Verzeichnis `/usr/libexec/cups` selbst **nicht gelöscht werden kann**, obwohl darin enthaltene Dateien erstellt, geändert oder gelöscht werden können.

Andererseits:
```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```
Hier zeigt das **`restricted`**-Flag an, dass das Verzeichnis `/usr/libexec` durch SIP geschützt ist. In einem durch SIP geschützten Verzeichnis können keine Dateien erstellt, geändert oder gelöscht werden.

Wenn eine Datei außerdem das **`com.apple.rootless`** extended **attribute** enthält, ist diese Datei ebenfalls durch **SIP geschützt**.

> [!TIP]
> Beachte, dass der **Sandbox**-Hook **`hook_vnode_check_setextattr`** jeden Versuch verhindert, das extended attribute **`com.apple.rootless`** zu ändern.

**SIP beschränkt außerdem andere root-Aktionen**, wie etwa:

- Laden nicht vertrauenswürdiger Kernel extensions
- Abrufen von Task-Ports für von Apple signierte Prozesse
- Ändern von NVRAM-Variablen
- Aktivieren von Kernel-Debugging

Die Optionen werden in einer nvram-Variable als Bitflag gespeichert (`csr-active-config` auf Intel; `lp-sip0` wird für ARM aus dem gebooteten Device Tree gelesen). Die Flags findest du im XNU-Quellcode in `csr.sh`:

<figure><img src="../../../images/image (1192).png" alt=""><figcaption></figcaption></figure>

### SIP-Status

Mit folgendem Befehl kannst du überprüfen, ob SIP auf deinem System aktiviert ist:
```bash
csrutil status
```
Wenn Sie SIP deaktivieren müssen, müssen Sie Ihren Computer im Wiederherstellungsmodus neu starten (indem Sie beim Start Command+R drücken) und anschließend den folgenden Befehl ausführen:
```bash
csrutil disable
```
Wenn Sie SIP aktiviert lassen, aber Debugging-Schutzmechanismen entfernen möchten, können Sie dies folgendermaßen tun:
```bash
csrutil enable --without debug
```
### Weitere Einschränkungen

- **Verhindert das Laden unsignierter Kernel Extensions** (kexts) und stellt sicher, dass nur verifizierte Extensions mit dem Systemkernel interagieren.
- **Verhindert das Debugging** von macOS-Systemprozessen und schützt zentrale Systemkomponenten vor unbefugtem Zugriff und unbefugten Änderungen.
- **Hindert Tools** wie dtrace daran, Systemprozesse zu untersuchen, und schützt dadurch zusätzlich die Integrität des Systembetriebs.

[**Mehr über SIP erfahren Sie in diesem Vortrag**](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)**.**<sup>[[1]](#references)</sup>

### **SIP-bezogene Entitlements**

- `com.apple.rootless.xpc.bootstrap`: launchd steuern
- `com.apple.rootless.install[.heritable]`: Zugriff auf das Dateisystem
- `com.apple.rootless.kext-management`: `kext_request`
- `com.apple.rootless.datavault.controller`: UF_DATAVAULT verwalten
- `com.apple.rootless.xpc.bootstrap`: XPC-Setup-Funktionen
- `com.apple.rootless.xpc.effective-root`: Root über launchd XPC
- `com.apple.rootless.restricted-block-devices`: Zugriff auf rohe Blockgeräte
- `com.apple.rootless.internal.installer-equivalent`: Uneingeschränkter Dateisystemzugriff
- `com.apple.rootless.restricted-nvram-variables[.heritable]`: Vollständiger Zugriff auf NVRAM
- `com.apple.rootless.storage.label`: Ändern von Dateien, die durch das com.apple.rootless xattr mit dem entsprechenden Label eingeschränkt sind
- `com.apple.rootless.volume.VM.label`: VM-Swap auf dem Volume verwalten

## SIP-Bypasses

Das Umgehen von SIP ermöglicht es einem Angreifer:

- **Auf Benutzerdaten zuzugreifen**: Sensible Benutzerdaten wie E-Mails, Nachrichten und den Safari-Verlauf aus allen Benutzerkonten zu lesen.
- **TCC Bypass**: Die TCC-Datenbank (Transparency, Consent, and Control) direkt zu manipulieren, um unbefugten Zugriff auf die Webcam, das Mikrofon und andere Ressourcen zu gewähren.
- **Persistence einzurichten**: Malware an durch SIP geschützten Orten abzulegen, wodurch sie sich nur schwer entfernen lässt, selbst mit Root-Rechten. Dies umfasst auch die Möglichkeit, das Malware Removal Tool (MRT) zu manipulieren.
- **Kernel Extensions zu laden**: Obwohl zusätzliche Schutzmaßnahmen vorhanden sind, vereinfacht das Umgehen von SIP das Laden unsignierter Kernel Extensions.

### Installer Packages

**Mit Apples Zertifikat signierte Installer Packages** können dessen Schutzmaßnahmen umgehen. Das bedeutet, dass selbst von Standardentwicklern signierte Packages blockiert werden, wenn sie versuchen, durch SIP geschützte Verzeichnisse zu ändern.

### Nicht vorhandene SIP-Datei

Eine mögliche Schwachstelle besteht darin, dass eine Datei erstellt werden kann, wenn sie in **`rootless.conf` angegeben ist, aber derzeit nicht existiert**. Malware könnte dies ausnutzen, um **Persistence** auf dem System einzurichten. Ein bösartiges Programm könnte beispielsweise eine .plist-Datei in `/System/Library/LaunchDaemons` erstellen, wenn sie in `rootless.conf` aufgeführt, aber nicht vorhanden ist.

### com.apple.rootless.install.heritable

> [!CAUTION]
> Das Entitlement **`com.apple.rootless.install.heritable`** ermöglicht das Umgehen von SIP

#### [CVE-2019-8561](https://objective-see.org/blog/blog_0x42.html) <a href="#cve" id="cve"></a>

Es wurde entdeckt, dass es möglich war, das Installer Package auszutauschen, nachdem das System dessen Code-Signatur verifiziert hatte. Anschließend installierte das System das bösartige Package anstelle des Originals. Da diese Aktionen von **`system_installd`** ausgeführt wurden, war es möglich, SIP zu umgehen.<sup>[[2]](#references)</sup>

#### [CVE-2020–9854](https://objective-see.org/blog/blog_0x4D.html) <a href="#cve-unauthd-chain" id="cve-unauthd-chain"></a>

Wenn ein Package von einem gemounteten Image oder einem externen Laufwerk installiert wurde, würde der **Installer** die Binärdatei von **diesem Dateisystem** ausführen (anstatt von einem durch SIP geschützten Ort). Dadurch konnte **`system_installd`** eine beliebige Binärdatei ausführen.<sup>[[3]](#references)</sup>

#### CVE-2021-30892 - Shrootless

[**Forscher aus diesem Blogbeitrag**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/) entdeckten eine Schwachstelle im System Integrity Protection (SIP)-Mechanismus von macOS, die als „Shrootless“-Schwachstelle bezeichnet wurde. Diese Schwachstelle betrifft den **`system_installd`**-Daemon, der über das Entitlement **`com.apple.rootless.install.heritable`** verfügt. Dieses ermöglicht es allen untergeordneten Prozessen, die Dateisystemeinschränkungen von SIP zu umgehen.<sup>[[4]](#references)</sup>

Der **`system_installd`**-Daemon installiert Packages, die von **Apple** signiert wurden.

Forscher stellten fest, dass **`system_installd`** während der Installation eines von Apple signierten Packages (einer .pkg-Datei) alle im Package enthaltenen **post-install**-Skripte **ausführt**. Diese Skripte werden von der Standardshell **`zsh`** ausgeführt, die automatisch Befehle aus der Datei **`/etc/zshenv`** ausführt, sofern diese existiert, auch im nicht-interaktiven Modus. Dieses Verhalten konnte von Angreifern ausgenutzt werden: Durch das Erstellen einer bösartigen `/etc/zshenv`-Datei und das Warten darauf, dass **`system_installd` `zsh` aufruft**, konnten sie beliebige Operationen auf dem Gerät ausführen.<sup>[[4]](#references)</sup>

Darüber hinaus wurde entdeckt, dass **`/etc/zshenv` als allgemeine Angriffstechnik verwendet werden konnte**, nicht nur für einen SIP Bypass. Jedes Benutzerprofil verfügt über eine `~/.zshenv`-Datei, die sich wie `/etc/zshenv` verhält, jedoch keine Root-Berechtigungen erfordert. Diese Datei konnte als Persistence-Mechanismus oder zur Rechteerweiterung verwendet werden und wurde bei jedem Start von `zsh` ausgelöst. Wenn ein Admin-Benutzer mit `sudo -s` oder `sudo <command>` zu Root wechselte, wurde die `~/.zshenv`-Datei ausgelöst, wodurch effektiv Root-Rechte erlangt wurden.<sup>[[4]](#references)</sup>

#### [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)

In [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/) wurde entdeckt, dass derselbe **`system_installd`**-Prozess weiterhin missbraucht werden konnte, da er das **post-install script in einem zufällig benannten, durch SIP geschützten Ordner innerhalb von `/tmp`** ablegte. Das Problem bestand darin, dass **`/tmp` selbst nicht durch SIP geschützt ist**. Daher konnte dort ein **virtuelles Image gemountet** werden. Anschließend legte der **Installer** darin das **post-install script** ab, das virtuelle Image wurde **unmountet**, alle **Ordner** wurden **neu erstellt** und das **post-install**-Skript mit dem auszuführenden **Payload** hinzugefügt.<sup>[[5]](#references)</sup>

#### [fsck_cs utility](https://www.theregister.com/2016/03/30/apple_os_x_rootless/)

Es wurde eine Schwachstelle identifiziert, bei der `fsck_cs` dazu gebracht wurde, eine wichtige Datei zu beschädigen, da das Programm **symbolischen Links** folgen konnte. Angreifer erstellten konkret einen Link von _`/dev/diskX`_ zur Datei `/System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist`. Die Ausführung von **`fsck_cs`** auf _`/dev/diskX`_ führte zur Beschädigung von `Info.plist`. Die Integrität dieser Datei ist für den SIP-Mechanismus (System Integrity Protection) des Betriebssystems von entscheidender Bedeutung, da dieser das Laden von Kernel Extensions steuert. Nach der Beschädigung war SIP nicht mehr in der Lage, Kernel-Ausschlüsse ordnungsgemäß zu verwalten.<sup>[[6]](#references)</sup>

Die Befehle zum Ausnutzen dieser Schwachstelle lauten:
```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```
Die Ausnutzung dieser Schwachstelle hat schwerwiegende Auswirkungen. Die Datei `Info.plist`, die normalerweise für die Verwaltung der Berechtigungen von Kernel Extensions zuständig ist, wird unwirksam. Dazu gehört auch die Unfähigkeit, bestimmte Extensions wie `AppleHWAccess.kext` auf eine Blacklist zu setzen. Da der Kontrollmechanismus von SIP dadurch außer Kraft gesetzt ist, kann diese Extension geladen werden und unbefugten Lese- und Schreibzugriff auf den RAM des Systems gewähren.<sup>[[6]](#references)</sup>

#### [Mount über SIP-geschützten Ordnern](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

Es war möglich, ein neues Dateisystem über **SIP-geschützten Ordnern zu mounten, um den Schutz zu umgehen**.<sup>[[1]](#references)</sup>
```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```
#### [Upgrader bypass (2016)](https://objective-see.org/blog/blog_0x14.html)

Das System ist so eingestellt, dass es von einem eingebetteten Installer-Disk-Image innerhalb der `Install macOS Sierra.app` bootet, um das Betriebssystem zu aktualisieren, wobei das Dienstprogramm `bless` verwendet wird. Der verwendete Befehl lautet wie folgt:<sup>[[7]](#references)</sup>
```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```
Die Sicherheit dieses Prozesses kann beeinträchtigt werden, wenn ein Angreifer das Upgrade-Image (`InstallESD.dmg`) vor dem Booten verändert. Die Strategie besteht darin, einen dynamischen Loader (dyld) durch eine bösartige Version (`libBaseIA.dylib`) zu ersetzen. Dieser Austausch führt dazu, dass der Code des Angreifers ausgeführt wird, sobald das Installationsprogramm gestartet wird.<sup>[[7]](#references)</sup>

Der Code des Angreifers erlangt während des Upgrade-Prozesses die Kontrolle, indem er das Vertrauen des Systems in das Installationsprogramm ausnutzt. Der Angriff erfolgt durch die Veränderung des `InstallESD.dmg`-Images mittels method swizzling, wobei insbesondere die Methode `extractBootBits` ins Visier genommen wird. Dadurch kann bösartiger Code eingeschleust werden, bevor das Disk-Image verwendet wird.<sup>[[7]](#references)</sup>

Darüber hinaus befindet sich im `InstallESD.dmg` ein `BaseSystem.dmg`, das als Root-Dateisystem des Upgrade-Codes dient. Wird dort eine dynamische Bibliothek eingeschleust, kann der bösartige Code innerhalb eines Prozesses ausgeführt werden, der in der Lage ist, Dateien auf OS-Ebene zu verändern. Dadurch steigt das Potenzial für eine vollständige Kompromittierung des Systems erheblich.<sup>[[7]](#references)</sup>

#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

In diesem Vortrag von [**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk) wird gezeigt, wie **`systemmigrationd`** (das SIP umgehen kann) ein **bash**- und ein **perl**-Skript ausführt, die über die Umgebungsvariablen **`BASH_ENV`** und **`PERL5OPT`** missbraucht werden können.<sup>[[8]](#references)</sup>

#### CVE-2023-42860 <a href="#cve-a-detailed-look" id="cve-a-detailed-look"></a>

Wie [**in diesem Blogbeitrag ausführlich beschrieben**](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts), erlaubten Pakete aus `InstallAssistant.pkg` die Ausführung eines `postinstall`-Skripts:<sup>[[9]](#references)</sup>
```bash
/usr/bin/chflags -h norestricted "${SHARED_SUPPORT_PATH}/SharedSupport.dmg"
```
und es war möglich, einen Symlink in `${SHARED_SUPPORT_PATH}/SharedSupport.dmg` zu erstellen, der es einem Benutzer erlaubte, **jede Datei zu unrestricten und den SIP-Schutz zu umgehen**.<sup>[[9]](#references)</sup>

### **com.apple.rootless.install**

> [!CAUTION]
> Das Entitlement **`com.apple.rootless.install`** ermöglicht das Umgehen von SIP

Das Entitlement `com.apple.rootless.install` ist dafür bekannt, den System Integrity Protection (SIP) unter macOS zu umgehen. Dies wurde insbesondere im Zusammenhang mit [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/) erwähnt.<sup>[[10]](#references)</sup>

In diesem speziellen Fall besitzt der unter `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc` befindliche XPC-Systemdienst dieses Entitlement. Dadurch kann der zugehörige Prozess SIP-Einschränkungen umgehen. Außerdem stellt dieser Dienst insbesondere eine Methode bereit, die das Verschieben von Dateien ermöglicht, ohne Sicherheitsmaßnahmen durchzusetzen.<sup>[[10]](#references)</sup>

## Versiegelte System-Snapshots

Versiegelte System-Snapshots sind eine von Apple in **macOS Big Sur (macOS 11)** eingeführte Funktion und Bestandteil des **System Integrity Protection (SIP)**-Mechanismus. Sie bieten eine zusätzliche Ebene für Sicherheit und Systemstabilität. Im Wesentlichen handelt es sich dabei um schreibgeschützte Versionen des System-Volumes.

Hier ein detaillierterer Überblick:

1. **Unveränderliches System**: Versiegelte System-Snapshots machen das macOS-System-Volume „unveränderlich“, sodass es nicht modifiziert werden kann. Dadurch werden unbefugte oder versehentliche Änderungen am System verhindert, die die Sicherheit oder Systemstabilität beeinträchtigen könnten.
2. **Systemsoftware-Updates**: Wenn du macOS-Updates oder Upgrades installierst, erstellt macOS einen neuen System-Snapshot. Das macOS-Startvolume verwendet anschließend **APFS (Apple File System)**, um zu diesem neuen Snapshot zu wechseln. Der gesamte Prozess zum Anwenden von Updates wird dadurch sicherer und zuverlässiger, da das System jederzeit zum vorherigen Snapshot zurückkehren kann, falls während des Updates etwas schiefgeht.
3. **Datentrennung**: Zusammen mit dem in macOS Catalina eingeführten Konzept der Trennung von Data- und System-Volumes stellt die Funktion der versiegelten System-Snapshots sicher, dass alle deine Daten und Einstellungen auf einem separaten **„Data“**-Volume gespeichert werden. Diese Trennung macht deine Daten vom System unabhängig, vereinfacht den Prozess der Systemupdates und erhöht die Systemsicherheit.

Beachte, dass diese Snapshots automatisch von macOS verwaltet werden und dank der Möglichkeiten zur gemeinsamen Speicherplatznutzung von APFS keinen zusätzlichen Speicherplatz auf deiner Festplatte belegen. Wichtig ist außerdem, dass sich diese Snapshots von **Time Machine-Snapshots** unterscheiden, bei denen es sich um für Benutzer zugängliche Backups des gesamten Systems handelt.

### Snapshots überprüfen

Der Befehl **`diskutil apfs list`** listet die **Details der APFS-Volumes** und deren Layout auf:

<pre><code>+-- Container disk3 966B902E-EDBA-4775-B743-CF97A0556A13
|   ====================================================
|   APFS Container Reference:     disk3
|   Size (Capacity Ceiling):      494384795648 B (494.4 GB)
|   Capacity In Use By Volumes:   219214536704 B (219.2 GB) (44.3% used)
|   Capacity Not Allocated:       275170258944 B (275.2 GB) (55.7% free)
|   |
|   +-< Physical Store disk0s2 86D4B7EC-6FA5-4042-93A7-D3766A222EBE
|   |   -----------------------------------------------------------
|   |   APFS Physical Store Disk:   disk0s2
|   |   Size:                       494384795648 B (494.4 GB)
|   |
|   +-> Volume disk3s1 7A27E734-880F-4D91-A703-FB55861D49B7
|   |   ---------------------------------------------------
<strong>|   |   APFS Volume Disk (Role):   disk3s1 (System)
</strong>|   |   Name:                      Macintosh HD (Case-insensitive)
<strong>|   |   Mount Point:               /System/Volumes/Update/mnt1
</strong>|   |   Capacity Consumed:         12819210240 B (12.8 GB)
|   |   Sealed:                    Broken
|   |   FileVault:                 Yes (Unlocked)
|   |   Encrypted:                 No
|   |   |
|   |   Snapshot:                  FAA23E0C-791C-43FF-B0E7-0E1C0810AC61
|   |   Snapshot Disk:             disk3s1s1
<strong>|   |   Snapshot Mount Point:      /
</strong><strong>|   |   Snapshot Sealed:           Yes
</strong>[...]
+-> Volume disk3s5 281959B7-07A1-4940-BDDF-6419360F3327
|   ---------------------------------------------------
|   APFS Volume Disk (Role):   disk3s5 (Data)
|   Name:                      Macintosh HD - Data (Case-insensitive)
<strong>    |   Mount Point:               /System/Volumes/Data
</strong><strong>    |   Capacity Consumed:         412071784448 B (412.1 GB)
</strong>    |   Sealed:                    No
|   FileVault:                 Yes (Unlocked)
</code></pre>

In der vorherigen Ausgabe ist zu sehen, dass **für Benutzer zugängliche Speicherorte** unter `/System/Volumes/Data` eingehängt werden.

Außerdem ist der **Snapshot des macOS-System-Volumes** unter `/` eingehängt und **versiegelt** (kryptografisch vom Betriebssystem signiert). Wenn SIP umgangen und das Volume verändert wird, **startet das Betriebssystem daher nicht mehr**.

Es ist außerdem möglich, **zu überprüfen, ob die Versiegelung aktiviert ist**, indem folgender Befehl ausgeführt wird:
```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```
Außerdem wird der Snapshot-Datenträger ebenfalls als **nur lesbar** eingebunden:
```bash
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
## Referenzen

- [1] [SyScan360 - Stefan Esser - OS X El Capitan sinking the S\H/IP](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)
- [2] [CVE-2019-8561 - Objective-See Blog](https://objective-see.org/blog/blog_0x42.html)
- [3] [CVE-2020–9854: „Unauthd“ (three) logic bugs ftw! - Objective-See Blog](https://objective-see.org/blog/blog_0x4D.html)
- [4] [Microsoft entdeckt neue macOS-Schwachstelle „Shrootless“, die System Integrity Protection umgehen könnte](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [5] [Technische Analyse: CVE-2022-22583 - Perception Point](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)
- [6] [Apples fruitless rootless security broken by code that fits in a tweet - The Register](https://www.theregister.com/2016/03/30/apple_os_x_rootless/)
- [7] [\[0day\] Apples System Integrity Protection umgehen - Objective-See Blog](https://objective-see.org/blog/blog_0x14.html)
- [8] [DEF CON 31 - Getting a Migraine - Unique SIP Bypass on MacOS - Or, Pearse, Bohra](https://www.youtube.com/watch?v=zxZesAN-TEk)
- [9] [Apple entschärft Schwachstellen in Installer Scripts - Kandji Blog](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts)
- [10] [CVE-2022-26712: Der POC für SIP-Bypass passt sogar in einen Tweet](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/)

{{#include ../../../banners/hacktricks-training.md}}
