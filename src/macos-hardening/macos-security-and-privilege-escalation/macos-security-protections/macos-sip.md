# macOS SIP

{{#include ../../../banners/hacktricks-training.md}}

## **Grundlegende Informationen**

**System Integrity Protection (SIP)** ist in macOS ein Mechanismus, der selbst die privilegiertesten Benutzer daran hindern soll, unbefugte Änderungen an wichtigen Systemordnern vorzunehmen. Diese Funktion spielt eine entscheidende Rolle bei der Wahrung der Integrität des Systems, indem sie Aktionen wie das Hinzufügen, Ändern oder Löschen von Dateien in geschützten Bereichen einschränkt. Zu den wichtigsten von SIP geschützten Ordnern gehören:

- **/System**
- **/bin**
- **/sbin**
- **/usr**

Die Regeln, die das Verhalten von SIP bestimmen, sind in der Konfigurationsdatei **`/System/Library/Sandbox/rootless.conf`** definiert. In dieser Datei kennzeichnen Pfade, denen ein Sternchen (\*) vorangestellt ist, Ausnahmen von den ansonsten strengen SIP-Einschränkungen.

Betrachten Sie das folgende Beispiel:
```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
Dieses Snippet weist darauf hin, dass SIP zwar grundsätzlich das Verzeichnis **`/usr`** schützt, Änderungen jedoch in bestimmten Unterverzeichnissen (`/usr/libexec/cups`, `/usr/local` und `/usr/share/man`) zulässig sind, wie durch das vorangestellte Sternchen (\*) angezeigt wird.

Um zu überprüfen, ob ein Verzeichnis oder eine Datei durch SIP geschützt wird, können Sie den Befehl **`ls -lOd`** verwenden und prüfen, ob das Flag **`restricted`** oder **`sunlnk`** vorhanden ist. Zum Beispiel:
```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```
In diesem Fall bedeutet das Flag **`sunlnk`**, dass das Verzeichnis `/usr/libexec/cups` selbst **nicht gelöscht werden kann**, obwohl darin Dateien erstellt, geändert oder gelöscht werden können.

Andererseits:
```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```
Hier zeigt das **`restricted`**-Flag an, dass das Verzeichnis `/usr/libexec` durch SIP geschützt ist. In einem durch SIP geschützten Verzeichnis können keine Dateien erstellt, geändert oder gelöscht werden.

Wenn eine Datei außerdem das erweiterte **Attribut** **`com.apple.rootless`** enthält, ist diese Datei ebenfalls durch **SIP geschützt**.

> [!TIP]
> Beachte, dass der **Sandbox**-Hook **`hook_vnode_check_setextattr`** jeden Versuch verhindert, das erweiterte Attribut **`com.apple.rootless`** zu ändern.

**SIP beschränkt außerdem andere root-Aktionen**, wie etwa:

- Laden nicht vertrauenswürdiger Kernel-Erweiterungen
- Abrufen von Task-Ports für von Apple signierte Prozesse
- Ändern von NVRAM-Variablen
- Ermöglichen von Kernel-Debugging

Die Optionen werden in einer nvram-Variable als Bitflag verwaltet (`csr-active-config` auf Intel; `lp-sip0` wird auf ARM aus dem gebooteten Device Tree gelesen). Die Flags findest du im XNU-Quellcode in `csr.sh`:

<figure><img src="../../../images/image (1192).png" alt=""><figcaption></figcaption></figure>

### SIP-Status

Mit dem folgenden Befehl kannst du überprüfen, ob SIP auf deinem System aktiviert ist:
```bash
csrutil status
```
Wenn Sie SIP deaktivieren müssen, müssen Sie Ihren Computer im Wiederherstellungsmodus neu starten (indem Sie während des Starts die Tastenkombination Command+R drücken) und anschließend den folgenden Befehl ausführen:
```bash
csrutil disable
```
Wenn Sie SIP aktiviert lassen, aber Debugging-Schutzmaßnahmen entfernen möchten, können Sie dies folgendermaßen tun:
```bash
csrutil enable --without debug
```
### Weitere Einschränkungen

- **Verhindert das Laden unsignierter Kernel extensions** (kexts) und stellt sicher, dass nur verifizierte Extensions mit dem Systemkernel interagieren.
- **Verhindert das Debugging** von macOS-Systemprozessen und schützt zentrale Systemkomponenten vor unbefugtem Zugriff und unbefugten Änderungen.
- **Verhindert, dass Tools** wie dtrace Systemprozesse untersuchen, und schützt dadurch zusätzlich die Integrität des Systembetriebs.

[**Mehr über SIP info in diesem Vortrag erfahren**](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)**.**<sup>[1]</sup>

### **SIP-bezogene Entitlements**

- `com.apple.rootless.xpc.bootstrap`: launchd kontrollieren
- `com.apple.rootless.install[.heritable]`: Zugriff auf das Dateisystem
- `com.apple.rootless.kext-management`: `kext_request`
- `com.apple.rootless.datavault.controller`: UF_DATAVAULT verwalten
- `com.apple.rootless.xpc.bootstrap`: XPC-Setup-Funktionen
- `com.apple.rootless.xpc.effective-root`: Root über launchd XPC
- `com.apple.rootless.restricted-block-devices`: Zugriff auf rohe Blockgeräte
- `com.apple.rootless.internal.installer-equivalent`: Unbeschränkter Dateisystemzugriff
- `com.apple.rootless.restricted-nvram-variables[.heritable]`: Vollständiger Zugriff auf NVRAM
- `com.apple.rootless.storage.label`: Durch com.apple.rootless xattr mit dem entsprechenden Label eingeschränkte Dateien ändern
- `com.apple.rootless.volume.VM.label`: VM-Swap auf dem Volume verwalten

## SIP-Bypasses

Das Umgehen von SIP ermöglicht einem Angreifer:

- **Zugriff auf Benutzerdaten**: Sensible Benutzerdaten wie E-Mails, Nachrichten und den Safari-Verlauf aller Benutzerkonten lesen.
- **TCC Bypass**: Die TCC-Datenbank (Transparency, Consent, and Control) direkt manipulieren, um unbefugten Zugriff auf die Webcam, das Mikrofon und andere Ressourcen zu gewähren.
- **Persistence etablieren**: Malware an durch SIP geschützten Orten platzieren, sodass sie selbst durch Root-Rechte nur schwer entfernt werden kann. Dazu gehört auch die Möglichkeit, das Malware Removal Tool (MRT) zu manipulieren.
- **Kernel extensions laden**: Obwohl zusätzliche Schutzmaßnahmen vorhanden sind, vereinfacht das Umgehen von SIP das Laden unsignierter Kernel extensions.

### Installer Packages

**Mit Apples Zertifikat signierte Installer packages** können dessen Schutzmaßnahmen umgehen. Das bedeutet, dass selbst von Standardentwicklern signierte Packages blockiert werden, wenn sie versuchen, durch SIP geschützte Verzeichnisse zu ändern.

### Nicht vorhandene SIP-Datei

Eine potenzielle Schwachstelle besteht darin, dass eine in **`rootless.conf` angegebene Datei, die derzeit nicht existiert**, erstellt werden kann. Malware könnte dies ausnutzen, um **Persistence** auf dem System zu etablieren. Beispielsweise könnte ein bösartiges Programm eine .plist-Datei in `/System/Library/LaunchDaemons` erstellen, wenn sie in `rootless.conf` aufgeführt, aber nicht vorhanden ist.

### com.apple.rootless.install.heritable

> [!CAUTION]
> Das Entitlement **`com.apple.rootless.install.heritable`** ermöglicht das Umgehen von SIP

#### [CVE-2019-8561](https://objective-see.org/blog/blog_0x42.html) <a href="#cve" id="cve"></a>

Es wurde entdeckt, dass es möglich war, das Installer package auszutauschen, nachdem das System dessen Code-Signatur verifiziert hatte, sodass das System anschließend das bösartige Package anstelle des Originals installierte. Da diese Aktionen von **`system_installd`** ausgeführt wurden, war es möglich, SIP zu umgehen.<sup>[2]</sup>

#### [CVE-2020–9854](https://objective-see.org/blog/blog_0x4D.html) <a href="#cve-unauthd-chain" id="cve-unauthd-chain"></a>

Wenn ein Package von einem gemounteten Image oder externen Laufwerk installiert wurde, würde der **Installer** die Binary von **diesem Dateisystem** ausführen (anstatt von einem durch SIP geschützten Ort), wodurch **`system_installd`** eine beliebige Binary ausführen konnte.<sup>[3]</sup>

#### CVE-2021-30892 - Shrootless

[**Forscher aus diesem Blogpost**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/) entdeckten eine Schwachstelle im System-Integrity-Protection-Mechanismus (SIP) von macOS, die als „Shrootless“-Schwachstelle bezeichnet wurde. Diese Schwachstelle betrifft den **`system_installd`**-Daemon, der über das Entitlement **`com.apple.rootless.install.heritable`** verfügt, wodurch alle seine Child-Prozesse die Dateisystembeschränkungen von SIP umgehen können.<sup>[4]</sup>

Der **`system_installd`**-Daemon installiert Packages, die von **Apple** signiert wurden.

Die Forscher stellten fest, dass **`system_installd`** während der Installation eines von Apple signierten Packages (einer .pkg-Datei) alle im Package enthaltenen **post-install**-Skripte **ausführt**. Diese Skripte werden von der Standard-Shell **`zsh`** ausgeführt, die automatisch Befehle aus der Datei **`/etc/zshenv`** ausführt, sofern diese existiert, selbst im nicht-interaktiven Modus. Dieses Verhalten könnte von Angreifern ausgenutzt werden: Durch das Erstellen einer bösartigen Datei `/etc/zshenv` und das Warten darauf, dass **`system_installd` `zsh` aufruft**, könnten sie beliebige Vorgänge auf dem Gerät ausführen.<sup>[4]</sup>

Darüber hinaus wurde festgestellt, dass **`/etc/zshenv` als allgemeine Angriffstechnik verwendet werden konnte**, nicht nur für einen SIP-Bypass. Jedes Benutzerprofil enthält eine Datei `~/.zshenv`, die sich genauso wie `/etc/zshenv` verhält, jedoch keine Root-Berechtigungen erfordert. Diese Datei könnte als Persistence-Mechanismus verwendet werden, der jedes Mal ausgelöst wird, wenn `zsh` startet, oder als Mechanismus zur Privilege Escalation. Wenn ein Admin-Benutzer mit `sudo -s` oder `sudo <command>` zu Root wechselt, würde die Datei `~/.zshenv` ausgelöst und dadurch effektiv zu Root eskalieren.<sup>[4]</sup>

#### [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)

In [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/) wurde entdeckt, dass derselbe **`system_installd`**-Prozess weiterhin missbraucht werden konnte, da er das **post-install script in einem zufällig benannten, durch SIP geschützten Ordner innerhalb von `/tmp`** ablegte. Das Problem besteht darin, dass **`/tmp` selbst nicht durch SIP geschützt ist**. Daher war es möglich, ein **virtuelles Image darauf zu mounten**. Anschließend legte der **Installer** dort das **post-install script** ab, **unmountete** das virtuelle Image, **erstellte alle Ordner** erneut und **fügte** das **post-install**-Skript mit dem auszuführenden **Payload** hinzu.<sup>[5]</sup>

#### [fsck_cs utility](https://www.theregister.com/2016/03/30/apple_os_x_rootless/)

Es wurde eine Schwachstelle identifiziert, bei der `fsck_cs` dazu gebracht wurde, eine wichtige Datei zu beschädigen, da das Tool **symbolischen Links** folgen konnte. Angreifer erstellten gezielt einen Link von _`/dev/diskX`_ auf die Datei `/System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist`. Das Ausführen von **`fsck_cs`** auf _`/dev/diskX`_ führte zur Beschädigung von `Info.plist`. Die Integrität dieser Datei ist für die SIP (System Integrity Protection) des Betriebssystems von entscheidender Bedeutung, da sie das Laden von Kernel extensions kontrolliert. Nach der Beschädigung ist SIP nicht mehr in der Lage, Kernel exclusions ordnungsgemäß zu verwalten.<sup>[6]</sup>

Die Befehle zum Ausnutzen dieser Schwachstelle lauten:
```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```
Die Ausnutzung dieser Schwachstelle hat schwerwiegende Auswirkungen. Die Datei `Info.plist`, die normalerweise für die Verwaltung der Berechtigungen von Kernel-Erweiterungen zuständig ist, wird unwirksam. Dazu gehört auch die Unfähigkeit, bestimmte Erweiterungen wie `AppleHWAccess.kext` auf die Blacklist zu setzen. Da der Kontrollmechanismus von SIP dadurch außer Kraft gesetzt ist, kann diese Erweiterung geladen werden und unautorisierten Lese- und Schreibzugriff auf den Arbeitsspeicher des Systems gewähren.<sup>[6]</sup>

#### [Mount über SIP-geschützten Ordnern](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

Es war möglich, ein neues Dateisystem über **SIP-geschützten Ordnern einzuhängen, um den Schutz zu umgehen**.<sup>[1]</sup>
```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```
#### [Upgrader bypass (2016)](https://objective-see.org/blog/blog_0x14.html)

Das System ist so eingestellt, dass es zum Upgrade des Betriebssystems von einem eingebetteten Installer-Disk-Image innerhalb der `Install macOS Sierra.app` bootet, wobei das `bless`-Utility verwendet wird. Der verwendete Befehl lautet wie folgt:<sup>[7]</sup>
```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```
Die Sicherheit dieses Prozesses kann beeinträchtigt werden, wenn ein Angreifer das Upgrade-Image (`InstallESD.dmg`) vor dem Booten verändert. Die Strategie besteht darin, einen dynamic loader (dyld) durch eine bösartige Version (`libBaseIA.dylib`) zu ersetzen. Dieser Austausch führt dazu, dass der Code des Angreifers ausgeführt wird, sobald das Installationsprogramm gestartet wird.<sup>[7]</sup>

Der Code des Angreifers erlangt während des Upgrade-Prozesses die Kontrolle, indem er das Vertrauen des Systems in das Installationsprogramm ausnutzt. Der Angriff erfolgt durch die Veränderung des `InstallESD.dmg`-Images mittels method swizzling, wobei insbesondere die `extractBootBits`-Methode angegriffen wird. Dadurch kann bösartiger Code eingeschleust werden, bevor das Disk-Image verwendet wird.<sup>[7]</sup>

Darüber hinaus befindet sich im `InstallESD.dmg` ein `BaseSystem.dmg`, das als Root-Dateisystem des Upgrade-Codes dient. Durch das Einschleusen einer dynamic library kann der bösartige Code innerhalb eines Prozesses ausgeführt werden, der in der Lage ist, Dateien auf OS-Ebene zu verändern, wodurch sich das Potenzial für eine Kompromittierung des Systems erheblich erhöht.<sup>[7]</sup>

#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

In diesem Vortrag von [**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk) wird gezeigt, wie **`systemmigrationd`** (das SIP umgehen kann) ein **bash**- und ein **perl**-Skript ausführt, die über die Umgebungsvariablen **`BASH_ENV`** und **`PERL5OPT`** missbraucht werden können.<sup>[8]</sup>

#### CVE-2023-42860 <a href="#cve-a-detailed-look" id="cve-a-detailed-look"></a>

Wie in [**diesem Blogbeitrag ausführlich beschrieben**](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts), ermöglichte ein `postinstall`-Skript aus `InstallAssistant.pkg`-Paketen Folgendes:<sup>[9]</sup>
```bash
/usr/bin/chflags -h norestricted "${SHARED_SUPPORT_PATH}/SharedSupport.dmg"
```
und es war möglich, einen Symlink in `${SHARED_SUPPORT_PATH}/SharedSupport.dmg` zu erstellen, der es einem Benutzer ermöglichen würde, **jede Datei zu unrestricten und den SIP-Schutz zu umgehen**.<sup>[9]</sup>

### **com.apple.rootless.install**

> [!CAUTION]
> Das Entitlement **`com.apple.rootless.install`** ermöglicht das Umgehen von SIP.

Das Entitlement `com.apple.rootless.install` ist dafür bekannt, den System Integrity Protection (SIP) unter macOS zu umgehen. Dies wurde insbesondere im Zusammenhang mit [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/) erwähnt.<sup>[10]</sup>

In diesem speziellen Fall besitzt der unter `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc` befindliche XPC-Systemdienst dieses Entitlement. Dadurch kann der zugehörige Prozess SIP-Einschränkungen umgehen. Außerdem stellt dieser Dienst eine Methode bereit, die das Verschieben von Dateien ohne Durchsetzung von Sicherheitsmaßnahmen ermöglicht.<sup>[10]</sup>

## Sealed System Snapshots

Sealed System Snapshots sind eine von Apple in **macOS Big Sur (macOS 11)** eingeführte Funktion und Bestandteil des **System Integrity Protection (SIP)**-Mechanismus. Sie bieten eine zusätzliche Ebene für Sicherheit und Systemstabilität. Im Wesentlichen handelt es sich dabei um schreibgeschützte Versionen des System-Volumes.

Hier ein detaillierterer Überblick:

1. **Unveränderliches System**: Sealed System Snapshots machen das macOS-System-Volume „unveränderlich“, sodass es nicht modifiziert werden kann. Dadurch werden nicht autorisierte oder versehentliche Änderungen am System verhindert, die die Sicherheit oder Systemstabilität beeinträchtigen könnten.
2. **Systemsoftware-Updates**: Wenn du macOS-Updates oder Upgrades installierst, erstellt macOS einen neuen System-Snapshot. Das macOS-Startvolume verwendet anschließend **APFS (Apple File System)**, um zu diesem neuen Snapshot zu wechseln. Der gesamte Update-Vorgang wird dadurch sicherer und zuverlässiger, da das System jederzeit zum vorherigen Snapshot zurückkehren kann, falls während des Updates ein Fehler auftritt.
3. **Datentrennung**: Zusammen mit dem in macOS Catalina eingeführten Konzept der Trennung von Daten- und System-Volume stellt die Funktion der Sealed System Snapshots sicher, dass alle deine Daten und Einstellungen auf einem separaten "**Data**"-Volume gespeichert werden. Diese Trennung macht deine Daten vom System unabhängig, vereinfacht Systemupdates und erhöht die Systemsicherheit.

Beachte, dass diese Snapshots automatisch von macOS verwaltet werden und dank der Funktionen zur gemeinsamen Speicherplatznutzung von APFS keinen zusätzlichen Speicherplatz auf deinem Datenträger belegen. Wichtig ist außerdem, dass sich diese Snapshots von **Time Machine snapshots** unterscheiden, bei denen es sich um für Benutzer zugängliche Backups des gesamten Systems handelt.

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

In der vorherigen Ausgabe ist zu sehen, dass **für Benutzer zugängliche Speicherorte** unter `/System/Volumes/Data` eingebunden werden.

Außerdem ist der **Snapshot des macOS-System-Volumes** unter `/` eingebunden und **versiegelt** (kryptografisch vom Betriebssystem signiert). Wenn SIP umgangen und der Snapshot verändert wird, **startet das Betriebssystem daher nicht mehr**.

Es ist auch möglich, **zu überprüfen, ob die Versiegelung aktiviert ist**, indem man folgenden Befehl ausführt:
```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```
Außerdem ist der Snapshot-Datenträger ebenfalls als **schreibgeschützt** eingebunden:
```bash
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
## Referenzen

- [1] [SyScan360 - Stefan Esser - OS X El Capitan: S\H/IP versenken](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)
- [2] [CVE-2019-8561 - Objective-See Blog](https://objective-see.org/blog/blog_0x42.html)
- [3] [CVE-2020–9854: „Unauthd“ (drei) Logikfehler ftw! - Objective-See Blog](https://objective-see.org/blog/blog_0x4D.html)
- [4] [Microsoft entdeckt neue macOS-Schwachstelle „Shrootless“, die den Bypass von System Integrity Protection ermöglichen könnte](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [5] [Technische Analyse: CVE-2022-22583 - Perception Point](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)
- [6] [Apples fruchtlose rootless-Sicherheit durch Code gebrochen, der in einen Tweet passt - The Register](https://www.theregister.com/2016/03/30/apple_os_x_rootless/)
- [7] [\[0day\] Apples System Integrity Protection umgehen - Objective-See Blog](https://objective-see.org/blog/blog_0x14.html)
- [8] [DEF CON 31 - Eine Migräne bekommen - Einzigartiger SIP Bypass auf MacOS - Or, Pearse, Bohra](https://www.youtube.com/watch?v=zxZesAN-TEk)
- [9] [Apple entschärft Schwachstellen in Installer Scripts - Kandji Blog](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts)
- [10] [CVE-2022-26712: Der POC für den SIP-Bypass passt sogar in einen Tweet](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/)

{{#include ../../../banners/hacktricks-training.md}}
