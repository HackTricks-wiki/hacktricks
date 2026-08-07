# macOS Kernel Extensions & Kernelcaches

{{#include ../../../banners/hacktricks-training.md}}

## Grundlegende Informationen

Kernel extensions (Kexts) sind **Pakete** mit der Erweiterung **`.kext`**, die **direkt in den macOS-Kernel-Space geladen** werden und dem Hauptbetriebssystem zusätzliche Funktionen bereitstellen.

### Deprecation-Status & DriverKit / System Extensions
Ab **macOS Catalina (10.15)** markierte Apple die meisten Legacy-KPIs als *deprecated* und führte die Frameworks **System Extensions & DriverKit** ein, die im **User-Space** ausgeführt werden. Ab **macOS Big Sur (11)** verweigert das Betriebssystem das Laden von Third-Party-Kexts, die auf deprecated KPIs basieren, sofern der Computer nicht im **Reduced Security**-Modus gestartet wurde. Auf Apple Silicon muss der Benutzer zum Aktivieren von Kexts zusätzlich:

1. In die **Recovery** neu starten → *Startup Security Utility*.
2. **Reduced Security** auswählen und **„Allow user management of kernel extensions from identified developers“** aktivieren.
3. Neu starten und die Kext unter **System Settings → Privacy & Security** genehmigen.

User-Land-Treiber, die mit DriverKit/System Extensions geschrieben wurden, **reduzieren die Angriffsfläche** erheblich, da Abstürze oder Speicherbeschädigungen auf einen sandboxed process statt auf den Kernel-Space beschränkt bleiben.<sup>[[1]](#references)</sup>

> 📝 Ab macOS Sequoia (15) hat Apple mehrere Legacy-Networking- und USB-KPIs vollständig entfernt – die einzige zukunftskompatible Lösung für Anbieter ist die Migration zu System Extensions.

### Anforderungen

Offensichtlich ist dies so leistungsfähig, dass das Laden einer Kernel Extension **kompliziert** ist. Dies sind die **Anforderungen**, die eine Kernel Extension erfüllen muss, um geladen zu werden:

- Beim **Starten des Recovery-Modus** müssen Kernel **Extensions zum Laden zugelassen** werden:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- Die Kernel Extension muss mit einem **Kernel-Code-Signing-Zertifikat** signiert sein, das nur von **Apple** **ausgestellt** werden kann. Apple prüft dabei das Unternehmen und die Gründe, aus denen das Zertifikat benötigt wird, ausführlich.
- Die Kernel Extension muss außerdem **notarized** sein, damit Apple sie auf Malware überprüfen kann.
- Anschließend kann nur der **root**-Benutzer die **Kernel Extension laden**, und die Dateien innerhalb des Pakets müssen **root gehören**.
- Während des Upload-Prozesses muss das Paket an einem **geschützten, nicht von root beschreibbaren Ort** vorbereitet werden: `/Library/StagedExtensions` (erfordert den Grant `com.apple.rootless.storage.KernelExtensionManagement`).
- Beim Versuch, sie zu laden, erhält der Benutzer schließlich eine [**Bestätigungsanfrage**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html). Wenn diese akzeptiert wird, muss der Computer **neu gestartet** werden, damit die Extension geladen wird.

### Ladeprozess

Unter Catalina lief der Prozess wie folgt ab: Interessant ist, dass der **Verifizierungsprozess** im **Userland** stattfindet. Allerdings können nur Anwendungen mit dem Grant **`com.apple.private.security.kext-management`** den **Kernel auffordern, eine Extension zu laden**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **startet** den **Verifizierungsprozess** zum Laden einer Extension.
- Es kommuniziert über einen **Mach-Service** mit **`kextd`**.
2. **`kextd`** überprüft verschiedene Dinge, beispielsweise die **Signatur**.
- Es kommuniziert mit **`syspolicyd`**, um zu **überprüfen**, ob die Extension **geladen** werden kann.
3. **`syspolicyd`** fordert den **Benutzer** auf, wenn die Extension zuvor noch nicht geladen wurde.
- **`syspolicyd`** meldet das Ergebnis an **`kextd`**.
4. **`kextd`** kann den Kernel schließlich **anweisen, die Extension zu laden**.

Wenn **`kextd`** nicht verfügbar ist, kann **`kextutil`** dieselben Prüfungen durchführen.

### Auflistung & Verwaltung (geladene Kexts)

`kextstat` war das historische Tool, ist aber in aktuellen macOS-Versionen **deprecated**. Die moderne Schnittstelle ist **`kmutil`**:
```bash
# List every extension currently linked in the kernel, sorted by load address
sudo kmutil showloaded --sort

# Show only third-party / auxiliary collections
sudo kmutil showloaded --collection aux

# Unload a specific bundle
sudo kmutil unload -b com.example.mykext
```
Die ältere Syntax ist weiterhin als Referenz verfügbar:
```bash
# (Deprecated) Get loaded kernel extensions
kextstat

# (Deprecated) Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
`kmutil inspect` kann auch verwendet werden, um **die Inhalte einer Kernel Collection (KC) zu dumpen** oder zu überprüfen, ob ein kext alle Symbolabhängigkeiten auflöst:
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> Obwohl die Kernel extensions voraussichtlich in `/System/Library/Extensions/` liegen, wirst du in diesem Ordner **keine Binärdatei finden**. Der Grund dafür ist der **kernelcache**. Um eine `.kext` zu reverse-engineeren, musst du daher einen Weg finden, sie zu erhalten.

Der **kernelcache** ist eine **vorcompilierte und vorverknüpfte Version des XNU-Kernels** zusammen mit wichtigen Geräte-**Treibern** und **Kernel extensions**. Er wird in einem **komprimierten** Format gespeichert und während des Bootvorgangs in den Speicher dekomprimiert. Der kernelcache ermöglicht eine **schnellere Bootzeit**, da eine sofort ausführbare Version des Kernels und wichtige Treiber verfügbar sind. Dadurch werden Zeit und Ressourcen eingespart, die andernfalls beim dynamischen Laden und Verknüpfen dieser Komponenten während des Bootvorgangs benötigt würden.

Die wichtigsten Vorteile des kernelcache sind die **Ladegeschwindigkeit** und die Tatsache, dass alle Module vorverknüpft sind (keine Beeinträchtigung der Ladezeit). Sobald alle Module vorverknüpft wurden, kann KXLD aus dem Speicher entfernt werden, sodass **XNU keine neuen KEXTs laden kann.**

> [!TIP]
> Das Tool [https://github.com/dhinakg/aeota](https://github.com/dhinakg/aeota) entschlüsselt Apples AEA-Container (Apple Encrypted Archive / AEA asset) — das verschlüsselte Containerformat, das Apple für OTA assets und einige IPSW-Bestandteile verwendet — und kann das zugrunde liegende `.dmg`/asset archive erzeugen, das du anschließend mit den bereitgestellten aastuff tools extrahieren kannst.


### Lokaler Kerlnelcache

In iOS befindet er sich unter **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`**. In macOS kannst du ihn mit folgendem Befehl finden: **`find / -name "kernelcache" 2>/dev/null`** \
In meinem Fall habe ich ihn in macOS hier gefunden:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

Hier findest du auch den [**kernelcache der Version 14 mit symbols**](https://x.com/tihmstar/status/1295814618242318337?lang=en).

#### IMG4 / BVX2 (LZFSE) compressed

Das IMG4-Dateiformat ist ein von Apple in iOS- und macOS-Geräten verwendetes Containerformat zum sicheren **Speichern und Verifizieren von Firmware**-Komponenten (wie dem **kernelcache**). Das IMG4-Format enthält einen Header und mehrere Tags, die verschiedene Datenelemente kapseln, darunter die eigentliche Payload (z. B. einen Kernel oder Bootloader), eine Signatur und eine Reihe von Manifest-Eigenschaften. Das Format unterstützt die kryptografische Verifizierung, sodass das Gerät vor der Ausführung die Authentizität und Integrität der Firmware-Komponente bestätigen kann.

Es besteht normalerweise aus den folgenden Komponenten:

- **Payload (IM4P)**:
- Oft komprimiert (LZFSE4, LZSS, …)
- Optional verschlüsselt
- **Manifest (IM4M)**:
- Enthält eine Signatur
- Zusätzliches Key/Value dictionary
- **Restore Info (IM4R)**:
- Auch als APNonce bekannt
- Verhindert das erneute Einspielen einiger Updates
- OPTIONAL: Dies wird normalerweise nicht gefunden

Kernelcache dekomprimieren:
```bash
# img4tool (https://github.com/tihmstar/img4tool)
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# imjtool (https://newandroidbook.com/tools/imjtool.html)
imjtool _img_name_ [extract]

# disarm (you can use it directly on the IMG4 file) - [https://newandroidbook.com/tools/disarm.html](https://newandroidbook.com/tools/disarm.html)
disarm -L kernelcache.release.v57 # From unzip ipsw

# disamer (extract specific parts, e.g. filesets) - [https://newandroidbook.com/tools/disarm.html](https://newandroidbook.com/tools/disarm.html)
disarm -e filesets kernelcache.release.d23
```
#### Disarm-Symbole für den Kernel

**`Disarm`** ermöglicht es, Funktionen aus dem kernelcache mithilfe von Matchern zu symbolicate. Diese Matcher sind lediglich einfache Musterregeln (Textzeilen), die disarm mitteilen, wie Funktionen, Argumente und Panic-/Log-Strings innerhalb einer Binärdatei erkannt und automatisch symboliziert werden.

Im Grunde gibst du den String an, den eine Funktion verwendet, und disarm findet ihn und **symbolicate ihn**.

Einige `xnu.matchers` findest du unter [https://newosxbook.com/tools/disarm.html](https://newosxbook.com/tools/disarm.html) im Abschnitt **`Matchers`**. Du kannst auch eigene Matcher erstellen.
```bash
# Go to /tmp/extracted where disarm extracted the filesets
disarm -e filesets kernelcache.release.d23 # Always extract to /tmp/extracted
cd /tmp/extracted
JMATCHERS=xnu.matchers disarm --analyze kernel.rebuilt  # Note that xnu.matchers is actually a file with the matchers
```
### Download

Ein **IPSW (iPhone/iPad Software)** ist Apples Firmware-Paketformat, das für Gerätewiederherstellungen, Updates und vollständige Firmware-Bundles verwendet wird. Unter anderem enthält es den **kernelcache**.

- [**KernelDebugKit Github**](https://github.com/dortania/KdkSupportPkg/releases)

Unter [https://github.com/dortania/KdkSupportPkg/releases](https://github.com/dortania/KdkSupportPkg/releases) lassen sich alle Kernel-Debug-Kits finden. Du kannst es herunterladen, mounten, mit dem Tool [Suspicious Package](https://www.mothersruin.com/software/SuspiciousPackage/get.html) öffnen, auf den Ordner **`.kext`** zugreifen und ihn **extrahieren**.

Überprüfe es mit folgendem Befehl auf Symbole:
```bash
nm -a ~/Downloads/Sandbox.kext/Contents/MacOS/Sandbox | wc -l
```
- [**theapplewiki.com**](https://theapplewiki.com/wiki/Firmware/Mac/14.x)**,** [**ipsw.me**](https://ipsw.me/)**,** [**theiphonewiki.com**](https://www.theiphonewiki.com/)

Manchmal veröffentlicht Apple **kernelcache** mit **symbols**. Du kannst einige Firmwares mit symbols herunterladen, indem du den Links auf diesen Seiten folgst. Die Firmwares enthalten neben anderen Dateien auch den **kernelcache**.

Um den Kernel-Cache zu **extract**, kannst du Folgendes ausführen:
```bash
# Install ipsw tool
brew install blacktop/tap/ipsw

# Extract only the kernelcache from the IPSW
ipsw extract --kernel /path/to/YourFirmware.ipsw -o out/

# You should get something like:
#   out/Firmware/kernelcache.release.iPhoneXX
#   or an IMG4 payload: out/Firmware/kernelcache.release.iPhoneXX.im4p

# If you get an IMG4 payload:
ipsw img4 im4p extract out/Firmware/kernelcache*.im4p -o kcache.raw
```
Eine weitere Option zum **extract** der Dateien besteht darin, zunächst die Erweiterung von `.ipsw` in `.zip` zu ändern und die Datei anschließend zu **unzip**.

Nach dem Extrahieren der Firmware erhältst du eine Datei wie: **`kernelcache.release.iphone14`**. Sie liegt im **IMG4**-Format vor. Die relevanten Informationen kannst du mit folgendem Tool extrahieren:

[**pyimg4**](https://github.com/m1stadev/PyIMG4)**:**
```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
[**img4tool**](https://github.com/tihmstar/img4tool)**:**
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```

```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
[**img4tool**](https://github.com/tihmstar/img4tool)**:**
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### Kernelcache untersuchen

Prüfe mit, ob der kernelcache Symbole enthält.
```bash
nm -a kernelcache.release.iphone14.e | wc -l
```
Damit können wir nun **alle Extensions** oder die **eine, die dich interessiert, extrahieren:**
```bash
# List all extensions
kextex -l kernelcache.release.iphone14.e
## Extract com.apple.security.sandbox
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# Extract all
kextex_all kernelcache.release.iphone14.e

# Check the extension for symbols
nm -a binaries/com.apple.security.sandbox | wc -l
```
## Aktuelle Schwachstellen & Exploitation-Techniken

| Jahr | CVE | Zusammenfassung |
|------|-----|---------|
| 2024 | **CVE-2024-44243** | Ein Logikfehler in **`storagekitd`** erlaubte es einem *root*-Angreifer, ein bösartiges Datei­system-Bundle zu registrieren, das letztlich ein **unsigniertes kext** lud, dadurch den **System Integrity Protection (SIP)**-Schutz **umging** und persistente Rootkits ermöglichte. Gepatcht in macOS 14.2 / 15.2. <sup>[[2]](#references)</sup>  |
| 2021 | **CVE-2021-30892** (*Shrootless*) | Ein Installations-Daemon mit dem Entitlement `com.apple.rootless.install` konnte missbraucht werden, um beliebige Post-Install-Skripte auszuführen, SIP zu deaktivieren und beliebige kexts zu laden. <sup>[[3]](#references)</sup> |

**Wichtige Erkenntnisse für Red-Teamer**

1. **Suche nach Daemons mit Entitlements (`codesign -dvv /path/bin | grep entitlements`), die mit Disk Arbitration, Installer oder Kext Management interagieren.**
2. **Das Ausnutzen von SIP-Bypasses gewährt fast immer die Möglichkeit, ein kext zu laden → Codeausführung im Kernel**.

**Defensive Hinweise**

*SIP aktiviert lassen*, Aufrufe von `kmutil load`/`kmutil create -n aux` durch Nicht-Apple-Binaries überwachen und bei jedem Schreibzugriff auf `/Library/Extensions` alarmieren. Endpoint-Security-Events `ES_EVENT_TYPE_NOTIFY_KEXTLOAD` bieten eine nahezu Echtzeit-Übersicht.

## Debugging von macOS-Kernel & kexts

Apples empfohlener Workflow besteht darin, ein **Kernel Debug Kit (KDK)** zu erstellen, das zum laufenden Build passt, und anschließend **LLDB** über eine Netzwerkverbindung mit dem **KDP (Kernel Debugging Protocol)** anzubinden.

### Einmaliges lokales Debugging eines Panics
```bash
# Create a symbolication bundle for the latest panic
sudo kdpwrit dump latest.kcdata
kmutil analyze-panic latest.kcdata -o ~/panic_report.txt
```
### Live-Remote-Debugging von einem anderen Mac aus

1. Lade die exakt passende **KDK**-Version für den Zielrechner herunter und installiere sie.
2. Verbinde den Ziel-Mac und den Host-Mac mit einem **USB-C- oder Thunderbolt-Kabel**.
3. Auf dem **Zielgerät**:
```bash
sudo nvram boot-args="debug=0x100 kdp_match_name=macbook-target"
reboot
```
4. Auf dem **Host**:
```bash
lldb
(lldb) kdp-remote "udp://macbook-target"
(lldb) bt  # get backtrace in kernel context
```
### LLDB an eine bestimmte geladene kext anhängen
```bash
# Identify load address of the kext
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# Attach
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```
> ℹ️  KDP stellt ausschließlich eine **read-only**-Schnittstelle bereit. Für dynamische Instrumentierung müssen Sie die Binärdatei auf der Festplatte patchen, **kernel function hooking** (z. B. `mach_override`) nutzen oder den Treiber für vollständigen Lese-/Schreibzugriff auf einen **hypervisor** migrieren.

## Referenzen

- [1] [DriverKit security for macOS - Apple Platform Security Guide](https://support.apple.com/guide/security/driverkit-security-seca48c92d43/web)
- [2] [Analyzing CVE-2024-44243, a macOS System Integrity Protection bypass through kernel extensions - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [3] [Microsoft finds new macOS vulnerability, Shrootless, that could bypass System Integrity Protection - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)

{{#include ../../../banners/hacktricks-training.md}}
