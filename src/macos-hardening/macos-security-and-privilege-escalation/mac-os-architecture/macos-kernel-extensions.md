# macOS Kernel Extensions & Debugging

{{#include ../../../banners/hacktricks-training.md}}

## Grundinformationen

Kernel-Erweiterungen (Kexts) sind **Pakete** mit einer **`.kext`**-Erweiterung, die **direkt in den macOS-Kernelraum geladen werden**, um zusätzliche Funktionalität zum Hauptbetriebssystem bereitzustellen.

### Abkündigungsstatus & DriverKit / Systemerweiterungen
Beginnend mit **macOS Catalina (10.15)** hat Apple die meisten veralteten KPIs als *abgekündigt* markiert und die **Systemerweiterungen & DriverKit**-Frameworks eingeführt, die im **Benutzermodus** ausgeführt werden. Ab **macOS Big Sur (11)** wird das Betriebssystem *verweigern,* Drittanbieter-Kexts zu laden, die auf abgekündigten KPIs basieren, es sei denn, die Maschine wird im **Reduzierten Sicherheitsmodus** gestartet. Auf Apple Silicon erfordert das Aktivieren von Kexts zusätzlich, dass der Benutzer:

1. In **Wiederherstellung** → *Startup Security Utility* neu startet.
2. **Reduzierte Sicherheit** auswählt und **„Benutzermanagement von Kernel-Erweiterungen von identifizierten Entwicklern zulassen“** ankreuzt.
3. Neu startet und die Kexts in **Systemeinstellungen → Datenschutz & Sicherheit** genehmigt.

Benutzerebene-Treiber, die mit DriverKit/Systemerweiterungen geschrieben wurden, **reduzieren die Angriffsfläche** erheblich, da Abstürze oder Speicherbeschädigungen auf einen sandboxed Prozess beschränkt sind und nicht auf den Kernelraum.

> 📝 Ab macOS Sequoia (15) hat Apple mehrere veraltete Netzwerk- und USB-KPIs vollständig entfernt – die einzige zukunftssichere Lösung für Anbieter besteht darin, auf Systemerweiterungen umzusteigen.

### Anforderungen

Offensichtlich ist es so mächtig, dass es **kompliziert ist, eine Kernel-Erweiterung zu laden**. Dies sind die **Anforderungen**, die eine Kernel-Erweiterung erfüllen muss, um geladen zu werden:

- Beim **Eintreten in den Wiederherstellungsmodus** müssen Kernel-**Erweiterungen** geladen werden dürfen:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- Die Kernel-Erweiterung muss **mit einem Kernel-Code-Signaturzertifikat signiert** sein, das nur von **Apple** **gewährt** werden kann. Wer wird das Unternehmen und die Gründe, warum es benötigt wird, im Detail überprüfen.
- Die Kernel-Erweiterung muss auch **notariell beglaubigt** sein, Apple wird in der Lage sein, sie auf Malware zu überprüfen.
- Dann ist der **Root**-Benutzer derjenige, der die **Kernel-Erweiterung laden** kann, und die Dateien im Paket müssen **dem Root gehören**.
- Während des Upload-Prozesses muss das Paket an einem **geschützten Nicht-Root-Standort** vorbereitet werden: `/Library/StagedExtensions` (erfordert die Genehmigung `com.apple.rootless.storage.KernelExtensionManagement`).
- Schließlich erhält der Benutzer beim Versuch, sie zu laden, eine [**Bestätigungsanfrage**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) und, wenn akzeptiert, muss der Computer **neu gestartet** werden, um sie zu laden.

### Ladeprozess

In Catalina war es so: Es ist interessant zu beachten, dass der **Überprüfungs**prozess im **Benutzermodus** erfolgt. Allerdings können nur Anwendungen mit der **`com.apple.private.security.kext-management`**-Genehmigung **den Kernel auffordern, eine Erweiterung zu laden**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **startet** den **Überprüfungs**prozess zum Laden einer Erweiterung
- Es wird mit **`kextd`** kommunizieren, indem es einen **Mach-Dienst** verwendet.
2. **`kextd`** wird mehrere Dinge überprüfen, wie die **Signatur**
- Es wird mit **`syspolicyd`** kommunizieren, um zu **überprüfen**, ob die Erweiterung **geladen** werden kann.
3. **`syspolicyd`** wird den **Benutzer** auffordern, wenn die Erweiterung nicht zuvor geladen wurde.
- **`syspolicyd`** wird das Ergebnis an **`kextd`** melden
4. **`kextd`** wird schließlich in der Lage sein, dem Kernel zu **sagen, die Erweiterung zu laden**

Wenn **`kextd`** nicht verfügbar ist, kann **`kextutil`** die gleichen Überprüfungen durchführen.

### Auflistung & Verwaltung (geladene Kexts)

`kextstat` war das historische Tool, ist aber in den neuesten macOS-Versionen **abgekündigt**. Die moderne Schnittstelle ist **`kmutil`**:
```bash
# List every extension currently linked in the kernel, sorted by load address
sudo kmutil showloaded --sort

# Show only third-party / auxiliary collections
sudo kmutil showloaded --collection aux

# Unload a specific bundle
sudo kmutil unload -b com.example.mykext
```
Ältere Syntax ist weiterhin zur Referenz verfügbar:
```bash
# (Deprecated) Get loaded kernel extensions
kextstat

# (Deprecated) Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
`kmutil inspect` kann auch verwendet werden, um **den Inhalt einer Kernel Collection (KC) zu dumpen** oder um zu überprüfen, ob ein kext alle Symbolabhängigkeiten auflöst:
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> Auch wenn die Kernel-Erweiterungen in `/System/Library/Extensions/` erwartet werden, wirst du in diesem Ordner **keine Binärdatei** finden. Das liegt am **Kernelcache**, und um eine `.kext` zurückzuverfolgen, musst du einen Weg finden, sie zu erhalten.

Der **Kernelcache** ist eine **vorkompilierte und vorverlinkte Version des XNU-Kernels**, zusammen mit wesentlichen Geräte-**Treibern** und **Kernel-Erweiterungen**. Er wird in einem **komprimierten** Format gespeichert und während des Bootvorgangs in den Arbeitsspeicher dekomprimiert. Der Kernelcache ermöglicht eine **schnellere Bootzeit**, indem eine sofort einsatzbereite Version des Kernels und wichtiger Treiber verfügbar ist, wodurch die Zeit und Ressourcen reduziert werden, die sonst für das dynamische Laden und Verlinken dieser Komponenten beim Booten benötigt würden.

### Lokaler Kernelcache

In iOS befindet er sich in **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`** in macOS kannst du ihn finden mit: **`find / -name "kernelcache" 2>/dev/null`** \
In meinem Fall habe ich ihn in macOS gefunden in:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

#### IMG4

Das IMG4-Dateiformat ist ein Containerformat, das von Apple in seinen iOS- und macOS-Geräten verwendet wird, um Firmware-Komponenten (wie **Kernelcache**) sicher **zu speichern und zu verifizieren**. Das IMG4-Format umfasst einen Header und mehrere Tags, die verschiedene Datenstücke kapseln, einschließlich der tatsächlichen Nutzlast (wie einen Kernel oder Bootloader), einer Signatur und einer Reihe von Manifest-Eigenschaften. Das Format unterstützt die kryptografische Verifizierung, die es dem Gerät ermöglicht, die Authentizität und Integrität der Firmware-Komponente vor der Ausführung zu bestätigen.

Es besteht normalerweise aus den folgenden Komponenten:

- **Nutzlast (IM4P)**:
- Oft komprimiert (LZFSE4, LZSS, …)
- Optional verschlüsselt
- **Manifest (IM4M)**:
- Enthält Signatur
- Zusätzliches Schlüssel/Wert-Wörterbuch
- **Wiederherstellungsinfo (IM4R)**:
- Auch bekannt als APNonce
- Verhindert das Wiederholen einiger Updates
- OPTIONAL: Normalerweise wird dies nicht gefunden

Dekomprimiere den Kernelcache:
```bash
# img4tool (https://github.com/tihmstar/img4tool)
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### Download

- [**KernelDebugKit Github**](https://github.com/dortania/KdkSupportPkg/releases)

In [https://github.com/dortania/KdkSupportPkg/releases](https://github.com/dortania/KdkSupportPkg/releases) ist es möglich, alle Kernel-Debug-Kits zu finden. Sie können es herunterladen, einbinden, mit dem [Suspicious Package](https://www.mothersruin.com/software/SuspiciousPackage/get.html) Tool öffnen, auf den **`.kext`** Ordner zugreifen und **es extrahieren**.

Überprüfen Sie es auf Symbole mit:
```bash
nm -a ~/Downloads/Sandbox.kext/Contents/MacOS/Sandbox | wc -l
```
- [**theapplewiki.com**](https://theapplewiki.com/wiki/Firmware/Mac/14.x)**,** [**ipsw.me**](https://ipsw.me/)**,** [**theiphonewiki.com**](https://www.theiphonewiki.com/)

Manchmal veröffentlicht Apple **kernelcache** mit **Symbols**. Sie können einige Firmware-Versionen mit Symbols über die Links auf diesen Seiten herunterladen. Die Firmwares enthalten den **kernelcache** neben anderen Dateien.

Um die Dateien zu **extrahieren**, ändern Sie zunächst die Erweiterung von `.ipsw` in `.zip` und **entpacken** Sie sie.

Nach dem Extrahieren der Firmware erhalten Sie eine Datei wie: **`kernelcache.release.iphone14`**. Sie ist im **IMG4**-Format, Sie können die interessanten Informationen mit:

[**pyimg4**](https://github.com/m1stadev/PyIMG4)**:**
```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
[**img4tool**](https://github.com/tihmstar/img4tool)**:**
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### Inspecting kernelcache

Überprüfen Sie, ob der kernelcache Symbole mit
```bash
nm -a kernelcache.release.iphone14.e | wc -l
```
Damit können wir jetzt **alle Erweiterungen** oder die **eine, die Sie interessiert:** **extrahieren:**
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
## Aktuelle Schwachstellen & Ausnutzungstechniken

| Jahr | CVE | Zusammenfassung |
|------|-----|-----------------|
| 2024 | **CVE-2024-44243** | Logikfehler in **`storagekitd`** ermöglichte es einem *root*-Angreifer, ein bösartiges Dateisystem-Bundle zu registrieren, das letztendlich einen **nicht signierten kext** ladete, **System Integrity Protection (SIP)** umging und persistente Rootkits ermöglichte. In macOS 14.2 / 15.2 gepatcht.   |
| 2021 | **CVE-2021-30892** (*Shrootless*) | Installationsdaemon mit der Berechtigung `com.apple.rootless.install` konnte missbraucht werden, um beliebige Post-Installations-Skripte auszuführen, SIP zu deaktivieren und beliebige kexts zu laden.  |

**Wichtige Erkenntnisse für Red-Teamer**

1. **Suchen Sie nach berechtigten Daemons (`codesign -dvv /path/bin | grep entitlements`), die mit Disk Arbitration, Installer oder Kext Management interagieren.**
2. **Der Missbrauch von SIP-Umgehungen gewährt fast immer die Fähigkeit, einen kext zu laden → Kernel-Code-Ausführung**.

**Defensive Tipps**

*Halten Sie SIP aktiviert*, überwachen Sie `kmutil load`/`kmutil create -n aux` Aufrufe von nicht-Apple-Binärdateien und alarmieren Sie bei jedem Schreibvorgang auf `/Library/Extensions`. Endpoint-Sicherheitsereignisse `ES_EVENT_TYPE_NOTIFY_KEXTLOAD` bieten nahezu Echtzeit-Transparenz.

## Debugging des macOS-Kernels & kexts

Apples empfohlener Workflow besteht darin, ein **Kernel Debug Kit (KDK)** zu erstellen, das mit dem laufenden Build übereinstimmt, und dann **LLDB** über eine **KDP (Kernel Debugging Protocol)**-Netzwerksitzung anzuhängen.

### Einmalige lokale Fehlersuche bei einem Panic
```bash
# Create a symbolication bundle for the latest panic
sudo kdpwrit dump latest.kcdata
kmutil analyze-panic latest.kcdata -o ~/panic_report.txt
```
### Live-Remote-Debugging von einem anderen Mac

1. Laden Sie die genaue **KDK**-Version für die Zielmaschine herunter und installieren Sie sie.
2. Verbinden Sie den Ziel-Mac und den Host-Mac mit einem **USB-C- oder Thunderbolt-Kabel**.
3. Auf dem **Ziel**:
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
### Anfügen von LLDB an eine bestimmte geladene kext
```bash
# Identify load address of the kext
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# Attach
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```
> ℹ️  KDP bietet nur eine **schreibgeschützte** Schnittstelle. Für dynamische Instrumentierung müssen Sie die Binärdatei auf der Festplatte patchen, **Kernel-Funktions-Hooking** (z.B. `mach_override`) nutzen oder den Treiber zu einem **Hypervisor** migrieren, um vollständigen Lese-/Schreibzugriff zu erhalten.

## References

- DriverKit-Sicherheit – Apple Platform Security Guide
- Microsoft Security Blog – *Analyzing CVE-2024-44243 SIP bypass*

{{#include ../../../banners/hacktricks-training.md}}
