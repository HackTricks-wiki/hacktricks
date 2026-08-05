# macOS Kernel Extensions & Kernelcaches

{{#include ../../../banners/hacktricks-training.md}}

## Grundlegende Informationen

Kernel extensions (Kexts) sind **Pakete** mit der Endung **`.kext`**, die **direkt in den macOS-Kernelspace geladen werden** und dem Hauptbetriebssystem zusätzliche Funktionen bereitstellen.

### Status der Deaktivierung & DriverKit / System Extensions
Ab **macOS Catalina (10.15)** markierte Apple die meisten veralteten KPIs als *deprecated* und führte die Frameworks **System Extensions & DriverKit** ein, die im **user-space** ausgeführt werden. Ab **macOS Big Sur (11)** verweigert das Betriebssystem das *Laden* von Third-party-kexts, die auf veralteten KPIs basieren, sofern der Rechner nicht im Modus **Reduced Security** gestartet wurde. Auf Apple Silicon erfordert die Aktivierung von kexts zusätzlich, dass der Benutzer:

1. In die **Recovery** → *Startup Security Utility* neu startet.
2. **Reduced Security** auswählt und **„Allow user management of kernel extensions from identified developers“** aktiviert.
3. Neu startet und die kext unter **System Settings → Privacy & Security** genehmigt.

Mit DriverKit/System Extensions geschriebene User-land-Treiber **reduzieren die Angriffsfläche** erheblich, da Abstürze oder Speicherbeschädigungen auf einen sandboxed Prozess statt auf den Kernelspace beschränkt bleiben.<sup>[1]</sup>

> 📝 Ab macOS Sequoia (15) hat Apple mehrere veraltete Netzwerk- und USB-KPIs vollständig entfernt – die einzige zukunftskompatible Lösung für Anbieter besteht darin, auf System Extensions zu migrieren.

### Anforderungen

Offensichtlich ist dies so leistungsfähig, dass das **Laden einer kernel extension kompliziert** ist. Dies sind die **Anforderungen**, die eine kernel extension erfüllen muss, um geladen zu werden:

- Beim **Starten des Recovery-Modus** muss das Laden von Kernel **extensions erlaubt** sein:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- Die kernel extension muss mit einem **kernel code signing certificate** signiert sein, das nur von **Apple** ausgestellt werden kann. Apple prüft das Unternehmen und die Gründe, aus denen das Zertifikat benötigt wird, eingehend.
- Die kernel extension muss außerdem **notarized** sein, damit Apple sie auf Malware prüfen kann.
- Anschließend kann nur der **root**-Benutzer die **kernel extension laden**, und die Dateien innerhalb des Pakets müssen **root gehören**.
- Während des Upload-Prozesses muss das Paket an einem **geschützten Speicherort außerhalb des root-Verzeichnisses** vorbereitet werden: `/Library/StagedExtensions` (erfordert den Grant `com.apple.rootless.storage.KernelExtensionManagement`).
- Beim Versuch, sie zu laden, erhält der Benutzer schließlich [**eine Bestätigungsanfrage**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html). Bei einer Bestätigung muss der Computer **neu gestartet** werden, damit die extension geladen wird.

### Ladevorgang

In Catalina war der Ablauf folgender: Interessant ist, dass der **Verifizierungsprozess** im **userland** stattfindet. Allerdings können nur Anwendungen mit dem Grant **`com.apple.private.security.kext-management`** den **Kernel auffordern, eine extension zu laden**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **startet** den **Verifizierungsprozess** zum Laden einer extension
- Es kommuniziert über einen **Mach service** mit **`kextd`**.
2. **`kextd`** prüft mehrere Dinge, beispielsweise die **Signatur**
- Es kommuniziert mit **`syspolicyd`**, um zu **prüfen**, ob die extension **geladen werden kann**.
3. **`syspolicyd`** fordert den **Benutzer** auf, eine Entscheidung zu treffen, wenn die extension zuvor noch nicht geladen wurde.
- **`syspolicyd`** meldet das Ergebnis an **`kextd`**
4. **`kextd`** kann den Kernel schließlich **anweisen, die extension zu laden**

Wenn **`kextd`** nicht verfügbar ist, kann **`kextutil`** dieselben Prüfungen durchführen.

### Aufzählung & Verwaltung (geladene kexts)

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
`kmutil inspect` kann ebenfalls verwendet werden, um **den Inhalt einer Kernel Collection (KC) auszugeben** oder zu überprüfen, ob ein kext alle Symbolabhängigkeiten auflöst:
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> Obwohl sich die Kernel Extensions erwartungsgemäß in `/System/Library/Extensions/` befinden, wirst du **keine Binärdatei finden**, wenn du diesen Ordner öffnest. Das liegt am **kernelcache**. Um eine `.kext` zu reverse-engineeren, musst du daher einen Weg finden, sie zu extrahieren.

Der **kernelcache** ist eine **vorab kompilierte und vorab verknüpfte Version des XNU-Kernels**, zusammen mit wichtigen Geräte-**Treibern** und **Kernel Extensions**. Er wird in einem **komprimierten** Format gespeichert und während des Bootvorgangs in den Speicher dekomprimiert. Der kernelcache ermöglicht eine **schnellere Bootzeit**, da eine sofort ausführbare Version des Kernels und der wichtigen Treiber bereitsteht. Dadurch werden Zeit und Ressourcen eingespart, die andernfalls während des Bootvorgangs für das dynamische Laden und Verknüpfen dieser Komponenten benötigt würden.

Die wichtigsten Vorteile des kernelcache sind die **Ladegeschwindigkeit** und die Tatsache, dass alle Module vorab verknüpft sind (keine Verzögerung beim Laden). Sobald alle Module vorab verknüpft wurden, kann KXLD aus dem Speicher entfernt werden, sodass **XNU keine neuen KEXTs laden kann.**

> [!TIP]
> Das Tool [https://github.com/dhinakg/aeota](https://github.com/dhinakg/aeota) entschlüsselt Apples AEA-Container (Apple Encrypted Archive / AEA asset) — das verschlüsselte Containerformat, das Apple für OTA-Assets und einige IPSW-Bestandteile verwendet — und kann das zugrunde liegende `.dmg`- bzw. Asset-Archiv erzeugen, das du anschließend mit den bereitgestellten aastuff-Tools extrahieren kannst.


### Lokaler Kernelcache

Unter iOS befindet er sich in **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`**. Unter macOS kannst du ihn mit folgendem Befehl finden: **`find / -name "kernelcache" 2>/dev/null`** \
In meinem Fall habe ich ihn unter macOS hier gefunden:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

Hier findest du auch den [**kernelcache von Version 14 mit Symbolen**](https://x.com/tihmstar/status/1295814618242318337?lang=en).

#### IMG4 / BVX2 (LZFSE)-komprimiert

Das IMG4-Dateiformat ist ein von Apple in iOS- und macOS-Geräten verwendetes Containerformat zum sicheren **Speichern und Überprüfen von Firmware**-Komponenten (wie dem **kernelcache**). Das IMG4-Format enthält einen Header und mehrere Tags, die verschiedene Datenbestandteile kapseln, darunter die eigentliche Payload (beispielsweise einen Kernel oder Bootloader), eine Signatur und eine Reihe von Manifest-Eigenschaften. Das Format unterstützt eine kryptografische Überprüfung, sodass das Gerät vor der Ausführung die Authentizität und Integrität der Firmware-Komponente bestätigen kann.

Es besteht normalerweise aus den folgenden Komponenten:

- **Payload (IM4P)**:
- Oft komprimiert (LZFSE4, LZSS, …)
- Optional verschlüsselt
- **Manifest (IM4M)**:
- Enthält eine Signatur
- Zusätzliches Key/Value-Dictionary
- **Restore Info (IM4R)**:
- Auch als APNonce bekannt
- Verhindert das erneute Einspielen bestimmter Updates
- OPTIONAL: Wird normalerweise nicht gefunden

Dekomprimiere den Kernelcache:
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

**`Disarm`** ermöglicht es, Funktionen aus dem kernelcache mithilfe von Matchern zu symbolisieren. Diese Matcher sind einfache Musterregeln (Textzeilen), die disarm mitteilen, wie Funktionen, Argumente sowie Panic-/Log-Strings innerhalb einer Binärdatei erkannt und automatisch symbolisiert werden.

Im Grunde gibst du den String an, den eine Funktion verwendet, und disarm findet ihn und **symbolisiert ihn**.
```bash
You can find some `xnu.matchers` in [https://newosxbook.com/tools/disarm.html](https://newosxbook.com/tools/disarm.html) in the **`Matchers`** section. You can also create your own matchers.

```bash
# Gehe zu /tmp/extracted, wo disarm die Dateisätze extrahiert hat
disarm -e filesets kernelcache.release.d23 # Immer nach /tmp/extracted extrahieren
cd /tmp/extracted
JMATCHERS=xnu.matchers disarm --analyze kernel.rebuilt  # Beachte, dass xnu.matchers tatsächlich eine Datei mit den Matchern ist
```

### Download

An **IPSW (iPhone/iPad Software)** is Apple’s firmware package format used for device restores, updates, and full firmware bundles. Among other things, it contains the **kernelcache**.

- [**KernelDebugKit Github**](https://github.com/dortania/KdkSupportPkg/releases)

In [https://github.com/dortania/KdkSupportPkg/releases](https://github.com/dortania/KdkSupportPkg/releases) it's possible to find all the kernel debug kits. You can download it, mount it, open it with [Suspicious Package](https://www.mothersruin.com/software/SuspiciousPackage/get.html) tool, access the **`.kext`** folder and **extract it**.

Check it for symbols with:

```bash
nm -a ~/Downloads/Sandbox.kext/Contents/MacOS/Sandbox | wc -l
```

- [**theapplewiki.com**](https://theapplewiki.com/wiki/Firmware/Mac/14.x)**,** [**ipsw.me**](https://ipsw.me/)**,** [**theiphonewiki.com**](https://www.theiphonewiki.com/)

Sometime Apple releases **kernelcache** with **symbols**. You can download some firmwares with symbols by following links on those pages. The firmwares will contain the **kernelcache** among other files.

To **extract** the kernel cache you can do:

```bash
# ipsw tool installieren
brew install blacktop/tap/ipsw

# Nur den kernelcache aus der IPSW extrahieren
ipsw extract --kernel /path/to/YourFirmware.ipsw -o out/

# Das Ergebnis sollte etwa so aussehen:
#   out/Firmware/kernelcache.release.iPhoneXX
#   oder eine IMG4-Nutzlast: out/Firmware/kernelcache.release.iPhoneXX.im4p

# Wenn du eine IMG4-Nutzlast erhältst:
ipsw img4 im4p extract out/Firmware/kernelcache*.im4p -o kcache.raw
```

Another option to **extract** the files start by changing the extension from `.ipsw` to `.zip` and **unzip** it.

After extracting the firmware you will get a file like: **`kernelcache.release.iphone14`**. It's in **IMG4** format, you can extract the interesting info with:

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

### Inspecting kernelcache

Check if the kernelcache has symbols with

```bash
nm -a kernelcache.release.iphone14.e | wc -l
```

With this we can now **extract all the extensions** or the **one you are interested in:**

```bash
# Alle Extensions auflisten
kextex -l kernelcache.release.iphone14.e
## com.apple.security.sandbox extrahieren
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# Alle extrahieren
kextex_all kernelcache.release.iphone14.e

# Die Extension auf Symbole prüfen
nm -a binaries/com.apple.security.sandbox | wc -l
```


## Recent vulnerabilities & exploitation techniques

| Year | CVE | Summary |
|------|-----|---------|
| 2024 | **CVE-2024-44243** | Logic flaw in **`storagekitd`** allowed a *root* attacker to register a malicious file-system bundle that ultimately loaded an **unsigned kext**, **bypassing System Integrity Protection (SIP)** and enabling persistent rootkits. Patched in macOS 14.2 / 15.2.   |
| 2021 | **CVE-2021-30892** (*Shrootless*) | Installation daemon with the entitlement `com.apple.rootless.install` could be abused to execute arbitrary post-install scripts, disable SIP and load arbitrary kexts.  |

**Take-aways for red-teamers**

1. **Look for entitled daemons (`codesign -dvv /path/bin | grep entitlements`) that interact with Disk Arbitration, Installer or Kext Management.**
2. **Abusing SIP bypasses almost always grants the ability to load a kext → kernel code execution**.

**Defensive tips**

*Keep SIP enabled*, monitor for `kmutil load`/`kmutil create -n aux` invocations coming from non-Apple binaries and alert on any write to `/Library/Extensions`. Endpoint Security events `ES_EVENT_TYPE_NOTIFY_KEXTLOAD` provide near real-time visibility.

## Debugging macOS kernel & kexts

Apple’s recommended workflow is to build a **Kernel Debug Kit (KDK)** that matches the running build and then attach **LLDB** over a **KDP (Kernel Debugging Protocol)** network session.

### One-shot local debug of a panic

```bash
# Symbolication-Bundle für den neuesten Panic erstellen
sudo kdpwrit dump latest.kcdata
kmutil analyze-panic latest.kcdata -o ~/panic_report.txt
```

### Live remote debugging from another Mac

1. Download + install the exact **KDK** version for the target machine.
2. Connect the target Mac and the host Mac with a **USB-C or Thunderbolt cable**.
3. On the **target**:

```bash
sudo nvram boot-args="debug=0x100 kdp_match_name=macbook-target"
reboot
```

4. On the **host**:

```bash
lldb
(lldb) kdp-remote "udp://macbook-target"
(lldb) bt  # Backtrace im Kernel-Kontext abrufen
```

### Attaching LLDB to a specific loaded kext

```bash
# Ladeadresse der kext ermitteln
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# Anhängen
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```

> ℹ️  KDP only exposes a **read-only** interface. For dynamic instrumentation you will need to patch the binary on-disk, leverage **kernel function hooking** (e.g. `mach_override`) or migrate the driver to a **hypervisor** for full read/write.

## References

- [1] [DriverKit security for macOS - Apple Platform Security Guide](https://support.apple.com/guide/security/driverkit-security-seca48c92d43/web)
- [2] [Analyzing CVE-2024-44243, a macOS System Integrity Protection bypass through kernel extensions - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)

{{#include ../../../banners/hacktricks-training.md}}
