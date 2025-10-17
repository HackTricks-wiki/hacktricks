# macOS Kernel-Erweiterungen & Kernelcaches

{{#include ../../../banners/hacktricks-training.md}}

## Grundlegende Informationen

Kernel extensions (Kexts) sind **Pakete** mit einer **`.kext`**-Erweiterung, die **direkt in den macOS-Kernelbereich geladen** werden und zusätzliche Funktionalität für das Betriebssystem bereitstellen.

### Deprecation-Status & DriverKit / System Extensions
Beginnend mit **macOS Catalina (10.15)** markierte Apple die meisten Legacy-KPIs als *deprecated* und führte die **System Extensions & DriverKit**-Frameworks ein, die im **user-space** laufen. Ab **macOS Big Sur (11)** verweigert das Betriebssystem das Laden von Drittanbieter-kexts, die auf veralteten KPIs basieren, es sei denn, die Maschine wird im **Reduced Security**-Modus gestartet. Auf Apple Silicon erfordert das Aktivieren von kexts zusätzlich, dass der Benutzer:

1. In **Recovery** → *Startup Security Utility* neu startet.
2. **Reduced Security** auswählt und **“Allow user management of kernel extensions from identified developers”** aktiviert.
3. Neustart durchführt und die kext in **System Settings → Privacy & Security** genehmigt.

User-land Treiber, die mit DriverKit/System Extensions geschrieben sind, reduzieren dramatisch die **attack surface**, weil Abstürze oder Speicherbeschädigungen auf einen sandboxed process begrenzt sind und nicht in den Kernelbereich gelangen.

> 📝 Ab macOS Sequoia (15) hat Apple mehrere Legacy Networking- und USB-KPIs vollständig entfernt – die einzige forward-kompatible Lösung für Anbieter ist die Migration zu System Extensions.

### Voraussetzungen

Offensichtlich ist das so mächtig, dass es **kompliziert ist, eine Kernel-Erweiterung zu laden**. Das sind die **Voraussetzungen**, die eine Kernel-Erweiterung erfüllen muss, damit sie geladen werden darf:

- Beim **Betreten des recovery mode** müssen Kernel **extensions erlaubt** sein, geladen zu werden:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- Die Kernel-Erweiterung muss mit einem **kernel code signing certificate** signiert sein, das nur von **Apple** vergeben werden kann. Apple wird das Unternehmen und die Gründe für die Notwendigkeit im Detail prüfen.
- Die Kernel-Erweiterung muss zudem **notarized** sein; Apple kann sie dann auf Malware prüfen.
- Danach ist der **root**-Benutzer derjenige, der die **Kernel-Erweiterung laden** kann, und die Dateien innerhalb des Pakets müssen **root gehören**.
- Während des Upload-Prozesses muss das Paket an einem **geschützten Nicht-Root-Ort** vorbereitet werden: `/Library/StagedExtensions` (erfordert das `com.apple.rootless.storage.KernelExtensionManagement`-Grant).
- Schließlich erhält der Benutzer beim Versuch, sie zu laden, [**eine Bestätigungsanfrage**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) und, wenn akzeptiert, muss der Computer **neu gestartet** werden, damit sie geladen wird.

### Ladevorgang

In Catalina sah das so aus: Interessant ist, dass der **Verifizierungs**prozess in **userland** stattfindet. Allerdings können nur Anwendungen mit dem **`com.apple.private.security.kext-management`**-Grant den **Kernel anfragen, eine Extension zu laden**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** CLI **startet** den **Verifizierungs**prozess zum Laden einer Extension
- Es wird mit **`kextd`** über einen **Mach service** kommunizieren.
2. **`kextd`** prüft mehrere Dinge, etwa die **Signatur**
- Es wird mit **`syspolicyd`** sprechen, um zu **prüfen**, ob die Extension **geladen** werden darf.
3. **`syspolicyd`** wird den **Benutzer** auffordern, falls die Extension nicht zuvor geladen wurde.
- **`syspolicyd`** meldet das Ergebnis an **`kextd`**
4. **`kextd`** kann schließlich dem Kernel mitteilen, die Extension zu **laden**

Wenn **`kextd`** nicht verfügbar ist, kann **`kextutil`** dieselben Prüfungen durchführen.

### Auflistung & Verwaltung (geladene kexts)

`kextstat` war das historische Tool, ist aber in aktuellen macOS-Versionen **deprecated**. Die moderne Schnittstelle ist **`kmutil`**:
```bash
# List every extension currently linked in the kernel, sorted by load address
sudo kmutil showloaded --sort

# Show only third-party / auxiliary collections
sudo kmutil showloaded --collection aux

# Unload a specific bundle
sudo kmutil unload -b com.example.mykext
```
Ältere Syntax ist weiterhin als Referenz verfügbar:
```bash
# (Deprecated) Get loaded kernel extensions
kextstat

# (Deprecated) Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
`kmutil inspect` kann außerdem dazu verwendet werden, **dump the contents of a Kernel Collection (KC)** oder zu verifizieren, dass ein kext alle symbolischen Abhängigkeiten auflöst:
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> Even though the kernel extensions are expected to be in `/System/Library/Extensions/`, if you go to this folder you **won't find any binary**. This is because of the **kernelcache** and in order to reverse one `.kext` you need to find a way to obtain it.

Die **kernelcache** ist eine **vor-kompilierte und vor-verlinkte Version des XNU-Kernels**, zusammen mit essenziellen Gerätetreibern und **kernel extensions**. Sie wird in einem **komprimierten** Format gespeichert und während des Bootvorgangs in den Speicher dekomprimiert. Die kernelcache ermöglicht eine **schnellere Bootzeit**, da eine sofort ausführbare Version des Kernels und wichtiger Treiber bereitsteht und so die Zeit und Ressourcen reduziert werden, die sonst für das dynamische Laden und Verlinken dieser Komponenten beim Booten aufgewendet würden.

Der Hauptvorteil der kernelcache ist die **Geschwindigkeit beim Laden** und dass alle Module vorverlinkt sind (kein Ladezeit-Overhead). Und sobald alle Module vorverlinkt sind, kann KXLD aus dem Speicher entfernt werden, sodass **XNU keine neuen KEXTs laden kann.**

> [!TIP]
> The [https://github.com/dhinakg/aeota](https://github.com/dhinakg/aeota) tool decrypts Apple’s AEA (Apple Encrypted Archive / AEA asset) containers — the encrypted container format Apple uses for OTA assets and some IPSW pieces — and can produce the underlying .dmg/asset archive that you can then extract with the provided aastuff tools.

### Lokaler Kernelcache

In iOS befindet sich der Kernelcache in **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`**; in macOS kannst du ihn finden mit: **`find / -name "kernelcache" 2>/dev/null`** \
In meinem Fall habe ich ihn in macOS hier gefunden:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

Find also here the [**kernelcache of version 14 with symbols**](https://x.com/tihmstar/status/1295814618242318337?lang=en).

#### IMG4 / BVX2 (LZFSE) komprimiert

Das IMG4-Dateiformat ist ein Containerformat, das Apple auf iOS- und macOS-Geräten verwendet, um Firmwarekomponenten (wie die **kernelcache**) sicher zu **speichern und zu verifizieren**. Das IMG4-Format enthält einen Header und mehrere Tags, die verschiedene Datenstücke umschließen, einschließlich des eigentlichen Payloads (z. B. eines Kernels oder Bootloaders), einer Signatur und einer Menge Manifest-Eigenschaften. Das Format unterstützt kryptografische Verifikation, sodass das Gerät die Echtheit und Integrität der Firmwarekomponente bestätigen kann, bevor es sie ausführt.

Es besteht üblicherweise aus den folgenden Komponenten:

- **Payload (IM4P)**:
- Often compressed (LZFSE4, LZSS, …)
- Optionally encrypted
- **Manifest (IM4M)**:
- Contains Signature
- Additional Key/Value dictionary
- **Restore Info (IM4R)**:
- Also known as APNonce
- Prevents replaying of some updates
- OPTIONAL: Usually this isn't found

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

**`Disarm`** ermöglicht es, Funktionen aus dem kernelcache mit Hilfe von matchers zu symbolicate.

Diese matchers sind einfache Pattern-Regeln (Textzeilen), die disarm sagen, wie Funktionen, Argumente und panic/log-Strings innerhalb einer Binary erkannt & auto-symbolicate werden.

Im Grunde gibst du die Zeichenkette an, die eine Funktion verwendet, und disarm findet sie und **symbolicate it**.
```bash
You can find some `xnu.matchers` in [https://newosxbook.com/tools/disarm.html](https://newosxbook.com/tools/disarm.html) in the **`Matchers`** section. You can also create your own matchers.

```bash
# Wechsle zu /tmp/extracted, wo disarm die filesets extrahiert hat
disarm -e filesets kernelcache.release.d23 # Always extract to /tmp/extracted
cd /tmp/extracted
JMATCHERS=xnu.matchers disarm --analyze kernel.rebuilt  # Note that xnu.matchers is actually a file with the matchers
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
# Installiere das ipsw-Tool
brew install blacktop/tap/ipsw

# Extrahiere nur den kernelcache aus dem IPSW
ipsw extract --kernel /path/to/YourFirmware.ipsw -o out/

# Du solltest so etwas erhalten:
#   out/Firmware/kernelcache.release.iPhoneXX
#   oder ein IMG4-Payload: out/Firmware/kernelcache.release.iPhoneXX.im4p

# Falls du ein IMG4-Payload bekommst:
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
# Alle Erweiterungen auflisten
kextex -l kernelcache.release.iphone14.e
## com.apple.security.sandbox extrahieren
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# Alles extrahieren
kextex_all kernelcache.release.iphone14.e

# Erweiterung auf Symbole prüfen
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
# Erstelle ein Symbolisierungs-Bundle für den neuesten panic
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
(lldb) bt  # get backtrace in kernel context
```

### Attaching LLDB to a specific loaded kext

```bash
# kext-Ladeadresse ermitteln
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# An Debugger anhängen
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```

> ℹ️  KDP only exposes a **read-only** interface. For dynamic instrumentation you will need to patch the binary on-disk, leverage **kernel function hooking** (e.g. `mach_override`) or migrate the driver to a **hypervisor** for full read/write.

## References

- DriverKit Security – Apple Platform Security Guide
- Microsoft Security Blog – *Analyzing CVE-2024-44243 SIP bypass*

{{#include ../../../banners/hacktricks-training.md}}
