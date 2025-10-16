# macOS Kernel-Erweiterungen & Kernelcaches

{{#include ../../../banners/hacktricks-training.md}}

## Grundlegende Informationen

Kernel extensions (Kexts) sind **Pakete** mit der **`.kext`**-Erweiterung, die **direkt in den macOS-Kernelraum geladen** werden und dem Betriebssystem zusätzliche Funktionalität bereitstellen.

### Abkündigungsstatus & DriverKit / System Extensions
Beginnend mit **macOS Catalina (10.15)** hat Apple die meisten Legacy-KPIs als *deprecated* markiert und die **System Extensions & DriverKit**-Frameworks eingeführt, die im **Benutzerraum** laufen. Ab **macOS Big Sur (11)** weigert sich das Betriebssystem, Drittanbieter-kexts zu laden, die auf veralteten KPIs basieren, es sei denn, die Maschine wurde im **Reduced Security**-Modus gestartet. Auf Apple Silicon erfordert das Aktivieren von kexts zusätzlich, dass der Benutzer:

1. In **Recovery** neu startet → *Startup Security Utility*.
2. **Reduced Security** auswählt und **„Allow user management of kernel extensions from identified developers“** aktiviert.
3. Neustart durchführt und die kext in **System Settings → Privacy & Security** genehmigt.

Treiber im Benutzerraum, die mit DriverKit/System Extensions geschrieben sind, reduzieren die Angriffsfläche drastisch, weil Abstürze oder Speicherbeschädigungen auf einen sandboxed Prozess beschränkt bleiben und nicht den Kernel betreffen.

> 📝 Ab macOS Sequoia (15) hat Apple mehrere Legacy-Netzwerk- und USB-KPIs vollständig entfernt – die einzige zukunftssichere Lösung für Anbieter ist die Migration zu System Extensions.

### Anforderungen

Offensichtlich ist das so mächtig, dass es kompliziert ist, eine Kernel-Erweiterung zu laden. Dies sind die **Anforderungen**, die eine Kernel-Erweiterung erfüllen muss, um geladen zu werden:

- Beim Start in den Wiederherstellungsmodus müssen Kernel-Erweiterungen das Laden erlaubt sein:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- Die Kernel-Erweiterung muss mit einem **Kernel-Code-Signing-Zertifikat** signiert sein, das nur von Apple **ausgestellt** werden kann. Apple wird das Unternehmen und die Gründe für die Notwendigkeit im Detail prüfen.
- Die Kernel-Erweiterung muss außerdem **notarisiert** sein; Apple kann sie dann auf Malware überprüfen.
- Anschließend kann nur der **root**-Benutzer die Kernel-Erweiterung **laden**, und die Dateien innerhalb des Pakets müssen **root** gehören.
- Während des Upload-Vorgangs muss das Paket in einem **geschützten Nicht-Root-Verzeichnis** vorbereitet werden: `/Library/StagedExtensions` (erfordert die `com.apple.rootless.storage.KernelExtensionManagement`-Berechtigung).
- Schließlich erhält der Benutzer beim Versuch, sie zu laden, [**eine Bestätigungsanfrage**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) und, wenn diese akzeptiert wird, muss der Rechner **neugestartet** werden, um sie zu laden.

### Ladevorgang

In Catalina sah es so aus: Es ist interessant festzustellen, dass der **Verifizierungs**-Prozess im **Benutzerraum** stattfindet. Nur Anwendungen mit der Berechtigung `com.apple.private.security.kext-management` können allerdings **den Kernel auffordern, eine Erweiterung zu laden**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** CLI **startet** den **Verifizierungs**-Prozess zum Laden einer Erweiterung
- Es kommuniziert mit **`kextd`** über einen **Mach-Service**.
2. **`kextd`** überprüft mehrere Dinge, z. B. die **Signatur**
- Es spricht mit **`syspolicyd`**, um zu **prüfen**, ob die Erweiterung **geladen** werden kann.
3. **`syspolicyd`** fordert den **Benutzer** auf, wenn die Erweiterung nicht zuvor geladen wurde.
- **`syspolicyd`** meldet das Ergebnis an **`kextd`**
4. **`kextd`** kann schließlich dem Kernel mitteilen, die Erweiterung zu laden

Falls **`kextd`** nicht verfügbar ist, kann **`kextutil`** dieselben Überprüfungen durchführen.

### Auflistung & Verwaltung (geladene kexts)

`kextstat` war das historische Tool, ist aber in neueren macOS-Versionen **deprecated**. Die moderne Schnittstelle ist **`kmutil`**:
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
`kmutil inspect` kann auch genutzt werden, um **die Inhalte einer Kernel Collection (KC) zu dumpen** oder zu prüfen, dass ein kext alle Symbolabhängigkeiten auflöst:
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> Obwohl die Kernel-Erweiterungen normalerweise in `/System/Library/Extensions/` erwartet werden, wirst du in diesem Ordner **keine Binärdatei finden**. Das liegt am **kernelcache** und um eine `.kext` zu reverse-engineeren, musst du einen Weg finden, sie zu bekommen.

Der **kernelcache** ist eine **vorkompilierte und vorverlinkte Version des XNU-Kernels**, zusammen mit wichtigen Gerätetreibern und **Kernel-Erweiterungen**. Er wird in einem **komprimierten** Format gespeichert und während des Bootvorgangs in den Speicher entpackt. Der kernelcache ermöglicht eine **schnellere Bootzeit**, weil eine sofort ausführbare Version des Kernels und der entscheidenden Treiber bereitsteht, wodurch die Zeit und Ressourcen reduziert werden, die sonst für das dynamische Laden und Verlinken dieser Komponenten beim Start benötigt würden.

Die Hauptvorteile des kernelcache sind die **schnellere Ladezeit** und dass alle Module vorverlinkt sind (keine Ladezeit-Behinderung). Und sobald alle Module vorverlinkt sind, kann KXLD aus dem Speicher entfernt werden, sodass **XNU keine neuen KEXTs laden kann.**

> [!TIP]
> The [https://github.com/dhinakg/aeota](https://github.com/dhinakg/aeota) tool decrypts Apple’s AEA (Apple Encrypted Archive / AEA asset) containers — the encrypted container format Apple uses for OTA assets and some IPSW pieces — and can produce the underlying .dmg/asset archive that you can then extract with the provided aastuff tools.

### Lokaler Kernelcache

Unter iOS befindet es sich in **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`**; unter macOS findest du es mit: **`find / -name "kernelcache" 2>/dev/null`** \
In meinem Fall habe ich es unter macOS hier gefunden:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

Find also here the [**kernelcache of version 14 with symbols**](https://x.com/tihmstar/status/1295814618242318337?lang=en).

#### IMG4 / BVX2 (LZFSE) komprimiert

Das IMG4-Dateiformat ist ein Containerformat, das Apple in seinen iOS- und macOS-Geräten verwendet, um Firmware-Komponenten (wie den **kernelcache**) sicher **zu speichern und zu verifizieren**. Das IMG4-Format enthält einen Header und mehrere Tags, die verschiedene Datenstücke kapseln, einschließlich der eigentlichen Nutzlast (wie ein Kernel oder Bootloader), einer Signatur und einer Reihe von Manifest-Eigenschaften. Das Format unterstützt kryptografische Verifikation, sodass das Gerät die Authentizität und Integrität der Firmware-Komponente vor deren Ausführung bestätigen kann.

Es besteht üblicherweise aus den folgenden Komponenten:

- **Payload (IM4P)**:
- Oft komprimiert (LZFSE4, LZSS, …)
- Optional verschlüsselt
- **Manifest (IM4M)**:
- Enthält Signatur
- Zusätzliches Key/Value-Wörterbuch
- **Restore Info (IM4R)**:
- Auch bekannt als APNonce
- Verhindert das Wiederabspielen bestimmter Updates
- OPTIONAL: Wird üblicherweise nicht gefunden

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
#### Disarm: Symbole für den Kernel

**`Disarm`** ermöglicht das symbolicate von Funktionen aus dem kernelcache mithilfe von matchers. Diese matchers sind einfach Pattern-Regeln (Textzeilen), die disarm sagen, wie Funktionen, Argumente und panic/log strings innerhalb eines binaries erkannt und automatisch symbolicated werden.

Im Grunde gibst du die Zeichenkette an, die eine Funktion verwendet, und disarm findet sie und **symbolicate it**.
```bash
You can find some `xnu.matchers` in [https://newosxbook.com/tools/disarm.html](https://newosxbook.com/tools/disarm.html) in the **`Matchers`** section. You can also create your own matchers.

```bash
# Gehe zu /tmp/extracted, wo disarm die filesets extrahiert hat
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
# Installiere ipsw-Tool
brew install blacktop/tap/ipsw

# Extrahiere nur den kernelcache aus dem IPSW
ipsw extract --kernel /path/to/YourFirmware.ipsw -o out/

# Sie sollten Folgendes erhalten:
#   out/Firmware/kernelcache.release.iPhoneXX
#   oder eine IMG4 payload: out/Firmware/kernelcache.release.iPhoneXX.im4p

# Falls Sie eine IMG4 payload erhalten:
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
## Extrahiere com.apple.security.sandbox
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# Alles extrahieren
kextex_all kernelcache.release.iphone14.e

# Prüfe die Extension auf Symbole
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
# Erstelle ein Symbolisierungs-Bundle für den neuesten Kernel-Panic
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
# Ladeadresse des Kexts ermitteln
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# Anfügen
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```

> ℹ️  KDP only exposes a **read-only** interface. For dynamic instrumentation you will need to patch the binary on-disk, leverage **kernel function hooking** (e.g. `mach_override`) or migrate the driver to a **hypervisor** for full read/write.

## References

- DriverKit Security – Apple Platform Security Guide
- Microsoft Security Blog – *Analyzing CVE-2024-44243 SIP bypass*

{{#include ../../../banners/hacktricks-training.md}}
