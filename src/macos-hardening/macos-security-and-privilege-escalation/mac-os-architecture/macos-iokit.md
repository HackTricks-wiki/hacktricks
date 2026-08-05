# macOS IOKit

{{#include ../../../banners/hacktricks-training.md}}

## Grundlegende Informationen

Das I/O Kit ist ein Open-Source-, objektorientiertes **Gerätetreiber-Framework** im XNU-Kernel und verarbeitet **dynamisch geladene Gerätetreiber**. Es ermöglicht, modularen Code während der Laufzeit zum Kernel hinzuzufügen, und unterstützt vielfältige Hardware.

IOKit-Treiber **exportieren grundsätzlich Funktionen aus dem Kernel**. Die **Typen** der Funktionsparameter sind **vordefiniert** und werden überprüft. Ähnlich wie XPC ist IOKit außerdem nur eine weitere Schicht **über Mach-Nachrichten**.

Der **IOKit-XNU-Kernel-Code** wird von Apple unter [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit) als Open Source veröffentlicht. Außerdem sind die IOKit-Komponenten im Userspace ebenfalls als Open Source verfügbar: [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser).

Allerdings ist **kein IOKit-Treiber** als Open Source verfügbar. Von Zeit zu Zeit kann eine Treiberveröffentlichung jedoch Symbole enthalten, die das Debugging erleichtern. Sieh dir hier an, wie du [**die Treibererweiterungen aus der Firmware erhältst**](#ipsw)**.**

Der Code ist in **C++** geschrieben. Du kannst demanglete C++-Symbole mit folgendem Befehl erhalten:
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
> [!CAUTION]
> **Exponierte Funktionen** von IOKit können **zusätzliche Sicherheitsprüfungen** durchführen, wenn ein Client versucht, eine Funktion aufzurufen. Beachte jedoch, dass die Apps durch die **Sandbox** normalerweise darauf beschränkt sind, mit welchen IOKit-Funktionen sie interagieren können.

## Treiber

In macOS befinden sie sich unter:

- **`/System/Library/Extensions`**
- KEXT-Dateien, die in das Betriebssystem OS X integriert sind.
- **`/Library/Extensions`**
- KEXT-Dateien, die von Drittanbieter-Software installiert wurden

In iOS befinden sie sich unter:

- **`/System/Library/Extensions`**
```bash
#Use kextstat to print the loaded drivers
kextstat
Executing: /usr/bin/kmutil showloaded
No variant specified, falling back to release
Index Refs Address            Size       Wired      Name (Version) UUID <Linked Against>
1  142 0                  0          0          com.apple.kpi.bsd (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
2   11 0                  0          0          com.apple.kpi.dsep (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
3  170 0                  0          0          com.apple.kpi.iokit (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
4    0 0                  0          0          com.apple.kpi.kasan (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
5  175 0                  0          0          com.apple.kpi.libkern (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
6  154 0                  0          0          com.apple.kpi.mach (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
7   88 0                  0          0          com.apple.kpi.private (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
8  106 0                  0          0          com.apple.kpi.unsupported (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
9    2 0xffffff8003317000 0xe000     0xe000     com.apple.kec.Libm (1) 6C1342CC-1D74-3D0F-BC43-97D5AD38200A <5>
10   12 0xffffff8003544000 0x92000    0x92000    com.apple.kec.corecrypto (11.1) F5F1255F-6552-3CF4-A9DB-D60EFDEB4A9A <8 7 6 5 3 1>
```
Bis zur Nummer 9 werden die aufgeführten Treiber **an der Adresse 0 geladen**. Das bedeutet, dass es sich dabei nicht um echte Treiber handelt, sondern um **Bestandteile des Kernels, die nicht entladen werden können**.

Um bestimmte Erweiterungen zu finden, kannst du Folgendes verwenden:
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
Zum Laden und Entladen von Kernel-Erweiterungen verwenden Sie:
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

Die **IORegistry** ist ein wichtiger Bestandteil des IOKit-Frameworks in macOS und iOS. Sie dient als Datenbank zur Darstellung der Hardwarekonfiguration und des Zustands des Systems. Sie ist eine **hierarchische Sammlung von Objekten, die die gesamte auf dem System geladene Hardware und alle Treiber** sowie deren Beziehungen zueinander darstellen.

Du kannst mit der CLI **`ioreg`** auf die IORegistry zugreifen, um sie über die Konsole zu untersuchen (besonders nützlich für iOS).
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
Du könntest **`IORegistryExplorer`** aus den **Xcode Additional Tools** von [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) herunterladen und die **macOS IORegistry** über eine **grafische** Benutzeroberfläche untersuchen.

<figure><img src="../../../images/image (1167).png" alt="" width="563"><figcaption></figcaption></figure>

In IORegistryExplorer werden „Planes“ verwendet, um die Beziehungen zwischen verschiedenen Objekten in der IORegistry zu organisieren und darzustellen. Jeder Plane repräsentiert eine bestimmte Art von Beziehung oder eine bestimmte Ansicht der Hardware- und Treiberkonfiguration des Systems. Hier sind einige der häufig verwendeten Planes, die dir in IORegistryExplorer begegnen können:

1. **IOService Plane**: Dies ist der allgemeinste Plane. Er zeigt die Service-Objekte an, die Treiber und Nubs (Kommunikationskanäle zwischen Treibern) repräsentieren. Er zeigt die Provider-Client-Beziehungen zwischen diesen Objekten.
2. **IODeviceTree Plane**: Dieser Plane stellt die physischen Verbindungen zwischen Geräten dar, wenn diese an das System angeschlossen sind. Er wird häufig verwendet, um die Hierarchie der über Busse wie USB oder PCI verbundenen Geräte zu visualisieren.
3. **IOPower Plane**: Zeigt Objekte und ihre Beziehungen im Hinblick auf das Power Management an. Er kann zeigen, welche Objekte den Power State anderer Objekte beeinflussen, und ist nützlich beim Debuggen von Problemen im Zusammenhang mit der Stromversorgung.
4. **IOUSB Plane**: Konzentriert sich speziell auf USB-Geräte und ihre Beziehungen und zeigt die Hierarchie von USB-Hubs und verbundenen Geräten.
5. **IOAudio Plane**: Dieser Plane stellt Audiogeräte und ihre Beziehungen innerhalb des Systems dar.
6. ...

## Beispiel für Driver Comm Code

Der folgende Code verbindet sich mit dem IOKit-Service `YourServiceNameHere` und ruft Selector 0 auf:

- Zuerst ruft er **`IOServiceMatching`** und **`IOServiceGetMatchingServices`** auf, um den Service abzurufen.
- Anschließend stellt er durch den Aufruf von **`IOServiceOpen`** eine Verbindung her.
- Schließlich ruft er mit **`IOConnectCallScalarMethod`** eine Funktion auf und gibt dabei den Selector 0 an (der Selector ist die Nummer, die der aufzurufenden Funktion zugewiesen wurde).

<details>
<summary>Beispiel für einen User-Space-Aufruf eines Driver-Selectors</summary>
```objectivec
#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>

int main(int argc, const char * argv[]) {
@autoreleasepool {
// Get a reference to the service using its name
CFMutableDictionaryRef matchingDict = IOServiceMatching("YourServiceNameHere");
if (matchingDict == NULL) {
NSLog(@"Failed to create matching dictionary");
return -1;
}

// Obtain an iterator over all matching services
io_iterator_t iter;
kern_return_t kr = IOServiceGetMatchingServices(kIOMasterPortDefault, matchingDict, &iter);
if (kr != KERN_SUCCESS) {
NSLog(@"Failed to get matching services");
return -1;
}

// Get a reference to the first service (assuming it exists)
io_service_t service = IOIteratorNext(iter);
if (!service) {
NSLog(@"No matching service found");
IOObjectRelease(iter);
return -1;
}

// Open a connection to the service
io_connect_t connect;
kr = IOServiceOpen(service, mach_task_self(), 0, &connect);
if (kr != KERN_SUCCESS) {
NSLog(@"Failed to open service");
IOObjectRelease(service);
IOObjectRelease(iter);
return -1;
}

// Call a method on the service
// Assume the method has a selector of 0, and takes no arguments
kr = IOConnectCallScalarMethod(connect, 0, NULL, 0, NULL, NULL);
if (kr != KERN_SUCCESS) {
NSLog(@"Failed to call method");
}

// Cleanup
IOServiceClose(connect);
IOObjectRelease(service);
IOObjectRelease(iter);
}
return 0;
}
```
</details>

Es gibt **weitere** Funktionen, mit denen IOKit-Funktionen aufgerufen werden können, abgesehen von **`IOConnectCallScalarMethod`**, wie etwa **`IOConnectCallMethod`**, **`IOConnectCallStructMethod`** ...

## Reversing des Treiber-Entry-Points

Diese kannst du beispielsweise aus einem [**Firmware-Image (ipsw)**](#ipsw) erhalten. Lade es anschließend in deinen bevorzugten Decompiler.

Du kannst mit dem Decompilieren der Funktion **`externalMethod`** beginnen, da dies die Treiberfunktion ist, die den Aufruf empfängt und die richtige Funktion aufruft:

<figure><img src="../../../images/image (1168).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../images/image (1169).png" alt=""><figcaption></figcaption></figure>

Dieser schreckliche demanglete Aufruf bedeutet:
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
Beachte, dass in der vorherigen Definition der Parameter **`self`** fehlt. Die korrekte Definition wäre:
```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
Die tatsächliche Definition findest du in [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388):
```cpp
IOUserClient2022::dispatchExternalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque *arguments,
const IOExternalMethodDispatch2022 dispatchArray[], size_t dispatchArrayCount,
OSObject * target, void * reference)
```
Mit diesen Informationen können Sie Ctrl+Right -> `Edit function signature` neu schreiben und die bekannten Typen festlegen:

<figure><img src="../../../images/image (1174).png" alt=""><figcaption></figcaption></figure>

Der neue dekompilierte Code sieht folgendermaßen aus:

<figure><img src="../../../images/image (1175).png" alt=""><figcaption></figcaption></figure>

Für den nächsten Schritt müssen wir die Struktur **`IOExternalMethodDispatch2022`** definiert haben. Sie ist als Open Source verfügbar unter [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176). Sie könnten sie folgendermaßen definieren:

<figure><img src="../../../images/image (1170).png" alt=""><figcaption></figcaption></figure>

Wenn Sie nun `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray` folgen, können Sie zahlreiche Daten sehen:

<figure><img src="../../../images/image (1176).png" alt="" width="563"><figcaption></figcaption></figure>

Ändern Sie den Datentyp zu **`IOExternalMethodDispatch2022:`**

<figure><img src="../../../images/image (1177).png" alt="" width="375"><figcaption></figcaption></figure>

Nach der Änderung:

<figure><img src="../../../images/image (1179).png" alt="" width="563"><figcaption></figcaption></figure>

Da wir nun wissen, dass sich darin ein **Array mit 7 Elementen** befindet (siehe den abschließenden dekompilierten Code), klicken Sie, um ein Array mit 7 Elementen zu erstellen:

<figure><img src="../../../images/image (1180).png" alt="" width="563"><figcaption></figcaption></figure>

Nach der Erstellung des Arrays können Sie alle exportierten Funktionen sehen:

<figure><img src="../../../images/image (1181).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Falls Sie sich erinnern: Um eine **exportierte** Funktion aus dem User Space **aufzurufen**, müssen wir nicht den Namen der Funktion aufrufen, sondern die **Selector-Nummer**. Hier sehen Sie, dass der Selector **0** die Funktion **`initializeDecoder`** ist, der Selector **1** **`startDecoder`** und der Selector **2** **`initializeEncoder`** ...

## Aktuelle IOKit-Angriffsfläche (2023–2025)

- **Keystroke capture über IOHIDFamily** – CVE-2024-27799 (14.5) zeigte, dass ein permissiver `IOHIDSystem`-Client HID-Events auch bei aktiviertem Secure Input abgreifen konnte. Stellen Sie sicher, dass `externalMethod`-Handler Berechtigungen über Entitlements erzwingen und sich nicht nur auf den User-Client-Typ verlassen.<sup>[[2]](#references)</sup>
- **Speicherbeschädigung in IOGPUFamily** – CVE-2024-44197 und CVE-2025-24257 behoben OOB-Schreibvorgänge, die von sandboxed Apps aus erreichbar waren, wenn diese fehlerhafte Daten variabler Länge an GPU User Clients übergaben. Der übliche Fehler sind unzureichende Bounds-Prüfungen für `IOConnectCallStructMethod`-Argumente.<sup>[[1]](#references)</sup>
- **Legacy-Keystroke-Monitoring** – CVE-2023-42891 (14.2) bestätigte, dass HID User Clients weiterhin einen Vektor für Sandbox-Escapes darstellen. Fuzzing sollte für jeden Treiber durchgeführt werden, der Keyboard-/Event-Queues bereitstellt.<sup>[[3]](#references)</sup>

### Schnelle Triage- und Fuzzing-Tipps

- Enumerieren Sie alle externen Methoden eines User Clients aus dem Userland, um einen Fuzzer mit Ausgangsdaten zu versorgen:
```bash
# list selectors for a service
python3 - <<'PY'
from ioreg import IORegistry
svc = 'IOHIDSystem'
reg = IORegistry()
obj = reg.get_service(svc)
for sel, name in obj.external_methods():
print(f"{sel:02d} {name}")
PY
```
- Achte beim Reversing auf die `IOExternalMethodDispatch2022`-Anzahlen. Ein häufiges Bug-Muster in aktuellen CVEs sind inkonsistente Werte für `structureInputSize`/`structureOutputSize` im Vergleich zur tatsächlichen `copyin`-Länge, was zu einem Heap-OOB in `IOConnectCallStructMethod` führt.
- Die Erreichbarkeit aus der Sandbox hängt weiterhin von Entitlements ab. Prüfe vor dem Zeitaufwand für ein Target, ob der Client aus einer Drittanbieter-App heraus zugelassen ist:
```bash
strings /System/Library/Extensions/IOHIDFamily.kext/Contents/MacOS/IOHIDFamily | \
grep -E "^com\.apple\.(driver|private)"
```
- Bei GPU/iomfb-Bugs reicht es oft aus, übergroße Arrays durch `IOConnectCallMethod` zu übergeben, um fehlerhafte Bounds auszulösen. Minimales Harness (Selector X) zum Auslösen der Größenverwechslung:
```c
uint8_t buf[0x1000];
size_t outSz = sizeof(buf);
IOConnectCallStructMethod(conn, X, buf, sizeof(buf), buf, &outSz);
```
## DriverKit — User-Space-Treiber

### Grundlegende Informationen

**DriverKit** ist Apples User-Space-Ersatz für Kernel Extensions (kexts), der in macOS 10.15 eingeführt wurde. DriverKit-Binaries (`.dext`-Bundles) laufen als User-Space-Prozesse, kommunizieren jedoch über ein privilegiertes IOKit-Interface direkt mit dem Kernel.

DriverKit Extensions verwalten Hardware:
- **USB**-Controller und -Geräte
- **Thunderbolt**- / PCIe-Geräte
- **HID** (Tastaturen, Mäuse, Gamecontroller)
- **Audio**-Hardware
- **Netzwerk**-Interfaces
- **Serielle** und **Block-Storage**-Geräte

Im Gegensatz zu kexts (die einen mit deaktiviertem SIP gestarteten Bootvorgang oder eine Notarisierung erforderten) werden DriverKit Extensions über `SystemExtensions.framework` installiert und benötigen lediglich eine **einmalige Benutzerfreigabe**.

### Erkennung und Enumeration
```bash
# List all installed system extensions (includes DriverKit)
systemextensionsctl list

# Find all DriverKit extension bundles
find / -name "*.dext" -type d 2>/dev/null

# Check a binary's DriverKit entitlements
codesign -d --entitlements - /path/to/binary.dext/binary 2>&1 | grep driverkit

# Common DriverKit entitlements:
# com.apple.developer.driverkit                    — Base DriverKit
# com.apple.developer.driverkit.transport.usb      — USB device access
# com.apple.developer.driverkit.transport.hid      — HID device access
# com.apple.developer.driverkit.transport.pci      — PCIe device access
# com.apple.developer.driverkit.transport.serial   — Serial port access
# com.apple.developer.driverkit.family.networking  — Network interface
# com.apple.developer.driverkit.family.audio       — Audio device
```
### Sicherheitsimplikationen

> [!WARNING]
> DriverKit-Binaries verfügen über einen **direkten Kommunikationskanal zum Kernel**. Das Senden fehlerhaft formatierter Nachrichten über diesen Kanal kann Kernel-Schwachstellen auslösen. Jeder Treiber registriert spezifische user-client-Klassen, und fehlerhaft formatierte `IOConnectCallMethod`-Aufrufe können eine Beschädigung des Kernel-Speichers verursachen.

**Angriffsfläche:**
1. **Kernel-IOKit-Message-Fuzzing** — Jeder DriverKit-user-client stellt aus dem Userspace aufrufbare Selektoren bereit. Fehlerhaft formatierte Argumente können Kernel-Bugs auslösen.
2. **USB-Geräte-Spoofing** — Ein kompromittiertes USB-DriverKit-Binary kann ein bösartiges USB-Geräteprofil präsentieren, z. B. eine Tastatur zur HID-Injection emulieren.
3. **DMA-Angriffe** — PCIe-/Thunderbolt-DriverKit-Erweiterungen haben potenziell DMA-Zugriff auf den physischen Speicher.
4. **Persistenz** — Nach der Installation als Systemerweiterung bleiben DriverKit-Binaries über Neustarts und App-Updates hinweg persistent.

### DriverKit-IOKit-User-Client-Fuzzing
```bash
# Enumerate DriverKit user-client classes from entitlements
codesign -d --entitlements - /path/to/binary.dext/binary 2>&1 \
| grep -A5 "com.apple.developer.driverkit.transport"

# List IOService matching for DriverKit drivers
ioreg -l | grep -i "UserClientClass" | sort -u

# Check if the driver's user-client is reachable from a sandboxed app
ioreg -c IOService -r -d 1 | grep -E '"IOClass"|"CFBundleIdentifier"' | head -40

# Minimal fuzzing harness for a DriverKit selector:
```

```c
#include <IOKit/IOKitLib.h>

io_connect_t conn;
// ... open connection to the DriverKit service ...

// Fuzz selector X with oversized struct input
uint8_t buf[0x2000];
memset(buf, 'A', sizeof(buf));
size_t outSz = sizeof(buf);
kern_return_t kr = IOConnectCallStructMethod(conn, X, buf, sizeof(buf), buf, &outSz);
// If the driver doesn't validate structureInputSize, this causes kernel OOB
```
### DriverKit CVEs

| CVE | Beschreibung |
|---|---|
| CVE-2022-26766 | Schwachstelle im DriverKit-USB-Stack – Ausführung von Code im Kernel |
| CVE-2021-30838 | Typverwechslung bei IOKit user-client in Grafiktreibern |
| CVE-2024-44197 | OOB-Schreibzugriff in IOGPUFamily über manipulierte DriverKit-Argumente |

## Referenzen

- [1] [Apple-Sicherheitsupdates – macOS Sequoia 15.1 / Sonoma 14.7.1 (IOGPUFamily)](https://support.apple.com/en-us/121564)
- [2] [Rapid7 – Zusammenfassung zu IOHIDFamily CVE-2024-27799](https://www.rapid7.com/db/vulnerabilities/apple-osx-iohidfamily-cve-2024-27799/)
- [3] [Apple-Sicherheitsupdates – macOS 13.6.1 (CVE-2023-42891 IOHIDFamily)](https://support.apple.com/en-us/121551)
- [4] [Apple Developer – DriverKit](https://developer.apple.com/documentation/driverkit)
- [5] [Apple Developer – System Extensions](https://developer.apple.com/documentation/systemextensions)

{{#include ../../../banners/hacktricks-training.md}}
