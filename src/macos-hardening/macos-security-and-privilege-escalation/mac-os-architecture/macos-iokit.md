# macOS IOKit

{{#include ../../../banners/hacktricks-training.md}}

## Grundlegende Informationen

Das I/O Kit ist ein Open-Source-, objektorientiertes **Gerätetreiber-Framework** im XNU-Kernel und verwaltet **dynamisch geladene Gerätetreiber**. Es ermöglicht, modularen Code im laufenden Betrieb zum Kernel hinzuzufügen, und unterstützt unterschiedliche Hardware.

IOKit-Treiber **exportieren grundsätzlich Funktionen aus dem Kernel**. Die **Typen** der Funktionsparameter sind **vordefiniert** und werden überprüft. Ähnlich wie XPC ist IOKit außerdem nur eine weitere Schicht **über Mach messages**.

Der **IOKit-XNU-Kernelcode** wird von Apple unter [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit) als Open Source veröffentlicht. Auch die IOKit-Komponenten im User Space sind als Open Source verfügbar: [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser).

Allerdings ist **kein IOKit-Treiber** als Open Source verfügbar. Von Zeit zu Zeit enthält eine Treiberveröffentlichung jedoch Symbole, die das Debuggen erleichtern. Siehe hier, wie du [**die Driver Extensions aus der Firmware erhältst**](#ipsw)**.**

Der Code ist in **C++** geschrieben. Du kannst demanglete C++-Symbole abrufen mit:
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
> [!CAUTION]
> Von IOKit **bereitgestellte Funktionen** können **zusätzliche Sicherheitsprüfungen** durchführen, wenn ein Client versucht, eine Funktion aufzurufen. Beachte jedoch, dass die Apps durch die **Sandbox** normalerweise darauf **beschränkt** sind, mit welchen IOKit-Funktionen sie interagieren können.

## Treiber

In macOS befinden sie sich unter:

- **`/System/Library/Extensions`**
- In das Betriebssystem OS X integrierte KEXT-Dateien.
- **`/Library/Extensions`**
- Von Drittanbieter-Software installierte KEXT-Dateien

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
Bis zur Nummer 9 werden die aufgelisteten Treiber **an Adresse 0 geladen**. Das bedeutet, dass es sich dabei nicht um echte Treiber handelt, sondern um **Bestandteile des Kernels, die nicht entladen werden können**.

Um bestimmte Extensions zu finden, kannst du Folgendes verwenden:
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
Zum Laden und Entladen von Kernel Extensions verwenden Sie:
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

Die **IORegistry** ist ein wichtiger Bestandteil des IOKit-Frameworks in macOS und iOS und dient als Datenbank zur Darstellung der Hardwarekonfiguration und des Zustands des Systems. Sie ist eine **hierarchische Sammlung von Objekten, die die gesamte auf dem System geladene Hardware und alle Treiber** sowie deren Beziehungen zueinander darstellen.

Mit der CLI **`ioreg`** kannst du die IORegistry über die Konsole untersuchen (besonders nützlich für iOS).
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
Du kannst **`IORegistryExplorer`** aus den **Xcode Additional Tools** von [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) herunterladen und die **macOS IORegistry** über eine **grafische** Oberfläche untersuchen.

<figure><img src="../../../images/image (1167).png" alt="" width="563"><figcaption></figcaption></figure>

In IORegistryExplorer werden „planes“ verwendet, um die Beziehungen zwischen verschiedenen Objekten in der IORegistry zu organisieren und darzustellen. Jede plane repräsentiert eine bestimmte Art von Beziehung oder eine bestimmte Ansicht der Hardware- und Treiberkonfiguration des Systems. Hier sind einige der häufig verwendeten planes, die dir in IORegistryExplorer begegnen können:

1. **IOService Plane**: Dies ist die allgemeinste plane. Sie zeigt die Service-Objekte an, die Treiber und Nubs (Kommunikationskanäle zwischen Treibern) repräsentieren. Sie zeigt die Provider-Client-Beziehungen zwischen diesen Objekten.
2. **IODeviceTree Plane**: Diese plane stellt die physischen Verbindungen zwischen Geräten dar, sobald sie mit dem System verbunden sind. Sie wird häufig verwendet, um die Hierarchie von Geräten zu visualisieren, die über Busse wie USB oder PCI verbunden sind.
3. **IOPower Plane**: Zeigt Objekte und ihre Beziehungen im Hinblick auf das Power Management an. Sie kann darstellen, welche Objekte den Power-Status anderer Objekte beeinflussen, und ist nützlich beim Debugging von Problemen im Zusammenhang mit der Stromversorgung.
4. **IOUSB Plane**: Diese plane konzentriert sich speziell auf USB-Geräte und ihre Beziehungen und zeigt die Hierarchie von USB-Hubs und verbundenen Geräten.
5. **IOAudio Plane**: Diese plane dient zur Darstellung von Audiogeräten und ihren Beziehungen innerhalb des Systems.
6. ...

## Driver-Kommunikationscode-Beispiel

Der folgende Code verbindet sich mit dem IOKit-Service `YourServiceNameHere` und ruft Selector 0 auf:

- Zuerst werden **`IOServiceMatching`** und **`IOServiceGetMatchingServices`** aufgerufen, um den Service abzurufen.
- Anschließend wird durch den Aufruf von **`IOServiceOpen`** eine Verbindung hergestellt.
- Schließlich wird mit **`IOConnectCallScalarMethod`** eine Funktion aufgerufen, wobei Selector 0 angegeben wird (der Selector ist die Nummer, die der aufzurufenden Funktion zugewiesen wurde).

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

Es gibt **weitere** Funktionen, mit denen IOKit-Funktionen aufgerufen werden können, neben **`IOConnectCallScalarMethod`**, wie zum Beispiel **`IOConnectCallMethod`**, **`IOConnectCallStructMethod`** ...

## Reversing driver entrypoint

Diese könntest du beispielsweise aus einem [**Firmware-Image (ipsw)**](#ipsw) erhalten. Lade es anschließend in deinen bevorzugten Decompiler.

Du könntest damit beginnen, die Funktion **`externalMethod`** zu dekompilieren, da dies die Treiberfunktion ist, die den Aufruf empfängt und die korrekte Funktion aufruft:

<figure><img src="../../../images/image (1168).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../images/image (1169).png" alt=""><figcaption></figcaption></figure>

Dieser schreckliche demangled Aufruf bedeutet:
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
Beachte, dass in der vorherigen Definition der Parameter **`self`** fehlt; die korrekte Definition wäre:
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

Für den nächsten Schritt müssen wir die Struktur **`IOExternalMethodDispatch2022`** definiert haben. Sie ist Open Source unter [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176) verfügbar. Sie könnten sie folgendermaßen definieren:

<figure><img src="../../../images/image (1170).png" alt=""><figcaption></figcaption></figure>

Wenn Sie nun `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray` folgen, können Sie zahlreiche Daten sehen:

<figure><img src="../../../images/image (1176).png" alt="" width="563"><figcaption></figcaption></figure>

Ändern Sie den Datentyp in **`IOExternalMethodDispatch2022:`**

<figure><img src="../../../images/image (1177).png" alt="" width="375"><figcaption></figcaption></figure>

Nach der Änderung:

<figure><img src="../../../images/image (1179).png" alt="" width="563"><figcaption></figcaption></figure>

Da wir nun wissen, dass es sich dabei um ein **Array mit 7 Elementen** handelt (siehe den abschließenden dekompilierten Code), klicken Sie, um ein Array mit 7 Elementen zu erstellen:

<figure><img src="../../../images/image (1180).png" alt="" width="563"><figcaption></figcaption></figure>

Nachdem das Array erstellt wurde, können Sie alle exportierten Funktionen sehen:

<figure><img src="../../../images/image (1181).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Falls Sie sich erinnern: Um eine **exportierte** Funktion aus dem User Space **aufzurufen**, müssen wir nicht den Namen der Funktion aufrufen, sondern die **Selector-Nummer**. Hier sehen Sie, dass Selector **0** die Funktion **`initializeDecoder`** ist, Selector **1** **`startDecoder`** und Selector **2** **`initializeEncoder`** ...

## Aktuelle IOKit-Angriffsfläche (2023–2025)

- **Erfassung von Tastatureingaben über IOHIDFamily** – CVE-2024-27799 (14.5) zeigte, dass ein permissiver `IOHIDSystem`-Client HID-Events auch bei aktiviertem Secure Input abgreifen konnte. Stellen Sie sicher, dass `externalMethod`-Handler Entitlements durchsetzen und sich nicht nur auf den User-Client-Typ beschränken.<sup>[[2]](#references)</sup>
- **Speicherbeschädigung in IOGPUFamily** – CVE-2024-44197 und CVE-2025-24257 behoben OOB-Schreibvorgänge, die von sandboxed Apps aus erreichbar waren, wenn diese fehlerhafte Daten variabler Länge an GPU-User-Clients übergaben. Der übliche Fehler sind unzureichende Bounds-Prüfungen für `IOConnectCallStructMethod`-Argumente.<sup>[[1]](#references)</sup>
- **Legacy-Überwachung von Tastatureingaben** – CVE-2023-42891 (14.2) bestätigte, dass HID-User-Clients weiterhin einen Sandbox-Escape-Vektor darstellen. Fuzzing sollte für jeden Driver durchgeführt werden, der Tastatur- oder Event-Queues bereitstellt.<sup>[[3]](#references)</sup>

### Schnelle Triage- und Fuzzing-Tipps

- Zählen Sie alle External Methods eines User-Clients aus dem Userland auf, um einen Fuzzer mit Startdaten zu versorgen:
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
- Achte beim Reversing auf die `IOExternalMethodDispatch2022`-Anzahlen. Ein häufiges Bug-Muster in aktuellen CVEs sind inkonsistente `structureInputSize`/`structureOutputSize`-Werte im Vergleich zur tatsächlichen `copyin`-Länge, was zu einem Heap-OOB in `IOConnectCallStructMethod` führt.
- Die Sandbox-Erreichbarkeit hängt weiterhin von Entitlements ab. Bevor du Zeit in ein Target investierst, prüfe, ob der Client aus einer Drittanbieter-App heraus zulässig ist:
```bash
strings /System/Library/Extensions/IOHIDFamily.kext/Contents/MacOS/IOHIDFamily | \
grep -E "^com\.apple\.(driver|private)"
```
- Bei GPU/iomfb bugs reicht es oft aus, über `IOConnectCallMethod` übergroße Arrays zu übergeben, um fehlerhafte Bounds auszulösen. Minimaler Harness (selector X), um eine Größenverwechslung auszulösen:
```c
uint8_t buf[0x1000];
size_t outSz = sizeof(buf);
IOConnectCallStructMethod(conn, X, buf, sizeof(buf), buf, &outSz);
```
## DriverKit — Treiber im User-Space

### Grundlegende Informationen

**DriverKit** ist Apples User-Space-Ersatz für Kernel-Erweiterungen (kexts), der in macOS 10.15 eingeführt wurde. DriverKit-Binärdateien (`.dext` bundles) laufen als User-Space-Prozesse, kommunizieren jedoch direkt über eine privilegierte IOKit-Schnittstelle mit dem Kernel.<sup>[[4]](#references)</sup>

DriverKit-Erweiterungen verwalten Hardware:
- **USB**-Controller und -Geräte
- **Thunderbolt**- / PCIe-Geräte
- **HID** (Tastaturen, Mäuse, Gamecontroller)
- **Audio**-Hardware
- **Networking**-Schnittstellen
- **Serial**- und **Block Storage**-Geräte

Im Gegensatz zu kexts (für die ein Boot mit deaktiviertem SIP oder eine Notarisierung erforderlich war) werden DriverKit-Erweiterungen über `SystemExtensions.framework` installiert und erfordern lediglich eine **einmalige Benutzerfreigabe**.<sup>[[5]](#references)</sup>

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
### Sicherheitsauswirkungen

> [!WARNING]
> DriverKit-Binaries verfügen über einen **direkten Kommunikationskanal zum Kernel**. Das Senden fehlerhaft formatierter Nachrichten über diesen Kanal kann Kernel-Schwachstellen auslösen. Jeder Treiber registriert spezifische User-Client-Klassen, und fehlerhaft formatierte `IOConnectCallMethod`-Aufrufe können eine Beschädigung des Kernel-Speichers verursachen.

**Angriffsfläche:**
1. **Kernel-IOKit-Message-Fuzzing** — Jeder DriverKit-User-Client stellt aus dem User-Space aufrufbare Selektoren bereit. Fehlerhaft formatierte Argumente lösen Kernel-Bugs aus.
2. **USB-Geräte-Spoofing** — Ein kompromittiertes USB-DriverKit-Binary kann ein bösartiges USB-Geräteprofil präsentieren (z. B. eine Tastatur für HID-Injection emulieren).
3. **DMA-Angriffe** — PCIe-/Thunderbolt-DriverKit-Erweiterungen können potenziell per DMA auf den physischen Speicher zugreifen.
4. **Persistenz** — Sobald sie als Systemerweiterung installiert sind, bleiben DriverKit-Binaries über Neustarts und App-Updates hinweg persistent.

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
### DriverKit-CVEs

| CVE | Beschreibung |
|---|---|
| CVE-2022-26766 | Schwachstelle im DriverKit-USB-Stack — kernel code execution |
| CVE-2021-30838 | IOKit-user-client-type confusion in Grafiktreibern |
| CVE-2024-44197 | IOGPUFamily-OOB-write über fehlerhafte DriverKit-Argumente |

## Referenzen

- [1] [Apple Security Updates – macOS Sequoia 15.1 / Sonoma 14.7.1 (IOGPUFamily)](https://support.apple.com/en-us/121564)
- [2] [Rapid7 – IOHIDFamily CVE-2024-27799 summary](https://www.rapid7.com/db/vulnerabilities/apple-osx-iohidfamily-cve-2024-27799/)
- [3] [Apple Security Updates – macOS 13.6.1 (CVE-2023-42891 IOHIDFamily)](https://support.apple.com/en-us/121551)
- [4] [Apple Developer — DriverKit](https://developer.apple.com/documentation/driverkit)
- [5] [Apple Developer — System Extensions](https://developer.apple.com/documentation/systemextensions)

{{#include ../../../banners/hacktricks-training.md}}
