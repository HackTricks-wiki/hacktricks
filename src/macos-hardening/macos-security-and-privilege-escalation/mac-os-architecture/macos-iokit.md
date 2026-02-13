# macOS IOKit

{{#include ../../../banners/hacktricks-training.md}}

## Grundlegende Informationen

Der I/O Kit ist ein Open-Source, objektorientiertes **device-driver framework** im XNU-Kernel und verwaltet **dynamically loaded device drivers**. Es erlaubt, modularen Code zur Laufzeit in den Kernel zu laden und unterstützt unterschiedliche Hardware.

IOKit-Treiber exportieren im Wesentlichen **export functions from the kernel**. Die Parameter-**types** dieser Funktionen sind **predefined** und werden überprüft. Außerdem ist IOKit, ähnlich wie XPC, nur eine weitere Schicht auf **top of Mach messages**.

**IOKit XNU kernel code** wird von Apple als Open Source bereitgestellt unter [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit). Darüber hinaus sind die User-Space IOKit-Komponenten ebenfalls Open Source: [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser).

Allerdings sind **no IOKit drivers** Open Source. Gelegentlich enthält eine Treiber-Version Symbole, die das Debuggen erleichtern. Check how to [**get the driver extensions from the firmware here**](#ipsw)**.**

Es ist in **C++** geschrieben. Du kannst demangled C++-Symbole mit:
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
> [!CAUTION]
> IOKit **exponierte Funktionen** könnten **zusätzliche Sicherheitsprüfungen** durchführen, wenn ein Client versucht, eine Funktion aufzurufen, beachten Sie jedoch, dass Apps normalerweise durch die **sandbox** **eingeschränkt** sind, mit welchen IOKit-Funktionen sie interagieren können.

## Treiber

In macOS befinden sie sich in:

- **`/System/Library/Extensions`**
- KEXT-Dateien, die im Betriebssystem OS X integriert sind.
- **`/Library/Extensions`**
- KEXT-Dateien, die von Drittanbieter-Software installiert wurden

In iOS befinden sie sich in:

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
Bis einschließlich Nummer 9 sind die aufgelisteten Treiber **bei Adresse 0 geladen**. Das bedeutet, dass es sich nicht um echte Treiber handelt, sondern **Teil des Kernels sind und nicht entladen werden können**.

Um bestimmte Extensions zu finden, kannst du Folgendes verwenden:
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
Um Kernel-Erweiterungen zu laden und zu entladen, führe Folgendes aus:
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

Die **IORegistry** ist ein zentraler Bestandteil des IOKit-Frameworks in macOS und iOS und dient als Datenbank zur Darstellung der Hardwarekonfiguration und des Zustands des Systems. Sie ist eine **hierarchische Sammlung von Objekten, die sämtliche Hardware und Treiber repräsentieren**, die im System geladen sind, sowie deren Beziehungen untereinander.

Du kannst die IORegistry mit dem cli **`ioreg`** abrufen, um sie von der Konsole aus zu inspizieren (besonders nützlich für iOS).
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
Sie können **`IORegistryExplorer`** aus den **Xcode Additional Tools** von [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) herunterladen und die **macOS IORegistry** über eine **grafische** Oberfläche untersuchen.

<figure><img src="../../../images/image (1167).png" alt="" width="563"><figcaption></figcaption></figure>

In IORegistryExplorer werden "planes" verwendet, um die Beziehungen zwischen verschiedenen Objekten in der IORegistry zu organisieren und anzuzeigen. Jede Plane repräsentiert einen bestimmten Beziehungstyp oder eine spezifische Ansicht der Hardware- und Treiberkonfiguration des Systems. Hier sind einige der üblichen planes, denen Sie in IORegistryExplorer begegnen könnten:

1. **IOService Plane**: Dies ist die allgemeinste Plane und zeigt die Service-Objekte, die Treiber und nubs (Kommunikationskanäle zwischen Treibern) repräsentieren. Sie zeigt die Provider-Client-Beziehungen zwischen diesen Objekten.
2. **IODeviceTree Plane**: Diese Plane stellt die physischen Verbindungen zwischen Geräten dar, wie sie am System angeschlossen sind. Sie wird häufig verwendet, um die Hierarchie von Geräten darzustellen, die über Busse wie USB oder PCI verbunden sind.
3. **IOPower Plane**: Zeigt Objekte und deren Beziehungen im Hinblick auf das Power-Management. Sie kann anzeigen, welche Objekte den Energiestatus anderer beeinflussen — nützlich zum Debuggen energiebezogener Probleme.
4. **IOUSB Plane**: Konzentriert sich speziell auf USB-Geräte und deren Beziehungen und zeigt die Hierarchie von USB-Hubs und angeschlossenen Geräten.
5. **IOAudio Plane**: Diese Plane dient der Darstellung von Audio-Geräten und deren Beziehungen im System.
6. ...

## Beispiel: Driver-Comm-Code

Der folgende Code verbindet sich mit dem IOKit-Service `YourServiceNameHere` und ruft Selector 0 auf:

- Zuerst ruft er **`IOServiceMatching`** und **`IOServiceGetMatchingServices`** auf, um den Service zu finden.
- Anschließend stellt er die Verbindung her, indem **`IOServiceOpen`** aufgerufen wird.
- Schließlich ruft er eine Funktion mit **`IOConnectCallScalarMethod`** auf und gibt dabei den Selector 0 an (der Selector ist die Nummer, die der aufzurufenden Funktion zugewiesen ist).

<details>
<summary>Beispiel: User-Space-Aufruf an einen Treiber-Selector</summary>
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

Es gibt **andere** Funktionen, die zur Aufruf von IOKit-Funktionen verwendet werden können, neben **`IOConnectCallScalarMethod`** wie **`IOConnectCallMethod`**, **`IOConnectCallStructMethod`**...

## Reverse-Engineering des Treiber-Einstiegspunkts

Du kannst diese beispielsweise aus einem [**firmware image (ipsw)**](#ipsw) erhalten. Lade es dann in deinen bevorzugten Decompiler.

Du kannst damit beginnen, die Funktion **`externalMethod`** zu dekompilieren, da dies die Treiberfunktion ist, die den Aufruf empfängt und die richtige Funktion aufruft:

<figure><img src="../../../images/image (1168).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../images/image (1169).png" alt=""><figcaption></figcaption></figure>

Dieser aufgelöste Aufruf bedeutet:
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
Beachte, dass in der vorherigen Definition der Parameter **`self`** fehlt; die korrekte Definition wäre:
```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
Tatsächlich findest du die eigentliche Definition in [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388):
```cpp
IOUserClient2022::dispatchExternalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque *arguments,
const IOExternalMethodDispatch2022 dispatchArray[], size_t dispatchArrayCount,
OSObject * target, void * reference)
```
Mit diesen Informationen kannst du Ctrl+Right -> `Edit function signature` neu schreiben und die bekannten Typen setzen:

<figure><img src="../../../images/image (1174).png" alt=""><figcaption></figcaption></figure>

Der neue dekompilierte Code sieht dann so aus:

<figure><img src="../../../images/image (1175).png" alt=""><figcaption></figcaption></figure>

Für den nächsten Schritt muss die Struktur **`IOExternalMethodDispatch2022`** definiert sein. Sie ist Open Source unter [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176), du kannst sie so definieren:

<figure><img src="../../../images/image (1170).png" alt=""><figcaption></figcaption></figure>

Wenn du nun dem `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray` folgst, siehst du viele Daten:

<figure><img src="../../../images/image (1176).png" alt="" width="563"><figcaption></figcaption></figure>

Ändere den Datentyp zu **`IOExternalMethodDispatch2022:`**

<figure><img src="../../../images/image (1177).png" alt="" width="375"><figcaption></figcaption></figure>

nach der Änderung:

<figure><img src="../../../images/image (1179).png" alt="" width="563"><figcaption></figcaption></figure>

Und da wir jetzt dort sind, haben wir ein **Array mit 7 Elementen** (siehe den endgültigen dekompilierten Code). Klicke, um ein Array mit 7 Elementen zu erstellen:

<figure><img src="../../../images/image (1180).png" alt="" width="563"><figcaption></figcaption></figure>

Nachdem das Array erstellt wurde, kannst du alle exportierten Funktionen sehen:

<figure><img src="../../../images/image (1181).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Wenn du dich erinnerst: Um eine **exportierte** Funktion aus dem Userspace aufzurufen, brauchen wir nicht den Namen der Funktion, sondern die **Selector-Nummer**. Hier siehst du, dass der Selector **0** die Funktion **`initializeDecoder`** ist, der Selector **1** **`startDecoder`**, der Selector **2** **`initializeEncoder`**...

## Aktuelle IOKit-Angriffsoberfläche (2023–2025)

- **Keystroke capture via IOHIDFamily** – CVE-2024-27799 (14.5) zeigte, dass ein zu permissiver `IOHIDSystem`-Client HID-Ereignisse selbst bei secure input abfangen konnte; stelle sicher, dass `externalMethod`-Handler Entitlements erzwingen und nicht nur den user-client-Typ prüfen.
- **IOGPUFamily memory corruption** – CVE-2024-44197 und CVE-2025-24257 schlossen OOB-Writes, die von sandboxed apps ausgenutzt werden konnten, wenn sie fehlerhafte variabel-lange Daten an GPU user clients übergeben; der übliche Fehler sind unzureichende Bounds bei den Argumenten von `IOConnectCallStructMethod`.
- **Legacy keystroke monitoring** – CVE-2023-42891 (14.2) bestätigte, dass HID user clients weiterhin ein sandbox-escape Vector sind; fuzz jeden Treiber, der keyboard/event queues exponiert.

### Schnelle Triage- & Fuzzing-Tipps

- Führe eine Enumeration aller external methods für einen user client aus dem userland durch, um einen fuzzer zu füttern:
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
- Beim reversing achte auf die `IOExternalMethodDispatch2022`-Counts. Ein häufiges Fehlerpattern in aktuellen CVEs ist eine Inkonsistenz von `structureInputSize`/`structureOutputSize` gegenüber der tatsächlichen `copyin`-Länge, was zu Heap-OOB in `IOConnectCallStructMethod` führt.
- Sandbox-Reachability hängt weiterhin von entitlements ab. Bevor du Zeit in ein Ziel investierst, prüfe, ob der client von einer Drittanbieter-App erlaubt ist:
```bash
strings /System/Library/Extensions/IOHIDFamily.kext/Contents/MacOS/IOHIDFamily | \
grep -E "^com\.apple\.(driver|private)"
```
- Bei GPU/iomfb bugs reicht das Übergeben übergroßer Arrays an `IOConnectCallMethod` oft aus, um bad bounds auszulösen. Minimal harness (selector X), um size confusion auszulösen:
```c
uint8_t buf[0x1000];
size_t outSz = sizeof(buf);
IOConnectCallStructMethod(conn, X, buf, sizeof(buf), buf, &outSz);
```
## Referenzen

- [Apple-Sicherheitsupdates – macOS Sequoia 15.1 / Sonoma 14.7.1 (IOGPUFamily)](https://support.apple.com/en-us/121564)
- [Rapid7 – IOHIDFamily CVE-2024-27799 Zusammenfassung](https://www.rapid7.com/db/vulnerabilities/apple-osx-iohidfamily-cve-2024-27799/)
- [Apple-Sicherheitsupdates – macOS 13.6.1 (CVE-2023-42891 IOHIDFamily)](https://support.apple.com/en-us/121551)
{{#include ../../../banners/hacktricks-training.md}}
