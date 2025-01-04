# macOS IOKit

{{#include ../../../banners/hacktricks-training.md}}

## Grundlegende Informationen

Das I/O Kit ist ein Open-Source, objektorientiertes **Gerätetreiber-Framework** im XNU-Kernel, das **dynamisch geladene Gerätetreiber** verwaltet. Es ermöglicht das Hinzufügen von modularer Software zum Kernel zur Laufzeit und unterstützt verschiedene Hardware.

IOKit-Treiber **exportieren Funktionen aus dem Kernel**. Diese Funktionsparameter **typen** sind **vordefiniert** und werden überprüft. Darüber hinaus ist IOKit, ähnlich wie XPC, nur eine weitere Schicht **oberhalb von Mach-Nachrichten**.

**IOKit XNU-Kernelcode** ist von Apple unter [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit) als Open Source veröffentlicht. Darüber hinaus sind auch die IOKit-Komponenten im Benutzerspeicher Open Source [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser).

Allerdings sind **keine IOKit-Treiber** Open Source. Dennoch kann von Zeit zu Zeit eine Veröffentlichung eines Treibers mit Symbolen erfolgen, die das Debuggen erleichtern. Überprüfen Sie, wie Sie [**die Treibererweiterungen aus der Firmware hier erhalten**](#ipsw)**.**

Es ist in **C++** geschrieben. Sie können demanglierte C++-Symbole mit folgendem Befehl erhalten:
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
> [!CAUTION]
> IOKit **exposed functions** könnten **zusätzliche Sicherheitsprüfungen** durchführen, wenn ein Client versucht, eine Funktion aufzurufen, aber beachten Sie, dass die Apps normalerweise durch den **Sandbox** eingeschränkt sind, mit welchen IOKit-Funktionen sie interagieren können.

## Treiber

In macOS befinden sie sich in:

- **`/System/Library/Extensions`**
- KEXT-Dateien, die in das OS X-Betriebssystem integriert sind.
- **`/Library/Extensions`**
- KEXT-Dateien, die von Drittanbieter-Software installiert wurden.

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
Bis zur Nummer 9 werden die aufgeführten Treiber **an der Adresse 0 geladen**. Das bedeutet, dass es sich nicht um echte Treiber handelt, sondern **um Teile des Kernels, die nicht entladen werden können**.

Um spezifische Erweiterungen zu finden, können Sie Folgendes verwenden:
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
Um Kernel-Erweiterungen zu laden und zu entladen, tun Sie Folgendes:
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

Der **IORegistry** ist ein entscheidender Teil des IOKit-Frameworks in macOS und iOS, der als Datenbank zur Darstellung der Hardwarekonfiguration und des Zustands des Systems dient. Es ist eine **hierarchische Sammlung von Objekten, die alle Hardware und Treiber** darstellen, die auf dem System geladen sind, sowie deren Beziehungen zueinander.

Sie können den IORegistry mit dem CLI **`ioreg`** abrufen, um ihn von der Konsole aus zu inspizieren (besonders nützlich für iOS).
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
Sie können **`IORegistryExplorer`** von **Xcode Additional Tools** von [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) herunterladen und das **macOS IORegistry** über eine **grafische** Benutzeroberfläche inspizieren.

<figure><img src="../../../images/image (1167).png" alt="" width="563"><figcaption></figcaption></figure>

In IORegistryExplorer werden "Planes" verwendet, um die Beziehungen zwischen verschiedenen Objekten im IORegistry zu organisieren und darzustellen. Jedes Plane repräsentiert eine spezifische Art von Beziehung oder eine bestimmte Ansicht der Hardware- und Treiberkonfiguration des Systems. Hier sind einige der gängigen Planes, die Sie in IORegistryExplorer antreffen könnten:

1. **IOService Plane**: Dies ist das allgemeinste Plane, das die Dienstobjekte anzeigt, die Treiber und Nubs (Kommunikationskanäle zwischen Treibern) repräsentieren. Es zeigt die Anbieter-Kunden-Beziehungen zwischen diesen Objekten.
2. **IODeviceTree Plane**: Dieses Plane repräsentiert die physischen Verbindungen zwischen Geräten, wie sie an das System angeschlossen sind. Es wird oft verwendet, um die Hierarchie der über Busse wie USB oder PCI verbundenen Geräte zu visualisieren.
3. **IOPower Plane**: Zeigt Objekte und deren Beziehungen im Hinblick auf das Energiemanagement an. Es kann zeigen, welche Objekte den Energiezustand anderer beeinflussen, was nützlich ist, um energiebezogene Probleme zu debuggen.
4. **IOUSB Plane**: Fokussiert sich speziell auf USB-Geräte und deren Beziehungen und zeigt die Hierarchie von USB-Hubs und angeschlossenen Geräten.
5. **IOAudio Plane**: Dieses Plane dient der Darstellung von Audiogeräten und deren Beziehungen innerhalb des Systems.
6. ...

## Driver Comm Code Beispiel

Der folgende Code verbindet sich mit dem IOKit-Dienst `"YourServiceNameHere"` und ruft die Funktion im Selektor 0 auf. Dafür:

- wird zuerst **`IOServiceMatching`** und **`IOServiceGetMatchingServices`** aufgerufen, um den Dienst zu erhalten.
- Dann wird eine Verbindung hergestellt, indem **`IOServiceOpen`** aufgerufen wird.
- Und schließlich wird eine Funktion mit **`IOConnectCallScalarMethod`** aufgerufen, wobei der Selektor 0 angegeben wird (der Selektor ist die Nummer, die der Funktion, die Sie aufrufen möchten, zugewiesen wurde).
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
Es gibt **andere** Funktionen, die verwendet werden können, um IOKit-Funktionen aufzurufen, abgesehen von **`IOConnectCallScalarMethod`**, wie **`IOConnectCallMethod`**, **`IOConnectCallStructMethod`**...

## Rückwärtsanalyse des Treiber-Einstiegspunkts

Sie könnten diese beispielsweise aus einem [**Firmware-Image (ipsw)**](#ipsw) erhalten. Laden Sie es dann in Ihren bevorzugten Decompiler.

Sie könnten mit der Dekompilierung der **`externalMethod`**-Funktion beginnen, da dies die Treiberfunktion ist, die den Aufruf empfängt und die richtige Funktion aufruft:

<figure><img src="../../../images/image (1168).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../images/image (1169).png" alt=""><figcaption></figcaption></figure>

Dieser schreckliche Aufruf demangled bedeutet:
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
Beachten Sie, dass im vorherigen Definition der **`self`** Parameter fehlt, die gute Definition wäre:
```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
Tatsächlich finden Sie die echte Definition in [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388):
```cpp
IOUserClient2022::dispatchExternalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque *arguments,
const IOExternalMethodDispatch2022 dispatchArray[], size_t dispatchArrayCount,
OSObject * target, void * reference)
```
Mit diesen Informationen können Sie Ctrl+Rechts -> `Edit function signature` verwenden und die bekannten Typen festlegen:

<figure><img src="../../../images/image (1174).png" alt=""><figcaption></figcaption></figure>

Der neue dekompilierte Code sieht folgendermaßen aus:

<figure><img src="../../../images/image (1175).png" alt=""><figcaption></figcaption></figure>

Für den nächsten Schritt müssen wir die **`IOExternalMethodDispatch2022`** Struktur definiert haben. Sie ist Open Source in [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176), Sie könnten sie definieren:

<figure><img src="../../../images/image (1170).png" alt=""><figcaption></figcaption></figure>

Jetzt, folgend der `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray`, können Sie eine Menge Daten sehen:

<figure><img src="../../../images/image (1176).png" alt="" width="563"><figcaption></figcaption></figure>

Ändern Sie den Datentyp in **`IOExternalMethodDispatch2022:`**

<figure><img src="../../../images/image (1177).png" alt="" width="375"><figcaption></figcaption></figure>

nach der Änderung:

<figure><img src="../../../images/image (1179).png" alt="" width="563"><figcaption></figcaption></figure>

Und wie wir jetzt wissen, haben wir ein **Array von 7 Elementen** (überprüfen Sie den endgültigen dekompilierten Code), klicken Sie, um ein Array von 7 Elementen zu erstellen:

<figure><img src="../../../images/image (1180).png" alt="" width="563"><figcaption></figcaption></figure>

Nachdem das Array erstellt wurde, können Sie alle exportierten Funktionen sehen:

<figure><img src="../../../images/image (1181).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Wenn Sie sich erinnern, um eine **exportierte** Funktion aus dem Benutzerspeicher aufzurufen, müssen wir nicht den Namen der Funktion aufrufen, sondern die **Selektornummer**. Hier sehen Sie, dass der Selektor **0** die Funktion **`initializeDecoder`** ist, der Selektor **1** ist **`startDecoder`**, der Selektor **2** **`initializeEncoder`**...

{{#include ../../../banners/hacktricks-training.md}}
