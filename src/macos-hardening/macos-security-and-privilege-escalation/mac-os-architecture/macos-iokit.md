# macOS IOKit

{{#include ../../../banners/hacktricks-training.md}}

## Podstawowe informacje

I/O Kit to open-source’owy, obiektowo zorientowany **framework sterowników urządzeń** w jądrze XNU, obsługujący **dynamicznie ładowane sterowniki urządzeń**. Umożliwia modularnemu kodowi dodawanie elementów do jądra w locie, zapewniając obsługę różnorodnego sprzętu.

Sterowniki IOKit zasadniczo **eksportują funkcje z jądra**. **Typy** parametrów tych funkcji są **predefiniowane** i weryfikowane. Ponadto, podobnie jak XPC, IOKit jest kolejną warstwą **nad komunikatami Mach**.

**Kod jądra XNU IOKit** jest udostępniany jako open-source przez Apple pod adresem [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit). Ponadto komponenty IOKit działające w przestrzeni użytkownika również są dostępne jako open-source: [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser).

Jednak **żadne sterowniki IOKit** nie są dostępne jako open-source. Mimo to od czasu do czasu wydanie sterownika może zawierać symbole, które ułatwiają jego debugowanie. Sprawdź, jak [**pobrać rozszerzenia sterowników z firmware tutaj**](#ipsw)**.**

Jest napisany w **C++**. Zdemanglowane symbole C++ można uzyskać za pomocą:
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
> [!CAUTION]
> **Udostępnione funkcje** IOKit mogą wykonywać **dodatkowe kontrole bezpieczeństwa**, gdy klient próbuje wywołać funkcję, ale należy pamiętać, że aplikacje są zazwyczaj **ograniczone** przez **sandbox** pod względem funkcji IOKit, z którymi mogą współpracować.

## Sterowniki

W macOS znajdują się w:

- **`/System/Library/Extensions`**
- Pliki KEXT wbudowane w system operacyjny OS X.
- **`/Library/Extensions`**
- Pliki KEXT instalowane przez oprogramowanie firm trzecich

W iOS znajdują się w:

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
Do numeru 9 wymienione sterowniki są **załadowane pod adresem 0**. Oznacza to, że nie są to prawdziwe sterowniki, lecz **część kernela i nie można ich wyładować**.

Aby znaleźć konkretne rozszerzenia, możesz użyć:
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
Aby załadować i wyładować kernel extensions, wykonaj:
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

**IORegistry** jest kluczową częścią frameworka IOKit w systemach macOS i iOS, która służy jako baza danych przedstawiająca konfigurację i stan sprzętu systemu. Jest to **hierarchiczny zbiór obiektów reprezentujących cały sprzęt i sterowniki** załadowane w systemie oraz relacje między nimi.

Możesz uzyskać dostęp do IORegistry za pomocą CLI **`ioreg`**, aby przeglądać je z konsoli (szczególnie przydatne w systemie iOS).
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
Możesz pobrać **`IORegistryExplorer`** z **Xcode Additional Tools** ze strony [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) i przeglądać **macOS IORegistry** za pomocą **graficznego** interfejsu.

<figure><img src="../../../images/image (1167).png" alt="" width="563"><figcaption></figcaption></figure>

W IORegistryExplorer „planes” służą do organizowania i wyświetlania relacji między różnymi obiektami w IORegistry. Każdy plane przedstawia określony typ relacji lub konkretny widok konfiguracji sprzętu i driverów systemu. Oto niektóre z typowych planes, które możesz napotkać w IORegistryExplorer:

1. **IOService Plane**: Jest to najbardziej ogólny plane, wyświetlający obiekty usług reprezentujące drivery i nubs (kanały komunikacyjne między driverami). Pokazuje relacje provider-client między tymi obiektami.
2. **IODeviceTree Plane**: Ten plane przedstawia fizyczne połączenia między urządzeniami podłączonymi do systemu. Jest często używany do wizualizacji hierarchii urządzeń podłączonych za pośrednictwem magistral takich jak USB lub PCI.
3. **IOPower Plane**: Wyświetla obiekty i ich relacje w kontekście zarządzania energią. Może pokazywać, które obiekty wpływają na stan zasilania innych, co jest przydatne podczas debugowania problemów związanych z zasilaniem.
4. **IOUSB Plane**: Skupia się konkretnie na urządzeniach USB i ich relacjach, pokazując hierarchię hubów USB i podłączonych urządzeń.
5. **IOAudio Plane**: Ten plane służy do przedstawiania urządzeń audio i ich relacji w systemie.
6. ...

## Przykład kodu komunikacji z driverem

Poniższy kod łączy się z usługą IOKit `YourServiceNameHere` i wywołuje selector 0:

- Najpierw wywołuje **`IOServiceMatching`** i **`IOServiceGetMatchingServices`**, aby uzyskać usługę.
- Następnie ustanawia połączenie, wywołując **`IOServiceOpen`**.
- Na końcu wywołuje funkcję za pomocą **`IOConnectCallScalarMethod`**, wskazując selector 0 (selector to numer przypisany wywoływanej funkcji).

<details>
<summary>Przykład wywołania selectora drivera z przestrzeni użytkownika</summary>
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

Istnieją **inne** funkcje, których można używać do wywoływania funkcji IOKit, poza **`IOConnectCallScalarMethod`**, takie jak **`IOConnectCallMethod`**, **`IOConnectCallStructMethod`**...

## Odwracanie funkcji wejściowej drivera

Możesz uzyskać je na przykład z [**obrazu firmware (ipsw)**](#ipsw). Następnie załaduj go do wybranego dekompilatora.

Możesz rozpocząć dekompilację funkcji **`externalMethod`**, ponieważ jest to funkcja drivera, która odbiera wywołanie i wywołuje właściwą funkcję:

<figure><img src="../../../images/image (1168).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../images/image (1169).png" alt=""><figcaption></figcaption></figure>

To okropne wywołanie po demanglowaniu oznacza:
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
Zauważ, że w poprzedniej definicji pominięto parametr **`self`**; poprawna definicja wyglądałaby tak:
```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
Właściwą definicję można znaleźć w [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388):
```cpp
IOUserClient2022::dispatchExternalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque *arguments,
const IOExternalMethodDispatch2022 dispatchArray[], size_t dispatchArrayCount,
OSObject * target, void * reference)
```
Mając te informacje, możesz wybrać Ctrl+Right -> `Edit function signature` i ustawić znane typy:

<figure><img src="../../../images/image (1174).png" alt=""><figcaption></figcaption></figure>

Nowy zdekompilowany kod będzie wyglądał tak:

<figure><img src="../../../images/image (1175).png" alt=""><figcaption></figcaption></figure>

W następnym kroku musimy mieć zdefiniowaną strukturę **`IOExternalMethodDispatch2022`**. Jest ona opensource w [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176), możesz ją zdefiniować:

<figure><img src="../../../images/image (1170).png" alt=""><figcaption></figcaption></figure>

Teraz, podążając za `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray`, możesz zobaczyć dużo danych:

<figure><img src="../../../images/image (1176).png" alt="" width="563"><figcaption></figcaption></figure>

Zmień typ danych na **`IOExternalMethodDispatch2022:`**

<figure><img src="../../../images/image (1177).png" alt="" width="375"><figcaption></figcaption></figure>

po zmianie:

<figure><img src="../../../images/image (1179).png" alt="" width="563"><figcaption></figcaption></figure>

Ponieważ wiemy już, że znajduje się tam **array zawierająca 7 elementów** (sprawdź końcowy zdekompilowany kod), kliknij, aby utworzyć array zawierającą 7 elementów:

<figure><img src="../../../images/image (1180).png" alt="" width="563"><figcaption></figcaption></figure>

Po utworzeniu array możesz zobaczyć wszystkie eksportowane funkcje:

<figure><img src="../../../images/image (1181).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Jeśli pamiętasz, aby **wywołać** **eksportowaną** funkcję z user space, nie musimy wywoływać nazwy funkcji, lecz **numeru selectora**. Tutaj możesz zobaczyć, że selector **0** to funkcja **`initializeDecoder`**, selector **1** to **`startDecoder`**, a selector **2** to **`initializeEncoder`**...

## Najnowsza powierzchnia ataku IOKit (2023–2025)

- **Przechwytywanie keystrokes przez IOHIDFamily** – CVE-2024-27799 (14.5) pokazało, że permisywny klient `IOHIDSystem` mógł przechwytywać zdarzenia HID nawet przy włączonym secure input; upewnij się, że handlery `externalMethod` wymuszają entitlements, zamiast opierać się wyłącznie na typie user-client.<sup>[[2]](#references)</sup>
- **Korupcja pamięci w IOGPUFamily** – CVE-2024-44197 i CVE-2025-24257 naprawiły zapisy poza zakresem osiągalne z sandboxed apps, które przekazywały nieprawidłowe dane o zmiennej długości do GPU user clients; typowym bugiem są niewystarczające kontrole bounds wokół argumentów `IOConnectCallStructMethod`.<sup>[[1]](#references)</sup>
- **Legacy monitoring keystrokes** – CVE-2023-42891 (14.2) potwierdziło, że HID user clients nadal stanowią vector sandbox escape; wykonuj fuzzing każdego drivera udostępniającego kolejki klawiatury/zdarzeń.<sup>[[3]](#references)</sup>

### Szybki triage i wskazówki dotyczące fuzzingu

- Wylicz wszystkie external methods dla user client z userland, aby zasilić nimi fuzzer:
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
- Podczas reverse engineeringu zwróć uwagę na liczby `IOExternalMethodDispatch2022`. Częsty wzorzec błędów w nowszych CVE to niespójność między `structureInputSize`/`structureOutputSize` a rzeczywistą długością `copyin`, prowadząca do heap OOB w `IOConnectCallStructMethod`.
- Dostępność Sandbox nadal zależy od entitlements. Zanim poświęcisz czas na cel, sprawdź, czy klient może korzystać z niego z poziomu aplikacji zewnętrznej:
```bash
strings /System/Library/Extensions/IOHIDFamily.kext/Contents/MacOS/IOHIDFamily | \
grep -E "^com\.apple\.(driver|private)"
```
- W przypadku błędów GPU/iomfb przekazanie tablic o zbyt dużym rozmiarze przez `IOConnectCallMethod` często wystarcza do wywołania błędnych granic. Minimalny harness (selector X) wywołujący niezgodność rozmiaru:
```c
uint8_t buf[0x1000];
size_t outSz = sizeof(buf);
IOConnectCallStructMethod(conn, X, buf, sizeof(buf), buf, &outSz);
```
## DriverKit — Sterowniki w przestrzeni użytkownika

### Podstawowe informacje

**DriverKit** to wprowadzone w macOS 10.15 rozwiązanie firmy Apple zastępujące rozszerzenia jądra (kexts) w przestrzeni użytkownika. Binarne pliki DriverKit (bundles `.dext`) działają jako procesy w przestrzeni użytkownika, ale komunikują się bezpośrednio z jądrem za pośrednictwem uprzywilejowanego interfejsu IOKit.

Rozszerzenia DriverKit obsługują sprzęt:
- kontrolery i urządzenia **USB**
- urządzenia **Thunderbolt** / PCIe
- urządzenia **HID** (klawiatury, myszy, kontrolery gier)
- sprzęt **Audio**
- interfejsy **Networking**
- urządzenia **Serial** i **Block Storage**

W przeciwieństwie do kexts (które wymagały uruchomienia systemu z wyłączonym SIP lub notarization), rozszerzenia DriverKit są instalowane za pośrednictwem `SystemExtensions.framework` i wymagają jedynie **jednorazowej zgody użytkownika**.

### Wykrywanie i enumeracja
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
### Implikacje bezpieczeństwa

> [!WARNING]
> Binaries DriverKit mają **bezpośredni kanał komunikacji z kernelem**. Wysyłanie zniekształconych wiadomości przez ten kanał może wywołać vulnerabilities w kernelu. Każdy driver rejestruje określone klasy user-client, a zniekształcone wywołania `IOConnectCallMethod` mogą powodować uszkodzenie pamięci kernela.

**Powierzchnia ataku:**
1. **Fuzzing komunikatów kernela IOKit** — Każdy user-client DriverKit udostępnia selektory, które można wywoływać z user space. Zniekształcone argumenty mogą wywoływać błędy kernela.
2. **Spoofing urządzeń USB** — Zaatakowany binary DriverKit może przedstawiać profil złośliwego urządzenia USB (np. emulować klawiaturę w celu wykonania HID injection).
3. **Ataki DMA** — Rozszerzenia DriverKit dla PCIe/Thunderbolt mogą potencjalnie uzyskać dostęp DMA do pamięci fizycznej.
4. **Persistence** — Po zainstalowaniu jako system extension, binaries DriverKit pozostają aktywne po ponownym uruchomieniu systemu i aktualizacjach aplikacji.

### Fuzzing user-client IOKit DriverKit
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

| CVE | Opis |
|---|---|
| CVE-2022-26766 | Podatność stosu USB DriverKit — wykonanie kodu w kernelu |
| CVE-2021-30838 | Pomylenie typu user-client IOKit w sterownikach graficznych |
| CVE-2024-44197 | Zapis poza zakresem (OOB) w IOGPUFamily za pośrednictwem nieprawidłowych argumentów DriverKit |

## Referencje

- [1] [Apple Security Updates – macOS Sequoia 15.1 / Sonoma 14.7.1 (IOGPUFamily)](https://support.apple.com/en-us/121564)
- [2] [Rapid7 – IOHIDFamily CVE-2024-27799 summary](https://www.rapid7.com/db/vulnerabilities/apple-osx-iohidfamily-cve-2024-27799/)
- [3] [Apple Security Updates – macOS 13.6.1 (CVE-2023-42891 IOHIDFamily)](https://support.apple.com/en-us/121551)
- [4] [Apple Developer — DriverKit](https://developer.apple.com/documentation/driverkit)
- [5] [Apple Developer — System Extensions](https://developer.apple.com/documentation/systemextensions)

{{#include ../../../banners/hacktricks-training.md}}
