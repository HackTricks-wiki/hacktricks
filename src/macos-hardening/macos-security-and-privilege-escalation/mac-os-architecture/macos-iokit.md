# macOS IOKit

{{#include ../../../banners/hacktricks-training.md}}

## Podstawowe informacje

I/O Kit to otwartoźródłowy, obiektowy **framework sterowników urządzeń** w jądrze XNU, który obsługuje **sterowniki ładowane dynamicznie**. Umożliwia dodawanie modułowego kodu do jądra w czasie działania, wspierając różnorodny sprzęt.

Sterowniki IOKit zasadniczo **eksportują funkcje z jądra**. Typy **parametrów** tych funkcji są **z góry zdefiniowane** i weryfikowane. Ponadto, podobnie jak XPC, IOKit to kolejna warstwa działająca na **bazie Mach messages**.

**Kod jądra IOKit XNU** jest udostępniony jako open-source przez Apple pod adresem [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit). Dodatkowo komponenty IOKit działające w przestrzeni użytkownika są również open-source [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser).

Jednakże, **żadne sterowniki IOKit** nie są open-source. Niemniej jednak, od czasu do czasu wydanie sterownika może zawierać symbole, które ułatwiają jego debugowanie. Sprawdź, jak [**get the driver extensions from the firmware here**](#ipsw)**.**

Jest napisane w **C++**. Możesz uzyskać zdemanglowane symbole C++ za pomocą:
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
> [!CAUTION]
> Eksponowane funkcje IOKit mogą wykonywać **dodatkowe kontrole bezpieczeństwa**, gdy klient próbuje wywołać funkcję. Zwróć uwagę, że aplikacje są zazwyczaj **ograniczone** przez **sandbox** w zakresie funkcji IOKit, z którymi mogą wchodzić w interakcję.

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
Aż do numeru 9 wymienione sterowniki są **załadowane pod adresem 0**. Oznacza to, że nie są to prawdziwe sterowniki, lecz **część jądra i nie można ich odładować**.

Aby znaleźć konkretne rozszerzenia możesz użyć:
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
Aby załadować i odładować kernel extensions, wykonaj:
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

The **IORegistry** jest kluczową częścią frameworku IOKit w macOS i iOS, która służy jako baza danych reprezentująca konfigurację sprzętową i stan systemu. To **hierarchiczna kolekcja obiektów reprezentujących cały sprzęt i sterowniki** załadowane w systemie oraz ich wzajemne relacje.

Możesz uzyskać IORegistry za pomocą cli **`ioreg`** aby zbadać go z konsoli (szczególnie przydatne na iOS).
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
Możesz pobrać **`IORegistryExplorer`** z **Xcode Additional Tools** ze strony [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) i przeglądać **macOS IORegistry** przez **graficzny interfejs**.

<figure><img src="../../../images/image (1167).png" alt="" width="563"><figcaption></figcaption></figure>

W IORegistryExplorer „płaszczyzny” są używane do organizowania i wyświetlania relacji między różnymi obiektami w IORegistry. Każda płaszczyzna reprezentuje konkretny typ relacji lub określony widok konfiguracji sprzętu i sterowników systemu. Oto niektóre z powszechnych płaszczyzn, które możesz napotkać w IORegistryExplorer:

1. **IOService Plane**: To najbardziej ogólna płaszczyzna, wyświetlająca obiekty service reprezentujące sterowniki i nuby (kanały komunikacyjne między sterownikami). Pokazuje relacje provider-client między tymi obiektami.
2. **IODeviceTree Plane**: Ta płaszczyzna reprezentuje fizyczne połączenia między urządzeniami tak, jak są podłączone do systemu. Często używana do wizualizacji hierarchii urządzeń podłączonych przez magistrale takie jak USB czy PCI.
3. **IOPower Plane**: Wyświetla obiekty i ich relacje w kontekście zarządzania energią. Może pokazywać, które obiekty wpływają na stan zasilania innych, co jest przydatne przy debugowaniu problemów związanych z zasilaniem.
4. **IOUSB Plane**: Skoncentrowana na urządzeniach USB i ich relacjach, pokazuje hierarchię hubów USB i podłączonych urządzeń.
5. **IOAudio Plane**: Ta płaszczyzna służy do reprezentowania urządzeń audio i ich relacji w systemie.
6. ...

## Przykład kodu komunikacji z driverem

Poniższy kod łączy się z usługą IOKit `YourServiceNameHere` i wywołuje selector 0:

- Najpierw wywołuje **`IOServiceMatching`** i **`IOServiceGetMatchingServices`**, aby znaleźć usługę.
- Następnie nawiązuje połączenie wywołując **`IOServiceOpen`**.
- Na końcu wywołuje funkcję za pomocą **`IOConnectCallScalarMethod`**, wskazując selector 0 (selector to numer przypisany funkcji, którą chcesz wywołać).

<details>
<summary>Przykład wywołania selektora sterownika z przestrzeni użytkownika</summary>
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

Istnieją też **inne** funkcje, które mogą służyć do wywoływania funkcji IOKit, oprócz **`IOConnectCallScalarMethod`**, takie jak **`IOConnectCallMethod`**, **`IOConnectCallStructMethod`**...

## Analiza punktu wejścia sterownika

Możesz je na przykład uzyskać z [**firmware image (ipsw)**](#ipsw). Następnie załaduj obraz do swojego ulubionego dekompilatora.

Możesz rozpocząć dekompilację funkcji **`externalMethod`**, ponieważ to ona będzie odbierać połączenie i wywoływać właściwą funkcję:

<figure><img src="../../../images/image (1168).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../images/image (1169).png" alt=""><figcaption></figcaption></figure>

To zdemanglowane wywołanie oznacza:
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
Zauważ, że w poprzedniej definicji parametr **`self`** został pominięty, poprawna definicja powinna być:
```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
Właściwą definicję możesz znaleźć pod adresem [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388):
```cpp
IOUserClient2022::dispatchExternalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque *arguments,
const IOExternalMethodDispatch2022 dispatchArray[], size_t dispatchArrayCount,
OSObject * target, void * reference)
```
Mając te informacje możesz wcisnąć Ctrl+Right -> `Edit function signature` i ustawić znane typy:

<figure><img src="../../../images/image (1174).png" alt=""><figcaption></figcaption></figure>

Nowy zdekompilowany kod będzie wyglądał tak:

<figure><img src="../../../images/image (1175).png" alt=""><figcaption></figcaption></figure>

W następnym kroku musimy mieć zdefiniowaną strukturę **`IOExternalMethodDispatch2022`**. Jest open source w [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176), możesz ją zdefiniować:

<figure><img src="../../../images/image (1170).png" alt=""><figcaption></figcaption></figure>

Śledząc `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray` możesz zobaczyć dużo danych:

<figure><img src="../../../images/image (1176).png" alt="" width="563"><figcaption></figcaption></figure>

Zmień typ danych na **`IOExternalMethodDispatch2022:`**

<figure><img src="../../../images/image (1177).png" alt="" width="375"><figcaption></figcaption></figure>

Po zmianie:

<figure><img src="../../../images/image (1179).png" alt="" width="563"><figcaption></figcaption></figure>

A ponieważ jesteśmy tam teraz, mamy **tablicę 7 elementów** (sprawdź końcowy zdekompilowany kod), kliknij, aby utworzyć tablicę 7 elementów:

<figure><img src="../../../images/image (1180).png" alt="" width="563"><figcaption></figcaption></figure>

Po utworzeniu tablicy widać wszystkie eksportowane funkcje:

<figure><img src="../../../images/image (1181).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Jeśli pamiętasz, aby **call** an **exported** function from user space nie musimy wywoływać nazwy funkcji, lecz **selector number**. Tutaj widać, że selector **0** to funkcja **`initializeDecoder`**, selector **1** to **`startDecoder`**, selector **2** **`initializeEncoder`**...

## Najnowsza powierzchnia ataku IOKit (2023–2025)

- **Keystroke capture via IOHIDFamily** – CVE-2024-27799 (14.5) wykazał, że permissive `IOHIDSystem` client mógł przechwytywać zdarzenia HID nawet przy secure input; upewnij się, że `externalMethod` handlers egzekwują entitlements zamiast polegać tylko na typie user-client.
- **IOGPUFamily memory corruption** – CVE-2024-44197 i CVE-2025-24257 naprawiły OOB writes dostępne z sandboxed apps, które przekazują sfałszowane dane o zmiennej długości do GPU user clients; typowy błąd to słabe sprawdzanie granic wokół argumentów `IOConnectCallStructMethod`.
- **Legacy keystroke monitoring** – CVE-2023-42891 (14.2) potwierdził, że HID user clients nadal mogą być wektorem ucieczki z sandboxu; fuzzuj każdy driver wystawiający keyboard/event queues.

### Szybkie wskazówki dotyczące triage i fuzzingu

- Wyenumeruj wszystkie external methods dla user client z poziomu userland, aby zasilić fuzzer:
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
- Podczas reversingu zwróć uwagę na liczby w `IOExternalMethodDispatch2022`. Powszechny wzorzec błędu w niedawnych CVE to niespójność `structureInputSize`/`structureOutputSize` względem rzeczywistej długości `copyin`, co prowadzi do heap OOB w `IOConnectCallStructMethod`.
- Możliwość dotarcia do sandboxa nadal zależy od entitlements. Zanim poświęcisz czas na cel, sprawdź, czy klient jest dozwolony z aplikacji stron trzecich:
```bash
strings /System/Library/Extensions/IOHIDFamily.kext/Contents/MacOS/IOHIDFamily | \
grep -E "^com\.apple\.(driver|private)"
```
- W przypadku błędów GPU/iomfb, przekazanie zbyt dużych tablic przez `IOConnectCallMethod` często wystarcza, aby spowodować błędne sprawdzanie zakresu. Minimalny harness (selector X) do wywołania size confusion:
```c
uint8_t buf[0x1000];
size_t outSz = sizeof(buf);
IOConnectCallStructMethod(conn, X, buf, sizeof(buf), buf, &outSz);
```
## Źródła

- [Apple Security Updates – macOS Sequoia 15.1 / Sonoma 14.7.1 (IOGPUFamily)](https://support.apple.com/en-us/121564)
- [Rapid7 – IOHIDFamily CVE-2024-27799 summary](https://www.rapid7.com/db/vulnerabilities/apple-osx-iohidfamily-cve-2024-27799/)
- [Apple Security Updates – macOS 13.6.1 (CVE-2023-42891 IOHIDFamily)](https://support.apple.com/en-us/121551)
{{#include ../../../banners/hacktricks-training.md}}
