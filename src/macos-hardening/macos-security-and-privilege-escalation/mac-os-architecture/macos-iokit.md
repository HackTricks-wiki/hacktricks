# macOS IOKit

{{#include ../../../banners/hacktricks-training.md}}

## Informazioni di base

I/O Kit è un **framework per i driver dei dispositivi** open source e orientato agli oggetti nel kernel XNU, che gestisce i **driver dei dispositivi caricati dinamicamente**. Consente di aggiungere codice modulare al kernel al volo, supportando hardware diversificato.

I driver IOKit **esportano fondamentalmente funzioni dal kernel**. I **tipi** dei parametri di queste funzioni sono **predefiniti** e vengono verificati. Inoltre, analogamente a XPC, IOKit è semplicemente un altro livello **sopra i messaggi Mach**.

Il **codice del kernel XNU di IOKit** è open source e pubblicato da Apple su [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit). Inoltre, anche i componenti IOKit in user space sono open source [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser).

Tuttavia, **nessun driver IOKit** è open source. In ogni caso, occasionalmente una versione di un driver può includere simboli che ne facilitano il debugging. Scopri come [**ottenere le estensioni dei driver dal firmware qui**](#ipsw)**.**

È scritto in **C++**. Puoi ottenere i simboli C++ demangled con:
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
> [!CAUTION]
> Le **funzioni esposte** di IOKit potrebbero eseguire **controlli di sicurezza aggiuntivi** quando un client tenta di chiamare una funzione, ma nota che le app sono solitamente **limitate** dal **sandbox** riguardo alle funzioni IOKit con cui possono interagire.

## Driver

In macOS si trovano in:

- **`/System/Library/Extensions`**
- File KEXT integrati nel sistema operativo OS X.
- **`/Library/Extensions`**
- File KEXT installati da software di terze parti

In iOS si trovano in:

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
Fino al numero 9, i driver elencati sono **caricati all'indirizzo 0**. Ciò significa che non sono veri driver, ma **fanno parte del kernel e non possono essere scaricati**.

Per trovare estensioni specifiche puoi usare:
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
Per caricare e scaricare le estensioni del kernel:
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

La **IORegistry** è una parte fondamentale del framework IOKit in macOS e iOS, che funge da database per rappresentare la configurazione e lo stato dell'hardware del sistema. È una **raccolta gerarchica di oggetti che rappresentano tutto l'hardware e i driver** caricati nel sistema, nonché le relative relazioni.

È possibile ottenere la IORegistry usando la CLI **`ioreg`** per esaminarla dalla console (particolarmente utile su iOS).
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
Potresti scaricare **`IORegistryExplorer`** da **Xcode Additional Tools** all'indirizzo [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) e analizzare il **macOS IORegistry** tramite un'interfaccia **grafica**.

<figure><img src="../../../images/image (1167).png" alt="" width="563"><figcaption></figcaption></figure>

In IORegistryExplorer, i "planes" vengono utilizzati per organizzare e visualizzare le relazioni tra diversi oggetti nell'IORegistry. Ogni plane rappresenta un tipo specifico di relazione o una particolare vista della configurazione hardware e dei driver del sistema. Ecco alcuni dei planes più comuni che potresti incontrare in IORegistryExplorer:

1. **IOService Plane**: è il plane più generale e visualizza gli oggetti service che rappresentano driver e nub (canali di comunicazione tra driver). Mostra le relazioni provider-client tra questi oggetti.
2. **IODeviceTree Plane**: questo plane rappresenta le connessioni fisiche tra i dispositivi collegati al sistema. Viene spesso utilizzato per visualizzare la gerarchia dei dispositivi connessi tramite bus come USB o PCI.
3. **IOPower Plane**: visualizza gli oggetti e le loro relazioni in termini di gestione dell'alimentazione. Può mostrare quali oggetti influenzano lo stato energetico di altri, risultando utile per il debugging dei problemi relativi all'alimentazione.
4. **IOUSB Plane**: è incentrato specificamente sui dispositivi USB e sulle loro relazioni e mostra la gerarchia degli hub USB e dei dispositivi connessi.
5. **IOAudio Plane**: questo plane serve a rappresentare i dispositivi audio e le loro relazioni all'interno del sistema.
6. ...

## Esempio di codice per la comunicazione con un driver

Il codice seguente si connette al servizio IOKit `YourServiceNameHere` e chiama il selector 0:

- Chiama prima **`IOServiceMatching`** e **`IOServiceGetMatchingServices`** per ottenere il servizio.
- Stabilisce quindi una connessione chiamando **`IOServiceOpen`**.
- Infine, chiama una funzione con **`IOConnectCallScalarMethod`**, indicando il selector 0 (il selector è il numero assegnato alla funzione che vuoi chiamare).

<details>
<summary>Esempio di chiamata user-space a un selector del driver</summary>
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

Esistono **altre** funzioni che possono essere utilizzate per chiamare le funzioni IOKit oltre a **`IOConnectCallScalarMethod`**, come **`IOConnectCallMethod`**, **`IOConnectCallStructMethod`**...

## Reverse engineering dell'entrypoint del driver

Potresti ottenerle, ad esempio, da un [**firmware image (ipsw)**](#ipsw). Quindi, caricalo nel tuo decompilatore preferito.

Potresti iniziare a decompilare la funzione **`externalMethod`**, poiché questa è la funzione del driver che riceverà la chiamata e chiamerà la funzione corretta:

<figure><img src="../../../images/image (1168).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../images/image (1169).png" alt=""><figcaption></figcaption></figure>

Quella terribile chiamata demangled significa:
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
Nota come nella definizione precedente il parametro **`self`** sia omesso; la definizione corretta sarebbe:
```cpp
IOUserClient2022::dispatchExternalMethod(self, unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
In realtà, puoi trovare la definizione reale in [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/Kernel/IOUserClient.cpp#L6388):
```cpp
IOUserClient2022::dispatchExternalMethod(uint32_t selector, IOExternalMethodArgumentsOpaque *arguments,
const IOExternalMethodDispatch2022 dispatchArray[], size_t dispatchArrayCount,
OSObject * target, void * reference)
```
Con queste informazioni puoi riscrivere Ctrl+Right -> `Edit function signature` e impostare i tipi noti:

<figure><img src="../../../images/image (1174).png" alt=""><figcaption></figcaption></figure>

Il nuovo codice decompilato sarà simile a questo:

<figure><img src="../../../images/image (1175).png" alt=""><figcaption></figcaption></figure>

Per il passaggio successivo dobbiamo aver definito la struct **`IOExternalMethodDispatch2022`**. È opensource in [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176), puoi definirla:

<figure><img src="../../../images/image (1170).png" alt=""><figcaption></figcaption></figure>

Ora, seguendo `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray` puoi vedere molti dati:

<figure><img src="../../../images/image (1176).png" alt="" width="563"><figcaption></figcaption></figure>

Modifica il Data Type in **`IOExternalMethodDispatch2022:`**

<figure><img src="../../../images/image (1177).png" alt="" width="375"><figcaption></figcaption></figure>

dopo la modifica:

<figure><img src="../../../images/image (1179).png" alt="" width="563"><figcaption></figcaption></figure>

E poiché ora sappiamo che lì è presente un **array di 7 elementi** (controlla il codice decompilato finale), fai clic per creare un array di 7 elementi:

<figure><img src="../../../images/image (1180).png" alt="" width="563"><figcaption></figcaption></figure>

Dopo aver creato l'array puoi vedere tutte le funzioni esportate:

<figure><img src="../../../images/image (1181).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Se ricordi, per **chiamare** una funzione **esportata** dallo user space non dobbiamo chiamare il nome della funzione, ma il **numero del selector**. Qui puoi vedere che il selector **0** è la funzione **`initializeDecoder`**, il selector **1** è **`startDecoder`**, il selector **2** **`initializeEncoder`**...

## Superficie di attacco recente di IOKit (2023–2025)

- **Cattura delle digitazioni tramite IOHIDFamily** – CVE-2024-27799 (14.5) ha mostrato che un client `IOHIDSystem` permissivo poteva acquisire eventi HID anche con l'input sicuro attivo; assicurati che gli handler `externalMethod` applichino gli entitlement invece di basarsi solo sul tipo di user client.<sup>[2]</sup>
- **Corruzione della memoria di IOGPUFamily** – CVE-2024-44197 e CVE-2025-24257 hanno corretto scritture OOB raggiungibili da app in sandbox che inviano dati di lunghezza variabile malformati ai GPU user client; il bug tipico consiste in controlli dei limiti insufficienti sugli argomenti di `IOConnectCallStructMethod`.<sup>[1]</sup>
- **Monitoraggio legacy delle digitazioni** – CVE-2023-42891 (14.2) ha confermato che gli HID user client restano un vettore di sandbox-escape; sottoponi a fuzzing qualsiasi driver che esponga code di tastiera/eventi.<sup>[3]</sup>

### Suggerimenti rapidi per il triage e il fuzzing

- Enumera tutti gli external method di un user client da userland per inizializzare un fuzzer:
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
- Durante il reversing, presta attenzione ai conteggi di `IOExternalMethodDispatch2022`. Un pattern di bug comune nei CVE recenti consiste in valori incoerenti di `structureInputSize`/`structureOutputSize` rispetto alla lunghezza effettiva di `copyin`, causando un OOB nell'heap in `IOConnectCallStructMethod`.
- La raggiungibilità dalla Sandbox dipende ancora dagli entitlements. Prima di dedicare tempo a un target, verifica se il client è consentito da un'app di terze parti:
```bash
strings /System/Library/Extensions/IOHIDFamily.kext/Contents/MacOS/IOHIDFamily | \
grep -E "^com\.apple\.(driver|private)"
```
- Per i bug GPU/iomfb, passare array sovradimensionati tramite `IOConnectCallMethod` è spesso sufficiente per attivare controlli dei limiti errati. Minimal harness (selector X) per attivare la confusione sulle dimensioni:
```c
uint8_t buf[0x1000];
size_t outSz = sizeof(buf);
IOConnectCallStructMethod(conn, X, buf, sizeof(buf), buf, &outSz);
```
## DriverKit — Driver in user-space

### Informazioni di base

**DriverKit** è il sostituto in user-space di Apple per le estensioni del kernel (kext), introdotto in macOS 10.15. I binari DriverKit (bundle `.dext`) vengono eseguiti come processi in user-space, ma comunicano direttamente con il kernel tramite un'interfaccia IOKit privilegiata.

Le estensioni DriverKit gestiscono l'hardware:
- Controller e dispositivi **USB**
- Dispositivi **Thunderbolt** / PCIe
- **HID** (tastiere, mouse, game controller)
- Hardware **Audio**
- Interfacce di **Networking**
- Dispositivi **Serial** e di **Block Storage**

A differenza dei kext (che richiedevano l'avvio con SIP disabilitato o la notarization), le estensioni DriverKit vengono installate tramite `SystemExtensions.framework` e richiedono soltanto un'approvazione dell'utente una tantum.

### Rilevamento ed enumerazione
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
### Implicazioni di sicurezza

> [!WARNING]
> I binari DriverKit dispongono di un **canale di comunicazione diretto con il kernel**. L'invio di messaggi non validi attraverso questo canale può attivare vulnerabilità del kernel. Ogni driver registra classi user-client specifiche e le chiamate `IOConnectCallMethod` con argomenti non validi possono causare la corruzione della memoria del kernel.

**Superficie d'attacco:**
1. **Kernel IOKit message fuzzing** — Ogni user-client DriverKit espone selector richiamabili dallo user space. Argomenti non validi attivano bug del kernel.
2. **USB device spoofing** — Un binario USB DriverKit compromesso può presentare il profilo di un dispositivo USB malevolo (ad esempio, emulare una tastiera per eseguire HID injection).
3. **DMA attacks** — Le estensioni PCIe/Thunderbolt DriverKit possono avere un potenziale accesso DMA alla memoria fisica.
4. **Persistence** — Una volta installati come system extension, i binari DriverKit persistono tra i riavvii e gli aggiornamenti delle app.

### DriverKit IOKit User-Client Fuzzing
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
### CVE di DriverKit

| CVE | Descrizione |
|---|---|
| CVE-2022-26766 | Vulnerabilità dello stack USB di DriverKit — esecuzione di codice nel kernel |
| CVE-2021-30838 | Confusione del tipo user-client di IOKit nei driver grafici |
| CVE-2024-44197 | Scrittura OOB tramite argomenti DriverKit malformati in IOGPUFamily |

## Riferimenti

- [1] [Apple Security Updates – macOS Sequoia 15.1 / Sonoma 14.7.1 (IOGPUFamily)](https://support.apple.com/en-us/121564)
- [2] [Rapid7 – IOHIDFamily CVE-2024-27799 summary](https://www.rapid7.com/db/vulnerabilities/apple-osx-iohidfamily-cve-2024-27799/)
- [3] [Apple Security Updates – macOS 13.6.1 (CVE-2023-42891 IOHIDFamily)](https://support.apple.com/en-us/121551)
- [4] [Apple Developer — DriverKit](https://developer.apple.com/documentation/driverkit)
- [5] [Apple Developer — System Extensions](https://developer.apple.com/documentation/systemextensions)

{{#include ../../../banners/hacktricks-training.md}}
