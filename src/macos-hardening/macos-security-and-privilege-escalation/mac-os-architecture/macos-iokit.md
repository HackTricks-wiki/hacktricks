# macOS IOKit

{{#include ../../../banners/hacktricks-training.md}}

## Informazioni di base

L'I/O Kit è un framework open-source e orientato agli oggetti per i **device-driver** nel XNU kernel, che gestisce **driver di dispositivo caricati dinamicamente**. Permette di aggiungere codice modulare al kernel al volo, supportando hardware eterogeneo.

I driver IOKit fondamentalmente **esportano funzioni dal kernel**. I tipi di parametro di queste funzioni sono **predefiniti** e vengono verificati. Inoltre, similmente a XPC, IOKit è solo un altro livello **sopra i Mach messages**.

**IOKit XNU kernel code** è reso open-source da Apple in [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit). Inoltre, i componenti IOKit in user space sono anch'essi open-source [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser).

Tuttavia, **no IOKit drivers** sono open-source. Comunque, di tanto in tanto una release di un driver può includere simboli che ne facilitano il debug. Check how to [**get the driver extensions from the firmware here**](#ipsw)**.**

È scritto in **C++**. Puoi ottenere simboli C++ demangled con:
```bash
# Get demangled symbols
nm -C com.apple.driver.AppleJPEGDriver

# Demangled symbols from stdin
c++filt
__ZN16IOUserClient202222dispatchExternalMethodEjP31IOExternalMethodArgumentsOpaquePK28IOExternalMethodDispatch2022mP8OSObjectPv
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
> [!CAUTION]
> Le **funzioni esposte** di IOKit potrebbero eseguire **controlli di sicurezza aggiuntivi** quando un client tenta di chiamare una funzione, ma nota che le app sono solitamente **limitate** dal **sandbox** per quanto riguarda con quali funzioni di IOKit possono interagire.

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
Fino al numero 9, i driver elencati sono **caricati all'indirizzo 0**. Questo significa che quelli non sono veri driver ma **parte del kernel e non possono essere scaricati**.

Per trovare estensioni specifiche puoi usare:
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
Per caricare e scaricare kernel extensions, esegui:
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

La **IORegistry** è una parte fondamentale del framework IOKit in macOS e iOS, che funge da database per rappresentare la configurazione hardware e lo stato del sistema. È una **raccolta gerarchica di oggetti che rappresentano tutto l'hardware e i driver** caricati sul sistema e le loro relazioni reciproche.

Puoi ottenere l'IORegistry usando la cli **`ioreg`** per ispezionarlo dalla console (particolarmente utile per iOS).
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
Puoi scaricare **`IORegistryExplorer`** da **Xcode Additional Tools** su [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) e ispezionare l'**IORegistry di macOS** tramite un'interfaccia **grafica**.

<figure><img src="../../../images/image (1167).png" alt="" width="563"><figcaption></figcaption></figure>

In IORegistryExplorer, "planes" vengono usati per organizzare e visualizzare le relazioni tra i diversi oggetti nell'IORegistry. Ciascun plane rappresenta un tipo specifico di relazione o una vista particolare della configurazione hardware e dei driver del sistema. Ecco alcuni dei plane comuni che potresti incontrare in IORegistryExplorer:

1. **IOService Plane**: Questo è il plane più generale, che mostra gli oggetti service che rappresentano i driver e i nubs (canali di comunicazione tra driver). Mostra le relazioni provider-client tra questi oggetti.
2. **IODeviceTree Plane**: Questo plane rappresenta le connessioni fisiche tra i dispositivi così come sono collegati al sistema. Spesso viene usato per visualizzare la gerarchia dei dispositivi connessi tramite bus come USB o PCI.
3. **IOPower Plane**: Visualizza gli oggetti e le loro relazioni in termini di gestione dell'alimentazione. Può mostrare quali oggetti influenzano lo stato di alimentazione di altri, utile per il debug di problemi legati all'alimentazione.
4. **IOUSB Plane**: Specifico per dispositivi USB e le loro relazioni, mostrando la gerarchia degli hub USB e dei dispositivi connessi.
5. **IOAudio Plane**: Questo plane serve per rappresentare i dispositivi audio e le loro relazioni all'interno del sistema.
6. ...

## Esempio di codice di comunicazione con il driver

Il codice seguente si connette al servizio IOKit `YourServiceNameHere` e invoca il selector 0:

- Richiama prima **`IOServiceMatching`** e **`IOServiceGetMatchingServices`** per ottenere il servizio.
- Successivamente stabilisce una connessione chiamando **`IOServiceOpen`**.
- Infine chiama una funzione con **`IOConnectCallScalarMethod`** indicando il selector 0 (il selector è il numero assegnato alla funzione che si vuole chiamare).

<details>
<summary>Esempio di chiamata dallo spazio utente a un selector del driver</summary>
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

Ci sono **altre** funzioni che possono essere usate per chiamare le funzioni IOKit oltre a **`IOConnectCallScalarMethod`** come **`IOConnectCallMethod`**, **`IOConnectCallStructMethod`**...

## Analisi del punto di ingresso del driver

Puoi ottenerli, per esempio, da un [**firmware image (ipsw)**](#ipsw). Poi carica l'immagine nel tuo decompiler preferito.

Puoi iniziare a decompilare la funzione **`externalMethod`**, in quanto è la funzione del driver che riceverà la chiamata e invocherà la funzione corretta:

<figure><img src="../../../images/image (1168).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../images/image (1169).png" alt=""><figcaption></figcaption></figure>

Quella terribile chiamata demagled significa:
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
Nota come nella definizione precedente il parametro **`self`** è assente, la definizione corretta sarebbe:
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

Il nuovo codice decompilato apparirà così:

<figure><img src="../../../images/image (1175).png" alt=""><figcaption></figcaption></figure>

Per il passo successivo dobbiamo avere definita la struct **`IOExternalMethodDispatch2022`**. È open source in [https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176](https://github.com/apple-oss-distributions/xnu/blob/1031c584a5e37aff177559b9f69dbd3c8c3fd30a/iokit/IOKit/IOUserClient.h#L168-L176), puoi definirla:

<figure><img src="../../../images/image (1170).png" alt=""><figcaption></figcaption></figure>

Ora, seguendo `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray` puoi vedere molti dati:

<figure><img src="../../../images/image (1176).png" alt="" width="563"><figcaption></figcaption></figure>

Cambia il Data Type in **`IOExternalMethodDispatch2022:`**

<figure><img src="../../../images/image (1177).png" alt="" width="375"><figcaption></figcaption></figure>

dopo la modifica:

<figure><img src="../../../images/image (1179).png" alt="" width="563"><figcaption></figcaption></figure>

E come vedi ora abbiamo un **array di 7 elementi** (controlla il codice decompilato finale); clicca per creare un array di 7 elementi:

<figure><img src="../../../images/image (1180).png" alt="" width="563"><figcaption></figcaption></figure>

Dopo aver creato l'array puoi vedere tutte le funzioni esportate:

<figure><img src="../../../images/image (1181).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Se ricordi, per **chiamare** una funzione **esportata** dallo user space non è necessario chiamare il nome della funzione, ma il **numero di selector**. Qui puoi vedere che il selector **0** è la funzione **`initializeDecoder`**, il selector **1** è **`startDecoder`**, il selector **2** **`initializeEncoder`**...

## Superficie di attacco IOKit recente (2023–2025)

- **Keystroke capture via IOHIDFamily** – CVE-2024-27799 (14.5) ha mostrato che un client permissivo `IOHIDSystem` poteva catturare eventi HID anche con secure input; assicurati che gli handler `externalMethod` applichino gli entitlements invece di basarsi solo sul tipo di user-client.
- **IOGPUFamily memory corruption** – CVE-2024-44197 e CVE-2025-24257 hanno corretto OOB writes raggiungibili da app sandboxed che passano dati a lunghezza variabile malformati a GPU user clients; il bug tipico sono controlli dei limiti insufficienti attorno agli argomenti di `IOConnectCallStructMethod`.
- **Legacy keystroke monitoring** – CVE-2023-42891 (14.2) ha confermato che gli HID user clients restano un vettore di escape dalla sandbox; fuzz qualsiasi driver che espone keyboard/event queues.

### Consigli rapidi per triage e fuzzing

- Enumera tutti gli external methods per un user client da userland per popolare un fuzzer:
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
- When reversing, presta attenzione ai conteggi di `IOExternalMethodDispatch2022`. Un pattern di bug comune nelle CVE recenti è l'incoerenza tra `structureInputSize`/`structureOutputSize` e la lunghezza effettiva di `copyin`, che porta a heap OOB in `IOConnectCallStructMethod`.
- La raggiungibilità della sandbox dipende ancora dagli entitlements. Prima di spendere tempo su un target, verifica se il client è consentito da un'app di terze parti:
```bash
strings /System/Library/Extensions/IOHIDFamily.kext/Contents/MacOS/IOHIDFamily | \
grep -E "^com\.apple\.(driver|private)"
```
- Per i bug GPU/iomfb, passare array sovradimensionati tramite `IOConnectCallMethod` è spesso sufficiente per innescare controlli dei limiti errati. Harness minimale (selector X) per innescare size confusion:
```c
uint8_t buf[0x1000];
size_t outSz = sizeof(buf);
IOConnectCallStructMethod(conn, X, buf, sizeof(buf), buf, &outSz);
```
## Riferimenti

- [Aggiornamenti di sicurezza Apple – macOS Sequoia 15.1 / Sonoma 14.7.1 (IOGPUFamily)](https://support.apple.com/en-us/121564)
- [Rapid7 – Riepilogo CVE-2024-27799 IOHIDFamily](https://www.rapid7.com/db/vulnerabilities/apple-osx-iohidfamily-cve-2024-27799/)
- [Aggiornamenti di sicurezza Apple – macOS 13.6.1 (CVE-2023-42891 IOHIDFamily)](https://support.apple.com/en-us/121551)
{{#include ../../../banners/hacktricks-training.md}}
