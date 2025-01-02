# macOS IOKit

{{#include ../../../banners/hacktricks-training.md}}

## Informazioni di base

L'I/O Kit è un **framework per driver di dispositivo** open-source e orientato agli oggetti nel kernel XNU, gestisce **driver di dispositivo caricati dinamicamente**. Permette di aggiungere codice modulare al kernel al volo, supportando hardware diversificato.

I driver IOKit **esporteranno fondamentalmente funzioni dal kernel**. Questi parametri di funzione **tipi** sono **predefiniti** e vengono verificati. Inoltre, simile a XPC, IOKit è solo un altro strato **sopra i messaggi Mach**.

Il **codice IOKit del kernel XNU** è open-source da Apple in [https://github.com/apple-oss-distributions/xnu/tree/main/iokit](https://github.com/apple-oss-distributions/xnu/tree/main/iokit). Inoltre, i componenti IOKit dello spazio utente sono anch'essi open-source [https://github.com/opensource-apple/IOKitUser](https://github.com/opensource-apple/IOKitUser).

Tuttavia, **nessun driver IOKit** è open-source. Comunque, di tanto in tanto, un rilascio di un driver potrebbe venire con simboli che rendono più facile il debug. Controlla come [**ottenere le estensioni del driver dal firmware qui**](./#ipsw)**.**

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
> Le funzioni **esposte** di IOKit potrebbero eseguire **controlli di sicurezza aggiuntivi** quando un client tenta di chiamare una funzione, ma si noti che le app sono solitamente **limitati** dal **sandbox** con cui possono interagire le funzioni di IOKit.

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
Fino al numero 9, i driver elencati sono **caricati all'indirizzo 0**. Questo significa che non sono veri e propri driver ma **parte del kernel e non possono essere scaricati**.

Per trovare estensioni specifiche puoi usare:
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
Per caricare e scaricare le estensioni del kernel fare:
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
## IORegistry

Il **IORegistry** è una parte cruciale del framework IOKit in macOS e iOS che funge da database per rappresentare la configurazione e lo stato dell'hardware del sistema. È una **collezione gerarchica di oggetti che rappresentano tutto l'hardware e i driver** caricati sul sistema e le loro relazioni tra di loro.

Puoi ottenere l'IORegistry utilizzando il cli **`ioreg`** per ispezionarlo dalla console (particolarmente utile per iOS).
```bash
ioreg -l #List all
ioreg -w 0 #Not cut lines
ioreg -p <plane> #Check other plane
```
Puoi scaricare **`IORegistryExplorer`** da **Xcode Additional Tools** da [**https://developer.apple.com/download/all/**](https://developer.apple.com/download/all/) e ispezionare il **macOS IORegistry** attraverso un'interfaccia **grafica**.

<figure><img src="../../../images/image (1167).png" alt="" width="563"><figcaption></figcaption></figure>

In IORegistryExplorer, "piani" sono usati per organizzare e visualizzare le relazioni tra diversi oggetti nell'IORegistry. Ogni piano rappresenta un tipo specifico di relazione o una particolare vista della configurazione hardware e dei driver del sistema. Ecco alcuni dei piani comuni che potresti incontrare in IORegistryExplorer:

1. **IOService Plane**: Questo è il piano più generale, che mostra gli oggetti di servizio che rappresentano driver e nubs (canali di comunicazione tra driver). Mostra le relazioni fornitore-cliente tra questi oggetti.
2. **IODeviceTree Plane**: Questo piano rappresenta le connessioni fisiche tra i dispositivi mentre sono collegati al sistema. È spesso usato per visualizzare la gerarchia dei dispositivi connessi tramite bus come USB o PCI.
3. **IOPower Plane**: Mostra oggetti e le loro relazioni in termini di gestione dell'energia. Può mostrare quali oggetti stanno influenzando lo stato di alimentazione di altri, utile per il debug di problemi legati all'energia.
4. **IOUSB Plane**: Focalizzato specificamente sui dispositivi USB e le loro relazioni, mostrando la gerarchia degli hub USB e dei dispositivi connessi.
5. **IOAudio Plane**: Questo piano è per rappresentare i dispositivi audio e le loro relazioni all'interno del sistema.
6. ...

## Esempio di Codice per la Comunicazione del Driver

Il seguente codice si connette al servizio IOKit `"YourServiceNameHere"` e chiama la funzione all'interno del selettore 0. Per farlo:

- prima chiama **`IOServiceMatching`** e **`IOServiceGetMatchingServices`** per ottenere il servizio.
- Poi stabilisce una connessione chiamando **`IOServiceOpen`**.
- E infine chiama una funzione con **`IOConnectCallScalarMethod`** indicando il selettore 0 (il selettore è il numero assegnato alla funzione che vuoi chiamare).
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
Ci sono **altre** funzioni che possono essere utilizzate per chiamare le funzioni IOKit oltre a **`IOConnectCallScalarMethod`** come **`IOConnectCallMethod`**, **`IOConnectCallStructMethod`**...

## Inversione del punto di ingresso del driver

Puoi ottenerli ad esempio da un [**firmware image (ipsw)**](./#ipsw). Poi, caricalo nel tuo decompilatore preferito.

Puoi iniziare a decompilare la funzione **`externalMethod`** poiché questa è la funzione del driver che riceverà la chiamata e chiamerà la funzione corretta:

<figure><img src="../../../images/image (1168).png" alt="" width="315"><figcaption></figcaption></figure>

<figure><img src="../../../images/image (1169).png" alt=""><figcaption></figcaption></figure>

Quella terribile chiamata demangled significa:
```cpp
IOUserClient2022::dispatchExternalMethod(unsigned int, IOExternalMethodArgumentsOpaque*, IOExternalMethodDispatch2022 const*, unsigned long, OSObject*, void*)
```
Nota come nella definizione precedente il parametro **`self`** è mancante, la buona definizione sarebbe:
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

Ora, seguendo il `(IOExternalMethodDispatch2022 *)&sIOExternalMethodArray` puoi vedere molti dati:

<figure><img src="../../../images/image (1176).png" alt="" width="563"><figcaption></figcaption></figure>

Cambia il tipo di dato in **`IOExternalMethodDispatch2022:`**

<figure><img src="../../../images/image (1177).png" alt="" width="375"><figcaption></figcaption></figure>

dopo la modifica:

<figure><img src="../../../images/image (1179).png" alt="" width="563"><figcaption></figcaption></figure>

E come sappiamo lì abbiamo un **array di 7 elementi** (controlla il codice decompilato finale), clicca per creare un array di 7 elementi:

<figure><img src="../../../images/image (1180).png" alt="" width="563"><figcaption></figcaption></figure>

Dopo che l'array è stato creato puoi vedere tutte le funzioni esportate:

<figure><img src="../../../images/image (1181).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Se ricordi, per **chiamare** una funzione **esportata** dallo spazio utente non dobbiamo chiamare il nome della funzione, ma il **numero del selettore**. Qui puoi vedere che il selettore **0** è la funzione **`initializeDecoder`**, il selettore **1** è **`startDecoder`**, il selettore **2** **`initializeEncoder`**...

{{#include ../../../banners/hacktricks-training.md}}
