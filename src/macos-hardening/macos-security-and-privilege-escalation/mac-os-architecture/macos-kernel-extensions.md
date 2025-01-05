# macOS Kernel Extensions & Debugging

{{#include ../../../banners/hacktricks-training.md}}

## Informazioni di base

Le estensioni del kernel (Kexts) sono **pacchetti** con un'estensione **`.kext`** che vengono **caricati direttamente nello spazio del kernel di macOS**, fornendo funzionalità aggiuntive al sistema operativo principale.

### Requisiti

Ovviamente, è così potente che è **complicato caricare un'estensione del kernel**. Questi sono i **requisiti** che un'estensione del kernel deve soddisfare per essere caricata:

- Quando si **entra in modalità di recupero**, le **estensioni del kernel devono essere autorizzate** a essere caricate:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- L'estensione del kernel deve essere **firmata con un certificato di firma del codice del kernel**, che può essere **concesso solo da Apple**. Chi esaminerà in dettaglio l'azienda e le ragioni per cui è necessaria.
- L'estensione del kernel deve anche essere **notarizzata**, Apple sarà in grado di controllarla per malware.
- Poi, l'utente **root** è colui che può **caricare l'estensione del kernel** e i file all'interno del pacchetto devono **appartenere a root**.
- Durante il processo di caricamento, il pacchetto deve essere preparato in una **posizione protetta non-root**: `/Library/StagedExtensions` (richiede il grant `com.apple.rootless.storage.KernelExtensionManagement`).
- Infine, quando si tenta di caricarlo, l'utente riceverà una [**richiesta di conferma**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) e, se accettata, il computer deve essere **riavviato** per caricarlo.

### Processo di caricamento

In Catalina era così: È interessante notare che il processo di **verifica** avviene in **userland**. Tuttavia, solo le applicazioni con il grant **`com.apple.private.security.kext-management`** possono **richiedere al kernel di caricare un'estensione**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **avvia** il processo di **verifica** per caricare un'estensione
- Parlerà con **`kextd`** inviando utilizzando un **servizio Mach**.
2. **`kextd`** controllerà diverse cose, come la **firma**
- Parlerà con **`syspolicyd`** per **verificare** se l'estensione può essere **caricata**.
3. **`syspolicyd`** **chiederà** all'**utente** se l'estensione non è stata precedentemente caricata.
- **`syspolicyd`** riporterà il risultato a **`kextd`**
4. **`kextd`** sarà infine in grado di **dire al kernel di caricare** l'estensione

Se **`kextd`** non è disponibile, **`kextutil`** può eseguire gli stessi controlli.

### Enumerazione (kexts caricati)
```bash
# Get loaded kernel extensions
kextstat

# Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
## Kernelcache

> [!CAUTION]
> Anche se ci si aspetta che le estensioni del kernel siano in `/System/Library/Extensions/`, se si va in questa cartella **non si troverà alcun binario**. Questo è dovuto al **kernelcache** e per invertire un `.kext` è necessario trovare un modo per ottenerlo.

Il **kernelcache** è una **versione pre-compilata e pre-collegata del kernel XNU**, insieme a **driver** e **estensioni del kernel** essenziali. È memorizzato in un formato **compresso** e viene decompresso in memoria durante il processo di avvio. Il kernelcache facilita un **tempo di avvio più veloce** avendo una versione pronta all'uso del kernel e dei driver cruciali disponibili, riducendo il tempo e le risorse che altrimenti verrebbero spesi per caricare e collegare dinamicamente questi componenti all'avvio.

### Local Kerlnelcache

In iOS si trova in **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`** in macOS puoi trovarlo con: **`find / -name "kernelcache" 2>/dev/null`** \
Nel mio caso in macOS l'ho trovato in:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

#### IMG4

Il formato di file IMG4 è un formato contenitore utilizzato da Apple nei suoi dispositivi iOS e macOS per **memorizzare e verificare in modo sicuro** i componenti del firmware (come il **kernelcache**). Il formato IMG4 include un'intestazione e diversi tag che racchiudono diversi pezzi di dati, inclusi il payload effettivo (come un kernel o un bootloader), una firma e un insieme di proprietà del manifesto. Il formato supporta la verifica crittografica, consentendo al dispositivo di confermare l'autenticità e l'integrità del componente firmware prima di eseguirlo.

È solitamente composto dai seguenti componenti:

- **Payload (IM4P)**:
- Spesso compresso (LZFSE4, LZSS, …)
- Facoltativamente crittografato
- **Manifest (IM4M)**:
- Contiene la firma
- Dizionario chiave/valore aggiuntivo
- **Restore Info (IM4R)**:
- Conosciuto anche come APNonce
- Previene la ripetizione di alcuni aggiornamenti
- OPZIONALE: Di solito non si trova

Decomprimere il Kernelcache:
```bash
# img4tool (https://github.com/tihmstar/img4tool
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### Download

- [**KernelDebugKit Github**](https://github.com/dortania/KdkSupportPkg/releases)

In [https://github.com/dortania/KdkSupportPkg/releases](https://github.com/dortania/KdkSupportPkg/releases) è possibile trovare tutti i kernel debug kits. Puoi scaricarlo, montarlo, aprirlo con lo strumento [Suspicious Package](https://www.mothersruin.com/software/SuspiciousPackage/get.html), accedere alla cartella **`.kext`** e **estrarlo**.

Controllalo per simboli con:
```bash
nm -a ~/Downloads/Sandbox.kext/Contents/MacOS/Sandbox | wc -l
```
- [**theapplewiki.com**](https://theapplewiki.com/wiki/Firmware/Mac/14.x)**,** [**ipsw.me**](https://ipsw.me/)**,** [**theiphonewiki.com**](https://www.theiphonewiki.com/)

A volte Apple rilascia **kernelcache** con **simboli**. Puoi scaricare alcuni firmware con simboli seguendo i link su quelle pagine. I firmware conterranno il **kernelcache** tra gli altri file.

Per **estrarre** i file inizia cambiando l'estensione da `.ipsw` a `.zip` e **decomprimi**.

Dopo aver estratto il firmware otterrai un file come: **`kernelcache.release.iphone14`**. È in formato **IMG4**, puoi estrarre le informazioni interessanti con:

[**pyimg4**](https://github.com/m1stadev/PyIMG4)**:**
```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
[**img4tool**](https://github.com/tihmstar/img4tool)**:**
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### Ispezionare il kernelcache

Controlla se il kernelcache ha simboli con
```bash
nm -a kernelcache.release.iphone14.e | wc -l
```
Con questo possiamo ora **estrarre tutte le estensioni** o **quella che ti interessa:**
```bash
# List all extensions
kextex -l kernelcache.release.iphone14.e
## Extract com.apple.security.sandbox
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# Extract all
kextex_all kernelcache.release.iphone14.e

# Check the extension for symbols
nm -a binaries/com.apple.security.sandbox | wc -l
```
## Debugging

## Riferimenti

- [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
- [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

{{#include ../../../banners/hacktricks-training.md}}
