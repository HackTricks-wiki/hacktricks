# macOS Kernel Extensions & Debugging

{{#include ../../../banners/hacktricks-training.md}}

## Informazioni di base

Le estensioni del kernel (Kexts) sono **pacchetti** con un'estensione **`.kext`** che vengono **caricati direttamente nello spazio del kernel di macOS**, fornendo funzionalità aggiuntive al sistema operativo principale.

### Stato di deprecazione & DriverKit / Estensioni di sistema
A partire da **macOS Catalina (10.15)**, Apple ha contrassegnato la maggior parte delle KPI legacy come *deprecate* e ha introdotto i framework **System Extensions & DriverKit** che funzionano in **user-space**. Da **macOS Big Sur (11)**, il sistema operativo *rifiuterà di caricare* kext di terze parti che si basano su KPI deprecate a meno che la macchina non venga avviata in modalità **Reduced Security**. Su Apple Silicon, abilitare i kext richiede inoltre che l'utente:

1. Riavvii in **Recovery** → *Startup Security Utility*.
2. Selezioni **Reduced Security** e spunti **“Allow user management of kernel extensions from identified developers”**.
3. Riavvii e approvi il kext da **System Settings → Privacy & Security**.

I driver user-land scritti con DriverKit/System Extensions riducono drasticamente la **superficie di attacco** perché i crash o la corruzione della memoria sono confinati a un processo sandboxato piuttosto che allo spazio del kernel.

> 📝 Da macOS Sequoia (15), Apple ha rimosso completamente diverse KPI legacy di networking e USB – l'unica soluzione compatibile per i fornitori è migrare a System Extensions.

### Requisiti

Ovviamente, questo è così potente che è **complicato caricare un'estensione del kernel**. Questi sono i **requisiti** che un'estensione del kernel deve soddisfare per essere caricata:

- Quando **si entra in modalità di recupero**, le **estensioni del kernel devono essere autorizzate** a essere caricate:

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

### Enumerazione & gestione (kext caricati)

`kextstat` era lo strumento storico ma è **deprecato** nelle recenti versioni di macOS. L'interfaccia moderna è **`kmutil`**:
```bash
# List every extension currently linked in the kernel, sorted by load address
sudo kmutil showloaded --sort

# Show only third-party / auxiliary collections
sudo kmutil showloaded --collection aux

# Unload a specific bundle
sudo kmutil unload -b com.example.mykext
```
La sintassi più vecchia è ancora disponibile per riferimento:
```bash
# (Deprecated) Get loaded kernel extensions
kextstat

# (Deprecated) Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
`kmutil inspect` può anche essere utilizzato per **estrarre il contenuto di una Kernel Collection (KC)** o verificare che un kext risolva tutte le dipendenze dei simboli:
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> Anche se ci si aspetta che le estensioni del kernel siano in `/System/Library/Extensions/`, se vai in questa cartella **non troverai alcun binario**. Questo è dovuto al **kernelcache** e per fare il reverse di un `.kext` devi trovare un modo per ottenerlo.

Il **kernelcache** è una **versione pre-compilata e pre-collegata del kernel XNU**, insieme a **driver** e **estensioni del kernel** essenziali. È memorizzato in un formato **compresso** e viene decompresso in memoria durante il processo di avvio. Il kernelcache facilita un **tempo di avvio più veloce** avendo una versione pronta all'uso del kernel e dei driver cruciali disponibili, riducendo il tempo e le risorse che altrimenti verrebbero spese per caricare e collegare dinamicamente questi componenti all'avvio.

### Local Kerlnelcache

In iOS si trova in **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`** in macOS puoi trovarlo con: **`find / -name "kernelcache" 2>/dev/null`** \
Nel mio caso in macOS l'ho trovato in:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

#### IMG4

Il formato di file IMG4 è un formato contenitore utilizzato da Apple nei suoi dispositivi iOS e macOS per **memorizzare e verificare in modo sicuro** i componenti del firmware (come il **kernelcache**). Il formato IMG4 include un'intestazione e diversi tag che racchiudono diversi pezzi di dati, inclusi il payload effettivo (come un kernel o bootloader), una firma e un insieme di proprietà del manifesto. Il formato supporta la verifica crittografica, consentendo al dispositivo di confermare l'autenticità e l'integrità del componente del firmware prima di eseguirlo.

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
- OPZIONALE: Di solito questo non viene trovato

Decomprimere il Kernelcache:
```bash
# img4tool (https://github.com/tihmstar/img4tool)
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

A volte Apple rilascia **kernelcache** con **simboli**. Puoi scaricare alcuni firmware con simboli seguendo i link su queste pagine. I firmware conterranno il **kernelcache** tra gli altri file.

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
## Vulnerabilità recenti e tecniche di sfruttamento

| Anno | CVE | Riepilogo |
|------|-----|---------|
| 2024 | **CVE-2024-44243** | Un difetto logico in **`storagekitd`** ha permesso a un attaccante *root* di registrare un bundle di file system malevolo che alla fine ha caricato un **kext non firmato**, **bypassando la Protezione dell'Integrità di Sistema (SIP)** e abilitando rootkit persistenti. Corretto in macOS 14.2 / 15.2.   |
| 2021 | **CVE-2021-30892** (*Shrootless*) | Il demone di installazione con il diritto `com.apple.rootless.install` poteva essere abusato per eseguire script post-installazione arbitrari, disabilitare SIP e caricare kext arbitrari.  |

**Punti chiave per i red-teamers**

1. **Cercare demoni autorizzati (`codesign -dvv /path/bin | grep entitlements`) che interagiscono con Disk Arbitration, Installer o Kext Management.**
2. **L'abuso dei bypass SIP quasi sempre concede la possibilità di caricare un kext → esecuzione di codice nel kernel**.

**Consigli difensivi**

*Tenere SIP abilitato*, monitorare le invocazioni di `kmutil load`/`kmutil create -n aux` provenienti da binari non Apple e allertare su qualsiasi scrittura in `/Library/Extensions`. Gli eventi di Sicurezza degli Endpoint `ES_EVENT_TYPE_NOTIFY_KEXTLOAD` forniscono visibilità quasi in tempo reale.

## Debugging del kernel macOS e kext

Il flusso di lavoro raccomandato da Apple è costruire un **Kernel Debug Kit (KDK)** che corrisponda alla build in esecuzione e poi collegare **LLDB** tramite una sessione di rete **KDP (Kernel Debugging Protocol)**.

### Debug locale one-shot di un panic
```bash
# Create a symbolication bundle for the latest panic
sudo kdpwrit dump latest.kcdata
kmutil analyze-panic latest.kcdata -o ~/panic_report.txt
```
### Debugging remoto live da un altro Mac

1. Scarica + installa la versione esatta di **KDK** per la macchina target.
2. Collega il Mac target e il Mac host con un **cavo USB-C o Thunderbolt**.
3. Sul **target**:
```bash
sudo nvram boot-args="debug=0x100 kdp_match_name=macbook-target"
reboot
```
4. Sul **host**:
```bash
lldb
(lldb) kdp-remote "udp://macbook-target"
(lldb) bt  # get backtrace in kernel context
```
### Attaching LLDB a un kext caricato specifico
```bash
# Identify load address of the kext
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# Attach
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```
> ℹ️  KDP espone solo un'interfaccia **sola lettura**. Per l'istrumentazione dinamica sarà necessario patchare il binario su disco, sfruttare il **kernel function hooking** (ad es. `mach_override`) o migrare il driver a un **hypervisor** per pieno accesso in lettura/scrittura.

## Riferimenti

- DriverKit Security – Apple Platform Security Guide
- Microsoft Security Blog – *Analizzando il bypass SIP CVE-2024-44243*

{{#include ../../../banners/hacktricks-training.md}}
