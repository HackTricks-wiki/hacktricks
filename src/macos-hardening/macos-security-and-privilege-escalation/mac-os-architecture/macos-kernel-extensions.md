# Estensioni del kernel macOS e Kernelcaches

{{#include ../../../banners/hacktricks-training.md}}

## Informazioni di base

Le estensioni del kernel (Kexts) sono **pacchetti** con estensione **`.kext`** che vengono **caricati direttamente nello spazio del kernel di macOS**, fornendo funzionalità aggiuntive al sistema operativo principale.

### Stato di deprecazione e DriverKit / System Extensions
A partire da **macOS Catalina (10.15)**, Apple ha contrassegnato la maggior parte delle KPI legacy come *deprecate* e ha introdotto i framework **System Extensions e DriverKit**, che vengono eseguiti nello **user-space**. A partire da **macOS Big Sur (11)**, il sistema operativo *rifiuterà di caricare* Kext di terze parti che dipendono da KPI deprecate, a meno che la macchina non sia avviata in modalità **Reduced Security**. Sui dispositivi Apple Silicon, l'abilitazione dei Kext richiede inoltre che l'utente:

1. Riavvii in **Recovery** → *Startup Security Utility*.
2. Selezioni **Reduced Security** e spunti **“Allow user management of kernel extensions from identified developers”**.
3. Riavvii e approvi il Kext da **System Settings → Privacy & Security**.

I driver in user-land scritti con DriverKit/System Extensions **riducono drasticamente la attack surface**, perché i crash o la corruzione della memoria rimangono confinati in un processo sandboxed invece di interessare lo spazio del kernel.<sup>[[1]](#references)</sup>

> 📝 A partire da macOS Sequoia (15), Apple ha rimosso completamente diverse KPI legacy per il networking e le USB: l'unica soluzione compatibile con il futuro per i vendor consiste nella migrazione a System Extensions.

### Requisiti

Ovviamente, si tratta di una funzionalità così potente che **caricare un'estensione del kernel è complicato**. Questi sono i **requisiti** che un'estensione del kernel deve soddisfare per essere caricata:

- Quando si **entra in recovery mode**, le **estensioni del kernel devono poter essere caricate**:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- L'estensione del kernel deve essere **firmata con un certificato di firma del codice del kernel**, che può essere **rilasciato solo da Apple**. Apple esaminerà in dettaglio l'azienda e i motivi per cui il certificato è necessario.
- L'estensione del kernel deve inoltre essere **notarizzata**; Apple potrà verificarla per individuare eventuale malware.
- Successivamente, l'utente **root** è colui che può **caricare l'estensione del kernel** e i file all'interno del pacchetto devono **appartenere a root**.
- Durante il processo di upload, il pacchetto deve essere preparato in una **posizione protetta non-root**: `/Library/StagedExtensions` (richiede il grant `com.apple.rootless.storage.KernelExtensionManagement`).
- Infine, quando si tenta di caricarla, l'utente [**riceverà una richiesta di conferma**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) e, se accettata, il computer dovrà essere **riavviato** per caricarla.

### Processo di caricamento

In Catalina funzionava in questo modo: è interessante notare che il processo di **verifica** avviene in userland. Tuttavia, solo le applicazioni con il grant **`com.apple.private.security.kext-management`** possono **richiedere al kernel di caricare un'estensione**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. La cli **`kextutil`** **avvia** il processo di **verifica** per il caricamento di un'estensione
- Comunicherà con **`kextd`** inviando richieste tramite un **servizio Mach**.
2. **`kextd`** verificherà diversi elementi, come la **firma**
- Comunicherà con **`syspolicyd`** per **verificare** se l'estensione può essere **caricata**.
3. **`syspolicyd`** mostrerà una richiesta all'**utente** se l'estensione non è stata caricata in precedenza.
- **`syspolicyd`** comunicherà il risultato a **`kextd`**
4. **`kextd`** potrà infine **comunicare al kernel di caricare** l'estensione

Se **`kextd`** non è disponibile, **`kextutil`** può eseguire gli stessi controlli.

### Enumerazione e gestione (Kext caricati)

`kextstat` era lo strumento storico, ma è **deprecato** nelle versioni recenti di macOS. L'interfaccia moderna è **`kmutil`**:
```bash
# List every extension currently linked in the kernel, sorted by load address
sudo kmutil showloaded --sort

# Show only third-party / auxiliary collections
sudo kmutil showloaded --collection aux

# Unload a specific bundle
sudo kmutil unload -b com.example.mykext
```
La sintassi precedente è ancora disponibile come riferimento:
```bash
# (Deprecated) Get loaded kernel extensions
kextstat

# (Deprecated) Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
`kmutil inspect` può anche essere utilizzato per **eseguire il dump del contenuto di una Kernel Collection (KC)** o verificare che un kext risolva tutte le dipendenze dai simboli:
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> Anche se ci si aspetta che le kernel extensions si trovino in `/System/Library/Extensions/`, andando in questa cartella **non troverai alcun binary**. Questo accade a causa del **kernelcache** e, per fare reverse engineering di una `.kext`, devi trovare un modo per ottenerla.

Il **kernelcache** è una versione **pre-compilata e pre-collegata del kernel XNU**, insieme a **drivers** dei dispositivi essenziali e **kernel extensions**. È memorizzato in formato **compresso** e viene decompresso in memoria durante il processo di boot. Il kernelcache permette un **boot più rapido**, poiché rende disponibile una versione del kernel e dei drivers fondamentali pronta per l'esecuzione, riducendo il tempo e le risorse che altrimenti verrebbero impiegati per caricare e collegare dinamicamente questi componenti durante il boot.

I principali vantaggi del kernelcache sono la **velocità di caricamento** e il fatto che tutti i moduli siano prelinked (nessun impedimento durante il load time). Inoltre, una volta che tutti i moduli sono stati prelinked, KXLD può essere rimosso dalla memoria, quindi **XNU non può caricare nuove KEXT**.

> [!TIP]
> Il tool [https://github.com/dhinakg/aeota](https://github.com/dhinakg/aeota) decritta i container AEA (Apple Encrypted Archive / AEA asset) di Apple — il formato container cifrato utilizzato da Apple per gli asset OTA e alcune parti degli IPSW — e può produrre l'archivio .dmg/asset sottostante, che puoi quindi estrarre con gli strumenti aastuff forniti.


### Kernelcache locale

In iOS si trova in **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`**; in macOS puoi trovarlo con: **`find / -name "kernelcache" 2>/dev/null`** \
Nel mio caso, in macOS l'ho trovato in:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

Trova anche qui il [**kernelcache della versione 14 con symbols**](https://x.com/tihmstar/status/1295814618242318337?lang=en).

#### Compresso in IMG4 / BVX2 (LZFSE)

Il formato file IMG4 è un formato container utilizzato da Apple nei suoi dispositivi iOS e macOS per **memorizzare e verificare in modo sicuro i componenti del firmware** (come il **kernelcache**). Il formato IMG4 include un header e diversi tag che incapsulano varie parti di dati, tra cui il payload effettivo (come un kernel o un bootloader), una signature e un insieme di proprietà del manifest. Il formato supporta la verifica crittografica, consentendo al dispositivo di confermare l'autenticità e l'integrità del componente firmware prima della sua esecuzione.

Di solito è composto dai seguenti componenti:

- **Payload (IM4P)**:
- Spesso compresso (LZFSE4, LZSS, …)
- Facoltativamente cifrato
- **Manifest (IM4M)**:
- Contiene la Signature
- Dizionario Key/Value aggiuntivo
- **Restore Info (IM4R)**:
- Noto anche come APNonce
- Impedisce di riprodurre alcuni update
- OPTIONAL: Di solito non viene trovato

Decomprimi il Kernelcache:
```bash
# img4tool (https://github.com/tihmstar/img4tool)
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# imjtool (https://newandroidbook.com/tools/imjtool.html)
imjtool _img_name_ [extract]

# disarm (you can use it directly on the IMG4 file) - [https://newandroidbook.com/tools/disarm.html](https://newandroidbook.com/tools/disarm.html)
disarm -L kernelcache.release.v57 # From unzip ipsw

# disamer (extract specific parts, e.g. filesets) - [https://newandroidbook.com/tools/disarm.html](https://newandroidbook.com/tools/disarm.html)
disarm -e filesets kernelcache.release.d23
```
#### Disarm symbols per il kernel

**`Disarm`** consente di effettuare la symbolication delle funzioni dal kernelcache utilizzando i matchers. Questi matchers sono semplici regole di pattern (righe di testo) che indicano a disarm come riconoscere ed effettuare automaticamente la symbolication di funzioni, argomenti e stringhe di panic/log all'interno di un binary.

In pratica, si indica la stringa utilizzata da una funzione e disarm la individuerà ed effettuerà la **symbolication**.

Puoi trovare alcuni `xnu.matchers` su [https://newosxbook.com/tools/disarm.html](https://newosxbook.com/tools/disarm.html), nella sezione **`Matchers`**. Puoi anche creare i tuoi matchers.
```bash
# Go to /tmp/extracted where disarm extracted the filesets
disarm -e filesets kernelcache.release.d23 # Always extract to /tmp/extracted
cd /tmp/extracted
JMATCHERS=xnu.matchers disarm --analyze kernel.rebuilt  # Note that xnu.matchers is actually a file with the matchers
```
### Download

Un **IPSW (iPhone/iPad Software)** è il formato del pacchetto firmware di Apple utilizzato per il ripristino e l'aggiornamento dei dispositivi e per i bundle firmware completi. Tra le altre cose, contiene il **kernelcache**.

- [**KernelDebugKit Github**](https://github.com/dortania/KdkSupportPkg/releases)

In [https://github.com/dortania/KdkSupportPkg/releases](https://github.com/dortania/KdkSupportPkg/releases) è possibile trovare tutti i kernel debug kit. È possibile scaricarlo, montarlo, aprirlo con lo strumento [Suspicious Package](https://www.mothersruin.com/software/SuspiciousPackage/get.html), accedere alla cartella **`.kext`** ed **estrarlo**.

Verifica la presenza di symbols con:
```bash
nm -a ~/Downloads/Sandbox.kext/Contents/MacOS/Sandbox | wc -l
```
- [**theapplewiki.com**](https://theapplewiki.com/wiki/Firmware/Mac/14.x)**,** [**ipsw.me**](https://ipsw.me/)**,** [**theiphonewiki.com**](https://www.theiphonewiki.com/)

A volte Apple rilascia **kernelcache** con **symbols**. Puoi scaricare alcuni firmware con i symbols seguendo i link presenti in quelle pagine. I firmware conterranno il **kernelcache** tra gli altri file.

Per **estrarre** la kernel cache puoi eseguire:
```bash
# Install ipsw tool
brew install blacktop/tap/ipsw

# Extract only the kernelcache from the IPSW
ipsw extract --kernel /path/to/YourFirmware.ipsw -o out/

# You should get something like:
#   out/Firmware/kernelcache.release.iPhoneXX
#   or an IMG4 payload: out/Firmware/kernelcache.release.iPhoneXX.im4p

# If you get an IMG4 payload:
ipsw img4 im4p extract out/Firmware/kernelcache*.im4p -o kcache.raw
```
Un'altra opzione per **estrarre** i file consiste nel cambiare l'estensione da `.ipsw` a `.zip` e quindi **decomprimerlo**.

Dopo aver estratto il firmware, otterrai un file simile a: **`kernelcache.release.iphone14`**. È in formato **IMG4**; puoi estrarre le informazioni interessanti con:

[**pyimg4**](https://github.com/m1stadev/PyIMG4)**:**
```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
[**img4tool**](https://github.com/tihmstar/img4tool)**:
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```

```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
[**img4tool**](https://github.com/tihmstar/img4tool)**:
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### Ispezione del kernelcache

Verifica se il kernelcache contiene simboli con
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
## Vulnerabilità recenti e tecniche di exploitation

| Anno | CVE | Riepilogo |
|------|-----|---------|
| 2024 | **CVE-2024-44243** | Un difetto logico in **`storagekitd`** consentiva a un attacker *root* di registrare un bundle file-system malevolo che infine caricava un **kext non firmato**, **bypassando System Integrity Protection (SIP)** e abilitando rootkit persistenti. Risolto in macOS 14.2 / 15.2. <sup>[[2]](#references)</sup>  |
| 2021 | **CVE-2021-30892** (*Shrootless*) | Un daemon di installazione con l'entitlement `com.apple.rootless.install` poteva essere abusato per eseguire script post-install arbitrari, disabilitare SIP e caricare kext arbitrari. <sup>[[3]](#references)</sup> |

**Punti chiave per i red-teamers**

1. **Cercare daemon con entitlement (`codesign -dvv /path/bin | grep entitlements`) che interagiscono con Disk Arbitration, Installer o Kext Management.**
2. **L'abuso dei bypass di SIP concede quasi sempre la possibilità di caricare un kext → esecuzione di codice nel kernel**.

**Suggerimenti difensivi**

*Tenere SIP abilitato*, monitorare le invocazioni di `kmutil load`/`kmutil create -n aux` provenienti da binari non Apple e generare alert per qualsiasi scrittura in `/Library/Extensions`. Gli eventi di Endpoint Security `ES_EVENT_TYPE_NOTIFY_KEXTLOAD` forniscono visibilità quasi in tempo reale.

## Debug del kernel e dei kext di macOS

Il workflow consigliato da Apple consiste nel compilare un **Kernel Debug Kit (KDK)** corrispondente alla build in esecuzione e quindi collegare **LLDB** tramite una sessione di rete **KDP (Kernel Debugging Protocol)**.

### Debug locale one-shot di un panic
```bash
# Create a symbolication bundle for the latest panic
sudo kdpwrit dump latest.kcdata
kmutil analyze-panic latest.kcdata -o ~/panic_report.txt
```
### Live remote debugging da un altro Mac

1. Scarica e installa la versione esatta di **KDK** per la macchina target.
2. Collega il Mac target e il Mac host con un cavo **USB-C o Thunderbolt**.
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
### Collegare LLDB a una specifica kext caricata
```bash
# Identify load address of the kext
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# Attach
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```
> ℹ️ KDP espone solo un'interfaccia **di sola lettura**. Per la dynamic instrumentation sarà necessario patchare il binario su disco, sfruttare il **kernel function hooking** (ad es. `mach_override`) o migrare il driver a un **hypervisor** per ottenere accesso completo in lettura/scrittura.

## References

- [1] [DriverKit security for macOS - Apple Platform Security Guide](https://support.apple.com/guide/security/driverkit-security-seca48c92d43/web)
- [2] [Analyzing CVE-2024-44243, a macOS System Integrity Protection bypass through kernel extensions - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [3] [Microsoft finds new macOS vulnerability, Shrootless, that could bypass System Integrity Protection - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)

{{#include ../../../banners/hacktricks-training.md}}
