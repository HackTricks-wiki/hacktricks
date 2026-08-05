# macOS Kernel Extensions & Kernelcaches

{{#include ../../../banners/hacktricks-training.md}}

## Informazioni di base

Le kernel extensions (Kexts) sono **packages** con estensione **`.kext`** che vengono **caricati direttamente nello spazio del kernel di macOS**, fornendo funzionalità aggiuntive al sistema operativo principale.

### Stato di deprecazione & DriverKit / System Extensions
A partire da **macOS Catalina (10.15)** Apple ha contrassegnato la maggior parte dei KPI legacy come *deprecated* e ha introdotto i framework **System Extensions & DriverKit**, che vengono eseguiti nello **user-space**. Da **macOS Big Sur (11)** il sistema operativo *rifiuterà di caricare* kext di terze parti che si basano su KPI deprecated, a meno che la macchina non venga avviata in modalità **Reduced Security**. Su Apple Silicon, l'abilitazione dei kext richiede inoltre che l'utente:

1. Riavvii in **Recovery** → *Startup Security Utility*.
2. Selezioni **Reduced Security** e attivi **“Allow user management of kernel extensions from identified developers”**.
3. Riavvii e approvi il kext da **System Settings → Privacy & Security**.

I driver user-land scritti con DriverKit/System Extensions **riducono drasticamente la attack surface**, perché i crash o la corruzione della memoria rimangono confinati a un processo in sandbox invece che nello spazio del kernel.<sup>[1]</sup>

> 📝 A partire da macOS Sequoia (15), Apple ha rimosso completamente diversi KPI legacy per il networking e l'USB: l'unica soluzione compatibile con il futuro per i vendor è migrare alle System Extensions.

### Requisiti

Ovviamente, questa funzionalità è così potente che **caricare una kernel extension è complicato**. Questi sono i **requisiti** che una kernel extension deve soddisfare per essere caricata:

- Quando si **entra in recovery mode**, deve essere consentito il caricamento delle **kernel extensions**:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- La kernel extension deve essere **firmata con un certificato di kernel code signing**, che può essere **rilasciato solo da Apple**, che esaminerà dettagliatamente l'azienda e i motivi per cui è necessario.
- La kernel extension deve inoltre essere **notarized**; Apple potrà verificarla per individuare eventuale malware.
- Quindi, l'utente **root** è colui che può **caricare la kernel extension** e i files all'interno del package devono **appartenere a root**.
- Durante il processo di upload, il package deve essere preparato in una **posizione protetta non-root**: `/Library/StagedExtensions` (richiede il grant `com.apple.rootless.storage.KernelExtensionManagement`).
- Infine, quando si tenta di caricarla, l'utente [**riceverà una richiesta di conferma**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) e, se accettata, il computer dovrà essere **riavviato** per caricarla.

### Processo di caricamento

In Catalina funzionava così: è interessante notare che il processo di **verifica** avviene nello **userland**. Tuttavia, solo le applicazioni con il grant **`com.apple.private.security.kext-management`** possono **richiedere al kernel di caricare un'estensione**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **avvia** il processo di **verifica** per caricare un'estensione
- Comunicherà con **`kextd`** inviando una richiesta tramite un **Mach service**.
2. **`kextd`** verificherà diversi elementi, come la **signature**
- Comunicherà con **`syspolicyd`** per **verificare** se l'estensione può essere **caricata**.
3. **`syspolicyd`** chiederà conferma all'**utente** se l'estensione non è stata caricata in precedenza.
- **`syspolicyd`** comunicherà il risultato a **`kextd`**
4. **`kextd`** potrà infine **comunicare al kernel di caricare** l'estensione

Se **`kextd`** non è disponibile, **`kextutil`** può eseguire gli stessi controlli.

### Enumerazione & gestione (kext caricati)

`kextstat` era lo strumento storico, ma è **deprecated** nelle versioni recenti di macOS. L'interfaccia moderna è **`kmutil`**:
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
`kmutil inspect` può anche essere utilizzato per eseguire il **dump del contenuto di una Kernel Collection (KC)** o verificare che una kext risolva tutte le dipendenze dei simboli:
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> Anche se ci si aspetta che le kernel extensions si trovino in `/System/Library/Extensions/`, accedendo a questa cartella **non troverai alcun binary**. Questo avviene a causa del **kernelcache** e, per effettuare il reverse engineering di una `.kext`, è necessario trovare un modo per ottenerla.

Il **kernelcache** è una versione **pre-compilata e pre-collegata del kernel XNU**, insieme ai **driver** dei dispositivi essenziali e alle **kernel extensions**. È memorizzato in formato **compresso** e viene decompresso in memoria durante il processo di avvio. Il kernelcache consente un **boot time più rapido**, poiché rende disponibile una versione del kernel e dei driver essenziali pronta per l'esecuzione, riducendo il tempo e le risorse che altrimenti verrebbero impiegati per caricare e collegare dinamicamente questi componenti durante l'avvio.

I principali vantaggi del kernelcache sono la **velocità di caricamento** e il fatto che tutti i moduli siano prelinked (nessun impedimento durante il caricamento). Inoltre, una volta che tutti i moduli sono stati prelinked, KXLD può essere rimosso dalla memoria, quindi **XNU non può caricare nuovi KEXT**.

> [!TIP]
> Lo strumento [https://github.com/dhinakg/aeota](https://github.com/dhinakg/aeota) decritta i container AEA (Apple Encrypted Archive / AEA asset) di Apple — il formato dei container cifrati utilizzato da Apple per gli asset OTA e alcune parti degli IPSW — e può produrre l'archivio `.dmg`/asset sottostante, che puoi poi estrarre con gli strumenti aastuff forniti.


### Kernelcache locale

In iOS si trova in **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`**; in macOS puoi trovarlo con: **`find / -name "kernelcache" 2>/dev/null`** \
Nel mio caso, in macOS l'ho trovato in:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

Trova anche qui il [**kernelcache della versione 14 con symbols**](https://x.com/tihmstar/status/1295814618242318337?lang=en).

#### IMG4 / BVX2 (LZFSE) compresso

Il formato IMG4 è un formato container utilizzato da Apple nei suoi dispositivi iOS e macOS per **memorizzare e verificare in modo sicuro i componenti del firmware** (come il **kernelcache**). Il formato IMG4 include un header e diversi tag che incapsulano parti differenti dei dati, tra cui il payload effettivo (come un kernel o un bootloader), una signature e un insieme di proprietà del manifest. Il formato supporta la verifica crittografica, consentendo al dispositivo di confermare l'autenticità e l'integrità del componente firmware prima di eseguirlo.

Di solito è composto dai seguenti componenti:

- **Payload (IM4P)**:
- Spesso compresso (LZFSE4, LZSS, …)
- Facoltativamente cifrato
- **Manifest (IM4M)**:
- Contiene la Signature
- Dizionario aggiuntivo Key/Value
- **Restore Info (IM4R)**:
- Noto anche come APNonce
- Impedisce il replay di alcuni update
- OPZIONALE: di solito non viene trovato

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
#### Disarm symbols for the kernel

**`Disarm`** consente di effettuare il symbolicate delle funzioni dal kernelcache usando i matcher. Questi matcher sono semplici regole di pattern (righe di testo) che indicano a disarm come riconoscere ed eseguire automaticamente il symbolicate di funzioni, argomenti e stringhe di panic/log all'interno di un binary.

In pratica, indichi la stringa utilizzata da una funzione e disarm la troverà ed eseguirà il **symbolicate**.
```bash
You can find some `xnu.matchers` in [https://newosxbook.com/tools/disarm.html](https://newosxbook.com/tools/disarm.html) in the **`Matchers`** section. You can also create your own matchers.

```bash
# Vai a /tmp/extracted dove disarm ha estratto i fileset
disarm -e filesets kernelcache.release.d23 # Estrai sempre in /tmp/extracted
cd /tmp/extracted
JMATCHERS=xnu.matchers disarm --analyze kernel.rebuilt  # Nota che xnu.matchers è in realtà un file con i matcher
```

### Download

An **IPSW (iPhone/iPad Software)** is Apple’s firmware package format used for device restores, updates, and full firmware bundles. Among other things, it contains the **kernelcache**.

- [**KernelDebugKit Github**](https://github.com/dortania/KdkSupportPkg/releases)

In [https://github.com/dortania/KdkSupportPkg/releases](https://github.com/dortania/KdkSupportPkg/releases) it's possible to find all the kernel debug kits. You can download it, mount it, open it with [Suspicious Package](https://www.mothersruin.com/software/SuspiciousPackage/get.html) tool, access the **`.kext`** folder and **extract it**.

Check it for symbols with:

```bash
nm -a ~/Downloads/Sandbox.kext/Contents/MacOS/Sandbox | wc -l
```

- [**theapplewiki.com**](https://theapplewiki.com/wiki/Firmware/Mac/14.x)**,** [**ipsw.me**](https://ipsw.me/)**,** [**theiphonewiki.com**](https://www.theiphonewiki.com/)

Sometime Apple releases **kernelcache** with **symbols**. You can download some firmwares with symbols by following links on those pages. The firmwares will contain the **kernelcache** among other files.

To **extract** the kernel cache you can do:

```bash
# Installare lo strumento ipsw
brew install blacktop/tap/ipsw

# Estrarre solo il kernelcache dall'IPSW
ipsw extract --kernel /path/to/YourFirmware.ipsw -o out/

# Dovresti ottenere qualcosa di simile:
#   out/Firmware/kernelcache.release.iPhoneXX
#   oppure un payload IMG4: out/Firmware/kernelcache.release.iPhoneXX.im4p

# Se ottieni un payload IMG4:
ipsw img4 im4p extract out/Firmware/kernelcache*.im4p -o kcache.raw
```

Another option to **extract** the files start by changing the extension from `.ipsw` to `.zip` and **unzip** it.

After extracting the firmware you will get a file like: **`kernelcache.release.iphone14`**. It's in **IMG4** format, you can extract the interesting info with:

[**pyimg4**](https://github.com/m1stadev/PyIMG4)**:**

```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```

[**img4tool**](https://github.com/tihmstar/img4tool)**:**

```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```

```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```

[**img4tool**](https://github.com/tihmstar/img4tool)**:**

```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```

### Inspecting kernelcache

Check if the kernelcache has symbols with

```bash
nm -a kernelcache.release.iphone14.e | wc -l
```

With this we can now **extract all the extensions** or the **one you are interested in:**

```bash
# Elenca tutte le estensioni
kextex -l kernelcache.release.iphone14.e
## Estrai com.apple.security.sandbox
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# Estrai tutto
kextex_all kernelcache.release.iphone14.e

# Controlla i simboli dell'estensione
nm -a binaries/com.apple.security.sandbox | wc -l
```


## Recent vulnerabilities & exploitation techniques

| Year | CVE | Summary |
|------|-----|---------|
| 2024 | **CVE-2024-44243** | Logic flaw in **`storagekitd`** allowed a *root* attacker to register a malicious file-system bundle that ultimately loaded an **unsigned kext**, **bypassing System Integrity Protection (SIP)** and enabling persistent rootkits. Patched in macOS 14.2 / 15.2.   |
| 2021 | **CVE-2021-30892** (*Shrootless*) | Installation daemon with the entitlement `com.apple.rootless.install` could be abused to execute arbitrary post-install scripts, disable SIP and load arbitrary kexts.  |

**Take-aways for red-teamers**

1. **Look for entitled daemons (`codesign -dvv /path/bin | grep entitlements`) that interact with Disk Arbitration, Installer or Kext Management.**
2. **Abusing SIP bypasses almost always grants the ability to load a kext → kernel code execution**.

**Defensive tips**

*Keep SIP enabled*, monitor for `kmutil load`/`kmutil create -n aux` invocations coming from non-Apple binaries and alert on any write to `/Library/Extensions`. Endpoint Security events `ES_EVENT_TYPE_NOTIFY_KEXTLOAD` provide near real-time visibility.

## Debugging macOS kernel & kexts

Apple’s recommended workflow is to build a **Kernel Debug Kit (KDK)** that matches the running build and then attach **LLDB** over a **KDP (Kernel Debugging Protocol)** network session.

### One-shot local debug of a panic

```bash
# Crea un bundle di symbolication per il panic più recente
sudo kdpwrit dump latest.kcdata
kmutil analyze-panic latest.kcdata -o ~/panic_report.txt
```

### Live remote debugging from another Mac

1. Download + install the exact **KDK** version for the target machine.
2. Connect the target Mac and the host Mac with a **USB-C or Thunderbolt cable**.
3. On the **target**:

```bash
sudo nvram boot-args="debug=0x100 kdp_match_name=macbook-target"
reboot
```

4. On the **host**:

```bash
lldb
(lldb) kdp-remote "udp://macbook-target"
(lldb) bt  # get backtrace in kernel context
```

### Attaching LLDB to a specific loaded kext

```bash
# Identify load address of the kext
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# Attach
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```

> ℹ️  KDP only exposes a **read-only** interface. For dynamic instrumentation you will need to patch the binary on-disk, leverage **kernel function hooking** (e.g. `mach_override`) or migrate the driver to a **hypervisor** for full read/write.

## References

- [1] [DriverKit security for macOS - Apple Platform Security Guide](https://support.apple.com/guide/security/driverkit-security-seca48c92d43/web)
- [2] [Analyzing CVE-2024-44243, a macOS System Integrity Protection bypass through kernel extensions - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)

{{#include ../../../banners/hacktricks-training.md}}
