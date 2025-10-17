# Estensioni del kernel macOS & Kernelcaches

{{#include ../../../banners/hacktricks-training.md}}

## Informazioni di base

Kernel extensions (Kexts) sono **pacchetti** con una **`.kext`** extension che vengono **caricati direttamente nello spazio kernel di macOS**, fornendo funzionalità aggiuntive al sistema operativo principale.

### Stato di deprecazione & DriverKit / System Extensions
A partire da **macOS Catalina (10.15)** Apple ha contrassegnato la maggior parte delle KPI legacy come *deprecated* e ha introdotto i framework **System Extensions & DriverKit** che vengono eseguiti in **user-space**. Da **macOS Big Sur (11)** il sistema operativo *rifiuterà di caricare* kext di terze parti che si basano su KPI deprecate a meno che la macchina non venga avviata in modalità **Reduced Security**. Su Apple Silicon, abilitare i kext richiede inoltre all'utente di:

1. Riavviare in **Recovery** → *Startup Security Utility*.
2. Selezionare **Reduced Security** e spuntare **“Allow user management of kernel extensions from identified developers”**.
3. Riavviare e approvare il kext da **System Settings → Privacy & Security**.

I driver in user-land scritti con DriverKit/System Extensions riducono drasticamente l'attack surface perché crash o corruzione della memoria sono confinati a un processo sandboxato anziché nello spazio kernel.

> 📝 Da macOS Sequoia (15) Apple ha rimosso completamente diverse KPI legacy per networking e USB – l'unica soluzione forward-compatible per i vendor è migrare a System Extensions.

### Requisiti

Ovviamente, questo è così potente che è **complicato caricare una kernel extension**. Questi sono i **requisiti** che una kernel extension deve soddisfare per essere caricata:

- Quando si **entra in recovery mode**, le kernel **extensions devono essere consentite** per essere caricate:

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- La kernel extension deve essere **signed with a kernel code signing certificate**, che può essere concessa solo da Apple. Apple esaminerà in dettaglio l'azienda e le ragioni per cui è necessaria.
- La kernel extension deve inoltre essere **notarized**, Apple potrà verificarla per malware.
- Poi, l'utente **root** è colui che può **load the kernel extension** e i file all'interno del package devono **appartenere a root**.
- Durante il processo di upload, il package deve essere preparato in una **protected non-root location**: `/Library/StagedExtensions` (richiede il grant `com.apple.rootless.storage.KernelExtensionManagement`).
- Infine, quando si tenta di caricarla, l'utente [**riceverà una richiesta di conferma**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) e, se accettata, il computer deve essere **riavviato** per caricarla.

### Processo di caricamento

In Catalina era così: è interessante notare che il processo di **verification** avviene in **userland**. Tuttavia, solo le applicazioni con il grant **`com.apple.private.security.kext-management`** possono **request the kernel to load an extension**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** CLI **avvia** il processo di **verification** per il caricamento di un'estensione
- Comunica con **`kextd`** inviando una richiesta tramite un **Mach service**.
2. **`kextd`** controllerà diverse cose, come la **signature**
- Comunicherà con **`syspolicyd`** per **verificare** se l'estensione può essere **caricata**.
3. **`syspolicyd`** mostrerà una **prompt** all'**utente** se l'estensione non è stata precedentemente caricata.
- **`syspolicyd`** riporterà il risultato a **`kextd`**
4. **`kextd`** infine potrà **dire al kernel di caricare** l'estensione

Se **`kextd`** non è disponibile, **`kextutil`** può eseguire gli stessi controlli.

### Enumerazione & gestione (loaded kexts)

`kextstat` era lo strumento storico ma è **deprecato** nelle recenti release di macOS. L'interfaccia moderna è **`kmutil`**:
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
`kmutil inspect` può anche essere utilizzato per **eseguire il dump del contenuto di una Kernel Collection (KC)** o verificare che un kext risolva tutte le dipendenze dei simboli:
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> Anche se le kernel extensions dovrebbero trovarsi in `/System/Library/Extensions/`, se vai in questa cartella **non troverai alcun binario**. Questo è dovuto al **kernelcache** e per effettuare il reverse engineering di un `.kext` devi trovare un modo per ottenerlo.

Il **kernelcache** è una **versione pre-compilata e pre-collegata del kernel XNU**, insieme ai **drivers** essenziali del dispositivo e alle **kernel extensions**. Viene memorizzato in un formato **compresso** e viene decompresso in memoria durante il processo di boot. Il kernelcache favorisce un **tempo di avvio più rapido** disponendo di una versione del kernel e dei driver critici pronta all'esecuzione, riducendo il tempo e le risorse che altrimenti sarebbero spese per caricare e linkare dinamicamente questi componenti all'avvio.

I principali vantaggi del kernelcache sono la **velocità di caricamento** e il fatto che tutti i moduli siano prelinkati (nessun impedimento per il tempo di caricamento). Inoltre, una volta che tutti i moduli sono stati prelinkati, KXLD può essere rimosso dalla memoria così **XNU non può caricare nuovi KEXTs.**

> [!TIP]
> Lo strumento [https://github.com/dhinakg/aeota](https://github.com/dhinakg/aeota) decripta i contenitori AEA (Apple Encrypted Archive / AEA asset) di Apple — il formato di container criptato che Apple usa per gli asset OTA e alcuni pezzi di IPSW — e può produrre il .dmg/asset sottostante che puoi poi estrarre con gli strumenti aastuff forniti.


### Kernelcache locale

In iOS si trova in **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`**; in macOS puoi trovarlo con: **`find / -name "kernelcache" 2>/dev/null`** \
Nel mio caso su macOS l'ho trovato in:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

Trovi anche qui il [**kernelcache della versione 14 con simboli**](https://x.com/tihmstar/status/1295814618242318337?lang=en).

#### IMG4 / BVX2 (LZFSE) compresso

Il formato di file IMG4 è un formato contenitore usato da Apple nei suoi dispositivi iOS e macOS per memorizzare e verificare in modo sicuro i componenti firmware (come il kernelcache). Il formato IMG4 include un header e diversi tag che incapsulano differenti pezzi di dati, inclusa la payload effettiva (come un kernel o un bootloader), una firma e un insieme di proprietà del manifest. Il formato supporta la verifica crittografica, permettendo al dispositivo di confermare l'autenticità e l'integrità del componente firmware prima di eseguirlo.

Generalmente è composto dai seguenti componenti:

- **Payload (IM4P)**:
- Spesso compresso (LZFSE4, LZSS, …)
- Opzionalmente criptato
- **Manifest (IM4M)**:
- Contiene la Signature
- Dizionario aggiuntivo Key/Value
- **Restore Info (IM4R)**:
- Conosciuto anche come APNonce
- Previene il replay di alcuni aggiornamenti
- OPTIONAL: Solitamente questo non è presente

Decomprimere il kernelcache:
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
#### Disarm simboli per il kernel

**`Disarm`** permette di symbolicate le funzioni dal kernelcache usando i matchers.

Questi matchers sono semplici regole di pattern (righe di testo) che indicano a disarm come riconoscere e auto-symbolicate funzioni, argomenti e panic/log strings all'interno di un binario.

Quindi, praticamente indichi la stringa che una funzione usa e disarm la troverà e **symbolicate it**.
```bash
You can find some `xnu.matchers` in [https://newosxbook.com/tools/disarm.html](https://newosxbook.com/tools/disarm.html) in the **`Matchers`** section. You can also create your own matchers.

```bash
# Vai in /tmp/extracted dove disarm ha estratto i filesets
disarm -e filesets kernelcache.release.d23 # Always extract to /tmp/extracted
cd /tmp/extracted
JMATCHERS=xnu.matchers disarm --analyze kernel.rebuilt  # Note that xnu.matchers is actually a file with the matchers
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

# Controlla l'estensione per simboli
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
# Crea un bundle di simbolicazione per l'ultimo panic
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
(lldb) bt  # ottieni backtrace nel contesto kernel
```

### Attaching LLDB to a specific loaded kext

```bash
# Identificare l'indirizzo di caricamento del kext
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# Collegare
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```

> ℹ️  KDP only exposes a **read-only** interface. For dynamic instrumentation you will need to patch the binary on-disk, leverage **kernel function hooking** (e.g. `mach_override`) or migrate the driver to a **hypervisor** for full read/write.

## References

- DriverKit Security – Apple Platform Security Guide
- Microsoft Security Blog – *Analyzing CVE-2024-44243 SIP bypass*

{{#include ../../../banners/hacktricks-training.md}}
