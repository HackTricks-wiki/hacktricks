# Kernel e System Extensions di macOS

{{#include ../../../banners/hacktricks-training.md}}

## Kernel XNU

Il **core di macOS è XNU**, acronimo di "X is Not Unix". Questo kernel è composto fondamentalmente dal **microkernel Mach** (che verrà illustrato più avanti) **e** da elementi della Berkeley Software Distribution (**BSD**). XNU fornisce inoltre una piattaforma per i **kernel drivers tramite un sistema chiamato I/O Kit**. Il kernel XNU fa parte del progetto open source Darwin, il che significa che **il suo codice sorgente è liberamente accessibile**.

Dal punto di vista di un security researcher o di uno sviluppatore Unix, **macOS** può sembrare molto **simile** a un sistema **FreeBSD** con una GUI elegante e numerose applicazioni personalizzate. La maggior parte delle applicazioni sviluppate per BSD può essere compilata ed eseguita su macOS senza modifiche, poiché tutti i command-line tools familiari agli utenti Unix sono presenti in macOS. Tuttavia, poiché il kernel XNU integra Mach, esistono alcune differenze significative tra un sistema tradizionale Unix-like e macOS, e queste differenze possono causare potenziali problemi oppure offrire vantaggi unici.

Versione open source di XNU: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach è un **microkernel** progettato per essere **compatibile con UNIX**. Uno dei suoi principali principi di progettazione consisteva nel **minimizzare** la quantità di **codice** in esecuzione nello spazio del **kernel**, consentendo invece a molte funzioni tipiche del kernel, come file system, networking e I/O, di **essere eseguite come user-level tasks**.

In XNU, Mach è **responsabile di molte operazioni critiche a basso livello** normalmente gestite da un kernel, come lo scheduling del processore, il multitasking e la gestione della memoria virtuale.

### BSD

Il **kernel** XNU **incorpora** inoltre una quantità significativa di codice derivato dal progetto **FreeBSD**. Questo codice **viene eseguito come parte del kernel insieme a Mach**, nello stesso spazio degli indirizzi. Tuttavia, il codice FreeBSD all'interno di XNU può differire sostanzialmente dal codice FreeBSD originale, poiché sono state necessarie modifiche per garantirne la compatibilità con Mach. FreeBSD contribuisce a molte operazioni del kernel, tra cui:

- Gestione dei processi
- Gestione dei signal
- Meccanismi di sicurezza di base, inclusa la gestione di utenti e gruppi
- Infrastruttura delle system call
- Stack TCP/IP e socket
- Firewall e packet filtering

Comprendere l'interazione tra BSD e Mach può essere complesso, a causa dei loro diversi framework concettuali. Ad esempio, BSD utilizza i processi come unità fondamentale di esecuzione, mentre Mach opera sulla base dei thread. Questa discrepanza viene risolta in XNU **associando ogni processo BSD a un task Mach** che contiene esattamente un thread Mach. Quando viene utilizzata la system call fork() di BSD, il codice BSD all'interno del kernel usa funzioni Mach per creare una struttura task e una struttura thread.

Inoltre, **Mach e BSD mantengono modelli di sicurezza differenti**: il modello di sicurezza di **Mach** si basa sui **port rights**, mentre il modello di sicurezza di BSD si basa sulla **proprietà dei processi**. Le disparità tra questi due modelli hanno occasionalmente causato vulnerabilità di local privilege escalation. Oltre alle system call tipiche, esistono anche **Mach traps che consentono ai programmi user-space di interagire con il kernel**. Questi diversi elementi formano insieme l'architettura multifacetica e ibrida del kernel di macOS.<sup>[[1]](#references)</sup>

### I/O Kit - Drivers

I/O Kit è un **framework per device drivers** open source e object-oriented del kernel XNU, che gestisce i **device drivers caricati dinamicamente**. Consente di aggiungere codice modulare al kernel on-the-fly, supportando hardware diversi.


{{#ref}}
macos-iokit.md
{{#endref}}

### Coprocessori nell'architettura di macOS

Le piattaforme Apple si affidano a diversi coprocessori per mantenere il lavoro sensibile alla latenza lontano dai core principali e isolare le funzioni critiche per la sicurezza.

- **Secure Enclave Processor (SEP)**: un core ARM dedicato con il proprio microkernel e la propria catena di secure boot, normalmente in esecuzione a **EL3/secure world**. L'interazione avviene tramite mailbox drivers in macOS a EL1.
- Superficie d'attacco: gli aggiornamenti del firmware SEP e i daemon user-space (`seputil`, `securityd`) che fanno da proxy per le richieste.
- Impatto della compromissione: Leak di chiavi a lungo termine, bypass dei controlli biometrici e compromissione delle protezioni di FileVault o Apple Pay.
- **System Management Controller (SMC)**: esegue firmware proprietario su un microcontroller esterno ai livelli di eccezione ARM. macOS (EL1) vi accede tramite user clients di I/O Kit.
- Superficie d'attacco: messaggi USB-C power delivery, interfacce per la gestione di ventole e batteria e percorsi di aggiornamento del firmware.
- Impatto della compromissione: sovrascrivere i limiti termici, iniettare dati falsi dei sensori, interrompere l'alimentazione o installare backdoor persistenti in NVRAM.
- **T1/T2 Security Chips**: eseguono bridgeOS (derivato da watchOS) principalmente a EL1/EL3 sui propri core ARM. macOS comunica tramite canali simili a PCIe/USB mediati da IOKit.
- Superficie d'attacco: percorsi DFU/restore, endpoint IPC esposti da servizi come `tccd` e pipeline multimediali collegate al T2.
- Impatto della compromissione: disabilitare il secure boot, decrittografare il contenuto dell'SSD, dirottare i controlli di accesso a camera/microfono o emulare input HID per una persistenza furtiva.
- **Display Coprocessor (DCP)**: esegue firmware a EL1 all'interno di uno spazio degli indirizzi isolato e protetto da DART (l'IOMMU di Apple).
- Superficie d'attacco: interfacce `DCPAVService`, shared descriptor buffers e parsing delle immagini del firmware.
- Impatto della compromissione: iniettare frame arbitrari, intercettare i framebuffer o rendere inutilizzabile la pipeline del display per causare un DoS.
- **Apple Neural Engine (ANE)**: esegue microcode su un cluster ML dedicato (senza livelli ARM EL). macOS pianifica il lavoro tramite `ANECompilerService` e IOKit.
- Superficie d'attacco: binari dei modelli compilati (`.ane`), API Core ML che alimentano custom kernels e firmware loaders.
- Impatto della compromissione: alterare o esfiltrare modelli ML, fare leak di dati audio/video elaborati o sabotare l'inferenza on-device.
- **AGX GPU**: il firmware viene eseguito su core GPU personalizzati con uno scheduler; EL0 invia comandi Metal che EL1 convalida.
- Superficie d'attacco: Metal shader compiler, API di mapping dei shared buffer e interfacce ioctl `com.apple.AGXFirmware`.
- Impatto della compromissione: accesso DMA alla memoria di sistema, sandbox escapes tramite i GPU drivers o impianti persistenti nel firmware.
- **Apple Video Encoder (AVE)**: il firmware viene eseguito sul Media Engine in un sandbox simile a EL1. macOS interagisce tramite VideoToolbox e `AppleAVE2`.
- Superficie d'attacco: codec bitstreams, parameter sets, buffer forniti dall'utente e firmware update blobs.
- Impatto della compromissione: Leak di frame non compressi, bypass del DRM o ottenimento di code execution con accesso ai DMA engines.
- **Image Signal Processor (ISP)**: esegue secure firmware nel cluster Media Engine; i camera drivers di macOS operano a EL1.
- Superficie d'attacco: camera HAL, descrittori dei frame RAW, code di configurazione dell'ISP e aggiornamenti del firmware.
- Impatto della compromissione: acquisire silenziosamente i feed RAW della camera, disabilitare gli indicatori di privacy o iniettare immagini contraffatte.
- **AMX Matrix cores**: operano come unità coprocessor esposte a EL0/EL1 tramite nuove istruzioni.
- Superficie d'attacco: virtualizzazione dello stato AMX da parte del kernel (`thread_set_state`, context switches) e generazione di codice user-space.
- Impatto della compromissione: Leak dei tile registers di altri processi, fingerprinting dei workload o escalation tramite corruzione della memoria del kernel.

Il macOS moderno considera questi coprocessori componenti trusted nella catena di trust. Il firmware di SEP, SMC e T2 è firmato da Apple e i protocolli di handshake (spesso implementati tramite mailbox o famiglie I/O Kit) includono controlli challenge-response, in modo che solo firmware autenticato possa gestire le richieste.

### IPC - Comunicazione tra processi

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/
{{#endref}}

## Kernel Extensions di macOS

macOS è **estremamente restrittivo nel caricamento delle Kernel Extensions** (.kext), a causa degli elevati privilegi con cui verrà eseguito il codice. In pratica, per impostazione predefinita è virtualmente impossibile (a meno di trovare un bypass).

Nella pagina seguente puoi anche vedere come recuperare la `.kext` caricata da macOS all'interno del suo **kernelcache**:

{{#ref}}
macos-kernel-extensions.md
{{#endref}}

### System Extensions di macOS

Invece di utilizzare le Kernel Extensions, macOS ha creato le System Extensions, che offrono API user-level per interagire con il kernel. In questo modo, gli sviluppatori possono evitare di utilizzare le kernel extensions.

{{#ref}}
macos-system-extensions.md
{{#endref}}


### Cryptexes e RSR (Rapid Security Response)

- **Cryptex** sta per **CRYPTographically-sealed EXtension**. È un'immagine disco sealed (container) utilizzata da Apple per ospitare parti del sistema operativo (framework, shared libraries, app) che hanno maggiori probabilità di cambiare tra gli aggiornamenti principali del sistema operativo.
- Su macOS e iOS, i componenti inseriti nei cryptex possono essere **patchati o sostituiti** tramite RSR senza dover sigillare nuovamente l'intero volume di sistema.
- I cryptex risiedono nel volume **Preboot**, insieme al boot firmware, e vengono grafted nel file system del sistema operativo a runtime.
- Il caricamento del contenuto dei cryptex comporta una validazione: il sistema controlla i file seal, i manifest e gli hash root, quindi monta o “grafta” il contenuto del cryptex, in modo che a runtime le app utilizzino le versioni del cryptex, quando presenti.
- Nei boot log, il caricamento dei cryptex avviene dopo l'inizializzazione del kernel ma prima dell'avvio completo dei system services.


#### Rapid Security Response (RSR)

- **RSR** è il meccanismo di Apple per distribuire **security patch tra gli aggiornamenti regolari del sistema operativo**. È destinato al contenuto dei cryptex per aggiornare le parti vulnerabili (ad esempio librerie e framework) senza modificare il core system volume.
- Quando viene applicato un aggiornamento RSR, il dispositivo richiede al signing server di Apple un **manifest Cryptex1 Image4**. Questo manifest è legato crittograficamente al dispositivo e al nuovo contenuto del cryptex.
- L'AP boot ticket esistente per il sistema base **non viene modificato** da RSR. La patch opera in modo additivo sul base OS sealed.
- Su macOS, alcuni componenti patchati (ad esempio Safari) diventano attivi non appena l'app viene riavviata; non è sempre necessario un riavvio completo del sistema.
- Gli RSR sono **rimovibili**: ciascuno include una patch e un “antipatch” in grado di effettuare il rollback alla versione del base OS. Durante la rimozione, il contenuto del cryptex viene ripristinato.
- Gli aggiornamenti RSR sono generalmente molto più piccoli degli aggiornamenti completi del sistema operativo e richiedono un livello della batteria inferiore per l'installazione.


## Riferimenti

- [1] [The Mac Hacker's Handbook](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [2] [The Art of Mac Malware, Vol. 1 — Analysis](https://taomm.org/vol1/analysis.html)

{{#include ../../../banners/hacktricks-training.md}}
