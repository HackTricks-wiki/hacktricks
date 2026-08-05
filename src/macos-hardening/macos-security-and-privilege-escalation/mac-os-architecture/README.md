# Kernel e System Extensions di macOS

{{#include ../../../banners/hacktricks-training.md}}

## Kernel XNU

Il **cuore di macOS è XNU**, acronimo di "X is Not Unix". Questo kernel è fondamentalmente composto dal **microkernel Mach** (che verrà trattato più avanti), **e** da elementi della Berkeley Software Distribution (**BSD**). XNU fornisce inoltre una piattaforma per i **kernel driver tramite un sistema chiamato I/O Kit**. Il kernel XNU fa parte del progetto open source Darwin, il che significa che **il suo codice sorgente è liberamente accessibile**.

Dal punto di vista di un security researcher o di uno sviluppatore Unix, **macOS** può sembrare piuttosto **simile** a un sistema **FreeBSD** con una GUI elegante e numerose applicazioni personalizzate. La maggior parte delle applicazioni sviluppate per BSD può essere compilata ed eseguita su macOS senza modifiche, poiché tutti i command-line tools familiari agli utenti Unix sono presenti in macOS. Tuttavia, poiché il kernel XNU integra Mach, esistono alcune differenze significative tra un sistema tradizionale Unix-like e macOS, e queste differenze possono causare potenziali problemi o offrire vantaggi unici.

Versione open source di XNU: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach è un **microkernel** progettato per essere **compatibile con UNIX**. Uno dei suoi principali principi di progettazione era **ridurre al minimo** la quantità di **codice** in esecuzione nello spazio **kernel**, consentendo invece a molte funzioni tipiche del kernel, come file system, networking e I/O, di **essere eseguite come task a livello utente**.

In XNU, Mach è **responsabile di molte operazioni critiche a basso livello** normalmente gestite da un kernel, come lo scheduling del processore, il multitasking e la gestione della memoria virtuale.

### BSD

Il **kernel** XNU **incorpora** anche una quantità significativa di codice derivato dal progetto **FreeBSD**. Questo codice **viene eseguito come parte del kernel insieme a Mach**, nello stesso spazio degli indirizzi. Tuttavia, il codice FreeBSD incluso in XNU può differire sostanzialmente dal codice FreeBSD originale, poiché sono state necessarie modifiche per garantirne la compatibilità con Mach. FreeBSD contribuisce a numerose operazioni del kernel, tra cui:

- Gestione dei processi
- Gestione dei signal
- Meccanismi di sicurezza di base, inclusa la gestione di utenti e gruppi
- Infrastruttura delle system call
- Stack TCP/IP e socket
- Firewall e packet filtering

Comprendere l'interazione tra BSD e Mach può essere complesso, a causa dei loro diversi framework concettuali. Ad esempio, BSD utilizza i processi come unità fondamentale di esecuzione, mentre Mach opera basandosi sui thread. Questa discrepanza viene risolta in XNU **associando ogni processo BSD a un task Mach** che contiene esattamente un thread Mach. Quando viene utilizzata la system call fork() di BSD, il codice BSD all'interno del kernel usa funzioni Mach per creare una struttura task e una struttura thread.

Inoltre, **Mach e BSD mantengono modelli di sicurezza differenti**: il modello di sicurezza di **Mach** si basa sui **port rights**, mentre quello di BSD si basa sulla **proprietà dei processi**. Le disparità tra questi due modelli hanno occasionalmente causato vulnerabilità di local privilege escalation. Oltre alle system call tradizionali, esistono anche **Mach traps che consentono ai programmi user-space di interagire con il kernel**. Questi diversi elementi formano insieme l'architettura multifaccettata e ibrida del kernel di macOS.

### I/O Kit - Drivers

I/O Kit è un **framework object-oriented per i device driver** open source del kernel XNU e gestisce i **device driver caricati dinamicamente**. Consente di aggiungere codice modulare al kernel on-the-fly, supportando hardware diversi.


{{#ref}}
macos-iokit.md
{{#endref}}

### Coprocessori nell'architettura di macOS

Le piattaforme Apple utilizzano diversi coprocessori per mantenere il lavoro sensibile alla latenza al di fuori dei core principali e isolare le funzioni critiche per la sicurezza.

- **Secure Enclave Processor (SEP)**: un core ARM dedicato con un proprio microkernel e una propria catena di secure boot, generalmente in esecuzione a **EL3/secure world**. L'interazione avviene tramite mailbox driver in macOS a EL1.
- Attack surface: aggiornamenti del firmware SEP e i demoni user-space (`seputil`, `securityd`) che fanno da proxy per le richieste.
- Impact of compromise: leak di chiavi a lungo termine, bypass del controllo biometrico e compromissione delle protezioni di FileVault o Apple Pay.
- **System Management Controller (SMC)**: esegue firmware proprietario su un microcontroller esterno ai livelli di eccezione ARM. macOS (EL1) lo raggiunge tramite user client di I/O Kit.
- Attack surface: messaggi USB-C power delivery, interfacce per la gestione di ventole/batteria e percorsi di aggiornamento del firmware.
- Impact of compromise: override dei limiti termici, injection di dati falsi dei sensori, interruzione dell'alimentazione o installazione di persistent NVRAM backdoor.
- **T1/T2 Security Chips**: eseguono bridgeOS (derivato da watchOS) principalmente a EL1/EL3 sui propri core ARM. macOS comunica tramite canali simili a PCIe/USB mediati da IOKit.
- Attack surface: percorsi DFU/restore, endpoint IPC esposti da servizi come `tccd` e pipeline multimediali collegate al T2.
- Impact of compromise: disabilitazione del secure boot, decrittazione dei contenuti SSD, hijacking del controllo di camera/microfono o emulazione di input HID per una persistenza stealth.
- **Display Coprocessor (DCP)**: esegue firmware a EL1 all'interno di uno spazio degli indirizzi isolato e protetto da DART (IOMMU di Apple).
- Attack surface: interfacce `DCPAVService`, shared descriptor buffer e parsing delle immagini firmware.
- Impact of compromise: injection di frame arbitrari, snooping dei framebuffer o brick della pipeline del display per causare un DoS.
- **Apple Neural Engine (ANE)**: esegue microcode su un cluster ML dedicato (senza livelli ARM EL). macOS pianifica il lavoro tramite `ANECompilerService` e IOKit.
- Attack surface: binari dei modelli compilati (`.ane`), API Core ML che alimentano kernel personalizzati e firmware loader.
- Impact of compromise: manomissione o exfiltration dei modelli ML, leak di dati audio/video elaborati o sabotaggio dell'inferenza on-device.
- **GPU AGX**: il firmware viene eseguito su core GPU personalizzati con uno scheduler; EL0 invia comandi Metal che EL1 valida.
- Attack surface: compilatore di shader Metal, API di shared buffer mapping e interfacce ioctl `com.apple.AGXFirmware`.
- Impact of compromise: accesso DMA alla memoria di sistema, sandbox escapes tramite i GPU driver o persistent firmware implant.
- **Apple Video Encoder (AVE)**: il firmware viene eseguito sul Media Engine in un sandbox simile a EL1. macOS interagisce tramite VideoToolbox e `AppleAVE2`.
- Attack surface: codec bitstream, parameter set, buffer forniti dall'utente e blob di aggiornamento del firmware.
- Impact of compromise: leak di frame non compressi, bypass del DRM o code execution con accesso ai DMA engine.
- **Image Signal Processor (ISP)**: esegue firmware sicuro nel cluster Media Engine; i camera driver di macOS operano a EL1.
- Attack surface: camera HAL, descrittori dei frame RAW, code di configurazione ISP e aggiornamenti del firmware.
- Impact of compromise: acquisizione silenziosa dei feed della camera, disabilitazione degli indicatori di privacy o injection di immagini contraffatte.
- **Core AMX**: operano come unità coprocessor esposte a EL0/EL1 tramite nuove istruzioni.
- Attack surface: virtualizzazione kernel dello stato AMX (`thread_set_state`, context switch) e generazione di codice user-space.
- Impact of compromise: leak dei tile register di altri processi, fingerprinting dei workload o escalation tramite corruzione della memoria del kernel.

Il macOS moderno tratta questi coprocessori come componenti trusted nella chain of trust. Il firmware di SEP, SMC e T2 è firmato da Apple, e i protocolli di handshake (spesso implementati tramite mailbox o famiglie I/O Kit) includono controlli challenge-response, così che solo il firmware autenticato possa gestire le richieste.

### IPC - Inter Process Communication

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/
{{#endref}}

## Kernel Extensions di macOS

macOS è **estremamente restrittivo nel caricamento delle Kernel Extensions** (.kext), a causa degli elevati privilegi con cui verrà eseguito il codice. In effetti, per impostazione predefinita è praticamente impossibile (a meno che non venga trovato un bypass).

Nella pagina seguente puoi anche vedere come recuperare la `.kext` caricata da macOS all'interno del suo **kernelcache**:

{{#ref}}
macos-kernel-extensions.md
{{#endref}}

### System Extensions di macOS

Invece di utilizzare le Kernel Extensions, macOS ha creato le System Extensions, che offrono API a livello utente per interagire con il kernel. In questo modo, gli sviluppatori possono evitare di utilizzare le kernel extensions.

{{#ref}}
macos-system-extensions.md
{{#endref}}


### Cryptex e RSR (Rapid Security Response)

- **Cryptex** significa **CRYPTographically-sealed EXtension**. È un'immagine disco sigillata (container) utilizzata da Apple per ospitare parti dell'OS (framework, shared library, app) che hanno maggiori probabilità di cambiare tra gli aggiornamenti principali dell'OS.
- Su macOS e iOS, i componenti inseriti nei cryptex possono essere **patchati o sostituiti** tramite RSR senza dover sigillare nuovamente l'intero volume di sistema.
- I cryptex risiedono nel volume **Preboot**, insieme al boot firmware, e vengono grafted nel file system dell'OS a runtime.
- Il caricamento del contenuto dei cryptex comporta una validazione: il sistema controlla i file seal, i manifest e gli hash root, quindi monta o “grafta” il contenuto del cryptex, in modo che a runtime le app utilizzino le versioni del cryptex quando presenti.
- Nei log di boot, il caricamento dei cryptex avviene dopo l'inizializzazione del kernel, ma prima che tutti i system service siano attivi.


#### Rapid Security Response (RSR)

- **RSR** è il meccanismo di Apple per distribuire **security patch tra gli aggiornamenti regolari dell'OS**. Utilizza il contenuto dei cryptex per aggiornare le parti vulnerabili (ad esempio librerie e framework) senza modificare il core system volume.
- Quando applica un aggiornamento RSR, il dispositivo richiede al signing server di Apple un manifest **Cryptex1 Image4**. Questo manifest è associato crittograficamente al dispositivo e al nuovo contenuto del cryptex.
- L'AP boot ticket esistente per il sistema base **non viene modificato** da RSR. La patch opera in modo additivo sul base OS sigillato.
- Su macOS, alcuni componenti patchati (ad esempio Safari) diventano attivi non appena l'app viene rilanciata; non è sempre necessario un riavvio completo del sistema.
- Gli RSR sono **rimovibili**: ciascuno include una patch e un “antipatch” che può ripristinare la versione del base OS. Durante la rimozione, il contenuto del cryptex viene ripristinato.
- Gli aggiornamenti RSR sono generalmente molto più piccoli degli aggiornamenti completi dell'OS e richiedono un livello di batteria inferiore per l'installazione.


## Riferimenti

- [1] [The Mac Hacker's Handbook](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [2] [The Art of Mac Malware, Vol. 1 — Analysis](https://taomm.org/vol1/analysis.html)

{{#include ../../../banners/hacktricks-training.md}}
