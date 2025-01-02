# macOS Kernel & System Extensions

{{#include ../../../banners/hacktricks-training.md}}

## XNU Kernel

Il **nucleo di macOS è XNU**, che sta per "X is Not Unix". Questo kernel è fondamentalmente composto dal **microkernel Mach** (di cui si parlerà più avanti), **e** elementi dalla Berkeley Software Distribution (**BSD**). XNU fornisce anche una piattaforma per **driver del kernel tramite un sistema chiamato I/O Kit**. Il kernel XNU fa parte del progetto open source Darwin, il che significa che **il suo codice sorgente è liberamente accessibile**.

Dal punto di vista di un ricercatore di sicurezza o di uno sviluppatore Unix, **macOS** può sembrare piuttosto **simile** a un sistema **FreeBSD** con un'interfaccia grafica elegante e una serie di applicazioni personalizzate. La maggior parte delle applicazioni sviluppate per BSD si compileranno e funzioneranno su macOS senza necessitare di modifiche, poiché gli strumenti da riga di comando familiari agli utenti Unix sono tutti presenti in macOS. Tuttavia, poiché il kernel XNU incorpora Mach, ci sono alcune differenze significative tra un sistema tradizionale simile a Unix e macOS, e queste differenze potrebbero causare problemi potenziali o fornire vantaggi unici.

Versione open source di XNU: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach è un **microkernel** progettato per essere **compatibile con UNIX**. Uno dei suoi principi di design chiave era **minimizzare** la quantità di **codice** in esecuzione nello **spazio del kernel** e invece consentire a molte funzioni tipiche del kernel, come il file system, il networking e l'I/O, di **eseguire come attività a livello utente**.

In XNU, Mach è **responsabile di molte delle operazioni critiche a basso livello** che un kernel gestisce tipicamente, come la pianificazione dei processori, il multitasking e la gestione della memoria virtuale.

### BSD

Il **kernel** XNU **incorpora** anche una quantità significativa di codice derivato dal progetto **FreeBSD**. Questo codice **funziona come parte del kernel insieme a Mach**, nello stesso spazio di indirizzamento. Tuttavia, il codice FreeBSD all'interno di XNU può differire sostanzialmente dal codice FreeBSD originale perché sono state necessarie modifiche per garantire la sua compatibilità con Mach. FreeBSD contribuisce a molte operazioni del kernel, tra cui:

- Gestione dei processi
- Gestione dei segnali
- Meccanismi di sicurezza di base, inclusa la gestione di utenti e gruppi
- Infrastruttura delle chiamate di sistema
- Stack TCP/IP e socket
- Firewall e filtraggio dei pacchetti

Comprendere l'interazione tra BSD e Mach può essere complesso, a causa dei loro diversi quadri concettuali. Ad esempio, BSD utilizza i processi come unità fondamentale di esecuzione, mentre Mach opera basandosi sui thread. Questa discrepanza è riconciliata in XNU **associando ogni processo BSD a un'attività Mach** che contiene esattamente un thread Mach. Quando viene utilizzata la chiamata di sistema fork() di BSD, il codice BSD all'interno del kernel utilizza le funzioni Mach per creare una struttura di attività e thread.

Inoltre, **Mach e BSD mantengono ciascuno modelli di sicurezza diversi**: il modello di sicurezza di **Mach** si basa sui **diritti di porta**, mentre il modello di sicurezza di BSD opera in base alla **proprietà del processo**. Le disparità tra questi due modelli hanno occasionalmente portato a vulnerabilità di escalation dei privilegi locali. Oltre alle chiamate di sistema tipiche, ci sono anche **trappole Mach che consentono ai programmi in spazio utente di interagire con il kernel**. Questi diversi elementi insieme formano l'architettura ibrida e multifaccettata del kernel macOS.

### I/O Kit - Drivers

L'I/O Kit è un framework **per driver di dispositivo** open-source e orientato agli oggetti nel kernel XNU, gestisce **driver di dispositivo caricati dinamicamente**. Consente di aggiungere codice modulare al kernel al volo, supportando hardware diversificato.

{{#ref}}
macos-iokit.md
{{#endref}}

### IPC - Inter Process Communication

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/
{{#endref}}

## macOS Kernel Extensions

macOS è **super restrittivo nel caricare le Kernel Extensions** (.kext) a causa dei privilegi elevati con cui il codice verrà eseguito. In realtà, per impostazione predefinita è praticamente impossibile (a meno che non venga trovato un bypass).

Nella pagina seguente puoi anche vedere come recuperare il `.kext` che macOS carica all'interno del suo **kernelcache**:

{{#ref}}
macos-kernel-extensions.md
{{#endref}}

### macOS System Extensions

Invece di utilizzare le Kernel Extensions, macOS ha creato le System Extensions, che offrono API a livello utente per interagire con il kernel. In questo modo, gli sviluppatori possono evitare di utilizzare le kernel extensions.

{{#ref}}
macos-system-extensions.md
{{#endref}}

## References

- [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

{{#include ../../../banners/hacktricks-training.md}}
