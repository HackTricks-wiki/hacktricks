# Estensioni di sistema di macOS

{{#include ../../../banners/hacktricks-training.md}}

## System Extensions / Endpoint Security Framework

A differenza delle Kernel Extensions, le **System Extensions vengono eseguite nello user space** invece che nel kernel space, riducendo il rischio di un crash del sistema dovuto a un malfunzionamento dell'estensione.

<figure><img src="../../../images/image (606).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

Esistono tre tipi di system extensions: estensioni **DriverKit**, estensioni **Network** ed estensioni **Endpoint Security**.

### **DriverKit Extensions**

DriverKit è un'alternativa alle kernel extensions che **forniscono il supporto hardware**. Consente ai device driver (come i driver USB, Serial, NIC e HID) di essere eseguiti nello user space anziché nel kernel space. Il framework DriverKit include **versioni nello user space di alcune classi I/O Kit**, mentre il kernel inoltra i normali eventi I/O Kit allo user space, offrendo un ambiente più sicuro per l'esecuzione di questi driver.<sup>[2]</sup>

### **Network Extensions**

Le Network Extensions offrono la possibilità di personalizzare i comportamenti di rete. Esistono diversi tipi di Network Extensions:

- **App Proxy**: viene utilizzato per creare un client VPN che implementa un protocollo VPN personalizzato e orientato ai flussi. Ciò significa che gestisce il traffico di rete in base alle connessioni (o ai flussi), anziché ai singoli pacchetti.
- **Packet Tunnel**: viene utilizzato per creare un client VPN che implementa un protocollo VPN personalizzato e orientato ai pacchetti. Ciò significa che gestisce il traffico di rete in base ai singoli pacchetti.
- **Filter Data**: viene utilizzato per filtrare i "flussi" di rete. Può monitorare o modificare i dati di rete a livello di flusso.
- **Filter Packet**: viene utilizzato per filtrare i singoli pacchetti di rete. Può monitorare o modificare i dati di rete a livello di pacchetto.
- **DNS Proxy**: viene utilizzato per creare un provider DNS personalizzato. Può essere utilizzato per monitorare o modificare le richieste e le risposte DNS.<sup>[2]</sup>

## Endpoint Security Framework

Endpoint Security è un framework fornito da Apple in macOS che mette a disposizione un insieme di API per la sicurezza del sistema. È pensato per consentire a **security vendor e sviluppatori di creare prodotti in grado di monitorare e controllare l'attività del sistema**, così da identificare e proteggere dalle attività malevole.

Questo framework fornisce una **raccolta di API per monitorare e controllare l'attività del sistema**, come l'esecuzione dei processi, gli eventi del file system, gli eventi di rete e quelli del kernel.

Il nucleo di questo framework è implementato nel kernel, come Kernel Extension (KEXT) situata in **`/System/Library/Extensions/EndpointSecurity.kext`**.<sup>[2]</sup> Questa KEXT è composta da diversi componenti principali:

- **EndpointSecurityDriver**: funge da "entry point" per la kernel extension. È il principale punto di interazione tra il sistema operativo e il framework Endpoint Security.
- **EndpointSecurityEventManager**: questo componente è responsabile dell'implementazione dei kernel hook. I kernel hook consentono al framework di monitorare gli eventi di sistema intercettando le system call.
- **EndpointSecurityClientManager**: gestisce la comunicazione con i client nello user space, tenendo traccia dei client connessi e di quelli che devono ricevere le notifiche degli eventi.
- **EndpointSecurityMessageManager**: invia messaggi e notifiche degli eventi ai client nello user space.

Gli eventi che il framework Endpoint Security può monitorare sono categorizzati in:

- Eventi dei file
- Eventi dei processi
- Eventi dei socket
- Eventi del kernel (come il caricamento/scaricamento di una kernel extension o l'apertura di un device I/O Kit)

### Architettura del Endpoint Security Framework

<figure><img src="../../../images/image (1068).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

La **comunicazione nello user space** con il framework Endpoint Security avviene tramite la classe IOUserClient. Vengono utilizzate due sottoclassi diverse, a seconda del tipo di chiamante:

- **EndpointSecurityDriverClient**: richiede l'entitlement `com.apple.private.endpoint-security.manager`, posseduto esclusivamente dal processo di sistema `endpointsecurityd`.
- **EndpointSecurityExternalClient**: richiede l'entitlement `com.apple.developer.endpoint-security.client`. In genere viene utilizzato da software di sicurezza di terze parti che devono interagire con il framework Endpoint Security.<sup>[1]</sup>

Le Endpoint Security Extensions:**`libEndpointSecurity.dylib`** è la libreria C che le system extensions utilizzano per comunicare con il kernel. Questa libreria usa I/O Kit (`IOKit`) per comunicare con la Endpoint Security KEXT.<sup>[2]</sup>

**`endpointsecurityd`** è un daemon di sistema fondamentale coinvolto nella gestione e nell'avvio delle endpoint security system extensions, in particolare durante la fase di early boot. **Solo le system extensions** contrassegnate con **`NSEndpointSecurityEarlyBoot`** nel relativo file `Info.plist` ricevono questo trattamento durante l'early boot.<sup>[2]</sup>

Un altro daemon di sistema, **`sysextd`**, **convalida le system extensions** e le sposta nelle posizioni di sistema appropriate. Quindi chiede al daemon rilevante di caricare l'estensione. Il **`SystemExtensions.framework`** è responsabile dell'attivazione e della disattivazione delle system extensions.<sup>[2]</sup>

## Bypass di ESF

ESF viene utilizzato dagli strumenti di sicurezza che tenteranno di rilevare un red teamer, quindi qualsiasi informazione su come evitarlo potrebbe essere interessante.

### CVE-2021-30965

Il problema è che l'applicazione di sicurezza deve disporre delle **autorizzazioni Full Disk Access**. Pertanto, se un attacker riuscisse a rimuoverle, potrebbe impedire l'esecuzione del software:<sup>[3]</sup>
```bash
tccutil reset All
```
Per **ulteriori informazioni** su questo bypass e su quelli correlati, consulta il talk [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

Alla fine, il problema è stato risolto assegnando il nuovo permesso **`kTCCServiceEndpointSecurityClient`** all'app di sicurezza gestita da **`tccd`**, in modo che `tccutil` non ne cancelli i permessi, impedendone l'esecuzione.<sup>[3]</sup>

## Riferimenti

- [1] [OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight](https://www.youtube.com/watch?v=jaVkpM1UqOs)
- [2] [Knight.sc - System Extension Internals](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)
- [3] [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

{{#include ../../../banners/hacktricks-training.md}}
