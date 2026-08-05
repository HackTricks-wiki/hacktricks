# System Extensions macOS

{{#include ../../../banners/hacktricks-training.md}}

## System Extensions / Endpoint Security Framework

A differenza dei Kernel Extensions, le **System Extensions vengono eseguite nello user space** anziché nel kernel space, riducendo il rischio di un crash del sistema dovuto a un malfunzionamento dell'estensione.

<figure><img src="../../../images/image (606).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

Esistono tre tipi di system extensions: **DriverKit** Extensions, **Network** Extensions ed **Endpoint Security** Extensions.

### **DriverKit Extensions**

DriverKit è un sostituto dei kernel extensions che **forniscono il supporto hardware**. Consente ai device drivers (come i driver USB, Serial, NIC e HID) di essere eseguiti nello user space anziché nel kernel space. Il framework DriverKit include **versioni user space di alcune classi I/O Kit** e il kernel inoltra i normali eventi I/O Kit allo user space, offrendo un ambiente più sicuro per l'esecuzione di questi driver.<sup>[[2]](#references)</sup>

### **Network Extensions**

Network Extensions offrono la possibilità di personalizzare i comportamenti di rete. Esistono diversi tipi di Network Extensions:

- **App Proxy**: viene utilizzato per creare un client VPN che implementa un protocollo VPN custom orientato ai flow. Ciò significa che gestisce il traffico di rete in base alle connessioni (o flow), anziché ai singoli pacchetti.
- **Packet Tunnel**: viene utilizzato per creare un client VPN che implementa un protocollo VPN custom orientato ai pacchetti. Ciò significa che gestisce il traffico di rete in base ai singoli pacchetti.
- **Filter Data**: viene utilizzato per filtrare i "flow" di rete. Può monitorare o modificare i dati di rete a livello di flow.
- **Filter Packet**: viene utilizzato per filtrare i singoli pacchetti di rete. Può monitorare o modificare i dati di rete a livello di pacchetto.
- **DNS Proxy**: viene utilizzato per creare un provider DNS custom. Può essere utilizzato per monitorare o modificare le richieste e le risposte DNS.<sup>[[2]](#references)</sup>

## Endpoint Security Framework

Endpoint Security è un framework fornito da Apple in macOS che offre un insieme di API per la sicurezza del sistema. È destinato all'uso da parte di **security vendors e developers per creare prodotti in grado di monitorare e controllare l'attività del sistema**, così da identificare e proteggere dalle attività malevole.

Questo framework fornisce una **raccolta di API per monitorare e controllare l'attività del sistema**, come le esecuzioni dei processi, gli eventi del file system e gli eventi di rete e del kernel.

Il nucleo di questo framework è implementato nel kernel, come Kernel Extension (KEXT) situato in **`/System/Library/Extensions/EndpointSecurity.kext`**.<sup>[[2]](#references)</sup> Questo KEXT è costituito da diversi componenti fondamentali:

- **EndpointSecurityDriver**: funge da "entry point" per il kernel extension. È il principale punto di interazione tra il sistema operativo e il framework Endpoint Security.
- **EndpointSecurityEventManager**: questo componente è responsabile dell'implementazione dei kernel hooks. I kernel hooks consentono al framework di monitorare gli eventi del sistema intercettando le system calls.
- **EndpointSecurityClientManager**: gestisce la comunicazione con i client user space, tenendo traccia dei client connessi e di quelli che devono ricevere le notifiche degli eventi.
- **EndpointSecurityMessageManager**: invia messaggi e notifiche degli eventi ai client user space.

Gli eventi che il framework Endpoint Security può monitorare sono suddivisi in:

- Eventi dei file
- Eventi dei processi
- Eventi dei socket
- Eventi del kernel (come il caricamento o lo scaricamento di un kernel extension o l'apertura di un device I/O Kit)

### Architettura del framework Endpoint Security

<figure><img src="../../../images/image (1068).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

La **comunicazione user space** con il framework Endpoint Security avviene tramite la classe IOUserClient. Vengono utilizzate due diverse sottoclassi, a seconda del tipo di caller:

- **EndpointSecurityDriverClient**: richiede l'entitlement `com.apple.private.endpoint-security.manager`, posseduto solo dal processo di sistema `endpointsecurityd`.
- **EndpointSecurityExternalClient**: richiede l'entitlement `com.apple.developer.endpoint-security.client`. In genere viene utilizzato da software di sicurezza di terze parti che deve interagire con il framework Endpoint Security.<sup>[[1]](#references)</sup>

Le Endpoint Security Extensions:**`libEndpointSecurity.dylib`** è la libreria C che le system extensions utilizzano per comunicare con il kernel. Questa libreria usa l'I/O Kit (`IOKit`) per comunicare con il KEXT di Endpoint Security.<sup>[[2]](#references)</sup>

**`endpointsecurityd`** è un daemon di sistema fondamentale coinvolto nella gestione e nell'avvio delle endpoint security system extensions, in particolare durante la fase di early boot. **Solo le system extensions** contrassegnate con **`NSEndpointSecurityEarlyBoot`** nel loro file `Info.plist` ricevono questo trattamento durante l'early boot.<sup>[[2]](#references)</sup>

Un altro daemon di sistema, **`sysextd`**, **valida le system extensions** e le sposta nelle posizioni di sistema appropriate. Successivamente chiede al daemon pertinente di caricare l'estensione. Il framework **`SystemExtensions.framework`** è responsabile dell'attivazione e della disattivazione delle system extensions.<sup>[[2]](#references)</sup>

## Bypassing ESF

ESF è utilizzato da security tools che tenteranno di rilevare un red teamer, quindi qualsiasi informazione su come si potrebbe evitare questo rilevamento è interessante.

### CVE-2021-30965

Il punto è che l'applicazione di sicurezza deve disporre delle **Full Disk Access permissions**. Quindi, se un attacker riuscisse a rimuoverle, potrebbe impedire l'esecuzione del software:<sup>[[3]](#references)</sup>
```bash
tccutil reset All
```
Per **ulteriori informazioni** su questo bypass e su quelli correlati, consulta il talk [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

Alla fine questo problema è stato risolto assegnando il nuovo permesso **`kTCCServiceEndpointSecurityClient`** all'app di sicurezza gestita da **`tccd`**, in modo che `tccutil` non ne cancelli i permessi, impedendone l'esecuzione.<sup>[[3]](#references)</sup>

## Riferimenti

- [1] [OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight](https://www.youtube.com/watch?v=jaVkpM1UqOs)
- [2] [Knight.sc - System Extension Internals](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)
- [3] [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

{{#include ../../../banners/hacktricks-training.md}}
