# Container Runtimes, Engines, Builders, And Sandboxes

{{#include ../../../banners/hacktricks-training.md}}

Una delle principali fonti di confusione nella container security è che diversi componenti completamente distinti vengono spesso indicati con la stessa parola. "Docker" può riferirsi a un formato di immagine, a una CLI, a un daemon, a un sistema di build, a uno stack di runtime o semplicemente all'idea dei container in generale. Nel security work, questa ambiguità è un problema, perché livelli diversi sono responsabili di protezioni diverse. Un breakout causato da un bind mount configurato male non è la stessa cosa di un breakout causato da un bug nel low-level runtime, e nessuno dei due equivale a un errore nella cluster policy di Kubernetes.

Questa pagina separa l'ecosistema in base ai ruoli, così il resto della sezione può descrivere con precisione dove risiede effettivamente una protezione o una debolezza.

## OCI As The Common Language

I moderni stack di container Linux spesso interoperano perché utilizzano un insieme di specifiche OCI. La **OCI Image Specification** descrive come vengono rappresentate le immagini e i layer. La **OCI Runtime Specification** descrive come il runtime dovrebbe avviare il processo, inclusi namespaces, mount, cgroup e impostazioni di sicurezza. La **OCI Distribution Specification** standardizza il modo in cui i registry espongono i contenuti.

Questo è importante perché spiega perché un'immagine costruita con un tool può spesso essere eseguita con un altro e perché diversi engine possono condividere lo stesso low-level runtime. Spiega inoltre perché il comportamento di sicurezza può apparire simile tra prodotti diversi: molti di essi costruiscono la stessa configurazione OCI del runtime e la passano allo stesso piccolo insieme di runtime.

## Low-Level OCI Runtimes

Il low-level runtime è il componente più vicino al confine con il kernel. È la parte che crea effettivamente i namespace, scrive le impostazioni dei cgroup, applica capabilities e filtri seccomp e infine esegue `execve()` sul processo del container. Quando si parla di "container isolation" a livello meccanico, di solito ci si riferisce a questo layer, anche se non lo si dice esplicitamente.

### `runc`

`runc` è il runtime OCI di riferimento e rimane l'implementazione più conosciuta. È ampiamente utilizzato da Docker, containerd e da molte deployment Kubernetes. Molta ricerca pubblica e molto materiale di exploitation prendono di mira ambienti nello stile di `runc`, semplicemente perché sono comuni e perché `runc` definisce il baseline che molti immaginano quando pensano a un container Linux. Comprendere `runc` fornisce quindi al lettore un solido modello mentale della classica container isolation.

### `crun`

`crun` è un altro runtime OCI, scritto in C e ampiamente utilizzato nei moderni ambienti Podman. Viene spesso apprezzato per il buon supporto a cgroup v2, le solide funzionalità rootless e il minor overhead. Dal punto di vista della sicurezza, l'aspetto importante non è che sia scritto in un linguaggio diverso, ma che svolga comunque lo stesso ruolo: è il componente che trasforma la configurazione OCI in un process tree in esecuzione sotto il kernel. Un workflow Podman rootless spesso risulta più sicuro non perché `crun` risolva magicamente ogni problema, ma perché lo stack complessivo che lo circonda tende a fare maggiore affidamento su user namespaces e least privilege.

### `runsc` From gVisor

`runsc` è il runtime utilizzato da gVisor. In questo caso il confine cambia in modo significativo. Invece di passare la maggior parte delle syscall direttamente al kernel host nel modo usuale, gVisor inserisce un layer kernel in userspace che emula o media ampie parti dell'interfaccia Linux. Il risultato non è un normale container `runc` con alcuni flag aggiuntivi; è un design di sandbox diverso, il cui scopo è ridurre la attack surface del kernel host. I compromessi in termini di compatibilità e performance fanno parte di questo design, quindi gli ambienti che utilizzano `runsc` dovrebbero essere documentati diversamente rispetto ai normali ambienti con runtime OCI.

### `kata-runtime`

Kata Containers spinge ulteriormente il confine, avviando il workload all'interno di una lightweight virtual machine. Dal punto di vista amministrativo, questo può apparire ancora come una deployment di container e i layer di orchestration possono continuare a trattarlo come tale, ma il confine di isolamento sottostante è più vicino alla virtualizzazione che a un container classico che condivide il kernel host. Questo rende Kata utile quando si desidera un tenant isolation più forte senza abbandonare workflow incentrati sui container.

## Engines And Container Managers

Se il low-level runtime è il componente che comunica direttamente con il kernel, l'engine o manager è il componente con cui interagiscono solitamente utenti e operatori. Gestisce image pull, metadata, log, network, volume, operazioni di lifecycle ed esposizione delle API. Questo layer è estremamente importante perché molti compromessi reali avvengono qui: l'accesso a un runtime socket o a una daemon API può equivalere al compromesso dell'host anche se il low-level runtime è perfettamente funzionante.

### Docker Engine

Docker Engine è la container platform più riconoscibile per gli sviluppatori ed è una delle ragioni per cui il vocabolario dei container è diventato così legato a Docker. Il percorso tipico è dalla CLI `docker` a `dockerd`, che a sua volta coordina componenti di livello inferiore come `containerd` e un runtime OCI. Storicamente, le deployment Docker sono state spesso **rootful** e l'accesso al Docker socket è stato quindi un primitive molto potente. Per questo gran parte del materiale pratico sulla privilege escalation si concentra su `docker.sock`: se un processo può chiedere a `dockerd` di creare un container privilegiato, montare path dell'host o unirsi agli host namespace, potrebbe non aver bisogno di un kernel exploit.

### Podman

Podman è stato progettato attorno a un modello più daemonless. Operativamente, ciò rafforza l'idea che i container siano semplicemente processi gestiti tramite meccanismi Linux standard, anziché tramite un unico daemon privilegiato di lunga durata. Podman offre inoltre una storia **rootless** molto più solida rispetto alle classiche deployment Docker con cui molte persone hanno iniziato. Questo non rende Podman automaticamente sicuro, ma modifica in modo significativo il risk profile predefinito, soprattutto quando viene combinato con user namespaces, SELinux e `crun`.

### containerd

containerd è un componente centrale per la gestione del runtime in molti stack moderni. Viene utilizzato da Docker ed è anche uno dei principali backend di runtime per Kubernetes. Espone API potenti, gestisce immagini e snapshot e delega la creazione finale del processo a un low-level runtime. Le discussioni sulla sicurezza di containerd dovrebbero sottolineare che l'accesso al socket di containerd o alle funzionalità di `ctr`/`nerdctl` può essere altrettanto pericoloso dell'accesso all'API di Docker, anche se l'interfaccia e il workflow sembrano meno "developer friendly".

### CRI-O

CRI-O è più focalizzato rispetto a Docker Engine. Invece di essere una developer platform general-purpose, è costruito per implementare in modo pulito la Kubernetes Container Runtime Interface. Questo lo rende particolarmente comune nelle distribuzioni Kubernetes e negli ecosistemi incentrati su SELinux, come OpenShift. Dal punto di vista della sicurezza, questo scope più ristretto è utile perché riduce la confusione concettuale: CRI-O appartiene chiaramente al layer "eseguire container per Kubernetes", anziché essere una piattaforma che fa tutto.

### Incus, LXD, And LXC

I sistemi Incus/LXD/LXC meritano di essere distinti dai container applicativi in stile Docker perché vengono spesso utilizzati come **system containers**. Un system container dovrebbe solitamente assomigliare di più a una macchina leggera con un userspace completo, servizi long-running, una maggiore esposizione dei device e un'integrazione più estesa con l'host. I meccanismi di isolamento sono comunque primitive del kernel, ma le aspettative operative sono diverse. Di conseguenza, le misconfiguration in questo ambito assomigliano spesso meno a "bad app-container defaults" e più a errori nella lightweight virtualization o nella delega all'host.

### systemd-nspawn

systemd-nspawn occupa una posizione interessante perché è nativo di systemd e molto utile per testing, debugging ed esecuzione di ambienti simili a sistemi operativi. Non è il runtime production dominante nel cloud-native, ma compare abbastanza spesso nei lab e negli ambienti orientati alle distro da meritare una menzione. Per la security analysis, è un ulteriore promemoria del fatto che il concetto di "container" abbraccia diversi ecosistemi e stili operativi.

### Apptainer / Singularity

Apptainer (precedentemente Singularity) è comune negli ambienti di ricerca e HPC. I suoi trust assumptions, il workflow degli utenti e il modello di esecuzione differiscono in modo importante dagli stack incentrati su Docker/Kubernetes. In particolare, questi ambienti spesso attribuiscono grande importanza alla possibilità per gli utenti di eseguire workload pacchettizzati senza concedere loro ampi poteri privilegiati di gestione dei container. Se un reviewer presume che ogni ambiente container sia sostanzialmente "Docker su un server", interpreterà gravemente male queste deployment.

## Build-Time Tooling

Molte security discussion parlano soltanto del run time, ma anche i build-time tooling sono importanti perché determinano il contenuto delle immagini, l'esposizione dei build secret e la quantità di trusted context incorporata nell'artefatto finale.

**BuildKit** e `docker buildx` sono moderni build backend che supportano funzionalità come caching, secret mounting, SSH forwarding e multi-platform build. Si tratta di funzionalità utili, ma dal punto di vista della sicurezza creano anche punti in cui i secret possono fare leak nei layer dell'immagine o in cui un build context eccessivamente ampio può esporre file che non avrebbero mai dovuto essere inclusi. **Buildah** svolge un ruolo simile negli ecosistemi OCI-native, soprattutto insieme a Podman, mentre **Kaniko** viene spesso utilizzato in ambienti CI che non vogliono concedere un Docker daemon privilegiato alla build pipeline.

La lezione principale è che la creazione dell'immagine e l'esecuzione dell'immagine sono fasi diverse, ma una build pipeline debole può creare una runtime posture debole molto prima dell'avvio del container.

## Orchestration Is Another Layer, Not The Runtime

Kubernetes non dovrebbe essere mentalmente equiparato al runtime stesso. Kubernetes è l'orchestrator. Pianifica i Pod, memorizza lo stato desiderato ed esprime la security policy tramite la configurazione dei workload. Il kubelet comunica quindi con un'implementazione CRI come containerd o CRI-O, che a sua volta invoca un low-level runtime come `runc`, `crun`, `runsc` o `kata-runtime`.

Questa separazione è importante perché molte persone attribuiscono erroneamente una protezione a "Kubernetes", quando in realtà viene applicata dal node runtime, oppure attribuiscono ai "containerd defaults" un comportamento che deriva da un Pod spec. In pratica, la postura di sicurezza finale è una composizione: l'orchestrator richiede qualcosa, lo stack del runtime lo traduce e il kernel infine lo applica.

## Why Runtime Identification Matters During Assessment

Se si identificano presto engine e runtime, molte osservazioni successive diventano più facili da interpretare. Un container Podman rootless suggerisce che gli user namespaces siano probabilmente parte del quadro. Un Docker socket montato in un workload suggerisce che la privilege escalation tramite API sia un percorso realistico. Un nodo CRI-O/OpenShift dovrebbe far pensare immediatamente alle SELinux label e alla restricted workload policy. Un ambiente gVisor o Kata dovrebbe rendere più cauti nell'assumere che una classica breakout PoC per `runc` si comporti allo stesso modo.

Per questo, uno dei primi passaggi nella container assessment dovrebbe essere sempre rispondere a due semplici domande: **quale componente gestisce il container** e **quale runtime ha effettivamente avviato il processo**. Una volta chiarite queste risposte, il resto dell'ambiente diventa solitamente molto più facile da analizzare.

## Runtime Vulnerabilities

Non ogni container escape deriva da una misconfiguration dell'operatore. A volte è il runtime stesso a essere vulnerabile. Questo è importante perché un workload potrebbe essere in esecuzione con quella che sembra una configurazione accurata e tuttavia essere esposto a causa di una flaw nel low-level runtime.

L'esempio classico è **CVE-2019-5736** in `runc`, in cui un container malevolo poteva sovrascrivere il binario `runc` dell'host e poi attendere che una successiva invocazione di `docker exec` o di un runtime analogo attivasse codice controllato dall'attacker. Il percorso di exploitation è molto diverso da un semplice errore di bind mount o di capability, perché abusa del modo in cui il runtime rientra nello spazio dei processi del container durante la gestione di exec.<sup>[[1]](#references)</sup>

Un workflow di riproduzione minimo dal punto di vista di un red-team è:
```bash
go build main.go
./main
```
Quindi, dall'host:
```bash
docker exec -it <container-name> /bin/sh
```
La lezione principale non riguarda l'implementazione esatta dell'exploit storico, ma l'implicazione per la valutazione: se la versione del runtime è vulnerabile, la normale esecuzione di codice all'interno del container può essere sufficiente per compromettere l'host, anche quando la configurazione visibile del container non appare evidentemente debole.

I recenti CVE del runtime, come `CVE-2024-21626` in `runc`, le race condition sui mount di BuildKit e i bug di parsing di containerd, rafforzano lo stesso concetto. La versione del runtime e il livello di patch fanno parte del security boundary, non sono semplicemente dettagli di manutenzione.

## Riferimenti

- [1] [Breaking out of Docker via runC – Explaining CVE-2019-5736](https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/)

{{#include ../../../banners/hacktricks-training.md}}
