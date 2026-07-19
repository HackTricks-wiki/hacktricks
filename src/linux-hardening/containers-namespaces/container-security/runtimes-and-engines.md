# Container Runtimes, Engines, Builders E Sandbox

{{#include ../../../banners/hacktricks-training.md}}

Una delle principali fonti di confusione nella container security è che diversi componenti completamente differenti vengono spesso racchiusi nella stessa parola. "Docker" può riferirsi a un formato di immagine, a una CLI, a un daemon, a un sistema di build, a uno stack di runtime o semplicemente all'idea dei container in generale. Nel security work, questa ambiguità è un problema, perché livelli diversi sono responsabili di protezioni diverse. Un breakout causato da un bind mount configurato male non è la stessa cosa di un breakout causato da un bug nel low-level runtime, e nessuno dei due equivale a un errore nella policy del cluster Kubernetes.

Questa pagina separa l'ecosistema per ruolo, così il resto della sezione può descrivere con precisione dove risiede effettivamente una protezione o una debolezza.

## OCI Come Linguaggio Comune

Gli stack moderni di container Linux spesso interoperano perché parlano un insieme di specifiche OCI. La **OCI Image Specification** descrive come vengono rappresentate immagini e layer. La **OCI Runtime Specification** descrive come il runtime dovrebbe avviare il processo, inclusi namespace, mount, cgroup e impostazioni di sicurezza. La **OCI Distribution Specification** standardizza il modo in cui i registry espongono i contenuti.

Questo è importante perché spiega perché un'immagine costruita con uno strumento può spesso essere eseguita con un altro e perché diversi engine possono condividere lo stesso low-level runtime. Spiega anche perché il comportamento di sicurezza può apparire simile tra prodotti diversi: molti di essi costruiscono la stessa configurazione del runtime OCI e la passano allo stesso piccolo insieme di runtime.

## Low-Level OCI Runtimes

Il low-level runtime è il componente più vicino al confine con il kernel. È la parte che crea effettivamente i namespace, scrive le impostazioni dei cgroup, applica le capabilities e i filtri seccomp e infine esegue `execve()` sul processo del container. Quando si parla di "container isolation" a livello meccanico, di solito ci si riferisce a questo livello, anche senza dirlo esplicitamente.

### `runc`

`runc` è il runtime OCI di riferimento e rimane l'implementazione più conosciuta. È ampiamente utilizzato da Docker, containerd e molte deployment Kubernetes. Molta ricerca pubblica e materiale di exploitation prendono di mira gli ambienti basati su `runc` semplicemente perché sono comuni e perché `runc` definisce la baseline che molte persone hanno in mente quando pensano a un container Linux. Comprendere `runc` fornisce quindi un modello mentale solido per la classica container isolation.

### `crun`

`crun` è un altro runtime OCI, scritto in C e ampiamente utilizzato negli ambienti moderni Podman. Viene spesso apprezzato per il buon supporto a cgroup v2, la solida ergonomia rootless e il minore overhead. Dal punto di vista della sicurezza, l'aspetto importante non è che sia scritto in un linguaggio diverso, ma che svolga lo stesso ruolo: è il componente che trasforma la configurazione OCI in un process tree in esecuzione sotto il kernel. Un workflow Podman rootless spesso risulta più sicuro non perché `crun` risolva magicamente ogni problema, ma perché lo stack complessivo tende a puntare maggiormente su user namespace e least privilege.

### `runsc` Da gVisor

`runsc` è il runtime utilizzato da gVisor. In questo caso il confine assume un significato sostanzialmente diverso. Invece di passare la maggior parte delle syscall direttamente al kernel host nel modo usuale, gVisor inserisce un kernel layer in userspace che emula o media ampie parti dell'interfaccia Linux. Il risultato non è un normale container `runc` con alcuni flag aggiuntivi; è un design di sandbox diverso, il cui scopo è ridurre l'attack surface del kernel host. I compromessi in termini di compatibilità e performance fanno parte di questo design, quindi gli ambienti che usano `runsc` dovrebbero essere documentati diversamente rispetto ai normali ambienti con runtime OCI.

### `kata-runtime`

Kata Containers spinge ulteriormente il confine avviando il workload all'interno di una lightweight virtual machine. Dal punto di vista amministrativo, può continuare ad apparire come una deployment di container e i layer di orchestration possono continuare a trattarla come tale, ma il confine di isolation sottostante è più vicino alla virtualizzazione che a un container classico che condivide il kernel host. Questo rende Kata utile quando si desidera una tenant isolation più forte senza abbandonare i workflow incentrati sui container.

## Engine E Container Manager

Se il low-level runtime è il componente che comunica direttamente con il kernel, l'engine o manager è il componente con cui gli utenti e gli operatori interagiscono normalmente. Gestisce image pull, metadata, log, network, volume, operazioni del ciclo di vita ed esposizione delle API. Questo livello è estremamente importante perché molti compromessi reali avvengono qui: l'accesso a un runtime socket o a una daemon API può equivalere al compromesso dell'host anche se il low-level runtime è perfettamente integro.

### Docker Engine

Docker Engine è la container platform più riconoscibile per gli sviluppatori e uno dei motivi per cui il vocabolario dei container è diventato così incentrato su Docker. Il percorso tipico è dalla CLI `docker` a `dockerd`, che a sua volta coordina componenti di livello inferiore come `containerd` e un runtime OCI. Storicamente, le deployment Docker sono state spesso **rootful**, quindi l'accesso al Docker socket è stato un primitive molto potente. Per questo gran parte del materiale pratico sulla privilege escalation si concentra su `docker.sock`: se un processo può chiedere a `dockerd` di creare un container privilegiato, montare path dell'host o unirsi agli host namespace, potrebbe non aver bisogno di un kernel exploit.

### Podman

Podman è stato progettato attorno a un modello più daemonless. Dal punto di vista operativo, questo rafforza l'idea che i container siano semplicemente processi gestiti tramite meccanismi Linux standard, anziché tramite un unico daemon privilegiato di lunga durata. Podman offre inoltre una storia **rootless** molto più solida rispetto alle deployment Docker classiche con cui molte persone hanno iniziato. Questo non rende Podman automaticamente sicuro, ma modifica significativamente il risk profile predefinito, soprattutto se combinato con user namespace, SELinux e `crun`.

### containerd

containerd è un componente fondamentale per la gestione del runtime in molti stack moderni. Viene utilizzato da Docker ed è anche uno dei backend runtime Kubernetes più diffusi. Espone API potenti, gestisce immagini e snapshot e delega la creazione finale del processo a un low-level runtime. Le discussioni sulla sicurezza di containerd dovrebbero sottolineare che l'accesso al socket di containerd o alle funzionalità `ctr`/`nerdctl` può essere pericoloso quanto l'accesso all'API di Docker, anche se l'interfaccia e il workflow appaiono meno "developer friendly".

### CRI-O

CRI-O è più focalizzato rispetto a Docker Engine. Invece di essere una developer platform general-purpose, è costruito per implementare in modo pulito la Kubernetes Container Runtime Interface. Per questo è particolarmente comune nelle distribuzioni Kubernetes e negli ecosistemi incentrati su SELinux, come OpenShift. Dal punto di vista della sicurezza, questo scope più ristretto è utile perché riduce la confusione concettuale: CRI-O appartiene chiaramente al livello "eseguire container per Kubernetes", anziché essere una piattaforma completa.

### Incus, LXD E LXC

I sistemi Incus/LXD/LXC meritano di essere separati dai application container in stile Docker perché vengono spesso utilizzati come **system container**. Un system container dovrebbe normalmente assomigliare più a una macchina leggera, con un userspace più completo, servizi long-running, una maggiore esposizione dei device e un'integrazione più estesa con l'host. I meccanismi di isolation sono comunque primitive del kernel, ma le aspettative operative sono diverse. Di conseguenza, le misconfiguration qui assomigliano spesso meno a "bad app-container defaults" e più a errori nella lightweight virtualization o nella host delegation.

### systemd-nspawn

systemd-nspawn occupa una posizione interessante perché è nativo di systemd e molto utile per testing, debugging ed esecuzione di ambienti simili a sistemi operativi. Non è il runtime cloud-native di produzione dominante, ma compare abbastanza spesso nei lab e negli ambienti orientati alle distro da meritare una menzione. Per la security analysis, ricorda ancora una volta che il concetto di "container" comprende più ecosistemi e stili operativi.

### Apptainer / Singularity

Apptainer (precedentemente Singularity) è comune negli ambienti di ricerca e HPC. Le sue trust assumption, il workflow degli utenti e il modello di esecuzione differiscono in modi importanti dagli stack incentrati su Docker/Kubernetes. In particolare, questi ambienti spesso attribuiscono grande importanza alla possibilità per gli utenti di eseguire workload pacchettizzati senza concedere loro ampi privilegi di container management. Se un reviewer presume che ogni ambiente container sia sostanzialmente "Docker su un server", interpreterà molto male queste deployment.

## Build-Time Tooling

Molte discussioni sulla sicurezza parlano solo del runtime, ma il build-time tooling è importante perché determina il contenuto delle immagini, l'esposizione dei build secrets e la quantità di contesto trusted incorporata nell'artifact finale.

**BuildKit** e `docker buildx` sono moderni build backend che supportano funzionalità come caching, secret mounting, SSH forwarding e build multi-platform. Sono funzionalità utili, ma dal punto di vista della sicurezza creano anche punti in cui i secret possono fare leak nei layer delle immagini o in cui un build context troppo ampio può esporre file che non avrebbero mai dovuto essere inclusi. **Buildah** svolge un ruolo simile negli ecosistemi OCI-native, soprattutto insieme a Podman, mentre **Kaniko** viene spesso utilizzato in ambienti CI che non vogliono concedere un Docker daemon privilegiato alla build pipeline.

La lezione principale è che la creazione e l'esecuzione delle immagini sono fasi diverse, ma una build pipeline debole può creare una debole runtime posture molto prima dell'avvio del container.

## L'Orchestration È Un Altro Livello, Non Il Runtime

Kubernetes non dovrebbe essere mentalmente equiparato al runtime stesso. Kubernetes è l'orchestrator. Pianifica i Pod, memorizza lo stato desiderato ed esprime la security policy tramite la configurazione dei workload. Il kubelet comunica poi con un'implementazione CRI come containerd o CRI-O, che a sua volta invoca un low-level runtime come `runc`, `crun`, `runsc` o `kata-runtime`.

Questa separazione è importante perché molte persone attribuiscono erroneamente una protezione a "Kubernetes" quando in realtà viene applicata dal node runtime, oppure attribuiscono a "containerd defaults" un comportamento derivante da un Pod spec. In pratica, la security posture finale è una composizione: l'orchestrator richiede qualcosa, lo stack runtime lo traduce e infine il kernel lo applica.

## Perché L'Identificazione Del Runtime È Importante Durante L'Assessment

Se si identificano presto engine e runtime, molte osservazioni successive diventano più facili da interpretare. Un container Podman rootless suggerisce che gli user namespace siano probabilmente parte del quadro. Un Docker socket montato in un workload suggerisce che la privilege escalation basata sulle API sia un percorso realistico. Un nodo CRI-O/OpenShift dovrebbe far pensare immediatamente alle SELinux label e alla restricted workload policy. Un ambiente gVisor o Kata dovrebbe indurre maggiore cautela nell'assumere che una classica breakout PoC per `runc` si comporti allo stesso modo.

Per questo, uno dei primi passaggi di un container assessment dovrebbe sempre essere rispondere a due semplici domande: **quale componente gestisce il container** e **quale runtime ha effettivamente avviato il processo**. Una volta chiarite queste risposte, il resto dell'ambiente diventa generalmente molto più facile da analizzare.

## Runtime Vulnerabilities

Non ogni container escape deriva da una misconfiguration dell'operatore. A volte è il runtime stesso a essere vulnerabile. Questo è importante perché un workload potrebbe essere eseguito con una configurazione apparentemente accurata e rimanere comunque esposto a causa di una flaw nel low-level runtime.

L'esempio classico è **CVE-2019-5736** in `runc`, dove un container malevolo poteva sovrascrivere il binario `runc` dell'host e attendere che una successiva invocazione di `docker exec` o di un runtime simile attivasse codice controllato dall'attacker. Il percorso di exploit è molto diverso da un semplice errore di bind-mount o di capability, perché sfrutta il modo in cui il runtime rientra nello spazio dei processi del container durante la gestione di exec.

Un workflow di riproduzione minimale dal punto di vista di un red-team è:
```bash
go build main.go
./main
```
Quindi, dall'host:
```bash
docker exec -it <container-name> /bin/sh
```
La lezione principale non riguarda l’implementazione esatta dell’exploit storico, ma la sua implicazione per la valutazione: se la versione del runtime è vulnerabile, la normale esecuzione di codice all’interno del container può essere sufficiente a compromettere l’host, anche quando la configurazione visibile del container non appare manifestamente debole.

Le recenti CVE del runtime, come `CVE-2024-21626` in `runc`, le race condition sui mount di BuildKit e i bug di parsing di containerd, rafforzano lo stesso concetto. La versione del runtime e il livello delle patch fanno parte del confine di sicurezza, non sono semplicemente dettagli di manutenzione.
{{#include ../../../banners/hacktricks-training.md}}
