# Runtime, engine, builder e sandbox dei container

Una delle principali fonti di confusione nella container security è che diversi componenti completamente distinti vengono spesso indicati con la stessa parola. "Docker" può riferirsi a un formato per immagini, a una CLI, a un daemon, a un sistema di build, a uno stack di runtime o semplicemente all'idea dei container in generale. Nel lavoro di sicurezza, questa ambiguità è un problema, perché livelli diversi sono responsabili di protezioni diverse. Un breakout causato da un bind mount errato non è la stessa cosa di un breakout causato da un bug nel runtime di basso livello, e nessuno dei due equivale a un errore nella policy del cluster in Kubernetes.

Questa pagina separa l'ecosistema in base ai ruoli, così il resto della sezione può descrivere con precisione dove si trova effettivamente una protezione o una debolezza.

## OCI Come Linguaggio Comune

Gli stack moderni dei container Linux spesso interoperano perché utilizzano un insieme di specifiche OCI. La **OCI Image Specification** descrive come vengono rappresentate le immagini e i layer. La **OCI Runtime Specification** descrive come il runtime dovrebbe avviare il processo, inclusi namespace, mount, cgroup e impostazioni di sicurezza. La **OCI Distribution Specification** standardizza il modo in cui i registry espongono i contenuti.

Questo è importante perché spiega perché un'immagine costruita con uno strumento può spesso essere eseguita con un altro e perché diversi engine possono condividere lo stesso runtime di basso livello. Spiega anche perché il comportamento di sicurezza può apparire simile tra prodotti diversi: molti di essi costruiscono la stessa configurazione del runtime OCI e la passano allo stesso ristretto insieme di runtime.

## Runtime OCI a basso livello

Il runtime di basso livello è il componente più vicino al confine con il kernel. È la parte che crea effettivamente i namespace, scrive le impostazioni dei cgroup, applica capability e filtri seccomp e infine esegue `execve()` per avviare il processo del container. Quando si parla di "isolamento dei container" a livello meccanico, di solito ci si riferisce a questo livello, anche se non lo si dichiara esplicitamente.

### `runc`

`runc` è il runtime OCI di riferimento e rimane l'implementazione più conosciuta. È ampiamente utilizzato da Docker, containerd e da molte installazioni Kubernetes. Gran parte del materiale pubblico di ricerca ed exploitation prende di mira ambienti basati su `runc`, semplicemente perché sono comuni e perché `runc` definisce il baseline a cui molte persone pensano quando immaginano un container Linux. Comprendere `runc` fornisce quindi un solido modello mentale dell'isolamento classico dei container.

### `crun`

`crun` è un altro runtime OCI, scritto in C e ampiamente utilizzato negli ambienti Podman moderni. È spesso apprezzato per il buon supporto a cgroup v2, la solida ergonomia rootless e il minore overhead. Dal punto di vista della sicurezza, l'aspetto importante non è che sia scritto in un linguaggio diverso, ma che svolga comunque lo stesso ruolo: è il componente che trasforma la configurazione OCI in un albero di processi in esecuzione sotto il kernel. Un workflow Podman rootless spesso risulta più sicuro non perché `crun` risolva magicamente ogni problema, ma perché lo stack complessivo che lo circonda tende a puntare maggiormente su user namespace e least privilege.

### `runsc` di gVisor

`runsc` è il runtime utilizzato da gVisor. In questo caso il confine cambia in modo significativo. Invece di passare la maggior parte delle syscall direttamente al kernel host nel modo consueto, gVisor inserisce un livello kernel in userspace che emula o media ampie parti dell'interfaccia Linux. Il risultato non è un normale container `runc` con alcuni flag aggiuntivi; è un design di sandbox diverso, il cui obiettivo è ridurre la attack surface del kernel host. I compromessi relativi a compatibilità e performance fanno parte di questo design, quindi gli ambienti che utilizzano `runsc` dovrebbero essere documentati in modo diverso rispetto ai normali ambienti con runtime OCI.

### `kata-runtime`

Kata Containers spingono ulteriormente il confine, avviando il workload all'interno di una macchina virtuale leggera. Dal punto di vista amministrativo, questo può ancora apparire come un deployment di container e i layer di orchestrazione possono ancora trattarlo come tale, ma il confine di isolamento sottostante è più vicino alla virtualizzazione che a un container classico che condivide il kernel host. Questo rende Kata utile quando è necessario un isolamento più forte tra tenant senza abbandonare workflow incentrati sui container.

## Engine e container manager

Se il runtime di basso livello è il componente che comunica direttamente con il kernel, l'engine o manager è il componente con cui generalmente interagiscono utenti e operatori. Gestisce il pull delle immagini, i metadata, i log, le reti, i volumi, le operazioni sul ciclo di vita e l'esposizione delle API. Questo livello è estremamente importante perché molti compromessi reali avvengono qui: l'accesso a un runtime socket o a una daemon API può equivalere alla compromissione dell'host, anche se il runtime di basso livello è perfettamente funzionante.

### Docker Engine

Docker Engine è la piattaforma per container più riconoscibile tra gli sviluppatori e uno dei motivi per cui il vocabolario dei container ha assunto una forma così incentrata su Docker. Il percorso tipico è dalla CLI `docker` a `dockerd`, che a sua volta coordina componenti di livello inferiore come `containerd` e un runtime OCI. Storicamente, i deployment Docker sono spesso stati **rootful**, quindi l'accesso al socket Docker è stato un primitive molto potente. Per questo gran parte del materiale pratico sulla privilege escalation si concentra su `docker.sock`: se un processo può chiedere a `dockerd` di creare un container privilegiato, montare path dell'host o unirsi ai namespace dell'host, potrebbe non aver bisogno di alcun kernel exploit.

### Podman

Podman è stato progettato intorno a un modello più daemonless. Dal punto di vista operativo, questo aiuta a rafforzare l'idea che i container siano semplicemente processi gestiti tramite meccanismi Linux standard, anziché tramite un unico daemon privilegiato e a lunga esecuzione. Podman offre inoltre una storia **rootless** molto più solida rispetto ai deployment Docker classici con cui molte persone hanno iniziato. Questo non rende Podman automaticamente sicuro, ma modifica significativamente il profilo di rischio predefinito, soprattutto se combinato con user namespace, SELinux e `crun`.

### containerd

containerd è un componente centrale per la gestione del runtime in molti stack moderni. Viene utilizzato da Docker ed è anche uno dei backend runtime dominanti di Kubernetes. Espone API potenti, gestisce immagini e snapshot e delega la creazione finale del processo a un runtime di basso livello. Le discussioni sulla sicurezza di containerd dovrebbero sottolineare che l'accesso al socket di containerd o alle funzionalità di `ctr`/`nerdctl` può essere altrettanto pericoloso dell'accesso all'API di Docker, anche se l'interfaccia e il workflow appaiono meno "developer friendly".

### CRI-O

CRI-O è più specializzato rispetto a Docker Engine. Invece di essere una piattaforma general-purpose per sviluppatori, è costruito per implementare in modo pulito la Container Runtime Interface di Kubernetes. Questo lo rende particolarmente comune nelle distribuzioni Kubernetes e negli ecosistemi fortemente basati su SELinux, come OpenShift. Dal punto di vista della sicurezza, questo ambito più ristretto è utile perché riduce il disordine concettuale: CRI-O fa chiaramente parte del livello "eseguire container per Kubernetes", non di una piattaforma che fa tutto.

### Incus, LXD e LXC

I sistemi Incus/LXD/LXC devono essere distinti dai container applicativi in stile Docker perché spesso vengono utilizzati come **system container**. In genere ci si aspetta che un system container assomigli più a una macchina leggera, con un userspace più completo, servizi a lunga esecuzione, una maggiore esposizione dei device e un'integrazione più estesa con l'host. I meccanismi di isolamento sono comunque primitive del kernel, ma le aspettative operative sono diverse. Di conseguenza, le misconfiguration in questo contesto spesso assomigliano meno a "impostazioni predefinite errate dei container applicativi" e più a errori nella virtualizzazione leggera o nella delega all'host.

### systemd-nspawn

systemd-nspawn occupa una posizione interessante perché è nativo di systemd e molto utile per testing, debugging ed esecuzione di ambienti simili a sistemi operativi. Non è il runtime di produzione cloud-native dominante, ma compare abbastanza spesso nei lab e negli ambienti orientati alle distro da meritare una menzione. Per l'analisi della sicurezza, è un ulteriore promemoria del fatto che il concetto di "container" comprende più ecosistemi e stili operativi.

### Apptainer / Singularity

Apptainer (in precedenza Singularity) è comune negli ambienti di ricerca e HPC. Le sue assunzioni di trust, il workflow degli utenti e il modello di esecuzione differiscono in modi importanti dagli stack incentrati su Docker/Kubernetes. In particolare, questi ambienti spesso attribuiscono grande importanza alla possibilità per gli utenti di eseguire workload pacchettizzati senza concedere loro ampi privilegi di gestione dei container. Se un reviewer presume che ogni ambiente container sia sostanzialmente "Docker su un server", comprenderà molto male questi deployment.

## Tooling in fase di build

Molte discussioni sulla sicurezza parlano solo del runtime, ma anche il tooling in fase di build è importante perché determina il contenuto delle immagini, l'esposizione dei secret di build e la quantità di contesto trusted incorporato nell'artifact finale.

**BuildKit** e `docker buildx` sono backend di build moderni che supportano funzionalità come caching, secret mounting, SSH forwarding e build multi-platform. Sono funzionalità utili, ma dal punto di vista della sicurezza creano anche punti in cui i secret possono fare leak nei layer delle immagini o in cui un build context troppo ampio può esporre file che non avrebbero mai dovuto essere inclusi. **Buildah** svolge un ruolo simile negli ecosistemi OCI-native, soprattutto insieme a Podman, mentre **Kaniko** viene spesso utilizzato negli ambienti CI che non vogliono concedere un Docker daemon privilegiato alla pipeline di build.

La lezione principale è che la creazione delle immagini e l'esecuzione delle immagini sono fasi diverse, ma una pipeline di build debole può creare una postura di sicurezza runtime debole molto prima dell'avvio del container.

## L'orchestrazione è un altro livello, non il runtime

Kubernetes non dovrebbe essere mentalmente equiparato al runtime stesso. Kubernetes è l'orchestrator. Schedula i Pod, memorizza lo stato desiderato ed esprime la security policy attraverso la configurazione dei workload. Il kubelet comunica quindi con un'implementazione CRI come containerd o CRI-O, che a sua volta invoca un runtime di basso livello come `runc`, `crun`, `runsc` o `kata-runtime`.

Questa separazione è importante perché molte persone attribuiscono erroneamente una protezione a "Kubernetes", quando in realtà viene applicata dal runtime del nodo, oppure attribuiscono i comportamenti ai "default di containerd" quando invece derivano da un Pod spec. In pratica, la postura di sicurezza finale è una composizione: l'orchestrator richiede qualcosa, lo stack runtime lo traduce e infine il kernel lo applica.

## Perché l'identificazione del runtime è importante durante l'assessment

Se identifichi presto engine e runtime, molte osservazioni successive diventano più facili da interpretare. Un container Podman rootless suggerisce che gli user namespace siano probabilmente parte del modello. Un socket Docker montato in un workload suggerisce che la privilege escalation basata su API sia un percorso realistico. Un nodo CRI-O/OpenShift dovrebbe farti pensare immediatamente alle label SELinux e alla policy per workload restricted. Un ambiente gVisor o Kata dovrebbe renderti più prudente nell'assumere che una classica breakout PoC per `runc` si comporti allo stesso modo.

Per questo, uno dei primi passaggi in un container assessment dovrebbe sempre essere rispondere a due semplici domande: **quale componente sta gestendo il container** e **quale runtime ha effettivamente avviato il processo**. Una volta chiarite queste risposte, il resto dell'ambiente diventa generalmente molto più facile da analizzare.

## Vulnerabilità del runtime

Non tutti i container escape derivano da una misconfiguration dell'operatore. A volte è il runtime stesso a essere vulnerabile. Questo è importante perché un workload può essere in esecuzione con una configurazione apparentemente accurata e rimanere comunque esposto a una flaw del runtime di basso livello.

L'esempio classico è **CVE-2019-5736** in `runc`, dove un container malevolo poteva sovrascrivere il binario `runc` dell'host e attendere che una successiva invocazione di `docker exec`, o di un runtime simile, attivasse codice controllato dall'attacker. Il percorso di exploit è molto diverso da un semplice errore relativo a bind mount o capability, perché abusa del modo in cui il runtime rientra nello spazio dei processi del container durante la gestione di exec.<sup>[[1]](#references)</sup>

Un workflow di riproduzione minimale dal punto di vista di un red-team è:
```bash
go build main.go
./main
```
Quindi, dall'host:
```bash
docker exec -it <container-name> /bin/sh
```
La lezione chiave non riguarda l'implementazione esatta dell'exploit storico, ma l'implicazione per la valutazione: se la versione del runtime è vulnerabile, la normale code execution all'interno del container può essere sufficiente per compromettere l'host, anche quando la configurazione visibile del container non appare palesemente debole.

I CVE recenti dei runtime, come `CVE-2024-21626` in `runc`, le race condition sui mount di BuildKit e i bug di parsing di containerd, rafforzano lo stesso concetto. La versione e il livello di patch del runtime fanno parte del security boundary, non sono semplici dettagli di manutenzione.

## References

- [1] [Evasione da Docker tramite runC – Spiegazione di CVE-2019-5736](https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/)
{{#include ../../../banners/hacktricks-training.md}}
