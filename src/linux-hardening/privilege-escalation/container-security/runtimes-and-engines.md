# Runtime di Container, Engine, Builder e Sandbox

{{#include ../../../banners/hacktricks-training.md}}

Una delle maggiori fonti di confusione nella sicurezza dei container è che diversi componenti completamente differenti vengono spesso compressi nella stessa parola. "Docker" può riferirsi a un formato immagine, a una CLI, a un daemon, a un sistema di build, a uno stack di runtime o semplicemente all'idea dei container in generale. Per il lavoro di sicurezza, quell'ambiguità è un problema, perché livelli diversi sono responsabili di protezioni diverse. Un breakout causato da un bind mount errato non è la stessa cosa di un breakout causato da un bug a basso livello del runtime, e nessuno dei due è la stessa cosa di un errore di policy a livello di cluster in Kubernetes.

Questa pagina separa l'ecosistema per ruolo in modo che il resto della sezione possa parlare con precisione di dove vive effettivamente una protezione o una debolezza.

## OCI come linguaggio comune

Gli stack moderni di container Linux spesso interoperano perché parlano un insieme di specifiche OCI. La **OCI Image Specification** descrive come sono rappresentate immagini e layer. La **OCI Runtime Specification** descrive come il runtime dovrebbe avviare il processo, incluse namespaces, mount, cgroups e impostazioni di security. La **OCI Distribution Specification** standardizza come i registri espongono i contenuti.

Questo è importante perché spiega perché un'immagine container costruita con uno strumento può spesso essere eseguita con un altro, e perché diversi engine possono condividere lo stesso runtime a basso livello. Spiega anche perché il comportamento di sicurezza può apparire simile tra prodotti diversi: molti di essi stanno costruendo la stessa configurazione di runtime OCI e la consegnano allo stesso piccolo insieme di runtime.

## Runtime OCI a basso livello

Il runtime a basso livello è il componente che è più vicino al confine del kernel. È la parte che in realtà crea i namespaces, scrive le impostazioni dei cgroup, applica capabilities e filtri seccomp, e infine `execve()` il processo del container. Quando le persone discutono di "container isolation" a livello meccanico, questo è il layer di cui di solito parlano, anche se non lo dicono esplicitamente.

### `runc`

`runc` è il runtime OCI di riferimento e rimane l'implementazione più conosciuta. È ampiamente usato sotto Docker, containerd e molte distribuzioni Kubernetes. Molta ricerca pubblica e materiale di exploitation prende di mira ambienti in stile `runc` semplicemente perché sono comuni e perché `runc` definisce la baseline che molte persone pensano quando immaginano un container Linux. Capire `runc` dà quindi al lettore un forte modello mentale per l'isolamento classico dei container.

### `crun`

`crun` è un altro runtime OCI, scritto in C e ampiamente usato negli ambienti moderni Podman. Viene spesso lodato per il buon supporto a cgroup v2, per la forte ergonomia rootless e per il minore overhead. Dal punto di vista della sicurezza, l'importante non è che sia scritto in un linguaggio diverso, ma che svolge lo stesso ruolo: è il componente che trasforma la configurazione OCI in un albero di processi in esecuzione sotto il kernel. Un workflow rootless con Podman spesso finisce per sembrare più sicuro non perché `crun` risolva magicamente tutto, ma perché lo stack circostante tende a incentivare l'uso di user namespaces e il principio del minimo privilegio.

### `runsc` di gVisor

`runsc` è il runtime usato da gVisor. Qui il confine cambia in modo significativo. Invece di passare la maggior parte delle syscall direttamente al kernel host nel modo usuale, gVisor inserisce un layer kernel in userspace che emula o media gran parte dell'interfaccia Linux. Il risultato non è un normale container `runc` con qualche flag in più; è un design di sandbox differente il cui scopo è ridurre la superficie d'attacco del kernel host. Compatibilità e compromessi sulle prestazioni fanno parte di quel design, quindi gli ambienti che usano `runsc` dovrebbero essere documentati in modo diverso rispetto agli ambienti normali di runtime OCI.

### `kata-runtime`

Kata Containers spingono il confine più in là lanciando il workload all'interno di una macchina virtuale leggera. Amministrativamente, questo può ancora apparire come un deployment container, e i livelli di orchestrazione possono ancora trattarlo come tale, ma il confine di isolamento sottostante è più vicino alla virtualizzazione che a un classico container che condivide il kernel host. Questo rende Kata utile quando si desidera un isolamento tenant più forte senza abbandonare i workflow centrati sui container.

## Engine e Container Manager

Se il runtime a basso livello è il componente che parla direttamente con il kernel, l'engine o manager è il componente con cui di solito interagiscono utenti e operatori. Gestisce pull di immagini, metadata, log, reti, volumi, operazioni di lifecycle e l'esposizione delle API. Questo layer conta enormemente perché molte compromissioni nel mondo reale avvengono qui: l'accesso a una runtime socket o a un daemon API può essere equivalente a una compromissione dell'host anche se il runtime a basso livello è perfettamente sano.

### Docker Engine

Docker Engine è la piattaforma container più riconoscibile per gli sviluppatori ed è una delle ragioni per cui il vocabolario dei container è diventato così Docker-shaped. Il percorso tipico è dalla CLI `docker` a `dockerd`, che a sua volta coordina componenti a livello inferiore come `containerd` e un runtime OCI. Storicamente, i deployment Docker sono stati spesso **rootful**, e l'accesso al socket Docker è stato quindi una primitiva molto potente. Per questo motivo gran parte del materiale pratico di privilege-escalation si concentra su `docker.sock`: se un processo può chiedere a `dockerd` di creare un container privilegiato, montare percorsi dell'host o unire namespaces dell'host, potrebbe non aver bisogno affatto di un exploit del kernel.

### Podman

Podman è stato progettato intorno a un modello più daemonless. Operativamente, questo aiuta a rafforzare l'idea che i container sono semplicemente processi gestiti tramite meccanismi Linux standard piuttosto che attraverso un singolo daemon privilegiato di lunga vita. Podman ha anche una storia **rootless** molto più forte rispetto ai classici deployment Docker che molti hanno imparato all'inizio. Questo non rende automaticamente Podman sicuro, ma cambia significativamente il profilo di rischio di default, specialmente se combinato con user namespaces, SELinux e `crun`.

### containerd

containerd è un componente core di gestione dei runtime in molti stack moderni. Viene usato sotto Docker ed è anche uno dei backend runtime dominanti in Kubernetes. Espone API potenti, gestisce immagini e snapshot, e delega la creazione finale del processo a un runtime a basso livello. Le discussioni di sicurezza attorno a containerd dovrebbero sottolineare che l'accesso alla socket di containerd o alle funzionalità di `ctr`/`nerdctl` può essere altrettanto pericoloso quanto l'accesso all'API di Docker, anche se l'interfaccia e il workflow possono sembrare meno "developer friendly".

### CRI-O

CRI-O è più focalizzato rispetto a Docker Engine. Invece di essere una piattaforma general-purpose per sviluppatori, è costruito attorno all'implementazione pulita del Kubernetes Container Runtime Interface. Questo lo rende particolarmente comune nelle distribuzioni Kubernetes e negli ecosistemi forti su SELinux come OpenShift. Dal punto di vista della sicurezza, quello scopo più ristretto è utile perché riduce il clutter concettuale: CRI-O è molto parte del layer "esegui container per Kubernetes" piuttosto che una piattaforma tuttofare.

### Incus, LXD e LXC

I sistemi Incus/LXD/LXC valgono la separazione dai container in stile Docker perché sono spesso usati come **system containers**. Un system container è solitamente previsto come qualcosa di più simile a una macchina leggera con un userspace più completo, servizi a lunga esecuzione, esposizione di dispositivi più ricca e integrazione con l'host più estesa. I meccanismi di isolamento sono ancora primitivi del kernel, ma le aspettative operative sono diverse. Di conseguenza, le errate configurazioni qui spesso sembrano meno come "default di app-container errati" e più come errori in virtualizzazione leggera o delega dell'host.

### systemd-nspawn

systemd-nspawn occupa un posto interessante perché è nativo systemd ed è molto utile per testing, debugging e per eseguire ambienti simili a un OS. Non è il runtime dominante cloud-native in produzione, ma appare abbastanza spesso in lab e in ambienti orientati alle distro da meritare menzione. Per l'analisi di sicurezza, è un altro promemoria che il concetto di "container" abbraccia molteplici ecosistemi e stili operativi.

### Apptainer / Singularity

Apptainer (ex Singularity) è comune in ambienti di ricerca e HPC. Le sue assunzioni di trust, il workflow utente e il modello di esecuzione differiscono in modi importanti dagli stack centrati su Docker/Kubernetes. In particolare, questi ambienti spesso tengono molto a permettere agli utenti di eseguire workload impacchettati senza concedere loro ampi poteri di gestione dei container privilegiati. Se un revisore assume che ogni ambiente container sia fondamentalmente "Docker su un server", comprenderà male questi deployment.

## Tooling a tempo di build

Molte discussioni sulla sicurezza parlano solo del runtime, ma il tooling a tempo di build conta perché determina il contenuto delle immagini, l'esposizione di build secrets e quanto contesto trusted venga incorporato nell'artefatto finale.

**BuildKit** e `docker buildx` sono backend moderni di build che supportano funzionalità come caching, mount di secret, forwarding SSH e build multi-piattaforma. Sono funzionalità utili, ma dal punto di vista della sicurezza creano anche punti dove i segreti possono leak nei layer delle immagini o dove un contesto di build troppo ampio può esporre file che non avrebbero mai dovuto essere inclusi. **Buildah** svolge un ruolo simile negli ecosistemi OCI-native, specialmente attorno a Podman, mentre **Kaniko** è spesso usato in ambienti CI che non vogliono concedere un Docker daemon privilegiato alla pipeline di build.

La lezione chiave è che la creazione dell'immagine e l'esecuzione dell'immagine sono fasi diverse, ma una pipeline di build debole può creare una postura runtime debole molto prima che il container venga lanciato.

## L'orchestrazione è un altro layer, non il runtime

Kubernetes non dovrebbe essere mentalmente equiparato al runtime stesso. Kubernetes è l'orchestratore. Pianifica Pods, conserva lo stato desiderato ed esprime la policy di sicurezza attraverso la configurazione dei workload. Il kubelet poi parla con un'implementazione CRI come containerd o CRI-O, che a sua volta invoca un runtime a basso livello come `runc`, `crun`, `runsc` o `kata-runtime`.

Questa separazione è importante perché molte persone attribuiscono erroneamente una protezione a "Kubernetes" quando in realtà è applicata dal runtime del nodo, o incolpano i "default di containerd" per un comportamento che è nato da uno spec di Pod. In pratica, la postura di sicurezza finale è una composizione: l'orchestratore chiede qualcosa, lo stack di runtime lo traduce e infine il kernel lo applica.

## Perché l'identificazione del runtime è importante durante l'assessment

Se identifichi engine e runtime presto, molte osservazioni successive diventano più facili da interpretare. Un container Podman rootless suggerisce che gli user namespaces fanno probabilmente parte della storia. Un socket Docker montato in un workload suggerisce che una escalation di privilegi guidata dall'API è un percorso realistico. Un nodo CRI-O/OpenShift dovrebbe farti pensare immediatamente a etichette SELinux e a policy di workload ristrette. Un ambiente gVisor o Kata dovrebbe renderti più cauto nell'assumere che una PoC di breakout classica per `runc` si comporterà allo stesso modo.

Per questo uno dei primi passi in un assessment di container dovrebbe sempre essere rispondere a due semplici domande: **quale componente sta gestendo il container** e **quale runtime ha effettivamente lanciato il processo**. Una volta che quelle risposte sono chiare, il resto dell'ambiente di solito diventa molto più facile da ragionare.

## Vulnerabilità del runtime

Non tutte le escape dai container derivano da una cattiva configurazione dell'operatore. A volte il runtime stesso è il componente vulnerabile. Questo è importante perché un workload potrebbe girare con una configurazione che sembra attenta e comunque essere esposto tramite un difetto a basso livello del runtime.

L'esempio classico è **CVE-2019-5736** in `runc`, dove un container maligno poteva sovrascrivere il binario `runc` dell'host e poi aspettare che una successiva `docker exec` o una invocazione runtime simile scatenasse codice controllato dall'attaccante. Il percorso di exploit è molto diverso da un semplice errore di bind-mount o di capability perché abusa di come il runtime rientra nello spazio del processo del container durante la gestione di exec.

Un workflow di riproduzione minimo dal punto di vista di un red-team è:
```bash
go build main.go
./main
```
Quindi, dall'host:
```bash
docker exec -it <container-name> /bin/sh
```
La lezione chiave non è l'implementazione storica esatta dell'exploit, ma l'implicazione per la valutazione: se la versione del runtime è vulnerabile, l'esecuzione ordinaria di codice all'interno del container può essere sufficiente a compromettere l'host anche quando la configurazione visibile del container non appare manifestamente debole.

CVE recenti a livello di runtime come `CVE-2024-21626` in `runc`, i mount races di BuildKit e i bug di parsing in containerd rafforzano lo stesso punto. La versione del runtime e il livello di patch fanno parte del confine di sicurezza, non sono semplici dettagli di manutenzione.
{{#include ../../../banners/hacktricks-training.md}}
