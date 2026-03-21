# Runtimes, Engine, Builder e Sandbox per container

{{#include ../../../banners/hacktricks-training.md}}

Una delle principali fonti di confusione nella security dei container è che diversi componenti completamente differenti vengono spesso compressi nella stessa parola. "Docker" può riferirsi a un image format, a una CLI, a un daemon, a un build system, a uno stack runtime, o semplicemente all'idea di container in generale. Per il lavoro di security, questa ambiguità è un problema, perché diversi livelli sono responsabili di protezioni diverse. Un breakout causato da una bad bind mount non è la stessa cosa di un breakout causato da un bug a basso livello del runtime, e nessuno dei due è la stessa cosa di un errore di cluster policy in Kubernetes.

Questa pagina separa l'ecosistema per ruolo in modo che il resto della sezione possa parlare con precisione di dove una protezione o una debolezza vive realmente.

## OCI come linguaggio comune

Gli stack container moderni su Linux spesso interopera-no perché parlano un insieme di specifiche OCI. La **OCI Image Specification** descrive come sono rappresentate images e layers. La **OCI Runtime Specification** descrive come il runtime dovrebbe lanciare il processo, incluse namespaces, mounts, cgroups e impostazioni di security. La **OCI Distribution Specification** standardizza come i registri espongono il content.

Questo è importante perché spiega perché un container image costruito con uno strumento può spesso essere eseguito con un altro, e perché diversi engine possono condividere lo stesso runtime a basso livello. Spiega anche perché il comportamento di security può sembrare simile tra prodotti diversi: molti costruiscono la stessa configurazione runtime OCI e la passano allo stesso piccolo insieme di runtimes.

## Low-Level OCI Runtimes

Il low-level runtime è il componente più vicino al confine del kernel. È la parte che effettivamente crea namespaces, scrive impostazioni cgroup, applica capabilities e seccomp filters, e infine `execve()` il processo del container. Quando le persone discutono di "container isolation" a livello meccanico, questo è lo strato di cui di solito parlano, anche se non lo dicono esplicitamente.

### `runc`

`runc` è il reference OCI runtime e rimane l'implementazione più nota. È ampiamente usato sotto Docker, containerd e molte distribuzioni Kubernetes. Molta ricerca pubblica e materiale di exploitation prende di mira ambienti in stile `runc` semplicemente perché sono comuni e perché `runc` definisce il baseline che molti immaginano quando pensano a un Linux container. Capire `runc` fornisce quindi al lettore un solido modello mentale per l'isolamento classico dei container.

### `crun`

`crun` è un altro OCI runtime, scritto in C e molto usato negli ambienti Podman moderni. È spesso lodato per il buon supporto di cgroup v2, per l'ergonomia rootless, e per l'overhead inferiore. Da un punto di vista della security, la cosa importante non è che sia scritto in un linguaggio diverso, ma che svolge lo stesso ruolo: è il componente che trasforma la configurazione OCI in un albero di processi in esecuzione sotto il kernel. Un workflow rootless con Podman spesso finisce per risultare più sicuro non perché `crun` risolva tutto, ma perché lo stack intorno tende a spingere maggiormente su user namespaces e least privilege.

### `runsc` di gVisor

`runsc` è il runtime usato da gVisor. Qui il confine cambia in modo significativo. Invece di passare la maggior parte delle syscalls direttamente al kernel host nel modo usuale, gVisor inserisce un layer di kernel in userspace che emula o media ampie parti dell'interfaccia Linux. Il risultato non è un normale container `runc` con qualche flag in più; è un design di sandbox diverso il cui scopo è ridurre la surface di attacco del host-kernel. Compatibilità e compromessi sulle performance fanno parte di quel design, quindi gli ambienti che usano `runsc` dovrebbero essere documentati differentemente rispetto agli ambienti runtime OCI normali.

### `kata-runtime`

Kata Containers spingono il confine più in là lanciando il workload all'interno di una lightweight virtual machine. Amministrativamente, questo può ancora sembrare una deployment di container, e i livelli di orchestrazione possono ancora trattarla come tale, ma il confine di isolamento sottostante è più vicino alla virtualizzazione che a un classico container che condivide il host-kernel. Questo rende Kata utile quando si desidera un isolamento tenant più forte senza abbandonare i workflow centrati sui container.

## Engines e Container Managers

Se il low-level runtime è il componente che parla direttamente con il kernel, l'engine o manager è il componente con cui utenti e operatori di solito interagiscono. Gestisce image pulls, metadata, logs, networks, volumes, lifecycle operations e l'esposizione delle API. Questo livello conta moltissimo perché molte compromissioni nel mondo reale avvengono qui: l'accesso a un runtime socket o a una daemon API può equivalere a una compromissione dell'host anche se il low-level runtime stesso è perfettamente sano.

### Docker Engine

Docker Engine è la piattaforma container più riconoscibile per gli sviluppatori ed è uno dei motivi per cui il lessico dei container è diventato così Docker-shaped. Il percorso tipico è `docker` CLI verso `dockerd`, che a sua volta coordina componenti a basso livello come `containerd` e un OCI runtime. Storicamente, le deployment Docker sono state spesso **rootful**, e l'accesso al Docker socket è stato quindi un primitivo molto potente. È per questo che tanto materiale pratico di privilege-escalation si concentra su `docker.sock`: se un processo può chiedere a `dockerd` di creare un container privilegiato, montare path dell'host, o joinare host namespaces, potrebbe non servire affatto un kernel exploit.

### Podman

Podman è stato progettato intorno a un modello più daemonless. Operativamente, questo aiuta a rinforzare l'idea che i container sono semplicemente processi gestiti tramite meccanismi Linux standard piuttosto che tramite un lungo daemon privilegiato. Podman ha anche una storia rootless molto più forte rispetto alle classiche deployment Docker con cui molti hanno imparato. Questo non rende Podman automaticamente sicuro, ma cambia significativamente il profilo di rischio di default, specialmente quando combinato con user namespaces, SELinux e `crun`.

### containerd

containerd è un componente core di gestione runtime in molti stack moderni. È usato sotto Docker ed è anche uno dei backend runtime dominanti in Kubernetes. Espone API potenti, gestisce images e snapshots, e delega la creazione finale del processo a un runtime a basso livello. Le discussioni di security attorno a containerd dovrebbero enfatizzare che l'accesso al containerd socket o alle funzionalità di `ctr`/`nerdctl` può essere altrettanto pericoloso quanto l'accesso all'API di Docker, anche se l'interfaccia e il workflow sembrano meno "developer friendly".

### CRI-O

CRI-O è più focalizzato rispetto a Docker Engine. Invece di essere una piattaforma general-purpose per sviluppatori, è costruito attorno all'implementazione pulita della Kubernetes Container Runtime Interface. Questo lo rende particolarmente comune nelle distribuzioni Kubernetes e negli ecosistemi pesanti su SELinux come OpenShift. Da un punto di vista della security, quel campo d'azione più ristretto è utile perché riduce il disordine concettuale: CRI-O fa molto parte del layer "run containers for Kubernetes" piuttosto che di una piattaforma tuttofare.

### Incus, LXD e LXC

I sistemi Incus/LXD/LXC valgono la pena di essere separati dagli application container in stile Docker perché sono spesso usati come **system containers**. Un system container è solitamente previsto per assomigliare più a una macchina lightweight con un userspace più completo, servizi a lunga durata, esposizione di device più ricca e una integrazione host più estesa. I meccanismi di isolamento sono ancora primitive del kernel, ma le aspettative operative sono diverse. Di conseguenza, le misconfigurazioni qui spesso somigliano meno a "cattive default per app-container" e più a errori nella lightweight virtualization o nella delegation dell'host.

### systemd-nspawn

systemd-nspawn occupa un posto interessante perché è systemd-native ed è molto utile per testing, debugging e per eseguire ambienti simil-OS. Non è il runtime dominante in produzione cloud-native, ma appare abbastanza spesso in lab e in ambienti orientati alle distro da meritare menzione. Per l'analisi di security, è un promemoria che il concetto di "container" abbraccia più ecosistemi e stili operativi.

### Apptainer / Singularity

Apptainer (ex Singularity) è comune in ambienti di ricerca e HPC. Le sue assunzioni di trust, il workflow utente e il modello di esecuzione differiscono in modi importanti dagli stack centrati su Docker/Kubernetes. In particolare, questi ambienti tengono spesso molto a permettere agli utenti di eseguire workload confezionati senza concedere loro ampi poteri di gestione dei container privilegiati. Se un reviewer assume che ogni ambiente container sia fondamentalmente "Docker su un server", fraintenderà gravemente queste deployment.

## Build-Time Tooling

Molte discussioni di security parlano solo del run time, ma il tooling di build-time conta perché determina il contenuto delle image, l'esposizione di build secrets, e quanto contesto trusted viene incorporato nell'artifact finale.

**BuildKit** e `docker buildx` sono backend di build moderni che supportano feature come caching, secret mounting, SSH forwarding e multi-platform builds. Sono feature utili, ma da un punto di vista della security creano anche punti dove secrets possono leak in image layers o dove un build context eccessivamente ampio può esporre file che non avrebbero dovuto essere inclusi. **Buildah** svolge un ruolo simile negli ecosistemi OCI-native, specialmente intorno a Podman, mentre **Kaniko** è spesso usato in CI che non vogliono concedere un Docker daemon privilegiato alla pipeline di build.

La lezione chiave è che image creation e image execution sono fasi diverse, ma una pipeline di build debole può creare una posture runtime debole molto prima che il container venga lanciato.

## L'orchestrazione è un altro layer, non il runtime

Kubernetes non dovrebbe essere mentalmente equiparato al runtime stesso. Kubernetes è l'orchestrator. Schedule Pods, memorizza lo stato desiderato, ed esprime policy di security tramite la configurazione dei workload. Il kubelet poi parla con un'implementazione CRI come containerd o CRI-O, che a sua volta invoca un low-level runtime come `runc`, `crun`, `runsc`, o `kata-runtime`.

Questa separazione è importante perché molte persone attribuiscono erroneamente una protezione a "Kubernetes" quando in realtà è fatta rispettare dal runtime del nodo, o incolpano "containerd defaults" per un comportamento che è derivato da un Pod spec. In pratica, la postura finale di security è una composizione: l'orchestrator chiede qualcosa, lo stack runtime lo traduce, e il kernel infine lo fa rispettare.

## Perché l'identificazione del runtime conta durante una valutazione

Se identifichi engine e runtime presto, molte osservazioni successive diventano più facili da interpretare. Un container Podman rootless suggerisce che user namespaces sono probabilmente parte della storia. Un Docker socket montato in un workload suggerisce che l'escalation basata su API è un percorso realistico. Un nodo CRI-O/OpenShift dovrebbe immediatamente farti pensare a SELinux labels e a restricted workload policy. Un ambiente gVisor o Kata dovrebbe renderti più cauto nell'assumere che una classica PoC di breakout `runc` si comporterà allo stesso modo.

Per questo uno dei primi passi in una assessment dei container dovrebbe sempre essere rispondere a due semplici domande: **which component is managing the container** e **which runtime actually launched the process**. Una volta che quelle risposte sono chiare, il resto dell'ambiente di solito diventa molto più semplice da ragionare.

## Runtime Vulnerabilities

Non ogni container escape deriva da una misconfiguration dell'operatore. A volte il runtime stesso è il componente vulnerabile. Questo conta perché un workload può essere in esecuzione con quella che sembra una configurazione attenta e comunque essere esposto tramite un difetto del runtime a basso livello.

L'esempio classico è **CVE-2019-5736** in `runc`, dove un container malevolo poteva sovrascrivere il binario `runc` dell'host e poi aspettare una successiva invocazione runtime come `docker exec` per innescare codice controllato dall'attaccante. Il percorso di exploit è molto diverso da un semplice bind-mount o da un errore di capability perché abusa di come il runtime rientra nello spazio di processo del container durante la gestione degli exec.

Un workflow minimo di riproduzione dal punto di vista di un red-team è:
```bash
go build main.go
./main
```
Poi, dall'host:
```bash
docker exec -it <container-name> /bin/sh
```
La lezione chiave non è l'esatta implementazione storica dell'exploit, ma l'implicazione per la valutazione: se la versione del runtime è vulnerabile, l'esecuzione di codice ordinaria in-container può essere sufficiente per compromettere l'host anche quando la configurazione visibile del container non sembra palesemente debole.

Recenti CVE di runtime come `CVE-2024-21626` in `runc`, le mount races di BuildKit e i bug di parsing di containerd rafforzano lo stesso punto. La versione del runtime e il livello di patch fanno parte del confine di sicurezza, non sono meri dettagli di manutenzione.
