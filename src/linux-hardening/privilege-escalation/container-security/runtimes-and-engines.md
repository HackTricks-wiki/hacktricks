# Container Runtimes, Engines, Builders, And Sandboxes

{{#include ../../../banners/hacktricks-training.md}}

Una delle maggiori fonti di confusione nella sicurezza dei container è che diversi componenti completamente differenti vengono spesso condensati nella stessa parola. "Docker" può riferirsi a un formato di immagine, a una CLI, a un daemon, a un sistema di build, a uno stack runtime, o semplicemente all'idea di container in generale. Per il lavoro di sicurezza, quell'ambiguità è un problema, perché livelli diversi sono responsabili di protezioni diverse. Un breakout causato da un bad bind mount non è la stessa cosa di un breakout causato da un bug a basso livello nel runtime, e nessuno dei due è la stessa cosa di un errore di policy del cluster in Kubernetes.

Questa pagina separa l'ecosistema per ruolo in modo che il resto della sezione possa parlare con precisione di dove una protezione o una debolezza risiedono realmente.

## OCI As The Common Language

Gli stack container moderni su Linux spesso interoperano perché parlano un insieme di specifiche OCI. La **OCI Image Specification** descrive come sono rappresentate le immagini e i layer. La **OCI Runtime Specification** descrive come il runtime dovrebbe lanciare il processo, incluse namespaces, mounts, cgroups e impostazioni di sicurezza. La **OCI Distribution Specification** standardizza come i registri espongono il contenuto.

Questo è importante perché spiega perché un'immagine container costruita con uno strumento può spesso essere eseguita con un altro, e perché diversi engine possono condividere lo stesso runtime a basso livello. Spiega anche perché il comportamento di sicurezza può sembrare simile tra prodotti differenti: molti di essi stanno costruendo la stessa configurazione OCI runtime e la passando allo stesso piccolo insieme di runtimes.

## Low-Level OCI Runtimes

Il low-level runtime è il componente più vicino al confine del kernel. È la parte che crea effettivamente i namespaces, scrive le impostazioni dei cgroup, applica capabilities e seccomp filters, e infine esegue `execve()` sul processo del container. Quando le persone discutono di "container isolation" a livello meccanico, questo è il layer di cui di solito parlano, anche se non lo dicono esplicitamente.

### `runc`

`runc` è il runtime di riferimento OCI e rimane l'implementazione più conosciuta. È ampiamente usato sotto Docker, containerd e molte distribuzioni Kubernetes. Molta ricerca pubblica e materiale di exploitation prende di mira ambienti in stile `runc` semplicemente perché sono comuni e perché `runc` definisce il baseline che molti immaginano quando pensano a un container Linux. Capire `runc` fornisce quindi al lettore un modello mentale forte per l'isolamento classico dei container.

### `crun`

`crun` è un altro OCI runtime, scritto in C e ampiamente usato negli ambienti Podman moderni. È spesso elogiato per il buon supporto a cgroup v2, per una migliore ergonomia rootless e per un overhead minore. Dal punto di vista della sicurezza, l'importante non è che sia scritto in un linguaggio diverso, ma che svolge comunque lo stesso ruolo: è il componente che trasforma la configurazione OCI in un albero di processi in esecuzione sotto il kernel. Un workflow Podman rootless spesso finisce per sembrare più sicuro non perché `crun` risolva tutto, ma perché lo stack complessivo intorno tende a privilegiare user namespaces e least privilege.

### `runsc` From gVisor

`runsc` è il runtime usato da gVisor. Qui il confine cambia in modo significativo. Invece di passare la maggior parte delle syscall direttamente al kernel host nel modo usuale, gVisor inserisce uno strato kernel in userspace che emula o media grandi parti dell'interfaccia Linux. Il risultato non è un normale container `runc` con qualche flag in più; è un design di sandbox differente il cui scopo è ridurre la superficie d'attacco del kernel host. I compromessi su compatibilità e performance fanno parte di quel design, quindi gli ambienti che usano `runsc` dovrebbero essere documentati differentemente rispetto agli ambienti runtime OCI normali.

### `kata-runtime`

Kata Containers spingono il confine più in là lanciando il carico di lavoro all'interno di una virtual machine leggera. Amministrativamente, questo può ancora sembrare un deployment di container, e i layer di orchestrazione possono ancora trattarlo come tale, ma il confine di isolamento sottostante è più vicino alla virtualizzazione che a un classico container che condivide il kernel host. Questo rende Kata utile quando si desidera un isolamento tenant più forte senza abbandonare i workflow centrati sui container.

## Engines And Container Managers

Se il low-level runtime è il componente che parla direttamente con il kernel, l'engine o manager è il componente con cui utenti e operatori solitamente interagiscono. Gestisce image pull, metadata, logs, networks, volumes, operazioni di lifecycle e l'esposizione delle API. Questo layer conta enormemente perché molte compromissioni reali avvengono qui: accesso a un runtime socket o a un'API daemon può essere equivalente a una compromissione dell'host anche se il low-level runtime è perfettamente sano.

### Docker Engine

Docker Engine è la piattaforma container più riconoscibile per gli sviluppatori ed è una delle ragioni per cui il vocabolario dei container si è così tanto plasmato su Docker. Il percorso tipico è la CLI `docker` verso `dockerd`, che a sua volta coordina componenti di livello inferiore come `containerd` e un OCI runtime. Storicamente, i deployment Docker sono stati spesso **rootful**, e l'accesso al Docker socket è quindi stato un primitivo molto potente. Questo è il motivo per cui tanto materiale pratico di privilege-escalation si concentra su `docker.sock`: se un processo può chiedere a `dockerd` di creare un container privilegiato, montare path dell'host o unirsi ai namespace dell'host, potrebbe non aver bisogno affatto di un exploit del kernel.

### Podman

Podman è stato progettato attorno a un modello più daemonless. Operativamente, questo aiuta a rafforzare l'idea che i container sono semplicemente processi gestiti tramite meccanismi Linux standard piuttosto che tramite un unico daemon privilegiato di lunga vita. Podman ha anche una storia rootless molto più forte rispetto ai classici deployment Docker con cui molti hanno iniziato. Questo non rende automaticamente Podman sicuro, ma cambia significativamente il profilo di rischio predefinito, specialmente quando combinato con user namespaces, SELinux e `crun`.

### containerd

containerd è un componente di gestione runtime core in molti stack moderni. Viene usato sotto Docker ed è anche uno dei backend runtime dominanti in Kubernetes. Espone API potenti, gestisce immagini e snapshot, e delega la creazione finale dei processi a un runtime a basso livello. Le discussioni di sicurezza intorno a containerd dovrebbero enfatizzare che l'accesso al socket di containerd o alle funzionalità `ctr`/`nerdctl` può essere tanto pericoloso quanto l'accesso all'API di Docker, anche se l'interfaccia e il workflow sembrano meno "developer friendly".

### CRI-O

CRI-O è più focalizzato rispetto a Docker Engine. Invece di essere una piattaforma generica per sviluppatori, è costruito attorno all'implementazione pulita della Kubernetes Container Runtime Interface. Questo lo rende particolarmente comune nelle distribuzioni Kubernetes e negli ecosistemi pesanti su SELinux come OpenShift. Dal punto di vista della sicurezza, quel campo d'azione più ristretto è utile perché riduce il disordine concettuale: CRI-O è molto parte del layer "run containers for Kubernetes" piuttosto che una piattaforma tuttofare.

### Incus, LXD, And LXC

I sistemi Incus/LXD/LXC valgono separati dai container in stile Docker perché sono spesso usati come system containers. Un system container è solitamente previsto che somigli più a una macchina leggera con un userspace più completo, servizi di lunga durata, esposizione di device più ricca e integrazione host più estesa. I meccanismi di isolamento sono comunque primitive del kernel, ma le aspettative operative sono diverse. Di conseguenza, le misconfigurazioni qui spesso assomigliano meno a "cattive impostazioni predefinite per app-container" e più a errori in virtualizzazione leggera o delega dell'host.

### systemd-nspawn

systemd-nspawn occupa un posto interessante perché è systemd-native ed è molto utile per testing, debugging ed esecuzione di ambienti simili a OS. Non è il runtime dominante nella produzione cloud-native, ma appare abbastanza spesso in lab e ambienti orientati alle distro da meritare una menzione. Per l'analisi di sicurezza, è un altro promemoria che il concetto di "container" abbraccia più ecosistemi e stili operativi.

### Apptainer / Singularity

Apptainer (ex Singularity) è comune negli ambienti di ricerca e HPC. Le sue assunzioni di trust, il workflow utente e il modello di esecuzione differiscono in modo importante dagli stack centrati su Docker/Kubernetes. In particolare, questi ambienti spesso tengono molto a permettere agli utenti di eseguire workload impacchettati senza consegnare loro ampi poteri di gestione di container privilegiati. Se un revisore presume che ogni ambiente container sia fondamentalmente "Docker su un server", fraintenderà gravemente questi deployment.

## Build-Time Tooling

Molte discussioni di sicurezza parlano solo del run time, ma il tooling in fase di build conta anche perché determina i contenuti dell'immagine, l'esposizione di build secrets e quanto contesto trusted viene incorporato nell'artefatto finale.

**BuildKit** e `docker buildx` sono backend di build moderni che supportano funzionalità come caching, secret mounting, SSH forwarding e build multi-piattaforma. Sono feature utili, ma dal punto di vista della sicurezza creano anche punti dove i secrets possono leak nei layer dell'immagine o dove un contesto di build troppo ampio può esporre file che non avrebbero mai dovuto essere inclusi. **Buildah** svolge un ruolo simile negli ecosistemi OCI-native, specialmente intorno a Podman, mentre **Kaniko** è spesso usato in ambienti CI che non vogliono concedere un Docker daemon privilegiato alla pipeline di build.

La lezione chiave è che la creazione dell'immagine e l'esecuzione dell'immagine sono fasi diverse, ma una pipeline di build debole può creare una postura runtime debole molto prima che il container venga lanciato.

## Orchestration Is Another Layer, Not The Runtime

Kubernetes non dovrebbe essere mentalmente equiparato al runtime stesso. Kubernetes è l'orchestrator. Pianifica i Pod, conserva lo stato desiderato ed esprime policy di sicurezza tramite la configurazione del workload. Il kubelet poi parla con un'implementazione CRI come containerd o CRI-O, che a loro volta invocano un low-level runtime come `runc`, `crun`, `runsc` o `kata-runtime`.

Questa separazione è importante perché molte persone attribuiscono erroneamente una protezione a "Kubernetes" quando in realtà è applicata dal runtime del nodo, o incolpano "containerd defaults" per comportamenti che sono invece derivati da una specifica Pod. In pratica, la postura di sicurezza finale è una composizione: l'orchestrator richiede qualcosa, lo stack runtime lo traduce, e infine il kernel lo applica.

## Why Runtime Identification Matters During Assessment

Se identifichi early l'engine e il runtime, molte osservazioni successive diventano più facili da interpretare. Un container Podman rootless suggerisce che user namespaces probabilmente fanno parte della storia. Un Docker socket montato in un workload suggerisce che una escalation di privilegi guidata dall'API è una strada realistica. Un nodo CRI-O/OpenShift dovrebbe farti pensare immediatamente a SELinux labels e a restricted workload policy. Un ambiente gVisor o Kata dovrebbe farti essere più cauto nell'assumere che una classica PoC di breakout per `runc` si comporterà allo stesso modo.

Per questo uno dei primi passi in una valutazione dei container dovrebbe sempre essere rispondere a due semplici domande: **quale componente sta gestendo il container** e **quale runtime ha effettivamente lanciato il processo**. Una volta che quelle risposte sono chiare, il resto dell'ambiente di solito diventa molto più facile da ragionare.

## Runtime Vulnerabilities

Non ogni escape da container deriva da una misconfigurazione dell'operatore. A volte il runtime stesso è il componente vulnerabile. Questo è importante perché un workload può essere eseguito con quella che sembra una configurazione attenta e essere comunque esposto tramite un difetto a basso livello del runtime.

L'esempio classico è **CVE-2019-5736** in `runc`, dove un container malevolo poteva sovrascrivere il binario `runc` dell'host e poi aspettare una successiva invocazione di `docker exec` o simile per far scattare codice controllato dall'attaccante. Il percorso di exploit è molto diverso da un semplice errore di bind-mount o di capabilities perché abusa di come il runtime rientra nello spazio di processo del container durante la gestione di exec.

Un workflow di riproduzione minimo dal punto di vista del red-team è:
```bash
go build main.go
./main
```
Quindi, dall'host:
```bash
docker exec -it <container-name> /bin/sh
```
La lezione chiave non è l'implementazione storica esatta dell'exploit, ma l'implicazione per l'assessment: se la versione del runtime è vulnerabile, ordinary in-container code execution può essere sufficiente a compromettere l'host anche quando la configurazione visibile del container non sembra apertamente debole.

Recenti CVE del runtime come `CVE-2024-21626` in `runc`, BuildKit mount races, e bug di parsing di containerd rafforzano lo stesso punto. La versione del runtime e il livello delle patch fanno parte del confine di sicurezza, non sono semplici dettagli di manutenzione.
{{#include ../../../banners/hacktricks-training.md}}
