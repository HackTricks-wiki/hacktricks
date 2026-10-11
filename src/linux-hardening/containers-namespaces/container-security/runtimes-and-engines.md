# Runtime, engine, builder e sandbox per container

{{#include ../../../banners/hacktricks-training.md}}

Una delle principali fonti di confusione nella sicurezza dei container è che componenti molto diversi vengono spesso indicati con la stessa parola. «Docker» può riferirsi a un formato di immagine, a una CLI, a un daemon, a un sistema di build, a uno stack runtime o semplicemente all’idea generale dei container. Nelle attività di sicurezza, questa ambiguità è un problema, perché i diversi livelli sono responsabili di protezioni diverse. Un breakout causato da un bind mount errato non è la stessa cosa di un breakout dovuto a un bug del runtime di basso livello, e nessuno dei due equivale a un errore nelle policy del cluster Kubernetes.

Questa pagina distingue i componenti dell’ecosistema in base al loro ruolo, così che il resto della sezione possa indicare con precisione dove risiede una protezione o una vulnerabilità.

## OCI come linguaggio comune

Gli stack moderni di container Linux spesso interoperano perché parlano un insieme di specifiche OCI. **OCI Image Specification** descrive la rappresentazione di immagini e layer. **OCI Runtime Specification** descrive come il runtime deve avviare il processo, inclusi namespace, mount, cgroup e impostazioni di sicurezza. **OCI Distribution Specification** standardizza il modo in cui i registry espongono i contenuti.

Questo spiega perché spesso un’immagine container creata con uno strumento può essere eseguita con un altro, e perché diversi engine possono condividere lo stesso runtime di basso livello. Spiega anche perché il comportamento di sicurezza può apparire simile tra prodotti diversi: molti di essi creano la stessa configurazione runtime OCI e la passano allo stesso ristretto insieme di runtime.

## Runtime OCI di basso livello

Il runtime di basso livello è il componente più vicino al confine con il kernel. È la parte che crea effettivamente i namespace, scrive le impostazioni dei cgroup, applica capability e filtri seccomp e infine esegue `execve()` sul processo del container. Quando si parla di «isolamento dei container» a livello meccanico, di solito ci si riferisce a questo livello, anche senza dirlo esplicitamente.

### `runc`

`runc` è il runtime OCI di riferimento e rimane l’implementazione più nota. È ampiamente usato con Docker, containerd e molte installazioni Kubernetes. Molte ricerche pubbliche e materiali di exploit prendono di mira ambienti basati su `runc` semplicemente perché sono comuni e perché `runc` definisce il modello di base a cui molte persone pensano quando immaginano un container Linux. Comprendere `runc` fornisce quindi al lettore un solido modello mentale dell’isolamento classico dei container.

### `crun`

`crun` è un altro runtime OCI, scritto in C e ampiamente usato negli ambienti Podman moderni. Viene spesso apprezzato per il buon supporto ai cgroup v2, la facilità d’uso in modalità rootless e il minore overhead. Dal punto di vista della sicurezza, l’aspetto importante non è che sia scritto in un altro linguaggio, ma che svolga lo stesso ruolo: trasforma la configurazione OCI in un albero di processi in esecuzione sotto il kernel. Un workflow Podman rootless spesso risulta più sicuro non perché `crun` risolva magicamente ogni problema, ma perché lo stack complessivo tende a fare maggiore affidamento sugli user namespace e sul principio del privilegio minimo.

### `runsc` di gVisor

`runsc` è il runtime usato da gVisor. In questo caso, il confine cambia in modo significativo. Invece di passare la maggior parte delle syscall direttamente al kernel host nel modo consueto, gVisor inserisce un kernel in userspace che emula o media gran parte dell’interfaccia Linux. Il risultato non è un normale container `runc` con qualche flag aggiuntivo: è un design di sandbox diverso, concepito per ridurre la superficie d’attacco del kernel host. I compromessi in termini di compatibilità e prestazioni fanno parte del design, quindi gli ambienti che usano `runsc` dovrebbero essere documentati diversamente dai normali ambienti con runtime OCI.

### `kata-runtime`

Kata Containers sposta ulteriormente il confine, avviando il workload all’interno di una macchina virtuale leggera. Dal punto di vista amministrativo, può sembrare comunque un deployment di container, e i livelli di orchestrazione possono continuare a trattarlo come tale, ma il confine di isolamento sottostante è più vicino alla virtualizzazione che a un container classico che condivide il kernel host. Kata è quindi utile quando si desidera un isolamento più forte tra tenant senza abbandonare i workflow basati sui container.

## Engine e manager di container

Se il runtime di basso livello è il componente che comunica direttamente con il kernel, l’engine o manager è quello con cui interagiscono di solito utenti e operatori. Gestisce il pull delle immagini, i metadati, i log, le reti, i volumi, le operazioni sul ciclo di vita e l’esposizione delle API. Questo livello è estremamente importante perché molte compromissioni reali avvengono qui: l’accesso a un socket runtime o all’API di un daemon può equivalere alla compromissione dell’host, anche se il runtime di basso livello funziona perfettamente.

### Docker Engine

Docker Engine è la piattaforma di container più riconoscibile per gli sviluppatori ed è uno dei motivi per cui il vocabolario dei container ha assunto una forma così legata a Docker. Il percorso tipico va dalla CLI `docker` a `dockerd`, che coordina a sua volta componenti di livello inferiore come `containerd` e un runtime OCI. Storicamente, le installazioni Docker sono spesso state **rootful**, e l’accesso al socket Docker è quindi una primitiva molto potente. Per questo gran parte del materiale pratico sulla privilege escalation si concentra su `docker.sock`: se un processo può chiedere a `dockerd` di creare un container privilegiato, montare percorsi host o unirsi ai namespace host, potrebbe non aver bisogno di un kernel exploit.

Confronta i numeri di release usando i componenti major, minor e patch, senza rimuovere i punti: `18.09.1` è più vecchia sia di `18.09.2` sia di `18.09.4`, nonostante il componente minor con zero iniziale. Le [note di rilascio di Docker 18.09](https://docs.docker.com/engine/release-notes/18.09/) documentano la correzione di `runc` inclusa in 18.09.2 per CVE-2019-5736 e la correzione del riferimento di build inclusa in 18.09.4 per CVE-2019-13139. Queste versioni sono indizi, non prove della possibilità di sfruttare una vulnerabilità. Le stesse note di rilascio avvertono che daemon, client e runtime sono distribuiti separatamente: controlla quindi il runtime installato e i backport del vendor oltre alla versione del daemon. Un problema relativo ai riferimenti di build richiede inoltre l’accesso al workflow di build interessato e input controllato dall’attaccante.

### Podman

Podman è stato progettato secondo un modello più orientato all’assenza di daemon. Dal punto di vista operativo, questo aiuta a sottolineare che i container sono semplicemente processi gestiti tramite i meccanismi Linux standard, anziché tramite un unico daemon privilegiato di lunga durata. Podman offre anche un supporto **rootless** molto più solido rispetto alle installazioni Docker classiche che molti hanno conosciuto per prime. Questo non rende Podman automaticamente sicuro, ma cambia in modo significativo il profilo di rischio predefinito, soprattutto se abbinato a user namespace, SELinux e `crun`.

### containerd

containerd è un componente fondamentale per la gestione del runtime in molti stack moderni. È usato con Docker ed è anche uno dei principali backend runtime di Kubernetes. Espone API potenti, gestisce immagini e snapshot e delega la creazione finale dei processi a un runtime di basso livello. Nelle analisi di sicurezza di containerd va sottolineato che l’accesso al socket di containerd o alle funzionalità di `ctr`/`nerdctl` può essere pericoloso quanto l’accesso all’API Docker, anche se l’interfaccia e il workflow sembrano meno «developer friendly».

### CRI-O

CRI-O ha un ambito più ristretto rispetto a Docker Engine. Invece di essere una piattaforma generalista per sviluppatori, è progettato per implementare in modo lineare la Kubernetes Container Runtime Interface. È quindi particolarmente comune nelle distribuzioni Kubernetes e negli ecosistemi che fanno ampio uso di SELinux, come OpenShift. Dal punto di vista della sicurezza, questo ambito più ristretto è utile perché riduce la complessità concettuale: CRI-O appartiene chiaramente al livello «esecuzione di container per Kubernetes», anziché essere una piattaforma tuttofare.

Quando un nodo Kubernetes usa CRI-O, verifica la **release CRI-O attiva sul nodo** e se l’identità corrente può creare Pod in un namespace che viene pianificato su quel nodo. [CVE-2022-0811](https://github.com/cri-o/cri-o/security/advisories/GHSA-6x2m-w449-qwx7) consentiva a valori sysctl appositamente creati nei Pod di modificare un parametro del kernel host e arrivare all’esecuzione come root sull’host nelle release interessate. L’advisory upstream elenca le release corrette e le soluzioni alternative. Un comando locale `crio --version` potrebbe non rilevare un runtime annidato in Minikube o in un altro container nodo; un log di avvio Minikube leggibile può fornire un indizio sulla versione, ma costituisce una prova storica, non una conferma del runtime effettivamente in esecuzione o del suo stato di patch. Prima di considerarlo un’escalation raggiungibile, verifica il runtime effettivo del nodo, le autorizzazioni per la creazione dei Pod, le regole di ammissione e i confini rilevanti di seccomp e degli user namespace.

È possibile anche eseguire una verifica locale diretta di `pinns`: i [ricercatori segnalano che non è necessario Kubernetes per invocare l’helper vulnerabile](https://www.crowdstrike.com/en-us/blog/cr8escape-new-vulnerability-discovered-in-cri-o-container-engine-cve-2022-0811/). Verifica se l’account corrente può eseguire un `pinns` di proprietà di root con setuid, se NoNewPrivs o un mount `nosuid` impediscono tale transizione e se la **build dell’helper** installata è priva della correzione. L’[advisory upstream](https://github.com/cri-o/cri-o/security/advisories/GHSA-6x2m-w449-qwx7) elenca le versioni corrette, ma la versione mostrata dal daemon da sola non dimostra quale binario helper sia installato, e i backport dei distributori possono cambiare l’esposizione. Un file setuid è solo un possibile indizio: convalida la provenienza dell’helper, la configurazione e il comportamento dei sysctl host senza eseguirlo durante una normale enumerazione.

### Incus, LXD e LXC

I sistemi Incus/LXD/LXC vanno distinti dai container applicativi in stile Docker perché spesso vengono usati come **container di sistema**. In genere ci si aspetta che un container di sistema assomigli di più a una macchina leggera, con uno userspace più completo, servizi di lunga durata, maggiore esposizione dei dispositivi e un’integrazione più ampia con l’host. I meccanismi di isolamento sono comunque primitive del kernel, ma le aspettative operative sono diverse. Di conseguenza, le configurazioni errate qui assomigliano spesso meno a «impostazioni predefinite errate per container applicativi» e più a errori nella virtualizzazione leggera o nella delega di privilegi sull’host.

### systemd-nspawn

systemd-nspawn occupa una posizione interessante perché è nativo di systemd ed è molto utile per test, debugging ed esecuzione di ambienti simili a un sistema operativo. Non è il runtime di produzione dominante negli ambienti cloud-native, ma è abbastanza diffuso nei laboratori e negli ambienti incentrati sulle distribuzioni da meritare una menzione. Per l’analisi di sicurezza, ricorda ancora una volta che il concetto di «container» comprende diversi ecosistemi e stili operativi.

### Apptainer / Singularity

Apptainer (in precedenza Singularity) è comune negli ambienti di ricerca e HPC. Le sue ipotesi di fiducia, i workflow utente e il modello di esecuzione differiscono in aspetti importanti dagli stack incentrati su Docker/Kubernetes. In particolare, questi ambienti spesso devono consentire agli utenti di eseguire workload pacchettizzati senza concedere loro ampi privilegi per la gestione di container. Chi presume che ogni ambiente container sia fondamentalmente «Docker su un server» fraintenderà gravemente queste installazioni.

## Strumenti per la fase di build

Molte discussioni sulla sicurezza parlano solo dell’esecuzione, ma sono importanti anche gli strumenti di build, perché determinano i contenuti delle immagini, l’esposizione dei secret durante la build e la quantità di contesto attendibile incorporata nell’artefatto finale.

**BuildKit** e `docker buildx` sono backend di build moderni che supportano funzionalità come caching, mount di secret, inoltro SSH e build multipiattaforma. Sono funzionalità utili, ma dal punto di vista della sicurezza creano anche occasioni in cui i secret possono finire nei layer delle immagini o in cui un contesto di build troppo ampio può esporre file che non avrebbero mai dovuto essere inclusi. **Buildah** svolge un ruolo simile negli ecosistemi nativi OCI, soprattutto con Podman, mentre **Kaniko** viene spesso usato negli ambienti CI che non vogliono concedere un daemon Docker privilegiato alla pipeline di build.

La lezione fondamentale è che la creazione e l’esecuzione delle immagini sono fasi diverse, ma una pipeline di build debole può compromettere la sicurezza del runtime ben prima che il container venga avviato.

## L’orchestrazione è un livello distinto dal runtime

Kubernetes non va confuso con il runtime. Kubernetes è l’orchestratore: pianifica i Pod, archivia lo stato desiderato ed esprime le policy di sicurezza tramite la configurazione dei workload. Kubelet comunica poi con un’implementazione CRI come containerd o CRI-O, che a sua volta invoca un runtime di basso livello come `runc`, `crun`, `runsc` o `kata-runtime`.

Questa distinzione è importante perché spesso si attribuisce erroneamente una protezione a «Kubernetes» quando in realtà è applicata dal runtime del nodo, oppure si attribuisce il comportamento alle «impostazioni predefinite di containerd» quando invece deriva dalla specifica di un Pod. In pratica, il livello di sicurezza finale è il risultato della composizione di più elementi: l’orchestratore richiede qualcosa, lo stack runtime lo traduce e il kernel lo applica.

## Perché identificare il runtime è importante durante una valutazione

Se identifichi subito l’engine e il runtime, sarà più facile interpretare molte delle osservazioni successive. Un container Podman rootless suggerisce che probabilmente entrano in gioco gli user namespace. Un socket Docker montato in un workload suggerisce che la privilege escalation tramite API sia una possibilità concreta. Un nodo CRI-O/OpenShift dovrebbe farti pensare subito alle etichette SELinux e alle policy per workload con restrizioni. In un ambiente gVisor o Kata, dovresti essere più prudente nel presumere che un PoC classico per un breakout da `runc` si comporti allo stesso modo.

Per questo, uno dei primi passaggi nella valutazione dei container dovrebbe consistere nel rispondere a due semplici domande: **quale componente gestisce il container** e **quale runtime ha effettivamente avviato il processo**. Chiariti questi aspetti, di solito diventa molto più facile ragionare sul resto dell’ambiente.

## Vulnerabilità del runtime

Non tutte le evasioni dai container derivano da errori di configurazione degli operatori. A volte è vulnerabile il runtime stesso. Questo è importante perché un workload può essere eseguito con una configurazione apparentemente prudente e risultare comunque esposto a causa di un difetto del runtime di basso livello.

L’esempio classico è **CVE-2019-5736** in `runc`, che consentiva a un container malevolo di sovrascrivere il binario `runc` dell’host e poi attendere che una successiva invocazione di `docker exec` o di un’operazione analoga attivasse codice controllato dall’attaccante. Il percorso di exploit è molto diverso da un semplice errore di bind mount o di capability, perché sfrutta il modo in cui il runtime rientra nello spazio dei processi del container durante la gestione di `exec`.<sup>[[1]](#references)</sup>

Un workflow minimo di riproduzione dal punto di vista di un red team è:

```bash
go build main.go
./main
```

Quindi, dall'host:

```bash
docker exec -it <container-name> /bin/sh
```

La lezione fondamentale non riguarda l’implementazione esatta dell’exploit storico, ma le implicazioni per la valutazione: se la versione del runtime è vulnerabile, la normale esecuzione di codice all’interno del container può bastare a compromettere l’host, anche quando la configurazione visibile del container non sembra palesemente debole.

Le vulnerabilità CVE recenti dei runtime, come `CVE-2024-21626` in `runc`, le race condition sui mount di BuildKit e i bug di parsing di containerd ribadiscono lo stesso punto. La versione del runtime e il livello delle patch fanno parte del perimetro di sicurezza, non sono semplici dettagli di manutenzione.

## References

- [1] [Evasione da Docker tramite runC – Spiegazione di CVE-2019-5736](https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/)
{{#include ../../../banners/hacktricks-training.md}}
