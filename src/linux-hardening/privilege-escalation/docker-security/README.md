# Sicurezza di Docker

{{#include ../../../banners/hacktricks-training.md}}

## **Sicurezza di Base del Motore Docker**

Il **motore Docker** utilizza i **Namespaces** e i **Cgroups** del kernel Linux per isolare i container, offrendo un livello base di sicurezza. Ulteriore protezione è fornita tramite il **Capabilities dropping**, **Seccomp** e **SELinux/AppArmor**, migliorando l'isolamento dei container. Un **auth plugin** può ulteriormente limitare le azioni degli utenti.

![Sicurezza di Docker](https://sreeninet.files.wordpress.com/2016/03/dockersec1.png)

### Accesso Sicuro al Motore Docker

Il motore Docker può essere accesso localmente tramite un socket Unix o remotamente utilizzando HTTP. Per l'accesso remoto, è essenziale utilizzare HTTPS e **TLS** per garantire riservatezza, integrità e autenticazione.

Il motore Docker, per impostazione predefinita, ascolta sul socket Unix a `unix:///var/run/docker.sock`. Nei sistemi Ubuntu, le opzioni di avvio di Docker sono definite in `/etc/default/docker`. Per abilitare l'accesso remoto all'API e al client Docker, esporre il demone Docker su un socket HTTP aggiungendo le seguenti impostazioni:
```bash
DOCKER_OPTS="-D -H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Tuttavia, esporre il daemon Docker su HTTP non è consigliato a causa di preoccupazioni di sicurezza. È consigliabile proteggere le connessioni utilizzando HTTPS. Ci sono due approcci principali per garantire la connessione:

1. Il client verifica l'identità del server.
2. Sia il client che il server si autenticano reciprocamente.

I certificati vengono utilizzati per confermare l'identità di un server. Per esempi dettagliati di entrambi i metodi, fare riferimento a [**questa guida**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/).

### Sicurezza delle Immagini dei Container

Le immagini dei container possono essere memorizzate in repository privati o pubblici. Docker offre diverse opzioni di archiviazione per le immagini dei container:

- [**Docker Hub**](https://hub.docker.com): Un servizio di registry pubblico di Docker.
- [**Docker Registry**](https://github.com/docker/distribution): Un progetto open-source che consente agli utenti di ospitare il proprio registry.
- [**Docker Trusted Registry**](https://www.docker.com/docker-trusted-registry): L'offerta commerciale di registry di Docker, con autenticazione utente basata su ruoli e integrazione con i servizi di directory LDAP.

### Scansione delle Immagini

I container possono avere **vulnerabilità di sicurezza** sia a causa dell'immagine di base che a causa del software installato sopra l'immagine di base. Docker sta lavorando a un progetto chiamato **Nautilus** che esegue la scansione di sicurezza dei container e elenca le vulnerabilità. Nautilus funziona confrontando ogni layer dell'immagine del container con il repository delle vulnerabilità per identificare le falle di sicurezza.

Per ulteriori [**informazioni leggi questo**](https://docs.docker.com/engine/scan/).

- **`docker scan`**

Il comando **`docker scan`** consente di eseguire la scansione delle immagini Docker esistenti utilizzando il nome o l'ID dell'immagine. Ad esempio, eseguire il seguente comando per scansionare l'immagine hello-world:
```bash
docker scan hello-world

Testing hello-world...

Organization:      docker-desktop-test
Package manager:   linux
Project name:      docker-image|hello-world
Docker image:      hello-world
Licenses:          enabled

✓ Tested 0 dependencies for known issues, no vulnerable paths found.

Note that we do not currently have vulnerability data for your image.
```
- [**`trivy`**](https://github.com/aquasecurity/trivy)
```bash
trivy -q -f json <container_name>:<tag>
```
- [**`snyk`**](https://docs.snyk.io/snyk-cli/getting-started-with-the-cli)
```bash
snyk container test <image> --json-file-output=<output file> --severity-threshold=high
```
- [**`clair-scanner`**](https://github.com/arminc/clair-scanner)
```bash
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
### Firma delle Immagini Docker

La firma delle immagini Docker garantisce la sicurezza e l'integrità delle immagini utilizzate nei container. Ecco una spiegazione condensata:

- **Docker Content Trust** utilizza il progetto Notary, basato su The Update Framework (TUF), per gestire la firma delle immagini. Per ulteriori informazioni, vedere [Notary](https://github.com/docker/notary) e [TUF](https://theupdateframework.github.io).
- Per attivare la fiducia nei contenuti Docker, impostare `export DOCKER_CONTENT_TRUST=1`. Questa funzione è disattivata per impostazione predefinita nelle versioni di Docker 1.10 e successive.
- Con questa funzione attivata, possono essere scaricate solo immagini firmate. Il primo push dell'immagine richiede l'impostazione delle frasi segrete per le chiavi root e di tagging, con Docker che supporta anche Yubikey per una maggiore sicurezza. Maggiori dettagli possono essere trovati [qui](https://blog.docker.com/2015/11/docker-content-trust-yubikey/).
- Tentare di scaricare un'immagine non firmata con la fiducia nei contenuti attivata risulta in un errore "No trust data for latest".
- Per i push delle immagini dopo il primo, Docker richiede la frase segreta della chiave del repository per firmare l'immagine.

Per eseguire il backup delle tue chiavi private, utilizza il comando:
```bash
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Quando si cambia host Docker, è necessario spostare le chiavi root e repository per mantenere le operazioni.

## Caratteristiche di Sicurezza dei Container

<details>

<summary>Riepilogo delle Caratteristiche di Sicurezza dei Container</summary>

**Caratteristiche Principali di Isolamento dei Processi**

Negli ambienti containerizzati, isolare i progetti e i loro processi è fondamentale per la sicurezza e la gestione delle risorse. Ecco una spiegazione semplificata dei concetti chiave:

**Namespace**

- **Scopo**: Garantire l'isolamento delle risorse come processi, rete e filesystem. In particolare in Docker, i namespace mantengono i processi di un container separati dall'host e da altri container.
- **Utilizzo di `unshare`**: Il comando `unshare` (o la syscall sottostante) è utilizzato per creare nuovi namespace, fornendo un ulteriore livello di isolamento. Tuttavia, mentre Kubernetes non blocca intrinsecamente questo, Docker lo fa.
- **Limitazione**: Creare nuovi namespace non consente a un processo di tornare ai namespace predefiniti dell'host. Per penetrare nei namespace dell'host
```
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep
```
**Seccomp**

È abilitato per impostazione predefinita in Docker. Aiuta a **limitare ulteriormente le syscalls** che il processo può chiamare.\
Il **profilo Seccomp predefinito di Docker** può essere trovato in [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json)

**AppArmor**

Docker ha un modello che puoi attivare: [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

Questo permetterà di ridurre le capacità, le syscalls, l'accesso a file e cartelle...

</details>

### Namespaces

I **Namespaces** sono una funzionalità del kernel Linux che **partiziona le risorse del kernel** in modo tale che un insieme di **processi** **veda** un insieme di **risorse** mentre un **altro** insieme di **processi** vede un **insieme** diverso di risorse. La funzionalità funziona avendo lo stesso namespace per un insieme di risorse e processi, ma quei namespace si riferiscono a risorse distinte. Le risorse possono esistere in più spazi.

Docker utilizza i seguenti Namespaces del kernel Linux per ottenere l'isolamento dei Container:

- pid namespace
- mount namespace
- network namespace
- ipc namespace
- UTS namespace

Per **maggiori informazioni sui namespaces** controlla la seguente pagina:

{{#ref}}
namespaces/
{{#endref}}

### cgroups

La funzionalità del kernel Linux **cgroups** fornisce la capacità di **ristretto risorse come cpu, memoria, io, larghezza di banda di rete tra** un insieme di processi. Docker consente di creare Container utilizzando la funzionalità cgroup che consente il controllo delle risorse per il Container specifico.\
Di seguito è riportato un Container creato con la memoria dello spazio utente limitata a 500m, la memoria del kernel limitata a 50m, la condivisione della cpu a 512, il blkioweight a 400. La condivisione della CPU è un rapporto che controlla l'uso della CPU del Container. Ha un valore predefinito di 1024 e un intervallo tra 0 e 1024. Se tre Container hanno la stessa condivisione della CPU di 1024, ciascun Container può utilizzare fino al 33% della CPU in caso di contesa delle risorse CPU. Il blkio-weight è un rapporto che controlla l'IO del Container. Ha un valore predefinito di 500 e un intervallo tra 10 e 1000.
```
docker run -it -m 500M --kernel-memory 50M --cpu-shares 512 --blkio-weight 400 --name ubuntu1 ubuntu bash
```
Per ottenere il cgroup di un container puoi fare:
```bash
docker run -dt --rm denial sleep 1234 #Run a large sleep inside a Debian container
ps -ef | grep 1234 #Get info about the sleep process
ls -l /proc/<PID>/ns #Get the Group and the namespaces (some may be uniq to the hosts and some may be shred with it)
```
Per ulteriori informazioni controlla:

{{#ref}}
cgroups.md
{{#endref}}

### Capacità

Le capacità consentono un **controllo più fine delle capacità che possono essere consentite** per l'utente root. Docker utilizza la funzionalità di capacità del kernel Linux per **limitare le operazioni che possono essere eseguite all'interno di un Container** indipendentemente dal tipo di utente.

Quando un container docker viene eseguito, il **processo abbandona capacità sensibili che il processo potrebbe utilizzare per sfuggire all'isolamento**. Questo cerca di garantire che il processo non sarà in grado di eseguire azioni sensibili e fuggire:

{{#ref}}
../linux-capabilities.md
{{#endref}}

### Seccomp in Docker

Questa è una funzionalità di sicurezza che consente a Docker di **limitare le syscalls** che possono essere utilizzate all'interno del container:

{{#ref}}
seccomp.md
{{#endref}}

### AppArmor in Docker

**AppArmor** è un miglioramento del kernel per confinare **i container** a un **insieme limitato** di **risorse** con **profili per programma**.:

{{#ref}}
apparmor.md
{{#endref}}

### SELinux in Docker

- **Sistema di Etichettatura**: SELinux assegna un'etichetta unica a ogni processo e oggetto del filesystem.
- **Applicazione delle Politiche**: Applica politiche di sicurezza che definiscono quali azioni un'etichetta di processo può eseguire su altre etichette all'interno del sistema.
- **Etichette dei Processi del Container**: Quando i motori dei container avviano processi del container, di solito viene assegnata un'etichetta SELinux confinata, comunemente `container_t`.
- **Etichettatura dei File all'interno dei Container**: I file all'interno del container sono solitamente etichettati come `container_file_t`.
- **Regole di Politica**: La politica SELinux garantisce principalmente che i processi con l'etichetta `container_t` possano interagire solo (leggere, scrivere, eseguire) con file etichettati come `container_file_t`.

Questo meccanismo garantisce che anche se un processo all'interno di un container viene compromesso, è confinato a interagire solo con oggetti che hanno le etichette corrispondenti, limitando significativamente il potenziale danno derivante da tali compromissioni.

{{#ref}}
../selinux.md
{{#endref}}

### AuthZ & AuthN

In Docker, un plugin di autorizzazione gioca un ruolo cruciale nella sicurezza decidendo se consentire o bloccare le richieste al demone Docker. Questa decisione viene presa esaminando due contesti chiave:

- **Contesto di Autenticazione**: Questo include informazioni complete sull'utente, come chi sono e come si sono autenticati.
- **Contesto del Comando**: Questo comprende tutti i dati pertinenti relativi alla richiesta effettuata.

Questi contesti aiutano a garantire che solo le richieste legittime da parte di utenti autenticati vengano elaborate, migliorando la sicurezza delle operazioni Docker.

{{#ref}}
authz-and-authn-docker-access-authorization-plugin.md
{{#endref}}

## DoS da un container

Se non limiti correttamente le risorse che un container può utilizzare, un container compromesso potrebbe causare un DoS all'host su cui è in esecuzione.

- CPU DoS
```bash
# stress-ng
sudo apt-get install -y stress-ng && stress-ng --vm 1 --vm-bytes 1G --verify -t 5m

# While loop
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
```
- Bandwidth DoS
```bash
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target IP> 4444; done
```
## Flag Docker Interessanti

### --privileged flag

Nella pagina seguente puoi imparare **cosa implica il flag `--privileged`**:

{{#ref}}
docker-privileged.md
{{#endref}}

### --security-opt

#### no-new-privileges

Se stai eseguendo un container in cui un attaccante riesce ad accedere come utente a bassa privilegio. Se hai un **binary suid mal configurato**, l'attaccante potrebbe abusarne e **escalare i privilegi all'interno** del container. Questo potrebbe permettergli di fuggire da esso.

Eseguire il container con l'opzione **`no-new-privileges`** abilitata **prevenirà questo tipo di escalation dei privilegi**.
```
docker run -it --security-opt=no-new-privileges:true nonewpriv
```
#### Altro
```bash
#You can manually add/drop capabilities with
--cap-add
--cap-drop

# You can manually disable seccomp in docker with
--security-opt seccomp=unconfined

# You can manually disable seccomp in docker with
--security-opt apparmor=unconfined

# You can manually disable selinux in docker with
--security-opt label:disable
```
Per ulteriori opzioni **`--security-opt`** controlla: [https://docs.docker.com/engine/reference/run/#security-configuration](https://docs.docker.com/engine/reference/run/#security-configuration)

## Altre Considerazioni sulla Sicurezza

### Gestione dei Segreti: Migliori Pratiche

È fondamentale evitare di incorporare segreti direttamente nelle immagini Docker o di utilizzare variabili d'ambiente, poiché questi metodi espongono le tue informazioni sensibili a chiunque abbia accesso al container tramite comandi come `docker inspect` o `exec`.

**I volumi Docker** sono un'alternativa più sicura, raccomandata per accedere a informazioni sensibili. Possono essere utilizzati come un filesystem temporaneo in memoria, mitigando i rischi associati a `docker inspect` e al logging. Tuttavia, gli utenti root e quelli con accesso `exec` al container potrebbero comunque accedere ai segreti.

**I segreti Docker** offrono un metodo ancora più sicuro per gestire informazioni sensibili. Per le istanze che richiedono segreti durante la fase di costruzione dell'immagine, **BuildKit** presenta una soluzione efficiente con supporto per segreti a tempo di costruzione, migliorando la velocità di costruzione e fornendo funzionalità aggiuntive.

Per sfruttare BuildKit, può essere attivato in tre modi:

1. Tramite una variabile d'ambiente: `export DOCKER_BUILDKIT=1`
2. Prefissando i comandi: `DOCKER_BUILDKIT=1 docker build .`
3. Abilitandolo per impostazione predefinita nella configurazione di Docker: `{ "features": { "buildkit": true } }`, seguito da un riavvio di Docker.

BuildKit consente l'uso di segreti a tempo di costruzione con l'opzione `--secret`, assicurando che questi segreti non siano inclusi nella cache di costruzione dell'immagine o nell'immagine finale, utilizzando un comando come:
```bash
docker build --secret my_key=my_value ,src=path/to/my_secret_file .
```
Per i segreti necessari in un container in esecuzione, **Docker Compose e Kubernetes** offrono soluzioni robuste. Docker Compose utilizza una chiave `secrets` nella definizione del servizio per specificare i file segreti, come mostrato in un esempio di `docker-compose.yml`:
```yaml
version: "3.7"
services:
my_service:
image: centos:7
entrypoint: "cat /run/secrets/my_secret"
secrets:
- my_secret
secrets:
my_secret:
file: ./my_secret_file.txt
```
Questa configurazione consente l'uso di segreti durante l'avvio dei servizi con Docker Compose.

Negli ambienti Kubernetes, i segreti sono supportati nativamente e possono essere ulteriormente gestiti con strumenti come [Helm-Secrets](https://github.com/futuresimple/helm-secrets). I controlli di accesso basati sui ruoli (RBAC) di Kubernetes migliorano la sicurezza nella gestione dei segreti, simile a Docker Enterprise.

### gVisor

**gVisor** è un kernel applicativo, scritto in Go, che implementa una parte sostanziale della superficie di sistema Linux. Include un runtime [Open Container Initiative (OCI)](https://www.opencontainers.org) chiamato `runsc` che fornisce un **confine di isolamento tra l'applicazione e il kernel host**. Il runtime `runsc` si integra con Docker e Kubernetes, rendendo semplice l'esecuzione di container sandboxed.

{% embed url="https://github.com/google/gvisor" %}

### Kata Containers

**Kata Containers** è una comunità open source che lavora per costruire un runtime di container sicuro con macchine virtuali leggere che si comportano e performano come container, ma forniscono **un isolamento del carico di lavoro più forte utilizzando la tecnologia di virtualizzazione hardware** come secondo strato di difesa.

{% embed url="https://katacontainers.io/" %}

### Suggerimenti Riassuntivi

- **Non utilizzare il flag `--privileged` o montare un** [**socket Docker all'interno del container**](https://raesene.github.io/blog/2016/03/06/The-Dangers-Of-Docker.sock/)**.** Lo socket Docker consente di avviare container, quindi è un modo semplice per prendere il controllo completo dell'host, ad esempio, eseguendo un altro container con il flag `--privileged`.
- **Non eseguire come root all'interno del container. Utilizzare un** [**utente diverso**](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user) **e** [**spazi dei nomi utente**](https://docs.docker.com/engine/security/userns-remap/)**.** Il root nel container è lo stesso che sull'host a meno che non venga rimappato con gli spazi dei nomi utente. È solo leggermente limitato da, principalmente, spazi dei nomi Linux, capacità e cgroups.
- [**Eliminare tutte le capacità**](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities) **(`--cap-drop=all`) e abilitare solo quelle necessarie** (`--cap-add=...`). Molti carichi di lavoro non necessitano di capacità e aggiungerle aumenta l'ambito di un potenziale attacco.
- [**Utilizzare l'opzione di sicurezza “no-new-privileges”**](https://raesene.github.io/blog/2019/06/01/docker-capabilities-and-no-new-privs/) per impedire ai processi di acquisire più privilegi, ad esempio tramite binari suid.
- [**Limitare le risorse disponibili per il container**](https://docs.docker.com/engine/reference/run/#runtime-constraints-on-resources)**.** I limiti delle risorse possono proteggere la macchina da attacchi di denial of service.
- **Regolare i profili** [**seccomp**](https://docs.docker.com/engine/security/seccomp/)**,** [**AppArmor**](https://docs.docker.com/engine/security/apparmor/) **(o SELinux)** per limitare le azioni e le syscalls disponibili per il container al minimo necessario.
- **Utilizzare** [**immagini docker ufficiali**](https://docs.docker.com/docker-hub/official_images/) **e richiedere firme** o costruire le proprie basate su di esse. Non ereditare o utilizzare immagini [backdoored](https://arstechnica.com/information-technology/2018/06/backdoored-images-downloaded-5-million-times-finally-removed-from-docker-hub/). Inoltre, conservare le chiavi root e le frasi di accesso in un luogo sicuro. Docker ha piani per gestire le chiavi con UCP.
- **Ricostruire regolarmente** le proprie immagini per **applicare patch di sicurezza all'host e alle immagini.**
- Gestire i propri **segreti con saggezza** in modo che sia difficile per l'attaccante accedervi.
- Se **esponi il demone docker utilizza HTTPS** con autenticazione client e server.
- Nel tuo Dockerfile, **preferisci COPY invece di ADD**. ADD estrae automaticamente file compressi e può copiare file da URL. COPY non ha queste capacità. Ogni volta che è possibile, evita di utilizzare ADD per non essere suscettibile ad attacchi tramite URL remoti e file Zip.
- Avere **container separati per ogni micro-servizio**
- **Non mettere ssh** all'interno del container, “docker exec” può essere utilizzato per ssh nel Container.
- Avere **immagini di container più piccole**

## Docker Breakout / Privilege Escalation

Se sei **all'interno di un container docker** o hai accesso a un utente nel **gruppo docker**, potresti provare a **fuggire e aumentare i privilegi**:

{{#ref}}
docker-breakout-privilege-escalation/
{{#endref}}

## Bypass del Plugin di Autenticazione Docker

Se hai accesso allo socket docker o hai accesso a un utente nel **gruppo docker ma le tue azioni sono limitate da un plugin di autenticazione docker**, controlla se puoi **bypassarlo:**

{{#ref}}
authz-and-authn-docker-access-authorization-plugin.md
{{#endref}}

## Hardening Docker

- Lo strumento [**docker-bench-security**](https://github.com/docker/docker-bench-security) è uno script che controlla dozzine di best practice comuni per il deployment di container Docker in produzione. I test sono tutti automatizzati e si basano sul [CIS Docker Benchmark v1.3.1](https://www.cisecurity.org/benchmark/docker/).\
Devi eseguire lo strumento dall'host che esegue docker o da un container con privilegi sufficienti. Scopri **come eseguirlo nel README:** [**https://github.com/docker/docker-bench-security**](https://github.com/docker/docker-bench-security).

## Riferimenti

- [https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
- [https://twitter.com/\_fel1x/status/1151487051986087936](https://twitter.com/_fel1x/status/1151487051986087936)
- [https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html](https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html)
- [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-1overview/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-1overview/)
- [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/)
- [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/)
- [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-4container-image/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-4container-image/)
- [https://en.wikipedia.org/wiki/Linux_namespaces](https://en.wikipedia.org/wiki/Linux_namespaces)
- [https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57](https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57)
- [https://www.redhat.com/sysadmin/privileged-flag-container-engines](https://www.redhat.com/sysadmin/privileged-flag-container-engines)
- [https://docs.docker.com/engine/extend/plugins_authorization](https://docs.docker.com/engine/extend/plugins_authorization)
- [https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57](https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57)
- [https://resources.experfy.com/bigdata-cloud/top-20-docker-security-tips/](https://resources.experfy.com/bigdata-cloud/top-20-docker-security-tips/)


{{#include ../../../banners/hacktricks-training.md}}
