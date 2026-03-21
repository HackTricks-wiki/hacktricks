# Namespaces

{{#include ../../../../../banners/hacktricks-training.md}}

Namespaces sono la funzionalità del kernel che fa sembrare un container "la sua macchina" anche se in realtà è solo un albero di processi dell'host. Non creano un nuovo kernel e non virtualizzano tutto, ma permettono al kernel di presentare viste diverse di risorse selezionate a diversi gruppi di processi. Questa è la chiave dell'illusione del container: il carico di lavoro vede un filesystem, una tabella dei processi, uno stack di rete, un hostname, risorse IPC e un modello di identità utente/gruppo che appaiono locali, anche se il sistema sottostante è condiviso.

Per questo i namespaces sono il primo concetto che la maggior parte delle persone incontra quando impara come funzionano i container. Allo stesso tempo, sono uno dei concetti più spesso fraintesi perché i lettori spesso presumono che "ha namespaces" significhi "è isolato in modo sicuro". In realtà, un namespace isola solo la specifica classe di risorse per cui è stato progettato. Un processo può avere un PID namespace privato e comunque essere pericoloso perché ha una bind mount host scrivibile. Può avere un network namespace privato e comunque essere pericoloso perché conserva `CAP_SYS_ADMIN` e gira senza seccomp. I namespaces sono fondamentali, ma sono solo uno strato nel confine finale.

## Namespace Types

Linux containers fanno comunemente affidamento su più tipi di namespace contemporaneamente. Il **mount namespace** dà al processo una tabella di mount separata e quindi una vista filesystem controllata. Il **PID namespace** cambia la visibilità e la numerazione dei processi in modo che il carico di lavoro veda il proprio albero di processi. Il **network namespace** isola interfacce, route, socket e lo stato del firewall. Il **IPC namespace** isola SysV IPC e le code di messaggi POSIX. Il **UTS namespace** isola hostname e NIS domain name. Il **user namespace** rimappa gli user e group ID in modo che root dentro il container non significhi necessariamente root sull'host. Il **cgroup namespace** virtualizza la gerarchia di cgroup visibile, e il **time namespace** virtualizza alcuni clock nelle kernel più recenti.

Ognuno di questi namespaces risolve un problema diverso. Per questo l'analisi pratica della sicurezza dei container spesso si riduce a verificare **quali namespaces sono isolati** e **quali sono stati deliberatamente condivisi con l'host**.

## Host Namespace Sharing

Molte escape da container non iniziano con una vulnerabilità del kernel. Iniziano con un operatore che indebolisce deliberatamente il modello di isolamento. Gli esempi `--pid=host`, `--network=host`, e `--userns=host` sono **Docker/Podman-style CLI flags** usati qui come esempi concreti di condivisione di namespace con l'host. Altri runtimes esprimono la stessa idea in modo diverso. In Kubernetes gli equivalenti appaiono solitamente come impostazioni del Pod come `hostPID: true`, `hostNetwork: true`, o `hostIPC: true`. In stack di runtime di livello più basso come containerd o CRI-O, lo stesso comportamento è spesso raggiunto tramite la configurazione runtime OCI generata piuttosto che tramite una flag rivolta all'utente con lo stesso nome. In tutti questi casi, il risultato è simile: il carico di lavoro non riceve più la vista di namespace isolata di default.

Per questo le revisioni dei namespace non dovrebbero mai fermarsi a "il processo è in qualche namespace". La domanda importante è se il namespace è privato per il container, condiviso con container fratelli, o collegato direttamente all'host. In Kubernetes la stessa idea appare con flag come `hostPID`, `hostNetwork`, e `hostIPC`. I nomi cambiano tra le piattaforme, ma il modello di rischio è lo stesso: un namespace host condiviso rende i privilegi residui del container e lo stato dell'host raggiungibile molto più significativi.

## Inspection

La panoramica più semplice è:
```bash
ls -l /proc/self/ns
```
Ogni voce è un collegamento simbolico con un identificatore simile a un inode. Se due processi puntano allo stesso identificatore di namespace, si trovano nello stesso namespace di quel tipo. Questo rende `/proc` un posto molto utile per confrontare il processo corrente con altri processi interessanti sulla macchina.

Questi comandi rapidi sono spesso sufficienti per cominciare:
```bash
readlink /proc/self/ns/mnt
readlink /proc/self/ns/pid
readlink /proc/self/ns/net
readlink /proc/1/ns/mnt
```
Da lì, il passo successivo è confrontare il processo del container con i processi dell'host o con processi vicini e determinare se un namespace è effettivamente privato o meno.

### Enumerare le istanze di namespace dall'host

Quando si ha già accesso all'host e si vuole capire quanti namespace distinti di un determinato tipo esistono, `/proc` fornisce un inventario rapido:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name pid    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name net    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name ipc    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name uts    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name user   -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name cgroup -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name time   -exec readlink {} \; 2>/dev/null | sort -u
```
Se vuoi trovare quali processi appartengono a uno specifico identificatore di namespace, passa da `readlink` a `ls -l` e cerca con grep il numero del namespace di destinazione:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```
Questi comandi sono utili perché consentono di stabilire se un host esegue un singolo workload isolato, molti workload isolati, o una combinazione di istanze con namespace condivisi e privati.

### Entering A Target Namespace

Quando il processo chiamante ha privilegi sufficienti, `nsenter` è il metodo standard per entrare nel namespace di un altro processo:
```bash
nsenter -m TARGET_PID --pid /bin/bash   # mount
nsenter -t TARGET_PID --pid /bin/bash   # pid
nsenter -n TARGET_PID --pid /bin/bash   # network
nsenter -i TARGET_PID --pid /bin/bash   # ipc
nsenter -u TARGET_PID --pid /bin/bash   # uts
nsenter -U TARGET_PID --pid /bin/bash   # user
nsenter -C TARGET_PID --pid /bin/bash   # cgroup
nsenter -T TARGET_PID --pid /bin/bash   # time
```
L'elenco di queste forme insieme non significa che ogni assessment ne abbia bisogno, ma che il post-exploitation specifico per namespace diventa spesso molto più semplice una volta che l'operatore conosce la sintassi di ingresso esatta invece di ricordare solo la forma all-namespaces.

## Pagine

Le seguenti pagine spiegano ciascun namespace in maggiore dettaglio:

{{#ref}}
mount-namespace.md
{{#endref}}

{{#ref}}
pid-namespace.md
{{#endref}}

{{#ref}}
network-namespace.md
{{#endref}}

{{#ref}}
ipc-namespace.md
{{#endref}}

{{#ref}}
uts-namespace.md
{{#endref}}

{{#ref}}
user-namespace.md
{{#endref}}

{{#ref}}
cgroup-namespace.md
{{#endref}}

{{#ref}}
time-namespace.md
{{#endref}}

Mentre le leggi, tieni a mente due idee. Primo, ogni namespace isola solo un tipo di vista. Secondo, un namespace privato è utile solo se il resto del modello di privilegi rende ancora significativa quell'isolamento.

## Runtime Defaults

| Runtime / platform | Comportamento predefinito dei namespace | Indebolimenti manuali comuni |
| --- | --- | --- |
| Docker Engine | New mount, PID, network, IPC, and UTS namespaces by default; user namespaces are available but not enabled by default in standard rootful setups | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Podman | New namespaces by default; rootless Podman automatically uses a user namespace; cgroup namespace defaults depend on cgroup version | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Kubernetes | Pods do **not** share host PID, network, or IPC by default; Pod networking is private to the Pod, not to each individual container; user namespaces are opt-in via `spec.hostUsers: false` on supported clusters | `hostPID: true`, `hostNetwork: true`, `hostIPC: true`, `spec.hostUsers: true` / omitting user-namespace opt-in, privileged workload settings |
| containerd / CRI-O under Kubernetes | Usually follow Kubernetes Pod defaults | same as Kubernetes row; direct CRI/OCI specs can also request host namespace joins |

La regola principale di portabilità è semplice: il **concept** di condivisione dei namespace host è comune tra i runtime, ma la **syntax** è specifica del runtime.
