# Namespaces

{{#include ../../../../../banners/hacktricks-training.md}}

Namespaces sono la feature del kernel che fanno sembrare un container "la sua macchina" anche se in realtà è solo un albero di processi dell'host. Non creano un nuovo kernel e non virtualizzano tutto, ma permettono al kernel di presentare viste diverse di risorse selezionate a diversi gruppi di processi. Questo è il nucleo dell'illusione del container: il workload vede un filesystem, una tabella dei processi, uno stack di rete, un hostname, risorse IPC e un modello di identità utenti/gruppi che appaiono locali, anche se il sistema sottostante è condiviso.

Questo è il motivo per cui namespaces è il primo concetto che la maggior parte delle persone incontra quando impara come funzionano i container. Allo stesso tempo, sono uno dei concetti più spesso fraintesi perché i lettori presumono spesso che "ha namespaces" significhi "è isolato in modo sicuro". In realtà, un namespace isola solo la specifica classe di risorse per cui è stato progettato. Un processo può avere un private PID namespace ed essere comunque pericoloso perché ha un host bind mount scrivibile. Può avere un private network namespace ed essere comunque pericoloso perché mantiene `CAP_SYS_ADMIN` e gira senza seccomp. I namespaces sono fondamentali, ma sono solo uno strato nel confine finale.

## Namespace Types

I Linux container comunemente si basano su diversi tipi di namespace contemporaneamente. The **mount namespace** fornisce al processo una tabella dei mount separata e quindi una vista controllata del filesystem. The **PID namespace** cambia la visibilità e la numerazione dei processi così che il workload veda il proprio albero dei processi. The **network namespace** isola interfacce, route, socket e lo stato del firewall. The **IPC namespace** isola SysV IPC e POSIX message queues. The **UTS namespace** isola hostname e NIS domain name. The **user namespace** rimappa gli user e group ID in modo che root dentro il container non significhi necessariamente root sull'host. The **cgroup namespace** virtualizza la gerarchia di cgroup visibile, e the **time namespace** virtualizza orologi selezionati nei kernel più recenti.

Ognuno di questi namespaces risolve un problema diverso. Per questo l'analisi pratica della sicurezza dei container spesso si riduce a controllare **which namespaces are isolated** e **which ones have been deliberately shared with the host**.

## Host Namespace Sharing

Molti breakout da container non iniziano con una vulnerabilità del kernel. Iniziano con un operatore che indebolisce deliberatamente il modello di isolamento. Gli esempi `--pid=host`, `--network=host`, e `--userns=host` sono **Docker/Podman-style CLI flags** usati qui come esempi concreti di condivisione del namespace con l'host. Altri runtime esprimono la stessa idea in modo diverso. In Kubernetes gli equivalenti solitamente compaiono come impostazioni del Pod come `hostPID: true`, `hostNetwork: true`, o `hostIPC: true`. In stack runtime di livello inferiore come containerd o CRI-O, lo stesso comportamento è spesso ottenuto tramite la OCI runtime configuration generata piuttosto che tramite una flag rivolta all'utente con lo stesso nome. In tutti questi casi, il risultato è simile: il workload non riceve più la vista di namespace isolato di default.

Ecco perché le revisioni dei namespace non dovrebbero mai fermarsi a "il processo è in qualche namespace". La domanda importante è se il namespace è privato al container, condiviso con container fratelli, o unito direttamente all'host. In Kubernetes la stessa idea ricorre con flag come `hostPID`, `hostNetwork`, e `hostIPC`. I nomi cambiano tra le piattaforme, ma il pattern di rischio è lo stesso: un host namespace condiviso rende i privilegi residui del container e lo stato raggiungibile dell'host molto più rilevanti.

## Inspection

La panoramica più semplice è:
```bash
ls -l /proc/self/ns
```
Ogni voce è un collegamento simbolico con un identificatore simile a un inode. Se due processi puntano allo stesso identificatore di namespace, appartengono allo stesso namespace di quel tipo. Questo rende `/proc` un posto molto utile per confrontare il processo corrente con altri processi interessanti sulla macchina.

Questi comandi rapidi sono spesso sufficienti per cominciare:
```bash
readlink /proc/self/ns/mnt
readlink /proc/self/ns/pid
readlink /proc/self/ns/net
readlink /proc/1/ns/mnt
```
Da lì, il passo successivo è confrontare il processo del container con i processi dell'host o dei processi vicini e determinare se un namespace sia effettivamente privato o meno.

### Enumerazione delle istanze di namespace dall'host

Quando hai già accesso all'host e vuoi capire quante namespace distinte di un dato tipo esistono, `/proc` fornisce un inventario rapido:
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
Se vuoi trovare quali processi appartengono a un identificatore di namespace specifico, passa da `readlink` a `ls -l` e usa grep per il numero del namespace di destinazione:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```
Questi comandi sono utili perché permettono di determinare se un host sta eseguendo un singolo carico di lavoro isolato, molti carichi di lavoro isolati, o una combinazione di istanze con namespace condivisi e privati.

### Entrare in un namespace di destinazione

Quando il chiamante ha privilegi sufficienti, `nsenter` è il metodo standard per entrare nel namespace di un altro processo:
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
Lo scopo di elencare queste forme insieme non è che ogni assessment abbia bisogno di tutte, ma che il post-exploitation specifico del namespace spesso diventa molto più semplice una volta che l'operatore conosce la sintassi di ingresso esatta invece di ricordare solo la forma all-namespaces.

## Pagine

Le seguenti pagine spiegano ogni namespace in modo più dettagliato:

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

Leggendole, tieni a mente due concetti. Primo, ogni namespace isola solo un tipo di vista. Secondo, un namespace privato è utile solo se il resto del modello di privilegi rende ancora significativo quell'isolamento.

## Runtime Defaults

| Runtime / platform | Default namespace posture | Common manual weakening |
| --- | --- | --- |
| Docker Engine | New mount, PID, network, IPC, and UTS namespaces by default; user namespaces are available but not enabled by default in standard rootful setups | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Podman | New namespaces by default; rootless Podman automatically uses a user namespace; cgroup namespace defaults depend on cgroup version | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Kubernetes | Pods do **not** share host PID, network, or IPC by default; Pod networking is private to the Pod, not to each individual container; user namespaces are opt-in via `spec.hostUsers: false` on supported clusters | `hostPID: true`, `hostNetwork: true`, `hostIPC: true`, `spec.hostUsers: true` / omitting user-namespace opt-in, privileged workload settings |
| containerd / CRI-O under Kubernetes | Usually follow Kubernetes Pod defaults | same as Kubernetes row; direct CRI/OCI specs can also request host namespace joins |

La regola principale di portabilità è semplice: il **concetto** di condivisione del namespace host è comune tra i runtime, ma la **sintassi** è specifica del runtime.
{{#include ../../../../../banners/hacktricks-training.md}}
