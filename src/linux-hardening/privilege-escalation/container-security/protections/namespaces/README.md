# Namespaces

{{#include ../../../../../banners/hacktricks-training.md}}

Namespaces sono la funzionalità del kernel che fa sentire un container come "la sua macchina" anche se in realtà è solo un albero di processi dell'host. Non creano un nuovo kernel e non virtualizzano tutto, ma permettono al kernel di presentare diverse viste di risorse selezionate a gruppi diversi di processi. Questo è il nucleo dell'illusione del container: il workload vede un filesystem, una tabella dei processi, uno stack di rete, un hostname, risorse IPC e un modello di identità utenti/gruppi che appaiono locali, anche se il sistema sottostante è condiviso.

Ecco perché i namespaces sono il primo concetto che la maggior parte delle persone incontra quando impara come funzionano i container. Allo stesso tempo, sono uno dei concetti più spesso fraintesi perché i lettori assumono spesso che "ha namespaces" significhi "è isolato in modo sicuro". In realtà, un namespace isola solo la specifica classe di risorse per cui è stato progettato. Un processo può avere un PID namespace privato e risultare comunque pericoloso perché ha un bind mount dell'host scrivibile. Può avere un network namespace privato e risultare comunque pericoloso perché mantiene `CAP_SYS_ADMIN` e gira senza seccomp. I namespaces sono fondamentali, ma sono solo uno strato del confine finale.

## Namespace Types

I container Linux si basano spesso su più tipi di namespace contemporaneamente. Il **mount namespace** fornisce al processo una tabella di mount separata e quindi una vista del filesystem controllata. Il **PID namespace** cambia la visibilità e la numerazione dei processi così il workload vede il proprio albero di processi. Il **network namespace** isola interfacce, route, socket e lo stato del firewall. Il **IPC namespace** isola SysV IPC e le code di messaggi POSIX. Il **UTS namespace** isola hostname e il NIS domain name. Il **user namespace** rimappa gli UID e GID in modo che root all'interno del container non significhi necessariamente root sull'host. Il **cgroup namespace** virtualizza la gerarchia di cgroup visibile, e il **time namespace** virtualizza alcuni orologi nei kernel più recenti.

Ciascuno di questi namespace risolve un problema diverso. Per questo motivo l'analisi pratica della sicurezza dei container spesso si riduce a verificare **quali namespaces sono isolati** e **quali sono stati deliberatamente condivisi con l'host**.

## Host Namespace Sharing

Molte fughe da container non iniziano con una vulnerabilità del kernel. Iniziano con un operatore che indebolisce deliberatamente il modello di isolamento. Gli esempi `--pid=host`, `--network=host` e `--userns=host` sono **Docker/Podman-style CLI flags** usati qui come esempi concreti di condivisione dei namespace con l'host. Altri runtime esprimono la stessa idea in modo diverso. In Kubernetes gli equivalenti di solito appaiono come impostazioni del Pod quali `hostPID: true`, `hostNetwork: true` o `hostIPC: true`. In stack di runtime a più basso livello come containerd o CRI-O, lo stesso comportamento è spesso ottenuto tramite la OCI runtime configuration generata piuttosto che tramite una flag rivolta all'utente con lo stesso nome. In tutti questi casi, il risultato è simile: il workload non riceve più la vista di namespace isolata di default.

Per questo motivo le revisioni dei namespace non dovrebbero mai fermarsi a "il processo è in qualche namespace". La domanda importante è se il namespace è privato al container, condiviso con container fratelli, o collegato direttamente all'host. In Kubernetes la stessa idea appare con flag come `hostPID`, `hostNetwork` e `hostIPC`. I nomi cambiano tra le piattaforme, ma il pattern di rischio è lo stesso: un namespace host condiviso rende i privilegi residui del container e lo stato dell'host raggiungibile molto più significativi.

## Inspection

La panoramica più semplice è:
```bash
ls -l /proc/self/ns
```
Ogni voce è un link simbolico con un identificatore simile a un inode. Se due processi puntano allo stesso identificatore di namespace, si trovano nello stesso namespace di quel tipo. Questo rende `/proc` un posto molto utile per confrontare il processo corrente con altri processi interessanti sulla macchina.

Questi comandi rapidi sono spesso sufficienti per cominciare:
```bash
readlink /proc/self/ns/mnt
readlink /proc/self/ns/pid
readlink /proc/self/ns/net
readlink /proc/1/ns/mnt
```
Da lì, il passo successivo è confrontare il processo del container con i processi dell'host o con quelli vicini e determinare se un namespace è effettivamente privato o meno.

### Enumerare le istanze di namespace dall'host

Quando si ha già accesso all'host e si vuole capire quante istanze distinte di namespace di un dato tipo esistono, `/proc` fornisce un inventario rapido:
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
Se vuoi scoprire a quali processi appartiene uno specifico identificatore di namespace, passa da `readlink` a `ls -l` e fai grep per il numero del namespace target:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```
Questi comandi sono utili perché permettono di determinare se un host sta eseguendo un singolo workload isolato, molti workload isolati, o una combinazione di istanze con namespace condivisi e privati.

### Entrare in un target namespace

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
Lo scopo di elencare queste forme insieme non è che ogni assessment ne richieda tutte, ma che la post-exploitation specifica per namespace spesso diventa molto più semplice una volta che l'operatore conosce la sintassi d'ingresso esatta invece di ricordare solo la forma per tutti i namespace.

## Pages

The following pages explain each namespace in more detail:

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

Durante la lettura, tieni a mente due concetti. Primo, ogni namespace isola un solo tipo di vista. Secondo, un namespace privato è utile solo se il resto del modello di privilegi rende quell'isolamento ancora significativo.

## Runtime Defaults

| Runtime / platform | Default namespace posture | Common manual weakening |
| --- | --- | --- |
| Docker Engine | Nuovi namespace mount, PID, network, IPC e UTS per impostazione predefinita; i user namespace sono disponibili ma non abilitati di default nelle configurazioni rootful standard | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Podman | Nuovi namespace per impostazione predefinita; Podman rootless usa automaticamente un user namespace; le impostazioni predefinite del cgroup namespace dipendono dalla versione di cgroup | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Kubernetes | Per impostazione predefinita i Pod **non** condividono PID, network o IPC dell'host; la rete del Pod è privata al Pod, non a ciascun container individuale; i user namespace sono opt-in tramite `spec.hostUsers: false` sui cluster che lo supportano | `hostPID: true`, `hostNetwork: true`, `hostIPC: true`, `spec.hostUsers: true` / omitting user-namespace opt-in, privileged workload settings |
| containerd / CRI-O under Kubernetes | Di solito seguono le impostazioni predefinite dei Pod di Kubernetes | same as Kubernetes row; direct CRI/OCI specs can also request host namespace joins |

La regola principale di portabilità è semplice: il **concetto** di condivisione dei namespace dell'host è comune tra i runtime, ma la **sintassi** è specifica per runtime.
{{#include ../../../../../banners/hacktricks-training.md}}
