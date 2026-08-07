# Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

I namespace sono la funzionalità del kernel che fa sembrare un container una "macchina propria", anche se in realtà è solo un albero di processi dell'host. Non creano un nuovo kernel e non virtualizzano ogni componente, ma permettono al kernel di presentare viste diverse delle risorse selezionate a gruppi diversi di processi. Questo è il nucleo dell'illusione del container: il workload vede un filesystem, una tabella dei processi, uno stack di rete, un hostname, risorse IPC e un modello di identità utente/gruppo che sembrano locali, anche se il sistema sottostante è condiviso.

Questo è il motivo per cui i namespace sono il primo concetto che la maggior parte delle persone incontra quando impara come funzionano i container. Allo stesso tempo, sono uno dei concetti più fraintesi, perché spesso si presume che "avere i namespace" significhi "essere isolati in modo sicuro". In realtà, un namespace isola solo la classe specifica di risorse per cui è stato progettato. Un processo può avere un namespace PID privato ed essere comunque pericoloso perché dispone di un bind mount dell'host scrivibile. Può avere un namespace di rete privato ed essere comunque pericoloso perché conserva `CAP_SYS_ADMIN` ed è in esecuzione senza seccomp. I namespace sono fondamentali, ma rappresentano solo un livello del confine finale.

## Tipi di namespace

I container Linux fanno comunemente affidamento su diversi tipi di namespace contemporaneamente. Il **mount namespace** fornisce al processo una tabella dei mount separata e quindi una vista controllata del filesystem. Il **PID namespace** modifica la visibilità e la numerazione dei processi, così il workload vede il proprio albero dei processi. Il **network namespace** isola interfacce, route, socket e stato del firewall. Il **IPC namespace** isola l'IPC SysV e le code di messaggi POSIX. Il **UTS namespace** isola l'hostname e il nome del dominio NIS. Il **user namespace** rimappa gli ID utente e gruppo, così root all'interno del container non significa necessariamente root sull'host. Il **cgroup namespace** virtualizza la gerarchia cgroup visibile, mentre il **time namespace** virtualizza determinati clock nei kernel più recenti.

Ognuno di questi namespace risolve un problema diverso. Per questo l'analisi pratica della sicurezza dei container spesso consiste nel verificare **quali namespace sono isolati** e **quali sono stati deliberatamente condivisi con l'host**.

## Condivisione dei namespace dell'host

Molti container breakout non iniziano con una vulnerabilità del kernel. Iniziano con un operatore che indebolisce deliberatamente il modello di isolamento. Gli esempi `--pid=host`, `--network=host` e `--userns=host` sono **flag CLI in stile Docker/Podman** usati qui come esempi concreti di condivisione dei namespace dell'host. Altri runtime esprimono la stessa idea in modo diverso. In Kubernetes, gli equivalenti compaiono solitamente come impostazioni del Pod come `hostPID: true`, `hostNetwork: true` o `hostIPC: true`. Negli stack runtime di livello più basso come containerd o CRI-O, lo stesso comportamento viene spesso ottenuto tramite la configurazione runtime OCI generata, anziché tramite un flag rivolto all'utente con lo stesso nome. In tutti questi casi, il risultato è simile: il workload non riceve più la vista predefinita dei namespace isolati.

Per questo le verifiche dei namespace non dovrebbero mai fermarsi alla frase "il processo è in un qualche namespace". La domanda importante è se il namespace sia privato del container, condiviso con container fratelli o direttamente associato all'host. In Kubernetes la stessa idea compare con flag come `hostPID`, `hostNetwork` e `hostIPC`. I nomi cambiano tra le piattaforme, ma il pattern di rischio è lo stesso: un namespace dell'host condiviso rende molto più significativi i privilegi rimanenti del container e lo stato dell'host raggiungibile.

## Ispezione

La panoramica più semplice è:
```bash
ls -l /proc/self/ns
```
Ogni voce è un collegamento simbolico con un identificatore simile a un inode. Se due processi puntano allo stesso identificatore di namespace, si trovano nello stesso namespace di quel tipo. Questo rende `/proc` un luogo molto utile per confrontare il processo corrente con altri processi interessanti presenti sulla macchina.

Questi comandi rapidi sono spesso sufficienti per iniziare:
```bash
readlink /proc/self/ns/mnt
readlink /proc/self/ns/pid
readlink /proc/self/ns/net
readlink /proc/1/ns/mnt
```
Da lì, il passo successivo consiste nel confrontare il processo del container con i processi dell'host o dei container vicini e determinare se un namespace è effettivamente privato oppure no.

### Enumerazione delle Istanze dei Namespace dall'Host

Quando hai già accesso all'host e vuoi capire quante istanze distinte di un determinato tipo di namespace esistono, `/proc` fornisce un inventario rapido:
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
Se vuoi individuare quali processi appartengono a uno specifico identificatore di namespace, passa da `readlink` a `ls -l` e usa grep per cercare il numero del namespace target:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```
Questi comandi sono utili perché consentono di determinare se un host esegue un workload isolato, più workload isolati oppure una combinazione di istanze con namespace condivisi e privati.

### Accesso al namespace di destinazione

Quando il chiamante dispone dei privilegi sufficienti, `nsenter` è il metodo standard per unirsi al namespace di un altro processo:
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
Il punto di elencare insieme queste forme non è che ogni assessment debba usarle tutte, ma che il post-exploitation specifico per namespace diventa spesso molto più semplice quando l'operator conosce la sintassi esatta per l'accesso, invece di ricordare solo la forma relativa a tutti i namespace.

## Pagine

Le pagine seguenti spiegano ogni namespace in maggiore dettaglio:

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

Durante la lettura, tenete presenti due idee. Primo, ogni namespace isola un solo tipo di vista. Secondo, un namespace privato è utile solo se il resto del modello dei privilegi continua a rendere significativa tale separazione.

## Impostazioni predefinite dei runtime

| Runtime / piattaforma | Configurazione predefinita dei namespace | Indebolimento manuale comune |
| --- | --- | --- |
| Docker Engine | Nuovi namespace mount, PID, network, IPC e UTS per impostazione predefinita; i user namespace sono disponibili, ma non sono abilitati per impostazione predefinita nelle configurazioni rootful standard | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Podman | Nuovi namespace per impostazione predefinita; Podman rootless usa automaticamente un user namespace; i valori predefiniti del cgroup namespace dipendono dalla versione di cgroup | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Kubernetes | I Pod **non** condividono per impostazione predefinita PID, network o IPC dell'host; il networking del Pod è privato del Pod, non di ogni singolo container; i user namespace sono opt-in tramite `spec.hostUsers: false` nei cluster supportati | `hostPID: true`, `hostNetwork: true`, `hostIPC: true`, `spec.hostUsers: true` / omissione dell'opt-in dei user namespace, impostazioni per workload privilegiati |
| containerd / CRI-O under Kubernetes | Di solito seguono le impostazioni predefinite dei Pod Kubernetes | come nella riga Kubernetes; le specifiche CRI/OCI dirette possono inoltre richiedere il join ai namespace dell'host |

La principale regola di portabilità è semplice: il **concetto** di condivisione dei namespace dell'host è comune tra i runtime, ma la **sintassi** è specifica del runtime.

{{#include ../../../../../banners/hacktricks-training.md}}
