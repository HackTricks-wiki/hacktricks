# Namespace PID

{{#include ../../../../../banners/hacktricks-training.md}}

## Panoramica

Il namespace PID controlla come i processi sono numerati e quali processi sono visibili. Per questo un container può avere il proprio PID 1 anche se non è una macchina reale. All'interno del namespace, il workload vede quello che sembra essere un albero di processi locale. Fuori dal namespace, l'host vede comunque i reali PID dell'host e l'intero panorama dei processi.

Dal punto di vista della sicurezza, il namespace PID è importante perché la visibilità dei processi è preziosa. Se un workload può vedere i processi dell'host, potrebbe essere in grado di osservare nomi dei servizi, argomenti della riga di comando, secret passati negli argomenti dei processi, stato derivato dall'ambiente tramite `/proc`, e potenziali obiettivi per l'ingresso nel namespace. Se può fare più che limitarsi a vedere quei processi, per esempio inviando segnali o usando ptrace nelle giuste condizioni, il problema diventa molto più serio.

## Funzionamento

Un nuovo namespace PID inizia con una propria numerazione interna dei processi. Il primo processo creato al suo interno diventa PID 1 dal punto di vista del namespace, il che significa anche che riceve semantiche speciali simili a init per i figli orfani e il comportamento dei segnali. Questo spiega molte stranezze dei container relative ai processi init, al reaping degli zombie, e perché a volte vengono usati piccoli init wrapper nei container.

La lezione importante per la sicurezza è che un processo può sembrare isolato perché vede solo il proprio albero dei PID, ma quell'isolamento può essere rimosso deliberatamente. Docker espone questa possibilità tramite `--pid=host`, mentre Kubernetes lo fa tramite `hostPID: true`. Una volta che il container si unisce al namespace PID dell'host, il workload vede direttamente i processi dell'host e molte vie di attacco successive diventano molto più realistiche.

## Laboratorio

Per creare manualmente un namespace PID:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
La shell ora vede una vista dei processi privata. Il flag `--mount-proc` è importante perché monta un'istanza di procfs che corrisponde al nuovo namespace PID, rendendo la lista dei processi coerente dall'interno.

Per confrontare il comportamento del container:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
La differenza è immediata e facile da comprendere, perciò questo è un buon primo laboratorio per i lettori.

## Runtime Usage

I container normali in Docker, Podman, containerd e CRI-O ottengono il proprio namespace PID. I Kubernetes Pods di solito ricevono anche una vista PID isolata a meno che il workload non richieda esplicitamente la condivisione del PID dell'host. Gli ambienti LXC/Incus si basano sulla stessa primitiva del kernel, anche se i casi d'uso di system-container possono esporre alberi di processi più complicati e favorire scorciatoie di debugging.

La stessa regola vale ovunque: se il runtime sceglie di non isolare il namespace PID, si tratta di una riduzione deliberata del perimetro del container.

## Misconfigurations

La misconfigurazione canonica è la condivisione del PID dell'host. I team spesso la giustificano per comodità di debugging, monitoring o gestione dei servizi, ma dovrebbe sempre essere considerata un'eccezione significativa alla sicurezza. Anche se il container non ha una primitiva di scrittura immediata sui processi dell'host, la sola visibilità può rivelare molto sul sistema. Una volta aggiunte capability come `CAP_SYS_PTRACE` o un accesso utile a procfs, il rischio aumenta significativamente.

Un altro errore è assumere che, poiché il workload non può uccidere o ptrace i processi dell'host per impostazione predefinita, la condivisione del PID dell'host sia quindi innocua. Questa conclusione ignora il valore dell'enumerazione, la disponibilità di target per l'ingresso in namespace, e il modo in cui la visibilità dei PID si combina con altri controlli indeboliti.

## Abuse

Se il namespace PID dell'host è condiviso, un attaccante può ispezionare i processi dell'host, raccogliere gli argomenti dei processi, identificare servizi interessanti, trovare PID candidati per `nsenter`, o combinare la visibilità dei processi con privilegi relativi a ptrace per interferire con i workload dell'host o vicini. In alcuni casi, vedere semplicemente il processo di lunga durata giusto è sufficiente a rimodellare il resto del piano d'attacco.

Il primo passo pratico è sempre confermare che i processi dell'host siano effettivamente visibili:
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
Una volta che i PID dell'host sono visibili, gli argomenti dei processi e gli obiettivi di ingresso nei namespace diventano spesso la fonte di informazioni più utile:
```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
echo "PID=$p"
tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```
Se `nsenter` è disponibile e sono presenti privilegi sufficienti, verifica se un processo host visibile può essere usato come namespace bridge:
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
Anche quando l'accesso è bloccato, la condivisione dei PID dell'host è già preziosa perché rivela la disposizione dei servizi, i componenti in esecuzione e i processi privilegiati candidati da prendere di mira successivamente.

La visibilità dei PID dell'host rende inoltre l'abuso dei file-descriptor più realistico. Se un processo privilegiato dell'host o un workload vicino ha un file o una socket sensibile aperti, l'attaccante potrebbe essere in grado di ispezionare `/proc/<pid>/fd/` e riutilizzare quel handle a seconda della proprietà, delle opzioni di mount di procfs e del modello del servizio target.
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
Questi comandi sono utili perché mostrano se `hidepid=1` o `hidepid=2` riducono la visibilità tra processi e se descrittori chiaramente interessanti, come file segreti aperti, log o socket Unix, siano visibili.

### Esempio completo: host PID + `nsenter`

La condivisione del PID dell'host diventa una fuga diretta dall'host quando il processo ha anche sufficienti privilegi per unirsi ai namespace dell'host:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Se il comando riesce, il processo del container ora viene eseguito nei namespace mount, UTS, network, IPC e PID dell'host. L'impatto è la compromissione immediata dell'host.

Anche quando `nsenter` non è presente, lo stesso risultato può essere ottenuto tramite il binario dell'host se il filesystem dell'host è montato:
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### Note recenti di runtime

Alcuni attacchi rilevanti per il PID-namespace non sono le tradizionali configurazioni errate `hostPID: true`, ma bug di implementazione a runtime relativi a come le protezioni di procfs vengono applicate durante il setup del container.

#### Race di `maskedPaths` verso il procfs dell'host

Nelle versioni vulnerabili di `runc`, attaccanti in grado di controllare l'immagine del container o il carico di lavoro `runc exec` potrebbero gareggiare nella fase di masking sostituendo il `/dev/null` lato container con un symlink verso un percorso procfs sensibile come `/proc/sys/kernel/core_pattern`. Se il race ha successo, il bind mount del percorso mascherato potrebbe essere montato sull'obiettivo sbagliato e esporre al nuovo container i controlli procfs globali dell'host.

Comando utile per la verifica:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
Questo è importante perché l'impatto finale può essere lo stesso di un'esposizione diretta di procfs: `core_pattern` o `sysrq-trigger` scrivibili, seguiti dall'esecuzione di codice sull'host o da un denial of service.

#### Namespace injection con `insject`

Namespace injection tools, come `insject`, mostrano che l'interazione con il PID-namespace non richiede sempre di entrare preventivamente nel namespace target prima della creazione del processo. Un helper può collegarsi in un secondo momento, usare `setns()`, e eseguire mantenendo la visibilità nello spazio PID target:
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Questo tipo di tecnica è rilevante principalmente per il debugging avanzato, offensive tooling e i workflow di post-exploitation, dove il contesto del namespace deve essere associato dopo che il runtime ha già inizializzato il carico di lavoro.

### Pattern di abuso FD correlati

Due pattern vale la pena evidenziare esplicitamente quando i PID dell'host sono visibili. Primo, un processo privilegiato può mantenere aperto un file descriptor sensibile attraverso `execve()` perché non è stato marcato `O_CLOEXEC`. Secondo, i servizi possono passare file descriptor tramite socket Unix usando `SCM_RIGHTS`. In entrambi i casi l'oggetto interessante non è più il pathname, ma l'handle già aperto che un processo con privilegi inferiori può ereditare o ricevere.

Questo è rilevante nel lavoro con container perché l'handle può puntare a `docker.sock`, a un log privilegiato, a un file di segreti dell'host o a un altro oggetto di alto valore anche quando il percorso stesso non è direttamente raggiungibile dal filesystem del container.

## Controlli

Lo scopo di questi comandi è determinare se il processo ha una vista PID privata o se può già enumerare un panorama di processi molto più ampio.
```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```
Cosa è interessante qui:

- Se l'elenco dei processi contiene servizi evidenti dell'host, la condivisione dei PID dell'host è probabilmente già in atto.
- Vedere soltanto un piccolo albero locale del container costituisce il comportamento normale; vedere `systemd`, `dockerd`, o daemon non correlati non lo è.
- Una volta che i PID dell'host sono visibili, anche le informazioni sui processi in sola lettura diventano ricognizione utile.

Se scopri un container in esecuzione con condivisione dei PID dell'host, non considerarlo una differenza puramente estetica. È un cambiamento significativo in ciò che il carico di lavoro può osservare e potenzialmente influenzare.
