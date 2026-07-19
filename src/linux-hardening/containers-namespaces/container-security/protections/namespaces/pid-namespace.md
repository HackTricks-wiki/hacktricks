# Namespace PID

{{#include ../../../../../banners/hacktricks-training.md}}

## Panoramica

Il namespace PID controlla come vengono numerati i processi e quali processi sono visibili. Per questo un container può avere il proprio PID 1 anche se non è una macchina reale. All'interno del namespace, il workload vede quello che appare come un albero dei processi locale. Al di fuori del namespace, l'host continua a vedere i PID reali dell'host e l'intero panorama dei processi.

Dal punto di vista della sicurezza, il namespace PID è importante perché la visibilità dei processi è preziosa. Quando un workload può vedere i processi dell'host, potrebbe essere in grado di osservare i nomi dei servizi, gli argomenti della command line, i secret passati negli argomenti dei processi, lo stato derivato dall'ambiente tramite `/proc` e potenziali target per l'ingresso nei namespace. Se può fare qualcosa di più che limitarsi a vedere tali processi, ad esempio inviando segnali o usando ptrace nelle condizioni appropriate, il problema diventa molto più grave.

## Funzionamento

Un nuovo namespace PID inizia con una propria numerazione interna dei processi. Il primo processo creato al suo interno diventa il PID 1 dal punto di vista del namespace, il che significa anche che riceve semantiche speciali simili a quelle di init per i processi figli orfani e la gestione dei segnali. Questo spiega molte anomalie dei container relative ai processi init, alla raccolta dei processi zombie e al motivo per cui nei container vengono talvolta utilizzati piccoli wrapper init.

L'importante lezione di sicurezza è che un processo può sembrare isolato perché vede solo il proprio albero dei PID, ma tale isolamento può essere rimosso deliberatamente. Docker lo espone tramite `--pid=host`, mentre Kubernetes lo fa tramite `hostPID: true`. Quando il container entra nel namespace PID dell'host, il workload vede direttamente i processi dell'host e molti percorsi di attacco successivi diventano molto più realistici.

## Lab

Per creare manualmente un namespace PID:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
La shell ora vede una vista privata dei processi. Il flag `--mount-proc` è importante perché monta un'istanza di procfs che corrisponde al nuovo PID namespace, rendendo coerente l'elenco dei processi dall'interno.

Per confrontare il comportamento dei container:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
La differenza è immediata e facile da capire, motivo per cui questo è un buon primo lab per i lettori.

## Utilizzo a runtime

I container normali in Docker, Podman, containerd e CRI-O ricevono il proprio PID namespace. I Pod Kubernetes ricevono solitamente anch'essi una vista PID isolata, a meno che il workload non richieda esplicitamente la condivisione del PID dell'host. Gli ambienti LXC/Incus si basano sulla stessa primitiva del kernel, anche se i casi d'uso dei system-container possono esporre alberi dei processi più complessi e incoraggiare più scorciatoie di debugging.

La stessa regola si applica ovunque: se il runtime ha scelto di non isolare il PID namespace, si tratta di una riduzione deliberata del confine del container.

## Misconfigurations

La misconfiguration canonica è la condivisione del PID dell'host. I team la giustificano spesso per comodità di debugging, monitoring o gestione dei servizi, ma dovrebbe sempre essere trattata come un'eccezione di sicurezza significativa. Anche se il container non dispone di una write primitive immediata sui processi dell'host, la sola visibilità può rivelare molte informazioni sul sistema. Una volta aggiunte capability come `CAP_SYS_PTRACE` o un accesso utile a procfs, il rischio aumenta significativamente.

Un altro errore consiste nel presumere che, poiché il workload non può terminare o eseguire ptrace sui processi dell'host per impostazione predefinita, la condivisione del PID dell'host sia quindi innocua. Questa conclusione ignora il valore dell'enumeration, la disponibilità di target per l'ingresso nei namespace e il modo in cui la visibilità dei PID si combina con altri controlli indeboliti.

## Abuse

Se il PID namespace dell'host è condiviso, un attacker può ispezionare i processi dell'host, raccogliere gli argomenti dei processi, identificare servizi interessanti, individuare PID candidati per `nsenter` oppure combinare la visibilità dei processi con privilegi correlati a ptrace per interferire con i workload dell'host o adiacenti. In alcuni casi, vedere semplicemente il processo long-running corretto è sufficiente per ridefinire il resto del piano di attacco.

Il primo passaggio pratico consiste sempre nel verificare che i processi dell'host siano realmente visibili:
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
Se `nsenter` è disponibile e sussistono privilegi sufficienti, verifica se un processo host visibile può essere utilizzato come ponte tra namespace:
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
Anche quando l'ingresso è bloccato, la condivisione dei PID dell'host è già preziosa perché rivela la disposizione dei servizi, i componenti runtime e i processi privilegiati candidati da colpire in seguito.

La visibilità dei PID dell'host rende inoltre più realistico l'abuso dei descrittori di file. Se un processo privilegiato dell'host o un workload adiacente ha aperto un file o un socket sensibile, l'attaccante potrebbe essere in grado di ispezionare `/proc/<pid>/fd/` e riutilizzare quell'handle, a seconda della proprietà, delle opzioni di mount di procfs e del modello del servizio target.
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
Questi comandi sono utili perché indicano se `hidepid=1` o `hidepid=2` stanno riducendo la visibilità tra processi e se descrittori evidentemente interessanti, come file di secret aperti, log o socket Unix, sono visibili.

### Esempio completo: host PID + `nsenter`

La condivisione degli host PID diventa una fuga diretta dall'host quando il processo dispone anche di privilegi sufficienti per unirsi ai namespace dell'host:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Se il comando viene eseguito correttamente, il processo del container sta ora operando nei namespace mount, UTS, network, IPC e PID dell'host. L'impatto è la compromissione immediata dell'host.

Anche quando `nsenter` non è disponibile, lo stesso risultato può essere ottenuto tramite il binary dell'host se il filesystem dell'host è montato:
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### Note recenti sul runtime

Alcuni attacchi rilevanti per i PID namespace non sono le tradizionali configurazioni errate `hostPID: true`, ma bug nell'implementazione del runtime legati al modo in cui le protezioni di procfs vengono applicate durante la configurazione del container.

#### Race di `maskedPaths` verso il procfs dell'host

Nelle versioni vulnerabili di `runc`, gli attaccanti in grado di controllare l'immagine del container o il workload di `runc exec` potevano sfruttare una race nella fase di masking sostituendo il `/dev/null` del container con un symlink verso un path sensibile di procfs, come `/proc/sys/kernel/core_pattern`. Se la race aveva successo, il bind mount del masked path poteva finire sulla destinazione errata ed esporre al nuovo container i knob globali di procfs dell'host.

Comando utile per la revisione:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
Questo è importante perché l'impatto finale potrebbe essere lo stesso di un'esposizione diretta di procfs: `core_pattern` o `sysrq-trigger` scrivibili, seguiti dall'esecuzione di codice sull'host o da un denial of service.

#### Namespace injection con `insject`

Gli strumenti di Namespace injection come `insject` dimostrano che l'interazione con il PID namespace non richiede sempre di entrare nel namespace di destinazione prima della creazione del processo. Un helper può collegarsi in seguito, usare `setns()` ed eseguire codice mantenendo la visibilità sullo spazio dei PID di destinazione:
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Questo tipo di tecnica è rilevante principalmente per il debugging avanzato, gli strumenti offensivi e i workflow di post-exploitation in cui il contesto del namespace deve essere associato dopo che il runtime ha già inizializzato il workload.

### Pattern correlati di abuso degli FD

Due pattern meritano di essere evidenziati esplicitamente quando i PID dell'host sono visibili. Primo, un processo privilegiato può mantenere aperto un file descriptor sensibile attraverso `execve()` perché non era contrassegnato con `O_CLOEXEC`. Secondo, i servizi possono passare file descriptor attraverso socket Unix tramite `SCM_RIGHTS`. In entrambi i casi, l'oggetto interessante non è più il pathname, ma l'handle già aperto che un processo con privilegi inferiori può ereditare o ricevere.

Questo è importante nel lavoro con i container perché l'handle può puntare a `docker.sock`, a un log privilegiato, a un file di secret dell'host o a un altro oggetto di grande valore, anche quando il path stesso non è direttamente raggiungibile dal filesystem del container.

## Check

Lo scopo di questi comandi è determinare se il processo dispone di una vista privata dei PID oppure se può già enumerare un panorama dei processi molto più ampio.
```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```
Cosa è interessante qui:

- Se l'elenco dei processi contiene servizi host evidenti, probabilmente la condivisione degli host PID è già attiva.
- Vedere solo un piccolo albero locale al container è il comportamento normale di base; vedere `systemd`, `dockerd` o daemon non correlati non lo è.
- Una volta visibili gli host PID, anche le informazioni sui processi in sola lettura diventano utili per la reconnaissance.

Se scopri un container in esecuzione con la condivisione degli host PID, non considerarla una differenza estetica. Si tratta di un cambiamento importante in ciò che il workload può osservare e potenzialmente influenzare.
{{#include ../../../../../banners/hacktricks-training.md}}
