# CGroups

{{#include ../../../banners/hacktricks-training.md}}

## Informazioni di Base

**Linux Control Groups**, o **cgroups**, sono una funzionalità del kernel Linux che consente l'allocazione, la limitazione e la priorità delle risorse di sistema come CPU, memoria e I/O del disco tra gruppi di processi. Offrono un meccanismo per **gestire e isolare l'uso delle risorse** delle collezioni di processi, utile per scopi come la limitazione delle risorse, l'isolamento del carico di lavoro e la priorità delle risorse tra diversi gruppi di processi.

Ci sono **due versioni di cgroups**: versione 1 e versione 2. Entrambe possono essere utilizzate contemporaneamente su un sistema. La principale distinzione è che **cgroups versione 2** introduce una **struttura gerarchica, simile a un albero**, che consente una distribuzione delle risorse più sfumata e dettagliata tra i gruppi di processi. Inoltre, la versione 2 porta vari miglioramenti, tra cui:

Oltre alla nuova organizzazione gerarchica, la cgroups versione 2 ha anche introdotto **diverse altre modifiche e miglioramenti**, come il supporto per **nuovi controller delle risorse**, un migliore supporto per le applicazioni legacy e prestazioni migliorate.

In generale, cgroups **versione 2 offre più funzionalità e migliori prestazioni** rispetto alla versione 1, ma quest'ultima può ancora essere utilizzata in determinate situazioni in cui la compatibilità con sistemi più vecchi è una preoccupazione.

Puoi elencare i cgroups v1 e v2 per qualsiasi processo guardando il suo file cgroup in /proc/\<pid>. Puoi iniziare a guardare i cgroups della tua shell con questo comando:
```shell-session
$ cat /proc/self/cgroup
12:rdma:/
11:net_cls,net_prio:/
10:perf_event:/
9:cpuset:/
8:cpu,cpuacct:/user.slice
7:blkio:/user.slice
6:memory:/user.slice 5:pids:/user.slice/user-1000.slice/session-2.scope 4:devices:/user.slice
3:freezer:/
2:hugetlb:/testcgroup
1:name=systemd:/user.slice/user-1000.slice/session-2.scope
0::/user.slice/user-1000.slice/session-2.scope
```
La struttura dell'output è la seguente:

- **Numeri 2–12**: cgroups v1, con ogni riga che rappresenta un diverso cgroup. I controller per questi sono specificati accanto al numero.
- **Numero 1**: Anche cgroups v1, ma esclusivamente per scopi di gestione (impostato da, ad esempio, systemd), e privo di un controller.
- **Numero 0**: Rappresenta cgroups v2. Non sono elencati controller, e questa riga è esclusiva nei sistemi che eseguono solo cgroups v2.
- I **nomi sono gerarchici**, somigliando a percorsi di file, indicando la struttura e la relazione tra diversi cgroups.
- **Nomi come /user.slice o /system.slice** specificano la categorizzazione dei cgroups, con user.slice tipicamente per le sessioni di accesso gestite da systemd e system.slice per i servizi di sistema.

### Visualizzazione dei cgroups

Il filesystem è tipicamente utilizzato per accedere ai **cgroups**, divergendo dall'interfaccia delle chiamate di sistema Unix tradizionalmente utilizzata per le interazioni con il kernel. Per investigare la configurazione del cgroup di una shell, si dovrebbe esaminare il file **/proc/self/cgroup**, che rivela il cgroup della shell. Poi, navigando nella directory **/sys/fs/cgroup** (o **`/sys/fs/cgroup/unified`**) e localizzando una directory che condivide il nome del cgroup, si possono osservare varie impostazioni e informazioni sull'uso delle risorse pertinenti al cgroup.

![Cgroup Filesystem](<../../../images/image (1128).png>)

I file di interfaccia chiave per i cgroups sono prefissati con **cgroup**. Il file **cgroup.procs**, che può essere visualizzato con comandi standard come cat, elenca i processi all'interno del cgroup. Un altro file, **cgroup.threads**, include informazioni sui thread.

![Cgroup Procs](<../../../images/image (281).png>)

I cgroups che gestiscono le shell tipicamente comprendono due controller che regolano l'uso della memoria e il conteggio dei processi. Per interagire con un controller, si dovrebbero consultare i file che portano il prefisso del controller. Ad esempio, **pids.current** sarebbe consultato per accertare il conteggio dei thread nel cgroup.

![Cgroup Memory](<../../../images/image (677).png>)

L'indicazione di **max** in un valore suggerisce l'assenza di un limite specifico per il cgroup. Tuttavia, a causa della natura gerarchica dei cgroups, i limiti potrebbero essere imposti da un cgroup a un livello inferiore nella gerarchia delle directory.

### Manipolazione e Creazione di cgroups

I processi sono assegnati ai cgroups **scrivendo il loro ID di processo (PID) nel file `cgroup.procs`**. Questo richiede privilegi di root. Ad esempio, per aggiungere un processo:
```bash
echo [pid] > cgroup.procs
```
Allo stesso modo, **modificare gli attributi del cgroup, come impostare un limite di PID**, si fa scrivendo il valore desiderato nel file pertinente. Per impostare un massimo di 3.000 PID per un cgroup:
```bash
echo 3000 > pids.max
```
**Creare nuovi cgroups** comporta la creazione di una nuova sottodirectory all'interno della gerarchia cgroup, il che spinge il kernel a generare automaticamente i file di interfaccia necessari. Anche se i cgroups senza processi attivi possono essere rimossi con `rmdir`, sii consapevole di alcune restrizioni:

- **I processi possono essere collocati solo in cgroups foglia** (cioè, i più annidati in una gerarchia).
- **Un cgroup non può possedere un controller assente nel suo genitore**.
- **I controller per i cgroups figli devono essere dichiarati esplicitamente** nel file `cgroup.subtree_control`. Ad esempio, per abilitare i controller CPU e PID in un cgroup figlio:
```bash
echo "+cpu +pids" > cgroup.subtree_control
```
Il **root cgroup** è un'eccezione a queste regole, consentendo il posizionamento diretto dei processi. Questo può essere utilizzato per rimuovere i processi dalla gestione di systemd.

**Monitorare l'uso della CPU** all'interno di un cgroup è possibile attraverso il file `cpu.stat`, che mostra il tempo totale di CPU consumato, utile per tracciare l'uso tra i subprocessi di un servizio:

<figure><img src="../../../images/image (908).png" alt=""><figcaption><p>Statistiche sull'uso della CPU come mostrato nel file cpu.stat</p></figcaption></figure>

## Riferimenti

- **Libro: Come funziona Linux, 3ª edizione: Cosa ogni superutente dovrebbe sapere di Brian Ward**

{{#include ../../../banners/hacktricks-training.md}}
