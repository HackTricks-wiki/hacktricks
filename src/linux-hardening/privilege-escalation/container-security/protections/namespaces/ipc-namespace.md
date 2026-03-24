# Spazio dei nomi IPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Panoramica

Lo spazio dei nomi IPC isola **System V IPC objects** e **POSIX message queues**. Ciò include segmenti di memoria condivisa, semafori e code di messaggi che altrimenti sarebbero visibili a processi non correlati sull'host. In termini pratici, questo impedisce a un container di agganciarsi casualmente a oggetti IPC appartenenti ad altri workload o all'host.

Rispetto a mount, PID o user namespaces, lo spazio dei nomi IPC è spesso meno discusso, ma ciò non deve essere confuso con irrilevanza. La memoria condivisa e i meccanismi IPC correlati possono contenere stato molto utile. Se lo spazio dei nomi IPC dell'host è esposto, il workload può ottenere visibilità su oggetti di coordinamento inter-processo o dati che non erano destinati a oltrepassare il confine del container.

## Funzionamento

Quando il runtime crea un nuovo spazio dei nomi IPC, il processo ottiene il proprio insieme isolato di identificatori IPC. Questo significa che comandi come `ipcs` mostrano solo gli oggetti disponibili in quello spazio dei nomi. Se invece il container si unisce allo spazio dei nomi IPC dell'host, quegli oggetti diventano parte di una vista globale condivisa.

Questo è particolarmente importante in ambienti dove applicazioni o servizi fanno largo uso di memoria condivisa. Anche quando il container non può direttamente evadere sfruttando solo l'IPC, lo spazio dei nomi può causare leak di informazioni o abilitare interferenze tra processi che aiutano in modo significativo un attacco successivo.

## Laboratorio

Puoi creare un spazio dei nomi IPC privato con:
```bash
sudo unshare --ipc --fork bash
ipcs
```
E confronta il comportamento in fase di esecuzione con:
```bash
docker run --rm debian:stable-slim ipcs
docker run --rm --ipc=host debian:stable-slim ipcs
```
## Uso a runtime

Docker e Podman isolano l'IPC per impostazione predefinita. Kubernetes tipicamente assegna al Pod il proprio namespace IPC, condiviso dai container nello stesso Pod ma non, per impostazione predefinita, con l'host. La condivisione dell'IPC con l'host è possibile, ma dovrebbe essere considerata una riduzione significativa dell'isolamento piuttosto che una semplice opzione di runtime.

## Configurazioni errate

L'errore più ovvio è `--ipc=host` o `hostIPC: true`. Questo può essere fatto per compatibilità con software legacy o per comodità, ma cambia sostanzialmente il modello di fiducia. Un altro problema ricorrente è semplicemente trascurare l'IPC perché sembra meno drammatico rispetto a host PID o host networking. In realtà, se il carico di lavoro gestisce browser, database, carichi di lavoro scientifici o altro software che fa ampio uso di memoria condivisa, la superficie IPC può essere molto rilevante.

## Abuso

Quando l'IPC dell'host è condiviso, un attaccante può ispezionare o interferire con oggetti di memoria condivisa, ottenere nuove informazioni sul comportamento dell'host o dei workload vicini, oppure combinare le informazioni ottenute con la visibilità dei processi e capacità in stile ptrace. La condivisione dell'IPC è spesso una debolezza di supporto piuttosto che il percorso completo per il breakout, ma le debolezze di supporto contano perché accorciano e stabilizzano le catene di attacco reali.

Il primo passo utile è enumerare quali oggetti IPC sono visibili:
```bash
readlink /proc/self/ns/ipc
ipcs -a
ls -la /dev/shm 2>/dev/null | head -n 50
```
Se il namespace IPC dell'host è condiviso, grandi segmenti shared-memory o i proprietari di oggetti interessanti possono rivelare immediatamente il comportamento dell'applicazione:
```bash
ipcs -m -p
ipcs -q -p
```
In alcuni ambienti, i contenuti di `/dev/shm` stessi leak nomi di file, artefatti o tokens che vale la pena controllare:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```
La condivisione IPC raramente fornisce immediatamente host root di per sé, ma può esporre dati e canali di coordinamento che rendono molto più semplici attacchi a processi successivi.

### Esempio completo: Recupero di segreti da `/dev/shm`

Il caso di abuso completo più realistico è il furto di dati piuttosto che l'evasione diretta. Se host IPC o una vasta mappa di memoria condivisa sono esposti, artefatti sensibili possono talvolta essere recuperati direttamente:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```
Impatto:

- estrazione di secrets o materiale di sessione lasciato nella shared memory
- visibilità sulle applicazioni attualmente attive sull'host
- migliore targeting per successivi attacchi basati su PID-namespace o ptrace

La condivisione di IPC è quindi da considerarsi più un **amplificatore di attacchi** che una primitive standalone per host-escape.

## Verifiche

Questi comandi servono a verificare se il workload ha una vista IPC privata, se sono visibili oggetti significativi di shared-memory o message, e se `/dev/shm` espone artefatti utili.
```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```
Cosa è interessante qui:

- Se `ipcs -a` rivela oggetti posseduti da utenti o servizi inaspettati, il namespace potrebbe non essere isolato come previsto.
- Segmenti di shared memory grandi o insoliti spesso meritano di essere investigati.
- Una mount ampia di `/dev/shm` non è automaticamente un bug, ma in alcuni ambienti essa leaks nomi di file, artefatti e segreti transitori.

IPC raramente riceve la stessa attenzione dei tipi di namespace più grandi, ma in ambienti che lo usano intensamente, condividerlo con l'host è una vera e propria decisione di sicurezza.
{{#include ../../../../../banners/hacktricks-training.md}}
