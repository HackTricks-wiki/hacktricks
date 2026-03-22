# IPC Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Panoramica

Il namespace IPC isola **System V IPC objects** e **POSIX message queues**. Ciò include segmenti di memoria condivisa, semafori e code di messaggi che altrimenti sarebbero visibili tra processi non correlati sull'host. In termini pratici, questo impedisce a un container di collegarsi casualmente a oggetti IPC appartenenti ad altri workload o all'host.

Rispetto ai namespace mount, PID o user, il namespace IPC è spesso meno discusso, ma ciò non va confuso con irrilevanza. La memoria condivisa e i meccanismi IPC correlati possono contenere stato altamente utile. Se il namespace IPC dell'host è esposto, il workload può ottenere visibilità su oggetti di coordinamento inter-processo o su dati che non erano destinati a oltrepassare il confine del container.

## Funzionamento

Quando il runtime crea un nuovo namespace IPC, il processo ottiene il proprio set isolato di identificatori IPC. Ciò significa che comandi come `ipcs` mostrano solo gli oggetti disponibili in quel namespace. Se invece il container si unisce al namespace IPC dell'host, quegli oggetti diventano parte di una vista globale condivisa.

Questo è particolarmente importante in ambienti dove applicazioni o servizi fanno ampio uso della memoria condivisa. Anche quando il container non può evadere direttamente tramite IPC da solo, il namespace può leak informazioni o consentire interferenze tra processi che aiutano concretamente un attacco successivo.

## Laboratorio

Puoi creare un namespace IPC privato con:
```bash
sudo unshare --ipc --fork bash
ipcs
```
E confronta il comportamento a runtime con:
```bash
docker run --rm debian:stable-slim ipcs
docker run --rm --ipc=host debian:stable-slim ipcs
```
## Runtime Usage

Docker e Podman isolano l'IPC per impostazione predefinita. Kubernetes tipicamente assegna al Pod il proprio IPC namespace, condiviso tra i container nello stesso Pod ma non con l'host per impostazione predefinita. La condivisione dell'IPC con l'host è possibile, ma va considerata una riduzione significativa dell'isolamento piuttosto che una semplice opzione di runtime.

## Misconfigurations

L'errore ovvio è `--ipc=host` o `hostIPC: true`. Questo può essere fatto per compatibilità con software legacy o per comodità, ma cambia sostanzialmente il modello di fiducia. Un altro problema ricorrente è semplicemente trascurare l'IPC perché sembra meno drammatico rispetto a host PID o host networking. In realtà, se il carico di lavoro gestisce browser, database, carichi di lavoro scientifici o altro software che fa largo uso di memoria condivisa, la superficie IPC può essere molto rilevante.

## Abuse

Quando l'IPC dell'host è condiviso, un attaccante può ispezionare o interferire con oggetti di memoria condivisa, ottenere nuove informazioni sul comportamento dell'host o dei workload vicini, o combinare le informazioni ottenute con la visibilità dei processi e capacità in stile ptrace. La condivisione dell'IPC è spesso una debolezza di supporto piuttosto che il percorso completo di breakout, ma le debolezze di supporto contano perché accorciano e stabilizzano catene di attacco reali.

Il primo passo utile è enumerare quali oggetti IPC sono visibili:
```bash
readlink /proc/self/ns/ipc
ipcs -a
ls -la /dev/shm 2>/dev/null | head -n 50
```
Se l'IPC namespace dell'host è condiviso, grandi segmenti di memoria condivisa o proprietari di oggetti interessanti possono rivelare immediatamente il comportamento dell'applicazione:
```bash
ipcs -m -p
ipcs -q -p
```
In alcuni ambienti, i contenuti di `/dev/shm` stessi leak nomi di file, artefatti o token che vale la pena controllare:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```
IPC sharing raramente fornisce immediatamente host root da sola, ma può esporre dati e canali di coordinamento che rendono molto più semplici gli attacchi successivi ai processi.

### Esempio completo: `/dev/shm` Recupero di segreti

Il caso di abuso completo più realistico è il furto di dati piuttosto che una escape diretta. Se l'host IPC o un'ampia mappatura della memoria condivisa è esposta, artefatti sensibili possono talvolta essere recuperati direttamente:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```
Impatto:

- estrazione di segreti o materiale di sessione lasciato nella shared memory
- informazioni sulle applicazioni attualmente attive sull'host
- migliore identificazione degli obiettivi per successivi attacchi basati su PID-namespace o ptrace-based

La condivisione IPC è quindi da considerarsi più un **attack amplifier** che una host-escape primitive autonoma.

## Verifiche

Questi comandi servono a determinare se il workload ha una vista IPC privata, se oggetti significativi in shared-memory o message objects sono visibili, e se `/dev/shm` espone esso stesso artefatti utili.
```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```
Cosa è interessante qui:

- Se `ipcs -a` rivela oggetti di proprietà di utenti o servizi inattesi, il namespace potrebbe non essere così isolato come ci si aspetta.
- Segmenti di memoria condivisa grandi o insoliti spesso meritano un approfondimento.
- Un mount ampio di `/dev/shm` non è automaticamente un bug, ma in alcuni ambienti leaks filenames, artifacts, and transient secrets.

IPC riceve raramente la stessa attenzione dei tipi di namespace più ampi, ma in ambienti che lo usano intensamente, condividerlo con l'host è decisamente una decisione di sicurezza.
{{#include ../../../../../banners/hacktricks-training.md}}
