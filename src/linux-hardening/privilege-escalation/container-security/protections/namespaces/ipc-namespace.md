# IPC Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Panoramica

Il namespace IPC isola **System V IPC objects** e **POSIX message queues**. Questo include segmenti di memoria condivisa, semafori e code di messaggi che altrimenti sarebbero visibili tra processi non correlati sull'host. In termini pratici, questo impedisce a un container di collegarsi casualmente a oggetti IPC appartenenti ad altri carichi di lavoro o all'host.

Rispetto ai namespace mount, PID o user, l'IPC namespace è spesso meno discusso, ma ciò non va confuso con irrelevanza. La memoria condivisa e i meccanismi IPC correlati possono contenere stato estremamente utile. Se il namespace IPC dell'host viene esposto, il carico di lavoro può ottenere visibilità su oggetti di coordinamento inter-processo o dati che non erano destinati a valicare il confine del container.

## Funzionamento

Quando il runtime crea un nuovo IPC namespace, il processo ottiene il proprio set isolato di identificatori IPC. Questo significa che comandi come `ipcs` mostrano solo gli oggetti disponibili in quel namespace. Se invece il container si unisce al namespace IPC dell'host, quegli oggetti diventano parte di una vista globale condivisa.

Questo è particolarmente rilevante in ambienti dove applicazioni o servizi utilizzano intensamente la memoria condivisa. Anche quando il container non può direttamente evadere tramite IPC da solo, il namespace può leak informazioni o abilitare interferenze tra processi che facilitano materialmente un attacco successivo.

## Laboratorio

Puoi creare un IPC namespace privato con:
```bash
sudo unshare --ipc --fork bash
ipcs
```
E confronta il comportamento runtime con:
```bash
docker run --rm debian:stable-slim ipcs
docker run --rm --ipc=host debian:stable-slim ipcs
```
## Uso a runtime

Docker e Podman isolano l'IPC per impostazione predefinita. Kubernetes normalmente assegna al Pod il proprio namespace IPC, condiviso tra i container nello stesso Pod ma non, di default, con l'host. La condivisione dell'IPC dell'host è possibile, ma va considerata una riduzione significativa dell'isolamento piuttosto che una semplice opzione di runtime.

## Errate configurazioni

L'errore ovvio è `--ipc=host` o `hostIPC: true`. Questo può essere fatto per compatibilità con software legacy o per comodità, ma altera sostanzialmente il modello di trust. Un altro problema ricorrente è semplicemente trascurare l'IPC perché sembra meno drammatico rispetto a host PID o host networking. In realtà, se il workload gestisce browser, database, carichi scientifici o altro software che fa ampio uso di memoria condivisa, la superficie IPC può essere molto rilevante.

## Abuso

Quando l'host IPC è condiviso, un attacker può ispezionare o interferire con oggetti di memoria condivisa, ottenere nuove informazioni sul comportamento dell'host o dei workload vicini, oppure combinare le informazioni raccolte con visibilità dei processi e capacità ptrace-style. La condivisione dell'IPC è spesso una debolezza di supporto piuttosto che il percorso completo per il breakout, ma le debolezze di supporto contano perché accorciano e stabilizzano le catene di attacco reali.

Il primo passo utile è enumerare quali oggetti IPC sono visibili:
```bash
readlink /proc/self/ns/ipc
ipcs -a
ls -la /dev/shm 2>/dev/null | head -n 50
```
Se l'IPC namespace dell'host è condiviso, grandi segmenti di shared-memory o proprietari di oggetti interessanti possono rivelare immediatamente il comportamento dell'applicazione:
```bash
ipcs -m -p
ipcs -q -p
```
In alcuni ambienti, i contenuti di `/dev/shm` possono contenere leak di nomi di file, artefatti o token che vale la pena controllare:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```
La condivisione di IPC raramente concede immediatamente root dell'host da sola, ma può esporre dati e canali di coordinamento che rendono molto più semplici attacchi successivi ai processi.

### Esempio completo: `/dev/shm` Recupero dei segreti

Il caso di abuso completo più realistico è il furto di dati piuttosto che un'escape diretta. Se l'host IPC o un'ampia shared-memory layout risultano esposti, artefatti sensibili possono talvolta essere recuperati direttamente:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```
Impatto:

- estrazione di secrets o session material lasciati nella shared memory
- informazioni sulle applicazioni attualmente attive sull'host
- migliore targeting per successivi PID-namespace o ptrace-based attacks

La condivisione IPC va quindi intesa più come un **attack amplifier** che come una primitiva autonoma di host-escape.

## Controlli

Questi comandi servono a determinare se il workload ha una vista IPC privata, se sono visibili oggetti di shared-memory o message significativi, e se `/dev/shm` espone a sua volta artefatti utili.
```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```
- Se `ipcs -a` rivela oggetti posseduti da utenti o servizi inattesi, il namespace potrebbe non essere isolato come ci si aspetta.
- Segmenti di memoria condivisa grandi o insoliti spesso meritano ulteriori indagini.
- Una mount ampia di `/dev/shm` non è automaticamente un bug, ma in alcuni ambienti leaks nomi di file, artefatti e segreti transitori.

IPC riceve raramente la stessa attenzione dei tipi di namespace più grandi, ma in ambienti che lo usano intensamente, condividerlo con l'host è una vera e propria decisione di sicurezza.
