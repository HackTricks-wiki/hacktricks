# IPC Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Panoramica

L'IPC namespace isola gli **oggetti IPC System V** e le **code di messaggi POSIX**. Include segmenti di memoria condivisa, semafori e code di messaggi che altrimenti sarebbero visibili tra processi non correlati sull'host. In termini pratici, questo impedisce a un container di collegarsi casualmente agli oggetti IPC appartenenti ad altri workload o all'host.

Rispetto ai namespace mount, PID o user, l'IPC namespace viene discusso meno spesso, ma ciò non deve essere confuso con la sua irrilevanza. La memoria condivisa e i meccanismi IPC correlati possono contenere informazioni di stato altamente utili. Se l'IPC namespace dell'host è esposto, il workload può ottenere visibilità su oggetti o dati di coordinamento tra processi che non erano mai destinati a oltrepassare il confine del container.

## Operatività

Quando il runtime crea un nuovo IPC namespace, il processo ottiene un proprio set isolato di identificatori IPC. Ciò significa che comandi come `ipcs` mostrano solo gli oggetti disponibili in quel namespace. Se invece il container si unisce all'IPC namespace dell'host, tali oggetti diventano parte di una vista globale condivisa.

Questo è particolarmente importante negli ambienti in cui applicazioni o servizi utilizzano intensivamente la memoria condivisa. Anche quando il container non riesce a evadere direttamente utilizzando soltanto l'IPC, il namespace può causare un leak di informazioni o consentire interferenze tra processi che favoriscono concretamente un attacco successivo.

## Laboratorio

È possibile creare un IPC namespace privato con:
```bash
sudo unshare --ipc --fork bash
ipcs
```
E confronta il comportamento durante l'esecuzione con:
```bash
docker run --rm debian:stable-slim ipcs
docker run --rm --ipc=host debian:stable-slim ipcs
```
## Utilizzo a Runtime

Docker e Podman isolano IPC per impostazione predefinita. Kubernetes in genere assegna al Pod un proprio namespace IPC, condiviso tra i container dello stesso Pod ma non, per impostazione predefinita, con l'host. La condivisione dell'IPC dell'host è possibile, ma dovrebbe essere considerata una significativa riduzione dell'isolamento, non una semplice opzione del runtime.

## Misconfigurazioni

L'errore più evidente è `--ipc=host` o `hostIPC: true`. Questo può essere fatto per compatibilità con software legacy o per comodità, ma modifica sostanzialmente il modello di trust. Un altro problema ricorrente consiste semplicemente nel trascurare IPC perché appare meno significativo rispetto a host PID o al networking dell'host. In realtà, se il workload gestisce browser, database, workload scientifici o altro software che fa un uso intensivo della memoria condivisa, la superficie IPC può essere molto rilevante.

## Abuso

Quando l'IPC dell'host è condiviso, un attacker può ispezionare o interferire con gli oggetti di memoria condivisa, ottenere nuove informazioni sul comportamento dell'host o dei workload adiacenti oppure combinare le informazioni ottenute con la visibilità dei processi e capacità in stile ptrace. La condivisione dell'IPC è spesso una weakness di supporto, non l'intero percorso di breakout, ma le weakness di supporto sono importanti perché accorciano e stabilizzano le reali attack chain.

Il primo passaggio utile consiste nell'enumerare quali oggetti IPC siano effettivamente visibili:
```bash
readlink /proc/self/ns/ipc
ipcs -a
ls -la /dev/shm 2>/dev/null | head -n 50
```
Se il namespace IPC dell'host è condiviso, grandi segmenti di memoria condivisa o proprietari di oggetti interessanti possono rivelare immediatamente il comportamento dell'applicazione:
```bash
ipcs -m -p
ipcs -q -p
```
In alcuni ambienti, il contenuto stesso di `/dev/shm` può fare leak di nomi di file, artefatti o token che vale la pena verificare:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```
La condivisione di IPC raramente fornisce da sola un accesso root immediato all'host, ma può esporre dati e canali di coordinamento che rendono molto più semplici i successivi process attacks.

### Esempio completo: recupero di secret da `/dev/shm`

Il caso di abuso completo più realistico è il furto di dati, anziché un escape diretto. Se l'IPC dell'host o un layout di shared memory ampio è esposto, a volte è possibile recuperare direttamente artefatti sensibili:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```
Impatto:

- estrazione di secret o materiale di sessione lasciato nella memoria condivisa
- informazioni sulle applicazioni attualmente attive sull'host
- migliore targeting per attacchi successivi basati su PID-namespace o ptrace

La condivisione IPC va quindi considerata più come un **amplificatore dell'attacco** che come una primitiva autonoma per evadere dall'host.

## Controlli

Questi comandi servono a verificare se il workload dispone di una vista IPC privata, se sono visibili oggetti significativi di memoria condivisa o messaggistica e se `/dev/shm` espone direttamente artifact utili.
```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```
Cosa è interessante qui:

- Se `ipcs -a` rivela oggetti di proprietà di utenti o servizi imprevisti, il namespace potrebbe non essere isolato come previsto.
- I segmenti di memoria condivisa grandi o insoliti spesso meritano ulteriori verifiche.
- Un mount `/dev/shm` ampio non è automaticamente un bug, ma in alcuni ambienti espone filenames, artifacts e secrets temporanei.

IPC riceve raramente la stessa attenzione riservata ai tipi di namespace più importanti, ma negli ambienti che ne fanno un uso intensivo, condividerlo con l'host è a tutti gli effetti una decisione di sicurezza.

{{#include ../../../../../banners/hacktricks-training.md}}
