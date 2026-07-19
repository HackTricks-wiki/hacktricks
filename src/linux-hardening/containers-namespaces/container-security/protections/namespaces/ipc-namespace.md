# IPC Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Panoramica

L'IPC namespace isola gli **oggetti IPC System V** e le **POSIX message queues**. Include segmenti di memoria condivisa, semafori e message queue che altrimenti sarebbero visibili tra processi non correlati sull'host. In termini pratici, impedisce a un container di collegarsi facilmente agli oggetti IPC appartenenti ad altri workload o all'host.

Rispetto ai mount, PID o user namespaces, l'IPC namespace viene spesso analizzato meno, ma ciò non deve essere confuso con la sua irrilevanza. La memoria condivisa e i meccanismi IPC correlati possono contenere informazioni di stato molto utili. Se l'IPC namespace dell'host è esposto, il workload potrebbe ottenere visibilità su oggetti o dati utilizzati per il coordinamento tra processi, che non avrebbero mai dovuto oltrepassare il confine del container.

## Funzionamento

Quando il runtime crea un nuovo IPC namespace, il processo ottiene il proprio set isolato di identificatori IPC. Ciò significa che comandi come `ipcs` mostrano solo gli oggetti disponibili in quel namespace. Se invece il container entra nell'IPC namespace dell'host, tali oggetti diventano parte di una vista globale condivisa.

Questo è particolarmente importante negli ambienti in cui applicazioni o servizi utilizzano intensivamente la memoria condivisa. Anche quando il container non riesce a effettuare direttamente un breakout utilizzando solo l'IPC, il namespace può causare un leak di informazioni o consentire interferenze tra processi che possono agevolare concretamente un attacco successivo.

## Lab

Puoi creare un IPC namespace privato con:
```bash
sudo unshare --ipc --fork bash
ipcs
```
E confronta il comportamento a runtime con:
```bash
docker run --rm debian:stable-slim ipcs
docker run --rm --ipc=host debian:stable-slim ipcs
```
## Utilizzo a runtime

Docker e Podman isolano IPC per impostazione predefinita. Kubernetes in genere assegna al Pod un proprio IPC namespace, condiviso tra i container dello stesso Pod ma non, per impostazione predefinita, con l'host. La condivisione dell'IPC dell'host è possibile, ma dovrebbe essere considerata una riduzione significativa dell'isolamento, non una semplice opzione minore del runtime.

## Misconfigurazioni

L'errore più evidente è `--ipc=host` o `hostIPC: true`. Questo può essere fatto per garantire la compatibilità con software legacy o per comodità, ma modifica sostanzialmente il modello di trust. Un altro problema ricorrente consiste semplicemente nel trascurare l'IPC, perché sembra meno grave rispetto all'host PID o all'host networking. In realtà, se il workload gestisce browser, database, workload scientifici o altro software che fa ampio uso della shared memory, la superficie IPC può essere molto rilevante.

## Abuse

Quando l'IPC dell'host è condiviso, un attacker può ispezionare o interferire con gli oggetti di shared memory, ottenere nuove informazioni sul comportamento dell'host o dei workload vicini, oppure combinare le informazioni apprese con la visibilità sui processi e capabilities in stile ptrace. La condivisione dell'IPC è spesso una debolezza di supporto, più che l'intero percorso di breakout, ma le debolezze di supporto sono importanti perché accorciano e rendono più stabili le reali attack chain.

Il primo passaggio utile consiste nell'enumerare quali oggetti IPC siano effettivamente visibili:
```bash
readlink /proc/self/ns/ipc
ipcs -a
ls -la /dev/shm 2>/dev/null | head -n 50
```
Se il namespace IPC dell'host è condiviso, segmenti di memoria condivisa di grandi dimensioni o proprietari di oggetti interessanti possono rivelare immediatamente il comportamento dell'applicazione:
```bash
ipcs -m -p
ipcs -q -p
```
In alcuni ambienti, i contenuti di `/dev/shm` stessi possono rivelare nomi di file, artefatti o token che vale la pena controllare:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```
La condivisione di IPC raramente garantisce da sola un accesso root immediato all'host, ma può esporre dati e canali di coordinamento che rendono molto più semplici i successivi attacchi ai processi.

### Esempio completo: recupero di secret da `/dev/shm`

Il caso completo di abuso più realistico è il furto di dati, piuttosto che l'escape diretto. Se l'IPC dell'host o un layout di memoria condivisa ampio è esposto, a volte è possibile recuperare direttamente artefatti sensibili:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```
Impatto:

- estrazione di segreti o session material lasciati nella memoria condivisa
- informazioni sulle applicazioni attualmente attive sull'host
- migliore targeting per successivi attacchi basati su PID namespace o ptrace

La condivisione IPC è quindi meglio intesa come un **amplificatore di attacchi** piuttosto che come una primitiva autonoma di host escape.

## Check

Questi comandi servono a verificare se il workload dispone di una vista IPC privata, se sono visibili oggetti significativi di memoria condivisa o messaggistica e se `/dev/shm` espone artefatti utili.
```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```
Cosa è interessante qui:

- Se `ipcs -a` mostra oggetti di proprietà di utenti o servizi imprevisti, il namespace potrebbe non essere isolato come previsto.
- I segmenti di shared memory grandi o insoliti meritano spesso ulteriori verifiche.
- Un mount ampio di `/dev/shm` non è automaticamente un bug, ma in alcuni ambienti espone filenames, artifacts e secrets temporanei.

L'IPC riceve raramente la stessa attenzione riservata ai tipi di namespace più importanti, ma negli ambienti che lo utilizzano intensivamente, condividerlo con l'host è a tutti gli effetti una decisione di sicurezza.
{{#include ../../../../../banners/hacktricks-training.md}}
