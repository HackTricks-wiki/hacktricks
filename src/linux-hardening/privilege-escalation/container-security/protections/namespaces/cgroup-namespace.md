# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Overview

Il cgroup namespace non sostituisce i cgroups e non impone da solo limiti di risorse. Invece, cambia **come la gerarchia cgroup appare** al process. In altre parole, virtualizza le informazioni visibili del percorso cgroup così che il workload veda una vista confinata al container invece dell'intera gerarchia dell'host.

Questa è principalmente una funzione di visibilità e riduzione delle informazioni. Aiuta a far sembrare l'ambiente auto-contenuto e rivela meno sul layout dei cgroup dell'host. Può sembrare poco, ma conta comunque perché una visibilità non necessaria sulla struttura dell'host può aiutare la reconnaissance e semplificare catene di exploit dipendenti dall'ambiente.

## Operation

Senza un private cgroup namespace, un process può vedere percorsi cgroup relativi all'host che espongono più della gerarchia della macchina di quanto sia utile. Con un private cgroup namespace, `/proc/self/cgroup` e osservazioni correlate diventano più localizzate alla vista del container. Questo è particolarmente utile negli stack runtime moderni che vogliono che il workload veda un ambiente più pulito e meno rivelatore dell'host.

La virtualizzazione influisce anche su `/proc/<pid>/mountinfo`, non solo su `/proc/<pid>/cgroup`. Quando leggi un altro process da una diversa prospettiva di cgroup-namespace, i percorsi fuori dalla root del tuo namespace vengono mostrati con componenti iniziali `../`, che sono un utile indizio del fatto che stai guardando sopra il tuo sottoalbero delegato. Una sfumatura utile per labs e post-exploitation è che un cgroup namespace appena creato spesso necessita di un **cgroupfs remount dall'interno di quel namespace** prima che `mountinfo` rifletta in modo pulito la nuova root. Altrimenti potresti ancora vedere una mount root come `/..`, il che significa che il mount ereditato sta ancora esponendo una vista con root nell'antenato, anche se il namespace stesso è già cambiato.

## Lab

Puoi ispezionare un cgroup namespace con:
```bash
sudo unshare --cgroup --mount --fork bash
cat /proc/self/cgroup
cat /proc/self/mountinfo | grep cgroup
ls -l /proc/self/ns/cgroup
```
Se vuoi che `mountinfo` mostri più chiaramente la nuova root del cgroup-namespace, rimonta il filesystem cgroup dall'interno del nuovo namespace e confronta di nuovo:
```bash
mount --make-rslave /
umount /sys/fs/cgroup 2>/dev/null
mount -t cgroup2 none /sys/fs/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
E confronta il comportamento a runtime con:
```bash
docker run --rm debian:stable-slim cat /proc/self/cgroup
docker run --rm --cgroupns=host debian:stable-slim cat /proc/self/cgroup
```
Il cambiamento riguarda principalmente ciò che il processo può vedere, non l'esistenza o meno dell'enforcement di cgroup.

## Security Impact

Il cgroup namespace è meglio inteso come un **visibility-hardening layer**. Da solo non impedirà un breakout se il container ha cgroup mounts scrivibili, broad capabilities o un ambiente cgroup v1 pericoloso. Tuttavia, se il host cgroup namespace è shared, il processo apprende di più su come è organizzato il sistema e può trovare più facile allineare i percorsi cgroup relativi all'host con altre osservazioni.

Su **cgroup v2**, il namespace inizia ad avere un po' più importanza perché le regole di delegation sono più rigide. Se la gerarchia è montata con `nsdelegate`, il kernel tratta i cgroup namespaces come delegation boundaries: i control files degli ancestor dovrebbero rimanere fuori dalla portata del delegatee, e le scritture alla root del namespace sono limitate a file safe per la delegation come `cgroup.procs`, `cgroup.threads` e `cgroup.subtree_control`. Questo comunque non rende il namespace una primitive di escape da solo, ma cambia ciò che un workload compromesso può ispezionare e dove può creare in sicurezza sub-cgroups.

Quindi, anche se questo namespace di solito non è la star dei writeup su container breakout, contribuisce comunque all'obiettivo più ampio di minimizzare il host information leak e vincolare la cgroup delegation.

## Abuse

Il valore di abuso immediato è soprattutto reconnaissance. Se il host cgroup namespace è shared, confronta i percorsi visibili e cerca dettagli della gerarchia che rivelano informazioni sull'host:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
Se sono esposti anche i percorsi cgroup scrivibili, combina quella visibilità con una ricerca di interfacce legacy pericolose:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
Il namespace stesso raramente offre una escape immediata, ma spesso rende l’ambiente più facile da mappare prima di testare primitive di abuse basate su cgroup.

Anche un rapido controllo della runtime reality aiuta a dare priorità al percorso di attacco. Docker espone `--cgroupns=host|private`, mentre Podman supporta `host`, `private`, `container:<id>`, e `ns:<path>`. In particolare, su Podman il default è di solito **`host` su cgroup v1** e **`private` su cgroup v2**, quindi identificare semplicemente la versione del cgroup ti dice già quale posture del namespace è più probabile prima ancora di esaminare l’intera configurazione OCI.

### Modern v2 Recon: Is This A Delegated Subtree?

Su host moderni la domanda interessante spesso non è `release_agent`, ma se il processo corrente si trova dentro un subtree delegato di **cgroup v2** con sufficiente visibilità o accesso in scrittura per costruire gruppi annidati:
```bash
stat -fc %T /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
cat /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null
cat /sys/fs/cgroup/cgroup.events 2>/dev/null
```
Interpretazione utile:

- `cgroup2fs` significa che sei nella gerarchia unificata v2, quindi le classiche catene `release_agent` solo v1 dovrebbero smettere di essere la tua prima ipotesi.
- `cgroup.controllers` mostra quali controller sono disponibili dal parent e quindi verso cosa il subtree corrente potrebbe potenzialmente diramarsi nei children.
- `cgroup.subtree_control` mostra quali controller sono effettivamente abilitati per i descendants.
- `cgroup.events` espone `populated=0/1`, il che è utile per osservare se un subtree è diventato vuoto, ma non è un primitivo di host-code-execution come `release_agent` v1.

Se hai già abbastanza privilege per ispezionare direttamente un altro process namespace, confronta le viste con:
```bash
nsenter -t <pid> -C -- bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
```
### Esempio completo: Shared cgroup Namespace + cgroup v1 scrivibile

Il cgroup namespace da solo di solito non è sufficiente per l'escape. L'escalation pratica avviene quando i percorsi cgroup che rivelano l'host sono combinati con interfacce cgroup v1 scrivibili:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
Se quei file sono raggiungibili e scrivibili, passa immediatamente all’intero flusso di exploit `release_agent` da [cgroups.md](../cgroups.md). L’impatto è l’esecuzione di codice sull’host dall’interno del container.

Senza interfacce cgroup scrivibili, l’impatto è di solito limitato alla ricognizione.

## Checks

Lo scopo di questi comandi è vedere se il processo ha una vista privata del namespace cgroup o se sta apprendendo più della gerarchia dell’host di quanto realmente gli serva.
```bash
readlink /proc/self/ns/cgroup       # Namespace identifier for cgroup view
cat /proc/self/cgroup               # Visible cgroup paths from inside the workload
cat /proc/self/mountinfo | grep cgroup
stat -fc %T /sys/fs/cgroup          # cgroup2fs -> v2 unified hierarchy
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
mount | grep cgroup
```
Cosa è interessante qui:

- Se l'identificatore del namespace corrisponde a un processo host che ti interessa, il cgroup namespace potrebbe essere condiviso.
- I path che rivelano l'host in `/proc/self/cgroup` o le voci con root ancestrale in `mountinfo` sono utili per la reconnaissance anche quando non sono direttamente sfruttabili.
- Se viene usato `cgroup2fs`, concentrati su delegation, controller visibili e sottoalberi scrivibili invece di presumere che esistano ancora i vecchi primitive v1.
- Se i mount cgroup sono anche scrivibili, la questione della visibility diventa molto più importante.

Il cgroup namespace dovrebbe essere trattato come un livello di hardening della visibility piuttosto che come un meccanismo primario di prevenzione della escape. Esporre inutilmente la struttura cgroup dell'host aggiunge valore di reconnaissance per l'attaccante.

## References

- [Linux cgroup_namespaces(7)](https://man7.org/linux/man-pages/man7/cgroup_namespaces.7.html)
- [Linux kernel cgroup v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html)

{{#include ../../../../../banners/hacktricks-training.md}}
