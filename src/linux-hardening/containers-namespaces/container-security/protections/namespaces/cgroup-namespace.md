# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Panoramica

Il cgroup namespace non sostituisce i cgroup e non applica direttamente limiti alle risorse. Modifica invece **il modo in cui la gerarchia dei cgroup appare** al processo. In altre parole, virtualizza le informazioni visibili relative al percorso dei cgroup, in modo che il workload visualizzi una prospettiva limitata al container anziché l'intera gerarchia dell'host.

Si tratta principalmente di una funzionalità di visibilità e riduzione delle informazioni. Contribuisce a far apparire l'ambiente autonomo e rivela meno informazioni sulla struttura dei cgroup dell'host. Può sembrare un aspetto marginale, ma è comunque importante perché una visibilità non necessaria sulla struttura dell'host può agevolare la ricognizione e semplificare le exploit chain dipendenti dall'ambiente.

## Funzionamento

Senza un cgroup namespace privato, un processo può visualizzare percorsi dei cgroup relativi all'host, esponendo una parte della gerarchia della macchina maggiore di quella utile. Con un cgroup namespace privato, `/proc/self/cgroup` e le osservazioni correlate diventano più localizzate alla vista del container. Questo è particolarmente utile nei moderni runtime stack che vogliono offrire al workload un ambiente più pulito e che riveli meno informazioni sull'host.

La virtualizzazione influisce anche su `/proc/<pid>/mountinfo`, non solo su `/proc/<pid>/cgroup`. Quando leggi un altro processo da una prospettiva di cgroup namespace diversa, i percorsi esterni alla root del tuo namespace vengono mostrati con componenti iniziali `../`, fornendo un indizio utile del fatto che stai osservando al di sopra del tuo sottoalbero delegato. Un dettaglio utile per i lab e il post-exploitation è che un cgroup namespace appena creato spesso necessita di un **cgroupfs remount dall'interno di quel namespace** prima che `mountinfo` rifletta correttamente la nuova root. In caso contrario, potresti continuare a vedere una mount root come `/..`, il che significa che la mount ereditata sta ancora esponendo una vista con root su un antenato, anche se il namespace stesso è già cambiato.<sup>[[1]](#references)</sup>

## Lab

Puoi ispezionare un cgroup namespace con:
```bash
sudo unshare --cgroup --mount --fork bash
cat /proc/self/cgroup
cat /proc/self/mountinfo | grep cgroup
ls -l /proc/self/ns/cgroup
```
Se vuoi che `mountinfo` mostri più chiaramente la nuova root del cgroup namespace, rimonta il filesystem cgroup dall'interno del nuovo namespace e confronta di nuovo:
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
La modifica riguarda soprattutto ciò che il processo può vedere, non l'esistenza o meno dell'enforcement dei cgroup.

## Impatto sulla sicurezza

Il cgroup namespace va inteso soprattutto come un **visibility-hardening layer**. Da solo non impedirà un breakout se il container dispone di mount cgroup scrivibili, capabilities ampie o di un ambiente cgroup v1 pericoloso. Tuttavia, se il cgroup namespace dell'host è condiviso, il processo apprende maggiori dettagli sull'organizzazione del sistema e potrebbe riuscire più facilmente a mettere in relazione i cgroup path relativi all'host con altre osservazioni.

Su **cgroup v2**, il namespace diventa leggermente più importante perché le regole di delegation sono più restrittive. Se la gerarchia è montata con `nsdelegate`, il kernel tratta i cgroup namespace come confini di delegation: i control file degli ancestor dovrebbero rimanere fuori dalla portata del delegatee, mentre le scritture alla root del namespace sono limitate a file sicuri per la delegation, come `cgroup.procs`, `cgroup.threads` e `cgroup.subtree_control`.<sup>[[2]](#references)</sup> Questo non rende comunque il namespace una primitiva di escape di per sé, ma modifica ciò che un workload compromesso può ispezionare e il punto in cui può creare in sicurezza dei sub-cgroup.

Quindi, sebbene questo namespace non sia solitamente il protagonista dei writeup sui container breakout, contribuisce comunque all'obiettivo più ampio di ridurre al minimo il leakage di informazioni sull'host e limitare la cgroup delegation.

## Abuse

Il valore immediato per l'abuse consiste soprattutto nella reconnaissance. Se il cgroup namespace dell'host è condiviso, confronta i path visibili e cerca dettagli della gerarchia che rivelino l'host:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
Se vengono esposti anche percorsi cgroup scrivibili, combina tale visibilità con una ricerca delle interfacce legacy pericolose:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
Il namespace stesso raramente consente un escape immediato, ma spesso rende l'ambiente più facile da mappare prima di testare i primitive di abuso basati sui cgroup.

Un rapido controllo della realtà del runtime aiuta anche a stabilire la priorità dell'attacco. Docker espone `--cgroupns=host|private`, mentre Podman supporta `host`, `private`, `container:<id>` e `ns:<path>`. Nello specifico di Podman, il valore predefinito è solitamente **`host` su cgroup v1** e **`private` su cgroup v2**, quindi identificare semplicemente la versione dei cgroup indica già quale configurazione del namespace è più probabile, prima ancora di ispezionare la configurazione OCI completa.

### Modern v2 Recon: Si tratta di un subtree delegato?

Sugli host moderni, la domanda interessante spesso non riguarda `release_agent`, ma se il processo corrente si trova all'interno di un subtree **cgroup v2** delegato, con sufficiente visibilità o accesso in scrittura per creare gruppi annidati:
```bash
stat -fc %T /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
cat /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null
cat /sys/fs/cgroup/cgroup.events 2>/dev/null
```
Interpretazione utile:

- `cgroup2fs` significa che ti trovi nella gerarchia unificata v2, quindi le classiche catene `release_agent` riservate alla v1 non dovrebbero essere la tua prima ipotesi.
- `cgroup.controllers` mostra quali controller sono disponibili dal parent e quindi verso quali controller il subtree corrente potrebbe potenzialmente propagarsi nei children.
- `cgroup.subtree_control` mostra quali controller sono effettivamente abilitati per i descendants.
- `cgroup.events` espone `populated=0/1`, utile per monitorare se un subtree è diventato vuoto, ma **non** è una primitive per l'esecuzione di codice sull'host come `release_agent` nella v1.

Se disponi già di privilegi sufficienti per ispezionare direttamente il namespace di un altro processo, confronta le viste con:
```bash
nsenter -t <pid> -C -- bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
```
### Esempio completo: Shared cgroup Namespace + Writable cgroup v1

Il cgroup namespace da solo di solito non è sufficiente per l'escape. L'escalation pratica avviene quando i cgroup paths che rivelano l'host vengono combinati con interfacce cgroup v1 scrivibili:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
Se quei file sono raggiungibili e scrivibili, passa immediatamente al flusso completo di exploitation di `release_agent` descritto in [cgroups.md](../cgroups.md). L'impatto consiste nell'esecuzione di codice sull'host dall'interno del container.

Senza interfacce cgroup scrivibili, l'impatto è solitamente limitato alla ricognizione.

## Verifiche

Lo scopo di questi comandi è verificare se il processo dispone di una vista privata del namespace cgroup o se sta apprendendo più informazioni sulla gerarchia dell'host di quante ne siano realmente necessarie.
```bash
readlink /proc/self/ns/cgroup       # Namespace identifier for cgroup view
cat /proc/self/cgroup               # Visible cgroup paths from inside the workload
cat /proc/self/mountinfo | grep cgroup
stat -fc %T /sys/fs/cgroup          # cgroup2fs -> v2 unified hierarchy
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
mount | grep cgroup
```
Cosa è interessante qui:

- Se l'identificatore del namespace corrisponde a un processo host di interesse, il cgroup namespace potrebbe essere condiviso.
- I percorsi che rivelano l'host in `/proc/self/cgroup` o le entry con radice nell'ancestor in `mountinfo` sono utili per la reconnaissance anche quando non sono direttamente sfruttabili.
- Se è in uso `cgroup2fs`, concentrati sulla delegation, sui controller visibili e sui subtree scrivibili invece di presumere che esistano ancora le vecchie primitive v1.
- Se anche i mount dei cgroup sono scrivibili, la questione della visibilità diventa molto più importante.

Il cgroup namespace dovrebbe essere trattato come un layer di hardening della visibilità, non come un meccanismo primario di prevenzione dell'escape. Esporre inutilmente la struttura dei cgroup dell'host aggiunge valore di reconnaissance per l'attacker.

## Riferimenti

- [1] [cgroup_namespaces(7) — Linux manual page](https://man7.org/linux/man-pages/man7/cgroup_namespaces.7.html)
- [2] [Control Group v2 — The Linux Kernel documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html)

{{#include ../../../../../banners/hacktricks-training.md}}
