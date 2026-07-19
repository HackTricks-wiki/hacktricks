# Namespace cgroup

{{#include ../../../../../banners/hacktricks-training.md}}

## Panoramica

Il namespace cgroup non sostituisce i cgroup e non applica direttamente limiti alle risorse. Modifica invece **il modo in cui la gerarchia dei cgroup appare** al processo. In altre parole, virtualizza le informazioni visibili sul percorso dei cgroup, in modo che il workload visualizzi una vista relativa al container anziché l'intera gerarchia dell'host.

Si tratta principalmente di una funzionalità di visibilità e riduzione delle informazioni. Contribuisce a far apparire l'ambiente autosufficiente e rivela meno informazioni sul layout dei cgroup dell'host. Può sembrare un aspetto modesto, ma è comunque importante, perché una visibilità non necessaria sulla struttura dell'host può facilitare la ricognizione e semplificare exploit chain dipendenti dall'ambiente.

## Funzionamento

Senza un namespace cgroup privato, un processo può visualizzare percorsi dei cgroup relativi all'host che espongono una parte maggiore della gerarchia della macchina rispetto a quanto sia utile. Con un namespace cgroup privato, `/proc/self/cgroup` e le osservazioni correlate diventano più localizzate alla vista del container. Questo è particolarmente utile negli stack runtime moderni che vogliono offrire al workload un ambiente più pulito e che riveli meno informazioni sull'host.

La virtualizzazione influisce anche su `/proc/<pid>/mountinfo`, non solo su `/proc/<pid>/cgroup`. Quando si legge un altro processo da una prospettiva appartenente a un namespace cgroup diverso, i percorsi esterni alla root del proprio namespace vengono mostrati con componenti iniziali `../`, un indizio utile del fatto che si sta osservando al di sopra del proprio subtree delegato. Un dettaglio utile per i lab e il post-exploitation è che un namespace cgroup appena creato spesso necessita di un **remount di cgroupfs dall'interno di quel namespace** prima che `mountinfo` rifletta correttamente la nuova root. In caso contrario, si potrebbe continuare a vedere una mount root come `/..`, il che significa che la mount ereditata sta ancora esponendo una vista con root su un ancestor, anche se il namespace è già cambiato.

## Lab

È possibile esaminare un namespace cgroup con:
```bash
sudo unshare --cgroup --mount --fork bash
cat /proc/self/cgroup
cat /proc/self/mountinfo | grep cgroup
ls -l /proc/self/ns/cgroup
```
Se vuoi che `mountinfo` mostri più chiaramente la nuova root del cgroup namespace, rimonta il filesystem cgroup dall'interno del nuovo namespace e confronta nuovamente:
```bash
mount --make-rslave /
umount /sys/fs/cgroup 2>/dev/null
mount -t cgroup2 none /sys/fs/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
E confronta il comportamento in fase di esecuzione con:
```bash
docker run --rm debian:stable-slim cat /proc/self/cgroup
docker run --rm --cgroupns=host debian:stable-slim cat /proc/self/cgroup
```
La modifica riguarda soprattutto ciò che il processo può vedere, non l'esistenza o meno dell'**enforcement** dei cgroup.

## Impatto sulla sicurezza

Il **cgroup namespace** va inteso principalmente come un **livello di hardening della visibilità**. Da solo non impedirà un **breakout** se il container dispone di mount cgroup scrivibili, **capabilities** ampie o un ambiente cgroup v1 pericoloso. Tuttavia, se il **cgroup namespace** dell'host è condiviso, il processo acquisisce maggiori informazioni sull'organizzazione del sistema e potrebbe riuscire più facilmente a correlare i **path** cgroup relativi all'host con altre osservazioni.

Su **cgroup v2**, il namespace diventa leggermente più importante perché le regole di **delegation** sono più restrittive. Se la gerarchia è montata con `nsdelegate`, il kernel tratta i cgroup namespace come confini di **delegation**: i file di controllo degli ancestor dovrebbero rimanere fuori dalla portata del delegatee, mentre le scritture alla root del namespace sono limitate a file compatibili con la **delegation**, come `cgroup.procs`, `cgroup.threads` e `cgroup.subtree_control`. Questo non trasforma comunque il namespace in una primitiva di **escape**, ma modifica ciò che un workload compromesso può ispezionare e il punto in cui può creare in sicurezza dei sub-cgroup.

Pertanto, anche se questo namespace non è solitamente il protagonista dei writeup sui **container breakout**, contribuisce comunque all'obiettivo più ampio di ridurre al minimo il **leak** di informazioni sull'host e limitare la **delegation** dei cgroup.

## Abuse

Il valore immediato per l'**abuse** è principalmente di **reconnaissance**. Se il **cgroup namespace** dell'host è condiviso, confronta i path visibili e cerca dettagli della gerarchia che possano rivelare l'host:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
Se vengono esposti anche percorsi cgroup scrivibili, combina questa visibilità con una ricerca di interfacce legacy pericolose:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
Il namespace raramente consente un escape immediato, ma spesso rende l'ambiente più semplice da mappare prima di testare i primitivi di abuso basati su cgroup.

Un rapido controllo della realtà del runtime aiuta inoltre a stabilire le priorità dell'attack path. Docker espone `--cgroupns=host|private`, mentre Podman supporta `host`, `private`, `container:<id>` e `ns:<path>`. In particolare, su Podman il valore predefinito è generalmente **`host` su cgroup v1** e **`private` su cgroup v2**, quindi identificare semplicemente la versione di cgroup indica già quale configurazione del namespace è più probabile, prima ancora di esaminare la configurazione OCI completa.

### Modern v2 Recon: Si tratta di un sottoalbero delegato?

Sugli host moderni, la domanda interessante spesso non riguarda `release_agent`, ma se il processo corrente si trovi all'interno di un sottoalbero **cgroup v2** delegato, con visibilità o accesso in scrittura sufficienti per creare gruppi annidati:
```bash
stat -fc %T /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
cat /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null
cat /sys/fs/cgroup/cgroup.events 2>/dev/null
```
Interpretazione utile:

- `cgroup2fs` significa che ti trovi nella gerarchia unificata v2, quindi le classiche catene `release_agent` specifiche di v1 non dovrebbero essere la tua prima ipotesi.
- `cgroup.controllers` mostra quali controller sono disponibili dal parent e quindi verso quali controller l'attuale subtree potrebbe potenzialmente propagarsi per i child.
- `cgroup.subtree_control` mostra quali controller sono effettivamente abilitati per i discendenti.
- `cgroup.events` espone `populated=0/1`, utile per monitorare se un subtree è diventato vuoto, ma **non** è una primitiva di host-code-execution come `release_agent` di v1.

Se disponi già di privilegi sufficienti per ispezionare direttamente il namespace di un altro processo, confronta le viste con:
```bash
nsenter -t <pid> -C -- bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
```
### Esempio completo: Shared cgroup Namespace + Writable cgroup v1

Il cgroup namespace da solo generalmente non è sufficiente per l'escape. L'escalation pratica si verifica quando i percorsi cgroup che rivelano l'host vengono combinati con interfacce cgroup v1 scrivibili:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
Se quei file sono raggiungibili e scrivibili, passa immediatamente al flusso completo di exploitation di `release_agent` descritto in [cgroups.md](../cgroups.md). L'impatto consiste nell'esecuzione di codice sull'host dall'interno del container.

Senza interfacce cgroup scrivibili, l'impatto è generalmente limitato alla ricognizione.

## Verifiche

Lo scopo di questi comandi è verificare se il processo dispone di una vista privata del namespace cgroup o se sta acquisendo più informazioni sulla gerarchia dell'host di quanto sia realmente necessario.
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
- I path che rivelano l'host in `/proc/self/cgroup` o le entry con radice nell'ancestor in `mountinfo` sono utili per la ricognizione anche quando non sono direttamente sfruttabili.
- Se è in uso `cgroup2fs`, concentrati sulla delega, sui controller visibili e sui subtree scrivibili invece di presumere che le vecchie primitive v1 esistano ancora.
- Se anche i mount dei cgroup sono scrivibili, la questione della visibilità diventa molto più importante.

Il cgroup namespace dovrebbe essere considerato un livello di hardening della visibilità, non un meccanismo primario di prevenzione dell'escape. Esporre inutilmente la struttura dei cgroup dell'host aggiunge valore per la ricognizione dell'attaccante.

## Riferimenti

- [Linux cgroup_namespaces(7)](https://man7.org/linux/man-pages/man7/cgroup_namespaces.7.html)
- [Documentazione del kernel Linux sui cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html)

{{#include ../../../../../banners/hacktricks-training.md}}
