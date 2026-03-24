# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Panoramica

Il cgroup namespace non sostituisce i cgroups e non impone direttamente limiti di risorse. Invece, modifica **come appare la gerarchia dei cgroup** per il processo. In altre parole, virtualizza le informazioni visibili sui percorsi dei cgroup in modo che il carico di lavoro veda una vista a livello container anziché la gerarchia completa dell'host.

Si tratta principalmente di una funzionalità di visibilità e riduzione delle informazioni. Aiuta a far apparire l'ambiente autosufficiente e a rivelare meno sulla disposizione dei cgroup dell'host. Può sembrare modesto, ma è comunque importante perché una visibilità non necessaria sulla struttura dell'host può facilitare la ricognizione e semplificare catene di exploit dipendenti dall'ambiente.

## Funzionamento

Senza un namespace cgroup privato, un processo può vedere percorsi cgroup relativi all'host che espongono più della gerarchia della macchina di quanto sia utile. Con un namespace cgroup privato, `/proc/self/cgroup` e le osservazioni correlate diventano più localizzate alla vista del container. Questo è particolarmente utile negli stack di runtime moderni che vogliono che il carico di lavoro veda un ambiente più pulito e che riveli meno informazioni sull'host.

## Lab

Puoi ispezionare un cgroup namespace con:
```bash
sudo unshare --cgroup --fork bash
cat /proc/self/cgroup
ls -l /proc/self/ns/cgroup
```
E confronta il comportamento a runtime con:
```bash
docker run --rm debian:stable-slim cat /proc/self/cgroup
docker run --rm --cgroupns=host debian:stable-slim cat /proc/self/cgroup
```
La modifica riguarda principalmente ciò che il processo può vedere, non se il cgroup enforcement sia presente.

## Impatto sulla sicurezza

Il cgroup namespace va inteso soprattutto come uno strato di **visibility-hardening**. Da solo non impedirà un breakout se il container ha mount dei cgroup scrivibili, capabilities ampie, o un ambiente cgroup v1 pericoloso. Tuttavia, se il cgroup namespace dell'host è condiviso, il processo apprende di più su come il sistema è organizzato e può risultare più semplice allineare i percorsi cgroup relativi all'host con altre osservazioni.

Quindi, anche se questo namespace di solito non è la protagonista delle writeup sui container breakout, contribuisce comunque all'obiettivo più ampio di minimizzare l'host information leakage.

## Abuse

Il valore d'abuso immediato è per lo più reconnaissance. Se il cgroup namespace dell'host è condiviso, confronta i percorsi visibili e cerca dettagli della gerarchia che rivelino l'host:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
```
Se sono esposti anche percorsi cgroup scrivibili, combina quella visibilità con una ricerca di interfacce legacy pericolose:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
Il namespace di per sé raramente fornisce un instant escape, ma spesso rende l'ambiente più facile da mappare prima di testare cgroup-based abuse primitives.

### Esempio completo: Shared cgroup Namespace + Writable cgroup v1

Il cgroup namespace da solo di solito non è sufficiente per l'escape. L'escalation pratica avviene quando host-revealing cgroup paths sono combinati con writable cgroup v1 interfaces:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
Se quei file sono raggiungibili e scrivibili, pivot immediatamente nel flusso completo di exploitation `release_agent` da [cgroups.md](../cgroups.md). L'impatto è l'esecuzione di codice sull'host dall'interno del container.

Senza interfacce cgroup scrivibili, l'impatto è solitamente limitato alla ricognizione.

## Verifiche

Lo scopo di questi comandi è verificare se il processo ha una vista privata del namespace cgroup o sta apprendendo più sulla gerarchia dell'host di quanto realmente necessario.
```bash
readlink /proc/self/ns/cgroup   # Namespace identifier for cgroup view
cat /proc/self/cgroup           # Visible cgroup paths from inside the workload
mount | grep cgroup             # Mounted cgroup filesystems and their type
```
Cosa c'è di interessante qui:

- Se l'identificatore del namespace corrisponde a un processo host che ti interessa, il cgroup namespace può essere condiviso.
- I percorsi che rivelano l'host in `/proc/self/cgroup` sono utili per la ricognizione anche quando non sono direttamente sfruttabili.
- Se anche i cgroup mounts sono scrivibili, la questione della visibilità diventa molto più importante.

Il cgroup namespace dovrebbe essere trattato come un livello di hardening della visibilità piuttosto che come un meccanismo primario di escape-prevention. Esporre inutilmente la struttura cgroup dell'host aggiunge valore di ricognizione per l'attaccante.
{{#include ../../../../../banners/hacktricks-training.md}}
