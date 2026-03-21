# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Panoramica

Il cgroup namespace non sostituisce i cgroups e non applica di per sé limiti di risorse. Invece, modifica **come la gerarchia dei cgroup appare** al processo. In altre parole, virtualizza le informazioni sui percorsi cgroup visibili in modo che il workload veda una vista limitata al container invece dell'intera gerarchia dell'host.

Si tratta principalmente di una caratteristica di visibilità e riduzione delle informazioni. Aiuta a rendere l'ambiente auto-contenuto e a rivelare meno sulla disposizione dei cgroup dell'host. Può sembrare di poco conto, ma è comunque importante perché una visibilità non necessaria sulla struttura dell'host può facilitare la ricognizione e semplificare catene di exploit dipendenti dall'ambiente.

## Funzionamento

Senza un cgroup namespace privato, un processo può vedere percorsi cgroup relativi all'host che espongono più della gerarchia della macchina di quanto sia utile. Con un cgroup namespace privato, `/proc/self/cgroup` e osservazioni correlate diventano più localizzate alla vista del container. Questo è particolarmente utile negli stack runtime moderni che vogliono che il workload veda un ambiente più ordinato e meno rivelatore dell'host.

## Laboratorio

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
Il cambiamento riguarda principalmente ciò che il processo può vedere, non se l'enforcement dei cgroup esista.

## Security Impact

Il namespace dei cgroup va inteso principalmente come un **livello di indurimento della visibilità**. Di per sé non impedirà un breakout se il container ha cgroup mounts scrivibili, capabilities ampie, o un ambiente cgroup v1 pericoloso. Tuttavia, se il host cgroup namespace è condiviso, il processo apprende di più su come il sistema è organizzato e potrebbe trovare più facile allineare i percorsi cgroup relativi all'host con altre osservazioni.

Quindi, anche se questo namespace di solito non è la star dei container breakout writeups, contribuisce comunque all'obiettivo più ampio di minimizzare la fuga di informazioni sull'host.

## Abuse

Il valore di abuso immediato è soprattutto reconnaissance. Se il host cgroup namespace è condiviso, confronta i percorsi visibili e cerca dettagli gerarchici che rivelino l'host:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
```
Se sono esposti anche percorsi cgroup scrivibili, combina questa visibilità con una ricerca di interfacce legacy pericolose:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
Il namespace di per sé raramente permette un'escape immediata, ma spesso rende più facile mappare l'ambiente prima di testare cgroup-based abuse primitives.

### Esempio completo: Namespace cgroup condiviso + cgroup v1 scrivibile

Il namespace cgroup da solo di solito non è sufficiente per un'escape. L'escalation pratica avviene quando percorsi cgroup che rivelano l'host vengono combinati con interfacce cgroup v1 scrivibili:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
Se quei file sono raggiungibili e scrivibili, effettua un pivot immediatamente nel flusso completo di exploitation `release_agent` da [cgroups.md](../cgroups.md). L'impatto è host code execution dall'interno del container.

Senza interfacce cgroup scrivibili, l'impatto è solitamente limitato alla reconnaissance.

## Controlli

Lo scopo di questi comandi è verificare se il processo ha una private cgroup namespace view oppure sta venendo a conoscenza di più sulla gerarchia dell'host di quanto realmente necessario.
```bash
readlink /proc/self/ns/cgroup   # Namespace identifier for cgroup view
cat /proc/self/cgroup           # Visible cgroup paths from inside the workload
mount | grep cgroup             # Mounted cgroup filesystems and their type
```
Ciò che è interessante qui:

- Se l'identificatore del namespace corrisponde a un processo sull'host che ti interessa, il cgroup namespace potrebbe essere condiviso.
- I percorsi che rivelano l'host in `/proc/self/cgroup` sono utili per la reconnaissance anche quando non sono direttamente sfruttabili.
- Se anche i cgroup mounts sono scrivibili, la questione della visibility diventa molto più importante.

Il cgroup namespace dovrebbe essere trattato come un livello di visibility-hardening piuttosto che come un meccanismo primario di escape-prevention. Esporre inutilmente la struttura dei cgroup dell'host aggiunge valore di reconnaissance per l'attacker.
