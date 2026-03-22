# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Panoramica

Il cgroup namespace non sostituisce i cgroups e non impone di per sé limiti di risorse. Invece, modifica **come la gerarchia dei cgroup viene mostrata** al processo. In altre parole, virtualizza le informazioni sui percorsi dei cgroup visibili in modo che il carico di lavoro veda una vista limitata al container piuttosto che l'intera gerarchia dell'host.

Si tratta principalmente di una funzionalità di riduzione della visibilità e delle informazioni. Aiuta a far apparire l'ambiente autosufficiente e a rivelare meno della disposizione dei cgroup dell'host. Potrebbe sembrare modesto, ma è comunque importante perché una visibilità non necessaria sulla struttura dell'host può agevolare la ricognizione e semplificare catene di exploit dipendenti dall'ambiente.

## Funzionamento

Senza un cgroup namespace privato, un processo può vedere percorsi cgroup relativi all'host che espongono più della gerarchia della macchina del necessario. Con un cgroup namespace privato, `/proc/self/cgroup` e osservazioni correlate diventano più localizzate nella vista del container. Questo è particolarmente utile negli stack runtime moderni che vogliono che il carico di lavoro veda un ambiente più pulito e meno rivelatore dell'host.

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
La modifica riguarda principalmente ciò che il processo può vedere, non se esista cgroup enforcement.

## Impatto sulla sicurezza

Il cgroup namespace va inteso soprattutto come uno strato di **indurimento della visibilità**. Da solo non fermerà un breakout se il container ha cgroup mounts scrivibili, ampie capabilities, o un ambiente cgroup v1 pericoloso. Tuttavia, se il host cgroup namespace è condiviso, il processo ottiene più informazioni su come il sistema è organizzato e potrebbe risultare più semplice mettere in correlazione host-relative cgroup paths con altre osservazioni.

Quindi, anche se questo namespace di solito non è il protagonista dei writeups su container breakout, contribuisce comunque all'obiettivo più ampio di minimizzare l'host information leakage.

## Abuse

Il valore d'abuso immediato è per lo più reconnaissance. Se il host cgroup namespace è condiviso, confronta i visible paths e cerca dettagli della gerarchia che rivelino informazioni sull'host:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
```
Se anche i percorsi cgroup scrivibili sono esposti, combina quella visibilità con una ricerca di interfacce legacy pericolose:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
Il cgroup namespace di per sé raramente fornisce un escape immediato, ma spesso rende l'ambiente più facile da mappare prima di testare cgroup-based abuse primitives.

### Esempio completo: cgroup namespace condiviso + cgroup v1 scrivibile

Il cgroup namespace da solo di solito non è sufficiente per l'escape. L'escalation pratica avviene quando host-revealing cgroup paths sono combinati con writable cgroup v1 interfaces:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
Se quei file sono raggiungibili e scrivibili, pivot immediatamente nel full `release_agent` exploitation flow da [cgroups.md](../cgroups.md). L'impatto è host code execution dall'interno del container.

Senza cgroup interfaces scrivibili, l'impatto è solitamente limitato alla reconnaissance.

## Checks

Lo scopo di questi comandi è verificare se il processo ha una view privata del cgroup namespace o se sta apprendendo più sulla host hierarchy di quanto effettivamente necessario.
```bash
readlink /proc/self/ns/cgroup   # Namespace identifier for cgroup view
cat /proc/self/cgroup           # Visible cgroup paths from inside the workload
mount | grep cgroup             # Mounted cgroup filesystems and their type
```
Cosa c'è di interessante qui:

- Se l'identificatore del namespace corrisponde a un processo dell'host di tuo interesse, il cgroup namespace potrebbe essere condiviso.
- I percorsi che rivelano l'host in `/proc/self/cgroup` sono utili per reconnaissance anche quando non sono direttamente sfruttabili.
- Se anche i cgroup mounts sono scrivibili, la questione della visibilità diventa molto più importante.

Il cgroup namespace dovrebbe essere trattato come un livello di hardening della visibilità piuttosto che come un meccanismo primario per prevenire gli escape. Esporre inutilmente la struttura cgroup dell'host aggiunge valore di reconnaissance per l'attaccante.
{{#include ../../../../../banners/hacktricks-training.md}}
