# Namespace utente

{{#include ../../../../../banners/hacktricks-training.md}}

## Panoramica

Il user namespace cambia il significato di user e group ID permettendo al kernel di mappare gli ID visti all'interno del namespace su ID diversi all'esterno. Questa è una delle protezioni moderne più importanti per i container perché affronta direttamente il più grande problema storico dei container classici: **root all'interno del container era pericolosamente vicino al root sull'host**.

Con i user namespaces, un processo può girare come UID 0 dentro il container e corrispondere a una gamma di UID non privilegiati sull'host. Ciò significa che il processo può comportarsi come root per molte operazioni in-container pur avendo molto meno potere dal punto di vista dell'host. Questo non risolve tutti i problemi di sicurezza dei container, ma cambia in modo significativo le conseguenze di una compromissione del container.

## Funzionamento

Un user namespace dispone di file di mapping come `/proc/self/uid_map` e `/proc/self/gid_map` che descrivono come gli ID del namespace si traducono negli ID parent. Se root all'interno del namespace viene mappato su un UID dell'host non privilegiato, allora le operazioni che richiederebbero il vero root dell'host semplicemente non hanno lo stesso peso. Ecco perché i user namespaces sono centrali per i **rootless containers** e perché sono una delle maggiori differenze tra i vecchi default dei container rootful e i design moderni basati sul principio del least-privilege.

Il punto è sottile ma cruciale: root all'interno del container non viene eliminato, viene **tradotto**. Il processo continua a sperimentare un ambiente simile a root localmente, ma l'host non dovrebbe trattarlo come root completo.

## Lab

Un test manuale è:
```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```
Questo fa apparire l'utente corrente come root all'interno del namespace, pur non essendo root dell'host al di fuori di esso. È una delle dimostrazioni più semplici per capire perché user namespaces sono così preziosi.

Nei container, puoi confrontare la mappatura visibile con:
```bash
docker run --rm debian:stable-slim sh -c 'id && cat /proc/self/uid_map'
```
L'output esatto dipende dal fatto che il motore stia usando user namespace remapping o una configurazione rootful più tradizionale.

Puoi anche leggere la mappatura dal lato host con:
```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```
## Utilizzo a runtime

Rootless Podman è uno degli esempi più chiari di namespace utente trattati come un meccanismo di sicurezza di prima classe. Anche Rootless Docker si basa su di essi. Il supporto userns-remap di Docker migliora la sicurezza anche nelle installazioni con daemon rootful, sebbene storicamente molte installazioni lo lasciassero disabilitato per motivi di compatibilità. Il supporto di Kubernetes per i namespace utente è migliorato, ma adozione e valori di default variano per runtime, distro e policy del cluster. I sistemi Incus/LXC si basano inoltre pesantemente su UID/GID shifting e sui concetti di idmapping.

La tendenza generale è chiara: gli ambienti che usano seriamente i namespace utente di solito forniscono una risposta migliore a "what does container root actually mean?" rispetto a quelli che non lo fanno.

## Dettagli avanzati della mappatura

Quando un processo non privilegiato scrive in `uid_map` o `gid_map`, il kernel applica regole più restrittive rispetto a quelle applicate a uno scrittore privilegiato nel namespace padre. Sono consentite solo mappature limitate e, per `gid_map`, lo scrittore di solito deve prima disabilitare `setgroups(2)`:
```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```
Questo dettaglio è importante perché spiega perché la configurazione del namespace utente a volte fallisce negli esperimenti senza root e perché i runtime necessitano di una logica di supporto attenta per la delega di UID/GID.

Un'altra funzionalità avanzata è la **ID-mapped mount**. Invece di cambiare la proprietà su disco, una ID-mapped mount applica una mappatura del namespace utente a un mount in modo che la proprietà appaia tradotta attraverso quella vista di mount. Questo è particolarmente rilevante in ambienti rootless e nelle moderne configurazioni dei runtime perché permette di usare percorsi host condivisi senza operazioni ricorsive di `chown`. Dal punto di vista della sicurezza, la funzionalità cambia come un bind mount appare scrivibile dall'interno del namespace, anche se non riscrive i metadati del filesystem sottostante.

Infine, ricordate che quando un processo crea o entra in un nuovo namespace utente, riceve un insieme completo di capability **all'interno di quel namespace**. Questo non significa che acquisisca improvvisamente poteri a livello host. Significa che quelle capability possono essere usate solo dove il modello dei namespace e le altre protezioni lo permettono. Per questo `unshare -U` può improvvisamente rendere possibili operazioni privilegiate legate al mount o al namespace senza far scomparire direttamente il confine root dell'host.

## Misconfigurazioni

La debolezza principale è semplicemente non usare i namespace utente in ambienti dove sarebbero fattibili. Se il root del container è mappato troppo direttamente al root dell'host, i mount host scrivibili e le operazioni privilegiate del kernel diventano molto più pericolose. Un altro problema è forzare la condivisione del namespace utente dell'host o disabilitare il remapping per compatibilità senza riconoscere quanto ciò cambi il confine di fiducia.

I namespace utente devono essere considerati insieme al resto del modello. Anche quando sono attivi, un'ampia esposizione delle API del runtime o una configurazione del runtime molto debole possono comunque permettere escalation di privilegi tramite altri percorsi. Ma senza di essi, molte vecchie classi di breakout diventano molto più facili da sfruttare.

## Abuso

Se il container è rootful senza separazione del namespace utente, un bind mount host scrivibile diventa molto più pericoloso perché il processo potrebbe davvero scrivere come root dell'host. Anche le capability pericolose diventano più significative. L'attaccante non deve più lottare tanto contro il confine di traduzione perché quel confine quasi non esiste.

La presenza o l'assenza del namespace utente dovrebbe essere verificata presto quando si valuta un percorso di breakout dal container. Non risolve ogni questione, ma mostra immediatamente se "root in container" ha rilevanza diretta sull'host.

Il pattern di abuso più pratico è confermare la mappatura e poi testare immediatamente se il contenuto montato sull'host è scrivibile con privilegi rilevanti per l'host:
```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```
Se il file è creato come vero root dell'host, l'isolamento del user namespace è effettivamente assente per quel percorso. A quel punto, i classici host-file abuses diventano realistici:
```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```
Una conferma più sicura durante una valutazione live è scrivere un marcatore benigno invece di modificare file critici:
```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```
Questi controlli sono importanti perché rispondono rapidamente alla vera domanda: il root in questo container mappa abbastanza vicino al root dell'host da far sì che un mount scrivibile dell'host diventi immediatamente una via di compromissione dell'host?

### Esempio completo: Recupero delle capability locali del namespace

Se seccomp permette `unshare` e l'ambiente consente un nuovo user namespace, il processo può riottenere un set completo di capabilities all'interno di quel nuovo namespace:
```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```
Questo di per sé non è un host escape. La ragione per cui è importante è che i user namespaces possono riattivare azioni privilegiate locali al namespace che poi si combinano con mount deboli, kernel vulnerabili o superfici di runtime esposte in modo inadeguato.

## Checks

Questi comandi servono a rispondere alla domanda più importante in questa pagina: a cosa corrisponde root all'interno di questo container sull'host?
```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```
What is interesting here:

- Se il processo è UID 0 e le mappe mostrano una mappatura diretta o molto vicina al root dell'host, il container è molto più pericoloso.
- Se root è mappato su un intervallo non privilegiato dell'host, questa è una baseline molto più sicura e di solito indica un reale isolamento del user namespace.
- I file di mapping sono più preziosi del solo `id`, perché `id` mostra solo l'identità locale al namespace.

Se il workload gira con UID 0 e la mappatura mostra che ciò corrisponde strettamente al root dell'host, dovresti interpretare il resto dei privilegi del container in modo molto più restrittivo.
{{#include ../../../../../banners/hacktricks-training.md}}
