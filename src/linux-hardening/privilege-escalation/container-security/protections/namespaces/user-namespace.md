# Namespace utente

{{#include ../../../../../banners/hacktricks-training.md}}

## Panoramica

Il namespace utente modifica il significato degli UID e dei GID permettendo al kernel di mappare gli ID visti all'interno del namespace su ID diversi all'esterno. Questa è una delle protezioni moderne più importanti per i container perché affronta direttamente il problema storico più grande nei container classici: **il root all'interno del container era pericolosamente vicino al root sull'host**.

Con i namespace utente, un processo può girare come UID 0 all'interno del container e comunque corrispondere a un intervallo di UID non privilegiati sull'host. Questo significa che il processo può comportarsi come root per molte operazioni all'interno del container, pur avendo un potere molto ridotto dal punto di vista dell'host. Questo non risolve tutti i problemi di sicurezza dei container, ma cambia significativamente le conseguenze di una compromissione del container.

## Funzionamento

Un namespace utente ha file di mapping come `/proc/self/uid_map` e `/proc/self/gid_map` che descrivono come gli ID del namespace si traducono in ID del parent. Se il root all'interno del namespace è mappato su un UID non privilegiato dell'host, allora operazioni che richiederebbero il vero root dell'host semplicemente non hanno lo stesso impatto. Ecco perché i namespace utente sono centrali per i **rootless containers** e perché rappresentano una delle maggiori differenze tra i vecchi default dei container con root e i più moderni design basati sul principio del minimo privilegio.

Il punto è sottile ma cruciale: il root all'interno del container non viene eliminato, viene **tradotto**. Il processo continua a sperimentare un ambiente simile a root localmente, ma l'host non dovrebbe trattarlo come root completo.

## Lab

Un test manuale è:
```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```
Questo fa apparire l'utente corrente come root all'interno della namespace, pur non essendo root dell'host al di fuori di essa. È una delle migliori demo semplici per capire perché user namespaces sono così preziose.

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
## Runtime Usage

Rootless Podman è uno dei più chiari esempi di user namespaces trattati come meccanismo di sicurezza di prima classe. Anche Rootless Docker dipende da essi. Il supporto di Docker per userns-remap migliora la sicurezza anche nelle installazioni con daemon rootful, sebbene storicamente molte implementazioni lo abbiano lasciato disabilitato per ragioni di compatibilità. Il supporto di Kubernetes per user namespaces è migliorato, ma adozione e valori predefiniti variano a seconda del runtime, della distro e della policy del cluster. I sistemi Incus/LXC si basano anch'essi pesantemente sullo shifting di UID/GID e sulle idee di idmapping.

La tendenza generale è chiara: gli ambienti che usano seriamente user namespaces solitamente forniscono una risposta migliore a "cosa significa realmente container root?" rispetto agli ambienti che non li usano.

## Advanced Mapping Details

Quando un processo non privilegiato scrive in `uid_map` o `gid_map`, il kernel applica regole più rigorose rispetto a quelle valide per uno scrittore privilegiato nel namespace padre. Sono consentite solo mappature limitate e, per `gid_map`, lo scrittore di solito deve prima disabilitare `setgroups(2)`:
```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```
Questo dettaglio è importante perché spiega perché la configurazione di user-namespace a volte fallisce negli esperimenti rootless e perché i runtimes necessitano di una logica helper accurata per la delega di UID/GID.

Un'altra funzionalità avanzata è l'**ID-mapped mount**. Invece di cambiare la proprietà su disco, un ID-mapped mount applica una mappatura di user-namespace a un mount in modo che la proprietà appaia tradotta attraverso quella vista del mount. Questo è particolarmente rilevante in ambienti rootless e nelle moderne configurazioni runtime perché permette di usare percorsi host condivisi senza operazioni ricorsive di `chown`. Dal punto di vista della sicurezza, la funzionalità cambia come un bind mount appare scrivibile dall'interno della namespace, anche se non riscrive i metadati sottostanti del filesystem.

Infine, ricorda che quando un processo crea o entra in una nuova user namespace, riceve un set completo di capability **all'interno di quella namespace**. Questo non significa che abbia improvvisamente ottenuto poteri globali sull'host. Significa che quelle capability possono essere usate solo dove il modello di namespace e altre protezioni le consentono. È per questo che `unshare -U` può improvvisamente rendere possibili operazioni privilegiate di mount o locali alla namespace senza far scomparire direttamente il confine di root dell'host.

## Misconfigurazioni

Il principale punto debole è semplicemente non usare user namespaces in ambienti dove sarebbero fattibili. Se il container root mappa troppo direttamente al host root, writable host mounts e operazioni privilegiate del kernel diventano molto più pericolose. Un altro problema è forzare la condivisione della host user namespace o disabilitare il remapping per compatibilità senza riconoscere quanto ciò cambi il trust boundary.

Le user namespaces devono essere considerate insieme al resto del modello. Anche quando sono attive, un'esposizione ampia dell'API del runtime o una configurazione runtime molto debole possono comunque permettere escalation di privilegi tramite altre vie. Ma senza di esse, molte vecchie classi di breakout diventano molto più facili da sfruttare.

## Abusi

Se il container è rootful senza separazione user namespace, un writable host bind mount diventa molto più pericoloso perché il processo potrebbe effettivamente scrivere come host root. Anche le capability pericolose diventano più significative. L'attaccante non ha più bisogno di lottare tanto contro il confine di traduzione perché quel confine quasi non esiste.

La presenza o l'assenza di user namespaces dovrebbe essere verificata presto quando si valuta un percorso di container breakout. Non risponde a tutte le domande, ma mostra immediatamente se "root in container" ha rilevanza diretta sull'host.

Il pattern di abuso più pratico è confermare la mappatura e poi testare immediatamente se il contenuto mountato sull'host è scrivibile con privilegi rilevanti per l'host:
```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```
Se il file viene creato come root reale dell'host, la user namespace isolation è effettivamente assente per quel percorso. A quel punto, gli abusi classici sui file dell'host diventano realistici:
```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```
Una conferma più sicura durante un assessment live è scrivere un marcatore innocuo invece di modificare file critici:
```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```
Questi controlli sono importanti perché rispondono rapidamente alla vera domanda: il root in questo container è mappato abbastanza vicino al root dell'host da far sì che un mount dell'host scrivibile diventi immediatamente un vettore di compromissione dell'host?

### Esempio completo: Recupero delle capability locali del namespace

Se seccomp permette `unshare` e l'ambiente consente un nuovo user namespace, il processo può riottenere un set completo di capability all'interno di quel nuovo namespace:
```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```
Questo di per sé non è un host escape. La ragione per cui è importante è che i user namespaces possono riabilitare azioni privilegiate locali al namespace che poi si combinano con mount deboli, kernel vulnerabili o superfici di runtime esposte in modo inadeguato.

## Controlli

Questi comandi servono a rispondere alla domanda più importante di questa pagina: a cosa corrisponde root all'interno di questo container sull'host?
```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```
Cosa è interessante qui:

- Se il processo è UID 0 e i file di mapping mostrano una mappatura host-root diretta o molto vicina, il container è molto più pericoloso.
- Se root mappa su un intervallo host non privilegiato, quella è una condizione di base molto più sicura e di solito indica un vero isolamento del user namespace.
- I file di mapping sono più utili del solo `id`, perché `id` mostra solo l'identità locale al namespace.

Se il workload viene eseguito come UID 0 e la mappatura mostra che ciò corrisponde strettamente a root dell'host, dovresti considerare il resto dei privilegi del container con maggior rigore.
