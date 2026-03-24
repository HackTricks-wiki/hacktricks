# Namespace utente

{{#include ../../../../../banners/hacktricks-training.md}}

## Panoramica

Il namespace utente cambia il significato di UID e GID permettendo al kernel di mappare gli ID visti all'interno del namespace su ID differenti all'esterno. Questa è una delle protezioni più importanti dei container moderni perché affronta direttamente il più grande problema storico dei container classici: **root all'interno del container era pericolosamente vicino al root sull'host**.

Con i user namespaces, un processo può eseguire come UID 0 all'interno del container e corrispondere ancora a un intervallo di UID non privilegiati sull'host. Ciò significa che il processo può comportarsi come root per molte operazioni all'interno del container pur avendo molta meno potenza dal punto di vista dell'host. Questo non risolve tutti i problemi di sicurezza dei container, ma cambia in modo significativo le conseguenze di una compromissione del container.

## Funzionamento

Un user namespace ha file di mapping come `/proc/self/uid_map` e `/proc/self/gid_map` che descrivono come gli ID del namespace si traducono negli ID del parent. Se il root all'interno del namespace è mappato su un UID non privilegiato dell'host, allora le operazioni che richiederebbero il vero root dell'host semplicemente non hanno lo stesso peso. Ecco perché i user namespaces sono centrali per i **rootless containers** e perché rappresentano una delle maggiori differenze tra i vecchi default dei container con privilegi di root e i design moderni a privilegio minimo.

Il punto è sottile ma cruciale: root all'interno del container non viene eliminato, viene **tradotto**. Il processo sperimenta ancora un ambiente simile a root localmente, ma l'host non dovrebbe trattarlo come root completo.

## Lab

Un test manuale è:
```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```
Questo fa apparire l'utente corrente come root all'interno del namespace pur non essendo root dell'host al di fuori di esso. È una delle migliori demo semplici per capire perché i user namespaces sono così preziosi.

Nei container, puoi confrontare la mappatura visibile con:
```bash
docker run --rm debian:stable-slim sh -c 'id && cat /proc/self/uid_map'
```
L'output esatto dipende dal fatto che il motore stia usando la rimappatura dei namespace utente o una configurazione rootful più tradizionale.

Puoi anche leggere la mappatura dal lato host con:
```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```
## Uso a runtime

Rootless Podman è uno dei più chiari esempi di user namespaces trattati come meccanismo di sicurezza di prima classe. Anche Rootless Docker dipende da essi. Il supporto di Docker per userns-remap migliora la sicurezza anche nelle deployment con daemon rootful, sebbene storicamente molte installazioni lo abbiano lasciato disabilitato per motivi di compatibilità. Il supporto di Kubernetes per user namespaces è migliorato, ma adozione e valori predefiniti variano in base a runtime, distro e policy del cluster. I sistemi Incus/LXC si basano anch'essi pesantemente su UID/GID shifting e idmapping.

La tendenza generale è chiara: gli ambienti che usano seriamente user namespaces di solito forniscono una risposta migliore a "che cosa significa realmente 'container root'?" rispetto agli ambienti che non lo fanno.

## Dettagli avanzati di mappatura

Quando un processo non privilegiato scrive in `uid_map` o `gid_map`, il kernel applica regole più severe rispetto a quelle per uno scrivente privilegiato nel namespace padre. Sono consentite solo mappature limitate, e per `gid_map` lo scrivente di solito deve prima disabilitare `setgroups(2)`:
```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```
Questo dettaglio è importante perché spiega perché la configurazione di user namespace a volte fallisce negli esperimenti rootless e perché i runtime hanno bisogno di logica helper attenta attorno alla delega di UID/GID.

Un'altra funzionalità avanzata è la **ID-mapped mount**. Invece di modificare la proprietà sul disco, una **ID-mapped mount** applica una mappatura di user namespace a un mount in modo che la proprietà appaia tradotta attraverso quella vista del mount. Questo è particolarmente rilevante in ambienti rootless e nelle moderne configurazioni runtime perché permette di usare percorsi host condivisi senza operazioni ricorsive di `chown`. Dal punto di vista della sicurezza, la feature modifica come un bind mount appare scrivibile dall'interno del namespace, anche se non riscrive i metadati del filesystem sottostante.

Infine, ricordate che quando un processo crea o entra in un nuovo user namespace, riceve un set completo di capability **all'interno di quel namespace**. Ciò non significa che abbia improvvisamente acquisito poteri globali sull'host. Significa che quelle capabilities possono essere usate solo dove il modello dei namespace e altre protezioni lo permettono. Per questo motivo `unshare -U` può rendere improvvisamente possibili operazioni privilegiate di montaggio o locali al namespace senza eliminare direttamente il confine root dell'host.

## Malconfigurazioni

La debolezza principale è semplicemente non utilizzare i user namespace in ambienti dove sarebbero fattibili. Se il root del container è mappato troppo direttamente al root dell'host, i host mounts scrivibili e le operazioni privilegiate del kernel diventano molto più pericolosi. Un altro problema è forzare la condivisione del host user namespace o disabilitare il remapping per compatibilità senza riconoscere quanto ciò cambi il confine di fiducia.

I user namespaces devono essere considerati anche insieme al resto del modello. Anche quando sono attivi, un'esposizione ampia dell'API del runtime o una configurazione runtime molto debole possono ancora permettere escalation di privilegi attraverso altre vie. Ma senza di essi, molte vecchie classi di breakout diventano molto più facili da sfruttare.

## Abuso

Se il container è rootful senza separazione di user namespace, un host bind mount scrivibile diventa molto più pericoloso perché il processo potrebbe veramente scrivere come root dell'host. Anche le capability pericolose diventano conseguentemente più rilevanti. L'attaccante non deve più lottare tanto contro il confine di traduzione perché quel confine praticamente non esiste.

La presenza o assenza di user namespace dovrebbe essere verificata precocemente quando si valuta un percorso di breakout di un container. Non risolve ogni quesito, ma mostra immediatamente se "root in container" ha una rilevanza diretta sull'host.

Il pattern di abuso più pratico è confermare la mappatura e poi testare immediatamente se il contenuto montato dall'host è scrivibile con privilegi rilevanti per l'host:
```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```
Se il file viene creato come real host root, la user namespace isolation è effettivamente assente per quel percorso. A quel punto, i classic host-file abuses diventano realistici:
```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```
Una conferma più sicura durante una valutazione live è scrivere un marker benigno invece di modificare file critici:
```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```
Questi controlli sono importanti perché rispondono velocemente alla vera domanda: il root in questo container è mappato così strettamente al root dell'host che un mount host scrivibile diventa immediatamente una via di compromissione dell'host?

### Esempio completo: riacquisire le capability locali al namespace

Se seccomp permette `unshare` e l'ambiente consente la creazione di un nuovo user namespace, il processo può riacquisire un set completo di capability all'interno di quel nuovo namespace:
```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```
Questo, di per sé, non è un host escape. Il motivo per cui è importante è che user namespaces possono riattivare azioni privilegiate locali al namespace che poi si combinano con weak mounts, vulnerable kernels o runtime surfaces esposte in modo inappropriato.

## Controlli

Questi comandi servono a rispondere alla domanda più importante di questa pagina: a cosa corrisponde root all'interno di questo container sull'host?
```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```
- Se il processo è UID 0 e le mappe mostrano una mappatura host-root diretta o molto vicina, il container è molto più pericoloso.
- Se root viene mappato su un intervallo host non privilegiato, questa è una baseline molto più sicura e di solito indica un reale isolamento del user namespace.
- I file di mapping sono più utili di `id` da solo, perché `id` mostra solo l'identità locale al namespace.

Se il carico di lavoro gira come UID 0 e la mappatura mostra che questo corrisponde strettamente a root dell'host, dovresti interpretare il resto dei privilegi del container in modo molto più restrittivo.
{{#include ../../../../../banners/hacktricks-training.md}}
