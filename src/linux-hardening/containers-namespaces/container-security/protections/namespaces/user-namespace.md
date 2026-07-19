# Namespace degli utenti

{{#include ../../../../../banners/hacktricks-training.md}}

## Panoramica

Il namespace degli utenti cambia il significato degli user ID e dei group ID consentendo al kernel di mappare gli ID visualizzati all'interno del namespace su ID differenti all'esterno. Questa è una delle più importanti protezioni moderne dei container perché affronta direttamente il principale problema storico dei container classici: **root all'interno del container era fin troppo vicino a root sull'host**.

Con i user namespace, un processo può essere eseguito come UID 0 all'interno del container e corrispondere comunque a un intervallo di UID non privilegiati sull'host. Ciò significa che il processo può comportarsi come root per molte attività all'interno del container, pur avendo un potere molto più limitato dal punto di vista dell'host. Questo non risolve tutti i problemi di sicurezza dei container, ma modifica significativamente le conseguenze della compromissione di un container.

## Funzionamento

Un user namespace dispone di file di mapping come `/proc/self/uid_map` e `/proc/self/gid_map`, che descrivono come gli ID del namespace vengono tradotti negli ID del namespace padre. Se root all'interno del namespace viene mappato su un UID non privilegiato dell'host, le operazioni che richiederebbero il vero root dell'host non hanno semplicemente lo stesso peso. Per questo i user namespace sono fondamentali per i **rootless containers** e rappresentano una delle principali differenze tra i vecchi default dei container rootful e i design moderni basati sul least privilege.

Il punto è sottile ma cruciale: root all'interno del container non viene eliminato, viene **tradotto**. Il processo continua a trovarsi localmente in un ambiente simile a quello di root, ma l'host non dovrebbe trattarlo come root completo.

## Laboratorio

Un test manuale è:
```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```
Questo fa apparire l'utente corrente come root all'interno del namespace, pur non essendo root sull'host al di fuori di esso. È una delle migliori dimostrazioni semplici per capire perché gli user namespaces siano così importanti.

Nei container, puoi confrontare la mappatura visibile con:
```bash
docker run --rm debian:stable-slim sh -c 'id && cat /proc/self/uid_map'
```
L'output esatto dipende dal fatto che il motore utilizzi il remapping degli user namespace o una configurazione rootful più tradizionale.

Puoi anche leggere il mapping dal lato host con:
```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```
## Utilizzo a runtime

Rootless Podman è uno degli esempi più chiari di user namespaces trattati come meccanismo di sicurezza di prima classe. Anche Rootless Docker dipende da essi. Il supporto di Docker per userns-remap migliora la sicurezza anche nelle distribuzioni con daemon rootful, sebbene storicamente molte distribuzioni lo lasciassero disabilitato per motivi di compatibilità. Il supporto di Kubernetes per gli user namespaces è migliorato, ma l'adozione e le impostazioni predefinite variano in base al runtime, alla distro e alle policy del cluster. Anche i sistemi Incus/LXC fanno ampio affidamento sullo shifting degli UID/GID e sui concetti di idmapping.

La tendenza generale è chiara: gli ambienti che utilizzano seriamente gli user namespaces forniscono solitamente una risposta migliore alla domanda "che cosa significa realmente root nel container?" rispetto agli ambienti che non li utilizzano.

## Dettagli avanzati del mapping

Quando un processo non privilegiato scrive in `uid_map` o `gid_map`, il kernel applica regole più restrittive rispetto a quelle applicate a un writer privilegiato del parent namespace. Sono consentiti solo mapping limitati e, per `gid_map`, il writer deve solitamente disabilitare prima `setgroups(2)`:
```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```
Questo dettaglio è importante perché spiega perché la configurazione dei user namespace a volte fallisce negli esperimenti rootless e perché i runtime necessitano di una logica helper attenta per la delega di UID/GID.

Un'altra funzionalità avanzata è il **ID-mapped mount**. Anziché modificare la proprietà su disco, un ID-mapped mount applica una mapping di un user namespace a un mount, in modo che la proprietà appaia tradotta attraverso la vista di quel mount. Questo è particolarmente rilevante nelle configurazioni rootless e nei runtime moderni, perché consente di usare path condivisi dell'host senza eseguire operazioni ricorsive di `chown`. Dal punto di vista della sicurezza, la funzionalità modifica il modo in cui un bind mount appare scrivibile dall'interno del namespace, anche se non riscrive i metadati sottostanti del filesystem.

Infine, ricorda che quando un processo crea o accede a un nuovo user namespace, riceve un set completo di capability **all'interno di quel namespace**. Questo non significa che abbia improvvisamente ottenuto poteri globali sull'host. Significa che tali capability possono essere usate solo nei contesti consentiti dal modello dei namespace e dalle altre protezioni. Per questo `unshare -U` può rendere improvvisamente possibili operazioni di mount o operazioni privilegiate locali al namespace senza far scomparire direttamente il confine di root dell'host.

## Misconfigurations

La debolezza principale consiste semplicemente nel non usare user namespace negli ambienti in cui sarebbero praticabili. Se root nel container viene mappato troppo direttamente a root sull'host, i mount scrivibili dell'host e le operazioni privilegiate del kernel diventano molto più pericolosi. Un altro problema consiste nel forzare la condivisione dei user namespace dell'host o nel disabilitare il remapping per motivi di compatibilità, senza riconoscere quanto questo modifichi il trust boundary.

Anche i user namespace devono essere considerati insieme al resto del modello. Persino quando sono attivi, un'esposizione ampia delle API del runtime o una configurazione del runtime molto debole possono comunque consentire una privilege escalation attraverso altri percorsi. Tuttavia, senza di essi, molte vecchie classi di breakout diventano molto più facili da sfruttare.

## Abuse

Se il container è rootful senza separazione tramite user namespace, un bind mount scrivibile dell'host diventa molto più pericoloso perché il processo potrebbe scrivere effettivamente come root dell'host. Anche le capability pericolose diventano più rilevanti. L'attaccante non deve più contrastare con la stessa intensità il translation boundary, perché tale boundary praticamente non esiste.

La presenza o l'assenza dei user namespace dovrebbe essere verificata nelle fasi iniziali della valutazione di un percorso di container breakout. Non fornisce una risposta a ogni domanda, ma mostra immediatamente se "root nel container" ha una rilevanza diretta sull'host.

Il pattern di abuso più pratico consiste nel confermare la mapping e poi verificare immediatamente se il contenuto montato dall'host è scrivibile con privilegi rilevanti per l'host:
```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```
Se il file viene creato come root effettivo dell'host, l'isolamento del user namespace è di fatto assente per quel percorso. A quel punto, i classici abusi dei file dell'host diventano realistici:
```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```
Una conferma più sicura durante una valutazione in corso consiste nello scrivere un marker innocuo invece di modificare file critici:
```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```
Questi controlli sono importanti perché rispondono rapidamente alla domanda reale: root in questo container corrisponde in modo sufficientemente stretto a root sull'host, al punto che un mount dell'host scrivibile diventi immediatamente un percorso per compromettere l'host?

### Esempio completo: recuperare le capabilities locali al namespace

Se seccomp consente `unshare` e l'ambiente permette di creare un nuovo user namespace, il processo potrebbe recuperare un set completo di capabilities all'interno di quel nuovo namespace:
```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```
Questo non costituisce di per sé un host escape. Il motivo per cui è importante è che gli user namespaces possono riabilitare azioni privilegiate locali al namespace, che in seguito si combinano con mount deboli, kernel vulnerabili o superfici runtime esposte in modo improprio.

## Checks

Questi comandi servono a rispondere alla domanda più importante di questa pagina: a quale identità sull'host corrisponde root all'interno di questo container?
```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```
Cosa è interessante qui:

- Se il processo ha UID 0 e le mappe mostrano una mappatura diretta o molto vicina a host-root, il container è molto più pericoloso.
- Se root viene mappato a un intervallo host non privilegiato, questa è una baseline molto più sicura e di solito indica un'effettiva isolation tramite user namespace.
- I file di mapping sono più preziosi del comando `id` da solo, perché `id` mostra soltanto l'identità locale al namespace.

Se il workload viene eseguito come UID 0 e il mapping mostra che ciò corrisponde strettamente a host-root, dovresti interpretare in modo molto più rigoroso il resto dei privilegi del container.
{{#include ../../../../../banners/hacktricks-training.md}}
