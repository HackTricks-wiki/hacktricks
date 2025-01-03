# AppArmor

{{#include ../../../banners/hacktricks-training.md}}

## Informazioni di base

AppArmor è un **miglioramento del kernel progettato per limitare le risorse disponibili ai programmi attraverso profili per programma**, implementando efficacemente il Controllo di Accesso Obbligatorio (MAC) legando gli attributi di controllo accesso direttamente ai programmi invece che agli utenti. Questo sistema opera **caricando profili nel kernel**, solitamente durante l'avvio, e questi profili determinano quali risorse un programma può accedere, come connessioni di rete, accesso a socket raw e permessi di file.

Ci sono due modalità operative per i profili di AppArmor:

- **Modalità di Enforcement**: Questa modalità applica attivamente le politiche definite all'interno del profilo, bloccando le azioni che violano queste politiche e registrando eventuali tentativi di violazione attraverso sistemi come syslog o auditd.
- **Modalità di Complain**: A differenza della modalità di enforcement, la modalità di complain non blocca le azioni che vanno contro le politiche del profilo. Invece, registra questi tentativi come violazioni delle politiche senza applicare restrizioni.

### Componenti di AppArmor

- **Modulo del Kernel**: Responsabile dell'applicazione delle politiche.
- **Politiche**: Specificano le regole e le restrizioni per il comportamento dei programmi e l'accesso alle risorse.
- **Parser**: Carica le politiche nel kernel per l'applicazione o la segnalazione.
- **Utilità**: Questi sono programmi in modalità utente che forniscono un'interfaccia per interagire e gestire AppArmor.

### Percorso dei profili

I profili di AppArmor sono solitamente salvati in _**/etc/apparmor.d/**_\
Con `sudo aa-status` sarai in grado di elencare i binari che sono limitati da qualche profilo. Se puoi cambiare il carattere "/" con un punto nel percorso di ciascun binario elencato, otterrai il nome del profilo apparmor all'interno della cartella menzionata.

Ad esempio, un **profilo apparmor** per _/usr/bin/man_ si troverà in _/etc/apparmor.d/usr.bin.man_

### Comandi
```bash
aa-status     #check the current status
aa-enforce    #set profile to enforce mode (from disable or complain)
aa-complain   #set profile to complain mode (from diable or enforcement)
apparmor_parser #to load/reload an altered policy
aa-genprof    #generate a new profile
aa-logprof    #used to change the policy when the binary/program is changed
aa-mergeprof  #used to merge the policies
```
## Creazione di un profilo

- Per indicare l'eseguibile interessato, **i percorsi assoluti e i caratteri jolly** sono consentiti (per il file globbing) per specificare i file.
- Per indicare l'accesso che il binario avrà su **file** possono essere utilizzati i seguenti **controlli di accesso**:
- **r** (lettura)
- **w** (scrittura)
- **m** (mappa di memoria come eseguibile)
- **k** (blocco file)
- **l** (creazione di hard link)
- **ix** (per eseguire un altro programma con la nuova politica che eredita)
- **Px** (eseguire sotto un altro profilo, dopo aver pulito l'ambiente)
- **Cx** (eseguire sotto un profilo figlio, dopo aver pulito l'ambiente)
- **Ux** (eseguire senza restrizioni, dopo aver pulito l'ambiente)
- **Le variabili** possono essere definite nei profili e possono essere manipolate dall'esterno del profilo. Ad esempio: @{PROC} e @{HOME} (aggiungere #include \<tunables/global> al file del profilo)
- **Le regole di negazione sono supportate per sovrascrivere le regole di autorizzazione**.

### aa-genprof

Per iniziare facilmente a creare un profilo, apparmor può aiutarti. È possibile fare in modo che **apparmor ispezioni le azioni eseguite da un binario e poi ti consenta di decidere quali azioni vuoi consentire o negare**.\
Devi solo eseguire:
```bash
sudo aa-genprof /path/to/binary
```
Quindi, in una console diversa, esegui tutte le azioni che il binario eseguirà di solito:
```bash
/path/to/binary -a dosomething
```
Poi, nella prima console premi "**s**" e poi nelle azioni registrate indica se vuoi ignorare, consentire o altro. Quando hai finito premi "**f**" e il nuovo profilo sarà creato in _/etc/apparmor.d/path.to.binary_

> [!NOTE]
> Usando i tasti freccia puoi selezionare cosa vuoi consentire/negare/altro

### aa-easyprof

Puoi anche creare un modello di un profilo apparmor di un binario con:
```bash
sudo aa-easyprof /path/to/binary
# vim:syntax=apparmor
# AppArmor policy for binary
# ###AUTHOR###
# ###COPYRIGHT###
# ###COMMENT###

#include <tunables/global>

# No template variables specified

"/path/to/binary" {
#include <abstractions/base>

# No abstractions specified

# No policy groups specified

# No read paths specified

# No write paths specified
}
```
> [!NOTE]
> Nota che per impostazione predefinita in un profilo creato nulla è consentito, quindi tutto è negato. Dovrai aggiungere righe come `/etc/passwd r,` per consentire la lettura del binario `/etc/passwd`, ad esempio.

Puoi quindi **applicare** il nuovo profilo con
```bash
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
### Modificare un profilo dai log

Lo strumento seguente leggerà i log e chiederà all'utente se desidera consentire alcune delle azioni vietate rilevate:
```bash
sudo aa-logprof
```
> [!NOTE]
> Utilizzando i tasti freccia puoi selezionare cosa vuoi consentire/nnegare/qualunque cosa

### Gestire un Profilo
```bash
#Main profile management commands
apparmor_parser -a /etc/apparmor.d/profile.name #Load a new profile in enforce mode
apparmor_parser -C /etc/apparmor.d/profile.name #Load a new profile in complain mode
apparmor_parser -r /etc/apparmor.d/profile.name #Replace existing profile
apparmor_parser -R /etc/apparmor.d/profile.name #Remove profile
```
## Logs

Esempio di log **AUDIT** e **DENIED** da _/var/log/audit/audit.log_ dell'eseguibile **`service_bin`**:
```bash
type=AVC msg=audit(1610061880.392:286): apparmor="AUDIT" operation="getattr" profile="/bin/rcat" name="/dev/pts/1" pid=954 comm="service_bin" requested_mask="r" fsuid=1000 ouid=1000
type=AVC msg=audit(1610061880.392:287): apparmor="DENIED" operation="open" profile="/bin/rcat" name="/etc/hosts" pid=954 comm="service_bin" requested_mask="r" denied_mask="r" fsuid=1000 ouid=0
```
Puoi anche ottenere queste informazioni utilizzando:
```bash
sudo aa-notify -s 1 -v
Profile: /bin/service_bin
Operation: open
Name: /etc/passwd
Denied: r
Logfile: /var/log/audit/audit.log

Profile: /bin/service_bin
Operation: open
Name: /etc/hosts
Denied: r
Logfile: /var/log/audit/audit.log

AppArmor denials: 2 (since Wed Jan  6 23:51:08 2021)
For more information, please see: https://wiki.ubuntu.com/DebuggingApparmor
```
## Apparmor in Docker

Nota come il profilo **docker-profile** di docker venga caricato per impostazione predefinita:
```bash
sudo aa-status
apparmor module is loaded.
50 profiles are loaded.
13 profiles are in enforce mode.
/sbin/dhclient
/usr/bin/lxc-start
/usr/lib/NetworkManager/nm-dhcp-client.action
/usr/lib/NetworkManager/nm-dhcp-helper
/usr/lib/chromium-browser/chromium-browser//browser_java
/usr/lib/chromium-browser/chromium-browser//browser_openjdk
/usr/lib/chromium-browser/chromium-browser//sanitized_helper
/usr/lib/connman/scripts/dhclient-script
docker-default
```
Per impostazione predefinita, il **profilo docker-default di Apparmor** è generato da [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

**Riepilogo del profilo docker-default**:

- **Accesso** a tutta la **rete**
- **Nessuna capacità** è definita (Tuttavia, alcune capacità deriveranno dall'inclusione di regole di base, ad es. #include \<abstractions/base>)
- **Scrivere** in qualsiasi file di **/proc** **non è consentito**
- Altre **sottodirectory**/**file** di /**proc** e /**sys** hanno accesso in lettura/scrittura/blocco/link/esecuzione **negato**
- **Montaggio** **non è consentito**
- **Ptrace** può essere eseguito solo su un processo che è confinato dallo **stesso profilo apparmor**

Una volta che **esegui un container docker**, dovresti vedere il seguente output:
```bash
1 processes are in enforce mode.
docker-default (825)
```
Nota che **apparmor bloccherà anche i privilegi delle capacità** concessi al container per impostazione predefinita. Ad esempio, sarà in grado di **bloccare il permesso di scrivere all'interno di /proc anche se la capacità SYS_ADMIN è concessa** perché per impostazione predefinita il profilo apparmor di docker nega questo accesso:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined ubuntu /bin/bash
echo "" > /proc/stat
sh: 1: cannot create /proc/stat: Permission denied
```
Devi **disabilitare apparmor** per bypassare le sue restrizioni:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu /bin/bash
```
Nota che per impostazione predefinita **AppArmor** **vietera' anche al container di montare** cartelle dall'interno anche con la capacità SYS_ADMIN.

Nota che puoi **aggiungere/rimuovere** **capacità** al container docker (questo sarà comunque limitato da metodi di protezione come **AppArmor** e **Seccomp**):

- `--cap-add=SYS_ADMIN` aggiungi la capacità `SYS_ADMIN`
- `--cap-add=ALL` aggiungi tutte le capacità
- `--cap-drop=ALL --cap-add=SYS_PTRACE` rimuovi tutte le capacità e aggiungi solo `SYS_PTRACE`

> [!NOTE]
> Di solito, quando **scopri** di avere una **capacità privilegiata** disponibile **all'interno** di un **container** **docker** **ma** che una parte dell'**exploit non funziona**, questo sarà perché **apparmor di docker sta impedendo**.

### Esempio

(Esempio da [**qui**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/))

Per illustrare la funzionalità di AppArmor, ho creato un nuovo profilo Docker “mydocker” con la seguente riga aggiunta:
```
deny /etc/* w,   # deny write for all files directly in /etc (not in a subdir)
```
Per attivare il profilo, dobbiamo fare quanto segue:
```
sudo apparmor_parser -r -W mydocker
```
Per elencare i profili, possiamo eseguire il seguente comando. Il comando qui sotto sta elencando il mio nuovo profilo AppArmor.
```
$ sudo apparmor_status  | grep mydocker
mydocker
```
Come mostrato di seguito, otteniamo un errore quando cerchiamo di modificare “/etc/” poiché il profilo AppArmor impedisce l'accesso in scrittura a “/etc”.
```
$ docker run --rm -it --security-opt apparmor:mydocker -v ~/haproxy:/localhost busybox chmod 400 /etc/hostname
chmod: /etc/hostname: Permission denied
```
### AppArmor Docker Bypass1

Puoi scoprire quale **profilo apparmor sta eseguendo un container** utilizzando:
```bash
docker inspect 9d622d73a614 | grep lowpriv
"AppArmorProfile": "lowpriv",
"apparmor=lowpriv"
```
Quindi, puoi eseguire la seguente riga per **trovare il profilo esatto in uso**:
```bash
find /etc/apparmor.d/ -name "*lowpriv*" -maxdepth 1 2>/dev/null
```
In un caso strano puoi **modificare il profilo docker di apparmor e ricaricarlo.** Potresti rimuovere le restrizioni e "bypassarle".

### Bypass2 di AppArmor Docker

**AppArmor è basato su percorsi**, questo significa che anche se potrebbe essere **protetto** file all'interno di una directory come **`/proc`**, se puoi **configurare come il container verrà eseguito**, potresti **montare** la directory proc dell'host all'interno di **`/host/proc`** e non **sarà più protetta da AppArmor**.

### Bypass Shebang di AppArmor

In [**questo bug**](https://bugs.launchpad.net/apparmor/+bug/1911431) puoi vedere un esempio di come **anche se stai impedendo l'esecuzione di perl con determinate risorse**, se crei semplicemente uno script shell **specificando** nella prima riga **`#!/usr/bin/perl`** e **esegui il file direttamente**, sarai in grado di eseguire qualsiasi cosa tu voglia. E.g.:
```perl
echo '#!/usr/bin/perl
use POSIX qw(strftime);
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh"' > /tmp/test.pl
chmod +x /tmp/test.pl
/tmp/test.pl
```
{{#include ../../../banners/hacktricks-training.md}}
