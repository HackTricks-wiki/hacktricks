# Linux Forensics

{{#include ../../banners/hacktricks-training.md}}

## Raccolta iniziale di informazioni

### Informazioni di base

Prima di tutto, è consigliato avere una **USB** con **binaries e libraries affidabili e note** al suo interno (puoi semplicemente prendere Ubuntu e copiare le cartelle _/bin_, _/sbin_, _/lib,_ e _/lib64_), poi monta la USB e modifica le variabili d'ambiente per usare quei binaries:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
Una volta configurato il sistema per usare binari buoni e noti, puoi iniziare a **estrarre alcune informazioni di base**:
```bash
date #Date and time (Clock may be skewed, Might be at a different timezone)
uname -a #OS info
ifconfig -a || ip a #Network interfaces (promiscuous mode?)
ps -ef #Running processes
netstat -anp #Proccess and ports
lsof -V #Open files
netstat -rn; route #Routing table
df; mount #Free space and mounted devices
free #Meam and swap space
w #Who is connected
last -Faiwx #Logins
lsmod #What is loaded
cat /etc/passwd #Unexpected data?
cat /etc/shadow #Unexpected data?
find /directory -type f -mtime -1 -print #Find modified files during the last minute in the directory
```
#### Informazioni sospette

Mentre ottieni le informazioni di base dovresti controllare cose strane come:

- I **processi root** di solito girano con PID bassi, quindi se trovi un processo root con un PID alto potresti sospettare
- Controlla i **login registrati** di utenti senza una shell dentro `/etc/passwd`
- Controlla gli **hash delle password** dentro `/etc/shadow` per utenti senza una shell

### Memory Dump

Per ottenere la memoria del sistema in esecuzione, è consigliato usare [**LiME**](https://github.com/504ensicsLabs/LiME).\
Per **compilarlo**, devi usare lo **stesso kernel** che sta usando la macchina vittima.

> [!TIP]
> Ricorda che **non puoi installare LiME o qualsiasi altra cosa** nella macchina vittima perché apporterebbe diversi cambiamenti

Quindi, se hai una versione identica di Ubuntu puoi usare `apt-get install lime-forensics-dkms`\
In altri casi, devi scaricare [**LiME**](https://github.com/504ensicsLabs/LiME) da github e compilarlo con gli header corretti del kernel. Per **ottenere gli header esatti del kernel** della macchina vittima, puoi semplicemente **copiare la directory** `/lib/modules/<kernel version>` sulla tua macchina, e poi **compilare** LiME usando quelli:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME supporta 3 **formati**:

- Raw (ogni segmento concatenato insieme)
- Padded (come raw, ma con zeri nei bit di destra)
- Lime (formato consigliato con metadati)

LiME può anche essere usato per **inviare il dump via network** invece di memorizzarlo sul sistema usando qualcosa come: `path=tcp:4444`

### Disk Imaging

#### Shutting down

Prima di tutto, dovrai **spegnere il sistema**. Questo non è sempre un'opzione, perché a volte il sistema può essere un server di produzione che l'azienda non può permettersi di spegnere.\
Ci sono **2 modi** di spegnere il sistema, uno **shutdown normale** e uno **shutdown "plug the plug"**. Il primo permetterà ai **processi di terminare come al solito** e al **filesystem** di essere **sincronizzato**, ma permetterà anche al possibile **malware** di **distruggere le prove**. L'approccio "pull the plug" può comportare **una certa perdita di informazioni** (non molta informazione andrà persa, dato che abbiamo già acquisito un'immagine della memoria ) e il **malware non avrà alcuna opportunità** di fare qualcosa al riguardo. Pertanto, se **sospetti** che possa esserci un **malware**, esegui semplicemente il **comando** **`sync`** sul sistema e stacca la spina.

#### Taking an image of the disk

È importante notare che **prima di collegare il tuo computer a qualsiasi cosa relativa al caso**, devi essere sicuro che venga **montato in sola lettura** per evitare di modificare qualsiasi informazione.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Pre-analisi dell'immagine disco

Creare un'immagine disco senza ulteriori dati.
```bash
#Find out if it's a disk image using "file" command
file disk.img
disk.img: Linux rev 1.0 ext4 filesystem data, UUID=59e7a736-9c90-4fab-ae35-1d6a28e5de27 (extents) (64bit) (large files) (huge files)

#Check which type of disk image it's
img_stat -t evidence.img
raw
#You can list supported types with
img_stat -i list
Supported image format types:
raw (Single or split raw file (dd))
aff (Advanced Forensic Format)
afd (AFF Multiple File)
afm (AFF with external metadata)
afflib (All AFFLIB image formats (including beta ones))
ewf (Expert Witness Format (EnCase))

#Data of the image
fsstat -i raw -f ext4 disk.img
FILE SYSTEM INFORMATION
--------------------------------------------
File System Type: Ext4
Volume Name:
Volume ID: 162850f203fd75afab4f1e4736a7e776

Last Written at: 2020-02-06 06:22:48 (UTC)
Last Checked at: 2020-02-06 06:15:09 (UTC)

Last Mounted at: 2020-02-06 06:15:18 (UTC)
Unmounted properly
Last mounted on: /mnt/disk0

Source OS: Linux
[...]

#ls inside the image
fls -i raw -f ext4 disk.img
d/d 11: lost+found
d/d 12: Documents
d/d 8193:       folder1
d/d 8194:       folder2
V/V 65537:      $OrphanFiles

#ls inside folder
fls -i raw -f ext4 disk.img 12
r/r 16: secret.txt

#cat file inside image
icat -i raw -f ext4 disk.img 16
ThisisTheMasterSecret
```
## Cerca Malware noti

### Modified System Files

Linux offre strumenti per garantire l'integrità dei componenti di sistema, fondamentali per individuare file potenzialmente problematici.

- **Sistemi basati su RedHat**: Usa `rpm -Va` per un controllo completo.
- **Sistemi basati su Debian**: `dpkg --verify` per una verifica iniziale, seguita da `debsums | grep -v "OK$"` (dopo aver installato `debsums` con `apt-get install debsums`) per identificare eventuali problemi.

### Malware/Rootkit Detectors

Leggi la seguente pagina per imparare quali strumenti possono essere utili per trovare malware:


{{#ref}}
malware-analysis.md
{{#endref}}

## Cerca programmi installati

Per cercare in modo efficace i programmi installati sia sui sistemi Debian che RedHat, considera di sfruttare i log e i database di sistema insieme a controlli manuali nelle directory comuni.

- Per Debian, esamina _**`/var/lib/dpkg/status`**_ e _**`/var/log/dpkg.log`**_ per ottenere dettagli sulle installazioni dei pacchetti, usando `grep` per filtrare informazioni specifiche.
- Gli utenti RedHat possono interrogare il database RPM con `rpm -qa --root=/mntpath/var/lib/rpm` per elencare i pacchetti installati.

Per scoprire software installato manualmente o al di fuori di questi package manager, esplora directory come _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_, e _**`/sbin`**_. Combina gli elenchi delle directory con comandi specifici del sistema per identificare gli eseguibili non associati a package noti, migliorando la ricerca di tutti i programmi installati.
```bash
# Debian package and log details
cat /var/lib/dpkg/status | grep -E "Package:|Status:"
cat /var/log/dpkg.log | grep installed
# RedHat RPM database query
rpm -qa --root=/mntpath/var/lib/rpm
# Listing directories for manual installations
ls /usr/sbin /usr/bin /bin /sbin
# Identifying non-package executables (Debian)
find /sbin/ -exec dpkg -S {} \; | grep "no path found"
# Identifying non-package executables (RedHat)
find /sbin/ –exec rpm -qf {} \; | grep "is not"
# Find exacuable files
find / -type f -executable | grep <something>
```
## Recuperare Binary in Esecuzione Eliminati

Immagina un processo eseguito da /tmp/exec e poi eliminato. È possibile estrarlo
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## Triage della syscall trace con SQLite e FTS5

Quando un processo è ancora in esecuzione o può essere rieseguito in un lab, **`strace`** può fornire una trace comportamentale rapida senza bisogno di moduli kernel o telemetria EDR completa. Per trace di grandi dimensioni, evita di leggere direttamente il log grezzo o di incollarlo in un LLM: memorizzalo in un database **SQLite** e interroga solo il sottoinsieme minimo di cui hai bisogno.

> [!WARNING]
> Collegare `strace` cambia il timing del processo e può influire su race condition o altri bug fragili. Se possibile, preferisci riprodurre su una copia/sistema di lab.

### Capture

Per un nuovo processo:
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log <command>
```
Per un processo live:
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log -p <PID>
```
Opzioni utili:

- `-ff`: segui fork/thread e mantieni output separati per processo
- `-ttt`: timestamp in epoch per una facile correlazione della timeline
- `-yy`: risolvi i file descriptor nei path/socket di backing quando possibile
- `-s 4096`: evita che i path lunghi e gli argomenti dei buffer vengano troncati

### Normalizza

Uno schema pratico è una riga per syscall e una riga per argomento:
```sql
CREATE TABLE syscalls (
id        INTEGER PRIMARY KEY,
pid       INTEGER NOT NULL,
timestamp REAL    NOT NULL,
name      TEXT    NOT NULL,
ret_val   INTEGER,
errno     TEXT
);

CREATE TABLE syscall_args (
id         INTEGER PRIMARY KEY,
syscall_id INTEGER NOT NULL REFERENCES syscalls(id),
position   INTEGER NOT NULL,
raw        TEXT    NOT NULL,
type       INTEGER NOT NULL
);
```
Questo evita di cercare di appiattire linee di syscall eterogenee in un'unica tabella larga e mantiene i join prevedibili durante il triage.

### Indicizza gli argomenti ricchi di testo con FTS5

La ricerca ingenua dei percorsi con `LIKE "%...%"` diventa molto lenta su trace di grandi dimensioni. Crea invece un indice FTS5 per il testo degli argomenti e cerca lì:
```sql
CREATE VIRTUAL TABLE syscall_args_fts
USING fts5(raw, content='syscall_args', content_rowid='id');

INSERT INTO syscall_args_fts(rowid, raw)
SELECT id, raw FROM syscall_args;
```
Esempio: recuperare l’attività dei file sotto `/tmp` senza scansionare ogni riga:
```sql
SELECT s.timestamp, s.pid, s.name, a.position, a.raw
FROM syscall_args_fts f
JOIN syscall_args a ON a.id = f.rowid
JOIN syscalls s ON s.id = a.syscall_id
WHERE syscall_args_fts MATCH 'tmp'
AND s.name IN ('openat', 'stat', 'lstat', 'rename', 'unlink', 'execve')
ORDER BY s.timestamp;
```
### Investigazioni ad alto segnale

- **PATH hijacking / fake sudo**: cerca scritture e attività `chmod`/`rename` sotto `~/.local/bin/`, poi correla con successivi `execve` di nomi che sembrano privilegiati come `sudo`.
- **TOCTOU su file temporanei**: concentrati sullo stesso path `/tmp/...` tra `stat`, `access`, `openat`, `rename`, `unlink`, `link`, `symlink` e `execve` per identificare gap di check/use.
- **Causa radice del crash**: correla `mmap` di un file con scritture o truncation dello stesso inode/path da parte di un altro processo, poi ispeziona la sequenza di signal/exit per `SIGBUS`.
- **Recupero della destinazione di rete**: filtra `connect`, `sendto`, `sendmsg`, `recvfrom` e gli argomenti relativi ai socket per estrarre IP e porte del peer.

### LLM-assisted trace analysis

Se vuoi che un LLM assista, esponi un handle SQLite **read-only** e fornisci lo schema completo. Fallo eseguire SQL grezzo invece di racchiudere il database dietro funzioni helper strette. Di solito funziona meglio per join, correlazione temporale e ricerche FTS.

Regole pratiche:

- Mantieni il database in sola lettura, per esempio con `sqlite3 'file:trace.db?mode=ro'`.
- Fornisci al modello esempi di query valide `JOIN` e `FTS5 MATCH`.
- Non incollare nel prompt log grezzi `strace` multi-GB.
- Fai domande mirate come:
- "Elenca i file persistenti scritti da questo programma."
- "Ha creato o sostituito eseguibili in directory PATH controllate dall'utente?"
- "Spiega perché questa traccia termina in `SIGBUS`."

## Ispeziona le locazioni di Autostart

### Attività pianificate
```bash
cat /var/spool/cron/crontabs/*  \
/var/spool/cron/atjobs \
/var/spool/anacron \
/etc/cron* \
/etc/at* \
/etc/anacrontab \
/etc/incron.d/* \
/var/spool/incron/* \

#MacOS
ls -l /usr/lib/cron/tabs/ /Library/LaunchAgents/ /Library/LaunchDaemons/ ~/Library/LaunchAgents/
```
#### Hunt: Cron/Anacron abuse via 0anacron and suspicious stubs
Gli attaccanti spesso modificano lo stub 0anacron presente in ciascuna directory /etc/cron.*/ per garantire l'esecuzione periodica.
```bash
# List 0anacron files and their timestamps/sizes
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done

# Look for obvious execution of shells or downloaders embedded in cron stubs
grep -R --line-number -E 'curl|wget|/bin/sh|python|bash -c' /etc/cron.*/* 2>/dev/null
```
#### Hunt: rollback dell’hardening di SSH e shell backdoor
Le modifiche a sshd_config e alle shell degli account di sistema sono comuni nel post-exploitation per preservare l’accesso.
```bash
# Root login enablement (flag "yes" or lax values)
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config

# System accounts with interactive shells (e.g., games → /bin/sh)
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
#### Hunt: Cloud C2 markers (Dropbox/Cloudflare Tunnel)
- I beacon API di Dropbox in genere usano api.dropboxapi.com o content.dropboxapi.com su HTTPS con token Authorization: Bearer.
- Cerca in proxy/Zeek/NetFlow traffico Dropbox in uscita inatteso dai server.
- Cloudflare Tunnel (`cloudflared`) fornisce C2 di backup su outbound 443.
```bash
ps aux | grep -E '[c]loudflared|trycloudflare'
systemctl list-units | grep -i cloudflared
```
### Services

Percorsi in cui un malware potrebbe essere installato come servizio:

- **/etc/inittab**: Chiama script di inizializzazione come rc.sysinit, indirizzando poi verso ulteriori script di avvio.
- **/etc/rc.d/** e **/etc/rc.boot/**: Contengono script per l’avvio dei servizi, la seconda si trova nelle versioni più vecchie di Linux.
- **/etc/init.d/**: Usata in alcune versioni di Linux come Debian per memorizzare gli script di avvio.
- I servizi possono anche essere attivati tramite **/etc/inetd.conf** o **/etc/xinetd/**, a seconda della variante di Linux.
- **/etc/systemd/system**: Una directory per script del gestore di sistema e dei servizi.
- **/etc/systemd/system/multi-user.target.wants/**: Contiene collegamenti a servizi che dovrebbero essere avviati in un runlevel multi-user.
- **/usr/local/etc/rc.d/**: Per servizi personalizzati o di terze parti.
- **\~/.config/autostart/**: Per applicazioni di avvio automatico specifiche dell’utente, che può essere un nascondiglio per malware mirato all’utente.
- **/lib/systemd/system/**: File unit predefiniti a livello di sistema forniti dai pacchetti installati.

#### Hunt: systemd timers and transient units

La persistenza con Systemd non si limita ai file `.service`. Esamina le unità `.timer`, le unità a livello utente e le **transient units** create a runtime.
```bash
# Enumerate timers and inspect referenced services
systemctl list-timers --all
systemctl cat <name>.timer
systemctl cat <name>.service

# Search common system and user paths
find /etc/systemd/system /run/systemd/system /usr/lib/systemd/system -maxdepth 3 \( -name '*.service' -o -name '*.timer' \) -ls
find /home -path '*/.config/systemd/user/*' -type f \( -name '*.service' -o -name '*.timer' \) -ls

# Transient units created via systemd-run often land here
find /run/systemd/transient -maxdepth 2 -type f -ls 2>/dev/null

# Pull execution history for a suspicious unit
journalctl -u <name>.service
journalctl _SYSTEMD_UNIT=<name>.service
```
Le unità transient sono facili da non notare perché `/run/systemd/transient/` è **non persistente**. Se stai acquisendo un'immagine live, recuperala prima dello spegnimento.

### Kernel Modules

I moduli del kernel Linux, spesso utilizzati dal malware come componenti rootkit, vengono caricati all'avvio del sistema. Le directory e i file critici per questi moduli includono:

- **/lib/modules/$(uname -r)**: Contiene i moduli per la versione del kernel in esecuzione.
- **/etc/modprobe.d**: Contiene file di configurazione per controllare il caricamento dei moduli.
- **/etc/modprobe** e **/etc/modprobe.conf**: File per le impostazioni globali dei moduli.

### Other Autostart Locations

Linux utilizza vari file per eseguire automaticamente programmi all'accesso dell'utente, che potrebbero nascondere malware:

- **/etc/profile.d/**\*, **/etc/profile**, e **/etc/bash.bashrc**: Eseguiti per qualsiasi accesso utente.
- **\~/.bashrc**, **\~/.bash_profile**, **\~/.profile**, e **\~/.config/autostart**: File specifici dell'utente che vengono eseguiti al login.
- **/etc/rc.local**: Viene eseguito dopo l'avvio di tutti i servizi di sistema, segnando la fine della transizione verso un ambiente multiutente.

## Examine Logs

I sistemi Linux tengono traccia delle attività degli utenti e degli eventi di sistema tramite vari file di log. Questi log sono fondamentali per identificare accessi non autorizzati, infezioni malware e altri incidenti di sicurezza. I principali file di log includono:

- **/var/log/syslog** (Debian) o **/var/log/messages** (RedHat): Registrano messaggi e attività dell'intero sistema.
- **/var/log/auth.log** (Debian) o **/var/log/secure** (RedHat): Registrano i tentativi di autenticazione, i login riusciti e falliti.
- Usa `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` per filtrare gli eventi di autenticazione rilevanti.
- **/var/log/boot.log**: Contiene i messaggi di avvio del sistema.
- **/var/log/maillog** o **/var/log/mail.log**: Registrano le attività del server email, utili per tracciare i servizi correlati alla posta.
- **/var/log/kern.log**: Conserva i messaggi del kernel, inclusi errori e avvisi.
- **/var/log/dmesg**: Contiene i messaggi dei driver dei dispositivi.
- **/var/log/faillog**: Registra i tentativi di accesso falliti, aiutando nelle indagini su violazioni di sicurezza.
- **/var/log/cron**: Registra le esecuzioni dei cron job.
- **/var/log/daemon.log**: Traccia le attività dei servizi in background.
- **/var/log/btmp**: Documenta i tentativi di accesso falliti.
- **/var/log/httpd/**: Contiene i log di errore e di accesso di Apache HTTPD.
- **/var/log/mysqld.log** o **/var/log/mysql.log**: Registrano le attività del database MySQL.
- **/var/log/xferlog**: Registra i trasferimenti di file FTP.
- **/var/log/**: Controlla sempre qui la presenza di log inattesi.

> [!TIP]
> I log di sistema Linux e i sottosistemi di audit possono essere disabilitati o eliminati in caso di intrusione o incidente malware. Poiché i log sui sistemi Linux contengono generalmente alcune delle informazioni più utili sulle attività malevole, gli intrusi li eliminano regolarmente. Pertanto, quando si esaminano i file di log disponibili, è importante cercare lacune o voci fuori ordine che possano indicare eliminazione o manomissione.

### Journald triage (`journalctl`)

Sui moderni host Linux, il **systemd journal** è di solito la fonte con il maggior valore per **service execution**, **auth events**, **package operations** e i messaggi **kernel/user-space**. Durante la risposta live, cerca di preservare sia il journal **persistente** (`/var/log/journal/`) sia il journal di **runtime** (`/run/log/journal/`) perché l'attività dell'attaccante di breve durata potrebbe esistere solo nel secondo.
```bash
# List available boots and pivot around the suspicious one
journalctl --list-boots
journalctl -b -1

# Review a mounted image or copied journal directory offline
journalctl --directory /mnt/image/var/log/journal --list-boots
journalctl --directory /mnt/image/var/log/journal -b -1

# Inspect a single journal file and check integrity/corruption
journalctl --file system.journal --header
journalctl --file system.journal --verify

# High-signal filters
journalctl -u ssh.service
journalctl _SYSTEMD_UNIT=cron.service
journalctl _UID=0
journalctl _EXE=/usr/sbin/useradd
```
Campi utili del journal per il triage includono `_SYSTEMD_UNIT`, `_EXE`, `_COMM`, `_CMDLINE`, `_UID`, `_GID`, `_PID`, `_BOOT_ID`, e `MESSAGE`. Se `journald` è stato configurato senza storage persistente, aspettati solo dati recenti in `/run/log/journal/`.

### Triage del framework di audit (`auditd`)

Se `auditd` è abilitato, preferiscilo ogni volta che hai bisogno di **process attribution** per modifiche ai file, esecuzione di comandi, attività di login o installazione di pacchetti.
```bash
# Fast summaries
aureport --start today --summary -i
aureport --start today --login --failed -i
aureport --start today --executable -i

# Search raw events
ausearch --start today -m EXECVE -i
ausearch --start today -ua 1000 -m USER_CMD,EXECVE -i
ausearch --start today -m SERVICE_START,SERVICE_STOP -i

# Software installation/update events (especially useful on RHEL-like systems)
ausearch -m SOFTWARE_UPDATE -i
```
Quando le regole sono state distribuite con chiavi, fai pivot a partire da esse invece di fare grep sui log grezzi:
```bash
ausearch --start this-week -k <rule_key> --raw | aureport --file --summary -i
ausearch --start this-week -k <rule_key> --raw | aureport --user --summary -i
```
**Linux mantiene una cronologia dei comandi per ogni utente**, memorizzata in:

- \~/.bash_history
- \~/.zsh_history
- \~/.zsh_sessions/\*
- \~/.python_history
- \~/.\*\_history

Inoltre, il comando `last -Faiwx` fornisce un elenco dei login degli utenti. Controllalo per login sconosciuti o inattesi.

Controlla i file che possono concedere ulteriori privilegi:

- Rivedi `/etc/sudoers` per privilegi utente non previsti che potrebbero essere stati concessi.
- Rivedi `/etc/sudoers.d/` per privilegi utente non previsti che potrebbero essere stati concessi.
- Esamina `/etc/groups` per identificare appartenenze a gruppi o permessi insoliti.
- Esamina `/etc/passwd` per identificare appartenenze a gruppi o permessi insoliti.

Alcune app generano anche i propri log:

- **SSH**: Esamina _\~/.ssh/authorized_keys_ e _\~/.ssh/known_hosts_ per connessioni remote non autorizzate.
- **Gnome Desktop**: Controlla _\~/.recently-used.xbel_ per i file aperti di recente tramite applicazioni Gnome.
- **Firefox/Chrome**: Controlla la cronologia del browser e i download in _\~/.mozilla/firefox_ o _\~/.config/google-chrome_ per attività sospette.
- **VIM**: Rivedi _\~/.viminfo_ per i dettagli di utilizzo, come i percorsi dei file accessi e la cronologia delle ricerche.
- **Open Office**: Controlla l'accesso recente ai documenti che potrebbe indicare file compromessi.
- **FTP/SFTP**: Rivedi i log in _\~/.ftp_history_ o _\~/.sftp_history_ per trasferimenti di file che potrebbero essere non autorizzati.
- **MySQL**: Indaga _\~/.mysql_history_ per le query MySQL eseguite, che potrebbero rivelare attività database non autorizzate.
- **Less**: Analizza _\~/.lesshst_ per la cronologia di utilizzo, inclusi i file visualizzati e i comandi eseguiti.
- **Git**: Esamina _\~/.gitconfig_ e _.git/logs_ del progetto per le modifiche ai repository.

### USB Logs

[**usbrip**](https://github.com/snovvcrash/usbrip) è un piccolo software scritto in puro Python 3 che analizza i file di log Linux (`/var/log/syslog*` o `/var/log/messages*` a seconda della distro) per costruire tabelle della cronologia degli eventi USB.

È interessante **conoscere tutte le USB che sono state usate** e sarà più utile se hai un elenco autorizzato di USB per trovare "violation events" (l'uso di USB che non sono presenti in quell'elenco).

### Installation
```bash
pip3 install usbrip
usbrip ids download #Download USB ID database
```
### Esempi
```bash
usbrip events history #Get USB history of your curent linux machine
usbrip events history --pid 0002 --vid 0e0f --user kali #Search by pid OR vid OR user
#Search for vid and/or pid
usbrip ids download #Downlaod database
usbrip ids search --pid 0002 --vid 0e0f #Search for pid AND vid
```
Più esempi e informazioni dentro github: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

## Esaminare gli account utente e le attività di accesso

Esamina _**/etc/passwd**_, _**/etc/shadow**_ e i **security logs** per nomi insoliti o account creati e/o usati in stretta prossimità di noti eventi non autorizzati. Inoltre, controlla possibili attacchi brute-force su sudo.\
Inoltre, controlla file come _**/etc/sudoers**_ e _**/etc/groups**_ per privilegi inattesi concessi agli utenti.\
Infine, cerca account con **nessuna password** o password **facilmente indovinabili**.

## Esaminare il file system

### Analizzare le strutture del file system nell'investigazione di malware

Quando si investigano incidenti malware, la struttura del file system è una fonte cruciale di informazioni, rivelando sia la sequenza degli eventi sia il contenuto del malware. Tuttavia, gli autori di malware stanno sviluppando tecniche per ostacolare questa analisi, come modificare i timestamp dei file o evitare il file system per l'archiviazione dei dati.

Per contrastare questi metodi anti-forensic, è essenziale:

- **Condurre un'analisi approfondita della timeline** usando strumenti come **Autopsy** per visualizzare le timeline degli eventi o `mactime` di **Sleuth Kit** per dati di timeline dettagliati.
- **Indagare script inattesi** nel $PATH del sistema, che potrebbero includere script shell o PHP usati dagli attacker.
- **Esaminare `/dev` per file atipici**, poiché tradizionalmente contiene file speciali, ma può ospitare file correlati al malware.
- **Cercare file o directory nascosti** con nomi come ".. " (dot dot spazio) o "..^G" (dot dot control-G), che potrebbero nascondere contenuti malevoli.
- **Identificare file setuid root** usando il comando: `find / -user root -perm -04000 -print` Questo trova file con permessi elevati, che potrebbero essere abusati dagli attacker.
- **Rivedere i timestamp di cancellazione** nelle tabelle inode per individuare cancellazioni massive di file, indicando possibilmente la presenza di rootkits o trojan.
- **Ispezionare inode consecutivi** per file malevoli vicini dopo averne identificato uno, poiché potrebbero essere stati collocati insieme.
- **Controllare le directory binarie comuni** (_/bin_, _/sbin_) per file modificati di recente, poiché potrebbero essere alterati dal malware.
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
> [!TIP]
> Nota che un **attacker** può **modificare** il **tempo** per far **apparire i file** **legittimi**, ma non può **modificare** l’**inode**. Se scopri che un **file** indica che è stato creato e modificato allo **stesso momento** del resto dei file nella stessa cartella, ma l’**inode** è **inaspettatamente più grande**, allora i **timestamp di quel file sono stati modificati**.

### Inode-focused quick triage

If you suspect anti-forensics, run these inode-focused checks early:
```bash
# Filesystem inode pressure (possible inode exhaustion DoS)
df -i

# Identify all names that point to one inode
find / -xdev -inum <inode_number> 2>/dev/null

# Find deleted files still open by running processes
lsof +L1
lsof | grep '(deleted)'
```
Quando un inode sospetto si trova su un'immagine/dispositivo del filesystem EXT, ispeziona direttamente i metadati dell'inode:
```bash
sudo debugfs -R "stat <inode_number>" /dev/sdX
```
Campi utili:
- **Links**: se `0`, nessuna voce di directory fa attualmente riferimento all'inode.
- **dtime**: timestamp di eliminazione impostato quando l'inode è stato scollegato.
- **ctime/mtime**: aiuta a correlare i cambiamenti di metadati/contenuto con la timeline dell'incidente.

### Capacità, xattrs e rootkit userland basati su preload

La persistenza moderna su Linux spesso evita i binari **setuid** evidenti e invece abusa di **file capabilities**, **extended attributes** e del dynamic loader.
```bash
# Enumerate file capabilities (think cap_setuid, cap_sys_admin, cap_dac_override)
getcap -r / 2>/dev/null

# Inspect extended attributes on suspicious binaries and libraries
getfattr -d -m - /path/to/suspicious/file 2>/dev/null

# Global preload hook affecting every dynamically linked binary
cat /etc/ld.so.preload 2>/dev/null
stat /etc/ld.so.preload 2>/dev/null

# If a suspicious library is referenced, inspect its metadata and links
ls -lah /lib /lib64 /usr/lib /usr/lib64 /usr/local/lib 2>/dev/null | grep -E '\\.so(\\.|$)'
ldd /bin/ls
```
Prestare particolare attenzione alle librerie referenziate da percorsi **writable** come `/tmp`, `/dev/shm`, `/var/tmp` o posizioni insolite sotto `/usr/local/lib`. Controlla anche binari con capability fuori dalla normale ownership del package e correlali con i risultati di verifica dei package (`rpm -Va`, `dpkg --verify`, `debsums`).

## Confronta file di diverse versioni del filesystem

### Riepilogo del confronto tra versioni del filesystem

Per confrontare le versioni del filesystem e individuare le modifiche, usiamo comandi `git diff` semplificati:

- **Per trovare nuovi file**, confronta due directory:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
- **Per i contenuti modificati**, elenca le modifiche ignorando righe specifiche:
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
- **Per rilevare file eliminati**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
- **Filter options** (`--diff-filter`) aiutano a restringere a modifiche specifiche come file aggiunti (`A`), eliminati (`D`) o modificati (`M`).
- `A`: File aggiunti
- `C`: File copiati
- `D`: File eliminati
- `M`: File modificati
- `R`: File rinominati
- `T`: Cambiamenti di tipo (ad es., file a symlink)
- `U`: File non uniti
- `X`: File sconosciuti
- `B`: File rotti

## References

- [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf)
- [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)
- [https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
- **Book: Malware Forensics Field Guide for Linux Systems: Digital Forensics Field Guides**

- [Red Canary – Patching for persistence: How DripDropper Linux malware moves through the cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [Forensic Analysis of Linux Journals](https://stuxnet999.github.io/dfir/linux-journal-forensics/)
- [Red Hat Enterprise Linux 9 - Auditing the system](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening)
- [Say hi to Pike!](https://www.synacktiv.com/en/publications/say-hi-to-pike.html)
- [strace](https://strace.io/)
- [SQLite FTS5 Extension](https://www.sqlite.org/fts5.html)

{{#include ../../banners/hacktricks-training.md}}
