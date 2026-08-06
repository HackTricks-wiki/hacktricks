# Analisi forense di Linux

{{#include ../../banners/hacktricks-training.md}}

## Raccolta iniziale delle informazioni

### Informazioni di base

Innanzitutto, è consigliabile avere una **USB** con **binari e librerie affidabili e conosciuti** (è sufficiente procurarsi Ubuntu e copiare le cartelle _/bin_, _/sbin_, _/lib,_ e _/lib64_), quindi montare la USB e modificare le variabili d'ambiente per utilizzare tali binari:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
Una volta configurato il sistema affinché utilizzi binari affidabili e conosciuti, puoi iniziare a **estrarre alcune informazioni di base**:
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

Durante l'acquisizione delle informazioni di base dovresti verificare la presenza di elementi anomali come:

- I processi **root** di solito vengono eseguiti con PIDs bassi, quindi se trovi un processo root con un PID elevato potresti insospettirti
- Controlla i **login registrati** di utenti senza una shell all'interno di `/etc/passwd`
- Controlla la presenza di **hash delle password** all'interno di `/etc/shadow` per utenti senza una shell

### Dump della memoria

Per ottenere la memoria del sistema in esecuzione, è consigliato usare [**LiME**](https://github.com/504ensicsLabs/LiME).\
Per **compilarlo**, devi usare lo **stesso kernel** utilizzato dalla macchina vittima.

> [!TIP]
> Ricorda che **non puoi installare LiME o qualsiasi altra cosa** sulla macchina vittima, poiché questo apporterà diverse modifiche

Quindi, se disponi di una versione identica di Ubuntu, puoi usare `apt-get install lime-forensics-dkms`\
Negli altri casi, devi scaricare [**LiME**](https://github.com/504ensicsLabs/LiME) da github e compilarlo con gli header corretti del kernel. Per **ottenere gli header esatti del kernel** della macchina vittima, puoi semplicemente **copiare la directory** `/lib/modules/<kernel version>` sulla tua macchina e quindi **compilare** LiME utilizzandoli:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME supporta 3 **formats**:

- Raw (ogni segmento concatenato insieme)
- Padded (come raw, ma con zeri nei bit destri)
- Lime (formato consigliato con metadati

LiME può anche essere utilizzato per **inviare il dump tramite la rete** invece di archiviarlo sul sistema usando qualcosa come: `path=tcp:4444`

### Disk Imaging

#### Shutting down

Prima di tutto, sarà necessario **spegnere il sistema**. Questo non è sempre possibile, poiché a volte il sistema sarà un server di produzione che l'azienda non può permettersi di spegnere.\
Esistono **2 modi** per spegnere il sistema: uno **spegnimento normale** e uno spegnimento **"staccando la spina"**. Il primo consentirà ai **processi di terminare normalmente** e al **filesystem** di essere **sincronizzato**, ma permetterà anche al possibile **malware** di **distruggere le prove**. L'approccio **"staccare la spina"** può comportare una **perdita di alcune informazioni** (non andrà persa una quantità significativa di informazioni, poiché abbiamo già acquisito un'immagine della memoria), e il **malware non avrà alcuna possibilità** di intervenire. Pertanto, se **sospetti** che possa esserci un **malware**, esegui semplicemente il **comando** **`sync`** sul sistema e stacca la spina.

#### Taking an image of the disk

È importante notare che **prima di collegare il computer a qualsiasi elemento relativo al caso**, devi assicurarti che venga **montato in sola lettura** per evitare di modificare qualsiasi informazione.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Pre-analisi dell'immagine disco

Creazione di un'immagine disco senza ulteriori dati.
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
## Ricerca di Malware conosciuti

### File di sistema modificati

Linux offre strumenti per verificare l'integrità dei componenti di sistema, fondamentali per individuare file potenzialmente problematici.<sup>[[1]](#references)</sup>

- **Sistemi basati su RedHat**: usa `rpm -Va` per un controllo completo.
- **Sistemi basati su Debian**: usa `dpkg --verify` per una verifica iniziale, seguito da `debsums | grep -v "OK$"` (dopo aver installato `debsums` con `apt-get install debsums`) per identificare eventuali problemi.

### Rilevatori di Malware/Rootkit

Leggi la pagina seguente per conoscere gli strumenti che possono essere utili per trovare malware:


{{#ref}}
malware-analysis.md
{{#endref}}

## Ricerca dei programmi installati

Per cercare efficacemente i programmi installati sia sui sistemi Debian che RedHat, valuta l'utilizzo dei log e dei database di sistema insieme ai controlli manuali nelle directory comuni.<sup>[[1]](#references)</sup>

- Per Debian, esamina _**`/var/lib/dpkg/status`**_ e _**`/var/log/dpkg.log`**_ per recuperare i dettagli sulle installazioni dei pacchetti, usando `grep` per filtrare informazioni specifiche.
- Gli utenti RedHat possono interrogare il database RPM con `rpm -qa --root=/mntpath/var/lib/rpm` per elencare i pacchetti installati.

Per individuare software installato manualmente o al di fuori di questi package manager, esplora directory come _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_ e _**`/sbin`**_. Combina gli elenchi delle directory con comandi specifici del sistema per identificare gli eseguibili non associati a pacchetti noti, migliorando la ricerca di tutti i programmi installati.
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
## Recuperare i binari in esecuzione eliminati

Immagina un processo eseguito da /tmp/exec e poi eliminato. È possibile estrarlo.
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## Triage delle tracce delle syscall con SQLite e FTS5

Quando un processo è ancora in esecuzione o può essere rieseguito in un lab, **`strace`** può fornire rapidamente una traccia comportamentale senza dover ricorrere a kernel modules o alla telemetria completa di EDR. Per le tracce di grandi dimensioni, evita di leggere direttamente il log grezzo o di incollarlo in un **LLM**: salvalo in un database **SQLite** ed esegui query solo sul sottoinsieme minimo necessario.<sup>[[7]](#references)[[8]](#references)[[9]](#references)</sup>

> [!WARNING]
> Collegare `strace` modifica la temporizzazione del processo e può influire su race conditions o altri bug fragili. Quando possibile, preferisci riprodurre il problema su una copia o su un sistema lab.

### Cattura

Per un nuovo processo:
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log <command>
```
Per un processo in esecuzione:
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log -p <PID>
```
Opzioni utili:

- `-ff`: segue fork/thread e mantiene gli output per processo
- `-ttt`: timestamp epoch per facilitare la correlazione della timeline
- `-yy`: risolve i file descriptor nei relativi percorsi/socket quando possibile
- `-s 4096`: evita che gli argomenti contenenti percorsi lunghi e buffer vengano troncati

### Normalizzazione

Uno schema pratico prevede una riga per syscall e una riga per argomento:
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
Questo evita di tentare di appiattire righe eterogenee di syscall in un'unica tabella ampia e mantiene i join prevedibili durante il triage.

### Indicizza gli argomenti con molto testo con FTS5

La ricerca ingenua dei percorsi con `LIKE "%...%"` diventa molto lenta sulle tracce di grandi dimensioni. Crea un indice FTS5 per il testo degli argomenti ed esegui invece la ricerca su quello:
```sql
CREATE VIRTUAL TABLE syscall_args_fts
USING fts5(raw, content='syscall_args', content_rowid='id');

INSERT INTO syscall_args_fts(rowid, raw)
SELECT id, raw FROM syscall_args;
```
Esempio: recuperare l'attività dei file in `/tmp` senza esaminare ogni riga:
```sql
SELECT s.timestamp, s.pid, s.name, a.position, a.raw
FROM syscall_args_fts f
JOIN syscall_args a ON a.id = f.rowid
JOIN syscalls s ON s.id = a.syscall_id
WHERE syscall_args_fts MATCH 'tmp'
AND s.name IN ('openat', 'stat', 'lstat', 'rename', 'unlink', 'execve')
ORDER BY s.timestamp;
```
### Indagini ad alto segnale

- **PATH hijacking / fake sudo**: cerca scritture e attività `chmod`/`rename` in `~/.local/bin/`, quindi correla con successive chiamate `execve` di nomi che sembrano privilegiati, come `sudo`.
- **TOCTOU su file temporanei**: segui lo stesso percorso `/tmp/...` attraverso `stat`, `access`, `openat`, `rename`, `unlink`, `link`, `symlink` ed `execve` per identificare intervalli tra controllo e utilizzo.
- **Causa principale del crash**: correla una `mmap` di un file con scritture o troncamenti dello stesso inode/percorso da parte di un altro processo, quindi analizza la sequenza di segnali/uscite per individuare `SIGBUS`.
- **Recupero delle destinazioni di rete**: filtra `connect`, `sendto`, `sendmsg`, `recvfrom` e gli argomenti relativi ai socket per estrarre gli IP peer e le porte.

### Analisi delle tracce assistita da LLM

Se vuoi che un LLM collabori, esponi un handle SQLite **read-only** e forniscigli lo schema completo. Lascia che esegua SQL grezzo invece di avvolgere il database tramite funzioni helper limitate. Questo generalmente funziona meglio per i join, la correlazione temporale e le ricerche FTS.

Regole pratiche:

- Mantieni il database in modalità read-only, ad esempio con `sqlite3 'file:trace.db?mode=ro'`.
- Fornisci al modello esempi di query valide con `JOIN` e `FTS5 MATCH`.
- **Non** incollare nel prompt log `strace` grezzi di svariati GB.
- Poni domande mirate come:
- "Elenca i file persistenti scritti da questo programma."
- "Ha creato o sostituito eseguibili nelle directory del PATH controllate dall'utente?"
- "Spiega perché questa traccia termina con SIGBUS."

## Ispeziona le posizioni di avvio automatico

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
#### Hunt: abuso di Cron/Anacron tramite 0anacron e stub sospetti
Gli attaccanti spesso modificano lo stub 0anacron presente in ogni directory /etc/cron.*/ per garantire l'esecuzione periodica.<sup>[[4]](#references)</sup>
```bash
# List 0anacron files and their timestamps/sizes
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done

# Look for obvious execution of shells or downloaders embedded in cron stubs
grep -R --line-number -E 'curl|wget|/bin/sh|python|bash -c' /etc/cron.*/* 2>/dev/null
```
#### Hunt: rollback dell'hardening SSH e backdoor shell
Le modifiche a sshd_config e alle shell degli account di sistema sono comuni nel post-exploitation per mantenere l'accesso.<sup>[[4]](#references)</sup>
```bash
# Root login enablement (flag "yes" or lax values)
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config

# System accounts with interactive shells (e.g., games → /bin/sh)
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
#### Hunt: indicatori di Cloud C2 (Dropbox/Cloudflare Tunnel)
- I beacon dell'API di Dropbox usano tipicamente api.dropboxapi.com o content.dropboxapi.com tramite HTTPS con token Authorization: Bearer.
- Cerca nel proxy/Zeek/NetFlow traffico Dropbox in uscita imprevisto dai server.
- Cloudflare Tunnel (`cloudflared`) fornisce un C2 di backup tramite 443 in uscita.<sup>[[4]](#references)</sup>
```bash
ps aux | grep -E '[c]loudflared|trycloudflare'
systemctl list-units | grep -i cloudflared
```
### Servizi

Percorsi in cui un malware potrebbe essere installato come servizio:

- **/etc/inittab**: richiama script di inizializzazione come rc.sysinit, che a loro volta indirizzano agli script di avvio.
- **/etc/rc.d/** e **/etc/rc.boot/**: contengono script per l'avvio dei servizi; questi ultimi si trovano nelle versioni più vecchie di Linux.
- **/etc/init.d/**: utilizzata in alcune versioni di Linux, come Debian, per memorizzare gli script di avvio.
- I servizi possono anche essere attivati tramite **/etc/inetd.conf** o **/etc/xinetd/**, a seconda della variante di Linux.
- **/etc/systemd/system**: directory per gli script del gestore del sistema e dei servizi.
- **/etc/systemd/system/multi-user.target.wants/**: contiene link ai servizi che devono essere avviati in un runlevel multiutente.
- **/usr/local/etc/rc.d/**: per servizi personalizzati o di terze parti.
- **\~/.config/autostart/**: per le applicazioni ad avvio automatico specifiche dell'utente; può essere un nascondiglio per malware mirati agli utenti.
- **/lib/systemd/system/**: file di unità predefiniti a livello di sistema forniti dai pacchetti installati.

#### Ricerca: timer systemd e unità transitorie

La persistenza di systemd non è limitata ai file `.service`. Analizza le unità `.timer`, le unità a livello utente e le **unità transitorie** create durante l'esecuzione.
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
Le unità transient sono facili da non individuare perché `/run/systemd/transient/` è **non persistente**. Se stai raccogliendo un'immagine live, acquisiscila prima dello shutdown.

### Kernel Modules

I moduli del kernel Linux, spesso utilizzati dal malware come componenti rootkit, vengono caricati all'avvio del sistema. Le directory e i file critici per questi moduli includono:

- **/lib/modules/$(uname -r)**: Contiene i moduli per la versione del kernel in esecuzione.
- **/etc/modprobe.d**: Contiene i file di configurazione per controllare il caricamento dei moduli.
- **/etc/modprobe** e **/etc/modprobe.conf**: File per le impostazioni globali dei moduli.

### Other Autostart Locations

Linux utilizza vari file per eseguire automaticamente i programmi al login dell'utente, che potrebbero contenere malware:

- **/etc/profile.d/**\*, **/etc/profile** e **/etc/bash.bashrc**: Vengono eseguiti al login di qualsiasi utente.
- **\~/.bashrc**, **\~/.bash_profile**, **\~/.profile** e **\~/.config/autostart**: File specifici dell'utente che vengono eseguiti al suo login.
- **/etc/rc.local**: Viene eseguito dopo l'avvio di tutti i servizi di sistema, segnando la fine della transizione a un ambiente multiutente.

## Examine Logs

I sistemi Linux registrano le attività degli utenti e gli eventi di sistema attraverso vari file di log. Questi log sono fondamentali per identificare accessi non autorizzati, infezioni da malware e altri incidenti di sicurezza.<sup>[[2]](#references)</sup> I principali file di log includono:

- **/var/log/syslog** (Debian) o **/var/log/messages** (RedHat): Acquisiscono i messaggi e le attività dell'intero sistema.
- **/var/log/auth.log** (Debian) o **/var/log/secure** (RedHat): Registrano i tentativi di autenticazione e i login riusciti e falliti.
- Usa `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` per filtrare gli eventi di autenticazione rilevanti.
- **/var/log/boot.log**: Contiene i messaggi di avvio del sistema.
- **/var/log/maillog** o **/var/log/mail.log**: Registrano le attività del server email, utili per monitorare i servizi correlati alla posta elettronica.
- **/var/log/kern.log**: Memorizza i messaggi del kernel, inclusi errori e avvisi.
- **/var/log/dmesg**: Contiene i messaggi dei driver dei dispositivi.
- **/var/log/faillog**: Registra i tentativi di login falliti, agevolando le indagini sulle violazioni della sicurezza.
- **/var/log/cron**: Registra le esecuzioni dei cron job.
- **/var/log/daemon.log**: Tiene traccia delle attività dei servizi in background.
- **/var/log/btmp**: Documenta i tentativi di login falliti.
- **/var/log/httpd/**: Contiene i log degli errori e degli accessi di Apache HTTPD.
- **/var/log/mysqld.log** o **/var/log/mysql.log**: Registrano le attività del database MySQL.
- **/var/log/xferlog**: Registra i trasferimenti di file FTP.
- **/var/log/**: Controlla sempre la presenza di log imprevisti in questa directory.

> [!TIP]
> I log di sistema Linux e i sottosistemi di audit possono essere disabilitati o eliminati durante un'intrusione o un incidente causato da malware. Poiché i log sui sistemi Linux contengono generalmente alcune delle informazioni più utili sulle attività malevole, gli intrusi li eliminano regolarmente. Pertanto, quando esamini i file di log disponibili, è importante cercare lacune o voci fuori ordine che potrebbero indicare un'eliminazione o una manomissione.

### Journald triage (`journalctl`)

Sugli host Linux moderni, il **journal di systemd** è generalmente la fonte di maggior valore per l'**esecuzione dei servizi**, gli **eventi di autenticazione**, le **operazioni sui pacchetti** e i **messaggi del kernel e dello spazio utente**. Durante la risposta live, cerca di preservare sia il journal **persistente** (`/var/log/journal/`) sia il journal **runtime** (`/run/log/journal/`), perché l'attività di un attaccante di breve durata potrebbe esistere solo in quest'ultimo.<sup>[[5]](#references)</sup>
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
Campi utili del journal per il triage includono `_SYSTEMD_UNIT`, `_EXE`, `_COMM`, `_CMDLINE`, `_UID`, `_GID`, `_PID`, `_BOOT_ID` e `MESSAGE`. Se journald è stato configurato senza archiviazione persistente, aspettati di trovare solo dati recenti in `/run/log/journal/`.

### Triage del framework di auditing (`auditd`)

Se `auditd` è abilitato, preferiscilo ogni volta che ti serve l'**attribuzione del processo** per modifiche ai file, esecuzione di comandi, attività di login o installazione di pacchetti.<sup>[[6]](#references)</sup>
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
Quando le regole sono state distribuite con chiavi, esegui il pivot a partire da esse invece di cercare nei log grezzi con grep:
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

Inoltre, il comando `last -Faiwx` fornisce un elenco degli accessi degli utenti. Controllalo per individuare accessi sconosciuti o imprevisti.

Controlla i file che possono concedere privilegi aggiuntivi:

- Esamina `/etc/sudoers` per individuare privilegi utente imprevisti che potrebbero essere stati concessi.
- Esamina `/etc/sudoers.d/` per individuare privilegi utente imprevisti che potrebbero essere stati concessi.
- Esamina `/etc/groups` per identificare appartenenze a gruppi o permessi insoliti.
- Esamina `/etc/passwd` per identificare appartenenze a gruppi o permessi insoliti.

Alcune app generano anche i propri log:

- **SSH**: esamina _\~/.ssh/authorized_keys_ e _\~/.ssh/known_hosts_ per individuare connessioni remote non autorizzate.
- **Gnome Desktop**: controlla _\~/.recently-used.xbel_ per individuare i file a cui si è avuto recentemente accesso tramite le applicazioni Gnome.
- **Firefox/Chrome**: controlla la cronologia e i download del browser in _\~/.mozilla/firefox_ o _\~/.config/google-chrome_ per individuare attività sospette.
- **VIM**: esamina _\~/.viminfo_ per informazioni sull'utilizzo, come i percorsi dei file consultati e la cronologia delle ricerche.
- **Open Office**: controlla gli accessi recenti ai documenti, che potrebbero indicare file compromessi.
- **FTP/SFTP**: esamina i log in _\~/.ftp_history_ o _\~/.sftp_history_ per individuare trasferimenti di file potenzialmente non autorizzati.
- **MySQL**: analizza _\~/.mysql_history_ per individuare le query MySQL eseguite, che potrebbero rivelare attività non autorizzate sul database.
- **Less**: analizza _\~/.lesshst_ per la cronologia dell'utilizzo, inclusi i file visualizzati e i comandi eseguiti.
- **Git**: esamina _\~/.gitconfig_ e _.git/logs_ del progetto per individuare modifiche ai repository.

### Log USB

[**usbrip**](https://github.com/snovvcrash/usbrip) è un piccolo software scritto interamente in Python 3 che analizza i file di log Linux (`/var/log/syslog*` o `/var/log/messages*`, a seconda della distro) per creare tabelle della cronologia degli eventi USB.

È interessante **conoscere tutte le USB che sono state utilizzate** e sarà ancora più utile disporre di un elenco autorizzato di USB per individuare gli "eventi di violazione" (l'utilizzo di USB che non fanno parte di quell'elenco).

### Installazione
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
Ulteriori esempi e informazioni sono disponibili nel github: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

## Esaminare gli Account Utente e le Attività di Logon

Esaminare _**/etc/passwd**_, _**/etc/shadow**_ e i **security logs** alla ricerca di nomi o account insoliti creati e/o utilizzati in prossimità di eventi non autorizzati noti. Inoltre, verificare la presenza di possibili attacchi di tipo sudo brute-force.\
Inoltre, controllare file come _**/etc/sudoers**_ e _**/etc/groups**_ per individuare privilegi imprevisti assegnati agli utenti.\
Infine, cercare account con **nessuna password** o con password **facilmente indovinabili**.<sup>[[1]](#references)</sup>

## Esaminare il File System

### Analizzare le Strutture del File System nelle Indagini sul Malware

Durante l'analisi di incidenti legati a malware, la struttura del file system è una fonte cruciale di informazioni, poiché rivela sia la sequenza degli eventi sia il contenuto del malware. Tuttavia, gli autori di malware stanno sviluppando tecniche per ostacolare questa analisi, come la modifica dei timestamp dei file o l'evitare il file system per l'archiviazione dei dati.<sup>[[1]](#references)</sup>

Per contrastare questi metodi anti-forensics, è essenziale:

- **Condurre un'analisi approfondita della timeline** utilizzando strumenti come **Autopsy** per visualizzare le timeline degli eventi o `mactime` di **Sleuth Kit** per ottenere dati dettagliati sulla timeline.
- **Analizzare gli script imprevisti** presenti nel $PATH del sistema, che potrebbero includere script shell o PHP utilizzati dagli attaccanti.
- **Esaminare `/dev` alla ricerca di file atipici**, poiché normalmente contiene file speciali, ma potrebbe ospitare file correlati al malware.
- **Cercare file o directory nascosti** con nomi come ".. " (punto punto spazio) o "..^G" (punto punto control-G), che potrebbero nascondere contenuti malevoli.
- **Individuare i file setuid root** utilizzando il comando: `find / -user root -perm -04000 -print` Questo comando individua i file con permessi elevati, che potrebbero essere sfruttati dagli attaccanti.
- **Esaminare i timestamp delle eliminazioni** nelle tabelle inode per individuare eliminazioni massive di file, che potrebbero indicare la presenza di rootkit o trojan.
- **Ispezionare gli inode consecutivi** alla ricerca di file malevoli nelle vicinanze dopo averne identificato uno, poiché potrebbero essere stati collocati insieme.
- **Controllare le directory comuni dei binary** (_/bin_, _/sbin_) alla ricerca di file modificati di recente, poiché potrebbero essere stati alterati dal malware.
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
> [!TIP]
> Nota che un **attaccante** può **modificare** l'**orario** per far **apparire i file** **legittimi**, ma non può modificare l'**inode**. Se rilevi che un **file** indica di essere stato creato e modificato nello **stesso momento** degli altri file nella stessa cartella, ma l'**inode** è **inaspettatamente più grande**, allora i **timestamp di quel file sono stati modificati**.

### Quick triage incentrato sugli inode

Se sospetti l'anti-forensics, esegui queste verifiche incentrate sugli inode nelle prime fasi:
```bash
# Filesystem inode pressure (possible inode exhaustion DoS)
df -i

# Identify all names that point to one inode
find / -xdev -inum <inode_number> 2>/dev/null

# Find deleted files still open by running processes
lsof +L1
lsof | grep '(deleted)'
```
Quando un inode sospetto si trova su un'immagine/dispositivo di un filesystem EXT, esamina direttamente i metadati dell'inode:
```bash
sudo debugfs -R "stat <inode_number>" /dev/sdX
```
Campi utili:
- **Links**: se `0`, nessuna directory fa attualmente riferimento all'inode.
- **dtime**: timestamp di eliminazione impostato quando l'inode è stato scollegato.
- **ctime/mtime**: aiutano a correlare le modifiche ai metadati/contenuti con la timeline dell'incidente.

### Capabilities, xattrs e userland rootkit basati sul preload

La persistenza moderna su Linux spesso evita i binari `setuid` evidenti e sfrutta invece le **file capabilities**, gli **extended attributes** e il dynamic loader.
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
Presta particolare attenzione alle librerie referenziate da percorsi **scrivibili** come `/tmp`, `/dev/shm`, `/var/tmp` o posizioni insolite sotto `/usr/local/lib`. Controlla inoltre la presenza di binari dotati di capabilities al di fuori della normale gestione dei pacchetti e correla i risultati con quelli della verifica dei pacchetti (`rpm -Va`, `dpkg --verify`, `debsums`).

## Confrontare file di versioni diverse del filesystem

### Riepilogo del confronto tra versioni del filesystem

Per confrontare le versioni del filesystem e individuare le modifiche, utilizziamo comandi `git diff` semplificati:<sup>[[3]](#references)</sup>

- **Per trovare i nuovi file**, confronta due directory:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
- **Per il contenuto modificato, elenca le modifiche ignorando righe specifiche:**
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
- **Per rilevare i file eliminati**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
- **Opzioni di filtro** (`--diff-filter`) aiutano a restringere la ricerca a modifiche specifiche, come file aggiunti (`A`), eliminati (`D`) o modificati (`M`).
- `A`: File aggiunti
- `C`: File copiati
- `D`: File eliminati
- `M`: File modificati
- `R`: File rinominati
- `T`: Modifiche del tipo (ad esempio, da file a symlink)
- `U`: File non uniti
- `X`: File sconosciuti
- `B`: File danneggiati

## Riferimenti

- [1] [Guida sul campo alla Malware Forensics per Linux Systems: Digital Forensics Field Guides – Capitolo 3](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf)
- [2] [Spiegazione dei Linux Logs](https://www.plesk.com/blog/featured/linux-logs-explained/)
- [3] [Documentazione di git diff – opzione --diff-filter](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
- [4] [Red Canary – Patching for persistence: come il malware Linux DripDropper si sposta nel cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [5] [Analisi forense dei Linux Journals](https://stuxnet999.github.io/dfir/linux-journal-forensics/)
- [6] [Red Hat Enterprise Linux 9 - Auditing the system](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening)
- [7] [Say hi to Pike!](https://www.synacktiv.com/en/publications/say-hi-to-pike.html)
- [8] [strace](https://strace.io/)
- [9] [SQLite FTS5 Extension](https://www.sqlite.org/fts5.html)

{{#include ../../banners/hacktricks-training.md}}
