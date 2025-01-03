# Linux Forensics

{{#include ../../banners/hacktricks-training.md}}

## Raccolta Iniziale di Informazioni

### Informazioni di Base

Prima di tutto, è consigliato avere una **USB** con **binaries e librerie ben noti** (puoi semplicemente prendere ubuntu e copiare le cartelle _/bin_, _/sbin_, _/lib,_ e _/lib64_), poi monta la USB e modifica le variabili di ambiente per utilizzare quei binaries:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
Una volta configurato il sistema per utilizzare binari buoni e conosciuti, puoi iniziare a **estrarre alcune informazioni di base**:
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

Durante l'ottenimento delle informazioni di base, dovresti controllare cose strane come:

- **I processi root** di solito vengono eseguiti con PIDS bassi, quindi se trovi un processo root con un PID elevato potresti sospettare
- Controlla i **login registrati** degli utenti senza una shell all'interno di `/etc/passwd`
- Controlla gli **hash delle password** all'interno di `/etc/shadow` per gli utenti senza una shell

### Dump della memoria

Per ottenere la memoria del sistema in esecuzione, è consigliato utilizzare [**LiME**](https://github.com/504ensicsLabs/LiME).\
Per **compilarlo**, devi utilizzare lo **stesso kernel** che la macchina vittima sta utilizzando.

> [!NOTE]
> Ricorda che **non puoi installare LiME o qualsiasi altra cosa** nella macchina vittima poiché apporterà diverse modifiche ad essa

Quindi, se hai una versione identica di Ubuntu puoi usare `apt-get install lime-forensics-dkms`\
In altri casi, devi scaricare [**LiME**](https://github.com/504ensicsLabs/LiME) da github e compilarlo con le intestazioni del kernel corrette. Per **ottenere le intestazioni esatte del kernel** della macchina vittima, puoi semplicemente **copiare la directory** `/lib/modules/<kernel version>` sulla tua macchina, e poi **compilare** LiME utilizzando quelle:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME supporta 3 **formati**:

- Raw (ogni segmento concatenato insieme)
- Padded (stesso del raw, ma con zeri nei bit a destra)
- Lime (formato raccomandato con metadati)

LiME può anche essere utilizzato per **inviare il dump tramite rete** invece di memorizzarlo sul sistema utilizzando qualcosa come: `path=tcp:4444`

### Imaging del disco

#### Spegnimento

Prima di tutto, è necessario **spegnere il sistema**. Questo non è sempre un'opzione poiché a volte il sistema sarà un server di produzione che l'azienda non può permettersi di spegnere.\
Ci sono **2 modi** per spegnere il sistema, un **spegnimento normale** e uno **spegnimento "stacca la spina"**. Il primo permetterà ai **processi di terminare come al solito** e al **filesystem** di essere **synchronizzato**, ma permetterà anche al possibile **malware** di **distruggere le prove**. L'approccio "stacca la spina" può comportare **alcuna perdita di informazioni** (non molte informazioni andranno perse poiché abbiamo già preso un'immagine della memoria) e il **malware non avrà alcuna opportunità** di fare qualcosa al riguardo. Pertanto, se **sospetti** che ci possa essere un **malware**, esegui semplicemente il **comando** **`sync`** sul sistema e stacca la spina.

#### Prendere un'immagine del disco

È importante notare che **prima di collegare il computer a qualsiasi cosa relativa al caso**, è necessario essere certi che verrà **montato come sola lettura** per evitare di modificare qualsiasi informazione.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Pre-analisi dell'immagine del disco

Immaginare un'immagine del disco senza ulteriori dati.
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
## Cerca Malware conosciuto

### File di sistema modificati

Linux offre strumenti per garantire l'integrità dei componenti di sistema, fondamentale per individuare file potenzialmente problematici.

- **Sistemi basati su RedHat**: Usa `rpm -Va` per un controllo completo.
- **Sistemi basati su Debian**: `dpkg --verify` per una verifica iniziale, seguito da `debsums | grep -v "OK$"` (dopo aver installato `debsums` con `apt-get install debsums`) per identificare eventuali problemi.

### Rilevatori di Malware/Rootkit

Leggi la pagina seguente per conoscere gli strumenti che possono essere utili per trovare malware:

{{#ref}}
malware-analysis.md
{{#endref}}

## Cerca programmi installati

Per cercare efficacemente programmi installati su sistemi Debian e RedHat, considera di sfruttare i log di sistema e i database insieme a controlli manuali in directory comuni.

- Per Debian, ispeziona _**`/var/lib/dpkg/status`**_ e _**`/var/log/dpkg.log`**_ per ottenere dettagli sulle installazioni dei pacchetti, utilizzando `grep` per filtrare informazioni specifiche.
- Gli utenti di RedHat possono interrogare il database RPM con `rpm -qa --root=/mntpath/var/lib/rpm` per elencare i pacchetti installati.

Per scoprire software installato manualmente o al di fuori di questi gestori di pacchetti, esplora directory come _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_ e _**`/sbin`**_. Combina le liste delle directory con comandi specifici del sistema per identificare eseguibili non associati a pacchetti noti, migliorando la tua ricerca per tutti i programmi installati.
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
## Recuperare Binaries Eseguiti Cancellati

Immagina un processo che è stato eseguito da /tmp/exec e poi cancellato. È possibile estrarlo.
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
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
### Servizi

Percorsi in cui un malware potrebbe essere installato come servizio:

- **/etc/inittab**: Chiama script di inizializzazione come rc.sysinit, indirizzando ulteriormente agli script di avvio.
- **/etc/rc.d/** e **/etc/rc.boot/**: Contengono script per l'avvio dei servizi, il secondo si trova nelle versioni Linux più vecchie.
- **/etc/init.d/**: Utilizzato in alcune versioni di Linux come Debian per memorizzare script di avvio.
- I servizi possono anche essere attivati tramite **/etc/inetd.conf** o **/etc/xinetd/**, a seconda della variante di Linux.
- **/etc/systemd/system**: Una directory per gli script del gestore di sistema e servizi.
- **/etc/systemd/system/multi-user.target.wants/**: Contiene collegamenti ai servizi che dovrebbero essere avviati in un livello di esecuzione multi-utente.
- **/usr/local/etc/rc.d/**: Per servizi personalizzati o di terze parti.
- **\~/.config/autostart/**: Per applicazioni di avvio automatico specifiche per l'utente, che possono essere un nascondiglio per malware mirati all'utente.
- **/lib/systemd/system/**: File di unità predefiniti a livello di sistema forniti dai pacchetti installati.

### Moduli del Kernel

I moduli del kernel Linux, spesso utilizzati dal malware come componenti rootkit, vengono caricati all'avvio del sistema. Le directory e i file critici per questi moduli includono:

- **/lib/modules/$(uname -r)**: Contiene moduli per la versione del kernel in esecuzione.
- **/etc/modprobe.d**: Contiene file di configurazione per controllare il caricamento dei moduli.
- **/etc/modprobe** e **/etc/modprobe.conf**: File per le impostazioni globali dei moduli.

### Altre Posizioni di Avvio Automatico

Linux utilizza vari file per eseguire automaticamente programmi al momento del login dell'utente, potenzialmente ospitando malware:

- **/etc/profile.d/**\*, **/etc/profile**, e **/etc/bash.bashrc**: Eseguiti per qualsiasi login utente.
- **\~/.bashrc**, **\~/.bash_profile**, **\~/.profile**, e **\~/.config/autostart**: File specifici per l'utente che vengono eseguiti al loro login.
- **/etc/rc.local**: Viene eseguito dopo che tutti i servizi di sistema sono stati avviati, segnando la fine della transizione a un ambiente multiutente.

## Esaminare i Log

I sistemi Linux tracciano le attività degli utenti e gli eventi di sistema attraverso vari file di log. Questi log sono fondamentali per identificare accessi non autorizzati, infezioni da malware e altri incidenti di sicurezza. I file di log chiave includono:

- **/var/log/syslog** (Debian) o **/var/log/messages** (RedHat): Catturano messaggi e attività a livello di sistema.
- **/var/log/auth.log** (Debian) o **/var/log/secure** (RedHat): Registrano i tentativi di autenticazione, accessi riusciti e falliti.
- Usa `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` per filtrare eventi di autenticazione rilevanti.
- **/var/log/boot.log**: Contiene messaggi di avvio del sistema.
- **/var/log/maillog** o **/var/log/mail.log**: Registra le attività del server di posta, utile per tracciare i servizi legati alla posta elettronica.
- **/var/log/kern.log**: Memorizza messaggi del kernel, inclusi errori e avvisi.
- **/var/log/dmesg**: Contiene messaggi del driver del dispositivo.
- **/var/log/faillog**: Registra i tentativi di accesso falliti, utile per le indagini su violazioni della sicurezza.
- **/var/log/cron**: Registra le esecuzioni dei job cron.
- **/var/log/daemon.log**: Traccia le attività dei servizi in background.
- **/var/log/btmp**: Documenta i tentativi di accesso falliti.
- **/var/log/httpd/**: Contiene log di errore e accesso di Apache HTTPD.
- **/var/log/mysqld.log** o **/var/log/mysql.log**: Registra le attività del database MySQL.
- **/var/log/xferlog**: Registra i trasferimenti di file FTP.
- **/var/log/**: Controlla sempre per log inaspettati qui.

> [!NOTE]
> I log di sistema Linux e i sottosistemi di audit potrebbero essere disabilitati o eliminati in un'intrusione o in un incidente di malware. Poiché i log sui sistemi Linux contengono generalmente alcune delle informazioni più utili sulle attività dannose, gli intrusi li eliminano regolarmente. Pertanto, quando si esaminano i file di log disponibili, è importante cercare lacune o voci fuori ordine che potrebbero essere un'indicazione di eliminazione o manomissione.

**Linux mantiene una cronologia dei comandi per ogni utente**, memorizzata in:

- \~/.bash_history
- \~/.zsh_history
- \~/.zsh_sessions/\*
- \~/.python_history
- \~/.\*\_history

Inoltre, il comando `last -Faiwx` fornisce un elenco di accessi degli utenti. Controllalo per accessi sconosciuti o inaspettati.

Controlla i file che possono concedere privilegi extra:

- Rivedi `/etc/sudoers` per privilegi utente non previsti che potrebbero essere stati concessi.
- Rivedi `/etc/sudoers.d/` per privilegi utente non previsti che potrebbero essere stati concessi.
- Esamina `/etc/groups` per identificare eventuali appartenenze a gruppi o permessi insoliti.
- Esamina `/etc/passwd` per identificare eventuali appartenenze a gruppi o permessi insoliti.

Alcune app generano anche i propri log:

- **SSH**: Esamina _\~/.ssh/authorized_keys_ e _\~/.ssh/known_hosts_ per connessioni remote non autorizzate.
- **Gnome Desktop**: Controlla _\~/.recently-used.xbel_ per file recentemente accessi tramite applicazioni Gnome.
- **Firefox/Chrome**: Controlla la cronologia del browser e i download in _\~/.mozilla/firefox_ o _\~/.config/google-chrome_ per attività sospette.
- **VIM**: Rivedi _\~/.viminfo_ per dettagli sull'uso, come percorsi di file accessi e cronologia delle ricerche.
- **Open Office**: Controlla l'accesso ai documenti recenti che potrebbero indicare file compromessi.
- **FTP/SFTP**: Rivedi i log in _\~/.ftp_history_ o _\~/.sftp_history_ per trasferimenti di file che potrebbero essere non autorizzati.
- **MySQL**: Indaga _\~/.mysql_history_ per query MySQL eseguite, rivelando potenzialmente attività non autorizzate nel database.
- **Less**: Analizza _\~/.lesshst_ per la cronologia dell'uso, inclusi file visualizzati e comandi eseguiti.
- **Git**: Esamina _\~/.gitconfig_ e il progetto _.git/logs_ per modifiche ai repository.

### Log USB

[**usbrip**](https://github.com/snovvcrash/usbrip) è un piccolo software scritto in puro Python 3 che analizza i file di log di Linux (`/var/log/syslog*` o `/var/log/messages*` a seconda della distribuzione) per costruire tabelle di cronologia degli eventi USB.

È interessante **conoscere tutte le USB che sono state utilizzate** e sarà più utile se hai un elenco autorizzato di USB per trovare "eventi di violazione" (l'uso di USB che non sono all'interno di quell'elenco).

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
More examples and info inside the github: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

## Rivedere gli Account Utente e le Attività di Accesso

Esaminare il _**/etc/passwd**_, _**/etc/shadow**_ e i **log di sicurezza** per nomi o account insoliti creati e/o utilizzati in prossimità di eventi non autorizzati noti. Inoltre, controllare possibili attacchi di brute-force sudo.\
Inoltre, controllare file come _**/etc/sudoers**_ e _**/etc/groups**_ per privilegi inaspettati concessi agli utenti.\
Infine, cercare account con **nessuna password** o **password facilmente indovinabili**.

## Esaminare il File System

### Analizzare le Strutture del File System nell'Investigazione di Malware

Quando si indagano incidenti di malware, la struttura del file system è una fonte cruciale di informazioni, rivelando sia la sequenza degli eventi che il contenuto del malware. Tuttavia, gli autori di malware stanno sviluppando tecniche per ostacolare questa analisi, come modificare i timestamp dei file o evitare il file system per l'archiviazione dei dati.

Per contrastare questi metodi anti-forensi, è essenziale:

- **Condurre un'analisi approfondita della timeline** utilizzando strumenti come **Autopsy** per visualizzare le timeline degli eventi o `mactime` di **Sleuth Kit** per dati dettagliati sulla timeline.
- **Indagare su script inaspettati** nel $PATH del sistema, che potrebbero includere script shell o PHP utilizzati dagli attaccanti.
- **Esaminare `/dev` per file atipici**, poiché tradizionalmente contiene file speciali, ma potrebbe ospitare file relativi al malware.
- **Cercare file o directory nascosti** con nomi come ".. " (punto punto spazio) o "..^G" (punto punto controllo-G), che potrebbero nascondere contenuti dannosi.
- **Identificare file setuid root** utilizzando il comando: `find / -user root -perm -04000 -print` Questo trova file con permessi elevati, che potrebbero essere abusati dagli attaccanti.
- **Rivedere i timestamp di cancellazione** nelle tabelle inode per individuare cancellazioni di massa di file, che potrebbero indicare la presenza di rootkit o trojan.
- **Ispezionare inode consecutivi** per file dannosi vicini dopo averne identificato uno, poiché potrebbero essere stati collocati insieme.
- **Controllare le directory binarie comuni** (_/bin_, _/sbin_) per file recentemente modificati, poiché questi potrebbero essere stati alterati da malware.
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
> [!NOTE]
> Nota che un **attaccante** può **modificare** il **tempo** per far **apparire** i **file** **legittimi**, ma non può **modificare** l'**inode**. Se scopri che un **file** indica che è stato creato e modificato allo **stesso tempo** degli altri file nella stessa cartella, ma l'**inode** è **inaspettatamente più grande**, allora i **timestamp di quel file sono stati modificati**.

## Confronta file di diverse versioni del filesystem

### Riepilogo del confronto delle versioni del filesystem

Per confrontare le versioni del filesystem e individuare le modifiche, utilizziamo comandi `git diff` semplificati:

- **Per trovare nuovi file**, confronta due directory:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
- **Per contenuti modificati**, elenca le modifiche ignorando linee specifiche:
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
- **Per rilevare file eliminati**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
- **Le opzioni di filtro** (`--diff-filter`) aiutano a restringere a modifiche specifiche come file aggiunti (`A`), eliminati (`D`) o modificati (`M`).
- `A`: File aggiunti
- `C`: File copiati
- `D`: File eliminati
- `M`: File modificati
- `R`: File rinominati
- `T`: Cambiamenti di tipo (ad es., file a symlink)
- `U`: File non uniti
- `X`: File sconosciuti
- `B`: File danneggiati

## Riferimenti

- [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf)
- [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)
- [https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
- **Libro: Malware Forensics Field Guide for Linux Systems: Digital Forensics Field Guides**

{{#include ../../banners/hacktricks-training.md}}
