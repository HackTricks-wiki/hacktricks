# Linux Forensics

{{#include ../../banners/hacktricks-training.md}}

## Početno prikupljanje informacija

### Osnovne informacije

Pre svega, preporučuje se da imate neki **USB** sa **dobro poznatim binary fajlovima i bibliotekama** na njemu (možete jednostavno uzeti ubuntu i kopirati foldere _/bin_, _/sbin_, _/lib,_ i _/lib64_), zatim mount-ovati USB i izmeniti env promenljive da koriste te binary fajlove:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
Kada jednom konfigurišete sistem da koristi dobre i poznate binarne fajlove, možete početi sa **izvlačenjem nekih osnovnih informacija**:
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
#### Sumnjive informacije

Dok prikupljate osnovne informacije, trebalo bi da proverite neobične stvari kao što su:

- **Root procesi** obično rade sa niskim PID-ovima, pa ako pronađete root proces sa velikim PID-om, možete posumnjati
- Proverite **registrovane prijave** korisnika bez shell-a unutar `/etc/passwd`
- Proverite **password hashes** unutar `/etc/shadow` za korisnike bez shell-a

### Memory Dump

Da biste dobili memoriju pokrenutog sistema, preporučuje se da koristite [**LiME**](https://github.com/504ensicsLabs/LiME).\
Da biste ga **kompajlirali**, morate koristiti **isti kernel** koji koristi mašina žrtve.

> [!TIP]
> Zapamtite da **ne možete instalirati LiME ili bilo šta drugo** na mašinu žrtve jer će to napraviti nekoliko promena na njoj

Dakle, ako imate identičnu verziju Ubuntua, možete koristiti `apt-get install lime-forensics-dkms`\
U drugim slučajevima, potrebno je da preuzmete [**LiME**](https://github.com/504ensicsLabs/LiME) sa github i kompajlirate ga sa odgovarajućim kernel headers. Da biste **dobili tačne kernel headers** mašine žrtve, možete jednostavno **kopirati direktorijum** `/lib/modules/<kernel version>` na vašu mašinu, a zatim **kompajlirati** LiME koristeći ih:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME podržava 3 **format**:

- Raw (svaki segment spojen zajedno)
- Padded (isto kao raw, ali sa nulama u desnim bitovima)
- Lime (preporučeni format sa metapodacima)

LiME se takođe može koristiti za **slanje dump-a preko network-a** umesto da se čuva na sistemu, koristeći nešto poput: `path=tcp:4444`

### Disk Imaging

#### Shutting down

Pre svega, moraćete da **ugasite sistem**. Ovo nije uvek opcija jer ponekad sistem može biti production server koji kompanija ne može da priušti da ugasi.\
Postoje **2 načina** gašenja sistema, **normal shutdown** i **"plug the plug" shutdown**. Prvi će omogućiti da se **processes** završe kao i obično i da se **filesystem** **synchronizuje**, ali će takođe omogućiti mogućem **malware**-u da **uništi evidence**. Pristup "pull the plug" može dovesti do **nekog gubitka informacija** (neće se izgubiti mnogo info jer smo već uzeli image memorije) i **malware** neće imati **nikakvu priliku** da bilo šta uradi povodom toga. Zbog toga, ako **sumnjate** da može biti **malware**, samo izvršite **`sync`** **command** na sistemu i izvucite utikač.

#### Taking an image of the disk

Važno je napomenuti da, **pre nego što povežete računar sa bilo čim što je povezano sa slučajem**, morate biti sigurni da će biti **mountovan kao read only** kako biste izbegli modifikovanje bilo kakvih informacija.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Pre-analiza slike diska

Kreiranje slike diska bez dodatnih podataka.
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
## Pretraga za poznatim Malware

### Izmenjeni sistemski fajlovi

Linux nudi alate za proveru integriteta sistemskih komponenti, što je ključno za otkrivanje potencijalno problematičnih fajlova.

- **RedHat-based systems**: Koristite `rpm -Va` za sveobuhvatnu proveru.
- **Debian-based systems**: `dpkg --verify` za početnu verifikaciju, a zatim `debsums | grep -v "OK$"` (nakon instalacije `debsums` pomoću `apt-get install debsums`) da identifikujete bilo kakve probleme.

### Detektori Malware/Rootkit

Pročitajte sledeću stranicu da biste saznali više o alatima koji mogu biti korisni za pronalaženje malware:


{{#ref}}
malware-analysis.md
{{#endref}}

## Pretraga instaliranih programa

Da biste efikasno pretražili instalirane programe na Debian i RedHat systems, razmotrite korišćenje sistemskih logova i baza podataka uz ručne provere u uobičajenim direktorijumima.

- Za Debian, pregledajte _**`/var/lib/dpkg/status`**_ i _**`/var/log/dpkg.log`**_ da biste dohvatili detalje o instalacijama paketa, koristeći `grep` za filtriranje specifičnih informacija.
- RedHat korisnici mogu da upitaju RPM bazu podataka sa `rpm -qa --root=/mntpath/var/lib/rpm` da bi izlistali instalirane pakete.

Da biste otkrili softver instaliran ručno ili van ovih package managers, istražite direktorijume kao što su _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_, i _**`/sbin`**_. Kombinujte listanje direktorijuma sa komandama specifičnim za sistem kako biste identifikovali izvršne fajlove koji nisu povezani sa poznatim paketima, čime ćete poboljšati pretragu svih instaliranih programa.
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
## Povratak obrisanih pokrenutih binarnih fajlova

Zamislite proces koji je pokrenut iz /tmp/exec i zatim obrisan. Moguće je izvući ga
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## Triage syscall trace sa SQLite i FTS5

Kada proces još uvek radi ili može da se ponovo pokrene u laboratoriji, **`strace`** može da obezbedi brz behavioral trace bez potrebe za kernel modulima ili potpunom EDR telemetry. Za velike trace-ove, izbegavajte da direktno čitate raw log ili da ga lepite u LLM: sačuvajte ga u **SQLite** bazi i upitujte samo minimalni podskup koji vam je potreban.

> [!WARNING]
> Kačenje `strace` menja timing procesa i može uticati na race conditions ili druge fragile bugs. Po mogućnosti, radije reprodukujte na kopiji/lab sistemu.

### Capture

Za novi proces:
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log <command>
```
Za live process:
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log -p <PID>
```
Korisne opcije:

- `-ff`: prati forks/threads i zadržava izlaz po procesu
- `-ttt`: epoch timestamps za lako povezivanje vremenske linije
- `-yy`: razrešava file descriptors u backing paths/sockets kada je moguće
- `-s 4096`: sprečava da se dugi path i buffer arguments skraćuju

### Normalize

Praktična schema je jedan red po syscall-u i jedan red po argumentu:
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
Ovo izbegava pokušaj da se heterogene syscall linije spljošte u jednu široku tabelu i održava join-ove predvidljivim tokom triage.

### Indeksirajte tekstualno teške argumente pomoću FTS5

Naivno traženje path-ova pomoću `LIKE "%...%"` postaje veoma sporo na velikim tragovima. Umesto toga kreirajte FTS5 index za tekst argumenata i pretražujte njega:
```sql
CREATE VIRTUAL TABLE syscall_args_fts
USING fts5(raw, content='syscall_args', content_rowid='id');

INSERT INTO syscall_args_fts(rowid, raw)
SELECT id, raw FROM syscall_args;
```
Primer: oporavite aktivnost fajlova u `/tmp` bez skeniranja svakog reda:
```sql
SELECT s.timestamp, s.pid, s.name, a.position, a.raw
FROM syscall_args_fts f
JOIN syscall_args a ON a.id = f.rowid
JOIN syscalls s ON s.id = a.syscall_id
WHERE syscall_args_fts MATCH 'tmp'
AND s.name IN ('openat', 'stat', 'lstat', 'rename', 'unlink', 'execve')
ORDER BY s.timestamp;
```
### Visokosignalne istrage

- **PATH hijacking / fake sudo**: pretraži upise i `chmod`/`rename` aktivnost u `~/.local/bin/`, zatim poveži sa kasnijim `execve` privilegovano-nazvanih imena kao što je `sudo`.
- **TOCTOU na privremenim fajlovima**: pivotiraj na istu `/tmp/...` putanju kroz `stat`, `access`, `openat`, `rename`, `unlink`, `link`, `symlink`, i `execve` da identifikuješ check/use praznine.
- **Uzrok pada**: poveži `mmap` fajla sa upisima ili truncation istog inode/path od strane drugog procesa, zatim proveri signal/exit sekvencu za `SIGBUS`.
- **Oporavak network destinacije**: filtriraj `connect`, `sendto`, `sendmsg`, `recvfrom`, i socket-related argumente da izdvojiš peer IP adrese i portove.

### LLM-assisted trace analysis

Ako želiš da LLM pomogne, izloži **read-only** SQLite handle i daj mu kompletnu šemu. Pusti ga da izvršava raw SQL umesto da bazu obavijaš kroz uske helper funkcije. Ovo obično radi bolje za join-ove, temporal correlation, i FTS lookups.

Praktična pravila:

- Drži bazu read-only, na primer sa `sqlite3 'file:trace.db?mode=ro'`.
- Daj modelu primere validnih `JOIN` i `FTS5 MATCH` upita.
- Ne lepi raw multi-GB `strace` logove u prompt.
- Postavljaj fokusirana pitanja kao što su:
- "Nabroji persistent fajlove koje je ovaj program upisao."
- "Da li je kreirao ili zamenio izvršne fajlove u PATH direktorijumima pod kontrolom korisnika?"
- "Objasni zašto se ovaj trace završava u SIGBUS."

## Pregledaj Autostart lokacije

### Scheduled Tasks
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
Napadači često uređuju 0anacron stub prisutan u svakom /etc/cron.*/ direktorijumu kako bi obezbedili periodično izvršavanje.
```bash
# List 0anacron files and their timestamps/sizes
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done

# Look for obvious execution of shells or downloaders embedded in cron stubs
grep -R --line-number -E 'curl|wget|/bin/sh|python|bash -c' /etc/cron.*/* 2>/dev/null
```
#### Lov: vraćanje SSH hardening-a i backdoor shell-ova
Promene u sshd_config i shell-ovima sistemskih naloga su česte nakon eksploatacije radi očuvanja pristupa.
```bash
# Root login enablement (flag "yes" or lax values)
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config

# System accounts with interactive shells (e.g., games → /bin/sh)
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
#### Lov: Cloud C2 markeri (Dropbox/Cloudflare Tunnel)
- Dropbox API beacon-i tipično koriste api.dropboxapi.com ili content.dropboxapi.com preko HTTPS sa Authorization: Bearer tokenima.
- Lov u proxy/Zeek/NetFlow za neočekivani Dropbox egress sa servera.
- Cloudflare Tunnel (`cloudflared`) obezbeđuje backup C2 preko outbound 443.
```bash
ps aux | grep -E '[c]loudflared|trycloudflare'
systemctl list-units | grep -i cloudflared
```
### Services

Paths where a malware could be installed as a service:

- **/etc/inittab**: Poziva skripte za inicijalizaciju kao što je rc.sysinit, usmeravajući dalje ka startup skriptama.
- **/etc/rc.d/** and **/etc/rc.boot/**: Sadrže skripte za pokretanje servisa, pri čemu se drugi nalazi u starijim Linux verzijama.
- **/etc/init.d/**: Koristi se u određenim Linux verzijama kao što je Debian za skladištenje startup skripti.
- Services may also be activated via **/etc/inetd.conf** or **/etc/xinetd/**, u zavisnosti od Linux varijante.
- **/etc/systemd/system**: Direktorijum za skripte system and service manager-a.
- **/etc/systemd/system/multi-user.target.wants/**: Sadrži linkove ka servisima koji treba da se pokreću u multi-user runlevel-u.
- **/usr/local/etc/rc.d/**: Za custom ili third-party servise.
- **\~/.config/autostart/**: Za aplikacije sa automatskim pokretanjem specifičnim za korisnika, što može biti skriveno mesto za user-targeted malware.
- **/lib/systemd/system/**: Podrazumevane unit datoteke za ceo sistem koje obezbeđuju instalirani paketi.

#### Hunt: systemd timers and transient units

Systemd persistence is not limited to `.service` files. Investigate `.timer` units, user-level units, and **transient units** created at runtime.
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
Transient units su lako promašive jer je `/run/systemd/transient/` **nepostojan**. Ako prikupljate live image, uzmite ga pre gašenja.

### Kernel Modules

Linux kernel moduli, često korišćeni od strane malware-a kao rootkit komponente, učitavaju se pri sistemskom boot-u. Direktorijumi i fajlovi kritični za ove module uključuju:

- **/lib/modules/$(uname -r)**: Sadrži module za trenutnu verziju kernela.
- **/etc/modprobe.d**: Sadrži konfiguracione fajlove za kontrolu učitavanja modula.
- **/etc/modprobe** i **/etc/modprobe.conf**: Fajlovi za globalna podešavanja modula.

### Other Autostart Locations

Linux koristi različite fajlove za automatsko izvršavanje programa pri korisničkom login-u, što može skrivati malware:

- **/etc/profile.d/**\*, **/etc/profile**, i **/etc/bash.bashrc**: Izvršavaju se za svaki korisnički login.
- **\~/.bashrc**, **\~/.bash_profile**, **\~/.profile**, i **\~/.config/autostart**: Fajlovi specifični za korisnika koji se pokreću pri njegovom login-u.
- **/etc/rc.local**: Pokreće se nakon što su sve sistemske usluge startovane, označavajući kraj prelaska u multiuser okruženje.

## Examine Logs

Linux sistemi prate aktivnosti korisnika i sistemske događaje kroz razne log fajlove. Ovi logovi su ključni za identifikaciju neovlašćenog pristupa, infekcija malware-om i drugih bezbednosnih incidenata. Ključni log fajlovi uključuju:

- **/var/log/syslog** (Debian) ili **/var/log/messages** (RedHat): Beleže poruke i aktivnosti na nivou celog sistema.
- **/var/log/auth.log** (Debian) ili **/var/log/secure** (RedHat): Beleže pokušaje autentikacije, uspešne i neuspešne prijave.
- Koristite `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` da filtrirate relevantne autentikacione događaje.
- **/var/log/boot.log**: Sadrži poruke o pokretanju sistema.
- **/var/log/maillog** ili **/var/log/mail.log**: Loguje aktivnosti mail servera, korisno za praćenje servisa vezanih za email.
- **/var/log/kern.log**: Čuva poruke kernela, uključujući greške i upozorenja.
- **/var/log/dmesg**: Sadrži poruke device driver-a.
- **/var/log/faillog**: Beleži neuspešne pokušaje prijave, pomažući u istrazi bezbednosnih provala.
- **/var/log/cron**: Loguje izvršavanja cron job-ova.
- **/var/log/daemon.log**: Prati aktivnosti background servisa.
- **/var/log/btmp**: Dokumentuje neuspešne pokušaje prijave.
- **/var/log/httpd/**: Sadrži Apache HTTPD error i access log-ove.
- **/var/log/mysqld.log** ili **/var/log/mysql.log**: Loguju aktivnosti MySQL baze podataka.
- **/var/log/xferlog**: Beleži FTP file transfer-e.
- **/var/log/**: Uvek proverite da li ovde postoje neočekivani logovi.

> [!TIP]
> Linux sistemski logovi i audit subsistemi mogu biti onemogućeni ili obrisani tokom intrusion ili malware incidenta. Pošto logovi na Linux sistemima generalno sadrže neke od najkorisnijih informacija o malicioznim aktivnostima, uljezi ih rutinski brišu. Zato, kada pregledate dostupne log fajlove, važno je tražiti praznine ili zapise van redosleda koji mogu ukazivati na brisanje ili manipulaciju.

### Journald triage (`journalctl`)

Na modernim Linux hostovima, **systemd journal** je obično izvor najveće vrednosti za **service execution**, **auth events**, **package operations**, i **kernel/user-space messages**. Tokom live response-a, pokušajte da sačuvate i **persistent** journal (`/var/log/journal/`) i **runtime** journal (`/run/log/journal/`) jer kratkotrajna attacker aktivnost može postojati samo u ovom drugom.
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
Korisna journal polja za trijažu uključuju `_SYSTEMD_UNIT`, `_EXE`, `_COMM`, `_CMDLINE`, `_UID`, `_GID`, `_PID`, `_BOOT_ID`, i `MESSAGE`. Ako je journald bio podešen bez trajnog skladištenja, očekujte samo nedavne podatke u `/run/log/journal/`.

### Trijaža audit framework-a (`auditd`)

Ako je `auditd` omogućen, preferirajte ga kad god vam je potrebna **process attribution** za izmene fajlova, izvršavanje komandi, aktivnosti prijave ili instalaciju paketa.
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
Kada su pravila bila primenjena sa ključevima, pivotirajte sa njih umesto da grep-ujete sirove logove:
```bash
ausearch --start this-week -k <rule_key> --raw | aureport --file --summary -i
ausearch --start this-week -k <rule_key> --raw | aureport --user --summary -i
```
**Linux održava komandnu istoriju za svakog korisnika**, sačuvanu u:

- \~/.bash_history
- \~/.zsh_history
- \~/.zsh_sessions/\*
- \~/.python_history
- \~/.\*\_history

Pored toga, `last -Faiwx` komanda prikazuje listu korisničkih prijava. Proverite je zbog nepoznatih ili neočekivanih prijava.

Proverite fajlove koji mogu da daju dodatne rprivileges:

- Pregledajte `/etc/sudoers` zbog neočekivanih korisničkih privilegija koje su možda dodeljene.
- Pregledajte `/etc/sudoers.d/` zbog neočekivanih korisničkih privilegija koje su možda dodeljene.
- Ispitajte `/etc/groups` da biste identifikovali neuobičajena članstva u grupama ili dozvole.
- Ispitajte `/etc/passwd` da biste identifikovali neuobičajena članstva u grupama ili dozvole.

Neke apps takođe generišu sopstvene logove:

- **SSH**: Ispitajte _\~/.ssh/authorized_keys_ i _\~/.ssh/known_hosts_ radi neovlašćenih udaljenih konekcija.
- **Gnome Desktop**: Pogledajte _\~/.recently-used.xbel_ za nedavno pristupane fajlove preko Gnome aplikacija.
- **Firefox/Chrome**: Proverite istoriju pregleda i preuzimanja u _\~/.mozilla/firefox_ ili _\~/.config/google-chrome_ zbog sumnjivih aktivnosti.
- **VIM**: Pregledajte _\~/.viminfo_ za detalje o korišćenju, kao što su putanje do pristupanih fajlova i istorija pretrage.
- **Open Office**: Proverite nedavni pristup dokumentima koji može ukazivati na kompromitovane fajlove.
- **FTP/SFTP**: Pregledajte logove u _\~/.ftp_history_ ili _\~/.sftp_history_ za prenose fajlova koji su možda neovlašćeni.
- **MySQL**: Ispitajte _\~/.mysql_history_ za izvršene MySQL upite, što može otkriti neovlašćene aktivnosti nad bazom podataka.
- **Less**: Analizirajte _\~/.lesshst_ za istoriju korišćenja, uključujući pregledane fajlove i izvršene komande.
- **Git**: Pregledajte _\~/.gitconfig_ i project _.git/logs_ zbog promena u repozitorijumima.

### USB Logs

[**usbrip**](https://github.com/snovvcrash/usbrip) je mali softver napisan u čistom Python 3 koji parsira Linux log fajlove (`/var/log/syslog*` ili `/var/log/messages*` u zavisnosti od distroa) radi kreiranja tabela istorije USB događaja.

Zanimljivo je **znati sve USB uređaje koji su korišćeni**, a biće korisnije ako imate autorizovanu listu USB uređaja kako biste pronašli "violation events" (korišćenje USB uređaja koji nisu na toj listi).

### Installation
```bash
pip3 install usbrip
usbrip ids download #Download USB ID database
```
### Primeri
```bash
usbrip events history #Get USB history of your curent linux machine
usbrip events history --pid 0002 --vid 0e0f --user kali #Search by pid OR vid OR user
#Search for vid and/or pid
usbrip ids download #Downlaod database
usbrip ids search --pid 0002 --vid 0e0f #Search for pid AND vid
```
More examples and info inside the github: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

## Pregled korisničkih naloga i aktivnosti prijavljivanja

Ispitajte _**/etc/passwd**_, _**/etc/shadow**_ i **security logs** radi neobičnih imena ili naloga koji su kreirani i/ili korišćeni u blizini poznatih neovlašćenih događaja. Takođe, proverite moguće sudo brute-force napade.\
Takođe, proverite datoteke poput _**/etc/sudoers**_ i _**/etc/groups**_ radi neočekivanih privilegija dodeljenih korisnicima.\
Na kraju, potražite naloge sa **nema lozinke** ili **lako pogađajućim** lozinkama.

## Ispitajte file system

### Analiza struktura file system-a u istrazi malware-a

Prilikom istrage malware incidenata, struktura file system-a je ključan izvor informacija, jer otkriva i niz događaja i sadržaj malware-a. Međutim, autori malware-a razvijaju tehnike za otežavanje ove analize, kao što su modifikovanje vremenskih oznaka fajlova ili izbegavanje file system-a za skladištenje podataka.

Da biste se suprotstavili ovim anti-forensic metodama, neophodno je:

- **Sprovesti detaljnu timeline analizu** koristeći alate kao što su **Autopsy** za vizuelizaciju timeline događaja ili **Sleuth Kit's** `mactime` za detaljne timeline podatke.
- **Ispitati neočekivane skripte** u sistemskom $PATH, koje mogu uključivati shell ili PHP skripte koje koriste napadači.
- **Pregledati `/dev` za atipične fajlove**, jer tradicionalno sadrži specijalne fajlove, ali može da sadrži i fajlove povezane sa malware-om.
- **Potražiti skrivene fajlove ili direktorijume** sa imenima kao što su ".. " (tačka tačka razmak) ili "..^G" (tačka tačka kontrola-G), koji bi mogli skrivati zlonamerni sadržaj.
- **Identifikovati setuid root fajlove** pomoću komande: `find / -user root -perm -04000 -print` Ova komanda pronalazi fajlove sa povišenim privilegijama, koje napadači mogu zloupotrebiti.
- **Pregledati vremenske oznake brisanja** u inode tabelama da biste uočili masovna brisanja fajlova, što može ukazivati na prisustvo rootkits ili trojans.
- **Ispitati uzastopne inode-e** za obližnje zlonamerne fajlove nakon što identifikujete jedan, jer su možda postavljeni zajedno.
- **Proveriti uobičajene binarne direktorijume** (_/bin_, _/sbin_) za nedavno izmenjene fajlove, jer ih malware može izmeniti.
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
> [!TIP]
> Imajte na umu da **napadač** može da **izmeni** **vreme** kako bi **fajlovi izgledali** **legitimno**, ali ne može da izmeni **inode**. Ako utvrdite da **fajl** pokazuje da je kreiran i izmenjen u **isto vreme** kao i ostali fajlovi u istoj fascikli, ali je **inode** neočekivano veći, onda su **timestamp-ovi tog fajla bili izmenjeni**.

### Brza trijaža fokusirana na inode

Ako sumnjate na anti-forensics, pokrenite ove provere fokusirane na inode rano:
```bash
# Filesystem inode pressure (possible inode exhaustion DoS)
df -i

# Identify all names that point to one inode
find / -xdev -inum <inode_number> 2>/dev/null

# Find deleted files still open by running processes
lsof +L1
lsof | grep '(deleted)'
```
Kada se sumnjiv inode nalazi na EXT filesystem image/device, proverite inode metadata direktno:
```bash
sudo debugfs -R "stat <inode_number>" /dev/sdX
```
Korisna polja:
- **Links**: ako je `0`, nijedan direktorijumski unos trenutno ne referencira inode.
- **dtime**: vremenska oznaka brisanja postavljena kada je inode bio odvezan.
- **ctime/mtime**: pomaže da se usklade promene metapodataka/sadržaja sa vremenskom linijom incidenta.

### Capabilities, xattrs, and preload-based userland rootkits

Savremena Linux perzistencija često izbegava očigledne `setuid` binarne datoteke i umesto toga zloupotrebljava **file capabilities**, **extended attributes**, i dynamic loader.
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
Obratite posebnu pažnju na biblioteke navedene iz **writable** putanja kao što su `/tmp`, `/dev/shm`, `/var/tmp`, ili čudne lokacije pod `/usr/local/lib`. Takođe proverite binaries sa capability oznakama van uobičajenog vlasništva paketa i povežite ih sa rezultatima provere paketa (`rpm -Va`, `dpkg --verify`, `debsums`).

## Uporedite fajlove različitih filesystem verzija

### Sažetak poređenja filesystem verzija

Da biste uporedili filesystem verzije i precizno identifikovali promene, koristimo pojednostavljene `git diff` komande:

- **Da biste pronašli nove fajlove**, uporedite dva direktorijuma:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
- **Za izmenjeni sadržaj**, navedite izmene zanemarujući određene linije:
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
- **Za detekciju obrisanih fajlova**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
- **Opcije filtera** (`--diff-filter`) pomažu da se suzi izbor na određene izmene kao što su dodate (`A`), obrisane (`D`) ili izmenjene (`M`) datoteke.
- `A`: Dodate datoteke
- `C`: Kopirane datoteke
- `D`: Obrisane datoteke
- `M`: Izmenjene datoteke
- `R`: Preimenovane datoteke
- `T`: Promene tipa (npr. datoteka u symlink)
- `U`: Nespajane datoteke
- `X`: Nepoznate datoteke
- `B`: Oštećene datoteke

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
