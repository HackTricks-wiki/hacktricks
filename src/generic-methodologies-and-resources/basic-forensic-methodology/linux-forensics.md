# Linux Forensics

{{#include ../../banners/hacktricks-training.md}}

## Početno prikupljanje informacija

### Osnovne informacije

Pre svega, preporučuje se da imate neki **USB** sa **proverenim binarnim datotekama i bibliotekama** (možete jednostavno preuzeti ubuntu i kopirati foldere _/bin_, _/sbin_, _/lib,_ i _/lib64_), zatim montirati USB i izmeniti env promenljive kako biste koristili te binarne datoteke:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
Kada konfigurišete sistem da koristi pouzdane i poznate binarne datoteke, možete početi sa **izdvajanjem osnovnih informacija**:
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

Prilikom prikupljanja osnovnih informacija trebalo bi da proverite neobične stvari kao što su:

- **Root procesi** se obično pokreću sa malim vrednostima PIDS, pa ako pronađete root proces sa velikim PID-om, možete posumnjati
- Proverite **registrovane prijave** korisnika bez shell-a unutar `/etc/passwd`
- Proverite **hash vrednosti lozinki** unutar `/etc/shadow` za korisnike bez shell-a

### Memory Dump

Za dobijanje memorije pokrenutog sistema preporučuje se korišćenje alata [**LiME**](https://github.com/504ensicsLabs/LiME).\
Da biste ga **kompajlirali**, morate koristiti **isti kernel** koji koristi napadnuta mašina.

> [!TIP]
> Imajte na umu da **ne možete instalirati LiME niti bilo šta drugo** na napadnutoj mašini, jer će to napraviti nekoliko izmena na njoj

Dakle, ako imate identičnu verziju Ubuntu-a, možete koristiti `apt-get install lime-forensics-dkms`\
U drugim slučajevima, potrebno je da preuzmete [**LiME**](https://github.com/504ensicsLabs/LiME) sa github-a i kompajlirate ga sa odgovarajućim kernel headerima. Da biste **dobili tačne kernel headere** napadnute mašine, možete jednostavno **kopirati direktorijum** `/lib/modules/<kernel version>` na svoju mašinu i zatim **kompajlirati** LiME koristeći ih:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME podržava 3 **formata**:

- Raw (svaki segment spojen jedan za drugim)
- Padded (isto što i raw, ali sa nulama u desnim bitovima)
- Lime (preporučeni format sa metapodacima

LiME se takođe može koristiti za **slanje dump-a putem mreže** umesto njegovog čuvanja na sistemu, koristeći nešto poput: `path=tcp:4444`

### Pravljenje slike diska

#### Isključivanje

Pre svega, potrebno je da **isključite sistem**. To nije uvek moguće, jer sistem ponekad može biti produkcioni server koji kompanija ne može da priušti da isključi.\
Postoje **2 načina** za isključivanje sistema: **normalno isključivanje** i isključivanje **„izvlačenjem utikača“**. Prvi način će omogućiti da se **procesi normalno završe** i da se **filesystem** **sinhronizuje**, ali će takođe omogućiti mogućem **malware-u** da **uništi dokaze**. Pristup **„izvlačenja utikača“** može prouzrokovati **određeni gubitak informacija** (neće se izgubiti mnogo informacija, jer smo već napravili image memorije), a **malware neće imati nikakvu mogućnost** da bilo šta preduzme. Zato, ako **sumnjate** da možda postoji **malware**, samo izvršite **`sync`** **komandu** na sistemu i izvucite utikač.

#### Pravljenje slike diska

Važno je napomenuti da **pre povezivanja računara sa bilo čim što je povezano sa slučajem**, morate biti sigurni da će biti **montiran samo za čitanje**, kako biste izbegli menjanje bilo kakvih informacija.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Prethodna analiza slike diska

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
## Pretraga poznatog malware-a

### Izmenjene sistemske datoteke

Linux nudi alate za proveru integriteta sistemskih komponenti, što je ključno za otkrivanje potencijalno problematičnih datoteka.<sup>[[1]](#references)</sup>

- **Sistemi zasnovani na RedHat-u**: Koristite `rpm -Va` za sveobuhvatnu proveru.
- **Sistemi zasnovani na Debian-u**: Koristite `dpkg --verify` za početnu proveru, a zatim `debsums | grep -v "OK$"` (nakon instaliranja `debsums` pomoću `apt-get install debsums`) da biste identifikovali probleme.

### Detektori malware-a/rootkit-a

Pročitajte sledeću stranicu da biste saznali više o alatima koji mogu biti korisni za pronalaženje malware-a:


{{#ref}}
malware-analysis.md
{{#endref}}

## Pretraga instaliranih programa

Za efikasnu pretragu instaliranih programa na Debian i RedHat sistemima, razmotrite korišćenje sistemskih logova i baza podataka uz ručne provere u uobičajenim direktorijumima.<sup>[[1]](#references)</sup>

- Na Debian-u proverite _**`/var/lib/dpkg/status`**_ i _**`/var/log/dpkg.log`**_ da biste pronašli detalje o instalacijama paketa, koristeći `grep` za filtriranje određenih informacija.
- Korisnici RedHat-a mogu da upitaju RPM bazu pomoću `rpm -qa --root=/mntpath/var/lib/rpm` da bi izlistali instalirane pakete.

Da biste otkrili softver instaliran ručno ili izvan ovih package manager-a, istražite direktorijume kao što su _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_ i _**`/sbin`**_. Kombinujte izlistavanje direktorijuma sa komandama specifičnim za sistem da biste identifikovali izvršne datoteke koje nisu povezane sa poznatim paketima, čime ćete poboljšati pretragu svih instaliranih programa.
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
## Oporavak obrisanih pokrenutih binarnih datoteka

Zamislite proces koji je pokrenut iz /tmp/exec, a zatim obrisan. Moguće je izdvojiti ga
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## Trijaža tragova sistemskih poziva sa SQLite i FTS5

Kada je proces još uvek pokrenut ili se može ponovo izvršiti u lab okruženju, **`strace`** može da obezbedi brz trag ponašanja bez potrebe za kernel modulima ili potpunom EDR telemetrijom. Za velike tragove izbegavajte direktno čitanje sirovog loga ili njegovo unošenje u LLM: sačuvajte ga u **SQLite** bazi podataka i upitima dohvatite samo minimalni podskup koji vam je potreban.<sup>[[7]](#references)[[8]](#references)[[9]](#references)</sup>

> [!WARNING]
> Povezivanje pomoću `strace` menja vremensko ponašanje procesa i može uticati na race uslove ili druge osetljive greške. Kada je moguće, prednost dajte reprodukovanju problema na kopiji/lab sistemu.

### Prikupljanje

Za novi proces:
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log <command>
```
Za aktivan proces:
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log -p <PID>
```
Korisne opcije:

- `-ff`: prati forks/threads i čuva izlaz za svaki proces zasebno
- `-ttt`: epoch vremenske oznake za jednostavno povezivanje događaja na vremenskoj liniji
- `-yy`: razrešava deskriptore datoteka u odgovarajuće putanje/socket-e kada je moguće
- `-s 4096`: sprečava skraćivanje dugih putanja i buffer argumenata

### Normalizacija

Praktična šema je jedan red po sistemskom pozivu i jedan red po argumentu:
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
Ovo izbegava pokušaj svođenja heterogenih syscall linija u jednu široku tabelu i održava spajanja predvidivim tokom triage-a.

### Indeksirajte tekstualne argumente pomoću FTS5

Naivno traženje putanja pomoću `LIKE "%...%"` postaje veoma sporo na velikim tragovima. Napravite FTS5 indeks za tekst argumenata i pretražujte njega umesto toga:
```sql
CREATE VIRTUAL TABLE syscall_args_fts
USING fts5(raw, content='syscall_args', content_rowid='id');

INSERT INTO syscall_args_fts(rowid, raw)
SELECT id, raw FROM syscall_args;
```
Primer: utvrdite aktivnosti nad datotekama u direktorijumu `/tmp` bez skeniranja svakog reda:
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

- **PATH hijacking / fake sudo**: pretražite upise i aktivnosti `chmod`/`rename` unutar `~/.local/bin/`, a zatim ih povežite sa kasnijim `execve` pozivima za nazive koji deluju privilegovano, kao što je `sudo`.
- **TOCTOU on temporary files**: pratite istu `/tmp/...` putanju kroz `stat`, `access`, `openat`, `rename`, `unlink`, `link`, `symlink` i `execve` da biste identifikovali praznine između provere i upotrebe.
- **Crash root cause**: povežite `mmap` datoteke sa upisima ili skraćivanjem iste inode datoteke/putanje od strane drugog procesa, a zatim pregledajte sekvencu signala/izlaza u potrazi za `SIGBUS`.
- **Network destination recovery**: filtrirajte argumente povezane sa `connect`, `sendto`, `sendmsg`, `recvfrom` i socket-ima da biste izdvojili IP adrese i portove peer-ova.

### LLM-assisted trace analysis

Ako želite da LLM pomogne, omogućite mu **read-only** SQLite handle i prosledite mu celu šemu. Dozvolite mu da izvršava raw SQL umesto da bazu obmotavate uskim pomoćnim funkcijama. Ovo obično bolje funkcioniše za JOIN upite, vremensku korelaciju i FTS pretrage.

Praktična pravila:

- Ostavite bazu u režimu samo za čitanje, na primer pomoću `sqlite3 'file:trace.db?mode=ro'`.
- Dajte modelu primere validnih `JOIN` i `FTS5 MATCH` upita.
- Ne lepite raw multi-GB `strace` logove u prompt.
- Postavljajte fokusirana pitanja kao što su:
- "Izlistaj trajne datoteke koje je ovaj program upisao."
- "Da li je kreirao ili zamenio izvršne datoteke u PATH direktorijumima pod kontrolom korisnika?"
- "Objasni zašto se ovaj trace završava sa SIGBUS."

## Inspect Autostart locations

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
#### Istraga: zloupotreba Cron/Anacron putem 0anacron i sumnjivih stub-ova
Napadači često menjaju 0anacron stub koji se nalazi u svakom /etc/cron.*/ direktorijumu kako bi obezbedili periodično izvršavanje.<sup>[[4]](#references)</sup>
```bash
# List 0anacron files and their timestamps/sizes
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done

# Look for obvious execution of shells or downloaders embedded in cron stubs
grep -R --line-number -E 'curl|wget|/bin/sh|python|bash -c' /etc/cron.*/* 2>/dev/null
```
#### Potraga: rollback SSH hardening-a i backdoor shell-ovi
Izmene u sshd_config i shell-ovima sistemskih naloga česte su nakon post-exploitation aktivnosti radi očuvanja pristupa.<sup>[[4]](#references)</sup>
```bash
# Root login enablement (flag "yes" or lax values)
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config

# System accounts with interactive shells (e.g., games → /bin/sh)
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
#### Potraga: Cloud C2 indikatori (Dropbox/Cloudflare Tunnel)
- Dropbox API beacons obično koriste api.dropboxapi.com ili content.dropboxapi.com preko HTTPS-a sa `Authorization: Bearer` tokenima.
- Potražite u proxy/Zeek/NetFlow neočekivani Dropbox izlazni saobraćaj sa servera.
- Cloudflare Tunnel (`cloudflared`) obezbeđuje rezervni C2 preko odlaznog porta 443.<sup>[[4]](#references)</sup>
```bash
ps aux | grep -E '[c]loudflared|trycloudflare'
systemctl list-units | grep -i cloudflared
```
### Servisi

Putanje na kojima malware može biti instaliran kao servis:

- **/etc/inittab**: Poziva initialization skripte kao što je rc.sysinit i dalje usmerava na startup skripte.
- **/etc/rc.d/** i **/etc/rc.boot/**: Sadrže skripte za pokretanje servisa; druga putanja se može pronaći u starijim Linux verzijama.
- **/etc/init.d/**: Koristi se u određenim Linux verzijama, kao što je Debian, za čuvanje startup skripti.
- Servisi se takođe mogu aktivirati putem **/etc/inetd.conf** ili **/etc/xinetd/**, u zavisnosti od Linux varijante.
- **/etc/systemd/system**: Direktorijum za system i service manager skripte.
- **/etc/systemd/system/multi-user.target.wants/**: Sadrži linkove ka servisima koji treba da budu pokrenuti na multi-user runlevel-u.
- **/usr/local/etc/rc.d/**: Za prilagođene servise ili servise trećih strana.
- **\~/.config/autostart/**: Za automatsko pokretanje aplikacija specifičnih za korisnika; može biti mesto za skrivanje malware-a usmerenog na korisnike.
- **/lib/systemd/system/**: Podrazumevane unit datoteke na nivou sistema koje obezbeđuju instalirani paketi.

#### Provera: systemd timers i transient units

systemd persistence nije ograničen na `.service` datoteke. Istražite `.timer` units, units na nivou korisnika i **transient units** kreirane tokom izvršavanja.
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
Privremene jedinice je lako prevideti jer je `/run/systemd/transient/` **neperzistentan**. Ako prikupljate live image, preuzmite ga pre gašenja sistema.

### Kernel Modules

Linux kernel modules, koje malware često koristi kao rootkit komponente, učitavaju se pri pokretanju sistema. Direktorijumi i fajlovi važni za ove module uključuju:

- **/lib/modules/$(uname -r)**: Sadrži module za verziju trenutno pokrenutog kernela.
- **/etc/modprobe.d**: Sadrži konfiguracione fajlove za kontrolu učitavanja modula.
- **/etc/modprobe** i **/etc/modprobe.conf**: Fajlovi za globalna podešavanja modula.

### Other Autostart Locations

Linux koristi različite fajlove za automatsko izvršavanje programa nakon prijavljivanja korisnika, u kojima se potencijalno može nalaziti malware:

- **/etc/profile.d/**\*, **/etc/profile** i **/etc/bash.bashrc**: Izvršavaju se pri prijavljivanju bilo kog korisnika.
- **\~/.bashrc**, **\~/.bash_profile**, **\~/.profile** i **\~/.config/autostart**: Fajlovi specifični za korisnika koji se izvršavaju pri njegovom prijavljivanju.
- **/etc/rc.local**: Izvršava se nakon pokretanja svih sistemskih servisa i označava kraj prelaska u multiuser okruženje.

## Examine Logs

Linux sistemi prate aktivnosti korisnika i sistemske događaje kroz različite log fajlove. Ovi logovi su ključni za otkrivanje neovlašćenog pristupa, malware infekcija i drugih bezbednosnih incidenata.<sup>[[2]](#references)</sup> Ključni log fajlovi uključuju:

- **/var/log/syslog** (Debian) ili **/var/log/messages** (RedHat): Beleže sistemske poruke i aktivnosti na nivou celog sistema.
- **/var/log/auth.log** (Debian) ili **/var/log/secure** (RedHat): Beleže pokušaje autentifikacije, kao i uspešna i neuspešna prijavljivanja.
- Koristite `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` za filtriranje relevantnih događaja autentifikacije.
- **/var/log/boot.log**: Sadrži poruke pri pokretanju sistema.
- **/var/log/maillog** ili **/var/log/mail.log**: Beleže aktivnosti email servera i korisni su za praćenje servisa povezanih sa emailom.
- **/var/log/kern.log**: Čuva poruke kernela, uključujući greške i upozorenja.
- **/var/log/dmesg**: Sadrži poruke drajvera uređaja.
- **/var/log/faillog**: Beleži neuspešne pokušaje prijavljivanja i pomaže u istragama bezbednosnih proboja.
- **/var/log/cron**: Beleži izvršavanja cron jobova.
- **/var/log/daemon.log**: Prati aktivnosti servisa u pozadini.
- **/var/log/btmp**: Dokumentuje neuspešne pokušaje prijavljivanja.
- **/var/log/httpd/**: Sadrži Apache HTTPD logove grešaka i pristupa.
- **/var/log/mysqld.log** ili **/var/log/mysql.log**: Beleže aktivnosti MySQL baze podataka.
- **/var/log/xferlog**: Beleži FTP prenose fajlova.
- **/var/log/**: Uvek proverite da li se ovde nalaze neočekivani logovi.

> [!TIP]
> Linux sistemski logovi i audit podsistemi mogu biti onemogućeni ili obrisani tokom upada ili malware incidenta. Pošto logovi na Linux sistemima uglavnom sadrže neke od najkorisnijih informacija o zlonamernim aktivnostima, napadači ih rutinski brišu. Zato je prilikom pregledanja dostupnih log fajlova važno tražiti praznine ili zapise van redosleda, što može ukazivati na brisanje ili neovlašćene izmene.

### Journald triage (`journalctl`)

Na modernim Linux hostovima, **systemd journal** je obično najvredniji izvor informacija o **izvršavanju servisa**, **auth događajima**, **operacijama nad paketima** i **kernel/user-space porukama**. Tokom live response-a pokušajte da sačuvate i **perzistentni** journal (`/var/log/journal/`) i **runtime** journal (`/run/log/journal/`), jer kratkotrajne aktivnosti napadača mogu postojati samo u ovom drugom.<sup>[[5]](#references)</sup>
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
Korisna polja journal-a za trijažu obuhvataju `_SYSTEMD_UNIT`, `_EXE`, `_COMM`, `_CMDLINE`, `_UID`, `_GID`, `_PID`, `_BOOT_ID` i `MESSAGE`. Ako je journald konfigurisan bez persistentnog skladištenja, očekujte samo nedavne podatke u `/run/log/journal/`.

### Trijaža audit framework-a (`auditd`)

Ako je `auditd` omogućen, koristite ga prvenstveno kada vam je potrebno **utvrđivanje procesa** odgovornog za izmene datoteka, izvršavanje komandi, aktivnosti prijavljivanja ili instalaciju paketa.<sup>[[6]](#references)</sup>
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
Kada su pravila postavljena sa ključevima, pivotujte od njih umesto pretraživanja sirovih logova:
```bash
ausearch --start this-week -k <rule_key> --raw | aureport --file --summary -i
ausearch --start this-week -k <rule_key> --raw | aureport --user --summary -i
```
**Linux održava istoriju komandi za svakog korisnika**, sačuvanu u:

- \~/.bash_history
- \~/.zsh_history
- \~/.zsh_sessions/\*
- \~/.python_history
- \~/.\*\_history

Pored toga, komanda `last -Faiwx` pruža listu prijavljivanja korisnika. Proverite je zbog nepoznatih ili neočekivanih prijavljivanja.

Proverite fajlove koji mogu dodeliti dodatne privilegije:

- Pregledajte `/etc/sudoers` zbog neočekivanih privilegija korisnika koje su možda dodeljene.
- Pregledajte `/etc/sudoers.d/` zbog neočekivanih privilegija korisnika koje su možda dodeljene.
- Pregledajte `/etc/groups` da biste identifikovali neuobičajena članstva u grupama ili dozvole.
- Pregledajte `/etc/passwd` da biste identifikovali neuobičajena članstva u grupama ili dozvole.

Neke aplikacije takođe generišu sopstvene logove:

- **SSH**: Pregledajte _\~/.ssh/authorized_keys_ i _\~/.ssh/known_hosts_ zbog neovlašćenih udaljenih konekcija.
- **Gnome Desktop**: Proverite _\~/.recently-used.xbel_ da biste pronašli nedavno pristupane fajlove putem Gnome aplikacija.
- **Firefox/Chrome**: Proverite istoriju pregledača i preuzimanja u _\~/.mozilla/firefox_ ili _\~/.config/google-chrome_ zbog sumnjivih aktivnosti.
- **VIM**: Pregledajte _\~/.viminfo_ zbog detalja o korišćenju, kao što su putanje pristupanih fajlova i istorija pretrage.
- **Open Office**: Proverite nedavni pristup dokumentima koji može ukazivati na kompromitovane fajlove.
- **FTP/SFTP**: Pregledajte logove u _\~/.ftp_history_ ili _\~/.sftp_history_ zbog prenosa fajlova koji mogu biti neovlašćeni.
- **MySQL**: Istražite _\~/.mysql_history_ zbog izvršenih MySQL upita, koji potencijalno mogu otkriti neovlašćene aktivnosti nad bazom podataka.
- **Less**: Analizirajte _\~/.lesshst_ zbog istorije korišćenja, uključujući pregledane fajlove i izvršene komande.
- **Git**: Pregledajte _\~/.gitconfig_ i projektni _.git/logs_ zbog izmena u repozitorijumima.

### USB logovi

[**usbrip**](https://github.com/snovvcrash/usbrip) je mali softver napisan u čistom Pythonu 3 koji parsira Linux log fajlove (`/var/log/syslog*` ili `/var/log/messages*`, u zavisnosti od distribucije) radi konstruisanja tabela istorije USB događaja.

Zanimljivo je **znati koji su USB uređaji korišćeni**, a još je korisnije ako imate autorizovanu listu USB uređaja kako biste pronašli „događaje kršenja“ (korišćenje USB uređaja koji nisu na toj listi).

### Instalacija
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
Više primera i informacija nalazi se na github-u: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

## Pregled korisničkih naloga i aktivnosti prijavljivanja

Pregledajte _**/etc/passwd**_, _**/etc/shadow**_ i **security logs** u potrazi za neuobičajenim imenima ili nalozima koji su kreirani i/ili korišćeni u neposrednoj blizini poznatih neovlašćenih događaja. Takođe proverite moguće sudo brute-force napade.\
Pored toga, proverite datoteke kao što su _**/etc/sudoers**_ i _**/etc/groups**_ u potrazi za neočekivanim privilegijama dodeljenim korisnicima.\
Na kraju, potražite naloge **bez lozinki** ili sa **lako pogodivim** lozinkama.<sup>[[1]](#references)</sup>

## Ispitivanje sistema datoteka

### Analiza struktura sistema datoteka u istrazi malvera

Prilikom istrage incidenata sa malverom, struktura sistema datoteka predstavlja ključan izvor informacija, otkrivajući i redosled događaja i sadržaj malvera. Međutim, autori malvera razvijaju tehnike za otežavanje ove analize, kao što su menjanje vremenskih oznaka datoteka ili izbegavanje sistema datoteka za skladištenje podataka.<sup>[[1]](#references)</sup>

Za suprotstavljanje ovim anti-forensic metodama, neophodno je:

- **Sprovesti detaljnu analizu vremenske linije** pomoću alata kao što je **Autopsy** za vizuelizaciju vremenskih linija događaja ili `mactime` alata **Sleuth Kit-a** za detaljne podatke vremenske linije.
- **Istražiti neočekivane skripte** u sistemskom $PATH-u, koje mogu obuhvatati shell ili PHP skripte koje koriste napadači.
- **Pregledati `/dev` u potrazi za atipičnim datotekama**, pošto se u njemu tradicionalno nalaze posebne datoteke, ali može sadržati i datoteke povezane sa malverom.
- **Potražiti skrivene datoteke ili direktorijume** sa imenima poput ".. " (tačka tačka razmak) ili "..^G" (tačka tačka control-G), koji mogu skrivati zlonamerni sadržaj.
- **Identifikovati setuid root datoteke** pomoću komande: `find / -user root -perm -04000 -print` Ova komanda pronalazi datoteke sa povišenim dozvolama, koje bi napadači mogli zloupotrebiti.
- **Pregledati vremenske oznake brisanja** u inode tabelama kako bi se uočila masovna brisanja datoteka, što može ukazivati na prisustvo rootkit-a ili trojanaca.
- **Pregledati uzastopne inode-ove** u potrazi za obližnjim zlonamernim datotekama nakon identifikovanja jedne takve datoteke, jer su možda postavljene zajedno.
- **Proveriti uobičajene binarne direktorijume** (_/bin_, _/sbin_) u potrazi za nedavno izmenjenim datotekama, jer ih je možda izmenio malver.
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
> [!TIP]
> Imajte na umu da **napadač** može da **izmeni** **vreme** kako bi **datoteke izgledale** **legitimno**, ali ne može da izmeni **inode**. Ako utvrdite da **datoteka** pokazuje da je kreirana i izmenjena u **isto vreme** kao i ostale datoteke u istoj fascikli, ali da je **inode** **neočekivano veći**, onda su **vremenske oznake te datoteke izmenjene**.

### Brza trijaža usmerena na inode

Ako sumnjate na anti-forensics, rano pokrenite ove provere usmerene na inode:
```bash
# Filesystem inode pressure (possible inode exhaustion DoS)
df -i

# Identify all names that point to one inode
find / -xdev -inum <inode_number> 2>/dev/null

# Find deleted files still open by running processes
lsof +L1
lsof | grep '(deleted)'
```
Kada se sumnjivi inode nalazi na slici/uređaju EXT sistema datoteka, direktno pregledajte metapodatke inode-a:
```bash
sudo debugfs -R "stat <inode_number>" /dev/sdX
```
Korisna polja:
- **Links**: ako je `0`, nijedan direktorijumski unos trenutno ne referencira inode.
- **dtime**: vremenska oznaka brisanja postavljena kada je inode uklonjen.
- **ctime/mtime**: pomaže pri korelaciji promena metapodataka/sadržaja sa vremenskom linijom incidenta.

### Capabilities, xattrs i preload-based userland rootkits

Moderna Linux persistence često izbegava očigledne **setuid** binarne datoteke i umesto toga zloupotrebljava **file capabilities**, **extended attributes** i dinamički učitavač.
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
Posebnu pažnju obratite na biblioteke na koje se referencira iz **writable** putanja kao što su `/tmp`, `/dev/shm`, `/var/tmp` ili neobičnih lokacija unutar `/usr/local/lib`. Takođe proverite binarne datoteke sa capabilities izvan uobičajenog vlasništva paketa i uporedite ih sa rezultatima verifikacije paketa (`rpm -Va`, `dpkg --verify`, `debsums`).

## Poređenje različitih verzija filesystema

### Sažetak poređenja verzija filesystema

Za poređenje verzija filesystema i precizno utvrđivanje izmena koristimo pojednostavljene `git diff` komande:<sup>[[3]](#references)</sup>

- **Za pronalaženje novih datoteka**, uporedite dva direktorijuma:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
- **Za izmenjeni sadržaj**, navedite promene zanemarujući određene redove:
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
- **Za otkrivanje obrisanih datoteka**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
- **Opcije filtera** (`--diff-filter`) pomažu da se suzi izbor na određene promene, kao što su dodati (`A`), obrisani (`D`) ili izmenjeni (`M`) fajlovi.
- `A`: Dodati fajlovi
- `C`: Kopirani fajlovi
- `D`: Obrisani fajlovi
- `M`: Izmenjeni fajlovi
- `R`: Preimenovani fajlovi
- `T`: Promene tipa (npr. fajl u symlink)
- `U`: Nerešeni fajlovi
- `X`: Nepoznati fajlovi
- `B`: Oštećeni fajlovi

## References

- [1] [Vodič za forenzičku analizu malvera za Linux sisteme: Vodiči za digitalnu forenziku – Poglavlje 3](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf)
- [2] [Objašnjenje Linux logova](https://www.plesk.com/blog/featured/linux-logs-explained/)
- [3] [git diff dokumentacija – opcija --diff-filter](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
- [4] [Red Canary – Zakrpavanje radi persistence: Kako se Linux malware DripDropper kreće kroz cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [5] [Forenzička analiza Linux Journals](https://stuxnet999.github.io/dfir/linux-journal-forensics/)
- [6] [Red Hat Enterprise Linux 9 – Auditing sistema](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening)
- [7] [Pozdrav, Pike!](https://www.synacktiv.com/en/publications/say-hi-to-pike.html)
- [8] [strace](https://strace.io/)
- [9] [SQLite FTS5 ekstenzija](https://www.sqlite.org/fts5.html)
{{#include ../../banners/hacktricks-training.md}}
