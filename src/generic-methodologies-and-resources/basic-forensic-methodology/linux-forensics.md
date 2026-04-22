# Linux Forensics

{{#include ../../banners/hacktricks-training.md}}

## Početno prikupljanje informacija

### Osnovne informacije

Pre svega, preporučuje se da imate neki **USB** sa **dobro poznatim binarnim fajlovima i bibliotekama na njemu** (možete jednostavno uzeti ubuntu i kopirati foldere _/bin_, _/sbin_, _/lib,_ i _/lib64_), zatim montirati USB i izmeniti env promenljive da biste koristili te binarne fajlove:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
Kada podesite sistem da koristi dobre i poznate binarne fajlove, možete početi sa **izdvajanjem nekih osnovnih informacija**:
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

Da biste dobili memoriju sistema koji je pokrenut, preporučuje se da koristite [**LiME**](https://github.com/504ensicsLabs/LiME).\
Da biste ga **kompajlirali**, morate koristiti **isti kernel** koji koristi žrtvina mašina.

> [!TIP]
> Zapamtite da **ne možete instalirati LiME ili bilo šta drugo** na žrtvinu mašinu jer će to napraviti nekoliko promena na njoj

Dakle, ako imate identičnu verziju Ubuntua, možete koristiti `apt-get install lime-forensics-dkms`\
U drugim slučajevima, potrebno je da preuzmete [**LiME**](https://github.com/504ensicsLabs/LiME) sa github-a i kompajlirate ga sa odgovarajućim kernel header-ima. Da biste **dobili tačne kernel header-e** žrtvine mašine, možete jednostavno **kopirati direktorijum** `/lib/modules/<kernel version>` na svoju mašinu, a zatim **kompajlirati** LiME koristeći ih:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME podržava 3 **formata**:

- Raw (svaki segment spojen zajedno)
- Padded (isto kao raw, ali sa nulama u desnim bitovima)
- Lime (preporučeni format sa metapodacima)

LiME se takođe može koristiti za **slanje dump-a preko mreže** umesto da se čuva na sistemu koristeći nešto poput: `path=tcp:4444`

### Disk Imaging

#### Shutting down

Pre svega, moraćete da **ugasite sistem**. Ovo nije uvek opcija jer ponekad sistem može biti produkcioni server koji kompanija ne može da priušti da ugasi.\
Postoje **2 načina** gašenja sistema, **normalno gašenje** i **"plug the plug" gašenje**. Prvi će omogućiti da se **procesi završe kao i obično** i da se **filesystem** **sinhronizuje**, ali će takođe omogućiti mogućem **malware-u** da **uništi dokaze**. Pristup "pull the plug" može da dovede do **nekog gubitka informacija** (neće se mnogo informacija izgubiti jer smo već napravili image memorije) i **malware** neće imati nikakvu priliku da bilo šta uradi povodom toga. Zato, ako **sumnjate** da postoji **malware**, samo izvršite **`sync`** **command** na sistemu i izvucite utikač.

#### Taking an image of the disk

Važno je napomenuti da **pre nego što povežete svoj računar sa bilo čim što je povezano sa slučajem**, morate biti sigurni da će biti **mount-ovan kao read only** kako biste izbegli menjanje bilo kakvih informacija.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Predanaliza disk image

Kreiranje disk image-a bez dodatnih podataka.
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

Linux nudi alate za obezbeđivanje integriteta sistemskih komponenti, što je ključno za uočavanje potencijalno problematičnih datoteka.

- **RedHat-based sistemi**: Koristite `rpm -Va` za sveobuhvatnu proveru.
- **Debian-based sistemi**: `dpkg --verify` za početnu verifikaciju, zatim `debsums | grep -v "OK$"` (nakon instalacije `debsums` pomoću `apt-get install debsums`) da biste identifikovali eventualne probleme.

### Detektori malware-a/rootkit-a

Pročitajte sledeću stranicu da biste naučili o alatima koji mogu biti korisni za pronalaženje malware-a:


{{#ref}}
malware-analysis.md
{{#endref}}

## Pretraga instaliranih programa

Da biste efikasno pretražili instalirane programe na Debian i RedHat sistemima, razmotrite korišćenje sistemskih logova i baza podataka, zajedno sa ručnim proverama u uobičajenim direktorijumima.

- Za Debian, proverite _**`/var/lib/dpkg/status`**_ i _**`/var/log/dpkg.log`**_ da biste dobili detalje o instalacijama paketa, koristeći `grep` za filtriranje određenih informacija.
- RedHat korisnici mogu da upitaju RPM bazu podataka sa `rpm -qa --root=/mntpath/var/lib/rpm` da bi prikazali instalirane pakete.

Da biste otkrili softver instaliran ručno ili van ovih package manager-a, pregledajte direktorijume kao što su _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_, i _**`/sbin`**_. Kombinujte listanje direktorijuma sa sistemskim komandama specifičnim za sistem kako biste identifikovali izvršne fajlove koji nisu povezani sa poznatim paketima, čime poboljšavate pretragu svih instaliranih programa.
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
## Oporavak obrisanih pokrenutih binarnih fajlova

Zamislite proces koji je izvršen iz /tmp/exec i zatim obrisan. Moguće je izdvojiti ga
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
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
Napadači često menjaju 0anacron stub prisutan u svakom /etc/cron.*/ direktorijumu kako bi obezbedili periodično izvršavanje.
```bash
# List 0anacron files and their timestamps/sizes
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done

# Look for obvious execution of shells or downloaders embedded in cron stubs
grep -R --line-number -E 'curl|wget|/bin/sh|python|bash -c' /etc/cron.*/* 2>/dev/null
```
#### Lov: rollback SSH hardening i backdoor shell-ovi
Promene u sshd_config i shell-ovima sistemskih naloga su česte posle eksploatacije radi očuvanja pristupa.
```bash
# Root login enablement (flag "yes" or lax values)
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config

# System accounts with interactive shells (e.g., games → /bin/sh)
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
#### Lov: Cloud C2 markeri (Dropbox/Cloudflare Tunnel)
- Dropbox API beaconi tipično koriste api.dropboxapi.com ili content.dropboxapi.com preko HTTPS sa Authorization: Bearer tokenima.
- Lovite u proxy/Zeek/NetFlow za neočekivani Dropbox egress sa servera.
- Cloudflare Tunnel (`cloudflared`) obezbeđuje backup C2 preko outbound 443.
```bash
ps aux | grep -E '[c]loudflared|trycloudflare'
systemctl list-units | grep -i cloudflared
```
### Services

Putanje gde malware može biti instaliran kao service:

- **/etc/inittab**: Poziva inicijalizacione skripte kao što je rc.sysinit, usmeravajući dalje ka startup skriptama.
- **/etc/rc.d/** i **/etc/rc.boot/**: Sadrže skripte za pokretanje servisa, pri čemu se ovo drugo nalazi u starijim Linux verzijama.
- **/etc/init.d/**: Koristi se u određenim Linux verzijama kao što je Debian za čuvanje startup skripti.
- Servisi se takođe mogu aktivirati preko **/etc/inetd.conf** ili **/etc/xinetd/**, u zavisnosti od Linux varijante.
- **/etc/systemd/system**: Direktorijum za skripte sistema i service managera.
- **/etc/systemd/system/multi-user.target.wants/**: Sadrži linkove ka servisima koji treba da se pokrenu u multi-user runlevel-u.
- **/usr/local/etc/rc.d/**: Za custom ili third-party servise.
- **\~/.config/autostart/**: Za aplikacije sa automatskim pokretanjem specifične za korisnika, što može biti mesto za skriveni malware usmeren na korisnika.
- **/lib/systemd/system/**: System-wide default unit fajlovi koje obezbeđuju instalirani paketi.

#### Hunt: systemd timers and transient units

Systemd persistence nije ograničen na `.service` fajlove. Istražite `.timer` unit-e, user-level unit-e i **transient units** kreirane tokom runtime-a.
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
Transient units su lako propuštaju jer je `/run/systemd/transient/` **non-persistent**. Ako prikupljate live image, uzmite ga pre gašenja.

### Kernel Modules

Linux kernel modules, često korišćeni od strane malware-a kao rootkit komponente, učitavaju se pri system boot-u. Direktorijumi i fajlovi kritični za ove module uključuju:

- **/lib/modules/$(uname -r)**: Sadrži modules za verziju kernel-a koja je u radu.
- **/etc/modprobe.d**: Sadrži config fajlove za kontrolu učitavanja module-a.
- **/etc/modprobe** i **/etc/modprobe.conf**: Fajlovi za globalna module podešavanja.

### Other Autostart Locations

Linux koristi razne fajlove za automatsko izvršavanje programa pri korisničkom login-u, što može skrivati malware:

- **/etc/profile.d/**\*, **/etc/profile**, i **/etc/bash.bashrc**: Izvršavaju se za bilo koji user login.
- **\~/.bashrc**, **\~/.bash_profile**, **\~/.profile**, i **\~/.config/autostart**: User-specific fajlovi koji se izvršavaju pri njihovom login-u.
- **/etc/rc.local**: Pokreće se nakon što su svi system services startovani, označavajući kraj prelaska u multiuser okruženje.

## Examine Logs

Linux sistemi prate korisničke aktivnosti i system događaje kroz različite log fajlove. Ovi logovi su ključni za identifikaciju neovlašćenog pristupa, malware infekcija i drugih security incidenata. Ključni log fajlovi uključuju:

- **/var/log/syslog** (Debian) ili **/var/log/messages** (RedHat): Hvataju system-wide poruke i aktivnosti.
- **/var/log/auth.log** (Debian) ili **/var/log/secure** (RedHat): Beleže authentication pokušaje, uspešne i neuspešne logins.
- Koristite `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` da filtrirate relevantne authentication događaje.
- **/var/log/boot.log**: Sadrži poruke pri system startup-u.
- **/var/log/maillog** ili **/var/log/mail.log**: Loguju aktivnosti email servera, korisno za praćenje email-related servisa.
- **/var/log/kern.log**: Čuva kernel poruke, uključujući greške i upozorenja.
- **/var/log/dmesg**: Čuva device driver poruke.
- **/var/log/faillog**: Beleži neuspešne login pokušaje, pomažući u istragama security breach-a.
- **/var/log/cron**: Loguje cron job izvršavanja.
- **/var/log/daemon.log**: Prati aktivnosti background servisa.
- **/var/log/btmp**: Dokumentuje neuspešne login pokušaje.
- **/var/log/httpd/**: Sadrži Apache HTTPD error i access logove.
- **/var/log/mysqld.log** ili **/var/log/mysql.log**: Loguju aktivnosti MySQL baze podataka.
- **/var/log/xferlog**: Beleži FTP file transfer-e.
- **/var/log/**: Uvek proverite da li ovde postoje neočekivani logovi.

> [!TIP]
> Linux system logovi i audit subsystems mogu biti onemogućeni ili obrisani tokom intrusion ili malware incidenta. Pošto logovi na Linux sistemima generalno sadrže neke od najkorisnijih informacija o zlonamernim aktivnostima, intruders ih rutinski brišu. Zato je pri pregledanju dostupnih log fajlova važno tražiti praznine ili unose van redosleda, što može ukazivati na brisanje ili tampering.

### Journald triage (`journalctl`)

Na modernim Linux hostovima, **systemd journal** je obično najvredniji izvor za **service execution**, **auth events**, **package operations**, i **kernel/user-space messages**. Tokom live response-a, pokušajte da sačuvate i **persistent** journal (`/var/log/journal/`) i **runtime** journal (`/run/log/journal/`) jer kratkotrajna attacker aktivnost može postojati samo u ovom drugom.
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
Korisna polja journala za trijažu uključuju `_SYSTEMD_UNIT`, `_EXE`, `_COMM`, `_CMDLINE`, `_UID`, `_GID`, `_PID`, `_BOOT_ID` i `MESSAGE`. Ako je `journald` bio konfigurisan bez persistent storage, očekujte samo nedavne podatke u `/run/log/journal/`.

### Audit framework trijaža (`auditd`)

Ako je `auditd` omogućen, dajte mu prednost kad god vam treba **process attribution** za promene fajlova, izvršavanje komandi, login aktivnost ili instalaciju paketa.
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
Kada su pravila raspoređena sa ključevima, pivotiraj sa njih umesto da pretražuješ raw logove:
```bash
ausearch --start this-week -k <rule_key> --raw | aureport --file --summary -i
ausearch --start this-week -k <rule_key> --raw | aureport --user --summary -i
```
**Linux održava istoriju komandi za svakog korisnika**, čuvanu u:

- \~/.bash_history
- \~/.zsh_history
- \~/.zsh_sessions/\*
- \~/.python_history
- \~/.\*\_history

Pored toga, komanda `last -Faiwx` daje listu korisničkih prijavljivanja. Proverite je zbog nepoznatih ili neočekivanih prijavljivanja.

Proverite fajlove koji mogu da daju dodatne rprivileges:

- Pregledajte `/etc/sudoers` zbog neočekivanih korisničkih privilegija koje su možda dodeljene.
- Pregledajte `/etc/sudoers.d/` zbog neočekivanih korisničkih privilegija koje su možda dodeljene.
- Ispitajte `/etc/groups` da biste identifikovali neuobičajena članstva u grupama ili dozvole.
- Ispitajte `/etc/passwd` da biste identifikovali neuobičajena članstva u grupama ili dozvole.

Neke aplikacije takođe generišu sopstvene logove:

- **SSH**: Ispitajte _\~/.ssh/authorized_keys_ i _\~/.ssh/known_hosts_ zbog neovlašćenih udaljenih konekcija.
- **Gnome Desktop**: Pogledajte _\~/.recently-used.xbel_ za nedavno pristupane fajlove putem Gnome aplikacija.
- **Firefox/Chrome**: Proverite istoriju pregledača i preuzimanja u _\~/.mozilla/firefox_ ili _\~/.config/google-chrome_ zbog sumnjivih aktivnosti.
- **VIM**: Pregledajte _\~/.viminfo_ za detalje o upotrebi, kao što su putanje do pristupanih fajlova i istorija pretrage.
- **Open Office**: Proverite nedavni pristup dokumentima koji može ukazivati na kompromitovane fajlove.
- **FTP/SFTP**: Pregledajte logove u _\~/.ftp_history_ ili _\~/.sftp_history_ za prenos fajlova koji bi mogli biti neovlašćeni.
- **MySQL**: Ispitajte _\~/.mysql_history_ za izvršene MySQL upite, što potencijalno otkriva neovlašćene aktivnosti nad bazom podataka.
- **Less**: Analizirajte _\~/.lesshst_ za istoriju upotrebe, uključujući pregledane fajlove i izvršene komande.
- **Git**: Pregledajte _\~/.gitconfig_ i project _.git/logs_ zbog promena u repozitorijumima.

### USB Logs

[**usbrip**](https://github.com/snovvcrash/usbrip) je mali komad softvera napisan u čistom Pythonu 3 koji parsira Linux log fajlove (`/var/log/syslog*` ili `/var/log/messages*` u zavisnosti od distroa) radi pravljenja tabela istorije USB događaja.

Zanimljivo je **znati sve USB uređaje koji su korišćeni** i biće korisnije ako imate autorizovanu listu USB uređaja kako biste pronašli "violation events" (upotrebu USB uređaja koji nisu na toj listi).

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
Više primera i informacija na github-u: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

## Pregled korisničkih naloga i aktivnosti prijavljivanja

Pregledajte _**/etc/passwd**_, _**/etc/shadow**_ i **security logs** za neuobičajena imena ili naloge kreirane i/ili korišćene u neposrednoj blizini poznatih neovlašćenih događaja. Takođe, proverite moguće sudo brute-force napade.\
Takođe, proverite fajlove kao što su _**/etc/sudoers**_ i _**/etc/groups**_ za neočekivane privilegije dodeljene korisnicima.\
Na kraju, potražite naloge sa **bez lozinki** ili **lako pogađivim** lozinkama.

## Ispitajte fajl sistem

### Analiza struktura fajl sistema u istrazi malware-a

Prilikom istrage incidenata sa malware-om, struktura fajl sistema je ključni izvor informacija, jer otkriva i niz događaja i sadržaj malware-a. Međutim, autori malware-a razvijaju tehnike za otežavanje ove analize, kao što su izmena vremenskih oznaka fajlova ili izbegavanje fajl sistema za skladištenje podataka.

Da bi se suprotstavilo ovim anti-forenzičkim metodama, neophodno je:

- **Sprovesti temeljnu analizu vremenske linije** koristeći alate kao što je **Autopsy** za vizuelizaciju vremenskih linija događaja ili **Sleuth Kit's** `mactime` za detaljne podatke o vremenskoj liniji.
- **Istražiti neočekivane skripte** u sistemskom $PATH-u, koje mogu uključivati shell ili PHP skripte koje koriste napadači.
- **Pregledati `/dev` za atipične fajlove**, jer tradicionalno sadrži posebne fajlove, ali može da sadrži i fajlove povezane sa malware-om.
- **Tražiti skrivene fajlove ili direktorijume** sa imenima poput ".. " (tačka tačka razmak) ili "..^G" (tačka tačka kontrola-G), koji mogu da sakriju zlonamerni sadržaj.
- **Identifikovati setuid root fajlove** koristeći komandu: `find / -user root -perm -04000 -print` Ovo pronalazi fajlove sa povišenim privilegijama, koje napadači mogu zloupotrebiti.
- **Pregledati vremenske oznake brisanja** u inode tabelama da bi se uočila masovna brisanja fajlova, što može ukazivati na prisustvo rootkits ili trojanaca.
- **Ispitati uzastopne inodes** za obližnje zlonamerne fajlove nakon identifikacije jednog, jer su možda postavljeni zajedno.
- **Proveriti uobičajene binarne direktorijume** (_/bin_, _/sbin_) za nedavno izmenjene fajlove, jer bi malware mogao da ih izmeni.
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
> [!TIP]
> Imajte na umu da **napadač** može da **izmeni** **vreme** kako bi **fajlovi izgledali** **legitimno**, ali ne može da izmeni **inode**. Ako utvrdite da **fajl** pokazuje da je kreiran i izmenjen u **isto vreme** kao i ostali fajlovi u istoj fascikli, ali je **inode** neočekivano veći, onda su **timestamps** tog fajla bili izmenjeni.

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
Kada je sumnjiv inode na EXT filesystem image/device, proveri inode metadata direktno:
```bash
sudo debugfs -R "stat <inode_number>" /dev/sdX
```
Корисна поља:
- **Links**: ако је `0`, ниједан унос у директоријуму тренутно не референцира inode.
- **dtime**: timestamp брисања постављен када је inode unlinked.
- **ctime/mtime**: помаже у корелацији промена метаподатака/садржаја са временском линијом инцидента.

### Capabilities, xattrs, and preload-based userland rootkits

Савремена Linux persistence често избегава очигледне `setuid` binaries и уместо тога злоупотребљава **file capabilities**, **extended attributes**, и dynamic loader.
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
Obratite posebnu pažnju na biblioteke na koje se referencira iz **writable** putanja kao što su `/tmp`, `/dev/shm`, `/var/tmp`, ili čudnih lokacija pod `/usr/local/lib`. Takođe proverite binaries sa capability-ima van normalnog vlasništva paketa i povežite ih sa rezultatima provere paketa (`rpm -Va`, `dpkg --verify`, `debsums`).

## Uporedite fajlove različitih verzija filesystem-a

### Sažetak poređenja verzija filesystem-a

Da biste uporedili verzije filesystem-a i precizno identifikovali promene, koristimo pojednostavljene `git diff` komande:

- **Da biste pronašli nove fajlove**, uporedite dva direktorijuma:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
- **Za izmenjeni sadržaj**, navedite promene uz ignorisanje određenih linija:
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
- **Za detekciju obrisanih fajlova**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
- **Filter options** (`--diff-filter`) pomažu da se suzi izbor na konkretne izmene kao što su dodate (`A`), obrisane (`D`) ili izmenjene (`M`) datoteke.
- `A`: Dodate datoteke
- `C`: Kopirane datoteke
- `D`: Obrisane datoteke
- `M`: Izmenjene datoteke
- `R`: Preimenovane datoteke
- `T`: Promene tipa (npr. file u symlink)
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

{{#include ../../banners/hacktricks-training.md}}
