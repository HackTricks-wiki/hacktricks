# Linux Forensics

{{#include ../../banners/hacktricks-training.md}}

## Početno prikupljanje informacija

### Osnovne informacije

Prvo, preporučuje se da imate neki **USB** sa **dobro poznatim binarnim datotekama i bibliotekama** (možete jednostavno preuzeti ubuntu i kopirati foldere _/bin_, _/sbin_, _/lib,_ i _/lib64_), zatim montirajte USB i modifikujte env varijable da koristite te binarne datoteke:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
Kada konfigurišete sistem da koristi dobre i poznate binarne datoteke, možete početi sa **ekstrakcijom osnovnih informacija**:
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

Dok prikupljate osnovne informacije, trebali biste proveriti čudne stvari kao što su:

- **Root procesi** obično se pokreću sa niskim PIDS, pa ako pronađete root proces sa velikim PID-om, možete posumnjati
- Proverite **registrovane prijave** korisnika bez shel-a unutar `/etc/passwd`
- Proverite **hash-eve lozinke** unutar `/etc/shadow` za korisnike bez shel-a

### Dump memorije

Da biste dobili memoriju pokrenutog sistema, preporučuje se korišćenje [**LiME**](https://github.com/504ensicsLabs/LiME).\
Da biste ga **kompajlirali**, morate koristiti **isti kernel** koji koristi žrtvinska mašina.

> [!NOTE]
> Zapamtite da **ne možete instalirati LiME ili bilo šta drugo** na žrtvinskoj mašini jer će to napraviti nekoliko promena na njoj

Dakle, ako imate identičnu verziju Ubuntua, možete koristiti `apt-get install lime-forensics-dkms`\
U drugim slučajevima, potrebno je preuzeti [**LiME**](https://github.com/504ensicsLabs/LiME) sa github-a i kompajlirati ga sa ispravnim kernel header-ima. Da biste **dobili tačne kernel header-e** žrtvinske mašine, možete jednostavno **kopirati direktorijum** `/lib/modules/<kernel version>` na vašu mašinu, a zatim **kompajlirati** LiME koristeći ih:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME podržava 3 **formata**:

- Raw (svaki segment spojен zajedno)
- Padded (isto kao raw, ali sa nulama u desnim bitovima)
- Lime (preporučeni format sa metapodacima)

LiME se takođe može koristiti za **slanje dump-a putem mreže** umesto da se čuva na sistemu koristeći nešto poput: `path=tcp:4444`

### Disk Imaging

#### Isključivanje

Prvo, potrebno je da **isključite sistem**. Ovo nije uvek opcija jer ponekad sistem može biti produkcijski server koji kompanija ne može priuštiti da isključi.\
Postoje **2 načina** za isključivanje sistema, **normalno isključivanje** i **"isključi kabl" isključivanje**. Prvi će omogućiti da se **procesi završe kao obično** i da se **fajl sistem** **sinhronizuje**, ali će takođe omogućiti mogućem **malware-u** da **uništi dokaze**. Pristup "isključi kabl" može doneti **neke gubitke informacija** (neće se mnogo informacija izgubiti jer smo već uzeli sliku memorije) i **malware neće imati priliku** da uradi bilo šta povodom toga. Stoga, ako **sumnjate** da može biti **malware**, jednostavno izvršite **`sync`** **komandu** na sistemu i isključite kabl.

#### Uzimanje slike diska

Važno je napomenuti da **pre nego što povežete svoj računar sa bilo čim vezanim za slučaj**, morate biti sigurni da će biti **montiran kao samo za čitanje** kako biste izbegli modifikaciju bilo kojih informacija.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Disk Image pre-analysis

Imaging disk slike bez dodatnih podataka.
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
## Pretraga poznatog Malware-a

### Izmenjeni sistemski fajlovi

Linux nudi alate za osiguranje integriteta sistemskih komponenti, što je ključno za uočavanje potencijalno problematičnih fajlova.

- **RedHat-bazirani sistemi**: Koristite `rpm -Va` za sveobuhvatnu proveru.
- **Debian-bazirani sistemi**: `dpkg --verify` za inicijalnu verifikaciju, a zatim `debsums | grep -v "OK$"` (nakon instalacije `debsums` sa `apt-get install debsums`) za identifikaciju bilo kakvih problema.

### Malware/Rootkit detektori

Pročitajte sledeću stranicu da biste saznali o alatima koji mogu biti korisni za pronalaženje malware-a:

{{#ref}}
malware-analysis.md
{{#endref}}

## Pretraga instaliranih programa

Da biste efikasno pretražili instalirane programe na Debian i RedHat sistemima, razmotrite korišćenje sistemskih logova i baza podataka zajedno sa ručnim proverama u uobičajenim direktorijumima.

- Za Debian, proverite _**`/var/lib/dpkg/status`**_ i _**`/var/log/dpkg.log`**_ da biste dobili detalje o instalacijama paketa, koristeći `grep` za filtriranje specifičnih informacija.
- RedHat korisnici mogu upititi RPM bazu podataka sa `rpm -qa --root=/mntpath/var/lib/rpm` da bi prikazali instalirane pakete.

Da biste otkrili softver instaliran ručno ili van ovih menadžera paketa, istražite direktorijume kao što su _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_, i _**`/sbin`**_. Kombinujte liste direktorijuma sa sistemskim komandama kako biste identifikovali izvršne fajlove koji nisu povezani sa poznatim paketima, čime poboljšavate pretragu za svim instaliranim programima.
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
## Oporavak Izbrisanih Pokrenutih Binarnih Fajlova

Zamislite proces koji je izvršen iz /tmp/exec i zatim obrisan. Moguće je da se izvuče.
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## Inspekcija lokacija za automatsko pokretanje

### Zakazani zadaci
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
### Usluge

Putanje gde se zlonamerni softver može instalirati kao usluga:

- **/etc/inittab**: Poziva skripte inicijalizacije kao što su rc.sysinit, usmeravajući dalje na skripte za pokretanje.
- **/etc/rc.d/** i **/etc/rc.boot/**: Sadrže skripte za pokretanje usluga, pri čemu se potonja nalazi u starijim verzijama Linux-a.
- **/etc/init.d/**: Koristi se u određenim verzijama Linux-a kao što je Debian za čuvanje skripti za pokretanje.
- Usluge se takođe mogu aktivirati putem **/etc/inetd.conf** ili **/etc/xinetd/**, u zavisnosti od varijante Linux-a.
- **/etc/systemd/system**: Direktorijum za skripte menadžera sistema i usluga.
- **/etc/systemd/system/multi-user.target.wants/**: Sadrži linkove do usluga koje treba pokrenuti u višekorisničkom režimu.
- **/usr/local/etc/rc.d/**: Za prilagođene ili usluge trećih strana.
- **\~/.config/autostart/**: Za automatske aplikacije specifične za korisnika, koje mogu biti skriveno mesto za zlonamerni softver usmeren na korisnike.
- **/lib/systemd/system/**: Podrazumevane jedinice sistema koje obezbeđuju instalirani paketi.

### Kernel moduli

Linux kernel moduli, često korišćeni od strane zlonamernog softvera kao komponenti rootkita, učitavaju se prilikom pokretanja sistema. Direktorijumi i datoteke kritične za ove module uključuju:

- **/lib/modules/$(uname -r)**: Sadrži module za trenutnu verziju kernela.
- **/etc/modprobe.d**: Sadrži konfiguracione datoteke za kontrolu učitavanja modula.
- **/etc/modprobe** i **/etc/modprobe.conf**: Datoteke za globalne postavke modula.

### Druge lokacije za automatsko pokretanje

Linux koristi razne datoteke za automatsko izvršavanje programa prilikom prijavljivanja korisnika, potencijalno skrivajući zlonamerni softver:

- **/etc/profile.d/**\*, **/etc/profile**, i **/etc/bash.bashrc**: Izvršavaju se za bilo koju prijavu korisnika.
- **\~/.bashrc**, **\~/.bash_profile**, **\~/.profile**, i **\~/.config/autostart**: Datoteke specifične za korisnika koje se pokreću prilikom njihove prijave.
- **/etc/rc.local**: Izvršava se nakon što su sve sistemske usluge pokrenute, označavajući kraj prelaska na višekorisničko okruženje.

## Istraži logove

Linux sistemi prate aktivnosti korisnika i događaje sistema kroz razne log datoteke. Ovi logovi su ključni za identifikaciju neovlašćenog pristupa, infekcija zlonamernim softverom i drugih bezbednosnih incidenata. Ključne log datoteke uključuju:

- **/var/log/syslog** (Debian) ili **/var/log/messages** (RedHat): Zabeležavaju poruke i aktivnosti širom sistema.
- **/var/log/auth.log** (Debian) ili **/var/log/secure** (RedHat): Beleže pokušaje autentifikacije, uspešne i neuspešne prijave.
- Koristite `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` za filtriranje relevantnih događaja autentifikacije.
- **/var/log/boot.log**: Sadrži poruke o pokretanju sistema.
- **/var/log/maillog** ili **/var/log/mail.log**: Logovi aktivnosti email servera, korisni za praćenje usluga vezanih za email.
- **/var/log/kern.log**: Čuva poruke kernela, uključujući greške i upozorenja.
- **/var/log/dmesg**: Sadrži poruke drajvera uređaja.
- **/var/log/faillog**: Beleži neuspešne pokušaje prijave, pomažući u istragama bezbednosnih proboja.
- **/var/log/cron**: Logovi izvršavanja cron poslova.
- **/var/log/daemon.log**: Prati aktivnosti pozadinskih usluga.
- **/var/log/btmp**: Dokumentuje neuspešne pokušaje prijave.
- **/var/log/httpd/**: Sadrži Apache HTTPD greške i logove pristupa.
- **/var/log/mysqld.log** ili **/var/log/mysql.log**: Logovi aktivnosti MySQL baze podataka.
- **/var/log/xferlog**: Beleži FTP prenose datoteka.
- **/var/log/**: Uvek proverite za neočekivane logove ovde.

> [!NOTE]
> Linux sistemski logovi i audit pod-sistemi mogu biti onemogućeni ili obrisani tokom upada ili incidenta sa zlonamernim softverom. Pošto logovi na Linux sistemima obično sadrže neke od najkorisnijih informacija o zlonamernim aktivnostima, napadači ih rutinski brišu. Stoga, prilikom ispitivanja dostupnih log datoteka, važno je tražiti praznine ili neuredne unose koji bi mogli biti indikacija brisanja ili manipulacije.

**Linux održava istoriju komandi za svakog korisnika**, koja se čuva u:

- \~/.bash_history
- \~/.zsh_history
- \~/.zsh_sessions/\*
- \~/.python_history
- \~/.\*\_history

Pored toga, komanda `last -Faiwx` pruža listu prijava korisnika. Proverite je za nepoznate ili neočekivane prijave.

Proverite datoteke koje mogu dodeliti dodatne privilegije:

- Pregledajte `/etc/sudoers` za neočekivane privilegije korisnika koje su možda dodeljene.
- Pregledajte `/etc/sudoers.d/` za neočekivane privilegije korisnika koje su možda dodeljene.
- Istražite `/etc/groups` da identifikujete bilo kakva neobična članstva u grupama ili dozvole.
- Istražite `/etc/passwd` da identifikujete bilo kakva neobična članstva u grupama ili dozvole.

Neke aplikacije takođe generišu svoje logove:

- **SSH**: Istražite _\~/.ssh/authorized_keys_ i _\~/.ssh/known_hosts_ za neovlašćene udaljene konekcije.
- **Gnome Desktop**: Pogledajte _\~/.recently-used.xbel_ za nedavno pristupane datoteke putem Gnome aplikacija.
- **Firefox/Chrome**: Proverite istoriju pretraživača i preuzimanja u _\~/.mozilla/firefox_ ili _\~/.config/google-chrome_ za sumnjive aktivnosti.
- **VIM**: Pregledajte _\~/.viminfo_ za detalje o korišćenju, kao što su pristupane putanje datoteka i istorija pretrage.
- **Open Office**: Proverite za nedavni pristup dokumentima koji mogu ukazivati na kompromitovane datoteke.
- **FTP/SFTP**: Pregledajte logove u _\~/.ftp_history_ ili _\~/.sftp_history_ za prenose datoteka koji bi mogli biti neovlašćeni.
- **MySQL**: Istražite _\~/.mysql_history_ za izvršene MySQL upite, što može otkriti neovlašćene aktivnosti u bazi podataka.
- **Less**: Analizirajte _\~/.lesshst_ za istoriju korišćenja, uključujući pregledane datoteke i izvršene komande.
- **Git**: Istražite _\~/.gitconfig_ i projekat _.git/logs_ za promene u repozitorijumima.

### USB logovi

[**usbrip**](https://github.com/snovvcrash/usbrip) je mali komad softvera napisan u čistom Python 3 koji analizira Linux log datoteke (`/var/log/syslog*` ili `/var/log/messages*` u zavisnosti od distribucije) za konstruisanje tabela istorije događaja USB-a.

Zanimljivo je **znati sve USB uređaje koji su korišćeni** i biće korisnije ako imate ovlašćenu listu USB uređaja da pronađete "događaje kršenja" (korišćenje USB uređaja koji nisu na toj listi).

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
Više primera i informacija unutar github-a: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

## Pregled korisničkih naloga i aktivnosti prijavljivanja

Istražite _**/etc/passwd**_, _**/etc/shadow**_ i **bezbednosne logove** za neobična imena ili naloge koji su kreirani i ili korišćeni u bliskoj blizini poznatih neovlašćenih događaja. Takođe, proverite moguće sudo brute-force napade.\
Pored toga, proverite datoteke kao što su _**/etc/sudoers**_ i _**/etc/groups**_ za neočekivane privilegije dodeljene korisnicima.\
Na kraju, potražite naloge sa **bez lozinki** ili **lako pogađanim** lozinkama.

## Istraživanje fajl sistema

### Analiza struktura fajl sistema u istraživanju malvera

Kada istražujete incidente sa malverom, struktura fajl sistema je ključni izvor informacija, otkrivajući kako redosled događaja tako i sadržaj malvera. Međutim, autori malvera razvijaju tehnike za ometanje ove analize, kao što su modifikovanje vremenskih oznaka fajlova ili izbegavanje fajl sistema za skladištenje podataka.

Da biste se suprotstavili ovim anti-forenzičkim metodama, važno je:

- **Sprovesti temeljnu analizu vremenske linije** koristeći alate kao što su **Autopsy** za vizualizaciju vremenskih linija događaja ili **Sleuth Kit's** `mactime` za detaljne podatke o vremenskoj liniji.
- **Istražiti neočekivane skripte** u sistemskom $PATH, koje mogu uključivati shell ili PHP skripte koje koriste napadači.
- **Istražiti `/dev` za atipične fajlove**, jer tradicionalno sadrži specijalne fajlove, ali može sadržati i fajlove povezane sa malverom.
- **Pretražiti skrivene fajlove ili direktorijume** sa imenima kao što su ".. " (tačka tačka razmak) ili "..^G" (tačka tačka kontrola-G), koji mogu prikrivati zlonamerni sadržaj.
- **Identifikovati setuid root fajlove** koristeći komandu: `find / -user root -perm -04000 -print` Ovo pronalazi fajlove sa povišenim privilegijama, koje napadači mogu zloupotrebiti.
- **Pregledati vremenske oznake brisanja** u inode tabelama kako bi se uočila masovna brisanja fajlova, što može ukazivati na prisustvo rootkit-ova ili trojanaca.
- **Inspektovati uzastopne inode** za obližnje zlonamerne fajlove nakon identifikacije jednog, jer su možda postavljeni zajedno.
- **Proveriti uobičajene binarne direktorijume** (_/bin_, _/sbin_) za nedavno modifikovane fajlove, jer bi ovi mogli biti izmenjeni od strane malvera.
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
> [!NOTE]
> Imajte na umu da **napadač** može **modifikovati** **vreme** kako bi **datoteke izgledale** **legitimno**, ali ne može **modifikovati** **inode**. Ako otkrijete da **datoteka** pokazuje da je kreirana i modifikovana u **isto vreme** kao i ostale datoteke u istoj fascikli, ali je **inode** **neočekivano veći**, onda su **vremenske oznake te datoteke modifikovane**.

## Upoređivanje datoteka različitih verzija datotečnog sistema

### Sažetak upoređivanja verzija datotečnog sistema

Da bismo uporedili verzije datotečnog sistema i precizno odredili promene, koristimo pojednostavljene `git diff` komande:

- **Da pronađete nove datoteke**, uporedite dve fascikle:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
- **Za izmenjen sadržaj**, navedite promene ignorišući specifične linije:
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
- **Da biste otkrili obrisane fajlove**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
- **Opcije filtriranja** (`--diff-filter`) pomažu u sužavanju na specifične promene kao što su dodati (`A`), obrisani (`D`), ili izmenjeni (`M`) fajlovi.
- `A`: Dodati fajlovi
- `C`: Kopirani fajlovi
- `D`: Obrisani fajlovi
- `M`: Izmenjeni fajlovi
- `R`: Preimenovani fajlovi
- `T`: Promene tipa (npr., fajl u symlink)
- `U`: Neusaglašeni fajlovi
- `X`: Nepoznati fajlovi
- `B`: Pokvareni fajlovi

## Reference

- [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf)
- [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)
- [https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
- **Knjiga: Malware Forensics Field Guide for Linux Systems: Digital Forensics Field Guides**

{{#include ../../banners/hacktricks-training.md}}
