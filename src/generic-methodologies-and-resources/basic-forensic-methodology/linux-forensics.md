# Linux Forensics

{{#include ../../banners/hacktricks-training.md}}

## Mkusanyiko wa Taarifa za Awali

### Taarifa za Msingi

Kwanza kabisa, inashauriwa kuwa na **USB** yenye **binaries na maktaba zinazojulikana vizuri** (unaweza tu kupata ubuntu na nakala za folda _/bin_, _/sbin_, _/lib,_ na _/lib64_), kisha unganisha USB, na badilisha mabadiliko ya mazingira ili kutumia binaries hizo:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
Mara tu umepanga mfumo kutumia binaries nzuri na zinazojulikana unaweza kuanza **kuchota taarifa za msingi**:
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
#### Taarifa za Kutia Shaka

Wakati wa kupata taarifa za msingi unapaswa kuangalia mambo ya ajabu kama:

- **Mchakato wa Root** kwa kawaida huendesha na PIDS za chini, hivyo ikiwa utapata mchakato wa root wenye PID kubwa unaweza kuwa na shaka
- Angalia **kuingia kwa watumiaji** waliojiandikisha bila shell ndani ya `/etc/passwd`
- Angalia **hash za nywila** ndani ya `/etc/shadow` kwa watumiaji bila shell

### Dump ya Kumbukumbu

Ili kupata kumbukumbu ya mfumo unaoendesha, inashauriwa kutumia [**LiME**](https://github.com/504ensicsLabs/LiME).\
Ili **kuandika** hiyo, unahitaji kutumia **kernel sawa** ambayo mashine ya mwathirika inatumia.

> [!NOTE]
> Kumbuka kwamba huwezi **kufunga LiME au kitu kingine chochote** kwenye mashine ya mwathirika kwani itafanya mabadiliko kadhaa kwake

Hivyo, ikiwa una toleo sawa la Ubuntu unaweza kutumia `apt-get install lime-forensics-dkms`\
Katika hali nyingine, unahitaji kupakua [**LiME**](https://github.com/504ensicsLabs/LiME) kutoka github na kuandika kwa kutumia vichwa sahihi vya kernel. Ili **kupata vichwa sahihi vya kernel** vya mashine ya mwathirika, unaweza tu **kunakili directory** `/lib/modules/<kernel version>` kwenye mashine yako, na kisha **kuandika** LiME kwa kutumia hivyo:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME inasaidia **format** 3:

- Raw (sehemu zote zimeunganishwa pamoja)
- Padded (sawa na raw, lakini na sifuri katika bits za kulia)
- Lime (format inayopendekezwa yenye metadata)

LiME pia inaweza kutumika **kutuma dump kupitia mtandao** badala ya kuihifadhi kwenye mfumo kwa kutumia kitu kama: `path=tcp:4444`

### Disk Imaging

#### Kuzima

Kwanza kabisa, utahitaji **kuzima mfumo**. Hii si chaguo kila wakati kwani wakati mwingine mfumo utakuwa seva ya uzalishaji ambayo kampuni haiwezi kumudu kuzima.\
Kuna **njia 2** za kuzima mfumo, **kuzima kawaida** na **kuzima "vuta plug"**. Ya kwanza itaruhusu **mchakato kumalizika kama kawaida** na **filesystem** kuwa **sawa**, lakini pia itaruhusu **malware** inayoweza **kuharibu ushahidi**. Njia ya "vuta plug" inaweza kuleta **kupoteza taarifa** (sio nyingi za taarifa zitapotea kwani tayari tumepata picha ya kumbukumbu) na **malware haitakuwa na fursa yoyote** ya kufanya chochote kuhusu hilo. Hivyo, ikiwa unahisi kuwa kuna **malware**, tekeleza tu **amri** **`sync`** kwenye mfumo na vuta plug.

#### Kuchukua picha ya diski

Ni muhimu kutambua kwamba **kabla ya kuunganisha kompyuta yako na chochote kinachohusiana na kesi**, unahitaji kuwa na uhakika kwamba itakuwa **imewekwa kama kusoma tu** ili kuepuka kubadilisha taarifa yoyote.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Disk Image pre-analysis

Kuchora picha ya diski bila data zaidi.
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
## Tafuta Malware inayojulikana

### Faili za Mfumo Zilizobadilishwa

Linux inatoa zana za kuhakikisha uaminifu wa vipengele vya mfumo, muhimu kwa kugundua faili zinazoweza kuwa na matatizo.

- **Mifumo ya RedHat**: Tumia `rpm -Va` kwa ukaguzi wa kina.
- **Mifumo ya Debian**: `dpkg --verify` kwa uthibitisho wa awali, ikifuatiwa na `debsums | grep -v "OK$"` (baada ya kufunga `debsums` kwa `apt-get install debsums`) ili kubaini matatizo yoyote.

### Vifaa vya Kugundua Malware/Rootkit

Soma ukurasa ufuatao kujifunza kuhusu zana ambazo zinaweza kuwa na manufaa katika kutafuta malware:

{{#ref}}
malware-analysis.md
{{#endref}}

## Tafuta programu zilizowekwa

Ili kutafuta kwa ufanisi programu zilizowekwa kwenye mifumo ya Debian na RedHat, fikiria kutumia kumbukumbu za mfumo na hifadhidata pamoja na ukaguzi wa mikono katika directories za kawaida.

- Kwa Debian, angalia _**`/var/lib/dpkg/status`**_ na _**`/var/log/dpkg.log`**_ ili kupata maelezo kuhusu usakinishaji wa pakiti, ukitumia `grep` kuchuja taarifa maalum.
- Watumiaji wa RedHat wanaweza kuuliza hifadhidata ya RPM kwa `rpm -qa --root=/mntpath/var/lib/rpm` ili orodhesha pakiti zilizowekwa.

Ili kugundua programu zilizowekwa kwa mikono au nje ya wasimamizi hawa wa pakiti, chunguza directories kama _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_, na _**`/sbin`**_. Changanya orodha za directories na amri maalum za mfumo ili kubaini executable zisizohusishwa na pakiti zinazojulikana, kuboresha utafutaji wako wa programu zote zilizowekwa.
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
## Rejesha Binaries Zilizofutwa Zinazoendesha

Fikiria mchakato uliofanywa kutoka /tmp/exec na kisha kufutwa. Inawezekana kutoa.
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## Kagua maeneo ya Autostart

### Kazi za Ratiba
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
### Services

Njia ambapo malware inaweza kuwekwa kama huduma:

- **/etc/inittab**: Inaita skripti za kuanzisha kama rc.sysinit, ikielekeza zaidi kwenye skripti za kuanzisha.
- **/etc/rc.d/** na **/etc/rc.boot/**: Zina skripti za kuanzisha huduma, ya mwisho ikipatikana katika toleo za zamani za Linux.
- **/etc/init.d/**: Inatumika katika toleo fulani za Linux kama Debian kwa kuhifadhi skripti za kuanzisha.
- Huduma zinaweza pia kuanzishwa kupitia **/etc/inetd.conf** au **/etc/xinetd/**, kulingana na toleo la Linux.
- **/etc/systemd/system**: Kadiria kwa skripti za meneja wa mfumo na huduma.
- **/etc/systemd/system/multi-user.target.wants/**: Inashikilia viungo vya huduma ambazo zinapaswa kuanzishwa katika kiwango cha kuendesha watumiaji wengi.
- **/usr/local/etc/rc.d/**: Kwa huduma za kawaida au za wahusika wengine.
- **\~/.config/autostart/**: Kwa programu za kuanzisha kiotomatiki maalum kwa mtumiaji, ambazo zinaweza kuwa mahali pa kuficha malware inayolenga watumiaji.
- **/lib/systemd/system/**: Faili za kitengo za kawaida za mfumo zinazotolewa na pakiti zilizowekwa.

### Kernel Modules

Moduli za kernel za Linux, mara nyingi hutumiwa na malware kama sehemu za rootkit, zinawekwa wakati wa kuanzisha mfumo. Maktaba na faili muhimu kwa moduli hizi ni pamoja na:

- **/lib/modules/$(uname -r)**: Inashikilia moduli za toleo la kernel linalotumika.
- **/etc/modprobe.d**: Inashikilia faili za usanidi kudhibiti upakiaji wa moduli.
- **/etc/modprobe** na **/etc/modprobe.conf**: Faili za mipangilio ya moduli za kimataifa.

### Other Autostart Locations

Linux inatumia faili mbalimbali kwa kutekeleza programu kiotomatiki wakati wa kuingia kwa mtumiaji, ambayo inaweza kuwa na malware:

- **/etc/profile.d/**\*, **/etc/profile**, na **/etc/bash.bashrc**: Zinatekelezwa kwa kuingia kwa mtumiaji yeyote.
- **\~/.bashrc**, **\~/.bash_profile**, **\~/.profile**, na **\~/.config/autostart**: Faili maalum za mtumiaji zinazotekelezwa wakati wa kuingia kwao.
- **/etc/rc.local**: Inatekelezwa baada ya huduma zote za mfumo kuanzishwa, ikionyesha mwisho wa mpito kwenda mazingira ya watumiaji wengi.

## Examine Logs

Mifumo ya Linux inafuatilia shughuli za watumiaji na matukio ya mfumo kupitia faili mbalimbali za kumbukumbu. Kumbukumbu hizi ni muhimu kwa kutambua ufikiaji usioidhinishwa, maambukizi ya malware, na matukio mengine ya usalama. Faili muhimu za kumbukumbu ni pamoja na:

- **/var/log/syslog** (Debian) au **/var/log/messages** (RedHat): Huhifadhi ujumbe na shughuli za mfumo mzima.
- **/var/log/auth.log** (Debian) au **/var/log/secure** (RedHat): Huhifadhi majaribio ya uthibitishaji, kuingia kwa mafanikio na yasiyofanikiwa.
- Tumia `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` kuchuja matukio muhimu ya uthibitishaji.
- **/var/log/boot.log**: Inashikilia ujumbe wa kuanzisha mfumo.
- **/var/log/maillog** au **/var/log/mail.log**: Huhifadhi shughuli za seva ya barua pepe, muhimu kwa kufuatilia huduma zinazohusiana na barua pepe.
- **/var/log/kern.log**: Huhifadhi ujumbe wa kernel, ikiwa ni pamoja na makosa na onyo.
- **/var/log/dmesg**: Inashikilia ujumbe wa dereva wa kifaa.
- **/var/log/faillog**: Huhifadhi majaribio ya kuingia yasiyofanikiwa, kusaidia katika uchunguzi wa uvunjaji wa usalama.
- **/var/log/cron**: Huhifadhi utekelezaji wa kazi za cron.
- **/var/log/daemon.log**: Inafuatilia shughuli za huduma za nyuma.
- **/var/log/btmp**: Huhifadhi majaribio ya kuingia yasiyofanikiwa.
- **/var/log/httpd/**: Inashikilia kumbukumbu za makosa na ufikiaji wa Apache HTTPD.
- **/var/log/mysqld.log** au **/var/log/mysql.log**: Huhifadhi shughuli za hifadhidata ya MySQL.
- **/var/log/xferlog**: Huhifadhi uhamisho wa faili za FTP.
- **/var/log/**: Daima angalia kumbukumbu zisizotarajiwa hapa.

> [!NOTE]
> Kumbukumbu za mfumo wa Linux na mifumo ya ukaguzi zinaweza kuzimwa au kufutwa katika uvunjaji au tukio la malware. Kwa sababu kumbukumbu kwenye mifumo ya Linux kwa ujumla zina habari muhimu zaidi kuhusu shughuli mbaya, wavamizi mara nyingi huzifuta. Hivyo, wakati wa kuchunguza faili za kumbukumbu zinazopatikana, ni muhimu kutafuta mapengo au entries zisizo za kawaida ambazo zinaweza kuwa dalili za kufutwa au kuingilia kati.

**Linux inahifadhi historia ya amri kwa kila mtumiaji**, iliyohifadhiwa katika:

- \~/.bash_history
- \~/.zsh_history
- \~/.zsh_sessions/\*
- \~/.python_history
- \~/.\*\_history

Zaidi ya hayo, amri `last -Faiwx` inatoa orodha ya kuingia kwa watumiaji. Angalia kwa kuingia zisizojulikana au zisizotarajiwa.

Angalia faili ambazo zinaweza kutoa rprivileges za ziada:

- Kagua `/etc/sudoers` kwa haki za mtumiaji zisizotarajiwa ambazo zinaweza kuwa zimetolewa.
- Kagua `/etc/sudoers.d/` kwa haki za mtumiaji zisizotarajiwa ambazo zinaweza kuwa zimetolewa.
- Kagua `/etc/groups` ili kubaini uanachama wa vikundi au ruhusa zisizo za kawaida.
- Kagua `/etc/passwd` ili kubaini uanachama wa vikundi au ruhusa zisizo za kawaida.

Baadhi ya programu pia zinaweza kuunda kumbukumbu zake:

- **SSH**: Kagua _\~/.ssh/authorized_keys_ na _\~/.ssh/known_hosts_ kwa uhusiano wa mbali usioidhinishwa.
- **Gnome Desktop**: Angalia _\~/.recently-used.xbel_ kwa faili zilizofikiwa hivi karibuni kupitia programu za Gnome.
- **Firefox/Chrome**: Kagua historia ya kivinjari na upakuaji katika _\~/.mozilla/firefox_ au _\~/.config/google-chrome_ kwa shughuli za kushangaza.
- **VIM**: Kagua _\~/.viminfo_ kwa maelezo ya matumizi, kama vile njia za faili zilizofikiwa na historia ya utafutaji.
- **Open Office**: Kagua ufikiaji wa hati za hivi karibuni ambazo zinaweza kuashiria faili zilizovunjwa.
- **FTP/SFTP**: Kagua kumbukumbu katika _\~/.ftp_history_ au _\~/.sftp_history_ kwa uhamisho wa faili ambao unaweza kuwa haujaidhinishwa.
- **MySQL**: Chunguza _\~/.mysql_history_ kwa maswali ya MySQL yaliyotekelezwa, ambayo yanaweza kufichua shughuli zisizoidhinishwa za hifadhidata.
- **Less**: Changanua _\~/.lesshst_ kwa historia ya matumizi, ikiwa ni pamoja na faili zilizotazamwa na amri zilizotekelezwa.
- **Git**: Kagua _\~/.gitconfig_ na mradi _.git/logs_ kwa mabadiliko ya hifadhidata.

### USB Logs

[**usbrip**](https://github.com/snovvcrash/usbrip) ni kipande kidogo cha programu kilichoandikwa kwa Python 3 safi ambacho kinachambua faili za kumbukumbu za Linux (`/var/log/syslog*` au `/var/log/messages*` kulingana na distro) kwa ajili ya kujenga meza za historia ya matukio ya USB.

Ni muhimu **kujua USB zote ambazo zimekuwa zikitumika** na itakuwa na manufaa zaidi ikiwa una orodha iliyoidhinishwa ya USB ili kupata "matukio ya ukiukaji" (matumizi ya USB ambazo ziko nje ya orodha hiyo).

### Installation
```bash
pip3 install usbrip
usbrip ids download #Download USB ID database
```
### Mifano
```bash
usbrip events history #Get USB history of your curent linux machine
usbrip events history --pid 0002 --vid 0e0f --user kali #Search by pid OR vid OR user
#Search for vid and/or pid
usbrip ids download #Downlaod database
usbrip ids search --pid 0002 --vid 0e0f #Search for pid AND vid
```
Zaidi ya mifano na taarifa ndani ya github: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

## Kagua Akaunti za Watumiaji na Shughuli za Kuingia

Chunguza _**/etc/passwd**_, _**/etc/shadow**_ na **rekodi za usalama** kwa majina yasiyo ya kawaida au akaunti zilizoundwa na au kutumika karibu na matukio yanayojulikana yasiyoidhinishwa. Pia, angalia mashambulizi ya sudo brute-force yanayowezekana.\
Zaidi ya hayo, angalia faili kama _**/etc/sudoers**_ na _**/etc/groups**_ kwa ruhusa zisizotarajiwa zilizotolewa kwa watumiaji.\
Hatimaye, tafuta akaunti zenye **hakuna nywila** au **nywila zinazoweza kukisiwa kwa urahisi**.

## Kagua Mfumo wa Faili

### Kuchambua Miundo ya Mfumo wa Faili katika Uchunguzi wa Malware

Wakati wa kuchunguza matukio ya malware, muundo wa mfumo wa faili ni chanzo muhimu cha taarifa, ukifunua mfululizo wa matukio na maudhui ya malware. Hata hivyo, waandishi wa malware wanakuza mbinu za kuzuia uchambuzi huu, kama vile kubadilisha muda wa faili au kuepuka mfumo wa faili kwa ajili ya uhifadhi wa data.

Ili kupambana na mbinu hizi za anti-forensic, ni muhimu:

- **Fanya uchambuzi wa kina wa muda** ukitumia zana kama **Autopsy** kwa ajili ya kuonyesha mfululizo wa matukio au **Sleuth Kit's** `mactime` kwa data ya kina ya muda.
- **Chunguza skripti zisizotarajiwa** katika $PATH ya mfumo, ambazo zinaweza kujumuisha skripti za shell au PHP zinazotumiwa na washambuliaji.
- **Kagua `/dev` kwa faili zisizo za kawaida**, kwani kwa kawaida ina faili maalum, lakini inaweza kuwa na faili zinazohusiana na malware.
- **Tafuta faili au saraka zilizofichwa** zikiwa na majina kama ".. " (dot dot space) au "..^G" (dot dot control-G), ambazo zinaweza kuficha maudhui mabaya.
- **Tambua faili za setuid root** ukitumia amri: `find / -user root -perm -04000 -print` Hii inapata faili zenye ruhusa za juu, ambazo zinaweza kutumiwa vibaya na washambuliaji.
- **Kagua muda wa kufuta** katika meza za inode ili kugundua kufutwa kwa faili kwa wingi, ambayo inaweza kuashiria uwepo wa rootkits au trojans.
- **Kagua inodes zinazofuatana** kwa faili mbaya karibu baada ya kubaini moja, kwani zinaweza kuwa zimewekwa pamoja.
- **Angalia saraka za binary za kawaida** (_/bin_, _/sbin_) kwa faili zilizobadilishwa hivi karibuni, kwani hizi zinaweza kubadilishwa na malware.
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
> [!NOTE]
> Kumbuka kwamba **mshambuliaji** anaweza **kubadilisha** **wakati** ili kufanya **faili kuonekana** **halali**, lakini hawezi **kubadilisha** **inode**. Ikiwa unapata kwamba **faili** inaonyesha kwamba iliumbwa na kubadilishwa kwa **wakati mmoja** na faili zingine katika folda hiyo hiyo, lakini **inode** ni **kubwa zaidi** **kivyake**, basi **alama za wakati za faili hiyo zimebadilishwa**.

## Linganisha faili za toleo tofauti la mfumo wa faili

### Muhtasari wa Linganisho la Toleo la Mfumo wa Faili

Ili kulinganisha toleo za mfumo wa faili na kubaini mabadiliko, tunatumia amri rahisi za `git diff`:

- **Ili kupata faili mpya**, linganisha directories mbili:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
- **Kwa yaliyobadilishwa**, orodhesha mabadiliko huku ukipuuzilia mbali mistari maalum:
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
- **Kugundua faili zilizofutwa**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
- **Chaguo za kuchuja** (`--diff-filter`) husaidia kupunguza hadi mabadiliko maalum kama vile faili zilizoongezwa (`A`), zilizofutwa (`D`), au zilizobadilishwa (`M`).
- `A`: Faili zilizoongezwa
- `C`: Faili zilizokopwa
- `D`: Faili zilizofutwa
- `M`: Faili zilizobadilishwa
- `R`: Faili zilizobadilishwa jina
- `T`: Mabadiliko ya aina (mfano, faili hadi symlink)
- `U`: Faili zisizounganishwa
- `X`: Faili zisizojulikana
- `B`: Faili zilizovunjika

## Marejeleo

- [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf)
- [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)
- [https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
- **Kitabu: Malware Forensics Field Guide for Linux Systems: Digital Forensics Field Guides**

{{#include ../../banners/hacktricks-training.md}}
