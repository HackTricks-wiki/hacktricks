# Linux Forensics

{{#include ../../banners/hacktricks-training.md}}

## Initial Information Gathering

### Basic Information

Her şeyden önce, üzerinde **iyi bilinen binary ve library'ler** bulunan bazı **USB**'lerin olması önerilir (ubuntu alıp _/bin_, _/sbin_, _/lib,_ ve _/lib64_ klasörlerini kopyalayabilirsiniz), ardından USB'yi mount edin ve bu binary'leri kullanmak için env değişkenlerini değiştirin:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
Sistemi iyi ve bilinen binary'leri kullanacak şekilde yapılandırdıktan sonra, **bazı temel bilgileri çıkarmaya** başlayabilirsiniz:
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
#### Şüpheli bilgiler

Temel bilgileri elde ederken şu tür garip şeyleri kontrol etmelisiniz:

- **Root işlemleri** genellikle düşük PID'lerle çalışır, bu yüzden büyük bir PID'ye sahip bir root işlemi bulursanız şüphelenebilirsiniz
- /etc/passwd içinde shell'i olmayan kullanıcıların **registered logins** kayıtlarını kontrol edin
- Shell'i olmayan kullanıcılar için /etc/shadow içinde **password hashes** olup olmadığını kontrol edin

### Memory Dump

Çalışan sistemin belleğini elde etmek için [**LiME**](https://github.com/504ensicsLabs/LiME) kullanmanız önerilir.\
Bunu **compile** etmek için, kurban makinenin kullandığı **same kernel**'i kullanmanız gerekir.

> [!TIP]
> LiME veya başka herhangi bir şeyi kurban makineye **kuramayacağınızı** unutmayın; çünkü bu, sistemde birçok değişiklik yapar

Dolayısıyla, eğer Ubuntu'nun birebir aynı bir sürümüne sahipseniz `apt-get install lime-forensics-dkms` kullanabilirsiniz\
Diğer durumlarda, [**LiME**](https://github.com/504ensicsLabs/LiME) aracını github'dan indirip doğru kernel headers ile compile etmeniz gerekir. Kurban makinenin **exact kernel headers** bilgisini elde etmek için, `/lib/modules/<kernel version>` dizinini makinenize **copy** edebilir ve ardından LiME'ı bunları kullanarak **compile** edebilirsiniz:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME 3 **formatı** destekler:

- Raw (tüm segmentler birleştirilmiş halde)
- Padded (raw ile aynı, ancak sağ bitlerde sıfırlar ile)
- Lime (metadata içeren önerilen format)

LiME ayrıca dökümü sistemde saklamak yerine ağ üzerinden **göndermek** için de kullanılabilir, örneğin: `path=tcp:4444`

### Disk Imaging

#### Shutting down

Öncelikle, **sistemi kapatmanız** gerekecek. Bu her zaman bir seçenek değildir çünkü bazen sistem, şirketin kapatmayı göze alamayacağı bir production server olabilir.\
Sistemi kapatmanın **2 yolu** vardır: **normal shutdown** ve **"plug the plug" shutdown**. İlk yöntem, **processes**in her zamanki gibi **sonlanmasına** ve **filesystem**in **senkronize edilmesine** izin verir, ancak aynı zamanda olası **malware**in **kanıtları yok etmesine** de imkan tanır. "pull the plug" yaklaşımı ise **bir miktar bilgi kaybına** yol açabilir (zaten memory'nin bir image'ını aldığımız için çok fazla bilgi kaybolmayacaktır) ve **malware**in buna karşı bir şey yapma fırsatı olmaz. Bu nedenle, bir **malware** olabileceğinden **şüpheleniyorsanız**, sistemde sadece **`sync`** **command**ini çalıştırın ve fişi çekin.

#### Taking an image of the disk

Bilmeniz gereken önemli bir nokta, **bilgisayarınızı vaka ile ilgili herhangi bir şeye bağlamadan önce**, herhangi bir bilgiyi değiştirmemek için onun **sadece okuma olarak mount edileceğinden** emin olmanız gerektiğidir.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Disk Görüntüsü ön analizi

Daha fazla veri olmadan bir disk görüntüsünü imajlamak.
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
## Bilinen Malware için Araştırma

### Değiştirilmiş Sistem Dosyaları

Linux, sistem bileşenlerinin bütünlüğünü sağlamak için araçlar sunar; bu, potansiyel olarak sorunlu dosyaları tespit etmek açısından kritiktir.

- **RedHat-based systems**: Kapsamlı bir kontrol için `rpm -Va` kullanın.
- **Debian-based systems**: İlk doğrulama için `dpkg --verify`, ardından sorunları belirlemek için `debsums | grep -v "OK$"` kullanın (`debsums` paketini `apt-get install debsums` ile kurduktan sonra).

### Malware/Rootkit Detectors

Malware bulmak için yararlı olabilecek araçları öğrenmek üzere aşağıdaki sayfayı okuyun:


{{#ref}}
malware-analysis.md
{{#endref}}

## Kurulu programları ara

Debian ve RedHat sistemlerinde kurulu programları etkili şekilde aramak için, yaygın dizinlerdeki manuel kontrollerin yanı sıra sistem loglarını ve veritabanlarını kullanmayı düşünün.

- Debian için, paket kurulumlarına dair ayrıntıları almak üzere _**`/var/lib/dpkg/status`**_ ve _**`/var/log/dpkg.log`**_ dosyalarını inceleyin; belirli bilgileri filtrelemek için `grep` kullanın.
- RedHat kullanıcıları, kurulu paketleri listelemek için RPM veritabanını `rpm -qa --root=/mntpath/var/lib/rpm` ile sorgulayabilir.

Bu paket yöneticileri dışında manuel veya farklı yollarla kurulmuş yazılımları ortaya çıkarmak için _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_ ve _**`/sbin`**_ gibi dizinleri inceleyin. Dizin सूचीlemelerini sistem-özel komutlarla birleştirerek bilinen paketlerle ilişkili olmayan çalıştırılabilir dosyaları belirleyin; böylece tüm kurulu programlar için aramanızı güçlendirin.
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
## Silinmiş Çalışan Binary'leri Kurtarma

/tmp/exec konumundan çalıştırılmış ve ardından silinmiş bir process'i hayal edin. Onu çıkarmak mümkündür
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## Autostart konumlarını incele

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
Saldırganlar, periyodik yürütmeyi garanti altına almak için çoğu zaman her bir /etc/cron.*/ dizini altında bulunan 0anacron stub’ını düzenler.
```bash
# List 0anacron files and their timestamps/sizes
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done

# Look for obvious execution of shells or downloaders embedded in cron stubs
grep -R --line-number -E 'curl|wget|/bin/sh|python|bash -c' /etc/cron.*/* 2>/dev/null
```
#### Av: SSH hardening rollback ve backdoor shells
`sshd_config` ve sistem hesap kabuklarında yapılan değişiklikler, erişimi korumak için post-exploitation sonrasında yaygındır.
```bash
# Root login enablement (flag "yes" or lax values)
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config

# System accounts with interactive shells (e.g., games → /bin/sh)
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
#### Hunt: Cloud C2 işaretleri (Dropbox/Cloudflare Tunnel)
- Dropbox API beacon’ları tipik olarak HTTPS üzerinden Authorization: Bearer token’ları ile api.dropboxapi.com veya content.dropboxapi.com kullanır.
- Beklenmeyen Dropbox çıkış trafiğini sunucularda proxy/Zeek/NetFlow içinde avla.
- Cloudflare Tunnel (`cloudflared`), outbound 443 üzerinden yedek C2 sağlar.
```bash
ps aux | grep -E '[c]loudflared|trycloudflare'
systemctl list-units | grep -i cloudflared
```
### Services

Bir malware’in service olarak kurulabileceği yollar:

- **/etc/inittab**: rc.sysinit gibi initialization scriptlerini çağırır, ardından startup scriptlerine yönlendirir.
- **/etc/rc.d/** ve **/etc/rc.boot/**: service başlatma scriptlerini içerir; ikincisi eski Linux sürümlerinde bulunur.
- **/etc/init.d/**: Debian gibi bazı Linux sürümlerinde startup scriptlerini saklamak için kullanılır.
- Services ayrıca Linux varyantına bağlı olarak **/etc/inetd.conf** veya **/etc/xinetd/** üzerinden de etkinleştirilebilir.
- **/etc/systemd/system**: system ve service manager scriptleri için bir dizin.
- **/etc/systemd/system/multi-user.target.wants/**: multi-user runlevel’da başlatılması gereken services’e ait linkleri içerir.
- **/usr/local/etc/rc.d/**: özel veya üçüncü taraf services için.
- **\~/.config/autostart/**: kullanıcıya özel otomatik startup uygulamaları için; kullanıcıyı hedefleyen malware için saklanma yeri olabilir.
- **/lib/systemd/system/**: kurulu paketler tarafından sağlanan sistem genelindeki varsayılan unit dosyaları.

#### Hunt: systemd timers and transient units

Systemd persistence yalnızca `.service` dosyalarıyla sınırlı değildir. `.timer` units, user-level units ve çalışma zamanında oluşturulan **transient units** dosyalarını inceleyin.
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
Transient units, `/run/systemd/transient/` **kalıcı değildir** olduğu için kolayca gözden kaçabilir. Canlı bir image topluyorsanız, shutdown öncesinde alın.

### Kernel Modules

Linux kernel modules, genellikle malware tarafından rootkit bileşenleri olarak kullanılır ve sistem boot sırasında yüklenir. Bu modüller için kritik dizinler ve dosyalar şunlardır:

- **/lib/modules/$(uname -r)**: Çalışan kernel sürümü için modülleri tutar.
- **/etc/modprobe.d**: Module loading kontrol etmek için configuration files içerir.
- **/etc/modprobe** ve **/etc/modprobe.conf**: Global module ayarları için files.

### Other Autostart Locations

Linux, kullanıcı login olduğunda programları otomatik çalıştırmak için çeşitli files kullanır; bunlar malware barındırabilir:

- **/etc/profile.d/**\*, **/etc/profile**, ve **/etc/bash.bashrc**: Her kullanıcı login’i için çalıştırılır.
- **\~/.bashrc**, **\~/.bash_profile**, **\~/.profile**, ve **\~/.config/autostart**: Kullanıcıya özel, onların login’inde çalışan files.
- **/etc/rc.local**: Tüm system services başladıktan sonra çalışır ve multiuser environment’a geçişin sonunu işaret eder.

## Examine Logs

Linux systems, user activities ve system events’i çeşitli log files üzerinden takip eder. Bu logs, unauthorized access, malware infections ve diğer security incidents’leri belirlemek için kritiktir. Önemli log files şunlardır:

- **/var/log/syslog** (Debian) veya **/var/log/messages** (RedHat): System-wide messages ve activities’i kaydeder.
- **/var/log/auth.log** (Debian) veya **/var/log/secure** (RedHat): Authentication attempts, başarılı ve başarısız logins’i kaydeder.
- İlgili authentication events’i filtrelemek için `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` kullanın.
- **/var/log/boot.log**: System startup messages içerir.
- **/var/log/maillog** veya **/var/log/mail.log**: Email server activities’ini loglar, email-related services’i izlemek için kullanışlıdır.
- **/var/log/kern.log**: Errors ve warnings dahil kernel messages’i saklar.
- **/var/log/dmesg**: Device driver messages içerir.
- **/var/log/faillog**: Başarısız login attempts’i kaydeder, security breach investigations’a yardımcı olur.
- **/var/log/cron**: Cron job executions’ı loglar.
- **/var/log/daemon.log**: Background service activities’ini takip eder.
- **/var/log/btmp**: Başarısız login attempts’i belgeler.
- **/var/log/httpd/**: Apache HTTPD error ve access logs içerir.
- **/var/log/mysqld.log** veya **/var/log/mysql.log**: MySQL database activities’ini loglar.
- **/var/log/xferlog**: FTP file transfers’ı kaydeder.
- **/var/log/**: Burada beklenmeyen logs için her zaman kontrol edin.

> [!TIP]
> Linux system logs ve audit subsystems, bir intrusion veya malware incident sırasında disabled veya deleted edilmiş olabilir. Linux systems üzerindeki logs genellikle malicious activities hakkında en faydalı bilgilerin bir kısmını içerdiğinden, intruders rutin olarak bunları siler. Bu nedenle, mevcut log files incelenirken deletion veya tampering göstergesi olabilecek boşluklara veya sıra dışı girişlere bakmak önemlidir.

### Journald triage (`journalctl`)

Modern Linux hosts üzerinde, **systemd journal** genellikle **service execution**, **auth events**, **package operations** ve **kernel/user-space messages** için en değerli kaynaktır. Live response sırasında, hem **persistent** journal (`/var/log/journal/`) hem de **runtime** journal (`/run/log/journal/`) korunmaya çalışılmalıdır; çünkü kısa ömürlü attacker activity yalnızca ikincisinde bulunabilir.
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
Triage için faydalı journal alanları `_SYSTEMD_UNIT`, `_EXE`, `_COMM`, `_CMDLINE`, `_UID`, `_GID`, `_PID`, `_BOOT_ID` ve `MESSAGE` içerir. Eğer journald kalıcı storage olmadan yapılandırıldıysa, yalnızca `/run/log/journal/` altında yakın tarihli data bekleyin.

### Audit framework triage (`auditd`)

`auditd` enabled ise, file changes, command execution, login activity veya package installation için **process attribution** gerektiğinde onu tercih edin.
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
Kurallar anahtarlarla dağıtıldığında, ham logları grep’lemek yerine bunlardan pivot yapın:
```bash
ausearch --start this-week -k <rule_key> --raw | aureport --file --summary -i
ausearch --start this-week -k <rule_key> --raw | aureport --user --summary -i
```
**Linux, her kullanıcı için bir command history tutar**, şurada saklanır:

- \~/.bash_history
- \~/.zsh_history
- \~/.zsh_sessions/\*
- \~/.python_history
- \~/.\*\_history

Ayrıca, `last -Faiwx` komutu kullanıcı girişlerinin bir listesini sağlar. Bilinmeyen veya beklenmeyen login’ler için kontrol edin.

Ek rprivileges verebilecek dosyaları kontrol edin:

- Verilen beklenmedik user privileges olup olmadığını görmek için `/etc/sudoers` dosyasını inceleyin.
- Verilen beklenmedik user privileges olup olmadığını görmek için `/etc/sudoers.d/` dizinini inceleyin.
- Olağandışı group memberships veya permissions tespit etmek için `/etc/groups` dosyasını inceleyin.
- Olağandışı group memberships veya permissions tespit etmek için `/etc/passwd` dosyasını inceleyin.

Bazı apps kendi loglarını da üretir:

- **SSH**: Yetkisiz remote connections için _\~/.ssh/authorized_keys_ ve _\~/.ssh/known_hosts_ dosyalarını inceleyin.
- **Gnome Desktop**: Gnome applications aracılığıyla yakın zamanda erişilen dosyalar için _\~/.recently-used.xbel_ dosyasına bakın.
- **Firefox/Chrome**: Şüpheli activities için _\~/.mozilla/firefox_ veya _\~/.config/google-chrome_ içindeki browser history ve downloads kayıtlarını kontrol edin.
- **VIM**: Erişilen file paths ve search history gibi usage details için _\~/.viminfo_ dosyasını inceleyin.
- **Open Office**: Compromised files’a işaret edebilecek recent document access kayıtlarını kontrol edin.
- **FTP/SFTP**: Yetkisiz olabilecek file transfers için _\~/.ftp_history_ veya _\~/.sftp_history_ içindeki logları inceleyin.
- **MySQL**: Çalıştırılmış MySQL queries için _\~/.mysql_history_ dosyasını inceleyin; bu, yetkisiz database activities’i açığa çıkarabilir.
- **Less**: Görüntülenen files ve çalıştırılan commands dahil usage history için _\~/.lesshst_ dosyasını analiz edin.
- **Git**: Repositories üzerindeki changes için _\~/.gitconfig_ ve project _.git/logs_ dosyalarını inceleyin.

### USB Logs

[**usbrip**](https://github.com/snovvcrash/usbrip) saf Python 3 ile yazılmış küçük bir yazılımdır; USB event history tabloları oluşturmak için Linux log files (`/var/log/syslog*` veya distro’ya bağlı olarak `/var/log/messages*`) ayrıştırır.

Kullanılmış tüm USBs’leri **bilmek** ilginçtir ve onaylı bir USB listesi varsa, listede olmayan USBs’lerin kullanımını içeren "violation events"i bulmak için daha da faydalı olacaktır.

### Installation
```bash
pip3 install usbrip
usbrip ids download #Download USB ID database
```
### Örnekler
```bash
usbrip events history #Get USB history of your curent linux machine
usbrip events history --pid 0002 --vid 0e0f --user kali #Search by pid OR vid OR user
#Search for vid and/or pid
usbrip ids download #Downlaod database
usbrip ids search --pid 0002 --vid 0e0f #Search for pid AND vid
```
More examples and info inside the github: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

## Kullanıcı Hesaplarını ve Oturum Açma Etkinliklerini İncele

_**/etc/passwd**_, _**/etc/shadow**_ ve **security logs** dosyalarını, olağandışı isimler veya bilinen yetkisiz olaylara yakın zamanda oluşturulmuş ve/veya kullanılmış hesaplar açısından inceleyin. Ayrıca olası sudo brute-force saldırılarını kontrol edin.\
Bunun yanında, kullanıcılara verilmiş beklenmedik yetkiler için _**/etc/sudoers**_ ve _**/etc/groups**_ gibi dosyalara bakın.\
Son olarak, **parolası olmayan** veya **kolay tahmin edilen** parolalara sahip hesapları arayın.

## Dosya Sistemini İncele

### Malware Soruşturmasında Dosya Sistemi Yapılarının Analizi

Malware olaylarını incelerken, dosya sisteminin yapısı hem olayların sırasını hem de malware’in içeriğini ortaya koyan kritik bir bilgi kaynağıdır. Ancak malware yazarları, dosya zaman damgalarını değiştirmek veya veri depolamak için dosya sistemini kullanmaktan kaçınmak gibi bu analizi zorlaştıran teknikler geliştiriyorlar.

Bu anti-forensic yöntemlere karşı koymak için şunlar önemlidir:

- Olay zaman çizelgelerini görselleştirmek için **Autopsy** ya da ayrıntılı zaman çizelgesi verileri için **Sleuth Kit**'in `mactime` aracını kullanarak **kapsamlı bir timeline analizi yapın**.
- Sistemin $PATH içinde, saldırganlar tarafından kullanılan shell veya PHP scriptlerini içerebilecek **beklenmedik scriptleri inceleyin**.
- Geleneksel olarak özel dosyalar içeren ancak malware ile ilgili dosyalar da barındırabilen **/dev içindeki olağandışı dosyaları inceleyin**.
- " .. " (nokta nokta boşluk) veya "..^G" (nokta nokta kontrol-G) gibi adlara sahip **gizli dosya veya dizinleri arayın**; bunlar zararlı içeriği gizliyor olabilir.
- `find / -user root -perm -04000 -print` komutunu kullanarak **setuid root dosyalarını belirleyin**. Bu, saldırganlarca kötüye kullanılabilecek yükseltilmiş izinlere sahip dosyaları bulur.
- inode tablolarındaki **silinme zaman damgalarını** inceleyerek toplu dosya silmelerini tespit edin; bu, rootkit veya trojan varlığına işaret ediyor olabilir.
- Birini belirledikten sonra, yakınlardaki zararlı dosyaları bulmak için **ardışık inode'ları inceleyin**; birlikte yerleştirilmiş olabilirler.
- **Ortak binary dizinlerini** (_/bin_, _/sbin_) yakın zamanda değiştirilmiş dosyalar için kontrol edin; bunlar malware tarafından değiştirilmiş olabilir.
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
> [!TIP]
> Bir **attacker** **time**’ı **modify** ederek **files**’ın **legitimate** görünmesini sağlayabilir, ancak **inode**’u **modify** edemez. Eğer bir **file**’ın, aynı klasördeki diğer dosyalarla **same time**’da oluşturulup değiştirildiğini, fakat **inode**’unun **unexpectedly bigger** olduğunu görürseniz, o zaman o **file**’ın **timestamps**’leri **modified** edilmiştir.

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
Bir şüpheli inode bir EXT filesystem image/device üzerinde olduğunda, inode metadata’sını doğrudan inceleyin:
```bash
sudo debugfs -R "stat <inode_number>" /dev/sdX
```
Yararlı alanlar:
- **Links**: eğer `0` ise, şu anda hiçbir dizin girdisi inode'u referans etmiyor.
- **dtime**: inode bağlantısı kaldırıldığında ayarlanan silinme zaman damgası.
- **ctime/mtime**: metadata/içerik değişikliklerini olay zaman çizelgesiyle ilişkilendirmeye yardımcı olur.

### Capabilities, xattrs, and preload-based userland rootkits

Modern Linux persistence often avoids obvious `setuid` binaries and instead abuses **file capabilities**, **extended attributes**, and the dynamic loader.
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
Özellikle `/tmp`, `/dev/shm`, `/var/tmp` gibi **writable** yollarından veya `/usr/local/lib` altındaki garip konumlardan referans verilen kütüphanelere dikkat edin. Ayrıca normal paket sahipliği dışında kalan capability-bearing binary'leri kontrol edin ve bunları paket doğrulama sonuçlarıyla (`rpm -Va`, `dpkg --verify`, `debsums`) ilişkilendirin.

## Farklı filesystem sürümlerindeki dosyaları karşılaştırın

### Filesystem Version Comparison Summary

filesystem sürümlerini karşılaştırmak ve değişiklikleri belirlemek için basitleştirilmiş `git diff` komutları kullanırız:

- **Yeni dosyaları bulmak için**, iki dizini karşılaştırın:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
- **Değiştirilmiş içerik için**, belirli satırları göz ardı ederek değişiklikleri listeleyin:
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
- **Silinmiş dosyaları tespit etmek için**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
- **Filter seçenekleri** (`--diff-filter`) added (`A`), deleted (`D`) veya modified (`M`) files gibi belirli değişiklikleri daraltmaya yardımcı olur.
- `A`: Added files
- `C`: Copied files
- `D`: Deleted files
- `M`: Modified files
- `R`: Renamed files
- `T`: Type changes (örn. file to symlink)
- `U`: Unmerged files
- `X`: Unknown files
- `B`: Broken files

## References

- [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf)
- [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)
- [https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
- **Book: Malware Forensics Field Guide for Linux Systems: Digital Forensics Field Guides**

- [Red Canary – Patching for persistence: How DripDropper Linux malware moves through the cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [Forensic Analysis of Linux Journals](https://stuxnet999.github.io/dfir/linux-journal-forensics/)
- [Red Hat Enterprise Linux 9 - Auditing the system](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening)

{{#include ../../banners/hacktricks-training.md}}
