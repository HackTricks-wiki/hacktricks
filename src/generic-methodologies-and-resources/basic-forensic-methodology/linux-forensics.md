# Linux Forensics

{{#include ../../banners/hacktricks-training.md}}

## Initial Information Gathering

### Basic Information

Her şeyden önce, üzerinde **bilinen iyi ikili dosyalar ve kütüphaneler bulunan bir USB** bulundurmanız önerilir (ubuntu alıp _/bin_, _/sbin_, _/lib,_ ve _/lib64_ klasörlerini kopyalayabilirsiniz); ardından USB'yi mount edin ve bu ikili dosyaları kullanmak için env değişkenlerini değiştirin:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
Sistemi iyi ve bilinen binary'leri kullanacak şekilde yapılandırdıktan sonra **bazı temel bilgileri çıkarmaya** başlayabilirsiniz:
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

Temel bilgileri elde ederken aşağıdakiler gibi tuhaf şeyleri kontrol etmelisiniz:

- **Root process'leri** genellikle düşük PID'lerle çalışır; bu nedenle büyük bir PID'ye sahip bir root process'i bulursanız şüphelenebilirsiniz
- `/etc/passwd` içinde shell'i olmayan kullanıcıların **kayıtlı login'lerini** kontrol edin
- Shell'i olmayan kullanıcılar için `/etc/shadow` içinde **password hash'lerini** kontrol edin

### Bellek Dökümü

Çalışan sistemin belleğini elde etmek için [**LiME**](https://github.com/504ensicsLabs/LiME) kullanmanız önerilir.\
**Compile** etmek için victim machine'in kullandığı **aynı kernel'i** kullanmanız gerekir.

> [!TIP]
> Victim machine'e **LiME veya başka herhangi bir şey kuramayacağınızı** unutmayın; bu, makinede çeşitli değişikliklere neden olur

Bu nedenle, Ubuntu'nun aynı sürümüne sahipseniz `apt-get install lime-forensics-dkms` kullanabilirsiniz.\
Diğer durumlarda [**LiME**](https://github.com/504ensicsLabs/LiME) dosyasını github'dan indirmeniz ve doğru kernel header'larıyla compile etmeniz gerekir. Victim machine'in **tam kernel header'larını elde etmek** için `/lib/modules/<kernel version>` dizinini makinenize **kopyalayabilir** ve ardından LiME'ı bunları kullanarak **compile** edebilirsiniz:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME 3 **formatı** destekler:

- Raw (her segmentin birleştirilmesi)
- Padded (Raw ile aynı, ancak sağ bitlerde sıfırlar bulunur)
- Lime (metadata içeren önerilen format

LiME, `path=tcp:4444` gibi bir yöntem kullanarak dump'ı sistemde depolamak yerine **network üzerinden göndermek** için de kullanılabilir.

### Disk İmajı

#### Kapatma

Her şeyden önce sistemi **kapatmanız** gerekir. Bu her zaman mümkün olmayabilir; çünkü bazen sistem, şirketin kapatmayı göze alamayacağı bir production server olabilir.\
Sistemi kapatmanın **2 yolu** vardır: **normal kapatma** ve **"fişi çekerek" kapatma**. İlk yöntem, **process'lerin normal şekilde sonlanmasını** ve **filesystem'in** **senkronize edilmesini** sağlar; ancak olası **malware'in** **kanıtları yok etmesine** de olanak tanır. "Fişi çekme" yaklaşımı **bazı veri kayıplarına** yol açabilir (memory'nin imajını zaten aldığımız için bilgilerin çoğu kaybolmayacaktır) ve **malware'in** bu konuda herhangi bir şey yapma **fırsatı olmayacaktır**. Bu nedenle, bir **malware** olabileceğinden **şüpheleniyorsanız**, sistemde yalnızca **`sync`** **command'ini** çalıştırın ve fişi çekin.

#### Diskin imajını alma

**Bilgisayarınızı vakayla ilgili herhangi bir şeye bağlamadan önce**, herhangi bir bilgiyi değiştirmemek için bunun **salt okunur olarak mount edileceğinden** emin olmanız önemlidir.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Disk Image ön analizi

Daha fazla veri içermeyen bir disk imajı oluşturma.
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
## Bilinen Malware'leri Arama

### Değiştirilmiş Sistem Dosyaları

Linux, potansiyel olarak sorunlu dosyaları tespit etmek için kritik önem taşıyan sistem bileşenlerinin bütünlüğünü doğrulamaya yönelik araçlar sunar.<sup>[[1]](#references)</sup>

- **RedHat tabanlı sistemler**: Kapsamlı bir kontrol için `rpm -Va` kullanın.
- **Debian tabanlı sistemler**: İlk doğrulama için `dpkg --verify` kullanın; ardından herhangi bir sorunu tespit etmek için `debsums | grep -v "OK$"` komutunu çalıştırın (`debsums` paketini `apt-get install debsums` ile yükledikten sonra).

### Malware/Rootkit Detector'leri

Malware bulmak için yararlı olabilecek araçlar hakkında bilgi edinmek üzere aşağıdaki sayfayı okuyun:


{{#ref}}
malware-analysis.md
{{#endref}}

## Yüklü programları arama

Hem Debian hem de RedHat sistemlerinde yüklü programları etkili bir şekilde aramak için, yaygın dizinlerdeki manuel kontrollerin yanı sıra sistem günlüklerinden ve veritabanlarından yararlanmayı değerlendirin.<sup>[[1]](#references)</sup>

- Debian için, paket kurulumlarıyla ilgili ayrıntıları almak üzere _**`/var/lib/dpkg/status`**_ ve _**`/var/log/dpkg.log`**_ dosyalarını inceleyin; belirli bilgileri filtrelemek için `grep` kullanın.
- RedHat kullanıcıları, yüklü paketleri listelemek için RPM veritabanını `rpm -qa --root=/mntpath/var/lib/rpm` komutuyla sorgulayabilir.

Bu paket yöneticileri kullanılarak manuel olarak veya bunların dışında yüklenen yazılımları ortaya çıkarmak için _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_ ve _**`/sbin`**_ gibi dizinleri inceleyin. Bilinen paketlerle ilişkilendirilmemiş çalıştırılabilir dosyaları tespit etmek ve tüm yüklü programları arama sürecinizi geliştirmek için dizin listelemelerini sisteme özgü komutlarla birleştirin.
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
## Silinmiş Çalışan Binary Dosyalarını Kurtarma

/tmp/exec konumundan çalıştırılmış ve ardından silinmiş bir process düşünün. Bu process'i çıkarmak mümkündür.
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## SQLite ve FTS5 ile Syscall Trace Triage

Bir process hâlâ çalışıyorsa veya bir lab ortamında yeniden çalıştırılabiliyorsa, **`strace`**, kernel modüllerine veya eksiksiz EDR telemetry'sine ihtiyaç duymadan hızlı bir davranış trace'i sağlayabilir. Büyük trace'ler için raw log'u doğrudan okumaktan veya bir LLM'e yapıştırmaktan kaçının: Verileri bir **SQLite** database'inde saklayın ve yalnızca ihtiyacınız olan minimum alt kümeyi sorgulayın.<sup>[[7]](#references)[[8]](#references)[[9]](#references)</sup>

> [!WARNING]
> `strace` bağlamak process timing'ini değiştirir ve race condition'ları veya diğer hassas bug'ları etkileyebilir. Mümkün olduğunda yeniden üretmeyi bir kopya/lab sistemi üzerinde tercih edin.

### Capture

Yeni bir process için:
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log <command>
```
Canlı bir işlem için:
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log -p <PID>
```
Kullanışlı seçenekler:

- `-ff`: fork/thread işlemlerini takip eder ve işlem başına çıktıları ayrı tutar
- `-ttt`: kolay zaman çizelgesi korelasyonu için epoch zaman damgaları
- `-yy`: mümkün olduğunda dosya tanımlayıcılarını destekleyen yollar/soketlerle çözümler
- `-s 4096`: uzun yol ve arabellek bağımsız değişkenlerinin kesilmesini önler

### Normalleştir

Pratik bir şema, her syscall ve her bağımsız değişken için bir satırdır:
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
Bu, heterojen syscall satırlarını tek ve geniş bir tabloya düzleştirmeye çalışmayı önler ve triage sırasında join işlemlerinin öngörülebilir kalmasını sağlar.

### FTS5 ile metin ağırlıklı argümanları indeksleyin

`LIKE "%...%"` ile yapılan naif path aramaları, büyük trace'lerde çok yavaşlar. Argüman metni için bir FTS5 index'i oluşturun ve bunun yerine onu arayın:
```sql
CREATE VIRTUAL TABLE syscall_args_fts
USING fts5(raw, content='syscall_args', content_rowid='id');

INSERT INTO syscall_args_fts(rowid, raw)
SELECT id, raw FROM syscall_args;
```
Örnek: her satırı taramadan `/tmp` altındaki dosya etkinliğini kurtarma:
```sql
SELECT s.timestamp, s.pid, s.name, a.position, a.raw
FROM syscall_args_fts f
JOIN syscall_args a ON a.id = f.rowid
JOIN syscalls s ON s.id = a.syscall_id
WHERE syscall_args_fts MATCH 'tmp'
AND s.name IN ('openat', 'stat', 'lstat', 'rename', 'unlink', 'execve')
ORDER BY s.timestamp;
```
### Yüksek sinyalli incelemeler

- **PATH hijacking / fake sudo**: `~/.local/bin/` altındaki yazma ve `chmod`/`rename` etkinliklerini arayın, ardından bunları `sudo` gibi ayrıcalıklı görünümlü adların sonraki `execve` çağrılarıyla ilişkilendirin.
- **Geçici dosyalarda TOCTOU**: Denetim/kullanım arasındaki boşlukları belirlemek için aynı `/tmp/...` yolunu `stat`, `access`, `openat`, `rename`, `unlink`, `link`, `symlink` ve `execve` genelinde takip edin.
- **Çökme kök nedeni**: Bir dosyanın `mmap` çağrısını, başka bir process tarafından aynı inode/yol üzerinde gerçekleştirilen yazma veya truncate işlemleriyle ilişkilendirin, ardından `SIGBUS` için signal/exit sequence'i inceleyin.
- **Network hedefinin kurtarılması**: Eş IP'lerini ve portlarını çıkarmak için `connect`, `sendto`, `sendmsg`, `recvfrom` ve socket ile ilgili argümanları filtreleyin.

### LLM destekli trace analizi

Bir LLM'nin yardımcı olmasını istiyorsanız, **read-only** bir SQLite handle'ı sunun ve tam schema'yı verin. Veritabanını dar helper function'ların arkasına sarmak yerine raw SQL çalıştırmasına izin verin. Bu yaklaşım genellikle join'ler, temporal correlation ve FTS lookup'ları için daha iyi sonuç verir.

Pratik kurallar:

- Veritabanını read-only tutun; örneğin `sqlite3 'file:trace.db?mode=ro'`.
- Modele geçerli `JOIN` ve `FTS5 MATCH` query'leri için örnekler verin.
- Raw multi-GB `strace` log'larını prompt'a yapıştırmayın.
- Aşağıdakiler gibi odaklanmış sorular sorun:
- "Bu programın yazdığı kalıcı dosyaları listele."
- "Kullanıcı tarafından kontrol edilen PATH dizinlerinde executable oluşturdu veya değiştirdi mi?"
- "Bu trace'in neden SIGBUS ile sona erdiğini açıkla."

## Autostart konumlarını inceleyin

### Zamanlanmış görevler
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
#### Hunt: 0anacron ve şüpheli stub'lar üzerinden Cron/Anacron abuse
Saldırganlar, periyodik çalıştırmayı garanti altına almak için genellikle her bir /etc/cron.*/ dizininde bulunan 0anacron stub'ını düzenler.<sup>[[4]](#references)</sup>
```bash
# List 0anacron files and their timestamps/sizes
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done

# Look for obvious execution of shells or downloaders embedded in cron stubs
grep -R --line-number -E 'curl|wget|/bin/sh|python|bash -c' /etc/cron.*/* 2>/dev/null
```
#### Hunt: SSH hardening rollback and backdoor shells
sshd_config ve sistem hesaplarının kabuklarında yapılan değişiklikler, erişimi korumak için post-exploitation sonrasında yaygındır.<sup>[[4]](#references)</sup>
```bash
# Root login enablement (flag "yes" or lax values)
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config

# System accounts with interactive shells (e.g., games → /bin/sh)
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
#### Hunt: Cloud C2 işaretleri (Dropbox/Cloudflare Tunnel)
- Dropbox API beacon'ları genellikle HTTPS üzerinden Authorization: Bearer token'larıyla api.dropboxapi.com veya content.dropboxapi.com kullanır.
- Sunuculardan beklenmeyen Dropbox çıkış trafiğini proxy/Zeek/NetFlow üzerinde arayın.
- Cloudflare Tunnel (`cloudflared`), giden 443 üzerinden yedek C2 sağlar.<sup>[[4]](#references)</sup>
```bash
ps aux | grep -E '[c]loudflared|trycloudflare'
systemctl list-units | grep -i cloudflared
```
### Services

Bir malware'ın service olarak kurulabileceği yollar:

- **/etc/inittab**: rc.sysinit gibi initialization script'lerini çağırır ve devamında startup script'lerine yönlendirir.
- **/etc/rc.d/** ve **/etc/rc.boot/**: Service startup için script'ler içerir; ikincisi daha eski Linux sürümlerinde bulunur.
- **/etc/init.d/**: Debian gibi bazı Linux sürümlerinde startup script'lerini depolamak için kullanılır.
- Linux varyantına bağlı olarak services, **/etc/inetd.conf** veya **/etc/xinetd/** üzerinden de etkinleştirilebilir.
- **/etc/systemd/system**: System ve service manager script'leri için bir dizindir.
- **/etc/systemd/system/multi-user.target.wants/**: Multi-user runlevel'da başlatılması gereken services bağlantılarını içerir.
- **/usr/local/etc/rc.d/**: Özel veya üçüncü taraf services için kullanılır.
- **\~/.config/autostart/**: Kullanıcıya özel automatic startup application'ları içindir ve kullanıcıları hedefleyen malware için bir saklanma noktası olabilir.
- **/lib/systemd/system/**: Kurulu paketler tarafından sağlanan system-wide varsayılan unit file'larını içerir.

#### Hunt: systemd timers and transient units

Systemd persistence yalnızca `.service` file'larıyla sınırlı değildir. `.timer` unit'lerini, user-level unit'lerini ve runtime sırasında oluşturulan **transient units**'leri araştırın.
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
Transient unit'leri gözden kaçırmak kolaydır çünkü `/run/systemd/transient/` **kalıcı değildir**. Canlı bir imaj topluyorsanız, sistemi kapatmadan önce bu dizini alın.

### Kernel Modules

Linux kernel modülleri, genellikle malware tarafından rootkit bileşenleri olarak kullanılır ve sistem açılışında yüklenir. Bu modüller için kritik dizin ve dosyalar şunlardır:

- **/lib/modules/$(uname -r)**: Çalışan kernel sürümüne ait modülleri içerir.
- **/etc/modprobe.d**: Modül yüklemesini kontrol eden yapılandırma dosyalarını içerir.
- **/etc/modprobe** ve **/etc/modprobe.conf**: Global modül ayarları için kullanılan dosyalardır.

### Other Autostart Locations

Linux, kullanıcı login olduğunda programları otomatik olarak çalıştırmak için çeşitli dosyalar kullanır; bu dosyalar malware barındırabilir:

- **/etc/profile.d/**\*, **/etc/profile** ve **/etc/bash.bashrc**: Herhangi bir kullanıcının login işlemi için çalıştırılır.
- **\~/.bashrc**, **\~/.bash_profile**, **\~/.profile** ve **\~/.config/autostart**: Kullanıcıya özel olup ilgili kullanıcı login olduğunda çalıştırılan dosyalardır.
- **/etc/rc.local**: Tüm sistem servisleri başlatıldıktan sonra çalışır ve çok kullanıcılı ortama geçişin sonunu belirtir.

## Examine Logs

Linux sistemleri, çeşitli log dosyaları aracılığıyla kullanıcı etkinliklerini ve sistem olaylarını takip eder. Bu log'lar yetkisiz erişimleri, malware bulaşmalarını ve diğer güvenlik olaylarını belirlemek için kritik öneme sahiptir.<sup>[[2]](#references)</sup> Temel log dosyaları şunlardır:

- **/var/log/syslog** (Debian) veya **/var/log/messages** (RedHat): Sistem genelindeki mesajları ve etkinlikleri kaydeder.
- **/var/log/auth.log** (Debian) veya **/var/log/secure** (RedHat): Authentication denemelerini, başarılı ve başarısız login işlemlerini kaydeder.
- İlgili authentication olaylarını filtrelemek için `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` kullanın.
- **/var/log/boot.log**: Sistem başlangıç mesajlarını içerir.
- **/var/log/maillog** veya **/var/log/mail.log**: E-posta sunucusu etkinliklerini kaydeder ve e-postayla ilgili servisleri izlemek için kullanışlıdır.
- **/var/log/kern.log**: Hatalar ve uyarılar dahil olmak üzere kernel mesajlarını depolar.
- **/var/log/dmesg**: Device driver mesajlarını içerir.
- **/var/log/faillog**: Başarısız login denemelerini kaydeder ve güvenlik ihlali soruşturmalarına yardımcı olur.
- **/var/log/cron**: Cron job çalıştırmalarını kaydeder.
- **/var/log/daemon.log**: Arka planda çalışan servislerin etkinliklerini takip eder.
- **/var/log/btmp**: Başarısız login denemelerini belgeler.
- **/var/log/httpd/**: Apache HTTPD hata ve erişim log'larını içerir.
- **/var/log/mysqld.log** veya **/var/log/mysql.log**: MySQL veritabanı etkinliklerini kaydeder.
- **/var/log/xferlog**: FTP dosya transferlerini kaydeder.
- **/var/log/**: Beklenmeyen log'lar için bu dizini her zaman kontrol edin.

> [!TIP]
> Linux sistem log'ları ve audit alt sistemleri, bir intrusion veya malware olayında devre dışı bırakılmış ya da silinmiş olabilir. Linux sistemlerindeki log'lar genellikle malicious etkinlikler hakkında en yararlı bilgilerin bir kısmını içerdiğinden, intruder'lar bunları rutin olarak siler. Bu nedenle, mevcut log dosyalarını incelerken silme veya tampering belirtisi olabilecek boşlukları ya da sırası bozulmuş girdileri aramak önemlidir.

### Journald triage (`journalctl`)

Modern Linux host'larında **systemd journal**, genellikle **servis çalıştırma**, **auth olayları**, **package işlemleri** ve **kernel/user-space mesajları** için en değerli kaynaktır. Live response sırasında hem **kalıcı** journal'ı (`/var/log/journal/`) hem de **runtime** journal'ı (`/run/log/journal/`) korumaya çalışın; çünkü kısa süreli attacker etkinlikleri yalnızca ikincisinde bulunabilir.<sup>[[5]](#references)</sup>
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
Triage için yararlı journal alanları arasında `_SYSTEMD_UNIT`, `_EXE`, `_COMM`, `_CMDLINE`, `_UID`, `_GID`, `_PID`, `_BOOT_ID` ve `MESSAGE` bulunur. journald persistent storage olmadan yapılandırıldıysa, `/run/log/journal/` altında yalnızca yakın tarihli verileri bekleyin.

### Audit framework triage (`auditd`)

`auditd` etkinse, file changes, command execution, login activity veya package installation için **process attribution** gerektiğinde onu tercih edin.<sup>[[6]](#references)</sup>
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
Kurallar anahtarlarla dağıtıldığında, ham loglarda grep yapmak yerine bunlardan pivot edin:
```bash
ausearch --start this-week -k <rule_key> --raw | aureport --file --summary -i
ausearch --start this-week -k <rule_key> --raw | aureport --user --summary -i
```
**Linux her kullanıcı için bir komut geçmişi tutar**; bu geçmiş şuralarda saklanır:

- \~/.bash_history
- \~/.zsh_history
- \~/.zsh_sessions/\*
- \~/.python_history
- \~/.\*\_history

Ayrıca `last -Faiwx` komutu, kullanıcı oturum açmalarının bir listesini sağlar. Bilinmeyen veya beklenmeyen oturum açmaları tespit etmek için bu listeyi kontrol edin.

Ek ayrıcalıklar sağlayabilecek dosyaları kontrol edin:

- Beklenmedik şekilde verilmiş kullanıcı ayrıcalıklarını tespit etmek için `/etc/sudoers` dosyasını inceleyin.
- Beklenmedik şekilde verilmiş kullanıcı ayrıcalıklarını tespit etmek için `/etc/sudoers.d/` dizinini inceleyin.
- Olağandışı grup üyeliklerini veya izinlerini belirlemek için `/etc/groups` dosyasını inceleyin.
- Olağandışı grup üyeliklerini veya izinlerini belirlemek için `/etc/passwd` dosyasını inceleyin.

Bazı uygulamalar da kendi loglarını oluşturur:

- **SSH**: Yetkisiz uzak bağlantıları tespit etmek için _\~/.ssh/authorized_keys_ ve _\~/.ssh/known_hosts_ dosyalarını inceleyin.
- **Gnome Desktop**: Gnome uygulamaları aracılığıyla yakın zamanda erişilen dosyaları görmek için _\~/.recently-used.xbel_ dosyasını inceleyin.
- **Firefox/Chrome**: Şüpheli etkinlikleri tespit etmek için _\~/.mozilla/firefox_ veya _\~/.config/google-chrome_ dizinlerindeki tarayıcı geçmişini ve indirilen dosyaları kontrol edin.
- **VIM**: Erişilen dosya yolları ve arama geçmişi gibi kullanım ayrıntılarını görmek için _\~/.viminfo_ dosyasını inceleyin.
- **Open Office**: Ele geçirilmiş dosyalara işaret edebilecek yakın zamanda erişilmiş belgeleri kontrol edin.
- **FTP/SFTP**: Yetkisiz olabilecek dosya aktarımlarını tespit etmek için _\~/.ftp_history_ veya _\~/.sftp_history_ dosyalarındaki logları inceleyin.
- **MySQL**: Yetkisiz veritabanı etkinliklerini ortaya çıkarabilecek çalıştırılmış MySQL sorgularını tespit etmek için _\~/.mysql_history_ dosyasını inceleyin.
- **Less**: Görüntülenen dosyalar ve çalıştırılan komutlar dahil kullanım geçmişini analiz etmek için _\~/.lesshst_ dosyasını inceleyin.
- **Git**: Depolardaki değişiklikleri tespit etmek için _\~/.gitconfig_ dosyasını ve proje içindeki _.git/logs_ dizinini inceleyin.

### USB Logları

[**usbrip**](https://github.com/snovvcrash/usbrip), USB olay geçmişi tabloları oluşturmak amacıyla Linux log dosyalarını (dağıtıma bağlı olarak `/var/log/syslog*` veya `/var/log/messages*`) ayrıştıran, saf Python 3 ile yazılmış küçük bir yazılımdır.

**Kullanılmış tüm USB'leri bilmek** ilginçtir ve "ihlal olaylarını" (listede bulunmayan USB'lerin kullanılması) tespit etmek için yetkili USB'lerden oluşan bir listeniz varsa daha da yararlı olacaktır.

### Kurulum
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
github içinde daha fazla örnek ve bilgi: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

## Kullanıcı Hesaplarını ve Oturum Açma Etkinliklerini İnceleme

Bilinen yetkisiz olaylara yakın zamanlarda oluşturulan veya kullanılan olağandışı adları ya da hesapları tespit etmek için _**/etc/passwd**_, _**/etc/shadow**_ ve **security logs** dosyalarını inceleyin. Ayrıca olası sudo brute-force saldırılarını kontrol edin.\
Bununla birlikte, kullanıcılara beklenmedik ayrıcalıklar verilip verilmediğini görmek için _**/etc/sudoers**_ ve _**/etc/groups**_ gibi dosyaları kontrol edin.\
Son olarak, **no passwords** veya **easily guessed** parolalara sahip hesapları arayın.<sup>[[1]](#references)</sup>

## Dosya Sistemini İnceleme

### Malware Investigation Sırasında Dosya Sistemi Yapılarını Analiz Etme

Malware olaylarını araştırırken dosya sisteminin yapısı, hem olayların sırasını hem de malware'in içeriğini ortaya çıkaran kritik bir bilgi kaynağıdır. Ancak malware yazarları, dosya zaman damgalarını değiştirmek veya veri depolamak için dosya sistemini kullanmaktan kaçınmak gibi bu analizi zorlaştıran teknikler geliştiriyor.<sup>[[1]](#references)</sup>

Bu anti-forensic yöntemlere karşı koymak için şunları yapmak önemlidir:

- Olay zaman çizelgelerini görselleştirmek için **Autopsy** veya ayrıntılı zaman çizelgesi verileri için **Sleuth Kit's** `mactime` gibi araçları kullanarak **kapsamlı bir zaman çizelgesi analizi gerçekleştirin**.
- Saldırganlar tarafından kullanılan shell veya PHP scriptlerini içerebilecek sistemin $PATH'i içindeki **beklenmeyen scriptleri araştırın**.
- Geleneksel olarak özel dosyalar içeren, ancak malware ile ilişkili dosyaları barındırabilen **`/dev` dizinindeki sıra dışı dosyaları inceleyin**.
- Kötü amaçlı içeriği gizleyebilecek ".. " (dot dot space) veya "..^G" (dot dot control-G) gibi adlara sahip **gizli dosya veya dizinleri arayın**.
- `find / -user root -perm -04000 -print` komutunu kullanarak **setuid root dosyalarını belirleyin**. Bu komut, saldırganlar tarafından kötüye kullanılabilecek yükseltilmiş izinlere sahip dosyaları bulur.
- Muhtemelen rootkits veya trojans varlığına işaret eden toplu dosya silme işlemlerini tespit etmek için inode tablolarındaki **silinme zaman damgalarını inceleyin**.
- Bir kötü amaçlı dosya belirledikten sonra yakındaki diğer kötü amaçlı dosyaları bulmak için **ardışık inode'ları inceleyin**; bu dosyalar birlikte yerleştirilmiş olabilir.
- Malware tarafından değiştirilmiş olabileceklerinden, son zamanlarda değiştirilmiş dosyalar için yaygın binary dizinlerini (_/bin_, _/sbin_) **kontrol edin**.
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
> [!TIP]
> Bir **saldırganın**, **dosyaların** **meşru görünmesini** sağlamak için **zamanı** **değiştirebileceğini**, ancak **inode'u** değiştiremeyeceğini unutmayın. Bir **dosyanın**, aynı klasördeki diğer dosyalarla **aynı zamanda oluşturulduğunu ve değiştirildiğini** gösterdiğini, ancak **inode'un** **beklenmedik şekilde daha büyük** olduğunu fark ederseniz, bu **dosyanın zaman damgaları değiştirilmiştir**.

### Inode odaklı hızlı triage

Anti-forensics'ten şüpheleniyorsanız, şu inode odaklı kontrolleri erkenden çalıştırın:
```bash
# Filesystem inode pressure (possible inode exhaustion DoS)
df -i

# Identify all names that point to one inode
find / -xdev -inum <inode_number> 2>/dev/null

# Find deleted files still open by running processes
lsof +L1
lsof | grep '(deleted)'
```
Şüpheli bir inode bir EXT dosya sistemi imajı/cihazı üzerindeyse, inode meta verilerini doğrudan inceleyin:
```bash
sudo debugfs -R "stat <inode_number>" /dev/sdX
```
Kullanışlı alanlar:
- **Links**: `0` ise inode'a şu anda hiçbir dizin girdisi başvurmuyor demektir.
- **dtime**: inode unlink edildiğinde ayarlanan silinme zaman damgası.
- **ctime/mtime**: metadata/içerik değişikliklerini olay zaman çizelgesiyle ilişkilendirmeye yardımcı olur.

### Capabilities, xattrs ve preload tabanlı userland rootkit'leri

Modern Linux persistence, genellikle bariz **setuid** binary'lerinden kaçınır ve bunun yerine **file capabilities**, **extended attributes** ve dynamic loader'ı kötüye kullanır.
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
`/tmp`, `/dev/shm`, `/var/tmp` gibi **yazılabilir** yollardan veya `/usr/local/lib` altındaki alışılmadık konumlardan referans verilen kütüphanelere özellikle dikkat edin. Ayrıca normal paket sahipliği dışında kalan capability içeren binary'leri kontrol edin ve bunları paket doğrulama sonuçlarıyla (`rpm -Va`, `dpkg --verify`, `debsums`) ilişkilendirin.

## Farklı filesystem sürümlerindeki dosyaları karşılaştırma

### Filesystem Sürümü Karşılaştırma Özeti

Filesystem sürümlerini karşılaştırmak ve değişiklikleri belirlemek için basitleştirilmiş `git diff` komutlarını kullanırız:<sup>[[3]](#references)</sup>

- **Yeni dosyaları bulmak için** iki dizini karşılaştırın:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
- **Değiştirilmiş içerik için**, belirli satırları göz ardı ederek değişiklikleri listeleyin:
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
- **Silinen dosyaları tespit etmek için**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
- **Filter options** (`--diff-filter`) belirli değişiklikleri, örneğin eklenen (`A`), silinen (`D`) veya değiştirilen (`M`) dosyaları daraltmaya yardımcı olur.
- `A`: Eklenen dosyalar
- `C`: Kopyalanan dosyalar
- `D`: Silinen dosyalar
- `M`: Değiştirilen dosyalar
- `R`: Yeniden adlandırılan dosyalar
- `T`: Tür değişiklikleri (ör. dosyadan symlink'e)
- `U`: Birleştirilmemiş dosyalar
- `X`: Bilinmeyen dosyalar
- `B`: Bozuk dosyalar

## References

- [1] [Linux Sistemleri için Malware Forensics Field Guide: Digital Forensics Field Guides – Bölüm 3](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf)
- [2] [Linux Logları Açıklaması](https://www.plesk.com/blog/featured/linux-logs-explained/)
- [3] [git diff Documentation – --diff-filter seçeneği](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
- [4] [Red Canary – Persistence için patch uygulama: DripDropper Linux malware cloud içinde nasıl ilerliyor](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [5] [Linux Journal'larının Forensic Analizi](https://stuxnet999.github.io/dfir/linux-journal-forensics/)
- [6] [Red Hat Enterprise Linux 9 - Sistemin auditing işlemi](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening)
- [7] [Pike ile tanışın!](https://www.synacktiv.com/en/publications/say-hi-to-pike.html)
- [8] [strace](https://strace.io/)
- [9] [SQLite FTS5 Extension](https://www.sqlite.org/fts5.html)
{{#include ../../banners/hacktricks-training.md}}
