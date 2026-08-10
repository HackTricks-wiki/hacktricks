# Linux Adli İncelemesi

## İlk Bilgi Toplama

### Temel Bilgiler

Her şeyden önce, üzerinde bazı **iyi olduğu bilinen binary'ler ve library'ler bulunan bir **USB** bulundurmanız önerilir (ubuntu'yu indirip _/bin_, _/sbin_, _/lib,_ ve _/lib64_ klasörlerini kopyalayabilirsiniz); ardından USB'yi mount edin ve bu binary'leri kullanmak için env değişkenlerini değiştirin:
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

Temel bilgileri elde ederken aşağıdakiler gibi garip şeyleri kontrol etmelisiniz:

- **Root işlemleri** genellikle düşük PID'lerle çalışır; bu nedenle büyük bir PID'ye sahip bir root işlemi bulursanız şüphelenebilirsiniz
- `/etc/passwd` içinde shell'i olmayan kullanıcıların **kayıtlı girişlerini** kontrol edin
- Shell'i olmayan kullanıcılar için `/etc/shadow` içinde **password hash'lerini** kontrol edin

### Bellek Dökümü

Çalışan sistemin belleğini elde etmek için [**LiME**](https://github.com/504ensicsLabs/LiME) kullanılması önerilir.\
Bunu **derlemek** için victim makinesinin kullandığı **aynı kernel'i** kullanmanız gerekir.

> [!TIP]
> Victim makinesine **LiME veya başka herhangi bir şey yükleyemeyeceğinizi** unutmayın; çünkü bu, makinede çeşitli değişiklikler yapacaktır

Bu nedenle, Ubuntu'nun aynı sürümüne sahipseniz `apt-get install lime-forensics-dkms` kullanabilirsiniz.\
Diğer durumlarda [**LiME**](https://github.com/504ensicsLabs/LiME) dosyasını github'dan indirmeniz ve doğru kernel header'larıyla derlemeniz gerekir. Victim makinesinin **tam kernel header'larını elde etmek** için `/lib/modules/<kernel version>` dizinini makinenize **kopyalayabilir** ve ardından LiME'ı bunları kullanarak **derleyebilirsiniz**:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME 3 **formatı** destekler:

- Raw (her segment birbiriyle birleştirilir)
- Padded (Raw ile aynı, ancak sağ bitlerde sıfırlar bulunur)
- Lime (metadata içeren önerilen format

LiME, `path=tcp:4444` gibi bir yöntem kullanarak dump'ı sistemde depolamak yerine **network üzerinden göndermek** için de kullanılabilir.

### Disk Imaging

#### Kapatma

Her şeyden önce sistemi **kapatmanız** gerekecektir. Bu her zaman bir seçenek değildir; çünkü bazı durumlarda sistem, şirketin kapatmayı göze alamayacağı bir production server olabilir.\
Sistemi kapatmanın **2 yolu** vardır: **normal shutdown** ve **"fişi çekme" shutdown**. İlki **process'lerin normal şekilde sonlanmasına** ve **filesystem'in** **synchronize edilmesine** olanak tanır; ancak olası **malware'in** **kanıtları yok etmesine** de izin verir. "Fişi çekme" yaklaşımı **bir miktar bilgi kaybına** yol açabilir (memory'nin image'ını zaten aldığımız için bilgilerin çoğu kaybolmayacaktır) ve **malware'in** bu konuda herhangi bir şey yapma **fırsatı olmayacaktır**. Bu nedenle bir **malware** olabileceğinden **şüpheleniyorsanız**, sistemde yalnızca **`sync`** **command'ini** çalıştırın ve fişi çekin.

#### Disk görüntüsünün alınması

**Computer'ınızı vakayla ilgili herhangi bir şeye bağlamadan önce**, herhangi bir bilginin değiştirilmesini önlemek için bunun **read only olarak mount edileceğinden** emin olmanız önemlidir.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Disk Image ön analizi

Daha fazla veri içermeyen bir disk image oluşturma.
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
## Bilinen Malware'ı Arama

### Değiştirilmiş Sistem Dosyaları

Linux, potansiyel olarak sorunlu dosyaları tespit etmek için kritik olan sistem bileşenlerinin bütünlüğünü doğrulamaya yönelik araçlar sunar.<sup>[[1]](#references)</sup>

- **RedHat tabanlı sistemler**: Kapsamlı bir kontrol için `rpm -Va` kullanın.
- **Debian tabanlı sistemler**: İlk doğrulama için `dpkg --verify` kullanın; ardından sorunları tespit etmek için `debsums | grep -v "OK$"` çalıştırın (`debsums` paketini `apt-get install debsums` ile yükledikten sonra).

### Malware/Rootkit Detectors

Malware bulmak için yararlı olabilecek araçlar hakkında bilgi edinmek üzere aşağıdaki sayfayı okuyun:


{{#ref}}
malware-analysis.md
{{#endref}}

## Yüklü programları arama

Hem Debian hem de RedHat sistemlerinde yüklü programları etkili bir şekilde aramak için yaygın dizinlerdeki manuel kontrollerin yanı sıra sistem loglarından ve veritabanlarından yararlanmayı değerlendirin.<sup>[[1]](#references)</sup>

- Debian için paket kurulumlarıyla ilgili ayrıntıları almak üzere _**`/var/lib/dpkg/status`**_ ve _**`/var/log/dpkg.log`**_ dosyalarını inceleyin; belirli bilgileri filtrelemek için `grep` kullanın.
- RedHat kullanıcıları, yüklü paketleri listelemek için RPM veritabanını `rpm -qa --root=/mntpath/var/lib/rpm` komutuyla sorgulayabilir.

Bu paket yöneticileri kullanılarak manuel olarak veya bunların dışında yüklenen yazılımları ortaya çıkarmak için _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_ ve _**`/sbin`**_ gibi dizinleri inceleyin. Bilinen paketlerle ilişkili olmayan çalıştırılabilir dosyaları tespit etmek ve yüklü tüm programları aramanızı genişletmek için dizin listelemelerini sisteme özgü komutlarla birleştirin.
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

/tmp/exec üzerinden çalıştırılan ve ardından silinen bir process düşünün. Onu çıkarmak mümkündür
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## SQLite ve FTS5 ile Syscall Trace Triage

Bir process hâlâ çalışıyorsa veya bir lab ortamında yeniden çalıştırılabiliyorsa, **`strace`** kernel module'larına ya da tam EDR telemetry'sine ihtiyaç duymadan hızlı bir davranış trace'i sağlayabilir. Büyük trace'ler için raw log'u doğrudan okumaktan veya bir LLM'e yapıştırmaktan kaçının: Log'u bir **SQLite** database'inde saklayın ve yalnızca ihtiyacınız olan minimum alt kümeyi sorgulayın.<sup>[[7]](#references)[[8]](#references)[[9]](#references)</sup>

> [!WARNING]
> `strace` ile process'e bağlanmak, process timing'ini değiştirir ve race condition'ları veya diğer hassas bug'ları etkileyebilir. Mümkün olduğunda reproducing işlemini bir kopya/lab sisteminde gerçekleştirmeyi tercih edin.

### Capture

Yeni bir process için:
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log <command>
```
Canlı bir süreç için:
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log -p <PID>
```
Yararlı seçenekler:

- `-ff`: fork/thread işlemlerini takip eder ve işlem başına çıktıları ayrı tutar
- `-ttt`: kolay zaman çizelgesi korelasyonu için epoch zaman damgaları
- `-yy`: mümkün olduğunda file descriptor'ları arka plandaki path/socket'lere çözümler
- `-s 4096`: uzun path ve buffer argümanlarının kesilmesini önler

### Normalize Et

Pratik bir şema, her syscall ve her argüman için bir satır olacak şekildedir:
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
Bu, heterojen syscall satırlarını tek ve geniş bir tabloya düzleştirmeye çalışmayı önler ve triage sırasında join işlemlerini öngörülebilir tutar.

### FTS5 ile metin ağırlıklı argümanları indeksleyin

`LIKE "%...%"` ile yapılan naif path aramaları, büyük trace'lerde çok yavaşlar. Argüman metni için bir FTS5 index'i oluşturun ve bunun yerine onu arayın:
```sql
CREATE VIRTUAL TABLE syscall_args_fts
USING fts5(raw, content='syscall_args', content_rowid='id');

INSERT INTO syscall_args_fts(rowid, raw)
SELECT id, raw FROM syscall_args;
```
Örnek: Her satırı taramadan `/tmp` altındaki dosya etkinliğini kurtarma:
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

- **PATH hijacking / fake sudo**: `~/.local/bin/` altında yazma ve `chmod`/`rename` etkinliklerini arayın, ardından bunları `sudo` gibi ayrıcalıklı görünen adların sonraki `execve` çağrılarıyla ilişkilendirin.
- **Geçici dosyalarda TOCTOU**: Denetim/kullanım arasındaki boşlukları tespit etmek için aynı `/tmp/...` yolunu `stat`, `access`, `openat`, `rename`, `unlink`, `link`, `symlink` ve `execve` boyunca takip edin.
- **Çökme kök nedeni**: Bir dosyanın `mmap` çağrısını, aynı inode/yol üzerinde başka bir process tarafından gerçekleştirilen yazma veya truncation işlemleriyle ilişkilendirin; ardından `SIGBUS` için signal/exit sequence bilgisini inceleyin.
- **Network destination recovery**: Peer IP'lerini ve portlarını çıkarmak için `connect`, `sendto`, `sendmsg`, `recvfrom` ve socket ile ilgili argümanları filtreleyin.

### LLM-assisted trace analysis

Bir LLM'den yardım almak istiyorsanız, **read-only** bir SQLite handle sunun ve full schema bilgisini verin. Veritabanını dar kapsamlı helper function'ların arkasına sarmak yerine raw SQL çalıştırmasına izin verin. Bu yaklaşım genellikle join'ler, temporal correlation ve FTS lookup'ları için daha iyi sonuç verir.

Pratik kurallar:

- Veritabanını read-only tutun; örneğin `sqlite3 'file:trace.db?mode=ro'`.
- Modele geçerli `JOIN` ve `FTS5 MATCH` query örnekleri verin.
- Ham, çok GB boyutundaki `strace` log'larını prompt'a yapıştırmayın.
- Şu tür odaklanmış sorular sorun:
- "Bu program tarafından yazılan kalıcı dosyaları listele."
- "Kullanıcı tarafından kontrol edilen PATH dizinlerinde executable dosyalar oluşturdu veya değiştirdi mi?"
- "Bu trace neden SIGBUS ile sonlanıyor?"

## Autostart konumlarını inceleme

### Zamanlanmış Görevler
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
#### Hunt: Cron/Anacron abuse via 0anacron ve şüpheli stub'lar
Saldırganlar, periyodik çalıştırmayı sağlamak için genellikle her /etc/cron.*/ dizini altında bulunan 0anacron stub'ını düzenler.<sup>[[4]](#references)</sup>
```bash
# List 0anacron files and their timestamps/sizes
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done

# Look for obvious execution of shells or downloaders embedded in cron stubs
grep -R --line-number -E 'curl|wget|/bin/sh|python|bash -c' /etc/cron.*/* 2>/dev/null
```
#### Araştırma: SSH hardening rollback ve backdoor shells
sshd_config ve system account shell'lerinde yapılan değişiklikler, erişimi korumak için post-exploitation sonrasında yaygındır.<sup>[[4]](#references)</sup>
```bash
# Root login enablement (flag "yes" or lax values)
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config

# System accounts with interactive shells (e.g., games → /bin/sh)
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
#### Hunt: Cloud C2 göstergeleri (Dropbox/Cloudflare Tunnel)
- Dropbox API beacon'ları genellikle HTTPS üzerinden `api.dropboxapi.com` veya `content.dropboxapi.com` adreslerini ve `Authorization: Bearer` token'larını kullanır.
- Sunuculardan beklenmeyen Dropbox çıkış trafiğini proxy/Zeek/NetFlow üzerinde araştırın.
- Cloudflare Tunnel (`cloudflared`), dışarıya giden 443 üzerinden yedek C2 sağlar.<sup>[[4]](#references)</sup>
```bash
ps aux | grep -E '[c]loudflared|trycloudflare'
systemctl list-units | grep -i cloudflared
```
### Hizmetler

Bir malware'in service olarak kurulabileceği yollar:

- **/etc/inittab**: rc.sysinit gibi initialization script'lerini çağırır ve devamında startup script'lerine yönlendirir.
- **/etc/rc.d/** ve **/etc/rc.boot/**: Service startup için script'leri içerir; ikincisi eski Linux sürümlerinde bulunur.
- **/etc/init.d/**: Debian gibi belirli Linux sürümlerinde startup script'lerini depolamak için kullanılır.
- Linux varyantına bağlı olarak service'ler **/etc/inetd.conf** veya **/etc/xinetd/** üzerinden de etkinleştirilebilir.
- **/etc/systemd/system**: System ve service manager script'leri için bir dizindir.
- **/etc/systemd/system/multi-user.target.wants/**: Multi-user runlevel'da başlatılması gereken service'lere yönelik link'leri içerir.
- **/usr/local/etc/rc.d/**: Özel veya third-party service'ler için kullanılır.
- **\~/.config/autostart/**: Kullanıcıya özel automatic startup application'ları içindir ve user-targeted malware için bir saklanma noktası olabilir.
- **/lib/systemd/system/**: Kurulu package'ler tarafından sağlanan system-wide default unit file'larını içerir.

#### Araştırma: systemd timer'ları ve transient unit'ler

Systemd persistence yalnızca `.service` file'larıyla sınırlı değildir. `.timer` unit'lerini, user-level unit'lerini ve runtime sırasında oluşturulan **transient unit**'leri inceleyin.
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
Transient units are kolayca gözden kaçabilir çünkü `/run/systemd/transient/` **kalıcı değildir**. Canlı bir imaj topluyorsanız, sistemi kapatmadan önce bu dizini alın.

### Kernel Modules

Linux kernel modules, genellikle malware tarafından rootkit bileşenleri olarak kullanılır ve sistem açılışında yüklenir. Bu modules için kritik dizin ve dosyalar şunlardır:

- **/lib/modules/$(uname -r)**: Çalışan kernel sürümüne ait modules öğelerini barındırır.
- **/etc/modprobe.d**: Module loading işlemini kontrol etmek için yapılandırma dosyalarını içerir.
- **/etc/modprobe** ve **/etc/modprobe.conf**: Global module ayarları için kullanılan dosyalardır.

### Other Autostart Locations

Linux, user login sırasında programları otomatik olarak çalıştırmak için çeşitli dosyalar kullanır; bu dosyalar malware barındırabilir:

- **/etc/profile.d/**\*, **/etc/profile** ve **/etc/bash.bashrc**: Herhangi bir user login olduğunda çalıştırılır.
- **\~/.bashrc**, **\~/.bash_profile**, **\~/.profile** ve **\~/.config/autostart**: User login olduğunda çalışan user-specific dosyalardır.
- **/etc/rc.local**: Tüm system services başlatıldıktan sonra çalışır ve multiuser ortamına geçişin sonunu belirtir.

## Examine Logs

Linux systems, çeşitli log files aracılığıyla user activities ve system events bilgilerini takip eder. Bu logs, unauthorized access, malware infections ve diğer security incidents olaylarını tespit etmek için kritik öneme sahiptir.<sup>[[2]](#references)</sup> Önemli log files şunlardır:

- **/var/log/syslog** (Debian) veya **/var/log/messages** (RedHat): System-wide messages ve activities bilgilerini yakalar.
- **/var/log/auth.log** (Debian) veya **/var/log/secure** (RedHat): Authentication attempts ile successful ve failed logins bilgilerini kaydeder.
- İlgili authentication events öğelerini filtrelemek için `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` kullanın.
- **/var/log/boot.log**: System startup messages içerir.
- **/var/log/maillog** veya **/var/log/mail.log**: Email server activities bilgilerini kaydeder; email-related services takibi için kullanışlıdır.
- **/var/log/kern.log**: Errors ve warnings dahil olmak üzere kernel messages bilgilerini depolar.
- **/var/log/dmesg**: Device driver messages bilgilerini barındırır.
- **/var/log/faillog**: Failed login attempts bilgilerini kaydeder ve security breach investigations süreçlerine yardımcı olur.
- **/var/log/cron**: Cron job executions bilgilerini kaydeder.
- **/var/log/daemon.log**: Background service activities bilgilerini takip eder.
- **/var/log/btmp**: Failed login attempts bilgilerini belgeler.
- **/var/log/httpd/**: Apache HTTPD error ve access logs içerir.
- **/var/log/mysqld.log** veya **/var/log/mysql.log**: MySQL database activities bilgilerini kaydeder.
- **/var/log/xferlog**: FTP file transfers bilgilerini kaydeder.
- **/var/log/**: Beklenmeyen logs için her zaman kontrol edin.

> [!TIP]
> Linux system logs ve audit subsystems, bir intrusion veya malware incident sırasında devre dışı bırakılmış ya da silinmiş olabilir. Linux systems üzerindeki logs genellikle malicious activities hakkında en yararlı bilgilerin bir kısmını içerdiğinden, intruders bunları rutin olarak siler. Bu nedenle, mevcut log files incelenirken deletion veya tampering göstergesi olabilecek gaps ya da sırası bozulmuş entries olup olmadığına dikkat etmek önemlidir.

### Journald triage (`journalctl`)

Modern Linux hosts üzerinde **systemd journal**, genellikle **service execution**, **auth events**, **package operations** ve **kernel/user-space messages** için en değerli kaynaktır. Live response sırasında hem **persistent** journal'ı (`/var/log/journal/`) hem de **runtime** journal'ı (`/run/log/journal/`) korumaya çalışın; çünkü kısa süreli attacker activity yalnızca ikincisinde bulunabilir.<sup>[[5]](#references)</sup>
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
Triage için yararlı journal alanları arasında `_SYSTEMD_UNIT`, `_EXE`, `_COMM`, `_CMDLINE`, `_UID`, `_GID`, `_PID`, `_BOOT_ID` ve `MESSAGE` bulunur. journald persistent storage olmadan yapılandırıldıysa, `/run/log/journal/` altında yalnızca yakın tarihli veriler bulunmasını bekleyin.

### Audit framework triage (`auditd`)

`auditd` etkinse dosya değişiklikleri, command execution, login activity veya package installation için **process attribution** gerektiğinde onu tercih edin.<sup>[[6]](#references)</sup>
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
Kurallar anahtarlarla deploy edildiğinde, ham log'larda grep yapmak yerine bunlardan pivot edin:
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

Ayrıca `last -Faiwx` komutu, kullanıcı oturum açma işlemlerinin bir listesini sağlar. Bilinmeyen veya beklenmeyen oturum açma işlemleri için bu listeyi kontrol edin.

Ek ayrıcalıklar sağlayabilecek dosyaları kontrol edin:

- Beklenmedik kullanıcı ayrıcalıkları verilmiş olup olmadığını belirlemek için `/etc/sudoers` dosyasını inceleyin.
- Beklenmedik kullanıcı ayrıcalıkları verilmiş olup olmadığını belirlemek için `/etc/sudoers.d/` dizinini inceleyin.
- Olağan dışı grup üyeliklerini veya izinlerini belirlemek için `/etc/groups` dosyasını inceleyin.
- Olağan dışı grup üyeliklerini veya izinlerini belirlemek için `/etc/passwd` dosyasını inceleyin.

Bazı uygulamalar ayrıca kendi loglarını oluşturur:

- **SSH**: Yetkisiz uzak bağlantıları belirlemek için _\~/.ssh/authorized_keys_ ve _\~/.ssh/known_hosts_ dosyalarını inceleyin.
- **Gnome Desktop**: Gnome uygulamaları aracılığıyla yakın zamanda erişilen dosyaları belirlemek için _\~/.recently-used.xbel_ dosyasını inceleyin.
- **Firefox/Chrome**: Şüpheli etkinlikler için _\~/.mozilla/firefox_ veya _\~/.config/google-chrome_ dizinlerindeki tarayıcı geçmişini ve indirilen dosyaları kontrol edin.
- **VIM**: Erişilen dosya yolları ve arama geçmişi gibi kullanım ayrıntıları için _\~/.viminfo_ dosyasını inceleyin.
- **Open Office**: Ele geçirilmiş dosyalara işaret edebilecek son belge erişimlerini kontrol edin.
- **FTP/SFTP**: Yetkisiz olabilecek dosya aktarımları için _\~/.ftp_history_ veya _\~/.sftp_history_ dosyalarındaki logları inceleyin.
- **MySQL**: Yetkisiz veritabanı etkinliklerini açığa çıkarabilecek çalıştırılmış MySQL sorguları için _\~/.mysql_history_ dosyasını inceleyin.
- **Less**: Görüntülenen dosyalar ve çalıştırılan komutlar dahil kullanım geçmişi için _\~/.lesshst_ dosyasını analiz edin.
- **Git**: Depolardaki değişiklikler için _\~/.gitconfig_ dosyasını ve projelerdeki _.git/logs_ dizinini inceleyin.

### USB Logları

[**usbrip**](https://github.com/snovvcrash/usbrip), USB olay geçmişi tabloları oluşturmak amacıyla Linux log dosyalarını (`/var/log/syslog*` veya dağıtıma bağlı olarak `/var/log/messages*`) ayrıştıran, saf Python 3 ile yazılmış küçük bir yazılımdır.

**Kullanılmış tüm USB'leri bilmek** ilgi çekicidir; ayrıca "ihlal olaylarını" (listedekiler arasında bulunmayan USB'lerin kullanımını) tespit etmek için yetkili USB'lerden oluşan bir listeye sahip olmak daha faydalı olacaktır.

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
github içinde daha fazla örnek ve bilgi bulunabilir: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

## Kullanıcı Hesaplarını ve Oturum Açma Etkinliklerini İnceleme

Bilinen yetkisiz olaylarla yakın zamanlarda oluşturulan veya kullanılan olağandışı adlar ya da hesaplar için _**/etc/passwd**_, _**/etc/shadow**_ ve **güvenlik günlüklerini** inceleyin. Ayrıca olası sudo brute-force saldırılarını kontrol edin.\
Bunun yanı sıra, kullanıcılara beklenmedik ayrıcalıklar verilip verilmediğini kontrol etmek için _**/etc/sudoers**_ ve _**/etc/groups**_ gibi dosyaları inceleyin.\
Son olarak, **parolası olmayan** veya **kolayca tahmin edilebilen** parolalara sahip hesapları arayın.<sup>[[1]](#references)</sup>

## Dosya Sistemini İnceleme

### Malware Investigation'da Dosya Sistemi Yapılarını Analiz Etme

Malware olaylarını araştırırken dosya sisteminin yapısı, hem olayların sırasını hem de malware'in içeriğini ortaya çıkaran kritik bir bilgi kaynağıdır. Ancak malware yazarları, dosya zaman damgalarını değiştirmek veya veri depolamak için dosya sistemini kullanmaktan kaçınmak gibi bu analizi zorlaştıran teknikler geliştiriyor.<sup>[[1]](#references)</sup>

Bu anti-forensic yöntemlere karşı koymak için şunları yapmak önemlidir:

- Olay zaman çizelgelerini görselleştirmek için **Autopsy** veya ayrıntılı zaman çizelgesi verileri için **Sleuth Kit'in** `mactime` aracını kullanarak **kapsamlı bir zaman çizelgesi analizi gerçekleştirin**.
- Saldırganlar tarafından kullanılan shell veya PHP scriptlerini içerebilecek sistemin $PATH'indeki **beklenmeyen scriptleri inceleyin**.
- Geleneksel olarak özel dosyalar içeren, ancak malware ile ilgili dosyaları barındırabilecek `/dev` dizinini **alışılmadık dosyalar açısından inceleyin**.
- Kötü amaçlı içeriği gizleyebilecek ".. " (dot dot space) veya "..^G" (dot dot control-G) gibi adlara sahip **gizli dosya ya da dizinleri arayın**.
- `find / -user root -perm -04000 -print` komutunu kullanarak **setuid root dosyalarını belirleyin**. Bu komut, saldırganlar tarafından kötüye kullanılabilecek yükseltilmiş izinlere sahip dosyaları bulur.
- Muhtemelen rootkit veya trojan varlığına işaret edebilecek toplu dosya silme işlemlerini tespit etmek için inode tablolarındaki **silinme zaman damgalarını inceleyin**.
- Bir kötü amaçlı dosya belirledikten sonra, birlikte yerleştirilmiş olabileceklerinden yakındaki **ardışık inode'ları inceleyin**.
- Malware tarafından değiştirilmiş olabileceklerinden, **yaygın binary dizinlerinde** (_/bin_, _/sbin_) yakın zamanda değiştirilmiş dosyaları kontrol edin.
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
> [!TIP]
> Bir **saldırganın**, **dosyaların meşru görünmesini sağlamak** için **zamanı** **değiştirebileceğini**, ancak **inode'u** değiştiremeyeceğini unutmayın. Bir **dosyanın**, aynı klasördeki diğer dosyalarla **aynı zamanda oluşturulduğunu ve değiştirildiğini** gösterdiğini, ancak **inode'un** **beklenmedik şekilde daha büyük** olduğunu fark ederseniz, bu dosyanın **zaman damgaları değiştirilmiştir**.

### Inode-odaklı hızlı ön inceleme

anti-forensics'den şüpheleniyorsanız, şu inode-odaklı kontrolleri erkenden çalıştırın:
```bash
# Filesystem inode pressure (possible inode exhaustion DoS)
df -i

# Identify all names that point to one inode
find / -xdev -inum <inode_number> 2>/dev/null

# Find deleted files still open by running processes
lsof +L1
lsof | grep '(deleted)'
```
Şüpheli bir inode EXT filesystem image/device üzerinde olduğunda, inode metadata'sını doğrudan inceleyin:
```bash
sudo debugfs -R "stat <inode_number>" /dev/sdX
```
Kullanışlı alanlar:
- **Links**: `0` ise hiçbir dizin girdisi şu anda inode'a referans vermiyor demektir.
- **dtime**: inode'un bağlantısı kaldırıldığında ayarlanan silinme zaman damgasıdır.
- **ctime/mtime**: metadata/içerik değişikliklerini olay zaman çizelgesiyle ilişkilendirmeye yardımcı olur.

### Capabilities, xattrs ve preload tabanlı userland rootkit'ler

Modern Linux persistence genellikle bariz **setuid** binary'lerinden kaçınır ve bunun yerine **file capabilities**, **extended attributes** ve dynamic loader'ı kötüye kullanır.
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
**yazılabilir** konumlardan (örneğin `/tmp`, `/dev/shm`, `/var/tmp` veya `/usr/local/lib` altındaki alışılmadık konumlardan) referans verilen kütüphanelere özellikle dikkat edin. Ayrıca normal paket sahipliği dışında kalan capability taşıyan binary dosyalarını kontrol edin ve bunları paket doğrulama sonuçlarıyla (`rpm -Va`, `dpkg --verify`, `debsums`) ilişkilendirin.

## Farklı filesystem sürümlerindeki dosyaları karşılaştırma

### Filesystem Sürümü Karşılaştırma Özeti

Filesystem sürümlerini karşılaştırmak ve değişiklikleri belirlemek için basitleştirilmiş `git diff` komutlarını kullanırız:<sup>[[3]](#references)</sup>

- **Yeni dosyaları bulmak için** iki dizini karşılaştırın:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
- **Değiştirilmiş içerik** için, belirli satırları yok sayarak değişiklikleri listeleyin:
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
- **Silinen dosyaları tespit etmek için**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
- **Filter options** (`--diff-filter`), eklenen (`A`), silinen (`D`) veya değiştirilen (`M`) dosyalar gibi belirli değişiklikleri filtrelemeye yardımcı olur.
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

- [1] [Linux Systems için Malware Forensics Field Guide: Digital Forensics Field Guides – Bölüm 3](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf)
- [2] [Linux Logs Açıklaması](https://www.plesk.com/blog/featured/linux-logs-explained/)
- [3] [git diff Documentation – --diff-filter seçeneği](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
- [4] [Red Canary – Persistence için patch uygulama: DripDropper Linux malware cloud içinde nasıl ilerliyor](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [5] [Linux Journals'ın Forensic Analizi](https://stuxnet999.github.io/dfir/linux-journal-forensics/)
- [6] [Red Hat Enterprise Linux 9 - Sistemin denetlenmesi](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening)
- [7] [Pike'a merhaba deyin!](https://www.synacktiv.com/en/publications/say-hi-to-pike.html)
- [8] [strace](https://strace.io/)
- [9] [SQLite FTS5 Extension](https://www.sqlite.org/fts5.html)
{{#include ../../banners/hacktricks-training.md}}
