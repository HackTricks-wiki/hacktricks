# Linux Forensics

{{#include ../../banners/hacktricks-training.md}}

## İlk Bilgi Toplama

### Temel Bilgiler

İlk olarak, üzerinde **iyi bilinen binary'ler ve library'ler** bulunan bazı **USB**'lere sahip olmanız önerilir (sadece ubuntu alıp _/bin_, _/sbin_, _/lib,_ ve _/lib64_ klasörlerini kopyalayabilirsiniz), ardından USB'yi mount edin ve bu binary'leri kullanmak için env değişkenlerini değiştirin:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
Sistemi iyi ve bilinen binary’leri kullanacak şekilde yapılandırdıktan sonra, **bazı temel bilgileri çıkarmaya** başlayabilirsiniz:
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
#### Şüpheli bilgi

Temel bilgileri elde ederken şu tür garip şeyleri kontrol etmelisiniz:

- **Root process**ler genellikle düşük PID’lerle çalışır, bu yüzden büyük bir PID’ye sahip bir root process bulursanız şüphelenebilirsiniz
- `/etc/passwd` içinde shell’i olmayan kullanıcıların **registered logins** kayıtlarını kontrol edin
- Shell’i olmayan kullanıcılar için `/etc/shadow` içinde **password hashes** olup olmadığını kontrol edin

### Memory Dump

Çalışan sistemin belleğini elde etmek için [**LiME**](https://github.com/504ensicsLabs/LiME) kullanılması önerilir.\
Bunu **compile** etmek için, kurban makinenin kullandığı **aynı kernel**i kullanmanız gerekir.

> [!TIP]
> LiME veya başka herhangi bir şeyi kurban makineye **install edemeyeceğinizi** unutmayın; çünkü bu, sistemde çeşitli değişikliklere neden olur

Dolayısıyla, birebir aynı sürümde bir Ubuntu’nuz varsa `apt-get install lime-forensics-dkms` kullanabilirsiniz\
Diğer durumlarda, [**LiME**](https://github.com/504ensicsLabs/LiME)’i github’dan indirip doğru kernel headers ile compile etmeniz gerekir. Kurban makinenin **tam kernel headers**’ını elde etmek için, sadece `/lib/modules/<kernel version>` dizinini makinenize **copy** edebilir ve ardından LiME’yi bunları kullanarak **compile** edebilirsiniz:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME 3 **formatı** destekler:

- Raw (tüm segmentler birlikte birleştirilmiş)
- Padded (raw ile aynı, ancak sağ bitlerde sıfırlar ile)
- Lime (metadata içeren önerilen format)

LiME ayrıca dump'ı sistemde saklamak yerine **network üzerinden göndermek** için de kullanılabilir; örneğin: `path=tcp:4444`

### Disk Imaging

#### Shutting down

Öncelikle, **sistemi kapatmanız** gerekecek. Bu her zaman bir seçenek değildir çünkü bazen sistem, şirketin kapatmayı göze alamayacağı bir production server olabilir.\
Sistemi kapatmanın **2 yolu** vardır: **normal shutdown** ve **"plug the plug" shutdown**. İlki, **processes**'lerin her zamanki gibi sonlanmasına ve **filesystem**'in **synchronizes** edilmesine izin verir, ancak olası **malware**'in delilleri **destroy evidence** etmesine de olanak tanır. "pull the plug" yaklaşımı ise **bazı information loss**'a neden olabilir (memory image'ı zaten aldığımız için bilginin çok fazla kısmı kaybolmayacaktır) ve **malware**'in buna karşı bir şey yapma fırsatı olmaz. Bu nedenle, bir **malware** şüpheniz varsa, sistemde yalnızca **`sync`** **command**'ini çalıştırın ve fişi çekin.

#### Taking an image of the disk

Bilmek önemlidir ki, **bilgisayarınızı vakayla ilgili herhangi bir şeye bağlamadan önce**, herhangi bir bilgiyi değiştirmemek için onun **read only** olarak **mounted** edileceğinden emin olmanız gerekir.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Disk Image ön analizi

Daha fazla veri olmadan bir disk image’ini image almak.
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
## Bilinen Malware için Arama

### Değiştirilmiş Sistem Dosyaları

Linux, sistem bileşenlerinin bütünlüğünü sağlamak için araçlar sunar; bu, potansiyel olarak sorunlu dosyaları tespit etmek açısından kritiktir.

- **RedHat tabanlı sistemler**: Kapsamlı bir kontrol için `rpm -Va` kullanın.
- **Debian tabanlı sistemler**: İlk doğrulama için `dpkg --verify`, ardından herhangi bir sorunu belirlemek için (`apt-get install debsums` ile `debsums` kurduktan sonra) `debsums | grep -v "OK$"` kullanın.

### Malware/Rootkit Detectors

Araçlar hakkında bilgi edinmek için aşağıdaki sayfayı okuyun; bunlar malware bulmada faydalı olabilir:


{{#ref}}
malware-analysis.md
{{#endref}}

## Yüklü programları arama

Hem Debian hem de RedHat sistemlerinde yüklü programları etkili biçimde aramak için, yaygın dizinlerdeki manuel kontrollerle birlikte sistem loglarını ve veritabanlarını kullanmayı değerlendirin.

- Debian için, paket kurulumlarının ayrıntılarını almak üzere _**`/var/lib/dpkg/status`**_ ve _**`/var/log/dpkg.log`**_ dosyalarını inceleyin; belirli bilgileri filtrelemek için `grep` kullanın.
- RedHat kullanıcıları, yüklü paketleri listelemek için RPM veritabanını `rpm -qa --root=/mntpath/var/lib/rpm` ile sorgulayabilir.

Bu paket yöneticileri dışında veya elle kurulmuş yazılımları ortaya çıkarmak için, _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_, ve _**`/sbin`**_ gibi dizinleri inceleyin. Dizin listelemelerini sistem-özel komutlarla birleştirerek bilinen paketlerle ilişkilendirilmeyen çalıştırılabilir dosyaları belirleyin; böylece tüm yüklü programlar için aramanızı güçlendirin.
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
## Silinmiş Çalışan Binary’leri Kurtarma

/tmp/exec konumundan çalıştırılmış ve ardından silinmiş bir süreç hayal edin. Onu çıkarmak mümkündür
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## SQLite ve FTS5 ile Syscall Trace Triage

Bir süreç hâlâ çalışıyorsa veya laboratuvarda yeniden çalıştırılabiliyorsa, **`strace`** kernel modüllerine ya da tam EDR telemetry’sine ihtiyaç duymadan hızlı bir davranışsal trace sağlayabilir. Büyük trace’ler için, raw log’u doğrudan okumaktan veya bir LLM’e yapıştırmaktan kaçının: onu bir **SQLite** veritabanında saklayın ve yalnızca ihtiyacınız olan en küçük alt kümeyi sorgulayın.

> [!WARNING]
> `strace` eklemek süreç zamanlamasını değiştirir ve race conditions veya diğer kırılgan bug’ları etkileyebilir. Mümkün olduğunda bir kopya/lab sisteminde yeniden üretmeyi tercih edin.

### Capture

Yeni bir süreç için:
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log <command>
```
Canlı bir process için:
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log -p <PID>
```
Faydalı seçenekler:

- `-ff`: fork/threads takibini yap ve her process için çıktıları ayrı tut
- `-ttt`: timeline korelasyonu için kolay epoch timestamp'leri
- `-yy`: mümkün olduğunda file descriptor'ları bağlı path'lere/sockets'lere çözümle
- `-s 4096`: uzun path ve buffer argümanlarının kısaltılmasını önle

### Normalize

Pratik bir şema, syscall başına bir satır ve argüman başına bir satırdır:
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
Bu, heterojen syscall satırlarını tek geniş bir tabloya düzleştirmeye çalışmaktan kaçınır ve triage sırasında join’leri öngörülebilir tutar.

### Index metin-ağır arguments with FTS5

Büyük trace’lerde `LIKE "%...%"` ile naive path hunting çok yavaş olur. Bunun yerine argument text için bir FTS5 index oluşturun ve onunla search yapın:
```sql
CREATE VIRTUAL TABLE syscall_args_fts
USING fts5(raw, content='syscall_args', content_rowid='id');

INSERT INTO syscall_args_fts(rowid, raw)
SELECT id, raw FROM syscall_args;
```
Örnek: her satırı taramadan `/tmp` altındaki dosya etkinliğini kurtarın:
```sql
SELECT s.timestamp, s.pid, s.name, a.position, a.raw
FROM syscall_args_fts f
JOIN syscall_args a ON a.id = f.rowid
JOIN syscalls s ON s.id = a.syscall_id
WHERE syscall_args_fts MATCH 'tmp'
AND s.name IN ('openat', 'stat', 'lstat', 'rename', 'unlink', 'execve')
ORDER BY s.timestamp;
```
### High-signal investigations

- **PATH hijacking / fake sudo**: `~/.local/bin/` altında yazmaları ve `chmod`/`rename` etkinliğini ara, ardından `sudo` gibi ayrıcalıklı görünen adlara yapılan sonraki `execve` ile ilişkilendir.
- **TOCTOU on temporary files**: aynı `/tmp/...` path üzerinde `stat`, `access`, `openat`, `rename`, `unlink`, `link`, `symlink` ve `execve` boyunca pivot yaparak check/use boşluklarını belirle.
- **Crash root cause**: bir dosyanın `mmap` edilmesini, başka bir process tarafından aynı inode/path üzerinde yapılan yazmalar veya truncation ile ilişkilendir, ardından `SIGBUS` için signal/exit sequence'i incele.
- **Network destination recovery**: peer IP'leri ve portları çıkarmak için `connect`, `sendto`, `sendmsg`, `recvfrom` ve socket ile ilgili arguments'i filtrele.

### LLM-assisted trace analysis

If you want an LLM to assist, expose a **read-only** SQLite handle and give it the full schema. Let it issue raw SQL instead of wrapping the database behind narrow helper functions. This usually works better for joins, temporal correlation, and FTS lookups.

Practical rules:

- Keep the database read-only, for example with `sqlite3 'file:trace.db?mode=ro'`.
- Give the model examples of valid `JOIN` and `FTS5 MATCH` queries.
- Do **not** paste raw multi-GB `strace` logs into the prompt.
- Ask focused questions such as:
- "List persistent files written by this program."
- "Did it create or replace executables in user-controlled PATH directories?"
- "Explain why this trace ends in SIGBUS."

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
#### Cron/Anacron abuse via 0anacron ve şüpheli stub’lar ile Hunt
Saldırganlar, periyodik yürütmeyi garanti altına almak için genellikle her bir /etc/cron.*/ dizini altında bulunan 0anacron stub’ını düzenler.
```bash
# List 0anacron files and their timestamps/sizes
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done

# Look for obvious execution of shells or downloaders embedded in cron stubs
grep -R --line-number -E 'curl|wget|/bin/sh|python|bash -c' /etc/cron.*/* 2>/dev/null
```
#### Hunt: SSH hardening rollback and backdoor shells
sshd_config ve sistem hesap shell’lerindeki değişiklikler, erişimi kalıcı kılmak için post-exploitation sonrasında yaygındır.
```bash
# Root login enablement (flag "yes" or lax values)
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config

# System accounts with interactive shells (e.g., games → /bin/sh)
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
#### Avla: Cloud C2 işaretleri (Dropbox/Cloudflare Tunnel)
- Dropbox API beacon’ları tipik olarak HTTPS üzerinden Authorization: Bearer token’ları ile api.dropboxapi.com veya content.dropboxapi.com kullanır.
- proxy/Zeek/NetFlow içinde sunuculardan beklenmeyen Dropbox egress için avla.
- Cloudflare Tunnel (`cloudflared`), outbound 443 üzerinden yedek C2 sağlar.
```bash
ps aux | grep -E '[c]loudflared|trycloudflare'
systemctl list-units | grep -i cloudflared
```
### Hizmetler

Kötü amaçlı yazılımın bir servis olarak kurulabileceği yollar:

- **/etc/inittab**: rc.sysinit gibi başlatma betiklerini çağırır, bunlar da daha sonra startup betiklerine yönlendirir.
- **/etc/rc.d/** ve **/etc/rc.boot/**: Servis başlangıcı için betikler içerir; ikincisi eski Linux sürümlerinde bulunur.
- **/etc/init.d/**: Debian gibi bazı Linux sürümlerinde startup betiklerini saklamak için kullanılır.
- Servisler ayrıca Linux varyantına bağlı olarak **/etc/inetd.conf** veya **/etc/xinetd/** üzerinden de etkinleştirilebilir.
- **/etc/systemd/system**: system ve service manager betikleri için bir dizin.
- **/etc/systemd/system/multi-user.target.wants/**: Çok kullanıcılı bir runlevel'da başlatılması gereken servislere ait linkleri içerir.
- **/usr/local/etc/rc.d/**: Özel veya üçüncü taraf servisler için.
- **\~/.config/autostart/**: Kullanıcıya özel otomatik başlatma uygulamaları için; kullanıcı hedefli malware için saklanma yeri olabilir.
- **/lib/systemd/system/**: Yüklü paketler tarafından sağlanan sistem genelindeki varsayılan unit dosyaları.

#### Hunt: systemd timers and transient units

Systemd persistence `.service` dosyalarıyla sınırlı değildir. `.timer` unit'lerini, user-level unit'leri ve çalışma zamanında oluşturulan **transient units**'leri inceleyin.
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
Transient units are easy to miss because `/run/systemd/transient/` **kalıcı olmayan**dır. Canlı bir image topluyorsanız, kapatmadan önce alın.

### Kernel Modules

Linux kernel modules, often utilized by malware as rootkit components, sistem açılışında yüklenir. Bu modüller için kritik dizinler ve dosyalar şunlardır:

- **/lib/modules/$(uname -r)**: Çalışan kernel sürümü için modülleri tutar.
- **/etc/modprobe.d**: Module loading’i kontrol etmek için configuration dosyalarını içerir.
- **/etc/modprobe** ve **/etc/modprobe.conf**: Global module ayarları için dosyalar.

### Other Autostart Locations

Linux, kullanıcı login olduğunda programları otomatik çalıştırmak için çeşitli dosyalar kullanır; bunlar malware barındırabilir:

- **/etc/profile.d/**\*, **/etc/profile**, ve **/etc/bash.bashrc**: Herhangi bir user login’i için çalıştırılır.
- **\~/.bashrc**, **\~/.bash_profile**, **\~/.profile**, ve **\~/.config/autostart**: Kullanıcıya özel, login sırasında çalışan dosyalar.
- **/etc/rc.local**: Tüm system services başladıktan sonra çalışır ve multiuser environment’a geçişin sonunu işaret eder.

## Examine Logs

Linux sistemleri, user activities ve system events’i çeşitli log dosyaları aracılığıyla takip eder. Bu loglar unauthorized access, malware infections ve diğer security incident’leri belirlemek için kritiktir. Başlıca log dosyaları şunlardır:

- **/var/log/syslog** (Debian) veya **/var/log/messages** (RedHat): Tüm sistem mesajlarını ve activities’i yakalar.
- **/var/log/auth.log** (Debian) veya **/var/log/secure** (RedHat): Authentication denemelerini, başarılı ve başarısız login’leri kaydeder.
- İlgili authentication event’lerini filtrelemek için `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` kullanın.
- **/var/log/boot.log**: System startup mesajlarını içerir.
- **/var/log/maillog** veya **/var/log/mail.log**: Email server activities’ini loglar, email-related services’i izlemek için kullanışlıdır.
- **/var/log/kern.log**: Error ve warning’ler dahil kernel mesajlarını saklar.
- **/var/log/dmesg**: Device driver mesajlarını tutar.
- **/var/log/faillog**: Başarısız login denemelerini kaydeder, security breach investigation’larına yardımcı olur.
- **/var/log/cron**: Cron job yürütmelerini loglar.
- **/var/log/daemon.log**: Arka plan service activities’ini izler.
- **/var/log/btmp**: Başarısız login denemelerini belgelemektedir.
- **/var/log/httpd/**: Apache HTTPD error ve access loglarını içerir.
- **/var/log/mysqld.log** veya **/var/log/mysql.log**: MySQL database activities’ini loglar.
- **/var/log/xferlog**: FTP file transfers’ı kaydeder.
- **/var/log/**: Burada unexpected loglar için her zaman kontrol edin.

> [!TIP]
> Linux system logs ve audit subsystems bir intrusion veya malware incident’inde devre dışı bırakılmış veya silinmiş olabilir. Linux sistemlerindeki loglar genellikle malicious activities hakkında en yararlı bilgilerin bir kısmını içerdiğinden, intruders bunları rutin olarak siler. Bu nedenle, mevcut log dosyalarını incelerken, silme veya tampering belirtisi olabilecek boşlukları ya da sıralaması bozuk girdileri aramak önemlidir.

### Journald triage (`journalctl`)

Modern Linux host’larda, **systemd journal** genellikle **service execution**, **auth events**, **package operations** ve **kernel/user-space messages** için en yüksek değerli kaynaktır. Live response sırasında, kısa ömürlü attacker activity yalnızca ikincisinde mevcut olabileceği için hem **persistent** journal’ı (`/var/log/journal/`) hem de **runtime** journal’ı (`/run/log/journal/`) korumaya çalışın.
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
Triage için yararlı journal alanları arasında `_SYSTEMD_UNIT`, `_EXE`, `_COMM`, `_CMDLINE`, `_UID`, `_GID`, `_PID`, `_BOOT_ID` ve `MESSAGE` bulunur. Eğer journald kalıcı depolama olmadan yapılandırıldıysa, `/run/log/journal/` altında yalnızca son verileri bekleyin.

### Audit framework triage (`auditd`)

Eğer `auditd` etkinse, dosya değişiklikleri, komut çalıştırma, oturum açma etkinliği veya paket kurulumu için **process attribution** gerektiğinde her zaman onu tercih edin.
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
Kurallar anahtarlarla dağıtıldığında, ham loglarda grep yapmak yerine onlardan pivot yapın:
```bash
ausearch --start this-week -k <rule_key> --raw | aureport --file --summary -i
ausearch --start this-week -k <rule_key> --raw | aureport --user --summary -i
```
**Linux maintains a command history for each user**, stored in:

- \~/.bash_history
- \~/.zsh_history
- \~/.zsh_sessions/\*
- \~/.python_history
- \~/.\*\_history

Moreover, the `last -Faiwx` command provides a list of user logins. Check it for unknown or unexpected logins.

Check files that can grant extra rprivileges:

- Review `/etc/sudoers` for unanticipated user privileges that may have been granted.
- Review `/etc/sudoers.d/` for unanticipated user privileges that may have been granted.
- Examine `/etc/groups` to identify any unusual group memberships or permissions.
- Examine `/etc/passwd` to identify any unusual group memberships or permissions.

Some apps alse generates its own logs:

- **SSH**: Examine _\~/.ssh/authorized_keys_ and _\~/.ssh/known_hosts_ for unauthorized remote connections.
- **Gnome Desktop**: Look into _\~/.recently-used.xbel_ for recently accessed files via Gnome applications.
- **Firefox/Chrome**: Check browser history and downloads in _\~/.mozilla/firefox_ or _\~/.config/google-chrome_ for suspicious activities.
- **VIM**: Review _\~/.viminfo_ for usage details, such as accessed file paths and search history.
- **Open Office**: Check for recent document access that may indicate compromised files.
- **FTP/SFTP**: Review logs in _\~/.ftp_history_ or _\~/.sftp_history_ for file transfers that might be unauthorized.
- **MySQL**: Investigate _\~/.mysql_history_ for executed MySQL queries, potentially revealing unauthorized database activities.
- **Less**: Analyze _\~/.lesshst_ for usage history, including viewed files and commands executed.
- **Git**: Examine _\~/.gitconfig_ and project _.git/logs_ for changes to repositories.

### USB Logs

[**usbrip**](https://github.com/snovvcrash/usbrip) is a small piece of software written in pure Python 3 which parses Linux log files (`/var/log/syslog*` or `/var/log/messages*` depending on the distro) for constructing USB event history tables.

It is interesting to **know all the USBs that have been used** and it will be more useful if you have an authorized list of USBs to find "violation events" (the use of USBs that aren't inside that list).

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
Daha fazla örnek ve bilgi github içinde: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

## Kullanıcı Hesaplarını ve Oturum Açma Aktivitelerini İncele

_analyze the _**/etc/passwd**_, _**/etc/shadow**_ ve **security logs**_ içinde, bilinen yetkisiz olaylara yakın zamanda oluşturulmuş ve/veya kullanılmış sıra dışı isimler veya hesaplar olup olmadığını inceleyin. Ayrıca olası sudo brute-force saldırılarını da kontrol edin.\
Bunun yanında, kullanıcılara verilmiş beklenmedik yetkiler için _**/etc/sudoers**_ ve _**/etc/groups**_ gibi dosyaları kontrol edin.\
Son olarak, **şifresi olmayan** veya **kolay tahmin edilen** şifrelere sahip hesapları arayın.

## Dosya Sistemini İncele

### Malware Soruşturmasında Dosya Sistemi Yapılarının Analizi

Malware olaylarını araştırırken, dosya sisteminin yapısı kritik bir bilgi kaynağıdır; hem olayların sırasını hem de malware içeriğini ortaya çıkarır. Ancak malware yazarları, dosya zaman damgalarını değiştirmek veya veri depolamak için dosya sisteminden kaçınmak gibi bu analizi zorlaştıran teknikler geliştiriyor.

Bu anti-forensic yöntemlere karşı koymak için şunlar önemlidir:

- Olay zaman çizelgelerini görselleştirmek için **Autopsy** gibi araçlarla veya ayrıntılı zaman çizelgesi verileri için **Sleuth Kit**'in `mactime` aracını kullanarak **kapsamlı bir zaman çizelgesi analizi** yapın.
- Saldırganlar tarafından kullanılan shell veya PHP scriptleri içerebilecek, sistemin $PATH içindeki **beklenmedik scriptleri** inceleyin.
- Geleneksel olarak özel dosyalar içeren ancak malware ile ilişkili dosyaları da barındırabilen **/dev içindeki atipik dosyaları** inceleyin.
- Kötü amaçlı içeriği gizleyebilecek ".. " (nokta nokta boşluk) veya "..^G" (nokta nokta kontrol-G) gibi adlara sahip **gizli dosya veya dizinleri** arayın.
- Şu komutu kullanarak **setuid root dosyalarını** belirleyin: `find / -user root -perm -04000 -print` Bu, saldırganlar tarafından kötüye kullanılabilecek yükseltilmiş izinlere sahip dosyaları bulur.
- rootkit veya trojan varlığına işaret edebilecek toplu dosya silmelerini tespit etmek için inode tablolarındaki **silme zaman damgalarını** inceleyin.
- Birini belirledikten sonra, yakın konumlandırılmış kötü amaçlı dosyalar olabileceği için **ardışık inode'ları** kontrol edin; birlikte yerleştirilmiş olabilirler.
- Malware tarafından değiştirilebileceklerinden, yakın zamanda değiştirilmiş dosyalar için **yaygın binary dizinlerini** (_/bin_, _/sbin_) kontrol edin.
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
> [!TIP]
> Dikkat edin ki bir **attacker** **time** değerini **modify** ederek **files appear** **legitimate** hale getirebilir, ancak **inode**’u **modify** edemez. Eğer bir **file**’ın, aynı klasördeki diğer dosyalarla aynı **time**’da oluşturulup değiştirilmiş göründüğünü, ancak **inode**’unun beklenmedik şekilde daha büyük olduğunu fark ederseniz, o zaman o **file**’ın **timestamps** değerleri değiştirilmiştir.

### Inode-focused quick triage

Eğer anti-forensics’ten şüpheleniyorsanız, bu inode-focused kontrolleri erken çalıştırın:
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
- **Links**: `0` ise, hiçbir dizin girdisi şu anda inode’a referans vermiyor.
- **dtime**: inode bağlantısı kaldırıldığında ayarlanan silinme zaman damgası.
- **ctime/mtime**: metadata/içerik değişikliklerini olay zaman çizelgesiyle ilişkilendirmeye yardımcı olur.

### Capabilities, xattrs, and preload-based userland rootkits

Modern Linux persistence çoğu zaman bariz `setuid` binary’lerden kaçınır ve bunun yerine **file capabilities**, **extended attributes** ve dynamic loader’ı kötüye kullanır.
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
Özellikle `/tmp`, `/dev/shm`, `/var/tmp` gibi **yazılabilir** yollardan veya `/usr/local/lib` altındaki garip konumlardan referans verilen kütüphanelere dikkat edin. Ayrıca normal paket sahipliği dışında capability taşıyan binary’leri de kontrol edin ve bunları paket doğrulama sonuçlarıyla (`rpm -Va`, `dpkg --verify`, `debsums`) ilişkilendirin.

## Farklı filesystem sürümlerindeki dosyaları karşılaştırın

### Filesystem Sürüm Karşılaştırma Özeti

Filesystem sürümlerini karşılaştırmak ve değişiklikleri belirlemek için basitleştirilmiş `git diff` komutları kullanırız:

- **Yeni dosyaları bulmak için**, iki dizini karşılaştırın:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
- **Değiştirilmiş içerik için**, belirli satırları yok sayarak değişiklikleri listele:
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
- **Silinmiş dosyaları tespit etmek için**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
- **Filter options** (`--diff-filter`) belirli değişiklikleri daraltmaya yardımcı olur; örneğin eklenen (`A`), silinen (`D`) veya değiştirilmiş (`M`) dosyalar.
- `A`: Eklenen dosyalar
- `C`: Kopyalanan dosyalar
- `D`: Silinen dosyalar
- `M`: Değiştirilen dosyalar
- `R`: Yeniden adlandırılan dosyalar
- `T`: Tür değişiklikleri (örn. file to symlink)
- `U`: Birleştirilmemiş dosyalar
- `X`: Bilinmeyen dosyalar
- `B`: Bozuk dosyalar

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
