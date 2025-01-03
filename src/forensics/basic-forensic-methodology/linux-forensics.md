# Linux Forensics

{{#include ../../banners/hacktricks-training.md}}

## İlk Bilgi Toplama

### Temel Bilgiler

Öncelikle, üzerinde **iyi bilinen ikili dosyalar ve kütüphaneler bulunan bir **USB** bulundurmanız önerilir** (sadece ubuntu alıp _/bin_, _/sbin_, _/lib,_ ve _/lib64_ klasörlerini kopyalayabilirsiniz), ardından USB'yi bağlayın ve bu ikili dosyaları kullanmak için çevre değişkenlerini değiştirin:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
Sistemi iyi ve bilinen ikili dosyaları kullanacak şekilde yapılandırdıktan sonra **bazı temel bilgileri çıkarmaya** başlayabilirsiniz:
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

Temel bilgileri elde ederken, tuhaf şeyler için kontrol etmelisiniz:

- **Root süreçleri** genellikle düşük PID'lerle çalışır, bu yüzden büyük bir PID ile bir root süreci bulursanız şüphelenebilirsiniz.
- `/etc/passwd` içinde bir shell'i olmayan kullanıcıların **kayıtlı girişlerini** kontrol edin.
- Shell'i olmayan kullanıcılar için `/etc/shadow` içinde **şifre hash'lerini** kontrol edin.

### Bellek Dökümü

Çalışan sistemin belleğini elde etmek için [**LiME**](https://github.com/504ensicsLabs/LiME) kullanmanız önerilir.\
Bunu **derlemek** için, kurban makinesinin kullandığı **aynı çekirdek** ile çalışmalısınız.

> [!NOTE]
> Kurban makinesine **LiME veya başka bir şey** yükleyemeyeceğinizi unutmayın, çünkü bu makinede birçok değişiklik yapacaktır.

Bu nedenle, eğer aynı Ubuntu sürümüne sahipseniz `apt-get install lime-forensics-dkms` kullanabilirsiniz.\
Diğer durumlarda, [**LiME**](https://github.com/504ensicsLabs/LiME) github'dan indirmeniz ve doğru çekirdek başlıkları ile derlemeniz gerekir. Kurban makinesinin **tam çekirdek başlıklarını** elde etmek için, sadece `/lib/modules/<kernel version>` dizinini makinenize **kopyalayabilir** ve ardından bunları kullanarak LiME'yi **derleyebilirsiniz**:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME 3 **formatı** destekler:

- Ham (her segment bir araya getirilmiş)
- Doldurulmuş (ham ile aynı, ancak sağ bitlerde sıfırlarla)
- Lime (meta verilerle önerilen format)

LiME ayrıca **dökümü ağ üzerinden göndermek için** de kullanılabilir, bunu yapmak için şöyle bir şey kullanabilirsiniz: `path=tcp:4444`

### Disk Görüntüleme

#### Kapatma

Öncelikle, **sistemi kapatmanız** gerekecek. Bu her zaman bir seçenek değildir çünkü bazen sistem, şirketin kapatmayı göze alamayacağı bir üretim sunucusu olacaktır.\
Sistemi kapatmanın **2 yolu** vardır, bir **normal kapatma** ve bir **"fişi çekme" kapatma**. İlk yöntem, **işlemlerin normal şekilde sonlanmasına** ve **dosya sisteminin** **senkronize edilmesine** izin verir, ancak aynı zamanda olası **kötü amaçlı yazılımın** **kanıtları yok etmesine** de olanak tanır. "Fişi çekme" yaklaşımı, **bazı bilgi kaybı** taşıyabilir (çok fazla bilgi kaybolmayacak çünkü zaten belleğin bir görüntüsünü aldık) ve **kötü amaçlı yazılımın** bununla ilgili bir şey yapma fırsatı olmayacaktır. Bu nedenle, eğer **kötü amaçlı yazılım** olabileceğinden **şüpheleniyorsanız**, sistemde **`sync`** **komutunu** çalıştırın ve fişi çekin.

#### Diskin görüntüsünü alma

**Dava ile ilgili herhangi bir şeye bilgisayarınızı bağlamadan önce**, bunun **sadece okunur olarak monte edileceğinden** emin olmanız önemlidir, böylece herhangi bir bilgiyi değiştirmemiş olursunuz.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Disk Image ön analizi

Veri kalmayan bir disk görüntüsünü görüntüleme.
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
## Bilinen Kötü Amaçlı Yazılımları Ara

### Değiştirilmiş Sistem Dosyaları

Linux, potansiyel olarak sorunlu dosyaları tespit etmek için kritik olan sistem bileşenlerinin bütünlüğünü sağlamak için araçlar sunar.

- **RedHat tabanlı sistemler**: Kapsamlı bir kontrol için `rpm -Va` kullanın.
- **Debian tabanlı sistemler**: İlk doğrulama için `dpkg --verify` kullanın, ardından `debsums | grep -v "OK$"` (önce `apt-get install debsums` ile `debsums` yükledikten sonra) ile herhangi bir sorunu tespit edin.

### Kötü Amaçlı Yazılım/Rootkit Tespit Cihazları

Kötü amaçlı yazılımları bulmak için faydalı olabilecek araçlar hakkında bilgi edinmek için aşağıdaki sayfayı okuyun:

{{#ref}}
malware-analysis.md
{{#endref}}

## Yüklenmiş Programları Ara

Debian ve RedHat sistemlerinde yüklenmiş programları etkili bir şekilde aramak için, sistem günlüklerini ve veritabanlarını manuel kontrollerle birlikte kullanmayı düşünün.

- Debian için, paket yüklemeleri hakkında bilgi almak için _**`/var/lib/dpkg/status`**_ ve _**`/var/log/dpkg.log`**_ dosyalarını kontrol edin, belirli bilgileri filtrelemek için `grep` kullanın.
- RedHat kullanıcıları, yüklenmiş paketleri listelemek için `rpm -qa --root=/mntpath/var/lib/rpm` ile RPM veritabanını sorgulayabilir.

Bu paket yöneticileri dışında manuel olarak yüklenmiş yazılımları ortaya çıkarmak için _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_ ve _**`/sbin`**_ gibi dizinleri keşfedin. Bilinen paketlerle ilişkilendirilmemiş çalıştırılabilir dosyaları tanımlamak için dizin listelemelerini sistem spesifik komutlarla birleştirerek tüm yüklenmiş programlar için aramanızı geliştirin.
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
## Silinmiş Çalışan İkili Dosyaları Kurtarma

/tmp/exec konumundan çalıştırılan ve ardından silinen bir süreci hayal edin. Onu çıkarmak mümkündür.
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## Autostart konumlarını incele

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
### Hizmetler

Kötü amaçlı yazılımın bir hizmet olarak kurulabileceği yollar:

- **/etc/inittab**: rc.sysinit gibi başlatma betiklerini çağırır, daha sonra başlatma betiklerine yönlendirir.
- **/etc/rc.d/** ve **/etc/rc.boot/**: Hizmet başlatma betiklerini içerir, ikincisi daha eski Linux sürümlerinde bulunur.
- **/etc/init.d/**: Debian gibi belirli Linux sürümlerinde başlatma betiklerini depolamak için kullanılır.
- Hizmetler, Linux varyantına bağlı olarak **/etc/inetd.conf** veya **/etc/xinetd/** aracılığıyla da etkinleştirilebilir.
- **/etc/systemd/system**: Sistem ve hizmet yöneticisi betikleri için bir dizin.
- **/etc/systemd/system/multi-user.target.wants/**: Çok kullanıcılı çalışma seviyesinde başlatılması gereken hizmetlere bağlantılar içerir.
- **/usr/local/etc/rc.d/**: Özel veya üçüncü taraf hizmetler için.
- **\~/.config/autostart/**: Kullanıcıya özgü otomatik başlatma uygulamaları için, kullanıcı hedefli kötü amaçlı yazılımlar için bir saklanma yeri olabilir.
- **/lib/systemd/system/**: Yüklenmiş paketler tarafından sağlanan sistem genelindeki varsayılan birim dosyaları.

### Çekirdek Modülleri

Kötü amaçlı yazılım tarafından genellikle rootkit bileşenleri olarak kullanılan Linux çekirdek modülleri, sistem önyüklemesi sırasında yüklenir. Bu modüller için kritik dizinler ve dosyalar şunlardır:

- **/lib/modules/$(uname -r)**: Çalışan çekirdek sürümü için modülleri tutar.
- **/etc/modprobe.d**: Modül yüklemeyi kontrol eden yapılandırma dosyalarını içerir.
- **/etc/modprobe** ve **/etc/modprobe.conf**: Küresel modül ayarları için dosyalar.

### Diğer Otomatik Başlatma Yerleri

Linux, kullanıcı girişi sırasında programları otomatik olarak çalıştırmak için çeşitli dosyalar kullanır, bu da kötü amaçlı yazılımları barındırma potansiyeline sahiptir:

- **/etc/profile.d/**\*, **/etc/profile**, ve **/etc/bash.bashrc**: Herhangi bir kullanıcı girişi için çalıştırılır.
- **\~/.bashrc**, **\~/.bash_profile**, **\~/.profile**, ve **\~/.config/autostart**: Kullanıcıya özgü dosyalar, kullanıcı girişi sırasında çalışır.
- **/etc/rc.local**: Tüm sistem hizmetleri başlatıldıktan sonra çalışır, çok kullanıcılı bir ortama geçişin sonunu işaret eder.

## Günlükleri İnceleyin

Linux sistemleri, kullanıcı etkinliklerini ve sistem olaylarını çeşitli günlük dosyaları aracılığıyla takip eder. Bu günlükler, yetkisiz erişimi, kötü amaçlı yazılım enfeksiyonlarını ve diğer güvenlik olaylarını tanımlamak için kritik öneme sahiptir. Anahtar günlük dosyaları şunlardır:

- **/var/log/syslog** (Debian) veya **/var/log/messages** (RedHat): Sistem genelindeki mesajları ve etkinlikleri yakalar.
- **/var/log/auth.log** (Debian) veya **/var/log/secure** (RedHat): Kimlik doğrulama girişimlerini, başarılı ve başarısız girişleri kaydeder.
- İlgili kimlik doğrulama olaylarını filtrelemek için `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` komutunu kullanın.
- **/var/log/boot.log**: Sistem başlatma mesajlarını içerir.
- **/var/log/maillog** veya **/var/log/mail.log**: E-posta sunucusu etkinliklerini kaydeder, e-posta ile ilgili hizmetleri takip etmek için yararlıdır.
- **/var/log/kern.log**: Hata ve uyarılar da dahil olmak üzere çekirdek mesajlarını saklar.
- **/var/log/dmesg**: Aygıt sürücü mesajlarını tutar.
- **/var/log/faillog**: Başarısız giriş girişimlerini kaydeder, güvenlik ihlali soruşturmalarına yardımcı olur.
- **/var/log/cron**: Cron işlerinin yürütülmelerini kaydeder.
- **/var/log/daemon.log**: Arka plan hizmeti etkinliklerini takip eder.
- **/var/log/btmp**: Başarısız giriş girişimlerini belgeler.
- **/var/log/httpd/**: Apache HTTPD hata ve erişim günlüklerini içerir.
- **/var/log/mysqld.log** veya **/var/log/mysql.log**: MySQL veritabanı etkinliklerini kaydeder.
- **/var/log/xferlog**: FTP dosya transferlerini kaydeder.
- **/var/log/**: Beklenmedik günlükler için burayı her zaman kontrol edin.

> [!NOTE]
> Linux sistem günlükleri ve denetim alt sistemleri, bir ihlal veya kötü amaçlı yazılım olayı sırasında devre dışı bırakılabilir veya silinebilir. Çünkü Linux sistemlerindeki günlükler genellikle kötü niyetli etkinlikler hakkında en yararlı bilgileri içerir, saldırganlar bunları düzenli olarak siler. Bu nedenle, mevcut günlük dosyalarını incelerken, silinme veya müdahale belirtisi olabilecek boşluklar veya düzensiz girişler aramak önemlidir.

**Linux, her kullanıcı için bir komut geçmişi tutar**, şu dosyalarda saklanır:

- \~/.bash_history
- \~/.zsh_history
- \~/.zsh_sessions/\*
- \~/.python_history
- \~/.\*\_history

Ayrıca, `last -Faiwx` komutu kullanıcı girişlerinin bir listesini sağlar. Bilinmeyen veya beklenmedik girişler için kontrol edin.

Ek rprivilejeleri verebilecek dosyaları kontrol edin:

- Verilen beklenmedik kullanıcı ayrıcalıkları için `/etc/sudoers` dosyasını gözden geçirin.
- Verilen beklenmedik kullanıcı ayrıcalıkları için `/etc/sudoers.d/` dosyasını gözden geçirin.
- Herhangi bir olağandışı grup üyeliği veya izinleri tanımlamak için `/etc/groups` dosyasını inceleyin.
- Herhangi bir olağandışı grup üyeliği veya izinleri tanımlamak için `/etc/passwd` dosyasını inceleyin.

Bazı uygulamalar ayrıca kendi günlüklerini oluşturur:

- **SSH**: Yetkisiz uzaktan bağlantılar için _\~/.ssh/authorized_keys_ ve _\~/.ssh/known_hosts_ dosyalarını inceleyin.
- **Gnome Masaüstü**: Gnome uygulamaları aracılığıyla yakın zamanda erişilen dosyalar için _\~/.recently-used.xbel_ dosyasını kontrol edin.
- **Firefox/Chrome**: Şüpheli etkinlikler için _\~/.mozilla/firefox_ veya _\~/.config/google-chrome_ dizinlerinde tarayıcı geçmişi ve indirmeleri kontrol edin.
- **VIM**: Erişim sağlanan dosya yolları ve arama geçmişi gibi kullanım detayları için _\~/.viminfo_ dosyasını gözden geçirin.
- **Open Office**: Kompromize olmuş dosyaları gösterebilecek yakın tarihli belge erişimlerini kontrol edin.
- **FTP/SFTP**: Yetkisiz olabilecek dosya transferleri için _\~/.ftp_history_ veya _\~/.sftp_history_ dosyalarını gözden geçirin.
- **MySQL**: Yetkisiz veritabanı etkinliklerini ortaya çıkarabilecek yürütülen MySQL sorguları için _\~/.mysql_history_ dosyasını araştırın.
- **Less**: Görüntülenen dosyalar ve yürütülen komutlar dahil olmak üzere kullanım geçmişi için _\~/.lesshst_ dosyasını analiz edin.
- **Git**: Depolardaki değişiklikler için _\~/.gitconfig_ ve proje _.git/logs_ dosyalarını inceleyin.

### USB Günlükleri

[**usbrip**](https://github.com/snovvcrash/usbrip), USB olay geçmişi tabloları oluşturmak için Linux günlük dosyalarını (`/var/log/syslog*` veya dağıtıma bağlı olarak `/var/log/messages*`) ayrıştıran saf Python 3 ile yazılmış küçük bir yazılımdır.

Kullanılan tüm USB'leri **bilmek** ilginçtir ve "ihlal olaylarını" bulmak için yetkilendirilmiş bir USB listesine sahip olmanız daha faydalı olacaktır (o listedeki USB'lerin dışındaki USB'lerin kullanımı). 

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
Daha fazla örnek ve bilgi github'da: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

## Kullanıcı Hesaplarını ve Giriş Aktivitelerini Gözden Geçirin

_**/etc/passwd**_, _**/etc/shadow**_ ve **güvenlik günlüklerini** olağandışı isimler veya bilinen yetkisiz olaylarla yakın zamanda oluşturulmuş veya kullanılmış hesaplar için inceleyin. Ayrıca, olası sudo brute-force saldırılarını kontrol edin.\
Ayrıca, kullanıcılara verilen beklenmedik ayrıcalıkları kontrol etmek için _**/etc/sudoers**_ ve _**/etc/groups**_ gibi dosyaları kontrol edin.\
Son olarak, **şifresiz** veya **kolay tahmin edilebilen** şifreleri olan hesapları arayın.

## Dosya Sistemini İnceleyin

### Kötü Amaçlı Yazılım Soruşturmasında Dosya Sistemi Yapılarını Analiz Etme

Kötü amaçlı yazılım olaylarını araştırırken, dosya sisteminin yapısı bilgi için kritik bir kaynaktır ve hem olayların sırasını hem de kötü amaçlı yazılımın içeriğini ortaya çıkarır. Ancak, kötü amaçlı yazılım yazarları, dosya zaman damgalarını değiştirmek veya veri depolamak için dosya sisteminden kaçınmak gibi bu analizi engellemek için teknikler geliştirmektedir.

Bu anti-forensic yöntemlere karşı koymak için, şunları yapmak önemlidir:

- **Olay zaman çizelgelerini görselleştirmek için** **Autopsy** gibi araçlar kullanarak kapsamlı bir zaman çizelgesi analizi yapın veya detaylı zaman çizelgesi verileri için **Sleuth Kit'in** `mactime` aracını kullanın.
- **Sistemin $PATH'inde beklenmedik betikleri** araştırın; bu, saldırganlar tarafından kullanılan shell veya PHP betiklerini içerebilir.
- **Atypik dosyalar için `/dev`'i inceleyin**, çünkü genellikle özel dosyalar içerir, ancak kötü amaçlı yazılımla ilgili dosyalar barındırabilir.
- **Kötü amaçlı içeriği gizleyebilecek** ".. " (nokta nokta boşluk) veya "..^G" (nokta nokta kontrol-G) gibi isimlere sahip gizli dosyaları veya dizinleri arayın.
- **Yükseltilmiş izinlere sahip setuid root dosyalarını** bulmak için şu komutu kullanın: `find / -user root -perm -04000 -print` Bu, saldırganlar tarafından kötüye kullanılabilecek yüksek izinlere sahip dosyaları bulur.
- **Kütük tablolarındaki silme zaman damgalarını** gözden geçirerek, kök kitleri veya trojanların varlığını gösterebilecek kitlesel dosya silme işlemlerini tespit edin.
- **Birini belirledikten sonra** yan yana kötü amaçlı dosyalar için ardışık inode'ları inceleyin; çünkü bunlar birlikte yerleştirilmiş olabilir.
- **Son zamanlarda değiştirilmiş dosyalar için yaygın ikili dizinleri** (_/bin_, _/sbin_) kontrol edin; çünkü bunlar kötü amaçlı yazılım tarafından değiştirilmiş olabilir.
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
> [!NOTE]
> Bir **saldırganın** **zamanı** **değiştirerek** **dosyaların meşru görünmesini** sağlayabileceğini, ancak **inode'u** **değiştiremeyeceğini** unutmayın. Eğer bir **dosyanın**, aynı klasördeki diğer dosyalarla **aynı anda** oluşturulup **değiştirildiğini** gösterdiğini, ancak **inode'unun** **beklenmedik şekilde büyük** olduğunu bulursanız, o **dosyanın zaman damgalarının değiştirildiği** anlamına gelir.

## Farklı dosya sistemi sürümlerini karşılaştırma

### Dosya Sistemi Sürüm Karşılaştırma Özeti

Dosya sistemi sürümlerini karşılaştırmak ve değişiklikleri belirlemek için basitleştirilmiş `git diff` komutlarını kullanıyoruz:

- **Yeni dosyaları bulmak için**, iki dizini karşılaştırın:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
- **Değiştirilmiş içerik için**, değişiklikleri belirli satırları göz ardı ederek listeleyin:
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
- **Silinmiş dosyaları tespit etmek için**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
- **Filtre seçenekleri** (`--diff-filter`), eklenen (`A`), silinen (`D`) veya değiştirilen (`M`) dosyalar gibi belirli değişikliklere daraltmaya yardımcı olur.
- `A`: Eklenen dosyalar
- `C`: Kopyalanan dosyalar
- `D`: Silinen dosyalar
- `M`: Değiştirilen dosyalar
- `R`: Yeniden adlandırılan dosyalar
- `T`: Tür değişiklikleri (örneğin, dosya ile symlink arasında)
- `U`: Birleştirilmemiş dosyalar
- `X`: Bilinmeyen dosyalar
- `B`: Bozuk dosyalar

## Referanslar

- [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf)
- [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)
- [https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
- **Kitap: Linux Sistemleri için Kötü Amaçlı Yazılım Adli Bilişim Alan Rehberi**

{{#include ../../banners/hacktricks-training.md}}
