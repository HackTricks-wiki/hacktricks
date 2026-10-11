# SUID Shared Library and Linker Abuse

{{#include ../../banners/hacktricks-training.md}}

SUID binary’ler genellikle doğrudan komut çalıştırma açısından incelenir; ancak özel SUID programları dynamic linker üzerinden de güvenlik açığı içerebilir. Temel ortak nokta basittir: ayrıcalıklı bir executable, düşük ayrıcalıklı bir kullanıcının etkileyebileceği bir path veya yapılandırmadan kod yükler.<sup>[[1]](#references)</sup>

Bu sayfada genel teknik kalıplar ele alınır: eksik library’ler, yazılabilir library dizinleri, `RPATH`/`RUNPATH`, sudo üzerinden `LD_PRELOAD`, linker yapılandırması ve SUID hardlink karışıklığı.

Bu kontrollerin arkasındaki ELF program header’ları, dynamic section ve loader davranışı için [ELF basic information](../../binary-exploitation/basic-stack-binary-exploitation-methodology/elf-tricks.md) sayfasına bakın.

## Hızlı Keşif

Önce alışılmadık SUID dosyalarını bulun ve bunların dynamic olarak link edilip edilmediğini kontrol edin:<sup>[[1]](#references)[[3]](#references)</sup>

```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```

Bilinmeyen bir çalıştırılabilir dosya için `readelf` kullanın: [`ldd`, güvenilmeyen bir ELF yorumlayıcısını çalıştırabilir](https://man7.org/linux/man-pages/man1/ldd.1.html). `readelf` doğrudan bağımlılıkları gösterir; bu nedenle yükleyicinin gerçekten seçtiği yolu ayrıca doğrulayın.<sup>[[1]](#references)[[3]](#references)</sup>

Standart olmayan konumlara, özel uygulama yollarına, root tarafından sahip olunan ancak paket yöneticilerinin yönettiği dizinlerin dışındaki ikililere ve yazılabilir dizinlerden yüklenen bağımlılıklara odaklanın.<sup>[[1]](#references)</sup>

Yazılabilirlik denetimleri:

```bash
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```

## Missing Shared Object Injection

Bazı özel SUID binary'leri mevcut olmayan bir shared object'i yüklemeye çalışır. Eksik dosyanın yolu saldırganın denetimindeki bir dizinin altındaysa, binary saldırganın sağladığı kodu etkin kullanıcı olarak yükleyebilir.<sup>[[1]](#references)</sup>

Aynı sınır, çağıranın yazabildiği bir home veya yapılandırma dizini altındaki mutlak `.so` yolunda `dlopen()` çağıran ve **sudo üzerinden çalıştırılmasına izin verilen özel bir binary** için de geçerlidir. Bu geç aşamadaki kütüphane yüklemesi `ldd` çıktısında ve ELF `NEEDED` girdilerinde görünmeyebilir. Sınırlı bir `strings` incelemesi veya **ayrıcalıksız** bir çalıştırmanın izlenmesi, denenmiş yolu ortaya çıkarabilir; uygulama parolası veya menü seçeneği bu aramayı koşula bağlayabilir. Bunu privilege escalation olarak değerlendirmeden önce etkin sudo kuralını, tam yolu ve üst dizin izinlerini, ayrıca ayrıcalıklı çalıştırmanın bu arama noktasına ulaştığını doğrulayın. Sırf içeriğini listelemek için sudo hedefini çalıştırmayın.

Başarısız kütüphane aramalarını `strace`'in syscall filtresiyle bulun:<sup>[[2]](#references)</sup>

```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```

Binary, `libexample.so` için yazılabilir bir path'te arama yapıyorsa, minimal bir proof library constructor kullanabilir. Validation sırasında proof-of-impact zararsız tutun:<sup>[[6]](#references)</sup>

```c
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor))
static void init(void) {
    setuid(0);
    setgid(0);
    system("id > /tmp/suid-so-ran");
}
```

Binary'nin yüklemeye çalıştığı tam dosya adıyla derleyin:

```bash
gcc -shared -fPIC proof.c -o /writable/path/libexample.so
/path/to/suid-binary
cat /tmp/suid-so-ran
```

Eksploite edilebilir durum yalnızca eksik kütüphaneden ibaret değildir. Saldırganın, ayrıcalıklı yükleyicinin kabul edeceği bir yola uyumlu bir shared object yerleştirebilmesi gerekir.<sup>[[1]](#references)</sup>

## Writable Library Directory

Bazen tüm bağımlılıklar mevcuttur, ancak bunları çözümlemek için kullanılan dizinlerden biri yazılabilirdir. Bu, yüklenen bir kütüphanenin değiştirilmesine veya aynı ada sahip, önceliği daha yüksek bir kütüphanenin yerleştirilmesine olanak sağlayabilir.<sup>[[1]](#references)</sup>

Aynı inceleme, SUID biti olmasa ve izin verilen RunAs hesabı root olmasa bile, **sudo üzerinden çalıştırılmasına izin verilen** özel bir ELF için de geçerlidir. `DT_NEEDED` girdilerini, yükleyicinin çözeceği kütüphane yol adıyla karşılaştırın; ardından çağıranın bu dosyaya yazıp yazamadığını veya yazılabilir, aranabilir bir üst dizin üzerinden dosyayı değiştirip değiştiremediğini kontrol edin. Kesin sudo RunAs kuralını, sembolik bağlantıları ve ACL'leri, yükleyici politikasını ve hedef sürecin kütüphaneyi daha yüksek ayrıcalıklı hesap olarak yüklediğini doğrulayın. Yazılabilir bir `.so` dosyası veya tek başına bir bağımlılık adı yalnızca bir ipucudur; sudo komutunu çalıştırmadan metadata'yı inceleyin.<sup>[[1]](#references)[[3]](#references)[[5]](#references)</sup>

Bağımlılık yollarını inceleyin:<sup>[[1]](#references)[[3]](#references)</sup>

```bash
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```

Dizin yazılabilir durumdaysa, bunu laboratuvarda kopya üzerinde güvenli bir yöntemle doğrulayın. Canlı bir hostta sistem kütüphanelerini değiştirmek, aynı anda başlayan süreçlerin tutarsız kütüphane sürümleriyle çalışmasına yol açabilir.<sup>[[8]](#references)</sup>

### chroot içindeki yazılabilir kütüphaneler

Tek başına chroot, devralınan dosya tanımlayıcılarını kapatmaz veya tüm dosya sistemi erişimini kısıtlamaz. Bir sandbox, yeni kökünün dışındaki bir dizine işaret eden dizin tanımlayıcısını açık bırakırsa ve hapsedilen süreç bu tanımlayıcıyı kullanabiliyorsa (örneğin erişilebilir bir `/proc/<pid>/fd/` girdisi üzerinden), host yollarına erişim mümkün olabilir. Bu bir dosya sistemi sınırı sorunudur; tek başına root ayrıcalıkları sağlamaz.<sup>[[11]](#references)[[12]](#references)</sup>

Hapsedilen kullanıcının, jail içinden başlatıldığında **host root-SUID executable** tarafından kullanılacak bir kütüphane dizinine yazıp yazamadığını ayrıca kontrol edin. Loader, bağımlılıkları sürecin dosya sistemi görünümünde çözümler; bu nedenle buradaki saldırgan denetimindeki bir kütüphane, SUID programının etkin kimliğiyle çalışabilir. Tam executable'ı, SUID bitini ve mount politikasını, tanımlayıcının hedefini ve erişim izinlerini, jail'in kütüphane arama yolunu ve programın host executable'a gerçekten erişebildiğini doğrulayın. Sandbox başlatıcısındaki bir file capability, yazılabilir bir jail veya tek başına bir host SUID binary'si yalnızca bir ipucudur; zincirin tamamı sandbox'ın uygulamasına bağlıdır.<sup>[[1]](#references)[[11]](#references)[[12]](#references)</sup>

## RPATH ve RUNPATH

`RPATH` ve `RUNPATH`, loader'a kütüphaneleri nerede arayacağını söyleyen dynamic-section girdileridir. Saldırganın yazabildiği dizinleri işaret ettiklerinde SUID programlarında tehlikelidirler.<sup>[[1]](#references)</sup>

Bunları tespit edin:<sup>[[3]](#references)[[10]](#references)</sup>

```bash
readelf -d /path/to/suid-binary | egrep 'RPATH|RUNPATH'
objdump -p /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
```

Örnek riskli çıktı:

```text
0x000000000000001d (RUNPATH)            Library runpath: [/opt/app/lib]
0x0000000000000001 (NEEDED)             Shared library: [libcustom.so]
```

`/opt/app/lib` yazılabiliyorsa ve ikili dosyanın `libcustom.so` dosyasına ihtiyacı varsa, saldırgan buraya kötü amaçlı bir `libcustom.so` yerleştirebilir:<sup>[[1]](#references)</sup>

```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```

`RPATH` ve `RUNPATH` tüm çözümleme ayrıntılarında aynı değildir, ancak privilege-escalation incelemesinde pratik soru aynıdır: SUID binary, bir library adı için saldırganın yazabildiği bir dizinde arama yapıyor mu?<sup>[[1]](#references)</sup>

## LD_PRELOAD, LD_LIBRARY_PATH ve SUID

Normal programlarda `LD_PRELOAD` ve `LD_LIBRARY_PATH`, shared object yüklenmesini zorlayabilir veya etkileyebilir. SUID programlarında dynamic loader genellikle secure-execution mode'a geçer ve tehlikeli ortam değişkenlerini yok sayar.<sup>[[1]](#references)</sup>

Bu, kullanıcının `LD_PRELOAD` ayarlayabilmesinin tek başına basit bir SUID binary'nin genellikle savunmasız olduğu anlamına gelmediği demektir:<sup>[[1]](#references)</sup>

```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```

Yaygın istisna, `SETENV` etiketi veya geçerli `setenv` seçeneği gibi, hedef için komut satırından ortam değişkeni atamasına izin veren bir sudo ilkesidir. Hedef dinamik olarak bağlıysa ve sudo `LD_PRELOAD=/path/to/library` atamasını kabul ediyorsa, hedef çağıranın denetimindeki kodu yükleyebilir. Etkin kuralı ve hedef kimliğini kontrol edin. Dinamik yükleyicinin devralınan `LD_PRELOAD` değerini SUID `sudo` süreci başlamadan önce temizlediği sistemlerde, `LD_PRELOAD` değerini yalnızca `env_keep` listesine eklemek yeterli değildir; komut satırından yapılan atama, sudo kendi başlangıcını tamamladıktan sonra değerlendirilir.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
sudo -l
# Check SETENV/setenv and the target command's allowed arguments
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```

Bu durumları birbirine karıştırmayın; yukarıdaki loader ve sudo policy kuralları bunları birbirinden ayırır:<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

- Normal bir SUID binary'ye karşı `LD_PRELOAD`: genellikle secure execution tarafından engellenir.
- Privileged, dynamically linked bir target için sudo komut satırı ataması olarak kabul edilen `LD_PRELOAD`: potansiyel olarak istismar edilebilir.
- Yazılabilir bir path'te eksik `.so`: SUID binary bu path'i doğal olarak yüklediğinde istismar edilebilir.
- Yazılabilir bir dizine yönlendiren `RPATH`/`RUNPATH`: gerekli bir library kontrol edilebildiğinde istismar edilebilir.
- `/etc/ld.so.preload` veya linker config dosyasına yazma erişimi: sistem genelinde etkilidir ve yüksek etkiye sahiptir.

## Linker Yapılandırması

`ld.so`, linker cache'i ve `/etc/ld.so.preload` dosyasını kullanır; `ldconfig` bu cache'i `/etc/ld.so.conf` dosyasından ve buradan dahil edilen dosyalardan, genellikle `/etc/ld.so.conf.d/` dizininden oluşturur.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Önemli kontroller:

```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```

Yazılabilir linker yapılandırması, genellikle tek bir güvenlik açığı bulunan SUID binary'den daha ciddi bir sorundur; çünkü dinamik olarak bağlanan birçok süreci etkileyebilir. `/etc/ld.so.preload` özellikle tehlikelidir, çünkü ayrıcalıklı süreçlere bir shared object yüklenmesini zorlayabilir.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

## SUID Hardlink Karmaşası

Hardlink'ler, aynı SUID inode'un birden fazla ad altında görünmesini sağlayabilir.<sup>[[9]](#references)</sup> Bu; ayrıcalıklı bir yardımcı programı gizlemek, cleanup işlemlerini şaşırtmak veya basit yol tabanlı incelemeleri atlatmak için kullanışlıdır.

Birden fazla bağlantısı olan SUID dosyalarını bulun:<sup>[[9]](#references)</sup>

```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```

Aynı inode'a giden tüm yolları inceleyin:<sup>[[9]](#references)</sup>

```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```

Kötüye kullanım, hardlink'in izinleri değiştirmesi değildir. Sorun yol karmaşasıdır: ayrıcalıklı bir inode, savunmacıların veya betiklerin beklemediği bir ad üzerinden erişilebilir olabilir.<sup>[[9]](#references)</sup> Inode ve hardlink iş akışı hakkında daha fazla bilgi için [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md) sayfasına bakın.

## Savunma Notları

- SUID ikililerini olabildiğince az sayıda tutun, denetleyin ve mümkün olduğunda paket yöneticisiyle yönetin.
- Yazılabilir veya uygulama tarafından yönetilen dizinlere işaret eden `RPATH`/`RUNPATH` girdilerinden kaçının.<sup>[[1]](#references)[[8]](#references)</sup>
- Kütüphane dizinlerinin sahibi root olsun ve normal kullanıcılar tarafından yazılamasın.<sup>[[8]](#references)</sup>
- `LD_PRELOAD`, `LD_LIBRARY_PATH` veya benzeri loader değişkenlerinin sudo üzerinden korunmasına izin vermeyin.<sup>[[1]](#references)[[5]](#references)</sup>
- `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/` dosyalarını ve beklenmeyen SUID dosyalarını izleyin.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
- Hardlink'lenmiş SUID dosyalarını inceleyin ve standart sistem yollarının dışındaki özel SUID wrapper'larını araştırın.<sup>[[9]](#references)</sup>

## References

- [1] [ld.so(8) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [strace(1) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man1/strace.1.html)
- [3] [readelf (GNU Binary Utilities)](https://sourceware.org/binutils/docs/binutils/readelf.html)
- [4] [sudo(8) — Linux kılavuz sayfası](https://www.man7.org/linux/man-pages/man8/sudo.8.html)
- [5] [sudoers(5) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [6] [Common Attributes (GCC)](https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html)
- [7] [ldconfig(8) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [8] [Dinamik Bağlayıcı Güçlendirmesi (The GNU C Library)](https://www.sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [9] [Hard Linkler (GNU Findutils)](https://www.gnu.org/software/findutils/manual/html_node/find_html/Hard-Links.html)
- [10] [objdump (GNU Binary Utilities)](https://www.sourceware.org/binutils/docs/binutils/objdump.html)
- [11] [chroot(2) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [12] [proc_pid_fd(5) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)
{{#include ../../banners/hacktricks-training.md}}
