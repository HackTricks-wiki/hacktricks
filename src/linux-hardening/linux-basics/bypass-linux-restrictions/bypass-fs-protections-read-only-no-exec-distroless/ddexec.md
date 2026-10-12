# DDexec / EverythingExec

{{#include ../../../../banners/hacktricks-training.md}}

## Bağlam

Linux normalde programları diskte veya bellekte depolanan çalıştırılabilir dosyalardan çalıştırır. Bir çalıştırılabilir dosyayı yol adı veya dosya tanımlayıcısı üzerinden tanıyabilir; bu nedenle normal bir dosya sistemi yol adı her zaman gerekli değildir.<sup>[[2]](#references)</sup>

DDexec / EverythingExec, **zaten çalışan bir sürecin** belleğini kullanır. [Linux Fileless Execution](../../../post-exploitation/linux-fileless-execution.md) sayfasında anonim dosya çalıştırma ve ilgili tespit ve adli veri toplama konuları ele alınır; [Memory Bypasses overview](index.html#memory-bypasses) sayfasında ayrıca MemExec ve Memdlopen bağlantıları bulunur.<sup>[[1]](#references)</sup>

Bu teknik, **salt okunur, noexec, dosya adı whitelist'i ve hash whitelist'i gibi yaygın koruma tekniklerini bypass etmenizi** sağlar.<sup>[[1]](#references)</sup>

## Bağımlılıklar

Betik, çalışmak için aşağıdaki araçlara ihtiyaç duyar. Bu araçların saldırdığınız sistemde erişilebilir olması gerekir (varsayılan olarak hepsini her yerde bulabilirsiniz):

```
dd
bash | zsh | ash (busybox)
head
tail
cut
grep
od
readlink
wc
tr
base64
```

## Teknik

Bir sürecin belleğini istediğiniz gibi değiştirebiliyorsanız süreci ele geçirebilirsiniz. Bu, mevcut bir süreci ele geçirip başka bir programla değiştirmek için kullanılabilir. Bunu `ptrace()` syscall'ını kullanarak (syscall çalıştırma yeteneğinizin veya sistemde gdb'nin bulunmasının gerektiği bir yöntem) ya da daha ilginç bir şekilde `/proc/$pid/mem` dosyasına yazarak yapabiliriz.<sup>[[1]](#references)</sup>

`/proc/$pid/mem` dosyası, bir sürecin tüm adres alanının bire bir eşlemesidir (_ör._ x86-64'te `0x0000000000000000` ile `0x7ffffffffffff000` arası). Bu, dosyadan `x` ofsetinde okuma veya dosyaya yazmanın, `x` sanal adresindeki içeriği okumak veya değiştirmekle aynı olduğu anlamına gelir.

Şimdi çözmemiz gereken dört temel sorun var:

- Genellikle dosyayı yalnızca root ve dosyanın sahibi olan program değiştirebilir.
- ASLR.
- Programın adres alanında eşlenmemiş bir adrese okumaya veya yazmaya çalışırsak G/Ç hatası alırız.

Bu sorunların kusursuz olmasalar da işe yarayan çözümleri var:

- Çoğu kabuk yorumlayıcısı, alt süreçlere aktarılacak dosya tanıtıcıları oluşturulmasına izin verir. Yazma izinleriyle kabuğun `mem` dosyasına işaret eden bir fd oluşturabiliriz... böylece bu fd'yi kullanan alt süreçler kabuğun belleğini değiştirebilir.
- ASLR sorun bile değil; sürecin adres alanı hakkında bilgi edinmek için kabuğun `maps` dosyasını veya procfs'deki başka bir dosyayı inceleyebiliriz.
- Bu nedenle dosyada `lseek()` kullanmamız gerekiyor. Kabuğun içinden bunu ancak adı kötüye çıkmış `dd` ile yapabiliriz.

### Daha ayrıntılı olarak

Adımlar oldukça basit ve anlamak için herhangi bir uzmanlık gerektirmiyor:<sup>[[1]](#references)</sup>

- Çalıştırmak istediğimiz ikili dosyayı ve loader'ı ayrıştırıp ihtiyaç duydukları eşlemeleri buluruz. Ardından, genel olarak her `execve()` çağrısında kernel'ın yaptığı adımların aynısını gerçekleştirecek bir "shell"code hazırlarız:
  - Söz konusu eşlemeleri oluştururuz.
  - İkili dosyaları bu eşlemelere okuruz.
  - İzinleri ayarlarız.
  - Son olarak stack'i programın argümanlarıyla başlatır ve yardımcı vektörü (loader'ın ihtiyaç duyduğu) yerleştiririz.
  - Loader'a atlayıp geri kalanını ona bırakırız (programın ihtiyaç duyduğu kütüphaneleri yüklemesini).
- Sürecin, çalıştırdığı syscall'dan sonra döneceği adresi `syscall` dosyasından alırız.
- Çalıştırılabilir olan bu konumu, shellcode'umuzla üzerine yazarız (`mem` aracılığıyla yazılamayan sayfaları değiştirebiliriz).
- Çalıştırmak istediğimiz programı sürecin stdin'ine aktarırız (söz konusu "shell"code tarafından `read()` ile okunur).
- Bu noktada programımız için gerekli kütüphaneleri yüklemek ve programa atlamak loader'a kalır.

**Araca** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec) **göz atın.**<sup>[[1]](#references)</sup>

## EverythingExec

`dd` için birkaç alternatif var. Bunlardan biri olan `tail`, şu anda `mem` dosyasında `lseek()` yapmak için kullanılan varsayılan programdır (`dd` kullanmanın tek amacı buydu). Bu alternatifler şunlardır:<sup>[[1]](#references)</sup>

```bash
tail
hexdump
cmp
xxd
```

`SEEKER` değişkenini ayarlayarak kullanılan seeker'ı değiştirebilirsiniz, _ör._:

```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```

Scriptte, henüz uygulanmamış başka bir geçerli seeker bulursanız `SEEKER_ARGS` değişkenini ayarlayarak yine de onu kullanabilirsiniz:

```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```

Bunu engelleyin, EDR'ler.

## References

- [1] [DDexec: Linux'ta ikili dosyaları dosyasız ve gizlice çalıştırma tekniği](https://github.com/arget13/DDexec)
- [2] [execveat(2) — Linux kılavuz sayfası](https://manpages.debian.org/trixie/manpages-dev/execveat.2.en.html)
{{#include ../../../../banners/hacktricks-training.md}}
