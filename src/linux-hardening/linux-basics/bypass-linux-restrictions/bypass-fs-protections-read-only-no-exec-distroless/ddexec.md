# DDexec / EverythingExec

{{#include ../../../../banners/hacktricks-training.md}}

## Bağlam

Linux'ta bir programı çalıştırmak için programın bir dosya olarak mevcut olması ve dosya sistemi hiyerarşisi üzerinden bir şekilde erişilebilir olması gerekir (bu, `execve()`'nin çalışma şeklidir). Bu dosya diskte veya RAM'de (tmpfs, memfd) bulunabilir, ancak bir dosya yoluna ihtiyacınız vardır. Bu durum, bir Linux sisteminde neyin çalıştırıldığını kontrol etmeyi çok kolaylaştırır; tehditleri ve saldırganların araçlarını tespit etmeyi veya bunların kendilerine ait herhangi bir şeyi çalıştırmaya çalışmasını tamamen engellemeyi kolaylaştırır (_ör._ ayrıcalıksız kullanıcıların herhangi bir yere çalıştırılabilir dosyalar yerleştirmesine izin vermemek).

Ancak bu teknik tüm bunları değiştirmek için burada. İstediğiniz process'i başlatamıyorsanız... **o zaman zaten mevcut olan bir process'i hijack edersiniz**.

Bu teknik, **read-only, noexec, dosya adı whitelisting ve hash whitelisting gibi yaygın koruma tekniklerini bypass etmenizi** sağlar.<sup>[[1]](#references)</sup>

## Bağımlılıklar

Son script'in çalışması için aşağıdaki araçlara bağlıdır; saldırdığınız sistemde bunlara erişilebilir olması gerekir (varsayılan olarak hepsini her yerde bulabilirsiniz):
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

Bir process'in belleğini keyfi olarak değiştirebiliyorsanız, onu ele geçirebilirsiniz. Bu, zaten mevcut olan bir process'i hijack etmek ve onu başka bir programla değiştirmek için kullanılabilir. Bunu ya `ptrace()` syscall'ını kullanarak (syscall'ları execute etme yeteneğine sahip olmanız veya sistemde gdb bulunması gerekir) ya da daha ilginç bir şekilde `/proc/$pid/mem` dosyasına yazarak gerçekleştirebiliriz.<sup>[[1]](#references)</sup>

`/proc/$pid/mem` dosyası, bir process'in tüm address space'inin bire bir eşlemesidir (_örn._ x86-64'te `0x0000000000000000` ile `0x7ffffffffffff000` arası). Bu, bu dosyadan `x` offset'inden okuma veya bu dosyaya `x` offset'ine yazma işleminin, sanal adres `x`'teki içeriği okumak veya değiştirmekle aynı olduğu anlamına gelir.

Şimdi, karşılaşmamız gereken dört temel problem var:

- Genel olarak yalnızca root ve dosyanın program sahibi onu değiştirebilir.
- ASLR.
- Programın address space'inde map edilmemiş bir adresten okumaya veya bu adrese yazmaya çalışırsak bir I/O hatası alırız.

Bu problemlerin, mükemmel olmasalar da iyi olan çözümleri vardır:

- Çoğu shell interpreter, daha sonra child process'ler tarafından inherit edilecek file descriptor'ların oluşturulmasına izin verir. Yazma izinleriyle shell'in `mem` dosyasını gösteren bir fd oluşturabiliriz... böylece bu fd'yi kullanan child process'ler shell'in belleğini değiştirebilir.
- ASLR aslında bir problem bile değildir; process'in address space'i hakkında bilgi edinmek için shell'in `maps` dosyasını veya procfs içindeki başka herhangi bir dosyayı kontrol edebiliriz.
- Bu nedenle dosya üzerinde `lseek()` gerçekleştirmemiz gerekir. Shell'den bu, kötü şöhretli `dd` kullanılmadığı sürece yapılamaz.

### Daha detaylı

Adımlar nispeten kolaydır ve bunları anlamak için herhangi bir uzmanlık gerektirmez:<sup>[[1]](#references)</sup>

- Çalıştırmak istediğimiz binary'yi ve loader'ı parse ederek ihtiyaç duydukları mapping'leri öğrenin. Ardından, genel olarak kernel'in her `execve()` çağrısında gerçekleştirdiği adımların aynısını yapacak bir "shell"code hazırlayın:
- Söz konusu mapping'leri oluşturun.
- Binary'leri bunların içine okuyun.
- İzinleri ayarlayın.
- Son olarak stack'i programın argümanlarıyla initialize edin ve auxiliary vector'ü (loader tarafından gerekir) yerleştirin.
- Loader'a jump edin ve geri kalanını onun yapmasına izin verin (program tarafından ihtiyaç duyulan library'leri load eder).
- `syscall` dosyasından, process'in gerçekleştirdiği syscall'dan sonra döneceği adresi elde edin.
- Executable olacak bu konumu shellcode'umuzla overwrite edin (`mem` üzerinden unwritable page'leri değiştirebiliriz).
- Çalıştırmak istediğimiz programı process'in stdin'ine aktarın (söz konusu "shell"code tarafından `read()` edilecektir).
- Bu noktada gerekli library'leri programımız için load etmek ve programa jump etmek loader'a kalır.

**Tool'a şu adresten göz atın:** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec).<sup>[[1]](#references)</sup>

## EverythingExec

`dd` için çeşitli alternatifler vardır; bunlardan biri olan `tail`, şu anda `mem` dosyası üzerinde `lseek()` gerçekleştirmek için kullanılan varsayılan programdır (`dd` kullanmanın tek amacı buydu). Söz konusu alternatifler şunlardır:<sup>[[1]](#references)</sup>
```bash
tail
hexdump
cmp
xxd
```
`SEEKER` değişkenini ayarlayarak kullanılan seeker'ı değiştirebilirsiniz, _örn._:
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Script'te uygulanmamış başka bir geçerli seeker bulursanız, `SEEKER_ARGS` değişkenini ayarlayarak yine de kullanabilirsiniz:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Bunu engelleyin, EDR'ler.

## References

- [1] [DDexec: Linux'ta binary dosyalarını fileless ve stealthy şekilde çalıştırma tekniği](https://github.com/arget13/DDexec)
{{#include ../../../../banners/hacktricks-training.md}}
