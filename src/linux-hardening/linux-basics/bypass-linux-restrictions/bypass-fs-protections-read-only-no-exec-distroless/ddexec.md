# DDexec / EverythingExec

{{#include ../../../../banners/hacktricks-training.md}}

## Bağlam

Linux'ta bir programı çalıştırmak için programın bir dosya olarak mevcut olması ve dosya sistemi hiyerarşisi üzerinden bir şekilde erişilebilir olması gerekir (bu, `execve()` işleyişidir). Bu dosya diskte veya RAM'de (tmpfs, memfd) bulunabilir; ancak bir filepath gerekir. Bu durum, Linux sisteminde neyin çalıştırılacağını kontrol etmeyi çok kolaylaştırır; tehditleri ve saldırganın araçlarını tespit etmeyi veya bunların herhangi bir şeyi çalıştırmaya çalışmasını tamamen engellemeyi kolaylaştırır (_örn._ ayrıcalıksız kullanıcıların herhangi bir yere executable dosyalar yerleştirmesine izin vermemek).

Ancak bu teknik, tüm bunları değiştirmek için burada. İstediğiniz process'i başlatamıyorsanız... **o zaman zaten mevcut olan bir process'i hijack edersiniz**.

Bu teknik, **read-only, noexec, file-name whitelisting, hash whitelisting gibi yaygın protection tekniklerini bypass etmenizi sağlar...**<sup>[[1]](#references)</sup>

## Dependencies

Final script'in çalışması için aşağıdaki tools'a bağlıdır; saldırdığınız sistemde bunlara erişilebilir olması gerekir (varsayılan olarak hepsini her yerde bulabilirsiniz):
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

Bir process'in belleğini keyfi olarak değiştirebiliyorsanız, onu ele geçirebilirsiniz. Bu, zaten mevcut olan bir process'i hijack etmek ve onu başka bir programla değiştirmek için kullanılabilir. Bunu ya `ptrace()` syscall'ını kullanarak (syscall çalıştırma yeteneğine sahip olmanız veya sistemde gdb bulunması gerekir) ya da daha ilginç bir şekilde `/proc/$pid/mem` dosyasına yazarak gerçekleştirebiliriz.<sup>[[1]](#references)</sup>

`/proc/$pid/mem` dosyası, bir process'in tüm address space'inin bire bir eşlemesidir (_örn._ x86-64'te `0x0000000000000000` ile `0x7ffffffffffff000` arası). Bu, bu dosyadan `x` offset'inden okuma yapmanın veya bu dosyaya `x` offset'ine yazmanın, sanal `x` adresindeki içeriği okumak veya değiştirmekle aynı olduğu anlamına gelir.

Şimdi, karşılaşmamız gereken dört temel problem var:

- Genel olarak yalnızca root ve dosyanın sahibi olan program onu değiştirebilir.
- ASLR.
- Programın address space'inde map edilmemiş bir adresten okumaya veya bu adrese yazmaya çalışırsak bir I/O error alırız.

Bu problemlerin, mükemmel olmasalar da işimize yarayan çözümleri vardır:

- Çoğu shell interpreter, daha sonra child process'lere inherit edilecek file descriptor'ların oluşturulmasına izin verir. Write permission'lara sahip ve shell'in `mem` dosyasını gösteren bir fd oluşturabiliriz... böylece bu fd'yi kullanan child process'ler shell'in belleğini değiştirebilir.
- ASLR aslında bir problem bile değildir; process'in address space'i hakkında bilgi edinmek için shell'in `maps` dosyasını veya procfs içindeki başka herhangi bir dosyayı kontrol edebiliriz.
- Bu nedenle dosya üzerinde `lseek()` kullanmamız gerekir. Shell'den bunu, meşhur `dd`'yi kullanmadan yapmak mümkün değildir.

### Daha ayrıntılı olarak

Adımlar görece kolaydır ve bunları anlamak için herhangi bir uzmanlık gerektirmez:<sup>[[1]](#references)</sup>

- Çalıştırmak istediğimiz binary'yi ve hangi mapping'lere ihtiyaç duyduklarını öğrenmek için loader'ı parse edin. Ardından, genel hatlarıyla kernel'in her `execve()` çağrısında gerçekleştirdiği adımların aynısını yapacak bir "shell"code hazırlayın:
- Söz konusu mapping'leri oluşturun.
- Binary'leri bunların içine okuyun.
- Permission'ları ayarlayın.
- Son olarak stack'i programın argument'larıyla initialize edin ve auxiliary vector'ı (loader tarafından gereklidir) yerleştirin.
- Loader'a jump edin ve geri kalanını onun yapmasına izin verin (programın ihtiyaç duyduğu library'leri load edin).
- Process'in, çalıştırdığı syscall'dan sonra döneceği adresi `syscall` dosyasından elde edin.
- Executable olacak bu konumu shellcode'umuzla overwrite edin (`mem` üzerinden unwritable page'leri değiştirebiliriz).
- Çalıştırmak istediğimiz programı process'in stdin'ine gönderin (söz konusu "shell"code tarafından `read()` edilecektir).
- Bu noktada programımız için gerekli library'leri load etmek ve programın içine jump etmek loader'ın görevidir.

**Tool'a göz atın:** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec)<sup>[[1]](#references)</sup>

## EverythingExec

`dd` için, `tail` de dahil olmak üzere, çeşitli alternatifler vardır. `tail` şu anda `mem` dosyası üzerinde `lseek()` yapmak için kullanılan varsayılan programdır (`dd` kullanılmasının tek amacı buydu). Söz konusu alternatifler şunlardır:<sup>[[1]](#references)</sup>
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

## Referanslar

- [1] [DDexec: Linux'ta binary dosyalarını fileless ve stealthy şekilde çalıştırma tekniği](https://github.com/arget13/DDexec)

{{#include ../../../../banners/hacktricks-training.md}}
