# DDexec / EverythingExec

{{#include ../../../../banners/hacktricks-training.md}}

## Bağlam

Linux'ta bir programı çalıştırmak için programın bir dosya olarak mevcut olması ve dosya sistemi hiyerarşisi üzerinden bir şekilde erişilebilir olması gerekir (bu, `execve()` işlevinin çalışma şeklidir). Bu dosya diskte veya RAM'de (tmpfs, memfd) bulunabilir, ancak bir dosya yoluna ihtiyaç vardır. Bu durum, bir Linux sisteminde neyin çalıştırılacağını kontrol etmeyi çok kolaylaştırır; tehditleri ve saldırganın araçlarını tespit etmeyi veya bunların herhangi birini çalıştırmaya çalışmalarını tamamen engellemeyi kolaylaştırır (_ör._ ayrıcalıksız kullanıcıların herhangi bir yere çalıştırılabilir dosyalar yerleştirmesine izin vermemek).

Ancak bu teknik tüm bunları değiştirmek için kullanılır. İstediğiniz süreci başlatamıyorsanız... **o hâlde zaten mevcut olan bir süreci ele geçirirsiniz**.

Bu teknik, **read-only, noexec, file-name whitelisting, hash whitelisting gibi yaygın koruma tekniklerini bypass etmenizi sağlar...**

## Bağımlılıklar

Son script'in çalışması için aşağıdaki araçlara bağlıdır; bu araçların saldırdığınız sistemde erişilebilir olması gerekir (varsayılan olarak hepsini her yerde bulabilirsiniz):
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

Bir process'in memory'sini keyfi olarak değiştirebiliyorsanız, onun kontrolünü ele geçirebilirsiniz. Bu, zaten mevcut olan bir process'i hijack etmek ve başka bir programla değiştirmek için kullanılabilir. Bunu ya `ptrace()` syscall'ını kullanarak (syscall çalıştırma yeteneğine sahip olmanız veya sistemde gdb bulunması gerekir) ya da daha ilginç bir şekilde `/proc/$pid/mem` dosyasına yazarak gerçekleştirebiliriz.

`/proc/$pid/mem` dosyası, bir process'in tüm address space'inin bire bir eşlemesidir (_ör._ x86-64'te `0x0000000000000000` ile `0x7ffffffffffff000` arası). Bu, bu dosyadan `x` offset'inden okuma veya bu dosyaya `x` offset'ine yazma işleminin, sanal adres `x`'teki içeriği okumak veya değiştirmekle aynı olduğu anlamına gelir.

Şimdi karşılaşmamız gereken dört temel problem var:

- Genel olarak yalnızca root ve dosyanın sahibi olan program onu değiştirebilir.
- ASLR.
- Programın address space'inde map edilmemiş bir adresten okumaya veya bu adrese yazmaya çalışırsak bir I/O error alırız.

Bu problemlerin, mükemmel olmasalar da işe yarayan çözümleri vardır:

- Çoğu shell interpreter, daha sonra child process'lere inherit edilecek file descriptor'ların oluşturulmasına izin verir. Write permission'lara sahip, shell'in `mem` dosyasını gösteren bir fd oluşturabiliriz... böylece bu fd'yi kullanan child process'ler shell'in memory'sini değiştirebilir.
- ASLR bir problem bile değildir; process'in address space'i hakkında bilgi edinmek için shell'in `maps` dosyasını veya procfs içindeki başka bir dosyayı kontrol edebiliriz.
- Bu nedenle dosya üzerinde `lseek()` yapmamız gerekir. Shell'den bu işlem, meşhur `dd` kullanılmadan yapılamaz.

### Daha ayrıntılı

Adımlar nispeten kolaydır ve anlaşılmaları için herhangi bir uzmanlık gerektirmez:

- Çalıştırmak istediğimiz binary'yi ve loader'ı parse ederek ihtiyaç duydukları mapping'leri öğrenin. Ardından, genel olarak kernel'in her `execve()` çağrısında gerçekleştirdiği adımların aynısını yapacak bir "shell"code hazırlayın:
- Söz konusu mapping'leri oluşturun.
- Binary'leri bunların içine okuyun.
- Permission'ları ayarlayın.
- Son olarak stack'i programın argümanlarıyla initialize edin ve auxiliary vector'ü yerleştirin (loader tarafından gereklidir).
- Loader'a jump edin ve geri kalanını onun yapmasına izin verin (programın ihtiyaç duyduğu library'leri load eder).
- Process'in çalıştırdığı syscall sonrasında geri döneceği adresi `syscall` dosyasından alın.
- Executable olacak bu konumu shellcode'umuzla overwrite edin (`mem` üzerinden unwritable page'leri değiştirebiliriz).
- Çalıştırmak istediğimiz programı process'in stdin'ine gönderin (söz konusu "shell"code tarafından `read()` edilecektir).
- Bu noktada gerekli library'leri programımız için load etmek ve programın içine jump etmek loader'ın sorumluluğundadır.

**Tool'a göz atın:** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec)

## EverythingExec

`dd` için, bunlardan biri olan `tail` gibi çeşitli alternatifler vardır. `tail`, şu anda `mem` dosyasında `lseek()` yapmak için kullanılan varsayılan programdır (`dd` kullanılmasının tek amacı buydu). Söz konusu alternatifler şunlardır:
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

- [https://github.com/arget13/DDexec](https://github.com/arget13/DDexec)

{{#include ../../../../banners/hacktricks-training.md}}
