# DDexec / EverythingExec

## Bağlam

Linux'ta bir programı çalıştırmak için programın bir dosya olarak mevcut olması ve dosya sistemi hiyerarşisi üzerinden bir şekilde erişilebilir olması gerekir (bu, `execve()` işlevinin çalışma şeklidir). Bu dosya diskte veya RAM'de (tmpfs, memfd) bulunabilir, ancak bir dosya yoluna ihtiyacınız vardır. Bu durum, bir Linux sisteminde neyin çalıştırıldığını kontrol etmeyi, tehditleri ve saldırganın araçlarını tespit etmeyi veya bunların herhangi bir şeyi çalıştırmaya çalışmasını tamamen engellemeyi (_ör._ ayrıcalıksız kullanıcıların herhangi bir yere executable dosyalar yerleştirmesine izin vermemek) oldukça kolaylaştırır.

Ancak bu teknik tüm bunları değiştirmek için burada. İstediğiniz process'i başlatamıyorsanız... **o hâlde zaten mevcut olan bir process'i hijack edersiniz**.

Bu teknik, **read-only, noexec, file-name whitelisting ve hash whitelisting gibi yaygın protection technique'lerini bypass etmenizi sağlar**.<sup>[[1]](#references)</sup>

## Dependencies

Final script'in çalışması için aşağıdaki tools'a bağlıdır; bu tools'ların saldırdığınız sistemde erişilebilir olması gerekir (varsayılan olarak hepsini her yerde bulabilirsiniz):
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

Bir process'in belleğini keyfi olarak değiştirebiliyorsanız onu ele geçirebilirsiniz. Bu, zaten mevcut olan bir process'i hijack etmek ve onu başka bir programla değiştirmek için kullanılabilir. Bunu ya `ptrace()` syscall'ını kullanarak (syscall'ları çalıştırabilme yeteneğine sahip olmanız veya sistemde gdb bulunması gerekir) ya da daha ilginç bir şekilde `/proc/$pid/mem` dosyasına yazarak gerçekleştirebiliriz.<sup>[[1]](#references)</sup>

`/proc/$pid/mem` dosyası, bir process'in tüm adres alanının bire bir eşlemesidir (_ör._ x86-64'te `0x0000000000000000` ile `0x7ffffffffffff000` arası). Bu, bu dosyadan `x` offset'inden okuma yapmanın veya bu dosyaya `x` offset'inden yazmanın, sanal adres `x`'teki içeriği okumak veya değiştirmekle aynı olduğu anlamına gelir.

Şimdi, karşılaşmamız gereken dört temel sorun var:

- Genel olarak yalnızca root ve dosyanın sahibi olan program onu değiştirebilir.
- ASLR.
- Programın adres alanında map edilmemiş bir adresten okumaya veya bu adrese yazmaya çalışırsak bir I/O error alırız.

Bu sorunların, kusursuz olmasalar da işe yarayan çözümleri vardır:

- Çoğu shell interpreter, daha sonra child process'ler tarafından inherit edilecek file descriptor'ların oluşturulmasına izin verir. Write permissions ile shell'in `mem` dosyasını gösteren bir fd oluşturabiliriz... böylece bu fd'yi kullanan child process'ler shell'in belleğini değiştirebilir.
- ASLR aslında bir sorun bile değildir; process'in adres alanı hakkında bilgi edinmek için shell'in `maps` dosyasını veya procfs içindeki herhangi başka bir dosyayı inceleyebiliriz.
- Bu nedenle dosya üzerinde `lseek()` yapmamız gerekir. Shell üzerinden bu, infamous `dd` kullanılmadığı sürece yapılamaz.

### Daha ayrıntılı olarak

Adımlar görece kolaydır ve bunları anlamak için herhangi bir uzmanlık gerektirmez:<sup>[[1]](#references)</sup>

- Çalıştırmak istediğimiz binary'yi ve loader'ı parse ederek ihtiyaç duydukları mapping'leri belirleyin. Ardından, genel olarak kernel'in her `execve()` çağrısında gerçekleştirdiği adımların aynısını yapacak bir "shell"code hazırlayın:
- Söz konusu mapping'leri oluşturun.
- Binary'leri bunların içine okuyun.
- Permissions'ları ayarlayın.
- Son olarak stack'i programın argümanlarıyla initialize edin ve auxiliary vector'ü yerleştirin (loader tarafından gereklidir).
- Loader'a jump edin ve geri kalanını onun yapmasına izin verin (programın ihtiyaç duyduğu library'leri load eder).
- `syscall` dosyasından, process'in gerçekleştirdiği syscall sonrasında geri döneceği adresi elde edin.
- Executable olacak bu konumu shellcode'umuzla overwrite edin (`mem` üzerinden unwritable page'leri değiştirebiliriz).
- Çalıştırmak istediğimiz programı process'in stdin'ine gönderin (söz konusu "shell"code tarafından `read()` edilecektir).
- Bu noktada programımız için gerekli library'leri load etmek ve programın içine jump etmek loader'ın sorumluluğundadır.

**Araca göz atın:** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec).<sup>[[1]](#references)</sup>

## EverythingExec

`dd` için, bunlardan biri olan `tail` dahil olmak üzere çeşitli alternatifler vardır. `tail`, şu anda `mem` dosyası üzerinde `lseek()` yapmak için kullanılan varsayılan programdır (`dd` kullanmanın tek amacı buydu). Söz konusu alternatifler şunlardır:<sup>[[1]](#references)</sup>
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
