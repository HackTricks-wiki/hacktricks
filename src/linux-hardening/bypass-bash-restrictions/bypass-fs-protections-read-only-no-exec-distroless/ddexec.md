# DDexec / EverythingExec

{{#include ../../../banners/hacktricks-training.md}}

## Bağlam

Linux'ta bir programı çalıştırmak için, bir dosya olarak var olması gerekir, dosya sistemi hiyerarşisi aracılığıyla bir şekilde erişilebilir olmalıdır (bu, `execve()`'nin çalışma şeklidir). Bu dosya diskte veya ram'de (tmpfs, memfd) bulunabilir ama bir dosya yoluna ihtiyacınız var. Bu, bir Linux sisteminde neyin çalıştırılacağını kontrol etmeyi çok kolay hale getirmiştir, tehditleri ve saldırganın araçlarını tespit etmeyi veya onların hiçbir şey çalıştırmaya çalışmasını engellemeyi kolaylaştırır (_ör. g._ yetkisiz kullanıcıların yürütülebilir dosyaları herhangi bir yere yerleştirmesine izin vermemek).

Ama bu teknik tüm bunları değiştirmek için burada. Eğer istediğiniz süreci başlatamıyorsanız... **o zaman zaten var olan birini ele geçirirsiniz**.

Bu teknik, **salt okunur, noexec, dosya adı beyaz listeleme, hash beyaz listeleme gibi yaygın koruma tekniklerini atlamanıza olanak tanır...**

## Bağımlılıklar

Son script, çalışması için aşağıdaki araçlara bağımlıdır, bunların saldırdığınız sistemde erişilebilir olması gerekir (varsayılan olarak, bunların hepsini her yerde bulacaksınız):
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

Eğer bir sürecin belleğini keyfi olarak değiştirebiliyorsanız, onu ele geçirebilirsiniz. Bu, zaten var olan bir süreci kaçırmak ve onu başka bir programla değiştirmek için kullanılabilir. Bunu ya `ptrace()` sistem çağrısını kullanarak (bu, sistemde sistem çağrılarını çalıştırma yeteneğine veya gdb'nin mevcut olmasına ihtiyaç duyar) ya da daha ilginç bir şekilde, `/proc/$pid/mem` dosyasına yazarak başarabiliriz.

`/proc/$pid/mem` dosyası, bir sürecin tüm adres alanının bire bir eşlemesidir (_örneğin_ `0x0000000000000000` ile `0x7ffffffffffff000` arasında x86-64'te). Bu, bu dosyadan `x` ofsetinde okumak veya yazmanın, sanal adres `x`'teki içeriği okumak veya değiştirmekle aynı olduğu anlamına gelir.

Şimdi, karşılaşmamız gereken dört temel sorun var:

- Genel olarak, yalnızca root ve dosyanın program sahibi onu değiştirebilir.
- ASLR.
- Programın adres alanında haritalanmamış bir adrese okumaya veya yazmaya çalışırsak, bir I/O hatası alırız.

Bu sorunların, mükemmel olmasa da, iyi olan çözümleri vardır:

- Çoğu shell yorumlayıcısı, daha sonra çocuk süreçler tarafından miras alınacak dosya tanımlayıcılarının oluşturulmasına izin verir. Yazma izinleri olan `mem` dosyasına işaret eden bir fd oluşturabiliriz... böylece o fd'yi kullanan çocuk süreçler shell'in belleğini değiştirebilir.
- ASLR bile bir sorun değildir, sürecin adres alanı hakkında bilgi edinmek için shell'in `maps` dosyasını veya procfs'den herhangi bir dosyayı kontrol edebiliriz.
- Bu nedenle dosya üzerinde `lseek()` yapmamız gerekiyor. Shell'den bu, kötü ünlü `dd` kullanılmadıkça yapılamaz.

### Daha ayrıntılı

Adımlar görece kolaydır ve anlamak için herhangi bir uzmanlık gerektirmez:

- Çalıştırmak istediğimiz ikili dosyayı ve yükleyiciyi ayrıştırarak hangi haritalara ihtiyaç duyduklarını öğrenin. Ardından, genel olarak, her `execve()` çağrısında çekirdek tarafından gerçekleştirilen aynı adımları gerçekleştirecek bir "shell" kodu oluşturun:
- Söz konusu haritaları oluşturun.
- İkili dosyaları bunlara okuyun.
- İzinleri ayarlayın.
- Son olarak, program için argümanlarla yığını başlatın ve yükleyici tarafından gereken yardımcı vektörü yerleştirin.
- Yükleyiciye atlayın ve geri kalanını yapmasına izin verin (programın ihtiyaç duyduğu kütüphaneleri yükleyin).
- `syscall` dosyasından, sürecin yürüttüğü sistem çağrısından sonra döneceği adresi alın.
- O yeri, yürütülebilir olacak şekilde, shell kodumuzla üzerine yazın (yazılamaz sayfaları `mem` üzerinden değiştirebiliriz).
- Çalıştırmak istediğimiz programı sürecin stdin'ine geçirin (söz konusu "shell" kodu tarafından `read()` ile okunacaktır).
- Bu noktada, yükleyicinin programımız için gerekli kütüphaneleri yüklemesi ve içine atlaması kalır.

**Aracı kontrol edin** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec)

## EverythingExec

`dd` için birkaç alternatif vardır, bunlardan biri olan `tail`, şu anda `mem` dosyasında `lseek()` yapmak için kullanılan varsayılan programdır (bu, `dd` kullanmanın tek amacıdır). Bu alternatifler şunlardır:
```bash
tail
hexdump
cmp
xxd
```
`SEEKER` değişkenini ayarlayarak kullanılan arayıcıyı değiştirebilirsiniz, _ör. g._:
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Eğer scriptte uygulanmamış başka bir geçerli seeker bulursanız, `SEEKER_ARGS` değişkenini ayarlayarak yine de kullanabilirsiniz:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Bunu engelle, EDR'ler.

## Referanslar

- [https://github.com/arget13/DDexec](https://github.com/arget13/DDexec)

{{#include ../../../banners/hacktricks-training.md}}
