# macOS Bellek Dökümü

{{#include ../../../banners/hacktricks-training.md}}

## Bellek Artefaktları

### Takas Dosyaları

Takas dosyaları, örneğin `/private/var/vm/swapfile0`, **fiziksel bellek dolduğunda önbellek olarak** hizmet eder. Fiziksel bellek dolduğunda, veriler bir takas dosyasına aktarılır ve ihtiyaç duyulduğunda fiziksel belleğe geri getirilir. Birden fazla takas dosyası bulunabilir; isimleri swapfile0, swapfile1 gibi olabilir.

### Hibernasyon Görüntüsü

`/private/var/vm/sleepimage` konumundaki dosya, **hibernasyon modunda** kritik öneme sahiptir. **OS X hibernasyona geçtiğinde bellek verileri bu dosyada saklanır**. Bilgisayar uyandığında, sistem bu dosyadan bellek verilerini alır ve kullanıcının kaldığı yerden devam etmesine olanak tanır.

Modern MacOS sistemlerinde, bu dosyanın genellikle güvenlik nedenleriyle şifreli olduğunu ve kurtarmanın zor olduğunu belirtmek gerekir.

- Sleepimage için şifrelemenin etkin olup olmadığını kontrol etmek için `sysctl vm.swapusage` komutu çalıştırılabilir. Bu, dosyanın şifreli olup olmadığını gösterecektir.

### Bellek Baskı Günlükleri

MacOS sistemlerinde başka bir önemli bellekle ilgili dosya **bellek baskı günlüğü**dür. Bu günlükler `/var/log` konumunda bulunur ve sistemin bellek kullanımı ve baskı olayları hakkında ayrıntılı bilgi içerir. Bellekle ilgili sorunları teşhis etmek veya sistemin zamanla belleği nasıl yönettiğini anlamak için özellikle yararlı olabilir.

## osxpmem ile bellek dökümü

Bir MacOS makinesinde belleği dökmek için [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip) kullanılabilir.

**Not**: Aşağıdaki talimatlar yalnızca Intel mimarisine sahip Mac'ler için geçerlidir. Bu araç artık arşivlenmiştir ve son sürümü 2017'de çıkmıştır. Aşağıdaki talimatlarla indirilen ikili dosya, 2017'de Apple Silicon olmadığı için Intel yongalarını hedef alır. arm64 mimarisi için ikili dosyayı derlemek mümkün olabilir, ancak bunu kendiniz denemeniz gerekecek.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Eğer bu hatayı bulursanız: `osxpmem.app/MacPmem.kext yüklenemedi - (libkern/kext) kimlik doğrulama hatası (dosya sahipliği/izinleri); hatalar için sistem/kernel günlüklerini kontrol edin veya kextutil(8) deneyin` Bunu düzeltmek için:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Diğer hatalar**, "Güvenlik ve Gizlilik --> Genel" bölümünde **kext'in yüklenmesine izin vererek** düzeltilebilir, sadece **izin verin**.

Ayrıca bu **tek satırı** uygulamayı indirmek, kext'i yüklemek ve belleği dökmek için kullanabilirsiniz:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
{{#include ../../../banners/hacktricks-training.md}}
