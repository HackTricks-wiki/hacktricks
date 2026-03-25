# macOS Bellek Dökmeleri

{{#include ../../../banners/hacktricks-training.md}}

## Bellek Artefaktları

### Swap Dosyaları

Swap dosyaları, örneğin `/private/var/vm/swapfile0`, fiziksel bellek dolduğunda **önbellek görevi görür**. Fiziksel bellekte yer kalmadığında, veriler bir swap dosyasına aktarılır ve gerektiğinde tekrar fiziksel belleğe geri getirilir. Birden fazla swap dosyası bulunabilir; isimleri genellikle swapfile0, swapfile1 vb. şeklindedir.

### Hibernasyon Görüntüsü

`/private/var/vm/sleepimage` konumundaki dosya **hibernasyon modu** sırasında hayati öneme sahiptir. **OS X hibernasyona geçtiğinde bellek verileri bu dosyaya kaydedilir.** Bilgisayar uyandığında sistem bu dosyadan bellek verilerini geri yükler ve kullanıcı kaldığı yerden devam edebilir.

Modern macOS sistemlerinde bu dosyanın genellikle güvenlik nedeniyle şifrelenmiş olduğunu, bu yüzden kurtarmanın zorlaştığını belirtmek gerekir.

- sleepimage için şifrelemenin etkin olup olmadığını kontrol etmek için `sysctl vm.swapusage` komutu çalıştırılabilir. Bu, dosyanın şifrelenip şifrelenmediğini gösterecektir.

### Bellek Basıncı Kayıtları

macOS sistemlerinde bir diğer önemli bellekle ilgili dosya **memory pressure log** kayıtlarıdır. Bu loglar `/var/log` içinde bulunur ve sistemin bellek kullanımı ile basınç olayları hakkında ayrıntılı bilgi içerir. Bellekle ilgili sorunları teşhis etmek veya sistemin zaman içinde belleği nasıl yönettiğini anlamak için özellikle faydalı olabilirler.

## osxpmem ile bellek dökme

MacOS makinesinde belleği dökmek için [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip) kullanılabilir.

**Not**: Bu artık büyük ölçüde bir **miras iş akışıdır**. `osxpmem` bir kernel extension yüklemesine bağlıdır, [Rekall](https://github.com/google/rekall) projesi arşivlenmiştir, son sürüm **2017** tarihli olup yayımlanan ikili sadece **Intel Macs** hedeflemektedir. Güncel macOS sürümlerinde, özellikle **Apple Silicon** üzerinde, kext tabanlı tüm RAM edinimi genellikle modern kernel-extension kısıtlamaları, SIP ve platform-imza gereksinimleri tarafından engellenir. Pratikte, modern sistemlerde tüm RAM görüntüsü almak yerine çoğunlukla bir **process-scoped dump** yapmanız daha olasıdır.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Eğer bu hatayı alırsanız: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` bunu şu şekilde düzeltebilirsiniz:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Diğer hatalar** "Security & Privacy --> General" içinde **kext'in yüklenmesine izin verilmesi** ile düzeltilebilir, sadece **izin verin**.

Ayrıca uygulamayı indirmek, kext'i yüklemek ve belleği dump etmek için bu **oneliner**'ı kullanabilirsiniz:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## LLDB ile canlı process dökümü

Güncel macOS sürümleri için genellikle en pratik yaklaşım, tüm fiziksel belleğin imajını almaya çalışmak yerine bir **specific process**'in belleğini dökmektir.

LLDB canlı bir hedeften Mach-O core file kaydedebilir:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target.core
```
Varsayılan olarak bu genellikle bir **skinny core** oluşturur. LLDB'nin tüm eşlenmiş process belleğini dahil etmesini zorlamak için:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target-full.core --style full
```
dumping öncesi yararlı takip komutları:
```bash
# Show loaded images and main binary
(lldb) image list

# Inspect mapped regions and permissions
(lldb) memory region --all

# Dump only one interesting range
(lldb) memory read --force --outfile /tmp/region.bin --binary <start> <end>
```
Bu, geri kazanma hedefi olduğunda genellikle yeterlidir:

- Şifre çözülmüş configuration blob'ları
- Bellek içindeki token'lar, cookie'ler veya kimlik bilgileri
- Yalnızca at-rest korumasına sahip düz metin gizli veriler
- Unpacking / JIT / runtime patching sonrasında şifre çözülmüş Mach-O sayfaları

Hedef **hardened runtime** ile korunuyorsa veya `taskgated` attach'i reddediyorsa, genellikle aşağıdaki durumlardan biri gerekir:

- Hedef **`get-task-allow`** özelliğine sahip
- Debugger'ınız uygun **debugger entitlement** ile imzalanmış
- Siz **root**'sunuz ve hedef, hardened olmayan üçüncü taraf bir process

Bir task portu elde etme ve bununla neler yapılabileceğine dair daha fazla arka plan için:

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

## Frida veya userland okuyucularla seçici dumps

Tam bir core çok gürültülü olduğunda, yalnızca ilginç okunabilir aralıkları dump'lamak genellikle daha hızlıdır. Frida özellikle yararlıdır çünkü sürece bağlanabildiğinizde **targeted extraction** için iyi çalışır.

Örnek yaklaşım:

1. Okunabilir/yazılabilir aralıkları listele
2. Modül, heap, stack veya anonim belleğe göre filtrele
3. Aday string'ler, anahtarlar, protobuf'lar, plist/XML blob'ları veya şifre çözülmüş kod/veri içeren bölgeleri dump'la

Tüm okunabilir anonim aralıkları dump'lamak için minimal Frida örneği:
```javascript
Process.enumerateRanges({ protection: 'rw-', coalesce: true }).forEach(function (range) {
try {
if (range.file) return;
var dump = range.base.readByteArray(range.size);
var f = new File('/tmp/' + range.base + '.bin', 'wb');
f.write(dump);
f.close();
} catch (e) {}
});
```
Bu, devasa core dosyalarından kaçınmak ve yalnızca şunları toplamak istediğinizde faydalıdır:

- App heap chunks containing secrets
- Anonymous regions created by custom packers or loaders
- JIT / unpacked code pages after changing protections

Eski userland araçları, örneğin [`readmem`](https://github.com/gdbinit/readmem), hâlâ mevcuttur; ancak bunlar esasen doğrudan `task_for_pid`/`vm_read` tarzı döküm için **kaynak referansları** olarak yararlıdır ve modern Apple Silicon iş akışları için iyi bakım görmemektedir.

## Hızlı ön değerlendirme notları

- `sysctl vm.swapusage` hâlâ **swap kullanımını** ve swap'in **şifreli olup olmadığını** kontrol etmek için hızlı bir yoldur.
- `sleepimage` özellikle **hibernate/safe sleep** senaryoları için hâlâ ilgili olsa da, modern sistemler genellikle onu korur; bu yüzden güvenilir bir edinim yolu olarak değil, kontrol edilecek bir **artefakt kaynağı** olarak ele alınmalıdır.
- Güncel macOS sürümlerinde, boot policy, SIP state ve kext loading'i kontrol etmediğiniz sürece, genellikle **process-level dumping** tam bir **full physical memory imaging**'den daha gerçekçidir.

## Referanslar

- [https://www.appspector.com/blog/core-dump](https://www.appspector.com/blog/core-dump)
- [https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)

{{#include ../../../banners/hacktricks-training.md}}
