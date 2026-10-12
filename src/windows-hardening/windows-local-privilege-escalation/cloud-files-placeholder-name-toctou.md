# Windows MDL-Mapped User Buffer Double-Fetch

{{#include ../../banners/hacktricks-training.md}}

Bir Windows kernel driver, çağıranın sağladığı sayfalardaki verileri doğruladıktan sonra aynı sayfalara işaret eden bir pointer'ı güvenlik açısından hassas bir API'ye ilettiğinde double-fetch oluşur. Sayfaları kilitlemek ve eşlemek içeriklerini değiştirilemez yapmaz. `cldflt.sys` içindeki CVE-2025-55680 bu örüntüyü gösterir: driver, Cloud Files placeholder'ın göreli adını doğruladıktan sonra hâlâ çağıranın değiştirebildiği buffer'a başvurarak nesneyi oluşturdu.<sup>[[1]](#references)[[3]](#references)</sup>

`CfCreatePlaceholders()` kayıtlı bir Cloud Files sync root'un altında dosyalar veya dizinler oluşturur. Savunmasız kod yolunda, doğrulama sonrasında adın değiştirilmesi ayrıcalıklı oluşturma işlemini bu root'un dışına yönlendirebilirdi.<sup>[[1]](#references)[[2]](#references)</sup>

## Sayfaları kilitlemek verileri neden kilitlemedi

Savunmasız `HsmpOpCreatePlaceholders()` kod yolu, çağıranın payload'ı için bir MDL ayırdı, `ProbeForRead()` ve `MmProbeAndLockPages()` çağrılarını yaptı ve bu sayfaları kernel sanal adres alanına eşledi. MDL, fiziksel sayfaları tanımlar ve bellekte kalmalarını sağlar. Baytlarının anlık görüntüsünü **almaz**. Bu nedenle user mode, driver sistem eşlemesi üzerinden okurken aynı fiziksel belleği değiştirebilir.<sup>[[1]](#references)[[3]](#references)</sup>

İlgili istek ve kullanım yolu şuydu:<sup>[[1]](#references)</sup>

1. `cldapi.dll`, `IO_REPARSE_TAG_CLOUD` (`0x9000001A`) etiketi ve `0xC0000001` create-placeholder işlemiyle Cloud Files kontrol kodu `0x903BC` gönderdi.
2. Her payload kaydı, göreli ad ve dosya kimliği için 16 bitlik offset/length çiftleri içeriyordu. Sabit alanların çoğu stack kaydına kopyalanırken değişken uzunluktaki ad eşlenmiş user sayfalarında kaldı.
3. Driver, UTF-16 adı taradı ve ters eğik çizgi veya iki nokta üst üste karakteri varsa reddetti.
4. Ardından `Buffer`'ı hâlâ eşlenmiş payload içindeki bir konumu gösteren bir `UNICODE_STRING` oluşturdu ve bunu `OBJECT_ATTRIBUTES.ObjectName` alanına atadı.
5. `FltCreateFileEx2()` bu pointer'ı yeniden okudu. Böylece eşzamanlı bir yazıcı, doğrulamanın bir dizgeyi, dosya oluşturmanın ise başka bir dizgeyi görmesine neden olabilirdi.

Her iki okuma da kernel sanal adresi kullansa bile bu bir **double-fetch** örneğidir: güvenlik sınırı, driver'ın hangi sanal eşlemeyi dereference ettiğine değil, alttaki depolama alanına bağlıdır.<sup>[[1]](#references)</sup>

## Cloud Files yarış düzeni

Açıklanan exploit stratejisi, double-fetch'i path redirection'a dönüştürmek için tekrarlanan istekler, mutator thread'ler ve bir junction kullandı:<sup>[[1]](#references)</sup>

1. Saldırganın kontrolündeki bir dizini `CfRegisterSyncRoot()` ile kaydedin ve altına korumalı bir hedefe junction olan `JUSTASTRING` oluşturun.
2. Geçerli tek bileşenli `JUSTASTRINGDnewfile.dll` adına sahip paylaşılan bir placeholder kaydı hazırlayın.
3. Mutator thread'lerin UTF-16 `D` code unit'ini `D` ile `\` arasında değiştirmesini sağlayın. İkinci gösterim `JUSTASTRING\newfile.dll` olur.
4. Worker thread'lerin aynı payload'a başvuran create-placeholder isteklerini tekrar tekrar göndermesini sağlayın ve aynı anda bir monitor ile korumalı hedefi kontrol edin.
5. Başarılı bir yinelemede ayraç içermeyen gösterim doğrulanır, ardından sonraki create işlemi ayraç içeren gösterimi gördüğünde junction izlenir.

Bu primitive yalnızca korumalı dosya veya dizin oluşturmayı sağlar. Bunu code execution'a dönüştürmek için oluşturulan dosyanın içeriğinin ve uygun bir DLL side-loading hedefi gibi ayrıcalıklı bir tüketicinin de kontrol edilmesi gerekir. İlk analiz bu zincirin son aşamasını kullandı, ancak loader'ı, payload'ı veya eksiksiz, bağımsız bir exploit'i yayımlamadı.<sup>[[1]](#references)</sup>

Windows path-lookup yarışlarını özellikle uzatan tamamlayıcı teknikler için bkz. [Kernel Race Condition Exploitation via Object Manager Slow Paths](kernel-race-condition-object-manager-slowdown.md).

## References

- [1] [Exodus Intelligence - Microsoft Windows Cloud Files Minifilter TOCTOU Ayrıcalık Yükseltme](https://blog.exodusintel.com/2025/10/20/microsoft-windows-cloud-files-minifilter-toctou-privilege-escalation/)
- [2] [Microsoft Learn - CfCreatePlaceholders işlevi](https://learn.microsoft.com/en-us/windows/win32/api/cfapi/nf-cfapi-cfcreateplaceholders)
- [3] [Microsoft Learn - MmProbeAndLockPages işlevi](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmprobeandlockpages)
{{#include ../../banners/hacktricks-training.md}}
