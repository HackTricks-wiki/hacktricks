# macOS AppleFS

{{#include ../../banners/hacktricks-training.md}}

## Apple Özel Dosya Sistemi (APFS)

**Apple File System (APFS)**, Hierarchical File System Plus (HFS+) dosya sisteminin yerini almak üzere tasarlanmış modern bir dosya sistemidir. Geliştirilmesi, **daha iyi performans, güvenlik ve verimlilik** ihtiyacından kaynaklanmıştır.

APFS'nin dikkate değer özelliklerinden bazıları şunlardır:<sup>[[1]](#references)</sup>

1. **Alan Paylaşımı**: APFS, birden fazla birimin tek bir fiziksel cihazdaki **aynı temel boş depolama alanını paylaşmasına** olanak tanır. Bu, birimlerin manuel olarak yeniden boyutlandırılmasına veya yeniden bölümlendirilmesine gerek kalmadan dinamik olarak büyüyüp küçülebilmesini sağlayarak alanın daha verimli kullanılmasına olanak verir.
1. Bu, disklerdeki geleneksel bölümlerle karşılaştırıldığında APFS'de **farklı bölümlerin (birimlerin) tüm disk alanını paylaştığı**, normal bir bölümün ise genellikle sabit bir boyuta sahip olduğu anlamına gelir.
2. **Anlık Görüntüler**: APFS, dosya sisteminin **salt okunur** ve belirli bir andaki durumunu temsil eden **anlık görüntüler oluşturmayı** destekler. Anlık görüntüler, çok az ek depolama alanı kullandıkları ve hızlıca oluşturulabildikleri veya geri yüklenebildikleri için verimli yedeklemeler ve kolay sistem geri dönüşleri sağlar.
3. **Klonlar**: APFS, klon veya orijinal dosya değiştirilene kadar orijinalle **aynı depolama alanını paylaşan dosya veya dizin klonları oluşturabilir**. Bu özellik, depolama alanını çoğaltmadan dosya veya dizin kopyaları oluşturmak için verimli bir yöntem sağlar.
4. **Şifreleme**: APFS, **yerel olarak tam disk şifrelemesini** ve dosya başına veya dizin başına şifrelemeyi destekleyerek farklı kullanım senaryolarında veri güvenliğini artırır.
5. **Çökme Koruması**: APFS, ani güç kaybı veya sistem çökmeleri durumunda bile **dosya sistemi tutarlılığını sağlayan copy-on-write metadata şeması** kullanır ve veri bozulması riskini azaltır.

Genel olarak APFS, performans, güvenilirlik ve güvenliğe odaklanarak Apple cihazları için daha modern, esnek ve verimli bir dosya sistemi sunar.
```bash
diskutil list # Get overview of the APFS volumes
```
## Firmlinks

`Data` volume'u **`/System/Volumes/Data`** konumuna mount edilir (bunu `diskutil apfs list` komutuyla kontrol edebilirsiniz).

Firmlink listesi **`/usr/share/firmlinks`** dosyasında bulunabilir.
```bash

```
## Referanslar

- [1] [APFS Guide - Özellikler - Apple Developer Documentation](https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/APFS_Guide/Features/Features.html)

{{#include ../../banners/hacktricks-training.md}}
