# macOS AppleFS

{{#include ../../banners/hacktricks-training.md}}

## Apple'a Ait Dosya Sistemi (APFS)

**Apple Dosya Sistemi (APFS)**, Hiyerarşik Dosya Sistemi Artı (HFS+) yerine geçmek üzere tasarlanmış modern bir dosya sistemidir. Geliştirilmesi, **geliştirilmiş performans, güvenlik ve verimlilik** ihtiyacından kaynaklanmıştır.

APFS'nin bazı dikkat çekici özellikleri şunlardır:

1. **Alan Paylaşımı**: APFS, bir fiziksel cihazda **aynı temel boş depolamayı paylaşan birden fazla hacme** izin verir. Bu, hacimlerin manuel yeniden boyutlandırma veya yeniden bölümleme gerektirmeden dinamik olarak büyüyüp küçülmesiyle daha verimli alan kullanımını sağlar.
1. Bu, dosya disklerindeki geleneksel bölümlerle karşılaştırıldığında, **APFS'de farklı bölümlerin (hacimlerin) tüm disk alanını paylaştığı** anlamına gelir; oysa normal bir bölüm genellikle sabit bir boyuta sahipti.
2. **Anlık Görüntüler**: APFS, **okunabilir** olan, dosya sisteminin belirli bir zamandaki anlık görüntülerini **oluşturmayı** destekler. Anlık görüntüler, minimum ek depolama alanı tüketerek verimli yedeklemeler ve kolay sistem geri yüklemeleri sağlar ve hızlı bir şekilde oluşturulabilir veya geri alınabilir.
3. **Klonlar**: APFS, **orijinal dosya veya dizinle aynı depolamayı paylaşan dosya veya dizin klonları oluşturabilir**; bu, ya klon ya da orijinal dosya değiştirilene kadar geçerlidir. Bu özellik, depolama alanını çoğaltmadan dosya veya dizinlerin kopyalarını oluşturmanın verimli bir yolunu sağlar.
4. **Şifreleme**: APFS, **tam disk şifrelemesini** yanı sıra dosya başına ve dizin başına şifrelemeyi de yerel olarak destekleyerek farklı kullanım senaryolarında veri güvenliğini artırır.
5. **Çökme Koruması**: APFS, dosya sistemi tutarlılığını sağlamak için **kopyala-yaz metadata şemasını** kullanır; bu, ani güç kaybı veya sistem çökmesi durumlarında bile veri bozulma riskini azaltır.

Genel olarak, APFS, Apple cihazları için daha modern, esnek ve verimli bir dosya sistemi sunar; geliştirilmiş performans, güvenilirlik ve güvenlik üzerine odaklanmıştır.
```bash
diskutil list # Get overview of the APFS volumes
```
## Firmlinks

`Data` hacmi **`/System/Volumes/Data`** dizinine monte edilmiştir (bunu `diskutil apfs list` ile kontrol edebilirsiniz).

Firmlinklerin listesi **`/usr/share/firmlinks`** dosyasında bulunabilir.
```bash

```
{{#include ../../banners/hacktricks-training.md}}
