# macOS Seri Numarası

{{#include ../../../banners/hacktricks-training.md}}

## Temel Bilgiler

Her Mac'in çözümlenebilir 12 karakterlik bir seri numarasına sahip olduğunu varsaymayın. Apple'ın eski formatı üretim ve yapılandırma bilgilerini kodluyordu, ancak Apple 2021'de yeni ürünlerle birlikte rastgeleleştirilmiş seri numaralarını kullanıma sunmaya başladı. Rastgeleleştirilmiş format, üretim veya yapılandırma ayrıntılarını açığa çıkarmaz.<sup>[[1]](#references)</sup>

### Eski 12 karakterlik format

2010'dan rastgeleleştirilmiş formata geçişe kadar üretilen birçok cihaz için 12 karakterlik format hâlâ yararlı envanter ipuçları sağlayabilir:<sup>[[3]](#references)</sup>

- 1–3. karakterler üretim konumunu belirtir.
- 4–5. karakterler üretim yılının yarısını ve haftasını kodlar.
- 6–8. karakterler aynı konumda ve zamanda üretilen birimleri birbirinden ayırır.
- 9–12. karakterler model veya yapılandırma kodunu belirtir.

Örneğin, `C02L13ECF8J2` bu eski yapıyı izler. Community-maintained fabrika eşleştirmelerinde Amerika Birleşik Devletleri'ndeki konumlar için `FC`, `F`, `XA`, `XB`, `QP` ve `G8`; Meksika için `RN`; Cork için `CK`; Çek Cumhuriyeti'ndeki bir Foxconn konumu için `VM`; Singapur için `SG` veya `E`; Malezya için `MB`; Kore için `PT` veya `CY`; Tayvan için `EE`, `QT` veya `UV` gibi ön ekler bulunur. `FK`, `F1`, `F2`, `W8`, `DL`, `DM`, `DN`, `YM`, `7J`, `1C`, `4H`, `WQ`, `F7`, `C0`, `C3` ve `C7` dahil çok sayıda ön ek Çin'deki tesislerle ilişkilendirilmiştir; `RM` ise yenilenmiş cihazlarla ilişkilendirilmiştir.<sup>[[3]](#references)</sup>

Dördüncü karakterdeki tarih kodları, `C` (2010'un ilk yarısı) ile `Z` (2019'un ikinci yarısı) arasında değişir ve bu dizi daha sonra yeniden kullanılır. Beşinci karakter için `1`–`9` rakamları 1–9. haftaları, sesli harfler ve `S` hariç `C`–`Y` harfleri ise 10–27. haftaları temsil eder; dördüncü karakter yılın ikinci yarısını gösteriyorsa 26 ekleyin.<sup>[[3]](#references)</sup>

Bu eşleştirmeler eski cihazların triage işlemleri için kullanışlıdır, ancak köken, yaş veya gerçeklik konusunda kesin kanıt oluşturmaz. Sonucu Apple'ın envanter verileriyle doğrulayın.

Güvenilir tanımlama için seri numarasını cihazdan alın ve modeli karakter konumlarından çıkarmaya çalışmak yerine Apple'ın coverage veya teknik özellik lookup aracını kullanın.<sup>[[2]](#references)</sup>

### Seri numarasını alma

Grafik arayüz, seri numarasını **Apple menüsü > Bu Mac Hakkında** bölümünde gösterir.<sup>[[2]](#references)</sup> Bir shell üzerinden aşağıdaki komutlardan herhangi biri platform seri numarasını okur:
```bash
system_profiler SPHardwareDataType | awk -F ': ' '/Serial Number/ {print $2}'
ioreg -rd1 -c IOPlatformExpertDevice | awk -F '"' '/IOPlatformSerialNumber/ {print $4}'
```
Seri numarasını bir kimlik olarak değerlendirin, doğrulayıcı olarak değil: kayıt veya sahiplik kararları vermeden önce cihazı ilgili Apple veya MDM envanter iş akışı üzerinden doğrulayın.

## References

- [1] [MacRumors - Apple rastgeleleştirilmiş seri numaralarına geçişi başlatıyor](https://www.macrumors.com/2021/05/05/purple-iphone-12-randomized-serial-number/)
- [2] [Apple Support - Mac model adınızı ve seri numaranızı bulma](https://support.apple.com/en-us/102767)
- [3] [Beetstech - Bir Apple seri numarasının ardındaki anlamı çözümleme](https://beetstech.com/blog/decode-meaning-behind-apple-serial-number)
{{#include ../../../banners/hacktricks-training.md}}
