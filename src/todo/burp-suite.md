# Burp Suite

{{#include ../banners/hacktricks-training.md}}

## Intruder payload türleri

Burp Intruder aşağıdaki yerleşik payload oluşturucularını ve dönüşümlerini içerir:<sup>[[1]](#references)</sup>

- **Simple list:** Yapılandırılmış bir string listesini payload olarak kullanır.
- **Runtime file:** Çalışma zamanında satır başına bir payload okur. Burp dosyanın tamamını belleğe yüklemediği için büyük listelerde kullanışlıdır.
- **Case modification:** Değiştirilmemiş değeri, küçük harfli ve büyük harfli biçimleri, `Propername` (ilk harf büyük, geri kalanı küçük) veya `ProperName` (ilk harf büyük, kalan karakterler değiştirilmemiş) biçimini oluşturur. Burp yinelenen sonuçları atar.
- **Numbers:** Yapılandırılmış bir aralık içinde sıralı veya rastgele sayılar oluşturur.
- **Brute forcer:** Seçilen bir karakter kümesi ile minimum/maksimum uzunluk için her permütasyonu oluşturur.

## Eklentiler ve yardımcı araçlar

- **Collabfiltrator**, komutları çalıştıran ve çıktılarını Burp Collaborator'a DNS sorguları üzerinden exfiltrate eden payloadlar oluşturur.<sup>[[2]](#references)</sup>
- **Burp Suite Exporter**, Burp bulgularını diğer raporlama iş akışlarında kullanılmak üzere dışa aktarır.<sup>[[3]](#references)</sup>
- **HTTP Script Generator**, HTTP isteklerini çeşitli dillerdeki scriptlere dönüştürür.<sup>[[4]](#references)</sup>

## References

- [1] [PortSwigger documentation - Burp Intruder payload türleri](https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/payload-types)
- [2] [GitHub - 0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator)
- [3] [ArtsSEC - Burp Suite Exporter](https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e)
- [4] [GitHub - h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)
{{#include ../banners/hacktricks-training.md}}
