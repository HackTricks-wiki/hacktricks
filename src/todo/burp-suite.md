# Burp Suite

{{#include ../banners/hacktricks-training.md}}

## Intruder payload türleri

- **Simple list:** Payload olarak yapılandırılmış bir string listesi kullanır.
- **Runtime file:** Çalışma zamanında satır başına bir payload okur. Burp tüm dosyayı belleğe yüklemediği için bu, büyük listeler açısından kullanışlıdır.
- **Case modification:** Bir input string'inin büyük/küçük harf kullanımını değiştirir; örneğin lowercase, uppercase, sentence case veya title case yapar.
- **Numbers:** Yapılandırılmış bir aralık içinde sıralı veya rastgele sayılar oluşturur.
- **Brute forcer:** Seçilen bir karakter kümesi ve minimum/maksimum uzunluk için tüm permütasyonları oluşturur.<sup>[[1]](#references)</sup>

## Extensions ve yardımcı araçlar

- **Collabfiltrator**, komutları çalıştıran ve çıktıları Burp Collaborator'a DNS sorguları üzerinden exfiltrate eden payload'lar oluşturur.<sup>[[2]](#references)</sup>
- **Burp Suite Exporter**, Burp bulgularını diğer raporlama iş akışlarında kullanılmak üzere dışa aktarır.<sup>[[3]](#references)</sup>
- **HTTP Script Generator**, HTTP isteklerini çeşitli dillerdeki script'lere dönüştürür.<sup>[[4]](#references)</sup>

## References

- [1] [PortSwigger documentation - Burp Intruder payload türleri](https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/payload-types)
- [2] [GitHub - 0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator)
- [3] [ArtsSEC - Burp Suite Exporter](https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e)
- [4] [GitHub - h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)
{{#include ../banners/hacktricks-training.md}}
