# Bir Web Sayfasından Hassas Bilgi Çalma

{{#include ../banners/hacktricks-training.md}}

Bir **web sayfası mevcut oturuma göre hassas bilgiler görüntülüyorsa**—çerezler, hesap verileri veya kredi kartı bilgileri gibi—bir saldırgan bu bilgileri dışarı sızdırmaya çalışabilir. Başlıca teknikler şunlardır:

- [**CORS bypass**](../pentesting-web/cors-bypass.md): Bir CORS yanlış yapılandırması, kötü amaçlı bir origin'in cross-origin istekler aracılığıyla hassas yanıtları okumasına izin verebilir.
- [**XSS**](../pentesting-web/xss-cross-site-scripting/index.html): Hedef origin'deki bir XSS güvenlik açığı, enjekte edilen JavaScript'in bilgileri okumasına ve dışarı sızdırmasına izin verebilir.
- [**Dangling markup**](../pentesting-web/dangling-markup-html-scriptless-injection/index.html): Script injection kullanılamadığında, enjekte edilen HTML öğeleri yine de hassas içeriği yakalayabilir.
- [**Clickjacking**](../pentesting-web/clickjacking.md): Framing korumaları yoksa saldırgan, kullanıcıyı hassas sayfayla etkileşime girmesi için kandırabilir. Bağlantısı verilen vaka çalışması bu tekniği göstermektedir.<sup>[[1]](#references)</sup>

## References

- [1] [Apache örnek servlet'i Information Disclosure'a yol açıyor](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)
{{#include ../banners/hacktricks-training.md}}
