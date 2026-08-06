# Web Üzerinden Hassas Bilgi İfşasını Çalma

{{#include ../banners/hacktricks-training.md}}

Bir noktada **session'ınıza dayalı hassas bilgiler sunan bir web sayfası bulursanız**: Belki cookie'leri yansıtıyor, CC bilgilerini yazdırıyor veya başka herhangi bir hassas bilgi sunuyor olabilir; bunları çalmayı deneyebilirsiniz.\
Burada bunu gerçekleştirmek için deneyebileceğiniz başlıca yöntemleri sunuyorum:

- [**CORS bypass**](../pentesting-web/cors-bypass.md): CORS header'larını bypass edebilirseniz, kötü amaçlı bir sayfaya Ajax request gerçekleştirerek bilgileri çalabilirsiniz.
- [**XSS**](../pentesting-web/xss-cross-site-scripting/index.html): Sayfada bir XSS açığı bulursanız, bilgileri çalmak için bunu abuse edebilirsiniz.
- [**Danging Markup**](../pentesting-web/dangling-markup-html-scriptless-injection/index.html): XSS tag'lerini inject edemiyorsanız bile, diğer standart HTML tag'lerini kullanarak bilgileri çalabilirsiniz.
- [**Clickjaking**](../pentesting-web/clickjacking.md): Bu saldırıya karşı herhangi bir koruma yoksa, kullanıcıyı hassas verileri size göndermesi için kandırabilirsiniz (bir örnek [burada](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)).<sup>[[1]](#references)</sup>

## References

- [1] [Apache example servlet leads to Information Disclosure](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)

{{#include ../banners/hacktricks-training.md}}
