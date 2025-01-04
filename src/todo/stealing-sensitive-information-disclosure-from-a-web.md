# Web'den Hassas Bilgi Sızdırma

{{#include ../banners/hacktricks-training.md}}

Eğer bir noktada **oturumunuza dayalı olarak hassas bilgileri sunan bir web sayfası bulursanız**: Belki çerezleri yansıtıyordur, ya da kredi kartı bilgilerini yazdırıyordur veya başka herhangi bir hassas bilgi, bunu çalmaya çalışabilirsiniz.\
İşte bunu başarmak için deneyebileceğiniz ana yollar:

- [**CORS bypass**](../pentesting-web/cors-bypass.md): CORS başlıklarını aşabilirseniz, kötü niyetli bir sayfa için Ajax isteği yaparak bilgileri çalabilirsiniz.
- [**XSS**](../pentesting-web/xss-cross-site-scripting/index.html): Sayfada bir XSS açığı bulursanız, bunu bilgileri çalmak için kötüye kullanabilirsiniz.
- [**Danging Markup**](../pentesting-web/dangling-markup-html-scriptless-injection/index.html): XSS etiketlerini enjekte edemiyorsanız, yine de diğer normal HTML etiketlerini kullanarak bilgileri çalma şansınız olabilir.
- [**Clickjaking**](../pentesting-web/clickjacking.md): Bu saldırıya karşı bir koruma yoksa, kullanıcıyı hassas verileri göndermesi için kandırabilirsiniz (bir örnek [burada](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)).

{{#include ../banners/hacktricks-training.md}}
