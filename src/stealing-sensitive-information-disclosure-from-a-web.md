# Web'den Hassas Bilgilerin Çalınması

{{#include ./banners/hacktricks-training.md}}

Eğer bir noktada **oturumunuza dayalı hassas bilgileri sunan bir web sayfası bulursanız**: Belki çerezleri yansıtıyordur, ya da kredi kartı detaylarını veya başka herhangi bir hassas bilgiyi yazdırıyordur, bunu çalmaya çalışabilirsiniz.\
Burada bunu başarmak için deneyebileceğiniz ana yolları sunuyorum:

- [**CORS bypass**](pentesting-web/cors-bypass.md): CORS başlıklarını aşabiliyorsanız, kötü niyetli bir sayfa için Ajax isteği yaparak bilgileri çalabilirsiniz.
- [**XSS**](pentesting-web/xss-cross-site-scripting/): Sayfada bir XSS açığı bulursanız, bunu bilgileri çalmak için kötüye kullanabilirsiniz.
- [**Danging Markup**](pentesting-web/dangling-markup-html-scriptless-injection/): XSS etiketlerini enjekte edemiyorsanız bile, diğer normal HTML etiketlerini kullanarak bilgileri çalmaya devam edebilirsiniz.
- [**Clickjaking**](pentesting-web/clickjacking.md): Bu saldırıya karşı bir koruma yoksa, kullanıcıyı hassas verileri göndermesi için kandırabilirsiniz (bir örnek [burada](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)).

{{#include ./banners/hacktricks-training.md}}
