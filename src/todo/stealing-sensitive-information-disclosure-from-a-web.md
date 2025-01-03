# Web'den Hassas Bilgi Sızdırma

{{#include ../banners/hacktricks-training.md}}

Eğer bir noktada **oturumunuza dayalı hassas bilgileri sunan bir web sayfası bulursanız**: Belki çerezleri yansıtıyordur, ya da kredi kartı bilgilerini veya başka hassas bilgileri yazdırıyordur, bunu çalmaya çalışabilirsiniz.\
İşte bunu başarmak için deneyebileceğiniz ana yollar:

- [**CORS bypass**](../pentesting-web/cors-bypass.md): CORS başlıklarını aşabilirseniz, kötü niyetli bir sayfa için Ajax isteği yaparak bilgileri çalabilirsiniz.
- [**XSS**](../pentesting-web/xss-cross-site-scripting/): Sayfada bir XSS açığı bulursanız, bunu kullanarak bilgileri çalabilirsiniz.
- [**Danging Markup**](../pentesting-web/dangling-markup-html-scriptless-injection/): XSS etiketlerini enjekte edemiyorsanız, yine de diğer normal HTML etiketlerini kullanarak bilgileri çalabilirsiniz.
- [**Clickjaking**](../pentesting-web/clickjacking.md): Bu saldırıya karşı bir koruma yoksa, kullanıcıyı hassas verileri göndermesi için kandırabilirsiniz (bir örnek [burada](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)).

{{#include ../banners/hacktricks-training.md}}
