# Other Web Tricks

{{#include ../banners/hacktricks-training.md}}

### Host header

Arka uç, bazı işlemleri gerçekleştirmek için **Host header** değerine birkaç kez güvenebilir. Örneğin, bu değeri **password reset göndermek için kullanılacak domain** olarak kullanabilir. Bu nedenle, password reset bağlantısını içeren bir e-posta aldığınızda kullanılan domain, Host header'a yazdığınız domain olur. Ardından diğer kullanıcılar için password reset isteğinde bulunabilir ve onların password reset kodlarını çalmak için domain'i sizin kontrolünüzde olan bir domain ile değiştirebilirsiniz. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).<sup>[[1]](#references)</sup>

> [!WARNING]
> Token'ı almak için kullanıcının password reset bağlantısına tıklamasını beklemeniz gerekmeyebilir; çünkü **spam filtreleri veya diğer aracı cihazlar/botlar, bağlantıyı analiz etmek için bağlantıya tıklayabilir**.

### Session booleans

Bazı durumlarda bir doğrulamayı başarıyla tamamladığınızda arka uç, **session'ınıza ait bir security attribute'a değeri "True" olan bir boolean ekler**. Ardından farklı bir endpoint, bu kontrolü başarıyla geçip geçmediğinizi öğrenir.\
Ancak **kontrolü geçerseniz** ve session'ınıza security attribute içinde bu "True" değeri atanırsa, **aynı attribute'a bağlı olan** ancak erişim **izninizin olmaması gereken** diğer kaynaklara **erişmeyi** deneyebilirsiniz. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).<sup>[[2]](#references)</sup>

### Register functionality

Zaten mevcut olan bir kullanıcı olarak register olmaya çalışın. Ayrıca eşdeğer karakterleri (noktalar, çok sayıda boşluk ve Unicode) kullanmayı deneyin.

### Takeover emails

Bir email register edin, doğrulamadan önce email'i değiştirin; ardından yeni confirmation email ilk register edilen email'e gönderilirse herhangi bir email'i takeover edebilirsiniz. Veya ilk email'i doğrulayarak ikinci email'i etkinleştirebiliyorsanız herhangi bir account'u da takeover edebilirsiniz.

### Access Internal servicedesk of companies using atlassian


{{#ref}}
https://yourcompanyname.atlassian.net/servicedesk/customer/user/login
{{#endref}}

### TRACE method

Developer'lar production ortamında çeşitli debugging seçeneklerini devre dışı bırakmayı unutabilir. Örneğin, HTTP `TRACE` method'u diagnostic amaçlar için tasarlanmıştır. Etkinleştirilmişse web server, `TRACE` method'unu kullanan isteklere, alınan isteği response içinde aynen yansıtarak yanıt verir. Bu davranış çoğu zaman zararsızdır, ancak bazen reverse proxy'ler tarafından isteklere eklenebilecek dahili authentication header'larının adları gibi bilgilerin açığa çıkmasına neden olur.![Post görseli](https://miro.medium.com/max/60/1*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Post görseli](https://miro.medium.com/max/1330/1*wDFRADTOd9Tj63xucenvAA.png)

## References

- [1] [Host Header Injection ile herhangi bir kullanıcının hesabını nasıl takeover edebildim](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2)
- [2] [Daha az bilinen bir attack vector: Second Order IDOR attacks](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a)

{{#include ../banners/hacktricks-training.md}}
