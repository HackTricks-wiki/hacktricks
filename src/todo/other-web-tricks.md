# Diğer Web Trick'leri

{{#include ../banners/hacktricks-training.md}}

### Host header

Back-end, bazı işlemleri gerçekleştirmek için **Host header**'a güvenir. Örneğin değerini **password reset göndermek için kullanılacak domain** olarak kullanabilir. Bu nedenle password reset bağlantısını içeren bir email aldığınızda, kullanılan domain, Host header'a koyduğunuz domaindir. Ardından diğer kullanıcılar için password reset isteğinde bulunabilir ve onların password reset kodlarını çalmak için domain'i sizin kontrolünüzde olan bir domain ile değiştirebilirsiniz. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).<sup>[[1]](#references)</sup>

> [!WARNING]
> Kullanıcının password reset bağlantısına tıklamasını beklemenize bile gerek olmayabileceğini unutmayın; çünkü **spam filtreleri veya diğer aracı cihazlar/botlar bağlantıyı analiz etmek için bağlantıya tıklayabilir**.

### Session boolean'ları

Bazı durumlarda bir doğrulamayı başarıyla tamamladığınızda back-end, **session'ınızın bir security attribute'una değeri "True" olan bir boolean ekler**. Ardından farklı bir endpoint, bu kontrolü başarıyla geçip geçmediğinizi öğrenir.\
Ancak **kontrolü geçerseniz** ve session'ınıza security attribute içinde bu "True" değeri verilirse, **aynı attribute'a bağlı olan**, ancak erişim **yetkinizin olmaması gereken** diğer kaynaklara **erişmeyi** deneyebilirsiniz. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).<sup>[[2]](#references)</sup>

### Register functionality

Zaten mevcut olan bir kullanıcı olarak register olmayı deneyin. Ayrıca eşdeğer karakterleri (noktalar, çok sayıda boşluk ve Unicode) kullanmayı deneyin.

### Email takeover'ları

Bir email register edin, doğrulamadan önce email'i değiştirin; ardından yeni confirmation email'i ilk register edilen email'e gönderilirse herhangi bir email'i takeover edebilirsiniz. Ya da ikinci email'i ilkini doğrulayarak etkinleştirebiliyorsanız, herhangi bir hesabı da takeover edebilirsiniz.

### atlassian kullanarak şirketlerin internal servicedesk'ine erişim


{{#ref}}
https://yourcompanyname.atlassian.net/servicedesk/customer/user/login
{{#endref}}

### TRACE methodu

Developer'lar production environment'ında çeşitli debugging seçeneklerini devre dışı bırakmayı unutabilir. Örneğin HTTP `TRACE` methodu diagnostic amaçlar için tasarlanmıştır. Etkinleştirilmişse web server, `TRACE` methodunu kullanan isteklere, alınan isteği response içinde tam olarak echo ederek yanıt verir. Bu davranış çoğunlukla zararsızdır, ancak bazen reverse proxy'ler tarafından isteklere eklenebilen internal authentication header'larının adı gibi bilgi disclosure'larına yol açabilir.![Image for post](https://miro.medium.com/max/60/1*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Image for post](https://miro.medium.com/max/1330/1*wDFRADTOd9Tj63xucenvAA.png)

## References

- [1] [How I was able to take over any user's account with Host Header injection](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2)
- [2] [A less known attack vector: Second order IDOR attacks](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a)

{{#include ../banners/hacktricks-training.md}}
