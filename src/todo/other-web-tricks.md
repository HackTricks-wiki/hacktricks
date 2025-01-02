# Diğer Web Hileleri

{{#include ../banners/hacktricks-training.md}}

### Host başlığı

Birçok kez arka uç, bazı işlemleri gerçekleştirmek için **Host başlığına** güvenir. Örneğin, bu değeri **şifre sıfırlama için kullanılacak alan adı** olarak kullanabilir. Yani, şifrenizi sıfırlamak için bir bağlantı içeren bir e-posta aldığınızda, kullanılan alan adı Host başlığında belirttiğiniz alandır. Ardından, diğer kullanıcıların şifre sıfırlama taleplerini yapabilir ve alan adını kontrolünüzde olan bir alan adıyla değiştirerek şifre sıfırlama kodlarını çalabilirsiniz. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).

> [!WARNING]
> Kullanıcının şifre sıfırlama bağlantısına tıklamasını beklemenize gerek kalmadan token'ı alabileceğinizi unutmayın, çünkü belki de **spam filtreleri veya diğer ara cihazlar/botlar bunu analiz etmek için tıklayacaktır**.

### Oturum boolean'ları

Bazen bazı doğrulamaları doğru bir şekilde tamamladığınızda arka uç, **oturumunuza bir güvenlik niteliğine "True" değeriyle bir boolean ekler**. Ardından, farklı bir uç nokta bu kontrolü başarıyla geçip geçmediğinizi bilecektir.\
Ancak, eğer **kontrolden geçerseniz** ve oturumunuza güvenlik niteliğinde "True" değeri verilirse, **erişim izniniz olmaması gereken** ancak **aynı niteliğe bağlı olan diğer kaynaklara erişmeyi** deneyebilirsiniz. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).

### Kayıt işlevselliği

Zaten mevcut bir kullanıcı olarak kaydolmayı deneyin. Eşdeğer karakterler (nokta, çok sayıda boşluk ve Unicode) kullanmayı da deneyin.

### E-postaları ele geçirme

Bir e-posta kaydedin, onaylamadan önce e-postayı değiştirin, ardından, yeni onay e-postası ilk kaydedilen e-postaya gönderilirse, herhangi bir e-postayı ele geçirebilirsiniz. Ya da ikinci e-postayı birincisini onaylayacak şekilde etkinleştirebilirseniz, herhangi bir hesabı da ele geçirebilirsiniz.

### Atlassian kullanarak şirketlerin İç Servis Masasına Erişim

{% embed url="https://yourcompanyname.atlassian.net/servicedesk/customer/user/login" %}

### TRACE yöntemi

Geliştiriciler, üretim ortamında çeşitli hata ayıklama seçeneklerini devre dışı bırakmayı unutabilir. Örneğin, HTTP `TRACE` yöntemi tanısal amaçlar için tasarlanmıştır. Eğer etkinse, web sunucusu `TRACE` yöntemini kullanan isteklere, alınan isteği yanıtında yankılayarak yanıt verir. Bu davranış genellikle zararsızdır, ancak bazen, ters proxyler tarafından isteklere eklenebilecek dahili kimlik doğrulama başlıklarının adları gibi bilgi ifşasına yol açabilir.![Image for post](https://miro.medium.com/max/60/1*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Image for post](https://miro.medium.com/max/1330/1*wDFRADTOd9Tj63xucenvAA.png)

{{#include ../banners/hacktricks-training.md}}
