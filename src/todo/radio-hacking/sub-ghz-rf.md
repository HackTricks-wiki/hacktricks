# Sub-GHz RF

{{#include ../../banners/hacktricks-training.md}}

## Garaj Kapıları

Garaj kapısı açıcıları genellikle 300-190 MHz aralığında çalışır ve en yaygın frekanslar 300 MHz, 310 MHz, 315 MHz ve 390 MHz'dir. Bu frekans aralığı, diğer frekans bantlarına göre daha az kalabalık olduğu ve diğer cihazlardan gelen parazit yaşama olasılığının daha düşük olması nedeniyle garaj kapısı açıcıları için yaygın olarak kullanılır.

## Araç Kapıları

Çoğu araç anahtar uzaktan kumandası ya **315 MHz ya da 433 MHz** üzerinde çalışır. Bu ikisi de radyo frekanslarıdır ve çeşitli uygulamalarda kullanılır. İki frekans arasındaki ana fark, 433 MHz'nin 315 MHz'den daha uzun bir menzile sahip olmasıdır. Bu, 433 MHz'nin uzaktan anahtarsız giriş gibi daha uzun menzil gerektiren uygulamalar için daha iyi olduğu anlamına gelir.\
Avrupa'da 433.92MHz yaygın olarak kullanılırken, ABD ve Japonya'da 315MHz kullanılmaktadır.

## **Kaba Güç Saldırısı**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

Her kodu 5 kez göndermek yerine (alıcıya ulaşmasını sağlamak için böyle gönderilir) sadece bir kez gönderirseniz, süre 6 dakikaya düşer:

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

Ve eğer sinyaller arasındaki 2 ms bekleme süresini **kaldırırsanız**, süreyi **3 dakikaya düşürebilirsiniz.**

Ayrıca, De Bruijn Dizisi kullanarak (tüm potansiyel ikili sayıların gönderilmesi için gereken bit sayısını azaltmanın bir yolu) bu **süre sadece 8 saniyeye düşer**:

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

Bu saldırının bir örneği [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame) adresinde uygulanmıştır.

**Bir önsöz gerektirmek, De Bruijn Dizisi** optimizasyonunu engelleyecek ve **dönüşümlü kodlar bu saldırıyı önleyecektir** (kodun bruteforce edilemeyecek kadar uzun olduğunu varsayarsak).

## Sub-GHz Saldırısı

Bu sinyalleri Flipper Zero ile saldırmak için kontrol edin:


{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Dönüşümlü Kod Koruması

Otomatik garaj kapısı açıcıları genellikle garaj kapısını açmak ve kapatmak için kablosuz bir uzaktan kumanda kullanır. Uzaktan kumanda, garaj kapısı açıcıya **bir radyo frekansı (RF) sinyali** gönderir ve bu, motoru kapıyı açmak veya kapatmak için etkinleştirir.

Birinin, RF sinyalini kesmek ve daha sonra kullanmak üzere kaydetmek için bir kod yakalayıcı cihazı kullanması mümkündür. Bu, **tekrar saldırısı** olarak bilinir. Bu tür bir saldırıyı önlemek için, birçok modern garaj kapısı açıcı daha güvenli bir şifreleme yöntemi olan **dönüşümlü kod** sistemini kullanır.

**RF sinyali genellikle bir dönüşümlü kod kullanılarak iletilir**, bu da kodun her kullanımda değiştiği anlamına gelir. Bu, birinin sinyali **kesmesini** ve garaja **yetkisiz** erişim sağlamasını **zorlaştırır**.

Dönüşümlü kod sisteminde, uzaktan kumanda ve garaj kapısı açıcı, uzaktan kumanda her kullanıldığında **yeni bir kod üreten** bir **paylaşılan algoritmaya** sahiptir. Garaj kapısı açıcı yalnızca **doğru koda** yanıt verecektir, bu da birinin yalnızca bir kodu yakalayarak garaja yetkisiz erişim sağlamasını çok daha zor hale getirir.

### **Eksik Bağlantı Saldırısı**

Temelde, düğmeyi dinlersiniz ve **uzaktan kumanda cihazın menzilinden çıktığında sinyali yakalarsınız** (örneğin, araba veya garaj). Daha sonra cihaza geçer ve **yakalanan kodu kullanarak açarsınız**.

### Tam Bağlantı Engelleme Saldırısı

Bir saldırgan, **sinyali araç veya alıcı yakınında engelleyebilir** böylece **alıcı kodu gerçekten ‘duyamaz** ve bu olduğunda, engellemeyi durdurduğunuzda kodu **yakalayabilir ve tekrar oynatabilirsiniz**.

Kurban bir noktada **anahtarları kullanarak aracı kilitleyecektir**, ancak saldırgan **yeterince "kapıyı kapat" kodunu kaydetmiş olacaktır** ki umarım kapıyı açmak için yeniden gönderilebilir (bir **frekans değişikliği gerekebilir** çünkü bazı araçlar kapatmak ve açmak için aynı kodları kullanır ama farklı frekanslarda her iki komutu dinler).

> [!WARNING]
> **Engelleme çalışır**, ancak dikkat çekicidir çünkü **aracını kilitleyen kişi kapıları test ederse** kilitli olduklarından emin olmak için aracın kilitli olmadığını fark eder. Ayrıca, böyle saldırılardan haberdar iseler, kapıların kilit **sesini** yapmadığını veya aracın **ışıklarının** ‘kilitle’ düğmesine bastıklarında hiç yanmadığını dinleyebilirler.

### **Kod Yakalama Saldırısı (aka ‘RollJam’)**

Bu daha **gizli bir Engelleme tekniğidir**. Saldırgan sinyali engeller, böylece kurban kapıyı kilitlemeye çalıştığında çalışmaz, ancak saldırgan bu kodu **kaydeder**. Daha sonra, kurban düğmeye basarak aracı **tekrar kilitlemeye çalışır** ve araç **bu ikinci kodu kaydeder**.\
Bundan hemen sonra **saldırgan ilk kodu gönderebilir** ve **araç kilitlenecektir** (kurban ikinci basışın kapattığını düşünecektir). Ardından, saldırgan **çalıntı ikinci kodu aracı açmak için gönderebilir** (bir **"kapalı araç" kodunun da açmak için kullanılabileceğini varsayarsak**). Bir frekans değişikliği gerekebilir (çünkü bazı araçlar açmak ve kapatmak için aynı kodları kullanır ama her iki komutu farklı frekanslarda dinler).

Saldırgan, **aracın alıcısını engelleyebilir ve kendi alıcısını değil** çünkü eğer araç alıcısı örneğin 1MHz geniş bantta dinliyorsa, saldırgan uzaktan kumandanın kullandığı tam frekansı **engellemeyecek** ama **o spektrumda yakın bir frekansta** engelleme yaparken **saldırganın alıcısı daha küçük bir aralıkta dinleyecektir** ve uzaktan kumanda sinyalini **engelleme sinyali olmadan** dinleyebilir.

> [!WARNING]
> Spesifikasyonlarda görülen diğer uygulamalar, **dönüşümlü kodun gönderilen toplam kodun bir kısmı** olduğunu göstermektedir. Yani gönderilen kod bir **24 bit anahtardır**; ilk **12'si dönüşümlü kod**, **ikinci 8'i komut** (kilitleme veya açma gibi) ve son 4'ü **kontrol toplamıdır**. Bu tür bir uygulama yapan araçlar da doğal olarak savunmasızdır çünkü saldırgan yalnızca dönüşümlü kod segmentini değiştirmek zorundadır ve böylece **her iki frekansta da herhangi bir dönüşümlü kodu kullanabilir**.

> [!CAUTION]
> Kurban, saldırgan ilk kodu gönderirken üçüncü bir kod gönderirse, birinci ve ikinci kod geçersiz hale gelecektir.

### Alarm Sesini Engelleme Saldırısı

Bir araçta kurulu bir aftermarket dönüşümlü kod sistemine karşı test yaparken, **aynı kodu iki kez göndermek** hemen **alarmı** ve immobilizeri etkinleştirdi ve benzersiz bir **hizmet reddi** fırsatı sağladı. Ironik olarak, **alarmı** ve immobilizeri **devre dışı bırakmanın** yolu **uzaktan kumandayı** **basmak** oldu, bu da bir saldırgana **sürekli DoS saldırısı** gerçekleştirme yeteneği sağladı. Ya da bu saldırıyı **önceki saldırı ile birleştirerek daha fazla kod elde edebilir** çünkü kurban saldırıyı bir an önce durdurmak isteyecektir.

## Referanslar

- [https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/](https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/)
- [https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [https://samy.pl/defcon2015/](https://samy.pl/defcon2015/)
- [https://hackaday.io/project/164566-how-to-hack-a-car/details](https://hackaday.io/project/164566-how-to-hack-a-car/details)

{{#include ../../banners/hacktricks-training.md}}
