# Sub-GHz RF

{{#include ../../banners/hacktricks-training.md}}

## Garaj Kapıları

Garaj kapısı açıcıları genellikle 300-190 MHz aralığında çalışır ve en yaygın frekanslar 300 MHz, 310 MHz, 315 MHz ve 390 MHz'dir. Bu frekans aralığı, diğer frekans bantlarına göre daha az kalabalık olduğu ve diğer cihazlardan gelen parazitlerden daha az etkilenme olasılığı olduğu için garaj kapısı açıcıları için yaygın olarak kullanılır.

## Araç Kapıları

Çoğu araç anahtar uzaktan kumandası ya **315 MHz ya da 433 MHz** frekansında çalışır. Bu frekanslar her ikisi de radyo frekanslarıdır ve çeşitli uygulamalarda kullanılır. İki frekans arasındaki ana fark, 433 MHz'nin 315 MHz'den daha uzun bir menzil sunmasıdır. Bu, 433 MHz'nin uzaktan anahtarsız giriş gibi daha uzun menzil gerektiren uygulamalar için daha iyi olduğu anlamına gelir.\
Avrupa'da 433.92MHz yaygın olarak kullanılırken, ABD ve Japonya'da 315MHz kullanılmaktadır.

## **Kaba Güç Saldırısı**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

Her kodu 5 kez göndermek yerine (alıcıya ulaşmasını sağlamak için böyle gönderilir) sadece bir kez gönderirseniz, süre 6 dakikaya düşer:

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

Ve eğer **sinaller arasındaki 2 ms bekleme** süresini **kaldırırsanız, süreyi 3 dakikaya düşürebilirsiniz.**

Ayrıca, De Bruijn Dizisi kullanarak (tüm potansiyel ikili sayıları kaba kuvvetle göndermek için gereken bit sayısını azaltmanın bir yolu) bu **süre sadece 8 saniyeye düşer**:

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

Bu saldırının bir örneği [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame) adresinde uygulanmıştır.

**Bir önsöz gerektirmek, De Bruijn Dizisi** optimizasyonunu engelleyecek ve **dönüşümlü kodlar bu saldırıyı önleyecektir** (kodun kaba kuvvetle kırılmayacak kadar uzun olduğunu varsayarsak).

## Sub-GHz Saldırısı

Bu sinyalleri Flipper Zero ile saldırmak için kontrol edin:

{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Dönüşümlü Kod Koruması

Otomatik garaj kapısı açıcıları genellikle garaj kapısını açmak ve kapatmak için kablosuz bir uzaktan kumanda kullanır. Uzaktan kumanda, garaj kapısı açıcıya **bir radyo frekansı (RF) sinyali** gönderir ve bu da motoru kapıyı açmak veya kapatmak için etkinleştirir.

Birinin, RF sinyalini kesmek ve daha sonra kullanmak üzere kaydetmek için bir kod yakalayıcı cihaz kullanması mümkündür. Bu, **tekrar saldırısı** olarak bilinir. Bu tür bir saldırıyı önlemek için, birçok modern garaj kapısı açıcı daha güvenli bir şifreleme yöntemi olan **dönüşümlü kod** sistemini kullanır.

**RF sinyali genellikle dönüşümlü kod kullanılarak iletilir**, bu da kodun her kullanımda değiştiği anlamına gelir. Bu, birinin sinyali **yakalamayı** ve garaja **yetkisiz** erişim sağlamayı **zorlaştırır**.

Dönüşümlü kod sisteminde, uzaktan kumanda ve garaj kapısı açıcı, uzaktan kumanda her kullanıldığında **yeni bir kod üreten** bir **paylaşılan algoritmaya** sahiptir. Garaj kapısı açıcı yalnızca **doğru koda** yanıt verecek, bu da birinin yalnızca bir kodu yakalayarak garaja yetkisiz erişim sağlamasını çok daha zor hale getirecektir.

### **Eksik Bağlantı Saldırısı**

Temelde, düğmeyi dinlersiniz ve **uzaktan kumanda cihazın menzilinden çıktığında sinyali yakalarsınız** (örneğin, araç veya garaj). Daha sonra cihaza geçer ve **yakalanan kodu kullanarak açarsınız**.

### Tam Bağlantı Boğma Saldırısı

Bir saldırgan, **sinyali araç veya alıcı yakınında boğabilir** böylece **alıcı kodu gerçekten ‘duyamaz’** ve bu gerçekleştiğinde, boğmayı durdurduğunuzda kodu **yakalamak ve tekrar göndermek** için basitçe yapabilirsiniz.

Kurban bir noktada **anahtarları aracı kilitlemek için kullanacaktır**, ancak o zaman saldırgan **yeterince "kapıyı kapat" kodunu kaydetmiş olacaktır** ki umarım bu kodlar kapıyı açmak için yeniden gönderilebilir (bir **frekans değişikliği gerekebilir** çünkü bazı araçlar kapıyı açmak ve kapatmak için aynı kodları kullanır ama her iki komutu farklı frekanslarda dinler).

> [!WARNING]
> **Boğma çalışır**, ancak dikkat çekicidir çünkü **aracı kilitleyen kişi kapıları test ederse** kilitli olduklarından emin olmak için arabanın kilitli olmadığını fark eder. Ayrıca, böyle saldırılardan haberdar iseler, kapıların kilit **sesini** yapmadığını veya aracın **ışıklarının** ‘kilitle’ düğmesine bastıklarında hiç yanmadığını dinleyebilirler.

### **Kod Yakalama Saldırısı (aka ‘RollJam’)**

Bu daha **gizli bir Boğma tekniğidir**. Saldırgan sinyali boğar, böylece kurban kapıyı kilitlemeye çalıştığında çalışmaz, ancak saldırgan bu kodu **kaydeder**. Daha sonra, kurban düğmeye basarak aracı tekrar kilitlemeye çalışır ve araç **bu ikinci kodu kaydeder**.\
Bundan hemen sonra **saldırgan ilk kodu gönderebilir** ve **araç kilitlenecektir** (kurban ikinci basışın kapattığını düşünecektir). Ardından, saldırgan **ç stolen kodu aracı açmak için gönderebilir** (bir **"aracı kapat" kodunun da açmak için kullanılabileceğini varsayarsak**). Bir frekans değişikliği gerekebilir (çünkü bazı araçlar kapıyı açmak ve kapatmak için aynı kodları kullanır ama her iki komutu farklı frekanslarda dinler).

Saldırgan **aracın alıcısını boğabilir ve kendi alıcısını boğmaz** çünkü eğer aracın alıcısı örneğin 1MHz geniş bantta dinliyorsa, saldırgan uzaktan kumandanın kullandığı tam frekansı **boğmaz** ama **o spektrumda yakın bir frekansı boğar** ve **saldırganın alıcısı daha küçük bir aralıkta dinleyecektir** böylece uzaktan kumanda sinyalini **boğma sinyali olmadan** dinleyebilir.

> [!WARNING]
> Diğer uygulamalarda görülen spesifikasyonlar, **dönüşümlü kodun toplam gönderilen kodun bir kısmı** olduğunu göstermektedir. Yani gönderilen kod bir **24 bit anahtardır** burada ilk **12 dönüşümlü kod**, **ikinci 8 komut** (kilitleme veya açma gibi) ve son 4 **kontrol toplamıdır**. Bu tür bir uygulama yapan araçlar da doğal olarak savunmasızdır çünkü saldırgan yalnızca dönüşümlü kod segmentini değiştirmelidir ki **her iki frekansta da herhangi bir dönüşümlü kodu kullanabilsin**.

> [!CAUTION]
> Kurban, saldırgan ilk kodu gönderirken üçüncü bir kod gönderirse, birinci ve ikinci kod geçersiz hale gelecektir.

### Alarm Seslendirme Boğma Saldırısı

Bir araçta kurulu bir aftermarket dönüşümlü kod sistemine karşı test yaparken, **aynı kodu iki kez göndermek** hemen **alarmı** ve immobilizeri etkinleştirdi ve benzersiz bir **hizmet reddi** fırsatı sağladı. Ironik olarak, **alarmı** ve immobilizeri **devre dışı bırakmanın** yolu **uzaktan kumandayı** **basmak** oldu, bu da bir saldırgana **sürekli DoS saldırısı** yapma yeteneği sağladı. Ya da bu saldırıyı **önceki saldırı ile birleştirerek daha fazla kod elde edebilir** çünkü kurban saldırıyı bir an önce durdurmak isteyecektir.

## Referanslar

- [https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/](https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/)
- [https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [https://samy.pl/defcon2015/](https://samy.pl/defcon2015/)
- [https://hackaday.io/project/164566-how-to-hack-a-car/details](https://hackaday.io/project/164566-how-to-hack-a-car/details)

{{#include ../../banners/hacktricks-training.md}}
