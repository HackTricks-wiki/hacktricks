# Sub-GHz RF

{{#include ../../banners/hacktricks-training.md}}

## Garaj Kapıları

Garaj kapısı açıcıları genellikle 300-190 MHz aralığındaki frekanslarda çalışır; en yaygın frekanslar 300 MHz, 310 MHz, 315 MHz ve 390 MHz'tir. Bu frekans aralığı, diğer frekans bantlarına kıyasla daha az yoğun olduğu ve diğer cihazlardan kaynaklanan parazitlerle karşılaşma olasılığı daha düşük olduğu için garaj kapısı açıcılarında yaygın olarak kullanılır.

## Araç Kapıları

Çoğu araç anahtarlığı **315 MHz veya 433 MHz** frekanslarından birinde çalışır. Bunların ikisi de çeşitli uygulamalarda kullanılan radyo frekanslarıdır. İki frekans arasındaki temel fark, 433 MHz'in 315 MHz'den daha uzun bir menzile sahip olmasıdır. Bu da 433 MHz'i uzaktan anahtarsız giriş gibi daha uzun menzil gerektiren uygulamalar için daha uygun hale getirir.\
Avrupa'da 433.92MHz, ABD ve Japonya'da ise 315MHz yaygın olarak kullanılır.<sup>[[1]](#references)</sup>

## **Brute-force Attack**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

Her kodu 5 kez göndermek (alıcının kodu aldığından emin olmak için bu şekilde gönderilir) yerine yalnızca bir kez gönderirseniz süre 6 dakikaya düşer:

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

ve sinyaller arasındaki **2 ms'lik bekleme** süresini **kaldırırsanız süreyi 3 dakikaya düşürebilirsiniz.**

Ayrıca, tüm olası ikili sayıları bruteforce etmek için gönderilmesi gereken bit sayısını azaltan bir yöntem olan De Bruijn Sequence kullanıldığında bu **süre yalnızca 8 saniyeye düşer**:

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

Bu saldırının bir örneği [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame)<sup>[[3]](#references)</sup> adresinde uygulanmıştır.

**Preamble gerektirilmesi De Bruijn Sequence** optimizasyonunu önler ve **rolling codes bu saldırıyı engeller** (kodun bruteforce edilemeyecek kadar uzun olduğu varsayımıyla).

## Sub-GHz Attack

Bu sinyallere Flipper Zero ile saldırmak için şuraya bakın:


{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Rolling Codes Protection

Otomatik garaj kapısı açıcıları, garaj kapısını açıp kapatmak için genellikle kablosuz bir uzaktan kumanda kullanır. Uzaktan kumanda, garaj kapısı açıcısına bir **radyo frekansı (RF) sinyali** gönderir ve bu sinyal, kapıyı açmak veya kapatmak için motoru etkinleştirir.

Bir kişinin code grabber olarak bilinen bir cihazı kullanarak RF sinyalini yakalaması ve daha sonra kullanmak üzere kaydetmesi mümkündür. Bu, **replay attack** olarak bilinir. Bu tür bir saldırıyı önlemek için birçok modern garaj kapısı açıcısı, **rolling code** sistemi olarak bilinen daha güvenli bir encryption yöntemi kullanır.

**RF sinyali genellikle rolling code kullanılarak iletilir**; bu, kodun her kullanımda değiştiği anlamına gelir. Bu durum, bir kişinin sinyali **intercept etmesini** ve garaja **yetkisiz** erişim sağlamak için **kullanmasını** **zorlaştırır**.

Bir rolling code sisteminde uzaktan kumanda ve garaj kapısı açıcısı, uzaktan kumanda her kullanıldığında yeni bir kod **üreten ortak bir algorithm** kullanır. Garaj kapısı açıcısı yalnızca **doğru koda** yanıt verir; bu da bir kişinin yalnızca bir kodu yakalayarak garaja yetkisiz erişim sağlamasını çok daha zorlaştırır.

### **Missing Link Attack**

Temel olarak düğmeyi dinler ve uzaktan kumanda cihazın (örneğin aracın veya garajın) **menzili dışındayken sinyali yakalarsınız**. Ardından cihazın yanına gider ve **yakalanan kodu onu açmak için kullanırsınız**.<sup>[[2]](#references)</sup>

### Full Link Jamming Attack

Bir saldırgan, **alıcının kodu gerçekten ‘duyamaması’** için aracın veya alıcının yakınındaki sinyali **jam edebilir** ve bu gerçekleştiğinde, jamming işlemini durdurduktan sonra kodu kolayca **yakalayıp replay edebilir**.

Kurban bir noktada **aracı kilitlemek için anahtarları kullanır**, ancak saldırgan umarız kapıyı açmak için yeniden gönderebileceği yeterli sayıda "close door" kodunu kaydetmiş olur (aynı kodları açmak ve kapatmak için kullanan ancak iki komut için farklı frekansları dinleyen araçlar bulunduğundan **frekans değişikliği gerekebilir**).

> [!WARNING]
> **Jamming çalışır**, ancak fark edilmesi kolaydır; çünkü **aracı kilitleyen kişi kapıların kilitli olduğunu doğrulamak için kapıları basitçe test ederse** aracın kilidinin açıldığını fark eder. Ayrıca bu tür saldırılardan haberdarlarsa, ‘lock’ düğmesine bastıklarında kapıların kilitlenme **sesinin hiç çıkmadığını** veya aracın **ışıklarının yanıp sönmediğini** fark edebilirler.

### **Code Grabbing Attack ( aka ‘RollJam’ )**

Bu, daha **gizli bir Jamming tekniğidir**. Saldırgan sinyali jam eder; böylece kurban kapıyı kilitlemeye çalıştığında işlem gerçekleşmez, ancak saldırgan **bu kodu kaydeder**. Ardından kurban düğmeye basarak aracı **tekrar kilitlemeye çalışır** ve araç **bu ikinci kodu kaydeder**.\
Bunun hemen ardından **saldırgan ilk kodu gönderebilir** ve **araç kilitlenir** (kurban ikinci basışın aracı kilitlediğini düşünür). Daha sonra saldırgan, aracı açmak için **çalınan ikinci kodu gönderebilir** (**"close car" kodunun aracı açmak için de kullanılabildiği** varsayımıyla). Aynı kodları açmak ve kapatmak için kullanan ancak iki komut için farklı frekansları dinleyen araçlar bulunduğundan frekans değişikliği gerekebilir.<sup>[[3]](#references)[[2]](#references)</sup>

Saldırgan, **kendi alıcısını değil aracın alıcısını jam edebilir**; çünkü aracın alıcısı örneğin 1MHz geniş bant dinliyorsa saldırgan uzaktan kumandanın kullandığı tam frekansı değil, bu spektrumda **ona yakın bir frekansı jam eder**. Buna karşılık **saldırganın alıcısı daha dar bir aralıkta dinleme yapar** ve jam sinyali olmadan uzaktan kumandanın sinyalini dinleyebilir.

> [!WARNING]
> Spesifikasyonlarda görülen diğer uygulamalar, **rolling code'un gönderilen toplam kodun bir bölümü** olduğunu gösterir. Örneğin gönderilen kod, ilk **12 biti rolling code**, sonraki **8 biti komut** (lock veya unlock gibi) ve son 4 biti **checksum** olan **24 bitlik bir anahtar** olabilir. Bu türü uygulayan araçlar da doğal olarak savunmasızdır; çünkü saldırganın her iki frekansta da **herhangi bir rolling code'u kullanabilmek** için yalnızca rolling code bölümünü değiştirmesi yeterlidir.

> [!CAUTION]
> Kurban saldırgan ilk kodu gönderirken üçüncü bir kod gönderirse ilk ve ikinci kodun geçersiz hale geleceğini unutmayın.

### Alarm Sounding Jamming Attack

Bir araçta kurulu aftermarket bir rolling code sistemine karşı yapılan testlerde, **aynı kodun iki kez gönderilmesi** alarmı ve immobiliser'ı **hemen etkinleştirdi** ve benzersiz bir **denial of service** fırsatı sağladı. İronik olarak **alarmı** ve immobiliser'ı **devre dışı bırakmanın yolu** uzaktan kumandaya **basmaktı**; bu da saldırgana sürekli olarak **DoS attack gerçekleştirme** imkânı sağladı. Alternatif olarak bu saldırı, kurban saldırıyı mümkün olduğunca çabuk durdurmak isteyeceğinden, **daha fazla kod elde etmek için önceki saldırıyla birleştirilebilir**.<sup>[[2]](#references)</sup>

## References

- [1] [What Radio Frequency Does Car Key Fobs Run On?](https://www.americanradioarchives.com/what-radio-frequency-do-car-key-fobs-run-on/)
- [2] [Bypassing Rolling Code Systems](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [3] [Drive It Like You Hacked It (DEF CON 23) - OpenSesame / RollJam](https://samy.pl/defcon2015/)
- [4] [How to hack a car (RollJam recreation)](https://hackaday.io/project/164566-how-to-hack-a-car/details)

{{#include ../../banners/hacktricks-training.md}}
