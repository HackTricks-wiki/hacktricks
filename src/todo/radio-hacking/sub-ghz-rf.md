# Sub-GHz RF

{{#include ../../banners/hacktricks-training.md}}

## Garaj Kapıları

Garaj kapısı açıcıları genellikle 300-190 MHz aralığındaki frekanslarda çalışır; en yaygın frekanslar 300 MHz, 310 MHz, 315 MHz ve 390 MHz'tir. Bu frekans aralığı, diğer frekans bantlarına kıyasla daha az yoğun olduğu ve diğer cihazlardan kaynaklanan parazitlerle karşılaşma olasılığı daha düşük olduğu için garaj kapısı açıcılarında yaygın olarak kullanılır.

## Araç Kapıları

Çoğu araç anahtarlığı **315 MHz veya 433 MHz** frekanslarından birinde çalışır. Bunların ikisi de radyo frekansıdır ve çeşitli farklı uygulamalarda kullanılır. İki frekans arasındaki temel fark, 433 MHz'in 315 MHz'e göre daha uzun bir menzile sahip olmasıdır. Bu, 433 MHz'i uzaktan anahtarsız giriş gibi daha uzun menzil gerektiren uygulamalar için daha uygun hale getirir.\
Avrupa'da 433.92MHz, ABD ve Japonya'da ise 315MHz yaygın olarak kullanılır.<sup>[[1]](#references)</sup>

## **Brute-force Attack**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

Her kodu 5 kez göndermek yerine (alıcının kodu aldığından emin olmak için bu şekilde gönderilir) yalnızca bir kez gönderirseniz süre 6 dakikaya düşer:

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

ve sinyaller arasındaki **2 ms'lik bekleme** süresini **kaldırırsanız süreyi 3 dakikaya indirebilirsiniz.**

Ayrıca De Bruijn Sequence kullanarak (tüm olası binary sayıları brute-force etmek için gönderilmesi gereken bit sayısını azaltan bir yöntem) bu **süre yalnızca 8 saniyeye düşer**:<sup>[[3]](#references)</sup>

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

Bu saldırının bir örneği [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame) adresinde uygulanmıştır.

**Bir preamble gerektirilmesi De Bruijn Sequence** optimizasyonunu engeller ve **rolling codes bu saldırıyı önler** (kodun brute-force edilemeyecek kadar uzun olduğu varsayılarak).

## Sub-GHz Attack

Bu sinyallere Flipper Zero ile saldırmak için şurayı kontrol edin:


{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Rolling Codes Protection

Otomatik garaj kapısı açıcıları, garaj kapısını açmak ve kapatmak için genellikle kablosuz bir uzaktan kumanda kullanır. Uzaktan kumanda, garaj kapısı açıcıya **bir radio frequency (RF) signal** gönderir ve bu sinyal kapıyı açmak veya kapatmak için motoru etkinleştirir.

Bir kişinin code grabber olarak bilinen bir cihaz kullanarak RF sinyalini yakalaması ve daha sonra kullanmak üzere kaydetmesi mümkündür. Bu işlem **replay attack** olarak bilinir. Bu tür saldırıları önlemek için birçok modern garaj kapısı açıcı, **rolling code** sistemi olarak bilinen daha güvenli bir encryption yöntemi kullanır.

**RF signal genellikle rolling code kullanılarak iletilir**; bu, kodun her kullanımda değiştiği anlamına gelir. Bu durum, bir kişinin sinyali **intercept** etmesini ve garaja **unauthorised** erişim sağlamak için **kullanmasını** **zorlaştırır**.

Bir rolling code sisteminde uzaktan kumanda ve garaj kapısı açıcı, kumanda her kullanıldığında yeni bir kod **üreten ortak bir algorithm** kullanır. Garaj kapısı açıcı yalnızca **doğru code**'a yanıt verir; bu da bir kişinin yalnızca bir kodu yakalayarak garaja yetkisiz erişim sağlamasını çok daha zorlaştırır.

### **Missing Link Attack**

Temel olarak düğmeyi dinler ve kumanda cihazın (örneğin araç veya garaj) **menzili dışındayken sinyali yakalarsınız**. Daha sonra cihaza gider ve **yakalanan kodu kullanarak cihazı açarsınız**.<sup>[[2]](#references)</sup>

### Full Link Jamming Attack

Bir attacker, **receiver**'ın yakınındaki sinyali **jam** edebilir; böylece **receiver kodu gerçekten ‘duyamaz’**. Bu gerçekleştiğinde, jamming'i durdurduktan sonra kodu kolayca **capture and replay** edebilirsiniz.<sup>[[2]](#references)</sup>

Kurban bir noktada **aracı kilitlemek için anahtarları kullanır**, ancak saldırı **yeterli sayıda "close door" kodunu kaydetmiş** olur; böylece bu kodlar kapıyı açmak için yeniden gönderilebilir (aynı kodları açma ve kapatma için kullanan, ancak her iki komutu farklı frekanslarda dinleyen araçlar olduğundan **frekans değişikliği gerekebilir**).

> [!WARNING]
> **Jamming çalışır**, ancak fark edilebilir; çünkü **aracı kilitleyen kişi kapıların kilitli olduğundan emin olmak için kapıları kontrol ederse** aracın kilidinin açılmış olduğunu fark eder. Ayrıca bu tür saldırıların farkında olan kişiler, ‘lock’ düğmesine bastıklarında kapıların hiçbir zaman kilitlenme **sesini çıkarmadığını** veya aracın **ışıklarının yanıp sönmediğini** de fark edebilir.

### **Code Grabbing Attack ( aka ‘RollJam’ )**

Bu, daha **gizli bir Jamming tekniğidir**. Saldırgan sinyali jam eder; böylece kurban kapıyı kilitlemeye çalıştığında işlem başarısız olur, ancak saldırgan **bu kodu kaydeder**. Ardından kurban düğmeye basarak **aracı tekrar kilitlemeye çalışır** ve araç **bu ikinci kodu kaydeder**.<sup>[[2]](#references)[[4]](#references)</sup>\
Bundan hemen sonra **saldırgan ilk kodu gönderebilir** ve **araç kilitlenir** (kurban ikinci basışın aracı kilitlediğini düşünür). Ardından saldırgan, aracı açmak için **çalınan ikinci kodu gönderebilir** (bir **"close car" kodunun aracı açmak için de kullanılabildiği** varsayımıyla). (Açma ve kapatma için aynı kodları kullanan, ancak her iki komutu farklı frekanslarda dinleyen araçlar olduğundan frekans değişikliği gerekebilir.)

Saldırgan, kendi receiver'ını değil **araç receiver'ını jam edebilir**; çünkü araç receiver'ı örneğin 1MHz geniş bant dinliyorsa saldırgan, kumanda tarafından kullanılan tam frekansı değil, bu spektrumda **ona yakın bir frekansı jam eder**. Bu sırada **saldırganın receiver'ı daha küçük bir aralıkta dinleme yaparak** kumanda sinyalini **jam sinyali olmadan dinleyebilir**.

> [!WARNING]
> Spesifikasyonlarda görülen diğer uygulamalar, **rolling code'un gönderilen toplam kodun bir bölümü** olduğunu gösterir. Örneğin gönderilen kod, ilk **12 biti rolling code**, sonraki **8 biti lock veya unlock gibi command** ve son 4 biti **checksum** olan **24 bitlik bir key** olabilir. Bu türü uygulayan araçlar da doğal olarak savunmasızdır; çünkü saldırganın **her iki frekansta herhangi bir rolling code'u kullanabilmek** için yalnızca rolling code bölümünü değiştirmesi yeterlidir.

> [!CAUTION]
> Kurban saldırgan ilk kodu gönderirken üçüncü bir kod gönderirse ilk ve ikinci kodların geçersiz hale geleceğini unutmayın.

### Alarm Sounding Jamming Attack

Bir araçta kurulu aftermarket rolling code sistemine karşı yapılan testlerde, **aynı kodun iki kez gönderilmesi** alarmı ve immobiliser'ı hemen **etkinleştirerek** benzersiz bir **denial of service** fırsatı sağladı. İronik olarak, **alarmı** ve immobiliser'ı **devre dışı bırakmanın** yolu **uzaktan kumandaya basmaktı**; bu da saldırgana sürekli olarak **DoS attack gerçekleştirme** imkânı veriyordu. Alternatif olarak bu saldırı, kurban saldırıyı en kısa sürede durdurmak isteyeceğinden, **daha fazla kod elde etmek için önceki saldırıyla** birleştirilebilir.<sup>[[2]](#references)</sup>

## References

- [1] [What Radio Frequency Does Car Key Fobs Run On?](https://www.americanradioarchives.com/what-radio-frequency-do-car-key-fobs-run-on/)
- [2] [Bypassing Rolling Code Systems - Andrew Mohawk](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [3] [Samy Kamkar - DEF CON 23: Drive It Like You Hacked It (OpenSesame)](https://samy.pl/defcon2015/)
- [4] [How To Hack A Car - RollJam recreation with YARD Stick One / RTL-SDR](https://hackaday.io/project/164566-how-to-hack-a-car/details)

{{#include ../../banners/hacktricks-training.md}}
