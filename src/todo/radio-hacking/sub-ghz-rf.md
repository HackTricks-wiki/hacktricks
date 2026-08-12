# Sub-GHz RF

{{#include ../../banners/hacktricks-training.md}}

## Garage Doors

Garage-door uzaktan kumandaları, bölgeye ve ürüne özgü çeşitli sub-GHz tahsislerini kullanır. 300, 310, 315, 390 ve 433.92 MHz gibi frekanslarla karşılaşılabilir; ancak evrensel bir “300–190 MHz” garage-door bandı yoktur. İletim yapmadan önce hedefin etiketini, yasal düzenleme bölgesini ve gözlemlenen sinyali belirleyin.<sup>[[1]](#references)</sup>

## Car Doors

Birçok car key fob **315 MHz veya 433.92 MHz** kullanır; seçimde bölgesel kurallar ve araç tasarımı etkilidir. Tek başına frekans, 433 MHz'in 315 MHz'ten daha uzun menzilli olduğu anlamına gelmez: iletim gücü, anten verimliliği, modulation, receiver sensitivity, yayılım ve yerel düzenlemelerin tümü önemlidir. Avrupa'da genellikle 433.92 MHz, Kuzey Amerika ve Japonya'da ise 315 MHz kullanılır.<sup>[[1]](#references)</sup>

## **Brute-force Attack**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

Gösterilen fixed-code sisteminde, her kodu beş kez göndermek yerine bir kez göndermek, tahmini süreyi altı dakikaya düşürür:

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

Sinyaller arasındaki 2 ms'lik beklemeyi kaldırmak, bu gösterimdeki süreyi yaklaşık üç dakikaya düşürür.

Aday bit dizilerinin örtüşmesini sağlamak için De Bruijn sequence kullanılması, receiver sürekli diziyi gerekli bir preamble veya frame reset olmadan kabul ettiğinde gösterilen attack süresini yaklaşık sekiz saniyeye düşürür.<sup>[[3]](#references)</sup>

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

OpenSesame, bu attack'i uyumlu fixed-code sistemlerine karşı uygular.<sup>[[5]](#references)</sup>

**Bir preamble gerektirilmesi, De Bruijn Sequence** optimizasyonunu önler ve **rolling codes bu attack'i engeller** (kodun bruteforce edilemeyecek kadar uzun olduğu varsayımıyla).

## Sub-GHz Attack

Bu sinyallere Flipper Zero ile attack uygulamak için şuraya bakın:


{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Rolling Codes Protection

Automatic garage-door opener'lar, garage-door'u açıp kapatmak için genellikle kablosuz bir remote control kullanır. Remote control, garage-door opener'a bir **radio frequency (RF) signal** gönderir; bu sinyal, kapıyı açmak veya kapatmak üzere motoru etkinleştirir.

Bir kişinin code grabber olarak bilinen bir cihazı kullanarak RF signal'i yakalaması ve daha sonra kullanmak üzere kaydetmesi mümkündür. Bu, **replay attack** olarak bilinir. Bu tür bir attack'i önlemek için birçok modern garage-door opener, **rolling code** sistemi olarak bilinen daha güvenli bir encryption yöntemi kullanır.

**RF signal genellikle rolling code kullanılarak iletilir**; bu, kodun her kullanımda değiştiği anlamına gelir. Bu durum, bir kişinin sinyali **intercept etmesini** ve garage'a **unauthorised** erişim sağlamak için **kullanmasını** **zorlaştırır**.

Bir rolling code sisteminde remote control ile garage-door opener, remote her kullanıldığında yeni bir kod **üreten ortak bir algorithm** kullanır. Garage-door opener yalnızca **doğru koda** yanıt verir; bu da bir kişinin yalnızca bir kodu yakalayarak garage'a unauthorised erişim sağlamasını çok daha zorlaştırır.

### **Missing Link Attack**

Temel olarak düğmeyi dinler ve remote cihazın (örneğin car veya garage) **menzili dışındayken sinyali yakalarsınız**. Daha sonra cihaza yaklaşır ve **yakalanan kodu kullanarak cihazı açarsınız**.<sup>[[2]](#references)</sup>

### Full Link Jamming Attack

> [!CAUTION]
> Kasıtlı RF interference birçok yargı bölgesinde yasa dışıdır ve safety-relevant sistemleri bozabilir. Jamming testlerini yalnızca shielded, yetkilendirilmiş bir laboratuvarda ve geçerli radio regulations kapsamında gerçekleştirin.<sup>[[6]](#references)</sup>

Bir attacker, receiver'ın kodu decode edememesi için **vehicle veya receiver yakınındaki sinyali jamleyebilir**, engellenen transmission'ı ayrı olarak capture edebilir, jamming'i durdurabilir ve ardından yakalanan kodu replay edebilir.<sup>[[2]](#references)</sup>

Mağdur bir noktada **car'ı kilitlemek için keys kullanacaktır**; ancak attack, umarız kapıyı açmak için yeniden gönderilebilecek kadar **"close door" code** kaydetmiş olacaktır (bazı car'lar açma ve kapatma için aynı kodları kullanırken her iki komutu farklı frekanslarda dinlediğinden **frekans değişikliği gerekebilir**).

> [!WARNING]
> **Jamming işe yarar**, ancak fark edilmesi kolaydır; car'ı kilitleyen kişi kilitli olduğundan emin olmak için **kapıları kontrol ederse** car'ın kilitli olmadığını fark eder. Ayrıca bu tür attack'lerin farkında olan kişiler, ‘lock’ düğmesine bastıklarında kapıların hiçbir zaman kilitlenme **sesi çıkarmadığını** veya car **lights'larının yanıp sönmediğini** anlayabilir.

### **Code Grabbing Attack ( aka ‘RollJam’ )**

Bu, daha **gizli bir Jamming tekniğidir**. Attacker, sinyali jamler; böylece mağdur kapıyı kilitlemeye çalıştığında işlem başarısız olur, ancak attacker **bu kodu kaydeder**. Ardından mağdur düğmeye basarak car'ı **tekrar kilitlemeye çalışır** ve car **bu ikinci kodu kaydeder**.<sup>[[2]](#references)</sup><sup>[[4]](#references)</sup>\
Bunun hemen ardından **attacker ilk kodu gönderebilir** ve **car kilitlenir** (mağdur ikinci basışın car'ı kilitlediğini düşünür). Daha sonra attacker, car'ın kilidini açmak için **çalınan ikinci kodu gönderebilir** (**"close car" code'unun car'ı açmak için de kullanılabildiği varsayımıyla**). Bazı car'lar açma ve kapatma için aynı kodları kullanırken her iki komutu farklı frekanslarda dinlediğinden frekans değişikliği gerekebilir.

Bir RollJam uygulaması receiver bandwidth'inden yararlanır: jammer, vehicle'ın daha geniş receiver'ını desensitize etmek için remote'un carrier'ına yeterince yakın iletim yaparken attacker's daha dar receiver'ı remote üzerinde merkezlenmiş kalır ve sinyali kaydetmeye devam edebilir. Kesin offset ve bandwidth hedef hardware'ine bağlıdır.<sup>[[2]](#references)</sup>

> [!WARNING]
> Specifications'larda görülen diğer uygulamalar, **rolling code'un gönderilen toplam kodun bir bölümü** olduğunu gösterir. Örneğin gönderilen kod, ilk **12 biti rolling code**, sonraki **8 biti command** (lock veya unlock gibi) ve son 4 biti **checksum** olan **24 bitlik bir key** olabilir. Bu türü uygulayan vehicle'lar da doğal olarak savunmasızdır; çünkü attacker'ın her iki frekansta da **herhangi bir rolling code'u kullanabilmesi** için yalnızca rolling code segmentini değiştirmesi yeterlidir.

> [!CAUTION]
> Mağdur attacker ilk kodu gönderirken üçüncü bir kod gönderirse ilk ve ikinci kodların geçersiz hale geleceğini unutmayın.

### Alarm Sounding Jamming Attack

Bir car'a kurulan aftermarket rolling code sistemi üzerinde yapılan testte, **aynı kodun iki kez gönderilmesi** alarmı ve immobiliser'ı hemen **etkinleştirdi** ve benzersiz bir **denial of service** fırsatı sağladı. İronik olarak **alarmı** ve immobiliser'ı **devre dışı bırakmanın** yolu **remote'a basmaktı**; bu da attacker's sürekli olarak DoS attack gerçekleştirebilmesini sağlıyordu. Alternatif olarak bu attack, mağdur attack'i mümkün olduğunca hızlı durdurmak isteyeceğinden, **daha fazla kod elde etmek için önceki attack ile birleştirilebilir**.<sup>[[2]](#references)</sup>

## References

- [1] [Flipper Zero documentation - bölgesel Sub-GHz frekansları](https://docs.flipper.net/zero/sub-ghz/frequencies)
- [2] [Rolling Code Systems'ı Bypass Etme - Andrew Mohawk](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [3] [Samy Kamkar - DEF CON 23: Hacklediğiniz Gibi Sürün (OpenSesame)](https://samy.pl/defcon2015/)
- [4] [Bir Car Nasıl Hacklenir - YARD Stick One / RTL-SDR ile RollJam yeniden oluşturma](https://hackaday.io/project/164566-how-to-hack-a-car/details)
- [5] [OpenSesame source code](https://github.com/samyk/opensesame)
- [6] [FCC Enforcement Advisory - Jammer Enforcement](https://www.fcc.gov/document/jammer-enforcement)
{{#include ../../banners/hacktricks-training.md}}
