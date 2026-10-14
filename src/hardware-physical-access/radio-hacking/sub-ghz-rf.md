# Sub-GHz RF

{{#include ../../banners/hacktricks-training.md}}

## Garaj Kapıları

Garaj kapısı kumandaları, bölgeye ve ürüne özgü çeşitli sub-GHz frekans tahsislerini kullanır. 300, 310, 315, 390 ve 433.92 MHz gibi frekanslara rastlanır, ancak evrensel bir “300–190 MHz” garaj kapısı bandı yoktur. Sinyal göndermeden önce hedefin etiketini, mevzuat bölgesini ve gözlemlenen sinyali belirleyin.<sup>[[1]](#references)</sup>

## Araç Kapıları

Birçok araç anahtarlığı **315 MHz veya 433.92 MHz** kullanır; seçimi bölgesel kurallar ve araç tasarımı etkiler. Yalnızca frekans, 433 MHz'in 315 MHz'den daha uzun menzilli olduğu anlamına gelmez: iletim gücü, anten verimliliği, modülasyon, alıcı hassasiyeti, yayılım ve yerel mevzuatın tümü önemlidir. Avrupa'da yaygın olarak 433.92 MHz, Kuzey Amerika ve Japonya'da ise 315 MHz kullanılır.<sup>[[1]](#references)</sup>

## **Brute-force Attack**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

Gösterilen sabit kodlu sistemde, her kodu beş kez yerine bir kez göndermek tahmini süreyi altı dakikaya indirir:

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

Sinyaller arasındaki 2 ms bekleme süresini kaldırmak, bu gösterimi yaklaşık üç dakikaya indirir.

Aday bit dizilerinin üst üste binmesini sağlayan bir De Bruijn dizisi kullanmak, alıcının sürekli diziyi gerekli bir önsöz veya çerçeve sıfırlaması olmadan kabul etmesi durumunda gösterilen saldırıyı yaklaşık sekiz saniyeye indirir.<sup>[[3]](#references)</sup>

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

OpenSesame, bu saldırıyı uyumlu sabit kodlu sistemlere karşı uygular.<sup>[[5]](#references)</sup>

**Önsöz gerekliliği De Bruijn Sequence** optimizasyonunu engeller ve **rolling code bu saldırıyı önler** (kodun brute-force ile kırılamayacak kadar uzun olduğu varsayımıyla).

## Sub-GHz Attack

Bu sinyallere Flipper Zero ile saldırmak için şuraya bakın:


{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Rolling Codes Koruması

Otomatik garaj kapısı açıcılar, garaj kapısını açıp kapatmak için genellikle kablosuz bir uzaktan kumanda kullanır. Uzaktan kumanda, garaj kapısı açıcısına **bir radyo frekansı (RF) sinyali gönderir**; bu sinyal, kapıyı açmak veya kapatmak üzere motoru etkinleştirir.

Birinin, RF sinyalini yakalayıp daha sonra kullanmak üzere kaydetmek için code grabber olarak bilinen bir cihaz kullanması mümkündür. Bu, **replay attack** olarak bilinir. Bu tür saldırıları önlemek için birçok modern garaj kapısı açıcısı, **rolling code** sistemi olarak bilinen daha güvenli bir şifreleme yöntemi kullanır.

**RF sinyali genellikle rolling code kullanılarak iletilir**; yani kod her kullanımda değişir. Bu, birinin sinyali **yakalamayı** ve garaja yetkisiz erişim sağlamak için **kullanmayı** **zorlaştırır**.

Rolling code sisteminde uzaktan kumanda ve garaj kapısı açıcısı, kumanda her kullanıldığında yeni bir kod **üreten ortak bir algoritmaya** sahiptir. Garaj kapısı açıcı yalnızca **doğru koda** yanıt verir; böylece birinin yalnızca bir kodu yakalayarak garaja yetkisiz erişim sağlaması çok daha zorlaşır.

### **Missing Link Attack**

Temel olarak, düğmeye basılmasını dinler ve kumanda cihazın (örneğin araç veya garajın) **menzili dışındayken sinyali yakalarsınız**. Ardından cihazın yanına gidip **yakalanan kodu kullanarak onu açarsınız**.<sup>[[2]](#references)</sup>

### Full Link Jamming Attack

> [!CAUTION]
> Kasıtlı RF paraziti birçok yargı bölgesinde yasa dışıdır ve güvenlikle ilgili sistemleri aksatabilir. Jamming testlerini yalnızca yalıtılmış, yetkili bir laboratuvarda ve geçerli radyo düzenlemelerine uygun olarak gerçekleştirin.<sup>[[6]](#references)</sup>

Bir saldırgan, alıcının kodu çözmesini engellemek için **aracın veya alıcının yakınındaki sinyali jam edebilir**, engellenen iletimi ayrıca yakalayabilir, jamming'i durdurabilir ve ardından yakalanan kodu yeniden gönderebilir.<sup>[[2]](#references)</sup>

Mağdur bir noktada **aracı kilitlemek için anahtarları kullanır**, ancak saldırı, umarız kapıyı açmak için yeniden gönderilebilecek yeterli sayıda "kapıyı kapat" kodunu **kaydetmiş olur** (açma ve kapatma için aynı kodları kullanan, ancak iki komutu farklı frekanslarda dinleyen araçlar olduğundan **frekans değişikliği gerekebilir**).

> [!WARNING]
> **Jamming işe yarar**, ancak fark edilmesi kolaydır; çünkü **aracı kilitleyen kişi kapıların kilitli olduğundan emin olmak için kapıları kontrol ederse**, aracın kilidinin açılmış olduğunu fark eder. Ayrıca bu tür saldırılardan haberdarlarsa, ‘lock’ düğmesine bastıklarında kapılardan hiç kilit **sesi** gelmediğini veya aracın **ışıklarının** yanıp sönmediğini fark edebilirler.

### **Code Grabbing Attack ( aka ‘RollJam’ )**

Bu, daha **gizli bir Jamming tekniğidir**. Saldırgan sinyali jam eder; böylece mağdur kapıyı kilitlemeye çalıştığında işlem başarısız olur, ancak saldırgan **bu kodu kaydeder**. Ardından mağdur düğmeye basarak **aracı tekrar kilitlemeye çalışır** ve araç **bu ikinci kodu kaydeder**.<sup>[[2]](#references)</sup><sup>[[4]](#references)</sup>\
Bunun hemen ardından **saldırgan ilk kodu gönderebilir** ve **araç kilitlenir** (mağdur ikinci basışın kapıyı kilitlediğini düşünür). Ardından saldırgan, aracı açmak için **çalınan ikinci kodu gönderebilir** (**"aracı kapat" kodunun aracı açmak için de kullanılabildiği** varsayımıyla). Açma ve kapatma için aynı kodları kullanan, ancak iki komutu farklı frekanslarda dinleyen araçlar olduğundan frekans değişikliği gerekebilir.

Bir RollJam uygulaması, alıcı bant genişliğinden yararlanır: jammer, aracın daha geniş alıcı bandını duyarsızlaştıracak kadar uzaktan kumandanın taşıyıcı frekansına yakın bir frekansta iletim yaparken saldırganın daha dar bantlı alıcısı uzaktan kumandanın frekansına ayarlı kalır ve sinyali kaydedebilir. Kesin frekans farkı ve bant genişliği hedef donanıma bağlıdır.<sup>[[2]](#references)</sup>

> [!WARNING]
> Spesifikasyonlarda görülen diğer uygulamalar, **rolling code'un gönderilen toplam kodun bir bölümü** olduğunu gösterir. Örneğin gönderilen kod, ilk **12 biti rolling code**, sonraki **8 biti komut** (kilitleme veya kilit açma gibi) ve son 4 biti **checksum** olan **24 bitlik bir anahtar** olabilir. Bu türü uygulayan araçlar da doğal olarak savunmasızdır; çünkü saldırganın her iki frekansta da **herhangi bir rolling code'u kullanabilmek** için yalnızca rolling code bölümünü değiştirmesi yeterlidir.

> [!CAUTION]
> Saldırgan ilk kodu gönderirken mağdur üçüncü bir kod gönderirse ilk ve ikinci kodların geçersiz olacağını unutmayın.

### Alarm Sounding Jamming Attack

Bir araca kurulu satış sonrası rolling code sisteminde yapılan testte, **aynı kodun iki kez gönderilmesi** alarmı ve immobiliser'ı hemen etkinleştirerek benzersiz bir **hizmet reddi** fırsatı sağladı. İşin ironik yanı, alarmı ve immobiliser'ı **devre dışı bırakmanın** yolu **uzaktan kumandaya basmaktı**; bu da saldırgana **sürekli DoS saldırısı gerçekleştirme** olanağı verdi. Ya da mağdur saldırıyı mümkün olduğunca çabuk durdurmak isteyeceğinden, bu saldırıyı **önceki saldırıyla birleştirerek daha fazla kod elde edebilirsiniz**.<sup>[[2]](#references)</sup>

## References

- [1] [Flipper Zero belgeleri - bölgesel Sub-GHz frekansları](https://docs.flipper.net/zero/sub-ghz/frequencies)
- [2] [Rolling Code Sistemlerini Atlatma - Andrew Mohawk](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [3] [Samy Kamkar - DEF CON 23: Hacklediğin Gibi Sür (OpenSesame)](https://samy.pl/defcon2015/)
- [4] [Bir Araba Nasıl Hacklenir - YARD Stick One / RTL-SDR ile RollJam'in yeniden oluşturulması](https://hackaday.io/project/164566-how-to-hack-a-car/details)
- [5] [OpenSesame kaynak kodu](https://github.com/samyk/opensesame)
- [6] [FCC Uygulama Uyarısı - Jammer Uygulaması](https://www.fcc.gov/document/jammer-enforcement)
{{#include ../../banners/hacktricks-training.md}}
