# Phishing Tespit Etme

{{#include ../../banners/hacktricks-training.md}}

## Giriş

Bir phishing girişimini tespit etmek için **günümüzde kullanılan phishing tekniklerini anlamak önemlidir**. Bu gönderinin ana sayfasında bu bilgileri bulabilirsiniz, bu yüzden günümüzde hangi tekniklerin kullanıldığını bilmiyorsanız ana sayfaya gitmenizi ve en azından o bölümü okumanızı öneririm.

Bu gönderi, **saldırganların bir şekilde kurbanın alan adını taklit etmeye veya kullanmaya çalışacakları** fikrine dayanmaktadır. Eğer alan adınız `example.com` ise ve bir şekilde tamamen farklı bir alan adı olan `youwonthelottery.com` kullanılarak phishing yapılıyorsa, bu teknikler bunu açığa çıkarmayacaktır.

## Alan adı varyasyonları

E-posta içinde **benzer bir alan adı** kullanacak olan **phishing** girişimlerini **açığa çıkarmak** oldukça **kolaydır**.\
Saldırganın kullanabileceği en olası phishing adlarının bir listesini **oluşturmak** ve bunun **kayıtlı olup olmadığını kontrol etmek** veya sadece herhangi bir **IP** kullanıp kullanmadığını kontrol etmek yeterlidir.

### Şüpheli alanları bulma

Bu amaçla, aşağıdaki araçlardan herhangi birini kullanabilirsiniz. Bu araçların, alan adının herhangi bir IP ile ilişkilendirilip ilişkilendirilmediğini kontrol etmek için otomatik olarak DNS istekleri de gerçekleştireceğini unutmayın:

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

### Bitflipping

**Bu tekniğin kısa bir açıklamasını ana sayfada bulabilirsiniz. Ya da orijinal araştırmayı** [**https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/**](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/) **okuyabilirsiniz.**

Örneğin, microsoft.com alan adında 1 bitlik bir değişiklik onu _windnws.com_ haline getirebilir.\
**Saldırganlar, kurbanla ilgili mümkün olduğunca çok bit-flipping alan adı kaydedebilirler ve meşru kullanıcıları kendi altyapılarına yönlendirebilirler.**

**Tüm olası bit-flipping alan adları da izlenmelidir.**

### Temel kontroller

Potansiyel şüpheli alan adları listesine sahip olduğunuzda, bunları (özellikle HTTP ve HTTPS portlarını) **kontrol etmelisiniz** ve **kurbanın alanına benzer bir giriş formu kullanıp kullanmadıklarını görmek için** kontrol etmelisiniz.\
Ayrıca, port 3333'ü kontrol ederek açık olup olmadığını ve `gophish` örneğini çalıştırıp çalıştırmadığını görebilirsiniz.\
Her keşfedilen şüpheli alanın **ne kadar eski olduğunu bilmek de ilginçtir**, ne kadar gençse o kadar risklidir.\
Şüpheli web sayfasının HTTP ve/veya HTTPS ekran görüntülerini alabilir ve şüpheli olup olmadığını görmek için **erişim sağlayarak daha derin bir inceleme yapabilirsiniz.**

### Gelişmiş kontroller

Bir adım daha ileri gitmek istiyorsanız, **şüpheli alanları izlemeyi ve zaman zaman daha fazlasını aramayı** öneririm (her gün? sadece birkaç saniye/dakika alır). Ayrıca, ilgili IP'lerin açık **portlarını kontrol etmeli** ve **`gophish` veya benzeri araçların örneklerini aramalısınız** (evet, saldırganlar da hata yapar) ve **şüpheli alanların ve alt alanların HTTP ve HTTPS web sayfalarını izlemelisiniz** ve kurbanın web sayfalarından herhangi bir giriş formunu kopyalayıp kopyalamadıklarını görmek için.\
Bunu **otomatikleştirmek** için, kurbanın alanlarının giriş formlarının bir listesini oluşturmayı, şüpheli web sayfalarını taramayı ve şüpheli alanlardaki her giriş formunu kurbanın alanındaki her giriş formu ile karşılaştırmayı öneririm, `ssdeep` gibi bir şey kullanarak.\
Eğer şüpheli alanların giriş formlarını bulduysanız, **saçma kimlik bilgileri göndermeyi** ve **sizi kurbanın alanına yönlendirip yönlendirmediğini kontrol etmeyi** deneyebilirsiniz.

## Anahtar kelimeleri kullanan alan adları

Ana sayfa, **kurbanın alan adını daha büyük bir alan adı içinde yerleştirme** tekniğini de belirtmektedir (örneğin, paypal-financial.com için paypal.com).

### Sertifika Şeffaflığı

Önceki "Brute-Force" yaklaşımını almak mümkün değil, ancak aslında **bu tür phishing girişimlerini açığa çıkarmak mümkündür** aynı zamanda sertifika şeffaflığı sayesinde. Her seferinde bir CA tarafından bir sertifika verildiğinde, detaylar kamuya açık hale gelir. Bu, sertifika şeffaflığını okuyarak veya hatta izleyerek, **adında bir anahtar kelime kullanan alanları bulmanın mümkün olduğu anlamına gelir.** Örneğin, bir saldırgan [https://paypal-financial.com](https://paypal-financial.com) için bir sertifika oluşturursa, sertifikayı görmek "paypal" anahtar kelimesini bulmak ve şüpheli e-postanın kullanıldığını bilmek mümkündür.

Gönderi [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/) Censys'i belirli bir anahtar kelimeyi etkileyen sertifikaları aramak ve tarih (sadece "yeni" sertifikalar) ve CA vereni "Let's Encrypt" ile filtrelemek için kullanabileceğinizi öneriyor:

![https://0xpatrik.com/content/images/2018/07/cert_listing.png](<../../images/image (1115).png>)

Ancak, bunu ücretsiz web [**crt.sh**](https://crt.sh) kullanarak "aynısını" yapabilirsiniz. **Anahtar kelimeyi arayabilir** ve **sonuçları tarih ve CA ile filtreleyebilirsiniz**.

![](<../../images/image (519).png>)

Bu son seçeneği kullanarak, gerçek alanın herhangi bir kimliğinin şüpheli alanlardan herhangi biriyle eşleşip eşleşmediğini görmek için Kimlikleri Eşleştirme alanını bile kullanabilirsiniz (şüpheli bir alanın yanlış pozitif olabileceğini unutmayın).

**Bir diğer alternatif** ise [**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067) adlı harika projedir. CertStream, belirli anahtar kelimeleri (yaklaşık) gerçek zamanlı olarak tespit etmek için kullanabileceğiniz yeni oluşturulan sertifikaların gerçek zamanlı bir akışını sağlar. Aslında, tam olarak bunu yapan [**phishing_catcher**](https://github.com/x0rz/phishing_catcher) adlı bir proje bulunmaktadır.

### **Yeni alanlar**

**Son bir alternatif**, bazı TLD'ler için **yeni kayıtlı alanların** bir listesini toplamak ([Whoxy](https://www.whoxy.com/newly-registered-domains/) bu hizmeti sağlar) ve **bu alanlardaki anahtar kelimeleri kontrol etmektir**. Ancak, uzun alan adları genellikle bir veya daha fazla alt alan adı kullanır, bu nedenle anahtar kelime FLD içinde görünmeyecek ve phishing alt alanını bulamayacaksınız.

{{#include ../../banners/hacktricks-training.md}}
