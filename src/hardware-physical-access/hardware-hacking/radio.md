# Radio

{{#include ../../banners/hacktricks-training.md}}

Sinyal tanımlandıktan sonra protokole özgü çalışmalar için [RFID/NFC, sub-GHz, infrared, BLE ve LoRaWAN testlerine](../radio-hacking/README.md) bakın.

## SigDigger

[**SigDigger**](https://github.com/BatchDrake/SigDigger), bilinmeyen radyo sinyallerinden bilgi çıkarmak için tasarlanmış, GNU/Linux ve macOS için ücretsiz bir dijital sinyal analiz aracıdır. SoapySDR üzerinden SDR cihazlarını destekler ve FSK, PSK, ASK, analog video, kesikli sinyaller ve analog ses kanalları için gerçek zamanlı demodülasyon ve analiz araçları sunar.<sup>[[1]](#references)</sup>

### Temel Yapılandırma

Kurulumdan sonra yapılandırmayı düşünebileceğiniz birkaç seçenek vardır.\
Ayarlar bölümünde (ikinci sekme düğmesi) bir **SDR cihazı** veya giriş dosyası, ayarlanacak frekans ve örnekleme hızını seçin. Bilgisayarınız destekliyorsa 2.56 Msps’ye kadar bir hız uygun olabilir.

![SDR cihazı, giriş dosyası, frekans ve örnekleme hızı seçeneklerini gösteren SigDigger ayarları](<../../images/image (245).png>)

GUI davranışı ayarlarında, bilgisayarınız destekliyorsa birkaç seçeneği etkinleştirmeniz önerilir:

![SigDigger - Temel Yapılandırma: Bilgisayarınız destekliyorsa GUI davranışı ayarlarında birkaç seçeneği etkinleştirmeniz önerilir](<../../images/image (472).png>)

> [!TIP]
> Bilgisayarınızın sinyalleri yakalamadığını fark ederseniz OpenGL’yi devre dışı bırakmayı ve örnekleme hızını düşürmeyi deneyin.

### Kullanım

- Bir sinyali bir süre **yakalamak ve analiz etmek** için "Push to capture" düğmesini istediğiniz süre boyunca basılı tutun.

![Temel Yapılandırma - Kullanım: Bir sinyali bir süre yakalayıp analiz etmek için "Push to capture" düğmesini gerektiği kadar basılı tutun](<../../images/image (960).png>)

- SigDigger’ın **Tuner** özelliği **sinyalleri daha iyi yakalamanıza** yardımcı olur (ancak sinyalleri bozabilir de). İdeal olarak 0’dan başlayın ve eklenen **gürültü**, istediğiniz **sinyal iyileşmesinden** daha **fazla** olana kadar değeri artırın.

![Yakalanan radyo sinyalini iyileştirmek için ayarlanmış SigDigger tuner denetimi](<../../images/image (1099).png>)

### Radyo kanalıyla senkronizasyon

[**SigDigger**](https://github.com/BatchDrake/SigDigger) ile dinlemek istediğiniz kanala senkronize olun, "Baseband audio preview" seçeneğini yapılandırın, gönderilen tüm bilgileri almak için bant genişliğini ayarlayın ve ardından Tuner’ı gürültünün belirgin biçimde artmaya başladığı seviyenin hemen öncesine ayarlayın:<sup>[[1]](#references)</sup>

![Baseband audio preview ve bant genişliği yapılandırılmış, senkronize edilmiş SigDigger radyo kanalı](<../../images/image (585).png>)

## İlginç ipuçları

- Bir cihaz bilgi patlamaları gönderirken genellikle **ilk kısım bir preamble olur**; bu nedenle orada **bilgi bulamazsanız** veya **bazı hatalar görürseniz** endişelenmeniz **gerekmez**.
- Bilgi çerçevelerinde genellikle **birbirleriyle hizalanmış farklı çerçeveler bulmanız gerekir**:

![Radyo kanalıyla senkronizasyon - İlginç ipuçları: Bilgi çerçevelerinde genellikle birbirleriyle hizalanmış farklı çerçeveler bulmanız gerekir](<../../images/image (1076).png>)

![Radyo kanalıyla senkronizasyon - İlginç ipuçları: Bilgi çerçevelerinde genellikle birbirleriyle hizalanmış farklı çerçeveler bulmanız gerekir](<../../images/image (597).png>)

- **Seviye geçişlerini çıkardıktan sonra bunları decode etmeniz gerekebilir.** Manchester encoding’de bir geçiş yönü `0`, ters yönü ise `1` anlamına gelir; kullanılan kesin polarite, geçerli kurala bağlıdır.
- Payload Manchester encoding kullansa bile preamble aynı örneklenmiş seviyenin art arda tekrarlarından oluşabilir; bu nedenle decode etmeden önce çerçeve sınırını belirleyin.

### IQ ile modülasyon türünü belirleme

Sinyallerde bilgiyi saklamanın 3 yolu vardır: **genliği**, **frekansı** veya **fazı** modüle etmek.\
Bir sinyali incelerken bilgiyi saklamak için hangi yöntemin kullanıldığını anlamaya çalışabilirsiniz (daha fazla yöntem aşağıda); IQ grafiğini incelemek iyi bir yöntemdir.

![Sinyalin genlik, frekans veya faz modülasyonu kullanıp kullanmadığını belirlemek için kullanılan SigDigger IQ grafiği](<../../images/image (788).png>)

- **AM tespiti**: IQ grafiğinde örneğin **2 daire** görünüyorsa (muhtemelen biri 0’da, diğeri farklı bir genlikte), bu bir AM sinyali olabilir. Bunun nedeni IQ grafiğinde 0 ile daire arasındaki mesafenin sinyalin genliği olmasıdır; dolayısıyla kullanılan farklı genlikleri görselleştirmek kolaydır.
- **PM tespiti**: Önceki görseldeki gibi, birbiriyle ilişkili olmayan küçük daireler görürseniz muhtemelen faz modülasyonu kullanılıyordur. IQ grafiğinde nokta ile 0,0 arasındaki açı sinyalin fazıdır; bu da 4 farklı faz kullanıldığı anlamına gelir.
  - Bilginin fazın kendisinde değil, fazın değişmesinde saklı olduğunu unutmayın. Bu durumda farklı fazları net biçimde ayırt edemezsiniz.
- **FM tespiti**: IQ’da frekansları tanımlayan bir alan yoktur (merkeze olan mesafe genlik, açı ise fazdır).\
  Bu nedenle FM’i tanımak için bu grafikte **temelde yalnızca bir daire** görmeniz gerekir.\
  Ayrıca frekans ofseti, IQ dairesi etrafındaki dönüş hızını değiştirir. Bu nedenle SigDigger’da dönüş hızındaki veya yönündeki değişim FM’e işaret edebilir.

## AM Örneği

{{#file}}
sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### AM’i belirleme

#### Zarfı inceleme

[**SigDigger**](https://github.com/BatchDrake/SigDigger) ile AM verilerini incelerken sinyalin **zarfı**, farklı genlik seviyelerini ortaya çıkarabilir. Örnek sinyal bilgiyi genlik modülasyonlu darbeler olarak gönderir; bir darbe şu şekildedir:<sup>[[1]](#references)</sup>

![Belirgin darbe genliği seviyelerine sahip SigDigger AM sinyal zarfı](<../../images/image (590).png>)

Bir sembolün bir kısmı dalga biçiminde şu şekilde görünür:

![AM’i belirleme - Zarfı inceleme: Bir sembolün bir kısmının dalga biçimindeki görünümü](<../../images/image (734).png>)

#### Histogramı inceleme

Bilginin bulunduğu **sinyalin tamamını seçin**, **Amplitude** modunu ve **Selection** seçeneğini seçin, ardından **Histogram**’a tıklayın. Yalnızca 2 belirgin seviye görebilirsiniz.

![Seçili AM sinyali için iki belirgin seviyeyi gösteren SigDigger genlik histogramı](<../../images/image (264).png>)

Örneğin, bu AM sinyalinde Amplitude yerine Frequency seçerseniz yalnızca 1 frekans bulursunuz (frekansla modüle edilen bilginin tek bir frekans kullanması mümkün değildir).

![AM sinyali için tek frekans gösteren SigDigger frekans histogramı](<../../images/image (732).png>)

Çok sayıda frekans bulursanız, bu muhtemelen FM değildir; kanal nedeniyle sinyalin frekansı değişmiş olabilir.

#### IQ ile

Bu örnekte **büyük bir daire** ve merkezde **çok sayıda nokta** olduğunu görebilirsiniz.

![Histogramı inceleme - IQ ile: Bu örnekte büyük bir daire ve merkezde çok sayıda nokta görebilirsiniz](<../../images/image (222).png>)

### Sembol hızını bulma

#### Tek sembolle

Bir sembolü net biçimde içeren en küçük aralığı seçin ve **Selection freq** değerini kontrol edin. Bu örnekte değer 1.013 kHz, yani yaklaşık 1 kHz’dir.

![Sembol hızını bulma - Tek sembolle: Bulabildiğiniz en küçük sembol aralığını seçin (böylece tek bir sembol olduğundan emin olursunuz) ve "Selection freq" değerini kontrol edin. Bu örnekte değer 1.013 kHz’dir (yani 1 kHz).](<../../images/image (78).png>)

#### Bir sembol grubuyla

Seçeceğiniz sembol sayısını belirtebilirsiniz; SigDigger tek bir sembolün frekansını hesaplar (muhtemelen daha fazla sembol seçmek daha iyi sonuç verir). Bu örnekte 10 sembol seçildi ve "Selection freq" değeri 1.004 kHz:

![Seçilen on sembolü kullanarak SigDigger’da sembol hızı hesaplama](<../../images/image (1008).png>)

### Bitleri alma

AM’i belirleyip **sembol hızını** tahmin ettikten sonra sinyal bölgesini seçin, genlik örnekleme ve karar seviyelerini yapılandırın, **Gardner clock recovery**’yi seçin ve **Sample** düğmesine basın:

![AM örnekleme, sembol hızı ve Gardner clock recovery için yapılandırılmış SigDigger Get Bits paneli](<../../images/image (965).png>)

- **Sync to selection intervals**, sembol hızını bulmak için daha önce aralıklar seçtiyseniz bu sembol hızının kullanılacağı anlamına gelir.
- **Manual**, belirtilen sembol hızının kullanılacağı anlamına gelir.
- **Fixed interval selection** bölümünde seçilecek aralık sayısını belirtirsiniz; araç bu sayıdan sembol hızını hesaplar.
- **Gardner clock recovery** kullanışlı bir varsayılan seçenektir, ancak yine de yaklaşık bir sembol hızı gerekir.

Sample düğmesine bastığınızda şu görünür:

![Bir sembol grubuyla - Bitleri alma: Sample düğmesine bastığınızda görünenler](<../../images/image (644).png>)

Şimdi SigDigger’a bilgiyi taşıyan seviyenin **aralığını** belirtmek için **alt seviyeye** tıklayın ve en yüksek seviyeye ulaşana kadar basılı tutun:

![Alt genlik seviyesinden üst seviyeye doğru SigDigger seviye aralığı seçimi](<../../images/image (439).png>)

Örneğin **4 farklı genlik seviyesi** olsaydı, **Bits per symbol** değerini 2 olarak ayarlamanız ve en düşük seviyeden en yükseğe kadar seçim yapmanız gerekirdi.

Son olarak **Zoom** değerini artırıp **Row size** değerini değiştirerek bitleri görebilirsiniz (tüm bitleri almak için hepsini seçip kopyalayabilirsiniz):

![Bir sembol grubuyla - Bitleri alma: Son olarak Zoom değerini artırıp Row size değerini değiştirerek bitleri görebilirsiniz (tüm bitleri almak için hepsini seçip kopyalayabilirsiniz)](<../../images/image (276).png>)

Sinyal sembol başına 1’den fazla bit içeriyorsa (örneğin 2), SigDigger hangi sembolün 00, 01, 10 veya 11 olduğunu bilemez; her birini farklı **gri tonlarıyla** gösterir (bitleri kopyalarsanız **0 ile 3 arasındaki sayıları** kullanır; bunları işlemeniz gerekir).

**Manchester** gibi line encoding yöntemlerinde, protokolde kullanılan kurala göre her geçerli geçiş çiftini (`01` veya `10`) bir veri bitine dönüştürün.

## FM Örneği

{{#file}}
sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### FM’i belirleme

#### Frekansları ve dalga biçimini inceleme

FM ile modüle edilmiş bilgi gönderen örnek sinyal:

![FM’i belirleme - Frekansları ve dalga biçimini inceleme: FM ile modüle edilmiş bilgi gönderen örnek sinyal](<../../images/image (725).png>)

Spektrumda **iki frekans** net biçimde görülür; ancak bunları zaman alanındaki dalga biçiminde ayırt etmek zor olabilir:

![İki frekansın doğrudan ayırt edilmesinin zor olduğu SigDigger FM dalga biçimi](<../../images/image (717).png>)

Bunun nedeni yakalamanın iki frekansın ortasında merkezlenmiş olmasıdır; dolayısıyla frekans ofsetleri yaklaşık olarak birbirinin tersidir:

![İki frekansı yaklaşık olarak birbirinin tersi şeklinde gösteren SigDigger FM yakalaması](<../../images/image (942).png>)

Senkronize edilen frekans **bir frekansa diğerinden daha yakınsa**, 2 farklı frekansı kolayca görebilirsiniz:

![FM’i belirleme - Frekansları ve dalga biçimini inceleme: Senkronize edilen frekans bir frekansa diğerinden daha yakınsa 2 farklı frekansı kolayca görebilirsiniz](<../../images/image (422).png>)

![FM’i belirleme - Frekansları ve dalga biçimini inceleme: Senkronize edilen frekans bir frekansa diğerinden daha yakınsa 2 farklı frekansı kolayca görebilirsiniz](<../../images/image (488).png>)

#### Histogramı inceleme

Bilgi içeren sinyalin frekans histogramını incelerseniz 2 farklı sinyali kolayca görebilirsiniz:

![Frekansları ve dalga biçimini inceleme - Histogramı inceleme: Bilgi içeren sinyalin frekans histogramını incelediğinizde 2 farklı sinyali kolayca görebilirsiniz](<../../images/image (871).png>)

Bu durumda **Amplitude histogram**’ı kontrol ederseniz **yalnızca bir genlik** görürsünüz; dolayısıyla sinyal **AM olamaz** (çok sayıda genlik görürseniz bunun nedeni sinyalin kanal boyunca güç kaybetmesi olabilir):

![FM sinyali için tek bir genlik seviyesi gösteren SigDigger genlik histogramı](<../../images/image (817).png>)

Faz histogramı da aşağıdaki gibidir (sinyalin faz modülasyonlu olmadığını açıkça gösterir):

![Frekansları ve dalga biçimini inceleme - Histogramı inceleme: Faz histogramı, sinyalin faz modülasyonlu olmadığını açıkça gösterir](<../../images/image (996).png>)

#### IQ ile

IQ’da frekansları tanımlayan bir alan yoktur (merkeze olan mesafe genlik, açı ise fazdır).\
Bu nedenle FM’i tanımak için bu grafikte **temelde yalnızca bir daire** görmeniz gerekir.\
Ayrıca frekans ofseti, IQ dairesi etrafındaki dönüş hızını değiştirir. Bu nedenle SigDigger’da dönüş hızındaki veya yönündeki değişim FM’e işaret edebilir:

![FM’in daire etrafındaki dönüş hızındaki değişiklikler olarak göründüğü SigDigger IQ grafiği](<../../images/image (81).png>)

### Sembol hızını bulma

Sembol taşıyan frekansları bulduktan sonra sembol hızını bulmak için **AM örneğinde kullanılan yöntemin aynısını** kullanabilirsiniz.

### Bitleri alma

Sinyalin **frekans modülasyonlu olduğunu** ve **sembol hızını** belirledikten sonra bitleri almak için **AM örneğinde kullanılan yöntemin aynısını** kullanabilirsiniz.

## References

- [1] [SigDigger - GNU/Linux ve macOS için ücretsiz dijital sinyal analiz aracı](https://github.com/BatchDrake/SigDigger)
{{#include ../../banners/hacktricks-training.md}}
