# Radio

{{#include ../../banners/hacktricks-training.md}}

## SigDigger

[**SigDigger**](https://github.com/BatchDrake/SigDigger), bilinmeyen radyo sinyallerinden bilgi çıkarmak için tasarlanmış, GNU/Linux ve macOS için ücretsiz bir dijital sinyal analiz aracıdır. SoapySDR üzerinden SDR cihazlarını destekler ve FSK, PSK, ASK, analog video, burst sinyaller ve analog ses kanalları için gerçek zamanlı demodülasyon ve analiz araçları sunar.<sup>[[1]](#references)</sup>

### Temel Yapılandırma

Yüklemeden sonra yapılandırmayı düşünebileceğiniz birkaç şey var.\
Ayarlar bölümünde (ikinci sekme düğmesi) bir **SDR cihazı** veya giriş dosyası, ayarlanacak frekans ve örnekleme hızını seçin. Ana bilgisayar destekliyorsa 2.56 Msps’ye kadar bir hız uygun olabilir.

![SDR cihazı, giriş dosyası, frekans ve örnekleme hızı seçeneklerini gösteren SigDigger ayarları](<../../images/image (245).png>)

Bilgisayarınız destekliyorsa GUI davranış ayarlarında birkaç seçeneği etkinleştirmeniz önerilir:

![SigDigger - Temel Yapılandırma: Bilgisayarınız destekliyorsa GUI davranış ayarlarında birkaç seçeneği etkinleştirmeniz önerilir](<../../images/image (472).png>)

> [!TIP]
> Bilgisayarınızın sinyalleri yakalamadığını fark ederseniz OpenGL’yi devre dışı bırakmayı ve örnekleme hızını düşürmeyi deneyin.

### Kullanım Alanları

- Bir sinyali bir süre **yakalamak ve analiz etmek** için "Push to capture" düğmesini gerektiği kadar basılı tutun.

![Temel Yapılandırma - Kullanım Alanları: Bir sinyali bir süre yakalayıp analiz etmek için "Push to capture" düğmesini gerektiği kadar basılı tutun](<../../images/image (960).png>)

- SigDigger’ın **Tuner** özelliği **sinyalleri daha iyi yakalamanıza** yardımcı olur (ancak sinyalleri bozabilir de). İdeal olarak 0’dan başlayın ve eklenen **gürültü**, ihtiyacınız olan **sinyal iyileşmesinden** daha fazla olana kadar değeri artırın.

![Yakalanan radyo sinyalini iyileştirmek için ayarlanmış SigDigger Tuner denetimi](<../../images/image (1099).png>)

### Radyo kanalıyla senkronizasyon

Duymak istediğiniz kanalla [**SigDigger** ](https://github.com/BatchDrake/SigDigger) üzerinden senkronize olun, "Baseband audio preview" seçeneğini yapılandırın, gönderilen tüm bilgileri almak için bant genişliğini ayarlayın ve ardından Tuner’ı gürültünün belirgin biçimde artmaya başladığı seviyenin hemen öncesine getirin:<sup>[[1]](#references)</sup>

![Baseband audio preview ve bant genişliği yapılandırılmış, radyo kanalıyla senkronize SigDigger](<../../images/image (585).png>)

## İlginç ipuçları

- Bir cihaz bilgi burst’leri gönderirken genellikle **ilk kısım bir preamble olur**. Bu nedenle orada **bilgi bulamazsanız** veya **hatalar varsa** endişelenmeniz **gerekmez**.
- Bilgi frame’lerinde genellikle **birbirleriyle iyi hizalanmış farklı frame’ler bulmanız gerekir**:

![Radyo kanalıyla senkronizasyon - İlginç ipuçları: Bilgi frame’lerinde genellikle birbirleriyle iyi hizalanmış farklı frame’ler bulmanız gerekir](<../../images/image (1076).png>)

![Radyo kanalıyla senkronizasyon - İlginç ipuçları: Bilgi frame’lerinde genellikle birbirleriyle iyi hizalanmış farklı frame’ler bulmanız gerekir](<../../images/image (597).png>)

- **Seviye geçişlerini elde ettikten sonra bunları decode etmeniz gerekebilir.** Manchester encoding’de geçişin bir yönü `0`, ters yönü `1` anlamına gelir; hangi yönün hangisini temsil ettiği kullanılan kurala bağlıdır.
- Payload Manchester encoding kullansa bile preamble aynı örneklenmiş seviyenin art arda tekrarlarından oluşabilir. Bu nedenle decode işleminden önce frame sınırını belirleyin.

### IQ ile modülasyon türünü belirleme

Sinyallerde bilgi saklamanın 3 yolu vardır: **genlik**, **frekans** veya **faz** modülasyonu.\
Bir sinyali incelerken hangi yöntemin bilgi saklamak için kullanıldığını anlamak üzere farklı yollar deneyebilirsiniz (daha fazla yöntem aşağıda); iyi bir yöntem IQ grafiğini incelemektir.

![Bir sinyalin genlik, frekans veya faz modülasyonu kullanıp kullanmadığını belirlemek için kullanılan SigDigger IQ grafiği](<../../images/image (788).png>)

- **AM’yi belirleme**: IQ grafiğinde örneğin **2 daire** görünüyorsa (muhtemelen biri 0’da, diğeri farklı bir genlikte), bu bir AM sinyali olabilir. IQ grafiğinde 0 noktasıyla daire arasındaki mesafe sinyalin genliğini gösterdiğinden farklı genliklerin kullanıldığını görmek kolaydır.
- **PM’yi belirleme**: Önceki görüntüde olduğu gibi, birbiriyle ilişkili görünmeyen küçük daireler görüyorsanız muhtemelen faz modülasyonu kullanılıyordur. IQ grafiğinde noktayla (0,0) arasındaki açı sinyalin fazını gösterir; bu, 4 farklı fazın kullanıldığı anlamına gelir.
  - Bilginin fazın kendisinde değil, fazın değiştirilmesinde saklandığını unutmayın. Bu durumda farklı fazları net biçimde ayırt edemezsiniz.
- **FM’yi belirleme**: IQ’da frekansları gösteren bir alan yoktur (merkeze uzaklık genliği, açı ise fazı gösterir).\
  Bu nedenle FM’yi belirlemek için bu grafikte temelde **yalnızca bir daire** görmeniz gerekir.\
  Ayrıca, frekans kayması IQ dairesi etrafındaki dönüş hızını değiştirir. Dolayısıyla SigDigger’da dönüş hızındaki veya yönündeki değişiklik FM’ye işaret edebilir.

## AM Örneği

{{#file}}
sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### AM’yi belirleme

#### Zarfı inceleme

AM verilerini [**SigDigger**](https://github.com/BatchDrake/SigDigger) ile incelerken sinyalin **zarfı**, farklı genlik seviyelerini ortaya çıkarabilir. Örnek sinyal, bilgiyi genlik modülasyonlu darbeler olarak gönderiyor; bir darbe şöyle görünür:<sup>[[1]](#references)</sup>

![Belirgin darbe genlik seviyelerine sahip SigDigger AM sinyal zarfı](<../../images/image (590).png>)

Dalga biçiminde sembolün bir kısmı şöyle görünür:

![AM’yi belirleme - Zarfı inceleme: Dalga biçiminde sembolün bir kısmı böyle görünür](<../../images/image (734).png>)

#### Histogramı inceleme

Bilginin bulunduğu **sinyalin tamamını seçebilir**, **Amplitude** modunu ve **Selection** seçeneğini seçip **Histogram** düğmesine tıklayabilirsiniz. Yalnızca 2 belirgin seviye bulunduğunu görebilirsiniz.

![Seçili AM sinyalinin iki belirgin seviyesini gösteren SigDigger genlik histogramı](<../../images/image (264).png>)

Örneğin, bu AM sinyalinde Amplitude yerine Frequency seçerseniz yalnızca 1 frekans bulursunuz (frekans modülasyonlu bilgi yalnızca 1 frekans kullanıyor olamaz).

![AM sinyali için tek bir frekans gösteren SigDigger frekans histogramı](<../../images/image (732).png>)

Çok sayıda frekans bulursanız sinyal muhtemelen FM değildir; kanal nedeniyle sinyal frekansı değişmiş olabilir.

#### IQ ile

Bu örnekte **büyük bir daire** ve merkezin çevresinde **çok sayıda nokta** olduğunu görebilirsiniz.

![Histogramı inceleme - IQ ile: Bu örnekte büyük bir daire ve merkezin çevresinde çok sayıda nokta görebilirsiniz](<../../images/image (222).png>)

### Sembol hızını bulma

#### Tek sembolle

Açıkça tek bir sembol içeren en küçük aralığı seçin ve **Selection freq** değerini kontrol edin. Bu örnekte değer 1.013 kHz, yani yaklaşık 1 kHz’dir.

![Sembol hızını bulma - Tek sembolle: Bulabildiğiniz en küçük sembol aralığını seçin (böylece yalnızca bir sembol olduğundan emin olursunuz) ve "Selection freq" değerini kontrol edin. Bu örnekte değer 1.013 kHz’dir (yani 1 kHz).](<../../images/image (78).png>)

#### Bir sembol grubuyla

Seçeceğiniz sembol sayısını da belirtebilirsiniz; SigDigger bir sembolün frekansını hesaplar (seçilen sembol sayısı arttıkça sonuç muhtemelen daha doğru olur). Bu örnekte 10 sembol seçtim ve "Selection freq" değeri 1.004 kHz:

![Seçilen on sembol grubunu kullanarak SigDigger ile sembol hızı hesaplama](<../../images/image (1008).png>)

### Bitleri elde etme

AM’yi belirleyip **sembol hızını** tahmin ettikten sonra sinyal bölgesini seçin, genlik örneklemesini ve karar seviyelerini yapılandırın, **Gardner clock recovery** seçeneğini belirleyin ve **Sample** düğmesine basın:

![AM örneklemesi, sembol hızı ve Gardner clock recovery için yapılandırılmış SigDigger Get Bits paneli](<../../images/image (965).png>)

- **Sync to selection intervals**, sembol hızını bulmak için daha önce aralıklar seçtiyseniz bu sembol hızının kullanılacağı anlamına gelir.
- **Manual**, belirtilen sembol hızının kullanılacağı anlamına gelir.
- **Fixed interval selection** seçeneğinde seçilecek aralık sayısını belirtirsiniz; araç bu değerden sembol hızını hesaplar.
- **Gardner clock recovery** kullanışlı bir varsayılan seçenektir, ancak yine de yaklaşık bir sembol hızı gerekir.

Sample düğmesine bastığınızda şu görünür:

![Bir sembol grubuyla - Bitleri elde etme: Sample düğmesine bastığınızda bu görünür](<../../images/image (644).png>)

Şimdi SigDigger’a bilgiyi taşıyan seviyenin **aralığını** göstermek için **alt seviyeye** tıklayın ve en yüksek seviyeye ulaşana kadar basılı tutun:

![Alt genlik seviyesinden üst seviyeye kadar SigDigger seviye aralığı seçimi](<../../images/image (439).png>)

Örneğin **4 farklı genlik seviyesi** olsaydı **Bits per symbol** değerini 2 olarak ayarlamanız ve en düşük seviyeden en yüksek seviyeye kadar seçim yapmanız gerekirdi.

Son olarak **Zoom** değerini artırıp **Row size** değerini değiştirerek bitleri görebilirsiniz (tüm bitleri almak için hepsini seçip kopyalayabilirsiniz):

![Bir sembol grubuyla - Bitleri elde etme: Son olarak Zoom değerini artırıp Row size değerini değiştirerek bitleri görebilirsiniz (tüm bitleri almak için hepsini seçip kopyalayabilirsiniz)](<../../images/image (276).png>)

Sinyalde sembol başına 1’den fazla bit varsa (örneğin 2), SigDigger hangi sembolün 00, 01, 10 veya 11 olduğunu **bilemez**. Her sembolü temsil etmek için farklı **gri tonları** kullanır (bitleri kopyalarsanız **0 ile 3 arasındaki sayıları** kullanır; bunları sizin işlemeniz gerekir).

**Manchester** gibi line encoding türlerinde, her geçerli geçiş çiftini (`01` veya `10`) protokolün kullandığı kurala göre bir veri bitine dönüştürün.

## FM Örneği

{{#file}}
sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### FM’yi belirleme

#### Frekansları ve dalga biçimini inceleme

FM ile modüle edilmiş bilgi gönderen örnek sinyal:

![FM’yi belirleme - Frekansları ve dalga biçimini inceleme: FM ile modüle edilmiş bilgi gönderen örnek sinyal](<../../images/image (725).png>)

Spektrumda **iki frekans** açıkça görülür, ancak bunları zaman alanındaki dalga biçiminde ayırt etmek zor olabilir:

![İki frekansı doğrudan ayırt etmenin zor olduğu SigDigger FM dalga biçimi](<../../images/image (717).png>)

Bunun nedeni, yakalamanın iki frekansın ortasında merkezlenmiş olması ve bu nedenle frekans kaymalarının yaklaşık olarak birbirinin tersi olmasıdır:

![İki frekansı yaklaşık olarak birbirinin tersi olarak gösteren SigDigger FM yakalaması](<../../images/image (942).png>)

Senkronize edilen frekans **bir frekansa diğerinden daha yakınsa** iki farklı frekansı kolayca görebilirsiniz:

![FM’yi belirleme - Frekansları ve dalga biçimini inceleme: Senkronize edilen frekans bir frekansa diğerinden daha yakınsa iki farklı frekansı kolayca görebilirsiniz](<../../images/image (422).png>)

![FM’yi belirleme - Frekansları ve dalga biçimini inceleme: Senkronize edilen frekans bir frekansa diğerinden daha yakınsa iki farklı frekansı kolayca görebilirsiniz](<../../images/image (488).png>)

#### Histogramı inceleme

Bilgi içeren sinyalin frekans histogramını incelerseniz iki farklı sinyali kolayca görebilirsiniz:

![Frekansları ve dalga biçimini inceleme - Histogramı inceleme: Bilgi içeren sinyalin frekans histogramını incelerseniz iki farklı sinyali kolayca görebilirsiniz](<../../images/image (871).png>)

Bu durumda **Amplitude histogram** seçeneğini kontrol ederseniz **yalnızca bir genlik** bulursunuz; dolayısıyla sinyal **AM olamaz** (çok sayıda genlik bulursanız bunun nedeni sinyalin kanal boyunca güç kaybetmesi olabilir):

![FM sinyali için tek bir genlik seviyesi gösteren SigDigger genlik histogramı](<../../images/image (817).png>)

Faz histogramı ise şöyledir (sinyalin faz modülasyonlu olmadığını açıkça gösterir):

![Frekansları ve dalga biçimini inceleme - Histogramı inceleme: Faz histogramı, sinyalin faz modülasyonlu olmadığını açıkça gösterir](<../../images/image (996).png>)

#### IQ ile

IQ’da frekansları gösteren bir alan yoktur (merkeze uzaklık genliği, açı ise fazı gösterir).\
Bu nedenle FM’yi belirlemek için bu grafikte temelde **yalnızca bir daire** görmeniz gerekir.\
Ayrıca, frekans kayması IQ dairesi etrafındaki dönüş hızını değiştirir. Dolayısıyla SigDigger’da dönüş hızındaki veya yönündeki değişiklik FM’ye işaret edebilir:

![FM’nin daire etrafındaki dönüş hızındaki değişikliklerle görüldüğü SigDigger IQ grafiği](<../../images/image (81).png>)

### Sembol hızını bulma

Sembol taşıyan frekansları bulduktan sonra sembol hızını belirlemek için **AM örneğinde kullanılan tekniğin aynısını** kullanabilirsiniz.

### Bitleri elde etme

Sinyalin **frekans modülasyonlu** olduğunu ve **sembol hızını** belirledikten sonra bitleri elde etmek için **AM örneğinde kullanılan tekniğin aynısını** kullanabilirsiniz.

## References

- [1] [SigDigger - GNU/Linux ve macOS için ücretsiz dijital sinyal analiz aracı](https://github.com/BatchDrake/SigDigger)
{{#include ../../banners/hacktricks-training.md}}
