# Radyo

{{#include ../../banners/hacktricks-training.md}}

## SigDigger

[**SigDigger** ](https://github.com/BatchDrake/SigDigger), bilinmeyen radyo sinyallerinin bilgilerini çıkarmak için tasarlanmış, GNU/Linux ve macOS için ücretsiz bir dijital sinyal analizörüdür. SoapySDR aracılığıyla çeşitli SDR cihazlarını destekler ve FSK, PSK ve ASK sinyallerinin ayarlanabilir demodülasyonunu, analog video çözümlemesini, patlayıcı sinyalleri analiz etmeyi ve analog ses kanallarını dinlemeyi (hepsi gerçek zamanlı) sağlar.

### Temel Konfigürasyon

Kurulumdan sonra yapılandırmayı düşünebileceğiniz birkaç şey vardır.\
Ayarlar (ikinci sekme düğmesi) kısmında **SDR cihazını** seçebilir veya **bir dosya** seçerek okunacak dosyayı ve senkronize edilecek frekansı ve örnekleme hızını (PC'niz destekliyorsa 2.56Msps'a kadar önerilir) ayarlayabilirsiniz.\\

![](<../../images/image (245).png>)

GUI davranışında, PC'niz destekliyorsa birkaç şeyi etkinleştirmeniz önerilir:

![](<../../images/image (472).png>)

> [!NOTE]
> Eğer PC'nizin bir şeyleri yakalamadığını fark ederseniz, OpenGL'i devre dışı bırakmayı ve örnekleme hızını düşürmeyi deneyin.

### Kullanımlar

- Sadece **bir sinyalin bir kısmını yakalamak ve analiz etmek** için "Yakalamak için bas" düğmesini ihtiyacınız olduğu sürece basılı tutun.

![](<../../images/image (960).png>)

- SigDigger'ın **Tuner'ı**, **daha iyi sinyaller yakalamaya** yardımcı olur (ancak bunları da bozabilir). İdeal olarak 0 ile başlayın ve **sinyalin iyileşmesinden daha büyük** olan **gürültüyü** bulana kadar **büyütmeye devam edin**.

![](<../../images/image (1099).png>)

### Radyo kanalı ile senkronize olma

[**SigDigger** ](https://github.com/BatchDrake/SigDigger) ile duymak istediğiniz kanal ile senkronize olun, "Temel bant ses önizlemesi" seçeneğini yapılandırın, gönderilen tüm bilgileri almak için bant genişliğini ayarlayın ve ardından Tuner'ı gürültünün gerçekten artmaya başlamadan önceki seviyeye ayarlayın:

![](<../../images/image (585).png>)

## İlginç ipuçları

- Bir cihaz bilgi patlamaları gönderdiğinde, genellikle **ilk kısım bir öncül olacaktır**, bu yüzden orada **bilgi bulamazsanız** veya **bazı hatalar varsa** endişelenmenize gerek yoktur.
- Bilgi çerçevelerinde genellikle **birbirleriyle iyi hizalanmış farklı çerçeveler bulmalısınız**:

![](<../../images/image (1076).png>)

![](<../../images/image (597).png>)

- **Bitleri geri aldıktan sonra, bunları bir şekilde işlemeniz gerekebilir**. Örneğin, Manchester kodlamasında yukarı+aşağı bir 1 veya 0, aşağı+yukarı ise diğeridir. Yani 1'lerin ve 0'ların (yukarı ve aşağı) çiftleri gerçek bir 1 veya gerçek bir 0 olacaktır.
- Bir sinyal Manchester kodlaması kullanıyorsa (bir sırada iki 0 veya 1'den fazlasını bulmak imkansızdır), **öncül içinde birden fazla 1 veya 0 bulabilirsiniz**!

### IQ ile modülasyon türünü açığa çıkarma

Sinyallerde bilgiyi depolamanın 3 yolu vardır: **amplitüd**, **frekans** veya **faz** modüle etmek.\
Bir sinyali kontrol ediyorsanız, bilgiyi depolamak için neyin kullanıldığını anlamanın farklı yolları vardır (aşağıda daha fazla yol bulabilirsiniz) ancak iyi bir yol IQ grafiğini kontrol etmektir.

![](<../../images/image (788).png>)

- **AM'yi tespit etme**: IQ grafiğinde örneğin **2 daire** görünüyorsa (muhtemelen biri 0'da ve diğeri farklı bir amplitüde), bu bir AM sinyali olduğu anlamına gelebilir. Bunun nedeni, IQ grafiğinde 0 ile daire arasındaki mesafenin sinyalin amplitüdü olmasıdır, bu nedenle kullanılan farklı amplitüdlere görsel olarak ulaşmak kolaydır.
- **PM'yi tespit etme**: Önceki resimde olduğu gibi, eğer birbirleriyle ilişkili olmayan küçük daireler bulursanız, bu muhtemelen bir faz modülasyonunun kullanıldığı anlamına gelir. Bunun nedeni, IQ grafiğinde nokta ile 0,0 arasındaki açının sinyalin fazı olmasıdır, bu da 4 farklı fazın kullanıldığı anlamına gelir.
- Bilginin, bir fazın değişmesi gerçeğinde gizli olduğunu ve fazın kendisinde olmadığını unutmayın, farklı fazları net bir şekilde ayırt edemezsiniz.
- **FM'yi tespit etme**: IQ'nun frekansları tanımlamak için bir alanı yoktur (merkeze olan mesafe amplitüd ve açı fazdır).\
Bu nedenle, FM'yi tanımlamak için bu grafikte **temelde sadece bir daire görmelisiniz**.\
Ayrıca, farklı bir frekans IQ grafiğinde **daire boyunca bir hız ivmesi** ile "temsil edilir" (bu nedenle SysDigger'da sinyali seçtiğinizde IQ grafiği doldurulur, eğer oluşturulan dairede bir ivme veya yön değişikliği bulursanız bu FM olabilir):

## AM Örneği

{{#file}}
sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### AM'yi açığa çıkarma

#### Zarfı kontrol etme

[**SigDigger** ](https://github.com/BatchDrake/SigDigger) ile AM bilgilerini kontrol ederken ve sadece **zarfı** inceleyerek farklı net amplitüd seviyeleri görebilirsiniz. Kullanılan sinyal, AM'de bilgi gönderen darbeler gönderiyor, bir darbenin görünümü şöyle:

![](<../../images/image (590).png>)

Ve bu da dalga formuyla sembolün bir kısmının görünümüdür:

![](<../../images/image (734).png>)

#### Histogramı kontrol etme

Bilgi bulunan **tüm sinyali** seçebilir, **Amplitüd** modunu ve **Seçim**'i seçebilir ve **Histogram**'a tıklayabilirsiniz. İki net seviyenin yalnızca bulunduğunu gözlemleyebilirsiniz.

![](<../../images/image (264).png>)

Örneğin, bu AM sinyalinde Amplitüd yerine Frekansı seçerseniz sadece 1 frekans bulursunuz (frekans modülasyonunda bilgi sadece 1 frekans kullanıyorsa).

![](<../../images/image (732).png>)

Eğer birçok frekans bulursanız, bu muhtemelen bir FM olmayacaktır, sinyal frekansı sadece kanal nedeniyle değiştirilmiş olabilir.

#### IQ ile

Bu örnekte, **büyük bir daire** olduğunu ancak aynı zamanda **merkezde birçok nokta** olduğunu görebilirsiniz.

![](<../../images/image (222).png>)

### Sembol Hızını Alma

#### Bir sembolle

Bulduğunuz en küçük sembolü seçin (böylece sadece 1 olduğundan emin olursunuz) ve "Seçim frekansı"nı kontrol edin. Bu durumda 1.013kHz (yani 1kHz) olacaktır.

![](<../../images/image (78).png>)

#### Bir grup sembolle

Seçmek istediğiniz sembol sayısını da belirtebilir ve SigDigger 1 sembolün frekansını hesaplayacaktır (seçilen sembol sayısı arttıkça muhtemelen daha iyi olacaktır). Bu senaryoda 10 sembol seçtim ve "Seçim frekansı" 1.004 kHz:

![](<../../images/image (1008).png>)

### Bitleri Alma

Bu bir **AM modüle edilmiş** sinyal olduğunu ve **sembol hızını** bulduğunuzu (ve bu durumda yukarı bir şeyin 1 ve aşağı bir şeyin 0 anlamına geldiğini bilerek), sinyalde kodlanmış **bitleri elde etmek** çok kolaydır. Bu nedenle, bilgiyi içeren sinyali seçin ve örnekleme ve karar verme ayarlarını yapılandırın ve örnekle düğmesine basın (lütfen **Amplitüd**'ün seçili olduğundan, keşfedilen **Sembol hızının** yapılandırıldığından ve **Gadner saat geri kazanımının** seçildiğinden emin olun):

![](<../../images/image (965).png>)

- **Seçim aralıklarına senkronize olma**, daha önce sembol hızını bulmak için aralıklar seçtiyseniz, o sembol hızı kullanılacaktır.
- **Manuel**, belirtilen sembol hızının kullanılacağı anlamına gelir.
- **Sabit aralık seçimi** ile seçilmesi gereken aralık sayısını belirtirsiniz ve sembol hızını buradan hesaplar.
- **Gadner saat geri kazanımı** genellikle en iyi seçenektir, ancak yine de bazı yaklaşık sembol hızlarını belirtmeniz gerekir.

Örnekle düğmesine bastığınızda bu görünür:

![](<../../images/image (644).png>)

Artık SigDigger'ın **bilgi taşıyan seviyenin aralığını** anlaması için **alt seviyeye** tıklayıp en büyük seviyeye kadar basılı tutmanız gerekir:

![](<../../images/image (439).png>)

Eğer örneğin **4 farklı amplitüd seviyesi** olsaydı, **Sembol başına bit sayısını 2** olarak yapılandırmanız ve en küçüğünden en büyüğüne kadar seçmeniz gerekirdi.

Son olarak, **Zoom**'u **artırarak** ve **Satır boyutunu** **değiştirerek** bitleri görebilirsiniz (ve tüm bitleri almak için hepsini seçip kopyalayabilirsiniz):

![](<../../images/image (276).png>)

Eğer sinyalin sembol başına 1'den fazla biti varsa (örneğin 2), SigDigger **hangi sembolün** 00, 01, 10, 11 olduğunu bilmenin bir yoluna sahip değildir, bu nedenle her birini temsil etmek için farklı **gri tonları** kullanacaktır (ve eğer bitleri kopyalarsanız **0'dan 3'e kadar** sayılar kullanacaktır, bunları işlemeniz gerekecektir).

Ayrıca, **Manchester** gibi **kodlamalar** kullanın ve **yukarı+aşağı** **1 veya 0** olabilir ve aşağı+yukarı bir 1 veya 0 olabilir. Bu durumlarda, elde edilen yukarıları (1) ve aşağıları (0) **işlemeniz** gerekir, böylece 01 veya 10 çiftlerini 0 veya 1 olarak değiştirebilirsiniz.

## FM Örneği

{{#file}}
sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### FM'yi açığa çıkarma

#### Frekansları ve dalga formunu kontrol etme

FM'de modüle edilmiş bilgi gönderen sinyal örneği:

![](<../../images/image (725).png>)

Önceki resimde, **2 frekansın kullanıldığını** oldukça iyi gözlemleyebilirsiniz, ancak **dalga formunu** incelerseniz **2 farklı frekansı doğru bir şekilde tanımlamakta zorlanabilirsiniz**:

![](<../../images/image (717).png>)

Bu, sinyali her iki frekansta da yakaladığım için, bu nedenle biri diğerinin negatifine yaklaşık olarak eşittir:

![](<../../images/image (942).png>)

Eğer senkronize frekans **bir frekansa diğerine göre daha yakınsa**, 2 farklı frekansı kolayca görebilirsiniz:

![](<../../images/image (422).png>)

![](<../../images/image (488).png>)

#### Histogramı kontrol etme

Bilgi içeren sinyalin frekans histogramını kontrol ettiğinizde, 2 farklı sinyali kolayca görebilirsiniz:

![](<../../images/image (871).png>)

Bu durumda, **Amplitüd histogramını** kontrol ederseniz **sadece bir amplitüd** bulursunuz, bu nedenle **AM olamaz** (eğer birçok amplitüd bulursanız, bu muhtemelen sinyalin kanal boyunca güç kaybettiği anlamına gelir):

![](<../../images/image (817).png>)

Ve bu da faz histogramı olacaktır (bu, sinyalin fazda modüle edilmediğini çok net bir şekilde gösterir):

![](<../../images/image (996).png>)

#### IQ ile

IQ'nun frekansları tanımlamak için bir alanı yoktur (merkeze olan mesafe amplitüd ve açı fazdır).\
Bu nedenle, FM'yi tanımlamak için bu grafikte **temelde sadece bir daire görmelisiniz**.\
Ayrıca, farklı bir frekans IQ grafiğinde **daire boyunca bir hız ivmesi** ile "temsil edilir" (bu nedenle SysDigger'da sinyali seçtiğinizde IQ grafiği doldurulur, eğer oluşturulan dairede bir ivme veya yön değişikliği bulursanız bu FM olabilir):

![](<../../images/image (81).png>)

### Sembol Hızını Alma

Sembolleri taşıyan frekansları bulduktan sonra, sembol hızını almak için **AM örneğinde kullanılan aynı tekniği** kullanabilirsiniz.

### Bitleri Alma

Sinyalin **frekans modüle edildiğini** ve **sembol hızını** bulduktan sonra, bitleri almak için **AM örneğinde kullanılan aynı tekniği** kullanabilirsiniz.

{{#include ../../banners/hacktricks-training.md}}
