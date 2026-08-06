# Radio

{{#include ../../banners/hacktricks-training.md}}

## SigDigger

[**SigDigger** ](https://github.com/BatchDrake/SigDigger), bilinmeyen radyo sinyallerinden bilgi çıkarmak için tasarlanmış, GNU/Linux ve macOS için ücretsiz bir digital signal analyzer'dır. SoapySDR aracılığıyla çeşitli SDR cihazlarını destekler ve FSK, PSK ve ASK sinyallerinin ayarlanabilir demodülasyonuna, analog videonun decode edilmesine, bursty sinyallerin analiz edilmesine ve analog voice channel'ların dinlenmesine olanak tanır (tümü real time olarak).<sup>[[1]](#references)</sup>

### Basic Config

Kurulumdan sonra yapılandırmayı düşünebileceğiniz birkaç şey vardır.\
Settings bölümünde (ikinci tab düğmesi) **SDR device**'ı veya okunacak **bir dosyayı** seçebilir, syntonise edilecek frekansı ve Sample rate'i belirleyebilirsiniz (PC'niz destekliyorsa önerilen değer 2.56Msps'e kadardır).

![SDR device, input file, frequency ve sample rate seçeneklerini gösteren SigDigger ayarları](<../../images/image (245).png>)

GUI behaviour bölümünde, PC'niz destekliyorsa birkaç seçeneği etkinleştirmeniz önerilir:

![SigDigger - Basic Config: GUI behaviour bölümünde PC'niz destekliyorsa birkaç seçeneği etkinleştirmeniz önerilir](<../../images/image (472).png>)

> [!TIP]
> PC'nizin sinyalleri capture etmediğini fark ederseniz OpenGL'i devre dışı bırakmayı ve sample rate'i düşürmeyi deneyin.

### Uses

- Bir sinyalin **bir süreliğine capture edilmesi ve analiz edilmesi** için ihtiyacınız olduğu sürece "Push to capture" düğmesini basılı tutun.

![Basic Config - Uses: Bir sinyali bir süreliğine capture edip analiz etmek için ihtiyacınız olduğu sürece "Push to capture" düğmesini basılı tutun](<../../images/image (960).png>)

- SigDigger'ın **Tuner**'ı **daha iyi sinyaller capture etmenize** yardımcı olur (ancak sinyalleri bozabilir de). İdeal olarak 0 ile başlayın ve eklenen **noise**'un ihtiyacınız olan **signal improvement**'ından daha büyük olduğunu fark edene kadar **değeri artırmaya devam edin**.

![Capture edilen radyo sinyalini iyileştirmek için ayarlanmış SigDigger tuner kontrolü](<../../images/image (1099).png>)

### Synchronize with radio channel

[**SigDigger** ](https://github.com/BatchDrake/SigDigger) ile duymak istediğiniz channel ile synchronize olun, "Baseband audio preview" seçeneğini yapılandırın, gönderilen tüm bilgileri alacak şekilde bandwith'i ayarlayın ve ardından noise gerçekten artmaya başlamadan önceki seviyeye Tuner'ı ayarlayın:<sup>[[1]](#references)</sup>

![Baseband audio preview ve yapılandırılmış bandwidth ile synchronize edilmiş SigDigger radyo channel'ı](<../../images/image (585).png>)

## Interesting tricks

- Bir cihaz bilgi burst'leri gönderirken genellikle **ilk kısım bir preamble** olur; bu nedenle **orada bilgi bulamazsanız** veya **bazı hatalar varsa** **endişelenmenize gerek yoktur**.
- Bilgi frame'lerinde genellikle **birbirleriyle iyi hizalanmış farklı frame'ler bulmanız gerekir**:

![Synchronize with radio channel - Interesting tricks: Bilgi frame'lerinde genellikle birbirleriyle iyi hizalanmış farklı frame'ler bulmanız gerekir](<../../images/image (1076).png>)

![Synchronize with radio channel - Interesting tricks: Bilgi frame'lerinde genellikle birbirleriyle iyi hizalanmış farklı frame'ler bulmanız gerekir](<../../images/image (597).png>)

- **Bit'leri recover ettikten sonra onları bir şekilde process etmeniz gerekebilir**. Örneğin Manchester codification'da up+down 1 veya 0, down+up ise diğeri olur. Dolayısıyla 1 ve 0 çiftleri (up ve down'lar) gerçek bir 1 veya gerçek bir 0 olacaktır.
- Bir sinyal Manchester codification kullanıyor olsa bile (art arda ikiden fazla 0 veya 1 bulmak mümkün değildir), **preamble içinde bir arada birkaç 1 veya 0 bulabilirsiniz**!

### Uncovering modulation type with IQ

Sinyallerde bilgi depolamanın 3 yolu vardır: **amplitude**, **frequency** veya **phase**'i modüle etmek.\
Bir sinyali inceliyorsanız, bilgiyi depolamak için hangisinin kullanıldığını anlamaya çalışmanın farklı yolları vardır (aşağıda daha fazla yol verilmiştir); ancak iyi yöntemlerden biri IQ grafiğini kontrol etmektir.

![Bir sinyalin amplitude, frequency veya phase modulation kullanıp kullanmadığını belirlemek için kullanılan SigDigger IQ grafiği](<../../images/image (788).png>)

- **AM tespiti**: IQ grafiğinde örneğin **2 circle** görünüyorsa (muhtemelen biri 0'da, diğeri farklı bir amplitude'de), bu bir AM sinyali olabilir. Bunun nedeni IQ grafiğinde 0 ile circle arasındaki mesafenin sinyalin amplitude'ü olmasıdır; dolayısıyla kullanılan farklı amplitude'leri görselleştirmek kolaydır.
- **PM tespiti**: Önceki görselde olduğu gibi, birbirleriyle ilişkili olmayan küçük circle'lar bulursanız muhtemelen phase modulation kullanılıyordur. Bunun nedeni IQ grafiğinde nokta ile 0,0 arasındaki açının sinyalin phase'i olmasıdır; bu da 4 farklı phase kullanıldığı anlamına gelir.
- Bilginin phase'in kendisinde değil, bir phase'in değiştirilmiş olması gerçeğinde gizli olduğunu unutmayın; bu durumda farklı phase'leri net biçimde ayrılmış olarak göremezsiniz.
- **FM tespiti**: IQ'da frequency'leri tanımlayacak bir alan yoktur (merkeze uzaklık amplitude, açı ise phase'dir).\
Bu nedenle FM'i belirlemek için bu grafikte temelde **yalnızca bir circle görmeniz gerekir**.\
Ayrıca farklı bir frequency, IQ grafiğinde **circle boyunca hızlanma** ile "temsil edilir" (yani SysDigger'da sinyali seçtiğinizde IQ grafiği doldurulur; oluşan circle'da bir hızlanma veya yön değişikliği bulursanız bu FM anlamına gelebilir):

## AM Example

{{#file}}
sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Uncovering AM

#### Checking the envelope

[**SigDigger** ](https://github.com/BatchDrake/SigDigger) ile AM bilgisini kontrol ederken ve yalnızca **envelope**'a bakarken farklı ve net amplitude seviyeleri görebilirsiniz. Kullanılan sinyal AM'de bilgi içeren pulse'lar gönderiyor; bir pulse şu şekilde görünür:<sup>[[1]](#references)</sup>

![Net pulse amplitude seviyelerine sahip SigDigger AM sinyal envelope'u](<../../images/image (590).png>)

Bir symbol'ün waveform ile birlikte bir kısmı ise şu şekilde görünür:

![Uncovering AM - Checking the envelope: Bir symbol'ün waveform ile birlikte bir kısmı](<../../images/image (734).png>)

#### Checking the Histogram

Bilginin bulunduğu **tüm sinyali seçebilir**, **Amplitude** mode ve **Selection**'ı seçip **Histogram**'a tıklayabilirsiniz. Yalnızca 2 net seviyenin bulunduğunu gözlemleyebilirsiniz.

![Seçili AM sinyali için iki net seviye gösteren SigDigger amplitude histogram'ı](<../../images/image (264).png>)

Örneğin bu AM sinyalinde Amplitude yerine Frequency'i seçerseniz yalnızca 1 frequency bulursunuz (frequency'de modüle edilen bilginin yalnızca 1 frequency kullanmasının bir yolu yoktur).

![AM sinyali için tek frequency gösteren SigDigger frequency histogram'ı](<../../images/image (732).png>)

Çok sayıda frequency bulursanız bu muhtemelen FM değildir; channel nedeniyle yalnızca sinyalin frequency'si değiştirilmiş olabilir.

#### With IQ

Bu örnekte **büyük bir circle** olduğunu, ancak aynı zamanda **merkezde çok sayıda nokta** bulunduğunu görebilirsiniz.

![Checking the Histogram - With IQ: Bu örnekte büyük bir circle ve merkezde çok sayıda nokta](<../../images/image (222).png>)

### Get Symbol Rate

#### With one symbol

Bulabildiğiniz en küçük symbol'ü seçin (böylece yalnızca 1 olduğundan emin olursunuz) ve "Selection freq" değerini kontrol edin. Bu durumda değer 1.013kHz (yani 1kHz) olur.

![Get Symbol Rate - With one symbol: Bulabildiğiniz en küçük symbol'ü seçin ve "Selection freq" değerini kontrol edin. Bu durumda değer 1.013kHz'dir (yani 1kHz)](<../../images/image (78).png>)

#### With a group of symbols

Seçeceğiniz symbol sayısını da belirtebilirsiniz; SigDigger 1 symbol'ün frequency'sini hesaplar (muhtemelen ne kadar çok symbol seçilirse sonuç o kadar iyi olur). Bu senaryoda 10 symbol seçtim ve "Selection freq" değeri 1.004 Khz:

![Seçili on symbol grubunu kullanarak SigDigger symbol-rate hesaplaması](<../../images/image (1008).png>)

### Get Bits

Bunun **AM modulated** bir sinyal ve **symbol rate** olduğunu bulduktan sonra (ve bu durumda yukarı yönün 1, aşağı yönün 0 anlamına geldiğini bildiğinizden), sinyalde encoded edilmiş **bit'leri elde etmek** çok kolaydır. Bilgi içeren sinyali seçin, sampling ve decision'ı yapılandırın ve sample'a basın ( **Amplitude**'ın seçili olduğunu, bulunan **Symbol rate**'in yapılandırıldığını ve **Gadner clock recovery**'nin seçili olduğunu kontrol edin):

![AM sampling, symbol rate ve Gardner clock recovery için yapılandırılmış SigDigger Get Bits paneli](<../../images/image (965).png>)

- **Sync to selection intervals**, symbol rate'i bulmak için daha önce interval'lar seçtiyseniz bu symbol rate'in kullanılacağı anlamına gelir.
- **Manual**, belirtilen symbol rate'in kullanılacağı anlamına gelir.
- **Fixed interval selection** bölümünde seçilmesi gereken interval sayısını belirtirsiniz; SigDigger buradan symbol rate'i hesaplar.
- **Gadner clock recovery** genellikle en iyi seçenektir; ancak yine de yaklaşık bir symbol rate belirtmeniz gerekir.

Sample'a bastığınızda şu görünür:

![With a group of symbols - Get Bits: Sample'a basıldığında görünen ekran](<../../images/image (644).png>)

Şimdi SigDigger'ın bilgi taşıyan seviyenin **range'inin nerede olduğunu anlaması** için **alt seviyeye** tıklayıp en yüksek seviyeye ulaşana kadar tıklamayı sürdürmeniz gerekir:

![Alt amplitude seviyesinden üst seviyeye kadar SigDigger level-range seçimi](<../../images/image (439).png>)

Örneğin **4 farklı amplitude seviyesi** olsaydı **Bits per symbol'ü 2** olarak yapılandırmanız ve en düşük seviyeden en yüksek seviyeye kadar seçim yapmanız gerekirdi.

Son olarak **Zoom'u artırıp** **Row size'ı değiştirerek** bit'leri görebilirsiniz (tümünü seçip kopyalayarak bütün bit'leri alabilirsiniz):

![With a group of symbols - Get Bits: Zoom'u artırıp Row size'ı değiştirerek bit'leri görebilirsiniz](<../../images/image (276).png>)

Sinyal symbol başına 1'den fazla bit içeriyorsa (örneğin 2), SigDigger hangi symbol'ün 00, 01, 10 veya 11 olduğunu bilemez; bu nedenle her birini temsil etmek için farklı **grey scale**'ler kullanır (bit'leri kopyalarsanız **0 ile 3 arasındaki sayıları** kullanır; bunları process etmeniz gerekir).

Ayrıca **codification** olarak **Manchester** kullanıldığında **up+down** 1 veya 0, down+up ise 1 veya 0 olabilir. Bu durumlarda elde edilen up'ları (1) ve down'ları (0) process ederek 01 veya 10 çiftlerini 0 veya 1 ile değiştirmeniz gerekir.

## FM Example

{{#file}}
sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Uncovering FM

#### Checking the frequencies and waveform

FM'de modüle edilmiş bilgi gönderen bir sinyal örneği:

![Uncovering FM - Checking the frequencies and waveform: FM'de modüle edilmiş bilgi gönderen sinyal](<../../images/image (725).png>)

Önceki görselde **2 frequency kullanıldığını** oldukça iyi gözlemleyebilirsiniz; ancak **waveform'u incelerseniz** **2 farklı frequency'yi doğru şekilde tanımlayamayabilirsiniz**:

![İki frequency'nin doğrudan ayırt edilmesinin zor olduğu SigDigger FM waveform'u](<../../images/image (717).png>)

Bunun nedeni sinyali her iki frequency'de capture etmemdir; dolayısıyla biri yaklaşık olarak diğerinin negative'idir:

![İki frequency'yi birbirlerinin yaklaşık negative'i olarak gösteren SigDigger FM capture'ı](<../../images/image (942).png>)

Synchronized frequency **bir frequency'ye diğerinden daha yakınsa** 2 farklı frequency'yi kolayca görebilirsiniz:

![Uncovering FM - Checking the frequencies and waveform: Synchronized frequency bir frequency'ye diğerinden daha yakınsa 2 farklı frequency'yi kolayca görebilirsiniz](<../../images/image (422).png>)

![Uncovering FM - Checking the frequencies and waveform: Synchronized frequency bir frequency'ye diğerinden daha yakınsa 2 farklı frequency'yi kolayca görebilirsiniz](<../../images/image (488).png>)

#### Checking the histogram

Bilgi içeren sinyalin frequency histogram'ını kontrol ettiğinizde 2 farklı sinyali kolayca görebilirsiniz:

![Checking the frequencies and waveform - Checking the histogram: Bilgi içeren sinyalin frequency histogram'ını kontrol ettiğinizde 2 farklı sinyal görebilirsiniz](<../../images/image (871).png>)

Bu durumda **Amplitude histogram**'ını kontrol ederseniz **yalnızca bir amplitude** bulursunuz; dolayısıyla sinyal **AM olamaz** (çok sayıda amplitude bulursanız bunun nedeni channel boyunca sinyalin güç kaybetmiş olması olabilir):

![Tek bir amplitude seviyesi gösteren SigDigger FM sinyali amplitude histogram'ı](<../../images/image (817).png>)

Phase histogram'ı ise şu şekilde olur (sinyalin phase'de modüle edilmediğini oldukça net gösterir):

![Checking the frequencies and waveform - Checking the histogram: Sinyalin phase'de modüle edilmediğini net biçimde gösteren phase histogram'ı](<../../images/image (996).png>)

#### With IQ

IQ'da frequency'leri tanımlayacak bir alan yoktur (merkeze uzaklık amplitude, açı ise phase'dir).\
Bu nedenle FM'i belirlemek için bu grafikte temelde **yalnızca bir circle görmeniz gerekir**.\
Ayrıca farklı bir frequency, IQ grafiğinde **circle boyunca hızlanma** ile "temsil edilir" (yani SysDigger'da sinyali seçtiğinizde IQ grafiği doldurulur; oluşan circle'da bir hızlanma veya yön değişikliği bulursanız bu FM anlamına gelebilir):

![FM'in circle çevresindeki hızlanma değişiklikleri olarak göründüğü SigDigger IQ grafiği](<../../images/image (81).png>)

### Get Symbol Rate

Symbol'leri taşıyan frequency'leri bulduktan sonra symbol rate'i elde etmek için **AM example'da kullanılan tekniğin aynısını** kullanabilirsiniz.

### Get Bits

Sinyalin **frequency'de modüle edildiğini** ve **symbol rate'i** bulduktan sonra bit'leri elde etmek için **AM example'da kullanılan tekniğin aynısını** kullanabilirsiniz.

## References

- [1] [SigDigger - GNU/Linux ve macOS için ücretsiz digital signal analyzer](https://github.com/BatchDrake/SigDigger)

{{#include ../../banners/hacktricks-training.md}}
