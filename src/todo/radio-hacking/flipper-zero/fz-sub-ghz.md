# FZ - Sub-GHz

{{#include ../../../banners/hacktricks-training.md}}

## Giriş <a href="#introduction" id="introduction"></a>

Flipper Zero, yapılandırılan bölgeye yönelik frekans kısıtlamalarına tabi olarak, yerleşik modülüyle **300-928 MHz aralığındaki radyo frekanslarını alabilir ve iletebilir**. Kapılar, bariyerler, radyo kilitleri, anahtarlar, kablosuz kapı zilleri, akıllı ışıklar ve diğer cihazlarda kullanılan uyumlu uzaktan kumandaları okuyabilir, kaydedebilir ve emüle edebilir.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (714).png" alt=""><figcaption></figcaption></figure>

## Sub-GHz Donanımı <a href="#sub-ghz-hardware" id="sub-ghz-hardware"></a>

Flipper Zero, bir CC1101 transceiver ve radyo antenine dayanan yerleşik bir sub-1 GHz modülüne sahiptir. Gerçek menzil; frekansa, antene, ortama ve vericiye bağlıdır. Flipper, uygun koşullarda yaklaşık 50 metreye kadar menzil belirtir. Donanım 300-348 MHz, 387-464 MHz ve 779-928 MHz aralıklarını kapsarken firmware ve bölgesel kurallar iletim işlemini daha da kısıtlar.<sup>[[1]](#references)[[2]](#references)</sup>

<figure><img src="../../../images/image (923).png" alt=""><figcaption></figcaption></figure>

## İşlemler

### Frequency Analyser

> [!TIP]
> Kumandanın kullandığı frekans nasıl bulunur

Analiz sırasında Flipper Zero, frekans yapılandırmasında kullanılabilen tüm frekanslarda sinyal gücünü (RSSI) tarar. Flipper Zero, -90 [dBm](https://en.wikipedia.org/wiki/DBm) değerinden daha güçlü sinyaller arasındaki en yüksek RSSI değerine sahip frekansı gösterir.<sup>[[1]](#references)</sup>

Kumandanın frekansını belirlemek için aşağıdakileri yapın:

1. Kumandayı Flipper Zero'nun sol tarafına, cihaza çok yakın olacak şekilde yerleştirin.
2. **Main Menu** **→ Sub-GHz** menüsüne gidin.
3. **Frequency Analyzer** seçeneğini belirleyin, ardından analiz etmek istediğiniz kumandanın düğmesine basılı tutun.
4. Ekrandaki frekans değerini kontrol edin.

### Read

> [!TIP]
> Kullanılan frekans hakkında bilgi edinin (kullanılan frekansı bulmanın başka bir yolu)

**Read** seçeneği, yapılandırılan frekans ve modulation üzerinde dinleme yapar (varsayılan olarak 433.92 MHz AM). Desteklenen bir sinyali tanıdığında ekran, daha sonra kaydedilebilecek ve yeniden oynatılabilecek bilgileri gösterir.<sup>[[1]](#references)</sup>

Read kullanılırken **sol düğmeye** basıp **yapılandırma yapmak** mümkündür.\
Şu anda **4 modulation** (AM270, AM650, FM328 ve FM476) ve kayıtlı **birkaç ilgili frekans** bulunmaktadır:

<figure><img src="../../../images/image (947).png" alt=""><figcaption></figcaption></figure>

İzin verilen herhangi bir frekansı seçebilirsiniz. Kumandanın hangi frekansı kullandığından emin değilseniz **Hopping'i ON** (varsayılan olarak kapalı) konumuna getirin, ardından Flipper sinyali yakalayıp frekansı bildirene kadar kumanda düğmesine birkaç kez basın.

> [!CAUTION]
> Frekanslar arasında geçiş yapmak biraz zaman alır. Bu nedenle geçiş sırasında iletilen sinyaller kaçırılabilir. Daha iyi sinyal alımı için Frequency Analyzer tarafından belirlenen sabit bir frekans ayarlayın.

### **Read Raw**

> [!TIP]
> Yapılandırılan frekanstaki bir sinyali ele geçirin (ve yeniden oynatın)

**Read Raw** seçeneği, seçilen frekansta gönderilen sinyalleri kaydeder. Bu özellik, yetkili testler sırasında bir sinyali yakalayıp yeniden oynatmak için kullanılabilir.<sup>[[1]](#references)</sup>

Varsayılan olarak **Read Raw, AM650 ile 433.92 MHz** kullanır. Read seçeneği farklı bir frekans veya modulation üzerinde sinyal bulduysa, bu ayarları değiştirmek için Read Raw içinde Sol düğmeye basın.

### Brute-Force

Bir garaj kapısı gibi bir cihaz tarafından kullanılan protokolü biliyorsanız, **aday kodlar oluşturmak ve bunları Flipper Zero ile iletmek** mümkün olabilir. `flipperzero-bruteforce` projesi, yaygın birkaç static-code protokolünü destekler.<sup>[[3]](#references)</sup>

### Add Manually

> [!TIP]
> Yapılandırılmış bir protokol listesinden sinyal ekleyin

#### Desteklenen protokollerin listesi <a href="#id-3iglu" id="id-3iglu"></a>

Add Manually menüsü, Flipper Zero tarafından belgelenen protokol preset'lerini sunar.<sup>[[4]](#references)</sup>

| Princeton_433 (statik kod sistemlerinin çoğuyla çalışır) | 433.92 | Static  |
| -------------------------------------------------------- | ------ | ------- |
| Nice Flo 12bit_433                                       | 433.92 | Static  |
| Nice Flo 24bit_433                                       | 433.92 | Static  |
| CAME 12bit_433                                           | 433.92 | Static  |
| CAME 24bit_433                                           | 433.92 | Static  |
| Linear_300                                               | 300.00 | Static  |
| CAME TWEE                                                | 433.92 | Static  |
| Gate TX_433                                              | 433.92 | Static  |
| DoorHan_315                                              | 315.00 | Dynamic |
| DoorHan_433                                              | 433.92 | Dynamic |
| LiftMaster_315                                           | 315.00 | Dynamic |
| LiftMaster_390                                           | 390.00 | Dynamic |
| Security+2.0_310                                         | 310.00 | Dynamic |
| Security+2.0_315                                         | 315.00 | Dynamic |
| Security+2.0_390                                         | 390.00 | Dynamic |

### Desteklenen Sub-GHz vendor'ları

Flipper Zero'nun supported-vendors listesini kontrol edin.<sup>[[5]](#references)</sup>

### Bölgeye göre desteklenen frekanslar

İletim yapmadan önce resmi regional-frequency listesini kontrol edin.<sup>[[6]](#references)</sup>

### Test

> [!TIP]
> Kaydedilen frekansların dBm değerlerini alın

## References

- [1] [Sub-GHz - Flipper Zero Kullanıcı Dokümantasyonu](https://docs.flipperzero.one/sub-ghz)
- [2] [Texas Instruments CC1101 veri sayfası](https://www.ti.com/lit/ds/symlink/cc1101.pdf)
- [3] [tobiabocchi/flipperzero-bruteforce](https://github.com/tobiabocchi/flipperzero-bruteforce)
- [4] [Flipper Zero - Manuel olarak oluşturulmuş bir kumanda ekleme](https://docs.flipperzero.one/sub-ghz/add-new-remote)
- [5] [Flipper Zero - Desteklenen Sub-GHz vendor'ları](https://docs.flipperzero.one/sub-ghz/supported-vendors)
- [6] [Flipper Zero - Bölgesel Sub-GHz frekansları](https://docs.flipperzero.one/sub-ghz/frequencies)
{{#include ../../../banners/hacktricks-training.md}}
