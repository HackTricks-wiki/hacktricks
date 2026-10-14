# FZ - Sub-GHz

{{#include ../../../banners/hacktricks-training.md}}

## Giriş <a href="#introduction" id="introduction"></a>

Flipper Zero, yapılandırılan bölgeye ait frekans kısıtlamalarına tabi olarak yerleşik modülüyle **300-928 MHz aralığındaki radyo frekanslarını alıp iletebilir**. Kapılar, bariyerler, radyo kilitleri, anahtarlar, kablosuz kapı zilleri, akıllı ışıklar ve diğer cihazlarla kullanılan uyumlu uzaktan kumandaları okuyabilir, kaydedebilir ve taklit edebilir.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (714).png" alt=""><figcaption></figcaption></figure>

## Sub-GHz Donanımı <a href="#sub-ghz-hardware" id="sub-ghz-hardware"></a>

Flipper Zero, CC1101 alıcı-vericisine ve bir radyo antenine dayanan yerleşik bir 1 GHz altı modüle sahiptir. Gerçek menzil; frekansa, antene, ortama ve vericiye bağlıdır. Flipper, uygun koşullarda yaklaşık 50 metreye kadar menzil belirtir. Donanım 300-348 MHz, 387-464 MHz ve 779-928 MHz aralıklarını kapsarken, firmware ve bölgesel kurallar iletim için ek kısıtlamalar getirir.<sup>[[1]](#references)[[2]](#references)</sup>

<figure><img src="../../../images/image (923).png" alt=""><figcaption></figcaption></figure>

## Eylemler

### Frequency Analyzer

> [!TIP]
> Uzaktan kumandanın hangi frekansı kullandığını bulma

Analiz sırasında Flipper Zero, frekans yapılandırmasında kullanılabilir olan tüm frekanslardaki sinyal gücünü (RSSI) tarar. Flipper Zero, RSSI değeri en yüksek ve sinyal gücü -90 [dBm](https://en.wikipedia.org/wiki/DBm) üzerindeki frekansı görüntüler.<sup>[[1]](#references)</sup>

Uzaktan kumandanın frekansını belirlemek için şu adımları izleyin:

1. Uzaktan kumandayı Flipper Zero'nun sol tarafına çok yakın yerleştirin.
2. **Ana Menü** **→ Sub-GHz** bölümüne gidin.
3. **Frequency Analyzer** seçeneğini belirleyin, ardından analiz etmek istediğiniz uzaktan kumandanın düğmesini basılı tutun.
4. Ekrandaki frekans değerini inceleyin.

### Read

> [!TIP]
> Kullanılan frekans hakkında bilgi edinme (kullanılan frekansı bulmanın başka bir yolu)

**Read** seçeneği, yapılandırılan frekans ve modülasyonu (varsayılan olarak 433.92 MHz AM) dinler. Desteklenen bir sinyali algıladığında, ekranda daha sonra kaydedilip yeniden oynatılabilecek bilgiler görüntülenir.<sup>[[1]](#references)</sup>

Read kullanılırken **sol düğmeye** basıp **ayarları yapılandırmak** mümkündür.\
Şu anda **4 modülasyon** (AM270, AM650, FM328 ve FM476) ve kayıtlı **çeşitli önemli frekanslar** bulunur:

<figure><img src="../../../images/image (947).png" alt=""><figcaption></figcaption></figure>

İzin verilen herhangi bir frekansı seçebilirsiniz. Uzaktan kumandanın hangi frekansı kullandığından emin değilseniz, **Hopping** seçeneğini **ON** (varsayılan olarak kapalı) yapın ve Flipper sinyali yakalayıp frekansı bildirene kadar uzaktan kumandanın düğmesine birkaç kez basın.

> [!CAUTION]
> Frekanslar arasında geçiş yapmak zaman alır; bu nedenle geçiş sırasında iletilen sinyaller kaçırılabilir. Sinyali daha iyi almak için Frequency Analyzer ile belirlenen sabit bir frekans ayarlayın.

### **Read Raw**

> [!TIP]
> Yapılandırılan frekanstaki bir sinyali ele geçirme (ve yeniden oynatma)

**Read Raw** seçeneği, seçilen frekansta gönderilen sinyalleri kaydeder. Yetkili testler sırasında bir sinyali yakalayıp yeniden oynatmak için kullanılabilir.<sup>[[1]](#references)</sup>

Varsayılan olarak **Read Raw**, **AM650** modülasyonuyla **433.92 MHz** frekansını da kullanır. Read seçeneği farklı bir frekans veya modülasyonda sinyal bulduysa, bu ayarları değiştirmek için Read Raw içindeyken Sol düğmesine basın.

### Brute-Force

Garaj kapısı gibi bir cihazın kullandığı protokolü biliyorsanız, **olası kodlar üretip bunları Flipper Zero ile iletmek** mümkün olabilir. `flipperzero-bruteforce` projesi, yaygın birkaç statik kod protokolünü destekler.<sup>[[3]](#references)</sup>

### Add Manually

> [!TIP]
> Yapılandırılmış protokoller listesinden sinyal ekleme

#### Desteklenen protokollerin listesi <a href="#id-3iglu" id="id-3iglu"></a>

Add Manually menüsünde, Flipper Zero tarafından belgelenen protokol ön ayarları bulunur.<sup>[[4]](#references)</sup>

| Princeton_433 (çoğu statik kod sistemiyle çalışır) | 433.92 | Statik  |
| -------------------------------------------------------------- | ------ | ------- |
| Nice Flo 12bit_433                                             | 433.92 | Statik  |
| Nice Flo 24bit_433                                             | 433.92 | Statik  |
| CAME 12bit_433                                                 | 433.92 | Statik  |
| CAME 24bit_433                                                 | 433.92 | Statik  |
| Linear_300                                                     | 300.00 | Statik  |
| CAME TWEE                                                      | 433.92 | Statik  |
| Gate TX_433                                                    | 433.92 | Statik  |
| DoorHan_315                                                    | 315.00 | Dinamik |
| DoorHan_433                                                    | 433.92 | Dinamik |
| LiftMaster_315                                                 | 315.00 | Dinamik |
| LiftMaster_390                                                 | 390.00 | Dinamik |
| Security+2.0_310                                               | 310.00 | Dinamik |
| Security+2.0_315                                               | 315.00 | Dinamik |
| Security+2.0_390                                               | 390.00 | Dinamik |

### Desteklenen Sub-GHz satıcıları

Flipper Zero'nun desteklenen satıcılar listesini inceleyin.<sup>[[5]](#references)</sup>

### Bölgeye göre desteklenen frekanslar

İletim yapmadan önce resmi bölgesel frekans listesini inceleyin.<sup>[[6]](#references)</sup>

### Test

> [!TIP]
> Kaydedilmiş frekansların dBm değerlerini görüntüleme

## References

- [1] [Sub-GHz - Flipper Zero Kullanıcı Belgeleri](https://docs.flipperzero.one/sub-ghz)
- [2] [Texas Instruments CC1101 veri sayfası](https://www.ti.com/lit/ds/symlink/cc1101.pdf)
- [3] [tobiabocchi/flipperzero-bruteforce](https://github.com/tobiabocchi/flipperzero-bruteforce)
- [4] [Flipper Zero - Elle oluşturulmuş bir uzaktan kumanda ekleme](https://docs.flipperzero.one/sub-ghz/add-new-remote)
- [5] [Flipper Zero - Desteklenen Sub-GHz satıcıları](https://docs.flipperzero.one/sub-ghz/supported-vendors)
- [6] [Flipper Zero - Bölgesel Sub-GHz frekansları](https://docs.flipperzero.one/sub-ghz/frequencies)
{{#include ../../../banners/hacktricks-training.md}}
