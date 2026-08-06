# FZ - Sub-GHz

{{#include ../../../banners/hacktricks-training.md}}

## Giriş <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero, yerleşik modülüyle **300-928 MHz aralığındaki radyo frekanslarını alıp iletebilir**; bu modül uzaktan kumandaları okuyabilir, kaydedebilir ve taklit edebilir. Bu kumandalar kapılar, bariyerler, radyo kilitleri, uzaktan kumandalı anahtarlar, kablosuz kapı zilleri, akıllı ışıklar ve daha fazlasıyla etkileşim için kullanılır. Flipper Zero, güvenliğinizin tehlikeye girip girmediğini öğrenmenize yardımcı olabilir.

<figure><img src="../../../images/image (714).png" alt=""><figcaption></figcaption></figure>

## Sub-GHz donanımı <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero, [﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿[CC1101 chip](https://www.ti.com/lit/ds/symlink/cc1101.pdf) tabanlı yerleşik bir 1 GHz altı modüle ve bir radyo antenine sahiptir (maksimum menzil 50 metredir). Hem CC1101 chip hem de anten, 300-348 MHz, 387-464 MHz ve 779-928 MHz bantlarındaki frekanslarda çalışacak şekilde tasarlanmıştır.

<figure><img src="../../../images/image (923).png" alt=""><figcaption></figcaption></figure>

## Eylemler

### Frequency Analyser

> [!TIP]
> Kumandanın hangi frekansı kullandığını bulma

Analiz sırasında Flipper Zero, frekans yapılandırmasında kullanılabilen tüm frekanslardaki sinyal gücünü (RSSI) tarar. Flipper Zero, -90 [dBm](https://en.wikipedia.org/wiki/DBm) değerinden daha güçlü sinyale sahip, en yüksek RSSI değerinin bulunduğu frekansı görüntüler.<sup>[[1]](#references)</sup>

Kumandanın frekansını belirlemek için aşağıdakileri yapın:

1. Kumandayı Flipper Zero'nun sol tarafına, cihaza çok yakın olacak şekilde yerleştirin.
2. **Main Menu** **→ Sub-GHz** bölümüne gidin.
3. **Frequency Analyzer** seçeneğini belirleyin, ardından analiz etmek istediğiniz kumandanın düğmesine basılı tutun.
4. Ekrandaki frekans değerini kontrol edin.

### Read

> [!TIP]
> Kullanılan frekans hakkında bilgi bulma (kullanılan frekansı bulmanın başka bir yolu)

**Read** seçeneği, belirtilen modulation üzerinde **yapılandırılmış frekansı dinler**: varsayılan olarak 433.92 AM. Okuma sırasında **bir şey bulunursa**, ekranda **bilgi görüntülenir**. Bu bilgi, sinyali gelecekte çoğaltmak için kullanılabilir.<sup>[[1]](#references)</sup>

Read kullanılırken **sol düğmeye** basmak ve **yapılandırma yapmak** mümkündür.\
Şu anda **4 modulation** (AM270, AM650, FM328 ve FM476) ve **çeşitli ilgili frekanslar** kayıtlıdır:

<figure><img src="../../../images/image (947).png" alt=""><figcaption></figcaption></figure>

İlginizi çeken **herhangi birini ayarlayabilirsiniz**. Ancak kumandanızın kullandığı frekansın hangisi olduğundan **emin değilseniz**, **Hopping'i ON** olarak ayarlayın (varsayılan olarak Off) ve Flipper sinyali yakalayıp frekansı ayarlamak için ihtiyacınız olan bilgileri verene kadar düğmeye birkaç kez basın.

> [!CAUTION]
> Frekanslar arasında geçiş yapmak zaman alır; bu nedenle geçiş sırasında iletilen sinyaller kaçırılabilir. Daha iyi sinyal alımı için Frequency Analyzer tarafından belirlenen sabit bir frekans ayarlayın.

### **Read Raw**

> [!TIP]
> Yapılandırılmış frekanstaki bir sinyali çalma (ve replay etme)

**Read Raw** seçeneği, dinleme frekansında gönderilen sinyalleri **kaydeder**. Bu özellik bir sinyali **çalmak** ve **tekrarlamak** için kullanılabilir.<sup>[[1]](#references)</sup>

Varsayılan olarak **Read Raw de AM650 üzerinde 433.92 frekansındadır**. Ancak Read seçeneğiyle ilginizi çeken sinyalin **farklı bir frekans/modulation üzerinde olduğunu bulduysanız**, Read Raw seçeneğindeyken sol düğmeye basarak bunu **değiştirebilirsiniz**.

### Brute-Force

Örneğin garaj kapısı tarafından kullanılan protokolü biliyorsanız, **tüm kodları oluşturup Flipper Zero ile göndermek** mümkündür. Bu, yaygın garaj türlerini destekleyen bir örnektir: [**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)

### Add Manually

> [!TIP]
> Yapılandırılmış bir protokol listesinden sinyal ekleme

#### [supported protocols](https://docs.flipperzero.one/sub-ghz/add-new-remote) listesi <a href="#id-3iglu" id="id-3iglu"></a>

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

Listeyi [https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors) adresinde kontrol edin.

### Bölgelere göre desteklenen frekanslar

Listeyi [https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies) adresinde kontrol edin.

### Test

> [!TIP]
> Kaydedilmiş frekansların dBm değerlerini alma

## References

- [1] [Sub-GHz - Flipper Zero User Documentation](https://docs.flipperzero.one/sub-ghz)

{{#include ../../../banners/hacktricks-training.md}}
