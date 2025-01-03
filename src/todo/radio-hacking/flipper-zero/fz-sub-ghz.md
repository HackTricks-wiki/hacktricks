# FZ - Sub-GHz

{{#include ../../../banners/hacktricks-training.md}}

## Intro <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero, **300-928 MHz aralığında radyo frekanslarını alabilir ve iletebilir** ve uzaktan kumandaları okuyabilir, kaydedebilir ve taklit edebilir. Bu kumandalar, kapılar, bariyerler, radyo kilitleri, uzaktan kumanda anahtarları, kablosuz kapı zilleri, akıllı ışıklar ve daha fazlası ile etkileşim için kullanılır. Flipper Zero, güvenliğinizin tehlikeye girip girmediğini öğrenmenize yardımcı olabilir.

<figure><img src="../../../images/image (714).png" alt=""><figcaption></figcaption></figure>

## Sub-GHz donanımı <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero, [﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿[CC1101 çipi](https://www.ti.com/lit/ds/symlink/cc1101.pdf) ve bir radyo anteni (maksimum menzil 50 metredir) ile donatılmış bir alt-1 GHz modülüne sahiptir. Hem CC1101 çipi hem de antena, 300-348 MHz, 387-464 MHz ve 779-928 MHz bantlarında çalışacak şekilde tasarlanmıştır.

<figure><img src="../../../images/image (923).png" alt=""><figcaption></figcaption></figure>

## Eylemler

### Frekans Analizörü

> [!NOTE]
> Uzaktan kumandanın hangi frekansı kullandığını nasıl bulabilirsiniz

Analiz sırasında, Flipper Zero, frekans yapılandırmasında mevcut olan tüm frekanslarda sinyal gücünü (RSSI) tarar. Flipper Zero, -90 [dBm](https://en.wikipedia.org/wiki/DBm) değerinden daha yüksek sinyal gücüne sahip en yüksek RSSI değerine sahip frekansı gösterir.

Uzaktan kumandanın frekansını belirlemek için şunları yapın:

1. Uzaktan kumandayı Flipper Zero'nun soluna çok yakın bir yere yerleştirin.
2. **Ana Menü** **→ Sub-GHz**'ye gidin.
3. **Frekans Analizörü**'nü seçin, ardından analiz etmek istediğiniz uzaktan kumanda üzerindeki düğmeye basılı tutun.
4. Ekrandaki frekans değerini gözden geçirin.

### Oku

> [!NOTE]
> Kullanılan frekans hakkında bilgi bulun (hangi frekansın kullanıldığını bulmanın başka bir yolu)

**Oku** seçeneği, belirtilen modülasyonda **yapılandırılmış frekansta dinler**: varsayılan olarak 433.92 AM. Eğer **bir şey bulunursa** okuma sırasında, ekranda **bilgi verilir**. Bu bilgi, gelecekte sinyali çoğaltmak için kullanılabilir.

Okuma sırasında, **sol düğmeye** basarak **yapılandırma** yapabilirsiniz.\
Bu anda **4 modülasyon** (AM270, AM650, FM328 ve FM476) ve **birçok ilgili frekans** saklanmıştır:

<figure><img src="../../../images/image (947).png" alt=""><figcaption></figcaption></figure>

**İlginizi çeken herhangi birini** ayarlayabilirsiniz, ancak eğer **hangi frekansın** uzaktan kumandanız tarafından kullanıldığından **emin değilseniz**, **Hopping'i AÇIK** (varsayılan olarak Kapalı) olarak ayarlayın ve Flipper bunu yakalayana kadar düğmeye birkaç kez basın, böylece frekansı ayarlamak için gereken bilgiyi alırsınız.

> [!CAUTION]
> Frekanslar arasında geçiş yapmak biraz zaman alır, bu nedenle geçiş sırasında iletilen sinyaller kaçırılabilir. Daha iyi sinyal alımı için, Frekans Analizörü tarafından belirlenen sabit bir frekans ayarlayın.

### **Ham Oku**

> [!NOTE]
> Yapılandırılmış frekansta bir sinyali çalın (ve tekrar edin)

**Ham Oku** seçeneği, dinleme frekansında gönderilen sinyalleri **kaydeder**. Bu, bir sinyali **çalmak** ve **tekrar etmek** için kullanılabilir.

Varsayılan olarak **Ham Oku da 433.92 AM650**'de bulunmaktadır, ancak Okuma seçeneği ile ilginizi çeken sinyalin **farklı bir frekans/modülasyonda olduğunu bulursanız, bunu da değiştirebilirsiniz** sol düğmeye basarak (Ham Oku seçeneği içindeyken).

### Kaba Kuvvet

Eğer garaj kapısı tarafından kullanılan protokolü biliyorsanız, **tüm kodları üretebilir ve bunları Flipper Zero ile gönderebilirsiniz.** Bu, genel yaygın garaj türlerini destekleyen bir örnektir: [**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)

### Manuel Ekle

> [!NOTE]
> Yapılandırılmış bir protokol listesine sinyaller ekleyin

#### [desteklenen protokoller](https://docs.flipperzero.one/sub-ghz/add-new-remote) listesi <a href="#id-3iglu" id="id-3iglu"></a>

| Princeton_433 (statik kod sistemlerinin çoğuyla çalışır) | 433.92 | Statik  |
| -------------------------------------------------------- | ------ | ------- |
| Nice Flo 12bit_433                                      | 433.92 | Statik  |
| Nice Flo 24bit_433                                      | 433.92 | Statik  |
| CAME 12bit_433                                          | 433.92 | Statik  |
| CAME 24bit_433                                          | 433.92 | Statik  |
| Linear_300                                              | 300.00 | Statik  |
| CAME TWEE                                               | 433.92 | Statik  |
| Gate TX_433                                             | 433.92 | Statik  |
| DoorHan_315                                             | 315.00 | Dinamik |
| DoorHan_433                                             | 433.92 | Dinamik |
| LiftMaster_315                                          | 315.00 | Dinamik |
| LiftMaster_390                                          | 390.00 | Dinamik |
| Security+2.0_310                                        | 310.00 | Dinamik |
| Security+2.0_315                                        | 315.00 | Dinamik |
| Security+2.0_390                                        | 390.00 | Dinamik |

### Desteklenen Sub-GHz satıcıları

[https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors) adresindeki listeyi kontrol edin

### Bölgeye göre desteklenen frekanslar

[https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies) adresindeki listeyi kontrol edin

### Test

> [!NOTE]
> Kaydedilen frekansların dBm'lerini alın

## Referans

- [https://docs.flipperzero.one/sub-ghz](https://docs.flipperzero.one/sub-ghz)

{{#include ../../../banners/hacktricks-training.md}}
