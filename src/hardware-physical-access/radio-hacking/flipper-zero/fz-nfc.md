# FZ - NFC

{{#include ../../../banners/hacktricks-training.md}}

## Giriş <a href="#id-9wrzi" id="id-9wrzi"></a>

RFID ve NFC hakkında bilgi için aşağıdaki sayfaya bakın:


{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Desteklenen NFC kartları <a href="#id-9wrzi" id="id-9wrzi"></a>

> [!CAUTION]
> Flipper Zero, NFC kartlarının yanı sıra çeşitli **Mifare** Classic ve Ultralight ile **NTAG** gibi **diğer Yüksek frekanslı kart türlerini** de destekler.

Aşağıdaki yetenek listesi, orijinal makalede belgelenen firmware'i açıklar ve mevcut kapsamlı destek matrisi olarak değerlendirilmemelidir. Flipper firmware'i zaman içinde protokoller eklemiş ve NFC davranışını değiştirmiştir; yüklü firmware için güncel resmi belgelere bakın.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Banka kartları (EMV)** — yalnızca UID, SAK ve ATQA'yı okur; kaydetmez.
- **Bilinmeyen kartlar** — UID, SAK ve ATQA'yı okur ve bir UID'yi emulate eder.

**B, F ve V türü NFC kartlarında**, belgelenen firmware UID'yi kaydetmeden okuyabiliyordu.

### A türü NFC kartları <a href="#uvusf" id="uvusf"></a>

#### Banka kartı (EMV) <a href="#kzmrp" id="kzmrp"></a>

Belgelenen firmware, banka kartındaki UID, SAK, ATQA ve mevcut uygulama verilerini **kaydetmeden** okuyabiliyordu.

Bu banka kartlarında firmware, kartı kaydetmeden veya emulate etmeden verileri görüntülüyordu.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&ixlib=react-9.1.1&h=916&w=2662" alt=""><figcaption></figcaption></figure>

#### Bilinmeyen kartlar <a href="#id-37eo8" id="id-37eo8"></a>

Flipper Zero **NFC kartının türünü belirleyemediğinde**, yalnızca **UID, SAK ve ATQA** **okunup kaydedilebilir**.

Bilinmeyen bir NFC kartında bu mod yalnızca UID'sini emulate edebilir.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&ixlib=react-9.1.1&h=932&w=2634" alt=""><figcaption></figcaption></figure>

### B, F ve V türü NFC kartları <a href="#wyg51" id="wyg51"></a>

Orijinal makalede belgelenen firmware'de B, F ve V türü NFC kartlarının tanımlayıcısı yalnızca okunup görüntülenebiliyor, kaydedilemiyordu.<sup>[[1]](#references)</sup>

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&ixlib=react-9.1.1&h=1080&w=2704" alt=""><figcaption></figcaption></figure>

## İşlemler

NFC'ye giriş için [**bu sayfayı okuyun**](../pentesting-rfid.md#high-frequency-rfid-tags-1356-mhz-1).

### Oku

Flipper Zero NFC kartlarını okuyabilir ancak ISO 14443 üzerine kurulu tüm üst düzey protokolleri uygulamaz. Bu nedenle, uygulama protokolü bilinmezken düşük düzeyli UID, SAK ve ATQA bilgilerini elde edebilir. Yalnızca UID ile yetkilendirme yapan basit erişim sistemlerinde araç bu tanımlayıcıyı okuyabilir, elle girmenize ve emulate etmenize olanak tanır; kriptografik kimlik doğrulaması kullanan sistemler kopyalanmış bir UID'den fazlasını gerektirir.<sup>[[1]](#references)</sup>

#### UID'yi Okumak ve İçindeki Verileri Okumak <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../images/image (217).png" alt=""><figcaption></figcaption></figure>

Flipper'da 13.56 MHz etiketleri okuma işlemi iki bölüme ayrılabilir:<sup>[[1]](#references)</sup>

- **Düşük düzeyli okuma** — yalnızca UID, SAK ve ATQA'yı okur. Flipper, karttan okunan bu verilere dayanarak üst düzey protokolü tahmin etmeye çalışır. Bu yalnızca belirli etkenlere dayalı bir varsayım olduğundan bundan yüzde 100 emin olamazsınız.
- **Üst düzey okuma** — belirli bir üst düzey protokol kullanarak kart belleğindeki verileri okur. Örneğin Mifare Ultralight'taki verileri, Mifare Classic'in sektörlerini veya PayPass/Apple Pay kartının özniteliklerini okumak.

### Belirli Türü Oku

Flipper Zero düşük düzeyli verilerden kart türünü belirleyemiyorsa `Extra Actions` menüsünde `Read Specific Card Type` seçeneğini belirleyip **okumak istediğiniz kart türünü elle belirtebilirsiniz**.

#### EMV Banka Kartları (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

Daha eski Flipper firmware'leri ve uyumlu EMV kartları, UID'den fazlasını açığa çıkarabiliyordu. Kartın sunduğu kayıtlara bağlı olarak bu veriler PAN'ı, son kullanma tarihini, kart sahibinin adını veya işlem günlüğünü içerebilirdi. Verilerin kullanılabilirliği karta, uygulamaya ve firmware'e göre değişir. Kartın üzerinde yazılı manyetik şerit CVV'si bu yolla açığa çıkmaz ve bu kayıtların okunması, temassız ödeme yapmak için gereken kriptografik işlem yeteneğini klonlamaz.<sup>[[1]](#references)</sup>

## References

- [1] [Flipper Zero ile RFID Protokollerini İncelemek](https://blog.flipperzero.one/rfid/)
- [2] [Flipper Zero belgeleri - NFC](https://docs.flipper.net/zero/nfc)
{{#include ../../../banners/hacktricks-training.md}}
