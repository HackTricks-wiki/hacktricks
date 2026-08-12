# FZ - NFC

{{#include ../../../banners/hacktricks-training.md}}

## Giriş <a href="#id-9wrzi" id="id-9wrzi"></a>

RFID ve NFC hakkında bilgi için aşağıdaki sayfayı kontrol edin:


{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Desteklenen NFC kartları <a href="#id-9wrzi" id="id-9wrzi"></a>

> [!CAUTION]
> NFC kartlarının yanı sıra Flipper Zero, çeşitli **Mifare** Classic ve Ultralight ile **NTAG** gibi **diğer High-frequency kart türlerini** de destekler.

Aşağıdaki yetenek listesi, orijinal makalede belgelenen firmware'i açıklar ve güncel, kapsamlı destek matrisi olarak değerlendirilmemelidir. Flipper firmware'i zaman içinde protokoller eklemiş ve NFC davranışını değiştirmiştir; yüklü firmware için güncel resmi belgeleri kontrol edin.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Bank cards (EMV)** — yalnızca UID, SAK ve ATQA'yı kaydetmeden okur.
- **Unknown cards** — UID, SAK ve ATQA'yı okur ve bir UID emulate eder.

**NFC card types B, F, and V** için belgelenen firmware, bir UID'yi kaydetmeden okuyabiliyordu.

### NFC cards type A <a href="#uvusf" id="uvusf"></a>

#### Bank card (EMV) <a href="#kzmrp" id="kzmrp"></a>

Belgelenen firmware, bir bank card üzerinden UID, SAK, ATQA ve mevcut application data'yı **kaydetmeden** okuyabiliyordu.

Bu bank cards için firmware, card'ı kaydetmeden veya emulate etmeden verileri görüntülüyordu.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&ixlib=react-9.1.1&h=916&w=2662" alt=""><figcaption></figcaption></figure>

#### Unknown cards <a href="#id-37eo8" id="id-37eo8"></a>

Flipper Zero **NFC card's type'ını belirleyemediğinde**, yalnızca bir **UID, SAK ve ATQA** **okunabilir ve kaydedilebilir**.

Bilinmeyen bir NFC card için bu mod yalnızca UID'sini emulate edebilir.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&ixlib=react-9.1.1&h=932&w=2634" alt=""><figcaption></figcaption></figure>

### NFC cards types B, F, and V <a href="#wyg51" id="wyg51"></a>

Orijinal makalede belgelenen firmware'de NFC card types B, F ve V için yalnızca identifier okunup kaydedilmeden görüntülenebiliyordu.<sup>[[1]](#references)</sup>

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&ixlib=react-9.1.1&h=1080&w=2704" alt=""><figcaption></figcaption></figure>

## İşlemler

NFC hakkında giriş için [**bu sayfayı okuyun**](../pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### Okuma

Flipper Zero NFC cards okuyabilir, ancak ISO 14443 üzerine kurulu her higher-level protocol'u uygulamaz. Bu nedenle application protocol bilinmezken low-level UID, SAK ve ATQA'yı alabilir. Yalnızca UID ile yetkilendirme yapan primitive access systems için araç bu identifier'ı okuyabilir, manuel olarak girebilir ve emulate edebilir; cryptographically authenticated systems, kopyalanmış bir UID'den daha fazlasını gerektirir.<sup>[[1]](#references)</sup>

#### Reading the UID VS Reading the Data Inside <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../images/image (217).png" alt=""><figcaption></figcaption></figure>

Flipper'da 13.56 MHz tags okuma iki bölüme ayrılabilir:<sup>[[1]](#references)</sup>

- **Low-level read** — yalnızca UID, SAK ve ATQA'yı okur. Flipper, card'dan okunan bu verilere dayanarak high-level protocol'u tahmin etmeye çalışır. Bu konuda %100 emin olamazsınız; çünkü bu yalnızca belirli faktörlere dayalı bir varsayımdır.
- **High-level read** — belirli bir high-level protocol kullanarak card'ın memory'sindeki verileri okur. Bu, bir Mifare Ultralight üzerindeki verileri, bir Mifare Classic'teki sectors'ı veya PayPass/Apple Pay'deki card attributes'larını okumak anlamına gelir.

### Read Specific

Flipper Zero low-level data'dan card türünü bulamazsa, `Extra Actions` içinde `Read Specific Card Type` seçeneğini belirleyebilir ve **okumak istediğiniz card türünü** **manuel olarak** **belirtebilirsiniz**.

#### EMV Bank Cards (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

Daha eski Flipper firmware'leri ve uyumlu EMV cards, card tarafından bu records kullanılabilir olduğunda UID'den fazlasını, potansiyel olarak PAN, expiration date, cardholder name veya transaction log'u açığa çıkarabiliyordu. Kullanılabilirlik card'a, application'a ve firmware'e göre değişir. Card üzerinde basılı magnetic-stripe CVV bu şekilde açığa çıkmaz ve bu records'ları okumak, contactless payment yapmak için gereken cryptographic transaction capability'yi clone etmez.<sup>[[1]](#references)</sup>

## References

- [1] [Diving into RFID Protocols with Flipper Zero](https://blog.flipperzero.one/rfid/)
- [2] [Flipper Zero documentation - NFC](https://docs.flipper.net/zero/nfc)
{{#include ../../../banners/hacktricks-training.md}}
