# FZ - NFC

{{#include ../../../banners/hacktricks-training.md}}

## Giriş <a href="#id-9wrzi" id="id-9wrzi"></a>

RFID ve NFC hakkında bilgi için aşağıdaki sayfaya bakın:


{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Desteklenen NFC kartları <a href="#id-9wrzi" id="id-9wrzi"></a>

> [!CAUTION]
> NFC kartlarının yanı sıra Flipper Zero, birkaç **Mifare** Classic ve Ultralight ile **NTAG** gibi **diğer High-frequency kart türlerini** de destekler.

Desteklenen kartlar listesine yeni NFC kartı türleri eklenecektir. Flipper Zero aşağıdaki **NFC type A kartlarını** (ISO 14443A) destekler:

- **Bank cards (EMV)** — yalnızca UID, SAK ve ATQA'yı okur, kaydetmez.
- **Bilinmeyen kartlar** — UID, SAK ve ATQA'yı okur ve bir UID'yi emulate eder.

**NFC type B, type F ve type V kartları** için Flipper Zero, UID'yi kaydetmeden okuyabilir.

### NFC type A kartları <a href="#uvusf" id="uvusf"></a>

#### Bank card (EMV) <a href="#kzmrp" id="kzmrp"></a>

Flipper Zero, bank cards üzerindeki UID, SAK, ATQA ve depolanan verileri yalnızca **kaydetmeden** okuyabilir.

Bank card reading screenBank cards için Flipper Zero, verileri yalnızca **kaydetmeden ve emulate etmeden** okuyabilir.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&ixlib=react-9.1.1&h=916&w=2662" alt=""><figcaption></figcaption></figure>

#### Bilinmeyen kartlar <a href="#id-37eo8" id="id-37eo8"></a>

Flipper Zero **NFC kartının türünü belirleyemediğinde**, yalnızca bir **UID, SAK ve ATQA** **okunabilir ve kaydedilebilir**.

Unknown card reading screenBilinmeyen NFC kartları için Flipper Zero yalnızca bir UID'yi emulate edebilir.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&ixlib=react-9.1.1&h=932&w=2634" alt=""><figcaption></figcaption></figure>

### NFC type B, F ve V kartları <a href="#wyg51" id="wyg51"></a>

**NFC type B, type F ve type V kartları** için Flipper Zero, UID'yi kaydetmeden yalnızca **okuyabilir ve görüntüleyebilir**.

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&ixlib=react-9.1.1&h=1080&w=2704" alt=""><figcaption></figcaption></figure>

## İşlemler

NFC hakkında giriş için [**bu sayfayı okuyun**](../pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### Oku

Flipper Zero **NFC kartlarını okuyabilir**, ancak ISO 14443 tabanlı **tüm protokolleri anlayamaz**. Bununla birlikte, **UID düşük seviyeli bir öznitelik** olduğundan, **UID'nin zaten okunduğu ancak yüksek seviyeli veri aktarım protokolünün hâlâ bilinmediği** bir durumla karşılaşabilirsiniz. Yetkilendirme için UID kullanan basit okuyucularda Flipper'ı kullanarak UID'yi okuyabilir, emulate edebilir ve manuel olarak girebilirsiniz.<sup>[[1]](#references)</sup>

#### UID'yi Okumaya Karşı İçindeki Verileri Okuma <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../images/image (217).png" alt=""><figcaption></figcaption></figure>

Flipper'da 13.56 MHz kartlarının okunması iki bölüme ayrılabilir:<sup>[[1]](#references)</sup>

- **Düşük seviyeli okuma** — yalnızca UID, SAK ve ATQA'yı okur. Flipper, karttan okunan bu verilere göre yüksek seviyeli protokolü tahmin etmeye çalışır. Bu yalnızca belirli etkenlere dayalı bir varsayım olduğundan bundan %100 emin olamazsınız.
- **Yüksek seviyeli okuma** — belirli bir yüksek seviyeli protokol kullanarak kartın belleğindeki verileri okur. Bu, Mifare Ultralight üzerindeki verileri, Mifare Classic üzerindeki sektörleri veya PayPass/Apple Pay üzerindeki kart özniteliklerini okumak anlamına gelir.

### Specific Oku

Flipper Zero düşük seviyeli verilerden kart türünü bulamadığında, `Extra Actions` bölümünden `Read Specific Card Type` seçeneğini belirleyebilir ve okumak istediğiniz kartın türünü **manuel olarak** **belirtebilirsiniz**.

#### EMV Bank Cards (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

UID'yi basitçe okumaya ek olarak, bir bank card üzerinden çok daha fazla veri çıkarabilirsiniz. **Tam kart numarasını** (kartın ön yüzündeki 16 hane), **geçerlilik tarihini** ve bazı durumlarda **kart sahibinin adını** ve **en son işlemlerin** listesini almak mümkündür.\
Ancak **CVV'yi bu şekilde okuyamazsınız** (kartın arkasındaki 3 hane). Ayrıca **bank cards replay attacks saldırılarına karşı korunur**, bu nedenle kartı Flipper ile kopyalayıp ardından bir şey ödemek için emulate etmeye çalışmak işe yaramaz.<sup>[[1]](#references)</sup>

## Referanslar

- [1] [Flipper Zero ile RFID Protocols'a Derinlemesine Bakış](https://blog.flipperzero.one/rfid/)

{{#include ../../../banners/hacktricks-training.md}}
