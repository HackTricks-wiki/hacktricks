# FZ - 125kHz RFID

{{#include ../../../banners/hacktricks-training.md}}

## Giriş

125 kHz tag'lerin nasıl çalıştığı hakkında arka plan bilgisi için bkz.:

{{#ref}}
../pentesting-rfid.md
{{#endref}}

[Düşük frekanslı RFID giriş bölümü](../pentesting-rfid.md#low-frequency-rfid-tags-125khz), yaygın tag ailelerini ve veri formatlarını açıklar.

## İşlemler

### Oku

Tag verilerini yakalamak için **Read** seçeneğini kullanın. Başarılı bir okumadan sonra Flipper Zero, kaydedilen tag'i emulate edebilir.<sup>[[1]](#references)</sup>

> [!WARNING]
> Bazı intercom okuyucuları, okumadan önce bir write komutu göndererek yazılabilir duplicate tag'leri tespit etmeye çalışır. Flipper Zero emulation, yazılabilir tag belleğini aynı şekilde dışa sunmaz.<sup>[[1]](#references)</sup>

### Manuel ekle

Tag verilerini Flipper Zero'ya manuel olarak girebilir, kaydedebilir ve ardından emulate edebilirsiniz.<sup>[[1]](#references)</sup>

#### Kartlardaki ID'ler

Bazen bir kartın ID'sinin tamamı veya bir kısmı dış yüzeyine basılmış olur.

- **EM Marin**

Örneğin, görseldeki EM-Marin kartı beş ID byte'ının son üçünü gösterir. Tag okunamıyorsa eksik iki byte brute-force ile bulunabilir.

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

Benzer şekilde, görseldeki HID kartı üç ID byte'ının yalnızca ikisini gösterir.

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### Emulate/Write

Bir tag'i okuduktan veya ID'sini manuel olarak girdikten sonra Flipper Zero, kaydedilen credential'ı emulate edebilir. Desteklenen yazılabilir tag'ler için kaydedilen verileri uyumlu bir karta write da edebilir.<sup>[[1]](#references)</sup>

## References

- [1] [Flipper Zero: RFID Protokollerine Derinlemesine Bakış](https://blog.flipperzero.one/rfid/)
{{#include ../../../banners/hacktricks-training.md}}
