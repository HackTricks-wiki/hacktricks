# FZ - 125kHz RFID

{{#include ../../../banners/hacktricks-training.md}}

## Giriş

125 kHz etiketlerin nasıl çalıştığı hakkında bilgi için bkz.:

{{#ref}}
../pentesting-rfid.md
{{#endref}}

[Low-frequency RFID introduction](../pentesting-rfid.md#low-frequency-rfid-tags-125khz), yaygın etiket ailelerini ve veri formatlarını açıklar.

## İşlemler

### Oku

Etiket verilerini yakalamak için **Oku** seçeneğini kullanın. Başarılı bir okumadan sonra Flipper Zero kaydedilen etiketi emüle edebilir.<sup>[[1]](#references)</sup>

> [!WARNING]
> Bazı interkom okuyucuları, okumadan önce bir yazma komutu göndererek yazılabilir kopya etiketleri algılamaya çalışır. Flipper Zero emülasyonu, yazılabilir etiket belleğini aynı şekilde sunmaz.<sup>[[1]](#references)</sup>

### Manuel ekle

Etiket verilerini Flipper Zero'ya manuel olarak girebilir, kaydedebilir ve ardından emüle edebilirsiniz.<sup>[[1]](#references)</sup>

#### Kartlardaki ID'ler

Bazen bir kartın ID'sinin tamamı veya bir kısmı kartın dış yüzeyine basılmıştır.

- **EM Marin**

Örneğin, görseldeki EM-Marin kartında ID'sini oluşturan beş baytın son üçü görünür. Etiket okunamıyorsa eksik iki bayt brute-force ile bulunabilir.

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

Benzer şekilde, görseldeki HID kartında ID'sini oluşturan üç baytın yalnızca ikisi basılıdır.

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### Emüle et/Yaz

Bir etiketi okuduktan veya ID'sini manuel olarak girdikten sonra Flipper Zero, kaydedilen kimlik bilgisini emüle edebilir. Desteklenen yazılabilir etiketlerde, kaydedilen verileri uyumlu bir karta da yazabilir.<sup>[[1]](#references)</sup>

## References

- [1] [Flipper Zero: RFID Protokollerine Derinlemesine Bakış](https://blog.flipperzero.one/rfid/)
{{#include ../../../banners/hacktricks-training.md}}
