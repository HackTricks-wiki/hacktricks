# Radio Hacking

{{#include ../../banners/hacktricks-training.md}}

Radio güvenlik testleri, bir cihazın kablosuz sinyalleri nasıl ilettiğini, aldığını ve yorumladığını inceler. Yazılım tanımlı radyo (SDR), sinyalin yerini belirlemeye, eşfazlı/dikfazlı (I/Q) örnekleri kaydetmeye ve protokole özgü donanımlara bağlı kalmadan demodülasyon ve kod çözmeyi test etmeye yardımcı olabilir.<sup>[[1]](#references)</sup>

Uygulanabilir bir iş akışında frekans bandını ve kanal genişliğini belirleyin, bilinen birkaç cihaz eylemini kaydedin, ortaya çıkan sinyalleri karşılaştırın ve ardından modülasyonu ve paket yapısını saptayın. Yeniden oynatma veya iletim testlerini yalnızca yalıtılmış bir ortamda, yetkiniz olan frekanslarda ve ekipmanlarda yapın. Bu bölümdeki sayfalar RFID, NFC, sub-GHz radio, infrared, BLE ve ilgili araçları ele alır.<sup>[[1]](#references)</sup>

## İlgili arayüzü bulun

- Bir erişim kartı veya kontak anahtarı için [RFID/NFC etiket türleri ve saldırıları](pentesting-rfid.md), [Proxmark3 iş akışları](proxmark-3.md) veya [iButton ve 1-Wire anahtarları](ibutton.md) ile başlayın. [Flipper Zero kılavuzu](flipper-zero/README.md), arayüze özgü eylemlere bağlantı verir.
- Bir uzaktan kumanda sinyali için [sub-GHz RF ve rolling code'lar](sub-ghz-rf.md) veya [infrared protokolleri ve saldırıları](infrared.md) sayfalarını kullanın.
- Yakındaki cihazlar ve sensörler için [BLE advertising, GATT ve mesh testleri](pentesting-ble-bluetooth-low-energy.md) veya [LPWAN/LoRaWAN güvenliği](low-power-wide-area-network.md) sayfalarını kullanın.
- Kaydedilmiş veya bilinmeyen RF sinyalleri için [SigDigger sinyal analizi](../hardware-hacking/radio.md#sigdigger) ya da [FISSURE framework'ü](fissure-the-rf-framework.md) sayfasını kullanın.
- Uydu terminali downlink'leri için [VSAT forward-link sinyal enjeksiyonu](vsat-forward-link-injection.md) sayfasına bakın.



## References

- [1] [Great Scott Gadgets - HackRF ile Yazılım Tanımlı Radyo](https://greatscottgadgets.com/sdr/1/)
{{#include ../../banners/hacktricks-training.md}}
