# Radyo Hacking

{{#include ../../banners/hacktricks-training.md}}

Radyo güvenlik testleri, bir cihazın kablosuz sinyalleri nasıl ilettiğini, aldığını ve yorumladığını inceler. Yazılım tanımlı radyo (SDR), protokole özgü donanımlara bağlı kalmadan bir sinyalin yerini bulmaya, faz içi/kareleme (I/Q) örneklerini kaydetmeye ve demodülasyon ile kod çözmeyi test etmeye yardımcı olabilir.<sup>[[1]](#references)</sup>

Pratik bir iş akışında frekans bandı ve kanal genişliği belirlenir, bilinen birkaç cihaz eylemi kaydedilir, ortaya çıkan sinyaller karşılaştırılır ve ardından modülasyon ile paket yapısı saptanır. Tekrar oynatma veya iletim testlerini yalnızca yalıtılmış bir ortamda ve yetkiniz olan frekanslarda ve ekipmanlarla yapın. Bu bölümdeki sayfalar RFID, NFC, sub-GHz radyo, kızılötesi, BLE ve ilgili araçları kapsar.<sup>[[1]](#references)</sup>

## İlgili arayüzü bulun

- Bir erişim kartı veya temassız anahtar için [RFID/NFC etiket türleri ve saldırıları](pentesting-rfid.md), [Proxmark3 iş akışları](proxmark-3.md) veya [iButton ve 1-Wire anahtarları](ibutton.md) ile başlayın. [Flipper Zero kılavuzu](flipper-zero/README.md), arayüze özgü eylemlere bağlantı verir.
- Bir uzaktan kumanda sinyali için [sub-GHz RF ve rolling code'lar](sub-ghz-rf.md) veya [kızılötesi protokoller ve saldırılar](infrared.md) sayfalarını kullanın.
- Yakındaki cihazlar ve sensörler için [BLE advertising, GATT ve mesh testlerini](pentesting-ble-bluetooth-low-energy.md) veya [LPWAN/LoRaWAN güvenliğini](low-power-wide-area-network.md) kullanın.
- Kaydedilmiş veya bilinmeyen RF sinyalleri için [SigDigger sinyal analizini](../hardware-hacking/radio.md#sigdigger) veya [FISSURE framework'ünü](fissure-the-rf-framework.md) kullanın.

## References

- [1] [Great Scott Gadgets - HackRF ile Yazılım Tanımlı Radyo](https://greatscottgadgets.com/sdr/1/)
{{#include ../../banners/hacktricks-training.md}}
