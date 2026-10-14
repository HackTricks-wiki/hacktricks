# FZ - Kızılötesi

{{#include ../../../banners/hacktricks-training.md}}

## Giriş <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Kızılötesinin nasıl çalıştığı hakkında daha fazla bilgi için:


{{#ref}}
../infrared.md
{{#endref}}

## Flipper Zero'da IR Sinyal Alıcısı <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper Zero, yaygın IR kumandalarından gelen sinyalleri yakalamak için demodüle edici bir IR alıcısı kullanır. Bazı telefonlarda, belirli Xiaomi modelleri de dahil olmak üzere, IR vericisi bulunur; ancak çoğu telefon kumanda sinyallerini alamaz ve çözümleyemez.<sup>[[1]](#references)</sup>

Flipper'ın kızılötesi **alıcısı oldukça hassastır**. Kumanda ile TV arasında **bir yerde dururken bile sinyali yakalayabilirsiniz**. Kumandayı doğrudan Flipper'ın IR bağlantı noktasına doğrultmanız gerekmez. Bu özellik, biri TV'nin yakınında durup kanalları değiştirirken sizin ve Flipper'ın uzakta olduğunuz durumlarda işe yarar.

Protokol çözümleme yazılımda gerçekleşir. Tanınan protokoller, çözülmüş komutlar olarak saklanabilir; desteklenmeyen protokoller ise donanımın taşıyıcı frekansı ve zamanlama sınırlarına tabi olarak ham zamanlama verisi biçiminde yakalanıp yeniden oynatılabilir.<sup>[[1]](#references)</sup>

## İşlemler

### Evrensel Kumandalar

Flipper Zero'nun evrensel kumanda modu; desteklenen TV'ler, ses ekipmanları, projektörler ve klimalar için kızılötesi veritabanındaki bilinen komutları sırayla dener. Her cihazı kontrol edeceği garanti değildir ve yalnızca sahibi olduğunuz veya test etmek için yetkilendirildiğiniz ekipmanlarda kullanılmalıdır.<sup>[[1]](#references)</sup>

Evrensel Kumanda modundayken güç düğmesine basmanız yeterlidir; Flipper, bildiği tüm TV'lere ait **"Power Off" komutlarını sırayla gönderir**: Sony, Samsung, Panasonic... ve diğerleri. TV sinyali aldığında tepki verir ve kapanır.

Bu tür brute-force işlemleri zaman alır. Sözlük ne kadar büyükse işlemin tamamlanması da o kadar uzun sürer. TV'den geri bildirim alınmadığı için TV'nin hangi sinyali tanıdığını belirlemek mümkün değildir.

### Yeni Kumanda Öğrenme

Flipper Zero **bir kızılötesi sinyal yakalayabilir**. Protokolü ve komutu tanırsa çözümlenmiş biçimini saklar; aksi takdirde daha sonra yeniden oynatmak üzere ham zamanlama verisini saklayabilir.<sup>[[1]](#references)</sup>

## References

- [1] [Flipper Zero Kızılötesi Bağlantı Noktasıyla TV'lerin Kontrolünü Ele Alma](https://blog.flipperzero.one/infrared/)
{{#include ../../../banners/hacktricks-training.md}}
