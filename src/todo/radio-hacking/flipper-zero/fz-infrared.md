# FZ - Kızılötesi

{{#include ../../../banners/hacktricks-training.md}}

## Giriş <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Kızılötesinin nasıl çalıştığı hakkında daha fazla bilgi için:


{{#ref}}
../infrared.md
{{#endref}}

## Flipper Zero'da IR Sinyal Alıcısı <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper Zero, yaygın IR kumandalarından sinyalleri yakalamak için demodülasyon yapan bir IR alıcısı kullanır. Bazı telefonlarda, belirli Xiaomi modelleri de dahil olmak üzere, IR vericisi bulunur; ancak çoğu telefon uzaktan kumanda sinyallerini alamaz ve decode edemez.<sup>[[1]](#references)</sup>

Flipper'ın infrared **alıcısı oldukça hassastır**. Kumanda ile TV'nin **arasında bir yerde** dururken bile **sinyali yakalayabilirsiniz**. Kumandayı doğrudan Flipper'ın IR portuna doğrultmak gerekli değildir. Bu, biri TV'nin yanında durarak kanal değiştirirken ve siz ile Flipper TV'den biraz uzaktayken işe yarar.

Protocol decoding software'de gerçekleşir. Tanınan protokoller decode edilmiş komutlar olarak saklanabilir; desteklenmeyen protokoller ise donanımın taşıyıcı frekansı ve zamanlama sınırlarına tabi olarak ham zamanlama verileri şeklinde yakalanıp yeniden oynatılabilir.<sup>[[1]](#references)</sup>

## İşlemler

### Evrensel Kumandalar

Flipper Zero'nun evrensel kumanda modu, desteklenen TV'ler, ses ekipmanları, projektörler ve klimalar için infrared veritabanındaki bilinen komutlar arasında sırayla geçiş yapar. Her cihazı kontrol edeceği garanti edilmez ve yalnızca sahibi olduğunuz veya test etme yetkiniz bulunan ekipmanlarda kullanılmalıdır.<sup>[[1]](#references)</sup>

Universal Remote modunda güç düğmesine basmak yeterlidir; Flipper bildiği tüm TV'lerin **"Power Off"** komutlarını **sırayla gönderir**: Sony, Samsung, Panasonic... ve diğerleri. TV sinyali aldığında tepki verir ve kapanır.

Bu tür brute-force işlemi zaman alır. Dictionary ne kadar büyükse tamamlanması da o kadar uzun sürer. TV'den herhangi bir geri bildirim gelmediği için TV'nin tam olarak hangi sinyali tanıdığını öğrenmek mümkün değildir.

### Yeni Kumanda Öğrenme

Flipper Zero **bir infrared sinyalini yakalayabilir**. Protocol ve komutu tanırsa decode edilmiş bir gösterim saklar; aksi takdirde daha sonra yeniden oynatmak üzere ham zamanlama verilerini saklayabilir.<sup>[[1]](#references)</sup>

## References

- [1] [Flipper Zero Infrared Port ile TV'leri Ele Geçirme](https://blog.flipperzero.one/infrared/)
{{#include ../../../banners/hacktricks-training.md}}
