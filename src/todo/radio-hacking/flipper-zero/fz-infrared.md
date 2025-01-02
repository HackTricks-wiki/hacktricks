# FZ - Kızılötesi

{{#include ../../../banners/hacktricks-training.md}}

## Giriş <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Kızılötesinin nasıl çalıştığı hakkında daha fazla bilgi için kontrol edin:

{{#ref}}
../infrared.md
{{#endref}}

## Flipper Zero'daki IR Sinyal Alıcısı <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper, **IR uzaktan kumandalardan sinyalleri yakalamayı** sağlayan dijital bir IR sinyal alıcısı TSOP kullanır. Xiaomi gibi bazı **akıllı telefonlar** da IR portuna sahiptir, ancak **çoğu yalnızca** sinyal iletebilir ve **almakta** başarısızdır.

Flipper'ın kızılötesi **alıcı oldukça hassastır**. Uzaktan kumanda ile TV arasında **bir yerde kalırken bile sinyali yakalayabilirsiniz**. Uzaktan kumandayı doğrudan Flipper'ın IR portuna doğrultmak gereksizdir. Bu, birinin TV'nin yanında dururken kanalları değiştirmesi durumunda işe yarar; hem siz hem de Flipper bir mesafede olabilirsiniz.

**Kızılötesi** sinyalin **çözülmesi** yazılım tarafında gerçekleştiğinden, Flipper Zero potansiyel olarak **herhangi bir IR uzaktan kumanda kodunun alımını ve iletimini** destekler. Tanınamayan **bilinmeyen** protokoller durumunda, **ham sinyali tam olarak alındığı gibi kaydeder ve tekrar oynatır**.

## Eylemler

### Evrensel Uzaktan Kumandalar

Flipper Zero, **herhangi bir TV, klima veya medya merkezi** kontrol etmek için bir **evrensel uzaktan kumanda** olarak kullanılabilir. Bu modda, Flipper **SD karttaki sözlüğe göre** desteklenen tüm üreticilerin **bilinen kodlarını** **brute force** ile dener. Bir restoran TV'sini kapatmak için belirli bir uzaktan kumanda seçmenize gerek yoktur.

Evrensel Uzaktan Kumanda modunda güç düğmesine basmak yeterlidir ve Flipper, bildiği tüm TV'lerin "Gücü Kapat" komutlarını **sırasıyla gönderecektir**: Sony, Samsung, Panasonic... ve devam eder. TV sinyalini aldığında, tepki verecek ve kapanacaktır.

Bu tür bir brute-force zaman alır. Sözlük ne kadar büyükse, tamamlanması o kadar uzun sürer. TV'nin tam olarak hangi sinyali tanıdığını bulmak imkansızdır çünkü TV'den geri bildirim yoktur.

### Yeni Uzaktan Kumanda Öğrenme

Flipper Zero ile **kızılötesi bir sinyali yakalamak** mümkündür. Eğer **veritabanında sinyali bulursa**, Flipper otomatik olarak **bu cihazın ne olduğunu bilecektir** ve sizin onunla etkileşimde bulunmanıza izin verecektir.\
Eğer bulamazsa, Flipper **sinyali saklayabilir** ve **tekrar oynatmanıza** izin verecektir.

## Referanslar

- [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

{{#include ../../../banners/hacktricks-training.md}}
