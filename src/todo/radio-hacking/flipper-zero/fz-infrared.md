# FZ - Kızılötesi

{{#include ../../../banners/hacktricks-training.md}}

## Giriş <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Kızılötesinin nasıl çalıştığı hakkında daha fazla bilgi için:


{{#ref}}
../infrared.md
{{#endref}}

## Flipper Zero'da IR Sinyal Alıcısı <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper, **IR uzaktan kumandalarından gelen sinyallerin yakalanmasına olanak tanıyan** TSOP adlı dijital bir IR sinyal alıcısı kullanır. Xiaomi gibi IR bağlantı noktasına sahip bazı **akıllı telefonlar** da vardır, ancak **çoğunun yalnızca sinyal gönderebildiğini** ve **sinyal alamadığını** unutmayın.<sup>[[1]](#references)</sup>

Flipper'ın kızılötesi **alıcısı oldukça hassastır**. Hatta kumanda ile TV'nin **arasında bir yerde** dururken bile **sinyali yakalayabilirsiniz**. Kumandayı doğrudan Flipper'ın IR bağlantı noktasına doğrultmak gerekli değildir. Bu, biri TV'nin yanında durarak kanalları değiştirirken sizin ve Flipper'ın biraz uzakta olduğunuz durumlarda işe yarar.

Kızılötesi sinyalin **kod çözme işlemi** yazılım tarafında gerçekleştiği için Flipper Zero, potansiyel olarak **her türlü IR uzaktan kumanda kodunu almayı ve iletmeyi** destekler. Tanınamayan ve **bilinmeyen** protokoller söz konusu olduğunda sinyali alınan haliyle **kaydeder ve oynatır**.<sup>[[1]](#references)</sup>

## Eylemler

### Evrensel Kumandalar

Flipper Zero, **herhangi bir TV'yi, klimayı veya medya merkezini kontrol etmek için evrensel kumanda** olarak kullanılabilir. Bu modda Flipper, **SD karttaki sözlüğe göre** desteklenen tüm üreticilerin **bilinen tüm kodlarına bruteforce uygular**. Bir restoranın TV'sini kapatmak için belirli bir kumanda seçmenize gerek yoktur.<sup>[[1]](#references)</sup>

Evrensel Kumanda modunda güç düğmesine basmak yeterlidir; Flipper bildiği tüm TV'lerin **"Power Off"** komutlarını sırayla gönderir: Sony, Samsung, Panasonic... ve diğerleri. TV kendi sinyalini aldığında tepki verir ve kapanır.

Bu tür bir bruteforce zaman alır. Sözlük ne kadar büyükse işlemin tamamlanması da o kadar uzun sürer. TV'den herhangi bir geri bildirim gelmediği için TV'nin tam olarak hangi sinyali tanıdığını öğrenmek mümkün değildir.

### Yeni Kumanda Öğren

Flipper Zero ile **bir kızılötesi sinyali yakalamak** mümkündür. Sinyali **veritabanında bulursa** Flipper bunun **hangi cihaza ait olduğunu otomatik olarak bilir** ve cihazla etkileşim kurmanıza olanak tanır.\
Bulamazsa Flipper **sinyali depolayabilir** ve **yeniden oynatmanıza** izin verir.<sup>[[1]](#references)</sup>

## Kaynaklar

- [1] [Flipper Zero'nun Kızılötesi Bağlantı Noktasıyla TV'leri Ele Geçirmek](https://blog.flipperzero.one/infrared/)

{{#include ../../../banners/hacktricks-training.md}}
