# PDF Dosya analizi

{{#include ../../../banners/hacktricks-training.md}}

**Daha fazla bilgi için kontrol edin:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)

PDF formatı, karmaşıklığı ve verileri gizleme potansiyeli ile bilinir, bu da onu CTF adli bilişim zorlukları için bir odak noktası haline getirir. Düz metin unsurlarını, sıkıştırılmış veya şifrelenmiş olabilecek ikili nesnelerle birleştirir ve JavaScript veya Flash gibi dillerdeki betikleri içerebilir. PDF yapısını anlamak için Didier Stevens'ın [giriş materyaline](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) başvurulabilir veya bir metin düzenleyici veya Origami gibi PDF'ye özel bir düzenleyici kullanılabilir.

PDF'lerin derinlemesine keşfi veya manipülasyonu için [qpdf](https://github.com/qpdf/qpdf) ve [Origami](https://github.com/mobmewireless/origami-pdf) gibi araçlar mevcuttur. PDF'lerdeki gizli veriler şunlarda gizlenebilir:

- Görünmez katmanlar
- Adobe tarafından sağlanan XMP meta veri formatı
- Artan nesil
- Arka planla aynı renkteki metin
- Resimlerin arkasındaki metin veya üst üste binen resimler
- Gösterilmeyen yorumlar

Özel PDF analizi için, [PeepDF](https://github.com/jesparza/peepdf) gibi Python kütüphaneleri, özel ayrıştırma betikleri oluşturmak için kullanılabilir. Ayrıca, PDF'nin gizli veri depolama potansiyeli o kadar geniştir ki, NSA'nın PDF riskleri ve karşı önlemleri üzerine rehberi gibi kaynaklar, artık orijinal konumunda barındırılmasa da, hala değerli bilgiler sunmaktadır. [Rehberin bir kopyası](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) ve Ange Albertini tarafından hazırlanan [PDF formatı hileleri](https://github.com/corkami/docs/blob/master/PDF/PDF.md) koleksiyonu, konu hakkında daha fazla okuma sağlayabilir.

{{#include ../../../banners/hacktricks-training.md}}
