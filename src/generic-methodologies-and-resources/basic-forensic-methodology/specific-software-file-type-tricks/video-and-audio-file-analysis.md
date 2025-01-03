{{#include ../../../banners/hacktricks-training.md}}

**Ses ve video dosyası manipülasyonu**, **CTF adli bilişim zorlukları** için temel bir unsurdur ve gizli mesajları saklamak veya ortaya çıkarmak için **steganografi** ve meta veri analizinden yararlanır. **[mediainfo](https://mediaarea.net/en/MediaInfo)** ve **`exiftool`** gibi araçlar, dosya meta verilerini incelemek ve içerik türlerini tanımlamak için gereklidir.

Ses zorlukları için, **[Audacity](http://www.audacityteam.org/)**, dalga formlarını görüntülemek ve ses spektrumlarını analiz etmek için öne çıkan bir araçtır; bu, ses içinde kodlanmış metni ortaya çıkarmak için gereklidir. **[Sonic Visualiser](http://www.sonicvisualiser.org/)**, detaylı spektrum analizi için şiddetle tavsiye edilir. **Audacity**, gizli mesajları tespit etmek için parçaları yavaşlatma veya tersine çevirme gibi ses manipülasyonlarına olanak tanır. **[Sox](http://sox.sourceforge.net/)**, ses dosyalarını dönüştürme ve düzenleme konusunda uzmanlaşmış bir komut satırı aracıdır.

**En Az Anlamlı Bitler (LSB)** manipülasyonu, ses ve video steganografisinde yaygın bir tekniktir ve medya dosyalarının sabit boyutlu parçalarını kullanarak verileri gizlice yerleştirir. **[Multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng)**, **DTMF tonları** veya **Morse kodu** olarak gizlenmiş mesajları çözmek için faydalıdır.

Video zorlukları genellikle ses ve video akışlarını bir araya getiren konteyner formatlarını içerir. **[FFmpeg](http://ffmpeg.org/)**, bu formatları analiz etmek ve manipüle etmek için başvurulan araçtır; içeriği de-multiplexing yapabilir ve oynatabilir. Geliştiriciler için, **[ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html)**, FFmpeg'in yeteneklerini Python'a entegre ederek gelişmiş scriptable etkileşimler sağlar.

Bu araçlar dizisi, CTF zorluklarında gereken çok yönlülüğü vurgular; katılımcılar, ses ve video dosyaları içinde gizli verileri ortaya çıkarmak için geniş bir analiz ve manipülasyon teknikleri yelpazesini kullanmalıdır.

## References

- [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)

{{#include ../../../banners/hacktricks-training.md}}
