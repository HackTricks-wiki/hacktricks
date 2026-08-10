# Video ve Ses Dosyası Analizi

**Ses ve video dosyası manipülasyonu**, gizli mesajları saklamak veya ortaya çıkarmak için **steganography** ve metadata analizinden yararlanan **CTF forensics challenges** kapsamında temel bir tekniktir. **[mediainfo](https://mediaarea.net/en/MediaInfo)** ve **`exiftool`** gibi araçlar, dosya metadata'sını incelemek ve içerik türlerini belirlemek için gereklidir.<sup>[[1]](#references)</sup>

Ses challenges için **[Audacity](http://www.audacityteam.org/)**, metin olarak kodlanmış verileri ortaya çıkarmak için gerekli olan waveforms görüntüleme ve spectrogram analizinde öne çıkan bir araçtır. Ayrıntılı spectrogram analizi için **[Sonic Visualiser](http://www.sonicvisualiser.org/)** şiddetle tavsiye edilir. **Audacity**, gizli mesajları tespit etmek için parçaları yavaşlatma veya tersine çevirme gibi ses manipülasyonlarına olanak tanır. Bir command-line utility olan **[Sox](http://sox.sourceforge.net/)**, ses dosyalarını dönüştürme ve düzenleme konusunda başarılıdır.<sup>[[1]](#references)</sup>

**Least Significant Bits (LSB)** manipülasyonu, verileri fark edilmeden gömmek için media files içindeki sabit boyutlu chunk'lardan yararlanan, ses ve video steganography'sinde yaygın bir tekniktir. **[Multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng)**, **DTMF tones** veya **Morse code** olarak gizlenmiş mesajların decoding işlemi için kullanışlıdır.<sup>[[1]](#references)</sup>

Video challenges genellikle ses ve video stream'lerini bir araya getiren container formats içerir. **[FFmpeg](http://ffmpeg.org/)**, bu formatları analiz etmek ve manipüle etmek için tercih edilen araçtır; içeriği de-multiplex etme ve oynatma yeteneğine sahiptir. Developers için **[ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html)**, gelişmiş scriptable etkileşimler için FFmpeg'in yeteneklerini Python'a entegre eder.<sup>[[1]](#references)</sup>

Bu araç dizisi, CTF challenges kapsamında gereken çok yönlülüğü vurgular; katılımcılar ses ve video dosyaları içindeki gizli verileri ortaya çıkarmak için geniş bir analiz ve manipülasyon teknikleri yelpazesi kullanmalıdır.

## References

- [1] [Video ve Ses dosyası analizi – Trail of Bits CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)
{{#include ../../../banners/hacktricks-training.md}}
