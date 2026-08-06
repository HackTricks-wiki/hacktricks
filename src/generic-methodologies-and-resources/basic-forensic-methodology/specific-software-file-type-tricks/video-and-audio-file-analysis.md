# Video ve Audio File Analysis

{{#include ../../../banners/hacktricks-training.md}}

**Audio ve video file manipulation**, **steganography** ve metadata analysis kullanarak gizli mesajları saklama veya ortaya çıkarma amacıyla **CTF forensics challenges** içinde yaygın olarak kullanılır. **[mediainfo](https://mediaarea.net/en/MediaInfo)** ve **`exiftool`** gibi araçlar, file metadata'sını incelemek ve content türlerini belirlemek için gereklidir.<sup>[[1]](#references)</sup>

Audio challenges için **[Audacity](http://www.audacityteam.org/)**, waveform'ları görüntüleme ve audio içine kodlanmış metinleri ortaya çıkarmak için gerekli olan spectrogram'ları analiz etme konusunda öne çıkan bir araçtır. Ayrıntılı spectrogram analysis için **[Sonic Visualiser](http://www.sonicvisualiser.org/)** şiddetle önerilir. **Audacity**, gizli mesajları tespit etmek için track'leri yavaşlatma veya tersine çevirme gibi audio manipulation işlemlerine olanak tanır. Bir command-line utility olan **[Sox](http://sox.sourceforge.net/)**, audio file'larını dönüştürme ve düzenleme konusunda başarılıdır.<sup>[[1]](#references)</sup>

**Least Significant Bits (LSB)** manipulation, verileri gizlice gömmek için media file'larının sabit boyutlu chunk'larından yararlanan, audio ve video steganography'de yaygın bir tekniktir. **[Multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng)**, **DTMF tones** veya **Morse code** olarak gizlenmiş mesajları decode etmek için kullanışlıdır.<sup>[[1]](#references)</sup>

Video challenges genellikle audio ve video stream'lerini bir araya getiren container format'larını içerir. **[FFmpeg](http://ffmpeg.org/)**, bu format'ları analiz etmek ve manipulation işlemlerinden geçirmek için başvurulan araçtır; içeriği de-multiplex etme ve oynatma yeteneğine sahiptir. Developer'lar için **[ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html)**, gelişmiş script edilebilir etkileşimler için FFmpeg'in yeteneklerini Python'a entegre eder.<sup>[[1]](#references)</sup>

Bu araçlar, **CTF challenges** içinde gereken versatility'yi ortaya koyar; katılımcılar audio ve video file'ları içindeki gizli verileri ortaya çıkarmak için geniş bir analysis ve manipulation teknikleri yelpazesi kullanmalıdır.

## Referanslar

- [1] [Video ve Audio file analysis – Trail of Bits CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)

{{#include ../../../banners/hacktricks-training.md}}
