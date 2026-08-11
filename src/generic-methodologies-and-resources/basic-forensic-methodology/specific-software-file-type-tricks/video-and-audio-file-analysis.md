# Video ve Audio File Analysis

{{#include ../../../banners/hacktricks-training.md}}

**Audio ve video file manipulation**, **steganography** ve metadata analizinden yararlanarak gizli mesajları sakladığı veya ortaya çıkardığı için **CTF forensics challenges** alanının temel unsurlarındandır. **[mediainfo](https://mediaarea.net/en/MediaInfo)** ve **`exiftool`** gibi araçlar, file metadata'sını incelemek ve content types'ı belirlemek için gereklidir.<sup>[[1]](#references)</sup>

Audio challenges için **[Audacity](http://www.audacityteam.org/)**, waveforms görüntüleme ve audio'da kodlanmış metinleri ortaya çıkarmak için gerekli olan spectrograms analizinde öne çıkan bir araçtır. Ayrıntılı spectrogram analizi için **[Sonic Visualiser](http://www.sonicvisualiser.org/)** kesinlikle önerilir. **Audacity**, gizli mesajları tespit etmek için tracks'leri yavaşlatma veya tersine çevirme gibi audio manipulation işlemlerine olanak tanır. Bir command-line utility olan **[Sox](http://sox.sourceforge.net/)**, audio files'ı dönüştürme ve düzenleme konusunda başarılıdır.<sup>[[1]](#references)</sup>

**Least Significant Bits (LSB)** manipulation, media files'ın sabit boyutlu chunks'larından yararlanarak verileri fark edilmeden gömmek için audio ve video steganography'de kullanılan yaygın bir tekniktir. **[Multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng)**, **DTMF tones** veya **Morse code** olarak gizlenmiş mesajların decode edilmesi için kullanışlıdır.<sup>[[1]](#references)</sup>

Video challenges genellikle audio ve video streams'lerini bir araya getiren container formats'ı içerir. **[FFmpeg](http://ffmpeg.org/)**, bu formats'ları analiz etmek ve manipulate etmek için başvurulan araçtır; içeriği de-multiplex etme ve oynatma yeteneğine sahiptir. Developers için **[ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html)**, gelişmiş scriptable interactions için FFmpeg'in yeteneklerini Python'a entegre eder.<sup>[[1]](#references)</sup>

Bu araçlar dizisi, CTF challenges'larında gereken versatility'yi vurgular; katılımcılar audio ve video files içindeki gizli verileri ortaya çıkarmak için geniş bir analiz ve manipulation teknikleri yelpazesi kullanmalıdır.

## References

- [1] [Video ve Audio file analysis – Trail of Bits CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)
{{#include ../../../banners/hacktricks-training.md}}
