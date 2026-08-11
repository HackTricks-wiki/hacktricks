# Crypto CTF Misc

{{#include ../../banners/hacktricks-training.md}}

Bu bölüm, cryptography challenge'larında ortaya çıkan ancak diğer kategorilere tam olarak uymayan teknikleri içerir.

## Esoteric languages

### Technique

Bir challenge, esoteric-language programı çalıştırmayı ve çıktısını decode etmeyi gerektirdiğinde bu iş akışını kullanın.

Bir challenge size standart bir dile benzemeyen bir code verirse:

- Ayırt edici bir token veya instruction sequence arayarak dili belirleyin.
- Bir online interpreter veya Docker image kullanın.
- Çıktı garipse execution sonrasında katmanlı encoding/compression olup olmadığını kontrol edin.

Yararlı bir language index'i Esolang wiki'dir.<sup>[[1]](#references)</sup>

## References

- [1] [Esolang, esoteric programming languages wiki](https://esolangs.org/wiki/Main_Page)
{{#include ../../banners/hacktricks-training.md}}
