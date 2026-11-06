# Crypto CTF Misc

{{#include ../../banners/hacktricks-training.md}}

Bu bölüm, kriptografi challenge'larında kullanılan ancak diğer kategorilere tam olarak uymayan teknikleri içerir.

## Ezoterik diller

### Teknik

Bir challenge, ezoterik bir dil programını çalıştırıp çıktısını çözmenizi gerektiriyorsa bu iş akışını kullanın.

Bir challenge standart bir dile benzemeyen bir kod veriyorsa:

- Belirgin bir token veya komut dizisini arayarak dili belirleyin.
- Çevrimiçi bir interpreter veya Docker image kullanın.
- Çıktı tuhafsa çalıştırmanın ardından gelen katmanlı encoding veya compression işlemlerini araştırın.

Yararlı bir dil dizini Esolang wiki'dir.<sup>[[1]](#references)</sup> Sıradan encoding ve compression katmanları için [Crypto CTF workflow](../ctf-workflow/) bölümünü kullanın. İpucu, çalıştırılabilir sözdizimi yerine görünmez metinse [text steganography](../../stego/text/) bölümüne bakın.

### Önceden yüklenmiş interpreter durumunu dışarı aktarma

Bir challenge ezoterik dilde kaynak kodu kabul edip bunu **özel bir interpreter** içinde çalıştırıyorsa, kaynak kodu bir decoding bulmacası olarak değerlendirmeden önce interpreter'ın başlangıç belleğini, stack'ini ve çıktı komutlarını inceleyin. Interpreter, gizli bir veriyi Befunge stack'ine önceden yüklediğinde kısa bir program, bu veriyi hesaplamadan mevcut byte'ları stack'ten çıkarıp yazdırabilir. Bunun için çalıştırılan kaynak kodu kontrol edebilmeniz ve bir çıktı opcode'unun bulunması gerekir; normal, boş bir interpreter'da işe yaramaz. Bir Befunge challenge'ında aşağıdaki girdi, stack'e ters sırayla önceden yüklenmiş bir flag'den karakterleri art arda yazdırdı.<sup>[[2]](#references)[[3]](#references)</sup>

```befunge
>,<
```

`>` sağa doğru yürütmeyi başlatır, `,` bir karakteri stack'ten çıkarıp yazdırır ve `<` komut işaretçisini `,` konumuna geri gönderir. Özel interpreter'ın underflow ve komut sınırı davranışını kontrol edin: belirtilen uygulama, stack tükendiğinde veya 1.024 komut yürütüldükten sonra durur. Secret doğrudan stack'te değilse, standart Befunge semantiğini varsaymak yerine diğer başlatılmış durumu ve kullanılabilir çıktı/okuma komutlarını inceleyin.<sup>[[3]](#references)[[4]](#references)</sup>



## References

- [1] [Esolang, ezoterik programlama dilleri wiki'si](https://esolangs.org/wiki/Main_Page)
- [2] [WolvCTF 2024 Befuddled1 özgün writeup'ı](https://github.com/C0d3-Bre4k3rs/WolvCTF2024-Writeups/blob/main/befuddled1/README.md)
- [3] [WolvCTF 2024 Befuddled1 interpreter kaynak kodu](https://github.com/C0d3-Bre4k3rs/WolvCTF2024-Writeups/blob/main/befuddled1/files/befunge.py)
- [4] [Befunge dil referansı](https://esolangs.org/wiki/Befunge)
{{#include ../../banners/hacktricks-training.md}}
