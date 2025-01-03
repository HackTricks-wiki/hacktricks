# ZIP'ler için hileler

{{#include ../../../banners/hacktricks-training.md}}

**Komut satırı araçları**, **zip dosyalarını** yönetmek için, zip dosyalarını teşhis etmek, onarmak ve kırmak için gereklidir. İşte bazı anahtar yardımcı programlar:

- **`unzip`**: Bir zip dosyasının neden açılmadığını gösterir.
- **`zipdetails -v`**: Zip dosyası format alanlarının detaylı analizini sunar.
- **`zipinfo`**: Bir zip dosyasının içeriğini çıkarmadan listeler.
- **`zip -F input.zip --out output.zip`** ve **`zip -FF input.zip --out output.zip`**: Bozulmuş zip dosyalarını onarmaya çalışır.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Zip şifrelerini brute-force ile kırmak için bir araç, yaklaşık 7 karaktere kadar olan şifreler için etkilidir.

[Zip dosya formatı spesifikasyonu](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT), zip dosyalarının yapısı ve standartları hakkında kapsamlı bilgiler sunar.

Şifre korumalı zip dosyalarının **içindeki dosya adlarını veya dosya boyutlarını şifrelemediğini** belirtmek önemlidir; bu, RAR veya 7z dosyalarıyla paylaşılmayan bir güvenlik açığıdır. Ayrıca, daha eski ZipCrypto yöntemiyle şifrelenmiş zip dosyaları, sıkıştırılmış bir dosyanın şifrelenmemiş bir kopyası mevcutsa **düz metin saldırısına** karşı savunmasızdır. Bu saldırı, zip'in şifresini kırmak için bilinen içeriği kullanır; bu zayıflık [HackThis'in makalesinde](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) ve [bu akademik çalışmada](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf) detaylandırılmıştır. Ancak, **AES-256** şifrelemesiyle güvence altına alınmış zip dosyaları bu düz metin saldırısına karşı bağışıklık gösterir, bu da hassas veriler için güvenli şifreleme yöntemlerinin seçilmesinin önemini vurgular.

## Referanslar

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)

{{#include ../../../banners/hacktricks-training.md}}
