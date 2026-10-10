# Stego

{{#include ../banners/hacktricks-training.md}}

Bu bölüm; görsellerden, seslerden, videolardan, belgelerden, arşivlerden ve metinlerden **gizli verileri bulmaya ve çıkarmaya** odaklanır. Steganografi, verileri başka verilerin içine yerleştirerek iletişimin varlığını gizler.<sup>[[1]](#references)</sup>

Kriptografik saldırılar için buradaysanız **Crypto** bölümüne gidin.

## Başlangıç Noktası

Steganografiyi bir adli bilişim problemi olarak ele alın: gerçek kapsayıcıyı belirleyin, yüksek sinyal değerine sahip konumları (metadata, eklenmiş veriler, gömülü dosyalar) tarayın ve ancak bundan sonra içerik düzeyinde çıkarma tekniklerini uygulayın.

### İş akışı ve önceliklendirme

Kapsayıcı tanımlamaya, metadata ve dizgeleri incelemeye, carving'e ve biçime özgü dallanmaya öncelik veren yapılandırılmış bir iş akışı.

{{#ref}}
workflow/README.md
{{#endref}}

### Görseller

CTF stego çalışmalarının çoğu burada yer alır: LSB/bit düzlemleri (PNG/BMP), parça/dosya biçimi tuhaflıkları, JPEG araçları ve çok kareli GIF numaraları.

{{#ref}}
images/README.md
{{#endref}}

### Ses

Spektrogram mesajları, örneklerde LSB gömme ve telefon tuş takımı tonları (DTMF) sık karşılaşılan örüntülerdir.

{{#ref}}
audio/README.md
{{#endref}}

### Metin

Metin normal şekilde görüntüleniyor ama beklenmedik davranıyorsa Unicode homogliflerini, sıfır genişlikli karakterleri veya boşluk tabanlı kodlamayı göz önünde bulundurun.

{{#ref}}
text/README.md
{{#endref}}

### Belgeler

PDF ve Office dosyaları öncelikle kapsayıcılardır; saldırılar genellikle gömülü dosyalar/akışlar, nesne/ilişki grafikleri ve ZIP çıkarma etrafında şekillenir.

{{#ref}}
documents/README.md
{{#endref}}

### Malware ve teslimat tarzı steganografi

Payload teslimatı, verileri piksellerde gizlemek yerine işaretçilerle sınırlandırılmış metin payload'ları taşıyan, GIF veya PNG görselleri gibi geçerli görünen dosyaları kullanabilir.

{{#ref}}
malware-and-network/README.md
{{#endref}}

## References

- [1] [NIST CSRC Sözlüğü - Steganografi](https://csrc.nist.gov/glossary/term/steganography)
{{#include ../banners/hacktricks-training.md}}
