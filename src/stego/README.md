# Stego

{{#include ../banners/hacktricks-training.md}}

Bu bölüm; görsellerden, seslerden, videolardan, belgelerden, arşivlerden ve metinlerden **gizli verileri bulmaya ve çıkarmaya** odaklanır. Steganography, verileri başka verilerin içine yerleştirerek bir iletişimin varlığını gizler.<sup>[[1]](#references)</sup>

Kriptografik saldırılar için buradaysanız **Crypto** bölümüne gidin.

## Entry Point

Steganography'yi bir adli bilişim problemi olarak ele alın: gerçek kapsayıcıyı belirleyin, yüksek sinyalli konumları (metadata, eklenmiş veriler, gömülü dosyalar) listeleyin ve ancak bundan sonra içerik düzeyinde extraction tekniklerini uygulayın.

### İş akışı ve triage

Kapsayıcı tanımlamayı, metadata/string incelemesini, carving işlemini ve formata özel dallanmayı önceliklendiren yapılandırılmış bir iş akışı.

{{#ref}}
workflow/README.md
{{#endref}}

### Görseller

CTF stego işlemlerinin çoğunun bulunduğu alan: LSB/bit düzlemleri (PNG/BMP), chunk/dosya formatı anormallikleri, JPEG araçları ve çok kareli GIF hileleri.

{{#ref}}
images/README.md
{{#endref}}

### Ses

Spektrogram mesajları, sample LSB embedding ve telefon tuş takımı tonları (DTMF) tekrarlanan kalıplardır.

{{#ref}}
audio/README.md
{{#endref}}

### Metin

Metin normal şekilde görüntüleniyor ancak beklenmedik davranıyorsa Unicode homoglyph'lerini, zero-width karakterleri veya whitespace tabanlı encoding'i değerlendirin.

{{#ref}}
text/README.md
{{#endref}}

### Belgeler

PDF'ler ve Office dosyaları öncelikle kapsayıcılardır; saldırılar genellikle gömülü dosyalar/stream'ler, object/relationship grafikleri ve ZIP extraction etrafında şekillenir.

{{#ref}}
documents/README.md
{{#endref}}

### Malware ve delivery tarzı steganography

Payload delivery, verileri piksellerde gizlemek yerine marker ile ayrılmış text payload'ları taşıyan GIF veya PNG görselleri gibi geçerli görünen dosyaları kullanabilir.

{{#ref}}
malware-and-network/README.md
{{#endref}}

## References

- [1] [NIST CSRC Sözlüğü - Steganography](https://csrc.nist.gov/glossary/term/steganography)
{{#include ../banners/hacktricks-training.md}}
