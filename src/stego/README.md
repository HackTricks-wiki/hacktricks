# Stego

{{#include ../banners/hacktricks-training.md}}

Bu bölüm, dosyalardan (görüntüler/ses/video/belgeler/arşivler) ve metin tabanlı steganografiden **gizli verileri bulmaya ve çıkarmaya** odaklanır.

Kriptografik saldırılarla ilgileniyorsanız **Crypto** bölümüne gidin.

## Başlangıç Noktası

Steganografiye bir adli bilişim problemi olarak yaklaşın: gerçek container'ı belirleyin, yüksek sinyalli konumları (metadata, eklenmiş veriler, gömülü dosyalar) tarayın ve ancak bundan sonra içerik düzeyinde extraction tekniklerini uygulayın.

### Workflow ve triage

Container identification, metadata/string inspection, carving ve formata özgü dallanmayı önceliklendiren yapılandırılmış bir workflow.

{{#ref}}
workflow/README.md
{{#endref}}

### Görüntüler

CTF stego çalışmalarının çoğu burada yer alır: LSB/bit-planes (PNG/BMP), chunk/file-format anormallikleri, JPEG araçları ve çok kareli GIF hileleri.

{{#ref}}
images/README.md
{{#endref}}

### Ses

Spectrogram mesajları, sample LSB embedding ve telefon tuş takımı tonları (DTMF) tekrarlanan kalıplardır.

{{#ref}}
audio/README.md
{{#endref}}

### Metin

Metin normal şekilde görüntüleniyor ancak beklenmedik davranıyorsa Unicode homoglyph'lerini, zero-width karakterleri veya whitespace tabanlı encoding'i değerlendirin.

{{#ref}}
text/README.md
{{#endref}}

### Belgeler

PDF'ler ve Office dosyaları öncelikle container'lardır; saldırılar genellikle gömülü dosyalar/stream'ler, object/relationship graph'ları ve ZIP extraction etrafında şekillenir.

{{#ref}}
documents/README.md
{{#endref}}

### Malware ve delivery tarzı steganografi

Payload delivery sıklıkla pixel-level hiding yerine marker-delimited text payload'ları taşıyan, geçerli görünen dosyaları (ör. GIF/PNG) kullanır.

{{#ref}}
malware-and-network/README.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
