# Stego

{{#include ../banners/hacktricks-training.md}}

Bu bölüm, dosyalardan (images/audio/video/documents/archives) ve metin tabanlı steganografiden gizli verilerin bulunması ve çıkarılmasına odaklanır.

If you're here for cryptographic attacks, go to the **Crypto** section.

## Giriş

Steganografiye adli bilişim problemi olarak yaklaşın: gerçek konteyneri tespit edin, yüksek-sinyalli konumları (metadata, appended data, embedded files) listeleyin ve ancak o zaman içerik düzeyinde çıkarma tekniklerini uygulayın.

### İş Akışı & triage

Konteyner tespitini, metadata/string incelemesini, carving'i ve formata özgü dallanmayı önceliklendiren yapılandırılmış bir iş akışı.
{{#ref}}
workflow/README.md
{{#endref}}

### Images

CTF stego'nun çoğunun bulunduğu yer: LSB/bit-planes (PNG/BMP), chunk/file-format weirdness, JPEG tooling ve multi-frame GIF tricks.
{{#ref}}
images/README.md
{{#endref}}

### Audio

Spektrogram mesajları, sample LSB embedding ve telephone keypad tones (DTMF) tekrar eden kalıplardır.
{{#ref}}
audio/README.md
{{#endref}}

### Text

Metin normal görünüyorsa ama beklenmedik şekilde davranıyorsa, Unicode homoglyphs, zero-width characters veya whitespace-based encoding'i göz önünde bulundurun.
{{#ref}}
text/README.md
{{#endref}}

### Documents

PDF'ler ve Office dosyaları öncelikle konteynerdir; saldırılar genellikle embedded files/streams, object/relationship graphs ve ZIP extraction etrafında döner.
{{#ref}}
documents/README.md
{{#endref}}

### Malware and delivery-style steganography

Payload delivery çoğunlukla pixel-level hiding yerine, marker-delimited text payloads taşıyan geçerli görünen dosyaları (ör. GIF/PNG) kullanır.
{{#ref}}
malware-and-network/README.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
