# Dief van Sensitiewe Inligting Ontbloot vanaf 'n Web

{{#include ../banners/hacktricks-training.md}}

As jy op 'n stadium 'n **webblad vind wat sensitiewe inligting op grond van jou sessie aan jou bied**: Miskien reflekteer dit koekies, of druk dit CC besonderhede of enige ander sensitiewe inligting, kan jy probeer om dit te steel.\
Hier bied ek jou die hoofmaniere aan om dit te probeer bereik:

- [**CORS omseiling**](../pentesting-web/cors-bypass.md): As jy CORS koptekste kan omseil, sal jy in staat wees om die inligting te steel deur 'n Ajax versoek vir 'n kwaadwillige bladsy uit te voer.
- [**XSS**](../pentesting-web/xss-cross-site-scripting/): As jy 'n XSS kwesbaarheid op die bladsy vind, mag jy dit kan misbruik om die inligting te steel.
- [**Danging Markup**](../pentesting-web/dangling-markup-html-scriptless-injection/): As jy nie XSS etikette kan inspuit nie, mag jy steeds in staat wees om die inligting te steel deur ander gewone HTML etikette te gebruik.
- [**Clickjaking**](../pentesting-web/clickjacking.md): As daar geen beskerming teen hierdie aanval is nie, mag jy die gebruiker kan mislei om jou die sensitiewe data te stuur (een voorbeeld [hier](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)).

{{#include ../banners/hacktricks-training.md}}
