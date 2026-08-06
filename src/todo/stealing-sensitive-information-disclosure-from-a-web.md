# Sensitiewe inligting uit 'n Web steel

{{#include ../banners/hacktricks-training.md}}

As jy op enige stadium 'n **webblad vind wat sensitiewe inligting op grond van jou sessie vertoon**: Miskien reflekteer dit cookies, of vertoon dit kredietkaartbesonderhede of enige ander sensitiewe inligting, kan jy probeer om dit te steel.\
Hier bied ek die belangrikste maniere aan waarop jy dit kan probeer regkry:

- [**CORS bypass**](../pentesting-web/cors-bypass.md): As jy CORS headers kan omseil, sal jy die inligting kan steel deur 'n Ajax request vir 'n kwaadwillige bladsy uit te voer.
- [**XSS**](../pentesting-web/xss-cross-site-scripting/index.html): As jy 'n XSS vulnerability op die bladsy vind, kan jy dit moontlik misbruik om die inligting te steel.
- [**Danging Markup**](../pentesting-web/dangling-markup-html-scriptless-injection/index.html): As jy nie XSS tags kan inject nie, kan jy moontlik steeds die inligting steel deur ander gewone HTML tags te gebruik.
- [**Clickjaking**](../pentesting-web/clickjacking.md): As daar geen beskerming teen hierdie attack is nie, kan jy die gebruiker moontlik mislei om die sensitiewe data aan jou te stuur ('n voorbeeld [hier](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)).<sup>[[1]](#references)</sup>

## Verwysings

- [1] [Apache example servlet lei tot Information Disclosure](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)

{{#include ../banners/hacktricks-training.md}}
