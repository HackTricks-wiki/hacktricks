# Steel van sensitiewe inligting vanaf ’n webblad

{{#include ../banners/hacktricks-training.md}}

As ’n **webblad sensitiewe inligting op grond van die huidige sessie vertoon**—soos cookies, rekeningdata of kredietkaartbesonderhede—kan ’n aanvaller probeer om dit te exfiltreer. Die belangrikste tegnieke sluit in:

- [**CORS bypass**](../pentesting-web/cors-bypass.md): ’n CORS-wankonfigurasie kan ’n kwaadwillige oorsprong toelaat om sensitiewe response deur cross-origin requests te lees.
- [**XSS**](../pentesting-web/xss-cross-site-scripting/index.html): ’n XSS-kwesbaarheid in die teiken-oorsprong kan geïnjekteerde JavaScript toelaat om die inligting te lees en te exfiltreer.
- [**Dangling markup**](../pentesting-web/dangling-markup-html-scriptless-injection/index.html): Wanneer script injection nie beskikbaar is nie, kan geïnjekteerde HTML-elemente steeds sensitiewe inhoud vaslê.
- [**Clickjacking**](../pentesting-web/clickjacking.md): As framing-beskerming ontbreek, kan ’n aanvaller ’n gebruiker mislei om met die sensitiewe bladsy te interaksieer. Die gekoppelde gevallestudie demonstreer hierdie tegniek.<sup>[[1]](#references)</sup>

## References

- [1] [Apache-voorbeeldservlet lei tot inligtingsopenbaarmaking](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)
{{#include ../banners/hacktricks-training.md}}
