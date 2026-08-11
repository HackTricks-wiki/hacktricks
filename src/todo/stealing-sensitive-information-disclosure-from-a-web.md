# Kuiba Taarifa Nyeti kutoka kwenye Ukurasa wa Wavuti

{{#include ../banners/hacktricks-training.md}}

Ikiwa **ukurasa wa wavuti unaonyesha taarifa nyeti kulingana na session ya sasa**—kama vile cookies, data ya akaunti, au maelezo ya kadi ya mkopo—attacker anaweza kujaribu kuzi-exfiltrate. Mbinu kuu ni pamoja na:

- [**CORS bypass**](../pentesting-web/cors-bypass.md): Misconfiguration ya CORS inaweza kuruhusu origin hasidi kusoma majibu nyeti kupitia maombi ya cross-origin.
- [**XSS**](../pentesting-web/xss-cross-site-scripting/index.html): Vulnerability ya XSS kwenye origin lengwa inaweza kuruhusu JavaScript iliyoingizwa kusoma na ku-exfiltrate taarifa.
- [**Dangling markup**](../pentesting-web/dangling-markup-html-scriptless-injection/index.html): Wakati script injection haipatikani, HTML elements zilizoingizwa bado zinaweza kunasa maudhui nyeti.
- [**Clickjacking**](../pentesting-web/clickjacking.md): Ikiwa ulinzi wa framing haupo, attacker anaweza kumdanganya mtumiaji kuingiliana na ukurasa nyeti. Case study iliyounganishwa inaonyesha mbinu hii.<sup>[[1]](#references)</sup>

## References

- [1] [Apache example servlet husababisha Disclosure ya Taarifa](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)
{{#include ../banners/hacktricks-training.md}}
