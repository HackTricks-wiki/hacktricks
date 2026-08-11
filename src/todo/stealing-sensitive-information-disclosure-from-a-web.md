# Krađa osetljivih informacija sa web stranice

{{#include ../banners/hacktricks-training.md}}

Ako **web stranica prikazuje osetljive informacije na osnovu trenutne sesije**—kao što su cookies, podaci o nalogu ili podaci kreditne kartice—napadač može pokušati da ih eksfiltrira. Glavne tehnike uključuju:

- [**CORS bypass**](../pentesting-web/cors-bypass.md): CORS misconfiguration može omogućiti zlonamernom originu da čita osetljive odgovore putem cross-origin zahteva.
- [**XSS**](../pentesting-web/xss-cross-site-scripting/index.html): XSS ranjivost u ciljnom originu može omogućiti ubačenom JavaScript-u da pročita i eksfiltrira informacije.
- [**Dangling markup**](../pentesting-web/dangling-markup-html-scriptless-injection/index.html): Kada injection skripte nije dostupan, ubačeni HTML elementi i dalje mogu uhvatiti osetljiv sadržaj.
- [**Clickjacking**](../pentesting-web/clickjacking.md): Ako zaštite od framing-a nisu prisutne, napadač može prevariti korisnika da stupi u interakciju sa osetljivom stranicom. Povezana studija slučaja pokazuje ovu tehniku.<sup>[[1]](#references)</sup>

## References

- [1] [Apache primer servlet-a dovodi do otkrivanja informacija](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)
{{#include ../banners/hacktricks-training.md}}
