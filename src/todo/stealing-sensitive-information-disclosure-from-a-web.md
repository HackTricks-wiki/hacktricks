# Krađa osetljivih informacija iz Disclosure-a na Webu

{{#include ../banners/hacktricks-training.md}}

Ako u nekom trenutku pronađete **web stranicu koja prikazuje osetljive informacije na osnovu vaše sesije**: Možda odražava cookies, ili ispisuje podatke o karticama ili neke druge osetljive informacije, možete pokušati da ih ukradete.\
Ovde su predstavljeni glavni načini na koje to možete pokušati:

- [**CORS bypass**](../pentesting-web/cors-bypass.md): Ako možete zaobići CORS headers, moći ćete da ukradete informacije izvršavanjem Ajax zahteva za malicious stranicu.
- [**XSS**](../pentesting-web/xss-cross-site-scripting/index.html): Ako pronađete XSS vulnerability na stranici, možda ćete moći da je iskoristite za krađu informacija.
- [**Danging Markup**](../pentesting-web/dangling-markup-html-scriptless-injection/index.html): Ako ne možete da ubacite XSS tags, možda ćete i dalje moći da ukradete informacije koristeći druge uobičajene HTML tags.
- [**Clickjaking**](../pentesting-web/clickjacking.md): Ako ne postoji zaštita od ovog attack-a, možda ćete moći da prevarite korisnika da vam pošalje osetljive podatke (primer je dostupan [ovde](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)).<sup>[[1]](#references)</sup>

## Reference

- [1] [Apache example servlet leads to Information Disclosure](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)

{{#include ../banners/hacktricks-training.md}}
