# Krađa Osetljivih Informacija putem Otkrića sa Veba

{{#include ./banners/hacktricks-training.md}}

Ako u nekom trenutku pronađete **vеб страницу koja vam prikazuje osetljive informacije na osnovu vaše sesije**: Možda odražava kolačiće, ili štampa ili CC detalje ili bilo koje druge osetljive informacije, možete pokušati da ih ukradete.\
Evo glavnih načina na koje možete pokušati da to postignete:

- [**CORS zaobilaženje**](pentesting-web/cors-bypass.md): Ako možete da zaobiđete CORS zaglavlja, moći ćete da ukradete informacije izvršavajući Ajax zahtev za zloćudnu stranicu.
- [**XSS**](pentesting-web/xss-cross-site-scripting/): Ako pronađete XSS ranjivost na stranici, možda ćete moći da je iskoristite da ukradete informacije.
- [**Danging Markup**](pentesting-web/dangling-markup-html-scriptless-injection/): Ako ne možete da injektujete XSS oznake, i dalje možete da ukradete informacije koristeći druge uobičajene HTML oznake.
- [**Clickjaking**](pentesting-web/clickjacking.md): Ako ne postoji zaštita protiv ovog napada, možda ćete moći da prevarite korisnika da vam pošalje osetljive podatke (primer [ovde](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)).

{{#include ./banners/hacktricks-training.md}}
