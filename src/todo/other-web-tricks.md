# Ostali trikovi na webu

{{#include ../banners/hacktricks-training.md}}

## Host header

Back end sistemi ponekad veruju HTTP `Host` polju prilikom konstruisanja apsolutnih linkova. Ako email za resetovanje lozinke koristi host koji je dostavio napadač, slanje zahteva za resetovanje naloga žrtve može proslediti link sa tokenom kroz domen koji kontroliše napadač. Takođe testirajte forwarded-host polja, obradu dupliranih Host zaglavlja i request target-e u apsolutnom obliku na svakom proxy hop-u.<sup>[[1]](#references)</sup>

> [!WARNING]
> Klik korisnika možda nije neophodan: **mail security skeneri, preview servisi ili drugi posrednici mogu automatski zatražiti link koji kontroliše napadač**, čime se otkriva reset token.

## Boolean vrednosti sesije

Neke aplikacije beleže završenu verifikaciju kao boolean vrednost u sesiji, a zatim dopuštaju drugom endpoint-u da se osloni na tu zastavicu. Nakon što legitimno prođete proveru za jedan resurs, testirajte da li ista zastavica greškom autorizuje drugog korisnika, objekat ili workflow. Ovo je second-order authorization/state-reuse propust, a ne samo IDOR.<sup>[[2]](#references)</sup>

## Funkcionalnost registracije

Pokušajte da se registrujete kao već postojeći korisnik. Takođe pokušajte da koristite ekvivalentne karaktere (tačke, mnogo razmaka i Unicode).

## Confusion stanja pri promeni email adrese

Registrujte email adresu i promenite je pre potvrđivanja. Proverite da li se potvrda za novu adresu šalje na staru adresu ili da li potvrđivanje starog tokena aktivira novu adresu. Confirmation tokeni moraju biti vezani za tačan nalog, adresu na čekanju, svrhu i trenutno stanje.

## Izloženi Atlassian service desks


{{#ref}}
https://yourcompanyname.atlassian.net/servicedesk/customer/user/login
{{#endref}}

## TRACE metoda

HTTP `TRACE` metoda zahteva vraćanje primljenog request-a u petlji radi dijagnostike. RFC 9110 zahteva od primalaca da iz reflektovanog sadržaja izostave osetljiva polja, kao što su credential-i i cookies, ali nebezbedne implementacije ili zaglavlja dodata od strane posrednika i dalje mogu otkriti interne transformacije request-a. Browser-i sprečavaju script-generisane TRACE request-e, pa istorijski cross-site tracing napad takođe zavisi od zasebnog načina za ubacivanje zaštićenih polja.<sup>[[3]](#references)</sup>![Slika koja prikazuje TRACE response](https://miro.medium.com/max/60/1*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Slika za post](https://miro.medium.com/max/1330/1*wDFRADTOd9Tj63xucenvAA.png)

## References

- [1] [Kako sam uspeo da preuzmem bilo čiji korisnički nalog pomoću Host Header Injection napada](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2)
- [2] [Manje poznat attack vector: Second Order IDOR attacks](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a)
- [3] [RFC 9110, odeljak 9.3.8 — TRACE](https://www.rfc-editor.org/rfc/rfc9110.html#name-trace)
{{#include ../banners/hacktricks-training.md}}
