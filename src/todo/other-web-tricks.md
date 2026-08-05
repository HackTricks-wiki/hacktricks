# Ostale Web trikove

{{#include ../banners/hacktricks-training.md}}

### Host header

U više navrata back-end veruje **Host header-u** za izvršavanje određenih radnji. Na primer, može koristiti njegovu vrednost kao **domen na koji treba poslati resetovanje lozinke**. Dakle, kada primite email sa linkom za resetovanje lozinke, koristi se domen koji ste naveli u Host header-u. Zatim možete zatražiti resetovanje lozinke drugih korisnika i promeniti domen na domen koji je pod vašom kontrolom kako biste ukrali njihove kodove za resetovanje lozinke. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).<sup>[[1]](#references)</sup>

> [!WARNING]
> Imajte na umu da možda čak ne morate čekati da korisnik klikne na link za resetovanje lozinke da biste dobili token, jer je moguće da će **spam filteri ili drugi posrednički uređaji/botovi kliknuti na njega radi analize**.

### Booleanske vrednosti sesije

Ponekad, kada ispravno završite određenu verifikaciju, back-end će **samo dodati booleansku vrednost "True" bezbednosnom atributu vaše sesije**. Zatim će drugi endpoint proveriti da li ste uspešno prošli tu proveru.\
Međutim, ako **prođete proveru** i vašoj sesiji bude dodeljena vrednost "True" u bezbednosnom atributu, možete pokušati da **pristupite drugim resursima** koji **zavise od istog atributa**, ali za koje **ne bi trebalo da imate dozvole**. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).<sup>[[2]](#references)</sup>

### Funkcionalnost registracije

Pokušajte da se registrujete kao već postojeći korisnik. Takođe pokušajte da koristite ekvivalentne karaktere (tačke, mnogo razmaka i Unicode).

### Preuzimanje email naloga

Registrujte email adresu, a pre nego što je potvrdite promenite email adresu; zatim, ako se novi email za potvrdu pošalje na prvu registrovanu email adresu, možete preuzeti bilo koju email adresu. Ili, ako možete omogućiti drugu email adresu potvrđivanjem prve, takođe možete preuzeti bilo koji nalog.

### Pristup internom servicedesk-u kompanija koje koriste atlassian


{{#ref}}
https://yourcompanyname.atlassian.net/servicedesk/customer/user/login
{{#endref}}

### TRACE metoda

Programeri mogu zaboraviti da onemoguće različite debugging opcije u production okruženju. Na primer, HTTP `TRACE` metoda je namenjena dijagnostici. Ako je omogućena, web server će odgovoriti na zahteve koji koriste `TRACE` metodu tako što će u odgovoru ispisati tačan zahtev koji je primljen. Ovo ponašanje je često bezopasno, ali povremeno dovodi do otkrivanja informacija, kao što je naziv internih authentication header-a koje reverse proxy-ji mogu dodati zahtevima.![Image for post](https://miro.medium.com/max/60/1*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Image for post](https://miro.medium.com/max/1330/1*wDFRADTOd9Tj63xucenvAA.png)

## Reference

- [1] [Kako sam uspeo da preuzmem bilo čiji nalog pomoću Host Header injection-a](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2)
- [2] [Manje poznat attack vector: Second order IDOR attacks](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a)

{{#include ../banners/hacktricks-training.md}}
