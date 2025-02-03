# Other Web Tricks

{{#include ./banners/hacktricks-training.md}}

### Host header

Više puta back-end veruje **Host header** da izvrši neke radnje. Na primer, može koristiti njegovu vrednost kao **domen za slanje resetovanja lozinke**. Tako kada primite email sa linkom za resetovanje lozinke, domen koji se koristi je onaj koji ste stavili u Host header. Tada možete zatražiti resetovanje lozinke drugih korisnika i promeniti domen na onaj koji kontrolišete kako biste ukrali njihove kodove za resetovanje lozinke. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).

> [!WARNING]
> Imajte na umu da je moguće da ne morate ni da čekate da korisnik klikne na link za resetovanje lozinke da biste dobili token, jer možda čak i **spam filteri ili drugi posrednički uređaji/botovi će kliknuti na njega da ga analiziraju**.

### Session booleans

Nekada kada ispravno završite neku verifikaciju, back-end će **samo dodati boolean sa vrednošću "True" u sigurnosni atribut vaše sesije**. Tada, druga tačka će znati da ste uspešno prošli tu proveru.\
Međutim, ako **prođete proveru** i vašoj sesiji je dodeljena ta "True" vrednost u sigurnosnom atributu, možete pokušati da **pristupite drugim resursima** koji **zavise od istog atributa** ali za koje **ne biste trebali imati dozvole** za pristup. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).

### Register functionality

Pokušajte da se registrujete kao već postojeći korisnik. Takođe pokušajte koristiti ekvivalentne karaktere (tačke, puno razmaka i Unicode).

### Takeover emails

Registrujte email, pre nego što ga potvrdite promenite email, zatim, ako je novi email za potvrdu poslat na prvi registrovani email, možete preuzeti bilo koji email. Ili ako možete omogućiti drugi email koji potvrđuje prvi, takođe možete preuzeti bilo koji nalog.

### Access Internal servicedesk of companies using atlassian

{{#ref}}
https://yourcompanyname.atlassian.net/servicedesk/customer/user/login
{{#endref}}

### TRACE method

Programeri mogu zaboraviti da onemoguće razne opcije za debagovanje u produkcionom okruženju. Na primer, HTTP `TRACE` metoda je dizajnirana za dijagnostičke svrhe. Ako je omogućena, web server će odgovoriti na zahteve koji koriste `TRACE` metodu tako što će u odgovoru ponoviti tačan zahtev koji je primljen. Ovo ponašanje je često bezopasno, ali povremeno dovodi do otkrivanja informacija, kao što su imena internih autentifikacionih zaglavlja koja mogu biti dodata zahtevima od strane obrnjenih proksija.![Image for post](https://miro.medium.com/max/60/1*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Image for post](https://miro.medium.com/max/1330/1*wDFRADTOd9Tj63xucenvAA.png)

{{#include ./banners/hacktricks-training.md}}

### Same-Site Scripting

Dešava se kada naiđemo na domen ili poddomen koji se rešava na localhost ili 127.0.0.1 zbog određenih DNS pogrešnih konfiguracija. Omogućava napadaču da prevari RFC2109 (HTTP State Management Mechanism) ograničenja iste domene, i stoga preuzme podatke o upravljanju stanjem. Takođe može omogućiti cross-site scripting. Možete pročitati više o tome [ovde](https://seclists.org/bugtraq/2008/Jan/270)
