# Ostale Web tehnike

{{#include ../banners/hacktricks-training.md}}

### Host header

Više puta back-end veruje **Host header-u** za izvršavanje određenih radnji. Na primer, njegovu vrednost može koristiti kao **domen na koji treba poslati resetovanje lozinke**. Dakle, kada primite e-poruku sa linkom za resetovanje lozinke, koristi se domen koji ste naveli u Host header-u. Zatim možete zatražiti resetovanje lozinke drugih korisnika i promeniti domen na domen koji je pod vašom kontrolom kako biste ukrali njihove kodove za resetovanje lozinke. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).<sup>[[1]](#references)</sup>

> [!WARNING]
> Imajte na umu da možda čak ni ne morate čekati da korisnik klikne na link za resetovanje lozinke da biste dobili token, jer ga možda čak i **spam filteri ili drugi posrednički uređaji/botovi otvore kako bi ga analizirali**.

### Boolean vrednosti sesije

Ponekad, kada pravilno završite neku proveru, back-end će **samo dodati boolean vrednost "True" sigurnosnom atributu vaše sesije**. Zatim će drugi endpoint znati da li ste uspešno prošli tu proveru.\
Međutim, ako **prođete proveru** i vašoj sesiji bude dodeljena vrednost "True" u sigurnosnom atributu, možete pokušati da **pristupite drugim resursima** koji **zavise od istog atributa**, ali kojima **ne bi trebalo da imate dozvolu** za pristup. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).<sup>[[2]](#references)</sup>

### Funkcionalnost registracije

Pokušajte da se registrujete kao korisnik koji već postoji. Takođe pokušajte da koristite ekvivalentne karaktere (tačke, mnogo razmaka i Unicode).

### Preuzimanje e-mail naloga

Registrujte e-mail adresu, a zatim pre njene potvrde promenite e-mail adresu. Ako se nova e-poruka za potvrdu pošalje na prvu registrovanu e-mail adresu, možete preuzeti bilo koju e-mail adresu. Ili, ako možete omogućiti drugu e-mail adresu potvrdom prve, takođe možete preuzeti bilo koji nalog.

### Pristup internom servicedesk-u kompanija koje koriste atlassian


{{#ref}}
https://yourcompanyname.atlassian.net/servicedesk/customer/user/login
{{#endref}}

### TRACE metoda

Programeri mogu zaboraviti da onemoguće različite opcije za debugging u production okruženju. Na primer, HTTP `TRACE` metoda je namenjena dijagnostici. Ako je omogućena, web server će na zahteve koji koriste `TRACE` metodu odgovoriti tako što će u odgovoru ispisati tačan zahtev koji je primljen. Ovo ponašanje je često bezopasno, ali povremeno dovodi do otkrivanja informacija, kao što je naziv internih authentication header-a koje reverse proxy-ji mogu dodati zahtevima.![Image for post](https://miro.medium.com/max/60/1*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Image for post](https://miro.medium.com/max/1330/1*wDFRADTOd9Tj63xucenvAA.png)

## Reference

- [1] [How I was able to take over any user's account with Host Header Injection](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2)
- [2] [A less known attack vector: Second Order IDOR attacks](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a)

{{#include ../banners/hacktricks-training.md}}
