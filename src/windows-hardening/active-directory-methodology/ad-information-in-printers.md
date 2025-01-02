{{#include ../../banners/hacktricks-training.md}}

Postoji nekoliko blogova na Internetu koji **ističu opasnosti ostavljanja štampača konfiguranih sa LDAP sa podrazumevanim/slabim** lozinkama.\
To je zato što bi napadač mogao **prevariti štampač da se autentifikuje protiv lažnog LDAP servera** (obično je `nc -vv -l -p 444` dovoljno) i da uhvati **lozinke štampača u čistom tekstu**.

Takođe, nekoliko štampača će sadržati **logove sa korisničkim imenima** ili čak mogu biti u mogućnosti da **preuzmu sva korisnička imena** sa Kontrolera domena.

Sve ove **osetljive informacije** i uobičajeni **nedostatak sigurnosti** čine štampače veoma zanimljivim za napadače.

Neki blogovi o ovoj temi:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

## Konfiguracija štampača

- **Lokacija**: Lista LDAP servera se nalazi na: `Network > LDAP Setting > Setting Up LDAP`.
- **Ponašanje**: Interfejs omogućava izmene LDAP servera bez ponovnog unošenja lozinki, što je usmereno na pogodnost korisnika, ali predstavlja sigurnosne rizike.
- **Eksploatacija**: Eksploatacija uključuje preusmeravanje adrese LDAP servera na kontrolisanu mašinu i korišćenje funkcije "Test Connection" za hvatanje lozinki.

## Hvatanje lozinki

**Za detaljnije korake, pogledajte originalni [izvor](https://grimhacker.com/2018/03/09/just-a-printer/).**

### Metod 1: Netcat Listener

Jednostavan netcat listener bi mogao biti dovoljan:
```bash
sudo nc -k -v -l -p 386
```
Međutim, uspeh ove metode varira.

### Metoda 2: Potpuni LDAP Server sa Slapd

Pouzdaniji pristup uključuje postavljanje potpunog LDAP servera jer štampač izvršava null bind nakon čega sledi upit pre nego što pokuša vezivanje kredencijala.

1. **Postavljanje LDAP Servera**: Vodič prati korake iz [ovog izvora](https://www.server-world.info/en/note?os=Fedora_26&p=openldap).
2. **Ključni Koraci**:
- Instalirajte OpenLDAP.
- Konfigurišite admin lozinku.
- Uvezite osnovne šeme.
- Postavite naziv domena na LDAP DB.
- Konfigurišite LDAP TLS.
3. **Izvršenje LDAP Usluge**: Kada je postavljen, LDAP usluga se može pokrenuti koristeći:
```bash
slapd -d 2
```
## Reference

- [https://grimhacker.com/2018/03/09/just-a-printer/](https://grimhacker.com/2018/03/09/just-a-printer/)

{{#include ../../banners/hacktricks-training.md}}
