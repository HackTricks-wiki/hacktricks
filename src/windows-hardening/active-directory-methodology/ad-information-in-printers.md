{{#include ../../banners/hacktricks-training.md}}

Daar is verskeie blogs op die Internet wat **die gevare van die gebruik van printers met LDAP met standaard/ swak** aanmeldbesonderhede beklemtoon.\
Dit is omdat 'n aanvaller die printer kan **mislei om teen 'n kwaadwillige LDAP-bediener te verifieer** (tipies is 'n `nc -vv -l -p 444` genoeg) en die printer **aanmeldbesonderhede in duidelike teks** kan vang.

Ook, verskeie printers sal **logs met gebruikersname** bevat of kan selfs in staat wees om **alle gebruikersname** van die Domeinbeheerder te **aflaai**.

Al hierdie **sensitiewe inligting** en die algemene **gebrek aan sekuriteit** maak printers baie interessant vir aanvallers.

Sommige blogs oor die onderwerp:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

## Printer Konfigurasie

- **Ligging**: Die LDAP-bediener lys is te vind by: `Network > LDAP Setting > Setting Up LDAP`.
- **Gedrag**: Die koppelvlak laat LDAP-bediener wysigings toe sonder om aanmeldbesonderhede weer in te voer, wat op gebruikersgerief gemik is, maar sekuriteitsrisiko's inhou.
- **Eksploiteer**: Die eksploitasie behels die herleiding van die LDAP-bediener adres na 'n beheerde masjien en die gebruik van die "Toets Verbinding" kenmerk om aanmeldbesonderhede te vang.

## Vang Aanmeldbesonderhede

**Vir meer gedetailleerde stappe, verwys na die oorspronklike [bron](https://grimhacker.com/2018/03/09/just-a-printer/).**

### Metode 1: Netcat Luisteraar

'n Eenvoudige netcat luisteraar mag genoeg wees:
```bash
sudo nc -k -v -l -p 386
```
Maar, die sukses van hierdie metode verskil.

### Metode 2: Volledige LDAP-bediener met Slapd

'n Meer betroubare benadering behels die opstelling van 'n volledige LDAP-bediener omdat die drukker 'n null bind uitvoer gevolg deur 'n navraag voordat dit probeer om akreditasie te bind.

1. **LDAP-bedieneropstelling**: Die gids volg stappe van [this source](https://www.server-world.info/en/note?os=Fedora_26&p=openldap).
2. **Belangrike Stappe**:
- Installeer OpenLDAP.
- Konfigureer admin wagwoord.
- Importeer basiese skemas.
- Stel domeinnaam op LDAP DB.
- Konfigureer LDAP TLS.
3. **LDAP-diensuitvoering**: Sodra dit opgestel is, kan die LDAP-diens uitgevoer word met:
```bash
slapd -d 2
```
## Verwysings

- [https://grimhacker.com/2018/03/09/just-a-printer/](https://grimhacker.com/2018/03/09/just-a-printer/)

{{#include ../../banners/hacktricks-training.md}}
