# Informacije u štampačima

{{#include ../../banners/hacktricks-training.md}}

Na Internetu postoji nekoliko blogova koji **ističu opasnosti ostavljanja štampača konfigurisanih sa LDAP-om i podrazumevanim/slabim** logon akreditivima.  \
Ovo je zato što napadač može da **navede štampač da se autentifikuje prema lažnom LDAP serveru** (obično je dovoljan `nc -vv -l -p 389` ili `slapd -d 2`) i presretne **akreditive štampača u čistom tekstu**.

Takođe, nekoliko štampača sadržaće **logove sa korisničkim imenima** ili će čak moći da **preuzme sva korisnička imena** sa Domain Controller-a.

Sve ove **osetljive informacije** i uobičajeni **nedostatak bezbednosti** čine štampače veoma zanimljivim napadačima.

Nekoliko uvodnih blogova o ovoj temi:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)<sup>[[4]](#references)</sup>
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)<sup>[[5]](#references)</sup>

---

## Konfiguracija štampača

- **Lokacija**: Lista LDAP servera obično se nalazi u web interfejsu (npr. *Network ➜ LDAP Setting ➜ Setting Up LDAP*).
- **Ponašanje**: Mnogi ugrađeni web serveri dozvoljavaju izmene LDAP servera **bez ponovnog unošenja akreditiva** (funkcija za lakšu upotrebu → bezbednosni rizik).
- **Eksploatacija**: Preusmerite adresu LDAP servera na host pod kontrolom napadača i upotrebite dugme *Test Connection* / *Address Book Sync* da biste primorali štampač da izvrši bind prema vama.

---

## Presretanje akreditiva

### Method 1 – Netcat Listener
```bash
sudo nc -k -v -l -p 389     # LDAPS → 636 (or 3269)
```
Mali/stari MFP uređaji mogu slati jednostavan *simple-bind* u čistom tekstu, što netcat može da presretne. Moderni uređaji obično prvo izvršavaju anonimni upit, a zatim pokušavaju bind, pa se rezultati razlikuju.<sup>[[1]](#references)</sup>

### Metod 2 – Full Rogue LDAP server (preporučeno)

Pošto će mnogi uređaji izvršiti anonimnu pretragu *pre* autentifikacije, pokretanje pravog LDAP daemon-a daje mnogo pouzdanije rezultate:<sup>[[1]](#references)</sup>
```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # set any base-DN – it will not be validated

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```
Kada štampač izvrši svoj lookup, videćete kredencijale u čistom tekstu u debug izlazu.

> 💡  Takođe možete koristiti `impacket/examples/ldapd.py` (Python rogue LDAP) ili `Responder -w -r -f` za prikupljanje NTLMv2 hash-eva preko LDAP/SMB-a.

---

## Nedavne Pass-Back ranjivosti (2024-2025)

Pass-back *nije* teoretski problem – vendori i dalje objavljuju advisories tokom 2024/2025. koji tačno opisuju ovu klasu napada.

### Xerox VersaLink – CVE-2024-12510 & CVE-2024-12511

Firmware ≤ 57.69.91 za Xerox VersaLink C70xx MFP uređaje omogućavao je autentifikovanom administratoru (ili bilo kome kada podrazumevani kredencijali ostanu nepromenjeni) da:

* **CVE-2024-12510 – LDAP pass-back**: promeni adresu LDAP servera i pokrene lookup, zbog čega uređaj leak-uje konfigurisane Windows kredencijale ka hostu kojim upravlja napadač.
* **CVE-2024-12511 – SMB/FTP pass-back**: identičan problem preko *scan-to-folder* odredišta, pri čemu se leak-uju NetNTLMv2 ili FTP kredencijali u čistom tekstu.<sup>[[2]](#references)</sup>

Jednostavan listener, kao što je:
```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```
ili rogue SMB server (`impacket-smbserver`) dovoljan je za prikupljanje akreditiva.

### Canon imageRUNNER / imageCLASS – savetovanje od 20. maja 2025.

Canon je potvrdio slabost **SMTP/LDAP pass-back** u desetinama proizvodnih linija Laser & MFP. Napadač sa administratorskim pristupom može da izmeni konfiguraciju servera i preuzme sačuvane akreditive za LDAP **ili** SMTP (mnoge organizacije koriste privilegovani nalog da bi omogućile skeniranje u e-poštu).<sup>[[3]](#references)</sup>

Uputstvo proizvođača izričito preporučuje:

1. Ažuriranje na zakrpljeni firmware čim bude dostupan.
2. Korišćenje snažnih i jedinstvenih administratorskih lozinki.
3. Izbegavanje privilegovanih AD naloga za integraciju štampača.

---

## Automatizovani alati za enumeraciju / eksploataciju

| Alat | Namena | Primer |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | Zloupotreba PostScript/PJL/PCL, pristup sistemu datoteka, provera podrazumevanih akreditiva, *SNMP discovery* | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | Prikupljanje konfiguracije (uključujući adresare i LDAP akreditive) putem HTTP/HTTPS | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | Hvatanje i prosleđivanje NetNTLM hash vrednosti iz SMB/FTP pass-back saobraćaja | `responder -I eth0 -wrf` |
| **impacket-ldapd.py** | Lagani rogue LDAP servis za prijem bind zahteva u čistom tekstu | `python ldapd.py -debug` |

---

## Ojačavanje i detekcija

1. Pravovremeno **zakrpiti / ažurirati firmware** MFP uređaja (proveriti PSIRT biltene proizvođača).
2. **Service Accounts sa najmanjim privilegijama** – nikada ne koristiti Domain Admin za LDAP/SMB/SMTP; ograničiti ih na *read-only* OU opsege.
3. **Ograničiti pristup za upravljanje** – smestiti web/IPP/SNMP interfejse štampača u management VLAN ili iza ACL/VPN-a.
4. **Onemogućiti nekorišćene protokole** – FTP, Telnet, raw-9100 i starije SSL cipher-e.
5. **Omogućiti audit logging** – neki uređaji mogu da šalju LDAP/SMTP greške putem syslog-a; korelisati neočekivane bind zahteve.
6. **Nadgledati LDAP bind zahteve u čistom tekstu** sa neuobičajenih izvora (štampači bi obično trebalo da komuniciraju samo sa DC-ovima).
7. **Koristiti SNMPv3 ili onemogućiti SNMP** – community `public` često leak-uje konfiguraciju uređaja i LDAP-a.

---

## Reference

- [1] [To je samo štampač... Šta je najgore što može da se desi?](https://grimhacker.com/2018/03/09/just-a-printer/)
- [2] [Xerox Versalink C7025 višenamenski štampač: ranjivosti Pass-Back napada (otklonjene)](https://www.rapid7.com/blog/post/2025/02/14/xerox-versalink-c7025-multifunction-printer-pass-back-attack-vulnerabilities-fixed/)
- [3] [CP2025-004 ublažavanje/otklanjanje ranjivosti za proizvodne štampače, višenamenske štampače za kancelarije/male kancelarije i laserske štampače](https://psirt.canon/advisory-information/cp2025-004/)
- [4] [Preuzimanje domenskih akreditiva putem štampača sa Netcat-om](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [5] [Eksploatacija višenamenskih štampača tokom angažmana za penetration test](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

{{#include ../../banners/hacktricks-training.md}}
