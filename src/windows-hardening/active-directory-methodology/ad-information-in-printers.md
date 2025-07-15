# Informacije u štampačima

{{#include ../../banners/hacktricks-training.md}}

Postoji nekoliko blogova na Internetu koji **ističu opasnosti ostavljanja štampača konfiguranih sa LDAP sa podrazumevanim/slabim** lozinkama.  \
To je zato što bi napadač mogao **da prevari štampač da se autentifikuje protiv lažnog LDAP servera** (obično je `nc -vv -l -p 389` ili `slapd -d 2` dovoljno) i uhvati **lozinke štampača u čistom tekstu**.

Takođe, nekoliko štampača će sadržati **logove sa korisničkim imenima** ili čak mogu biti u mogućnosti da **preuzmu sva korisnička imena** sa Kontrolera domena.

Sve ove **osetljive informacije** i uobičajeni **nedostatak sigurnosti** čine štampače veoma zanimljivim za napadače.

Neki uvodni blogovi o ovoj temi:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

---
## Konfiguracija štampača

- **Lokacija**: Lista LDAP servera se obično nalazi u veb interfejsu (npr. *Mreža ➜ LDAP Podešavanje ➜ Podešavanje LDAP-a*).
- **Ponašanje**: Mnogi ugrađeni veb serveri omogućavaju izmene LDAP servera **bez ponovnog unošenja lozinki** (karakteristika upotrebljivosti → bezbednosni rizik).
- **Eksploatacija**: Preusmerite adresu LDAP servera na host koji kontroliše napadač i koristite dugme *Testiraj vezu* / *Sinhronizacija adresara* da primorate štampač da se poveže sa vama.

---
## Hvatanje lozinki

### Metod 1 – Netcat Listener
```bash
sudo nc -k -v -l -p 389     # LDAPS → 636 (or 3269)
```
Mali/stari MFP-ovi mogu slati jednostavan *simple-bind* u čistom tekstu koji netcat može uhvatiti. Moderni uređaji obično prvo obavljaju anonimnu pretragu, a zatim pokušavaju vezivanje, tako da se rezultati razlikuju.

### Metod 2 – Potpuni Rogue LDAP server (preporučeno)

Zato što mnogi uređaji izdaju anonimnu pretragu *pre nego što* se autentifikuju, postavljanje pravog LDAP demona daje mnogo pouzdanije rezultate:
```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # set any base-DN – it will not be validated

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```
Kada štampač izvrši pretragu, videćete kredencijale u čistom tekstu u izlazu za debagovanje.

> 💡  Takođe možete koristiti `impacket/examples/ldapd.py` (Python rogue LDAP) ili `Responder -w -r -f` za prikupljanje NTLMv2 hash-eva preko LDAP/SMB.

---
## Nedavne Pass-Back Ranljivosti (2024-2025)

Pass-back *nije* teoretski problem – dobavljači nastavljaju da objavljuju obaveštenja u 2024/2025 koja tačno opisuju ovu klasu napada.

### Xerox VersaLink – CVE-2024-12510 & CVE-2024-12511

Firmware ≤ 57.69.91 Xerox VersaLink C70xx MFP-ova omogućio je autentifikovanom administratoru (ili bilo kome kada su podrazumevani kredencijali ostali) da:

* **CVE-2024-12510 – LDAP pass-back**: promeni adresu LDAP servera i pokrene pretragu, uzrokujući da uređaj otkrije konfigurisane Windows kredencijale na hostu pod kontrolom napadača.
* **CVE-2024-12511 – SMB/FTP pass-back**: identičan problem putem *scan-to-folder* odredišta, otkrivajući NetNTLMv2 ili FTP kredencijale u čistom tekstu.

Jednostavan slušalac kao što je:
```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```
or rogue SMB server (`impacket-smbserver`) je dovoljan za prikupljanje kredencijala.

### Canon imageRUNNER / imageCLASS – Savet 20. maj 2025.

Canon je potvrdio **SMTP/LDAP pass-back** slabost u desetinama Laser & MFP proizvodnih linija. Napadač sa administratorskim pristupom može da izmeni konfiguraciju servera i preuzme sačuvane kredencijale za LDAP **ili** SMTP (mnoge organizacije koriste privilegovani nalog za omogućavanje skeniranja na e-mail).

Preporuke proizvođača izričito sugerišu:

1. Ažuriranje na zakrpljeni firmware čim postane dostupan.
2. Korišćenje jakih, jedinstvenih administratorskih lozinki.
3. Izbegavanje privilegovanih AD naloga za integraciju štampača.

---
## Alati za automatsku enumeraciju / eksploataciju

| Alat | Svrha | Primer |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | Zloupotreba PostScript/PJL/PCL, pristup fajl sistemu, provera podrazumevanih kredencijala, *SNMP otkrivanje* | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | Prikupljanje konfiguracije (uključujući adresare i LDAP kredencijale) putem HTTP/HTTPS | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | Hvatanje i preusmeravanje NetNTLM hash-eva iz SMB/FTP pass-back | `responder -I eth0 -wrf` |
| **impacket-ldapd.py** | Lagana rogue LDAP usluga za primanje clear-text veza | `python ldapd.py -debug` |

---
## Ojačavanje i detekcija

1. **Patch / ažuriranje firmware-a** MFP-ova odmah (proverite PSIRT biltene proizvođača).
2. **Računi usluga sa najmanjim privilegijama** – nikada ne koristiti Domain Admin za LDAP/SMB/SMTP; ograničiti na *samo za čitanje* OU opsege.
3. **Ograničiti pristup upravljanju** – staviti web/IPP/SNMP interfejse štampača u upravljački VLAN ili iza ACL/VPN.
4. **Onemogućiti neiskorišćene protokole** – FTP, Telnet, raw-9100, stariji SSL šifri.
5. **Omogućiti audit logovanje** – neki uređaji mogu syslog-ovati LDAP/SMTP greške; korelirati neočekivane veze.
6. **Pratiti clear-text LDAP veze** sa neobičnih izvora (štampači obično komuniciraju samo sa DC-ima).
7. **SNMPv3 ili onemogućiti SNMP** – zajednica `public` često otkriva konfiguraciju uređaja i LDAP.

---
## Reference

- [https://grimhacker.com/2018/03/09/just-a-printer/](https://grimhacker.com/2018/03/09/just-a-printer/)
- Rapid7. “Xerox VersaLink C7025 MFP Pass-Back Attack Vulnerabilities.” februar 2025.
- Canon PSIRT. “Mitigacija ranjivosti protiv SMTP/LDAP passback za laserske štampače i male multifunkcionalne štampače.” maj 2025.

{{#include ../../banners/hacktricks-training.md}}
