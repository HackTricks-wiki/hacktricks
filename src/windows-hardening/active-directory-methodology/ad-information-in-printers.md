# Informacije u štampačima

{{#include ../../banners/hacktricks-training.md}}

Na Internetu postoji nekoliko blogova koji **ukazuju na opasnosti ostavljanja štampača konfigurisanih sa LDAP-om i podrazumevanim/slabim** pristupnim podacima za prijavljivanje.  \
To je zato što napadač može da **navede štampač da se autentifikuje na rogue LDAP server** (obično je dovoljan `nc -vv -l -p 389` ili `slapd -d 2`) i preuzme **kredencijale štampača u clear-text obliku**.

Takođe, mnogi štampači sadrže **logove sa korisničkim imenima** ili čak mogu da **preuzmu sva korisnička imena** sa Domain Controller-a.

Sve ove **osetljive informacije** i uobičajeni **nedostatak bezbednosti** čine štampače veoma zanimljivim napadačima.

Neki uvodni blogovi o ovoj temi:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)<sup>[[4]](#references)</sup>
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)<sup>[[5]](#references)</sup>

---

## Konfiguracija štampača

- **Lokacija**: Lista LDAP servera se obično nalazi u web interfejsu (npr. *Network ➜ LDAP Setting ➜ Setting Up LDAP*).
- **Ponašanje**: Mnogi ugrađeni web serveri dozvoljavaju izmene LDAP servera **bez ponovnog unošenja pristupnih podataka** (funkcija za lakšu upotrebu → bezbednosni rizik).
- **Eksploatacija**: Preusmerite adresu LDAP servera na host pod kontrolom napadača i koristite dugme *Test Connection* / *Address Book Sync* da biste primorali štampač da izvrši bind prema vama.

---

## Preuzimanje kredencijala

### Method 1 – Netcat Listener
```bash
sudo nc -k -v -l -p 389     # Plain LDAP only
```
Mali/stari MFP uređaji mogu poslati jednostavan *simple-bind* čiji su bind DN i lozinka vidljivi u sirovom BER toku. Moderni uređaji obično prvo izvršavaju anonymous upit, a zatim pokušavaju bind, pa se rezultati razlikuju.<sup>[[1]](#references)</sup>

Običan `nc` listener na portu 636/3269 prima samo TLS ciphertext; testiranje LDAPS zahteva LDAP endpoint sa podrškom za TLS, a preusmeravanje bi trebalo da ne uspe kada uređaj ispravno validira sertifikat servera.

### Method 2 – Full Rogue LDAP server (preporučeno)

Pošto će mnogi uređaji izvršiti anonymous pretragu *pre* autentifikacije, postavljanje pravog LDAP daemon-a daje mnogo pouzdanije rezultate:<sup>[[1]](#references)</sup>
```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # set any base-DN – it will not be validated

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```
Kada štampač izvrši svoje pretraživanje, u izlazu za otklanjanje grešaka videćete kredencijale u čistom tekstu.

> 💡  Responder uključuje rogue LDAP i SMB authentication servise. Jednostavan LDAP bind može otkriti konfigurisanu lozinku, dok NTLM authentication proizvodi challenge-response materijal; nemojte oba ishoda opisivati kao lozinku u čistom tekstu.

---

## Nedavne Pass-Back ranjivosti (2024-2025)

Pass-back *nije* teoretski problem – vendori i dalje objavljuju advisories tokom 2024/2025. koji tačno opisuju ovu klasu napada.

### Xerox VersaLink – CVE-2024-12510 & CVE-2024-12511

Firmware ≤ 57.69.91 za Xerox VersaLink C70xx MFP uređaje omogućavao je autentifikovanom administratoru (ili bilo kome kada podrazumevani kredencijali ostanu nepromenjeni) da:

* **CVE-2024-12510 – LDAP pass-back**: promeni adresu LDAP servera i pokrene pretragu, zbog čega uređaj leak-uje konfigurisane Windows kredencijale ka hostu pod kontrolom napadača.
* **CVE-2024-12511 – SMB/FTP pass-back**: identičan problem putem odredišta *scan-to-folder*, pri čemu se leak-uju NetNTLMv2 ili FTP kredencijali u čistom tekstu.<sup>[[2]](#references)</sup>

Jednostavan listener, kao što je:
```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```
ili lažni SMB server (`impacket-smbserver`) dovoljan je za prikupljanje kredencijala.

### Canon imageRUNNER / imageCLASS – savet od 20. maja 2025.

Canon je potvrdio slabost **SMTP/LDAP pass-back** u desetinama proizvodnih linija Laser & MFP uređaja. Napadač sa admin pristupom može da izmeni konfiguraciju servera i preuzme sačuvane kredencijale za LDAP **ili** SMTP (mnoge organizacije koriste privilegovani nalog za omogućavanje funkcije scan-to-mail).<sup>[[3]](#references)</sup>

Smernice proizvođača izričito preporučuju:

1. Ažuriranje na zakrpljeni firmware čim bude dostupan.
2. Korišćenje snažnih i jedinstvenih admin lozinki.
3. Izbegavanje privilegovanih AD naloga za integraciju printera.

---

### Brother uređaji i OEM varijante – admin pristup izveden iz serijskog broja do servisnih kredencijala

Koordinisana objava iz 2025. demonstrirala je naročito korisni lanac napada na pogođenim Brother uređajima; delovi skupa ranjivosti utiču i na OEM modele, zato proverite tačan model u odnosu na savet proizvođača. Neautentifikovani napadač može da dobije serijski broj uređaja putem HTTP/HTTPS/IPP protokola na ranjivom firmware-u, dok serijski brojevi mogu biti dostupni i putem protokola za upravljanje, kao što su SNMP ili PJL. Ako fabrička lozinka nikada nije promenjena, serijski broj deterministički daje administratorsku lozinku. Nakon autentifikacije, odvojena pass-back slabost CVE-2024-51984 otkriva konfigurisane lozinke eksternih servisa, kao što su LDAP ili FTP, u plaintext obliku, pretvarajući pristup za upravljanje printerom u ponovo upotrebljive mrežne kredencijale. Firmware rešava otkrivanje lozinki servisa, ali prethodno proizvedeni uređaji i dalje zahtevaju da operater zameni početnu administratorsku lozinku izvedenu iz serijskog broja.<sup>[[6]](#references)</sup>

Aktuelni Metasploit uključuje auxiliary module koji otkriva serijski broj putem HTTP-a, SNMP-a ili PJL-a, generiše kandidatsku početnu lozinku i opciono je proverava u odnosu na web konzolu. `DiscoverSerialVia=AUTO` pokušava podržane puteve za otkrivanje; navedite `TargetSerial` umesto toga kada inventar imovine već sadrži serijski broj.<sup>[[7]](#references)</sup>
```text
msfconsole -q
use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978
set RHOSTS <printer-ip>
set DiscoverSerialVia AUTO
run
```
Koristite rezultat samo za validaciju autorizovanih sredstava. Da li lozinka funkcioniše zavisi od tačnog modela i, što je ključno, od toga da li je fabrička administratorska lozinka već promenjena.<sup>[[6]](#references)[[7]](#references)</sup>

---

## Alati za automatizovanu enumeraciju / exploitation

| Alat | Svrha | Primer |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | Zloupotreba PostScript/PJL/PCL, pristup sistemu datoteka, provera podrazumevanih kredencijala, *SNMP discovery* | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | Prikupljanje konfiguracije (uključujući adresare i LDAP kredencijale) putem HTTP/HTTPS | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | Pokretanje rogue authentication servisa i hvatanje/prosleđivanje NetNTLM-a iz SMB callback-ova | `sudo responder -I eth0 -v` |
| **Metasploit Brother auxiliary** | Otkrivanje serijskog broja, izvođenje kandidatne fabričke administratorske lozinke i verifikacija pristupa web konzoli | `use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978` |

---

## Ojačavanje i detekcija

1. **Pravovremeno instalirajte zakrpe / ažurirajte firmware** na MFP uređajima (proverite PSIRT biltene proizvođača).
2. **Zamenite fabričke administratorske lozinke** – sam firmware ne uklanja početne lozinke izvedene iz serijskog broja sa prethodno proizvedenih pogođenih Brother/OEM uređaja.<sup>[[6]](#references)</sup>
3. **Service Accounts sa najmanjim privilegijama** – nikada ne koristite Domain Admin za LDAP/SMB/SMTP; ograničite ih na *read-only* OU opsege.
4. **Ograničite pristup za upravljanje** – postavite web/IPP/SNMP interfejse štampača u management VLAN ili iza ACL/VPN-a.
5. **Ograničite izlazni saobraćaj štampača** – dozvolite svakom uređaju da kontaktira samo očekivane DC/LDAP, mail, DNS/NTP, print i scan-file destinacije. Pass-back zahteva callback ka endpointu koji je izabrao attacker.
6. **Onemogućite nekorišćene protokole** – FTP, Telnet, raw-9100, starije SSL cipher-e.
7. **Omogućite audit logging** – neki uređaji mogu da šalju LDAP/SMTP greške putem syslog-a; korelišite neočekivane bind-ove.
8. **Nadgledajte authentication destinacije** – generišite upozorenje kada štampač pokrene LDAP, SMB, SMTP ili FTP ka hostu izvan svoje allowlist-e, naročito odmah nakon management login-a ili promene konfiguracije.
9. **SNMPv3 ili onemogućite SNMP** – community `public` često leak-uje informacije o uređaju i serijskom broju.

---



---

## References

- [1] [To je samo štampač... Šta je najgore što može da se desi?](https://grimhacker.com/2018/03/09/just-a-printer/)
- [2] [Xerox Versalink C7025 multifunkcionalni štampač: Pass-Back Attack ranjivosti (otklonjene)](https://www.rapid7.com/blog/post/2025/02/14/xerox-versalink-c7025-multifunction-printer-pass-back-attack-vulnerabilities-fixed/)
- [3] [CP2025-004 ublažavanje/otklanjanje ranjivosti za proizvodne štampače, multifunkcionalne štampače za kancelarije/male kancelarije i laserske štampače](https://psirt.canon/advisory-information/cp2025-004/)
- [4] [Dobijanje domen kredencijala kroz štampač pomoću Netcat-a](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [5] [Exploiting multifunkcionalnih štampača tokom angažmana penetration testing-a](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [6] [Više Brother uređaja: više ranjivosti (OTKLANJENO)](https://www.rapid7.com/blog/post/multiple-brother-devices-multiple-vulnerabilities-fixed/)
- [7] [Metasploit: modul za zaobilaženje authentication-a podrazumevanog administratora Brother uređaja](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978.rb)
{{#include ../../banners/hacktricks-training.md}}
