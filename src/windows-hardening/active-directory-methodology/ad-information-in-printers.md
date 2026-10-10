# Informacije u štampačima

{{#include ../../banners/hacktricks-training.md}}

Na Internetu postoji nekoliko blogova koji **ističu opasnosti ostavljanja štampača konfigurisanih za LDAP sa podrazumevanim/slabim** kredencijalima za prijavu.  \
To je zato što napadač može **navesti štampač da se autentifikuje na lažnom LDAP serveru** (obično su dovoljni `nc -vv -l -p 389` ili `slapd -d 2`) i uhvatiti **kredencijale štampača u čistom tekstu**.

Pored toga, neki štampači sadrže **evidencije sa korisničkim imenima** ili čak mogu da **preuzmu sva korisnička imena** sa Domain Controller-a.

Sve ove **osetljive informacije** i uobičajeni **nedostatak bezbednosti** čine štampače veoma zanimljivim napadačima.

Nekoliko uvodnih blogova o ovoj temi:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)<sup>[[4]](#references)</sup>
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)<sup>[[5]](#references)</sup>

---

## Konfiguracija štampača

- **Lokacija**: Lista LDAP servera obično se nalazi u veb-interfejsu (npr. *Mreža ➜ LDAP podešavanje ➜ Podešavanje LDAP-a*).
- **Ponašanje**: Mnogi ugrađeni veb-serveri dozvoljavaju izmene LDAP servera **bez ponovnog unosa kredencijala** (funkcija za lakšu upotrebu → bezbednosni rizik).
- **Eksploatacija**: Preusmerite adresu LDAP servera na host pod kontrolom napadača i upotrebite dugme *Testiraj vezu* / *Sinhronizuj adresar* da biste naveli štampač da se poveže sa vama.

---

## Hvatanje kredencijala

### Metod 1 – Netcat slušač

```bash
sudo nc -k -v -l -p 389     # Plain LDAP only
```

Mali/stari MFP-ovi mogu slati jednostavan *simple-bind* čiji su bind DN i lozinka vidljivi u sirovom BER toku. Moderni uređaji obično prvo izvrše anonimni upit, a zatim pokušaju bind, pa se rezultati razlikuju.<sup>[[1]](#references)</sup>

Običan `nc` listener na portu 636/3269 prima samo TLS šifrovani tekst; za testiranje LDAPS-a potreban je LDAP endpoint koji podržava TLS, a preusmeravanje bi trebalo da ne uspe kada uređaj ispravno proverava serverski sertifikat.

### Metod 2 – Potpuni Rogue LDAP server (preporučeno)

Pošto mnogi uređaji izvršavaju anonimnu pretragu *pre* autentifikacije, pokretanje pravog LDAP daemon-a daje mnogo pouzdanije rezultate:<sup>[[1]](#references)</sup>

```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # set any base-DN – it will not be validated

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```

Kada štampač izvrši pretragu, u izlazu za otklanjanje grešaka videćete akreditive u otvorenom tekstu.

> 💡 Responder uključuje lažne LDAP i SMB servise za autentifikaciju. Jednostavan LDAP bind može da otkrije konfigurisanu lozinku, dok NTLM autentifikacija proizvodi materijal za challenge-response; nemojte opisivati oba ishoda kao lozinku u otvorenom tekstu.

---

## Nedavne Pass-Back ranjivosti (2024-2025)

Pass-back nije samo teorijski problem – proizvođači i dalje objavljuju savete tokom 2024/2025. koji tačno opisuju ovu klasu napada.

### Xerox VersaLink – CVE-2024-12510 & CVE-2024-12511

Firmware ≤ 57.69.91 za Xerox VersaLink C70xx MFP uređaje omogućavao je autentifikovanom administratoru (ili bilo kome ako su podrazumevani akredити i dalje u upotrebi) da:

* **CVE-2024-12510 – LDAP pass-back**: promene adresu LDAP servera i pokrenu pretragu, zbog čega uređaj šalje konfigurisane Windows akreditive na host koji kontroliše napadač.
* **CVE-2024-12511 – SMB/FTP pass-back**: isti problem preko odredišta *scan-to-folder*, čime se otkrivaju NetNTLMv2 ili FTP akreditive u otvorenom tekstu.<sup>[[2]](#references)</sup>

Jednostavan listener, kao što je:

```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```

ili je dovoljan lažni SMB server (`impacket-smbserver`) za prikupljanje akreditiva.  

### Canon imageRUNNER / imageCLASS – bezbednosno upozorenje od 20. maja 2025.

Canon je potvrdio slabost **SMTP/LDAP pass-back** u desetinama linija Laser i MFP proizvoda. Napadač sa administratorskim pristupom može da izmeni konfiguraciju servera i dođe do sačuvanih akreditiva za LDAP **ili** SMTP (mnoge organizacije koriste privilegovani nalog za omogućavanje funkcije scan-to-mail).<sup>[[3]](#references)</sup>

Preporuke proizvođača izričito obuhvataju:

1. Ažuriranje na ispravljeni firmware čim postane dostupan.
2. Korišćenje jakih i jedinstvenih administratorskih lozinki.
3. Izbegavanje privilegovanih AD naloga za integraciju štampača.

---

### Brother uređaji i OEM varijante – pristup administratorskom nalogu i servisnim akreditivima izveden iz serijskog broja

Koordinisano otkrivanje ranjivosti iz 2025. pokazalo je naročito korisni lanac napada na pogođenim Brother uređajima; deo skupa ranjivosti utiče i na OEM modele, zato proverite tačan model u bezbednosnom upozorenju proizvođača. Napadač bez autentifikacije može da pribavi serijski broj uređaja preko HTTP/HTTPS/IPP protokola na ranjivom firmware-u, a serijski brojevi mogu biti dostupni i putem protokola za upravljanje kao što su SNMP ili PJL. Ako fabrička lozinka nikada nije promenjena, iz serijskog broja se deterministički dobija administratorska lozinka. Nakon autentifikacije, zasebna pass-back ranjivost CVE-2024-51984 otkriva lozinke za konfigurisane spoljne usluge, kao što su LDAP ili FTP, u čistom tekstu, pretvarajući pristup za upravljanje štampačem u akreditive za mrežu koji se mogu ponovo koristiti. Firmware ispravlja otkrivanje lozinki za usluge, ali na prethodno proizvedenim uređajima operater i dalje mora da zameni početnu administratorsku lozinku izvedenu iz serijskog broja.<sup>[[6]](#references)</sup>

Aktuelni Metasploit sadrži pomoćni modul koji pronalazi serijski broj preko HTTP-a, SNMP-a ili PJL-a, generiše moguću početnu lozinku i opciono je proverava u veb-konzoli. `DiscoverSerialVia=AUTO` isprobava podržane načine pronalaženja; navedite `TargetSerial` umesto toga ako inventar imovine već sadrži serijski broj.<sup>[[7]](#references)</sup>

```text
msfconsole -q
use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978
set RHOSTS <printer-ip>
set DiscoverSerialVia AUTO
run
```

Koristite rezultat samo za proveru ovlašćenih sredstava. Da li će lozinka raditi zavisi od tačnog modela i, što je ključno, od toga da li je fabrička administratorska lozinka već promenjena.<sup>[[6]](#references)[[7]](#references)</sup>

---

## Alatke za automatizovano nabrajanje / iskorišćavanje

| Alatka | Svrha | Primer |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | Zloupotreba PostScript/PJL/PCL protokola, pristup sistemu datoteka, provera podrazumevanih akreditiva, *SNMP discovery* | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | Prikupljanje konfiguracije (uključujući adresare i LDAP akreditive) preko HTTP/HTTPS protokola | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | Pokretanje lažnih servisa za autentifikaciju i hvatanje/prosleđivanje NetNTLM-a iz SMB callback zahteva | `sudo responder -I eth0 -v` |
| **Metasploit Brother auxiliary** | Otkrivanje serijskog broja, izvođenje moguće fabričke administratorske lozinke i provera pristupa veb-konzoli | `use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978` |

---

## Ojačavanje i detekcija

1. **Primenite zakrpe / ažurirajte firmver** na MFP uređajima bez odlaganja (proverite PSIRT bezbednosna obaveštenja dobavljača).
2. **Zamenite fabričke administratorske lozinke** – sam firmver ne uklanja početne lozinke izvedene iz serijskog broja na prethodno proizvedenim Brother/OEM uređajima na koje se ovo odnosi.<sup>[[6]](#references)</sup>
3. **Servisni nalozi sa najmanjim privilegijama** – nikada ne koristite Domain Admin za LDAP/SMB/SMTP; ograničite naloge na *read-only* OU opsege.
4. **Ograničite pristup za upravljanje** – smestite veb/IPP/SNMP interfejse štampača u VLAN za upravljanje ili iza ACL/VPN-a.
5. **Ograničite izlazni saobraćaj štampača** – dozvolite svakom uređaju da kontaktira samo očekivane DC/LDAP, mail, DNS/NTP, štampanje i odredišta za datoteke skeniranja. Pass-back zahteva callback ka krajnjoj tački koju je izabrao napadač.
6. **Onemogućite protokole koji se ne koriste** – FTP, Telnet, raw-9100 i starije SSL šifre.
7. **Omogućite evidentiranje revizije** – neki uređaji mogu slati neuspešne LDAP/SMTP pokušaje na syslog; korelišite neočekivane bind zahteve.
8. **Nadgledajte odredišta za autentifikaciju** – upozorite kada štampač pokrene LDAP, SMB, SMTP ili FTP vezu ka hostu izvan dozvoljene liste, naročito neposredno nakon prijave za upravljanje ili promene konfiguracije.
9. **Koristite SNMPv3 ili onemogućite SNMP** – community `public` često otkriva informacije o uređaju i serijskom broju.

---



---

## References

- [1] [To je samo štampač… Šta je najgore što može da se desi?](https://grimhacker.com/2018/03/09/just-a-printer/)
- [2] [Višenamenski štampač Xerox Versalink C7025: ranjivosti Pass-Back napada (otklonjene)](https://www.rapid7.com/blog/post/2025/02/14/xerox-versalink-c7025-multifunction-printer-pass-back-attack-vulnerabilities-fixed/)
- [3] [CP2025-004 Ublažavanje/otklanjanje ranjivosti za proizvodne štampače, višenamenske štampače za kancelarije/male kancelarije i laserske štampače](https://psirt.canon/advisory-information/cp2025-004/)
- [4] [Dobavljanje akreditiva domena preko štampača pomoću Netcata](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [5] [Iskorišćavanje višenamenskih štampača tokom angažmana na testu penetracije](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [6] [Više Brother uređaja: više ranjivosti (OTKLANJENE)](https://www.rapid7.com/blog/post/multiple-brother-devices-multiple-vulnerabilities-fixed/)
- [7] [Metasploit: modul za zaobilaženje autentifikacije podrazumevanog Brother administratora](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978.rb)
{{#include ../../banners/hacktricks-training.md}}
