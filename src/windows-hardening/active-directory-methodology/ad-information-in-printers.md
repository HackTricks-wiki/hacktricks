# Informacije u štampačima

{{#include ../../banners/hacktricks-training.md}}

Štampač sa sačuvanim LDAP akreditivima može da ih otkrije ako se promeni podešavanje servera, nakon čega se autentifikuje na zlonamerni endpoint.<sup>[[2]](#references)</sup> Ishod zavisi od načina bind-a: nezaštićeni simple bind otkriva lozinku, dok SASL challenge-response bind ne otkriva lozinku u čistom tekstu.<sup>[[8]](#references)</sup> Pogledajte [LDAP authentication and transport security](../../network-services-pentesting/pentesting-ldap.md#cleartext-credentials-and-tls-downgrade-risks).

Takođe, više štampača sadrži **logove sa korisničkim imenima** ili čak može da **preuzme sva korisnička imena** sa Domain Controller-a.

Sve ove **osetljive informacije** i čest **nedostatak bezbednosti** čine štampače veoma zanimljivim napadačima.

Neki uvodni blogovi o ovoj temi:

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)<sup>[[4]](#references)</sup>
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)<sup>[[5]](#references)</sup>

---

## Konfiguracija štampača

- **Lokacija**: Lista LDAP servera obično se nalazi u veb-interfejsu (npr. *Network ➜ LDAP Setting ➜ Setting Up LDAP*).
- **Ponašanje**: Mnogi ugrađeni veb-serveri dozvoljavaju izmenu LDAP servera **bez ponovnog unosa akreditiva** (funkcija za lakšu upotrebu → bezbednosni rizik).
- **Eksploatacija**: Preusmerite adresu LDAP servera na host pod kontrolom napadača i kliknite na dugme *Test Connection* / *Address Book Sync* da biste primorali štampač da izvrši bind prema vama.

---

## Hvatanje akreditiva

### Metod 1 – Netcat listener

```bash
sudo nc -k -v -l -p 389     # Plain LDAP only
```

Jednostavan BindRequest može da otkrije bind DN i lozinku u BER toku, čak i ako server kasnije odbije prijavu. Samo anonimni upit ili SASL pregovaranje ne otkrivaju sačuvanu lozinku.<sup>[[8]](#references)</sup>

Običan `nc` listener na portu 636/3269 vidi TLS rukovanje, a ne LDAP bind. Za LDAPS je potrebna TLS-capable krajnja tačka. Sama validacija sertifikata ne sprečava pass-back ako štampač prihvati promenjeno ime hosta, a nova krajnja tačka ima važeći sertifikat za to ime hosta; klijent mora i da ograniči koji server je ovlašćen da primi sačuvane akreditive.<sup>[[8]](#references)</sup>

### Metod 2 – Potpuni Rogue LDAP server (preporučeno)

Štampač može da zahteva validan LDAP odgovor pre nego što pokuša bind.<sup>[[10]](#references)</sup> Potpuni LDAP server može da obradi tu preliminarnu razmenu, ali ne može da navede klijenta koji je vezan za snažan SASL mehanizam ili predviđeni TLS server da otkrije lozinku.<sup>[[8]](#references)[[10]](#references)</sup>

```bash
# Debian/Ubuntu example
sudo apt install slapd ldap-utils
sudo dpkg-reconfigure slapd   # use a base DN compatible with the printer lookup

# run slapd in foreground / debug 2
slapd -d 2 -h "ldap:///"      # only LDAP, no LDAPS
```

Tretirajte upit kao dokaz uspostavljanja veze, a ne kao dokaz otkrivanja lozinke. Lozinka je izložena samo ako klijent pošalje bind sa lozinkom u otvorenom tekstu; proverite stvarni mehanizam bind-a i stanje TLS-a.<sup>[[8]](#references)</sup>

> 💡  Responder uključuje lažne LDAP i SMB servise za autentifikaciju. Jednostavan LDAP bind može da izloži podešenu lozinku, dok NTLM autentifikacija daje materijal za challenge-response; nemojte opisivati oba ishoda kao lozinku u otvorenom tekstu.

### Izbor SASL mehanizma

Neki LDAP klijenti na štampačima biraju među mehanizmima koje oglašava LDAP server.<sup>[[8]](#references)[[10]](#references)</sup> Istraživanje je pokazalo da klijent koji prihvata oglašeni SASL mehanizam sa lozinkom u otvorenom tekstu može da pošalje lozinku, dok bi uobičajeno NTLM pregovaranje dalo samo podatke za challenge-response.<sup>[[9]](#references)[[10]](#references)</sup> Ovo je **propust u klijentskoj politici**, a ne svojstvo svih SASL bind-ova: klijent koji zahteva jači mehanizam ili proverava identitet predviđenog TLS servera trebalo bi umesto toga bezbedno da odbije vezu.<sup>[[8]](#references)</sup> OpenLDAP podrazumevano onemogućava SASL mehanizme koji mogu da prenose lozinku u otvorenom tekstu, tako da standardni daemon ne dokazuje da takvo ponašanje postoji na štampaču.<sup>[[11]](#references)</sup>

---

## Nedavne ranjivosti tipa Pass-Back (2024-2025)

Pass-back nije teorijski problem – dobavljači i dalje objavljuju bezbednosna obaveštenja tokom 2024/2025. koja tačno opisuju ovu klasu napada.

### Xerox VersaLink – CVE-2024-12510 i CVE-2024-12511

Firmver ≤ 57.69.91 za Xerox VersaLink C70xx MFP uređaje omogućavao je autentifikovanom administratoru (ili bilo kome ako su podrazumevani podaci za prijavu ostali nepromenjeni) da:

* **CVE-2024-12510 – LDAP pass-back**: promeni adresu LDAP servera i pokrene upit, zbog čega uređaj šalje podešene Windows akreditive na host pod kontrolom napadača.
* **CVE-2024-12511 – SMB/FTP pass-back**: isti problem preko odredišta *scan-to-folder*, pri čemu dolazi do curenja NetNTLMv2 ili FTP akreditiva u otvorenom tekstu.<sup>[[2]](#references)</sup>

Jednostavan listener, kao što je:

```bash
sudo nc -k -v -l -p 389     # capture LDAP bind
```

ili je lažni SMB server (`impacket-smbserver`) dovoljan za prikupljanje akreditiva.

### Canon imageRUNNER / imageCLASS – savetodavno obaveštenje od 20. maja 2025.

Canon je potvrdio slabost **SMTP/LDAP pass-back** koja pogađa desetine linija Laser & MFP proizvoda. Napadač sa administratorskim pristupom može da izmeni konfiguraciju servera i pribavi sačuvane akreditive za LDAP **ili** SMTP (mnoge organizacije koriste privilegovani nalog za skeniranje i slanje e-pošte).<sup>[[3]](#references)</sup>

Smernice proizvođača izričito preporučuju:

1. Ažuriranje na ispravljeni firmware čim bude dostupan.
2. Korišćenje jakih, jedinstvenih administratorskih lozinki.
3. Izbegavanje privilegovanih AD naloga za integraciju štampača.

---

### Brother uređaji i OEM varijante – administratorski pristup izveden iz serijskog broja omogućava pristup akreditivima servisnih naloga

Koordinisano otkrivanje ranjivosti iz 2025. godine pokazalo je posebno korisnu sekvencu napada na pogođenim Brother uređajima; delovi skupa ranjivosti utiču i na OEM modele, zato proverite tačan model u savetodavnom obaveštenju proizvođača. Neautentifikovani napadač može da pribavi serijski broj uređaja putem HTTP/HTTPS/IPP protokola na ranjivom firmware-u, dok serijski brojevi mogu biti dostupni i putem protokola za upravljanje kao što su SNMP ili PJL. Ako fabrička lozinka nikada nije promenjena, iz serijskog broja se deterministički izvodi administratorska lozinka. Nakon autentifikacije, zasebna pass-back ranjivost CVE-2024-51984 otkriva lozinke za konfigurisane spoljne servise, kao što su LDAP ili FTP, u otvorenom tekstu, pretvarajući pristup za upravljanje štampačem u upotrebljive mrežne akreditive. Firmware rešava otkrivanje lozinki za servise, ali operater i dalje mora da zameni početnu administratorsku lozinku izvedenu iz serijskog broja na uređajima koji su već proizvedeni.<sup>[[6]](#references)</sup>

Aktuelni Metasploit uključuje pomoćni modul koji otkriva serijski broj putem HTTP-a, SNMP-a ili PJL-a, generiše moguću početnu lozinku i, po želji, proverava je putem web konzole. `DiscoverSerialVia=AUTO` isprobava podržane načine otkrivanja; navedite `TargetSerial` umesto toga ako inventar sredstava već sadrži serijski broj.<sup>[[7]](#references)</sup>

```text
msfconsole -q
use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978
set RHOSTS <printer-ip>
set DiscoverSerialVia AUTO
run
```

Koristite rezultat samo za validaciju ovlašćenih resursa. Da li lozinka funkcioniše zavisi od tačnog modela i, što je najvažnije, od toga da li je fabrička administratorska lozinka već promenjena.<sup>[[6]](#references)[[7]](#references)</sup>

---

## Automatizovani alati za enumeraciju / eksploataciju

| Alat | Svrha | Primer |
|------|---------|---------|
| **PRET** (Printer Exploitation Toolkit) | Zloupotreba PostScript/PJL/PCL, pristup sistemu datoteka, provera podrazumevanih akreditiva, *otkrivanje putem SNMP-a*; pogledajte [PJL assessment](../../network-services-pentesting/9100-pjl.md) | `python pret.py 192.168.1.50 pjl` |
| **Praeda** | Prikupljanje konfiguracije (uključujući adresare i LDAP akreditive) putem HTTP/HTTPS-a | `perl praeda.pl -t 192.168.1.50` |
| **Responder / ntlmrelayx** | Pokretanje lažnih servisa za autentifikaciju i hvatanje/prosleđivanje NetNTLM-a iz SMB povratnih veza | `sudo responder -I eth0 -v` |
| **Metasploit Brother auxiliary** | Otkrivanje serijskog broja, izvođenje moguće fabričke administratorske lozinke i provera pristupa veb-konzoli | `use auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978` |

---

## Ojačavanje bezbednosti i detekcija

1. **Pravovremeno instalirajte zakrpe / ažurirajte firmver** na MFP uređajima (proveravajte bezbednosna obaveštenja proizvođača PSIRT).
2. **Zamenite fabričke administratorske lozinke** – sam firmver ne uklanja početne lozinke izvedene iz serijskog broja na ranije proizvedenim Brother/OEM uređajima na koje ovo utiče.<sup>[[6]](#references)</sup>
3. **Nalozi servisa sa najmanjim privilegijama** – nikada ne koristite Domain Admin za LDAP/SMB/SMTP; ograničite opseg na OU-ove sa *pravom samo za čitanje*.
4. **Ograničite pristup za upravljanje** – postavite veb/IPP/SNMP interfejse štampača u VLAN za upravljanje ili iza ACL/VPN-a.
5. **Ograničite izlazni saobraćaj štampača** – dozvolite svakom uređaju da se povezuje samo sa očekivanim odredištima za DC/LDAP, poštu, DNS/NTP, štampanje i datoteke za skeniranje. Pass-back zahteva callback ka krajnjoj tački koju je izabrao napadač.
6. **Onemogućite neiskorišćene protokole** – FTP, Telnet, raw-9100 i starije SSL šifre.
7. **Omogućite beleženje revizije** – neki uređaji mogu da beleže LDAP/SMTP neuspehe putem syslog-a; povežite neočekivana povezivanja.
8. **Nadgledajte odredišta za autentifikaciju** – generišте upozorenje kada štampač pokрене LDAP, SMB, SMTP или FTP везу ка хосту ван листе дозвољених, нарочито одмах након пријаве за управљање или промене конфигурације.
9. **Користите SNMPv3 или онемогућите SNMP** – community `public` често открива информације о уређају и серијском броју.

---



---



## References

- [1] [То је само штампач… Шта је најгоре што може да се деси?](https://grimhacker.com/2018/03/09/just-a-printer/)
- [2] [Вишенаменски штампач Xerox Versalink C7025: рањивости на Pass-Back напад (отклоњене)](https://www.rapid7.com/blog/post/2025/02/14/xerox-versalink-c7025-multifunction-printer-pass-back-attack-vulnerabilities-fixed/)
- [3] [CP2025-004 Ублажавање/отклањање рањивости за производне штампаче, вишенаменске штампаче за канцеларије и мале канцеларије и ласерске штампаче](https://psirt.canon/advisory-information/cp2025-004/)
- [4] [Прибављање доменских акредитива преко штампача помоћу алатке Netcat](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [5] [Експлоатација вишенаменских штампача током ангажмана за тестирање пенетрације](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [6] [Више Brother уређаја: више рањивости (ОТКЛОЊЕНЕ)](https://www.rapid7.com/blog/post/multiple-brother-devices-multiple-vulnerabilities-fixed/)
- [7] [Metasploit: модул за заобилажење подразумеване Brother администраторске аутентификације](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978.rb)
- [8] [RFC 4513 – LDAP методе аутентификације и безбедносни механизми](https://datatracker.ietf.org/doc/html/rfc4513)
- [9] [Docker сервер за LDAP passback](https://github.com/cybertrinchera/ldap-passback-docker)
- [10] [LDAP pass back напад – ACCEIS](https://www.acceis.fr/ldap-pass-back-attack/)
- [11] [slapd-config(5) – SASL безбедносна својства](https://man7.org/linux/man-pages/man5/slapd-config.5.html)
{{#include ../../banners/hacktricks-training.md}}
