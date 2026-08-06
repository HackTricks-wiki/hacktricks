# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Kama golden ticket**, diamond ticket ni TGT inayoweza kutumiwa **kufikia service yoyote kama user yoyote**. Golden ticket inaforgiwa kabisa offline, inasimbwa kwa kutumia krbtgt hash ya domain hiyo, kisha inaingizwa kwenye logon session ili itumike. Kwa sababu domain controllers hazifuatilii TGT ambazo zenyewe (au wao) wamezitoa kihalali, zitakubali kwa urahisi TGT zilizosimbwa kwa kutumia krbtgt hash yake yenyewe.<sup>[[1]](#references)</sup>

Kuna mbinu mbili za kawaida za kugundua matumizi ya golden tickets:

- Tafuta TGS-REQs ambazo hazina AS-REQ inayolingana.
- Tafuta TGTs zilizo na thamani zisizo za kawaida, kama lifetime ya miaka 10 ya default ya Mimikatz.

**Diamond ticket** hutengenezwa kwa **kubadilisha fields za TGT halali iliyotolewa na DC**. Hili hufanyika kwa **kuomba** **TGT**, **kuifungua** kwa kutumia krbtgt hash ya domain, **kubadilisha** fields zinazohitajika za ticket, kisha **kuisimba tena**. Hili **huondoa mapungufu mawili yaliyotajwa hapo juu** ya golden ticket kwa sababu:<sup>[[1]](#references)</sup>

- TGS-REQs zitakuwa na AS-REQ iliyotangulia.
- TGT ilitolewa na DC, hivyo itakuwa na details zote sahihi kutoka kwenye Kerberos policy ya domain. Ingawa details hizi zinaweza kuforgiwa kwa usahihi katika golden ticket, mchakato huo ni mgumu zaidi na una uwezekano wa kukosewa.

### Mahitaji na workflow

- **Cryptographic material**: krbtgt AES256 key (inayopendekezwa) au NTLM hash ili ku-decrypt na kusaini tena TGT.
- **Legitimate TGT blob**: hupatikana kwa kutumia `/tgtdeleg`, `asktgt`, `s4u`, au kwa ku-export tickets kutoka memory.
- **Context data**: target user RID, group RIDs/SIDs, na (kwa hiari) PAC attributes zinazotokana na LDAP.
- **Service keys** (ikiwa tu unapanga kuunda upya service tickets): AES key ya service SPN itakayo-impersonate.

1. Pata TGT ya user yoyote unayemdhibiti kupitia AS-REQ (Rubeus `/tgtdeleg` ni rahisi kutumia kwa sababu hulazimisha client kutekeleza Kerberos GSS-API dance bila credentials).
2. Decrypt TGT iliyorejeshwa kwa kutumia krbtgt key, kisha patch PAC attributes (user, groups, logon info, SIDs, device claims, n.k.).
3. Encrypt na sign ticket tena kwa kutumia krbtgt key ileile, kisha inject ndani ya logon session ya sasa (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Kwa hiari, rudia mchakato huo kwenye service ticket kwa kutoa TGT blob halali pamoja na target service key ili kubaki stealthy kwenye network.

### Updated Rubeus tradecraft (2024+)

Kazi za hivi karibuni za Huntress ziliboresha `diamond` action ndani ya Rubeus kwa kuhamisha maboresho ya `/ldap` na `/opsec` ambayo hapo awali yalipatikana tu kwa golden/silver tickets. `/ldap` sasa hukusanya PAC context halisi kwa kufanya query kwenye LDAP **na** ku-mount SYSVOL ili kutoa account/group attributes pamoja na Kerberos/password policy (kwa mfano, `GptTmpl.inf`), huku `/opsec` ikifanya AS-REQ/AS-REP flow ilingane na Windows kwa kutekeleza two-step preauth exchange na kulazimisha AES-only pamoja na KDCOptions halisi. Hili hupunguza kwa kiasi kikubwa indicators zilizo wazi, kama PAC fields zinazokosekana au lifetimes zisizoendana na policy.<sup>[[3]](#references)</sup>
```powershell
# Query RID/context data (PowerView/SharpView/AD modules all work)
Get-DomainUser -Identity <username> -Properties objectsid | Select-Object samaccountname,objectsid

# Craft a high-fidelity diamond TGT and inject it
./Rubeus.exe diamond /tgtdeleg \
/ticketuser:svc_sql /ticketuserid:1109 \
/groups:512,519 \
/krbkey:<KRBTGT_AES256_KEY> \
/ldap /ldapuser:MARVEL\loki /ldappassword:Mischief$ \
/opsec /nowrap
```
- `/ldap` (pamoja na `/ldapuser` na `/ldappassword` za hiari) huuliza AD na SYSVOL ili kunakili data ya sera ya PAC ya mtumiaji lengwa.
- `/opsec` hulazimisha jaribio la tena la AS-REQ linalofanana na Windows, huweka flags zenye kelele kuwa sifuri na kutumia AES256 pekee.
- `/tgtdeleg` huzuia nenosiri la maandishi wazi au ufunguo wa NTLM/AES wa mwathiriwa kuguswa, huku bado ikirejesha TGT inayoweza kudekriptwa.

### Kukata upya service-ticket

Rubeus refresh hiyo hiyo iliongeza uwezo wa kutumia diamond technique kwenye TGS blobs. Kwa kuipa `diamond` **TGT iliyosimbwa kwa base64** (kutoka `asktgt`, `/tgtdeleg`, au TGT iliyoforgiwa hapo awali), **service SPN**, na **service AES key**, unaweza kutengeneza service tickets zenye uhalisia bila kugusa KDC—kimsingi silver ticket yenye usiri zaidi.<sup>[[3]](#references)</sup>
```powershell
./Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
Mtiririko huu ni bora unapokuwa tayari unadhibiti service account key (kwa mfano, iliyodumpiwa kwa `lsadump::lsa /inject` au `secretsdump.py`) na unataka kukata TGS ya matumizi moja inayolingana kikamilifu na sera ya AD, timelines na data ya PAC bila kutuma AS/TGS traffic mpya.<sup>[[3]](#references)</sup>

### Sapphire-style PAC swaps (2025)

Mbinu mpya zaidi ambayo wakati mwingine huitwa **sapphire ticket** inachanganya msingi wa "real TGT" wa Diamond na **S4U2self+U2U** ili kuiba PAC yenye privileges za juu na kuiweka ndani ya TGT yako. Badala ya kubuni SIDs za ziada, unaomba U2U S4U2self ticket kwa mtumiaji mwenye privileges za juu ambapo `sname` inalenga requester mwenye privileges za chini; KRB_TGS_REQ hubeba TGT ya requester katika `additional-tickets` na kuweka `ENC-TKT-IN-SKEY`, hivyo service ticket inaweza kufichuliwa kwa kutumia key ya mtumiaji huyo. Kisha unatoa PAC yenye privileges za juu na kuiunganisha kwenye TGT yako halali kabla ya kuitia saini upya kwa kutumia krbtgt key.<sup>[[2]](#references)[[5]](#references)</sup>

Impacket's `ticketer.py` sasa inakuja na sapphire support kupitia `-impersonate` + `-request` (live KDC exchange):<sup>[[2]](#references)[[5]](#references)</sup>
```bash
python3 ticketer.py -request -impersonate 'DAuser' \
-domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
-aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```
- `-impersonate` inakubali username au SID; `-request` inahitaji live user creds pamoja na krbtgt key material (AES/NTLM) ili kusimbua/kurekebisha tickets.

Dalili muhimu za OPSEC unapotumia variant hii:<sup>[[5]](#references)</sup>

- TGS-REQ itakuwa na `ENC-TKT-IN-SKEY` na `additional-tickets` (victim TGT) — hali adimu katika traffic ya kawaida.
- `sname` mara nyingi huwa sawa na requesting user (self-service access), na Event ID 4769 huonyesha caller na target kama SPN/user yuleyule.
- Tarajia entries zinazooana za 4768/4769 zenye client computer ileile lakini CNAMES tofauti (low-priv requester dhidi ya privileged PAC owner).

### OPSEC & detection notes

- Mbinu za kawaida za hunter (TGS bila AS, lifetimes za miongo) bado zinatumika kwa golden tickets, lakini diamond tickets hujitokeza zaidi wakati **maudhui ya PAC au group mapping yanaonekana kuwa haiwezekani**. Jaza kila PAC field (logon hours, user profile paths, device IDs) ili automated comparisons zisibandike forgery mara moja.<sup>[[3]](#references)</sup>
- **Usiongeze groups/RIDs kupita kiasi**. Ikiwa unahitaji `512` (Domain Admins) na `519` (Enterprise Admins) pekee, ishie hapo na uhakikishe kuwa target account inaonekana kwa njia inayowezekana kuwa ni mwanachama wa groups hizo kwingineko katika AD. `ExtraSids` nyingi ni giveaway.
- Swaps za mtindo wa Sapphire huacha U2U fingerprints: `ENC-TKT-IN-SKEY` + `additional-tickets`, pamoja na `sname` inayoelekeza kwa user (mara nyingi requester) katika 4769, na 4624 logon inayofuata kutoka kwenye forged ticket. Correlate fields hizo badala ya kutafuta tu mapengo ya no-AS-REQ.<sup>[[5]](#references)</sup>
- Microsoft ilianza kuondoa hatua kwa hatua **RC4 service ticket issuance** kwa sababu ya CVE-2026-20833; kutekeleza AES-only etypes kwenye KDC huimarisha domain na kuendana na diamond/sapphire tooling (`/opsec` tayari inalazimisha AES). Kuchanganya RC4 katika forged PACs kutazidi kuwa jambo linalojitokeza wazi.<sup>[[6]](#references)</sup>
- Mradi wa Splunk's Security Content unasambaza attack-range telemetry kwa diamond tickets pamoja na detections kama *Windows Domain Admin Impersonation Indicator*, ambayo hu-correlate mfululizo usio wa kawaida wa Event ID 4768/4769/4624 na mabadiliko ya PAC groups. Kurudia dataset hiyo (au kutengeneza yako kwa commands zilizo hapo juu) husaidia kuthibitisha SOC coverage kwa T1558.001 huku kukikupa alert logic halisi ya kukwepa.<sup>[[4]](#references)</sup>

## References

- [1] [Palo Alto Unit 42 – Precious Gemstones: The New Generation of Kerberos Attacks (2022)](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [2] [Core Security – Impacket: We Love Playing Tickets (2023)](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [3] [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [4] [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [5] [Хабр – Теневая сторона драгоценностей: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [6] [Microsoft – RC4 service ticket enforcement for CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
