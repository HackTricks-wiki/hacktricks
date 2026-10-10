# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Kama golden ticket**, diamond ticket ni TGT inayoweza kutumiwa **kufikia huduma yoyote kama mtumiaji yeyote**. Golden ticket hutengenezwa kabisa nje ya mtandao, husimbwa kwa kutumia krbtgt hash ya domain hiyo, kisha huingizwa kwenye logon session ili itumike. Kwa kuwa domain controllers hazifuatilii TGT ambazo zimezitoa kihalali, zitakubali kwa furaha TGT zilizosimbwa kwa krbtgt hash yao wenyewe.<sup>[[1]](#references)</sup>

Kuna mbinu mbili za kawaida za kugundua matumizi ya golden tickets:

- Tafuta TGS-REQs zisizo na AS-REQ inayolingana nazo.
- Tafuta TGT zenye thamani zisizo za kawaida, kama muda wa uhalali wa miaka 10 ambao Mimikatz hutumia kwa chaguomsingi.

**Diamond ticket** hutengenezwa kwa **kurekebisha sehemu za TGT halali iliyotolewa na DC**. Hili hufanywa kwa **kuomba** **TGT**, **kuisimbua** kwa kutumia krbtgt hash ya domain, **kurekebisha** sehemu zinazotakiwa za ticket, kisha **kuisimba tena**. Hili **hutatua kasoro mbili zilizotajwa hapo juu** za golden ticket kwa sababu:<sup>[[1]](#references)</sup>

- TGS-REQs zitakuwa na AS-REQ iliyotangulia.
- TGT ilitolewa na DC, kwa hiyo itakuwa na maelezo yote sahihi kutoka kwenye sera ya Kerberos ya domain. Ingawa maelezo haya yanaweza kuundwa kwa usahihi kwenye golden ticket, mchakato huo ni changamani zaidi na unaweza kusababisha makosa.

### Mahitaji na mtiririko wa kazi

- **Nyenzo za kriptografia**: krbtgt AES256 key (inayopendekezwa) au NTLM hash ili kusimbua na kusaini upya TGT.
- **Blob ya TGT halali**: hupatikana kwa kutumia `/tgtdeleg`, `asktgt`, `s4u`, au kwa kusafirisha tickets kutoka kwenye memory.
- **Data ya muktadha**: RID ya mtumiaji lengwa, RIDs/SIDs za group, na (kwa hiari) sifa za PAC zilizotokana na LDAP.
- **Service keys** (ikiwa tu unapanga kuunda upya service tickets): AES key ya service SPN inayotaka kuiga.

1. Pata TGT ya mtumiaji yeyote unayemdhibiti kupitia AS-REQ (`/tgtdeleg` ya Rubeus ni rahisi kwa sababu hulazimisha client kutekeleza mchakato wa Kerberos GSS-API bila credentials).
2. Simbua TGT iliyorudishwa kwa kutumia krbtgt key, rekebisha sifa za PAC (mtumiaji, groups, maelezo ya logon, SIDs, madai ya kifaa, n.k.).
3. Saini upya na usimbe ticket kwa kutumia krbtgt key ileile, kisha uiingize kwenye logon session ya sasa (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Kwa hiari, rudia mchakato huo kwa service ticket kwa kutoa blob halali ya TGT pamoja na service key ya huduma lengwa ili kupunguza uwezekano wa kugunduliwa kwenye mtandao.

### Mbinu mpya za Rubeus (2024+)

Kazi ya hivi karibuni ya Huntress iliboresha kitendo cha `diamond` ndani ya Rubeus kwa kuhamisha maboresho ya `/ldap` na `/opsec` yaliyokuwa yanapatikana tu kwa golden/silver tickets. Sasa `/ldap` hupata muktadha halisi wa PAC kwa kuuliza LDAP **na** kuunganisha SYSVOL ili kutoa sifa za akaunti/group pamoja na sera za Kerberos/password (kwa mfano, `GptTmpl.inf`), huku `/opsec` ikifanya mtiririko wa AS-REQ/AS-REP ufanane na wa Windows kwa kutekeleza mabadilishano ya hatua mbili ya preauth na kulazimisha AES pekee pamoja na KDCOptions halisi. Hili hupunguza kwa kiasi kikubwa viashiria vinavyojitokeza wazi, kama sehemu za PAC zinazokosekana au muda wa uhalali usioendana na sera.<sup>[[3]](#references)</sup>

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

- `/ldap` (pamoja na `/ldapuser` na `/ldappassword` za hiari) huuliza AD na SYSVOL ili kuakisi data ya sera ya PAC ya mtumiaji lengwa.
- `/opsec` hulazimisha jaribio la AS-REQ linalofanana na la Windows, huweka flags zenye kelele kuwa sifuri na kutumia AES256 pekee.
- `/tgtdeleg` hukuwezesha kuepuka kushughulikia nenosiri la victim lililo wazi au ufunguo wa NTLM/AES, huku bado ukipata TGT inayoweza kufumbuliwa.

### Kukata upya service-ticket

Usasishaji huo wa Rubeus pia uliongeza uwezo wa kutumia mbinu ya diamond kwenye TGS blobs. Kwa kuipa `diamond` **TGT iliyosimbwa kwa base64** (kutoka `asktgt`, `/tgtdeleg`, au TGT iliyoghushiwa awali), **service SPN**, na **ufunguo wa AES wa service**, unaweza kuunda service tickets halisi bila kuwasiliana na KDC—kwa ufanisi, silver ticket yenye ufichaji bora zaidi.<sup>[[3]](#references)</sup>

```powershell
./Rubeus.exe diamond \
  /ticket:<BASE64_TGT_OR_KRB-CRED> \
  /service:cifs/dc01.lab.local \
  /servicekey:<AES256_SERVICE_KEY> \
  /ticketuser:svc_sql /ticketuserid:1109 \
  /ldap /opsec /nowrap
```

Workflow hii ni bora unapokuwa tayari unadhibiti service account key (kwa mfano, iliyotolewa kwa `lsadump::lsa /inject` au `secretsdump.py`) na unataka kutengeneza TGS ya mara moja inayolingana kikamilifu na sera ya AD, ratiba na data ya PAC bila kutuma trafiki mpya ya AS/TGS.<sup>[[3]](#references)</sup>

### Sapphire-style PAC swaps (2025)

Mbinu mpya zaidi, ambayo wakati mwingine huitwa **sapphire ticket**, inachanganya msingi wa "real TGT" wa Diamond na **S4U2self+U2U** ili kuiba PAC yenye upendeleo wa juu na kuiweka kwenye TGT yako mwenyewe. Badala ya kubuni SID za ziada, unaomba tiketi ya U2U S4U2self ya mtumiaji mwenye upendeleo wa juu, ambapo `sname` inaelekezwa kwa mwombaji asiye na upendeleo; KRB_TGS_REQ inabeba TGT ya mwombaji kwenye `additional-tickets` na kuweka `ENC-TKT-IN-SKEY`, hivyo tiketi ya huduma inaweza kusimbuliwa kwa kutumia key ya mtumiaji huyo. Kisha unatoa PAC yenye upendeleo wa juu na kuiunganisha kwenye TGT yako halali kabla ya kuitia saini upya kwa kutumia key ya krbtgt.<sup>[[2]](#references)[[5]](#references)</sup>

Sasa Impacket's `ticketer.py` ina usaidizi wa sapphire kupitia `-impersonate` + `-request` (mabadilishano ya moja kwa moja na KDC):<sup>[[2]](#references)[[5]](#references)</sup>

```bash
python3 ticketer.py -request -impersonate 'DAuser' \
  -domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
  -aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```

- `-impersonate` hukubali username au SID; `-request` huhitaji creds za mtumiaji zilizo hai pamoja na nyenzo muhimu ya krbtgt (AES/NTLM) ili kusimbua/kurekebisha tickets.

Viashiria muhimu vya OPSEC unapotumia lahaja hii:<sup>[[5]](#references)</sup>

- TGS-REQ itakuwa na `ENC-TKT-IN-SKEY` na `additional-tickets` (TGT ya mwathiriwa) — hali isiyo ya kawaida katika trafiki ya kawaida.
- `sname` mara nyingi huwa sawa na mtumiaji anayeomba (ufikiaji wa kujihudumia), na Event ID 4769 huonyesha mpigaji na lengo wakiwa SPN/mtumiaji yuleyule.
- Tarajia maingizo yanayooanishwa ya 4768/4769 yenye kompyuta ileile ya mteja lakini CNAMES tofauti (mwombaji mwenye ruhusa ndogo dhidi ya mmiliki wa PAC mwenye upendeleo).

### OPSEC na vidokezo vya utambuzi

- Mbinu za jadi za hunter (TGS bila AS, muda wa uhalali wa miongo kadhaa) bado zinatumika kwa golden tickets, lakini diamond tickets hujitokeza hasa pale **maudhui ya PAC au ulinganishaji wa groups vinapoonekana haviwezekani**. Jaza kila sehemu ya PAC (saa za kuingia, njia za wasifu wa mtumiaji, device IDs) ili ulinganishaji wa kiotomatiki usitambue mara moja kughushi huko.<sup>[[3]](#references)</sup>
- **Usiongeze groups/RIDs kupita kiasi**. Ikiwa unahitaji `512` (Domain Admins) na `519` (Enterprise Admins) pekee, ishia hapo na uhakikishe kuwa akaunti lengwa inaonekana kwa mantiki kuwa mshiriki wa groups hizo kwingineko katika AD. `ExtraSids` nyingi kupita kiasi huashiria udanganyifu.
- Mabadilishano ya mtindo wa Sapphire huacha alama za U2U: `ENC-TKT-IN-SKEY` + `additional-tickets` pamoja na `sname` inayoelekeza kwa mtumiaji (mara nyingi mwombaji) katika 4769, na logon ya 4624 inayofuata kutoka kwenye ticket iliyoghushiwa. Linganisha sehemu hizo badala ya kuangalia tu mapengo ya no-AS-REQ.<sup>[[5]](#references)</sup>
- Microsoft imeanza kuondoa hatua kwa hatua **utoaji wa service ticket za RC4** kwa sababu ya CVE-2026-20833; kulazimisha etypes za AES pekee kwenye KDC huimarisha domain na kuendana na zana za diamond/sapphire (/opsec tayari hulazimisha AES). Kuweka RC4 kwenye PAC zilizoghushiwa kutazidi kujitokeza.<sup>[[6]](#references)</sup>
- Mradi wa Splunk's Security Content husambaza telemetry ya attack-range kwa diamond tickets pamoja na detections kama *Windows Domain Admin Impersonation Indicator*, inayolinganisha mfuatano usio wa kawaida wa Event ID 4768/4769/4624 na mabadiliko ya groups kwenye PAC. Kucheza tena dataset hiyo (au kutengeneza yako kwa kutumia amri zilizo hapo juu) husaidia kuthibitisha ufunikaji wa SOC kwa T1558.001 huku pia kukikupa mantiki halisi ya tahadhari ya kukwepa.<sup>[[4]](#references)</sup>

## References

- [1] [Palo Alto Unit 42 – Mawe ya Vito Yenye Thamani: Kizazi Kipya cha Mashambulizi ya Kerberos (2022)](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [2] [Core Security – Impacket: Tunapenda Kucheza na Tickets (2023)](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [3] [Huntress – Kukata Upya Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [4] [Splunk Security Content – Data za mashambulizi ya Diamond Ticket na detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [5] [Хабр – Upande wa giza wa vito: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [6] [Microsoft – Utekelezaji wa RC4 service ticket kwa CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)
{{#include ../../banners/hacktricks-training.md}}
