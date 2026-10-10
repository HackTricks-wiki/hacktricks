# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Kama golden ticket**, diamond ticket ni TGT inayoweza kutumiwa **kupata ufikiaji wa huduma yoyote kama mtumiaji yeyote**. Golden ticket hughushiwa kabisa nje ya mtandao, husimbwa kwa kutumia hash ya krbtgt ya domain hiyo, kisha huingizwa kwenye logon session ili itumike. Kwa kuwa domain controllers hazifuatilii TGT ambazo zenyewe zimesambaza kihalali, zitakubali bila tatizo TGT zilizosimbwa kwa hash yake yenyewe ya krbtgt.<sup>[[1]](#references)</sup>

Kuna mbinu mbili za kawaida za kugundua matumizi ya golden tickets:

- Tafuta TGS-REQ ambazo hazina AS-REQ inayolingana.
- Tafuta TGT zenye thamani zisizo za kawaida, kama muda wa matumizi wa miaka 10 ambao Mimikatz hutumia kwa chaguo-msingi.

**Diamond ticket** hutengenezwa kwa **kurekebisha sehemu za TGT halali iliyotolewa na DC**. Hili hufanywa kwa **kuomba** **TGT**, **kuisimbua** kwa hash ya krbtgt ya domain, **kurekebisha** sehemu zinazohitajika za ticket, kisha **kuisimba tena**. Hili **hutatua mapungufu mawili yaliyotajwa hapo juu** ya golden ticket kwa sababu:<sup>[[1]](#references)</sup>

- TGS-REQ zitakuwa na AS-REQ iliyotangulia.
- TGT ilitolewa na DC, kwa hivyo itakuwa na maelezo sahihi kutoka kwenye sera ya Kerberos ya domain. Ingawa maelezo haya yanaweza kughushiwa kwa usahihi kwenye golden ticket, kufanya hivyo ni changamano zaidi na kuna uwezekano wa makosa.

### Mahitaji na mtiririko wa kazi

- **Nyenzo za kriptografia**: ufunguo wa krbtgt AES256 (unaopendelewa) au hash ya NTLM ili kusimbua na kusaini upya TGT.
- **Blob halali ya TGT**: hupatikana kwa kutumia `/tgtdeleg`, `asktgt`, `s4u`, au kwa kuhamisha tickets kutoka kwenye memory.
- **Data ya muktadha**: RID ya mtumiaji lengwa, RIDs/SIDs za vikundi, na (hiari) sifa za PAC zilizopatikana kupitia LDAP.
- **Funguo za huduma** (ikiwa tu unapanga kutoa upya service tickets): ufunguo wa AES wa service SPN unayokusudia kuiga.

1. Pata TGT ya mtumiaji yeyote unayemdhibiti kupitia AS-REQ (`/tgtdeleg` ya Rubeus ni rahisi kwa sababu hulazimisha client kutekeleza mchakato wa Kerberos GSS-API bila credentials).
2. Simsua TGT iliyorejeshwa kwa kutumia ufunguo wa krbtgt, rekebisha sifa za PAC (mtumiaji, vikundi, maelezo ya logon, SIDs, madai ya kifaa, n.k.).
3. Simba tena/saini ticket kwa kutumia ufunguo huohuo wa krbtgt na uiingize kwenye logon session ya sasa (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Hiari: rudia mchakato huo kwa service ticket kwa kutoa blob halali ya TGT pamoja na ufunguo wa huduma lengwa ili kubaki stealthy kwenye mtandao.

### Mbinu za Rubeus zilizosasishwa (2024+)

Kazi ya hivi majuzi ya Huntress iliboresha kitendo cha `diamond` ndani ya Rubeus kwa kuhamisha maboresho ya `/ldap` na `/opsec` ambayo awali yalipatikana kwa golden/silver tickets pekee. Sasa `/ldap` hupata muktadha halisi wa PAC kwa kuuliza LDAP **na** kupachika SYSVOL ili kutoa sifa za akaunti/vikundi pamoja na sera ya Kerberos/nywila (kwa mfano, `GptTmpl.inf`), huku `/opsec` ikifanya mtiririko wa AS-REQ/AS-REP ufanane na wa Windows kwa kutekeleza ubadilishanaji wa preauth wa hatua mbili na kutumia AES pekee pamoja na KDCOptions halisi. Hili hupunguza sana viashiria vinavyoonekana wazi, kama sehemu za PAC zinazokosekana au muda wa matumizi usiolingana na sera.<sup>[[3]](#references)</sup>

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
- `/opsec` hulazimisha jaribio jipya la AS-REQ linalofanana na la Windows, huweka flags zenye kelele kuwa sifuri na kutumia AES256 pekee.
- `/tgtdeleg` huepusha kufikia nenosiri la maandishi wazi au ufunguo wa NTLM/AES wa mwathiriwa, huku bado ikirejesha TGT inayoweza kufumbuliwa.

### Kutengeneza upya service-ticket

Usasishaji huo wa Rubeus uliongeza uwezo wa kutumia mbinu ya diamond kwa TGS blobs. Kwa kuipa `diamond` **TGT iliyosimbwa kwa base64** (kutoka `asktgt`, `/tgtdeleg`, au TGT iliyoghushiwa awali), **service SPN**, na **ufunguo wa AES wa service**, unaweza kuunda service tickets halisi bila kugusa KDC—kwa ufanisi, silver ticket fiche zaidi.<sup>[[3]](#references)</sup>

```powershell
./Rubeus.exe diamond \
  /ticket:<BASE64_TGT_OR_KRB-CRED> \
  /service:cifs/dc01.lab.local \
  /servicekey:<AES256_SERVICE_KEY> \
  /ticketuser:svc_sql /ticketuserid:1109 \
  /ldap /opsec /nowrap
```

Mtiririko huu unafaa unapokuwa tayari unadhibiti service account key (kwa mfano, iliyotolewa kwa `lsadump::lsa /inject` au `secretsdump.py`) na unataka kuunda TGS ya mara moja inayolingana kikamilifu na sera za AD, ratiba na data ya PAC bila kutuma trafiki mpya ya AS/TGS.<sup>[[3]](#references)</sup>

### Mabadilishano ya PAC ya mtindo wa Sapphire (2025)

Mbinu mpya zaidi, ambayo wakati mwingine huitwa **sapphire ticket**, inachanganya msingi wa "real TGT" wa Diamond na **S4U2self+U2U** ili kuiba PAC ya mtumiaji mwenye haki za juu na kuiweka kwenye TGT yako mwenyewe. Badala ya kubuni SIDs za ziada, unaomba ticket ya U2U S4U2self ya mtumiaji mwenye haki za juu, huku `sname` ikilenga mwombaji mwenye haki chache; KRB_TGS_REQ hubeba TGT ya mwombaji katika `additional-tickets` na kuweka `ENC-TKT-IN-SKEY`, hivyo kuruhusu ticket ya huduma kusimbuliwa kwa kutumia key ya mtumiaji huyo. Kisha unatoa PAC ya mtumiaji mwenye haki za juu na kuiunganisha kwenye TGT yako halali kabla ya kuitia saini upya kwa kutumia key ya krbtgt.<sup>[[2]](#references)[[5]](#references)</sup>

Impacket's `ticketer.py` sasa ina usaidizi wa sapphire kupitia `-impersonate` + `-request` (mabadilishano ya moja kwa moja na KDC):<sup>[[2]](#references)[[5]](#references)</sup>

```bash
python3 ticketer.py -request -impersonate 'DAuser' \
  -domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
  -aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```

- `-impersonate` hukubali jina la mtumiaji au SID; `-request` inahitaji creds za mtumiaji zilizo hai pamoja na nyenzo za ufunguo wa krbtgt (AES/NTLM) ili kusimbua/kurekebisha tiketi.

Viashiria muhimu vya OPSEC unapotumia lahaja hii:<sup>[[5]](#references)</sup>

- TGS-REQ itakuwa na `ENC-TKT-IN-SKEY` na `additional-tickets` (TGT ya victim) — jambo lisilo la kawaida katika trafiki ya kawaida.
- `sname` mara nyingi huwa sawa na mtumiaji anayeomba (ufikiaji wa self-service), na Event ID 4769 huonyesha mpigaji na lengwa kama SPN/mtumiaji yuleyule.
- Tarajia maingizo ya 4768/4769 yanayolingana, yenye kompyuta ileile ya mteja lakini CNAMES tofauti (mwombaji mwenye haki ndogo dhidi ya mmiliki wa PAC mwenye mamlaka ya juu).

### OPSEC na maelezo ya ugunduzi

- Heuristics za kawaida za hunter (TGS bila AS, muda wa uhai wa muongo mmoja) bado zinatumika kwa golden tickets, lakini diamond tickets hujitokeza hasa pale **maudhui ya PAC au ulinganishaji wa vikundi unapoonekana kutowezekana**. Jaza kila sehemu ya PAC (saa za kuingia, njia za wasifu wa mtumiaji, vitambulisho vya kifaa) ili ulinganishaji wa kiotomatiki usigundue mara moja ughushi huo.<sup>[[3]](#references)</sup>
- **Usiongeze vikundi/RID kupita kiasi**. Ikiwa unahitaji `512` (Domain Admins) na `519` (Enterprise Admins) pekee, acha hapo na uhakikishe kuwa akaunti lengwa inaonekana kuwa mwanachama wa vikundi hivyo kwingineko katika AD. `ExtraSids` nyingi kupita kiasi hufichua ughushi.
- Mabadilishano ya mtindo wa Sapphire huacha alama za U2U: `ENC-TKT-IN-SKEY` + `additional-tickets`, pamoja na `sname` inayoelekeza kwa mtumiaji (mara nyingi mwombaji) katika 4769, na logon ya 4624 inayofuata kutoka kwa tiketi iliyoghushiwa. Linganisha sehemu hizo badala ya kutafuta tu mapengo ya no-AS-REQ.<sup>[[5]](#references)</sup>
- Microsoft ilianza kusitisha hatua kwa hatua utoaji wa **tiketi za huduma za RC4** kutokana na CVE-2026-20833; kulazimisha etypes za AES pekee kwenye KDC huimarisha domain na kuendana na zana za diamond/sapphire (/opsec tayari hulazimisha AES). Kuchanganya RC4 kwenye PAC zilizoghushiwa kutazidi kuonekana wazi.<sup>[[6]](#references)</sup>
- Mradi wa Splunk Security Content husambaza telemetry ya attack-range kwa diamond tickets pamoja na detections kama *Kiashiria cha Kuiga Domain Admin ya Windows*, ambacho huoanisha mfuatano usio wa kawaida wa Event ID 4768/4769/4624 na mabadiliko ya vikundi vya PAC. Kurudia dataset hiyo (au kutengeneza yako kwa kutumia amri zilizo hapo juu) husaidia kuthibitisha ufunikaji wa SOC kwa T1558.001 huku kukikupa mantiki thabiti ya tahadhari ya kukwepa.<sup>[[4]](#references)</sup>

## References

- [1] [Palo Alto Unit 42 – Mawe ya Thamani ya Thamani: Kizazi Kipya cha Mashambulizi ya Kerberos (2022)](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [2] [Core Security – Impacket: Tunapenda Kucheza Tiketi (2023)](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [3] [Huntress – Kukata Upya Tiketi ya Kerberos Diamond (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [4] [Splunk Security Content – Data na detections za shambulio la Diamond Ticket (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [5] [Хабр – Upande wa Giza wa Vito: Tiketi za Diamond na Sapphire (2025)](https://habr.com/ru/articles/891620/)
- [6] [Microsoft – Utekelezaji wa tiketi za huduma za RC4 kwa CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)
{{#include ../../banners/hacktricks-training.md}}
