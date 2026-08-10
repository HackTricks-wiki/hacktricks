# Kugundua Phishing

## Utangulizi

Ili kugundua jaribio la phishing, ni muhimu **kuelewa mbinu za phishing zinazotumiwa siku hizi**. Kwenye ukurasa mkuu wa chapisho hili, unaweza kupata taarifa hii; kwa hivyo, ikiwa hujui ni mbinu zipi zinazotumiwa leo, ninapendekeza uende kwenye ukurasa mkuu na usome angalau sehemu hiyo.

Chapisho hili linatokana na wazo kwamba **washambuliaji watajaribu kwa namna fulani kuiga au kutumia jina la domain la mwathiriwa**. Ikiwa domain yako inaitwa `example.com` na umefanyiwa phishing kwa kutumia jina tofauti kabisa la domain kwa sababu kama `youwonthelottery.com`, mbinu hizi hazitaweza kuigundua.

## Tofauti za majina ya domain

Ni **rahisi kwa kiasi** **kugundua** majaribio hayo ya **phishing** ambayo yatatumia jina la **domain inayofanana** ndani ya barua pepe.\
Inatosha **kutengeneza orodha ya majina ya phishing yanayowezekana zaidi** ambayo mshambuliaji anaweza kutumia na **kuangalia** kama **imesajiliwa**, au kuangalia tu kama kuna **IP** inayoitumia.

### Kutafuta domain zinazotiliwa shaka

Kwa madhumuni haya, unaweza kutumia mojawapo ya tools zifuatazo. Zote mbili hutatua candidate domains ili kuangalia kama zinatumika.<sup>[[3]](#references)[[4]](#references)</sup>

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

Kidokezo: Ukitengeneza candidate list, pia ipeleke kwenye DNS resolver logs zako ili kugundua **NXDOMAIN lookups kutoka ndani ya org yako** (watumiaji wanaojaribu kufikia typo kabla mshambuliaji hajaweza kuisajili). Elekeza domains hizi kwenye sinkhole au uzizuie mapema ikiwa policy inaruhusu.

### Bitflipping

**Kwa maelezo mafupi, tazama ukurasa mkuu; kwa utafiti wa msingi kuhusu bitsquatting ya Windows.com, tazama [Remy Hax's write-up](https://remyhax.xyz/posts/bitsquatting-windows/) na [ripoti ya BleepingComputer](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)**.<sup>[[1]](#references)[[2]](#references)</sup>

Kwa mfano, mabadiliko ya bit 1 kwenye domain microsoft.com yanaweza kuibadilisha kuwa _windnws.com._\
**Washambuliaji wanaweza kusajili domains nyingi za bit-flipping iwezekanavyo zinazohusiana na mwathiriwa ili kuwaelekeza watumiaji halali kwenye infrastructure yao**.<sup>[[1]](#references)[[2]](#references)</sup>

**Majina yote ya domains yanayowezekana kutokana na bit-flipping yanapaswa pia kufuatiliwa.**

Ikiwa pia unahitaji kuzingatia homoglyph/IDN lookalikes (kwa mfano, kuchanganya herufi za Latin/Cyrillic), angalia:

{{#ref}}
homograph-attacks.md
{{#endref}}

### Ukaguzi wa msingi

Baada ya kuwa na orodha ya majina ya domains yanayoweza kutiliwa shaka, unapaswa **kuyakagua** (hasa ports za HTTP na HTTPS) ili **kuona kama yanatumia login form inayofanana** na ile ya domain ya mwathiriwa.\
Unaweza pia kuangalia port 3333 ili kuona kama iko wazi na inaendesha instance ya `gophish`.\
Pia ni muhimu kujua **kila domain inayotiliwa shaka iliyogunduliwa ina umri gani**, kwani ilivyo changa ndivyo hatari inavyokuwa kubwa zaidi.\
Unaweza pia kupata **screenshots** za ukurasa wa wavuti wa HTTP na/au HTTPS unaotiliwa shaka ili kuona kama unaashiria shaka, na katika hali hiyo **kuufikia ili kuuchunguza kwa undani zaidi**.

### Ukaguzi wa hali ya juu

Ikiwa unataka kwenda hatua moja zaidi, ninapendekeza **kufuatilia domains hizo zinazotiliwa shaka na kutafuta nyingine zaidi** mara kwa mara (kila siku? huchukua sekunde/dakika chache tu). Unapaswa pia **kuangalia** **ports** zilizo wazi za IP zinazohusiana na **kutafuta instances za `gophish` au tools zinazofanana** (ndiyo, washambuliaji pia hufanya makosa) na **kufuatilia kurasa za wavuti za HTTP na HTTPS za domains na subdomains zinazotiliwa shaka** ili kuona kama zimenakili login form yoyote kutoka kwenye kurasa za wavuti za mwathiriwa.\
Ili **ku-automate hili**, ninapendekeza uwe na orodha ya login forms za domains za mwathiriwa, ufanye spidering ya kurasa za wavuti zinazotiliwa shaka, kisha ulinganishe kila login form inayopatikana ndani ya domains zinazotiliwa shaka na kila login form ya domain ya mwathiriwa kwa kutumia kitu kama `ssdeep`.\
Ikiwa umezipata login forms za domains zinazotiliwa shaka, unaweza kujaribu **kutuma junk credentials** na **kuangalia kama inaku-redirect kwenye domain ya mwathiriwa**.

---

### Hunting kwa kutumia favicon na web fingerprints (Shodan/Censys)

Phishing kits nyingi hutumia tena favicons kutoka kwenye brand wanayojiwakilisha. Shodan huhash data yake ya favicon iliyosimbwa kwa base64 kwa kutumia MurmurHash3, huku Censys ikionyesha favicon hash fields zake yenyewe.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup> Unaweza kutengeneza hash inayooana na Shodan na kuitumia kama pivot:

Mfano wa Python (mmh3):
```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```
- Query Shodan: `http.favicon.hash:309020573`
- Kwa kutumia tooling: angalia community tools kama favfreak ili kukokotoa hashes na kutengeneza Shodan dorks.<sup>[[16]](#references)</sup>

Maelezo
- Favicons hutumiwa tena; chukulia matches kama vidokezo na uhakiki maudhui na certs kabla ya kuchukua hatua.
- Changanya na heuristics za umri wa domain na keywords ili kupata usahihi bora zaidi.

### Uwindaji wa URL telemetry (urlscan.io)

`urlscan.io` huhifadhi screenshots za kihistoria, DOM, requests na metadata ya TLS za URLs zilizowasilishwa. Unaweza kuwinda matumizi mabaya ya brand na clones:<sup>[[8]](#references)</sup>

Mifano ya queries (UI au API):
- Tafuta lookalikes ukiondoa domains zako halali: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- Tafuta sites zinazotumia assets zako kupitia hotlinking: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- Punguza kwenye results za hivi karibuni: ongeza `AND date:>now-7d`

Mfano wa API:
```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
-H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```
Kutoka kwenye JSON, chunguza:
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays` ili kubaini vyeti vipya sana vya lookalikes
- thamani za `task.source` kama `certstream-suspicious` ili kuhusisha matokeo na ufuatiliaji wa CT

### Umri wa domain kupitia RDAP (scriptable)

RDAP hurejesha matukio ya usajili yanayoweza kusomeka na mashine. Ni muhimu kwa kubaini **domain zilizosajiliwa hivi karibuni (NRDs)**.<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```
Boresha pipeline yako kwa kuweka tag za domains kulingana na makundi ya umri wa usajili (kwa mfano, <7 days, <30 days) na upe kipaumbele cha triage ipasavyo.

### TLS/JAx fingerprints za kubaini AiTM infrastructure

Credential-phishing inaweza kutumia reverse proxies za **Adversary-in-the-Middle (AiTM)** (kwa mfano, Evilginx) kuiba session tokens.<sup>[[11]](#references)</sup> Unaweza kuongeza detections upande wa network:

- Log TLS/HTTP fingerprints (JA3/JA4/JA4S/JA4H) kwenye egress. Baadhi ya builds za Evilginx zimeonekana zikiwa na JA4 client/server values thabiti. Toa alert kuhusu fingerprints zinazojulikana kuwa mbaya tu kama signal dhaifu, na kila mara thibitisha kwa kutumia content na domain intel.<sup>[[12]](#references)</sup>
- Rekodi kwa njia proactive metadata za TLS certificate (issuer, SAN count, wildcard use, validity) kwa lookalike hosts zilizogunduliwa kupitia CT au urlscan, na correlate na umri wa DNS na geolocation.

> Kumbuka: Tumia fingerprints kama enrichment, si kama blockers pekee; frameworks hubadilika na zinaweza kurandomise au kuficha.

### Domain names zinazotumia keywords

Ukurasa mkuu pia unataja domain name variation technique inayohusisha kuweka **jina la domain la victim ndani ya domain kubwa zaidi** (kwa mfano, paypal-financial.com kwa paypal.com).

#### Certificate Transparency

Certificate Transparency (CT) logs hufichua certificate identities, hivyo kutafuta Subject au SAN names kwa brand keywords kunaweza kufichua lookalike domains (kwa mfano, certificate ya `paypal-financial.com` hufichua keyword ya `paypal`). Filter matokeo kwa issuance date na CA inapofaa, na validate candidates kwa sababu keyword matches zinaweza kuwa false positives.<sup>[[13]](#references)</sup>

Patrik Hudak's [phishing-domain hunting write-up](https://0xpatrik.com/phishing-domains/) ya awali inaonyesha workflow hii katika Censys, ikiwa ni pamoja na filters za certificate date na issuer kama Let's Encrypt.<sup>[[13]](#references)</sup>

Unaweza pia kutumia huduma ya bure ya [**crt.sh**](https://crt.sh) kutafuta keyword na kufilter matokeo kwa date na CA.<sup>[[13]](#references)</sup>

Sehemu yake ya Matching Identities inaweza kusaidia kulinganisha identities kutoka domain halisi na suspicious domains, lakini chukulia matches kama leads badala ya proof.<sup>[[13]](#references)</sup>

[*CertStream*](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067) hutiririsha CT updates karibu kwa real time, na [*phishing_catcher*](https://github.com/x0rz/phishing_catcher) hutumia stream hiyo kuscore certificate names zinazotiliwa shaka.<sup>[[14]](#references)[[15]](#references)</sup>

Ushauri wa vitendo: unapofanya triage ya CT hits, weka kipaumbele kwa NRDs, registrars wasioaminika/wasiojulikana, privacy-proxy WHOIS, na certs zilizo na `NotBefore` times za hivi karibuni sana. Dumisha allowlist ya domains/brands unazomiliki ili kupunguza noise.

#### **New domains**

Chaguo la pili ni kukusanya newly registered domains kwa TLD (kwa mfano, kupitia [Whoxy](https://www.whoxy.com/newly-registered-domains/)) na kufilter kwa brand keywords. Hii hukosa phishing inayohostiwa kwenye subdomains wakati keyword haipo kwenye registered domain.<sup>[[13]](#references)</sup>

Heuristic ya ziada: chukulia baadhi ya **file-extension TLDs** (kwa mfano, `.zip`, `.mov`) kwa mashaka ya ziada wakati wa alerting. Hizi mara nyingi huchanganywa na filenames kwenye lures; changanya TLD signal na brand keywords na umri wa NRD ili kupata precision bora.

## References

- [1] [Remy Hax – Bitsquatting Windows.com](https://remyhax.xyz/posts/bitsquatting-windows/)
- [2] [Hijacking traffic to Microsoft's windows.com with bitflipping](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [3] [dnstwist](https://github.com/elceef/dnstwist)
- [4] [urlcrazy](https://github.com/urbanadventurer/urlcrazy)
- [5] [Deep Dive: http.favicon](https://blog.shodan.io/deep-dive-http-favicon/)
- [6] [mmh3 documentation](https://mmh3.readthedocs.io/en/stable/quickstart.html)
- [7] [Platform Web Property Dataset](https://docs.censys.com/docs/platform-web-property-dataset)
- [8] [urlscan.io – Search API Reference](https://urlscan.io/docs/search/)
- [9] [Registration Data Access Protocol Help](https://www.verisign.com/news-insights/registration-data-access-protocol/help/)
- [10] [RFC 9083: JSON Responses for the Registration Data Access Protocol](https://www.rfc-editor.org/rfc/rfc9083.html)
- [11] [Token tactics: How to prevent, detect, and respond to cloud token theft](https://www.microsoft.com/en-us/security/blog/2022/11/16/token-tactics-how-to-prevent-detect-and-respond-to-cloud-token-theft/)
- [12] [APNIC Blog – JA4+ network fingerprinting](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [13] [Patrik Hudak – Finding Phishing: Tools and Techniques](https://0xpatrik.com/phishing-domains/)
- [14] [Ryan Sears – Introducing CertStream](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067)
- [15] [x0rz – Phishing Catcher](https://github.com/x0rz/phishing_catcher)
- [16] [Devansh Batham – FavFreak](https://github.com/devanshbatham/FavFreak)
{{#include ../../banners/hacktricks-training.md}}
